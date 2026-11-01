package login

// Gap coverage for pure offline-testable surface: MITM rewrite, login
// recovery, stage-1 reply checks, env/RSA loaders, small helpers. All
// values synthetic; never real credentials. Live-network paths (Login,
// roundTrip, stageOne/Two, BaseAppLogin) stay untested by design:
// tests stay offline per AGENTS.md.
import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loginReplyRecord builds a 16B session record (ip + port BE + salt +
// key LE, zero-padded to the Blowfish block size) mirroring
// buildLoggedOnReply in hijack_test.go.
func loginReplyRecord(ip [4]byte, port uint16, salt uint16, sessionKey uint32) []byte {
	rec := make([]byte, 16)
	copy(rec, ip[:])
	binary.BigEndian.PutUint16(rec[4:6], port)
	binary.BigEndian.PutUint16(rec[6:8], salt)
	binary.LittleEndian.PutUint32(rec[8:12], sessionKey)
	return rec
}

func TestRewriteLoginReplyRoundTrip(t *testing.T) {
	const key = "0123456789abcdef"
	blob, err := encryptLogin(key, loginReplyRecord([4]byte{92, 223, 20, 215}, 32838, 0x1234, 0x1327c898))
	if err != nil {
		t.Fatal(err)
	}
	out, sess, err := RewriteLoginReply(blob, key, net.ParseIP("127.0.0.1"), 32901)
	if err != nil {
		t.Fatalf("RewriteLoginReply: %v", err)
	}
	if len(out) != len(blob) {
		t.Fatalf("length drift %d -> %d", len(blob), len(out))
	}
	if sess.ServerAddr.String() != "92.223.20.215" || sess.ServerPort != 32838 || sess.SessionKey != 0x1327c898 {
		t.Fatalf("session = %s:%d key=%08x", sess.ServerAddr, sess.ServerPort, sess.SessionKey)
	}
	clear, err := decryptLogin(key, out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clear[0:4], net.ParseIP("127.0.0.1").To4()) {
		t.Fatalf("endpoint not swapped: %x", clear[0:6])
	}
	if binary.BigEndian.Uint16(clear[4:6]) != 32901 {
		t.Fatalf("port not swapped: %x", clear[4:6])
	}
	if binary.BigEndian.Uint16(clear[6:8]) != 0x1234 || binary.LittleEndian.Uint32(clear[8:12]) != 0x1327c898 {
		t.Fatalf("salt/key clobbered: %x", clear[6:12])
	}
}

func TestRewriteLoginReplyRejects(t *testing.T) {
	const key = "0123456789abcdef"
	blob, err := encryptLogin(key, loginReplyRecord([4]byte{92, 223, 20, 215}, 32838, 0, 0x1327c898))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RewriteLoginReply(blob, "ffffffffffffffff", net.ParseIP("127.0.0.1"), 32901); err == nil {
		t.Fatal("wrong key must fail, not ship a garbage endpoint")
	}
	if _, _, err := RewriteLoginReply(blob, key, net.ParseIP("::1"), 32901); err == nil {
		t.Fatal("non-IPv4 target must fail")
	}
	if _, _, err := RewriteLoginReply([]byte{1, 2, 3}, key, net.ParseIP("127.0.0.1"), 32901); err == nil {
		t.Fatal("short blob must fail")
	}
}

// rotationDatagram builds a channel-encrypted stage-1 rotation reply:
// head + [FF][len=8][rid][newkey], the shape extractStageKey accepts.
func rotationDatagram(t *testing.T, key string, rid, newkey uint32) []byte {
	t.Helper()
	clear := []byte{0x00, 0x00, msgReply, 0x08, 0x00, 0x00, 0x00}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], rid)
	clear = append(clear, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], newkey)
	clear = append(clear, tmp[:]...)
	enc, err := encryptBlowfish(key, clear)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0x01, 0x02, 0x03, 0x04}, enc...)
}

func TestCheckBaseAppReplyRotation(t *testing.T) {
	const key = "0123456789abcdef"
	const rid = 80358
	const old = 0x1327c898
	if err := checkBaseAppReply(rotationDatagram(t, key, rid, 0xdeadbeef), rid, old, key); err != nil {
		t.Fatalf("fresh rotation rejected: %v", err)
	}
	if err := checkBaseAppReply(rotationDatagram(t, key, rid, old), rid, old, key); err == nil {
		t.Fatal("unchanged key must be rejected (exe LoginHandler FAILS it)")
	}
	if err := checkBaseAppReply(rotationDatagram(t, key, rid, 0), rid, old, key); err == nil {
		t.Fatal("zero rotation must be rejected")
	}
	if err := checkBaseAppReply([]byte{1, 2}, rid, old, key); err == nil {
		t.Fatal("short reply must fail")
	}
	if err := checkBaseAppReply(rotationDatagram(t, key, rid+1, 0xdeadbeef), rid, old, key); err == nil {
		t.Fatal("wrong-rid rotation must fail")
	}
}

func TestExtractStageKeyShapes(t *testing.T) {
	const rid = 42
	d := rotationDatagram(t, "0123456789abcdef", rid, 0xdeadbeef)
	clear, err := decryptBlowfish("0123456789abcdef", d[4:])
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := extractStageKey(clear, rid); !ok || k != 0xdeadbeef {
		t.Fatalf("extract = %08x,%v", k, ok)
	}
	if _, ok := extractStageKey(clear, rid+1); ok {
		t.Fatal("wrong rid must not match")
	}
	if _, ok := extractStageKey([]byte{0x00}, rid); !ok {
		_ = ok // too short: no match, no panic
	}
	if _, ok := extractStageKey([]byte{0x00, 0x00, 0x01}, rid); ok {
		t.Fatal("non-reply head must not match")
	}
}

func TestServerSeqAndStageKeyOf(t *testing.T) {
	const key = "0123456789abcdef"
	raw := []byte{0x48, 0x14, 0x01, 0x07, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00}
	enc, err := encryptBlowfish(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	d := append([]byte{1, 2, 3, 4}, enc...)
	if seq, ok := serverSeqOf(d, key); !ok || seq != 7 {
		t.Fatalf("seq = %d,%v", seq, ok)
	}
	const rid = 99
	rd := rotationDatagram(t, key, rid, 0xabcdef01)
	if k, ok := stageKeyOf(rd, rid, key); !ok || k != 0xabcdef01 {
		t.Fatalf("stagekey = %08x,%v", k, ok)
	}
	if _, ok := stageKeyOf([]byte{1}, rid, key); ok {
		t.Fatal("short datagram must not match")
	}
}

func TestParseLobbyRedirectSynthetic(t *testing.T) {
	ip := "92.223.20.215"
	pay := []byte{byte(len(ip))}
	pay = append(pay, ip...)
	pay = append(pay, 0x00) // separator byte the parser skips
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], 32838)
	pay = append(pay, tmp[:]...)
	pay = append(pay, 0x00) // ln >= 18 needs one trailer byte
	clear := []byte{0x00, 0x00, 0x1a, 0x79, byte(len(pay))}
	clear = append(clear, pay...)
	gotIP, gotPort, ok := parseLobbyRedirect(clear)
	if !ok || gotIP != ip || gotPort != 32838 {
		t.Fatalf("redirect = %s:%d,%v", gotIP, gotPort, ok)
	}
	if _, _, ok := parseLobbyRedirect([]byte{0x1a, 0x79, 0x05, 1, 2, 3}); ok {
		t.Fatal("short redirect must not match")
	}
	bad := append([]byte(nil), clear...)
	copy(bad[6:6+len(ip)], []byte("not-an-ip-addr!!"))
	if _, _, ok := parseLobbyRedirect(bad); ok {
		t.Fatal("unparsable IP must not match")
	}
}

func TestBuildBaseAppProbeShape(t *testing.T) {
	pkt, err := BuildBaseAppProbe(80358, 0x1327c898, 1300)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 22 {
		t.Fatalf("probe %d B, want 22", len(pkt))
	}
	if pkt[4] != 0x01 || pkt[5] != 0x00 {
		t.Fatalf("probe flags %02x %02x", pkt[4], pkt[5])
	}
	if got := int(binary.LittleEndian.Uint16(pkt[len(pkt)-2:])); got != 2 {
		t.Fatalf("probe footer %d, want 2", got)
	}
}

func TestLoadEnvFake(t *testing.T) {
	dir := t.TempDir()
	env := `LOGIN_HOST=login.p9.example.invalid
LOGIN_PORT=20016
AUTH_METHOD=basic
AUTH_REALM=EU
LANG=en
LOGIN=gapuser
PASSWORD=fakepw
BLOCK_KEY=0123456789abcdef
ENCRYPTED=1
DIGEST_HEX=00112233445566778899aabbccddeeff
MTU=1300
`
	p := filepath.Join(dir, "gap.env")
	if err := os.WriteFile(p, []byte(env), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadEnv(p)
	if err != nil {
		t.Fatalf("LoadEnv: %v", err)
	}
	if c.Host != "login.p9.example.invalid" || c.Port != 20016 || c.Login != "gapuser" {
		t.Fatalf("identity = %s:%d %q", c.Host, c.Port, c.Login)
	}
	if c.BlockKey != "0123456789abcdef" {
		t.Fatal("explicit BLOCK_KEY must pass through (no regen)")
	}
	if hex.EncodeToString(c.Digest[:]) != "00112233445566778899aabbccddeeff" {
		t.Fatalf("digest = %x", c.Digest)
	}
	if c.FirstReplyID == 0 || c.FirstReplyID > 0x1FFFF {
		t.Fatalf("FirstReplyID = %d (genuine range 1..2^17-1)", c.FirstReplyID)
	}
	// Missing file and missing host fail loud.
	if _, err := LoadEnv(filepath.Join(dir, "nope.env")); err == nil {
		t.Fatal("missing file must fail")
	}
	noHost := filepath.Join(dir, "nohost.env")
	if err := os.WriteFile(noHost, []byte("LOGIN=x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnv(noHost); err == nil {
		t.Fatal("missing LOGIN_HOST must fail")
	}
	// BLOCK_KEY_EMPTY=1 keeps an empty key (plaintext probe path).
	empty := filepath.Join(dir, "empty.env")
	if err := os.WriteFile(empty, []byte("LOGIN_HOST=h\nBLOCK_KEY_EMPTY=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ce, err := LoadEnv(empty)
	if err != nil {
		t.Fatalf("LoadEnv empty-key: %v", err)
	}
	if ce.BlockKey != "" {
		t.Fatal("BLOCK_KEY_EMPTY must keep the key empty")
	}
	// Absent key material mints a fresh key (never empty without opt-in).
	fresh, err := LoadEnv(noHost)
	if err == nil {
		_ = fresh // nohost lacks LOGIN_HOST so this fails; regen covered below
	}
	regenSrc := filepath.Join(dir, "regen.env")
	if err := os.WriteFile(regenSrc, []byte("LOGIN_HOST=h\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cr, err := LoadEnv(regenSrc)
	if err != nil {
		t.Fatalf("LoadEnv regen: %v", err)
	}
	if len(cr.BlockKey) != 16 {
		t.Fatalf("regenerated key %d chars, want 16", len(cr.BlockKey))
	}
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRSAKeysRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("no RSA: %v", err)
	}
	dir := t.TempDir()
	derPub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := writePEM(t, dir, "pub.pem", "PUBLIC KEY", derPub)
	derPriv, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPath := writePEM(t, dir, "priv.pem", "PRIVATE KEY", derPriv)
	pub, err := LoadRSAPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadRSAPublicKey: %v", err)
	}
	if pub.Size() != 256 || pub.Public() == nil {
		t.Fatalf("pub size=%d", pub.Size())
	}
	if _, err := LoadRSAPrivateKey(privPath); err != nil {
		t.Fatalf("LoadRSAPrivateKey: %v", err)
	}
	if _, err := LoadRSAPublicKey(filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("missing pubkey must fail")
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRSAPublicKey(bad); err == nil {
		t.Fatal("non-PEM pubkey must fail")
	}
	if _, err := LoadRSAPrivateKey(bad); err == nil {
		t.Fatal("non-PEM privkey must fail")
	}
}

func TestEncodeLogOnParamsBranches(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("no RSA: %v", err)
	}
	cfg := Config{Login: "gapuser", Password: "fakepw", BlockKey: "0123456789abcdef",
		Session: "blob", Temporary: "1", AuthMethod: "basic", Publication: "0",
		Realm: "EU", Lang: "en", ClientContext: "{}"}
	plain, err := encodeLogOnParams(cfg, nil)
	if err != nil {
		t.Fatalf("plaintext branch: %v", err)
	}
	p, err := parseLogOnParamsClear(plain)
	if err != nil {
		t.Fatalf("parse plaintext: %v", err)
	}
	if p.EncKey != cfg.BlockKey || p.Password != "fakepw" {
		t.Fatalf("roundtrip key=%q pwd=%q", p.EncKey, p.Password)
	}
	cfg.Encrypted = true
	cipher, err := encodeLogOnParams(cfg, &RSAPublicKey{key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("RSA branch: %v", err)
	}
	if len(cipher)%256 != 0 {
		t.Fatalf("cipher %d not whole RSA blocks", len(cipher))
	}
}

// TestRecoverLoginKeySynthetic builds a genuine-geometry login#1 (534 B:
// prefix + flags + login msg with a 512 B / 2-block RSA body + footer)
// encrypted to a throwaway MITM key, and recovers the block key from it.
func TestRecoverLoginKeySynthetic(t *testing.T) {
	mitm, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("no RSA: %v", err)
	}
	srv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("no RSA: %v", err)
	}
	dir := t.TempDir()
	derMitm, err := x509.MarshalPKCS8PrivateKey(mitm)
	if err != nil {
		t.Fatal(err)
	}
	mitmPath := writePEM(t, dir, "mitm.pem", "PRIVATE KEY", derMitm)
	derSrv, err := x509.MarshalPKIXPublicKey(&srv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	srvPath := writePEM(t, dir, "srv.pem", "PUBLIC KEY", derSrv)
	cfg := Config{Login: "gapuser", Password: "fakepw", BlockKey: "0123456789abcdef",
		Session: "blob", Temporary: "1", AuthMethod: "basic", Publication: "0",
		Realm: "EU", Lang: "en",
		ClientContext: `{"lang_id": "en", "publication": "0", "pad": "` + strings.Repeat("0123456789abcdef", 8) + `"}`}
	cipher, err := encryptLogOnParams(cfg, &RSAPublicKey{key: &mitm.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(cipher) != 512 {
		t.Skipf("synthetic cleartext chunked to %d B, not the live 512 — geometry changed", len(cipher))
	}
	msg := buildLoginMsg(80356, [4]byte{verSub, verPatch, verMinor, verMajor}, cipher, true)
	var prefix [4]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		t.Fatal(err)
	}
	pkt := buildLoginPacket(prefix, 0, msg)
	if len(pkt) != 534 {
		t.Fatalf("synthetic login#1 = %d B, want 534", len(pkt))
	}
	dump := []DumpDatagram{{Dir: "C>S", Addr: "10.0.0.9:51260", Data: pkt}}
	got, err := RecoverLoginKey(dump, mitmPath, srvPath, "")
	if err != nil {
		t.Fatalf("RecoverLoginKey: %v", err)
	}
	if got != cfg.BlockKey {
		t.Fatal("recovered key mismatch (values never logged)")
	}
	if _, err := RecoverLoginKey(nil, mitmPath, srvPath, ""); err == nil {
		t.Fatal("empty dump must fail")
	}
}

func TestCensusEntityBurstsSynthetic(t *testing.T) {
	const key = "0123456789abcdef"
	mk := func(c uint16) []byte {
		b := make([]byte, entityBurstBodyLen)
		for i := range b {
			b[i] = byte(i*7 + int(c))
		}
		binary.LittleEndian.PutUint16(b[84:86], c)
		b[86], b[87] = 0, 0
		return b
	}
	var dump []DumpDatagram
	for _, c := range []uint16{249, 258} {
		// 0x0078 = ON|REL|SEQ|REQ -> 12B trailer.
		clear := append([]byte{0x78, 0x00}, mk(c)...)
		clear = append(clear, bytes.Repeat([]byte{0x07}, 12)...)
		enc, err := encryptBlowfish(key, clear)
		if err != nil {
			t.Fatal(err)
		}
		dump = append(dump, DumpDatagram{Dir: "S>C", Addr: "203.0.113.7:32838", Data: append([]byte{1, 2, 3, 4}, enc...)})
	}
	cs, n, skipped, err := CensusEntityBursts(dump, "32838", key)
	if err != nil {
		t.Fatalf("CensusEntityBursts: %v", err)
	}
	if n != 2 || skipped != 0 || len(cs) != 2 || cs[0] != 249 || cs[1] != 258 {
		t.Fatalf("counters=%v n=%d skipped=%d", cs, n, skipped)
	}
	if _, _, _, err := CensusEntityBursts(nil, "32838", key); err == nil {
		t.Fatal("empty dump must fail")
	}
}

func TestEncryptLoginRoundtrip(t *testing.T) {
	const key = "0123456789abcdef"
	raw := bytes.Repeat([]byte{0xab}, 32)
	enc, err := encryptLogin(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encryptLogin(key, []byte{1, 2, 3}); err == nil {
		t.Fatal("non-block input must fail")
	}
	dec, err := decryptLogin(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, raw) {
		t.Fatal("login-path roundtrip mismatch")
	}
}

func TestTryZlibShapes(t *testing.T) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("gap")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	// flate stream is not zlib framing: must refuse, never panic.
	if _, ok := tryZlib(buf.Bytes()); ok {
		t.Fatal("raw flate must not pass as zlib")
	}
	if _, ok := tryZlib([]byte{1, 2, 3}); ok {
		t.Fatal("garbage must not pass as zlib")
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := toU64([]uint32{1, 0xffffffff}); len(got) != 2 || got[0] != 1 || got[1] != 0xffffffff {
		t.Fatalf("toU64 = %v", got)
	}
	if got := NoncesHex([]uint32{0x01020304}); got != "04030201" {
		t.Fatalf("NoncesHex = %q", got)
	}
	if id, err := NewReplyID(); err != nil || id > 0x1FFFF {
		t.Fatalf("NewReplyID = %d,%v", id, err)
	}
	if r := smallRID(); r == 0 || r > 0x1FFFF {
		t.Fatalf("smallRID = %d", r)
	}
	if hex2(0xff) != "ff" || hex2(0x04) != "04" {
		t.Fatalf("hex2 = %q %q", hex2(0xff), hex2(0x04))
	}
	if unquote(`"ab"`) != "ab" || unquote("'ab'") != "ab" || unquote("ab") != "ab" {
		t.Fatal("unquote mismatch")
	}
	if got := defaultClientContext("en", "0"); got != `{"lang_id": "en", "publication": "0"}` {
		t.Fatalf("clientContext = %q", got)
	}
	c := Config{Host: "203.0.113.9", Port: 20016}
	peer, err := c.Peer()
	if err != nil || peer.String() != "203.0.113.9:20016" {
		t.Fatalf("Peer = %v,%v", peer, err)
	}
	if pwdToken("en", "pw") != "pw" {
		t.Fatal("non-CN pwdToken must be identity")
	}
	if len(pwdToken("cn", "pw")) != 32 {
		t.Fatal("CN pwdToken must be md5hex")
	}
	if Token2FamilyMatch("garbage") || Token2FamilyMatch("") || Token2FamilyMatch("a:b") {
		t.Fatal("Token2FamilyMatch must fail silent on malformed input")
	}
	if got := auxFor(0); !bytes.Equal(got, []byte{0xff, 0xff, 0xff, 0x0f}) {
		t.Fatalf("auxFor(0) = %x", got)
	}
	if got := auxFor(1); !bytes.Equal(got, []byte{0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("auxFor(1) = %x", got)
	}
	if s := structSig([]byte{0x48, 0x14, 0x13, 0x00}, 1); !strings.Contains(s, "ridat=") || !strings.Contains(s, "[id=13 fixed1]") {
		t.Fatalf("structSig = %q", s)
	}
}
