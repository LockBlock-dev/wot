package login

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blowfish"
)

// Server challenge datagram, pkt1 of wot_EU1_connection.pcapng.
const challengePktHx = "9f3d117b0000ff2c000000d8670100420c6375636b6f6f5f6379636c6511666361323233333830626465373137383acccc080000000000"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad vector: %v", err)
	}
	return b
}

func TestParseChallengeReply(t *testing.T) {
	replyID, status, rest, err := parseReply(mustHex(t, challengePktHx))
	if err != nil {
		t.Fatalf("parseReply: %v", err)
	}
	if replyID != 92120 || status != statusChallengeIssued {
		t.Fatalf("replyID=%d status=%d", replyID, status)
	}
	ch, err := parseChallenge(rest)
	if err != nil {
		t.Fatalf("parseChallenge: %v", err)
	}
	if ch.Type != "cuckoo_cycle" || ch.Prefix != "fca223380bde7178:" || ch.MaxNonce != 576716 {
		t.Fatalf("challenge = %+v", ch)
	}
}

func TestBuildLoginMsgShape(t *testing.T) {
	cipher := make([]byte, 512) // 2 RSA blocks, like a real token login
	msg := buildLoginMsg(92120, [4]byte{5, 0, 1, 17}, cipher, true)
	if msg[0] != msgLogin {
		t.Fatalf("ID = %02x", msg[0])
	}
	// Request len covers DATA only (version+flag+cipher), excluding the
	// 6 request-header bytes (ReplyID+nextOff). login.pcapng login#1:
	// len 517 = 4+1+512 with total message 1+2+523 = 526.
	if ln := int(binary.LittleEndian.Uint16(msg[1:3])); ln != 4+1+512 {
		t.Fatalf("len field = %d, want 517", ln)
	}
	if len(msg) != 3+6+4+1+512 {
		t.Fatalf("message bytes = %d, want 526", len(msg))
	}
	if id := binary.LittleEndian.Uint32(msg[3:7]); id != 92120 {
		t.Fatalf("replyID = %d", id)
	}
	if msg[7] != 0 || msg[8] != 0 || msg[9] != 5 {
		t.Fatalf("link/version = %x", msg[7:13])
	}
	// isEncrypted flag (IDA sub_140E6E100) sits between version and params.
	if msg[13] != 0x01 {
		t.Fatalf("isEncrypted = %02x", msg[13])
	}
	plain := buildLoginMsg(92120, [4]byte{5, 0, 1, 17}, cipher, false)
	if plain[13] != 0x00 {
		t.Fatalf("plaintext flag = %02x", plain[13])
	}
}

func TestBuildLoginPacketReqOff(t *testing.T) {
	// pcap pkt2: CR(3+191=194 B) at rel 2, login retry at rel 196,
	// footer c4 00 = 196 (first *request*, skipping unreliable CR).
	// Full datagram mirrors login.pcapng login#2: 4+2+194+526+2 = 728,
	// and the single-login datagram mirrors login#1: 4+2+526+2 = 534.
	cr := buildChallengeResponseMsg(0, "fca223380bde7178:0", make([]uint32, 42))
	if len(cr) != 3+191 {
		t.Fatalf("CR len = %d", len(cr))
	}
	login := buildLoginMsg(92121, [4]byte{5, 0, 1, 17}, make([]byte, 512), true)
	if len(login) != 526 {
		t.Fatalf("login msg = %d, want 526", len(login))
	}
	pkt := buildLoginPacket([4]byte{}, 0, cr, login)
	if len(pkt) != 728 {
		t.Fatalf("two-msg packet = %d, want 728", len(pkt))
	}
	foot := int(binary.LittleEndian.Uint16(pkt[len(pkt)-2:]))
	if foot != 2+len(cr) {
		t.Fatalf("two-msg reqOff = %d, want %d", foot, 2+len(cr))
	}
	// Single request still points at rel 2.
	solo := buildLoginPacket([4]byte{}, 0, login)
	if len(solo) != 534 {
		t.Fatalf("single packet = %d, want 534", len(solo))
	}
	if foot := int(binary.LittleEndian.Uint16(solo[len(solo)-2:])); foot != 2 {
		t.Fatalf("single reqOff = %d, want 2", foot)
	}
}

func TestBuildChallengeResponseShape(t *testing.T) {
	nonces := make([]uint32, 42)
	msg := buildChallengeResponseMsg(0, "fca223380bde7178:0", nonces)
	if msg[0] != msgChallengeResponse {
		t.Fatalf("ID = %02x", msg[0])
	}
	// duration f32 + keylen(1)+key(18) + 42*4 = 191 payload.
	if ln := int(binary.LittleEndian.Uint16(msg[1:3])); ln != 191 {
		t.Fatalf("len = %d, want 191", ln)
	}
}

// Genuine 2.4.0 vectors (game client via wotproxy, captures/wotproxy.hex):
// 55 B challenge (rid 97676), 64 B status-68 error, and login#2's 194 B
// challengeResponse message (flow 8 of captures/eu2-mitmproxy-flows).
const (
	genuineChallengeHx = "9fa31a470000ff2c0000008c7d0100420c6375636b6f6f5f6379636c6511333965383332643031346363656236363acccc080000000000"
	genuineError68Hx   = "9f3e1d7d0000ff350000008d7d0100442f496e76616c6964206c6f67696e2f70617373776f726420666f722062617369632061757468656e7469636174696f6e"
	genuineCRMsgHx     = "03bf000cc01b3d12346538376431633033636662383165323a30590400009c1e0000d33b0000f0c30000eafc00009cfd00001359010045760100b3b501000edc0100690d02006e2d0200943b0200ae4002009f910200c2e602002ffb0200213b030066770300e9b3030037fe03003c520400328104005aab04006bb804005fbe04003ecb04001ad30400c835050063820500f9880500bf9c050096ba0500fbe50500ed2606007b9306008ef806009a3a07002d8d07002fdb0700c8e0070062f30700"
)

func TestParseChallengeReply24(t *testing.T) {
	replyID, status, rest, err := parseReply(mustHex(t, genuineChallengeHx))
	if err != nil {
		t.Fatalf("parseReply: %v", err)
	}
	if replyID != 97676 || status != statusChallengeIssued {
		t.Fatalf("replyID=%d status=%d", replyID, status)
	}
	ch, err := parseChallenge(rest)
	if err != nil {
		t.Fatalf("parseChallenge: %v", err)
	}
	if ch.Type != "cuckoo_cycle" || ch.Prefix != "39e832d014cceb66:" || ch.MaxNonce != 576716 {
		t.Fatalf("challenge = %+v", ch)
	}
}

func TestParseErrorReply68(t *testing.T) {
	_, status, rest, err := parseReply(mustHex(t, genuineError68Hx))
	if err != nil {
		t.Fatalf("parseReply: %v", err)
	}
	if status != 68 {
		t.Fatalf("status=%d, want 68", status)
	}
	// Error bodies are plaintext packed strings (no Blowfish): the 0x2f
	// first byte is the length (47), not a '/' message prefix.
	msg, _, err := consumePackedString(rest)
	if err != nil {
		t.Fatalf("consumePackedString: %v", err)
	}
	if msg != "Invalid login/password for basic authentication" {
		t.Fatalf("msg=%q", msg)
	}
}

func TestChallengeResponseMatchesGenuine(t *testing.T) {
	raw := mustHex(t, genuineCRMsgHx)
	if len(raw) != 3+191 || raw[0] != msgChallengeResponse {
		t.Fatalf("msg shape: len=%d id=%02x", len(raw), raw[0])
	}
	if ln := int(binary.LittleEndian.Uint16(raw[1:3])); ln != 191 {
		t.Fatalf("len field = %d, want 191", ln)
	}
	dur := math.Float32frombits(binary.LittleEndian.Uint32(raw[3:7]))
	if dur <= 0 || dur > 5 {
		t.Fatalf("duration=%v", dur)
	}
	key, n, err := consumePackedString(raw[7:])
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if key != "4e87d1c03cfb81e2:0" {
		t.Fatalf("key=%q", key)
	}
	noncesRaw := raw[7+n:]
	if len(noncesRaw) != 42*4 {
		t.Fatalf("nonces bytes = %d, want 168", len(noncesRaw))
	}
	nonces := make([]uint32, 42)
	for i := range nonces {
		nonces[i] = binary.LittleEndian.Uint32(noncesRaw[4*i:])
		if i > 0 && nonces[i] <= nonces[i-1] {
			t.Fatalf("nonces not ascending at %d", i)
		}
	}
	// Our builder reproduces the genuine message: id+len and the whole
	// key+nonces blob byte-identical, duration within float32 rounding.
	rebuilt := buildChallengeResponseMsg(time.Duration(float64(dur)*float64(time.Second)), key, nonces)
	if !bytes.Equal(rebuilt[:3], raw[:3]) || !bytes.Equal(rebuilt[7:], raw[7:]) {
		t.Fatalf("builder mismatch")
	}
	if got := math.Float32frombits(binary.LittleEndian.Uint32(rebuilt[3:7])); math.Abs(float64(got-dur)) > 1e-9 {
		t.Fatalf("duration %v != %v", got, dur)
	}
}

func TestEncryptBlowfishRoundtrip(t *testing.T) {
	// encryptBlowfish must invert through decryptBlowfish for several
	// shapes (pure-ACK 10 B, reply-ish 23 B, arbitrary 41 B).
	for _, n := range []int{10, 23, 41} {
		plain := make([]byte, n)
		for i := range plain {
			plain[i] = byte(i*7 + 3)
		}
		enc, err := encryptBlowfish("0123456789abcdef", plain)
		if err != nil {
			t.Fatalf("encrypt %dB: %v", n, err)
		}
		if len(enc)%8 != 0 {
			t.Fatalf("enc %dB not a whole number of blocks", len(enc))
		}
		back, err := decryptBlowfish("0123456789abcdef", enc)
		if err != nil {
			t.Fatalf("decrypt %dB: %v", n, err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("roundtrip %dB mismatch", n)
		}
	}
}

func TestBuildChannelAckShape(t *testing.T) {
	// Genuine pure-ACK packet: 4 prefix + 24 encrypted; decrypted =
	// flags 48 14 + 4B channel word + fork-order footers [seq][cumul]
	// (paired replay raw "481400000000XX000000YY000000").
	ack, err := buildChannelPacket("0123456789abcdef", flagsUnrel, nil, midZero, 7, 42)
	if err != nil {
		t.Fatalf("buildChannelPacket: %v", err)
	}
	if len(ack) != 4+24 {
		t.Fatalf("ack = %d B, want 28", len(ack))
	}
	clear, err := decryptBlowfish("0123456789abcdef", ack[4:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(clear) != 14 || clear[0] != 0x48 || clear[1] != 0x14 {
		t.Fatalf("flags = %x", clear[:2])
	}
	seq, cumul, ok := channelSeqs(clear)
	if !ok || seq != 7 || cumul != 42 {
		t.Fatalf("footers seq=%d cumul=%d ok=%v", seq, cumul, ok)
	}
}

func TestBuildAuthenticateShape(t *testing.T) {
	// BaseApp.authenticate: [02][key LE], FIXED-4. With framing + footers
	// the packet is 4+24 = 28 B — the genuine post-reply size (paired
	// replay raw "58040288ae6a690b0000000001000000").
	StageBareAuth = false
	app := authApp(0x12345678)
	if len(app) != 6 || app[0] != 0x02 {
		t.Fatalf("app = %x", app)
	}
	ack, err := buildChannelPacket("0123456789abcdef", flagsRel, app, nil, 0, 1)
	if err != nil {
		t.Fatalf("buildChannelPacket: %v", err)
	}
	if len(ack) != 4+24 {
		t.Fatalf("auth packet = %d B, want 28", len(ack))
	}
	clear, err := decryptBlowfish("0123456789abcdef", ack[4:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(clear) != 16 || clear[2] != 0x02 {
		t.Fatalf("clear len=%d head=%x", len(clear), clear[:4])
	}
}

func TestBuildBaseAppLoginMsg(t *testing.T) {
	// EU2 capture flow 10 handshake: rid 74099, key fb6289e6, att 1, mtu 1300.
	msg := buildBaseAppLoginMsg(74099, 0xe68962fb, 1, 1300)
	want := mustHex(t, "00732101000000fb6289e6011405")
	if !bytes.Equal(msg, want) {
		t.Fatalf("msg=%x, want %x", msg, want)
	}
}

func TestParseRedirectVariant(t *testing.T) {
	// Second genuine envelope (logins.pcapng stage-1 on .213:32836):
	// middle byte 0xbc instead of flows3's 0x3f. Only the 0x44 core
	// ([44][ip4][port BE][00 00 01]) plus trailer are matched.
	clear := []byte{0x48, 0x14, 0x13, 0xbc, 0x44, 92, 223, 20, 213, 0x80, 0x3f,
		0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	tgt, ok := parseRedirect(clear)
	if !ok || tgt.String() != "92.223.20.213:32831" {
		t.Fatalf("redirect variant: %v %v", tgt, ok)
	}
	// Truncated envelope must not parse.
	if _, ok := parseRedirect(clear[:13]); ok {
		t.Fatalf("truncated redirect parsed")
	}
}

func TestCpsaltSession(t *testing.T) {
	// Stored sessions pass through (wg_cpsalt identity for GUIDs).
	if got := cpsaltSession("6f9619ff-8b86-d011-b42d-00c04fc964ff"); got != "6f9619ff-8b86-d011-b42d-00c04fc964ff" {
		t.Fatalf("passthrough = %q", got)
	}
	// Empty store mints a GUID, never "" — the game never sends md5("")
	// (d41d8cd98f00b204e9800998ecf8427e) on the wire.
	g1, g2 := cpsaltSession(""), cpsaltSession("")
	for _, g := range []string{g1, g2} {
		if len(g) != 36 || g[8] != '-' || g[13] != '-' || g[18] != '-' || g[23] != '-' {
			t.Fatalf("guid shape = %q", g)
		}
		if md5hex(g) == "d41d8cd98f00b204e9800998ecf8427e" {
			t.Fatalf("empty-hash session field")
		}
	}
	if g1 == g2 {
		t.Fatalf("fresh GUID minted twice identically")
	}
}

func TestRSARoundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Skipf("no RSA: %v", err)
	}
	pub := &RSAPublicKey{key: &priv.PublicKey}
	cfg := Config{Login: "u", Password: "p", BlockKey: "0123456789abcdef", ClientContext: "{}"}
	cfg.Session = "s"
	cipher, err := encryptLogOnParams(cfg, pub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(cipher)%256 != 0 {
		t.Fatalf("cipher %d not a whole number of RSA blocks", len(cipher))
	}
	// Decrypt chunk-wise like PublicKeyCipher::decrypt.
	var clear []byte
	for off := 0; off < len(cipher); off += 256 {
		blk, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipher[off:off+256], nil)
		if err != nil {
			t.Fatalf("decrypt block: %v", err)
		}
		clear = append(clear, blk...)
	}
	// flags + packed JSON username must lead the cleartext (py2.7 dict
	// order: session first; single-byte packed length since user JSON
	// is < 255 bytes). Compares the exact username bytes.
	user := cfg.Username()
	if len(user) >= 255 {
		t.Fatalf("username too long for 1-byte packed length")
	}
	if clear[0] != 0x01 || int(clear[1]) != len(user) || string(clear[2:2+len(user)]) != user {
		t.Fatalf("cleartext head = %x", clear[:16])
	}
}

// TestRSAChunkSizes proves partSize follows the loaded key (engine formula
// keySize-42), not a hardcoded 214: a 1024-bit key chunks 200 B into
// 2x128, and a 2024-bit key chunks 300 B into 2x253 = 506 B — exactly the
// live wire shape that a hardcoded 2048 partSize could never produce.
func TestRSAChunkSizes(t *testing.T) {
	for _, bits := range []int{1024, 2024} {
		priv, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Skipf("no RSA-%d: %v", bits, err)
		}
		pub := &RSAPublicKey{key: &priv.PublicKey}
		size := priv.PublicKey.Size()
		partSize := size - 42
		// Password sized so the full cleartext lands just over a whole
		// number of chunks (base cleartext is ~190 B since the username
		// JSON carries temporary/publication, so the target chunk count
		// is derived, not hardcoded to two).
		cfg := Config{
			Login: "u", BlockKey: "0123456789abcdef", ClientContext: "{}",
			// Fixed session: an empty SESSION mints a fresh GUID per
			// Username() call (wg_cpsalt emulation), which would make
			// the re-built reference cleartext differ byte-wise.
			Session: "6f9619ff-8b86-d011-b42d-00c04fc964ff",
		}
		baseLen := len(buildLogOnParamsClear(cfg))
		k := baseLen/partSize + 1
		target := k*partSize + 50 // 50 < partSize, so chunks = k+1
		cfg.Password = string(make([]byte, target-baseLen))
		cipher, err := encryptLogOnParams(cfg, pub)
		if err != nil {
			t.Fatalf("RSA-%d encrypt: %v", bits, err)
		}
		if len(cipher) != (k+1)*size {
			t.Fatalf("RSA-%d cipher = %d, want %d", bits, len(cipher), (k+1)*size)
		}
		// Decrypt chunk-wise like PublicKeyCipher::decrypt and compare.
		var clear []byte
		for off := 0; off < len(cipher); off += size {
			blk, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipher[off:off+size], nil)
			if err != nil {
				t.Fatalf("RSA-%d decrypt block: %v", bits, err)
			}
			clear = append(clear, blk...)
		}
		if !bytes.Equal(clear, buildLogOnParamsClear(cfg)) {
			t.Fatalf("RSA-%d roundtrip mismatch", bits)
		}
	}
}

// referenceEncrypt mirrors EncryptionFilter::encrypt (2.0.1) so tests can
// build vectors for decryptBlowfish: XOR-chain plaintext then Blowfish-ECB,
// append magic LE + wastage pad.
func referenceEncrypt(t *testing.T, key, plain []byte) []byte {
	t.Helper()
	magicOff := len(plain)
	body := append(append([]byte{}, plain...), 0xEF, 0xBE, 0xAD, 0xDE) // magic LE
	wastage := ((8-((len(body)+1)%8))%8 + 1)
	// Correct order: [plain][pad][magic][wastage]; magic ends at len-1.
	body = append(body[:magicOff], make([]byte, wastage-1)...)
	body = append(body, 0xEF, 0xBE, 0xAD, 0xDE, byte(wastage))
	c, err := blowfish.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(body))
	var prev []byte
	for i := 0; i < len(body); i += 8 {
		blk := append([]byte{}, body[i:i+8]...)
		if prev != nil {
			for j := range blk {
				blk[j] ^= prev[j]
			}
		}
		c.Encrypt(out[i:i+8], blk)
		prev = body[i : i+8]
	}
	return out
}

func TestBlowfishRoundtrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	plain := []byte("LoginReplyRecord?")
	enc := referenceEncrypt(t, key, plain)
	back, err := decryptBlowfish(string(key), enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(back) != string(plain) {
		t.Fatalf("roundtrip = %q", back)
	}
	if _, err := decryptBlowfish(string(key), enc[:len(enc)-8]); err == nil {
		t.Fatal("expected error on truncated input")
	}
}

func TestDecryptSession(t *testing.T) {
	key := []byte("0123456789abcdef")
	// ReplyRecord: ip 185.12.240.66 BE, port 32814 BE, salt 0, key u32 LE.
	rec := []byte{185, 12, 240, 66, 0x80, 0x2E, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12}
	rec = appendPackedString(rec, "welcome")
	s, err := decryptSession(referenceEncrypt(t, key, rec), string(key))
	if err != nil {
		t.Fatalf("decryptSession: %v", err)
	}
	if !s.ServerAddr.Equal([]byte{185, 12, 240, 66}) || s.ServerPort != 32814 {
		t.Fatalf("addr = %v:%d", s.ServerAddr, s.ServerPort)
	}
	if s.SessionKey != 0x12345678 || s.ServerMsg != "welcome" {
		t.Fatalf("session = %+v", s)
	}
}

func TestPackedStrings(t *testing.T) {
	for _, s := range []string{"", "cuckoo_cycle", string(make([]byte, 300))} {
		var b []byte
		b = appendPackedString(b, s)
		got, n, err := consumePackedString(b)
		if err != nil || got != s || n != len(b) {
			t.Fatalf("roundtrip %d: %v %d", len(s), err, n)
		}
	}
	if _, _, err := consumePackedString(nil); err == nil {
		t.Fatal("expected error on empty")
	}
}

func TestToken2Middle(t *testing.T) {
	m, ok := token2Middle("123456789:1234567890123456789:123456789012345678901234567890123456789")
	if !ok || m != "1234567890123456789" {
		t.Fatalf("middle = %q %v", m, ok)
	}
	m2, ok := token2Middle("123456789:1234567890123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if !ok || m2 != m {
		t.Fatalf("same machine, rotated tail must match: %q", m2)
	}
	if _, ok := token2Middle("notatoken"); ok {
		t.Fatalf("garbage must not parse")
	}
}

func TestSessionWireValue(t *testing.T) {
	// Wire `session` is md5hex of the stored BLOB TEXT (Sep 10-variant
	// sweep vs CE.txt ground truth `63ea1e93…`; IDA wg_cpsalt passes the
	// blob through, never the decrypted GUID). The blob itself must
	// never appear on the wire — only its 32-hex hash.
	cfg := Config{AuthMethod: "basic", Realm: "EU", Login: "u", Temporary: "0",
		Publication: "0", Session: "dGhpcyBpcyBhIHRlc3QgYmxvYiB0ZXh0"}
	u := cfg.Username()
	if !strings.Contains(u, md5hex("dGhpcyBpcyBhIHRlc3QgYmxvYiB0ZXh0")) {
		t.Fatalf("username lacks blob-md5: %s", u)
	}
	if strings.Contains(u, "dGhpcyBpcyBhIHRlc3QgYmxvYiB0ZXh0") {
		t.Fatalf("raw blob on the wire: %s", u)
	}
}
