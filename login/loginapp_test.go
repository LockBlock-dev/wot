package login

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/internal/cuckoo"
)

// serverTestMaxNonce loosens the PoW (easiness 8 at SIZESHIFT 20) so the
// offline tests solve within milliseconds; the shipped bound stays the
// DefaultMaxNonce production default. The cuckoo Verify only needs
// nonces < maxNonce.
const serverTestMaxNonce = 8 << 20

// testDigestA is the "guest" digest configured into the test server's
// version table (values are arbitrary; the gate compares bytes only).
var testDigestA = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// testVersions is the one-build table the tests run against: the live
// protocol bytes paired with testDigestA.
func testVersions() []ClientVersion {
	return []ClientVersion{{
		Name:   "test",
		Proto:  [4]byte{verSub, verPatch, verMinor, verMajor},
		Digest: testDigestA,
	}}
}

var (
	testPrivOnce sync.Once
	testPriv     *rsa.PrivateKey
	testKeyErr   error
)

// testRSAKey builds the shared RSA-2048 key once per test binary: every
// loginapp test needs the production chunk geometry (partSize = size-42)
// without paying keygen per test.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testPrivOnce.Do(func() {
		testPriv, testKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if testKeyErr != nil {
		t.Fatalf("rsa keygen: %v", testKeyErr)
	}
	return testPriv
}

// testServer builds a server configured for one test: digest allowlist =
// testDigestA, test-easiness PoW, record endpoint mirroring listen.
// The Verbose flag stays off; failures carry the returned reply shapes.
func testServer(t *testing.T, listen *net.UDPAddr) *LoginAppServer {
	t.Helper()
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce: serverTestMaxNonce,
		Versions: testVersions(),
	}, testRSAKey(t))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	return srv
}

// testPrefix is the caller-chosen C>S prefix (reply prefixes vary per
// packet; never assert theirs, callers' are just bytes here).
func testPrefix(t *testing.T) [4]byte {
	t.Helper()
	var p [4]byte
	if _, err := rand.Read(p[:]); err != nil {
		t.Fatalf("prefix rand: %v", err)
	}
	return p
}

// testClientConfig renders one LogOnParams bundle with the test identity
// (basic auth, public values only) — the production client's builders
// stay the single source of the wire truth.
func testClientConfig(pubkey *RSAPublicKey, encrypted bool) Config {
	return Config{
		Host:          "loginapp.test",
		Port:          20016,
		PubkeyPath:    "-",
		AuthMethod:    "basic",
		Realm:         "EU",
		Lang:          "en",
		Login:         "ExampleUser",
		Password:      "loginapp-test-password",
		BlockKey:      "0123456789abcdef", // cifre only: server encrypts with it
		ClientContext: `{"lang_id": "en", "publication": "0"}`,
		Encrypted:     encrypted,
		SolveTimeout:  15 * time.Second,
	}
}

// loginOneDatagram builds the client's login#1 bytes (plaintext-params
// probe wire only when encrypted=false).
func loginOneDatagram(t *testing.T, rid uint32, encrypted bool) []byte {
	t.Helper()
	priv := testRSAKey(t)
	cfg := testClientConfig(&RSAPublicKey{key: &priv.PublicKey}, encrypted)
	params, err := encryptLogOnParamsWithProvider(cfg, ProviderForConfig(cfg), &RSAPublicKey{key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	msg := buildLoginMsg(rid, [4]byte{verSub, verPatch, verMinor, verMajor}, params, encrypted)
	return buildLoginPacket(testPrefix(t), 0, msg)
}

// challengeOf opens a status-66 reply with the production parseChallenge.
func challengeOf(t *testing.T, pkt []byte, wantRid uint32) Challenge {
	t.Helper()
	rid, status, rest, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if status != statusChallengeIssued || rid != wantRid {
		t.Fatalf("challenge reply rid=%d status=%d (want rid=%d status=66)", rid, status, wantRid)
	}
	ch, err := parseChallenge(rest)
	if err != nil {
		t.Fatalf("challenge body: %v", err)
	}
	return ch
}

// pingDatagram renders the pinned 16-B ping request shape
// (ping/wotping.go encodeRequestWithPrefix vectors).
func pingDatagram(prefix [4]byte, rid uint32, seq uint8) []byte {
	b := make([]byte, 0, 16)
	b = append(b, prefix[:]...)
	b = append(b, 0x01, 0x00, msgPing)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], rid)
	b = append(b, tmp[:]...)
	b = append(b, 0x00, 0x00, seq, 0x02, 0x00)
	return b
}

func TestLoginAppChallengeReplyShape(t *testing.T) {
	srv := testServer(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016})
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 1234, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if len(pkt) != 55 {
		t.Fatalf("challenge datagram %d B, want 55 (genuine total, §5.2)", len(pkt))
	}
	ch := challengeOf(t, pkt, 1234)
	if ch.Type != challengeCuckoo {
		t.Fatalf("challenge type %q", ch.Type)
	}
	if ch.MaxNonce != serverTestMaxNonce {
		t.Fatalf("maxNonce %d, want echo of the configured bound", ch.MaxNonce)
	}
	if !strings.HasSuffix(ch.Prefix, ":") || len(ch.Prefix) != 17 {
		t.Fatalf("prefix %q lacks the 16-hex+colon shape", ch.Prefix)
	}

	// A second login#1 REPLACES the pending challenge (fresh PoW state
	// per attempt, live AwaitChallenge semantics).
	pkt2, err := srv.handlePacket(loginOneDatagram(t, 1235, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	ch2 := challengeOf(t, pkt2, 1235)
	if ch2.Prefix == ch.Prefix {
		t.Fatal("dependent challenges share a prefix — mint must be random")
	}
}

func TestLoginAppPingEcho(t *testing.T) {
	srv := testServer(t, nil)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	pkt, err := srv.handlePacket(pingDatagram(testPrefix(t), 0xb9bd42, 7), from, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016})
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if len(pkt) != 16 {
		t.Fatalf("ping reply %d B, want 16 (genuine echo, §8)", len(pkt))
	}
	rid, status, rest, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 0xb9bd42 || status != 7 || len(rest) != 0 {
		t.Fatalf("ping echo rid=%d status=%d rest=%d", rid, status, len(rest))
	}

	// Pings share the login port: a chained datagram (ping request
	// first, login request linked after it) answers the PING first and
	// never processes the login in the same datagram (never observed
	// live; the ping is the wotping probe shape, §8).
	loginDat := loginOneDatagram(t, 55, true)
	loginMsg := loginDat[6 : len(loginDat)-2] // drop prefix/flags/footer
	var ridBuf [4]byte
	binary.LittleEndian.PutUint32(ridBuf[:], 99)
	nextBuf := make([]byte, 2)
	binary.LittleEndian.PutUint16(nextBuf, uint16(2+8)) // login lands at rel 10
	mixedPfx := testPrefix(t)
	mixed := append([]byte{}, mixedPfx[:]...)
	mixed = append(mixed, 0x01, 0x00, msgPing)
	mixed = append(mixed, ridBuf[:]...)
	mixed = append(mixed, nextBuf...)
	mixed = append(mixed, 0x09) // ping seq
	mixed = append(mixed, loginMsg...)
	mixed = append(mixed, 0x02, 0x00) // first request = the ping at rel 2
	reply, err := srv.handlePacket(mixed, from, nil)
	if err != nil {
		t.Fatalf("mixed datagram: %v", err)
	}
	if reply == nil {
		t.Fatal("mixed datagram drew no ping reply")
	}
	if rid, status, rest, err := parseReply(reply); err != nil || rid != 99 || status != 9 || len(rest) != 0 {
		t.Fatalf("mixed datagram ping echo rid=%d status=%d rest=%d err=%v", rid, status, len(rest), err)
	}
}

func TestLoginAppProbeWalksAndSilences(t *testing.T) {
	srv := testServer(t, nil)
	// 15-B probe request: [prefix4][0100][01][rid 4][next 2][footer "02 00"].
	pfx := testPrefix(t)
	pkt := append([]byte{}, pfx[:]...)
	pkt = append(pkt, 0x01, 0x00, msgProbe)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 777)
	pkt = append(pkt, tmp[:]...)
	pkt = append(pkt, 0x00, 0x00, 0x02, 0x00)
	reply, err := srv.handlePacket(pkt, nil, nil)
	if err != nil {
		t.Fatalf("probe walk: %v", err)
	}
	if reply != nil {
		t.Fatalf("probe drew a reply (%d B); the EMPTY probe member is silent", len(reply))
	}
}

func TestLoginAppUnencryptedAndVersionRefused(t *testing.T) {
	srv := testServer(t, nil)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40003}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	// -empty-key probe shape: plaintext LogOnParams → live refusal 64
	// ("Unencrypted connection is not allowed.", §5.4).
	pkt, err := srv.handlePacket(loginOneDatagram(t, 21, false), from, listen)
	if err != nil {
		t.Fatalf("unencrypted: %v", err)
	}
	rid, status, rest, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 21 || status != statusMalformed {
		t.Fatalf("rid=%d status=%d, want 64", rid, status)
	}
	if text, _, _ := consumePackedString(rest); text != textUnencrypted {
		t.Fatalf("refusal text %q", text)
	}

	// Version gate: foreign client build → 65 (text is our wording).
	priv := testRSAKey(t)
	cfg := testClientConfig(&RSAPublicKey{key: &priv.PublicKey}, true)
	params, err := encryptLogOnParamsWithProvider(cfg, ProviderForConfig(cfg), &RSAPublicKey{key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	msg := buildLoginMsg(22, [4]byte{9, 9, 9, 9}, params, true)
	pkt, err = srv.handlePacket(buildLoginPacket(testPrefix(t), 0, msg), from, listen)
	if err != nil {
		t.Fatalf("bad version: %v", err)
	}
	rid, status, _, err = parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 22 || status != statusBadVersion {
		t.Fatalf("rid=%d status=%d, want 65", rid, status)
	}
}

func loginTwoDatagram(t *testing.T, rid uint32, ch Challenge, digest [16]byte, mutate func(*[]uint32)) []byte {
	t.Helper()
	key, nonces, err := solveChallengeFor(t, ch)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	if mutate != nil {
		mutate(&nonces)
	}
	priv := testRSAKey(t)
	cfg := testClientConfig(&RSAPublicKey{key: &priv.PublicKey}, true)
	cfg.Digest = digest
	params, err := encryptLogOnParamsWithProvider(cfg, ProviderForConfig(cfg), &RSAPublicKey{key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	respMsg := buildChallengeResponseMsg(250*time.Millisecond, key, nonces)
	msg := buildLoginMsg(rid, [4]byte{verSub, verPatch, verMinor, verMajor}, params, true)
	return buildLoginPacket(testPrefix(t), 0, respMsg, msg)
}

// solveChallengeFor is the test-side SolveFunc (production driver, test
// easiness bound).
func solveChallengeFor(t *testing.T, ch Challenge) (string, []uint32, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, nonces, _, err := cuckoo.SolveChallenge(ctx, ch.Prefix, ch.MaxNonce, 4)
	return key, nonces, err
}

func TestLoginAppDigestGateAndSuccess(t *testing.T) {
	srv := testServer(t, nil)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40004}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 31, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 31)

	// Foreign digest → the live 70 + recorded text (§5.4). The solution
	// verifies BEFORE the digest gate, so this leg consumes pending.
	bad := loginTwoDatagram(t, 32, ch, [16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}, nil)
	pkt, err = srv.handlePacket(bad, from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	rid, status, rest, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 32 || status != statusBadDigest {
		t.Fatalf("rid=%d status=%d, want 70", rid, status)
	}
	if text, _, _ := consumePackedString(rest); text != textBadDigest {
		t.Fatalf("digest text %q", text)
	}
	// The solution was verified BEFORE the digest gate → entry consumed;
	// a digest refusal does not leave challenge state behind.
	if len(srv.pending) != 0 {
		t.Fatalf("pending %d: a verified solution must consume the entry", len(srv.pending))
	}

	// Fresh cycle for the acceptance leg: login#1 → challenge → solved
	// login#2 with the allowlisted digest → LOGGED_ON.
	pkt, err = srv.handlePacket(loginOneDatagram(t, 33, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#3: %v", err)
	}
	ch = challengeOf(t, pkt, 33)
	good := loginTwoDatagram(t, 34, ch, testDigestA, nil)
	pkt, err = srv.handlePacket(good, from, listen)
	if err != nil {
		t.Fatalf("handlePacket#4: %v", err)
	}
	rid, status, rest, err = parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 34 || status != statusLoggedOn {
		t.Fatalf("rid=%d status=%d, want 1", rid, status)
	}
	clear, err := decryptLogin("0123456789abcdef", rest)
	if err != nil {
		t.Fatalf("reply decrypt: %v", err)
	}
	sess, err := parseSessionRecord(clear)
	if err != nil {
		t.Fatalf("record parse: %v", err)
	}
	if !sess.ServerAddr.Equal(net.IPv4(127, 0, 0, 1)) || sess.ServerPort != 20016 {
		t.Fatalf("record endpoint %v:%d, want mirrored 127.0.0.1:20016", sess.ServerAddr, sess.ServerPort)
	}
	if sess.SessionKey == 0 {
		t.Fatal("zero session key")
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(sess.ServerMsg), &msg); err != nil {
		t.Fatalf("servermsg parse: %v (len %d)", err, len(sess.ServerMsg))
	}
	if got := msg["name"].(string); got != "ExampleUser" {
		t.Fatalf("servermsg name %q", got)
	}
	if msg["security_msg"] != "old_pass" || msg["isDemoAccount"] != false {
		t.Fatalf("servermsg fields %v", msg)
	}
	id, _ := msg["token2"].(string)
	if len(id) != 69 || id[9] != ':' || id[29] != ':' {
		t.Fatalf("token2 shape %q (len %d)", id, len(id))
	}
	if id[0] == '0' || id[10] == '0' || id[30] == '0' {
		t.Fatal("token2 segments render as decimals — no leading zeros")
	}
	if got := msg["session_id"].(string); len(got) != 32 ||
		got[:3] != "06G" || got[10:16] != "000000" || got[16:22] != "41VPHF" {
		t.Fatalf("session_id shape %q", got)
	}
}

func TestLoginAppBadSolutionReissues(t *testing.T) {
	srv := testServer(t, nil)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40005}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 41, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 41)

	// Corrupt one nonce: verify must reject and REISSUE status 66
	// (our documented choice — the live wording is unobserved).
	mutate := func(ns *[]uint32) { (*ns)[7] ^= 0x4000 }
	pkt, err = srv.handlePacket(loginTwoDatagram(t, 42, ch, testDigestA, mutate), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	ch2 := challengeOf(t, pkt, 42)
	if ch2.Prefix == ch.Prefix {
		t.Fatal("reissue kept the old prefix — must mint fresh")
	}

	// Out-of-range and mangled key shapes get the same reissue without
	// indexing past the (possibly short) nonce table.
	short := make([]uint32, 12)
	pkt, err = srv.handlePacket(loginTwoDatagram(t, 43, ch, testDigestA, func(ns *[]uint32) { *ns = short }), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#3: %v", err)
	}
	if _, status, _, err := parseReply(pkt); err != nil || status != statusChallengeIssued {
		t.Fatalf("short nonce table: status=%d err=%v, want reissue 66", status, err)
	}
}

func TestLoginAppMalformedDatagrams(t *testing.T) {
	srv := testServer(t, nil)
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40006}
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 5)},
		{"reply flags", append([]byte{0xCC, 0x01, 0x02, 0x03, 0x00, 0x00, 0xFF}, make([]byte, 8)...)},
		{"footer zero", []byte{0x11, 0x22, 0x33, 0x44, 0x01, 0x00, 0xFF, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"unknown member", append([]byte{0x11, 0x22, 0x33, 0x44, 0x01, 0x00, 0x99, 0x00}, 0x02, 0x00)},
		{"truncated length", []byte{0x11, 0x22, 0x33, 0x44, 0x01, 0x00, 0x00, 0x02, 0x00}},
	}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}
	for _, tc := range cases {
		reply, err := srv.handlePacket(tc.pkt, from, listen)
		if tc.name == "unknown member" {
			// Unknown walk member: counted, silenced, no error.
			if err != nil || reply != nil {
				t.Fatalf("%s: err=%v reply=%v", tc.name, err, reply != nil)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: parse accepted %x", tc.name, tc.pkt)
		}
		if reply != nil {
			t.Fatalf("%s: drew a reply on a parse error", tc.name)
		}
	}
}

func TestServerMsgMintedShapes(t *testing.T) {
	tok, err := randToken2(123456789)
	if err != nil {
		t.Fatalf("token2: %v", err)
	}
	if len(tok) != 69 || tok[9] != ':' || tok[29] != ':' {
		t.Fatalf("token2 %q", tok)
	}
	if tok[:9] != "123456789" {
		t.Fatalf("token2 head %q", tok[:9])
	}
	if strings.Contains(tok[len(tok)-39:], ":") {
		t.Fatalf("token2 tail length %q", tok[30:])
	}

	sess, err := randSessionID()
	if err != nil {
		t.Fatalf("session_id: %v", err)
	}
	if len(sess) != 32 || sess[:3] != "06G" || sess[10:16] != "000000" || sess[16:22] != "41VPHF" {
		t.Fatalf("session_id %q does not match the genuine structure", sess)
	}
	for _, r := range sess {
		if !strings.ContainsRune(crockfordSession, r) {
			t.Fatalf("session_id rune %q outside the census alphabet", r)
		}
	}

	// The genuine compact field order pinned from the live servermsg
	// (§5.4 captures/game_20260920.log:413 — same name gives the same
	// 199-byte length).
	payload, err := serverMsgJSON("ExampleUser",
		"06G123456700000041VPHF1234567890",
		"123456789:1234567890123456789:123456789012345678901234567890123456789")
	if err != nil {
		t.Fatalf("servermsg: %v", err)
	}
	want := `{"isDemoAccount":false,"name":"ExampleUser",` +
		`"security_msg":"old_pass",` +
		`"session_id":"06G123456700000041VPHF1234567890",` +
		`"token2":"123456789:1234567890123456789:123456789012345678901234567890123456789"}`
	if payload != want || len(payload) != 199 {
		t.Fatalf("servermsg = %s (%d B), want %s (199 B)", payload, len(payload), want)
	}

	id := pseudoAccountID("ExampleUser")
	if id < 100000000 || id >= 1000000000 {
		t.Fatalf("pseudo id %d outside 9 digits", id)
	}
	if got := userNameOf(`{"auth_realm": "EU", "login": "ExampleUser", "session": "x", "temporary": "1", "auth_method": "basic", "publication": "0"}`); got != "ExampleUser" {
		t.Fatalf("userNameOf JSON %q", got)
	}
	if got := userNameOf("plain-name"); got != "plain-name" {
		t.Fatalf("userNameOf fallback %q", got)
	}
	// A token2 login sends the identity document with an EMPTY `login`.
	// Returning the document there is what put the whole JSON — session id
	// and token2 included — into the Account entity's `name`, which the
	// hangar renders in its top-left corner.
	tokenDoc := `{"session": "e65b", "token2": "123456789:409:140", "gameId": "wot", "login": "", "auth_method": "token2"}`
	if got := userNameOf(tokenDoc); got != "" {
		t.Fatalf("userNameOf token document = %q, want \"\" (no name in it)", got)
	}
	// The in-game name drops the login form's @domain.
	if got := displayNameOf("admin@wot.test"); got != "admin" {
		t.Fatalf("displayNameOf = %q, want admin", got)
	}
	if got := displayNameOf("ExampleUser"); got != "ExampleUser" {
		t.Fatalf("displayNameOf bare = %q", got)
	}
	if got := pseudoAccountID("ExampleUser"); got != pseudoAccountID("ExampleUser") {
		t.Fatal("pseudo id unstable for a fixed name")
	}
}

func TestLoginAppFullHandshakeLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("integration handshake needs the PoW solver")
	}
	srvAddr, srvStop := runTestServer(t)
	defer srvStop()
	priv := testRSAKey(t)

	cfg := testClientConfig(&RSAPublicKey{key: &priv.PublicKey}, true)
	cfg.Host = srvAddr.IP.String()
	cfg.Port = srvAddr.Port
	cfg.Digest = testDigestA
	cfg.Timeout = 3 * time.Second
	cfg.SolveTimeout = 15 * time.Second
	cfg.LoginAttempts = 3
	cfg.FirstReplyID = 500
	pub := &RSAPublicKey{key: &priv.PublicKey}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer conn.Close()
	cl, err := NewClient(cfg, pub, func(ctx context.Context, ch Challenge) (string, []uint32, error) {
		key, nonces, _, serr := cuckoo.SolveChallenge(ctx, ch.Prefix, ch.MaxNonce, 4)
		return key, nonces, serr
	}, conn)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sess, err := cl.Login(ctx)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !sess.ServerAddr.Equal(srvAddr.IP) || sess.ServerPort != uint16(srvAddr.Port) {
		t.Fatalf("record endpoint %v:%d, want mirrored %v:%d", sess.ServerAddr, sess.ServerPort, srvAddr.IP, srvAddr.Port)
	}
	if sess.SessionKey == 0 {
		t.Fatal("zero session key")
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(sess.ServerMsg), &msg); err != nil {
		t.Fatalf("servermsg: %v (%d B)", err, len(sess.ServerMsg))
	}
	for _, k := range []string{"isDemoAccount", "name", "security_msg", "session_id", "token2"} {
		if _, ok := msg[k]; !ok {
			t.Fatalf("servermsg key %q missing (%v)", k, msg)
		}
	}
	if msg["name"] != "ExampleUser" {
		t.Fatalf("servermsg name %v", msg["name"])
	}
}

// runTestServer binds a real socket and serves until t completes.
func runTestServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server socket: %v", err)
	}
	srv := testServer(t, conn.LocalAddr().(*net.UDPAddr))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, conn) }()
	return conn.LocalAddr().(*net.UDPAddr), func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && err != context.Canceled {
				t.Errorf("server stop: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("server did not stop")
		}
		conn.Close()
	}
}

// TestLoginAppCredentialGate proves the VerifyCredentials hook is wired
// into the login path: it sees the account name and password the client
// sent, a non-nil error refuses with status 68 and that error's text,
// and nil admits the login.
func TestLoginAppCredentialGate(t *testing.T) {
	var gotUser, gotPass string
	reject := true
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce: serverTestMaxNonce,
		Versions: testVersions(),
		VerifyCredentials: func(user, pass string) (int64, error) {
			gotUser, gotPass = user, pass
			if reject {
				return 0, errors.New(textBadPassword)
			}
			return 7, nil
		},
	}, testRSAKey(t))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40005}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	// Refusal leg: correct digest, rejected credentials → 68.
	pkt, err := srv.handlePacket(loginOneDatagram(t, 41, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 41)
	pkt, err = srv.handlePacket(loginTwoDatagram(t, 42, ch, testDigestA, nil), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	rid, status, rest, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 42 || status != statusBadPassword {
		t.Fatalf("rid=%d status=%d, want 68", rid, status)
	}
	if text, _, _ := consumePackedString(rest); text != textBadPassword {
		t.Fatalf("refusal text %q, want %q", text, textBadPassword)
	}
	if gotUser != "ExampleUser" || gotPass != "loginapp-test-password" {
		t.Fatalf("hook saw user=%q pass len=%d, want the client's own values",
			gotUser, len(gotPass))
	}

	// Acceptance leg: same credentials, hook admits → LOGGED_ON.
	reject = false
	pkt, err = srv.handlePacket(loginOneDatagram(t, 43, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#3: %v", err)
	}
	ch = challengeOf(t, pkt, 43)
	pkt, err = srv.handlePacket(loginTwoDatagram(t, 44, ch, testDigestA, nil), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#4: %v", err)
	}
	rid, status, _, err = parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 44 || status != statusLoggedOn {
		t.Fatalf("rid=%d status=%d, want 1", rid, status)
	}
}

// TestAccountIDFor proves the stored account id is authoritative: two
// accounts always map to different 9-digit ids, and id 0 (no account
// store) falls back to the name hash.
func TestAccountIDFor(t *testing.T) {
	if got := accountIDFor(1, "alice"); got != 100000001 {
		t.Fatalf("accountIDFor(1) = %d, want 100000001", got)
	}
	if got := accountIDFor(2, "alice"); got != 100000002 {
		t.Fatalf("accountIDFor(2) = %d, want 100000002", got)
	}
	// Same name, different accounts: the id must follow the account,
	// not the name.
	if accountIDFor(1, "alice") == accountIDFor(2, "alice") {
		t.Fatal("distinct accounts collided on the same id")
	}
	// No account store: the name hash is the fallback.
	if got, want := accountIDFor(0, "alice"), pseudoAccountID("alice"); got != want {
		t.Fatalf("accountIDFor(0) = %d, want the name hash %d", got, want)
	}
	// Always 9 digits, which is what the token2 head and the session
	// dict's int32 databaseID slot expect.
	for _, id := range []int64{0, 1, 42, 99999999} {
		got := accountIDFor(id, "alice")
		if got < 100000000 || got >= 1000000000 {
			t.Fatalf("accountIDFor(%d) = %d, not 9 digits", id, got)
		}
	}
}

// tokenLoginDatagram builds the client's login#2 bytes for a Steam-style
// token2 login: auth_method=token2, a token2, and an EMPTY login name —
// the document the live client sends.
func tokenLoginDatagram(t *testing.T, rid uint32, ch Challenge, digest [16]byte) []byte {
	t.Helper()
	key, nonces, err := solveChallengeFor(t, ch)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	priv := testRSAKey(t)
	cfg := testClientConfig(&RSAPublicKey{key: &priv.PublicKey}, true)
	cfg.AuthMethod = "token2"
	cfg.Login = ""
	cfg.Password = ""
	cfg.Token2 = "123456789:1234567890123456789:123456789012345678901234567890123456789"
	cfg.Digest = digest
	params, err := encryptLogOnParamsWithProvider(cfg, ProviderForConfig(cfg), &RSAPublicKey{key: &priv.PublicKey})
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	respMsg := buildChallengeResponseMsg(250*time.Millisecond, key, nonces)
	msg := buildLoginMsg(rid, [4]byte{verSub, verPatch, verMinor, verMajor}, params, true)
	return buildLoginPacket(testPrefix(t), 0, respMsg, msg)
}

// TestLoginAppTokenLogin proves a token login with no username lands on
// the mapped account without a password check. A Steam build always
// authenticates this way, so without the mapping every such login is
// refused as an unknown account, and with only the name mapped it is
// refused as a bad password (the token carries no password).
func TestLoginAppTokenLogin(t *testing.T) {
	var gotName string
	var verifyCalls int
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce:     serverTestMaxNonce,
		Versions:     testVersions(),
		TokenAccount: "admin",
		VerifyCredentials: func(user, pass string) (int64, error) {
			verifyCalls++
			return 0, errors.New(textBadPassword)
		},
		TokenLogin: func(name string) (int64, error) {
			gotName = name
			return 42, nil
		},
	}, testRSAKey(t))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40006}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 51, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 51)
	pkt, err = srv.handlePacket(tokenLoginDatagram(t, 52, ch, testDigestA), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	rid, status, _, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 52 || status != statusLoggedOn {
		t.Fatalf("rid=%d status=%d, want 1 (LOGGED_ON)", rid, status)
	}
	if gotName != "admin" {
		t.Fatalf("TokenLogin saw %q, want the mapped account", gotName)
	}
	if verifyCalls != 0 {
		t.Fatalf("VerifyCredentials called %d times, want 0 (no password to check)", verifyCalls)
	}
}

// TestLoginAppTokenLoginUnmapped proves the mapping is opt-in: with no
// TokenAccount the token login still goes through VerifyCredentials with
// the empty name, so an operator who wants the old refusal keeps it.
func TestLoginAppTokenLoginUnmapped(t *testing.T) {
	var gotUser string
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce: serverTestMaxNonce,
		Versions: testVersions(),
		VerifyCredentials: func(user, pass string) (int64, error) {
			gotUser = user
			return 0, errors.New(textBadPassword)
		},
		TokenLogin: func(name string) (int64, error) {
			t.Fatalf("TokenLogin called with no TokenAccount configured")
			return 0, nil
		},
	}, testRSAKey(t))
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40007}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 53, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 53)
	pkt, err = srv.handlePacket(tokenLoginDatagram(t, 54, ch, testDigestA), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	rid, status, _, err := parseReply(pkt)
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if rid != 54 || status != statusBadPassword {
		t.Fatalf("rid=%d status=%d, want 68", rid, status)
	}
	// A token document carries no name: `login` is empty and the credential
	// is the token. The hook must see that emptiness, not the document —
	// handing it the raw JSON is what put the session id and token2 into
	// the Account entity's `name`.
	if gotUser != "" {
		t.Fatalf("VerifyCredentials saw %q, want \"\" (the document has no login)", gotUser)
	}
}
