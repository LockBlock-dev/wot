package login

// Offline MITM round-trip: game keypair (M) encrypts, proxy re-encrypts
// to the server keypair (S); the server side recovers byte-identical
// cleartext and the proxy learns the fixture Blowfish key. Uses
// throwaway in-test keys only. Also pins the cleartext parser and the
// login#1/#2 packet extraction shapes.
import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	m, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return m, s
}

func fixtureClear() []byte {
	out := []byte{0x01}
	out = appendPackedString(out, `{"login": "t@t.t", "session": "0123456789abcdef0123456789abcdef"}`)
	out = appendPackedString(out, "pwdtoken")
	out = appendPackedString(out, "0123456789abcdef") // 16 B game key stand-in
	out = appendPackedString(out, `{"lang_id": "fr"}`)
	out = append(out, bytes.Repeat([]byte{0xAB}, 16)...) // digest
	out = append(out, 0x2A, 0x00, 0x00, 0x00)            // nonce 42
	return out
}

func TestParseLogOnParamsClear(t *testing.T) {
	p, err := parseLogOnParamsClear(fixtureClear())
	if err != nil {
		t.Fatal(err)
	}
	if p.Flags != 1 || len(p.Username) == 0 || p.EncKey != "0123456789abcdef" {
		t.Fatalf("bad parse: %+v", p)
	}
	if p.ClientCtx != `{"lang_id": "fr"}` || p.Nonce != 42 {
		t.Fatalf("bad ctx/nonce: %+v", p)
	}
	if _, err := parseLogOnParamsClear(fixtureClear()[:10]); err == nil {
		t.Fatal("truncated cleartext must fail")
	}
}

func TestMitmRoundTrip(t *testing.T) {
	m, s := testKeys(t)
	clear := fixtureClear()
	gameSide, err := encryptChunks(clear, &m.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(gameSide)%256 != 0 {
		t.Fatalf("cipher misaligned: %d", len(gameSide))
	}
	reenc, params, err := MitmLoginParams(gameSide, m, &s.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if params.EncKey != "0123456789abcdef" {
		t.Fatalf("wrong key extracted: %q", params.EncKey)
	}
	if len(reenc) != len(gameSide) {
		t.Fatalf("length drift %d -> %d", len(gameSide), len(reenc))
	}
	back, err := decryptChunks(reenc, s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, clear) {
		t.Fatal("server-side cleartext differs")
	}
	// Wrong private key must fail (fail-open upstream).
	if _, _, err := MitmLoginParams(gameSide, s, &m.PublicKey); err == nil {
		t.Fatal("wrong MITM key must fail")
	}
}

func encLoginPacket(t *testing.T, mPriv *rsa.PrivateKey, withCR bool) []byte {
	t.Helper()
	clear := fixtureClear()
	gameSide, err := encryptChunks(clear, &mPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := buildLoginMsg(77, [4]byte{5, 0, 1, 17}, gameSide, true)
	if !withCR {
		return buildLoginPacket([4]byte{1, 2, 3, 4}, 0, msg)
	}
	cr := buildChallengeResponseMsg(0, "k", []uint32{1, 2, 3})
	return buildLoginPacket([4]byte{1, 2, 3, 4}, 0, cr, msg)
}

func TestMitmPacketShapes(t *testing.T) {
	m, s := testKeys(t)
	for _, withCR := range []bool{false, true} {
		pkt := encLoginPacket(t, m, withCR)
		out, key, err := MitmPacket(pkt, m, &s.PublicKey)
		if err != nil {
			t.Fatalf("CR=%v: %v", withCR, err)
		}
		if key != "0123456789abcdef" {
			t.Fatalf("CR=%v: wrong key %q", withCR, key)
		}
		if len(out) != len(pkt) {
			t.Fatalf("CR=%v: length drift %d -> %d", withCR, len(pkt), len(out))
		}
		// The rebuilt packet must still parse (server side).
		params, _, _, encrypted, err := extractLoginParams(out)
		if err != nil || !encrypted {
			t.Fatalf("CR=%v: rebuilt packet unparsable: %v", withCR, err)
		}
		back, err := decryptChunks(params, s)
		if err != nil || !bytes.Equal(back, fixtureClear()) {
			t.Fatalf("CR=%v: server-side mismatch", withCR)
		}
	}
	// Non-login datagram forwards untouched (error, no rewrite).
	if _, _, err := MitmPacket([]byte{1, 2, 3}, m, &s.PublicKey); err == nil {
		t.Fatal("short datagram must fail")
	}
}
