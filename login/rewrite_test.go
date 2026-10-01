package login

// Offline stage-2 redirect rewrite: fixture channel cleartext carrying
// the [44][ip][port][00 00 01] core, encrypted, rewritten, verified.
import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func redirectFixture() []byte {
	// [13][3f]-style head + 0x44 core + trailer, then filler.
	clear := []byte{0x13, 0x3f, 0x44}
	clear = append(clear, 92, 223, 20, 215) // EU2 manager
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], 32956)
	clear = append(clear, tmp[:]...)
	clear = append(clear, 0x00, 0x00, 0x01)
	clear = append(clear, bytes.Repeat([]byte{0x07}, 20)...)
	return clear
}

func TestRewriteRedirect(t *testing.T) {
	const key = "0123456789abcdef"
	body, err := encryptBlowfish(key, redirectFixture())
	if err != nil {
		t.Fatal(err)
	}
	out, target, err := RewriteRedirect(body, key, net.ParseIP("127.0.0.1"), 32901)
	if err != nil {
		t.Fatal(err)
	}
	if target.String() != "92.223.20.215:32956" {
		t.Fatalf("wrong target %s", target)
	}
	if len(out) != len(body) {
		t.Fatalf("length drift %d -> %d", len(body), len(out))
	}
	clear, err := decryptBlowfish(key, out)
	if err != nil {
		t.Fatal(err)
	}
	back, _, ok := parseRedirectAt(clear)
	if !ok {
		t.Fatal("rewritten cleartext lost its redirect")
	}
	if back.String() != "127.0.0.1:32901" {
		t.Fatalf("wrong rewritten endpoint %s", back)
	}
	// Trailer + head preserved around the 0x44 core at index 2.
	if clear[2] != 0x44 || clear[9] != 0 || clear[10] != 0 || clear[11] != 1 || clear[0] != 0x13 {
		t.Fatalf("core damaged: %x", clear[:12])
	}
	// No redirect -> error, forward untouched upstream.
	plain, err := encryptBlowfish(key, bytes.Repeat([]byte{0x09}, 24))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RewriteRedirect(plain, key, net.ParseIP("127.0.0.1"), 32901); err == nil {
		t.Fatal("redirect-free body must fail")
	}
	// Wrong key -> error.
	if _, _, err := RewriteRedirect(body, "fedcba9876543210", net.ParseIP("127.0.0.1"), 32901); err == nil {
		t.Fatal("wrong key must fail")
	}
	// Misaligned body -> error.
	if _, _, err := RewriteRedirect(body[:len(body)-1], key, net.ParseIP("127.0.0.1"), 32901); err == nil {
		t.Fatal("misaligned body must fail")
	}
}
