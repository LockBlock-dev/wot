// Offline token2-shape tests (synthetic fixtures only, no captures).
package wgcs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstanceIID(t *testing.T) {
	if InstanceIID != 0x1600020001247C {
		t.Fatalf("IID=%x", InstanceIID)
	}
}

func TestFindToken2(t *testing.T) {
	pad := []byte("random-binary\x00\x01noise-callback")
	tok := "123456789:1234567890123456789:123456789012345678901234567890123456789"
	buf := append(append(append([]byte(nil), pad...), tok...), 0x00)
	got, ok := FindToken2(buf)
	if !ok || got != tok {
		t.Fatalf("ok=%v gotlen=%d", ok, len(got))
	}
	if _, ok := FindToken2([]byte("no-colons-here-at-all-just-noise-bytes-000")); ok {
		t.Fatal("noise must not match")
	}
	if _, ok := FindToken2([]byte("1:2:3")); ok {
		t.Fatal("short must not match")
	}
	// UTF-16LE inline form (broker WCHAR structs, IDA sub_180050190).
	var wide []byte
	wide = append(wide, 0xAA, 0xBB, 0xCC) // leading noise incl. odd byte
	for i := 0; i < len(tok); i++ {
		wide = append(wide, tok[i], 0x00)
	}
	wide = append(wide, 0x00, 0x00) // NUL terminator
	got, ok = FindToken2(wide)
	if !ok || got != tok {
		t.Fatalf("wide ok=%v gotlen=%d", ok, len(got))
	}
	// Wide noise (no colons) must not match.
	wnoise := []byte{'a', 0, 'b', 0, 'c', 0}
	if _, ok := FindToken2(wnoise); ok {
		t.Fatal("wide noise must not match")
	}
}

func TestLoginInfoSize(t *testing.T) {
	// IDA floor: struct spans +776 DWORD; callers pass >= 780.
	if LoginInfoSize < 780 || RememberMeBuf < 2048 || RememberMeStruct < 264 {
		t.Fatalf("sizes=%d/%d/%d", LoginInfoSize, RememberMeBuf, RememberMeStruct)
	}
}

func TestStoreToken2RoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t2.hex")
	tok := "123456789:1234567890123456789:123456789012345678901234567890123456789"
	if err := StoreToken2(p, tok); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil || len(raw) == 0 {
		t.Fatalf("keyfile: %v", err)
	}
	if id := TokenID(tok); id == "" || id == tok {
		t.Fatal("bad token id")
	}
	if err := StoreToken2(p, ""); err == nil {
		t.Fatal("empty must fail")
	}
}

func TestStubOutsideWindows(t *testing.T) {
	if _, err := Load("x.dll"); err == nil {
		t.Fatal("non-windows Load must fail")
	}
}
