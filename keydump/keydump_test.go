package keydump

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestParsePattern(t *testing.T) {
	needle, mask, err := ParsePattern("48 89 ?? E9")
	if err != nil {
		t.Fatal(err)
	}
	if len(needle) != 4 || mask[2] != 0x00 || mask[0] != 0xFF {
		t.Fatalf("bad parse: %x %x", needle, mask)
	}
	if _, _, err := ParsePattern(""); err == nil {
		t.Fatal("empty pattern must fail")
	}
	if _, _, err := ParsePattern("ZZ"); err == nil {
		t.Fatal("bad token must fail")
	}
}

func TestScan(t *testing.T) {
	hay := []byte{0x00, 0x48, 0x89, 0xAA, 0xE9, 0x48, 0x89, 0x5C, 0xE9}
	needle, mask, err := ParsePattern("48 89 ?? E9")
	if err != nil {
		t.Fatal(err)
	}
	got := Scan(hay, needle, mask)
	if len(got) != 2 || got[0] != 1 || got[1] != 5 {
		t.Fatalf("got %v", got)
	}
	// All-wildcard needle is degenerate: refuse.
	n2 := []byte{0, 0}
	m2 := []byte{0, 0}
	if out := Scan(hay, n2, m2); out != nil {
		t.Fatalf("all-wildcard must refuse, got %v", out)
	}
}

func TestDefaultPatternMatchesIDA(t *testing.T) {
	// Ground truth: 128 B at IDA sub_140E6E210 (EU 2.4.0.0); the pattern
	// must hit exactly once at offset 0 (the 34 B prologue alone hit 3
	// functions live on Sep 27).
	dump := "48895c240848896c2410488974241857415641574883ec20450fb6f84c8bf2488be94180f8ff7505440fb67910488b02498bceba01000000ff5008488d5518498bce448838e8667dffff488bc8488d5538e85a7dffff488bc8488d5558e84e7dffff488bc8488d5578e8427dffff41f6c701740f488d959c000000498bce"
	raw, err := hexDecode(t, dump)
	if err != nil {
		t.Fatal(err)
	}
	needle, mask, err := ParsePattern(DefaultPattern)
	if err != nil {
		t.Fatal(err)
	}
	got := Scan(raw, needle, mask)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("want single hit at 0, got %v", got)
	}
}

func hexDecode(t *testing.T, s string) ([]byte, error) {
	t.Helper()
	b := make([]byte, hex.DecodedLen(len(s)))
	if _, err := hex.Decode(b, []byte(s)); err != nil {
		return nil, err
	}
	return b, nil
}

func TestDefaultPatternParses(t *testing.T) {
	needle, mask, err := ParsePattern(DefaultPattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(needle) != 126 {
		t.Fatalf("want 126 signature bytes, got %d", len(needle))
	}
	lit, wild := 0, 0
	for _, m := range mask {
		if m == 0xFF {
			lit++
		} else {
			wild++
		}
	}
	// 110 literal (prologue + call/lea skeleton incl. the +58h key slot),
	// 16 wild (four E8 rel32 targets, which drift per build).
	if lit != 110 || wild != 16 {
		t.Fatalf("want 110 literal + 16 wild, got %d + %d", lit, wild)
	}
}

type fakeMem struct {
	base uint64
	data []byte
}

func (f fakeMem) Read(addr uint64, n int) ([]byte, error) {
	if addr < f.base || addr+uint64(n) > f.base+uint64(len(f.data)) {
		return nil, errors.New("out of range")
	}
	return append([]byte(nil), f.data[addr-f.base:addr-f.base+uint64(n)]...), nil
}

func TestReadKeyHeap(t *testing.T) {
	const obj = 0x1000
	key := []byte{0x7A, 0x54, 0x6C, 0x3F, 0x7E, 0xDE, 0x22, 0x32,
		0xF1, 0xEC, 0x77, 0x20, 0xF6, 0x38, 0x45, 0xAB}
	mem := make([]byte, 0x1010)
	base := uint64(0x1000)
	// String object at obj+0x58: [ptr=0x2000][len=16][cap].
	binary.LittleEndian.PutUint64(mem[0x58:], 0x2000)
	binary.LittleEndian.PutUint64(mem[0x58+16:], 16)
	copy(mem[0x1000:], key)
	got, _, strobj, err := ReadKey(fakeMem{base, mem}, obj)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) || len(strobj) != 32 {
		t.Fatalf("got %x strobj %dB", got, len(strobj))
	}
}

func TestReadKeySSO(t *testing.T) {
	const obj = 0x1000
	mem := make([]byte, 0x100)
	copy(mem[0x58:], []byte("shortkey!"))
	binary.LittleEndian.PutUint64(mem[0x58+16:], 9)
	got, _, _, err := ReadKey(fakeMem{0x1000, mem}, obj)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "shortkey!" {
		t.Fatalf("got %q", got)
	}
}

func TestReadKeyBadLen(t *testing.T) {
	mem := make([]byte, 0x100)
	binary.LittleEndian.PutUint64(mem[0x58+16:], 200)
	if _, _, _, err := ReadKey(fakeMem{0x1000, mem}, 0x1000); err == nil {
		t.Fatal("garbage length must fail")
	}
}

func TestKeyfileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/wotkeys.txt"
	k1 := bytes16()
	if err := AppendKey(p, 0x1234, k1, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	k2 := append(append([]byte(nil), k1...), 0xFF)
	if err := AppendKey(p, 0x5678, k2, nil); err != nil {
		t.Fatal(err)
	}
	got, err := LatestKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(k2) {
		t.Fatalf("want latest, got %x", got)
	}
}

func TestLatestKeysOrder(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/wotkeys.txt"
	var want [][]byte
	for i := 0; i < 5; i++ {
		k := append(bytes16(), byte(i))
		if err := AppendKey(p, uint64(i), k, nil); err != nil {
			t.Fatal(err)
		}
		want = append(want, k)
	}
	got, err := LatestKeys(p, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	// Newest first: want[4], want[3], want[2].
	for i := 0; i < 3; i++ {
		if string(got[i]) != string(want[4-i]) {
			t.Fatalf("slot %d mismatch", i)
		}
	}
}

func bytes16() []byte {
	return []byte{0xDE, 0x72, 0xBE, 0xA0, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
}
