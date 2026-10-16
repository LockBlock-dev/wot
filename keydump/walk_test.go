package keydump

import (
	"encoding/binary"
	"os"
	"testing"
)

type mapReader struct{ m map[uint64]byte }

func (r mapReader) Read(addr uint64, n int) ([]byte, error) {
	out := make([]byte, n)
	for i := range out {
		b, ok := r.m[addr+uint64(i)]
		if !ok {
			return nil, errTestOOB
		}
		out[i] = b
	}
	return out, nil
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errTestOOB = testErr("oob")

func putU64(m map[uint64]byte, addr uint64, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	for i := range b {
		m[addr+uint64(i)] = b[i]
	}
}

func TestWalkPatternMatchesFilter(t *testing.T) {
	needle, mask, err := ParsePattern(WalkDefaultPattern)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../World_of_Tanks_EU/2.4.1.0/win64/WorldOfTanks.exe")
	if err != nil {
		t.Skip("2.4.1.0 exe not vendored")
	}
	// Entry filter prologue file offset (RVA 0x2CAA130).
	off := 0x2CA9530
	if off+len(needle) > len(raw) {
		t.Fatal("short read")
	}
	for i := range needle {
		if mask[i] != 0 && raw[off+i] != needle[i] {
			t.Fatalf("pattern byte %d: want %02X got %02X", i, needle[i], raw[off+i])
		}
	}
	if got := Scan(raw, needle, mask); len(got) != 1 || got[0] != off {
		t.Fatalf("pattern hits %v, want [%x]", got, off)
	}
}

func TestReadStdStringSSO(t *testing.T) {
	m := map[uint64]byte{}
	base := uint64(0x1000)
	copy := func(addr uint64, b []byte) {
		for i, v := range b {
			m[addr+uint64(i)] = v
		}
	}
	for i := 0; i < 32; i++ {
		m[base+uint64(i)] = 0
	}
	copy(base, []byte("Avatar"))
	putU64(m, base+16, 6)
	putU64(m, base+24, 6) // cap <= 15: inline
	s, err := readStdString(mapReader{m}, base)
	if err != nil || s != "Avatar" {
		t.Fatalf("SSO: %q %v", s, err)
	}
}

func TestReadStdStringHeap(t *testing.T) {
	m := map[uint64]byte{}
	base, heap := uint64(0x1000), uint64(0x9000)
	for i := 0; i < 32; i++ {
		m[base+uint64(i)] = 0
	}
	name := "RespawnFrameworkVehicleComponent"
	for i := range []byte(name) {
		m[heap+uint64(i)] = name[i]
	}
	putU64(m, base, heap)
	putU64(m, base+16, uint64(len(name)))
	putU64(m, base+24, uint64(len(name)))
	s, err := readStdString(mapReader{m}, base)
	if err != nil || s != name {
		t.Fatalf("heap: %q %v", s, err)
	}
}

func TestReadStdStringRejectsGarbage(t *testing.T) {
	m := map[uint64]byte{}
	base := uint64(0x1000)
	putU64(m, base+16, 1<<20)
	if _, err := readStdString(mapReader{m}, base); err == nil {
		t.Fatal("expected rejection of absurd length")
	}
}

func TestWalkConfigDefaults(t *testing.T) {
	c := WalkConfig{}
	if err := c.withWalkDefaults(); err != nil {
		t.Fatal(err)
	}
	if c.ExeName != "WorldOfTanks.exe" || c.MaxEntries != 800 || len(c.Needle) == 0 {
		t.Fatalf("bad defaults: %+v", c)
	}
}
