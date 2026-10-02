package lobby

// Offline vehicle-descr sectioning: synthetic blobs built by a
// test-local mirror of the shipped writer
// (`VehicleDescriptor.makeCompactDescr` +
// `_combineVehicleCompactDescr` — field order and flag bits pinned
// to the .pyc, values synthetic). No captures here.
import (
	"bytes"
	"testing"
)

// mkDescr mirrors the shipped writer: header, ext, components,
// flags, optdevs, enh(count+6B), emb(pos+6B/7B), skip, camo.
func mkDescr(nation uint8, typeID uint16, comp []byte, flags uint8, optdev []uint16, enh []byte, embPos uint8, emb, inscr, camo []byte, skip bool) []byte {
	head := uint8(1) | nation<<4
	out := []byte{head, uint8(typeID)}
	if typeID > 255 {
		out[0] |= 2
		out = append(out, uint8(typeID>>8))
	}
	out = append(out, comp...)
	out = append(out, flags)
	for _, d := range optdev {
		out = append(out, uint8(d), uint8(d>>8))
	}
	out = append(out, enh...)
	if flags&32 != 0 {
		out = append(out, embPos)
		out = append(out, emb...)
		out = append(out, inscr...)
	}
	if skip {
		out = append(out, 0x00)
	}
	return append(out, camo...)
}

func TestParseIntDescr(t *testing.T) {
	it, na, id, err := ParseIntDescr([]byte{0x01, 0x2A})
	if err != nil || it != 1 || na != 0 || id != 0x2A {
		t.Fatalf("basic = (%d,%d,%d,%v)", it, na, id, err)
	}
	it, na, id, err = ParseIntDescr([]byte{0x23, 0x34, 0x01})
	// lo4 reads 3 (vehicle+ext bit, exactly like the shipped
	// parseIntCompactDescr); shipped vehicle paths compare ==1, so
	// extended vehicle IDs never occur live (per-nation IDs < 255).
	if err != nil || it != 3 || na != 2 || id != 0x134 {
		t.Fatalf("ext = (%d,%d,%x,%v)", it, na, id, err)
	}
	if NationName(2) != "usa" || NationName(10) != "italy" || NationName(11) != "" {
		t.Fatal("nation table mismatch")
	}
	if _, _, _, err := ParseIntDescr([]byte{0x00}); err == nil {
		t.Fatal("short head must fail")
	}
	if _, _, _, err := ParseIntDescr([]byte{0x02}); err == nil {
		t.Fatal("truncated ext must fail")
	}
}

func TestSectionMinimal(t *testing.T) {
	comp := bytes.Repeat([]byte{0x11}, 12) // 8 + 4*1 turret
	b := mkDescr(0, 42, comp, 0, nil, nil, 0, nil, nil, nil, false)
	if len(b) != 15 {
		t.Fatalf("len=%d, want 15", len(b))
	}
	s, err := SectionCompactDescr(b, 1)
	if err != nil {
		t.Fatalf("section: %v", err)
	}
	if s.ItemType != 1 || s.Nation != 0 || s.TypeID != 42 {
		t.Fatalf("head = %+v", s)
	}
	if s.CompOff != 2 || s.CompEnd != 14 || s.Flags != 0 || s.Total != 15 || s.CamoOff != -1 {
		t.Fatalf("sections = %+v", s)
	}
}

func TestSectionFull(t *testing.T) {
	comp := bytes.Repeat([]byte{0x22}, 16) // 2 turrets
	enh := append([]byte{2}, bytes.Repeat([]byte{0x33}, 12)...)
	emb := bytes.Repeat([]byte{0x44}, 6)    // 1 emblem
	inscr := bytes.Repeat([]byte{0x55}, 14) // 2 inscriptions
	b := mkDescr(2, 0x34, comp, 0x03|16|32|64|128,
		[]uint16{0x100, 0x200}, enh, 0x31, emb, inscr, []byte{0x66, 0x67}, true)
	s, err := SectionCompactDescr(b, 2)
	if err != nil {
		t.Fatalf("section: %v", err)
	}
	if s.TypeID != 0x34 || s.Nation != 2 {
		t.Fatalf("head = %+v", s)
	}
	if len(s.OptDev) != 2 || s.OptDev[0] != 0x100 || s.OptDev[1] != 0x200 {
		t.Fatalf("optdev = %x", s.OptDev)
	}
	if s.EnhEnd-s.EnhOff != 12 || s.EmblemsEnd-s.EmblemsOff != 6 || s.InscrEnd-s.InscrOff != 14 {
		t.Fatalf("rep sections = %+v", s)
	}
	if s.CamoOff < 0 || s.Total != len(b) {
		t.Fatalf("camo/total = %+v (len %d)", s, len(b))
	}
	// Wrong turret count must NOT section cleanly.
	if _, err := SectionCompactDescr(b, 1); err == nil {
		t.Fatal("1-turret section of a 2-turret blob must fail")
	}
	// Truncations must fail at every stage (no-camo variant: the
	// camo tail is length-less by design — `compactDescr[idx:]` in
	// the shipped splitter — so camo blobs absorb truncation).
	b2 := mkDescr(2, 0x34, comp, 0x03|16|32|64, []uint16{0x100, 0x200}, enh, 0x31, emb, inscr, nil, true)
	for _, n := range []int{1, 5, 14, 20, len(b2) - 1} {
		if _, err := SectionCompactDescr(b2[:n], 2); err == nil {
			t.Fatalf("truncation at %d must fail", n)
		}
	}
}
