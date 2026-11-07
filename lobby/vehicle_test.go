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
	// lo4 reads 3 = vehicle(1) | EXTENDED_VEHICLE_TYPE_ID_FLAG(2), and
	// `getTypeOfCompactDescr` subtracts the flag back off for the simple
	// item types — so the type is 1, not 3. 111 of the 1256 ownable
	// vehicles have a type id above 255 and take this path.
	if err != nil || it != 1 || na != 2 || id != 0x134 {
		t.Fatalf("ext = (%d,%d,%x,%v)", it, na, id, err)
	}
	// A turret (type 3) with the ext flag reads back as 3, not 1.
	if it, _, _, err := ParseIntDescr([]byte{0x45, 0x01, 0x00}); err != nil || it != 3 {
		t.Fatalf("ext turret = (%d,%v), want 3", it, err)
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

// TestVehicleGunKey pins the (turret, gun) pair the ammunition layout is
// keyed by: the component block is six little-endian u16s after the type
// head, and the client indexes `shellsLayout` by the third and fourth.
func TestVehicleGunKey(t *testing.T) {
	// A Panhard EBR 105's inventory descriptor, read out of the live client:
	// `41 4A 9D 00 65 00 CD 00 22 00 82 00 63 00 00`. Its own
	// `descriptor.chassis/turret/gun.compactDescr` are 40258 / 33347 / 25412,
	// which decode to ids 157 / 130 / 99 — bytes [2..3], [10..11] and
	// [12..13]. So the component block is
	// `chassis, engine, fuelTank, radio, turret, gun`: turret and gun are the
	// LAST two u16s.
	//
	// The key is the pair of COMPACT DESCRIPTORS, not the ids:
	// `vehicle_equipment.__parseLayout` builds
	// `shellsLayoutKey = (vehDescr.turret.compactDescr, vehDescr.gun.compactDescr)`.
	// `makeIntCompactDescrByID` is `(id << 8) + itemType + (nation << 4)`,
	// with `vehicleTurret` 3, `vehicleGun` 4 and this vehicle's nation 4
	// (france), so 130 -> 33347 and 99 -> 25412.
	cd := []byte{65, 74, 157, 0, 101, 0, 205, 0, 34, 0, 130, 0, 99, 0, 0}
	turret, gun, ok := VehicleGunKey(cd)
	if !ok {
		t.Fatal("VehicleGunKey failed")
	}
	if turret != 33347 || gun != 25412 {
		t.Fatalf("turret = %d, gun = %d, want 33347/25412 (the live client's own key)", turret, gun)
	}
	if _, _, ok := VehicleGunKey([]byte{1, 10}); ok {
		t.Fatal("a truncated descriptor must not resolve")
	}
}
