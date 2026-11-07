package lobby

import (
	"encoding/binary"
	"testing"
)

// parseTankmanCompDescr mirrors `tankmen.TankmanDescr.__initFromCompactDescr`
// for the fields a generated descriptor carries, so the test can assert the
// bytes round-trip the way the client reads them.
type parsedTankman struct {
	nation, roleIdx     uint8
	isPremium, isFemale bool
	extended            bool
	vehicleTypeID       uint16
	skillsEfficiencyXP  int
	numSkills           int
	lastSkillLevel      uint8
	firstName, lastName uint16
	iconID              uint16
	freeXP              uint32
	dossierCompactDescr []byte
}

func parseTankmanCompDescr(t *testing.T, cd []byte) parsedTankman {
	t.Helper()
	if len(cd) < 15 {
		t.Fatalf("compact descriptor too short: %d B", len(cd))
	}
	var p parsedTankman
	if cd[0]&0x0f != itemTankman {
		t.Fatalf("header %#x is not a tankman", cd[0])
	}
	p.nation = cd[0] >> 4 & 15
	flags := cd[1]
	p.extended = flags&128 != 0
	p.isPremium = flags&64 != 0
	p.isFemale = flags&32 != 0
	if flags&16 != 0 || flags&8 != 0 {
		t.Fatalf("generated descriptors carry no skills, flags %#x", flags)
	}
	off := 2
	if p.extended {
		p.vehicleTypeID = binary.BigEndian.Uint16(cd[off:])
		off += 2
	} else {
		p.vehicleTypeID = uint16(cd[off])
		off++
	}
	p.roleIdx = cd[off] >> 1
	p.skillsEfficiencyXP = int(cd[off]&1)<<16 | int(cd[off+1])<<8 | int(cd[off+2])
	off += 3
	p.numSkills = int(cd[off])
	p.lastSkillLevel = cd[off+1]
	off += 2
	if p.numSkills != 0 || p.lastSkillLevel != 0 {
		t.Fatalf("numSkills=%d lastSkillLevel=%d, want 0/0", p.numSkills, p.lastSkillLevel)
	}
	p.firstName = binary.BigEndian.Uint16(cd[off:])
	p.lastName = binary.BigEndian.Uint16(cd[off+2:])
	p.iconID = binary.BigEndian.Uint16(cd[off+4:])
	p.freeXP = binary.BigEndian.Uint32(cd[off+6:])
	off += 10
	p.dossierCompactDescr = cd[off:]
	return p
}

// TestTankmanCompDescr pins the descriptor layout against
// `tankmen.generateCompactDescr` for a skill-less crew member.
func TestTankmanCompDescr(t *testing.T) {
	cd := TankmanCompDescr(1, true, false, 7, 9, 3, 33, "gunner")
	if cd == nil {
		t.Fatal("nil descriptor")
	}
	p := parseTankmanCompDescr(t, cd)
	if p.nation != 1 || !p.isPremium || p.isFemale {
		t.Fatalf("passport = nation %d premium %t female %t", p.nation, p.isPremium, p.isFemale)
	}
	if p.extended {
		t.Fatal("typeID 33 fits in one byte, want the short form")
	}
	if p.vehicleTypeID != 33 {
		t.Fatalf("vehicleTypeID = %d, want 33", p.vehicleTypeID)
	}
	if p.roleIdx != tankmanRoleIndex["gunner"] {
		t.Fatalf("role index = %d, want %d", p.roleIdx, tankmanRoleIndex["gunner"])
	}
	if p.skillsEfficiencyXP != tankmanSkillsEfficiencyXP {
		t.Fatalf("skillsEfficiencyXP = %d, want %d", p.skillsEfficiencyXP, tankmanSkillsEfficiencyXP)
	}
	if p.firstName != 7 || p.lastName != 9 || p.iconID != 3 {
		t.Fatalf("name ids = %d/%d/%d, want 7/9/3", p.firstName, p.lastName, p.iconID)
	}
	if p.freeXP != 0 || len(p.dossierCompactDescr) != 0 {
		t.Fatalf("freeXP = %d, dossier %d B, want 0/empty", p.freeXP, len(p.dossierCompactDescr))
	}
}

// TestTankmanCompDescrExtended pins the two-byte vehicle type form: the
// client only reads it when the flag is set, so a typeID above 255 must set
// it or the descriptor parses as a different vehicle.
func TestTankmanCompDescrExtended(t *testing.T) {
	cd := TankmanCompDescr(4, false, true, 1, 2, 3, 1234, "commander")
	p := parseTankmanCompDescr(t, cd)
	if !p.extended {
		t.Fatal("typeID 1234 needs the extended form")
	}
	if p.vehicleTypeID != 1234 {
		t.Fatalf("vehicleTypeID = %d, want 1234", p.vehicleTypeID)
	}
	if !p.isFemale || p.isPremium {
		t.Fatalf("premium %t female %t, want false/true", p.isPremium, p.isFemale)
	}
}

// TestTankmanCompDescrUnknownRole pins that an unknown role is refused
// rather than silently written as commander.
func TestTankmanCompDescrUnknownRole(t *testing.T) {
	if cd := TankmanCompDescr(0, false, false, 1, 1, 1, 1, "pilot"); cd != nil {
		t.Fatalf("unknown role produced % x", cd)
	}
}

// TestTankmanInventory pins the barracks: every nation, every role, dense
// instance ids, and every descriptor parseable.
func TestTankmanInventory(t *testing.T) {
	inv := TankmanInventory(func(nation uint8) (uint16, bool) {
		return uint16(100 + nation), true
	})
	if len(inv) == 0 {
		t.Fatal("empty barracks")
	}
	if len(inv) != tankmanGroupsPerNation*len(TankmanRoles)*len(nationsWithGroups()) {
		t.Fatalf("%d tankmen, want %d", len(inv),
			tankmanGroupsPerNation*len(TankmanRoles)*len(nationsWithGroups()))
	}
	roles := map[uint8]int{}
	for id := int64(1); id <= int64(len(inv)); id++ {
		cd, ok := inv[id].([]byte)
		if !ok {
			t.Fatalf("instance %d is %T, want []byte", id, inv[id])
		}
		p := parseTankmanCompDescr(t, cd)
		roles[p.roleIdx]++
	}
	for _, role := range TankmanRoles {
		if roles[tankmanRoleIndex[role]] == 0 {
			t.Fatalf("no %s in the barracks", role)
		}
	}
}

// nationsWithGroups is the set of nations AllTankmanGroups covers.
func nationsWithGroups() map[uint8]bool {
	out := map[uint8]bool{}
	for _, g := range AllTankmanGroups {
		out[g.Nation] = true
	}
	return out
}

// TestTankmanGroups pins the generated name pools: every nation present, and
// every pool carrying at least one usable id in each table.
func TestTankmanGroups(t *testing.T) {
	if len(AllTankmanGroups) < 100 {
		t.Fatalf("%d name pools, want the full client list", len(AllTankmanGroups))
	}
	seen := map[uint8]bool{}
	for _, g := range AllTankmanGroups {
		seen[g.Nation] = true
		if len(g.FirstIDs) == 0 || len(g.LastIDs) == 0 || len(g.IconIDs) == 0 {
			t.Fatalf("nation %d pool has an empty table: %+v", g.Nation, g)
		}
	}
	if len(seen) != 11 {
		t.Fatalf("%d nations with name pools, want 11", len(seen))
	}
}
