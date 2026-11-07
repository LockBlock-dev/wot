package lobby

import (
	"encoding/binary"
	"testing"
)

// unitReader walks a packed unit blob the way the client's
// `UnitBase.unpack` does, so the test asserts the layout rather than a
// byte dump that would have to be rewritten on every change.
type unitReader struct {
	t   *testing.T
	b   []byte
	off int
}

func (r *unitReader) u8() uint8 {
	r.t.Helper()
	if r.off+1 > len(r.b) {
		r.t.Fatalf("read u8 past end at %d", r.off)
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *unitReader) u16() uint16 {
	r.t.Helper()
	if r.off+2 > len(r.b) {
		r.t.Fatalf("read u16 past end at %d", r.off)
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *unitReader) u32() uint32 {
	r.t.Helper()
	if r.off+4 > len(r.b) {
		r.t.Fatalf("read u32 past end at %d", r.off)
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *unitReader) i32() int32 { return int32(r.u32()) }

func (r *unitReader) i64() int64 {
	r.t.Helper()
	if r.off+8 > len(r.b) {
		r.t.Fatalf("read i64 past end at %d", r.off)
	}
	v := int64(binary.LittleEndian.Uint64(r.b[r.off:]))
	r.off += 8
	return v
}

func (r *unitReader) pascal() string {
	r.t.Helper()
	n := int(r.u16())
	if r.off+n > len(r.b) {
		r.t.Fatalf("pascal %d past end at %d", n, r.off)
	}
	s := string(r.b[r.off : r.off+n])
	r.off += n
	return s
}

// TestPackUnitLayout checks the packed squad against the client's own
// format strings (common/UnitBase.pyc `_IDS`, `_HEADER`,
// `_SLOT_PLAYERS`, `_PLAYER_DATA`).
func TestPackUnitLayout(t *testing.T) {
	u := NewSquadUnit(7)
	u.AddPlayer(UnitPlayer{
		AccountDBID: 100000002,
		AccountID:   100000002,
		NickName:    "admin",
		ClanDBID:    8760142,
		ClanAbbrev:  "ADMIN",
		Role:        UnitRoleCreator,
		TimeJoin:    1700000000,
	})
	u.SetReady(100000002, true)

	blob := PackUnit(u)
	r := &unitReader{t: t, b: blob}

	// _IDS '<IBB'
	if got := r.u32(); got != RosterTypeSquad {
		t.Fatalf("rosterType = %d, want %d", got, RosterTypeSquad)
	}
	if got := r.u8(); got != ExtrasSquad {
		t.Fatalf("extrasHandler = %d, want %d", got, ExtrasSquad)
	}
	if got := r.u8(); got != PrebattleSquad {
		t.Fatalf("prebattleType = %d, want %d", got, PrebattleSquad)
	}

	// Roster: three slots, each (idx, classMask, nationMask, levelMask).
	if got := r.u8(); got != 3 {
		t.Fatalf("slot count = %d, want 3", got)
	}
	for i := 0; i < 3; i++ {
		if got := r.u8(); got != uint8(i) {
			t.Fatalf("slot %d index = %d", i, got)
		}
		if got := r.u8(); got != 0 {
			t.Fatalf("slot %d classMask = %d", i, got)
		}
		if got := r.u16(); got != 0 {
			t.Fatalf("slot %d nationMask = %d", i, got)
		}
		if got := r.u8(); got != 0x0a {
			t.Fatalf("slot %d levelMask = %#02x, want 0x0a", i, got)
		}
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("limits mask = %d, want 0", got)
	}

	// _HEADER '<HHHHHHHHBiiiiii'
	if got := r.u16(); got != 1 {
		t.Fatalf("members len = %d, want 1", got)
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("vehicles len = %d, want 0", got)
	}
	if got := r.u16(); got != 1 {
		t.Fatalf("players len = %d, want 1", got)
	}
	for i := 0; i < 3; i++ {
		if got := r.u16(); got != 0 {
			t.Fatalf("header field %d = %d, want 0", i, got)
		}
	}
	if got := r.u16(); got != 1 {
		t.Fatalf("readyMask = %d, want 1", got)
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("flags = %d, want 0", got)
	}
	if got := r.u8(); got != 0 {
		t.Fatalf("closedSlotMask = %d, want 0", got)
	}
	for i := 0; i < 6; i++ {
		if got := r.i32(); got != 0 {
			t.Fatalf("header i32 %d = %d, want 0", i, got)
		}
	}

	// _SLOT_PLAYERS '<Bq'
	if got := r.u8(); got != 0 {
		t.Fatalf("member slot = %d, want 0", got)
	}
	if got := r.i64(); got != 100000002 {
		t.Fatalf("member dbid = %d", got)
	}

	// _PLAYER_DATA '<qiIHBHHHq?'
	if got := r.i64(); got != 100000002 {
		t.Fatalf("player dbid = %d", got)
	}
	if got := r.i32(); got != 100000002 {
		t.Fatalf("player accountID = %d", got)
	}
	if got := r.u32(); got != 1700000000 {
		t.Fatalf("player timeJoin = %d", got)
	}
	if got := r.u16(); got != UnitRoleCreator {
		t.Fatalf("player role = %d, want %d", got, UnitRoleCreator)
	}
	if got := r.u8(); got != 0 {
		t.Fatalf("player igrType = %d", got)
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("player rating = %d", got)
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("player wtr = %d", got)
	}
	if got := r.u16(); got != 0 {
		t.Fatalf("player periphery = %d", got)
	}
	if got := r.i64(); got != 8760142 {
		t.Fatalf("player clanDBID = %d", got)
	}
	if got := r.u8(); got != 0 {
		t.Fatalf("player isPremium = %d", got)
	}
	if got := r.pascal(); got != "admin" {
		t.Fatalf("player nickname = %q", got)
	}
	if got := r.pascal(); got != "ADMIN" {
		t.Fatalf("player clanAbbrev = %q", got)
	}
	// Badges: two zero length bytes.
	if got := r.u8(); got != 0 {
		t.Fatalf("badge ids len = %d", got)
	}
	if got := r.u8(); got != 0 {
		t.Fatalf("badge extra len = %d", got)
	}
	// Extra data: a pascal-framed pickled empty dict.
	if got := r.pascal(); got != string(emptyPickleDict) {
		t.Fatalf("extra data = % x", got)
	}
	// The trailing comment.
	if got := r.pascal(); got != "" {
		t.Fatalf("comment = %q", got)
	}
	if r.off != len(blob) {
		t.Fatalf("%d bytes left unread of %d", len(blob)-r.off, len(blob))
	}
}

// TestUnitSlotsAndReady checks the slot bookkeeping the manager relies
// on: a player takes the first free slot, leaving frees it, and the
// ready mask follows the slot.
func TestUnitSlotsAndReady(t *testing.T) {
	u := NewSquadUnit(1)
	slot, ok := u.AddPlayer(UnitPlayer{AccountDBID: 11})
	if !ok || slot != 0 {
		t.Fatalf("first player slot = %d/%v, want 0/true", slot, ok)
	}
	slot, ok = u.AddPlayer(UnitPlayer{AccountDBID: 22})
	if !ok || slot != 1 {
		t.Fatalf("second player slot = %d/%v, want 1/true", slot, ok)
	}
	u.SetReady(22, true)
	if u.ReadyMask != 1<<1 {
		t.Fatalf("readyMask = %#x, want 0x2", u.ReadyMask)
	}
	if !u.RemovePlayer(11) {
		t.Fatal("RemovePlayer(11) = false")
	}
	if u.SlotOf(11) != -1 {
		t.Fatal("slot 11 still occupied")
	}
	slot, ok = u.AddPlayer(UnitPlayer{AccountDBID: 33})
	if !ok || slot != 0 {
		t.Fatalf("reused slot = %d/%v, want 0/true", slot, ok)
	}
	// A full squad refuses the fourth player.
	u.AddPlayer(UnitPlayer{AccountDBID: 44})
	if _, ok := u.AddPlayer(UnitPlayer{AccountDBID: 55}); ok {
		t.Fatal("a full squad accepted a fourth player")
	}
}

// TestPackOps checks the op framing: opcode then the client's argument
// format.
func TestPackOps(t *testing.T) {
	ops := PackOps(
		OpReadyMask(0x0003),
		OpSetComment("hi"),
		OpRemovePlayer(100000002),
	)
	want := []byte{
		UnitOpReadyMask, 0x03, 0x00,
		UnitOpSetComment, 0x02, 0x00, 'h', 'i',
		UnitOpRemovePlayer, 0x02, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
	}
	if len(ops) != len(want) {
		t.Fatalf("ops = % x (%d B), want % x (%d B)", ops, len(ops), want, len(want))
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("ops[%d] = %#02x, want %#02x (% x)", i, ops[i], want[i], ops)
		}
	}
}
