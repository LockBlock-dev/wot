package server

import (
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// player is a test squad member.
func player(dbid int64, name string) lobby.UnitPlayer {
	return lobby.UnitPlayer{AccountDBID: dbid, AccountID: dbid, NickName: name}
}

// TestUnitCreateJoinLeave walks the squad lifecycle the client drives:
// create, a second account joins, the creator leaves, the squad survives
// with the remaining member, then the last one leaves and it is gone.
func TestUnitCreateJoinLeave(t *testing.T) {
	m := NewUnitManager()

	id, packed, ok := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)
	if !ok || id == 0 || len(packed) == 0 {
		t.Fatalf("Create = %d/%d B/%v", id, len(packed), ok)
	}
	if got := m.Members(id); len(got) != 1 || got[0] != 100000002 {
		t.Fatalf("members after create = %v", got)
	}

	if _, _, ok := m.Join(player(100000003, "friend"), id); !ok {
		t.Fatal("Join failed")
	}
	if got := m.Members(id); len(got) != 2 {
		t.Fatalf("members after join = %v", got)
	}

	// The creator leaves; the squad keeps the other member.
	if _, _, ok := m.Leave(100000002); !ok {
		t.Fatal("Leave failed")
	}
	if got := m.Members(id); len(got) != 1 || got[0] != 100000003 {
		t.Fatalf("members after leave = %v", got)
	}

	// The last member leaves; the squad is gone.
	m.Leave(100000003)
	if got := m.Members(id); len(got) != 0 {
		t.Fatalf("members after last leave = %v", got)
	}
	if _, _, ok := m.Join(player(100000004, "late"), id); ok {
		t.Fatal("joined a deleted squad")
	}
}

// TestUnitReadyAndVehicle checks the two doCmd paths the squad window
// uses: the ready toggle and the vehicle pick.
func TestUnitReadyAndVehicle(t *testing.T) {
	m := NewUnitManager()
	id, _, _ := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)

	_, packed, ok := m.DoCmd(100000002, id, lobby.UnitCmdSetUnitMemberRdy, 1, 0, "")
	if !ok {
		t.Fatal("ready cmd failed")
	}
	// The ready mask is the seventh u16 of the header; rather than
	// re-walk the blob, check the model through a second pack.
	u := m.UnitOf(100000002)
	if u == nil {
		t.Fatal("UnitOf = nil")
	}
	if u.ReadyMask != 1 {
		t.Fatalf("readyMask = %#x, want 1", u.ReadyMask)
	}
	if len(packed) == 0 {
		t.Fatal("empty packed unit")
	}

	if _, _, ok := m.DoCmd(100000002, id, lobby.UnitCmdSetUnitVehicle, 42, 0, ""); !ok {
		t.Fatal("vehicle cmd failed")
	}
	if got := u.Vehicles[100000002]; len(got) != 1 || got[0].InvID != 42 {
		t.Fatalf("vehicles = %v", got)
	}
	// Clearing the vehicle drops it.
	m.DoCmd(100000002, id, lobby.UnitCmdSetUnitVehicle, 0, 0, "")
	if _, ok := u.Vehicles[100000002]; ok {
		t.Fatal("vehicle not cleared")
	}
}

// TestUnitInvite checks that an invitation lands on the target and is
// cleared once it joins.
func TestUnitInvite(t *testing.T) {
	m := NewUnitManager()
	id, _, _ := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)
	if _, _, ok := m.Invite(100000002, id, []int64{100000003}, "join me"); !ok {
		t.Fatal("Invite failed")
	}
	inv := m.Invites(100000003)
	if len(inv) != 1 || inv[0].UnitID != id || inv[0].Comment != "join me" {
		t.Fatalf("invites = %+v", inv)
	}
	if inv[0].FromName != "admin" {
		t.Fatalf("invite sender = %q", inv[0].FromName)
	}
	m.Join(player(100000003, "friend"), id)
	if got := m.Invites(100000003); len(got) != 0 {
		t.Fatalf("invites after join = %+v", got)
	}
}

// TestUnitKick checks that the leader can remove a member.
func TestUnitKick(t *testing.T) {
	m := NewUnitManager()
	id, _, _ := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)
	m.Join(player(100000003, "friend"), id)
	if _, _, ok := m.DoCmd(100000002, id, lobby.UnitCmdKickUnitPlayer, 100000003, 0, ""); !ok {
		t.Fatal("kick failed")
	}
	if got := m.Members(id); len(got) != 1 || got[0] != 100000002 {
		t.Fatalf("members after kick = %v", got)
	}
	if m.UnitOf(100000003) != nil {
		t.Fatal("kicked player still has a unit")
	}
}

// TestUnitOneSquadPerAccount checks that creating a second squad
// replaces the first, which is what the client expects (it never holds
// two).
func TestUnitOneSquadPerAccount(t *testing.T) {
	m := NewUnitManager()
	first, _, _ := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)
	second, _, _ := m.Create(player(100000002, "admin"), lobby.PrebattleSquad)
	if first == second {
		t.Fatal("second create reused the first id")
	}
	if got := m.Members(first); len(got) != 0 {
		t.Fatalf("old squad still has members: %v", got)
	}
	if u := m.UnitOf(100000002); u == nil || u.ID != second {
		t.Fatalf("UnitOf = %+v, want id %d", u, second)
	}
}
