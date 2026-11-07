package server

import (
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// vehicleAt returns the compact descriptor of the first ownable vehicle
// at a tier, so the tests do not hard-code a descriptor.
func vehicleAt(t *testing.T, level uint8) []byte {
	t.Helper()
	for _, v := range lobby.AllOwnableVehicles {
		if v.Level == level {
			return v.CompDescr
		}
	}
	t.Fatalf("no ownable vehicle at tier %d", level)
	return nil
}

// TestMatchmakingEnqueueValidates checks the refusal paths: an unknown
// queue type, a vehicle that is not in the garage, and a double enqueue.
func TestMatchmakingEnqueueValidates(t *testing.T) {
	m := NewMatchmaking(nil)
	veh := vehicleAt(t, 5)

	// A queue type this server does not serve.
	res := m.Enqueue(1, "a", []int32{17, 1}, veh)
	if res.Ok() || res.Code != joinFailureQueueForbidden {
		t.Fatalf("ranked enqueue = %+v, want QUEUE_FORBIDDEN", res)
	}
	// No vehicle.
	res = m.Enqueue(1, "a", []int32{1, 1}, nil)
	if res.Ok() || res.Code != joinFailureWrongVehicle {
		t.Fatalf("no-vehicle enqueue = %+v, want WRONG_VEHICLE", res)
	}
	// Too few arguments.
	res = m.Enqueue(1, "a", []int32{1}, veh)
	if res.Ok() || res.Code != joinFailureWrongArgs {
		t.Fatalf("short enqueue = %+v, want WRONG_ARGS", res)
	}
	// The happy path, then a duplicate.
	if res := m.Enqueue(1, "a", []int32{1, 42}, veh); !res.Ok() || res.Added != 1 {
		t.Fatalf("enqueue = %+v", res)
	}
	if res := m.Enqueue(1, "a", []int32{1, 42}, veh); res.Ok() || res.Code != joinFailureQueueFailure {
		t.Fatalf("duplicate enqueue = %+v, want QUEUE_FAILURE", res)
	}
	// The census sees it, with the vehicle's class.
	players, classes := m.Census(1)
	if players != 1 {
		t.Fatalf("census players = %d, want 1", players)
	}
	class, _, _ := ClassOf(veh)
	if classes[class] != 1 {
		t.Fatalf("census classes = %v, want 1 in bucket %d", classes, class)
	}
	// Leaving empties it.
	if !m.Dequeue(1) {
		t.Fatal("Dequeue missed")
	}
	if players, _ := m.Census(1); players != 0 {
		t.Fatalf("census players = %d after leaving, want 0", players)
	}
}

// TestMatchmakingSquadQueuesTogether checks the platoon path: the leader's
// enqueue puts the whole squad in, and only the leader may do it.
func TestMatchmakingSquadQueuesTogether(t *testing.T) {
	units := NewUnitManager()
	m := NewMatchmaking(units)
	veh := vehicleAt(t, 5)
	m.VehicleOf = func(int64, int32) []byte { return veh }

	// Two players in a squad, the first is the leader.
	id, _, ok := units.Create(lobby.UnitPlayer{AccountDBID: 1, NickName: "leader"}, lobby.PrebattleSquad)
	if !ok {
		t.Fatal("Create failed")
	}
	if _, _, ok := units.Join(lobby.UnitPlayer{AccountDBID: 2, NickName: "member"}, id); !ok {
		t.Fatal("Join failed")
	}
	// The member's vehicle, so the squad entry resolves.
	units.DoCmd(2, id, lobby.UnitCmdSetUnitVehicle, 7, 0, "")

	// The member cannot queue the squad.
	res := m.Enqueue(2, "member", []int32{1, 7}, veh)
	if res.Ok() || res.Code != joinFailureQueueForbidden {
		t.Fatalf("member enqueue = %+v, want QUEUE_FORBIDDEN", res)
	}
	// The leader queues both.
	res = m.Enqueue(1, "leader", []int32{1, 7}, veh)
	if !res.Ok() || res.Added != 2 {
		t.Fatalf("leader enqueue = %+v, want 2 added", res)
	}
	if players, _ := m.Census(1); players != 2 {
		t.Fatalf("census players = %d, want 2", players)
	}
	// The leader leaving takes the squad with them.
	m.Dequeue(1)
	if players, _ := m.Census(1); players != 0 {
		t.Fatalf("census players = %d after the leader left, want 0", players)
	}
}

// TestMatchmakingRecordsFormedBattles checks that the matchmaker runs on
// every enqueue and records what it could have produced.
func TestMatchmakingRecordsFormedBattles(t *testing.T) {
	m := NewMatchmaking(nil)
	m.maker.TeamSize = 1
	veh := vehicleAt(t, 5)
	if res := m.Enqueue(1, "a", []int32{1, 1}, veh); !res.Ok() {
		t.Fatalf("enqueue 1 = %+v", res)
	}
	if len(m.Matches()) != 0 {
		t.Fatal("a battle formed from one player")
	}
	if res := m.Enqueue(2, "b", []int32{1, 2}, veh); !res.Ok() {
		t.Fatalf("enqueue 2 = %+v", res)
	}
	matches := m.Matches()
	if len(matches) != 1 {
		t.Fatalf("%d battles recorded, want 1", len(matches))
	}
	if matches[0].Size() != 2 {
		t.Fatalf("battle size = %d, want 2", matches[0].Size())
	}
	// The players stay queued: the handoff needs a battle server.
	if players, _ := m.Census(1); players != 2 {
		t.Fatalf("census players = %d after a formed battle, want 2 (not handed off)", players)
	}
}

// TestMatchmakingSoloFormsABattle checks the test mode the operator reaches
// with `-battle-team-size 0`: one queued player is enough, and the
// matchmaker's callback fires from Handoff — not from Enqueue, because the
// client must see its `onEnqueued` answer before the arena entry clears its
// entity table.
func TestMatchmakingSoloFormsABattle(t *testing.T) {
	m := NewMatchmaking(nil)
	m.Matchmaker().TeamSize = 0
	var got *Match
	m.OnMatch = func(match *Match) { got = match }
	veh := vehicleAt(t, 5)
	if res := m.Enqueue(1, "a", []int32{1, 1}, veh); !res.Ok() {
		t.Fatalf("enqueue = %+v", res)
	}
	if got != nil {
		t.Fatal("the handoff ran from Enqueue; it must wait for Handoff")
	}
	m.Handoff()
	if got == nil {
		t.Fatal("no battle formed from one player in solo mode")
	}
	if got.Size() != 1 || got.Entries[0].AccountID != 1 {
		t.Fatalf("battle = %+v", got)
	}
	// The player stays queued: the handoff is the arena's job, not the
	// queue's.
	if players, _ := m.Census(1); players != 1 {
		t.Fatalf("census players = %d, want 1", players)
	}
}
