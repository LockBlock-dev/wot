package server

import (
	"testing"
	"time"
)

// arenaPlayer builds a roster entry.
func arenaPlayer(id int64, name string) ArenaPlayer {
	return ArenaPlayer{AccountID: id, Name: name, VehicleCompDescr: []byte{1, 0, 0}}
}

// TestArenaCreateSplitsTeams checks the roster split: alternating, so the
// sides stay even.
func TestArenaCreateSplitsTeams(t *testing.T) {
	a := NewArenas()
	arena := a.Create([]ArenaPlayer{
		arenaPlayer(1, "a"), arenaPlayer(2, "b"),
		arenaPlayer(3, "c"), arenaPlayer(4, "d"),
	}, 1, 1, "spaces/01_karelia")
	if arena.State != ArenaRunning {
		t.Fatalf("state = %s, want running", arena.State)
	}
	if arena.SpaceID == 0 {
		t.Fatal("space id is zero")
	}
	want := map[int64]uint8{1: 0, 2: 1, 3: 0, 4: 1}
	for id, team := range want {
		if got := arena.Players[id].Team; got != team {
			t.Errorf("player %d team = %d, want %d", id, got, team)
		}
	}
	if len(arena.Order) != 4 {
		t.Fatalf("order = %v", arena.Order)
	}
}

// TestArenaReconnectHoldsTheSlot is the point of the whole thing: a dropped
// player keeps its battle, and a returning one gets the same arena back.
func TestArenaReconnectHoldsTheSlot(t *testing.T) {
	a := NewArenas()
	arena := a.Create([]ArenaPlayer{arenaPlayer(1, "a"), arenaPlayer(2, "b")}, 1, 1, "spaces/01_karelia")

	// The player drops.
	got, ok := a.Disconnect(1)
	if !ok || got.ID != arena.ID {
		t.Fatalf("Disconnect = %v/%v", got, ok)
	}
	if a.ArenaOf(1) == nil {
		t.Fatal("the slot was freed on disconnect")
	}
	if p := arena.Players[1]; p.Disconnected.IsZero() {
		t.Fatal("the disconnect was not stamped")
	}

	// The player comes back.
	back, player, ok := a.Reconnect(1)
	if !ok || back.ID != arena.ID || player.AccountID != 1 {
		t.Fatalf("Reconnect = %+v/%+v/%v", back, player, ok)
	}
	if !player.Disconnected.IsZero() {
		t.Fatal("the disconnect was not cleared")
	}
	// The same space and arena id, so the client rejoins the same battle.
	if back.SpaceID != arena.SpaceID || back.ArenaTypeID != arena.ArenaTypeID {
		t.Fatalf("rejoin handed back a different battle: %+v", back)
	}
}

// TestArenaReconnectWindowExpires checks that a slot is freed once the
// window passes, and that the player then has no battle to rejoin.
func TestArenaReconnectWindowExpires(t *testing.T) {
	a := NewArenas()
	a.ReconnectWindow = time.Minute
	now := time.Unix(1_700_000_000, 0)
	a.now = func() time.Time { return now }
	a.Create([]ArenaPlayer{arenaPlayer(1, "a"), arenaPlayer(2, "b")}, 1, 1, "spaces/01_karelia")
	a.Disconnect(1)

	// Inside the window: still held.
	if freed := a.Sweep(now.Add(30 * time.Second)); freed != 0 {
		t.Fatalf("swept %d slots inside the window", freed)
	}
	if a.ArenaOf(1) == nil {
		t.Fatal("the slot was freed inside the window")
	}
	// Past it: freed.
	if freed := a.Sweep(now.Add(2 * time.Minute)); freed != 1 {
		t.Fatalf("swept %d slots past the window, want 1", freed)
	}
	if a.ArenaOf(1) != nil {
		t.Fatal("the slot survived the window")
	}
	if _, _, ok := a.Reconnect(1); ok {
		t.Fatal("Reconnect succeeded after the window")
	}
	// The battle itself is still there for the other player.
	if a.ArenaOf(2) == nil {
		t.Fatal("the battle was dropped with one player still in it")
	}
}

// TestArenaFinishStampsResults checks the result the client's screen reads.
func TestArenaFinishStampsResults(t *testing.T) {
	a := NewArenas()
	arena := a.Create([]ArenaPlayer{arenaPlayer(1, "a"), arenaPlayer(2, "b")}, 1, 1, "spaces/01_karelia")
	done := a.Finish(arena.ID, 0)
	if done.State != ArenaFinished {
		t.Fatalf("state = %s", done.State)
	}
	winner := done.Players[1]
	loser := done.Players[2]
	if winner.Result == nil || loser.Result == nil {
		t.Fatal("a result is missing")
	}
	if !winner.Result.Survived || winner.Result.Credits == 0 {
		t.Fatalf("winner result = %+v", winner.Result)
	}
	if loser.Result.Survived || loser.Result.Credits == 0 {
		t.Fatalf("loser result = %+v", loser.Result)
	}
	// A finished battle cannot be rejoined.
	if _, _, ok := a.Reconnect(1); ok {
		t.Fatal("Reconnect succeeded on a finished battle")
	}
}

// TestArenaLeaveDropsTheBattle checks that the last player out takes the
// battle with them.
func TestArenaLeaveDropsTheBattle(t *testing.T) {
	a := NewArenas()
	arena := a.Create([]ArenaPlayer{arenaPlayer(1, "a")}, 1, 1, "spaces/01_karelia")
	if _, ok := a.Leave(1); !ok {
		t.Fatal("Leave missed")
	}
	if a.Len() != 0 {
		t.Fatalf("%d battles left", a.Len())
	}
	if a.ArenaOf(1) != nil {
		t.Fatal("the player still has a battle")
	}
	_ = arena
}
