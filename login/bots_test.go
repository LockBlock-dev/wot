package login

import (
	"bytes"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestBotRosterFillsBothTeams pins the roster: the allies up to `allies`, the
// rest on the enemy team, every bot a distinct playable tank with a crew.
func TestBotRosterFillsBothTeams(t *testing.T) {
	if len(lobby.AllOwnableVehicles) == 0 {
		t.Skip("no generated vehicle table")
	}
	bots := BotRoster(29, 14, nil, nil)
	if len(bots) != 29 {
		t.Fatalf("%d bots, want 29", len(bots))
	}
	allies, enemies := 0, 0
	for _, b := range bots {
		switch b.Team {
		case 1:
			allies++
		case 2:
			enemies++
		default:
			t.Fatalf("%s on team %d", b.Name, b.Team)
		}
		if len(b.VehicleCompDescr) < 3 {
			t.Fatalf("%s has no vehicle", b.Name)
		}
		if b.CrewSize <= 0 {
			t.Fatalf("%s has no crew", b.Name)
		}
		// The tank's own hit points, not the 1000 fallback: the health bar is
		// scaled to `publicInfo.maxHealth`.
		if b.MaxHealth <= 0 {
			t.Fatalf("%s has no hit points", b.Name)
		}
	}
	if allies != 14 || enemies != 15 {
		t.Fatalf("allies %d enemies %d, want 14 and 15", allies, enemies)
	}
}

// TestBotRosterOnlyUsesRenderableVehicles pins the crash guard: a synthetic
// tank whose model the client does not ship makes it fail to build the
// appearance and then die with an access violation, so the roster must be
// drawn only from the vehicles the client can draw.
func TestBotRosterOnlyUsesRenderableVehicles(t *testing.T) {
	if len(lobby.AllOwnableVehicles) == 0 {
		t.Skip("no generated vehicle table")
	}
	// Allow exactly one vehicle, so every bot must be that one.
	want := lobby.AllOwnableVehicles[0]
	renderable := map[string]bool{want.Name: true}
	bots := BotRoster(4, 2, nil, renderable)
	if len(bots) != 4 {
		t.Fatalf("%d bots, want 4", len(bots))
	}
	for _, b := range bots {
		if !bytes.Equal(b.VehicleCompDescr, want.CompDescr) {
			t.Fatalf("bot %q uses a vehicle outside the renderable set", b.Name)
		}
	}
	// An empty set yields nothing rather than falling back to the full table.
	if got := BotRoster(4, 2, nil, map[string]bool{}); len(got) != 0 {
		t.Fatalf("%d bots from an empty renderable set, want 0", len(got))
	}
}
