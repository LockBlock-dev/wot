package login

import (
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestBotRosterFillsBothTeams pins the roster: the allies up to `allies`, the
// rest on the enemy team, every bot a distinct playable tank with a crew.
func TestBotRosterFillsBothTeams(t *testing.T) {
	if len(lobby.AllOwnableVehicles) == 0 {
		t.Skip("no generated vehicle table")
	}
	bots := BotRoster(29, 14, nil)
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
	}
	if allies != 14 || enemies != 15 {
		t.Fatalf("allies %d enemies %d, want 14 and 15", allies, enemies)
	}
}
