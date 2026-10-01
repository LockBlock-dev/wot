package replay

import (
	"math"
	"testing"
)

// TestTimeline runs the full Extract pipeline on all fixtures and
// pins damage/kill goldens. Offline.
func TestTimeline(t *testing.T) {
	for _, tc := range []struct {
		file   string
		damage int
		kills  []KillEvent
	}{
		{"../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay", 47,
			[]KillEvent{
				{Time: 88.135, Victim: 4730055, Attacker: 4730062, Known: true},
				{Time: 309.83, Victim: 4730065, Attacker: 4730072, Known: true},
				{Time: 413.33, Victim: 4730053, Attacker: 4730054, Known: true},
				{Time: 531.825, Victim: 4730070, Attacker: 4730080, Known: true},
				{Time: 633.115, Victim: 4730080, Attacker: 4730054, Known: true},
			}},
		{"../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay", 85, nil},
		{"../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay", 181, nil},
	} {
		r, err := Open(tc.file)
		if err != nil {
			t.Skipf("no fixture: %v", err)
		}
		pkts, err := Packets(r.Stream)
		if err != nil {
			t.Fatal(err)
		}
		tl, err := Extract(tc.file, r, pkts)
		if err != nil {
			t.Fatal(err)
		}
		if tl.Setup["playerName"] != tl.Meta.Player {
			t.Fatalf("%s: setup player=%v meta=%q", tc.file, tl.Setup["playerName"], tl.Meta.Player)
		}
		veh, ok := tl.Setup["vehicles"].(map[string]any)
		if !ok || len(veh) == 0 {
			t.Fatalf("%s: no vehicles roster", tc.file)
		}
		if len(tl.Damage) != tc.damage {
			t.Fatalf("%s: damage=%d want %d", tc.file, len(tl.Damage), tc.damage)
		}
		if tc.kills != nil {
			if len(tl.Kills) != len(tc.kills) {
				t.Fatalf("%s: kills=%v", tc.file, tl.Kills)
			}
			for i, want := range tc.kills {
				got := tl.Kills[i]
				if math.Abs(float64(got.Time-want.Time)) > 0.01 ||
					got.Victim != want.Victim || got.Attacker != want.Attacker || got.Known != want.Known {
					t.Fatalf("%s: kill %d = %+v want %+v", tc.file, i, got, want)
				}
			}
		} else if len(tl.Kills) == 0 {
			t.Fatalf("%s: no kills", tc.file)
		}
		t.Logf("%s: damage=%d kills=%d explosions=%d tracers=%d",
			tl.Meta.Version, len(tl.Damage), len(tl.Kills), len(tl.Explosions), len(tl.Tracers))
	}
}
