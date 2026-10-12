package replay

import (
	"fmt"
	"sort"
	"strings"
)

// ShotLine is one fired shot booted to roster identity: battle time,
// shooter entity, player name, tank display name, shell caliber.
// Times are battle-relative seconds (replay clock); tracers arrive
// time-ordered so the feed needs no re-sorting (sorted defensively).
type ShotLine struct {
	Time   float32
	Entity int64
	Name   string
	Tank   string
	Range  float64
	ShotID int64
}

// String renders the feed row: `[mm:ss] [name] [tank] SHOT`.
func (s ShotLine) String() string {
	t := int(s.Time + 0.5)
	return fmt.Sprintf("[%02d:%02d] %s [%s] SHOT", t/60, t%60, s.Name, s.Tank)
}

// DisplayTank trims a vehicleType tag (`nation:PREFIX_Name...`) to its
// readable suffix (`GB41_Challenger` → `Challenger`, `A69_T110E5` →
// `T110E5`). Tags without an underscore pass through; empty is `?`.
func DisplayTank(tag string) string {
	if i := strings.Index(tag, ":"); i >= 0 {
		tag = tag[i+1:]
	}
	if i := strings.Index(tag, "_"); i >= 0 {
		tag = tag[i+1:]
	}
	if tag == "" {
		return "?"
	}
	return tag
}

// ShotFeed joins every decoded tracer with the setup roster
// (`Setup["vehicles"]`: avatarSessionID → {name, vehicleType}).
// Unknown entities (unrostered IDs such as replay a0=0) keep `?`
// identity rather than guessing — the feed reports, never invents.
func ShotFeed(tl *BattleTimeline) []ShotLine {
	names := map[int64]string{}
	tanks := map[int64]string{}
	if vm, ok := tl.Setup["vehicles"].(map[string]any); ok {
		for k, v := range vm {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			var id int64
			if _, err := fmt.Sscanf(k, "%d", &id); err != nil {
				continue
			}
			if n, _ := m["name"].(string); n != "" {
				names[id] = n
			}
			if vt, _ := m["vehicleType"].(string); vt != "" {
				tanks[id] = DisplayTank(vt)
			}
		}
	}
	out := make([]ShotLine, 0, len(tl.Tracers))
	for _, tr := range tl.Tracers {
		nm, ok := names[tr.A0]
		if !ok {
			nm = "?"
		}
		tn, ok := tanks[tr.A0]
		if !ok {
			tn = "?"
		}
		out = append(out, ShotLine{tr.Time, tr.A0, nm, tn, tr.Range, tr.ShotID})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time < out[j].Time })
	return out
}
