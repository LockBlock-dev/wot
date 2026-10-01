package replay

import (
	"fmt"
)

// BattleMeta identifies the battle for an exported timeline.
type BattleMeta struct {
	File    string `json:"file"`
	Version string `json:"version"`
	Map     string `json:"map"`
	Player  string `json:"player"`
	Packets int    `json:"packets"`
	Methods int    `json:"methods"`
	Props   int    `json:"props"`
}

// BattleTimeline is the full extracted event set of one replay:
// decoded method/property events plus derived kills. Slices are
// time-ordered by construction (stream order).
type BattleTimeline struct {
	Meta       BattleMeta       `json:"meta"`
	Setup      map[string]any   `json:"setup"`
	Results    []any            `json:"results,omitempty"`
	Damage     []DamageEvent    `json:"damage"`
	Kills      []KillEvent      `json:"kills"`
	Explosions []ExplosionEvent `json:"explosions,omitempty"`
	Tracers    []TracerEvent    `json:"tracers,omitempty"`
	Explodes   []ExplodeEvent   `json:"explodes,omitempty"`
	Shots      []ShotResult     `json:"shotResults,omitempty"`
}

// Extract runs the whole pipeline on an opened replay: entity table,
// exact method decode (open var wires tolerated), exact property
// decode, event filing, kill derivation. Versions without proven
// tables (2.0) are an error.
func Extract(path string, r *Replay, pkts []Packet) (*BattleTimeline, error) {
	ver := r.ClientVersion()
	tab, calls, _, err := DecodeAllLenient(ver, pkts)
	if err != nil {
		return nil, err
	}
	props, pskip, err := DecodePropsLenient(tab, pkts)
	if err != nil {
		return nil, err
	}
	if len(pskip) != 0 {
		return nil, fmt.Errorf("wotreplay: open prop indexes: %v", pskip)
	}
	var ev Events
	for _, c := range calls {
		ev.Collect(c.Time, c.Call.EntityID, c.Call)
	}
	tl := &BattleTimeline{
		Meta: BattleMeta{
			File:    path,
			Version: ver,
			Map:     r.MetaField("mapDisplayName"),
			Player:  r.MetaField("playerName"),
			Packets: len(pkts),
			Methods: len(calls),
			Props:   len(props),
		},
		Setup:      r.Meta,
		Results:    r.Extra,
		Damage:     ev.Damage,
		Explosions: ev.Explosions,
		Tracers:    ev.Tracers,
		Explodes:   ev.Explodes,
		Shots:      ev.ShotResults,
		Kills:      DeriveKills(props, ev.Damage),
	}
	if tl.Damage == nil {
		tl.Damage = []DamageEvent{}
	}
	if tl.Kills == nil {
		tl.Kills = []KillEvent{}
	}
	return tl, nil
}
