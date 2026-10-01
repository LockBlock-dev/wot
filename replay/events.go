package replay

// Battle-event extraction over decoded EntityMethod calls: damage,
// health, shots. All shapes proven by exact-consumption decode on
// the fixtures (see dispatch_test.go); field semantics follow the
// .def arg order (INT32 vehicle IDs are entity IDs).

// DamageHit is one showDamageFromShot damage-dict element.
type DamageHit struct {
	NetworkID uint64
	Segment   uint64
	Params    uint64
}

// DamageEvent is a Vehicle.showDamageFromShot call: the attacker's
// entity ID, per-segment hits, and trailing shot descriptors.
type DamageEvent struct {
	Time     float32
	Attacker uint32
	Target   uint32
	Hits     []DamageHit
	Arg2     uint64
	Arg3     uint64
	Arg4     int64
	Arg5     uint64
	Arg6     uint64
	Arg7     float64
	Arg8     uint64
}

// ExplosionEvent is a Vehicle.showDamageFromExplosion call.
type ExplosionEvent struct {
	Time     float32
	Attacker int64
	Pos      []float64
	Arg2     uint64
	Arg3     int64
	Arg4     uint64
	Arg5     uint64
}

// HealthEvent is a Vehicle.onHealthChanged call
// (INT16, INT16, INT32, UINT8, INT8).
type HealthEvent struct {
	Time   float32
	Target uint32
	A0     int64
	A1     int64
	A2     int64
	A3     uint64
	A4     int64
}

// AvatarHealthEvent is an Avatar.updateVehicleHealth call
// (INT32, INT16, INT8, UINT8, UINT8).
type AvatarHealthEvent struct {
	Time float32
	A0   int64
	A1   int64
	A2   int64
	A3   uint64
	A4   uint64
}

// TracerEvent is an Avatar.showTracer call: shot ID plus endpoints.
type TracerEvent struct {
	Time   float32
	A0     int64
	ShotID int64
	Flags  [4]uint64
	Range  float64
	Start  []float64
	End    []float64
	A9     float64
	A10    float64
	A11    uint64
	A12    uint64
}

// ExplodeEvent is an Avatar.explodeProjectile call.
type ExplodeEvent struct {
	Time   float32
	ShotID int64
	A1     uint64
	A2     uint64
	A3     uint64
	A4     uint64
	A5     float64
	Pos    []float64
	End    []float64
	A8     float64
	Tail   []any
}

// ShotResult is an Avatar.showShotResults call: one attack's results.
type ShotResult struct {
	Time      float32
	VehicleID uint64
	HitFlags  uint64
	GunIndex  uint64
}

func u(args []any, i int) uint64     { return args[i].(uint64) }
func s(args []any, i int) int64      { return args[i].(int64) }
func f(args []any, i int) float64    { return args[i].(float64) }
func v3(args []any, i int) []float64 { return args[i].([]float64) }

// Events walks decoded calls (see DecodeAll) and files them by event.
type Events struct {
	Damage       []DamageEvent
	Explosions   []ExplosionEvent
	Health       []HealthEvent
	AvatarHealth []AvatarHealthEvent
	Tracers      []TracerEvent
	Explodes     []ExplodeEvent
	ShotResults  []ShotResult
}

// Collect files one decoded call with its packet time.
func (e *Events) Collect(t float32, eid uint32, c DecodedCall) {
	switch c.Sig.Name {
	case "showDamageFromShot":
		hits := []DamageHit{}
		for _, h := range c.Args[1].([]any) {
			m := h.(map[string]any)
			hits = append(hits, DamageHit{m["networkID"].(uint64), m["segment"].(uint64), m["params"].(uint64)})
		}
		e.Damage = append(e.Damage, DamageEvent{t, uint32(s(c.Args, 0)), eid, hits,
			u(c.Args, 2), u(c.Args, 3), s(c.Args, 4), u(c.Args, 5), u(c.Args, 6), f(c.Args, 7), u(c.Args, 8)})
	case "showDamageFromExplosion":
		e.Explosions = append(e.Explosions, ExplosionEvent{t, s(c.Args, 0), v3(c.Args, 1),
			u(c.Args, 2), s(c.Args, 3), u(c.Args, 4), u(c.Args, 5)})
	case "onHealthChanged":
		e.Health = append(e.Health, HealthEvent{t, eid, s(c.Args, 0), s(c.Args, 1), s(c.Args, 2), u(c.Args, 3), s(c.Args, 4)})
	case "updateVehicleHealth":
		e.AvatarHealth = append(e.AvatarHealth, AvatarHealthEvent{t, s(c.Args, 0), s(c.Args, 1), s(c.Args, 2), u(c.Args, 3), u(c.Args, 4)})
	case "showTracer":
		var fl [4]uint64
		for i := 0; i < 4; i++ {
			fl[i] = u(c.Args, 2+i)
		}
		e.Tracers = append(e.Tracers, TracerEvent{t, s(c.Args, 0), s(c.Args, 1), fl, f(c.Args, 6),
			v3(c.Args, 7), v3(c.Args, 8), f(c.Args, 9), f(c.Args, 10), u(c.Args, 11), u(c.Args, 12)})
	case "explodeProjectile":
		e.Explodes = append(e.Explodes, ExplodeEvent{t, s(c.Args, 0), u(c.Args, 1), u(c.Args, 2),
			u(c.Args, 3), u(c.Args, 4), f(c.Args, 5), v3(c.Args, 6), v3(c.Args, 7), f(c.Args, 8), c.Args[9].([]any)})
	case "showShotResults":
		for _, h := range c.Args[0].([]any) {
			m := h.(map[string]any)
			e.ShotResults = append(e.ShotResults, ShotResult{t, m["vehicleID"].(uint64), m["hitFlags"].(uint64), m["gunInstallationIndex"].(uint64)})
		}
	}
}

// KillEvent is a derived death: a vehicle's health property reaching
// 0. No kill method fires in these battles, so kills come from
// health tracks; attacker = latest damaging attacker within
// killWindow before death (heuristic, flagged when absent).
type KillEvent struct {
	Time     float32
	Victim   uint32
	Attacker uint32
	Known    bool // false when no attacker damaged the victim recently
}

// killWindow is how far back to look for the killing damage.
const killWindow = 10.0

// DeriveKills folds vehicle health properties (name "health") into
// deaths (nonzero-to-zero transitions, so respawns re-arm) and
// attributes each to recent damage.
func DeriveKills(props []TimedProp, dmg []DamageEvent) []KillEvent {
	var out []KillEvent
	last := map[uint32]int64{}
	alive := map[uint32]bool{}
	for _, pr := range props {
		if pr.Prop.Sig.Name != "health" {
			continue
		}
		hp, ok := pr.Prop.Value.(int64)
		if !ok {
			continue
		}
		if hp == 0 && (!alive[pr.Prop.EntityID] || last[pr.Prop.EntityID] != 0) {
			k := KillEvent{Time: pr.Time, Victim: pr.Prop.EntityID}
			for _, d := range dmg {
				if d.Target == k.Victim && d.Time <= k.Time && k.Time-d.Time <= killWindow {
					k.Attacker, k.Known = d.Attacker, true
				}
			}
			out = append(out, k)
		}
		last[pr.Prop.EntityID] = hp
		alive[pr.Prop.EntityID] = true
	}
	return out
}
