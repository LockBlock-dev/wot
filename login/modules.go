package login

import (
	"math/rand"

	"github.com/LockBlock-dev/wot/entdef"
)

// Module and crew damage for the synthetic opponent.
//
// The official cell app damages the module or crewman behind the armour a
// shell penetrates, and tells the client with two calls:
//
//   - `Vehicle.onExtraHitted(extraIndex, hitPoint)` — which extra was hit and
//     where, so the client can place the device-hit effect;
//   - `Vehicle.startOrUpdateExtraFromOutside(name, args)` — starts the extra,
//     which for a track is `TrackHealth._start` → `addCrashedTrack`: the
//     broken-track visual.
//
// The extra indices are the client's `typeDescr.extras` order: the common
// `item_defs/vehicles/common/vehicle.xml` `<extras>` list, index 0 being the
// `_NoneExtra`, with the vehicle's own `<extras>` merged in (the TOG II has
// none, so the common list is the whole table). The HP values are the item
// defs' own: the engine's `<maxHealth>`, the radio's, the gun's, the fuel
// tank's, the chassis's (both tracks), and the turret's
// `<turretRotatorHealth>` / `<surveyingDeviceHealth>` / `<ammoBayHealth>`.
// The crewmen have no per-role HP in the defs; 100 is the game's standard.

// dummyModule is one damageable module or crewman of the dummy.
type dummyModule struct {
	// Name is the extra name, e.g. "engineHealth".
	Name string
	// Extra is the client's `typeDescr.extras` index.
	Extra int
	MaxHP float32
	// Crew marks a crewman: when every crewman is dead the tank is dead.
	Crew bool
}

// dummyModules is the TOG II's module and crew table, in the client's extras
// order.
var dummyModules = []dummyModule{
	{Name: "engineHealth", Extra: 62, MaxHP: 247},
	{Name: "ammoBayHealth", Extra: 63, MaxHP: 220},
	{Name: "fuelTankHealth", Extra: 64, MaxHP: 200},
	{Name: "radioHealth", Extra: 65, MaxHP: 160},
	{Name: "leftTrack0Health", Extra: 66, MaxHP: 170},
	{Name: "rightTrack0Health", Extra: 67, MaxHP: 170},
	{Name: "gunHealth", Extra: 68, MaxHP: 144},
	{Name: "turretRotatorHealth", Extra: 69, MaxHP: 140},
	{Name: "surveyingDeviceHealth", Extra: 70, MaxHP: 90},
	{Name: "commanderHealth", Extra: 71, MaxHP: 100, Crew: true},
	{Name: "driverHealth", Extra: 72, MaxHP: 100, Crew: true},
	{Name: "radioman1Health", Extra: 73, MaxHP: 100, Crew: true},
	{Name: "gunner1Health", Extra: 75, MaxHP: 100, Crew: true},
	{Name: "loader1Health", Extra: 77, MaxHP: 100, Crew: true},
	{Name: "loader2Health", Extra: 78, MaxHP: 100, Crew: true},
}

// moduleState is one module's or crewman's damage, as the session tracks it.
type moduleState struct {
	HP        float32
	Destroyed bool
}

// moduleIndex returns the index of a module by name, or -1.
func moduleIndex(name string) int {
	for i := range dummyModules {
		if dummyModules[i].Name == name {
			return i
		}
	}
	return -1
}

// moduleHit is one candidate module and its relative chance.
type moduleHit struct {
	Name   string
	Weight int
}

// The hit tables: which modules sit behind each face of each part. The real
// cell app reads them off the collision group's name (`engine`, `armor_1`,
// `track_l`, ...); a box model has no groups, so the faces stand in for them:
// the hull's front holds the driver, radio and ammo bay, its sides and rear
// the engine and fuel tanks, the turret the gun, rotator and optics, and the
// barrel only the gun. The tracks are picked by the hit's HEIGHT on a hull
// side, below `dummyTrackBand`.
var (
	hullFrontHits = []moduleHit{
		{"driverHealth", 25},
		{"radioHealth", 20},
		{"ammoBayHealth", 20},
		{"leftTrack0Health", 15},
		{"rightTrack0Health", 15},
		{"engineHealth", 5},
	}
	hullSideHits = []moduleHit{
		{"engineHealth", 25},
		{"fuelTankHealth", 20},
		{"radioHealth", 10},
		{"ammoBayHealth", 10},
		{"leftTrack0Health", 15},
		{"rightTrack0Health", 15},
		{"driverHealth", 5},
	}
	hullRearHits = []moduleHit{
		{"engineHealth", 40},
		{"fuelTankHealth", 30},
		{"radioHealth", 20},
		{"ammoBayHealth", 10},
	}
	hullTopHits = []moduleHit{
		{"ammoBayHealth", 40},
		{"engineHealth", 30},
		{"fuelTankHealth", 30},
	}
	turretHits = []moduleHit{
		{"gunHealth", 25},
		{"turretRotatorHealth", 25},
		{"surveyingDeviceHealth", 20},
		{"commanderHealth", 10},
		{"gunner1Health", 10},
		{"loader1Health", 5},
		{"loader2Health", 5},
	}
	gunHits = []moduleHit{
		{"gunHealth", 100},
	}
)

// dummyTrackBand is the fraction of the hull's height below which a side hit
// counts as a track hit: the tracks run along the bottom of the hull.
const dummyTrackBand = 0.45

// moduleDamageShare is the share of a shell's damage a module takes. The cell
// app scales it by the module's own damage factor; a half is the game's
// order of magnitude for a penetrating hit.
const moduleDamageShare = 0.5

// pickModule rolls the module a hit damages.
//
// part is the client's TankPartIndexes index, face the box face (0 ±X, 1 ±Y,
// 2 ±Z) and localNormal its outward normal in the part's frame, which is what
// tells a front hit from a rear one. localY is the hit point's height in the
// part's frame, which picks a track on a hull side.
func pickModule(part uint8, face int, localNormal [3]float32, localY float32) string {
	var table []moduleHit
	switch part {
	case 1:
		switch face {
		case 0:
			table = hullSideHits
		case 1:
			table = hullTopHits
		case 2:
			if localNormal[2] > 0 {
				table = hullFrontHits
			} else {
				table = hullRearHits
			}
		}
		// A low hit on the hull's flank is a track, not an engine.
		if face == 0 {
			min, max := dummyParts[0].Bounds[0], dummyParts[0].Bounds[1]
			if localY < min[1]+(max[1]-min[1])*dummyTrackBand {
				if localNormal[0] > 0 {
					return "rightTrack0Health"
				}
				return "leftTrack0Health"
			}
		}
	case 2:
		table = turretHits
	case 3:
		table = gunHits
	}
	if len(table) == 0 {
		return ""
	}
	total := 0
	for _, h := range table {
		total += h.Weight
	}
	roll := rand.Intn(total)
	for _, h := range table {
		if roll < h.Weight {
			return h.Name
		}
		roll -= h.Weight
	}
	return table[len(table)-1].Name
}

// fireChance is how likely a wrecked module is to set the tank alight, by
// module. The engine's own `<fireStartingChance>` is 0.15; a torn-open fuel
// tank is likelier.
var fireChance = map[string]float64{
	"engineHealth":   0.15,
	"fuelTankHealth": 0.25,
}

// damageModule applies one hit's module damage and returns the client calls
// that show it — the `onExtraHitted` hit point, and the extra start when the
// module is DESTROYED (a broken track, the only extra whose client side has a
// visual) — plus a fire when the wreck is a flammable one and the roll says
// so.
func (s *BaseAppServer) damageModule(t *botTarget, arenaID uint64, res shotResult, damage int, attacker uint32) ([]byte, *fireStart) {
	dummy := t.entity
	name := pickModule(res.Part, res.Face, res.LocalNormal, res.Local[1])
	if name == "" {
		return nil, nil
	}
	idx := moduleIndex(name)
	if idx < 0 {
		return nil, nil
	}
	// The module state is the TARGET's, not the session's: every synthetic
	// tank has its own tracks, engine and crew, so a shot at one cannot wreck
	// another.
	if t.modules == nil {
		t.modules = make([]moduleState, len(dummyModules))
		for i := range dummyModules {
			t.modules[i].HP = dummyModules[i].MaxHP
		}
	}
	m := &t.modules[idx]
	if m.Destroyed {
		return nil, nil // a wrecked module takes no more hits
	}
	amount := float32(damage) * moduleDamageShare
	if amount < 1 {
		amount = 1
	}
	m.HP -= amount
	destroyed := m.HP <= 0
	if destroyed {
		m.HP = 0
		m.Destroyed = true
	}
	hp := m.HP
	s.logf("arena %d: %s hit for %.0f (%.0f/%.0f left, destroyed=%v)",
		arenaID, name, amount, hp, dummyModules[idx].MaxHP, destroyed)

	var out []byte
	// The device-hit call: the extra and the world hit point.
	if el, err := EncodeClientMethodCall(dummy, "onExtraHitted", []entdef.Value{
		{Kind: entdef.VInt, Int: int64(dummyModules[idx].Extra)},
		{Kind: entdef.VSeq, Seq: []entdef.Value{
			{Kind: entdef.VFloat, Float: float64(res.Point[0])},
			{Kind: entdef.VFloat, Float: float64(res.Point[1])},
			{Kind: entdef.VFloat, Float: float64(res.Point[2])},
		}},
	}); err == nil {
		out = append(out, el...)
	}
	if !destroyed {
		return out, nil
	}
	// A destroyed track breaks its visual: `TrackHealth._start` calls
	// `addCrashedTrack`. The extra's args are unused, so a pickled None.
	if name == "leftTrack0Health" || name == "rightTrack0Health" {
		if el, err := EncodeClientMethodCall(dummy, "startOrUpdateExtraFromOutside", []entdef.Value{
			{Kind: entdef.VString, Str: name},
			{Kind: entdef.VString, Str: "\x80\x02N."},
		}); err == nil {
			out = append(out, el...)
		}
	}
	// A wrecked engine or fuel tank can set the tank alight.
	if chance, ok := fireChance[name]; ok && rand.Float64() < chance {
		return out, &fireStart{Extra: dummyModules[idx].Extra, Attacker: attacker}
	}
	return out, nil
}

// allCrewDead reports whether every crewman of the dummy is dead, which kills
// the tank: the crew is what keeps it fighting.
func (s *BaseAppServer) allCrewDead(t *botTarget) bool {
	if t.modules == nil {
		return false
	}
	any := false
	for i := range dummyModules {
		if !dummyModules[i].Crew {
			continue
		}
		any = true
		if !t.modules[i].Destroyed {
			return false
		}
	}
	return any
}

// moduleStateByName is a test and log helper.
func moduleStateByName(t *botTarget, name string) (moduleState, bool) {
	idx := moduleIndex(name)
	if idx < 0 || t.modules == nil || idx >= len(t.modules) {
		return moduleState{}, false
	}
	return t.modules[idx], true
}

// pickModuleForTest exposes the roll's table choice without the random pick.
func moduleTableFor(part uint8, face int, localNormal [3]float32) []moduleHit {
	switch part {
	case 1:
		switch face {
		case 0:
			return hullSideHits
		case 1:
			return hullTopHits
		case 2:
			if localNormal[2] > 0 {
				return hullFrontHits
			}
			return hullRearHits
		}
	case 2:
		return turretHits
	case 3:
		return gunHits
	}
	return nil
}
