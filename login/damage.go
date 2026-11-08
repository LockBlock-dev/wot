package login

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"net"

	"github.com/LockBlock-dev/wot/entdef"
	"strings"
	"sync/atomic"
)

// Server-side shot resolution and the damage it does, for the synthetic
// opponent a solo battle fields.
//
// The real battle is the cell app's: it traces the shell through the
// vehicle's collision mesh, rolls the penetration against the armour it
// meets, and streams the result. This server has no cell app, so the shell is
// traced against the dummy's hull box and the armour is the TOG II's own
// values from its item defs. The wire shapes are the client's: the reference's
// `showDamageFromShot` / `onHealthChanged` / `showShotResults`, with the
// method ids and argument types from the shipped 2.4.1 defs.

// `VEHICLE_HIT_EFFECT` codes the client's `DamageFromShotDecoder` maps to an
// effect group.
const (
	hitEffectPierced       uint8 = 4
	hitEffectNotPierced    uint8 = 3
	hitEffectDeviceDamaged uint8 = 6
	// hitEffectRicochet is `FINAL_RICOCHET`: the shell bounced off the armour.
	hitEffectRicochet uint8 = 2
	// hitEffectPiercedNoDamage is `ARMOR_PIERCED_NO_DAMAGE`: through a screen
	// only, missing the main armour behind it.
	hitEffectPiercedNoDamage uint8 = 0
)

// `VEHICLE_HIT_FLAGS`, as the reference's `ShellHit` sets them.
const (
	hitFlagDirect          uint32 = 0x100000
	hitFlagArmorNotPierced uint32 = 0x20
	hitFlagVehicleKilled   uint32 = 1
	hitFlagExploded        uint32 = 0x2000
	hitFlagRicochet        uint32 = 0x8
	hitFlagScreenPierced   uint32 = 0x40
	hitFlagsPierced        uint32 = hitFlagDirect | 0x100 | 0x10
)

// The share a shell's penetration and damage vary, either way.
const damageSpread = 0.25

// botTarget is one synthetic tank the player's shells can hit: its entity,
// where it stands, and its own damage state. The dummy and every bot in the
// battle is one, and the shell resolves against whichever is in its path.
type botTarget struct {
	entity *Entity
	id     uint32
	pos    [3]float32
	yaw    float32
	// collision is the client's collision mesh: the shell is traced through
	// its triangles, so the hit point, the normal and the armour are the
	// client's own. nil when the game's files are not available, and the
	// target cannot be hit.
	collision *vehicleCollision
	// dead is set when the health reaches 0, so a flight does not have to read
	// the health from another goroutine.
	dead      atomic.Bool
	health    int
	maxHealth int
	// stickers is the accumulated `damageStickers` (the shell holes); every
	// pierced hit re-sends the whole list.
	stickers []entdef.Value
	// infoIndex is this tank's row in the arena's `vehiclesInfo` list.
	infoIndex int
	// modules is its module and crew state, nil until the first module hit.
	modules []moduleState
}

// shotResult is what one shell does to the dummy.
type shotResult struct {
	Hit      bool
	Point    [3]float32 // world
	Local    [3]float32 // the hit point in the hit PART's frame
	LocalDir [3]float32 // the shell's direction in the hit part's frame
	Normal   [3]float32 // world, outward
	Distance float32
	Part     uint8         // TankPartIndexes
	Bounds   [2][3]float32 // the hit part's box, for the segment
	// Face is the box face the shell met (0 ±X, 1 ±Y, 2 ±Z) and LocalNormal
	// its outward normal in the part's frame; both pick the module behind it.
	Face        int
	LocalNormal [3]float32
	Armor       float32 // effective, after the impact angle
	Pierced     bool
	Damage      int
	Effect      uint8
	Flags       uint32
	// Target is the index into the session's targets of the tank the shell
	// hit, copied from the box.
	Target int
}

// rollVehicleHit is what a shell does to the armour it meets: it walks the
// plates along its way (screens, tracks, the gun, then the main armour) and
// returns the hit the client is shown, with the damage and the effect code.
//
// Ported from the reference's `armor::hit`: the outcome decides the damage,
// and an HE shell that does not pierce explodes on the armour instead.
func rollVehicleHit(sh shellSpec, target int, contact vehicleHit, dir [3]float32, distance float64, penFactor float32, c *vehicleCollision, pos [3]float32, yaw float32) (shotResult, bool) {
	impact, ok := armorHit(sh, float32(distance), penFactor, contact.Point, dir, c, pos, yaw)
	if !ok {
		return shotResult{}, false
	}
	h := impact.Hit
	res := shotResult{
		Hit:         true,
		Target:      target,
		Point:       h.Point,
		Normal:      h.Normal,
		Distance:    float32(distance),
		Part:        h.Part,
		Bounds:      h.Bounds,
		Local:       h.LocalPoint,
		LocalDir:    h.LocalDir,
		LocalNormal: h.LocalNormal,
		Face:        faceOf(h.LocalNormal),
		Armor:       effectiveArmor(sh, h),
		Pierced:     impact.Outcome == outcomePierced,
	}
	// A device the shell got through (the gun, a track, the surveying device)
	// is a module hit: the hull takes nothing and the client shows a critical
	// hit. The game names them `gun`, `leftTrack`, `rightTrack` and
	// `surveyingDevice`; a screen is an `armor_N` with a zero damage factor.
	device := !strings.HasPrefix(h.GroupName, "armor_")
	switch impact.Outcome {
	case outcomePierced, outcomeScreens:
		if device {
			res.Effect = hitEffectDeviceDamaged
			res.Flags = hitFlagsPierced
			res.Damage = 0
			return res, true
		}
		if impact.Outcome == outcomeScreens {
			// Through a screen only, missing the main armour behind it.
			res.Effect = hitEffectPiercedNoDamage
			res.Flags = hitFlagDirect | hitFlagScreenPierced
			return res, true
		}
		res.Damage = int(math.Round(float64(impact.Damage) * (1 + (rand.Float64()*2-1)*damageSpread)))
		res.Effect = hitEffectPierced
		res.Flags = hitFlagsPierced
	case outcomeRicochet:
		res.Effect = hitEffectRicochet
		res.Flags = hitFlagDirect | hitFlagRicochet
	case outcomeNotPierced:
		res.Effect = hitEffectNotPierced
		res.Flags = hitFlagDirect | hitFlagArmorNotPierced
		// An HE shell that does not pierce explodes on the armour: half its
		// damage at the armour, less what the armour absorbs.
		if sh.isHE() {
			if dmg := 0.5*sh.damageAt(distance) - 1.3*float64(res.Armor); dmg > 0 {
				res.Damage = int(math.Round(dmg * (1 + (rand.Float64()*2-1)*damageSpread)))
				res.Flags |= hitFlagExploded
			}
		}
	}
	return res, true
}

// effectiveArmor is the thickness the shell met at its angle, for the log and
// the HE explosion's absorption.
func effectiveArmor(sh shellSpec, h vehicleHit) float32 {
	if h.Material == nil {
		return 0
	}
	cos := float32(1)
	if h.Material.UseHitAngle {
		cos = clampF32(-dot3(h.LocalDir, h.LocalNormal), 0, 1)
	}
	return penetrationArmor(sh, cos, *h.Material)
}

// faceOf names the box face a normal points out of (0 ±X, 1 ±Y, 2 ±Z), which
// is what the module picker is keyed by.
func faceOf(n [3]float32) int {
	ax, ay, az := abs32(n[0]), abs32(n[1]), abs32(n[2])
	switch {
	case ax >= ay && ax >= az:
		return 0
	case ay >= az:
		return 1
	}
	return 2
}

// maxGroundRicochets is how many times a shell may skim off the ground before
// it stops.
const maxGroundRicochets = 3

// groundRicochetAngle is the largest angle between a shell's path and the
// ground it ricochets off, in radians: the reference's `GROUND.ricochet_angle`,
// 8 degrees.
const groundRicochetAngle = 8 * math.Pi / 180

// ricochetsOffGround reports whether a shell skims off the ground at this
// angle: AP and APCR only, within `groundRicochetAngle` of the surface.
func ricochetsOffGround(sh shellSpec, velocity, normal [3]float32) bool {
	if !sh.isAP() && !sh.isAPCR() {
		return false
	}
	l := float32(math.Sqrt(float64(velocity[0]*velocity[0] + velocity[1]*velocity[1] + velocity[2]*velocity[2])))
	if l < 1e-6 {
		return false
	}
	cos := -(velocity[0]*normal[0] + velocity[1]*normal[1] + velocity[2]*normal[2]) / l
	if cos < -1 {
		cos = -1
	}
	if cos > 1 {
		cos = 1
	}
	grazing := math.Asin(float64(cos))
	return grazing >= 0 && grazing <= groundRicochetAngle
}

// ricochetPenFactor is the share of its penetration a shell keeps off a
// ricochet: 0.75 for AP and APCR, all of it otherwise.
func ricochetPenFactor(sh shellSpec) float32 {
	if sh.isAP() || sh.isAPCR() {
		return 0.75
	}
	return 1
}

// splash is an HE shell exploding on the ground or a wall: every synthetic
// tank whose main armour the blast reaches takes its damage.
func (s *BaseAppServer) splash(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, sh shellSpec, shotID int32, attacker uint32, vehicle, avatar *Entity, marker nrlGunMarker, targets []*botTarget, center [3]float32) {
	for i, t := range targets {
		if t == nil || t.dead.Load() {
			continue
		}
		damage, hit, ok := explosionAt(sh, center, t)
		if !ok || damage <= 0 {
			continue
		}
		// The blast's way to the armour is the hit's own direction.
		dir := [3]float32{hit.Point[0] - center[0], hit.Point[1] - center[1], hit.Point[2] - center[2]}
		if l := dist3(hit.Point, center); l > 1e-6 {
			dir = [3]float32{dir[0] / l, dir[1] / l, dir[2] / l}
		}
		res := shotResult{
			Hit:         true,
			Target:      i,
			Point:       hit.Point,
			Normal:      dir,
			Distance:    dist3(center, hit.Point),
			Part:        hit.Part,
			Bounds:      hit.Bounds,
			Local:       hit.LocalPoint,
			LocalDir:    dir,
			LocalNormal: dir,
			Face:        faceOf(hit.LocalNormal),
			Pierced:     false,
			Damage:      int(math.Round(float64(damage))),
			Effect:      hitEffectNotPierced,
			Flags:       hitFlagDirect | hitFlagExploded,
		}
		s.logf("arena %d: HE blast %.1f m from bot %d: %d damage (armour %s)",
			arenaID, res.Distance, t.id, res.Damage, hit.GroupName)
		s.applyDamage(conn, from, st, arenaID, sh, shotID, attacker, vehicle, avatar, marker, t, res)
	}
}

// maxHitAngle is the steepest impact the normalization may turn a shell to,
// in radians: the reference's `MAX_HIT_ANGLE`.
const maxHitAngle = 1.5

// normalRandom is a standard normal sample (Box-Muller).
func normalRandom() float64 {
	u := math.Max(rand.Float64(), math.SmallestNonzeroFloat64)
	v := rand.Float64()
	return math.Sqrt(-2*math.Log(u)) * math.Cos(2*math.Pi*v)
}

// clampF64 clamps v to [lo, hi].
func clampF64(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// encodeHitSegment packs a hit point's segment the way `VehicleHit
// .encode_segment` does: the hull part and the hit effect in the low two
// bytes, then the quantized enter and exit points over the part's bounds.
func encodeHitSegment(bounds [2][3]float32, point, dir [3]float32, part, context uint8) uint64 {
	min, max := bounds[0], bounds[1]
	reach := float32(math.Sqrt(float64((max[0]-min[0])*(max[0]-min[0]) + (max[1]-min[1])*(max[1]-min[1]) + (max[2]-min[2])*(max[2]-min[2]))))
	from := [3]float32{point[0] - dir[0]*reach, point[1] - dir[1]*reach, point[2] - dir[2]*reach}
	to := [3]float32{point[0] + dir[0]*reach, point[1] + dir[1]*reach, point[2] + dir[2]*reach}
	header := uint64(part)<<8 | uint64(context)
	enter, exit, ok := clipToBox(from, to, min, max)
	if !ok {
		return header
	}
	quant := func(p [3]float32) [3]uint8 {
		var q [3]uint8
		for i := 0; i < 3; i++ {
			span := max[i] - min[i]
			v := float32(0)
			if span != 0 {
				v = (p[i] - min[i]) * 255 / span
			}
			if v < 0 {
				v = 0
			}
			if v > 255 {
				v = 255
			}
			q[i] = uint8(math.Round(float64(v)))
		}
		return q
	}
	a := quant(lerp3(from, to, enter))
	b := quant(lerp3(from, to, exit))
	return uint64(b[2])<<56 | uint64(b[1])<<48 | uint64(b[0])<<40 |
		uint64(a[2])<<32 | uint64(a[1])<<24 | uint64(a[0])<<16 | header
}

// clipToBox returns the fractions where the segment enters and leaves the
// box, if it crosses it.
func clipToBox(from, to, min, max [3]float32) (enter, exit float32, ok bool) {
	enter, exit = 0, 1
	delta := [3]float32{to[0] - from[0], to[1] - from[1], to[2] - from[2]}
	for i := 0; i < 3; i++ {
		if abs32(delta[i]) < 1e-9 {
			if from[i] < min[i] || from[i] > max[i] {
				return 0, 0, false
			}
			continue
		}
		a := (min[i] - from[i]) / delta[i]
		b := (max[i] - from[i]) / delta[i]
		if a > b {
			a, b = b, a
		}
		if a > enter {
			enter = a
		}
		if b < exit {
			exit = b
		}
		if enter > exit {
			return 0, 0, false
		}
	}
	return enter, exit, true
}

func lerp3(a, b [3]float32, t float32) [3]float32 {
	return [3]float32{
		a[0] + (b[0]-a[0])*t,
		a[1] + (b[1]-a[1])*t,
		a[2] + (b[2]-a[2])*t,
	}
}

// neg3 negates a direction.
func neg3(v [3]float32) [3]float32 {
	return [3]float32{-v[0], -v[1], -v[2]}
}

// hitParams is the `VEHICLE_HIT_POINT.params` word: the caliber in tenths of
// a millimetre, the shell kind and the hit effect, as `hit_point` packs them.
func hitParams(sh shellSpec, effect uint8) uint32 {
	caliber := uint32(sh.Caliber*10) & 0xFFFF
	return caliber<<8 | uint32(sh.KindIndex&15)<<4 | uint32(effect)
}

// hitPointValue builds one `VEHICLE_HIT_POINT`.
func hitPointValue(segment uint64, params uint32) entdef.Value {
	return entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "networkID", Value: entdef.Value{Kind: entdef.VUint}},
		{Name: "segment", Value: entdef.Value{Kind: entdef.VUint, Uint: segment}},
		{Name: "params", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(params)}},
	}}
}

// vec3Value builds a VECTOR3 argument.
func vec3Value(v [3]float32) entdef.Value {
	return entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VFloat, Float: float64(v[0])},
		{Kind: entdef.VFloat, Float: float64(v[1])},
		{Kind: entdef.VFloat, Float: float64(v[2])},
	}}
}

// showDamageFromShotElement is `Vehicle.showDamageFromShot`, the client's
// damage effect and hit point.
func showDamageFromShotElement(vehicle *Entity, attacker uint32, point entdef.Value, effects uint8, damage int, damageFactor uint8, speed float64) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VInt, Int: int64(attacker)},
		{Kind: entdef.VSeq, Seq: []entdef.Value{point}},
		{Kind: entdef.VUint, Uint: uint64(effects)},
		{Kind: entdef.VUint, Uint: 255}, // no prefab effect
		{Kind: entdef.VInt, Int: int64(damage)},
		{Kind: entdef.VUint, Uint: uint64(damageFactor)},
		{Kind: entdef.VUint, Uint: 0}, // the last material is not a shield
		{Kind: entdef.VFloat, Float: speed},
		{Kind: entdef.VUint, Uint: 0},
	}
	return EncodeClientMethodCall(vehicle, "showDamageFromShot", args)
}

// showShootingElement is `Vehicle.showShooting`, the muzzle flash and smoke
// the client plays on the shooter. The reference server sends it with the
// burst count, the gun installation index and the shell kind.
func showShootingElement(vehicle *Entity, burst, gunIndex, shellKind uint8) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(burst)},
		{Kind: entdef.VInt, Int: int64(int8(gunIndex))},
		{Kind: entdef.VUint, Uint: uint64(shellKind)},
	}
	return EncodeClientMethodCall(vehicle, "showShooting", args)
}

// onHealthChangedElement is `Vehicle.onHealthChanged`, the health the client
// shows and the death it triggers.
func onHealthChangedElement(vehicle *Entity, newHealth, oldHealth int, attacker uint32) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VInt, Int: int64(newHealth)},
		{Kind: entdef.VInt, Int: int64(oldHealth)},
		{Kind: entdef.VInt, Int: int64(attacker)},
		{Kind: entdef.VUint, Uint: 0}, // ATTACK_REASON.SHOT
		{Kind: entdef.VInt, Int: -1},
	}
	return EncodeClientMethodCall(vehicle, "onHealthChanged", args)
}

// showShotResultsElement is `Avatar.showShotResults`, the shooter's hit
// marker and kill credit.
func showShotResultsElement(avatar *Entity, vehicleID uint32, flags uint32) ([]byte, error) {
	result := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "vehicleID", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(vehicleID)}},
		{Name: "hitFlags", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(flags)}},
		{Name: "gunInstallationIndex", Value: entdef.Value{Kind: entdef.VUint}},
	}}
	args := []entdef.Value{{Kind: entdef.VSeq, Seq: []entdef.Value{result}}}
	return EncodeClientMethodCall(avatar, "showShotResults", args)
}

// showTracerElement is `Avatar.showTracer`: the shell the client draws flying
// from the gun.
func showTracerElement(avatar *Entity, shooter uint32, shotID int32, sh shellSpec, start, velocity [3]float32) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VInt, Int: int64(shooter)},
		{Kind: entdef.VInt, Int: int64(shotID)},
		{Kind: entdef.VUint, Uint: 0}, // not a ricochet
		{Kind: entdef.VUint, Uint: uint64(sh.EffectsIndex)},
		{Kind: entdef.VUint, Uint: 255}, // no prefab effect
		{Kind: entdef.VUint, Uint: uint64(sh.KindIndex)},
		{Kind: entdef.VFloat, Float: sh.Caliber},
		vec3Value(start),
		vec3Value(velocity),
		{Kind: entdef.VFloat, Float: sh.Gravity},
		{Kind: entdef.VFloat, Float: sh.MaxDistance},
		{Kind: entdef.VUint, Uint: 0},
		{Kind: entdef.VUint, Uint: 0},
	}
	return EncodeClientMethodCall(avatar, "showTracer", args)
}

// stopTracerElement is `Avatar.stopTracer`, which ends the shell at its hit.
func stopTracerElement(avatar *Entity, shotID int32, end [3]float32) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VInt, Int: int64(shotID)},
		vec3Value(end),
	}
	return EncodeClientMethodCall(avatar, "stopTracer", args)
}

func sign32(v float32) float32 {
	if v < 0 {
		return -1
	}
	return 1
}

// applyShot resolves the shot the client just fired against the synthetic
// tanks and streams the damage back. A miss sends nothing: the client has
// already drawn its own shot.
//
// Every synthetic tank is a `botTarget`, so the shell hits whichever one is in
// its path — the dummy is just the first of them.
func (s *BaseAppServer) applyShot(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64) {
	s.mu.Lock()
	if len(st.targets) == 0 || st.avatar == nil || st.vehicle == nil {
		s.mu.Unlock()
		return
	}
	hullNow := st.hull
	yaw, pitch := st.gunYaw, st.gunPitch
	aimWorld := st.aimWorld
	spec := st.gunSpec
	targets := append([]*botTarget(nil), st.targets...)
	vehicle := st.vehicle
	attacker := vehicle.ID
	avatar := st.avatar
	st.shotID++
	shotID := st.shotID
	s.mu.Unlock()

	sh := spec.Dispersion.Shell
	if sh.Damage <= 0 || spec.Dispersion.ShotSpeed <= 0 {
		s.logf("arena %d: shot: no shell damage data (shell %q); the shot is not resolved", arenaID, sh.Name)
		return
	}
	marker := gunMarkerFor(hullNow, yaw, pitch, spec, 1)
	v := marker.Velocity
	length := float32(math.Sqrt(float64(v[0]*v[0] + v[1]*v[1] + v[2]*v[2])))
	if length < 1e-6 {
		return
	}
	// The shell flies: gravity pulls it down and it lands on the first
	// vehicle it meets, on the terrain, or at its `maxDistance`. A shot that
	// lands on the ground is an explosion the client draws; a vehicle hit's
	// distance is what the penetration falls off with.
	s.mu.Lock()
	terrain := st.terrain
	statics := st.statics
	s.mu.Unlock()
	// A destructible the shell breaks is destroyed on the spot and the shell
	// goes on through it; anything else stops it.
	onStatic := func(tri staticTriangle) bool {
		switch tri.Kind {
		case bodyDestructible, bodyModule:
			if err := s.destroyStatic(conn, from, st, arenaID, tri); err != nil {
				s.logf("arena %d: destructible: %v", arenaID, err)
			}
			return true
		}
		return false
	}
	// The shell's flight. An AP or APCR shell that meets the ground at a
	// grazing angle skims off it and goes on, with less penetration, up to
	// `maxGroundRicochets` times.
	start := marker.Position
	penFactor := float32(1)
	flew := float32(0)
	ricochets := 0
	var landing shellLanding
	for {
		landing = flyShell(sh, start, v, terrain, targets, statics, onStatic)
		landing.Distance += flew
		if landing.Kind != landingTerrain || ricochets >= maxGroundRicochets {
			break
		}
		normal := [3]float32{0, 1, 0}
		if terrain != nil {
			if n, ok := terrain.NormalAt(landing.Point[0], landing.Point[2]); ok {
				normal = n
			}
		}
		if !ricochetsOffGround(sh, landing.Velocity, normal) {
			break
		}
		s.logf("arena %d: shot %s ricochets off the ground at %v, %.0f%% of its penetration left",
			arenaID, sh.Name, landing.Point, penFactor*100)
		v = reflect(landing.Velocity, normal)
		start = [3]float32{
			landing.Point[0] + normal[0]*0.05,
			landing.Point[1] + normal[1]*0.05,
			landing.Point[2] + normal[2]*0.05,
		}
		penFactor *= ricochetPenFactor(sh)
		flew = landing.Distance
		ricochets++
	}
	// The aim and the muzzle are the two numbers that decide whether a shot at
	// a top surface lands or sails over: the elevation is measured from the
	// gun pivot above the CHASSIS origin, and the pitch is clamped to the
	// gun's own limits.
	s.logf("arena %d: shot %s aim=%v gunYaw=%.3f gunPitch=%.3f muzzle=%v",
		arenaID, sh.Name, aimWorld, yaw, pitch, marker.Position)
	if landing.Kind != landingVehicle {
		// A miss: the client drew its own shot, so only the end and, for the
		// ground or a wall, the explosion go out. `explodeProjectile`'s shot
		// id is flagged unknown (`| 0x40000000`) so the client shows it from
		// these arguments alone.
		var app []byte
		app = append(app, EncodeSelectPlayerEntity()...)
		if el, err := stopTracerElement(avatar, shotID, landing.Point); err == nil {
			app = append(app, el...)
		}
		if landing.Kind == landingTerrain || landing.Kind == landingStatic {
			if el, err := explodeProjectileElement(avatar, uint32(shotID)|0x40000000, sh, landing); err == nil {
				app = append(app, el...)
			}
			// An HE shell explodes where it lands: the vehicles whose main
			// armour the blast reaches take its damage, the shooter's own
			// aside.
			if sh.isHE() {
				s.splash(conn, from, st, arenaID, sh, shotID, attacker, vehicle, avatar, marker, targets, landing.Point)
			}
		}
		if len(app) > 0 {
			st.sendMu.Lock()
			seq, cumul := s.nextSeq(st)
			err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
			st.sendMu.Unlock()
			if err != nil {
				s.logf("arena %d: miss: %v", arenaID, err)
			} else if landing.Kind == landingTerrain {
				s.logf("arena %d: shot %s landed on the ground at %v after %.0f m",
					arenaID, sh.Name, landing.Point, landing.Distance)
			} else if landing.Kind == landingStatic {
				s.logf("arena %d: shot %s stopped on a static model at %v after %.0f m",
					arenaID, sh.Name, landing.Point, landing.Distance)
			} else {
				s.logf("arena %d: shot %s flew its %.0f m and landed at %v",
					arenaID, sh.Name, landing.Distance, landing.Point)
			}
		}
		return
	}
	if landing.Target < 0 || landing.Target >= len(targets) {
		return
	}
	t := targets[landing.Target]
	// What the shell does to the armour it meets: the plates it walks are the
	// client's own triangles, so a screen stops it short of the hull and a
	// ricochet names the plate it bounced off.
	res, ok := rollVehicleHit(sh, landing.Target, landing.VHit, landing.Dir, float64(landing.Distance), penFactor, t.collision, t.pos, t.yaw)
	if !ok {
		// It met no armour on its way (only a device, or a gap): the shell
		// goes on, as the reference's `hit` returns None there.
		s.logf("arena %d: shot %s met no armour on bot %d at %v", arenaID, sh.Name, t.id, landing.VHit.LocalPoint)
		return
	}
	s.applyDamage(conn, from, st, arenaID, sh, shotID, attacker, vehicle, avatar, marker, t, res)
}

// applyDamage applies one shell's result to one target and sends the packets:
// the victim's own (its modules, health, stickers, kill) and the shooter's
// (the tracer, the hit marker, the damage log). A direct hit and an HE blast
// that reaches a vehicle both go through here.
func (s *BaseAppServer) applyDamage(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, sh shellSpec, shotID int32, attacker uint32, vehicle, avatar *Entity, marker nrlGunMarker, t *botTarget, res shotResult) {
	s.mu.Lock()
	oldHealth := t.health
	maxHealth := t.maxHealth
	s.mu.Unlock()
	if oldHealth <= 0 {
		return // a wreck takes no more shells
	}
	// The module or crewman behind the armour: a penetrating hit damages one,
	// and the client is told which one (`onExtraHitted`) and, for a wrecked
	// track, to break its visual (`startOrUpdateExtraFromOutside`).
	var moduleEls []byte
	var fire *fireStart
	if res.Pierced {
		// The shell's own damage, not the HP damage: a device hit (the gun)
		// deals no HP damage but still wrecks the device.
		moduleEls, fire = s.damageModule(t, arenaID, res, int(sh.Damage), attacker)
	}
	if maxHealth <= 0 {
		maxHealth = 1000
	}
	damage := res.Damage
	if damage < 0 {
		damage = 0
	}
	newHealth := oldHealth - damage
	if newHealth < 0 {
		newHealth = 0
	}
	// A tank whose crew is all dead is dead, whatever its hit points.
	if newHealth > 0 && s.allCrewDead(t) {
		newHealth = 0
	}
	damageFactor := 0
	if maxHealth > 0 {
		damageFactor = damage * 255 / maxHealth
		if damageFactor > 255 {
			damageFactor = 255
		}
	}
	flags := res.Flags
	if newHealth == 0 && damage > 0 {
		flags |= hitFlagVehicleKilled
	}
	segment := encodeHitSegment(res.Bounds, res.Local, res.LocalDir, res.Part, res.Effect)
	point := hitPointValue(segment, hitParams(sh, res.Effect))

	// Two packets, one per selected entity: the client's selection applies to
	// the elements that follow it in the same bundle, so the victim's methods
	// and the Avatar's must not share a packet.
	var victimApp, avatarApp []byte
	if el, err := EncodeSelectEntity(t.id); err == nil {
		victimApp = append(victimApp, el...)
	}
	// The module/crew calls are Vehicle client methods, so they ride behind
	// the victim's selection.
	victimApp = append(victimApp, moduleEls...)
	// A fire is a dynamic component on the victim: attaching it is what starts
	// the flame effect, and its burn runs on its own timer.
	var fireNode uint16
	if fire != nil {
		if el, node, err := s.startFireElement(st, t.id, fire.Extra, fire.Attacker); err == nil {
			victimApp = append(victimApp, el...)
			fireNode = node
		} else {
			s.logf("arena %d: fire start: %v", arenaID, err)
		}
	}
	if el, err := showDamageFromShotElement(t.entity, attacker, point, sh.EffectsIndex, damage, uint8(damageFactor), sh.Speed); err == nil {
		victimApp = append(victimApp, el...)
	}
	// The shell hole. `showDamageFromShot` only plays the impact effect; the
	// persistent hole is the vehicle's `damageStickers` (an ALL_CLIENTS
	// property), one `VEHICLE_HIT_POINT` per pierced hit whose segment
	// context is the sticker id. The client's `addDamageSticker` draws it.
	if res.Pierced && sh.HasPiercedSticker {
		// The sticker's segment is written EXIT→ENTRY, the reverse of the
		// shell's own path. `showDamageFromShot`'s hit point is read from its
		// START (the client's `parseHitPoints` collides from `segStart`), but
		// the persistent decal is anchored at its END: with an entry→exit
		// segment — what `encodeHitSegment` writes, and what the reference's
		// `VehicleHit::encode_segment` writes — the hole is drawn on the FAR
		// side of the tank. Measured by the player: "if I shoot on the north
		// side, the hole appears on the south side".
		sticker := hitPointValue(encodeHitSegment(res.Bounds, res.Local, neg3(res.LocalDir), res.Part, sh.PiercedSticker), hitParams(sh, hitEffectPierced))
		s.logf("arena %d: sticker %d on part %d (local %v, dir %v, bounds %v..%v)",
			arenaID, sh.PiercedSticker, res.Part, res.Local, res.LocalDir, res.Bounds[0], res.Bounds[1])
		s.mu.Lock()
		t.stickers = append(t.stickers, sticker)
		stickers := append([]entdef.Value(nil), t.stickers...)
		s.mu.Unlock()
		t.entity.Set("damageStickers", entdef.Value{Kind: entdef.VSeq, Seq: stickers})
		if el, err := EncodePropertyUpdate(t.entity, "damageStickers"); err == nil {
			s.logf("arena %d: damageStickers update %dB: % x", arenaID, len(el), el)
			victimApp = append(victimApp, el...)
		} else {
			s.logf("arena %d: damageStickers update failed: %v", arenaID, err)
		}
	}
	if damage > 0 {
		t.entity.SetInt("health", int64(newHealth))
		// A bare property is `[id][value]`, with NO length:
		// `EncodePropertyUpdate`'s `[id][u16 len][value]` is the
		// `updateEntity` run's form, and sending it standalone makes the
		// client read the length as the health and the value's low byte as
		// the next element id (health 926 = 0x039E → element `0x9E` =
		// exposed method 80, out of range on the 11-method Vehicle).
		victimApp = append(victimApp, EncodeBareU16(elVehicleHealth, uint16(newHealth))...)
		if el, err := onHealthChangedElement(t.entity, newHealth, oldHealth, attacker); err == nil {
			victimApp = append(victimApp, el...)
		}
	}
	// A kill also goes into the arena's `vehiclesInfo`.
	if newHealth == 0 && damage > 0 {
		if el := s.killVehiclesInfo(st, t.infoIndex, attacker); len(el) > 0 {
			victimApp = append(victimApp, el...)
		}
	}
	// The shooter's own gun: its muzzle flash and smoke. `showShooting` is a
	// Vehicle client method, so the own vehicle is selected for it; the
	// tracer that follows is an Avatar method and re-selects the player.
	if el, err := showShootingElement(vehicle, 1, 0, sh.KindIndex); err == nil {
		if sel, serr := EncodeSelectEntity(vehicle.ID); serr == nil {
			avatarApp = append(avatarApp, sel...)
		}
		avatarApp = append(avatarApp, el...)
	}
	// The shooter's own view: the shell and the hit marker.
	avatarApp = append(avatarApp, EncodeSelectPlayerEntity()...)
	if el, err := showTracerElement(avatar, attacker, shotID, sh, marker.Position, marker.Velocity); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	if el, err := stopTracerElement(avatar, shotID, res.Point); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	if el, err := showShotResultsElement(avatar, t.id, flags); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	// The damage log and the personal efficiency panel. Neither is fed by the
	// victim's health update: `Avatar.onBattleEvents` is the per-event record
	// (the bottom-left log and its totals) and `OwnVehicle.battleEventsSummary`
	// is the running total the panel's damage counter reads. Without them the
	// shot does damage on the server and the player's UI shows nothing.
	var events []battleEvent
	if damage > 0 {
		details := packDamage(uint64(damage), 0 /* ATTACK_REASON.SHOT */, uint64(battleLogShellType(sh.Kind)), -1)
		events = append(events, battleEvent{eventType: battleEventDamage, targetID: t.id, details: details, count: uint16(damage)})
	}
	if newHealth == 0 && damage > 0 {
		events = append(events, battleEvent{eventType: battleEventKill, targetID: t.id, details: packDamage(uint64(damage), 0, uint64(battleLogShellType(sh.Kind)), -1), count: 1})
	}
	if len(events) > 0 {
		if el, err := onBattleEventsElement(avatar, events); err == nil {
			avatarApp = append(avatarApp, el...)
		}
	}
	s.mu.Lock()
	t.health = newHealth
	st.damageDealt += uint32(damage)
	damageDealt := st.damageDealt
	comp := st.ownVehicle
	s.mu.Unlock()
	if el, err := battleEventsSummaryElement(comp, damageDealt); err == nil {
		avatarApp = append(avatarApp, el...)
	}

	st.sendMu.Lock()
	for _, app := range [][]byte{victimApp, avatarApp} {
		if len(app) == 0 {
			continue
		}
		seq, cumul := s.nextSeq(st)
		if err := s.sendReliableLocked(conn, from, st, app, seq, cumul); err != nil {
			s.logf("arena %d: shot: send failed: %v", arenaID, err)
			break
		}
	}
	st.sendMu.Unlock()
	if fireNode != 0 {
		go s.burnFire(conn, from, st, arenaID, t, fire.Attacker, fireNode)
	}
	s.logf("arena %d: shot %s hit bot %d part %d: %d damage (health %d -> %d, pierced=%v, armor=%.1f)",
		arenaID, sh.Name, t.id, res.Part, damage, oldHealth, newHealth, res.Pierced, res.Armor)
}

// killVehiclesInfo marks the victim dead in the arena's `vehiclesInfo` and
// counts the kill, returning the NRL NESTED updates that make the client
// apply it.
//
// The team panel's greyed-out row, the orange kill message and the kill column
// all read this: `isAlive` false and a `deathInfo` on the victim, `stFrags`
// and `frags` on the shooter.
//
// It has to be NESTED updates, not a whole-value re-send of the list. The
// client's `AvatarVehiclesInfo` component has no `set_vehiclesInfo` handler:
// a whole-value update sets the attribute and calls nothing, so `ClientArena`
// never learns about it and the row stays alive. Its handlers are
// `setNested_vehiclesInfo` (which buffers one field's diff) and the
// `__generation` bump that flushes the buffer into
// `ClientArena.updateVehicleInfo` plus the per-field setters
// (`setVehInfo_isAlive` → `updateVehicleIsAlive` → `onVehicleKilled`).
func (s *BaseAppServer) killVehiclesInfo(st *clientState, infoIndex int, attacker uint32) []byte {
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		return nil
	}
	fields := entdef.FixedDictFields(infoType)
	fieldIndex := func(name string) int {
		for i := range fields {
			if fields[i].Name == name {
				return i
			}
		}
		return -1
	}
	genIdx := fieldIndex("__generation")
	if genIdx < 0 {
		return nil
	}
	s.mu.Lock()
	if st.infoComp.TypeID == 0 || infoIndex < 0 || infoIndex >= len(st.infoVehicles) {
		s.mu.Unlock()
		return nil
	}
	victim := st.infoVehicles[infoIndex]
	victimID := uint32(0)
	if idv, ok := victim.Get("vehicleID"); ok {
		victimID = uint32(idv.Int)
	}
	victim = dictSet(victim, "isAlive", entdef.Value{Kind: entdef.VUint})
	victim = dictSet(victim, "deathInfo", entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "victimID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(victimID)}},
		{Name: "killerID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(attacker)}},
		{Name: "reasonID", Value: entdef.Value{Kind: entdef.VInt}},
		{Name: "equipmentID", Value: entdef.Value{Kind: entdef.VInt}},
		{Name: "numVehiclesAffected", Value: entdef.Value{Kind: entdef.VInt}},
	}})
	st.infoVehicles[infoIndex] = victim
	playerIdx := -1
	if st.infoPlayer >= 0 && st.infoPlayer < len(st.infoVehicles) {
		st.infoKills++
		playerIdx = st.infoPlayer
		shooter := st.infoVehicles[playerIdx]
		shooter = dictSet(shooter, "stFrags", entdef.Value{Kind: entdef.VUint, Uint: uint64(st.infoKills)})
		shooter = dictSet(shooter, "frags", entdef.Value{Kind: entdef.VInt, Int: int64(st.infoKills)})
		st.infoVehicles[playerIdx] = shooter
	}
	comp := st.infoComp
	nVehicles := len(st.infoVehicles)
	dummyIdx := infoIndex
	st.infoGen++
	gen := st.infoGen
	s.mu.Unlock()

	// One vehicle's fields, then its `__generation` bump: the client buffers
	// per FIELD NAME, so the flush has to come after the fields it should
	// carry and before the next vehicle's.
	nested := func(elemIdx int, name string, v entdef.Value) []byte {
		i := fieldIndex(name)
		if i < 0 {
			return nil
		}
		var buf bytes.Buffer
		if err := entdef.NewCodec().Write(&buf, fields[i].Type, v); err != nil {
			return nil
		}
		el, err := EncodeNrlNestedField(comp, 0, comp.Props, elemIdx, nVehicles, i, len(fields), buf.Bytes())
		if err != nil {
			return nil
		}
		return el
	}
	var out []byte
	out = append(out, nested(dummyIdx, "isAlive", entdef.Value{Kind: entdef.VUint})...)
	deathInfo, _ := victim.Get("deathInfo")
	out = append(out, nested(dummyIdx, "deathInfo", deathInfo)...)
	out = append(out, nested(dummyIdx, "__generation", entdef.Value{Kind: entdef.VUint, Uint: uint64(gen)})...)
	if playerIdx >= 0 {
		shooter := st.infoVehicles[playerIdx]
		frags, _ := shooter.Get("frags")
		stFrags, _ := shooter.Get("stFrags")
		out = append(out, nested(playerIdx, "frags", frags)...)
		out = append(out, nested(playerIdx, "stFrags", stFrags)...)
		out = append(out, nested(playerIdx, "__generation", entdef.Value{Kind: entdef.VUint, Uint: uint64(gen)})...)
	}
	return out
}

// battleEvent is one `BATTLE_EVENT`: the damage log's per-event record.
type battleEvent struct {
	eventType uint8
	targetID  uint32
	details   uint64
	count     uint16
}

// Battle event types (`BattleFeedbackCommon.BATTLE_EVENT_TYPE`).
const (
	battleEventDamage uint8 = 7
	battleEventKill   uint8 = 8
)

// Battle log shell types (`BATTLE_LOG_SHELL_TYPES`).
const (
	shellTypeHollowCharge uint8 = 0
	shellTypeAP           uint8 = 1
	shellTypeAPCR         uint8 = 3
	shellTypeHE           uint8 = 5
	shellTypeNone         uint8 = 127
)

// battleLogShellType maps a shell kind to the damage log's shell icon id.
func battleLogShellType(kind string) uint8 {
	switch kind {
	case "ARMOR_PIERCING":
		return shellTypeAP
	case "ARMOR_PIERCING_CR":
		return shellTypeAPCR
	case "HOLLOW_CHARGE":
		return shellTypeHollowCharge
	case "HIGH_EXPLOSIVE":
		return shellTypeHE
	}
	return shellTypeNone
}

// packDamage is `BattleFeedbackCommon.BATTLE_EVENT_TYPE.packDamage`: the
// damage, the attack reason, the shell type and the extended reason packed
// into the event's `details` word.
func packDamage(damage, attackReasonID, shellTypeID uint64, attackReasonExtID int8) uint64 {
	return (damage&0xFFFF)<<25 |
		(attackReasonID&0xFF)<<17 |
		(shellTypeID&0x7F)<<9 |
		// secondaryAttackReasonID = ATTACK_REASON_INDICES[NONE] = 16
		16&0xFF |
		uint64(uint8(attackReasonExtID))<<43
}

// onBattleEventsElement is `Avatar.onBattleEvents`, the per-event damage log
// the client's feedback controller turns into the damage log entries and the
// personal efficiency log.
func onBattleEventsElement(avatar *Entity, events []battleEvent) ([]byte, error) {
	t := entdef.Alias("BATTLE_EVENT")
	if t == nil {
		return nil, fmt.Errorf("no BATTLE_EVENT alias")
	}
	seq := make([]entdef.Value, 0, len(events))
	for _, ev := range events {
		v := entdef.ZeroValue(t)
		v = dictSet(v, "eventType", entdef.Value{Kind: entdef.VUint, Uint: uint64(ev.eventType)})
		v = dictSet(v, "targetID", entdef.Value{Kind: entdef.VUint, Uint: uint64(ev.targetID)})
		v = dictSet(v, "details", entdef.Value{Kind: entdef.VUint, Uint: ev.details})
		v = dictSet(v, "count", entdef.Value{Kind: entdef.VUint, Uint: uint64(ev.count)})
		seq = append(seq, v)
	}
	return EncodeClientMethodCall(avatar, "onBattleEvents", []entdef.Value{{Kind: entdef.VSeq, Seq: seq}})
}

// battleEventsSummaryElement is `OwnVehicle.battleEventsSummary`: the running
// totals the personal efficiency panel's damage counter reads
// (`BattleSummaryFeedbackEvent.fromDict`).
func battleEventsSummaryElement(comp nrlComponent, damage uint32) ([]byte, error) {
	t := entdef.Alias("BATTLE_EVENTS_SUMMARY")
	if t == nil {
		return nil, fmt.Errorf("no BATTLE_EVENTS_SUMMARY alias")
	}
	v := entdef.ZeroValue(t)
	v = dictSet(v, "damage", entdef.Value{Kind: entdef.VUint, Uint: uint64(damage)})
	// `lastKillerID`/`lastDeathReasonID` are the player's own death, not the
	// victim's: -1/0 is "not dead".
	v = dictSet(v, "lastKillerID", entdef.Value{Kind: entdef.VInt, Int: -1})
	v = dictSet(v, "attackReasonExtID", entdef.Value{Kind: entdef.VInt, Int: -1})
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, t, v); err != nil {
		return nil, err
	}
	return EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("battleEventsSummary"), buf.Bytes())
}

// The explosion of an HE shell beside a vehicle.
//
// Ported from the reference's `armor::explosion`: the blast reaches the
// vehicle's closest MAIN armour point within the shell's radius, and the
// plates between it and that point absorb their share of the damage. A screen
// or a track in the way eats into it, and the main armour stops it.
const (
	// explosionDamageFactor is the share of the shell's damage the blast
	// carries at the centre of its radius.
	explosionDamageFactor = 0.5
	// explosionEdgeDamageFactor is the share left at the radius's edge.
	explosionEdgeDamageFactor = 0.05
	// explosionDamageAbsorptionFactor is how much damage each millimetre of
	// armour between the blast and the main armour takes out of it.
	explosionDamageAbsorptionFactor = 1.3
	// explosionStandoff is how far past the armour point the walk goes, so
	// that the plate is crossed.
	explosionStandoff = 0.01
)

// explosionAt is what an HE shell's blast does to a vehicle whose centre is
// `center`: the damage left after the way to its main armour, and the hit that
// is shown.
func explosionAt(sh shellSpec, center [3]float32, t *botTarget) (float32, vehicleHit, bool) {
	if t == nil || t.collision == nil || sh.ExplosionRadius <= 0 {
		return 0, vehicleHit{}, false
	}
	radius := float32(sh.ExplosionRadius)
	closest, distance, _, ok := t.collision.closestPoint(t.pos, t.yaw, center)
	if !ok || distance > radius {
		return 0, vehicleHit{}, false
	}
	dir := [3]float32{closest[0] - center[0], closest[1] - center[1], closest[2] - center[2]}
	if l := dist3(closest, center); l > 1e-6 {
		dir = [3]float32{dir[0] / l, dir[1] / l, dir[2] / l}
	} else {
		return 0, vehicleHit{}, false
	}
	to := [3]float32{
		closest[0] + dir[0]*explosionStandoff*2,
		closest[1] + dir[1]*explosionStandoff*2,
		closest[2] + dir[2]*explosionStandoff*2,
	}
	hits := t.collision.hits(t.pos, t.yaw, center, to)
	seen := map[[2]int]bool{}
	absorbed := float32(0)
	var reached vehicleHit
	found := false
	for _, h := range hits {
		if h.Material == nil {
			continue
		}
		key := [2]int{int(h.Part), h.Group}
		if h.Material.CollideOnceOnly && seen[key] {
			continue
		}
		seen[key] = true
		absorbed += explosionDamageAbsorptionFactor * h.Material.Armor
		if h.Material.isMainArmor() {
			reached = h
			found = true
			break
		}
	}
	if !found {
		return 0, vehicleHit{}, false
	}
	falloff := 1 - (1-explosionEdgeDamageFactor)*distance/radius
	damage := explosionDamageFactor*float32(sh.damageAt(0))*falloff - absorbed
	if damage < 0 {
		damage = 0
	}
	return damage, reached, true
}
