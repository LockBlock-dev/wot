package login

import (
	"bytes"
	"fmt"
	"math"
	"math/rand"
	"net"

	"github.com/LockBlock-dev/wot/entdef"
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

// dummyPart is one of the dummy's hit parts: its collision box in the PART's
// own frame, where that frame sits in the vehicle frame, and the armour of
// each face in millimetres.
//
// The boxes are NOT guesses: they are the client's own `getBoundingBox(part)`,
// which is what `DamageFromShotDecoder.decodeSegment` maps a hit point's
// quantized fractions back through. Each is the `HKBodyFlagsData`
// `minBounds_`/`maxBounds_` of the part's collision model, in the part's own
// frame — the model's origin, which sits at the part's offset in the vehicle
// frame.
type dummyPart struct {
	// Part is the client's `TankPartIndexes` index: 1 hull, 2 turret.
	Part   uint8
	Bounds [2][3]float32
	// Offset is the part's origin in the vehicle frame, from the item defs.
	Offset [3]float32
	// Armour by face: front (+Z), side (±X), rear (-Z), top (+Y).
	Front, Side, Rear, Top float32
	// Device marks a part that is a module, not armour: a shell that
	// penetrates it damages the module and does NO hull damage (the gun).
	Device bool
}

// dummyParts is the TOG II's hull and turret.
//
// The hull is `Hull.havok`'s box, its origin at the chassis's
// `<hullPosition>0 1.3553 0`. The turret is `Turret_01.havok`'s box, its origin
// at the chassis's `<turretPositions><turret>0 0.704143 1.81585` — which is
// relative to the HULL, not the vehicle, so it sits at 2.059 m and the turret
// rises above the hull's 2.088 m top. Without it a shell aimed at the turret
// passed over the hull box and did nothing at all.
//
// The armour is the item defs' per-material table: the hull's `armor_1` 76.2,
// `armor_4` 50.8, `armor_9` 25.4; the turret's `armor_1` 114.3, `armor_3` 76.2,
// `armor_4` 53.3, `armor_6` 19.
var dummyParts = []dummyPart{
	{
		Part:   1, // TankPartIndexes.HULL
		Bounds: [2][3]float32{{-1.5622, -0.8706, -5.2344}, {1.5622, 0.7324, 4.2737}},
		Offset: [3]float32{0, 1.3553, 0},
		Front:  76.2, Side: 76.2, Rear: 50.8, Top: 25.4,
	},
	{
		Part:   2, // TankPartIndexes.TURRET
		Bounds: [2][3]float32{{-1.025, -0.2735, -1.4434}, {1.025, 0.9986, 1.0816}},
		Offset: [3]float32{0, 1.3553 + 0.704143, 1.81585},
		Front:  114.3, Side: 76.2, Rear: 53.3, Top: 19,
	},
	{
		// The gun is a DEVICE, not armour: a shell that penetrates its 25.4 mm
		// damages the gun module and does no hull damage, which is why
		// shooting a barrel shows a critical hit and no health bar movement.
		// Box from `Gun_01.havok`, its origin at the turret's plus the
		// chassis's `<gunPosition>0 0.46479 0.76407`.
		Part:   3, // TankPartIndexes.GUN
		Bounds: [2][3]float32{{-0.1589, -0.1617, -0.632}, {0.1589, 0.1617, 3.8129}},
		Offset: [3]float32{0, 1.3553 + 0.704143 + 0.46479, 1.81585 + 0.76407},
		Front:  25.4, Side: 25.4, Rear: 25.4, Top: 25.4,
		Device: true,
	},
}

// dummyHullBounds is the hull part's box, the bounds the hull's hit segment is
// quantized over.
var dummyHullBounds = dummyParts[0].Bounds

// `VEHICLE_HIT_EFFECT` codes the client's `DamageFromShotDecoder` maps to an
// effect group.
const (
	hitEffectPierced       uint8 = 4
	hitEffectNotPierced    uint8 = 3
	hitEffectDeviceDamaged uint8 = 6
)

// `VEHICLE_HIT_FLAGS`, as the reference's `ShellHit` sets them.
const (
	hitFlagDirect          uint32 = 0x100000
	hitFlagArmorNotPierced uint32 = 0x20
	hitFlagVehicleKilled   uint32 = 1
	hitFlagExploded        uint32 = 0x2000
	hitFlagsPierced        uint32 = hitFlagDirect | 0x100 | 0x10
)

// The share a shell's penetration and damage vary, either way.
const damageSpread = 0.25

// hitBox is an oriented box: the hull's collision volume for the trace.
//
// Center/Half are the trace volume in the vehicle frame; Origin is the HULL
// PART's origin in the world, which is the frame the hit point's segment is
// encoded in (the client decodes it against the part's own bounding box).
type hitBox struct {
	Center [3]float32
	Half   [3]float32
	Yaw    float32
	Origin [3]float32
	// Part is the client's `TankPartIndexes` index and Bounds the part's own
	// box, both of which the hit-point segment carries; Armor is front, side,
	// rear, top in millimetres.
	Part   uint8
	Bounds [2][3]float32
	Armor  [4]float32
	// Device marks a module part (the gun): a penetrating hit damages the
	// module and does no hull damage.
	Device bool
}

// intersect traces the ray origin+dir*t through the box. It returns the
// nearest positive t, the world hit point and outward normal, the normal in
// the box's own frame, and the face it hit (0 ±X, 1 ±Y, 2 ±Z).
func (b hitBox) intersect(origin, dir [3]float32) (t float32, point, normal, localNormal [3]float32, face int, ok bool) {
	// Into the box's frame.
	lx := origin[0] - b.Center[0]
	ly := origin[1] - b.Center[1]
	lz := origin[2] - b.Center[2]
	c, s := cos32(b.Yaw), sin32(b.Yaw)
	ox := lx*c - lz*s
	oz := lx*s + lz*c
	dx := dir[0]*c - dir[2]*s
	dz := dir[0]*s + dir[2]*c
	o := [3]float32{ox, ly, oz}
	d := [3]float32{dx, dir[1], dz}
	half := b.Half

	tmin := float32(-math.MaxFloat32)
	tmax := float32(math.MaxFloat32)
	face = -1
	for i := 0; i < 3; i++ {
		if abs32(d[i]) < 1e-6 {
			if abs32(o[i]) > half[i] {
				return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
			}
			continue
		}
		a := (-half[i] - o[i]) / d[i]
		bb := (half[i] - o[i]) / d[i]
		if a > bb {
			a, bb = bb, a
		}
		if a > tmin {
			tmin = a
			face = i
		}
		if bb < tmax {
			tmax = bb
		}
		if tmin > tmax {
			return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
		}
	}
	if tmax < 0 {
		return 0, [3]float32{}, [3]float32{}, [3]float32{}, 0, false
	}
	if tmin < 0 {
		tmin = 0
	}
	lp := [3]float32{o[0] + d[0]*tmin, o[1] + d[1]*tmin, o[2] + d[2]*tmin}
	ln := [3]float32{}
	switch face {
	case 0:
		ln[0] = sign32(lp[0])
	case 1:
		ln[1] = sign32(lp[1])
	case 2:
		ln[2] = sign32(lp[2])
	}
	// Back to world.
	point = [3]float32{
		b.Center[0] + lp[0]*c + lp[2]*s,
		b.Center[1] + lp[1],
		b.Center[2] - lp[0]*s + lp[2]*c,
	}
	normal = [3]float32{
		ln[0]*c + ln[2]*s,
		ln[1],
		-ln[0]*s + ln[2]*c,
	}
	return tmin, point, normal, ln, face, true
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
}

// resolveShot traces one shell against every part of the dummy and rolls its
// penetration and damage against the NEAREST one it meets.
func resolveShot(sh shellSpec, origin, dir [3]float32, boxes []hitBox) shotResult {
	var res shotResult
	for _, box := range boxes {
		t, point, normal, localNormal, face, ok := box.intersect(origin, dir)
		if !ok || (res.Hit && t >= res.Distance) {
			continue
		}
		res = rollShot(sh, box, t, point, normal, localNormal, face, dir)
	}
	return res
}

// rollShot rolls one hit on one part.
func rollShot(sh shellSpec, box hitBox, t float32, point, normal, localNormal [3]float32, face int, dir [3]float32) shotResult {
	armor := box.armorForFace(face, localNormal)
	// The impact angle: the cosine between the shell's path and the face's
	// outward normal. A grazing hit meets more armour.
	cos := abs32(dir[0]*normal[0] + dir[1]*normal[1] + dir[2]*normal[2])
	if cos < 0.1 {
		cos = 0.1
	}
	effective := armor / cos
	pen := float32(sh.Pen) * (1 + (rand.Float32()*2-1)*damageSpread)
	res := shotResult{
		Hit:      true,
		Point:    point,
		Normal:   normal,
		Distance: t,
		Armor:    effective,
		Pierced:  pen > effective,
	}
	if box.Device {
		// A module hit: the shell damages the device and the hull takes
		// nothing. `ARMOR_PIERCED_DEVICE_DAMAGED` is the client's
		// `VEHICLE_HIT_EFFECT` 6, which its feedback turns into a critical
		// hit; a shell that does not get through the 25.4 mm is a plain
		// non-penetration.
		if res.Pierced {
			res.Effect = hitEffectDeviceDamaged
			res.Flags = hitFlagsPierced
		} else {
			res.Effect = hitEffectNotPierced
			res.Flags = hitFlagDirect | hitFlagArmorNotPierced
		}
		res.Damage = 0
	} else if res.Pierced {
		res.Damage = int(math.Round(sh.Damage * (1 + (rand.Float64()*2-1)*damageSpread)))
		res.Effect = hitEffectPierced
		res.Flags = hitFlagsPierced
	} else {
		res.Effect = hitEffectNotPierced
		res.Flags = hitFlagDirect | hitFlagArmorNotPierced
		// An HE shell that does not pierce explodes on the armour: half its
		// damage at the armour, less what the armour absorbs.
		if sh.KindIndex == 1 {
			if dmg := 0.5*sh.Damage - 1.3*float64(effective); dmg > 0 {
				res.Damage = int(math.Round(dmg * (1 + (rand.Float64()*2-1)*damageSpread)))
				res.Flags |= hitFlagExploded
			}
		}
	}
	// The hit point and direction in the hit PART's frame, which is what the
	// client's hit-point segment is encoded over: the part's own origin, not
	// the trace box's centre.
	c, s := cos32(box.Yaw), sin32(box.Yaw)
	lx := point[0] - box.Origin[0]
	lz := point[2] - box.Origin[2]
	res.Local = [3]float32{lx*c - lz*s, point[1] - box.Origin[1], lx*s + lz*c}
	res.LocalDir = [3]float32{dir[0]*c - dir[2]*s, dir[1], dir[0]*s + dir[2]*c}
	res.Part = box.Part
	res.Bounds = box.Bounds
	res.Face = face
	res.LocalNormal = localNormal
	return res
}

// armorForFace is the nominal armour of the face the shell met.
func (b hitBox) armorForFace(face int, localNormal [3]float32) float32 {
	switch face {
	case 0:
		return b.Armor[1]
	case 1:
		return b.Armor[3]
	case 2:
		if localNormal[2] > 0 {
			return b.Armor[0]
		}
		return b.Armor[2]
	}
	return b.Armor[1]
}

// dummyBoxes is the dummy's parts at its spawn, in world space.
func dummyBoxes(pos [3]float32, yaw float32) []hitBox {
	out := make([]hitBox, 0, len(dummyParts))
	c, s := cos32(yaw), sin32(yaw)
	for _, p := range dummyParts {
		min, max := p.Bounds[0], p.Bounds[1]
		// The part frame's origin in the world.
		origin := [3]float32{
			pos[0] + p.Offset[0]*c + p.Offset[2]*s,
			pos[1] + p.Offset[1],
			pos[2] - p.Offset[0]*s + p.Offset[2]*c,
		}
		// The trace volume: the part frame's box centre, lifted by the part's
		// offset and turned with the hull.
		cx, cy, cz := (min[0]+max[0])/2, (min[1]+max[1])/2, (min[2]+max[2])/2
		out = append(out, hitBox{
			Center: [3]float32{
				origin[0] + cx*c + cz*s,
				origin[1] + cy,
				origin[2] - cx*s + cz*c,
			},
			Half:   [3]float32{(max[0] - min[0]) / 2, (max[1] - min[1]) / 2, (max[2] - min[2]) / 2},
			Yaw:    yaw,
			Origin: origin,
			Part:   p.Part,
			Bounds: p.Bounds,
			Armor:  [4]float32{p.Front, p.Side, p.Rear, p.Top},
			Device: p.Device,
		})
	}
	return out
}

// dummyBox is the hull part at its spawn, in world space.
func dummyBox(pos [3]float32, yaw float32) hitBox {
	return dummyBoxes(pos, yaw)[0]
}

// dummyBounds is the hull box in the HULL PART's frame, the bounds the
// hit-point segment is quantized over.
func dummyBounds() [2][3]float32 {
	return dummyHullBounds
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
// opponent and streams the damage back. A miss sends nothing: the client has
// already drawn its own shot.
func (s *BaseAppServer) applyShot(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64) {
	s.mu.Lock()
	if st.dummy == nil || st.avatar == nil || st.vehicle == nil || st.dummyHealth <= 0 {
		s.mu.Unlock()
		return
	}
	hullNow := st.hull
	yaw, pitch := st.gunYaw, st.gunPitch
	spec := st.gunSpec
	dummy := st.dummy
	dummyID := st.dummyID
	dummyPos := st.dummyPos
	dummyYaw := st.dummyYaw
	oldHealth := st.dummyHealth
	maxHealth := st.dummyMaxHealth
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
	dir := [3]float32{v[0] / length, v[1] / length, v[2] / length}
	res := resolveShot(sh, marker.Position, dir, dummyBoxes(dummyPos, dummyYaw))
	if !res.Hit {
		return
	}
	// The module or crewman behind the armour: a penetrating hit damages one,
	// and the client is told which one (`onExtraHitted`) and, for a wrecked
	// track, to break its visual (`startOrUpdateExtraFromOutside`).
	var moduleEls []byte
	if res.Pierced {
		// The shell's own damage, not the HP damage: a device hit (the gun)
		// deals no HP damage but still wrecks the device.
		moduleEls = s.damageModule(st, dummy, arenaID, res, int(sh.Damage))
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
	if newHealth > 0 && s.allCrewDead(st) {
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
	// the elements that follow it in the same bundle, so the dummy's methods
	// and the Avatar's must not share a packet.
	var dummyApp, avatarApp []byte
	if el, err := EncodeSelectEntity(dummyID); err == nil {
		dummyApp = append(dummyApp, el...)
	}
	// The module/crew calls are Vehicle client methods, so they ride behind
	// the dummy's selection.
	dummyApp = append(dummyApp, moduleEls...)
	if el, err := showDamageFromShotElement(dummy, attacker, point, sh.EffectsIndex, damage, uint8(damageFactor), sh.Speed); err == nil {
		dummyApp = append(dummyApp, el...)
	}
	// The shell hole. `showDamageFromShot` only plays the impact effect; the
	// persistent hole is the vehicle's `damageStickers` (an ALL_CLIENTS
	// property), one `VEHICLE_HIT_POINT` per pierced hit whose segment
	// context is the sticker id. The client's `addDamageSticker` draws it.
	if res.Pierced && sh.HasPiercedSticker {
		sticker := hitPointValue(encodeHitSegment(res.Bounds, res.Local, res.LocalDir, res.Part, sh.PiercedSticker), hitParams(sh, hitEffectPierced))
		s.mu.Lock()
		st.dummyStickers = append(st.dummyStickers, sticker)
		stickers := append([]entdef.Value(nil), st.dummyStickers...)
		s.mu.Unlock()
		dummy.Set("damageStickers", entdef.Value{Kind: entdef.VSeq, Seq: stickers})
		if el, err := EncodePropertyUpdate(dummy, "damageStickers"); err == nil {
			dummyApp = append(dummyApp, el...)
		}
	}
	if damage > 0 {
		dummy.SetInt("health", int64(newHealth))
		// A bare property is `[id][value]`, with NO length:
		// `EncodePropertyUpdate`'s `[id][u16 len][value]` is the
		// `updateEntity` run's form, and sending it standalone makes the
		// client read the length as the health and the value's low byte as
		// the next element id (health 926 = 0x039E → element `0x9E` =
		// exposed method 80, out of range on the 11-method Vehicle).
		dummyApp = append(dummyApp, EncodeBareU16(elVehicleHealth, uint16(newHealth))...)
		if el, err := onHealthChangedElement(dummy, newHealth, oldHealth, attacker); err == nil {
			dummyApp = append(dummyApp, el...)
		}
	}
	// A kill also goes into the arena's `vehiclesInfo`.
	if newHealth == 0 && damage > 0 {
		if el := s.killVehiclesInfo(st, dummyID, attacker); len(el) > 0 {
			dummyApp = append(dummyApp, el...)
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
	if el, err := showShotResultsElement(avatar, dummyID, flags); err == nil {
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
		events = append(events, battleEvent{eventType: battleEventDamage, targetID: dummyID, details: details, count: uint16(damage)})
	}
	if newHealth == 0 && damage > 0 {
		events = append(events, battleEvent{eventType: battleEventKill, targetID: dummyID, details: packDamage(uint64(damage), 0, uint64(battleLogShellType(sh.Kind)), -1), count: 1})
	}
	if len(events) > 0 {
		if el, err := onBattleEventsElement(avatar, events); err == nil {
			avatarApp = append(avatarApp, el...)
		}
	}
	s.mu.Lock()
	st.dummyHealth = newHealth
	st.damageDealt += uint32(damage)
	damageDealt := st.damageDealt
	comp := st.ownVehicle
	s.mu.Unlock()
	if el, err := battleEventsSummaryElement(comp, damageDealt); err == nil {
		avatarApp = append(avatarApp, el...)
	}

	st.sendMu.Lock()
	for _, app := range [][]byte{dummyApp, avatarApp} {
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
	s.logf("arena %d: shot %s hit dummy %d: %d damage (health %d -> %d, pierced=%v, armor=%.1f)",
		arenaID, sh.Name, dummyID, damage, oldHealth, newHealth, res.Pierced, res.Armor)
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
func (s *BaseAppServer) killVehiclesInfo(st *clientState, dummyID, attacker uint32) []byte {
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
	if st.infoComp.TypeID == 0 || st.infoDummy < 0 || st.infoDummy >= len(st.infoVehicles) {
		s.mu.Unlock()
		return nil
	}
	victim := st.infoVehicles[st.infoDummy]
	victim = dictSet(victim, "isAlive", entdef.Value{Kind: entdef.VUint})
	victim = dictSet(victim, "deathInfo", entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "victimID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(dummyID)}},
		{Name: "killerID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(attacker)}},
		{Name: "reasonID", Value: entdef.Value{Kind: entdef.VInt}},
		{Name: "equipmentID", Value: entdef.Value{Kind: entdef.VInt}},
		{Name: "numVehiclesAffected", Value: entdef.Value{Kind: entdef.VInt}},
	}})
	st.infoVehicles[st.infoDummy] = victim
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
	dummyIdx := st.infoDummy
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
