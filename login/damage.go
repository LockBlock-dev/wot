package login

import (
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

// The dummy's hull box, in metres, and its armour in millimetres. The TOG II
// is a long, tall heavy; its defs give 76.2 mm on the front and sides, 50.8 on
// the rear and 25.4 on the roof.
const (
	dummyHalfLength float32 = 5.0
	dummyHalfWidth  float32 = 1.7
	dummyHeight     float32 = 2.8

	dummyArmorFront float32 = 76.2
	dummyArmorSide  float32 = 76.2
	dummyArmorRear  float32 = 50.8
	dummyArmorTop   float32 = 25.4
)

// `VEHICLE_HIT_EFFECT` codes the client's `DamageFromShotDecoder` maps to an
// effect group.
const (
	hitEffectPierced    uint8 = 4
	hitEffectNotPierced uint8 = 3
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
type hitBox struct {
	Center [3]float32
	Half   [3]float32
	Yaw    float32
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
	Local    [3]float32 // the hit point in the hull's frame
	LocalDir [3]float32 // the shell's direction in the hull's frame
	Normal   [3]float32 // world, outward
	Distance float32
	Armor    float32 // effective, after the impact angle
	Pierced  bool
	Damage   int
	Effect   uint8
	Flags    uint32
}

// resolveShot traces one shell against the dummy's hull box and rolls its
// penetration and damage.
func resolveShot(sh shellSpec, origin, dir [3]float32, box hitBox) shotResult {
	t, point, normal, localNormal, face, ok := box.intersect(origin, dir)
	if !ok {
		return shotResult{}
	}
	armor := dummyArmorForFace(face, localNormal)
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
	if res.Pierced {
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
	// The hit point and direction in the hull's frame, which is what the
	// client's hit-point segment is encoded over.
	c, s := cos32(box.Yaw), sin32(box.Yaw)
	lx := point[0] - box.Center[0]
	lz := point[2] - box.Center[2]
	res.Local = [3]float32{lx*c - lz*s, point[1] - box.Center[1], lx*s + lz*c}
	res.LocalDir = [3]float32{dir[0]*c - dir[2]*s, dir[1], dir[0]*s + dir[2]*c}
	return res
}

// dummyArmorForFace is the nominal armour of the hull face the shell met.
func dummyArmorForFace(face int, localNormal [3]float32) float32 {
	switch face {
	case 0:
		return dummyArmorSide
	case 1:
		return dummyArmorTop
	case 2:
		if localNormal[2] > 0 {
			return dummyArmorFront
		}
		return dummyArmorRear
	}
	return dummyArmorSide
}

// dummyBox is the dummy's hull box at its spawn, in world space.
func dummyBox(pos [3]float32, yaw float32) hitBox {
	return hitBox{
		Center: [3]float32{pos[0], pos[1] + dummyHeight/2, pos[2]},
		Half:   [3]float32{dummyHalfWidth, dummyHeight / 2, dummyHalfLength},
		Yaw:    yaw,
	}
}

// dummyBounds is the hull box in its own frame, the bounds the hit-point
// segment is quantized over.
func dummyBounds() [2][3]float32 {
	return [2][3]float32{
		{-dummyHalfWidth, -dummyHeight / 2, -dummyHalfLength},
		{dummyHalfWidth, dummyHeight / 2, dummyHalfLength},
	}
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
	attacker := st.vehicle.ID
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
	res := resolveShot(sh, marker.Position, dir, dummyBox(dummyPos, dummyYaw))
	if !res.Hit {
		return
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
	segment := encodeHitSegment(dummyBounds(), res.Local, res.LocalDir, 1, res.Effect)
	point := hitPointValue(segment, hitParams(sh, res.Effect))

	var els [][]byte
	// Select the dummy, then its damage and health.
	if el, err := EncodeSelectEntity(dummyID); err == nil {
		els = append(els, el)
	}
	if el, err := showDamageFromShotElement(dummy, attacker, point, sh.EffectsIndex, damage, uint8(damageFactor), sh.Speed); err == nil {
		els = append(els, el)
	}
	if damage > 0 {
		dummy.SetInt("health", int64(newHealth))
		if el, err := EncodePropertyUpdate(dummy, "health"); err == nil {
			els = append(els, el)
		}
		if el, err := onHealthChangedElement(dummy, newHealth, oldHealth, attacker); err == nil {
			els = append(els, el)
		}
	}
	// The shooter's own view: the shell and the hit marker.
	els = append(els, EncodeSelectPlayerEntity())
	if el, err := showTracerElement(avatar, attacker, shotID, sh, marker.Position, marker.Velocity); err == nil {
		els = append(els, el)
	}
	if el, err := stopTracerElement(avatar, shotID, res.Point); err == nil {
		els = append(els, el)
	}
	if el, err := showShotResultsElement(avatar, dummyID, flags); err == nil {
		els = append(els, el)
	}

	s.mu.Lock()
	st.dummyHealth = newHealth
	s.mu.Unlock()

	st.sendMu.Lock()
	for _, el := range els {
		seq, cumul := s.nextSeq(st)
		if err := s.sendReliableLocked(conn, from, st, el, seq, cumul); err != nil {
			s.logf("arena %d: shot: send failed: %v", arenaID, err)
			break
		}
	}
	st.sendMu.Unlock()
	s.logf("arena %d: shot %s hit dummy %d: %d damage (health %d -> %d, pierced=%v, armor=%.1f)",
		arenaID, sh.Name, dummyID, damage, oldHealth, newHealth, res.Pierced, res.Armor)
}
