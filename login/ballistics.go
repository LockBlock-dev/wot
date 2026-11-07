package login

import (
	"math"

	"github.com/LockBlock-dev/wot/entdef"
)

// A shell's flight.
//
// The official server flies the shell: it leaves the gun at the shell's speed,
// gravity pulls it down, and it lands on the first vehicle it meets, on the
// terrain, or at the shell's `maxDistance`. What it hits decides everything
// downstream — the penetration falls off with the distance flown, the impact
// angle with the trajectory, and a shot that lands on the ground is an
// explosion the client draws.
//
// Ported from the reference's `gun.rs` `fly`.

// flightStep is the length of one flight step, in seconds.
const flightStep = 0.005

// explosionStep is how long the last step `explodeProjectile` gives is: the
// client projects the crater along it.
const explosionStep = 0.05

// noPrefabEffects is `INVALID_EFFECT_INDEX`: the client then plays only the
// legacy shot effects.
const noPrefabEffects uint8 = 255

// groundEffectMaterial is the `ground` effect material's index.
const groundEffectMaterial uint8 = 0

// shellLanding is where a shell's flight ends.
type shellLanding struct {
	// Kind is what it hit: landingVehicle, landingTerrain or landingRange.
	Kind uint8
	// Point is where it landed, in the world.
	Point [3]float32
	// Velocity is its velocity there, in m/s.
	Velocity [3]float32
	// Distance is how far it flew, in metres.
	Distance float32
	// Time is how long it flew, in seconds.
	Time float32
	// Hit is the vehicle hit, when Kind is landingVehicle.
	Hit shotResult
}

const (
	landingVehicle uint8 = 0
	landingTerrain uint8 = 1
	landingRange   uint8 = 2
)

// traceShot traces a SEGMENT against the boxes and returns the nearest hit.
//
// The ray form is `resolveShot`; this is the flight's step, which ends at the
// step's end and must not reach past it.
func traceShot(sh shellSpec, from, to [3]float32, boxes []hitBox, distanceOffset float64) shotResult {
	d := [3]float32{to[0] - from[0], to[1] - from[1], to[2] - from[2]}
	length := float32(math.Sqrt(float64(d[0]*d[0] + d[1]*d[1] + d[2]*d[2])))
	if length < 1e-9 {
		return shotResult{}
	}
	dir := [3]float32{d[0] / length, d[1] / length, d[2] / length}
	var res shotResult
	for _, box := range boxes {
		t, point, normal, localNormal, face, ok := box.intersect(from, dir)
		if !ok || t > length || (res.Hit && t >= res.Distance) {
			continue
		}
		res = rollShot(sh, box, t, point, normal, localNormal, face, dir, distanceOffset+float64(t))
	}
	return res
}

// flyShell flies a shell and returns where it lands.
//
// terrain may be nil (no ground), and boxes are the vehicles it may meet.
func flyShell(sh shellSpec, start, velocity [3]float32, terrain *Terrain, boxes []hitBox) shellLanding {
	pos, vel := start, velocity
	time := float32(0)
	gravity := float32(sh.Gravity)
	if gravity < 0 {
		gravity = -gravity
	}
	maxDistance := float32(sh.MaxDistance)
	if maxDistance <= 0 {
		maxDistance = 720
	}
	for {
		next := [3]float32{
			pos[0] + vel[0]*flightStep,
			pos[1] + vel[1]*flightStep,
			pos[2] + vel[2]*flightStep,
		}
		nextVel := [3]float32{vel[0], vel[1] - gravity*flightStep, vel[2]}
		if hit := traceShot(sh, pos, next, boxes, float64(time)*float64(sh.Speed)); hit.Hit {
			fraction := hit.Distance
			step := float32(math.Sqrt(float64(
				(next[0]-pos[0])*(next[0]-pos[0]) +
					(next[1]-pos[1])*(next[1]-pos[1]) +
					(next[2]-pos[2])*(next[2]-pos[2]))))
			t := float32(0)
			if step > 0 {
				t = fraction / step
			}
			if t < 0 {
				t = 0
			}
			if t > 1 {
				t = 1
			}
			hit.Distance = time*float32(sh.Speed) + fraction
			return shellLanding{
				Kind:     landingVehicle,
				Point:    hit.Point,
				Velocity: lerp3(vel, nextVel, t),
				Distance: hit.Distance,
				Time:     time + flightStep*t,
				Hit:      hit,
			}
		}
		if terrain != nil {
			if ground, ok := terrain.HeightAt(next[0], next[2]); ok && next[1] <= ground {
				above := pos[1] - ground
				if prev, ok := terrain.HeightAt(pos[0], pos[2]); ok {
					above = pos[1] - prev
				}
				below := ground - next[1]
				t := float32(0)
				if above+below > 0 {
					t = above / (above + below)
				}
				if t < 0 {
					t = 0
				}
				if t > 1 {
					t = 1
				}
				point := lerp3(pos, next, t)
				return shellLanding{
					Kind:     landingTerrain,
					Point:    point,
					Velocity: lerp3(vel, nextVel, t),
					Distance: float32(math.Sqrt(float64(
						(point[0]-start[0])*(point[0]-start[0]) +
							(point[1]-start[1])*(point[1]-start[1]) +
							(point[2]-start[2])*(point[2]-start[2])))),
					Time: time + flightStep*t,
				}
			}
		}
		flew := float32(math.Sqrt(float64(
			(next[0]-start[0])*(next[0]-start[0]) +
				(next[1]-start[1])*(next[1]-start[1]) +
				(next[2]-start[2])*(next[2]-start[2]))))
		if flew >= maxDistance {
			return shellLanding{
				Kind:     landingRange,
				Point:    next,
				Velocity: nextVel,
				Distance: flew,
				Time:     time + flightStep,
			}
		}
		pos, vel = next, nextVel
		time += flightStep
	}
}

// explodeProjectileElement is `Avatar.explodeProjectile`: the ground explosion
// the client draws for a shot that lands on the terrain.
//
// Its args are `(SHOT_ID, effectsIndex, prefabEffectsIndex, material,
// kindIndex, caliber, position, velocity, speed, ARRAY<UINT32>)`; the velocity
// is the last flight step's, which the client projects the crater along.
func explodeProjectileElement(avatar *Entity, shotID uint32, sh shellSpec, landing shellLanding) ([]byte, error) {
	prefab := uint64(noPrefabEffects)
	if sh.HasPrefabEffectsIndex {
		prefab = uint64(sh.PrefabEffectsIndex)
	}
	args := []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(shotID)},
		{Kind: entdef.VUint, Uint: uint64(sh.EffectsIndex)},
		{Kind: entdef.VUint, Uint: prefab},
		{Kind: entdef.VUint, Uint: uint64(groundEffectMaterial)},
		{Kind: entdef.VUint, Uint: uint64(sh.KindIndex)},
		{Kind: entdef.VFloat, Float: float64(sh.Caliber / 1000)},
		{Kind: entdef.VSeq, Seq: []entdef.Value{
			{Kind: entdef.VFloat, Float: float64(landing.Point[0])},
			{Kind: entdef.VFloat, Float: float64(landing.Point[1])},
			{Kind: entdef.VFloat, Float: float64(landing.Point[2])},
		}},
		{Kind: entdef.VSeq, Seq: []entdef.Value{
			{Kind: entdef.VFloat, Float: float64(landing.Velocity[0] * explosionStep)},
			{Kind: entdef.VFloat, Float: float64(landing.Velocity[1] * explosionStep)},
			{Kind: entdef.VFloat, Float: float64(landing.Velocity[2] * explosionStep)},
		}},
		{Kind: entdef.VFloat, Float: float64(math.Sqrt(float64(
			landing.Velocity[0]*landing.Velocity[0] +
				landing.Velocity[1]*landing.Velocity[1] +
				landing.Velocity[2]*landing.Velocity[2])))},
		{Kind: entdef.VSeq, Seq: nil},
	}
	return EncodeClientMethodCall(avatar, "explodeProjectile", args)
}
