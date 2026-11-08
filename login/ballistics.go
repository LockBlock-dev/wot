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
	// Target is the index into the session's targets of the vehicle hit, when
	// Kind is landingVehicle, and VHit where on its mesh.
	Target int
	VHit   vehicleHit
	// Dir is the shell's direction at the hit.
	Dir [3]float32
	// Material is the effect material the impact shows: the ground's for the
	// terrain, the static's own (stone, wood, metal) for a wall.
	Material uint8
}

const (
	landingVehicle uint8 = 0
	landingTerrain uint8 = 1
	landingRange   uint8 = 2
	// landingStatic is a space model the shell stopped on: a wall, a rock, or
	// a destructible it did not break through.
	landingStatic uint8 = 3
)

// traceTargets finds the nearest synthetic tank a segment meets, and where on
// its collision mesh.
//
// The segment is the flight's step, so it must not reach past the step's end:
// every part's triangles are tested, and the nearest crossing wins.
func traceTargets(targets []*botTarget, from, to [3]float32) (int, vehicleHit, bool) {
	best := -1
	var bestHit vehicleHit
	for i, t := range targets {
		if t == nil || t.dead.Load() || t.collision == nil {
			continue
		}
		h, ok := t.collision.firstHit(t.pos, t.yaw, from, to)
		if !ok {
			continue
		}
		if best < 0 || h.Distance < bestHit.Distance {
			best, bestHit = i, h
		}
	}
	return best, bestHit, best >= 0
}

// flyShell flies a shell and returns where it lands.
//
// terrain may be nil (no ground), targets are the vehicles it may meet, and
// statics the space's models. A destructible static the shell breaks is
// reported through onStatic, which returns whether the shell goes on through
// it (a fence, a tree) or stops there.
func flyShell(sh shellSpec, start, velocity [3]float32, terrain *Terrain, targets []*botTarget, statics *staticScene, onStatic func(staticTriangle) bool) shellLanding {
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
		// The statics first: a wall in front of a tank is what the shell meets.
		if statics != nil {
			if tri, t, ok := statics.segmentHit(pos, next); ok {
				point := lerp3(pos, next, t)
				if onStatic != nil && onStatic(tri) {
					// The shell broke it and goes on from there.
					pos = [3]float32{point[0] + vel[0]*0.002, point[1] + vel[1]*0.002, point[2] + vel[2]*0.002}
					continue
				}
				return shellLanding{
					Kind:     landingStatic,
					Point:    point,
					Velocity: lerp3(vel, nextVel, t),
					Material: staticEffectMaterial(tri),
					Distance: float32(math.Sqrt(float64(
						(point[0]-start[0])*(point[0]-start[0]) +
							(point[1]-start[1])*(point[1]-start[1]) +
							(point[2]-start[2])*(point[2]-start[2])))),
					Time: time + flightStep*t,
				}
			}
		}
		if idx, hit, ok := traceTargets(targets, pos, next); ok {
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
			dir := [3]float32{vel[0], vel[1], vel[2]}
			if l := float32(math.Sqrt(float64(dir[0]*dir[0] + dir[1]*dir[1] + dir[2]*dir[2]))); l > 1e-9 {
				dir = [3]float32{dir[0] / l, dir[1] / l, dir[2] / l}
			}
			return shellLanding{
				Kind:     landingVehicle,
				Point:    hit.Point,
				Velocity: lerp3(vel, nextVel, t),
				Distance: time*float32(sh.Speed) + fraction,
				Time:     time + flightStep*t,
				Target:   idx,
				VHit:     hit,
				Dir:      dir,
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
	material := landing.Material
	prefab := uint64(noPrefabEffects)
	if sh.HasPrefabEffectsIndex {
		prefab = uint64(sh.PrefabEffectsIndex)
	}
	args := []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(shotID)},
		{Kind: entdef.VUint, Uint: uint64(sh.EffectsIndex)},
		{Kind: entdef.VUint, Uint: prefab},
		{Kind: entdef.VUint, Uint: uint64(material)},
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
