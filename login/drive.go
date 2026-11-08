package login

import (
	"encoding/binary"
	"math"
)

// The player's tank, driven by the client's `vehicle_moveWith` flags.
//
// The real server simulates the vehicle's physics and streams the result; this
// is a stand-in, not the engine's track model — the hull moves and turns at the
// vehicle's own limits and rests on the terrain, with no collision, slope
// resistance or engine model. It does keep velocity in world space and model
// the tracks' lateral grip, which is what makes the handbrake slide instead of
// stopping dead. What matters is that the client's own prediction agrees with
// it: the client drives its hull locally and corrects toward whatever the
// server sends, so a server that never moves leaves the tank stuck at the
// spawn.
//
// The flags are `MOVEMENT_FLAGS` in the client's `Avatar.py`.

const (
	moveForward         uint8 = 1
	moveBackward        uint8 = 2
	moveRotateLeft      uint8 = 4
	moveRotateRight     uint8 = 8
	moveCruiseControl50 uint8 = 16
	moveCruiseControl25 uint8 = 32
	// moveBlockTracks is the handbrake (space): `CMD_BLOCK_TRACKS` in the
	// client's key map, which `Avatar.moveVehicle` folds into the same flag
	// byte it sends to `cell.vehicle_moveWith`. It locks the tracks, so the
	// tank brakes to a stop and cannot pivot on the spot.
	moveBlockTracks uint8 = 64
)

// How quickly the speed reaches what the flags ask for, in m/s², and how
// hard the tracks hold the hull against sideways motion.
const (
	// hullAcceleration is the longitudinal acceleration the engine can
	// produce. The real value comes from the engine's power and the
	// vehicle's weight; this is the stand-in the reference uses.
	hullAcceleration float32 = 4.0
	// hullBraking is the deceleration when the driver lifts off or reverses.
	hullBraking float32 = 10.0
	// hullHandbrakeBraking is the deceleration with the tracks locked. It is
	// lower than hullBraking so the hull keeps enough momentum to slide.
	hullHandbrakeBraking float32 = 7.0
	// hullGrip is the lateral acceleration the tracks can hold, in m/s².
	// High grip keeps the velocity aligned with the heading.
	hullGrip float32 = 30.0
	// hullHandbrakeGrip is the lateral grip with the tracks locked. The
	// tracks can no longer resist sideways motion, so the hull slides.
	hullHandbrakeGrip float32 = 5.0
	// handbrakeSteer is the steering authority left with the handbrake on.
	// A moving hull still steers (the wheeled vehicles steer their front
	// wheels), but with less bite than the tracks give.
	handbrakeSteer float32 = 0.7
	// handbrakePivotSpeed is the speed below which a handbraking hull cannot
	// pivot on the spot: the tracks are locked, so there is no differential
	// steering to turn with.
	handbrakePivotSpeed float32 = 0.5
	// handbrakeFullSteerSpeed is the speed at which a handbraking hull still
	// has full steering authority; below it the bite falls with the speed, so
	// the drift settles instead of spinning as the hull slows.
	handbrakeFullSteerSpeed float32 = 15.0
	// gravity is the engine's, m/s².
	gravity float32 = 9.81
	// hullLandingEpsilon is how close to the ground counts as landed.
	hullLandingEpsilon float32 = 0.05
	// hullSuspensionTravel is how far the hull can drop relative to the ground
	// in one tick before the tracks leave it, in metres: the suspension's
	// travel. A convex break (a ledge) drops the ground further than this in
	// one tick and the hull goes airborne.
	hullSuspensionTravel float32 = 0.3
	// hullMaxFollowSlope is the steepest slope the tracks can drive down, as
	// tan(angle): 1.0 is 45°. Ground steeper than this is fallen off, not
	// driven down — the heightmap turns a cliff into a steep ramp over one
	// cell, and without this the tank follows that ramp instead of flying off
	// it.
	hullMaxFollowSlope float32 = 1.0
)

// The reference's fitted physics, ported: the engine's power over its weight
// gives the drive, the ground's rolling friction the resistance, and the turn
// rate rises and falls over these times instead of snapping.
const (
	// powerFactor scales the engine's power into the drive the reference
	// measured on the real server.
	powerFactor float32 = 1.13
	// maxAcceleration caps the drive, in m/s².
	maxAcceleration float32 = 10.0
	// hullCoasting and hullBraking are the decelerations without a drive and
	// against it, in m/s².
	hullCoasting float32 = 14.0
	hullBraking2 float32 = 14.0
	// rotationOnMove is the share of the on-the-spot turn rate a moving hull
	// keeps.
	rotationOnMove float32 = 0.85
	// turningResistance is the extra resistance a turning hull fights, m/s².
	turningResistance float32 = 0.8
	// rotationRise and rotationFall are the times the yaw rate takes to reach
	// its goal and to fall back, in seconds.
	rotationRise float32 = 0.3
	rotationFall float32 = 0.2
	// pivotRadius is how far the blocked inner track is from the hull's
	// centre, in metres: driving into a turn with the tracks locked pivots it
	// on that track.
	pivotRadius float32 = 2.5
	// onSpotSpeed is the speed below which a turning hull counts as turning on
	// the spot.
	onSpotSpeed float32 = 0.5
	// boundsMargin keeps the hull's centre this far inside the map's bounds,
	// in metres. It is zero: the official server stops the hull's CENTRE at
	// the red line, so a tank can hang a track over it. A margin pushed the
	// whole hull inside and made the line feel like a wall.
	boundsMargin float32 = 0
	// edgeFriction is the share of the speed into the map's edge the tracks
	// lose along it.
	edgeFriction float32 = 0.5
)

// groundIndex maps a terrain ground to the defs' firm/medium/soft order.
func groundIndex(g uint8) int {
	switch g {
	case groundMedium:
		return 1
	case groundSoft:
		return 2
	}
	return 0
}

// approach moves v toward target by at most step.
func approach(v, target, step float32) float32 {
	if v < target {
		if v+step > target {
			return target
		}
		return v + step
	}
	if v-step < target {
		return target
	}
	return v - step
}

// Where the hull is sampled to tilt it with the ground: half its length and
// width, a typical tank's rather than the vehicle's own.
const (
	hullHalfLength float32 = 3.0
	hullHalfWidth  float32 = 1.7
)

// The engine's relative RPM at idle and just after shifting up, and the shares
// of the top speed the gearbox shifts up at (4 gears), as the reference reads
// them off the captured server.
const (
	idleRPM  float32 = 0.2
	shiftRPM float32 = 0.3
)

var gearShifts = [3]float32{0.27, 0.52, 0.8}

// motionLimits is a vehicle's movement limits, from its item defs.
type motionLimits struct {
	SpeedForward  float32
	SpeedBackward float32
	RotationSpeed float32
	// RotationSpeedByGround is the turn rate on firm, medium and soft ground,
	// in rad/s: the chassis' `rotationSpeed` on firm and slower on the others
	// as their `terrainResistance` rises, which is how the client's
	// `vehicles.py` derives `rotationSpeedLimit`.
	RotationSpeedByGround [3]float32
	// RollingFrictionByGround is the share of its weight each ground holds the
	// hull back with, from the vehicle's `physics/detailed` section.
	RollingFrictionByGround [3]float32
	// EnginePower is the engine's power in W and Weight the vehicle's mass in
	// kg, from the same section.
	EnginePower float32
	Weight      float32
	// CarryingPoint is where the front right track rests on the ground, from
	// the vehicle's centre: across to the track's centre, and along.
	CarryingPoint [2]float32
}

// hull is the player's tank as this server simulates it.
type hull struct {
	// Position is the hull's origin in the world.
	Position [3]float32
	// Direction is roll, pitch and yaw in radians, the order the position
	// updates carry them. A yaw of 0 faces +Z, and turning right increases it.
	Direction [3]float32
	// Velocity is the hull's world-space velocity in the XZ plane. It is
	// kept in world space, not in the hull frame: the hull turns under its
	// momentum, and the lateral component left behind is the slip angle the
	// tracks grip against — and, with the handbrake on, the slide that reads
	// as a drift.
	Velocity [2]float32
	// Speed is the signed longitudinal component of Velocity, in m/s: what
	// the engine, the track scroll and the dispersion model read.
	Speed float32
	// YawRate is in rad/s.
	YawRate float32
	// VerticalVelocity is the hull's vertical speed in m/s, negative falling.
	// Gravity owns it while the hull is airborne.
	VerticalVelocity float32
	// Airborne is true while the hull is off the ground: the terrain fell
	// away faster than the tracks could follow, and the height is the
	// trajectory's until it lands.
	Airborne bool
	// AirborneWhy records the drop, the expected drop and the ground's own
	// drop when the hull last left the ground, for the log.
	AirborneWhy [3]float32
	// Flags is the latest `vehicle_moveWith` byte.
	Flags  uint8
	Limits motionLimits
}

// targetSpeed is the speed the flags ask for: the top speed in their direction,
// reduced by cruise control.
func (h *hull) targetSpeed() float32 {
	if h.Flags&moveBlockTracks != 0 {
		return 0
	}
	share := float32(1)
	if h.Flags&moveCruiseControl25 != 0 {
		share = 0.25
	} else if h.Flags&moveCruiseControl50 != 0 {
		share = 0.5
	}
	switch {
	case h.Flags&moveForward != 0:
		return h.Limits.SpeedForward * share
	case h.Flags&moveBackward != 0:
		return -h.Limits.SpeedBackward * share
	}
	return 0
}

// step advances the hull by dt seconds. It reports whether the hull moved or
// turned, which is what decides whether a position update is worth sending.
func (h *hull) step(dt float32, ground uint8) bool {
	if dt <= 0 {
		return false
	}
	// Airborne: no tracks on the ground, so gravity owns the height, the hull
	// keeps its horizontal velocity and it cannot steer.
	if h.Airborne {
		h.VerticalVelocity -= gravity * dt
		h.Position[1] += h.VerticalVelocity * dt
		h.Position[0] += h.Velocity[0] * dt
		h.Position[2] += h.Velocity[1] * dt
		h.YawRate = 0
		return true
	}
	gi := groundIndex(ground)
	rotationSpeed := h.Limits.RotationSpeedByGround[gi]
	if rotationSpeed == 0 {
		rotationSpeed = h.Limits.RotationSpeed
	}
	yaw := h.Direction[2]
	// The hull frame: +Z at yaw 0, +X to the right.
	fx, fz := sin32(yaw), cos32(yaw)
	rx, rz := cos32(yaw), -sin32(yaw)

	// Split the world velocity into the hull's longitudinal and lateral
	// components.
	vLong := h.Velocity[0]*fx + h.Velocity[1]*fz
	vLat := h.Velocity[0]*rx + h.Velocity[1]*rz

	handbrake := h.Flags&moveBlockTracks != 0

	var turn float32
	switch h.Flags & (moveRotateLeft | moveRotateRight) {
	case moveRotateLeft:
		turn = -1
	case moveRotateRight:
		turn = 1
	}
	// Backing up steers like a car: left swings the rear to the left.
	if h.Flags&moveBackward != 0 {
		turn = -turn
	}
	var driveWay float32
	switch h.Flags & (moveForward | moveBackward) {
	case moveForward:
		driveWay = 1
	case moveBackward:
		driveWay = -1
	}
	// On its handbrake, driving into a turn pivots it on the blocked inner
	// track, its outer one carrying it around at this speed.
	pivot := driveWay * abs32(turn) * rotationSpeed * rotationOnMove * pivotRadius

	// The slope pulls it down: the pitch is positive nose down, so a downhill
	// accelerates it forward.
	slope := gravity * sin32(h.Direction[1])

	// Lateral: the tracks hold the hull against sideways motion. Locking them
	// drops that grip, so the hull keeps its velocity vector while the yaw
	// turns under it — the slide that reads as a drift.
	gripAcross := hullGrip
	if handbrake {
		gripAcross = hullHandbrakeGrip
	}
	vLat = approach(vLat, 0, gripAcross*dt)

	target := h.targetSpeed()
	way := float32(0)
	if target > 0 {
		way = 1
	} else if target < 0 {
		way = -1
	}
	switch {
	case handbrake:
		vLong = approach(vLong+slope*dt, pivot, hullHandbrakeBraking*dt)
	case target == 0:
		vLong = approach(vLong+slope*dt, 0, hullCoasting*dt)
	case vLong*way < 0:
		vLong = approach(vLong+slope*dt, 0, hullBraking2*dt)
	default:
		// Along its way: the drive, less the ground's resistance, and the
		// slope. The drive is the engine's power over its weight and its
		// speed, capped; without the defs' figures it falls back to the
		// stand-in acceleration.
		along := abs32(vLong)
		drive := hullAcceleration
		if h.Limits.EnginePower > 0 && h.Limits.Weight > 0 {
			drive = powerFactor * h.Limits.EnginePower / h.Limits.Weight / max32(along, 1e-3)
			if drive > maxAcceleration {
				drive = maxAcceleration
			}
		}
		resistance := h.Limits.RollingFrictionByGround[gi] * gravity
		if turn != 0 {
			resistance += turningResistance
		}
		if along > abs32(target) {
			along = approach(along, abs32(target), hullBraking2*dt)
		} else {
			// Short of power it stalls, unless the slope takes it back down
			// past what its tracks hold.
			floor := float32(0)
			if slope*way+hullBraking2 < 0 {
				floor = -1e9
			}
			along = clamp32(along+(drive-resistance+slope*way)*dt, floor, abs32(target))
		}
		vLong = along * way
	}

	// Recompose in the frame the forces acted in. The yaw update below does
	// NOT rotate this vector: the hull turns under its momentum, and the
	// lateral component that leaves behind is what the next tick grips
	// against.
	h.Velocity[0] = fx*vLong + rx*vLat
	h.Velocity[1] = fz*vLong + rz*vLat
	h.Speed = vLong

	// Yaw: the steering turns the hull, and the rate rises and falls over the
	// reference's times instead of snapping.
	goal := turn * rotationSpeed
	if handbrake {
		if abs32(vLong) < handbrakePivotSpeed {
			goal = 0
		} else {
			goal *= handbrakeSteer * min32(abs32(vLong)/handbrakeFullSteerSpeed, 1)
		}
	} else if abs32(vLong) >= onSpotSpeed || target != 0 {
		goal *= rotationOnMove
	}
	rise := rotationRise
	if goal == 0 || goal*h.YawRate < 0 {
		rise = rotationFall
	}
	h.YawRate = approach(h.YawRate, goal, rotationSpeed/rise*dt)
	h.Direction[2] = wrapAngle(yaw + h.YawRate*dt)

	h.Position[0] += h.Velocity[0] * dt
	h.Position[2] += h.Velocity[1] * dt
	return h.Velocity[0] != 0 || h.Velocity[1] != 0 || h.YawRate != 0
}

// keepWithin clamps the hull's centre inside the map's bounds, `boundsMargin`
// inside them: what of its velocity goes into an edge stops, and the rest is
// slowed by edgeFriction along it.
func (h *hull) keepWithin(minX, minZ, maxX, maxZ float32) {
	minX += boundsMargin
	minZ += boundsMargin
	maxX -= boundsMargin
	maxZ -= boundsMargin
	var stopped [2]float32
	if h.Position[0] < minX {
		h.Position[0] = minX
		if h.Velocity[0] < 0 {
			stopped[0] = h.Velocity[0]
			h.Velocity[0] = 0
		}
	} else if h.Position[0] > maxX {
		h.Position[0] = maxX
		if h.Velocity[0] > 0 {
			stopped[0] = h.Velocity[0]
			h.Velocity[0] = 0
		}
	}
	if h.Position[2] < minZ {
		h.Position[2] = minZ
		if h.Velocity[1] < 0 {
			stopped[1] = h.Velocity[1]
			h.Velocity[1] = 0
		}
	} else if h.Position[2] > maxZ {
		h.Position[2] = maxZ
		if h.Velocity[1] > 0 {
			stopped[1] = h.Velocity[1]
			h.Velocity[1] = 0
		}
	}
	if stopped[0] == 0 && stopped[1] == 0 {
		return
	}
	// Along the edge, slowed as much as its friction takes of what it stopped.
	along := [2]float32{}
	if stopped[0] != 0 {
		along[1] = h.Velocity[1]
	} else {
		along[0] = h.Velocity[0]
	}
	share := edgeFriction * float32(math.Hypot(float64(stopped[0]), float64(stopped[1])))
	if n := float32(math.Hypot(float64(along[0]), float64(along[1]))); n > share && n > 0 {
		k := (n - share) / n
		h.Velocity[0] *= k
		h.Velocity[1] *= k
	} else {
		h.Velocity[0] *= 0
		h.Velocity[1] *= 0
	}
}

// settle rests the hull on the terrain: at its height, rolled and pitched with
// its slope. It reports whether the ground was found — off the map there is
// none, and the caller has to refuse the move rather than let the tank drive
// out over the edge and fall.
//
// The vertical axis is a BODY ON THE GROUND, not a snap. While it follows the
// terrain its vertical speed is the ground's own slope rate, so a constant
// slope (however steep) is driven down smoothly. The hull only leaves the
// ground when the terrain drops away faster than that speed plus what gravity
// adds in the tick — a convex break, i.e. a ledge or a cliff — and then
// gravity owns its height until it lands. The old rule compared the drop to
// the hull's HORIZONTAL step against a fixed 45° slope, which followed every
// ledge a tank could drive over: the tank was glued to the ground and could
// never jump.
func (h *hull) settle(tr *Terrain, dt float32) bool {
	if tr == nil {
		return false
	}
	height := func(dx, dz float32) (float32, bool) {
		return tr.HeightAt(h.Position[0]+dx, h.Position[2]+dz)
	}
	center, ok := height(0, 0)
	if !ok {
		return false
	}
	if h.Airborne {
		h.VerticalVelocity -= gravity * dt
		h.Position[1] += h.VerticalVelocity * dt
		if h.Position[1] <= center+hullLandingEpsilon && h.VerticalVelocity <= 0 {
			h.Position[1] = center
			h.VerticalVelocity = 0
			h.Airborne = false
		} else {
			// Still in the air: pitch with the trajectory, keep the roll.
			if speed := float32(math.Hypot(float64(h.Velocity[0]), float64(h.Velocity[1]))); speed > 0.1 {
				h.Direction[1] = atan32(-h.VerticalVelocity / speed)
			}
			return true
		}
	} else {
		// Grounded: the terrain falls at `drop` over this tick. A hull
		// following the ground would descend by the terrain's own drop along
		// its travel, so the suspension only has to absorb the DIFFERENCE —
		// a convex break (a ledge) drops further than the suspension's travel
		// and the hull goes airborne, while a slope, however steep, is
		// followed exactly.
		drop := h.Position[1] - center
		expected := h.groundDrop(height, dt)
		// The steepest descent the tracks can follow this tick.
		if speed := float32(math.Hypot(float64(h.Velocity[0]), float64(h.Velocity[1]))); speed*dt*hullMaxFollowSlope < expected {
			expected = speed * dt * hullMaxFollowSlope
		}
		if drop > expected+hullSuspensionTravel {
			h.Airborne = true
			h.AirborneWhy = [3]float32{drop, expected, h.Position[1] - center}
			return true
		}
		h.VerticalVelocity = -drop / dt
		h.Position[1] = center
	}
	yaw := h.Direction[2]
	// The corners its tracks rest on: the chassis' `topRightCarryingPoint`
	// when the defs give it, else a typical tank's half length and width.
	along, across := hullHalfLength, hullHalfWidth
	if h.Limits.CarryingPoint[0] > 0 && h.Limits.CarryingPoint[1] > 0 {
		across, along = h.Limits.CarryingPoint[0], h.Limits.CarryingPoint[1]
	}
	fx, fz := sin32(yaw)*along, cos32(yaw)*along
	rx, rz := cos32(yaw)*across, -sin32(yaw)*across
	front, ok1 := height(fx, fz)
	back, ok2 := height(-fx, -fz)
	right, ok3 := height(rx, rz)
	left, ok4 := height(-rx, -rz)
	if ok1 && ok2 {
		// Pitched positively nose down.
		h.Direction[1] = -atan32((front - back) / (2 * along))
	}
	if ok3 && ok4 {
		// Rolled positively with its right side up.
		h.Direction[0] = atan32((right - left) / (2 * hullHalfWidth))
	}
	return true
}

// engineMode is `Vehicle.engineMode`, which the client's track scroll follows:
// idle (1) without flags, accelerating (3) until at the speed the flags ask
// for, then cruising (2), and the flags themselves.
func (h *hull) engineMode() [2]byte {
	mode := byte(2)
	switch {
	case h.Flags == 0:
		mode = 1
	case h.Flags&moveBlockTracks != 0:
		// The tracks are locked: the engine is off the drivetrain and idles
		// while the hull slides.
		mode = 1
	case abs32(h.targetSpeed()-h.Speed) > 0.01:
		mode = 3
	}
	return [2]byte{mode, h.Flags}
}

// engine is the gearbox's gear and the engine's RPM relative to its maximum,
// which the client's engine sound follows. In neutral (gear 0) at idle RPM when
// still, else the speed's share of the top speed picks a gear and the RPM goes
// from shiftRPM to 1 across it; turning in place, the RPM follows the turn rate
// in first gear.
func (h *hull) engine() (byte, float32) {
	// With the tracks locked the drivetrain is not driving the hull; the
	// engine sits at idle while the hull slides.
	if h.Flags&moveBlockTracks != 0 {
		return 0, idleRPM
	}
	top := h.Limits.SpeedForward
	if h.Speed < 0 {
		top = h.Limits.SpeedBackward
	}
	if top < 0.1 {
		top = 0.1
	}
	share := min32(abs32(h.Speed)/top, 1)
	turnLimit := h.Limits.RotationSpeed
	if turnLimit < 0.01 {
		turnLimit = 0.01
	}
	turnShare := min32(abs32(h.YawRate)/turnLimit, 1)
	if share < 0.02 {
		if turnShare < 0.02 {
			return 0, idleRPM
		}
		return 1, shiftRPM + (1-shiftRPM)*turnShare
	}
	gear := 0
	for _, shift := range gearShifts {
		if share >= shift {
			gear++
		}
	}
	low := float32(0)
	if gear > 0 {
		low = gearShifts[gear-1]
	}
	high := float32(1)
	if gear < len(gearShifts) {
		high = gearShifts[gear]
	}
	inGear := clamp32((share-low)/(high-low), 0, 1)
	return byte(gear + 1), shiftRPM + (1-shiftRPM)*inGear
}

// groundDrop is how far the ground descends along the hull's travel over dt,
// from the terrain's gradient at the position the hull CAME FROM: what a hull
// following the ground would drop this tick. A convex break drops further than
// this, and that difference is what the suspension has to absorb.
//
// The gradient is sampled behind the hull on purpose. Sampled at the new
// position it already sees the ledge's face, calls the drop followable and the
// tank drives down the cliff instead of flying off it.
func (h *hull) groundDrop(height func(dx, dz float32) (float32, bool), dt float32) float32 {
	speed := float32(math.Hypot(float64(h.Velocity[0]), float64(h.Velocity[1])))
	if speed < 0.01 {
		return 0
	}
	const probe float32 = 0.5
	backX, backZ := -h.Velocity[0]/speed*probe, -h.Velocity[1]/speed*probe
	// Forward and back along the travel line, around where the hull was.
	ax, az := h.Velocity[0]/speed*probe, h.Velocity[1]/speed*probe
	behind, ok1 := height(backX-ax, backZ-az)
	ahead, ok2 := height(backX+ax, backZ+az)
	if !ok1 || !ok2 {
		return 0
	}
	// The descent along the travel direction, positive going downhill.
	return -(ahead - behind) / (2 * probe) * speed * dt
}

// auxPhysicsData is the hull's attitude and its tracks' speeds, as the avatar's
// `ownVehicleAuxPhysicsData` carries them for the client to aim from and to
// animate the tracks with — `WoT.packAuxVehiclePhysicsData`'s layout, from the
// lowest bit: yaw on 15 bits over a turn, pitch on 12 bits over ±π/2, roll on 13
// bits over a turn, the left then right track speeds on 8 bits each over
// -15..30 m/s, and the engine's relative RPM on 8 bits over 0..1.2.
func (h *hull) auxPhysicsData() uint64 {
	// The inner track goes slower, the outer one faster. With the handbrake
	// on the tracks are locked: they do not scroll even while the hull
	// slides.
	left, right := float32(0), float32(0)
	if h.Flags&moveBlockTracks == 0 {
		turning := h.YawRate * hullHalfWidth
		left, right = h.Speed+turning, h.Speed-turning
	}
	_, rpm := h.engine()
	return packRange(rpm, 0, 1.2, 8)<<56 |
		packRange(right, -15, 30, 8)<<48 |
		packRange(left, -15, 30, 8)<<40 |
		packAngle(h.Direction[0], 13)<<27 |
		packRange(h.Direction[1], -math.Pi/2, math.Pi/2, 12)<<15 |
		packAngle(h.Direction[2], 15)
}

// packWheelScroll is `WoT.packWheelScroll`, the inverse of the client's
// `WoT.unpackWheelScroll` (`sub_142437050`):
//
//	value = (int8)byte * 0.19607845 - 24.90196
//
// i.e. a signed byte over [-50, 0] rad/s, 50/255 per step. The value is the
// wheel's angular speed, negative for forward travel.
func packWheelScroll(radPerSec float64) byte {
	const scale = 0.19607845
	const bias = 24.90196
	v := (radPerSec + bias) / scale
	if v < -128 {
		v = -128
	}
	if v > 127 {
		v = 127
	}
	return byte(int8(math.Round(v)))
}

// wheelsScroll is `Vehicle.wheelsScroll`: one packed byte per scrollable wheel,
// all turning at the hull's speed over their own radius.
func (h *hull) wheelsScroll(radii []float64) []byte {
	out := make([]byte, len(radii))
	for i, r := range radii {
		if r <= 0 {
			continue
		}
		out[i] = packWheelScroll(-float64(h.Speed) / r)
	}
	return out
}

// aimWorld is the point the driver is aiming at, in world space.
//
// The client sends `shotPoint - stabilisedVehPos` (`VehicleGunRotator.
// __trackPointOnServer`): an offset from the hull's POSITION in WORLD axes, not
// in the hull's frame. So it is added as it stands — rotating it by the hull yaw
// puts the aim point a hull-yaw's worth off, and because that error changes as
// the tank turns, the turret desyncs the moment it drives. Measured on a hull at
// yaw 2.938 with the aim 14.8 m along +Z: the client's own `getShotAngles` says
// -2.947 rad, and the rotated form gave 0.000.
//
// The world point is kept and the bearing re-derived from the current hull each
// tick, because the client only re-sends when the point changes.
func (h *hull) aimWorldPoint(local [3]float32) [3]float32 {
	return [3]float32{
		h.Position[0] + local[0],
		h.Position[1] + local[1],
		h.Position[2] + local[2],
	}
}

// aimLocalBearing is the world aim point's bearing in the hull frame, which is
// the turret yaw the client is aiming at.
func (h *hull) aimLocalBearing(world [3]float32) float32 {
	dx := world[0] - h.Position[0]
	dz := world[2] - h.Position[2]
	yaw := h.Direction[2]
	c, s := cos32(yaw), sin32(yaw)
	return atan2_32(dx*c-dz*s, dx*s+dz*c)
}

// packAngle is `gun_rotation_shared.encodeAngleToUint`: an angle over [-pi, pi)
// on the given number of bits.
func packAngle(angle float32, bits uint) uint64 {
	mask := uint64(1)<<bits - 1
	return uint64(round32(float64(mask+1)*(float64(angle)+math.Pi)/(2*math.Pi))) & mask
}

// packRange is `encodeRestrictedValueToUint`: a value over [lo, hi] on the given
// number of bits.
func packRange(v, lo, hi float32, bits uint) uint64 {
	t := float32(0)
	if hi != lo {
		t = (v - lo) / (hi - lo)
	}
	t = clamp32(t, 0, 1)
	mask := uint64(1)<<bits - 1
	return uint64(round32(float64(mask)*float64(t))) & mask
}

// Element ids for the volatile position updates. The player's own entity has no
// alias: `AvatarUpdatePlayerDetailed` always targets it, and its position is
// relative to the reference `RelativePosition` set just before.
const (
	elRelativePosition           = 0x16 // FIXED 12
	elAvatarUpdateAliasDetailed  = 0x1D // FIXED 26
	elAvatarUpdatePlayerDetailed = 0x1E // FIXED 25
)

// VehicleAlias is the AoI alias the player's own Vehicle enters the world with.
// The volatile position of anything but the player's own entity is addressed by
// alias, so the Vehicle needs a real one — `enterAoI` with 0 leaves it
// unaddressable and the client never learns where the tank is.
const VehicleAlias uint8 = 1

// roundVec3 rounds a position to the metre, the way the captured server places
// the reference point.
func roundVec3(v [3]float32) [3]float32 {
	return [3]float32{
		float32(math.Round(float64(v[0]))),
		float32(math.Round(float64(v[1]))),
		float32(math.Round(float64(v[2]))),
	}
}

// EncodeRelativePosition sets the base position the following relative updates
// are measured from. The captured server assigns it verbatim, without rounding.
func EncodeRelativePosition(pos [3]float32) []byte {
	out := make([]byte, 13)
	out[0] = elRelativePosition
	putVec3(out[1:], pos)
	return out
}

// EncodeAvatarUpdateAliasDetailed places an aliased entity at pos with the given
// direction, relative to the last reference position.
func EncodeAvatarUpdateAliasDetailed(refNum, alias uint8, pos, dir [3]float32) []byte {
	out := make([]byte, 27)
	out[0] = elAvatarUpdateAliasDetailed
	out[1] = refNum
	out[2] = alias
	putVec3(out[3:], pos)
	putVec3(out[15:], dir)
	return out
}

// EncodeAvatarUpdatePlayerDetailed places the player's own entity at pos with
// the given direction, relative to the last reference position.
func EncodeAvatarUpdatePlayerDetailed(refNum uint8, pos, dir [3]float32) []byte {
	out := make([]byte, 26)
	out[0] = elAvatarUpdatePlayerDetailed
	out[1] = refNum
	putVec3(out[2:], pos)
	putVec3(out[14:], dir)
	return out
}

// elForcedPosition is `FORCED_POSITION`: FIXED 38, the server-directed
// position of the client's controlled entity. The client answers it with
// `ACK_PHYSICS_CORRECTION` (0x05, FIXED 0).
const elForcedPosition = 0x1B

// EncodeForcedPosition places the client's controlled entity at pos with the
// given direction, outright — no reference point and no rounding.
//
// Layout, from the reference's `ForcedPosition`: entity id, space id, the
// vehicle it is mounted on, two bytes WoT adds that the BigWorld 14.4.1
// `forcedPosition` does not have (zero in every captured sample), then the
// position and the direction as raw floats. The two extra bytes sit *before*
// the position, not after: placing them at the end makes the position read as
// denormal garbage.
func EncodeForcedPosition(entityID, spaceID, vehicleID uint32, pos, dir [3]float32) []byte {
	out := make([]byte, 39)
	out[0] = elForcedPosition
	binary.LittleEndian.PutUint32(out[1:], entityID)
	binary.LittleEndian.PutUint32(out[5:], spaceID)
	binary.LittleEndian.PutUint32(out[9:], vehicleID)
	putVec3(out[15:], pos)
	putVec3(out[27:], dir)
	return out
}

func putVec3(dst []byte, v [3]float32) {
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(dst[i*4:], math.Float32bits(v[i]))
	}
}

func abs32(v float32) float32    { return float32(math.Abs(float64(v))) }
func min32(a, b float32) float32 { return float32(math.Min(float64(a), float64(b))) }
func max32(a, b float32) float32 { return float32(math.Max(float64(a), float64(b))) }
func sin32(v float32) float32    { return float32(math.Sin(float64(v))) }
func cos32(v float32) float32    { return float32(math.Cos(float64(v))) }
func atan32(v float32) float32   { return float32(math.Atan(float64(v))) }

func atan2_32(y, x float32) float32 { return float32(math.Atan2(float64(y), float64(x))) }
func round32(v float64) int64       { return int64(math.Round(v)) }

func clamp32(v, lo, hi float32) float32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// wrapAngle folds an angle into [-pi, pi).
func wrapAngle(a float32) float32 {
	for a >= math.Pi {
		a -= 2 * math.Pi
	}
	for a < -math.Pi {
		a += 2 * math.Pi
	}
	return a
}

// PackedXZScale is the `packedXZScale` a `CreateCellPlayer` advertises, which
// the client multiplies a packed position's x/z by to get metres.
//
// Read off the wire, not guessed: the captured server's `CreateCellPlayer` in
// battle 1 of `captures/proxy-20261031-1358.hex` (14:00:33.250) carries
// 0x3BFAA0B6 = 0.007644442, and the `0x35` records in the same battle only
// decode to plausible offsets from the `0x16` reference at that scale — 2760
// packed units is 21 m, not 2760 m. The client asserts `packedXZScale_ > 0.f`
// (`ServerConnection::createCellPlayer`, `sub_142CF7C20`, stores it at
// `connection+0x77C`), so a zero here is fatal.
const PackedXZScale float32 = 0.007644442
