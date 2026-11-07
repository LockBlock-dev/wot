package login

import (
	"encoding/binary"
	"math"
)

// The player's tank, driven by the client's `vehicle_moveWith` flags.
//
// The real server simulates the vehicle's physics and streams the result; this
// is the same stand-in the reference implementation uses — the hull moves and
// turns at the vehicle's own limits and rests on the terrain, with no collision,
// slope resistance or engine model. What matters is that the client's own
// prediction agrees with it: the client drives its hull locally and corrects
// toward whatever the server sends, so a server that never moves leaves the tank
// stuck at the spawn.
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

// How quickly the speed reaches what the flags ask for, in m/s².
const (
	hullAcceleration float32 = 4.0
	hullBraking      float32 = 10.0
)

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
}

// hull is the player's tank as this server simulates it.
type hull struct {
	// Position is the hull's origin in the world.
	Position [3]float32
	// Direction is roll, pitch and yaw in radians, the order the position
	// updates carry them. A yaw of 0 faces +Z, and turning right increases it.
	Direction [3]float32
	// Speed is signed along the heading, in m/s; YawRate is in rad/s.
	Speed   float32
	YawRate float32
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
func (h *hull) step(dt float32) bool {
	target := h.targetSpeed()
	// Braking applies when slowing down or reversing, accelerating otherwise.
	rate := hullAcceleration
	if abs32(target) < abs32(h.Speed) || target*h.Speed < 0 {
		rate = hullBraking
	}
	delta := clamp32(target-h.Speed, -rate*dt, rate*dt)
	h.Speed += delta

	var turn float32
	if h.Flags&moveBlockTracks == 0 {
		switch h.Flags & (moveRotateLeft | moveRotateRight) {
		case moveRotateLeft:
			turn = -1
		case moveRotateRight:
			turn = 1
		}
	}
	// Backing up steers like a car: left swings the rear to the left.
	if h.Flags&moveBackward != 0 {
		turn = -turn
	}
	h.YawRate = turn * h.Limits.RotationSpeed
	h.Direction[2] = wrapAngle(h.Direction[2] + h.YawRate*dt)

	yaw := h.Direction[2]
	h.Position[0] += sin32(yaw) * h.Speed * dt
	h.Position[2] += cos32(yaw) * h.Speed * dt
	return h.Speed != 0 || turn != 0
}

// settle rests the hull on the terrain: at its height, rolled and pitched with
// its slope. It reports whether the ground was found — off the map there is
// none, and the caller has to refuse the move rather than let the tank drive
// out over the edge and fall.
func (h *hull) settle(tr *Terrain) bool {
	if tr == nil {
		return false
	}
	height := func(dx, dz float32) (float32, bool) {
		return tr.HeightAt(h.Position[0]+dx, h.Position[2]+dz)
	}
	yaw := h.Direction[2]
	fx, fz := sin32(yaw)*hullHalfLength, cos32(yaw)*hullHalfLength
	rx, rz := cos32(yaw)*hullHalfWidth, -sin32(yaw)*hullHalfWidth

	center, ok := height(0, 0)
	if !ok {
		return false
	}
	front, ok1 := height(fx, fz)
	back, ok2 := height(-fx, -fz)
	right, ok3 := height(rx, rz)
	left, ok4 := height(-rx, -rz)
	h.Position[1] = center
	if ok1 && ok2 {
		// Pitched positively nose down.
		h.Direction[1] = -atan32((front - back) / (2 * hullHalfLength))
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

// auxPhysicsData is the hull's attitude and its tracks' speeds, as the avatar's
// `ownVehicleAuxPhysicsData` carries them for the client to aim from and to
// animate the tracks with — `WoT.packAuxVehiclePhysicsData`'s layout, from the
// lowest bit: yaw on 15 bits over a turn, pitch on 12 bits over ±π/2, roll on 13
// bits over a turn, the left then right track speeds on 8 bits each over
// -15..30 m/s, and the engine's relative RPM on 8 bits over 0..1.2.
func (h *hull) auxPhysicsData() uint64 {
	// The inner track goes slower, the outer one faster.
	turning := h.YawRate * hullHalfWidth
	left, right := h.Speed+turning, h.Speed-turning
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
