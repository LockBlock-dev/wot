package login

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestHullDrivesForward checks the hull reaches the vehicle's top speed and
// covers the ground that speed implies.
func TestHullDrivesForward(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Flags = moveForward
	// 20 s at 4 m/s² reaches 37 m/s in ~9.25 s, then holds.
	for i := 0; i < 200; i++ {
		h.step(0.1)
	}
	if math.Abs(float64(h.Speed-37)) > 0.01 {
		t.Fatalf("speed = %v, want 37", h.Speed)
	}
	if h.Position[2] <= 0 {
		t.Fatalf("position z = %v, want forward (+z)", h.Position[2])
	}
	if h.Position[0] != 0 {
		t.Fatalf("position x = %v, want 0 (no turn)", h.Position[0])
	}
}

// TestHullTurns checks the yaw follows the rotation flags at the chassis's rate,
// and that reversing steers the other way.
func TestHullTurns(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Flags = moveRotateRight
	for i := 0; i < 10; i++ {
		h.step(0.1)
	}
	if math.Abs(float64(h.Direction[2]-0.5)) > 1e-4 {
		t.Fatalf("yaw = %v, want 0.5 (0.5 rad/s for 1 s)", h.Direction[2])
	}
	// Backing up steers like a car: right swings the rear right, so the nose
	// goes left.
	h.Direction[2] = 0
	h.Flags = moveRotateRight | moveBackward
	h.step(0.1)
	if h.Direction[2] >= 0 {
		t.Fatalf("yaw = %v, want negative when reversing right", h.Direction[2])
	}
}

// TestHullEngineModeAndGear pins the two values the client's track scroll and
// engine sound follow.
//
// `Vehicle.engineMode` is `Tuple[2]{UINT8}`, not a UINT16: byte 0 is the mode
// and byte 1 the movement flags. The capture's own values are `0x0001` (mode 1
// idle, no flags), `0x0102` (mode 2 cruise, forward) and `0x0103` (mode 3
// accelerating, forward) — 2793 samples, all on the Vehicle, never on the
// Avatar. `VehicleAppearance.changeEngineMode` feeds `mode[0]` to
// `DetailedEngineState.mode`, which is what makes the engine sound leave idle;
// `Vehicle.hasMovingFlags` reads `mode[1] & 3`.
func TestHullEngineModeAndGear(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	if got := h.engineMode(); got != [2]byte{1, 0} {
		t.Fatalf("idle engineMode = %v, want {1,0}", got)
	}
	if gear, rpm := h.engine(); gear != 0 || math.Abs(float64(rpm-idleRPM)) > 1e-6 {
		t.Fatalf("idle engine = (%d, %v), want (0, %v)", gear, rpm, idleRPM)
	}
	h.Flags = moveForward
	h.step(0.1)
	if got := h.engineMode(); got[0] != 3 || got[1] != moveForward {
		t.Fatalf("accelerating engineMode = %v, want {3, %d}", got, moveForward)
	}
	for i := 0; i < 200; i++ {
		h.step(0.1)
	}
	if got := h.engineMode(); got[0] != 2 {
		t.Fatalf("cruising engineMode = %v, want mode 2", got)
	}
	if gear, _ := h.engine(); gear != 4 {
		t.Fatalf("top-speed gear = %d, want 4", gear)
	}
}

// TestHullAuxPhysicsDataIsLevelAtRest pins the packing against the value the
// client itself produces for a level, still tank: `WoT.packAuxVehiclePhysicsData`
// of (0, 0, 0, 0, 0, 0) is 0x55558004004000, and the engine's idle RPM is the
// only field that differs.
func TestHullAuxPhysicsDataIsLevelAtRest(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	got := h.auxPhysicsData()
	// Yaw 0, pitch 0, roll 0, both tracks 0: the same bits the client packs,
	// with the RPM field at idle rather than zero.
	const level = 0x55558004004000
	if got&0x00FFFFFFFFFFFF != level&0x00FFFFFFFFFFFF {
		t.Fatalf("aux = %#x, want the level bits of %#x", got, level)
	}
	if rpm := got >> 56; rpm == 0 {
		t.Fatalf("aux = %#x, want a non-zero idle RPM", got)
	}
}

// TestPositionElements pins the two volatile-position elements: the reference
// point then the player's own entity at zero from it.
func TestPositionElements(t *testing.T) {
	ref := EncodeRelativePosition([3]float32{397, 56, 402})
	if len(ref) != 13 || ref[0] != elRelativePosition {
		t.Fatalf("reference = % x, want 13 B starting %#02x", ref, elRelativePosition)
	}
	upd := EncodeAvatarUpdatePlayerDetailed(0, [3]float32{}, [3]float32{0, 0, 1.5})
	if len(upd) != 26 || upd[0] != elAvatarUpdatePlayerDetailed {
		t.Fatalf("update = % x, want 26 B starting %#02x", upd, elAvatarUpdatePlayerDetailed)
	}
	if upd[1] != 0 {
		t.Fatalf("ref_num = %d, want 0", upd[1])
	}
}

// TestAimWorldPointSurvivesTheHullTurning is the regression for the turret
// desyncing while driving.
//
// The client sends `shotPoint - stabilisedVehPos`, an offset from the hull's
// position in WORLD axes — not in the hull's frame. Rotating it by the hull yaw
// puts the aim point a hull-yaw's worth off, and because that error changes as
// the tank turns, the turret desyncs the moment it drives.
func TestAimWorldPointSurvivesTheHullTurning(t *testing.T) {
	h := hull{Position: [3]float32{100, 0, 100}}
	// Aiming 20 m along +Z from a hull facing +Z.
	world := h.aimWorldPoint([3]float32{0, 0, 20})
	if world != [3]float32{100, 0, 120} {
		t.Fatalf("world = %v, want (100, 0, 120)", world)
	}
	if got := h.aimLocalBearing(world); math.Abs(float64(got)) > 1e-6 {
		t.Fatalf("bearing = %v, want 0", got)
	}
	// Turn the hull 90 degrees right: the same world point is now 90 degrees
	// to the left of the hull, which is what the turret has to follow.
	h.Direction[2] = math.Pi / 2
	if got := h.aimLocalBearing(world); math.Abs(float64(got)+math.Pi/2) > 1e-6 {
		t.Fatalf("bearing after turning = %v, want -pi/2", got)
	}
	// The offset is in world axes whatever the hull's yaw: a point 20 m along
	// +Z stays 20 m along +Z, it is not swung round with the hull.
	if got := h.aimWorldPoint([3]float32{0, 0, 20}); got != [3]float32{100, 0, 120} {
		t.Fatalf("world after turning = %v, want (100, 0, 120)", got)
	}
	// The measured case: hull at yaw 2.938, aim 14.795 m along +Z. The client's
	// own `getShotAngles` says -2.947 rad.
	h = hull{Position: [3]float32{374.857, 56.4342, 388.649}, Direction: [3]float32{0, 0, 2.9382}}
	world = h.aimWorldPoint([3]float32{0, -0.0013, 14.795})
	if got := h.aimLocalBearing(world); math.Abs(float64(got)+2.947) > 0.02 {
		t.Fatalf("bearing = %v, want about -2.947", got)
	}
}

// settle reports whether it found the ground, so the tick can refuse a move
// that leaves the map: off the edge there is no terrain, and a hull that keeps
// its height there drives out into nothing and ends up underground.
func TestSettleReportsMissingGround(t *testing.T) {
	h := hull{Position: [3]float32{100, 50, 100}}
	if h.settle(nil) {
		t.Fatal("settle(nil) reported ground")
	}
	// A terrain that has no height anywhere is the off-map case.
	empty := &Terrain{}
	if h.settle(empty) {
		t.Fatal("settle reported ground off the map")
	}
	if h.Position[1] != 50 {
		t.Fatalf("height changed to %v with no ground", h.Position[1])
	}
}

// FORCED_POSITION is the element the client's own controlled entity is placed
// by, and the client answers it with ACK_PHYSICS_CORRECTION. Its layout is the
// reference's `ForcedPosition`: entity id, space id, the vehicle it is mounted
// on, two bytes WoT adds that the BigWorld 14.4.1 `forcedPosition` does not
// have, then the position and the direction as raw floats. The two extra bytes
// sit BEFORE the position — at the end they make the position read as denormal
// garbage.
func TestEncodeForcedPosition(t *testing.T) {
	got := EncodeForcedPosition(100003, 7, 100003,
		[3]float32{271.13, 60.88, 320.84}, [3]float32{0, 0, 1.5})
	if len(got) != 39 {
		t.Fatalf("len = %d, want 39 (1 id + 38 fixed)", len(got))
	}
	if got[0] != elForcedPosition {
		t.Fatalf("element id = %#x, want %#x", got[0], elForcedPosition)
	}
	if v := binary.LittleEndian.Uint32(got[1:]); v != 100003 {
		t.Fatalf("entity id = %d", v)
	}
	if v := binary.LittleEndian.Uint32(got[5:]); v != 7 {
		t.Fatalf("space id = %d", v)
	}
	if v := binary.LittleEndian.Uint32(got[9:]); v != 100003 {
		t.Fatalf("vehicle id = %d", v)
	}
	if got[13] != 0 || got[14] != 0 {
		t.Fatalf("the two unknown bytes = %#x %#x, want zero", got[13], got[14])
	}
	for i, want := range []float32{271.13, 60.88, 320.84} {
		if v := math.Float32frombits(binary.LittleEndian.Uint32(got[15+i*4:])); v != want {
			t.Fatalf("position[%d] = %v, want %v", i, v, want)
		}
	}
	for i, want := range []float32{0, 0, 1.5} {
		if v := math.Float32frombits(binary.LittleEndian.Uint32(got[27+i*4:])); v != want {
			t.Fatalf("direction[%d] = %v, want %v", i, v, want)
		}
	}
}

// TestHullHandbrakeSlidesInsteadOfStopping pins the handbrake's drift.
//
// The client's space bar is `CMD_BLOCK_TRACKS`, which `Avatar.moveVehicle`
// folds into the same flag byte it sends to `cell.vehicle_moveWith` as
// `MOVEMENT_FLAGS.BLOCK_TRACKS` (64). Locking the tracks drops their lateral
// grip, so the hull keeps its velocity vector while the steering turns it
// under that vector: a slide. It is not a dead stop, and it is not "drive
// straight through the handbrake" either.
func TestHullHandbrakeSlidesInsteadOfStopping(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Flags = moveForward
	for i := 0; i < 100; i++ {
		h.step(0.1)
	}
	if h.Speed < 30 {
		t.Fatalf("speed = %v, want the tank up to speed before the handbrake", h.Speed)
	}
	// Handbrake while still holding forward and a turn: the tracks lock, the
	// steering still bites while the hull is moving, and the velocity lags.
	h.Flags = moveForward | moveRotateRight | moveBlockTracks
	yaw := h.Direction[2]
	h.step(0.1)
	if h.YawRate == 0 {
		t.Fatal("yawRate = 0, want the steering to bite while moving")
	}
	if h.Speed <= 0 {
		t.Fatalf("speed = %v, want the hull to keep its momentum", h.Speed)
	}
	if h.Direction[2] == yaw {
		t.Fatalf("yaw = %v, want the hull to turn", h.Direction[2])
	}
	// The velocity is not along the heading: the hull is sliding. Keep the
	// handbrake on and the slide builds instead of being gripped away.
	for i := 0; i < 10; i++ {
		h.step(0.1)
	}
	if lateral := lateralSpeed(&h); abs32(lateral) < 3 {
		t.Fatalf("lateral speed = %v, want a slide", lateral)
	}
	// The brake still wins in the end.
	for i := 0; i < 100; i++ {
		h.step(0.1)
	}
	if h.Speed != 0 || h.Velocity != [2]float32{} {
		t.Fatalf("speed = %v velocity = %v, want the hull stopped", h.Speed, h.Velocity)
	}
	// Releasing it lets the tank drive again.
	h.Flags = moveForward
	for i := 0; i < 20; i++ {
		h.step(0.1)
	}
	if h.Speed <= 0 {
		t.Fatalf("speed = %v, want the tank moving again after the handbrake", h.Speed)
	}
}

// TestHullHandbrakeCannotPivotInPlace keeps the one behaviour the old model
// got right: with the tracks locked and no speed, the steering has nothing to
// push against, so the hull cannot turn on the spot.
func TestHullHandbrakeCannotPivotInPlace(t *testing.T) {
	h := hull{Limits: motionLimits{RotationSpeed: 0.5}}
	h.Flags = moveRotateRight | moveBlockTracks
	yaw := h.Direction[2]
	for i := 0; i < 50; i++ {
		h.step(0.1)
	}
	if h.Direction[2] != yaw {
		t.Fatalf("yaw = %v, want %v (no pivot with the tracks locked)", h.Direction[2], yaw)
	}
}

// TestHullGripHoldsTheTurn is the contrast: without the handbrake the tracks
// grip, so the velocity stays close to the heading instead of sliding.
func TestHullGripHoldsTheTurn(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Flags = moveForward
	for i := 0; i < 100; i++ {
		h.step(0.1)
	}
	h.Flags = moveForward | moveRotateRight
	for i := 0; i < 10; i++ {
		h.step(0.1)
	}
	if lateral := lateralSpeed(&h); abs32(lateral) > 2 {
		t.Fatalf("lateral speed = %v, want the tracks to hold the turn", lateral)
	}
}

// lateralSpeed is the hull's sideways velocity in its own frame, m/s.
func lateralSpeed(h *hull) float32 {
	yaw := h.Direction[2]
	return h.Velocity[0]*cos32(yaw) - h.Velocity[1]*sin32(yaw)
}
