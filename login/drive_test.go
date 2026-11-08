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
		h.step(0.1, groundFirm)
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
		h.step(0.1, groundFirm)
	}
	// The rate rises over `rotationRise`, so a second of turning covers a
	// little less than the full 0.5 rad; the steady rate is the chassis's.
	if math.Abs(float64(h.YawRate-0.5)) > 1e-4 {
		t.Fatalf("yawRate = %v, want 0.5 rad/s", h.YawRate)
	}
	if h.Direction[2] < 0.4 || h.Direction[2] > 0.5 {
		t.Fatalf("yaw = %v, want ~0.45 after a second of turning", h.Direction[2])
	}
	// Backing up steers like a car: right swings the rear right, so the nose
	// goes left.
	h.Direction[2] = 0
	h.YawRate = 0
	h.Flags = moveRotateRight | moveBackward
	for i := 0; i < 5; i++ {
		h.step(0.1, groundFirm)
	}
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
	h.step(0.1, groundFirm)
	if got := h.engineMode(); got[0] != 3 || got[1] != moveForward {
		t.Fatalf("accelerating engineMode = %v, want {3, %d}", got, moveForward)
	}
	for i := 0; i < 200; i++ {
		h.step(0.1, groundFirm)
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
	if h.settle(nil, nil, 0) {
		t.Fatal("settle(nil) reported ground")
	}
	// A terrain that has no height anywhere is the off-map case.
	empty := &Terrain{}
	if h.settle(empty, nil, 0) {
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
		h.step(0.1, groundFirm)
	}
	if h.Speed < 30 {
		t.Fatalf("speed = %v, want the tank up to speed before the handbrake", h.Speed)
	}
	// Handbrake while still holding forward and a turn: the tracks lock, the
	// steering still bites while the hull is moving, and the velocity lags.
	h.Flags = moveForward | moveRotateRight | moveBlockTracks
	yaw := h.Direction[2]
	h.step(0.1, groundFirm)
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
		h.step(0.1, groundFirm)
	}
	if lateral := lateralSpeed(&h); abs32(lateral) < 3 {
		t.Fatalf("lateral speed = %v, want a slide", lateral)
	}
	// With the throttle still held it pivots on the blocked inner track at
	// the pivot speed — `PIVOT_RADIUS` in the reference — rather than
	// stopping dead.
	for i := 0; i < 100; i++ {
		h.step(0.1, groundFirm)
	}
	if want := h.Limits.RotationSpeed * rotationOnMove * pivotRadius; math.Abs(float64(h.Speed-want)) > 0.01 {
		t.Fatalf("speed = %v, want the pivot speed %v", h.Speed, want)
	}
	// Let the throttle go and the brake does stop it.
	h.Flags = moveRotateRight | moveBlockTracks
	for i := 0; i < 100; i++ {
		h.step(0.1, groundFirm)
	}
	if h.Speed != 0 || h.Velocity != [2]float32{} {
		t.Fatalf("speed = %v velocity = %v, want the hull stopped", h.Speed, h.Velocity)
	}
	// Releasing it lets the tank drive again.
	h.Flags = moveForward
	for i := 0; i < 20; i++ {
		h.step(0.1, groundFirm)
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
		h.step(0.1, groundFirm)
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
		h.step(0.1, groundFirm)
	}
	h.Flags = moveForward | moveRotateRight
	for i := 0; i < 10; i++ {
		h.step(0.1, groundFirm)
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

// TestHullJumpsOffACliff drives the hull off a cliff: the ground drops faster
// than the tracks can follow, so it goes airborne and gravity brings it down
// onto the lower ground instead of snapping to it.
func TestHullJumpsOffACliff(t *testing.T) {
	const n = 34
	hm := &HeightMap{Width: n, Height: n, Heights: make([]float32, n*n)}
	// A 10 m cliff across the chunk: flat at 0 until the z=17 row, then 10 m
	// lower.
	for pz := 17; pz < n; pz++ {
		for px := 0; px < n; px++ {
			hm.Heights[pz*n+px] = -10
		}
	}
	tm := &Terrain{ChunkSize: 100, Chunks: map[[2]int16]*HeightMap{{0, 0}: hm}}
	h := hull{Position: [3]float32{10, 0, 10}, Velocity: [2]float32{0, 20}, Flags: moveForward, Limits: motionLimits{SpeedForward: 25}}
	if !h.settle(tm, nil, 0.1) {
		t.Fatal("no ground at spawn")
	}
	if h.Airborne {
		t.Fatal("airborne on flat ground")
	}
	// Drive to the cliff.
	for i := 0; i < 40 && !h.Airborne; i++ {
		h.step(0.1, groundFirm)
		if !h.settle(tm, nil, 0.1) {
			t.Fatalf("off the map at tick %d", i)
		}
	}
	if !h.Airborne {
		t.Fatal("the hull never went airborne off the cliff")
	}
	y0 := h.Position[1]
	// Falling: the height drops and the vertical speed is negative.
	for i := 0; i < 5; i++ {
		h.step(0.1, groundFirm)
		if !h.settle(tm, nil, 0.1) {
			t.Fatalf("off the map while falling at tick %d", i)
		}
	}
	if h.Position[1] >= y0 {
		t.Fatalf("height %v did not fall from %v", h.Position[1], y0)
	}
	if h.VerticalVelocity >= 0 {
		t.Fatalf("vertical velocity %v, want falling", h.VerticalVelocity)
	}
	// It lands on the lower ground.
	for i := 0; i < 40 && h.Airborne; i++ {
		h.step(0.1, groundFirm)
		if !h.settle(tm, nil, 0.1) {
			t.Fatalf("off the map while landing at tick %d", i)
		}
	}
	if h.Airborne {
		t.Fatal("the hull never landed")
	}
	if h.Position[1] > -5 {
		t.Fatalf("landed at %v, want the lower ground", h.Position[1])
	}
}

// TestHullFollowsASteepSlopeWithoutBouncing drives down a constant 30° slope:
// the hull's vertical speed is the ground's own rate, so it stays on it
// instead of going airborne every tick.
func TestHullFollowsASteepSlopeWithoutBouncing(t *testing.T) {
	const n = 34
	const spacing = 100.0 / (n - 5)
	hm := &HeightMap{Width: n, Height: n, Heights: make([]float32, n*n)}
	// The ground falls 30° along +Z (tan 30° = 0.577) from row 10.
	for pz := 0; pz < n; pz++ {
		for px := 0; px < n; px++ {
			z := float64(pz-(n-1)/2) * spacing
			if z > 0 {
				hm.Heights[pz*n+px] = float32(-z * 0.577)
			}
		}
	}
	tm := &Terrain{ChunkSize: 100, Chunks: map[[2]int16]*HeightMap{{0, 0}: hm}}
	h := hull{Position: [3]float32{50, 0, 10}, Velocity: [2]float32{0, 20}, Flags: moveForward, Limits: motionLimits{SpeedForward: 25}}
	if !h.settle(tm, nil, 0.1) {
		t.Fatal("no ground at spawn")
	}
	// The heightmap's triangulation zigzags, so a "constant" slope has small
	// ridges: the hull may hop a few centimetres off them, but it must never
	// leave the ground for real.
	maxOff := float32(0)
	for i := 0; i < 30; i++ {
		h.step(0.1, groundFirm)
		if !h.settle(tm, nil, 0.1) {
			t.Fatalf("off the map at tick %d", i)
		}
		if ground, ok := tm.HeightAt(h.Position[0], h.Position[2]); ok {
			if off := h.Position[1] - ground; off > maxOff {
				maxOff = off
			}
		}
	}
	if maxOff > 0.3 {
		t.Fatalf("the hull got %.2f m off a constant slope, want it to follow it", maxOff)
	}
}

// TestHullJumpsOffASmallLedge drives off a 2 m ledge at speed: the ground
// drops far faster than the hull's own vertical speed can follow, so it goes
// airborne instead of sticking to the ledge.
func TestHullJumpsOffASmallLedge(t *testing.T) {
	const n = 34
	hm := &HeightMap{Width: n, Height: n, Heights: make([]float32, n*n)}
	for pz := 17; pz < n; pz++ {
		for px := 0; px < n; px++ {
			hm.Heights[pz*n+px] = -2
		}
	}
	tm := &Terrain{ChunkSize: 100, Chunks: map[[2]int16]*HeightMap{{0, 0}: hm}}
	h := hull{Position: [3]float32{10, 0, 10}, Velocity: [2]float32{0, 20}, Flags: moveForward, Limits: motionLimits{SpeedForward: 25}}
	if !h.settle(tm, nil, 0.1) {
		t.Fatal("no ground at spawn")
	}
	for i := 0; i < 40 && !h.Airborne; i++ {
		h.step(0.1, groundFirm)
		if !h.settle(tm, nil, 0.1) {
			t.Fatalf("off the map at tick %d", i)
		}
	}
	if !h.Airborne {
		t.Fatal("the hull followed a 2 m ledge instead of jumping off it")
	}
}

// TestHullTurnsSlowerOnSoftGround pins the ground materials: the chassis'
// rotation speed is its firm-ground one, and the softer grounds turn slower as
// their `terrainResistance` rises.
func TestHullTurnsSlowerOnSoftGround(t *testing.T) {
	limits := motionLimits{
		SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5,
		RotationSpeedByGround: [3]float32{0.5, 0.4, 0.25},
	}
	turn := func(ground uint8) float32 {
		h := hull{Limits: limits}
		h.Flags = moveRotateRight
		for i := 0; i < 30; i++ {
			h.step(0.1, ground)
		}
		return h.YawRate
	}
	if firm, soft := turn(groundFirm), turn(groundSoft); !(firm > soft) {
		t.Fatalf("firm yaw rate %v, soft %v: want firm to turn faster", firm, soft)
	}
	if got := turn(groundSoft); math.Abs(float64(got-0.25)) > 1e-4 {
		t.Fatalf("soft yaw rate = %v, want 0.25", got)
	}
}

// TestHullStopsAtTheMapEdge pins `keepWithin`: the hull is clamped inside the
// bounds and the speed into the edge stops.
func TestHullStopsAtTheMapEdge(t *testing.T) {
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Flags = moveForward
	h.Position = [3]float32{0, 0, 98}
	for i := 0; i < 50; i++ {
		h.step(0.1, groundFirm)
		h.keepWithin(-100, -100, 100, 100)
	}
	if h.Position[2] > 100-boundsMargin+0.001 {
		t.Fatalf("z = %v, want it clamped inside the bounds", h.Position[2])
	}
	if h.Velocity[1] > 0 {
		t.Fatalf("velocity z = %v, want the speed into the edge stopped", h.Velocity[1])
	}
}

// staticQuad adds a quad's two triangles to a static scene, with their bounds.
func staticQuad(scene *staticScene, body string, kind staticBodyKind, a, b, c, d [3]float32) {
	for _, tri := range [][3][3]float32{{a, b, c}, {a, c, d}} {
		st := staticTriangle{Vertices: tri, Normal: triangleNormal(tri), Body: body, Kind: kind}
		for k := 0; k < 3; k++ {
			st.Bounds[0][k] = min32(min32(tri[0][k], tri[1][k]), tri[2][k])
			st.Bounds[1][k] = max32(max32(tri[0][k], tri[1][k]), tri[2][k])
		}
		scene.Triangles = append(scene.Triangles, st)
	}
	scene.rebuildGrid()
}

// TestHullDrivesUpAStaticRamp pins the static models as ground: a ramp's deck
// carries the hull up, and its edge launches it. Without this a ramp is only a
// wall to push out of, and a tank drives through it.
func TestHullDrivesUpAStaticRamp(t *testing.T) {
	terrain := flatTerrain()
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	// A 3 m rise over 10 m, from z=20 to z=30, 10 m wide.
	staticQuad(scene, "s_ramp", bodySolid,
		[3]float32{-5, 0, 20}, [3]float32{5, 0, 20}, [3]float32{5, 3, 30}, [3]float32{-5, 3, 30})
	h := hull{
		Position: [3]float32{0, 0, 0},
		Flags:    moveForward,
		Limits: motionLimits{
			SpeedForward: 15, SpeedBackward: 8, RotationSpeed: 0.5,
			RotationSpeedByGround:   [3]float32{0.5, 0.4, 0.3},
			RollingFrictionByGround: [3]float32{0.05, 0.05, 0.05},
			EnginePower:             700000, Weight: 40000,
			CarryingPoint: [2]float32{1.2, 2.0},
		},
	}
	h.settle(terrain, scene, 0.1)
	var peak float32
	airborne := false
	for i := 0; i < 300; i++ {
		h.step(0.1, groundFirm)
		h.settle(terrain, scene, 0.1)
		if h.Position[1] > peak {
			peak = h.Position[1]
		}
		if h.Airborne {
			airborne = true
		}
		if h.Position[2] > 40 {
			break
		}
	}
	if peak < 2.0 {
		t.Fatalf("the hull rose to %.2f m, want it carried up the ramp's 3 m", peak)
	}
	if !airborne {
		t.Fatal("the hull never left the ramp's edge")
	}
}

// TestHullJumpsOffABumpAtSpeed pins the crest: a tank driving fast over a bump
// leaves the ground, while the same bump at a crawl does not.
func TestHullJumpsOffABumpAtSpeed(t *testing.T) {
	// A 0.6 m bump over 4 m, centred on z=30.
	const n = 257
	hm := &HeightMap{Width: n, Height: n, Heights: make([]float32, n*n)}
	for iz := 0; iz < n; iz++ {
		for ix := 0; ix < n; ix++ {
			z := float32(iz) * 100 / float32(n-1)
			h := float32(0)
			if z >= 28 && z <= 32 {
				h = 0.6 * (1 - abs32(z-30)/2)
			}
			hm.Heights[iz*n+ix] = h
		}
	}
	terrain := &Terrain{ChunkSize: 100, Chunks: map[[2]int16]*HeightMap{{0, 0}: hm}}
	drive := func(speed float32) bool {
		h := hull{
			Position: [3]float32{50, 0, 0},
			Velocity: [2]float32{0, speed},
			Flags:    moveForward,
			Limits: motionLimits{
				SpeedForward: speed, SpeedBackward: 8, RotationSpeed: 0.5,
				RotationSpeedByGround:   [3]float32{0.5, 0.4, 0.3},
				RollingFrictionByGround: [3]float32{0.05, 0.05, 0.05},
				EnginePower:             700000, Weight: 40000,
				CarryingPoint: [2]float32{1.2, 2.0},
			},
		}
		h.settle(terrain, nil, 0.1)
		for i := 0; i < 300; i++ {
			h.step(0.1, groundFirm)
			h.settle(terrain, nil, 0.1)
			if h.Airborne {
				return true
			}
			if h.Position[2] > 60 {
				break
			}
		}
		return false
	}
	if !drive(15) {
		t.Error("a tank at 15 m/s did not leave a 0.6 m bump")
	}
	if drive(1.5) {
		t.Error("a tank at 1.5 m/s left the bump: a crawl follows the ground")
	}
}
