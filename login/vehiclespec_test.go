package login

import (
	"math"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestVehicleGunSpeedsFromDefs reads the rotation limits out of the game's own
// item defs for a real compact descriptor: turret `Turret_1_GB151_Headshaker`
// at 25 deg/s, gun `_5_5_inch_AT_Gun_Mk_II` at 26.25 deg/s. Both match what the
// client's own `vehicleTypeDescriptor` reports, which is the point — the
// server no longer has to guess. It skips when the client is not installed.
func TestVehicleGunSpeedsFromDefs(t *testing.T) {
	if FindScriptsPkg() == "" {
		t.Skip("no scripts.pkg")
	}
	// The compact descriptor the client sent for the player's tank.
	compDescr := []byte("Qd\xcb\x00\x96\x00\xcd\x00C\x00\xba\x00\x9c\x00\x00")
	sp, ok := vehicleGunSpeeds(compDescr)
	if !ok {
		t.Fatal("vehicleGunSpeeds did not resolve")
	}
	const deg = math.Pi / 180
	if want := 25 * deg; math.Abs(sp.Turret-want) > 1e-6 {
		t.Errorf("turret = %v rad/s, want %v (25 deg/s)", sp.Turret, want)
	}
	if want := 26.25 * deg; math.Abs(sp.Gun-want) > 1e-6 {
		t.Errorf("gun = %v rad/s, want %v (26.25 deg/s)", sp.Gun, want)
	}
	// The turret's arc comes from the turret's own `<guns>/<gun>` override, not
	// from the gun's `turretYawLimits` (which is the whole circle here).
	if want := -30 * deg; math.Abs(sp.YawMin-want) > 1e-6 {
		t.Errorf("yawMin = %v, want %v (-30 deg)", sp.YawMin, want)
	}
	if want := 30 * deg; math.Abs(sp.YawMax-want) > 1e-6 {
		t.Errorf("yawMax = %v, want %v (30 deg)", sp.YawMax, want)
	}
	// The gun's absolute elevation range, which is what `decodeGunAngles`
	// unpacks `gunAnglesPacked`'s low six bits against. The client's own
	// `typeDescriptor.gun.pitchLimits['absolute']` reports exactly these.
	if want := -0.3490658503988659; math.Abs(sp.PitchMin-want) > 1e-6 {
		t.Errorf("pitchMin = %v, want %v", sp.PitchMin, want)
	}
	if want := 0.10471975511965978; math.Abs(sp.PitchMax-want) > 1e-6 {
		t.Errorf("pitchMax = %v, want %v", sp.PitchMax, want)
	}
	// The gun's pivot sits above the hull's origin (turretPositions + the
	// gun's own gunPosition); measuring the elevation from the hull instead
	// reads a level aim as several degrees of depression.
	if sp.GunHeight <= 0.5 || sp.GunHeight > 4 {
		t.Errorf("gunHeight = %v m, want the turret + gun offset", sp.GunHeight)
	}
	// The hull's envelope comes from the same defs: 37 km/h forward and 14
	// back, which is 10.28 and 3.89 m/s — the numbers the client's own
	// `typeDescriptor.physics.speedLimits` reports — and the chassis's 33 deg/s
	// of rotation.
	if want := float32(37 / 3.6); sp.Limits.SpeedForward != want {
		t.Errorf("speedForward = %v, want %v", sp.Limits.SpeedForward, want)
	}
	if want := float32(14 / 3.6); sp.Limits.SpeedBackward != want {
		t.Errorf("speedBackward = %v, want %v", sp.Limits.SpeedBackward, want)
	}
	if want := float32(33 * deg); sp.Limits.RotationSpeed != want {
		t.Errorf("rotationSpeed = %v, want %v (33 deg/s)", sp.Limits.RotationSpeed, want)
	}
	// A turret that turns at 25 deg/s is nothing like the 30 rad/s constant
	// this used to send, which is the whole point.
	if sp.Turret > 1 {
		t.Errorf("turret = %v rad/s, that is a snap not a swing", sp.Turret)
	}
}

// TestVehicleGunSpeedsUnknownDescr keeps a bad descriptor from guessing.
func TestVehicleGunSpeedsUnknownDescr(t *testing.T) {
	if _, ok := vehicleGunSpeeds(nil); ok {
		t.Fatal("nil descriptor resolved")
	}
	if _, ok := vehicleGunSpeeds([]byte{0x01, 0x02}); ok {
		t.Fatal("garbage descriptor resolved")
	}
}

// TestOwnVehicleTargetingInfoCarriesTheRealDispersion pins that the
// `OwnVehicle` component's `targetingInfo` carries the gun's and chassis's own
// dispersion factors, not 1.0.
//
// The client's `Avatar.getOwnVehicleShotDispersionAngle` reads all five out of
// `self.__dispersionInfo`, which `OwnVehicle.update_targetingInfo` fills from
// this dict — so a hardcoded 1.0 makes every tank disperse as if it were a
// different vehicle, and `aimingTime` 2 makes it aim at the wrong rate.
func TestOwnVehicleTargetingInfoCarriesTheRealDispersion(t *testing.T) {
	if FindScriptsPkg() == "" {
		t.Skip("no scripts.pkg")
	}
	// The component overrides are built from the alias types, which the
	// dispatch loader does not register on its own.
	if err := entdef.InitAliasesFromDir("../../scripts-2.4.1/entity_defs"); err != nil {
		t.Skipf("no aliases: %v", err)
	}
	compDescr := []byte("Qd\xcb\x00\x96\x00\xcd\x00C\x00\xba\x00\x9c\x00\x00")
	sp, ok := vehicleGunSpeeds(compDescr)
	if !ok {
		t.Skip("no gun spec")
	}
	d := sp.Dispersion
	if d.AimingTime <= 0 || d.Movement <= 0 || d.Rotation <= 0 || d.TurretRotation <= 0 || d.AfterShot <= 0 {
		t.Fatalf("dispersion spec has a zero factor: %+v", d)
	}
	if d.ShotSpeed <= 0 || d.Piercing <= 0 {
		t.Fatalf("shell has no speed or penetration: %+v", d)
	}
	// The values are the defs' own, not the 1.0/2 fallbacks.
	if d.Movement == 1 || d.Rotation == 1 || d.TurretRotation == 1 || d.AimingTime == 2 {
		t.Fatalf("dispersion spec still holds a fallback: %+v", d)
	}
	ov := ownVehicleOverrides(100003, compDescr, nil)
	ti, ok := ov["targetingInfo"]
	if !ok {
		t.Fatal("no targetingInfo override")
	}
	fields := map[string]float64{}
	for _, f := range ti.Dict {
		if f.Value.Kind == entdef.VFloat {
			fields[f.Name] = f.Value.Float
		}
	}
	for name, want := range map[string]float64{
		"gunShotDispersionFactorsTurretRotation": d.TurretRotation,
		"chassisShotDispersionFactorsMovement":   d.Movement,
		"chassisShotDispersionFactorsRotation":   d.Rotation,
		"aimingTime":                             d.AimingTime,
		"gunShotDispersionFactorsAfterShot":      d.AfterShot,
	} {
		if got, ok := fields[name]; !ok || math.Abs(got-want) > 1e-9 {
			t.Errorf("targetingInfo[%s] = %v (present %v), want %v", name, got, ok, want)
		}
	}
}

// TestShellCompactDescrMatchesTheClient pins the shell compact descriptor
// against the live client, because it is the one value that decides whether the
// gun fires at all: `AmmoController.canShoot` returns `(False, WAITING)` while
// `__currShellCD` is None, and `__currShellCD` is only ever set from
// `vehicleSettings`/`vehicleAmmoList`, which carry this number.
//
// Ground truth read out of the running client on a UK 5.5-inch AT Gun Mk II:
// `typeDescriptor.shot.shell.compactDescr` is 85082, the shell is
// `_5_5_inch_AP_Mk_II`, and `uk/components/shells.xml` gives it id 332.
// `items.makeIntCompactDescrByID('shell', nation, id)` is
// `(id << 8) + 10 + (nation << 4)` with `uk` at index 5 in `nations.NAMES`.
func TestShellCompactDescrMatchesTheClient(t *testing.T) {
	if got := shellCompactDescr(5, 332); got != 85082 {
		t.Fatalf("shell CD = %d, want 85082 (the live client's own value)", got)
	}
	// The nation order is part of the wire format, not a display detail.
	if nationNames[5] != "uk" {
		t.Fatalf("nationNames[5] = %q, want uk", nationNames[5])
	}
	if shellItemType != 10 {
		t.Fatalf("shellItemType = %d, want 10", shellItemType)
	}
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no scripts.pkg")
	}
	id, err := shellIDIn(pkg, "uk", "_5_5_inch_AP_Mk_II")
	if err != nil {
		t.Fatal(err)
	}
	if id != 332 {
		t.Fatalf("shell id = %d, want 332", id)
	}
	if got := shellCompactDescr(5, id); got != 85082 {
		t.Fatalf("shell CD from the defs = %d, want 85082", got)
	}
}

// TestWheelScrollTupleMatchesTheClient pins the two things that decide whether
// a wheeled vehicle's wheels turn at all.
//
// The tuple length is `generalWheelsAnimatorConfig.getNonTrackWheelsCount()`,
// not the number of `wheel` entries: `Vehicle.set_wheelsScroll` zips
// `wheelsScroll` against the scroll-filter list `createWheelFilters` builds from
// that same count. The EBR 105 declares 16 wheels and only 8 are non-track, so
// a 16-byte tuple is silently truncated and the four siege-only wheels never
// get a value.
//
// The element id is `ENTITY_PROPERTY_BASE + FullIndex` with the base at 0xA7
// (the reference toolkit's `ElementIdRange::new(0xA7, 0xFE)`), and `wheelsScroll`
// is FullIndex 27. The capture pins the base independently: `0xb3` is one byte
// (`botDisplayStatus`, 12), `0xb4` two (`gunAnglesPacked`, 13), `0xb6` two
// (`engineMode`, 15) and `0xa8` one (`isStrafing`, 1).
func TestWheelScrollTupleMatchesTheClient(t *testing.T) {
	if elVehicleWheelsScroll != 0xC2 {
		t.Fatalf("wheelsScroll element = %#x, want 0xc2 (0xa7 + 27)", elVehicleWheelsScroll)
	}
	if elVehicleSiegeState != 0xAB {
		t.Fatalf("siegeState element = %#x, want 0xab (0xa7 + 4)", elVehicleSiegeState)
	}
	if elVehicleGunAnglesPacked != 0xB4 || elVehicleEngineMode != 0xB6 || elVehicleIsStrafing != 0xA8 {
		t.Fatalf("property base is not 0xa7: gunAnglesPacked %#x, engineMode %#x, isStrafing %#x",
			elVehicleGunAnglesPacked, elVehicleEngineMode, elVehicleIsStrafing)
	}
	// `Tuple[0]{UINT8}` has `VariableLengthHeaderSize` 1, so the element is
	// `c2 <len8> <count> <count bytes>` — the length covers the count byte.
	got := EncodeBareU8Tuple(elVehicleWheelsScroll, []byte{1, 2, 3})
	if want := []byte{0xC2, 4, 3, 1, 2, 3}; string(got) != string(want) {
		t.Fatalf("EncodeBareU8Tuple = % x, want % x", got, want)
	}
	if FindScriptsPkg() == "" {
		t.Skip("no scripts.pkg")
	}
	// The EBR 105's own compact descriptor, as the client sent it.
	compDescr := []byte("\x41\x4a\x9d\x00\x65\x00\xcd\x00\x22\x00\x82\x00\x63\x00\x00")
	sp, ok := vehicleGunSpeeds(compDescr)
	if !ok {
		t.Skip("no gun spec")
	}
	if len(sp.Dispersion.WheelRadii) != 8 {
		t.Fatalf("wheel radii = %d entries, want 8 (the EBR 105's non-track wheels)", len(sp.Dispersion.WheelRadii))
	}
	// The EBR runs two wheel sizes: 0.609 m on the leading pair, 0.59 m on the
	// rest. Both come from each wheel's own `geometry/radius`.
	for i, r := range sp.Dispersion.WheelRadii {
		if r < 0.5 || r > 0.7 {
			t.Errorf("wheel %d radius = %v, want a road-wheel radius from the def", i, r)
		}
	}
}
