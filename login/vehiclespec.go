package login

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// Gun and turret rotation speeds, read from the game's own item defs.
//
// `OwnVehicle.targetingInfo` carries `maxTurretRotationSpeed` and
// `maxGunRotationSpeed`, and `VehicleGunRotator` uses them as the rate limit for
// `getNextTurretYaw` — they are what makes the turret swing like a turret
// instead of snapping to the aim point. Sending a large constant (30 rad/s is
// 1719 deg/s) makes the turret instant.
//
// The real numbers are in the vehicle's own XML and in the nation's
// `components/guns.xml`, both inside `scripts.pkg`, both in degrees per second:
//
//	scripts/item_defs/vehicles/<nation>/<Vehicle>.xml   <Turret_...>/rotationSpeed
//	scripts/item_defs/vehicles/<nation>/components/guns.xml   <gun>/rotationSpeed
//
// The turret block is named after the turret the vehicle mounts, which the
// compact descriptor already carries, so the lookup is exact rather than a
// guess by class or tier.

// gunSpec is one vehicle's gun mount: rotation limits in radians per second and
// the turret's yaw arc in radians.
type gunSpec struct {
	Turret float64
	Gun    float64
	YawMin float64
	YawMax float64
	// PitchMin and PitchMax are the gun's absolute elevation range, in
	// radians — the `pitchLimits` the client's `decodeGunAngles` unpacks the
	// low six bits of `gunAnglesPacked` against.
	PitchMin float64
	PitchMax float64
	// GunHeight is how far the gun's pivot sits above the hull's origin, in
	// metres: the turret's `turretPositions/turret` plus the gun's own
	// `gunPosition`. The elevation is measured from there, not from the hull,
	// or a level aim reads as several degrees of depression.
	GunHeight float64
	// Limits is the hull's movement envelope, from the same defs.
	Limits motionLimits
	// Dispersion is the gun's dispersion model, from the same defs. It is
	// what the NRL gun marker's `dispersionAngle` is computed from.
	Dispersion dispersionSpec
	// MinPitchCurve and MaxPitchCurve are the gun's elevation limits per
	// turret yaw: the defs' `pitchLimits` are curves, not one range, so a gun
	// that clears its hull at the front can still depress over the side.
	MinPitchCurve pitchCurve
	MaxPitchCurve pitchCurve
	// MagazineSize is the shells in a full magazine, 1 without one: the gun
	// reloads it whole once empty, in its reload time. MagazineInterval is
	// the seconds between two of its shots.
	MagazineSize     uint32
	MagazineInterval float32
	// BurstSize is the shells the gun fires each time it is fired, 1 without
	// bursts; BurstInterval the seconds between two of them.
	BurstSize     uint32
	BurstInterval float32
}

// shellSpec is the default shell's damage model: the gun's mounted `shots`
// entry gives its speed, penetration and ballistics; the shell's own def
// gives its damage, kind, caliber and the hit effect the client plays.
type shellSpec struct {
	Name         string
	Damage       float64
	Pen          float64
	Kind         string
	KindIndex    uint8
	Caliber      float64
	Speed        float64
	Gravity      float64
	MaxDistance  float64
	EffectsIndex uint8
	// PiercedSticker is the shell's `armorPierced` damage sticker index in
	// `common/damage_stickers.xml` — the shell hole `Vehicle.addDamageSticker`
	// draws. HasPiercedSticker is false when the shell's effects entry names
	// none.
	PiercedSticker    uint8
	HasPiercedSticker bool
	// PenNear and PenFar are the armour it pierces within 100 m and beyond
	// 500 m, in millimetres; DamageNear and DamageFar the same for its damage.
	// The gun's `piercingPower` and the shell's `damage/armor` carry both.
	PenNear, PenFar       float64
	DamageNear, DamageFar float64
	// PenRandomization is how much its penetration varies either way, as a
	// share of it (`piercingPowerRandomization`, 0.25 by default).
	PenRandomization float64
	// NormalizationAngle is how far it turns toward an armour's normal as it
	// hits it, in radians: AP kinds only.
	NormalizationAngle float64
	// RicochetAngleCos is the cosine of the angle from an armour's normal past
	// which it ricochets off it: none for the kinds that never do.
	RicochetAngleCos float64
	HasRicochetAngle bool
	// JetPenLoss is the share of its penetration a HEAT jet loses per metre
	// once through a screen.
	JetPenLoss float64
	// ExplosionRadius is how far an HE shell's explosion damages, in metres:
	// the legacy mechanics' `caliber² / 5555`.
	ExplosionRadius float64
	// PrefabEffectsIndex is its prefab effects' index in
	// `common/prefab_effects/shot_effects.xml`.
	PrefabEffectsIndex    uint8
	HasPrefabEffectsIndex bool
}

// dispersionSpec is the client's own dispersion model, read from the defs the
// way `common/items/vehicles.py` reads them.
//
// The client's `Avatar.getOwnVehicleShotDispersionAngle` builds a factor from
// the hull's speed and turn rate and the turret's rotation rate, decays it
// toward that factor over `AimingTime`, and multiplies the gun's own
// `shotDispersionAngle` by it. The server has to run the same model, because
// the gun marker it sends carries the result and the client draws the
// crosshair from it.
type dispersionSpec struct {
	// Angle is `atan(shotDispersionRadius / 100)`, the gun's fully-aimed
	// dispersion in radians.
	Angle float64
	// AimingTime is the gun's `aimingTime`, in seconds: the time constant the
	// factor decays with.
	AimingTime float64
	// Movement, Rotation and TurretRotation are the three additive factors,
	// already in the units the client multiplies by: `vehicleMovement / 3.6`
	// (km/h to m/s), `vehicleRotation` in radians, and the gun's
	// `turretRotation` in radians.
	Movement       float64
	Rotation       float64
	TurretRotation float64
	// ShotSpeed is the loaded shell's muzzle velocity in m/s — the magnitude
	// of the gun marker's `shotVector`. The capture shows it constant for a
	// whole battle and switching only with the shell, so the default shell
	// (the one with the largest `defaultPortion`) is the one modelled.
	ShotSpeed float64
	// AfterShot is the gun's `shotDispersionFactors/afterShot`: how far the
	// dispersion jumps when it fires.
	AfterShot float64
	// Piercing is the default shell's `piercingPower`, the first of its two
	// values (at 100 m).
	Piercing float64
	// ShellCD is the default shell's compact descriptor, which is what
	// `OwnVehicle.vehicleAmmoList` and `vehicleSettings` carry and what the
	// client's ammo controller keys everything off. Without it
	// `AmmoController.canShoot` returns `(False, WAITING)` and the gun never
	// fires at all.
	//
	// `items.makeIntCompactDescrByID('shell', nation, id)` is
	// `(id << 8) + 10 + (nation << 4)` — item type 10 is `shell` in
	// `ITEM_TYPE_NAMES`, and the nation index is its position in
	// `nations.NAMES`. Verified against the live client: a UK 5.5-inch AP
	// Mk II is shell id 332 in `uk/components/shells.xml`, nation 5, and the
	// client's own `typeDescriptor.shot.shell.compactDescr` reads 85082 =
	// (332 << 8) + 10 + (5 << 4).
	ShellCD int32
	// ReloadTime is the gun's `reloadTime` in seconds, which is what
	// `vehicleGunReloadTime.baseTime` carries.
	ReloadTime float64
	// SiegeOn and SiegeOff are the vehicle's `siege_mode/switchOnTime` and
	// `switchOffTime`, in seconds. They are 0 on the wheeled French tanks —
	// the switch is instant — and non-zero on the Swedish tank destroyers.
	SiegeOn  float64
	SiegeOff float64
	// HasSiege is whether the vehicle declares a `siege_mode` section at all.
	HasSiege bool
	// SiegeLimits is the hull's movement envelope in siege mode, read from the
	// vehicle's `_siege_mode` sibling def. On the wheeled French tanks siege
	// mode is the FAST mode — the EBR 105 is 70/50 km/h in travel and 91/65 in
	// siege — so the hull's limits have to swap with the state or the tank
	// never actually goes faster.
	SiegeLimits motionLimits
	// HasSiegeLimits is whether that sibling def was found.
	HasSiegeLimits bool
	// WheelRadii is one radius per wheel that has a `scrollProcessor`, in the
	// chassis def's order. `Vehicle.wheelsScroll` carries one packed byte per
	// wheel and `WoT.unpackWheelScroll` turns it into that wheel's angular
	// speed, so the count and the radii are what the scroll is computed from.
	WheelRadii []float64
	// Shell is the default shell's damage model, from the gun's `shots` entry
	// and the shell's own def.
	Shell shellSpec
	// MagazineSize is the shells in a full magazine, 1 without one: the gun
	// reloads it whole once empty, in its reload time. MagazineInterval is
	// the seconds between two of its shots.
	MagazineSize     uint32
	MagazineInterval float32
	// BurstSize is the shells the gun fires each time it is fired, 1 without
	// bursts; BurstInterval the seconds between two of them.
	BurstSize     uint32
	BurstInterval float32
}

// gunSpeedCache is keyed by "<nation>/<vehicle>/<turret>/<gun>": the same
// vehicle with a different turret has different limits.
var gunSpeedCache sync.Map // map[string]gunSpec

// vehicleGunSpeeds resolves the rotation limits for a vehicle compact
// descriptor. ok is false when the descriptor or the defs cannot be resolved —
// the caller keeps its fallback rather than guessing.
func vehicleGunSpeeds(compDescr []byte) (gunSpec, bool) {
	if len(compDescr) == 0 {
		return gunSpec{}, false
	}
	r, err := lobby.ResolveCompactDescr(compDescr, generatedVehicleTable())
	if err != nil || len(r.Turrets) < 2 {
		return gunSpec{}, false
	}
	turret, gun := r.Turrets[0].Name, r.Turrets[1].Name
	key := r.NationName + "/" + r.Vehicle + "/" + turret + "/" + gun
	if v, ok := gunSpeedCache.Load(key); ok {
		return v.(gunSpec), true
	}

	pkg := FindScriptsPkg()
	if pkg == "" {
		return gunSpec{}, false
	}
	base := "scripts/item_defs/vehicles/" + r.NationName + "/"
	turretDeg, err := rotationSpeedIn(pkg, base+r.Vehicle+".xml", turret)
	if err != nil {
		return gunSpec{}, false
	}
	gunDeg, err := rotationSpeedIn(pkg, base+"components/guns.xml", gun)
	if err != nil {
		return gunSpec{}, false
	}
	yawMin, yawMax, err := yawLimitsIn(pkg, base+r.Vehicle+".xml", turret, gun)
	if err != nil {
		return gunSpec{}, false
	}
	limits, err := motionLimitsIn(pkg, base+r.Vehicle+".xml", r.Chassis.Name)
	if err != nil {
		return gunSpec{}, false
	}
	pitchMin, pitchMax, err := pitchLimitsIn(pkg, base+r.Vehicle+".xml", turret, gun)
	if err != nil {
		return gunSpec{}, false
	}
	gunHeight, err := gunHeightIn(pkg, base+r.Vehicle+".xml", turret, gun)
	if err != nil {
		return gunSpec{}, false
	}
	disp, err := dispersionIn(pkg, base+r.Vehicle+".xml", base+"components/guns.xml", r.Chassis.Name, gun)
	if err != nil {
		return gunSpec{}, false
	}
	curvesLo, curvesHi, _ := pitchCurvesIn(pkg, base+r.Vehicle+".xml", turret, gun)
	s := gunSpec{
		Turret:        turretDeg * math.Pi / 180,
		Gun:           gunDeg * math.Pi / 180,
		YawMin:        yawMin * math.Pi / 180,
		YawMax:        yawMax * math.Pi / 180,
		PitchMin:      pitchMin,
		PitchMax:      pitchMax,
		GunHeight:     gunHeight,
		Limits:        limits,
		Dispersion:    disp,
		MinPitchCurve: curvesLo,
		MaxPitchCurve: curvesHi,
	}
	gunSpeedCache.Store(key, s)
	return s, true
}

// rotationSpeedIn reads `<block>/rotationSpeed` out of one packed item-def XML.
func rotationSpeedIn(pkg, name, block string) (float64, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return 0, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return 0, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	// The blocks are nested (turrets under `<turrets0>`) and a component file
	// also carries a name -> id map whose entries have the same names but no
	// body, so the lookup walks the tree and takes the section that actually
	// has a `rotationSpeed`.
	rs := findRotationSpeed(f.Root, block)
	if rs == nil {
		return 0, fmt.Errorf("vehiclespec: %s has no %s/rotationSpeed", name, block)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(rs.AsString()), 64)
	if err != nil {
		return 0, fmt.Errorf("vehiclespec: %s/%s rotationSpeed %q: %w", name, block, rs.AsString(), err)
	}
	return v, nil
}

// yawLimitsIn reads the turret's yaw arc for one mounted gun, in degrees.
//
// It lives on the turret, under `<guns>/<gun>/turretYawLimits`, and overrides
// the gun's own limits — a turret that cannot rotate mounts a gun whose
// `turretYawLimits` is the whole circle, so reading the gun's alone gives
// +/-180 for a turret that really swings +/-30.
func yawLimitsIn(pkg, name, turret, gun string) (float64, float64, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return 0, 0, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	ts := findSection(f.Root, turret)
	if ts == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s has no %s", name, turret)
	}
	if gs := ts.Child("guns"); gs != nil {
		if g := gs.Child(gun); g != nil {
			if yl := g.Child("turretYawLimits"); yl != nil {
				return parsePair(yl.AsString())
			}
			// No limits declared means the turret turns all the way round:
			// the client's `typeDescriptor.gun.turretYawLimits` is then None
			// and `VehicleGunRotator` clamps nothing. Returning an error here
			// threw away the WHOLE gun spec for every such vehicle — the TOG
			// II among them — so it had no shell, no reload and no shot could
			// be resolved at all.
			return -180, 180, nil
		}
	}
	return 0, 0, fmt.Errorf("vehiclespec: %s/%s/guns/%s has no turretYawLimits", name, turret, gun)
}

// pitchLimitsIn reads the gun's absolute elevation range, in radians.
//
// It lives on the turret, under `<guns>/<gun>/pitchLimits`, as two flat lists of
// (yaw, pitch) pairs — `minPitch` and `maxPitch` — in degrees. The
// client's `typeDescriptor.gun.pitchLimits['absolute']` is the lowest of the
// mins and the highest of the maxes, which is what `decodeGunAngles` unpacks
// `gunAnglesPacked`'s low six bits against.
func pitchLimitsIn(pkg, name, turret, gun string) (float64, float64, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return 0, 0, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	ts := findSection(f.Root, turret)
	if ts == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s has no %s", name, turret)
	}
	gs := ts.Child("guns")
	if gs == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s/%s has no guns", name, turret)
	}
	g := gs.Child(gun)
	if g == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s/%s/guns has no %s", name, turret, gun)
	}
	pl := g.Child("pitchLimits")
	if pl == nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s/%s/guns/%s has no pitchLimits", name, turret, gun)
	}
	lo, err := pitchExtreme(pl.Child("minPitch"), math.Inf(1), math.Min)
	if err != nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	hi, err := pitchExtreme(pl.Child("maxPitch"), math.Inf(-1), math.Max)
	if err != nil {
		return 0, 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if math.IsInf(lo, 1) || math.IsInf(hi, -1) {
		return 0, 0, fmt.Errorf("vehiclespec: %s/%s/guns/%s pitchLimits is empty", name, turret, gun)
	}
	// The defs carry degrees; the client's `pitchLimits['absolute']` is in
	// radians, and that is what `decodeGunAngles` unpacks against.
	return lo * math.Pi / 180, hi * math.Pi / 180, nil
}

// gunHeightIn is how far the gun's pivot sits above the hull's origin: the
// hull's `turretPositions/turret` plus the turret's own `gunPosition`, both
// three-component vectors in the vehicle's frame.
func gunHeightIn(pkg, name, turret, gun string) (float64, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return 0, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return 0, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	turretY := 0.0
	if tp := findChildDeep(f.Root, "turretPositions"); tp != nil {
		// The entries are named `turret` in some defs and by the turret's own
		// name in others; fall back to the first one, which is the mounted
		// turret.
		t := tp.Child(turret)
		if t == nil {
			t = tp.Child("turret")
		}
		if t == nil && len(tp.Children) > 0 {
			t = tp.Children[0]
		}
		if t != nil {
			if v, err := vectorY(t); err == nil {
				turretY = v
			}
		}
	}
	ts := findSection(f.Root, turret)
	if ts == nil {
		return 0, fmt.Errorf("vehiclespec: %s has no %s", name, turret)
	}
	// `gunPosition` is the turret's own child — the gun's pivot in the
	// turret's frame — not the gun's.
	gunY := 0.0
	if gp := ts.Child("gunPosition"); gp != nil {
		if v, err := vectorY(gp); err == nil {
			gunY = v
		}
	}
	return turretY + gunY, nil
}

// findChildDeep is `Child` over the whole tree: `turretPositions` lives under
// the hull's section, whose name is not one this file otherwise needs.
func findChildDeep(s *entdef.Section, name string) *entdef.Section {
	if s == nil {
		return nil
	}
	if c := s.Child(name); c != nil {
		return c
	}
	for _, c := range s.Children {
		if found := findChildDeep(c, name); found != nil {
			return found
		}
	}
	return nil
}

// vectorY reads the Y of a three-component vector section.
//
// The packed defs carry these two ways: as text ("0.000000 0.61209 -0.509952")
// and as the 12 raw bytes of three little-endian float32, which is what
// `turretPositions` uses — `AsString` is empty for those, the bytes are in
// `Raw`.
func vectorY(s *entdef.Section) (float64, error) {
	if text := s.AsString(); text != "" {
		if fields := strings.Fields(text); len(fields) >= 3 {
			return strconv.ParseFloat(fields[1], 64)
		}
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err == nil && len(raw) >= 12 {
			return float64(math.Float32frombits(binary.LittleEndian.Uint32(raw[4:8]))), nil
		}
	}
	if len(s.Raw) >= 12 {
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(s.Raw[4:8]))), nil
	}
	return 0, fmt.Errorf("vehiclespec: %q is not a vector", s.Name)
}

// pitchExtreme folds one (yaw, pitch) pair list down to its lowest or highest
// pitch, whichever pick does.
func pitchExtreme(s *entdef.Section, seed float64, pick func(a, b float64) float64) (float64, error) {
	if s == nil {
		return seed, nil
	}
	fields := strings.Fields(s.AsString())
	if len(fields)%2 != 0 {
		return 0, fmt.Errorf("pitchLimits %q is not (yaw, pitch) pairs", s.AsString())
	}
	out := seed
	for i := 1; i < len(fields); i += 2 {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return 0, fmt.Errorf("pitchLimits %q: %w", s.AsString(), err)
		}
		out = pick(out, v)
	}
	return out, nil
}

// motionLimitsIn reads the hull's movement envelope: `speedLimits/forward` and
// `speedLimits/backward` at the vehicle's root, and the chassis's own
// `rotationSpeed`, all in metres per second and degrees per second.
func motionLimitsIn(pkg, name, chassis string) (motionLimits, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return motionLimits{}, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	sl := f.Root.Child("speedLimits")
	if sl == nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s has no speedLimits", name)
	}
	fwd, err := floatChild(sl, "forward")
	if err != nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	bwd, err := floatChild(sl, "backward")
	if err != nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	cs := findSection(f.Root, chassis)
	if cs == nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s has no %s", name, chassis)
	}
	rot, err := floatChild(cs, "rotationSpeed")
	if err != nil {
		return motionLimits{}, fmt.Errorf("vehiclespec: %s/%s: %w", name, chassis, err)
	}
	// `speedLimits` is in km/h — the client's own `typeDescriptor.physics.
	// speedLimits` reports 10.28 for a 37 — and `rotationSpeed` in degrees per
	// second. Both have to be converted, or the hull drives 3.6x too fast and
	// the client's physics fights every position update.
	lim := motionLimits{
		SpeedForward:  float32(fwd / 3.6),
		SpeedBackward: float32(bwd / 3.6),
		RotationSpeed: float32(rot * math.Pi / 180),
	}
	// The per-ground turn rate: the chassis' own on firm ground, slower on
	// the others as their `terrainResistance` rises (the client's
	// `vehicles.py` `rotationSpeedLimit`).
	res := cs.Child("terrainResistance")
	if res != nil {
		if v, err := vec3String(res); err == nil && v[0] > 0 {
			for i, r := range v {
				if r > 0 {
					lim.RotationSpeedByGround[i] = lim.RotationSpeed * v[0] / r
				} else {
					lim.RotationSpeedByGround[i] = lim.RotationSpeed
				}
			}
		}
	}
	if lim.RotationSpeedByGround[0] == 0 {
		lim.RotationSpeedByGround = [3]float32{lim.RotationSpeed, lim.RotationSpeed, lim.RotationSpeed}
	}
	// The rolling friction per ground and the carrying point, from the
	// vehicle's own `physics/detailed` section.
	if phys := findSectionDeep(f.Root, "physics"); phys != nil {
		if det := phys.Child("detailed"); det != nil {
			if ch := findSection(det, chassis); ch != nil {
				if g := ch.Child("grounds"); g != nil {
					for i, name := range []string{"firm", "medium", "soft"} {
						if sec := g.Child(name); sec != nil {
							if v, err := floatChild(sec, "rollingFriction"); err == nil {
								lim.RollingFrictionByGround[i] = float32(v)
							}
						}
					}
				}
			}
			if eng := findSection(det, "engines"); eng != nil {
				// The engine the vehicle mounts, by the name its
				// `<engines>` block gives it.
				if e := f.Root.Child("engines"); e != nil && len(e.Children) > 0 {
					if es := eng.Child(e.Children[0].Name); es != nil {
						if v, err := floatChild(es, "smplEnginePower"); err == nil {
							lim.EnginePower = float32(v)
						}
					}
				}
			}
		}
	}
	if cp := cs.Child("topRightCarryingPoint"); cp != nil {
		if v, err := vec2String(cp); err == nil {
			lim.CarryingPoint = v
		}
	}
	return lim, nil
}

// findSectionDeep returns the first section with this name anywhere in the tree.
func findSectionDeep(s *entdef.Section, name string) *entdef.Section {
	if s == nil {
		return nil
	}
	if s.Name == name {
		return s
	}
	for _, c := range s.Children {
		if got := findSectionDeep(c, name); got != nil {
			return got
		}
	}
	return nil
}

// floatChild reads one numeric child.
func floatChild(s *entdef.Section, name string) (float64, error) {
	c := s.Child(name)
	if c == nil {
		return 0, fmt.Errorf("no %s", name)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(c.AsString()), 64)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", name, c.AsString(), err)
	}
	return v, nil
}

// trueSection reads a boolean-ish def section: explicit true/1, or a
// present-but-empty marker. "false"/"0" never count as true.
func trueSection(s *entdef.Section) bool {
	if s == nil {
		return false
	}
	if s.OwnType == entdef.TypeBool {
		return s.AsBool()
	}
	v := s.AsString()
	if v == "" {
		v = s.StrVal()
	}
	return v == "true" || v == "1"
}

// parsePair reads a "min max" pair of degrees.
func parsePair(s string) (float64, float64, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("vehiclespec: %q is not a pair", s)
	}
	lo, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, 0, err
	}
	hi, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, 0, err
	}
	return lo, hi, nil
}

// findSection returns the first section with this name anywhere in the tree.
// findSectionHaving is `findSection` restricted to the section that actually
// carries `child`. A component file also holds a name -> id map whose entries
// have the same names but no body, so the first match by name is often the
// index entry rather than the definition.
func findSectionHaving(s *entdef.Section, name, child string) *entdef.Section {
	if s == nil {
		return nil
	}
	if s.Name == name && s.Child(child) != nil {
		return s
	}
	for _, c := range s.Children {
		if got := findSectionHaving(c, name, child); got != nil {
			return got
		}
	}
	return nil
}

func findSection(s *entdef.Section, name string) *entdef.Section {
	if s == nil {
		return nil
	}
	if s.Name == name {
		return s
	}
	for _, c := range s.Children {
		if got := findSection(c, name); got != nil {
			return got
		}
	}
	return nil
}

// findRotationSpeed returns the `rotationSpeed` of the first section named
// `name` that has one, anywhere in the tree.
func findRotationSpeed(s *entdef.Section, name string) *entdef.Section {
	if s == nil {
		return nil
	}
	if s.Name == name {
		if rs := s.Child("rotationSpeed"); rs != nil {
			return rs
		}
	}
	for _, c := range s.Children {
		if got := findRotationSpeed(c, name); got != nil {
			return got
		}
	}
	return nil
}

// generatedVehicleTable is `lobby.GeneratedTable()` built once: it walks every
// generated vehicle and component row, which is not something to redo per
// battle.
var generatedVehicleTable = sync.OnceValue(func() *lobby.StaticTable {
	return lobby.GeneratedTable()
})

// dispersionIn reads the gun's dispersion model out of the vehicle's own def
// and the shared gun def, converting each field the way the client's
// `common/items/vehicles.py` does:
//
//	gun/shotDispersionRadius          atan(r / 100)          radians
//	gun/aimingTime                    as-is                  seconds
//	gun/shotDispersionFactors/turretRotation   degrees -> radians
//	chassis/shotDispersionFactors/vehicleMovement  / 3.6    m/s
//	chassis/shotDispersionFactors/vehicleRotation  degrees -> radians
//	gun/shots/<shell>/speed           as-is                  m/s
//
// The shell is the one with the largest `defaultPortion`: the capture shows the
// gun marker's `shotVector` length constant for a whole battle and switching
// only when the player switched shells, so the default load is the one to
// model.
func dispersionIn(pkg, vehicleName, gunsName, chassis, gun string) (dispersionSpec, error) {
	raw, err := readFromZip(pkg, vehicleName)
	if err != nil {
		return dispersionSpec{}, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s: %w", vehicleName, err)
	}
	if f.Root == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s: no root", vehicleName)
	}
	cs := findSectionHaving(f.Root, chassis, "shotDispersionFactors")
	if cs == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s has no %s with shotDispersionFactors", vehicleName, chassis)
	}
	cf := cs.Child("shotDispersionFactors")
	if cf == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s has no shotDispersionFactors", vehicleName, chassis)
	}
	move, err := floatChild(cf, "vehicleMovement")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", vehicleName, chassis, err)
	}
	rot, err := floatChild(cf, "vehicleRotation")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", vehicleName, chassis, err)
	}

	raw, err = readFromZip(pkg, gunsName)
	if err != nil {
		return dispersionSpec{}, err
	}
	gf, err := entdef.ParseFile(raw)
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s: %w", gunsName, err)
	}
	if gf.Root == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s: no root", gunsName)
	}
	gs := findSectionHaving(gf.Root, gun, "shotDispersionRadius")
	if gs == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s has no %s with shotDispersionRadius", gunsName, gun)
	}
	radius, err := floatChild(gs, "shotDispersionRadius")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	aiming, err := floatChild(gs, "aimingTime")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	gdf := gs.Child("shotDispersionFactors")
	if gdf == nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s has no shotDispersionFactors", gunsName, gun)
	}
	turretRot, err := floatChild(gdf, "turretRotation")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	shell, err := defaultShell(gs)
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	reload, err := floatChild(gs, "reloadTime")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	// The shell's compact descriptor needs the nation, which is the first
	// path element of the vehicle's own def name.
	nation := ""
	if i := strings.Index(vehicleName, "vehicles/"); i >= 0 {
		rest := vehicleName[i+len("vehicles/"):]
		if j := strings.Index(rest, "/"); j > 0 {
			nation = rest[:j]
		}
	}
	// The scrollable wheels: `chassis/wheels/wheel` entries that declare a
	// `scrollProcessor`. Their `radius` is what turns the hull's speed into
	// the angular speed `wheelsScroll` carries.
	wheelRadii := wheelRadiiIn(f.Root)
	// The siege-mode envelope lives in a sibling def named `<vehicle>_siege_mode`.
	siegeLimits, hasSiegeLimits := motionLimits{}, false
	if i := strings.LastIndex(vehicleName, ".xml"); i > 0 {
		if lim, e := motionLimitsIn(pkg, vehicleName[:i]+"_siege_mode.xml", chassis); e == nil {
			siegeLimits, hasSiegeLimits = lim, true
		}
	}
	// The siege switch times live in the vehicle's own `siege_mode` section.
	siegeOn, siegeOff, hasSiege := 0.0, 0.0, false
	if sm := findSection(f.Root, "siege_mode"); sm != nil {
		hasSiege = true
		if v, e := floatChild(sm, "switchOnTime"); e == nil {
			siegeOn = v
		}
		if v, e := floatChild(sm, "switchOffTime"); e == nil {
			siegeOff = v
		}
	}
	if data, derr := shellDataIn(pkg, nation, shell.Name); derr == nil {
		shell.Damage = data.Damage
		shell.Kind = data.Kind
		shell.KindIndex = data.KindIndex
		shell.Caliber = data.Caliber
		shell.EffectsIndex = data.EffectsIndex
		shell.PiercedSticker = data.PiercedSticker
		shell.HasPiercedSticker = data.HasPiercedSticker
	}
	shellCD := int32(0)
	if nation != "" {
		if id, serr := shellIDIn(pkg, nation, shell.Name); serr == nil {
			for idx, n := range nationNames {
				if n == nation {
					shellCD = shellCompactDescr(idx, id)
					break
				}
			}
		}
	}
	afterShot, err := floatChild(gdf, "afterShot")
	if err != nil {
		return dispersionSpec{}, fmt.Errorf("vehiclespec: %s/%s: %w", gunsName, gun, err)
	}
	// The magazine and the burst, as `_readGunClip`/`_readGunBurst` read them:
	// a count and a rate per minute; a count of 1 has no interval.
	magSize, magInterval := readClip(gdf, "clip")
	burstSize, burstInterval := readClip(gdf, "burst")
	return dispersionSpec{
		Angle:            math.Atan(radius / 100),
		AimingTime:       aiming,
		Movement:         move / 3.6,
		Rotation:         rot * math.Pi / 180,
		TurretRotation:   turretRot * math.Pi / 180,
		ShotSpeed:        shell.Speed,
		AfterShot:        afterShot,
		Piercing:         shell.Pen,
		Shell:            shell,
		ShellCD:          shellCD,
		ReloadTime:       reload,
		SiegeOn:          siegeOn,
		SiegeOff:         siegeOff,
		HasSiege:         hasSiege,
		WheelRadii:       wheelRadii,
		SiegeLimits:      siegeLimits,
		HasSiegeLimits:   hasSiegeLimits,
		MagazineSize:     magSize,
		MagazineInterval: magInterval,
		BurstSize:        burstSize,
		BurstInterval:    burstInterval,
	}, nil
}

// defaultShell is the gun's default shell — the one with the largest
// `defaultPortion` — as its muzzle velocity, penetration at 100 m and
// ballistics, from the gun's mounted `shots` entry.
func defaultShell(gs *entdef.Section) (shellSpec, error) {
	shots := gs.Child("shots")
	if shots == nil {
		return shellSpec{}, fmt.Errorf("no shots")
	}
	bestPortion := -1.0
	var best shellSpec
	for _, sh := range shots.Children {
		portion := 0.0
		if p := sh.Child("defaultPortion"); p != nil {
			v, perr := strconv.ParseFloat(strings.TrimSpace(p.AsString()), 64)
			if perr != nil {
				return shellSpec{}, fmt.Errorf("shell %s defaultPortion %q: %w", sh.Name, p.AsString(), perr)
			}
			portion = v
		}
		if portion <= bestPortion {
			continue
		}
		v, serr := floatChild(sh, "speed")
		if serr != nil {
			return shellSpec{}, fmt.Errorf("shell %s: %w", sh.Name, serr)
		}
		gravity, _ := floatChild(sh, "gravity")
		maxDist, _ := floatChild(sh, "maxDistance")
		// `piercingPower` is two values, at 100 m and at 500 m.
		pen, penFar := 0.0, 0.0
		if pp := sh.Child("piercingPower"); pp != nil {
			if lo, hi, perr := parsePair(pp.AsString()); perr == nil {
				pen, penFar = lo, hi
			}
		}
		best = shellSpec{
			Name: sh.Name, Pen: pen, PenNear: pen, PenFar: penFar,
			Speed: v, Gravity: gravity, MaxDistance: maxDist,
		}
		bestPortion = portion
	}
	if bestPortion < 0 {
		return shellSpec{}, fmt.Errorf("no shells")
	}
	return best, nil
}

// shellDataIn reads the shell's own def: its damage, kind, caliber and the
// `shot_effects.xml` index the client plays the hit effect from.
func shellDataIn(pkg, nation, name string) (shellSpec, error) {
	if nation == "" {
		return shellSpec{}, fmt.Errorf("no nation")
	}
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/"+nation+"/components/shells.xml")
	if err != nil {
		return shellSpec{}, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return shellSpec{}, fmt.Errorf("shells.xml: %w", err)
	}
	if f.Root == nil {
		return shellSpec{}, fmt.Errorf("shells.xml: no root")
	}
	sh := findSection(f.Root, name)
	if sh == nil {
		return shellSpec{}, fmt.Errorf("no shell %q", name)
	}
	kind := ""
	if k := sh.Child("kind"); k != nil {
		kind = strings.TrimSpace(k.AsString())
	}
	caliber, _ := floatChild(sh, "caliber")
	damage := 0.0
	if d := sh.Child("damage"); d != nil {
		if v, derr := floatChild(d, "armor"); derr == nil {
			damage = v
		}
	}
	// `effects` is a packed BLOB in the shipped defs, not a leaf string:
	// `AsString` returns "" for it, `StrVal` decodes it.
	effects := ""
	if e := sh.Child("effects"); e != nil {
		effects = strings.TrimSpace(e.StrVal())
	}
	shell := shellSpec{
		Name:         name,
		Damage:       damage,
		Kind:         kind,
		KindIndex:    shellKindIndex(kind),
		Caliber:      caliber,
		EffectsIndex: shotEffectsIndex(pkg, effects),
	}
	shell.PiercedSticker, shell.HasPiercedSticker = piercedStickerIndex(pkg, effects)
	// The kind's own parameters, as `_readShell` reads them: AP kinds
	// normalize toward the armour's normal, AP/APCR/HEAT ricochet past an
	// angle, and every shell's explosion radius is `caliber² / 5555`.
	shell.DamageNear, shell.DamageFar = damage, damage
	if d := sh.Child("damage"); d != nil {
		if lo, hi, derr := parsePair(d.Child("armor").AsString()); derr == nil {
			shell.DamageNear, shell.DamageFar = lo, hi
		}
	}
	if v, verr := floatChild(sh, "piercingPowerRandomization"); verr == nil {
		shell.PenRandomization = v
	} else {
		shell.PenRandomization = 0.25
	}
	if strings.HasPrefix(kind, "ARMOR_PIERCING") {
		if v, verr := floatChild(sh, "normalizationAngle"); verr == nil {
			shell.NormalizationAngle = v * math.Pi / 180
		}
	}
	switch kind {
	case "ARMOR_PIERCING", "ARMOR_PIERCING_CR", "HOLLOW_CHARGE":
		if v, verr := floatChild(sh, "ricochetAngle"); verr == nil {
			shell.RicochetAngleCos = math.Cos(v * math.Pi / 180)
			shell.HasRicochetAngle = true
		}
	}
	if v, verr := floatChild(sh, "piercingPowerLossFactorByDistance"); verr == nil {
		shell.JetPenLoss = 10 * v
	}
	shell.ExplosionRadius = caliber * caliber / 5555
	shell.PrefabEffectsIndex, shell.HasPrefabEffectsIndex = prefabEffectsIndex(pkg, kind, sh)
	return shell, nil
}

// prefabEffectsIndex reads a shell's `prefabEffects`, else its kind's default
// in `common/vehicle.xml`, as the client's item loader does.
func prefabEffectsIndex(pkg, kind string, sh *entdef.Section) (uint8, bool) {
	name := ""
	if p := sh.Child("prefabEffects"); p != nil {
		name = strings.TrimSpace(p.StrVal())
	}
	if name == "" {
		return 0, false
	}
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/common/prefab_effects/shot_effects.xml")
	if err != nil {
		return 0, false
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return 0, false
	}
	for i, c := range f.Root.Children {
		if c.Name == name {
			return uint8(i), true
		}
	}
	return 0, false
}

// piercedStickerIndex is the shell's `armorPierced` damage sticker: the
// `targetStickers/armorPierced` name under its `shot_effects.xml` entry,
// resolved to its position in `common/damage_stickers.xml`. The client's
// `Vehicle.addDamageSticker` takes that index as the sticker id, see the
// reference server's `add_sticker`.
func piercedStickerIndex(pkg, effects string) (uint8, bool) {
	if effects == "" {
		return 0, false
	}
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/common/shot_effects.xml")
	if err != nil {
		return 0, false
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return 0, false
	}
	sticker := ""
	for _, c := range f.Root.Children {
		if c.Name != effects {
			continue
		}
		ts := c.Child("targetStickers")
		if ts == nil {
			break
		}
		if a := ts.Child("armorPierced"); a != nil {
			sticker = strings.TrimSpace(a.AsString())
		}
		break
	}
	if sticker == "" {
		return 0, false
	}
	raw, err = readFromZip(pkg, "scripts/item_defs/vehicles/common/damage_stickers.xml")
	if err != nil {
		return 0, false
	}
	f, err = entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return 0, false
	}
	idx := 0
	for _, c := range f.Root.Children {
		if strings.HasPrefix(c.Name, "xmlns:") || c.Name == "texture" {
			continue
		}
		if c.Name == sticker {
			return uint8(idx), true
		}
		idx++
	}
	return 0, false
}

// shellKindIndex is the shell kind's index in the client's
// `SHELL_TYPES_LIST` (the `kind` byte the tracer and the hit point carry).
func shellKindIndex(kind string) uint8 {
	switch kind {
	case "HOLLOW_CHARGE":
		return 0
	case "HIGH_EXPLOSIVE":
		return 1
	case "ARMOR_PIERCING":
		return 2
	case "ARMOR_PIERCING_HE":
		return 3
	case "ARMOR_PIERCING_CR":
		return 4
	}
	return 2
}

// shotEffectsIndex is the position of the shell's `effects` name in
// `common/shot_effects.xml`: the index the client's
// `vehicles.g_cache.shotEffects` is keyed by.
func shotEffectsIndex(pkg, effects string) uint8 {
	if effects == "" {
		return 0
	}
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/common/shot_effects.xml")
	if err != nil {
		return 0
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return 0
	}
	idx := 0
	for _, c := range f.Root.Children {
		if strings.HasPrefix(c.Name, "xmlns:") {
			continue
		}
		if c.Name == effects {
			return uint8(idx)
		}
		idx++
	}
	return 0
}

// wheelRadiiIn collects the radius of every wheel the client's wheel animator
// scrolls, in def order.
//
// The count is `generalWheelsAnimatorConfig.getNonTrackWheelsCount()`, which is
// the number of `wheel` entries carrying `<nonTrack>true</nonTrack>` — NOT every
// wheel. `Vehicle.set_wheelsScroll` zips `wheelsScroll` against
// `createWheelFilters`' scroll-filter list, which is built from that same count,
// so a longer tuple is silently truncated and a shorter one leaves the tail
// un-driven. The EBR 105 declares 16 wheels and only 8 are non-track.
//
// The `wheels` section sits under the chassis section, whose name varies per
// vehicle, so this walks the tree rather than looking it up by name.
func wheelRadiiIn(root *entdef.Section) []float64 {
	var out []float64
	var walk func(s *entdef.Section)
	walk = func(s *entdef.Section) {
		if s.Name == "wheels" {
			for _, w := range s.Children {
				if w.Name != "wheel" {
					continue
				}
				if nt := w.Child("nonTrack"); nt == nil || !trueSection(nt) {
					continue
				}
				// The wheel entry carries no `radius` of its own — it is in
				// the wheel's `geometry` — so the radius falls back to a
				// mid-size road wheel when it is missing.
				r := 0.5
				if g := w.Child("geometry"); g != nil {
					if v, e := floatChild(g, "radius"); e == nil && v > 0 {
						r = v
					}
				}
				out = append(out, r)
			}
		}
		for _, c := range s.Children {
			walk(c)
		}
	}
	walk(root)
	return out
}

// nationNames is `nations.NAMES` from the client's own `common/nations.pyc`.
// A shell's compact descriptor carries the nation as its index here, so the
// order is part of the wire format, not a display detail.
var nationNames = []string{
	"ussr", "germany", "usa", "china", "france", "uk", "japan", "czech",
	"sweden", "poland", "italy",
}

// shellItemType is `ITEM_TYPES['shell']`: the index of `shell` in
// `items.ITEM_TYPE_NAMES`.
const shellItemType = 10

// shellCompactDescr is `items.makeIntCompactDescrByID('shell', nation, id)`.
func shellCompactDescr(nation int, id int64) int32 {
	return int32((id << 8) + shellItemType + (int64(nation) << 4))
}

// shellIDIn reads a shell's `id` from a nation's `components/shells.xml`.
func shellIDIn(pkg, nation, shell string) (int64, error) {
	name := "scripts/item_defs/vehicles/" + nation + "/components/shells.xml"
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return 0, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return 0, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return 0, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	sh := f.Root.Child(shell)
	if sh == nil {
		return 0, fmt.Errorf("vehiclespec: %s has no shell %s", name, shell)
	}
	id, err := floatChild(sh, "id")
	if err != nil {
		return 0, fmt.Errorf("vehiclespec: %s/%s: %w", name, shell, err)
	}
	return int64(id), nil
}

// INTERPOLATION_DISTANCES are where a shell's near and far figures apply, in
// metres: its penetration and damage fall off linearly between them.
var interpolationDistances = [2]float64{100, 500}

// penAt is the shell's penetration after flying this far. A spec without the
// defs' near/far pair (a synthetic one) falls back to its single figure.
func (s shellSpec) penAt(distance float64) float64 {
	if s.PenNear == 0 && s.PenFar == 0 {
		return s.Pen
	}
	return interpolateByDistance(s.PenNear, s.PenFar, distance)
}

// damageAt is the shell's damage after flying this far, with the same
// fallback.
func (s shellSpec) damageAt(distance float64) float64 {
	if s.DamageNear == 0 && s.DamageFar == 0 {
		return s.Damage
	}
	return interpolateByDistance(s.DamageNear, s.DamageFar, distance)
}

// interpolateByDistance is the reference's `interpolate_by_distance`: linear
// from the near distance to the far one, clamped at both ends.
func interpolateByDistance(near, far, distance float64) float64 {
	first, last := interpolationDistances[0], interpolationDistances[1]
	t := (math.Max(distance, first) - first) / (last - first)
	if v := near + (far-near)*t; v > 0 {
		return v
	}
	return 0
}

// readClip reads a gun's `<clip>` or `<burst>`: its shell count and its rate
// per minute, turned into the seconds between two shells. A count of 1 is no
// magazine and no interval.
func readClip(gun *entdef.Section, name string) (uint32, float32) {
	sec := gun.Child(name)
	if sec == nil {
		return 1, 0
	}
	count := uint32(1)
	if c := sec.Child("count"); c != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(c.StrVal())); err == nil && v > 1 {
			count = uint32(v)
		}
	}
	if count <= 1 {
		return 1, 0
	}
	rate, err := floatChild(sec, "rate")
	if err != nil || rate <= 0 {
		return count, 0
	}
	return count, float32(60 / rate)
}
