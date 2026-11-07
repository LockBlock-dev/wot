package login

import (
	"math"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestResolveShotHitsTheDummyFront checks the trace and the front-armour
// penetration: a shell with more penetration than the TOG II's 76.2 mm front
// pierces it and rolls damage.
func TestResolveShotHitsTheDummyFront(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Name: "test", Damage: 300, Pen: 200, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	// From 20 m in front of the tank, firing straight at it (-Z).
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if !res.Pierced {
		t.Fatalf("pierced = false, want true (pen 200 vs armour %.1f)", res.Armor)
	}
	if math.Abs(float64(res.Armor-76.2)) > 0.01 {
		t.Fatalf("effective armour = %.2f, want 76.2", res.Armor)
	}
	if res.Damage < 225 || res.Damage > 375 {
		t.Fatalf("damage = %d, want 225..375 (300 ±25%%)", res.Damage)
	}
	if res.Effect != hitEffectPierced {
		t.Fatalf("effect = %d, want %d", res.Effect, hitEffectPierced)
	}
	if res.Flags != hitFlagsPierced {
		t.Fatalf("flags = %#x, want %#x", res.Flags, hitFlagsPierced)
	}
	// The front face is at +Z, so the hit point is there and the outward
	// normal points at the shooter.
	if math.Abs(float64(res.Point[2]-5)) > 0.01 {
		t.Fatalf("hit z = %v, want 5 (the front face)", res.Point[2])
	}
	if res.Normal[2] != 1 {
		t.Fatalf("normal = %v, want +Z", res.Normal)
	}
}

// TestResolveShotRearArmour checks that the same shell meets the thinner rear
// plate from behind.
func TestResolveShotRearArmour(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 200, KindIndex: 2, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, -20}, [3]float32{0, 0, 1}, box)
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if math.Abs(float64(res.Armor-50.8)) > 0.01 {
		t.Fatalf("effective armour = %.2f, want the 50.8 rear", res.Armor)
	}
	if !res.Pierced {
		t.Fatal("pen 200 should pierce the 50.8 rear")
	}
}

// TestResolveShotMisses checks that a shot beside the tank does nothing.
func TestResolveShotMisses(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 200, KindIndex: 2, Caliber: 76.2}
	if res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{1, 0, 0}, box); res.Hit {
		t.Fatalf("shot beside the tank hit at %v", res.Point)
	}
}

// TestResolveShotAngleIncreasesArmour checks the impact-angle term: a 45°
// hit on the 76.2 mm front meets about 107.8 mm.
func TestResolveShotAngleIncreasesArmour(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 1000, KindIndex: 2, Caliber: 76.2}
	// 45° off the front normal, from far enough left that the ray meets
	// the front plate before the side.
	dir := [3]float32{float32(math.Sin(math.Pi / 4)), 0, -float32(math.Cos(math.Pi / 4))}
	res := resolveShot(sh, [3]float32{-15, 2, 20}, dir, box)
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	want := 76.2 / math.Cos(math.Pi/4)
	if math.Abs(float64(res.Armor)-want) > 0.5 {
		t.Fatalf("effective armour = %.2f, want %.2f", res.Armor, want)
	}
}

// TestResolveShotNotPierced checks a shell that cannot get through: no
// damage, the resisted effect and the not-pierced flags.
func TestResolveShotNotPierced(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 50, KindIndex: 2, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if res.Pierced {
		t.Fatal("pen 50 should not pierce 76.2 mm")
	}
	if res.Damage != 0 {
		t.Fatalf("damage = %d, want 0", res.Damage)
	}
	if res.Effect != hitEffectNotPierced {
		t.Fatalf("effect = %d, want %d", res.Effect, hitEffectNotPierced)
	}
	if res.Flags != hitFlagDirect|hitFlagArmorNotPierced {
		t.Fatalf("flags = %#x, want %#x", res.Flags, hitFlagDirect|hitFlagArmorNotPierced)
	}
}

// TestResolveShotHEExplodes checks an HE shell that does not pierce still
// deals its explosion damage and sets the explosion flag.
func TestResolveShotHEExplodes(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 10, Kind: "HIGH_EXPLOSIVE", KindIndex: 1, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
	if !res.Hit || res.Pierced {
		t.Fatalf("hit=%v pierced=%v, want a non-piercing hit", res.Hit, res.Pierced)
	}
	if res.Damage <= 0 {
		t.Fatal("HE explosion did no damage")
	}
	if res.Flags&hitFlagExploded == 0 {
		t.Fatalf("flags = %#x, want the explosion bit", res.Flags)
	}
}

// TestEncodeHitSegment checks the hit-point segment's packing: the hull part
// and hit effect in the low bytes, the quantized enter/exit points above.
func TestEncodeHitSegment(t *testing.T) {
	bounds := dummyBounds()
	// A point on the front face, travelling -Z.
	seg := encodeHitSegment(bounds, [3]float32{0, 0, 5}, [3]float32{0, 0, -1}, 1, hitEffectPierced)
	if got := uint8(seg); got != hitEffectPierced {
		t.Fatalf("context = %d, want %d", got, hitEffectPierced)
	}
	if got := uint8(seg >> 8); got != 1 {
		t.Fatalf("part = %d, want 1 (hull)", got)
	}
	// The segment enters at the front (z = 5 → 255) and leaves at the rear
	// (z = -5 → 0); x and y are the box's middle (about 128).
	ax, ay, az := uint8(seg>>16), uint8(seg>>24), uint8(seg>>32)
	bx, by, bz := uint8(seg>>40), uint8(seg>>48), uint8(seg>>56)
	if az != 255 || bz != 0 {
		t.Fatalf("segment z = %d..%d, want 255..0", az, bz)
	}
	for _, v := range []uint8{ax, ay, bx, by} {
		if v < 126 || v > 130 {
			t.Fatalf("segment x/y = %d, want about 128", v)
		}
	}
}

// TestHitParams checks the `VEHICLE_HIT_POINT.params` word.
func TestHitParams(t *testing.T) {
	sh := shellSpec{Caliber: 76.2, KindIndex: 2}
	got := hitParams(sh, hitEffectPierced)
	want := uint32(762)<<8 | uint32(2)<<4 | uint32(hitEffectPierced)
	if got != want {
		t.Fatalf("params = %#x, want %#x", got, want)
	}
}

// TestDamageMethodCalls checks the client method calls against the shipped
// 2.4.1 defs: the exposed ids and the nine-argument showDamageFromShot.
func TestDamageMethodCalls(t *testing.T) {
	d := testDispatch(t)
	vehType := d.Entity("Vehicle")
	avatarType := d.Entity("Avatar")
	if vehType == nil || avatarType == nil {
		t.Fatal("defs have no Vehicle/Avatar")
	}
	vehicle := NewEntity(100, vehType)
	avatar := NewEntity(200, avatarType)

	point := hitPointValue(0x0102030405060708, hitParams(shellSpec{Caliber: 76.2, KindIndex: 2}, hitEffectPierced))
	el, err := showDamageFromShotElement(vehicle, 42, point, 3, 300, 61, 800)
	if err != nil {
		t.Fatalf("showDamageFromShot: %v", err)
	}
	if want := byte(entityMethodBase + 10); el[0] != want {
		t.Fatalf("showDamageFromShot id = %#x, want %#x", el[0], want)
	}
	if len(el) < 20 {
		t.Fatalf("showDamageFromShot = %d B, want the full nine-argument payload", len(el))
	}

	el, err = onHealthChangedElement(vehicle, 948, 1248, 42)
	if err != nil {
		t.Fatalf("onHealthChanged: %v", err)
	}
	if want := byte(entityMethodBase + 4); el[0] != want {
		t.Fatalf("onHealthChanged id = %#x, want %#x", el[0], want)
	}

	el, err = showShotResultsElement(avatar, 100, hitFlagsPierced)
	if err != nil {
		t.Fatalf("showShotResults: %v", err)
	}
	if want := byte(entityMethodBase + 54); el[0] != want {
		t.Fatalf("showShotResults id = %#x, want %#x", el[0], want)
	}

	el, err = showTracerElement(avatar, 42, 1, shellSpec{Caliber: 76.2, KindIndex: 2, Speed: 800, Gravity: 9.81, MaxDistance: 720}, [3]float32{0, 2, 20}, [3]float32{0, 0, -800})
	if err != nil {
		t.Fatalf("showTracer: %v", err)
	}
	// The live S>C tracers ride `1a 0x73`, i.e. exposed id 37 (the replay's
	// method id 17 is a different numbering).
	if want := byte(entityMethodBase + 37); el[0] != want {
		t.Fatalf("showTracer id = %#x, want %#x", el[0], want)
	}

	el, err = stopTracerElement(avatar, 1, [3]float32{0, 2, 5})
	if err != nil {
		t.Fatalf("stopTracer: %v", err)
	}
	if el[0] <= entityMethodBase || el[0] > entityMethodBase+0x58 {
		t.Fatalf("stopTracer id = %#x, outside the client method range", el[0])
	}
}

// TestDamageMethodCallsNeedTheDefs guards the argument shapes: a wrong count
// or type is an error, not a silently short element.
func TestDamageMethodCallsNeedTheDefs(t *testing.T) {
	d := testDispatch(t)
	vehType := d.Entity("Vehicle")
	if vehType == nil {
		t.Fatal("defs have no Vehicle")
	}
	vehicle := NewEntity(100, vehType)
	if _, err := EncodeClientMethodCall(vehicle, "showDamageFromShot", []entdef.Value{{Kind: entdef.VUint}}); err == nil {
		t.Fatal("showDamageFromShot accepted one argument")
	}
}

// TestDispersionShellData checks the shell's own def is read: damage, kind,
// penetration and the shot-effects index. It needs the game's scripts.pkg.
func TestDispersionShellData(t *testing.T) {
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no scripts.pkg")
	}
	d, err := dispersionIn(pkg,
		"scripts/item_defs/vehicles/uk/GB63_TOG_II.xml",
		"scripts/item_defs/vehicles/uk/components/guns.xml",
		"Chassis_GB63_TOG_II", "OQF_17pdr_Gun_Mk_VII_A")
	if err != nil {
		t.Fatalf("dispersionIn: %v", err)
	}
	if d.Shell.Name != "_17pdr_AP_Mk3T" {
		t.Fatalf("shell = %q, want the default AP", d.Shell.Name)
	}
	if d.Shell.Damage != 150 {
		t.Fatalf("damage = %v, want 150", d.Shell.Damage)
	}
	if d.Shell.Pen != 171 {
		t.Fatalf("pen = %v, want 171", d.Shell.Pen)
	}
	if d.Shell.KindIndex != 2 {
		t.Fatalf("kind = %d, want 2 (ARMOR_PIERCING)", d.Shell.KindIndex)
	}
	if d.Shell.Caliber != 76.2 {
		t.Fatalf("caliber = %v, want 76.2", d.Shell.Caliber)
	}
	if d.Shell.EffectsIndex == 0 {
		t.Fatalf("effects index = 0, want the shot_effects position")
	}
}
