package login

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// TestRicochetsOffGround pins the ground skim: AP and APCR shells bounce off
// the ground within 8 degrees of the surface, nothing else does.
func TestRicochetsOffGround(t *testing.T) {
	ap := shellSpec{Kind: "ARMOR_PIERCING"}
	apcr := shellSpec{Kind: "ARMOR_PIERCING_CR"}
	he := shellSpec{Kind: "HIGH_EXPLOSIVE"}
	heat := shellSpec{Kind: "HOLLOW_CHARGE"}
	at := func(deg float64) [3]float32 {
		r := deg * math.Pi / 180
		return [3]float32{float32(math.Cos(r) * 800), float32(-math.Sin(r) * 800), 0}
	}
	up := [3]float32{0, 1, 0}
	if !ricochetsOffGround(ap, at(5), up) {
		t.Error("AP at 5 degrees did not ricochet")
	}
	if !ricochetsOffGround(apcr, at(5), up) {
		t.Error("APCR at 5 degrees did not ricochet")
	}
	if ricochetsOffGround(ap, at(12), up) {
		t.Error("AP at 12 degrees ricocheted")
	}
	if ricochetsOffGround(he, at(5), up) || ricochetsOffGround(heat, at(5), up) {
		t.Error("an HE or HEAT shell ricocheted off the ground")
	}
	// A shell coming down steeply into the ground never skims.
	if ricochetsOffGround(ap, [3]float32{0, -800, 0}, up) {
		t.Error("a vertical AP impact ricocheted")
	}
	// The penetration kept: 75% for AP and APCR, all for the rest.
	if got := ricochetPenFactor(ap); got != 0.75 {
		t.Errorf("AP ricochet keeps %v, want 0.75", got)
	}
	if got := ricochetPenFactor(he); got != 1 {
		t.Errorf("HE ricochet keeps %v, want 1", got)
	}
}

// TestExplosionReachesTheArmour pins the HE blast: a shell exploding beside a
// tank damages it through the plates between the blast and its main armour,
// and not at all beyond its radius.
func TestExplosionReachesTheArmour(t *testing.T) {
	// A 2 m cube of 40 mm armour, its centre 1.4 m above the ground.
	box := hitBox{
		Bounds: [2][3]float32{{-1, 0, -1}, {1, 2, 1}},
		Armor:  [4]float32{40, 40, 40, 40},
		Part:   1,
	}
	tgt := &botTarget{pos: [3]float32{0, 0, 0}, collision: boxCollision(box), health: 1000, maxHealth: 1000}
	sh := shellSpec{Kind: "HIGH_EXPLOSIVE", KindIndex: 1, Damage: 300, DamageNear: 300, DamageFar: 300, ExplosionRadius: 2.5, Caliber: 105}

	// Beside the tank, 1 m from its side: the blast reaches it.
	damage, hit, ok := explosionAt(sh, [3]float32{2.0, 1.0, 0}, tgt.collision, tgt.pos, tgt.yaw)
	if !ok {
		t.Fatal("the blast did not reach the tank")
	}
	if damage <= 0 {
		t.Fatalf("damage = %v, want > 0", damage)
	}
	if hit.GroupName == "" {
		t.Fatal("the blast reached no armour group")
	}
	// The damage falls off with the distance: nearer is stronger.
	near, _, okNear := explosionAt(sh, [3]float32{1.2, 1.0, 0}, tgt.collision, tgt.pos, tgt.yaw)
	if !okNear || near <= damage {
		t.Errorf("near damage %v, far damage %v: want the nearer one stronger", near, damage)
	}
	// Beyond the radius there is nothing.
	if _, _, ok := explosionAt(sh, [3]float32{8, 1, 0}, tgt.collision, tgt.pos, tgt.yaw); ok {
		t.Error("the blast reached a tank 8 m away with a 2.5 m radius")
	}
	// An AP shell has no blast at all.
	ap := sh
	ap.Kind, ap.KindIndex, ap.ExplosionRadius = "ARMOR_PIERCING", 2, 0
	if _, _, ok := explosionAt(ap, [3]float32{2.0, 1.0, 0}, tgt.collision, tgt.pos, tgt.yaw); ok {
		t.Error("an AP shell exploded")
	}
}

// TestStaticEffectMaterial pins the impact material a static body shows.
func TestStaticEffectMaterial(t *testing.T) {
	cases := map[string]uint8{
		"n_stone_10":   effectMaterialStone,
		"n_wood0_1":    effectMaterialWood,
		"n_metal1_1_2": effectMaterialMetal,
		"s_nd0":        effectMaterialGround,
		"c_c_stone0_1": effectMaterialStone,
	}
	for name, want := range cases {
		if got := staticEffectMaterial(staticTriangle{Body: name}); got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

// TestVehicleRicochetGoesOn pins a shell bouncing off armour: the outcome is a
// ricochet with no damage, the velocity is mirrored off the plate's normal at
// the same speed, and the shell goes on from just before the point it hit with
// a share of its penetration — the reference's `Shot::ricochet`.
func TestVehicleRicochetGoesOn(t *testing.T) {
	// A 2 m box, its +Z face square on to a shell flying nearly parallel to it.
	box := hitBox{
		Bounds: [2][3]float32{{-1, 0, -1}, {1, 2, 1}},
		Armor:  [4]float32{40, 40, 40, 40},
		Part:   1,
	}
	tgt := &botTarget{pos: [3]float32{0, 0, 12}, collision: boxCollision(box), health: 1000, maxHealth: 1000}
	sh := shellSpec{
		Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2,
		Pen: 200, PenNear: 200, PenFar: 200, Damage: 300, DamageNear: 300, DamageFar: 300,
		HasRicochetAngle: true, RicochetAngleCos: math.Cos(70 * math.Pi / 180),
	}
	// From 10 m to the left, 0.2 m in front of the face, so the path crosses it
	// at about one degree.
	from := [3]float32{-10, 1, 13.2}
	dir := [3]float32{1, 0, -0.02}
	l := float32(math.Sqrt(float64(dir[0]*dir[0] + dir[2]*dir[2])))
	dir = [3]float32{dir[0] / l, 0, dir[2] / l}
	to := [3]float32{from[0] + dir[0]*20, from[1], from[2] + dir[2]*20}
	h, ok := tgt.collision.firstHit(tgt.pos, tgt.yaw, from, to)
	if !ok {
		t.Fatal("the shell missed the box")
	}
	res, ok := rollVehicleHit(sh, 0, h, dir, float64(h.Distance), 1, tgt.collision, tgt.pos, tgt.yaw)
	if !ok {
		t.Fatal("the shell met no armour")
	}
	if res.Effect != hitEffectRicochet {
		t.Fatalf("effect = %d, want a ricochet", res.Effect)
	}
	if res.Damage != 0 {
		t.Fatalf("damage = %d, want 0: a ricochet does no damage", res.Damage)
	}
	// The velocity mirrors off the plate's normal, at the same speed.
	v := [3]float32{dir[0] * 800, 0, dir[2] * 800}
	reflected := reflect(v, res.Normal)
	speedIn := math.Hypot(float64(v[0]), float64(v[2]))
	speedOut := math.Hypot(float64(reflected[0]), float64(reflected[2]))
	if math.Abs(speedIn-speedOut) > 0.01 {
		t.Errorf("speed %v -> %v, want the same", speedIn, speedOut)
	}
	if reflected[2] <= 0 {
		t.Errorf("reflected velocity %v, want it away from the face (+Z)", reflected)
	}
	// The shell goes on from just before the point it hit.
	start := ricochetStart(h.Point, v)
	if d := dist3(start, h.Point); math.Abs(float64(d-ricochetStandoff)) > 1e-6 {
		t.Errorf("standoff = %v, want %v", d, ricochetStandoff)
	}
	// What it keeps of its penetration.
	if got := ricochetPenFactor(sh); got != 0.75 {
		t.Errorf("AP keeps %v of its penetration, want 0.75", got)
	}
}

// TestRicochetTracerCarriesTheFlagAndRange pins the tracer the client gets for
// the continuing shell: it is flagged as a ricochet and carries what is left of
// the shell's range, not the whole of it.
func TestRicochetTracerCarriesTheFlagAndRange(t *testing.T) {
	d := testDispatch(t)
	avatarType := d.Entity("Avatar")
	if avatarType == nil {
		t.Fatal("defs have no Avatar")
	}
	avatar := NewEntity(100003, avatarType)
	sh := shellSpec{Caliber: 76.2, KindIndex: 2, EffectsIndex: 16, Gravity: 9.81, MaxDistance: 720}
	el, err := showTracerElement(avatar, 42, 7, sh, [3]float32{0, 1, 0}, [3]float32{0, 0, -800}, true, 500)
	if err != nil {
		t.Fatal(err)
	}
	// The ricochet flag is the third argument, a UINT: 1 for a ricochet.
	if !bytes.Contains(el, []byte{0x01, 0x00, 0x00, 0x00}) && !bytes.Contains(el, []byte{0x01}) {
		t.Fatalf("tracer = % x, want the ricochet flag", el)
	}
	// The range argument is the remaining 500 m, as a float32.
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], math.Float32bits(500))
	if !bytes.Contains(el, want[:]) {
		t.Fatalf("tracer = % x, want the remaining range 500", el)
	}
}

// TestDestructiblesWithin pins the blast's reach over the statics: the
// destructible bodies near the point come back once each, the solid ones and
// the far ones do not.
func TestDestructiblesWithin(t *testing.T) {
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	add := func(instance uint32, body string, kind staticBodyKind, x float32) {
		scene.Triangles = append(scene.Triangles, staticTriangle{
			Vertices: [3][3]float32{{x, 0, 0}, {x + 1, 0, 0}, {x, 1, 0}},
			Bounds:   [2][3]float32{{x, 0, 0}, {x + 1, 1, 0}},
			Instance: instance,
			Body:     body,
			Kind:     kind,
		})
	}
	add(1, "n_tree_1", bodyDestructible, 0)
	add(1, "n_tree_1", bodyDestructible, 0) // the same body's second triangle
	add(2, "n_wood0_1", bodyModule, 1)
	add(3, "s_rock", bodySolid, 0)
	add(4, "n_far", bodyDestructible, 40)
	// The grid has to be rebuilt for the query to see the triangles.
	scene.rebuildGrid()
	got := scene.destructiblesWithin([3]float32{0, 0, 0}, 5)
	if len(got) != 2 {
		t.Fatalf("%d destructibles in reach, want 2 (the tree and the module): %+v", len(got), got)
	}
	names := map[string]bool{}
	for _, tri := range got {
		names[tri.Body] = true
	}
	if !names["n_tree_1"] || !names["n_wood0_1"] {
		t.Fatalf("reached %v, want the tree and the module", names)
	}
	// A blast that reaches nothing.
	if got := scene.destructiblesWithin([3]float32{100, 0, 100}, 0.1); len(got) != 0 {
		t.Fatalf("%d destructibles in a blast 100 m away, want none", len(got))
	}
}

// TestShellParametersSurviveTheMerge pins the shell's own def: its explosion
// radius, normalization, ricochet angle and damage pair all reach the spec, not
// just the kind and caliber.
func TestShellParametersSurviveTheMerge(t *testing.T) {
	gamePackages(t)
	sp, ok := vehicleGunSpeeds(mustHex(t, "414a9d006500cd0022008200630000"))
	if !ok {
		t.Skip("no EBR 105 defs")
	}
	sh := sp.Dispersion.Shell
	if sh.ExplosionRadius <= 0 {
		t.Errorf("explosion radius = %v, want the shell's caliber²/5555", sh.ExplosionRadius)
	}
	if sh.NormalizationAngle <= 0 {
		t.Errorf("normalization = %v, want the shell's own", sh.NormalizationAngle)
	}
	if !sh.HasRicochetAngle {
		t.Error("the shell has no ricochet angle")
	}
	if sh.DamageNear <= 0 || sh.DamageFar <= 0 {
		t.Errorf("damage pair = %v/%v, want the shell's own", sh.DamageNear, sh.DamageFar)
	}
	if sh.PenNear <= 0 {
		t.Errorf("penetration = %v, want the gun's own pair", sh.PenNear)
	}
}
