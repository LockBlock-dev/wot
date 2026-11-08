package login

import (
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
	damage, hit, ok := explosionAt(sh, [3]float32{2.0, 1.0, 0}, tgt)
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
	near, _, okNear := explosionAt(sh, [3]float32{1.2, 1.0, 0}, tgt)
	if !okNear || near <= damage {
		t.Errorf("near damage %v, far damage %v: want the nearer one stronger", near, damage)
	}
	// Beyond the radius there is nothing.
	if _, _, ok := explosionAt(sh, [3]float32{8, 1, 0}, tgt); ok {
		t.Error("the blast reached a tank 8 m away with a 2.5 m radius")
	}
	// An AP shell has no blast at all.
	ap := sh
	ap.Kind, ap.KindIndex, ap.ExplosionRadius = "ARMOR_PIERCING", 2, 0
	if _, _, ok := explosionAt(ap, [3]float32{2.0, 1.0, 0}, tgt); ok {
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
