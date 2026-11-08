package login

import (
	"math"
	"path/filepath"
	"testing"
)

// TestVehicleCollisionFromTheGame loads the TOG II's real client collision
// model and traces shots through it: the armour the shell meets is the group's
// own material (the hull's front plate is `armor_1` at 76.2 mm, the turret's
// roof `armor_7` at 19), and the gun is a device that takes no hull damage.
//
// Skips when the game's files are not installed.
func TestVehicleCollisionFromTheGame(t *testing.T) {
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no game files")
	}
	if MapPackagesDir == "" {
		// The CLI derives it from the scripts package; the test does the same.
		MapPackagesDir = filepath.Dir(pkg)
	}
	c := VehicleCollisionFor("uk", "GB63_TOG_II")
	if c == nil {
		t.Skip("no TOG II collision model")
	}
	if len(c.Parts) != 4 {
		t.Fatalf("%d parts, want chassis, hull, turret and gun", len(c.Parts))
	}
	// The hull's front plate: +Z, armor_1, 76.2 mm.
	hull := c.Parts[1]
	if hull.Part != 1 {
		t.Fatalf("part 1 is %d", hull.Part)
	}
	if math.Abs(float64(hull.Offset[1]-1.3553)) > 1e-3 {
		t.Errorf("hull offset y = %v, want the chassis' hullPosition 1.3553", hull.Offset[1])
	}
	plate := func(part vehiclePartModel, name string) *material {
		for i := range part.Groups {
			if part.Groups[i].Name == name {
				return part.Groups[i].Material
			}
		}
		return nil
	}
	if m := plate(hull, "armor_1"); m == nil || math.Abs(float64(m.Armor-76.2)) > 0.01 {
		t.Fatalf("hull armor_1 = %+v, want 76.2 mm", m)
	}
	if m := plate(c.Parts[2], "armor_7"); m == nil || math.Abs(float64(m.Armor-19)) > 0.01 {
		t.Fatalf("turret armor_7 = %+v, want 19 mm", m)
	}
	gun := plate(c.Parts[3], "gun")
	if gun == nil || gun.isMainArmor() {
		t.Fatalf("gun material = %+v, want a device (no hull damage)", gun)
	}
	// A shot at the hull's front plate, from 20 m ahead of it.
	sh := shellSpec{Name: "AP", Damage: 300, Pen: 400, PenNear: 400, PenFar: 380, DamageNear: 300, DamageFar: 280, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	from := [3]float32{0, hull.Offset[1] + 0.3, 20}
	to := [3]float32{0, from[1], -20}
	h, ok := c.firstHit([3]float32{}, 0, from, to)
	if !ok {
		t.Fatal("the shot missed the hull")
	}
	if h.Part != 1 || h.GroupName != "armor_1" {
		t.Fatalf("hit part %d group %s, want the hull's armor_1", h.Part, h.GroupName)
	}
	// The TOG II's front plate is sloped, so the hit is inside the box's max
	// z: the point is on the mesh, not on the box.
	if h.Point[2] < 0 || h.Point[2] > hull.Bounds[1][2] {
		t.Errorf("hit z = %v, want the front plate inside the box's %v", h.Point[2], hull.Bounds[1][2])
	}
	if math.Abs(float64(h.Point[0])) > 0.01 {
		t.Errorf("hit x = %v, want the centre line", h.Point[0])
	}
	impact, ok := armorHit(sh, 20, 1, h.Point, [3]float32{0, 0, -1}, c, [3]float32{}, 0)
	if !ok || impact.Outcome != outcomePierced {
		t.Fatalf("impact = %+v, want a pierce (400 mm against 76.2)", impact)
	}
	if impact.Hit.GroupName != "armor_1" {
		t.Errorf("pierced %s, want armor_1", impact.Hit.GroupName)
	}
	// The same shot at the gun: a device, so the hull takes nothing.
	gunPart := c.Parts[3]
	gy := gunPart.Offset[1]
	gfrom := [3]float32{0, gy, 20}
	gto := [3]float32{0, gy, -20}
	gh, ok := c.firstHit([3]float32{}, 0, gfrom, gto)
	if !ok || gh.Part != 3 {
		t.Fatalf("gun hit = %+v (ok=%v), want the barrel", gh, ok)
	}
	gimpact, ok := armorHit(sh, 20, 1, gh.Point, [3]float32{0, 0, -1}, c, [3]float32{}, 0)
	if !ok {
		t.Fatal("the gun shot met no armour")
	}
	if gimpact.Damage != 0 {
		t.Errorf("gun hit damage = %v, want 0 (a device)", gimpact.Damage)
	}
}
