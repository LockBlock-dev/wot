package login

import (
	"math"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// flatTerrain is a flat ground at y = 0 over a kilometre.
func flatTerrain() *Terrain {
	const n = 65
	chunks := map[[2]int16]*HeightMap{}
	for x := int16(-5); x <= 5; x++ {
		for z := int16(-5); z <= 5; z++ {
			chunks[[2]int16{x, z}] = &HeightMap{Width: n, Height: n, Heights: make([]float32, n*n)}
		}
	}
	return &Terrain{ChunkSize: 100, Chunks: chunks}
}

// TestShellFliesAndHitsTheDummy pins the flight: a shell fired at the dummy
// reaches it, and the distance it reports is the distance flown.
func TestShellFliesAndHitsTheDummy(t *testing.T) {
	sh := shellSpec{
		Name: "AP", Damage: 300, Pen: 400, PenNear: 400, PenFar: 380,
		DamageNear: 300, DamageFar: 280, Kind: "ARMOR_PIERCING", KindIndex: 2,
		Caliber: 76.2, Speed: 800, Gravity: 9.81, MaxDistance: 720,
	}
	boxes := dummyBoxes([3]float32{0, 0, 0}, 0)
	// From 100 m in front, at the hull's upper plate.
	start := [3]float32{0, 1.6, 100}
	dir := [3]float32{0, 0, -1}
	vel := [3]float32{dir[0] * float32(sh.Speed), dir[1] * float32(sh.Speed), dir[2] * float32(sh.Speed)}
	landing := flyShell(sh, start, vel, flatTerrain(), boxes)
	if landing.Kind != landingVehicle {
		t.Fatalf("landing kind %d, want a vehicle hit", landing.Kind)
	}
	if math.Abs(float64(landing.Distance-95.7)) > 2 {
		t.Fatalf("distance = %.1f m, want ~95 m", landing.Distance)
	}
	if landing.Hit.Part != 1 {
		t.Fatalf("part %d, want the hull", landing.Hit.Part)
	}
}

// TestShellFallsShortOfTheDummy pins the arc: a shell aimed above the dummy
// drops onto the ground instead of hitting it.
func TestShellFallsShortOfTheDummy(t *testing.T) {
	sh := shellSpec{
		Name: "HE", Damage: 300, Pen: 50, PenNear: 50, PenFar: 40,
		DamageNear: 300, DamageFar: 280, Kind: "HIGH_EXPLOSIVE", KindIndex: 1,
		Caliber: 76.2, Speed: 200, Gravity: 9.81, MaxDistance: 720,
	}
	boxes := dummyBoxes([3]float32{0, 0, 0}, 0)
	// Aimed 20 m above the ground, 300 m out: the drop over that flight is
	// far more than 20 m.
	start := [3]float32{0, 20, 300}
	vel := [3]float32{0, 0, -float32(sh.Speed)}
	landing := flyShell(sh, start, vel, flatTerrain(), boxes)
	if landing.Kind != landingTerrain {
		t.Fatalf("landing kind %d, want the ground", landing.Kind)
	}
	if landing.Point[1] > 0.5 || landing.Point[1] < -0.5 {
		t.Fatalf("landed at y = %.2f, want the ground at 0", landing.Point[1])
	}
	// It flew over the dummy and dropped beyond it.
	if landing.Distance <= 300 {
		t.Fatalf("distance = %.1f m, want past the 300 m dummy", landing.Distance)
	}
}

// TestShellStopsAtItsMaxDistance pins the range: a shell that meets nothing
// ends at its `maxDistance`.
func TestShellStopsAtItsMaxDistance(t *testing.T) {
	sh := shellSpec{
		Name: "AP", Damage: 300, Pen: 400, Kind: "ARMOR_PIERCING", KindIndex: 2,
		Caliber: 76.2, Speed: 800, Gravity: 9.81, MaxDistance: 200,
	}
	start := [3]float32{0, 2000, 0}
	vel := [3]float32{0, 0, -800}
	landing := flyShell(sh, start, vel, nil, nil)
	if landing.Kind != landingRange {
		t.Fatalf("landing kind %d, want range", landing.Kind)
	}
	if math.Abs(float64(landing.Distance-200)) > 10 {
		t.Fatalf("distance = %.1f m, want ~200", landing.Distance)
	}
}

// TestReadClipPinsTheMagazine pins the gun's `<clip>`/`<burst>` reading: a
// count and a rate per minute, turned into the seconds between two shells; a
// count of 1 is no magazine and no interval.
func TestReadClipPinsTheMagazine(t *testing.T) {
	leaf := func(name, value string) *entdef.Section {
		return &entdef.Section{Name: name, OwnType: entdef.TypeString, Str: value}
	}
	gun := &entdef.Section{Name: "gun", Children: []*entdef.Section{
		{Name: "clip", Children: []*entdef.Section{leaf("count", "6"), leaf("rate", "30")}},
		{Name: "burst", Children: []*entdef.Section{leaf("count", "2"), leaf("rate", "60")}},
	}}
	if size, interval := readClip(gun, "clip"); size != 6 || math.Abs(float64(interval-2)) > 1e-6 {
		t.Fatalf("clip = %d shells, %v s, want 6 and 2", size, interval)
	}
	if size, interval := readClip(gun, "burst"); size != 2 || math.Abs(float64(interval-1)) > 1e-6 {
		t.Fatalf("burst = %d shells, %v s, want 2 and 1", size, interval)
	}
	// A count of 1 is no magazine.
	one := &entdef.Section{Name: "gun", Children: []*entdef.Section{
		{Name: "clip", Children: []*entdef.Section{leaf("count", "1"), leaf("rate", "30")}},
	}}
	if size, interval := readClip(one, "clip"); size != 1 || interval != 0 {
		t.Fatalf("single = %d, %v, want 1 and 0", size, interval)
	}
	if size, interval := readClip(one, "burst"); size != 1 || interval != 0 {
		t.Fatalf("no burst = %d, %v, want 1 and 0", size, interval)
	}
}
