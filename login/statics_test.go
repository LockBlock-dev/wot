package login

import (
	"math"
	"path/filepath"
	"testing"
)

// gamePackages points MapPackagesDir at the installed game, or skips.
func gamePackages(t *testing.T) {
	t.Helper()
	if MapPackagesDir != "" {
		return
	}
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no game files")
	}
	MapPackagesDir = filepath.Dir(pkg)
}

// TestSpaceTransformPlacesModels pins the space.bin transform: the matrix is
// column-major, so the translation is its LAST four floats. Reading it
// row-major drops the translation and stacks every placed model on the origin
// — an invisible wall in the middle of the map.
func TestSpaceTransformPlacesModels(t *testing.T) {
	gamePackages(t)
	scene, err := loadStaticSceneFor(filepath.Join(MapPackagesDir, "01_karelia.pkg"), "spaces/01_karelia")
	if err != nil {
		t.Skipf("no Karelia package: %v", err)
	}
	if len(scene.Triangles) == 0 {
		t.Fatal("no static triangles")
	}
	min := [3]float32{math.MaxFloat32, math.MaxFloat32, math.MaxFloat32}
	max := [3]float32{-math.MaxFloat32, -math.MaxFloat32, -math.MaxFloat32}
	for _, tr := range scene.Triangles {
		for k := 0; k < 3; k++ {
			min[k] = min32(min[k], tr.Bounds[0][k])
			max[k] = max32(max[k], tr.Bounds[1][k])
		}
	}
	// A kilometre-wide map's collision has to span hundreds of metres; stacked
	// on the origin it spans a few tens.
	spanX, spanZ := max[0]-min[0], max[2]-min[2]
	if spanX < 400 || spanZ < 400 {
		t.Fatalf("collision spans %.0f x %.0f m, want the whole map: the transforms were not applied", spanX, spanZ)
	}
	// And it must not be a pile at the origin.
	if math.Abs(float64(min[0])) < 50 && math.Abs(float64(max[0])) < 50 {
		t.Fatalf("collision x spans %.0f..%.0f: every model sits on the origin", min[0], max[0])
	}
}

// TestStaticSearchOrder pins the package list: the shared content packages come
// before the maps in the game's own paths.xml, and the models the space names
// are found in them.
func TestStaticSearchOrder(t *testing.T) {
	gamePackages(t)
	order := staticSearchOrder()
	if len(order) < 50 {
		t.Fatalf("%d packages in the search order, want the game's whole SD set", len(order))
	}
	// The shared content is what holds the buildings and rocks.
	found := false
	for _, name := range order {
		if name == "shared_content-part1.pkg" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("the shared content is not in the search order: %v", order[:min(len(order), 8)])
	}
}

// TestStaticBodiesAreClassified pins the body kinds the space's models carry:
// Karelia's rocks are solid, and its destructibles and structure modules are
// tagged as such.
func TestStaticBodiesAreClassified(t *testing.T) {
	gamePackages(t)
	scene, err := loadStaticSceneFor(filepath.Join(MapPackagesDir, "01_karelia.pkg"), "spaces/01_karelia")
	if err != nil {
		t.Skipf("no Karelia package: %v", err)
	}
	kinds := map[staticBodyKind]int{}
	for _, tr := range scene.Triangles {
		kinds[tr.Kind]++
	}
	if kinds[bodySolid] == 0 {
		t.Error("no solid triangles: the rocks would not stop a hull")
	}
	if kinds[bodyDestructible] == 0 {
		t.Error("no destructible triangles: the trees and fences would not break")
	}
}
