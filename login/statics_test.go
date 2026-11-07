package login

import (
	"os"
	"testing"
)

// TestPushOutOfAWall pins the static collision: a hull driven into a wall is
// pushed back out of it, and the speed into the wall stops.
func TestPushOutOfAWall(t *testing.T) {
	// A wall at x = 3, from z = -4 to 4, from the ground up to 3 m.
	wall := staticTriangle{
		Vertices: [3][3]float32{{3, 0, -4}, {3, 0, 4}, {3, 3, 0}},
		Normal:   [3]float32{-1, 0, 0},
	}
	wall.Bounds = [2][3]float32{{3, 0, -4}, {3, 3, 4}}
	scene := &staticScene{Triangles: []staticTriangle{wall}, Grid: map[[2]int32][]int32{}}
	// Index it.
	for x := int32(0); x <= 0; x++ {
		for z := int32(-1); z <= 0; z++ {
			scene.Grid[[2]int32{x, z}] = []int32{0}
		}
	}
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	h.Position = [3]float32{2.0, 0, 0}
	h.Velocity = [2]float32{5, 0} // driving +x, into the wall
	h.Flags = moveForward
	for i := 0; i < 20; i++ {
		h.step(0.1, groundFirm)
		h.pushOut(scene, hullCollisionBounds)
	}
	// The hull's box half-width is 1.7, so its centre must stay left of 1.3.
	if h.Position[0] > 3-1.7+0.01 {
		t.Fatalf("x = %v, want the hull pushed out of the wall (centre < 1.3)", h.Position[0])
	}
	if h.Velocity[0] > 0.01 {
		t.Fatalf("velocity x = %v, want the speed into the wall stopped", h.Velocity[0])
	}
}

// TestStaticSceneLoadsARealMap reads a real map's static models when the game
// is installed: the space.bin's placed models and their Havok collision.
func TestStaticSceneLoadsARealMap(t *testing.T) {
	dir := os.Getenv("WOT_MAP_PACKAGES")
	if dir == "" {
		dir = "/home/user/.local/share/Steam/steamapps/common/World of Tanks/eu/res/packages"
	}
	if _, err := os.Stat(dir + "/01_karelia.pkg"); err != nil {
		t.Skipf("no map packages: %v", err)
	}
	MapPackagesDir = dir
	s := StaticsFor("spaces/01_karelia")
	if s == nil {
		t.Fatal("no static scene")
	}
	if len(s.Triangles) < 100000 {
		t.Fatalf("%d triangles, want a whole map's", len(s.Triangles))
	}
	// The triangles are in the map's own coordinates: they must sit in a
	// plausible box, not at the origin.
	var minX, maxX float32 = 1e9, -1e9
	for _, tr := range s.Triangles {
		minX = min32(minX, tr.Bounds[0][0])
		maxX = max32(maxX, tr.Bounds[1][0])
	}
	if maxX-minX < 100 {
		t.Fatalf("triangles span %v m, want a whole map", maxX-minX)
	}
}
