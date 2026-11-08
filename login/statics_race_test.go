package login

import (
	"sync"
	"testing"
)

// TestStaticSceneSurvivesConcurrentDestroy is the regression for a server
// crash: the battle's turret tracker reads the scene from its own goroutine
// every tick, while a shell's destructible removal rewrites the grid. Without
// the lock that is a fatal "concurrent map read and map write", and the client
// then reports REASON_CORRUPTED_PACKET because the packets it was waiting for
// stop coming.
func TestStaticSceneSurvivesConcurrentDestroy(t *testing.T) {
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	for i := 0; i < 400; i++ {
		x := float32(i%20) * 2
		z := float32(i/20) * 2
		scene.Triangles = append(scene.Triangles, staticTriangle{
			Vertices: [3][3]float32{{x, 0, z}, {x + 1, 0, z}, {x, 1, z + 1}},
			Bounds:   [2][3]float32{{x, 0, z}, {x + 1, 1, z + 1}},
			Normal:   [3]float32{0, 1, 0},
			Instance: uint32(i),
			Body:     "body",
			Kind:     bodyModule,
		})
	}
	scene.rebuildGrid()

	// The reader: what trackTurret does with the scene.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			_ = scene.trianglesIn([3]float32{-100, -100, -100}, [3]float32{200, 200, 200})
			_, _ = scene.groundHeightAt(5, 5, 10)
			_ = scene.destructiblesWithin([3]float32{10, 0, 10}, 60)
			_, _, _ = scene.segmentHit([3]float32{0, 5, 0}, [3]float32{40, 5, 40})
		}
	}()

	// The writer: a shell destroying one module at a time.
	for i := 0; i < 400; i++ {
		scene.destroy(uint32(i), "body")
	}
	wg.Wait()

	if len(scene.Triangles) != 0 {
		t.Fatalf("%d triangles left, want 0 (every one was destroyed)", len(scene.Triangles))
	}
	if len(scene.Grid) != 0 {
		t.Fatalf("%d grid cells left, want 0", len(scene.Grid))
	}
}

// TestStaticSceneDestroyKeepsReaderPointersValid pins the other half: a reader
// holds POINTERS into Triangles, so destroy must build a fresh slice rather
// than compacting in place — otherwise a pointer taken before the removal
// silently starts naming a different triangle.
func TestStaticSceneDestroyKeepsReaderPointersValid(t *testing.T) {
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	for i := 0; i < 4; i++ {
		scene.Triangles = append(scene.Triangles, staticTriangle{
			Vertices: [3][3]float32{{float32(i), 0, 0}, {float32(i) + 1, 0, 0}, {float32(i), 1, 0}},
			Bounds:   [2][3]float32{{float32(i), 0, 0}, {float32(i) + 1, 1, 1}},
			Instance: uint32(i),
			Body:     "body",
		})
	}
	scene.rebuildGrid()
	held := scene.trianglesIn([3]float32{-1, -1, -1}, [3]float32{10, 10, 10})
	if len(held) != 4 {
		t.Fatalf("%d triangles, want 4", len(held))
	}
	before := *held[3]
	scene.destroy(0, "body")
	if *held[3] != before {
		t.Fatal("destroy rewrote a triangle a reader was still holding")
	}
}
