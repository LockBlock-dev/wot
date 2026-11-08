package login

import (
	"math"
	"testing"
)

// TestDestructibleTableFromTheGame pins the parse against the game's own file:
// the four kinds are there, the client's order is fragiles/fallingAtoms/trees/
// structures, and a structure's modules carry the material kinds the client
// assigns them (73 + their sorted id).
func TestDestructibleTableFromTheGame(t *testing.T) {
	if FindScriptsPkg() == "" {
		t.Skip("no game files")
	}
	tbl := Destructibles()
	if tbl == nil {
		t.Skip("no destructibles.xml")
	}
	counts := map[uint8]int{}
	for _, d := range tbl.Descs {
		counts[d.Type]++
	}
	for _, typ := range []uint8{destrTypeFragile, destrTypeFallingAtom, destrTypeTree, destrTypeStructure} {
		if counts[typ] == 0 {
			t.Errorf("no descriptor of type %d", typ)
		}
	}
	// The client's order: the first descriptor of each kind appears in it.
	first := map[uint8]int{}
	for i, d := range tbl.Descs {
		if _, ok := first[d.Type]; !ok {
			first[d.Type] = i
		}
	}
	if !(first[destrTypeFragile] < first[destrTypeFallingAtom] &&
		first[destrTypeFallingAtom] < first[destrTypeTree] &&
		first[destrTypeTree] < first[destrTypeStructure]) {
		t.Fatalf("kind order = %v, want fragiles, fallingAtoms, trees, structures", first)
	}
	// A structure's modules: `n_wood0_1` is 73 and its siblings follow.
	var structDesc *destructibleDesc
	for i := range tbl.Descs {
		if tbl.Descs[i].Type == destrTypeStructure && len(tbl.Descs[i].Modules) > 0 {
			structDesc = &tbl.Descs[i]
			break
		}
	}
	if structDesc == nil {
		t.Fatal("no structure with modules")
	}
	lowest := uint8(255)
	for _, mk := range structDesc.Modules {
		if mk < lowest {
			lowest = mk
		}
	}
	if lowest != destructibleMatKindNormalMin {
		t.Errorf("lowest module material kind = %d, want %d", lowest, destructibleMatKindNormalMin)
	}
	// A tree is destructible whole; a structure's body is a module; a body the
	// file does not list is solid.
	var tree *destructibleDesc
	for i := range tbl.Descs {
		if tbl.Descs[i].Type == destrTypeTree {
			tree = &tbl.Descs[i]
			break
		}
	}
	if kind, _ := tbl.bodyKindOf(tree.Filename, "anything"); kind != bodyDestructible {
		t.Errorf("a tree body = %d, want destructible", kind)
	}
	body := ""
	for name := range structDesc.Modules {
		body = name
		break
	}
	if kind, mk := tbl.bodyKindOf(structDesc.Filename, body); kind != bodyModule || mk != structDesc.Modules[body] {
		t.Errorf("structure body %q = (%d, %d), want a module", body, kind, mk)
	}
	if kind, _ := tbl.bodyKindOf(structDesc.Filename, "s_something"); kind != bodySolid {
		t.Errorf("an unlisted body = %d, want solid", kind)
	}
}

// TestChunkIDRoundTrip pins the chunk id the client computes from a position.
func TestChunkIDRoundTrip(t *testing.T) {
	for _, p := range [][2]float32{{0, 0}, {99.9, 99.9}, {-1, -1}, {397.5, 402.6}, {-401.3, -400}} {
		id := chunkIDAt(p[0], p[1])
		c := chunkCenter(id)
		if got := chunkIDAt(c[0], c[2]); got != id {
			t.Errorf("chunk of %v = %d, centre %v gives %d", p, id, c, got)
		}
	}
	// The client's formula: 100 m chunks biased by 127.
	if got, want := chunkIDAt(397.5, 402.6), uint16((3+127)<<8|(4+127)); got != want {
		t.Errorf("chunk at (397.5, 402.6) = %d, want %d", got, want)
	}
}

// TestDestroyStaticRemovesTheTriangles pins the collision side: a destroyed
// body leaves the scene, so later shells and hulls pass through it.
func TestDestroyStaticRemovesTheTriangles(t *testing.T) {
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	for i := 0; i < 2; i++ {
		scene.Triangles = append(scene.Triangles, staticTriangle{
			Vertices: [3][3]float32{{0, 0, 0}, {1, 0, 0}, {0, 1, 0}},
			Instance: uint32(i),
			Body:     "n_wood0_1",
			Kind:     bodyModule,
		})
	}
	if !scene.destroy(0, "n_wood0_1") {
		t.Fatal("destroy removed nothing")
	}
	if len(scene.Triangles) != 1 || scene.Triangles[0].Instance != 1 {
		t.Fatalf("%d triangles left, want the other instance", len(scene.Triangles))
	}
	if scene.destroy(0, "n_wood0_1") {
		t.Fatal("a second destroy removed something")
	}
}

// TestDestructibleTuples pins the wire tuples the client decodes: the angle 0
// is the middle of its range, and a module carries its material kind shifted
// left.
func TestDestructibleTuples(t *testing.T) {
	if got := packAngleToUint(0, 6); got != 32 {
		t.Errorf("packAngleToUint(0, 6) = %d, want 32", got)
	}
	if got := packAngleToUint(math.Pi/2, 6); got != 48 {
		t.Errorf("packAngleToUint(pi/2, 6) = %d, want 48", got)
	}
	if got := packAngleToUint(-math.Pi, 6); got != 0 {
		t.Errorf("packAngleToUint(-pi, 6) = %d, want 0", got)
	}
	// `decodeDestructibleModule`: destrID big-endian, then matKind<<1|shot.
	mod := tuple3(0x01, 0x02, 73<<1)
	if mod.Seq[0].Uint != 1 || mod.Seq[1].Uint != 2 || mod.Seq[2].Uint != 146 {
		t.Fatalf("module tuple = %v", mod.Seq)
	}
}
