package login

import (
	"archive/zip"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
	"os"
)

// A space's static models, what its `space.bin` places: each placed model of
// `BSMI` is one of `BSMO`'s, whose collision, when it has one, is a `.havok`
// file. Models without one are decor nothing collides with.
//
// Ported from the reference's `space/bin/*` and `space/statics.rs`.

// The collision constants, as the reference fitted them on the real server.
const (
	// staticsCell is the side of the grid's square cells the triangles are
	// indexed in, in metres: about a hull's length.
	staticsCell float32 = 8.0
	// wallAngle is how far from vertical a solid static triangle stops the
	// hull, in radians: flatter, it is ground the hull would climb.
	wallAngle float32 = 50 * math.Pi / 180
	// stepHeight is how high above the ground under its centre the hull's box
	// starts: what is lower it drives over.
	stepHeight float32 = 0.8
	// wallPasses is how many times a step pushes the hull out, deepest first.
	wallPasses = 4
	// wallFriction is the share of the speed a wall stops it also takes along
	// it.
	wallFriction float32 = 0.25
)

// hullCollisionBounds is the box of what collides of the hull, in its frame
// (x right, y up, z forward): a typical tank's, until the vehicle's own
// collision model is read.
var hullCollisionBounds = [2][3]float32{{-1.7, 0, -3.0}, {1.7, 2.2, 3.0}}

// staticTriangle is one triangle of a placed static model.
type staticTriangle struct {
	Vertices [3][3]float32
	// Bounds is its bounding box, minimum then maximum.
	Bounds [2][3]float32
	// Normal is its unit normal, its winding deciding its side.
	Normal [3]float32
	// Instance is which placed model it is of.
	Instance uint32
	// Model is the placed model's path, Body its collision body's name.
	Model string
	Body  string
	// Kind is what the body is to a shell, MatKind its material kind when it
	// is a structure module.
	Kind    staticBodyKind
	MatKind uint8
	// Chunk is the chunk the model stands in, DestrIndex its index in that
	// chunk's destructible list (the client's `destrID`).
	Chunk      uint16
	DestrIndex uint16
}

// staticScene is a space's static triangles, indexed in a ground-plane grid.
type staticScene struct {
	// mu guards Triangles and Grid.
	//
	// The scene is shared: the battle's turret-tracker goroutine reads it every
	// tick while a shell's destructible removal rewrites the grid. An
	// unsynchronised map read against that write is a fatal "concurrent map
	// read and map write" — measured, it killed the server mid-battle, and the
	// client then reported REASON_CORRUPTED_PACKET because the packets it was
	// waiting for stopped coming.
	mu sync.RWMutex
	// Triangles is the scene's collision geometry. Readers get POINTERS into
	// it, so destroy must never compact it in place: a reader that took a
	// pointer before the removal would otherwise find a different triangle
	// there afterwards. It builds a fresh slice instead.
	Triangles []staticTriangle
	// Grid maps a cell to the triangles overlapping it.
	Grid map[[2]int32][]int32
}

// loadStaticScene reads a space's static models, their collision triangles in
// the world.
func loadStaticScene(res *staticResources, spaceDir string, visibilityMask uint32) (*staticScene, error) {
	read := res.read
	bin, err := read(spaceDir + "/space.bin")
	if err != nil {
		return nil, err
	}
	stringsTable, instances, models, err := readSpaceBin(bin)
	if err != nil {
		return nil, err
	}
	// Each model's collision, loaded once for all its placements.
	type loaded struct {
		model *collisionModel
		err   error
	}
	cache := map[uint32]loaded{}
	scene := &staticScene{Grid: map[[2]int32][]int32{}}
	// The client names a destructible by its index in its CHUNK's list, so the
	// instances are counted per chunk in the order the space places them.
	table := Destructibles()
	chunkCounters := map[uint16]uint16{}
	for index, inst := range instances {
		if inst.VisibilityMask&visibilityMask == 0 {
			continue
		}
		if int(inst.Model) >= len(models) {
			continue
		}
		model := models[inst.Model]
		if model.Havok == 0 {
			continue
		}
		entry, ok := cache[model.Havok]
		if !ok {
			path, found := stringsTable[model.Havok]
			if !found {
				entry = loaded{err: errors.New("no path")}
			} else if raw, rerr := read(path); rerr != nil {
				entry = loaded{err: rerr}
			} else {
				cm, cerr := loadCollisionModel(raw)
				entry = loaded{model: cm, err: cerr}
			}
			cache[model.Havok] = entry
		}
		if entry.err != nil || entry.model == nil {
			continue
		}
		modelPath := stringsTable[model.Havok]
		// The chunk the model stands in, and its index in that chunk's
		// destructible list when it is one.
		origin := transformPoint(inst.Transform, [3]float32{})
		chunk := chunkIDAt(origin[0], origin[2])
		destrIndex := uint16(0)
		if table != nil {
			if d := table.desc(modelPath); d != nil {
				destrIndex = chunkCounters[chunk]
				chunkCounters[chunk] = destrIndex + 1
			}
		}
		for _, body := range entry.model.Bodies {
			kind, matKind := bodySolid, uint8(0)
			if table != nil {
				kind, matKind = table.bodyKindOf(modelPath, body.Name)
			}
			for _, tri := range body.Triangles {
				var world [3][3]float32
				for k := 0; k < 3; k++ {
					world[k] = transformPoint(inst.Transform, tri[k])
				}
				st := staticTriangle{
					Vertices:   world,
					Normal:     triangleNormal(world),
					Instance:   uint32(index),
					Model:      modelPath,
					Body:       body.Name,
					Kind:       kind,
					MatKind:    matKind,
					Chunk:      chunk,
					DestrIndex: destrIndex,
				}
				for k := 0; k < 3; k++ {
					st.Bounds[0][k] = min32(min32(world[0][k], world[1][k]), world[2][k])
					st.Bounds[1][k] = max32(max32(world[0][k], world[1][k]), world[2][k])
				}
				scene.Triangles = append(scene.Triangles, st)
			}
		}
	}
	// Index them in the grid.
	for i := range scene.Triangles {
		t := &scene.Triangles[i]
		x0 := int32(math.Floor(float64(t.Bounds[0][0] / staticsCell)))
		x1 := int32(math.Floor(float64(t.Bounds[1][0] / staticsCell)))
		z0 := int32(math.Floor(float64(t.Bounds[0][2] / staticsCell)))
		z1 := int32(math.Floor(float64(t.Bounds[1][2] / staticsCell)))
		for x := x0; x <= x1; x++ {
			for z := z0; z <= z1; z++ {
				key := [2]int32{x, z}
				scene.Grid[key] = append(scene.Grid[key], int32(i))
			}
		}
	}
	return scene, nil
}

// The effect materials' indices, from `system/data/effect_materials.xml` in
// the order the client loads them: what an impact shows.
const (
	effectMaterialGround uint8 = 0
	effectMaterialStone  uint8 = 1
	effectMaterialWood   uint8 = 2
	effectMaterialMetal  uint8 = 3
)

// staticEffectMaterial is the effect material a static body's impact shows,
// from its name: the game names them `n_stone_10`, `n_wood0_1`, `n_metal1_1_2`.
func staticEffectMaterial(tri staticTriangle) uint8 {
	name := strings.ToLower(tri.Body)
	switch {
	case strings.Contains(name, "stone"), strings.Contains(name, "brick"), strings.Contains(name, "concrete"):
		return effectMaterialStone
	case strings.Contains(name, "wood"):
		return effectMaterialWood
	case strings.Contains(name, "metal"), strings.Contains(name, "iron"):
		return effectMaterialMetal
	}
	return effectMaterialGround
}

// chunkIDAt is the chunk a world point stands in, as the client's
// `chunkIDFromChunkPosition` computes it: 100 m chunks, biased by 127.
func chunkIDAt(x, z float32) uint16 {
	gx := int(math.Floor(float64(x) / 100))
	gz := int(math.Floor(float64(z) / 100))
	return uint16((gx+127)<<8 | (gz + 127))
}

// chunkCenter is the world position of a chunk's centre, which is where its
// `AreaDestructibles` entity stands (the client reads the chunk back from the
// entity's position).
func chunkCenter(chunk uint16) [3]float32 {
	gx := int(chunk>>8) - 127
	gz := int(chunk&0xFF) - 127
	return [3]float32{float32(gx)*100 + 50, 0, float32(gz)*100 + 50}
}

// segmentHit is the nearest static triangle a segment meets, and the fraction
// along it.
func (s *staticScene) segmentHit(from, to [3]float32) (staticTriangle, float32, bool) {
	if s == nil {
		return staticTriangle{}, 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	min := [3]float32{min32(from[0], to[0]), min32(from[1], to[1]), min32(from[2], to[2])}
	max := [3]float32{max32(from[0], to[0]), max32(from[1], to[1]), max32(from[2], to[2])}
	delta := [3]float32{to[0] - from[0], to[1] - from[1], to[2] - from[2]}
	best := float32(-1)
	var bestTri staticTriangle
	for _, t := range s.trianglesInLocked(min, max) {
		if t.Kind == bodyRemains {
			continue
		}
		f, _, ok := segmentTriangle(from, delta, t.Vertices)
		if !ok {
			continue
		}
		if best < 0 || f < best {
			best, bestTri = f, *t
		}
	}
	if best < 0 {
		return staticTriangle{}, 0, false
	}
	return bestTri, best, true
}

// destroy removes every triangle of one placed model's body, so later shells
// and hulls pass through what broke. It reports whether anything was removed.
func (s *staticScene) destroy(instance uint32, body string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := false
	// A fresh slice, not `s.Triangles[:0]`: trianglesIn hands out pointers into
	// the old array, and compacting in place would leave them pointing at a
	// different triangle.
	keep := make([]staticTriangle, 0, len(s.Triangles))
	for _, t := range s.Triangles {
		if t.Instance == instance && t.Body == body {
			removed = true
			continue
		}
		keep = append(keep, t)
	}
	if !removed {
		return false
	}
	s.Triangles = keep
	// The grid indexes the triangles by position, so it has to be rebuilt.
	s.rebuildGridLocked()
	return true
}

// trianglesIn returns the triangles overlapping a box.
func (s *staticScene) trianglesIn(min, max [3]float32) []*staticTriangle {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trianglesInLocked(min, max)
}

// trianglesInLocked is trianglesIn for a caller that already holds the lock.
func (s *staticScene) trianglesInLocked(min, max [3]float32) []*staticTriangle {
	x0 := int32(math.Floor(float64(min[0] / staticsCell)))
	x1 := int32(math.Floor(float64(max[0] / staticsCell)))
	z0 := int32(math.Floor(float64(min[2] / staticsCell)))
	z1 := int32(math.Floor(float64(max[2] / staticsCell)))
	seen := map[int32]bool{}
	var out []*staticTriangle
	for x := x0; x <= x1; x++ {
		for z := z0; z <= z1; z++ {
			for _, i := range s.Grid[[2]int32{x, z}] {
				if seen[i] {
					continue
				}
				seen[i] = true
				t := &s.Triangles[i]
				if t.Bounds[1][0] < min[0] || t.Bounds[0][0] > max[0] ||
					t.Bounds[1][1] < min[1] || t.Bounds[0][1] > max[1] ||
					t.Bounds[1][2] < min[2] || t.Bounds[0][2] > max[2] {
					continue
				}
				out = append(out, t)
			}
		}
	}
	return out
}

// triangleNormal is a triangle's unit normal, zero if degenerate.
func triangleNormal(t [3][3]float32) [3]float32 {
	a := sub3(t[1], t[0])
	b := sub3(t[2], t[0])
	n := cross3(a, b)
	l := float32(math.Sqrt(float64(n[0]*n[0] + n[1]*n[1] + n[2]*n[2])))
	if l < 1e-8 {
		return [3]float32{}
	}
	return [3]float32{n[0] / l, n[1] / l, n[2] / l}
}

// --- space.bin -------------------------------------------------------------

// spaceInstance is one placed static model.
type spaceInstance struct {
	// Transform is the model's frame to the space's, a row-major 4x4.
	Transform [16]float32
	Model     uint32
	// VisibilityMask is the game modes it is in.
	VisibilityMask uint32
}

// spaceModel is one static model of the space.
type spaceModel struct {
	// Bounds is its bounding box in its own frame.
	Bounds [2][3]float32
	// Havok is its collision's string hash, 0 when it has none.
	Havok uint32
}

// spaceSection is one section of a compiled space.
type spaceSection struct {
	id     string
	offset uint32
	length uint32
}

// readSpaceBin decodes a `space.bin`: its strings, its placed models and its
// models.
func readSpaceBin(b []byte) (map[uint32]string, []spaceInstance, []spaceModel, error) {
	if len(b) < 8 {
		return nil, nil, nil, errors.New("space.bin: too short")
	}
	rootID := string(b[0:4])
	if rootID != "BWTB" {
		return nil, nil, nil, fmt.Errorf("space.bin: not a compiled space (%q)", rootID)
	}
	count := int(binary.LittleEndian.Uint32(b[20:24]))
	sections := map[string]spaceSection{}
	off := 24
	for i := 0; i < count && off+24 <= len(b); i++ {
		id := string(b[off : off+4])
		s := spaceSection{
			id:     id,
			offset: binary.LittleEndian.Uint32(b[off+8 : off+12]),
			length: binary.LittleEndian.Uint32(b[off+16 : off+20]),
		}
		sections[id] = s
		off += 24
	}
	get := func(id string) ([]byte, bool) {
		s, ok := sections[id]
		if !ok || int(s.offset)+int(s.length) > len(b) {
			return nil, false
		}
		return b[s.offset : s.offset+s.length], true
	}
	// The strings.
	stringsTable := map[uint32]string{}
	if raw, ok := get("BWST"); ok {
		pos := 0
		readU32 := func() (uint32, bool) {
			if pos+4 > len(raw) {
				return 0, false
			}
			v := binary.LittleEndian.Uint32(raw[pos : pos+4])
			pos += 4
			return v, true
		}
		size, ok1 := readU32()
		n, ok2 := readU32()
		if ok1 && ok2 {
			type entry struct {
				hash   uint32
				offset uint32
				length uint32
			}
			var entries []entry
			for i := 0; i < int(n); i++ {
				h, ok1 := readU32()
				o, ok2 := readU32()
				l, ok3 := readU32()
				if !ok1 || !ok2 || !ok3 {
					break
				}
				entries = append(entries, entry{hash: h, offset: o, length: l})
				_ = size
			}
			stringsLen, ok := readU32()
			if ok {
				base := pos
				for _, e := range entries {
					start := base + int(e.offset)
					end := start + int(e.length)
					if start < 0 || end > len(raw) {
						continue
					}
					stringsTable[fnv1a32(raw[start:end])] = string(raw[start:end])
				}
				_ = stringsLen
			}
		}
	}
	// The placed models.
	var instances []spaceInstance
	if raw, ok := get("BSMI"); ok {
		pos := 0
		readVector := func(elemSize int, fn func([]byte)) bool {
			if pos+8 > len(raw) {
				return false
			}
			size := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
			n := int(binary.LittleEndian.Uint32(raw[pos+4 : pos+8]))
			pos += 8
			if size != elemSize || n < 0 || pos+n*size > len(raw) {
				return false
			}
			for i := 0; i < n; i++ {
				fn(raw[pos : pos+size])
				pos += size
			}
			return true
		}
		var transforms [][16]float32
		readVector(64, func(e []byte) {
			var t [16]float32
			for i := 0; i < 16; i++ {
				t[i] = math.Float32frombits(binary.LittleEndian.Uint32(e[i*4 : i*4+4]))
			}
			transforms = append(transforms, t)
		})
		// Skip the second vector.
		if pos+8 <= len(raw) {
			size := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
			n := int(binary.LittleEndian.Uint32(raw[pos+4 : pos+8]))
			pos += 8 + size*n
		}
		var masks, models []uint32
		readVector(4, func(e []byte) { masks = append(masks, binary.LittleEndian.Uint32(e)) })
		// The models: 8-byte elements, the model's index in the first u32.
		readVector(8, func(e []byte) { models = append(models, binary.LittleEndian.Uint32(e)) })
		for i := range transforms {
			if i >= len(models) || i >= len(masks) {
				break
			}
			instances = append(instances, spaceInstance{Transform: transforms[i], Model: models[i], VisibilityMask: masks[i]})
		}
	}
	// The models.
	var models []spaceModel
	if raw, ok := get("BSMO"); ok {
		pos := 0
		readVectorHead := func() (int, int, bool) {
			if pos+8 > len(raw) {
				return 0, 0, false
			}
			size := int(binary.LittleEndian.Uint32(raw[pos : pos+4]))
			n := int(binary.LittleEndian.Uint32(raw[pos+4 : pos+8]))
			pos += 8
			return size, n, true
		}
		// Skip the first two vectors.
		for i := 0; i < 2; i++ {
			size, n, ok := readVectorHead()
			if !ok {
				break
			}
			pos += size * n
		}
		size, n, ok := readVectorHead()
		if ok && size >= 32 {
			for i := 0; i < n; i++ {
				if pos+size > len(raw) {
					break
				}
				e := raw[pos : pos+size]
				var m spaceModel
				for k := 0; k < 3; k++ {
					m.Bounds[0][k] = math.Float32frombits(binary.LittleEndian.Uint32(e[k*4 : k*4+4]))
					m.Bounds[1][k] = math.Float32frombits(binary.LittleEndian.Uint32(e[12+k*4 : 12+k*4+4]))
				}
				models = append(models, m)
				pos += size
			}
		}
		// Skip the twelve unknown vectors.
		for i := 0; i < 12; i++ {
			size, n, ok := readVectorHead()
			if !ok {
				break
			}
			pos += size * n
		}
		// The collisions: (havok hash, material hash).
		size, n, ok = readVectorHead()
		if ok && size >= 8 {
			for i := 0; i < n; i++ {
				if pos+size > len(raw) {
					break
				}
				e := raw[pos : pos+size]
				havok := binary.LittleEndian.Uint32(e[0:4])
				if i < len(models) {
					models[i].Havok = havok
				}
				pos += size
			}
		}
	}
	return stringsTable, instances, models, nil
}

// transformPoint applies a space's 4x4 to a point.
//
// The matrix is column-major, as the reference reads it
// (`Mat4::from_cols_array`): the first three columns are the model's scaled
// axes and the fourth its translation, which is the LAST four floats. Reading
// it row-major drops the translation and stacks every model of the space on
// the origin, which is an invisible wall in the middle of the map.
func transformPoint(m [16]float32, p [3]float32) [3]float32 {
	return [3]float32{
		m[0]*p[0] + m[4]*p[1] + m[8]*p[2] + m[12],
		m[1]*p[0] + m[5]*p[1] + m[9]*p[2] + m[13],
		m[2]*p[0] + m[6]*p[1] + m[10]*p[2] + m[14],
	}
}

// fnv1a32 is the space's string hash.
func fnv1a32(b []byte) uint32 {
	h := uint64(0xcbf29ce484222325)
	for _, c := range b {
		h ^= uint64(c)
		h *= 0x100000001b3
	}
	return uint32(h & 0xFFFFFFFF)
}

// --- the hull against the static models ------------------------------------

// pushOut pushes the hull's collision box out of the solid static models it
// overlaps, on the ground plane: their triangles within `wallAngle` of
// vertical, between `stepHeight` and its top, the deepest overlap first,
// `wallPasses` at most. What of its velocity goes into a wall stops, and
// slows the rest by `wallFriction`.
func (h *hull) pushOut(scene *staticScene, bounds [2][3]float32) {
	if scene == nil {
		return
	}
	for pass := 0; pass < wallPasses; pass++ {
		push, ok := h.deepestOverlap(scene, bounds)
		if !ok {
			return
		}
		h.Position[0] += push[0]
		h.Position[2] += push[1]
		n := [2]float32{push[0], push[1]}
		l := float32(math.Hypot(float64(n[0]), float64(n[1])))
		if l < 1e-6 {
			return
		}
		n[0] /= l
		n[1] /= l
		into := h.Velocity[0]*n[0] + h.Velocity[1]*n[1]
		if into < 0 {
			h.Velocity[0] -= n[0] * into
			h.Velocity[1] -= n[1] * into
			along := [2]float32{
				h.Velocity[0] - n[0]*(h.Velocity[0]*n[0]+h.Velocity[1]*n[1]),
				h.Velocity[1] - n[1]*(h.Velocity[0]*n[0]+h.Velocity[1]*n[1]),
			}
			al := float32(math.Hypot(float64(along[0]), float64(along[1])))
			max := wallFriction * -into
			if al > max && al > 0 {
				k := (al - max) / al
				h.Velocity[0] -= along[0] * (1 - k)
				h.Velocity[1] -= along[1] * (1 - k)
			}
		}
	}
}

// deepestOverlap is the largest push the hull's box needs to leave the solid
// static triangles it overlaps, on the ground plane.
func (h *hull) deepestOverlap(scene *staticScene, bounds [2][3]float32) ([2]float32, bool) {
	yaw := h.Direction[2]
	heading := [2]float32{sin32(yaw), cos32(yaw)}
	right := [2]float32{cos32(yaw), -sin32(yaw)}
	minB, maxB := bounds[0], bounds[1]
	center := [2]float32{minB[0] + maxB[0], minB[2] + maxB[2]}
	center[0] /= 2
	center[1] /= 2
	half := [2]float32{(maxB[0] - minB[0]) / 2, (maxB[2] - minB[2]) / 2}
	low := h.Position[1] + max32(stepHeight, minB[1])
	high := h.Position[1] + maxB[1]
	middle := [2]float32{
		h.Position[0] + heading[0]*center[1] + right[0]*center[0],
		h.Position[2] + heading[1]*center[1] + right[1]*center[0],
	}
	reach := float32(math.Hypot(float64(half[0]), float64(half[1])))
	least, ok := [2]float32{}, false
	for _, t := range scene.trianglesIn(
		[3]float32{middle[0] - reach, low, middle[1] - reach},
		[3]float32{middle[0] + reach, high, middle[1] + reach},
	) {
		// What a destroyed module leaves (`c_` bodies) is not there until it
		// is destroyed: colliding with it is an invisible wall.
		if t.Kind == bodyRemains {
			continue
		}
		if abs32(t.Normal[1]) >= sin32(wallAngle) {
			continue
		}
		outline, ok2 := clipToHeights(t.Vertices, low, high)
		if !ok2 {
			continue
		}
		push, ok3 := boxPush(middle, heading, right, half, outline)
		if !ok3 {
			continue
		}
		if !ok || push[0]*push[0]+push[1]*push[1] > least[0]*least[0]+least[1]*least[1] {
			least, ok = push, true
		}
	}
	return least, ok
}

// clipToHeights clips a triangle to a height band, returning its outline on
// the ground plane.
func clipToHeights(triangle [3][3]float32, low, high float32) ([][2]float32, bool) {
	clip := func(poly [][3]float32, height float32, keep func(float32) bool) [][3]float32 {
		out := make([][3]float32, 0, len(poly)+1)
		for i, from := range poly {
			to := poly[(i+1)%len(poly)]
			if keep(from[1]) {
				out = append(out, from)
			}
			if keep(from[1]) != keep(to[1]) {
				t := (height - from[1]) / (to[1] - from[1])
				out = append(out, [3]float32{
					from[0] + (to[0]-from[0])*t,
					height,
					from[2] + (to[2]-from[2])*t,
				})
			}
		}
		return out
	}
	poly := clip(triangle[:], low, func(y float32) bool { return y >= low })
	poly = clip(poly, high, func(y float32) bool { return y <= high })
	if len(poly) == 0 {
		return nil, false
	}
	out := make([][2]float32, len(poly))
	for i, v := range poly {
		out[i] = [2]float32{v[0], v[2]}
	}
	return out, true
}

// boxPush is how far to push a box on the ground plane out of a convex
// outline, least first: along the axis that separates them least, of the box's
// two and the outline's edges' normals, none if they don't overlap.
func boxPush(middle, heading, right, half [2]float32, outline [][2]float32) ([2]float32, bool) {
	var axes [][2]float32
	axes = append(axes, heading, right)
	for i := range outline {
		from := outline[i]
		to := outline[(i+1)%len(outline)]
		d := [2]float32{to[0] - from[0], to[1] - from[1]}
		n := [2]float32{-d[1], d[0]}
		l := float32(math.Hypot(float64(n[0]), float64(n[1])))
		if l > 1e-4 {
			axes = append(axes, [2]float32{n[0] / l, n[1] / l})
		}
	}
	var least [2]float32
	have := false
	for _, axis := range axes {
		center := middle[0]*axis[0] + middle[1]*axis[1]
		extent := half[0]*abs32(right[0]*axis[0]+right[1]*axis[1]) + half[1]*abs32(heading[0]*axis[0]+heading[1]*axis[1])
		low, high := float32(math.Inf(1)), float32(math.Inf(-1))
		for _, v := range outline {
			d := v[0]*axis[0] + v[1]*axis[1]
			low = min32(low, d)
			high = max32(high, d)
		}
		back := center + extent - low
		forward := high - (center - extent)
		if back <= 0 || forward <= 0 {
			return [2]float32{}, false
		}
		var push [2]float32
		if back < forward {
			push = [2]float32{-axis[0] * back, -axis[1] * back}
		} else {
			push = [2]float32{axis[0] * forward, axis[1] * forward}
		}
		if !have || push[0]*push[0]+push[1]*push[1] < least[0]*least[0]+least[1]*least[1] {
			least, have = push, true
		}
	}
	return least, have
}

// sub3, cross3 are vector helpers.
func sub3(a, b [3]float32) [3]float32 { return [3]float32{a[0] - b[0], a[1] - b[1], a[2] - b[2]} }
func cross3(a, b [3]float32) [3]float32 {
	return [3]float32{
		a[1]*b[2] - a[2]*b[1],
		a[2]*b[0] - a[0]*b[2],
		a[0]*b[1] - a[1]*b[0],
	}
}

// gameplayNames are the arena types, `ARENA_GAMEPLAY_NAMES` in the client's
// constants: a type's id is its index, which is its visibility bit when the
// space's settings give none.
var gameplayNames = []string{
	"ctf", "domination", "assault", "nations", "ctf2", "domination2", "assault2", "fallout",
	"fallout2", "fallout3", "fallout4", "ctf30x30", "domination30x30", "sandbox", "bootcamp",
	"epic", "maps_training", "rts", "rts_1x1", "rts_bootcamp", "comp7",
}

// visibilityMask is the bit a gameplay type is in a space's visibility mask.
func visibilityMask(settings []byte, gameplay string) uint32 {
	if f, err := entdef.ParseFile(settings); err == nil && f.Root != nil {
		if flags := f.Root.Child("spaceVisibilityFlags"); flags != nil {
			for _, t := range flags.Children {
				if t.Name != "type" {
					continue
				}
				tag := ""
				if c := t.Child("tag"); c != nil {
					tag = strings.TrimSpace(c.StrVal())
				}
				if tag != gameplay {
					continue
				}
				if c := t.Child("bitIndex"); c != nil {
					if v, err := strconv.Atoi(strings.TrimSpace(c.StrVal())); err == nil && v >= 0 && v < 20 {
						return 1 << uint(v)
					}
				}
			}
		}
	}
	for i, name := range gameplayNames {
		if name == gameplay {
			return 1 << uint(i)
		}
	}
	return 1 // ctf
}

// staticSearchPackages are the packages a space's shared models live in, in
// the order the game itself resolves them: `paths.xml`'s `<Package>` list,
// filtered to the ones an SD client mounts.
//
// A space's `space.bin` names its models by path, but only some of their
// `.havok` files ship in the map's own package: the buildings, rocks and
// vegetation are in the shared content ones, and a loader that reads only the
// map package leaves most of the map without collision (you drive through
// rocks).
var (
	staticSearchOnce sync.Once
	staticSearchList []string
)

// staticSearchOrder is the package list, read once.
func staticSearchOrder() []string {
	staticSearchOnce.Do(func() {
		root := filepath.Dir(filepath.Dir(MapPackagesDir))
		raw, err := os.ReadFile(filepath.Join(root, "paths.xml"))
		if err != nil {
			return
		}
		text := string(raw)
		for {
			i := strings.Index(text, "<Package")
			if i < 0 {
				break
			}
			j := strings.Index(text[i:], "</Package>")
			if j < 0 {
				break
			}
			entry := text[i : i+j]
			text = text[i+j:]
			// The type attribute: an SD client mounts the ones that list `sd`.
			if k := strings.Index(entry, `type="`); k >= 0 {
				types := entry[k+6:]
				if e := strings.Index(types, `"`); e >= 0 {
					types = types[:e]
				}
				if !strings.Contains(types, "sd") {
					continue
				}
			}
			if k := strings.Index(entry, ">"); k >= 0 {
				if path := strings.TrimSpace(entry[k+1:]); path != "" {
					staticSearchList = append(staticSearchList, filepath.Base(path))
				}
			}
		}
	})
	return staticSearchList
}

// sharedZipCache holds the opened shared packages, by name. They are large
// (1.5 GB each) but a zip's central directory is small, and every battle on
// any map reuses them.
var sharedZipCache sync.Map // name -> *zip.ReadCloser

// staticResources resolves a resource path for one space: its own package
// first, then the shared content packages, opened lazily.
type staticResources struct {
	mapFiles map[string]*zip.File
	shared   []map[string]*zip.File
	opened   int
}

// read resolves one path.
func (r *staticResources) read(path string) ([]byte, error) {
	if f := r.mapFiles[path]; f != nil {
		return readZipFile(f)
	}
	for {
		for _, files := range r.shared {
			if f := files[path]; f != nil {
				return readZipFile(f)
			}
		}
		order := staticSearchOrder()
		if r.opened >= len(order) {
			return nil, fmt.Errorf("statics: %s is in no package", path)
		}
		name := order[r.opened]
		r.opened++
		zr := openSharedZip(name)
		if zr == nil {
			continue
		}
		files := make(map[string]*zip.File, len(zr.File))
		for _, f := range zr.File {
			files[f.Name] = f
		}
		r.shared = append(r.shared, files)
	}
}

// openSharedZip opens one shared package, once per process.
func openSharedZip(name string) *zip.ReadCloser {
	if v, ok := sharedZipCache.Load(name); ok {
		zr, _ := v.(*zip.ReadCloser)
		return zr
	}
	zr, err := zip.OpenReader(filepath.Join(MapPackagesDir, name))
	if err != nil {
		sharedZipCache.Store(name, (*zip.ReadCloser)(nil))
		return nil
	}
	sharedZipCache.Store(name, zr)
	return zr
}

// staticsCache holds one static scene per space: loading a map's collision
// takes a moment, and every battle on it shares the triangles.
var staticsCache sync.Map

// StaticsFor returns a space's static scene, loading it once.
func StaticsFor(spacePath string) *staticScene {
	if MapPackagesDir == "" || spacePath == "" {
		return nil
	}
	if v, ok := staticsCache.Load(spacePath); ok {
		s, _ := v.(*staticScene)
		return s
	}
	name := spacePath
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	pkg := filepath.Join(MapPackagesDir, name+".pkg")
	scene, err := loadStaticSceneFor(pkg, spacePath)
	if err != nil {
		staticsCache.Store(spacePath, (*staticScene)(nil))
		return nil
	}
	staticsCache.Store(spacePath, scene)
	return scene
}

// loadStaticSceneFor reads a space's settings for its visibility mask, then its
// static scene.
func loadStaticSceneFor(pkg, spacePath string) (*staticScene, error) {
	zr, err := zip.OpenReader(pkg)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	res := &staticResources{mapFiles: make(map[string]*zip.File, len(zr.File))}
	var settings []byte
	for _, f := range zr.File {
		res.mapFiles[f.Name] = f
		if f.Name == spacePath+"/space.settings" {
			settings, _ = readZipFile(f)
		}
	}
	mask := visibilityMask(settings, "ctf")
	return loadStaticScene(res, spacePath, mask)
}

// destructiblesWithin is the distinct destructible bodies — a tree, a fence, a
// lamp post, a structure's module — whose triangles lie within `radius` of a
// point. Each is returned once, as its first triangle.
func (s *staticScene) destructiblesWithin(center [3]float32, radius float32) []staticTriangle {
	if s == nil || radius <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	min := [3]float32{center[0] - radius, center[1] - radius, center[2] - radius}
	max := [3]float32{center[0] + radius, center[1] + radius, center[2] + radius}
	type bodyKey struct {
		instance uint32
		body     string
	}
	seen := map[bodyKey]bool{}
	var out []staticTriangle
	for _, t := range s.trianglesInLocked(min, max) {
		if t.Kind != bodyDestructible && t.Kind != bodyModule {
			continue
		}
		key := bodyKey{instance: t.Instance, body: t.Body}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *t)
	}
	return out
}

// rebuildGrid re-indexes the scene's triangles in the grid.
func (s *staticScene) rebuildGrid() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildGridLocked()
}

// rebuildGridLocked is rebuildGrid for a caller that already holds the lock.
func (s *staticScene) rebuildGridLocked() {
	s.Grid = map[[2]int32][]int32{}
	for i := range s.Triangles {
		t := &s.Triangles[i]
		x0 := int32(math.Floor(float64(t.Bounds[0][0] / staticsCell)))
		x1 := int32(math.Floor(float64(t.Bounds[1][0] / staticsCell)))
		z0 := int32(math.Floor(float64(t.Bounds[0][2] / staticsCell)))
		z1 := int32(math.Floor(float64(t.Bounds[1][2] / staticsCell)))
		for x := x0; x <= x1; x++ {
			for z := z0; z <= z1; z++ {
				key := [2]int32{x, z}
				s.Grid[key] = append(s.Grid[key], int32(i))
			}
		}
	}
}

// groundHeightAt is the highest static surface under a point, below `maxY`: the
// deck of a ramp, a rock's top, a bridge. Only near-horizontal triangles count
// — a wall is the push-out's business, not the ground's — and what a destroyed
// module leaves is not there.
func (s *staticScene) groundHeightAt(x, z, maxY float32) (float32, bool) {
	if s == nil {
		return 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := [2]int32{
		int32(math.Floor(float64(x / staticsCell))),
		int32(math.Floor(float64(z / staticsCell))),
	}
	best := float32(0)
	found := false
	for _, i := range s.Grid[key] {
		t := &s.Triangles[i]
		if t.Kind == bodyRemains {
			continue
		}
		if abs32(t.Normal[1]) < sin32(wallAngle) {
			continue
		}
		if x < t.Bounds[0][0] || x > t.Bounds[1][0] || z < t.Bounds[0][2] || z > t.Bounds[1][2] {
			continue
		}
		h, ok := triangleHeightAt(*t, x, z)
		if !ok || h > maxY {
			continue
		}
		if !found || h > best {
			best, found = h, true
		}
	}
	return best, found
}

// triangleHeightAt is the height of a triangle's plane at (x, z), when the
// point is inside the triangle's footprint.
func triangleHeightAt(t staticTriangle, x, z float32) (float32, bool) {
	x1, z1 := t.Vertices[0][0], t.Vertices[0][2]
	x2, z2 := t.Vertices[1][0], t.Vertices[1][2]
	x3, z3 := t.Vertices[2][0], t.Vertices[2][2]
	den := (z2-z3)*(x1-x3) + (x3-x2)*(z1-z3)
	if abs32(den) < 1e-9 {
		return 0, false
	}
	a := ((z2-z3)*(x-x3) + (x3-x2)*(z-z3)) / den
	b := ((z3-z1)*(x-x3) + (x1-x3)*(z-z3)) / den
	c := 1 - a - b
	if a < -0.001 || b < -0.001 || c < -0.001 {
		return 0, false
	}
	return a*t.Vertices[0][1] + b*t.Vertices[1][1] + c*t.Vertices[2][1], true
}
