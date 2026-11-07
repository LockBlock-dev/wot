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
}

// staticScene is a space's static triangles, indexed in a ground-plane grid.
type staticScene struct {
	Triangles []staticTriangle
	// Grid maps a cell to the triangles overlapping it.
	Grid map[[2]int32][]int32
}

// loadStaticScene reads a space's static models, their collision triangles in
// the world.
func loadStaticScene(mapPkg, spaceDir string, visibilityMask uint32) (*staticScene, error) {
	zr, err := zip.OpenReader(mapPkg)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	read := func(name string) ([]byte, error) {
		f := files[name]
		if f == nil {
			return nil, fmt.Errorf("statics: no %s", name)
		}
		return readZipFile(f)
	}
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
		for _, body := range entry.model.Bodies {
			for _, tri := range body.Triangles {
				var world [3][3]float32
				for k := 0; k < 3; k++ {
					world[k] = transformPoint(inst.Transform, tri[k])
				}
				st := staticTriangle{
					Vertices: world,
					Normal:   triangleNormal(world),
					Instance: uint32(index),
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

// trianglesIn returns the triangles overlapping a box.
func (s *staticScene) trianglesIn(min, max [3]float32) []*staticTriangle {
	if s == nil {
		return nil
	}
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

// transformPoint applies a row-major 4x4 to a point.
func transformPoint(m [16]float32, p [3]float32) [3]float32 {
	return [3]float32{
		m[0]*p[0] + m[1]*p[1] + m[2]*p[2] + m[3],
		m[4]*p[0] + m[5]*p[1] + m[6]*p[2] + m[7],
		m[8]*p[0] + m[9]*p[1] + m[10]*p[2] + m[11],
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
	var settings []byte
	for _, f := range zr.File {
		if f.Name == spacePath+"/space.settings" {
			settings, _ = readZipFile(f)
			break
		}
	}
	mask := visibilityMask(settings, "ctf")
	return loadStaticScene(pkg, spacePath, mask)
}
