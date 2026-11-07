package login

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
)

// Map data, read from the game's own packages.
//
// The spawn points and bases are NOT in the map package: `res/packages/<map>.pkg`
// carries the geometry, the heightmaps and the zones, but the arena definition
// lives in the scripts package at `scripts/arena_defs/<map>.xml`. That is why
// the map package alone could never place a tank, and why the client drew its
// own default base markers — nothing had told it where the real ones are.

// ArenaDef is one map's standard-battle definition.
type ArenaDef struct {
	// Geometry is the space resource path, `spaces/01_karelia`.
	Geometry string
	// Bounds is the playable area on the ground plane.
	MinX, MinZ, MaxX, MaxZ float32
	// Spawns is where each team starts, team 1 then team 2, as (x, y, z).
	// The y is the terrain height at that point, which is why the arena defs
	// are the answer to the spawn height as well as the position.
	Spawns [2][3]float32
	// Bases is where each team's base sits, team 1 then team 2, as (x, y, z).
	Bases [2][3]float32
}

// LoadArenaDef reads `scripts/arena_defs/<map>.xml` for the named map.
//
// scriptsPkg is the game's `res/packages/scripts.pkg`; the definition is packed
// XML inside it, so it is read through the same parser the entity defs use.
func LoadArenaDef(scriptsPkg, mapName string) (*ArenaDef, error) {
	raw, err := readFromZip(scriptsPkg, "scripts/arena_defs/"+mapName+".xml")
	if err != nil {
		return nil, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return nil, fmt.Errorf("mapdata: %s: %w", mapName, err)
	}
	root := f.Root
	d := &ArenaDef{}
	if g := root.Child("geometry"); g != nil {
		d.Geometry = g.StrVal()
	}
	bb := root.Child("boundingBox")
	if bb == nil {
		return nil, fmt.Errorf("mapdata: %s has no boundingBox", mapName)
	}
	bl, err := vec2String(bb.Child("bottomLeft"))
	if err != nil {
		return nil, fmt.Errorf("mapdata: %s bottomLeft: %w", mapName, err)
	}
	ur, err := vec2String(bb.Child("upperRight"))
	if err != nil {
		return nil, fmt.Errorf("mapdata: %s upperRight: %w", mapName, err)
	}
	d.MinX, d.MinZ, d.MaxX, d.MaxZ = bl[0], bl[1], ur[0], ur[1]

	ctf := root.Child("gameplayTypes")
	if ctf != nil {
		ctf = ctf.Child("ctf")
	}
	if ctf == nil {
		return nil, fmt.Errorf("mapdata: %s has no ctf gameplay", mapName)
	}
	// A spawn point is preferred over a base: the base is where the flag is,
	// the spawn is where the tanks start, and they are not the same place.
	// `teamSpawnPoints/teamN/position`, and `teamBasePositions/teamN/position1`.
	// A spawn point is preferred over a base: the base is where the flag is,
	// the spawn is where the tanks start, and they are not the same place.
	// `ctf` carries only `teamBasePositions` on this map; a spawn point is
	// used when the map has one, and the base stands in when it does not.
	for i, team := range []string{"team1", "team2"} {
		base, hasBase := teamPosition(ctf.Child("teamBasePositions"), team)
		if hasBase {
			d.Bases[i] = base
		}
		if v, ok := teamPosition(ctf.Child("teamSpawnPoints"), team); ok {
			d.Spawns[i] = v
		} else if hasBase {
			d.Spawns[i] = base
		}
	}
	return d, nil
}

// teamPosition pulls one team's position out of a `teamSpawnPoints` or
// `teamBasePositions` list. The packer does not keep the def's `position` /
// `position1` naming consistently, so any single child carrying a 12-byte
// vector is taken.
func teamPosition(list *entdef.Section, team string) ([3]float32, bool) {
	if list == nil {
		return [3]float32{}, false
	}
	t := list.Child(team)
	if t == nil {
		return [3]float32{}, false
	}
	for _, c := range t.Children {
		if v, err := vec3Base64(c); err == nil {
			return v, true
		}
	}
	return [3]float32{}, false
}

// readFromZip pulls one named file out of a game package.
func readFromZip(pkg, name string) ([]byte, error) {
	zr, err := zip.OpenReader(pkg)
	if err != nil {
		return nil, fmt.Errorf("mapdata: %s: %w", pkg, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	return nil, fmt.Errorf("mapdata: %s has no %s", filepath.Base(pkg), name)
}

// vec2String reads a "x z" pair, the form the bounding box uses.
func vec2String(s *entdef.Section) ([2]float32, error) {
	if s == nil {
		return [2]float32{}, fmt.Errorf("missing")
	}
	fields := strings.Fields(s.StrVal())
	if len(fields) < 2 {
		return [2]float32{}, fmt.Errorf("%q is not a pair", s.StrVal())
	}
	var out [2]float32
	for i := 0; i < 2; i++ {
		v, err := strconv.ParseFloat(fields[i], 32)
		if err != nil {
			return out, err
		}
		out[i] = float32(v)
	}
	return out, nil
}

// vec3Base64 reads a position the arena defs carry as three little-endian
// float32s: x, y, z, where y is the terrain height.
func vec3Base64(s *entdef.Section) ([3]float32, error) {
	var out [3]float32
	// The packer stores a short base64 string as a decoded BLOB, so the value
	// arrives as raw bytes rather than text. Take whichever form is present.
	raw := s.Raw
	if len(raw) < 8 {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s.StrVal()))
		if err != nil {
			return out, err
		}
		raw = decoded
	}
	// A base position is a pair (x, z); a spawn point is a triple (x, y, z)
	// with the terrain height. Both forms occur, so take what is there.
	if len(raw) < 8 {
		return out, fmt.Errorf("position is %d B, want at least 8", len(raw))
	}
	// A pair is (x, z) on the ground plane; a triple is (x, y, z). Both are
	// returned in the (x, y, z) slots, so a pair's z lands in [2] and its y
	// stays 0 — reading a pair's second value as y is what put every spawn at
	// z = 0.
	if len(raw) >= 12 {
		for i := 0; i < 3; i++ {
			out[i] = math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4 : i*4+4]))
		}
		return out, nil
	}
	out[0] = math.Float32frombits(binary.LittleEndian.Uint32(raw[0:4]))
	out[2] = math.Float32frombits(binary.LittleEndian.Uint32(raw[4:8]))
	return out, nil
}

// DefaultScriptsPkg is where the game keeps the scripts package, relative to
// the client's `eu` directory.
const DefaultScriptsPkg = "res/packages/scripts.pkg"

// FindScriptsPkg looks for the scripts package under the usual client roots.
func FindScriptsPkg() string {
	for _, root := range []string{
		os.Getenv("WOT_CLIENT_DIR"),
		filepath.Join(os.Getenv("HOME"), ".local/share/Steam/steamapps/common/World of Tanks/eu"),
	} {
		if root == "" {
			continue
		}
		p := filepath.Join(root, DefaultScriptsPkg)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Terrain heights.
//
// Each `spaces/<map>/XXXXZZZZo.cdata_processed` (the chunk's grid coordinates
// as 16-bit hex) is itself a zip archive whose `terrain2/heights` holds that
// chunk's height map. That nested package is why the map package alone was not
// enough: the heights are one level deeper than the outer archive.

const (
	// heightMapMagic is `HeightMapHeader::MAGIC`, "hmp\0".
	heightMapMagic uint32 = 0x00706d68
	// heightMapVersionAbsQFloat is `VERSION_ABS_QFLOAT`: heights quantised to
	// integers.
	heightMapVersionAbsQFloat uint32 = 4
	// quantisedPNGMagic is `QUANTISED_PNG_VERSION`, "qpng".
	quantisedPNGMagic uint32 = 0x71706e67
	// quantisationLevel is the height one quantised unit stands for, in
	// metres: the samples are millimetres.
	quantisationLevel float32 = 0.001
	// visibleOffset is `TerrainHeightMap2::DEFAULT_VISIBLE_OFFSET`: samples
	// around the chunk's own, shared with its neighbours.
	visibleOffset = 2
	// defaultChunkSize is the chunk size when the space's settings give none.
	defaultChunkSize float32 = 100
)

// HeightMap is one chunk's heights, row-major, in metres.
type HeightMap struct {
	Width, Height int
	Heights       []float32
}

// Terrain is a space's chunks, keyed by their grid coordinates.
type Terrain struct {
	ChunkSize float32
	Chunks    map[[2]int16]*HeightMap
}

// LoadTerrain reads every chunk of a space out of the map package.
func LoadTerrain(mapPkg, spaceDir string) (*Terrain, error) {
	zr, err := zip.OpenReader(mapPkg)
	if err != nil {
		return nil, fmt.Errorf("mapdata: %s: %w", mapPkg, err)
	}
	defer zr.Close()
	t := &Terrain{ChunkSize: defaultChunkSize, Chunks: map[[2]int16]*HeightMap{}}
	prefix := spaceDir + "/"
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, prefix)
		if name == f.Name {
			continue
		}
		if name == "space.settings" {
			if raw, err := readZipFile(f); err == nil {
				if cs := chunkSizeFromSettings(raw); cs > 0 {
					t.ChunkSize = cs
				}
			}
			continue
		}
		coords, ok := strings.CutSuffix(name, "o.cdata_processed")
		if !ok || len(coords) != 8 {
			continue
		}
		x, err1 := strconv.ParseUint(coords[:4], 16, 16)
		z, err2 := strconv.ParseUint(coords[4:], 16, 16)
		if err1 != nil || err2 != nil {
			continue
		}
		raw, err := readZipFile(f)
		if err != nil {
			continue
		}
		heights, err := readFromZipBytes(raw, "terrain2/heights")
		if err != nil {
			continue
		}
		hm, err := decodeHeightMap(heights)
		if err != nil {
			continue
		}
		t.Chunks[[2]int16{int16(x), int16(z)}] = hm
	}
	if len(t.Chunks) == 0 {
		return nil, fmt.Errorf("mapdata: %s has no terrain chunks", spaceDir)
	}
	return t, nil
}

// HeightAt is the terrain height at a world position, if the space has a chunk
// there.
func (t *Terrain) HeightAt(x, z float32) (float32, bool) {
	cx := int16(math.Floor(float64(x / t.ChunkSize)))
	cz := int16(math.Floor(float64(z / t.ChunkSize)))
	hm := t.Chunks[[2]int16{cx, cz}]
	if hm == nil {
		return 0, false
	}
	return hm.heightAt(x-float32(cx)*t.ChunkSize, z-float32(cz)*t.ChunkSize, t.ChunkSize), true
}

// heightAt interpolates on the triangles the client renders, mirroring
// `TerrainHeightMap2::heightAt`.
func (h *HeightMap) heightAt(x, z, chunkSize float32) float32 {
	spacingX := chunkSize / float32(h.Width-visibleOffset*2-1)
	spacingZ := chunkSize / float32(h.Height-visibleOffset*2-1)
	xs := float32(math.Max(float64(x/spacingX+visibleOffset), 0))
	zs := float32(math.Max(float64(z/spacingZ+visibleOffset), 0))
	xf, zf := xs-float32(math.Floor(float64(xs))), zs-float32(math.Floor(float64(zs)))
	x0, z0 := int(xs), int(zs)
	get := func(px, pz int) float32 {
		if px >= h.Width {
			px = h.Width - 1
		}
		if pz >= h.Height {
			pz = h.Height - 1
		}
		return h.Heights[pz*h.Width+px]
	}
	// Neighbouring cells have opposite diagonals.
	if (x0^z0)&1 != 0 {
		h01, h10 := get(x0, z0+1), get(x0+1, z0)
		if 1-xf > zf {
			h00 := get(x0, z0)
			return h00 + (h10-h00)*xf + (h01-h00)*zf
		}
		h11 := get(x0+1, z0+1)
		return h11 + (h01-h11)*(1-xf) + (h10-h11)*(1-zf)
	}
	h00, h11 := get(x0, z0), get(x0+1, z0+1)
	if xf > zf {
		h10 := get(x0+1, z0)
		return h10 + (h00-h10)*(1-xf) + (h11-h10)*zf
	}
	h01 := get(x0, z0+1)
	return h01 + (h11-h01)*xf + (h00-h01)*(1-zf)
}

// decodeHeightMap reads a `terrain2/heights` blob.
func decodeHeightMap(raw []byte) (*HeightMap, error) {
	if len(raw) < 36 {
		return nil, fmt.Errorf("height map is %d B, too short", len(raw))
	}
	le := binary.LittleEndian
	if le.Uint32(raw[0:4]) != heightMapMagic {
		return nil, fmt.Errorf("not a height map")
	}
	width := int(le.Uint32(raw[4:8]))
	height := int(le.Uint32(raw[8:12]))
	version := le.Uint32(raw[16:20])
	if version != heightMapVersionAbsQFloat {
		return nil, fmt.Errorf("unsupported height map version %d", version)
	}
	if le.Uint32(raw[32:36]) != quantisedPNGMagic {
		return nil, fmt.Errorf("height map not compressed as a quantised png")
	}
	img, err := png.Decode(bytes.NewReader(raw[36:]))
	if err != nil {
		return nil, fmt.Errorf("height map png: %w", err)
	}
	b := img.Bounds()
	if b.Dx() != width || b.Dy() != height {
		return nil, fmt.Errorf("height map png is %dx%d, header says %dx%d", b.Dx(), b.Dy(), width, height)
	}
	// The pixels are the heights, four bytes each, little-endian int32 of
	// millimetres. Read the raw buffer rather than going through At(), which
	// premultiplies and would corrupt the value.
	var pix []byte
	switch m := img.(type) {
	case *image.RGBA:
		pix = m.Pix
	case *image.NRGBA:
		pix = m.Pix
	default:
		return nil, fmt.Errorf("height map png decoded as %T, want 8-bit rgba", img)
	}
	if len(pix) < width*height*4 {
		return nil, fmt.Errorf("height map png has %d B, want %d", len(pix), width*height*4)
	}
	heights := make([]float32, 0, width*height)
	for i := 0; i < width*height; i++ {
		v := int32(le.Uint32(pix[i*4 : i*4+4]))
		heights = append(heights, float32(v)*quantisationLevel)
	}
	return &HeightMap{Width: width, Height: height, Heights: heights}, nil
}

// chunkSizeFromSettings reads `chunkSize` out of a space's settings.
func chunkSizeFromSettings(raw []byte) float32 {
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return 0
	}
	c := f.Root.Child("chunkSize")
	if c == nil {
		return 0
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(c.StrVal()), 32)
	if err != nil {
		return 0
	}
	return float32(v)
}

// readZipFile reads one entry of an already-open package.
func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// readFromZipBytes reads one named entry out of a package held in memory — the
// nested archive a terrain chunk is.
func readFromZipBytes(raw []byte, name string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name == name {
			return readZipFile(f)
		}
	}
	return nil, fmt.Errorf("nested package has no %s", name)
}

// MapPackagesDir is where the game keeps its map packages,
// `res/packages`. Empty disables terrain lookups, and the spawn then falls
// back to a fixed height.
var MapPackagesDir string

// terrainCache holds one loaded Terrain per map: a space is 196 chunks and
// decoding them per battle would cost more than the battle.
var terrainCache sync.Map // map[string]*Terrain

// TerrainFor returns the terrain of a space path such as `spaces/01_karelia`,
// or nil when the map package is not available.
func TerrainFor(spacePath string) *Terrain {
	if MapPackagesDir == "" || spacePath == "" {
		return nil
	}
	if v, ok := terrainCache.Load(spacePath); ok {
		tr, _ := v.(*Terrain)
		return tr
	}
	name := spacePath
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	pkg := filepath.Join(MapPackagesDir, name+".pkg")
	tr, err := LoadTerrain(pkg, spacePath)
	if err != nil {
		terrainCache.Store(spacePath, (*Terrain)(nil))
		return nil
	}
	terrainCache.Store(spacePath, tr)
	return tr
}

// GroundHeight is the terrain height at a point, or fallback when the map is
// not available.
func GroundHeight(spacePath string, x, z, fallback float32) float32 {
	if tr := TerrainFor(spacePath); tr != nil {
		if h, ok := tr.HeightAt(x, z); ok {
			return h
		}
	}
	return fallback
}

// arenaDefCache holds one loaded ArenaDef per map.
var arenaDefCache sync.Map // map[string]*ArenaDef

// ArenaDefFor returns the arena definition of a space path such as
// `spaces/01_karelia`, or nil when the scripts package is not available.
func ArenaDefFor(spacePath string) *ArenaDef {
	if spacePath == "" {
		return nil
	}
	if v, ok := arenaDefCache.Load(spacePath); ok {
		d, _ := v.(*ArenaDef)
		return d
	}
	name := spacePath
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	pkg := FindScriptsPkg()
	if pkg == "" {
		arenaDefCache.Store(spacePath, (*ArenaDef)(nil))
		return nil
	}
	d, err := LoadArenaDef(pkg, name)
	if err != nil {
		arenaDefCache.Store(spacePath, (*ArenaDef)(nil))
		return nil
	}
	arenaDefCache.Store(spacePath, d)
	return d
}
