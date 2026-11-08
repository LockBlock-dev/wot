package login

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
)

// The maps a random battle may be played on.
//
// The game lists them in `scripts/arena_defs/_list_.xml`: one `<map>` per
// geometry, with its geometry id and its section name. The same list also
// carries the special modes (battle royale, epic random, comp7, fortrush, last
// stand, story mode, halloween) and the hangars, which a random battle must
// never pick, so they are filtered out by the markers the game itself puts in
// their names.
//
// A map's arena type is `geometryID | gameplayID<<16`, and ctf — the standard
// battle — is gameplay 0, so a random battle on a map uses its geometry id as
// the arena type.

// ArenaMap is one map a battle can be played on.
type ArenaMap struct {
	// Name is the map's section name, `01_karelia`.
	Name string
	// Geometry is the space resource path, `spaces/01_karelia`.
	Geometry string
	// ArenaTypeID is the arena type a standard (ctf) battle on it uses.
	ArenaTypeID int32
}

// specialModeMarkers are the parts of a name that mark a non-random mode: the
// hangars, battle royale, epic random battles, comp7, fortrush, last stand,
// story mode and halloween.
var specialModeMarkers = []string{
	"hangar_", "h33_",
	"_br_", "_br",
	"epic",
	"_comp7",
	"_fortrush",
	"_ls26",
	"_sm24", "_sm25",
	"_hw25", "_hw",
	"_scc",
	// Event variants of standard maps. Their display names are event names,
	// not map names: `108_normandy_nom` is "Oder" and `14_siegfried_line_nom`
	// is "Westfall" (the Normandy 1944 event), and `121_lost_paradise_v` /
	// `128_last_frontier_v` are the Halloween event's "Baie aux Huîtres" and
	// "Avant-poste". None of them is a random-battle map.
	"_nom",
	"_wt",
	"_nb",
}

// specialModeSuffixes are the endings that mark an event variant. They are
// checked as suffixes because `_v` alone would match inside ordinary names.
var specialModeSuffixes = []string{"_v"}

// isRandomBattleMap reports whether a map's name is a standard random-battle
// one.
func isRandomBattleMap(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range specialModeMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	for _, suffix := range specialModeSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	return true
}

// randomBattleMapsCache holds the list, loaded once.
var (
	randomBattleMapsOnce sync.Once
	randomBattleMapsList []ArenaMap
)

// RandomBattleMaps lists the maps a random battle may be played on, in the
// game's own order. It is empty when the game's files are not available.
func RandomBattleMaps() []ArenaMap {
	randomBattleMapsOnce.Do(func() {
		randomBattleMapsList = loadRandomBattleMaps()
	})
	return randomBattleMapsList
}

// loadRandomBattleMaps reads the game's arena list and keeps the standard
// maps.
func loadRandomBattleMaps() []ArenaMap {
	pkg := FindScriptsPkg()
	if pkg == "" {
		return nil
	}
	raw, err := readFromZip(pkg, "scripts/arena_defs/_list_.xml")
	if err != nil {
		return nil
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return nil
	}
	var out []ArenaMap
	for _, entry := range f.Root.Children {
		if entry.Name != "map" {
			continue
		}
		name := strings.TrimSpace(sectionString(entry, "name"))
		if name == "" || !isRandomBattleMap(name) {
			continue
		}
		if b, ok := boolChild(entry, "isHangar"); ok && b {
			continue
		}
		if b, ok := boolChild(entry, "isDevelopment"); ok && b {
			continue
		}
		id, ok := intChild(entry, "id")
		if !ok || id <= 0 {
			continue
		}
		geometry, err := arenaGeometry(pkg, name)
		if err != nil {
			continue
		}
		// A map whose package is not installed cannot be played: its
		// terrain, statics and minimap all come from it.
		if MapPackagesDir != "" {
			base := geometry
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			if _, err := os.Stat(filepath.Join(MapPackagesDir, base+".pkg")); err != nil {
				continue
			}
		}
		out = append(out, ArenaMap{Name: name, Geometry: geometry, ArenaTypeID: int32(id)})
	}
	return out
}

// arenaGeometry reads a map's space path from its own arena definition.
func arenaGeometry(pkg, name string) (string, error) {
	raw, err := readFromZip(pkg, "scripts/arena_defs/"+name+".xml")
	if err != nil {
		return "", err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return "", fmt.Errorf("maps: %s: %w", name, err)
	}
	geometry := strings.TrimSpace(sectionString(f.Root, "geometry"))
	if geometry == "" {
		return "", fmt.Errorf("maps: %s has no geometry", name)
	}
	return geometry, nil
}

// sectionString is a section's child text, or "".
func sectionString(sec *entdef.Section, name string) string {
	if sec == nil {
		return ""
	}
	c := sec.Child(name)
	if c == nil {
		return ""
	}
	return c.AsString()
}

// intChild reads an integer child.
func intChild(sec *entdef.Section, name string) (int64, bool) {
	c := sec.Child(name)
	if c == nil {
		return 0, false
	}
	var v int64
	if _, err := fmt.Sscanf(strings.TrimSpace(c.AsString()), "%d", &v); err != nil {
		return 0, false
	}
	return v, true
}

// ShuffledMaps returns a copy of the list in a random order: the rotation
// walks it, so consecutive battles differ and the order differs between
// server runs.
func ShuffledMaps(maps []ArenaMap) []ArenaMap {
	out := append([]ArenaMap(nil), maps...)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// MapRotation walks a shuffled list of maps, one per battle.
//
// Consecutive battles get different maps until the list wraps, and because the
// list is shuffled once at start-up the order differs between server runs.
type MapRotation struct {
	maps []ArenaMap
	next int
}

// NewMapRotation returns a rotation over a shuffled copy of maps.
func NewMapRotation(maps []ArenaMap) *MapRotation {
	return &MapRotation{maps: ShuffledMaps(maps)}
}

// Next returns the next map, and false when there are none.
func (r *MapRotation) Next() (ArenaMap, bool) {
	if r == nil || len(r.maps) == 0 {
		return ArenaMap{}, false
	}
	m := r.maps[r.next%len(r.maps)]
	r.next++
	return m, true
}

// Len is how many maps the rotation holds.
func (r *MapRotation) Len() int {
	if r == nil {
		return 0
	}
	return len(r.maps)
}
