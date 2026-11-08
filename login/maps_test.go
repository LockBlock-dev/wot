package login

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRandomBattleMapsAreStandard pins the list: the game's own arena list,
// without the special modes or the hangars, each with its geometry and its
// arena type.
func TestRandomBattleMapsAreStandard(t *testing.T) {
	gamePackages(t)
	maps := RandomBattleMaps()
	if len(maps) < 20 {
		t.Fatalf("%d maps, want the standard rotation", len(maps))
	}
	seen := map[string]bool{}
	for _, m := range maps {
		if m.Name == "" || m.Geometry == "" || m.ArenaTypeID <= 0 {
			t.Errorf("map %+v is incomplete", m)
		}
		if seen[m.Name] {
			t.Errorf("map %s is listed twice", m.Name)
		}
		seen[m.Name] = true
		if !strings.HasPrefix(m.Geometry, "spaces/") {
			t.Errorf("%s geometry = %q, want a spaces/ path", m.Name, m.Geometry)
		}
		// The special modes and the hangars must not be in it.
		for _, marker := range []string{"_br", "epic", "_comp7", "_fortrush", "_ls26", "_sm24", "_sm25", "_hw", "hangar_", "h33_"} {
			if strings.Contains(strings.ToLower(m.Name), marker) {
				t.Errorf("%s is a special mode (%s), not a random battle map", m.Name, marker)
			}
		}
		// And its package has to be installed for the battle to load.
		base := filepath.Base(m.Geometry)
		if _, err := os.Stat(filepath.Join(MapPackagesDir, base+".pkg")); err != nil {
			t.Errorf("%s: no %s.pkg: %v", m.Name, base, err)
		}
	}
	// Karelia is the first map of the game's list, with arena type 1.
	if maps[0].Name != "01_karelia" || maps[0].ArenaTypeID != 1 {
		t.Errorf("first map = %+v, want 01_karelia with type 1", maps[0])
	}
}

// TestMapRotationGivesADifferentMapEachBattle pins the rotation: consecutive
// battles get different maps until the list wraps, and every map is used once
// per cycle.
func TestMapRotationGivesADifferentMapEachBattle(t *testing.T) {
	maps := []ArenaMap{
		{Name: "a", Geometry: "spaces/a", ArenaTypeID: 1},
		{Name: "b", Geometry: "spaces/b", ArenaTypeID: 2},
		{Name: "c", Geometry: "spaces/c", ArenaTypeID: 3},
		{Name: "d", Geometry: "spaces/d", ArenaTypeID: 4},
	}
	r := NewMapRotation(maps)
	if r.Len() != 4 {
		t.Fatalf("Len = %d, want 4", r.Len())
	}
	var cycle []string
	for i := 0; i < 4; i++ {
		m, ok := r.Next()
		if !ok {
			t.Fatal("Next returned nothing")
		}
		cycle = append(cycle, m.Name)
	}
	seen := map[string]bool{}
	for i, name := range cycle {
		if seen[name] {
			t.Fatalf("cycle %v repeats %s", cycle, name)
		}
		seen[name] = true
		if i > 0 && cycle[i] == cycle[i-1] {
			t.Fatalf("consecutive battles got the same map: %v", cycle)
		}
	}
	// It wraps and keeps going.
	if m, ok := r.Next(); !ok || m.Name != cycle[0] {
		t.Fatalf("after a cycle, Next = %+v (ok=%v), want %s", m, ok, cycle[0])
	}
	// An empty rotation is not an error, it just has nothing to give.
	if _, ok := NewMapRotation(nil).Next(); ok {
		t.Error("an empty rotation gave a map")
	}
}

// TestEventMapVariantsAreNotRandomBattles pins the exclusion of the event
// variants whose display names are event names, not map names: "Oder" and
// "Westfall" (the Normandy 1944 event) and the Halloween "Baie aux Huîtres"
// and "Avant-poste".
func TestEventMapVariantsAreNotRandomBattles(t *testing.T) {
	for _, name := range []string{
		"108_normandy_nom", "14_siegfried_line_nom",
		"121_lost_paradise_v", "128_last_frontier_v",
	} {
		if isRandomBattleMap(name) {
			t.Errorf("%s is an event variant and must not be a random-battle map", name)
		}
	}
	for _, name := range []string{
		"01_karelia", "06_ensk_big", "99_poland", "120_graf_zeppelin",
		"112_eiffel_tower_ctf", "95_lost_city_ctf",
	} {
		if !isRandomBattleMap(name) {
			t.Errorf("%s is a standard map and must stay in the rotation", name)
		}
	}
}
