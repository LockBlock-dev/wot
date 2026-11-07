package login

import (
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestModuleTablesCoverEveryPart pins the hit tables: every part and face the
// trace can report has candidates, and every candidate is a real module.
func TestModuleTablesCoverEveryPart(t *testing.T) {
	for _, part := range []uint8{1, 2, 3} {
		for face := 0; face < 3; face++ {
			for _, n := range [][3]float32{{1, 0, 0}, {-1, 0, 0}, {0, 1, 0}, {0, -1, 0}, {0, 0, 1}, {0, 0, -1}} {
				table := moduleTableFor(part, face, n)
				if len(table) == 0 {
					t.Fatalf("part %d face %d normal %v has no module table", part, face, n)
				}
				for _, h := range table {
					if moduleIndex(h.Name) < 0 {
						t.Fatalf("part %d face %d names unknown module %q", part, face, h.Name)
					}
					if h.Weight <= 0 {
						t.Fatalf("%q weight = %d", h.Name, h.Weight)
					}
				}
			}
		}
	}
	// The gun's only module is the gun.
	if got := pickModule(3, 2, [3]float32{0, 0, 1}, 0); got != "gunHealth" {
		t.Fatalf("gun hit picked %q, want gunHealth", got)
	}
	// A low hull-side hit is a track, not an engine.
	low := dummyParts[0].Bounds[0][1] + 0.1
	if got := pickModule(1, 0, [3]float32{1, 0, 0}, low); got != "rightTrack0Health" {
		t.Fatalf("low right-side hit picked %q, want rightTrack0Health", got)
	}
	if got := pickModule(1, 0, [3]float32{-1, 0, 0}, low); got != "leftTrack0Health" {
		t.Fatalf("low left-side hit picked %q, want leftTrack0Health", got)
	}
}

// TestModuleDamageDestroysAndReports drives the module damage: a hit takes HP
// off the module, a second one wrecks it, and a wrecked track sends the extra
// start that breaks the visual.
func TestModuleDamageDestroysAndReports(t *testing.T) {
	s := tokenTestServer(t, nil)
	dummy := NewEntity(100004, s.cfg.Dispatch.Entity("Vehicle"))
	st := &clientState{}
	// A gun hit is deterministic: the gun is the only module behind the barrel.
	res := shotResult{
		Hit: true, Pierced: true, Part: 3, Face: 2,
		LocalNormal: [3]float32{0, 0, 1},
		Point:       [3]float32{0, 2.5, 3},
	}
	el := s.damageModule(st, dummy, 1, res, 200)
	if len(el) == 0 {
		t.Fatal("no client call for a module hit")
	}
	m, ok := moduleStateByName(st, "gunHealth")
	if !ok || m.Destroyed {
		t.Fatalf("gun state = %+v, want damaged but alive", m)
	}
	if m.HP >= dummyModules[moduleIndex("gunHealth")].MaxHP {
		t.Fatalf("gun HP = %v, want it reduced", m.HP)
	}
	// A second hit wrecks it and no further damage is taken.
	el = s.damageModule(st, dummy, 1, res, 200)
	if m, _ = moduleStateByName(st, "gunHealth"); !m.Destroyed {
		t.Fatalf("gun state = %+v, want destroyed", m)
	}
	if el = s.damageModule(st, dummy, 1, res, 200); len(el) != 0 {
		t.Fatal("a wrecked module took another hit")
	}
	// The track's destruction is the one with a visual: the extra start.
	st2 := &clientState{}
	trackRes := shotResult{
		Hit: true, Pierced: true, Part: 1, Face: 0,
		LocalNormal: [3]float32{1, 0, 0},
		Local:       [3]float32{1.5, dummyParts[0].Bounds[0][1] + 0.1, 0},
		Point:       [3]float32{1.5, 0.6, 0},
	}
	if el := s.damageModule(st2, dummy, 1, trackRes, 400); len(el) == 0 {
		t.Fatal("no track hit call")
	}
	if m, _ := moduleStateByName(st2, "rightTrack0Health"); !m.Destroyed {
		t.Fatalf("track state = %+v, want destroyed by a 400-damage hit", m)
	}
}

// TestAllCrewDeadKillsTheTank pins the crew rule: the tank dies when every
// crewman does.
func TestAllCrewDeadKillsTheTank(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{}
	if s.allCrewDead(st) {
		t.Fatal("a fresh session reported a dead crew")
	}
	st.modules = make([]moduleState, len(dummyModules))
	for i := range dummyModules {
		st.modules[i].HP = dummyModules[i].MaxHP
	}
	for i := range dummyModules {
		if dummyModules[i].Crew {
			st.modules[i].Destroyed = true
		}
	}
	if !s.allCrewDead(st) {
		t.Fatal("all crewmen dead but the tank is not")
	}
}

// TestModuleCallsSurviveTheClientReader runs the two calls through the
// client's method table: `onExtraHitted` and `startOrUpdateExtraFromOutside`.
func TestModuleCallsSurviveTheClientReader(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	dummy := NewEntity(100004, d.Entity("Vehicle"))
	for _, p := range d.Entity("Vehicle").CellProps {
		dummy.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	st := &clientState{}
	el := s.damageModule(st, dummy, 1, shotResult{
		Hit: true, Pierced: true, Part: 3, Face: 2,
		LocalNormal: [3]float32{0, 0, 1},
		Point:       [3]float32{0, 2.5, 3},
	}, 500)
	if len(el) == 0 {
		t.Fatal("no elements")
	}
	// The elements follow a selectEntity in the real bundle; here the calls
	// are checked on their own.
	sel, err := EncodeSelectEntity(dummy.ID)
	if err != nil {
		t.Fatal(err)
	}
	app := append(sel, el...)
	if err := CheckClientApp(d, app); err != nil {
		t.Fatalf("the client would drop the module calls: %v (app % x)", err, app)
	}
}
