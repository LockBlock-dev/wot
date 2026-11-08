package login

import (
	"testing"
	"time"

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
	if got := pickModule(3, 2, [3]float32{0, 0, 1}, 0, dummyParts[0].Bounds); got != "gunHealth" {
		t.Fatalf("gun hit picked %q, want gunHealth", got)
	}
	// A low hull-side hit is a track, not an engine.
	low := dummyParts[0].Bounds[0][1] + 0.1
	if got := pickModule(1, 0, [3]float32{1, 0, 0}, low, dummyParts[0].Bounds); got != "rightTrack0Health" {
		t.Fatalf("low right-side hit picked %q, want rightTrack0Health", got)
	}
	if got := pickModule(1, 0, [3]float32{-1, 0, 0}, low, dummyParts[0].Bounds); got != "leftTrack0Health" {
		t.Fatalf("low left-side hit picked %q, want leftTrack0Health", got)
	}
}

// TestModuleDamageDestroysAndReports drives the module damage: a hit takes HP
// off the module, a second one wrecks it, and a wrecked track sends the extra
// start that breaks the visual.
func TestModuleDamageDestroysAndReports(t *testing.T) {
	s := tokenTestServer(t, nil)
	dummy := NewEntity(100004, s.cfg.Dispatch.Entity("Vehicle"))
	tgt := &botTarget{entity: dummy, id: dummy.ID}
	// A gun hit is deterministic: the gun is the only module behind the barrel.
	res := shotResult{
		Hit: true, Pierced: true, Part: 3, Face: 2,
		LocalNormal: [3]float32{0, 0, 1},
		Point:       [3]float32{0, 2.5, 3},
	}
	el, _, _ := s.damageModule(tgt, 1, res, 200, 1)
	if len(el) == 0 {
		t.Fatal("no client call for a module hit")
	}
	m, ok := moduleStateByName(tgt, "gunHealth")
	if !ok || m.Destroyed {
		t.Fatalf("gun state = %+v, want damaged but alive", m)
	}
	if m.HP >= dummyModules[moduleIndex("gunHealth")].MaxHP {
		t.Fatalf("gun HP = %v, want it reduced", m.HP)
	}
	// A second hit wrecks it and no further damage is taken.
	el, _, _ = s.damageModule(tgt, 1, res, 200, 1)
	if m, _ = moduleStateByName(tgt, "gunHealth"); !m.Destroyed {
		t.Fatalf("gun state = %+v, want destroyed", m)
	}
	if el, _, _ = s.damageModule(tgt, 1, res, 200, 1); len(el) != 0 {
		t.Fatal("a wrecked module took another hit")
	}
	// The track's destruction is the one with a visual: the extra start.
	t2 := &botTarget{entity: dummy, id: dummy.ID}
	trackRes := shotResult{
		Hit: true, Pierced: true, Part: 1, Face: 0,
		LocalNormal: [3]float32{1, 0, 0},
		Local:       [3]float32{1.5, dummyParts[0].Bounds[0][1] + 0.1, 0},
		Point:       [3]float32{1.5, 0.6, 0},
	}
	if el, _, _ := s.damageModule(t2, 1, trackRes, 400, 1); len(el) == 0 {
		t.Fatal("no track hit call")
	}
	if m, _ := moduleStateByName(t2, "rightTrack0Health"); !m.Destroyed {
		t.Fatalf("track state = %+v, want destroyed by a 400-damage hit", m)
	}
}

// TestAllCrewDeadKillsTheTank pins the crew rule: the tank dies when every
// crewman does.
func TestAllCrewDeadKillsTheTank(t *testing.T) {
	s := tokenTestServer(t, nil)
	tgt := &botTarget{}
	if s.allCrewDead(tgt) {
		t.Fatal("a fresh target reported a dead crew")
	}
	tgt.modules = make([]moduleState, len(dummyModules))
	for i := range dummyModules {
		tgt.modules[i].HP = dummyModules[i].MaxHP
	}
	for i := range dummyModules {
		if dummyModules[i].Crew {
			tgt.modules[i].Destroyed = true
		}
	}
	if !s.allCrewDead(tgt) {
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
	tgt := &botTarget{entity: dummy, id: dummy.ID}
	el, _, _ := s.damageModule(tgt, 1, shotResult{
		Hit: true, Pierced: true, Part: 3, Face: 2,
		LocalNormal: [3]float32{0, 0, 1},
		Point:       [3]float32{0, 2.5, 3},
	}, 500, 1)
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

// TestFireComponentStartsAndStops pins the fire: the `Fire` dynamic component
// (type 64) with its `fireInfo`, and the unlink that puts it out.
//
// A fire is a component, not a property — the client's `Fire` is a
// `DynamicScriptComponent` and `isOnFire()` is `'fire' in
// self.dynamicComponents` — so the server attaches it to the burning vehicle's
// NRL node and unlinks it to stop the flames.
func TestFireComponentStartsAndStops(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	dummy := NewEntity(100004, d.Entity("Vehicle"))
	st := &clientState{nrlAlloc: newNrlNodeAlloc()}
	el, node, err := s.startFireElement(st, dummy.ID, 62, 100003)
	if err != nil {
		t.Fatalf("startFireElement: %v", err)
	}
	if len(el) == 0 || node == 0 {
		t.Fatalf("element %d B, node %d", len(el), node)
	}
	if el[0] != elNrlCreateNode {
		t.Fatalf("element id = %#02x, want %#02x (NRL create node)", el[0], elNrlCreateNode)
	}
	// The element opens with the entity node, then the component node:
	// [0x21][u16 len][0][entityNode u16][root u16][kind 1][entityID u32]
	// [0][compNode u16][entityNode u16][kind 2][type u16 LE].
	if len(el) < 21 {
		t.Fatalf("element too short: % x", el)
	}
	if got := uint16(el[18]) | uint16(el[19])<<8; got != FireNrlID {
		t.Fatalf("component type = %d, want %d (element % x)", got, FireNrlID, el[:24])
	}
	// The client's reader must accept it.
	if err := CheckClientApp(d, el); err != nil {
		t.Fatalf("the client would drop the fire component: %v (element % x)", err, el)
	}
	// The unlink carries the component's node.
	out, err := EncodeNrlUnlinkTree(node)
	if err != nil {
		t.Fatalf("EncodeNrlUnlinkTree: %v", err)
	}
	if out[0] != elNrlUnlinkTree {
		t.Fatalf("unlink element id = %#02x, want %#02x", out[0], elNrlUnlinkTree)
	}
	if got := uint16(out[3])<<8 | uint16(out[4]); got != node {
		t.Fatalf("unlink node = %d, want %d", got, node)
	}
}

// TestFireInfoCarriesTheDeviceAndAttacker pins the `FIRE_INFO` fields the
// client's `Fire.set_fireInfo` reads.
func TestFireInfoCarriesTheDeviceAndAttacker(t *testing.T) {
	v := fireInfoValue(62, 100003, time.Unix(1700000000, 0))
	for _, want := range []struct {
		name string
		kind entdef.ValueKind
	}{
		{"deviceExtraIndex", entdef.VInt},
		{"notificationIndex", entdef.VUint},
		{"attackerID", entdef.VInt},
		{"equipmentID", entdef.VUint},
		{"startTime", entdef.VFloat},
	} {
		f, ok := v.Get(want.name)
		if !ok {
			t.Fatalf("fireInfo has no %s", want.name)
		}
		if f.Kind != want.kind {
			t.Fatalf("%s kind = %v, want %v", want.name, f.Kind, want.kind)
		}
	}
	if f, _ := v.Get("deviceExtraIndex"); f.Int != 62 {
		t.Fatalf("deviceExtraIndex = %d, want 62 (the engine)", f.Int)
	}
	if f, _ := v.Get("attackerID"); f.Int != 100003 {
		t.Fatalf("attackerID = %d, want 100003", f.Int)
	}
	if f, _ := v.Get("startTime"); f.Float != 1700000000 {
		t.Fatalf("startTime = %v, want 1700000000", f.Float)
	}
}

// TestAmmoBayDetonates pins the ammo rack: destroying it destroys the tank with
// the special health the client reads as the detonation, not a plain wreck.
func TestAmmoBayDetonates(t *testing.T) {
	s := &BaseAppServer{}
	tgt := &botTarget{entity: NewEntity(100004, nil), id: 100004, health: 1000, maxHealth: 1000}
	// Enough damage to take the ammo bay's 220 HP down in one hit.
	res := shotResult{Hit: true, Part: 1, Face: 2, LocalNormal: [3]float32{0, 0, 1}, Local: [3]float32{0, 1, 0}}
	// The module a hit lands on is rolled, so keep hitting until the ammo bay
	// comes up.
	var boom *detonation
	for i := 0; i < 200 && boom == nil; i++ {
		_, _, boom = s.damageModule(tgt, 1, res, 100000, 42)
	}
	if boom == nil {
		t.Fatal("the ammo bay did not detonate")
	}
	if boom.health != ammoBayExplodedHealth {
		t.Errorf("health = %d, want %d", boom.health, ammoBayExplodedHealth)
	}
	// The client's own `SPECIAL_VEHICLE_HEALTH.AMMO_BAY_EXPLODED` is `-1 ^ 12`.
	if ammoBayExplodedHealth != -13 {
		t.Errorf("AMMO_BAY_EXPLODED = %d, want -13", ammoBayExplodedHealth)
	}
	// A destroyed ammo bay takes no more hits.
	if _, _, again := s.damageModule(tgt, 1, res, 100000, 42); again != nil {
		t.Error("a wrecked ammo bay detonated twice")
	}
}

// TestTurretDetachedHealth pins the turret detachment's health value: the
// client's `SPECIAL_VEHICLE_HEALTH.TURRET_DETACHED` (-1 ^ 28), which its
// `VehicleDamageState` maps to the exploded model.
func TestTurretDetachedHealth(t *testing.T) {
	if turretDetachedHealth != -29 {
		t.Errorf("TURRET_DETACHED = %d, want -29", turretDetachedHealth)
	}
	if turretDetachChance <= 0 || turretDetachChance > 1 {
		t.Errorf("detach chance = %v, want a share in (0, 1]", turretDetachChance)
	}
}
