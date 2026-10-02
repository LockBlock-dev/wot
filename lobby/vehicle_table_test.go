package lobby

// Offline vehicle-table tests: synthetic XML trees + hand tables only
// (no game files in tree tests; the real tree is exercised by a
// throwaway live-data probe, never committed).
import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func synthTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	veh := filepath.Join(root, "vehicles", "ussr")
	writeFile(t, filepath.Join(veh, "list.xml"),
		`<R04_T-34><id>4</id><level>5</level></R04_T-34><KV-1><id>5</id><level>5</level></KV-1>`)
	writeFile(t, filepath.Join(veh, "components", "chassis.xml"),
		`<ids><C_T34>0</C_T34><C_KV>1</C_KV></ids>`)
	writeFile(t, filepath.Join(veh, "components", "engines.xml"),
		`<ids><E_T34>0</E_T34></ids>`)
	writeFile(t, filepath.Join(veh, "components", "fuelTanks.xml"),
		`<ids><F_T34>0</F_T34></ids>`)
	writeFile(t, filepath.Join(veh, "components", "radios.xml"),
		`<ids><R_T34>0</R_T34></ids>`)
	writeFile(t, filepath.Join(veh, "components", "turrets.xml"),
		`<ids><T_T34_A>0</T_T34_A><T_T34_B>1</T_T34_B></ids>`)
	writeFile(t, filepath.Join(veh, "components", "guns.xml"),
		`<ids><G_T34>0</G_T34></ids>`)
	// Turret definitions ride the <turrets0> block (NOT bare
	// <turret> tags — the position vector below must NOT count).
	writeFile(t, filepath.Join(veh, "R04_T-34.xml"),
		`<pos><turret>0.1 0.2 0.3</turret></pos><turrets0><T_T34_A><level>4</level></T_T34_A><T_T34_B><level>5</level></T_T34_B></turrets0>`)
	return root
}

func TestLoadVehicleTablesSynthetic(t *testing.T) {
	tab, err := LoadVehicleTables(synthTree(t))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := tab.Vehicle(0, 4) // ussr
	if !ok || v.Name != "R04_T-34" || v.Turrets != 2 {
		t.Fatalf("vehicle = %+v ok=%v", v, ok)
	}
	if _, ok := tab.Vehicle(0, 999); ok {
		t.Fatal("unknown vehicle must miss")
	}
	if _, ok := tab.Vehicle(3, 4); ok {
		t.Fatal("unloaded nation must miss")
	}
	s, ok := tab.Component(0, CompGun, 0)
	if !ok || s != "G_T34" {
		t.Fatalf("gun = %q ok=%v", s, ok)
	}
	if _, ok := tab.Component(0, CompOptDevice, 0); ok {
		t.Fatal("missing kind must miss")
	}
}

func TestResolveCompactDescrSynthetic(t *testing.T) {
	tab, err := LoadVehicleTables(synthTree(t))
	if err != nil {
		t.Fatal(err)
	}
	// ussr T-34 (id 4), 2 turrets, no opts: 2+16+1 = 19B.
	comp := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}
	b := append([]byte{0x01, 0x04}, comp...)
	b = append(b, 0x00)
	r, err := ResolveCompactDescr(b, tab)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Vehicle != "R04_T-34" || r.NationName != "ussr" {
		t.Fatalf("head = %+v", r)
	}
	if r.Chassis.Name != "C_T34" || r.Engine.Name != "E_T34" {
		t.Fatalf("comps = %+v", r)
	}
	if len(r.Turrets) != 4 || r.Turrets[0].Name != "T_T34_A" || r.Turrets[3].Name != "G_T34" {
		t.Fatalf("turrets = %+v", r.Turrets)
	}
	// Unknown component ID fails loud.
	bad := append([]byte(nil), b...)
	bad[2] = 0x7F
	if _, err := ResolveCompactDescr(bad, tab); err == nil {
		t.Fatal("unknown chassis must fail")
	}
	// Unknown vehicle fails loud.
	bad2 := append([]byte(nil), b...)
	bad2[1] = 0x7F
	if _, err := ResolveCompactDescr(bad2, tab); err == nil {
		t.Fatal("unknown vehicle must fail")
	}
}
