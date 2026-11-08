package lobby

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

// writePkg makes a package with the given entries, the way the client's own
// vehicle packages are laid out.
func writePkg(t *testing.T, dir, name string, entries ...string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range entries {
		w, err := zw.Create(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadVehicleModelsReadsChassisModels(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, "vehicles_level_01.pkg",
		"vehicles/usa/A01_T1_Cunningham/normal/lod0/Chassis.model",
		"vehicles/usa/A01_T1_Cunningham/normal/lod0/Chassis.visual",
		"vehicles/usa/A01_T1_Cunningham/normal/lod1/Chassis.model",
	)
	// The event tank the client does not ship: its name is in the garage table
	// but no vehicle package carries a model for it.
	writePkg(t, dir, "vehicles_level_10-part1.pkg",
		"vehicles/german/G98_Waffentrager_E100/normal/lod0/Chassis.model",
	)
	// A package that is not a vehicle package must be ignored.
	writePkg(t, dir, "gui-part1.pkg",
		"vehicles/german/G98_Waffentrager_E100_WO/normal/lod0/Chassis.model",
	)

	set, err := LoadVehicleModels(dir)
	if err != nil {
		t.Fatalf("LoadVehicleModels: %v", err)
	}
	if !set["A01_T1_Cunningham"] {
		t.Fatal("A01_T1_Cunningham has a Chassis.model but is not in the set")
	}
	if !set["G98_Waffentrager_E100"] {
		t.Fatal("G98_Waffentrager_E100 has a Chassis.model but is not in the set")
	}
	if set["G98_Waffentrager_E100_WO"] {
		t.Fatal("a model outside the vehicles_* packages was counted")
	}
	if len(set) != 2 {
		t.Fatalf("%d vehicles, want 2: %v", len(set), set)
	}
}

func TestLoadVehicleModelsRefusesAnEmptyDirectory(t *testing.T) {
	if _, err := LoadVehicleModels(t.TempDir()); err == nil {
		t.Fatal("an empty directory was accepted; the roster would then be empty for no stated reason")
	}
}
