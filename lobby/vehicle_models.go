package lobby

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadVehicleModels returns the set of vehicle names whose model the client
// actually ships, read from its own vehicle packages.
//
// The generated garage table comes from item_defs and lists every ownable
// vehicle — 1232 of them, event, story-mode, IGR and other variants included.
// The client only ships models for about 1000: the rest are tanks whose art
// lives in a package that is not mounted. Handing one of those to a synthetic
// vehicle makes the client fail to build its appearance and then die with an
// access violation — measured, `G98_Waffentrager_E100_WO` produced
//
//	[Compound] Failed to load model vehicles/german/G98_Waffentrager_E100_WO/
//	          normal/lod0/Chassis.model! Compound building failed!
//	crash type="unhandled_exception" exception code="3221225477"
//
// on the next line. So the roster must be drawn from what the client can draw.
//
// The packages are ordinary ZIPs; only `vehicles_*.pkg` is read, and only the
// central directory, so this costs one pass over a handful of file headers.
func LoadVehicleModels(pkgsDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(pkgsDir)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "vehicles_") || !strings.HasSuffix(name, ".pkg") {
			continue
		}
		zr, err := zip.OpenReader(filepath.Join(pkgsDir, name))
		if err != nil {
			return nil, fmt.Errorf("wotserver: %s: %w", name, err)
		}
		for _, f := range zr.File {
			// vehicles/<nation>/<Name>/normal/lod0/Chassis.model
			parts := strings.Split(f.Name, "/")
			if len(parts) != 6 || parts[0] != "vehicles" || parts[5] != "Chassis.model" {
				continue
			}
			out[parts[2]] = true
		}
		zr.Close()
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("wotserver: no vehicle models under %s", pkgsDir)
	}
	return out, nil
}
