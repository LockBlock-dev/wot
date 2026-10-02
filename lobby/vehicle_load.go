package lobby

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Unpacked vehicle-item-defs loader (offline).
//
// Input is an UNPACKED `item_defs` tree (packed `.xml`/`.def` first
// through `wotunpack`: magic `0x62a14e45` → readable XML). Layout per
// nation dir `vehicles/<nation>/`: `list.xml` (`<Name><id>N…`),
// `components/<kind>.xml` (`<ids><Name>id…`), vehicle
// `<V>.xml` (turret definitions are top-level `<Turret…>` blocks).
// Only the 11 shipped nations load (compactNations); anything else is
// skipped, never guessed. Stdlib `encoding/xml` token scan only.

var vehicleCompFiles = map[CompKind]string{
	CompChassis:   "chassis.xml",
	CompEngine:    "engines.xml",
	CompFuelTank:  "fuelTanks.xml",
	CompRadio:     "radios.xml",
	CompTurret:    "turrets.xml",
	CompGun:       "guns.xml",
	CompOptDevice: "optionalDevices.xml",
}

// LoadVehicleTables builds a StaticTable from an unpacked item_defs
// directory. Missing nations/kinds are skipped (partial tables still
// resolve what they hold); malformed XML fails.
func LoadVehicleTables(itemDefsDir string) (*StaticTable, error) {
	tab := &StaticTable{
		Vehicles: map[uint16]map[uint16]VehicleInfo{},
		Comps:    map[uint16]map[CompKind]map[uint16]string{},
	}
	vehRoot := filepath.Join(itemDefsDir, "vehicles")
	for ni, nation := range compactNations {
		nd := filepath.Join(vehRoot, nation)
		if st, err := os.Stat(nd); err != nil || !st.IsDir() {
			continue
		}
		n := uint16(ni)
		if tab.Vehicles[n] == nil {
			tab.Vehicles[n] = map[uint16]VehicleInfo{}
			tab.Comps[n] = map[CompKind]map[uint16]string{}
		}
		turretNames := map[string]bool{}
		for kind, file := range vehicleCompFiles {
			ids, err := loadIDsFile(filepath.Join(nd, "components", file))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("lobby: %s/%s: %w", nation, file, err)
			}
			inv := map[uint16]string{}
			for name, id := range ids {
				inv[uint16(id)] = name
			}
			tab.Comps[n][kind] = inv
			if kind == CompTurret {
				for name := range ids {
					turretNames[name] = true
				}
			}
		}
		// Vehicle list: top-level <Name> blocks carrying <id>.
		lids, err := loadListFile(filepath.Join(nd, "list.xml"))
		if err != nil {
			return nil, fmt.Errorf("lobby: %s/list.xml: %w", nation, err)
		}
		// Turret counts: top-level tags intersecting the turret ids
		// (never bare `<turret>` tags — those also hold position
		// vectors in the shipped files). File names vary by nation
		// prefix (R/G/A/…), so every vehicle XML loads; the three
		// non-vehicle roots never match a list name.
		files, _ := filepath.Glob(filepath.Join(nd, "*.xml"))
		byFile := map[string]int{}
		for _, f := range files {
			base := strings.TrimSuffix(filepath.Base(f), ".xml")
			if base == "list" || base == "customization" || base == "Observer" {
				continue
			}
			byFile[base] = countTopTurretTags(f, turretNames)
		}
		for name, id := range lids {
			tab.Vehicles[n][uint16(id)] = VehicleInfo{
				Name:    name,
				Turrets: byFile[name],
			}
		}
	}
	return tab, nil
}

// loadIDsFile reads `<ids><Name>id…` (ignores the Observer 255 row
// like any other entry — callers resolve by ID verbatim).
func loadIDsFile(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scanIDs(f)
}

// scanIDs collects direct `<ids>` children names → int text.
func scanIDs(r io.Reader) (map[string]int, error) {
	out := map[string]int{}
	dec := xml.NewDecoder(r)
	inIDs := false
	var cur string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "ids" {
				inIDs = true
			} else if inIDs && cur == "" {
				cur = t.Name.Local
			}
		case xml.CharData:
			if inIDs && cur != "" {
				if id, err := strconv.Atoi(strings.TrimSpace(string(t))); err == nil {
					out[cur] = id
				}
			}
		case xml.EndElement:
			if t.Name.Local == "ids" {
				inIDs = false
			} else if inIDs && t.Name.Local == cur {
				cur = ""
			}
		}
	}
	return out, nil
}

// loadListFile reads top-level `<Name><id>N…` vehicle rows.
func loadListFile(path string) (map[string]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]int{}
	dec := xml.NewDecoder(f)
	depth := 0
	var top string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				top = t.Name.Local
			} else if depth == 2 && top != "" && t.Name.Local == "id" {
				var id int
				if err := dec.DecodeElement(&id, &t); err == nil {
					out[top] = id
				}
				depth--
			}
		case xml.EndElement:
			depth--
			if depth == 0 {
				top = ""
			}
		}
	}
	return out, nil
}

// countTopTurretTags counts the turret definitions of the default
// mode: direct `<Turret…>` children of the `<turrets0>` block
// intersected with turretNames. (Bare `<turret>` tags are position
// vectors; `<turret>/<gun>` wrappers carry names as TEXT, never as
// tags — case-sensitive matching separates all three.)
// Returns 0 on any read error (vehicle keeps a zero count, which
// Resolve rejects — never a guessed 1).
func countTopTurretTags(path string, turretNames map[string]bool) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	dec := xml.NewDecoder(f)
	depth := 0
	inBlock := 0
	n := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if t.Name.Local == "turrets0" {
				inBlock = depth
			} else if inBlock != 0 && depth == inBlock+1 && turretNames[t.Name.Local] {
				n++
			}
		case xml.EndElement:
			if inBlock != 0 && depth == inBlock && t.Name.Local == "turrets0" {
				inBlock = 0
			}
			depth--
		}
	}
	return n
}
