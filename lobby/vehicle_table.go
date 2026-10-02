package lobby

import "fmt"

// Vehicle component resolution (offline, table-driven).
//
// Wire why: SectionCompactDescr yields raw component IDs; names live
// in the vehicle item defs (`item_defs/vehicles/<nation>/list.xml`
// maps vehicle name→typeID, `components/<kind>.xml` map name→id via
// `<ids>`, turret definitions are top-level `<Turret_*...>` blocks in
// the vehicle XML — NOT `<turret>` tags, which also hold position
// vectors). This file resolves sections to names through a
// ComponentTable; the XML loader lives in vehicle_load.go, tests use
// synthetic tables (no game files in tree tests).

// CompKind selects a component namespace (one ids table per nation).
type CompKind int

const (
	CompChassis CompKind = iota
	CompEngine
	CompFuelTank
	CompRadio
	CompTurret
	CompGun
	CompOptDevice
)

// VehicleInfo is one vehicle row: display name + turret count (the
// sectioning input SectionCompactDescr needs).
type VehicleInfo struct {
	Name    string
	Turrets int
}

// ComponentTable resolves compactDescr IDs to display names. Lookups
// report presence — unknown IDs (modded/future content) fail loud,
// never guess.
type ComponentTable interface {
	Vehicle(nation uint8, typeID uint16) (VehicleInfo, bool)
	Component(nation uint8, kind CompKind, id uint16) (string, bool)
}

// StaticTable is an in-memory ComponentTable (filled by the XML
// loader or by hand in tests).
type StaticTable struct {
	Vehicles map[uint16]map[uint16]VehicleInfo
	Comps    map[uint16]map[CompKind]map[uint16]string
}

// Vehicle implements ComponentTable.
func (t *StaticTable) Vehicle(nation uint8, typeID uint16) (VehicleInfo, bool) {
	byType, ok := t.Vehicles[uint16(nation)]
	if !ok {
		return VehicleInfo{}, false
	}
	v, ok := byType[typeID]
	return v, ok
}

// Component implements ComponentTable.
func (t *StaticTable) Component(nation uint8, kind CompKind, id uint16) (string, bool) {
	byKind, ok := t.Comps[uint16(nation)]
	if !ok {
		return "", false
	}
	byID, ok := byKind[kind]
	if !ok {
		return "", false
	}
	s, ok := byID[id]
	return s, ok
}

// ResolvedPart is one named component (raw ID kept alongside).
type ResolvedPart struct {
	Kind CompKind
	ID   uint16
	Name string
}

// ResolvedDescr is a fully named vehicle descriptor.
type ResolvedDescr struct {
	NationName string
	Vehicle    string
	TypeID     uint16
	Chassis    ResolvedPart
	Engine     ResolvedPart
	FuelTank   ResolvedPart
	Radio      ResolvedPart
	Turrets    []ResolvedPart // turret,gun pairs flattened
	OptDevices []ResolvedPart
	Flags      uint8
	HasEnh     bool
	HasEmb     bool
	HasCamo    bool
}

// ResolveCompactDescr sections b (turret count from the table) and
// names every component ID. Unknown vehicle, turret count, or
// component ID fails — the caller, never this function, decides
// fallbacks.
func ResolveCompactDescr(b []byte, tab ComponentTable) (ResolvedDescr, error) {
	var r ResolvedDescr
	_, nation, id, err := ParseIntDescr(b)
	if err != nil {
		return r, err
	}
	v, ok := tab.Vehicle(nation, id)
	if !ok {
		return r, fmt.Errorf("lobby: unknown vehicle nation=%d id=%d", nation, id)
	}
	if v.Turrets < 1 {
		return r, fmt.Errorf("lobby: vehicle %s has %d turrets", v.Name, v.Turrets)
	}
	s, err := SectionCompactDescr(b, v.Turrets)
	if err != nil {
		return r, err
	}
	nm := func(kind CompKind, id uint16) (ResolvedPart, error) {
		name, ok := tab.Component(nation, kind, id)
		if !ok {
			return ResolvedPart{}, fmt.Errorf("lobby: unknown component nation=%s kind=%d id=%d", NationName(nation), kind, id)
		}
		return ResolvedPart{Kind: kind, ID: id, Name: name}, nil
	}
	comp := b[s.CompOff:s.CompEnd]
	get := func(off int) uint16 { return uint16(comp[off]) | uint16(comp[off+1])<<8 }
	r.NationName, r.Vehicle, r.TypeID = NationName(nation), v.Name, id
	if r.Chassis, err = nm(CompChassis, get(0)); err != nil {
		return r, err
	}
	if r.Engine, err = nm(CompEngine, get(2)); err != nil {
		return r, err
	}
	if r.FuelTank, err = nm(CompFuelTank, get(4)); err != nil {
		return r, err
	}
	if r.Radio, err = nm(CompRadio, get(6)); err != nil {
		return r, err
	}
	for i := 0; i < v.Turrets; i++ {
		tp, err := nm(CompTurret, get(8+i*4))
		if err != nil {
			return r, err
		}
		gp, err := nm(CompGun, get(10+i*4))
		if err != nil {
			return r, err
		}
		r.Turrets = append(r.Turrets, tp, gp)
	}
	for _, id := range s.OptDev {
		p, err := nm(CompOptDevice, id)
		if err != nil {
			return r, err
		}
		r.OptDevices = append(r.OptDevices, p)
	}
	r.Flags = s.Flags
	r.HasEnh = s.Flags&compactFlagEnh != 0
	r.HasEmb = s.Flags&compactFlagEmb != 0
	r.HasCamo = s.Flags&compactFlagCamo != 0
	return r, nil
}
