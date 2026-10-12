package lobby

// Static generated-data accessors (tables live in vehicle_data_gen.go,
// built by cmd/wotgendata from unpacked item_defs; runtime code never
// touches XML).

// GenShell is one shell entry: display kind, caliber in mm, damage vs
// armor/modules, penetration by range, ballistics, default ammo share,
// blast data for HE (splash radius, stun).
type GenShell struct {
	Name            string
	Kind            string
	Caliber         float64
	DamageArmor     int
	DamageDevices   int
	Pen             []float64
	Speed           float64
	Gravity         float64
	MaxDistance     float64
	Portion         float64
	ExplosionRadius float64
	HasStun         bool
	StunDuration    float64
}

// GenGun is one per-turret gun entry with mounted stats: nominal
// reload, ammo pool, drum clip (count/rate, rate = rounds/min),
// autoreloader per-shell times, volley/twin markers, shells.
type GenGun struct {
	Name            string
	Reload          float64
	MaxAmmo         int
	ClipCount       int
	ClipRate        float64
	BurstSize       int
	BurstRate       float64
	AutoShoot       bool
	Autoreload      []float64
	AutoReloadBoost bool
	DualGun         bool
	DualCharge      float64
	DualLock        float64
	DualRate        float64
	DualDelay       float64
	DualTimes       []float64
	TwinGun         bool
	TwinReloadTime  float64
	TwinDelay       float64
	Chargeable      bool
	Stationary      bool
	ExtraShot       bool
	ExtraReload     float64
	Shells          []GenShell
}

// Intra returns the nominal intra-clip interval in seconds (0 for
// single-shot guns).
func (g GenGun) Intra() float64 {
	if g.ClipCount <= 1 || g.ClipRate <= 0 {
		return 0
	}
	return 60 / g.ClipRate
}

// GenTurret is one turret definition with its mounted gun options.
type GenTurret struct {
	Name string
	Guns []GenGun
}

// GenVehicle is one vehicle row: list tag plus turret definitions
// (len(Turrets) is the sectioning turret count).
type GenVehicle struct {
	Tag     string
	Turrets []GenTurret
}

// GeneratedTable builds a StaticTable from the generated maps (no
// files, no errors — unknown content cannot occur by construction;
// callers resolving battle IDs fail loud on absence as usual).
func GeneratedTable() *StaticTable {
	tab := &StaticTable{
		Vehicles: map[uint16]map[uint16]VehicleInfo{},
		Comps:    map[uint16]map[CompKind]map[uint16]string{},
	}
	for n, byType := range GeneratedVehicles {
		tab.Vehicles[n] = map[uint16]VehicleInfo{}
		for id, v := range byType {
			tab.Vehicles[n][id] = VehicleInfo{Name: v.Tag, Turrets: len(v.Turrets)}
		}
	}
	kinds := []CompKind{CompChassis, CompEngine, CompFuelTank, CompRadio, CompTurret, CompGun, CompOptDevice}
	for n, byKind := range GeneratedComponents {
		tab.Comps[n] = map[CompKind]map[uint16]string{}
		for k, byID := range byKind {
			if k < 0 || k >= len(kinds) {
				continue
			}
			tab.Comps[n][kinds[k]] = byID
		}
	}
	return tab
}

// GunSpec resolves a mounted (turret, gun) name pair to its per-turret
// gun stats. Names come from ComponentTable resolution of battle
// module IDs; ok=false when the vehicle or pair is absent (multi-gun
// turrets keep every option — the caller picks by fired caliber).
func GunSpec(nation uint8, typeID uint16, turret, gun string) (GenGun, bool) {
	byType, ok := GeneratedVehicles[uint16(nation)]
	if !ok {
		return GenGun{}, false
	}
	v, ok := byType[typeID]
	if !ok {
		return GenGun{}, false
	}
	for _, t := range v.Turrets {
		if t.Name != turret {
			continue
		}
		for _, g := range t.Guns {
			if g.Name == gun {
				return g, true
			}
		}
	}
	return GenGun{}, false
}

// VehicleGuns lists every (turret, gun) option of a vehicle for
// caliber-based disambiguation when the mounted pair is unknown.
func VehicleGuns(nation uint8, typeID uint16) []GenGun {
	byType, ok := GeneratedVehicles[uint16(nation)]
	if !ok {
		return nil
	}
	v, ok := byType[typeID]
	if !ok {
		return nil
	}
	var out []GenGun
	for _, t := range v.Turrets {
		out = append(out, t.Guns...)
	}
	return out
}
