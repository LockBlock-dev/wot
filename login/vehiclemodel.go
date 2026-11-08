package login

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
)

// A vehicle's client collision models and the armour its groups are made of.
//
// The client hits a tank on its `hitTester/collisionModelClient` meshes: one
// `.havok` per part, each a set of bodies, one per armour group (`armor_3`,
// `leftTrack`, `gun`, `surveyingDevice`, …). The group's name is also the key
// into the vehicle's `<armor>` block, which gives its thickness and overrides
// the material's parameters from `common/vehicle.xml`.
//
// This is the port of the reference's `wot/collision.rs` and
// `base/armor.rs`: the shell is traced through the real triangles, so the hit
// point, the surface normal and the armour it meets are the client's own, not
// a bounding box's.

// material is what an armour group is made of: the game's `common/vehicle.xml`
// defaults, overridden by the vehicle's own `<armor>` entry.
type material struct {
	// Armor is its thickness, in millimetres.
	Armor float32
	// VehicleDamageFactor is the share of a piercing shell's damage the vehicle
	// takes behind it: 0 for screens, tracks and the gun, which only stop
	// shells.
	VehicleDamageFactor float32
	// UseHitAngle: whether a shell meets it at its angle, else as if square on.
	UseHitAngle bool
	MayRicochet bool
	// CheckCaliberForRicochet: a caliber of 3× its thickness or more never
	// ricochets off it.
	CheckCaliberForRicochet bool
	// CheckCaliberForHitAngleNorm: a caliber of more than twice its thickness
	// turns more toward its normal.
	CheckCaliberForHitAngleNorm bool
	// CollideOnceOnly: a shell only meets it once, whichever face it crosses.
	CollideOnceOnly bool
}

// isMainArmor reports whether the vehicle takes damage behind it: its main
// armour, not a screen.
func (m material) isMainArmor() bool { return m.VehicleDamageFactor > 0 }

// armorGroup is one body of a part's collision model: its triangles of one
// material.
type armorGroup struct {
	// Name is the body's name without its `s_`/`n_` prefix, `armor_3` say.
	Name string
	// Kind is its body flags' kind: the armour index for `armor_1`, or a
	// device's kind (23/24 tracks, 25 gun, 28 surveying device).
	Kind uint32
	// Material is what it is made of, nil for a group the vehicle does not
	// armour (the shell passes through it).
	Material  *material
	Triangles [][3][3]float32
}

// vehiclePartModel is one part's collision model, in the part's own frame.
type vehiclePartModel struct {
	// Part is the client's `TankPartIndexes` index: 0 chassis, 1 hull,
	// 2 turret, 3 gun.
	Part uint8
	// Offset is the part's origin in the vehicle frame (the chassis origin is
	// the vehicle's own position).
	Offset [3]float32
	// Bounds is the part's box, as the client's `getBoundingBox` reports it:
	// hit points are encoded over it.
	Bounds [2][3]float32
	// Radius is the sphere around the part's origin holding all its triangles.
	Radius float32
	Groups []armorGroup
}

// vehicleCollision is a vehicle's four part models, in `TankPartIndexes` order.
type vehicleCollision struct {
	Parts []vehiclePartModel
}

// vehicleCollisionCache holds one loaded model per vehicle, keyed by
// nation/name: a battle reuses it for every bot of that type.
var vehicleCollisionCache sync.Map // map[string]*vehicleCollision

// VehicleCollisionFor returns the client collision model of the named vehicle,
// or nil when the game's files are not available.
//
// nation is the item-defs directory (`uk`), name the vehicle's section
// (`GB63_TOG_II`).
func VehicleCollisionFor(nation, name string) *vehicleCollision {
	if nation == "" || name == "" {
		return nil
	}
	key := nation + "/" + name
	if v, ok := vehicleCollisionCache.Load(key); ok {
		c, _ := v.(*vehicleCollision)
		return c
	}
	c, err := loadVehicleCollision(nation, name)
	if err != nil {
		vehicleCollisionCache.Store(key, (*vehicleCollision)(nil))
		return nil
	}
	vehicleCollisionCache.Store(key, c)
	return c
}

// loadVehicleCollision reads a vehicle's four client collision models and the
// armour each of their groups is made of.
func loadVehicleCollision(nation, name string) (*vehicleCollision, error) {
	pkg := FindScriptsPkg()
	if pkg == "" {
		return nil, fmt.Errorf("vehiclemodel: no scripts package")
	}
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/"+nation+"/"+name+".xml")
	if err != nil {
		return nil, err
	}
	veh, err := entdef.ParseFile(raw)
	if err != nil {
		return nil, fmt.Errorf("vehiclemodel: %s: %w", name, err)
	}
	if veh.Root == nil {
		return nil, fmt.Errorf("vehiclemodel: %s: no root", name)
	}
	materials, err := loadMaterials(pkg)
	if err != nil {
		return nil, err
	}
	hullY, _ := vectorY2(sectionChild(veh.Root, "hull"), "hullPosition")
	// The chassis carries the hull's position; the vehicle's own root has no
	// hullPosition, so it comes from the chassis block.
	if chassis := firstChild(sectionChild(veh.Root, "chassis")); chassis != nil {
		if v, verr := vectorY2(chassis, "hullPosition"); verr == nil {
			hullY = v
		}
	}
	turret := firstChild(sectionChild(veh.Root, "turrets0"))
	gun := (*entdef.Section)(nil)
	if turret != nil {
		gun = firstChild(sectionChild(turret, "guns"))
	}
	turretY, gunY := 0.0, 0.0
	if hullSec := sectionChild(veh.Root, "hull"); hullSec != nil {
		if tp := hullSec.Child("turretPositions"); tp != nil {
			if t := firstChild(tp); t != nil {
				if v, verr := vectorY2(t, ""); verr == nil {
					turretY = v
				}
			}
		}
	}
	if turret != nil {
		if v, verr := vectorY2(turret, "gunPosition"); verr == nil {
			gunY = v
		}
	}

	parts := []struct {
		part   uint8
		sec    *entdef.Section
		offset [3]float32
	}{
		{0, firstChild(sectionChild(veh.Root, "chassis")), [3]float32{}},
		{1, sectionChild(veh.Root, "hull"), [3]float32{0, float32(hullY), 0}},
		{2, turret, [3]float32{0, float32(hullY + turretY), 0}},
		{3, gun, [3]float32{0, float32(hullY + turretY + gunY), 0}},
	}
	out := &vehicleCollision{}
	for _, p := range parts {
		if p.sec == nil {
			continue
		}
		model, err := loadPartModel(pkg, p.sec, p.part, p.offset, materials)
		if err != nil {
			return nil, fmt.Errorf("vehiclemodel: %s part %d: %w", name, p.part, err)
		}
		out.Parts = append(out.Parts, *model)
	}
	if len(out.Parts) == 0 {
		return nil, fmt.Errorf("vehiclemodel: %s has no collision model", name)
	}
	return out, nil
}

// loadPartModel loads one part's `.havok` and tags each of its groups with the
// material the part's `<armor>` block gives for that name.
func loadPartModel(pkg string, sec *entdef.Section, part uint8, offset [3]float32, materials map[string]material) (*vehiclePartModel, error) {
	ht := sec.Child("hitTester")
	if ht == nil {
		return nil, fmt.Errorf("no hitTester")
	}
	client := ht.Child("collisionModelClient")
	if client == nil {
		return nil, fmt.Errorf("no collisionModelClient")
	}
	// The definitions name a `.model`, the game ships it as a `.havok`.
	path := strings.TrimSpace(client.AsString())
	path = strings.TrimSuffix(path, ".model") + ".havok"
	raw, err := readVehicleRes(path)
	if err != nil {
		return nil, err
	}
	model, err := loadCollisionModel(raw)
	if err != nil {
		return nil, err
	}
	armor := readArmor(sec.Child("armor"), materials)
	groups := make([]armorGroup, 0, len(model.Bodies))
	for _, b := range model.Bodies {
		g := armorGroup{Name: b.Name, Kind: b.MaterialKind, Triangles: b.Triangles}
		if m, ok := armor[b.Name]; ok {
			mm := m
			g.Material = &mm
		}
		groups = append(groups, g)
	}
	radius := float32(0)
	for _, g := range groups {
		for _, t := range g.Triangles {
			for _, v := range t {
				if l := v[0]*v[0] + v[1]*v[1] + v[2]*v[2]; l > radius*radius {
					radius = float32(math.Sqrt(float64(l)))
				}
			}
		}
	}
	return &vehiclePartModel{Part: part, Offset: offset, Bounds: model.Bounds, Radius: radius, Groups: groups}, nil
}

// loadMaterials reads the game's material defaults from
// `common/vehicle.xml`'s `<materials>` block.
func loadMaterials(pkg string) (map[string]material, error) {
	raw, err := readFromZip(pkg, "scripts/item_defs/vehicles/common/vehicle.xml")
	if err != nil {
		return nil, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return nil, err
	}
	if f.Root == nil {
		return nil, fmt.Errorf("vehiclemodel: no common vehicle.xml root")
	}
	sec := f.Root.Child("materials")
	if sec == nil {
		return nil, fmt.Errorf("vehiclemodel: no <materials>")
	}
	out := make(map[string]material, len(sec.Children))
	for _, c := range sec.Children {
		out[c.Name] = materialFrom(c, material{})
	}
	return out, nil
}

// readArmor reads a part's `<armor>` block: a thickness per material name, with
// the material's parameters it overrides as children.
func readArmor(sec *entdef.Section, defaults map[string]material) map[string]material {
	out := map[string]material{}
	if sec == nil {
		return out
	}
	for _, c := range sec.Children {
		base, ok := defaults[c.Name]
		if !ok {
			// A material without a default is not one a vehicle uses.
			continue
		}
		thickness, err := strconv.ParseFloat(strings.TrimSpace(c.AsString()), 32)
		if err != nil {
			continue
		}
		m := materialFrom(c, base)
		m.Armor = float32(thickness)
		out[c.Name] = m
	}
	return out
}

// materialFrom applies a section's overrides to a base material.
func materialFrom(sec *entdef.Section, base material) material {
	m := base
	if v, err := floatChild(sec, "vehicleDamageFactor"); err == nil {
		m.VehicleDamageFactor = float32(v)
	}
	if b, ok := boolChild(sec, "useHitAngle"); ok {
		m.UseHitAngle = b
	}
	if b, ok := boolChild(sec, "mayRicochet"); ok {
		m.MayRicochet = b
	}
	if b, ok := boolChild(sec, "checkCaliberForRicochet"); ok {
		m.CheckCaliberForRicochet = b
	}
	if b, ok := boolChild(sec, "checkCaliberForHitAngleNorm"); ok {
		m.CheckCaliberForHitAngleNorm = b
	}
	if b, ok := boolChild(sec, "collideOnceOnly"); ok {
		m.CollideOnceOnly = b
	}
	return m
}

// boolChild reads one boolean child, as `true`/`false` or `1`/`0`.
func boolChild(sec *entdef.Section, name string) (bool, bool) {
	c := sec.Child(name)
	if c == nil {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(c.AsString())) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	return false, false
}

// sectionChild is `Child` that tolerates a nil section.
func sectionChild(sec *entdef.Section, name string) *entdef.Section {
	if sec == nil {
		return nil
	}
	return sec.Child(name)
}

// firstChild is the first child of a section, or nil.
func firstChild(sec *entdef.Section) *entdef.Section {
	if sec == nil || len(sec.Children) == 0 {
		return nil
	}
	return sec.Children[0]
}

// vectorY2 reads the Y of a vector section, or of the section itself when name
// is empty. The packed defs carry these both as text and as 12 raw bytes.
func vectorY2(sec *entdef.Section, name string) (float64, error) {
	if sec == nil {
		return 0, fmt.Errorf("no section")
	}
	if name != "" {
		sec = sec.Child(name)
		if sec == nil {
			return 0, fmt.Errorf("no %s", name)
		}
	}
	return vectorY(sec)
}

// readVehicleRes reads a `vehicles/…` resource from the game's vehicle
// packages. The files are spread over `vehicles_level_NN*.pkg`, so the packages
// are searched in order and the first hit wins.
func readVehicleRes(path string) ([]byte, error) {
	dir := MapPackagesDir
	if dir == "" {
		return nil, fmt.Errorf("vehiclemodel: no packages directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "vehicles_") || !strings.HasSuffix(name, ".pkg") {
			continue
		}
		raw, err := readFromZip(filepath.Join(dir, name), path)
		if err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("vehiclemodel: %s not in any vehicle package", path)
}
