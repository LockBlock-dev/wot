// Command wotgarage generates wot/lobby/garage_gen.go: every vehicle the
// client's own item_defs declares as ownable, with the compact descriptor
// an inventory entry carries for it.
//
//	go run ./cmd/wotgarage -item-defs /tmp/live/scripts/item_defs -out lobby/garage_gen.go
//
// Input is the UNPACKED item_defs tree (packed .xml first through
// wotunpack, or straight out of scripts.pkg):
//
//	vehicles/<nation>/list.xml          one block per vehicle: <id>, <tags>,
//	                                    <level>, <price>
//	vehicles/<nation>/components/*.xml  <ids>: component name -> id
//	vehicles/<nation>/<Name>.xml        the vehicle's own parts
//
// The nation index is the header nibble the compact descriptor carries
// (nations.pyc NAMES order), NOT the directory name, so the two are mapped
// explicitly and an unknown directory is skipped rather than guessed.
//
// What is excluded, and why: vehicles tagged `maps_training` are the
// training-mode bots and dummies (`R44_T80_MapsTraining_Dummy_LT_1`,
// `R04_T-34_MapsTraining_Player_MT_1`, …). They are real vehicle types but
// they are not ownable — the client shows them as `#maps_training:` bot
// entries, not as garage tanks. Everything else stays: premium, collector,
// reward, event and variant vehicles are all durable ownership, which is
// what the garage models.
//
// Each entry also carries the vehicle's CLASS (from the list entry's
// `<tags>`: lightTank/mediumTank/heavyTank/SPG/AT-SPG, in the client's own
// `constants.VEHICLE_CLASSES` order) and its TIER (from `<level>`). The
// matchmaker's queue census is indexed by the class, so it has to come from
// the client's own tag rather than from the name.
//
// The output is committed; runtime code never touches XML (same pattern as
// lobby/vehicle_data_gen.go and replay/methods_gen.go).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// nations is the compact-descriptor nation index order (shipped
// common/nations.pyc NAMES), which is also the item_defs directory name.
var nations = []string{
	"ussr", "germany", "usa", "china", "france", "uk",
	"japan", "czech", "sweden", "poland", "italy",
}

// excludedTags are the tags that mark a vehicle as not ownable.
var excludedTags = map[string]bool{
	"maps_training": true,
}

// componentFiles maps a component kind to its table file under
// vehicles/<nation>/components/.
var componentFiles = map[string]string{
	"chassis":  "chassis.xml",
	"engine":   "engines.xml",
	"fuelTank": "fuelTanks.xml",
	"radio":    "radios.xml",
	"turret":   "turrets.xml",
	"gun":      "guns.xml",
}

type vehicle struct {
	Nation    uint8
	TypeID    uint16
	Name      string
	CompDescr []byte
	Price     int64
	GoldPrice bool
	Class     uint8
	Level     uint8
	// CrewSize is how many crew slots the vehicle has, the number of
	// children of its `<crew>` section. The client requires a vehicle's
	// crew list to be exactly this long: `VehicleDescrCrew
	// ._validateAndComputeCrew` raises `wrong number or tankmen` on any
	// other length, and it is reached from the hangar's parameter panel,
	// not just from a battle.
	CrewSize uint8
}

// classTags maps a list entry's class tag to the client's own class index
// (`constants.VEHICLE_CLASSES = ('lightTank', 'mediumTank', 'heavyTank',
// 'SPG', 'AT-SPG')`). The matchmaker's census is indexed by it.
var classTags = map[string]uint8{
	"lightTank":  0,
	"mediumTank": 1,
	"heavyTank":  2,
	"SPG":        3,
	"AT-SPG":     4,
}

// classOf reads the class index out of a list entry's tags.
func classOf(tags []string) (uint8, bool) {
	for _, t := range tags {
		if c, ok := classTags[t]; ok {
			return c, true
		}
	}
	return 0, false
}

func main() {
	itemDefs := flag.String("item-defs", "", "unpacked item_defs directory")
	out := flag.String("out", "lobby/garage_gen.go", "Go file to write")
	flag.Parse()
	if *itemDefs == "" {
		fmt.Fprintln(os.Stderr, "wotgarage: -item-defs is required")
		os.Exit(2)
	}

	var all []vehicle
	skipped, failed := 0, 0
	for idx, nation := range nations {
		dir := filepath.Join(*itemDefs, "vehicles", nation)
		comps, err := loadComponents(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wotgarage: %s: %v\n", nation, err)
			os.Exit(1)
		}
		list, err := readPacked(filepath.Join(dir, "list.xml"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "wotgarage: %s: %v\n", nation, err)
			os.Exit(1)
		}
		for _, sec := range list.Root.Children {
			idSec := sec.Child("id")
			if idSec == nil {
				continue
			}
			tags := strings.Fields(sec.Child("tags").AsString())
			if notOwnable(tags) {
				skipped++
				continue
			}
			typeID, err := sectionInt(idSec)
			if err != nil {
				fmt.Fprintf(os.Stderr, "wotgarage: %s/%s: %v\n", nation, sec.Name, err)
				os.Exit(1)
			}
			cd, err := vehicleCompDescr(dir, nation, uint8(idx), uint16(typeID), sec.Name, comps)
			if err != nil {
				// A vehicle whose parts cannot be resolved is reported and
				// dropped: emitting a descriptor the client would reject is
				// worse than a shorter garage.
				fmt.Fprintf(os.Stderr, "wotgarage: skip %s/%s: %v\n", nation, sec.Name, err)
				failed++
				continue
			}
			price, gold := vehiclePrice(sec.Child("price"))
			class, ok := classOf(tags)
			if !ok {
				fmt.Fprintf(os.Stderr, "wotgarage: skip %s/%s: no class tag\n", nation, sec.Name)
				failed++
				continue
			}
			level, err := sectionInt(sec.Child("level"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "wotgarage: skip %s/%s: level: %v\n", nation, sec.Name, err)
				failed++
				continue
			}
			crewSize, err := vehicleCrewSize(filepath.Join(dir, sec.Name+".xml"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "wotgarage: skip %s/%s: crew: %v\n", nation, sec.Name, err)
				failed++
				continue
			}
			all = append(all, vehicle{
				Nation:    uint8(idx),
				TypeID:    uint16(typeID),
				Name:      sec.Name,
				CompDescr: cd,
				Price:     price,
				GoldPrice: gold,
				Class:     class,
				Level:     uint8(level),
				CrewSize:  crewSize,
			})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Nation != all[j].Nation {
			return all[i].Nation < all[j].Nation
		}
		return all[i].TypeID < all[j].TypeID
	})

	var b strings.Builder
	b.WriteString("// Code generated from the client's item_defs by wotgarage; DO NOT EDIT.\n")
	b.WriteString("// Every ownable vehicle the client declares, with the compact descriptor\n")
	b.WriteString("// an inventory entry carries for it. Regenerate after client updates.\n\n")
	b.WriteString("package lobby\n\n")
	b.WriteString("// AllOwnableVehicles is every vehicle in the client's own vehicle lists\n")
	b.WriteString("// except the training-mode bots and dummies (tagged `maps_training`),\n")
	b.WriteString("// which are real types but not ownable. Ordered by nation then typeID.\n")
	b.WriteString("var AllOwnableVehicles = []OwnableVehicle{\n")
	for _, v := range all {
		fmt.Fprintf(&b, "\t{Nation: %d, TypeID: %d, Name: %q, Price: %d, GoldPrice: %t, Class: %d, Level: %d, CrewSize: %d, CompDescr: []byte{%s}},\n",
			v.Nation, v.TypeID, v.Name, v.Price, v.GoldPrice, v.Class, v.Level, v.CrewSize, byteList(v.CompDescr))
	}
	b.WriteString("}\n")

	// Crew skins: every skin the client's crewSkins.xml declares.
	skins, err := crewSkinIDs(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: crew skins: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllCrewSkinIDs is every crew skin the client declares, so a garage can\n")
	b.WriteString("// own them all. The inventory keys them by intCD, not by skin id.\n")
	b.WriteString("var AllCrewSkinIDs = []uint16{\n")
	for _, id := range skins {
		fmt.Fprintf(&b, "\t%d,\n", id)
	}
	b.WriteString("}\n")

	// Dog tag components: every component the client's dog_tags.xml declares.
	tags, err := dogTagComponentIDs(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: dog tags: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllDogTagComponentIDs is every dog tag component the client declares\n")
	b.WriteString("// (backgrounds and engravings), so an account can unlock them all.\n")
	b.WriteString("var AllDogTagComponentIDs = []uint16{\n")
	for _, id := range tags {
		fmt.Fprintf(&b, "\t%d,\n", id)
	}
	b.WriteString("}\n")

	// Tankman name pools: every group the client's tankmen/<nation>.xml
	// declares, so a barracks can be filled with valid passports.
	groups, err := tankmanGroups(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: tankmen: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllTankmanGroups is every name pool the client's tankmen/<nation>.xml\n")
	b.WriteString("// declares. A tankman compact descriptor carries a first-name id, a\n")
	b.WriteString("// last-name id and an icon id, and `TankmanDescr` rejects any id its\n")
	b.WriteString("// nation config does not know, so these are the only usable values.\n")
	b.WriteString("var AllTankmanGroups = []TankmanGroup{\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "\t{Nation: %d, IsPremium: %t, IsFemale: %t, FirstIDs: []uint16{%s}, LastIDs: []uint16{%s}, IconIDs: []uint16{%s}},\n",
			g.Nation, g.IsPremium, g.IsFemale,
			uint16List(g.FirstIDs), uint16List(g.LastIDs), uint16List(g.IconIDs))
	}
	b.WriteString("}\n")

	// Consumables: every regular equipment the client's equipments.xml
	// declares (repair kits, first-aid kits, extinguishers, the crew
	// rations, …). Battle boosters and battle abilities live in the same
	// file but are a different item type, so they are filtered out.
	equip, err := equipmentList(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: equipment: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllEquipment is every regular consumable the client's\n")
	b.WriteString("// vehicles/common/equipments.xml declares, with its credit price.\n")
	b.WriteString("// Battle boosters and battle abilities share the file but are a\n")
	b.WriteString("// different item type, so they are not here.\n")
	b.WriteString("var AllEquipment = []Equipment{\n")
	for _, e := range equip {
		fmt.Fprintf(&b, "\t{ID: %d, Price: %d},\n", e.ID, e.Price)
	}
	b.WriteString("}\n")

	// Shells: every shell the client's per-nation shells.xml declares, with
	// its credit price. The loadout screen prices each shell of the mounted
	// gun from the shop's table, so a shell with no price raises inside the
	// presenter and aborts the whole loadout view.
	shells, err := shellList(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: shells: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllShells is every shell the client's vehicles/<nation>/components/\n")
	b.WriteString("// shells.xml declares, with its credit price.\n")
	b.WriteString("var AllShells = []Shell{\n")
	for _, sh := range shells {
		fmt.Fprintf(&b, "\t{Nation: %d, ID: %d, Price: %d},\n", sh.Nation, sh.ID, sh.Price)
	}
	b.WriteString("}\n")

	// Optional devices: every mounted equipment the client's
	// vehicles/common/optional_devices.xml declares — standard, deluxe
	// (upgraded) and modernized (experimental) tiers, plus the bounty ones.
	devices, err := optionalDeviceList(*itemDefs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: optional devices: %v\n", err)
		os.Exit(1)
	}
	b.WriteString("\n// AllOptionalDevices is every mounted equipment the client's\n")
	b.WriteString("// vehicles/common/optional_devices.xml declares, with its price.\n")
	b.WriteString("// The tiers are the `deluxe` and `modernized_*` tags; all of them\n")
	b.WriteString("// are ownable.\n")
	b.WriteString("var AllOptionalDevices = []OptionalDevice{\n")
	for _, d := range devices {
		fmt.Fprintf(&b, "\t{ID: %d, Credits: %d, Crystal: %d},\n", d.ID, d.Credits, d.Crystal)
	}
	b.WriteString("}\n")

	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "wotgarage: write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("%s: %d ownable vehicles (%d skipped as not ownable, %d dropped for unresolved parts)\n",
		*out, len(all), skipped, failed)
}

// vehicleCompDescr reads one vehicle's XML and builds its inventory
// descriptor from the STOCK parts: the first chassis, engine, fuel tank and
// radio, and the first turret's first gun. That is exactly what
// `VehicleDescr.makeCompactDescr` writes for a freshly built vehicle.
func vehicleCompDescr(dir, nation string, nationIdx uint8, typeID uint16, name string, comps map[string]map[string]uint16) ([]byte, error) {
	f, err := readPacked(filepath.Join(dir, name+".xml"))
	if err != nil {
		return nil, err
	}
	pick := func(section, kind string) (uint16, error) {
		sec := f.Root.Child(section)
		if sec == nil || len(sec.Children) == 0 {
			return 0, fmt.Errorf("no <%s>", section)
		}
		part := sec.Children[0].Name
		id, ok := comps[kind][part]
		if !ok {
			return 0, fmt.Errorf("%s %q not in the %s table", kind, part, kind)
		}
		return id, nil
	}
	chassis, err := pick("chassis", "chassis")
	if err != nil {
		return nil, err
	}
	engine, err := pick("engines", "engine")
	if err != nil {
		return nil, err
	}
	fuelTank, err := pick("fuelTanks", "fuelTank")
	if err != nil {
		return nil, err
	}
	radio, err := pick("radios", "radio")
	if err != nil {
		return nil, err
	}
	turretSec := f.Root.Child("turrets0")
	if turretSec == nil || len(turretSec.Children) == 0 {
		return nil, fmt.Errorf("no <turrets0>")
	}
	turretName := turretSec.Children[0].Name
	turret, ok := comps["turret"][turretName]
	if !ok {
		return nil, fmt.Errorf("turret %q not in the turret table", turretName)
	}
	guns := turretSec.Children[0].Child("guns")
	if guns == nil || len(guns.Children) == 0 {
		return nil, fmt.Errorf("turret %q has no <guns>", turretName)
	}
	gunName := guns.Children[0].Name
	gun, ok := comps["gun"][gunName]
	if !ok {
		return nil, fmt.Errorf("gun %q not in the gun table", gunName)
	}
	return lobby.VehicleCompDescr(nationIdx, typeID, chassis, engine, fuelTank, radio, turret, gun), nil
}

// loadComponents reads every component table for one nation.
func loadComponents(dir string) (map[string]map[string]uint16, error) {
	out := make(map[string]map[string]uint16, len(componentFiles))
	for kind, file := range componentFiles {
		f, err := readPacked(filepath.Join(dir, "components", file))
		if err != nil {
			return nil, err
		}
		ids := f.Root.Child("ids")
		if ids == nil {
			return nil, fmt.Errorf("%s has no <ids>", file)
		}
		table := make(map[string]uint16, len(ids.Children))
		for _, sec := range ids.Children {
			n, err := sectionInt(sec)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", file, sec.Name, err)
			}
			table[sec.Name] = uint16(n)
		}
		out[kind] = table
	}
	return out, nil
}

func readPacked(path string) (*entdef.File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return entdef.ParseFile(data)
}

// vehicleCrewSize counts a vehicle's crew slots: the children of its
// `<crew>` section, one per role (`<commander>radioman</commander>`,
// `<gunner/>`, …). The client's `VehicleDescrCrew` requires the crew list
// to be exactly this long.
func vehicleCrewSize(path string) (uint8, error) {
	f, err := readPacked(path)
	if err != nil {
		return 0, err
	}
	crew := f.Root.Child("crew")
	if crew == nil {
		return 0, fmt.Errorf("no <crew> section")
	}
	if len(crew.Children) == 0 || len(crew.Children) > 255 {
		return 0, fmt.Errorf("%d crew slots", len(crew.Children))
	}
	return uint8(len(crew.Children)), nil
}

// sectionInt reads a numeric section that the packed form may carry either
// as an int or as a STRING. The vehicle lists use both: `G79_Pz_IV_AusfGH`
// has `<id>0</id>` as an int, while `G02_Hummel` has `<id>01</id>` as a
// string — and `AsInt()` returns 0 for a string, which would silently
// collapse every string-id vehicle onto typeID 0.
func sectionInt(sec *entdef.Section) (int64, error) {
	if sec.OwnType == entdef.TypeString {
		n, err := strconv.ParseInt(strings.TrimSpace(sec.StrVal()), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("id %q is not a number: %w", sec.StrVal(), err)
		}
		return n, nil
	}
	return sec.AsInt(), nil
}

// crewSkinIDs reads every <crewSkin><id> from crewSkins.xml.
func crewSkinIDs(itemDefs string) ([]uint16, error) {
	f, err := readPacked(filepath.Join(itemDefs, "crewSkins", "crewSkins.xml"))
	if err != nil {
		return nil, err
	}
	var out []uint16
	for _, sec := range f.Root.Children {
		id := sec.Child("id")
		if id == nil {
			continue
		}
		n, err := sectionInt(id)
		if err != nil {
			return nil, err
		}
		out = append(out, uint16(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// dogTagComponentIDs reads every <component><componentId> from
// dog_tags.xml.
func dogTagComponentIDs(itemDefs string) ([]uint16, error) {
	f, err := readPacked(filepath.Join(itemDefs, "dog_tags", "dog_tags.xml"))
	if err != nil {
		return nil, err
	}
	var out []uint16
	for _, sec := range f.Root.Children {
		id := sec.Child("componentId")
		if id == nil {
			continue
		}
		n, err := sectionInt(id)
		if err != nil {
			return nil, err
		}
		out = append(out, uint16(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// vehiclePrice reads a list entry's <price>. The simple form is a credits
// amount (`<price>356700</price>`); the gold form nests a `<gold/>` marker
// (`<price>11200<gold/></price>`), which is what the shop's price tuple's
// second slot is for.
func vehiclePrice(sec *entdef.Section) (int64, bool) {
	if sec == nil {
		return 0, false
	}
	gold := sec.Child("gold") != nil
	n, err := sectionInt(sec)
	if err != nil || n < 0 {
		return 0, gold
	}
	return n, gold
}

// notOwnable reports whether any tag marks the vehicle as not ownable.
func notOwnable(tags []string) bool {
	for _, t := range tags {
		if excludedTags[t] {
			return true
		}
	}
	return false
}

// byteList renders a byte slice as a Go literal body.
func byteList(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ", ")
}

// tankmanGroup is one name pool from a nation's tankmen XML.
type tankmanGroup struct {
	Nation    uint8
	IsPremium bool
	IsFemale  bool
	FirstIDs  []uint16
	LastIDs   []uint16
	IconIDs   []uint16
}

// tankmanGroups reads every group from tankmen/<nation>.xml. The two
// top-level sections are `normalGroups` and `premiumGroups`; each child is a
// group with a `sex` and three id-keyed tables (`_<id>` element names, which
// `tankmen_readers._readIDs` turns into the integer ids the compact
// descriptor stores).
func tankmanGroups(itemDefs string) ([]tankmanGroup, error) {
	var out []tankmanGroup
	for idx, nation := range nations {
		f, err := readPacked(filepath.Join(itemDefs, "tankmen", nation+".xml"))
		if err != nil {
			return nil, err
		}
		for _, kind := range []struct {
			name    string
			premium bool
		}{{"normalGroups", false}, {"premiumGroups", true}} {
			sec := f.Root.Child(kind.name)
			if sec == nil {
				continue
			}
			for _, g := range sec.Children {
				sex := g.Child("sex")
				if sex == nil {
					continue
				}
				first, err := idTable(g.Child("firstNames"))
				if err != nil {
					return nil, fmt.Errorf("%s/%s/%s: %w", nation, kind.name, g.Name, err)
				}
				last, err := idTable(g.Child("lastNames"))
				if err != nil {
					return nil, fmt.Errorf("%s/%s/%s: %w", nation, kind.name, g.Name, err)
				}
				icons, err := idTable(g.Child("icons"))
				if err != nil {
					return nil, fmt.Errorf("%s/%s/%s: %w", nation, kind.name, g.Name, err)
				}
				if len(first) == 0 || len(last) == 0 || len(icons) == 0 {
					continue
				}
				out = append(out, tankmanGroup{
					Nation:    uint8(idx),
					IsPremium: kind.premium,
					IsFemale:  strings.TrimSpace(sex.AsString()) == "female",
					FirstIDs:  first,
					LastIDs:   last,
					IconIDs:   icons,
				})
			}
		}
	}
	return out, nil
}

// idTable reads a `_<id>` keyed table into the sorted ids it declares.
func idTable(sec *entdef.Section) ([]uint16, error) {
	if sec == nil {
		return nil, nil
	}
	var out []uint16
	for _, c := range sec.Children {
		if !strings.HasPrefix(c.Name, "_") {
			continue
		}
		n, err := strconv.ParseUint(c.Name[1:], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad id element %q: %w", c.Name, err)
		}
		out = append(out, uint16(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// uint16List renders ids as a Go composite literal body.
func uint16List(ids []uint16) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatUint(uint64(id), 10)
	}
	return strings.Join(parts, ", ")
}

// equipment is one consumable from equipments.xml.
type equipment struct {
	ID    uint16
	Price int64
}

// equipmentList reads every top-level section of equipments.xml whose
// `type` is absent or `regular`. `artefacts.Equipment.__init__` does
// `items.EQUIPMENT_TYPES[section.readString('type', 'regular')]`, so an
// absent element means regular; `battleBoosters` and `battleAbilities` are
// separate item types and are skipped.
func equipmentList(itemDefs string) ([]equipment, error) {
	f, err := readPacked(filepath.Join(itemDefs, "vehicles", "common", "equipments.xml"))
	if err != nil {
		return nil, err
	}
	var out []equipment
	for _, sec := range f.Root.Children {
		idSec := sec.Child("id")
		if idSec == nil {
			continue
		}
		if t := sec.Child("type"); t != nil && strings.TrimSpace(t.AsString()) != "regular" {
			continue
		}
		// `notForSale` marks the built-in and example consumables
		// (`builtinRepairkit`, `exampleAbility`, `removedRpmLimiter`): real
		// definitions, but not things an account can hold.
		if tags := sec.Child("tags"); tags != nil && strings.Contains(tags.AsString(), "notForSale") {
			continue
		}
		// `notInShop` marks the avatar-driven battle abilities
		// (`artillery_cw_tier6`, `bomber_fallout`, …): they are triggered by
		// the server in clan-wars and fallout battles, have no depot icon,
		// and render as a broken texture in the consumables list.
		//
		// The flag is a SECTION carrying the text "True", not a value
		// element, so `AsString` (which only handles value sections) returns
		// "" — `StrVal` is what reads it.
		if n := sec.Child("notInShop"); n != nil && strings.EqualFold(strings.TrimSpace(n.StrVal()), "true") {
			continue
		}
		id, err := sectionInt(idSec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sec.Name, err)
		}
		var price int64
		if p := sec.Child("price"); p != nil {
			price, err = sectionInt(p)
			if err != nil {
				return nil, fmt.Errorf("%s/price: %w", sec.Name, err)
			}
		}
		out = append(out, equipment{ID: uint16(id), Price: price})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// shell is one ammunition type from a nation's shells.xml.
type shell struct {
	Nation uint8
	ID     uint16
	Price  int64
}

// shellList reads every top-level shell block of every nation's
// components/shells.xml. Unlike the other component tables this file has no
// `<ids>` index: each shell is a top-level block carrying its own `<id>` and
// `<price>`.
func shellList(itemDefs string) ([]shell, error) {
	var out []shell
	for idx, nation := range nations {
		f, err := readPacked(filepath.Join(itemDefs, "vehicles", nation, "components", "shells.xml"))
		if err != nil {
			return nil, err
		}
		for _, sec := range f.Root.Children {
			idSec := sec.Child("id")
			if idSec == nil {
				continue
			}
			id, err := sectionInt(idSec)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", nation, sec.Name, err)
			}
			var price int64
			if p := sec.Child("price"); p != nil {
				price, err = sectionInt(p)
				if err != nil {
					return nil, fmt.Errorf("%s/%s/price: %w", nation, sec.Name, err)
				}
			}
			out = append(out, shell{Nation: uint8(idx), ID: uint16(id), Price: price})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Nation != out[j].Nation {
			return out[i].Nation < out[j].Nation
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// optionalDevice is one mounted equipment from optional_devices.xml.
type optionalDevice struct {
	ID      uint16
	Credits int64
	Crystal int64
}

// optionalDeviceList reads every top-level block of
// vehicles/common/optional_devices.xml. The price is `<price>N</price>` with
// an optional `<crystal/>` child selecting the currency; the deluxe tier is
// priced in crystal, everything else in credits.
func optionalDeviceList(itemDefs string) ([]optionalDevice, error) {
	f, err := readPacked(filepath.Join(itemDefs, "vehicles", "common", "optional_devices.xml"))
	if err != nil {
		return nil, err
	}
	var out []optionalDevice
	for _, sec := range f.Root.Children {
		idSec := sec.Child("id")
		if idSec == nil {
			continue
		}
		id, err := sectionInt(idSec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", sec.Name, err)
		}
		d := optionalDevice{ID: uint16(id)}
		if p := sec.Child("price"); p != nil {
			amount, err := sectionInt(p)
			if err != nil {
				return nil, fmt.Errorf("%s/price: %w", sec.Name, err)
			}
			if p.Child("crystal") != nil {
				d.Crystal = amount
			} else {
				d.Credits = amount
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
