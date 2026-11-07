package lobby

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// MaxHealthOf returns the hit points of the vehicle a compact descriptor
// names, or 0 when the type is not in the generated table.
//
// The descriptor carries the stock modules, so the match is on the type head
// (nation + type id), not on the whole byte string.
func MaxHealthOf(compDescr []byte) int {
	if len(compDescr) < 3 {
		return 0
	}
	_, nation, id, err := ParseIntDescr(compDescr)
	if err != nil {
		return 0
	}
	for i := range AllOwnableVehicles {
		v := &AllOwnableVehicles[i]
		if v.Nation == nation && v.TypeID == id {
			return v.MaxHealth
		}
	}
	return 0
}

// OwnableVehicle is one vehicle the client's item_defs declares as ownable:
// the nation index and typeID its compact descriptor carries, the item_defs
// block name for logs, and the descriptor itself.
type OwnableVehicle struct {
	Nation uint8
	TypeID uint16
	Name   string
	// CompDescr is the full vehicle compact descriptor an inventory entry
	// carries: the type head plus the stock chassis/engine/fuelTank/radio
	// and the first turret's turret+gun, then the flags byte.
	CompDescr []byte
	// Price is the list entry's <price>, and GoldPrice says which currency
	// it is in. The shop's price table is `(credits, gold)` per intCD.
	Price     int64
	GoldPrice bool
	// Class is the vehicle's class index in the client's own order
	// (`constants.VEHICLE_CLASSES`): 0 lightTank, 1 mediumTank,
	// 2 heavyTank, 3 SPG, 4 AT-SPG. The matchmaker's census is indexed by
	// it, so it comes from the list entry's <tags>, not from the name.
	Class uint8
	// Level is the vehicle's tier (1..11), from the list entry's <level>.
	Level uint8
	// MaxHealth is the vehicle's hit points: the hull's `<maxHealth>` in its
	// item defs, which is the number the client's `typeDescriptor` reports
	// and the one the health bar is scaled to. Not the turret's or a
	// module's.
	MaxHealth int
	// CrewSize is how many crew slots the vehicle has, the number of
	// children of its `<crew>` section. The client's `VehicleDescrCrew`
	// requires a vehicle's crew list to be exactly this long — any other
	// length raises `wrong number or tankmen` from the hangar's parameter
	// panel, so the server pads every list it sends to this size.
	CrewSize uint8
}

// VehicleCompDescr builds the compact descriptor an inventory entry carries
// for a vehicle: the type head plus the stock modules.
//
// Wire why: the inventory's `compDescr` for item type 1 is the FULL vehicle
// descriptor, not just the type head. `InventoryVehiclesValidator` does
// `vehicles.VehicleDescr(vehCompDescr)`, and that constructor runs
// `_splitVehicleCompactDescr`, which reads the component bytes at offset
// 2/3 — a two-byte type-only descriptor throws inside it, the client logs
// `(compact descriptor to XML mismatch?)` and the validator fails the
// account with a desync error.
//
// The layout is `VehicleDescr.makeCompactDescr`'s:
//
//	[header u8: itemType lo4 (=1 vehicle) | nation hi4, +2 EXTENDED]
//	[typeID lo8][ext u8 if EXTENDED (typeID hi8)]
//	[chassis u16][engine u16][fuelTank u16][radio u16]
//	[turret u16][gun u16]        (4 B per turret position)
//	[flags u8: optdev slot mask lo3 | 16 enh | 32 emb | 64 skip1 | 128 camo]
//
// A freshly built vehicle carries its stock parts and no optional devices,
// enhancements, emblems or camouflage, so the flags byte is 0.
func VehicleCompDescr(nation uint8, typeID uint16, chassis, engine, fuelTank, radio, turret, gun uint16) []byte {
	header := byte(compactItemVehicle) | nation<<compactNationShift
	out := make([]byte, 0, 16)
	if typeID < 0x100 {
		out = append(out, header, byte(typeID))
	} else {
		out = append(out, header|compactExtFlag, byte(typeID), byte(typeID>>8))
	}
	for _, id := range []uint16{chassis, engine, fuelTank, radio, turret, gun} {
		out = binary.LittleEndian.AppendUint16(out, id)
	}
	return append(out, 0) // flags
}

// GarageCompDescrs turns the generated ownable-vehicle list into the
// inventory's `compDescr` map: invID -> compact descriptor. Inventory ids
// start at 1 and are dense, which is what the client's garage carousel
// walks.
func GarageCompDescrs(vehicles []OwnableVehicle) map[int64][]byte {
	out := make(map[int64][]byte, len(vehicles))
	for i, v := range vehicles {
		out[int64(i+1)] = v.CompDescr
	}
	return out
}

// ValidateOwnableVehicles reports the first entry whose nation or typeID
// cannot be encoded, so a regenerated table fails loud instead of silently
// producing a descriptor the client would reject.
func ValidateOwnableVehicles(vehicles []OwnableVehicle) error {
	for _, v := range vehicles {
		if int(v.Nation) >= len(compactNations) {
			return fmt.Errorf("lobby: vehicle %q has nation %d, beyond the %d shipped nations", v.Name, v.Nation, len(compactNations))
		}
		if v.TypeID == 0 && v.Name == "" {
			return fmt.Errorf("lobby: vehicle entry with no name and typeID 0")
		}
		if _, _, err := parseVehicleTypeCompDescr(v.CompDescr); err != nil {
			return fmt.Errorf("lobby: vehicle %q: %w", v.Name, err)
		}
		if len(v.CompDescr) < 15 {
			return fmt.Errorf("lobby: vehicle %q descriptor is %d B, want at least 15 (head + 6 components + flags)", v.Name, len(v.CompDescr))
		}
	}
	return nil
}

// parseVehicleTypeCompDescr is the client's own byte-form reader
// (`items/vehicles.pyc parseVehicleCompactDescr`), used by the tests to
// round-trip what VehicleTypeCompDescr writes.
// VehicleTypeCompDescr is parseVehicleTypeCompDescr for callers outside the
// package: the nation index and type id a vehicle compact descriptor carries.
func VehicleTypeCompDescr(b []byte) (nation uint8, typeID uint16, err error) {
	return parseVehicleTypeCompDescr(b)
}

func parseVehicleTypeCompDescr(b []byte) (nation uint8, typeID uint16, err error) {
	if len(b) < 2 {
		return 0, 0, fmt.Errorf("lobby: vehicle compactDescr too short (%d B)", len(b))
	}
	header := b[0]
	typeID = uint16(b[1])
	if header&compactExtFlag != 0 {
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("lobby: extended vehicle compactDescr truncated")
		}
		typeID |= uint16(b[2]) << 8
	}
	return header >> compactNationShift & compactNationMask, typeID, nil
}

// Item type indices the compact descriptors carry (shipped
// common/items/__init__.pyc ITEM_TYPE_NAMES).
const (
	itemVehicle        = 1
	itemChassis        = 2
	itemTurret         = 3
	itemGun            = 4
	itemEngine         = 5
	itemFuelTank       = 6
	itemRadio          = 7
	itemTankman        = 8
	itemOptionalDevice = 9
	itemShell          = 10
	itemEquipment      = 11
	itemCustomization  = 12
	itemCrewSkin       = 13
	// crewSkinType is CrewSkinType.CREW_SKIN, the nibble a crew skin's
	// intCD carries where a vehicle carries its nation.
	crewSkinType = 1
	// skinInvItems is SkinInvData.ITEMS: the owned crew skins. The sibling
	// key 2 is SkinInvData.OUTFITS, which maps a tankman instance id to the
	// skin it wears.
	skinInvItems   = 1
	skinInvOutfits = 2
)

// ItemVehicle is the inventory section index for the garage
// (`items.ITEM_TYPE_NAMES` position of "vehicle").
const ItemVehicle = itemVehicle

// ItemTankman is the inventory section index for the barracks
// (`items.ITEM_TYPE_NAMES` position of "tankman").
const ItemTankman = itemTankman

// ItemEquipment is the inventory section index for consumables
// (`items.ITEM_TYPE_NAMES` position of "equipment").
const ItemEquipment = itemEquipment

// ItemOptionalDevice is the inventory section index for mounted equipment
// (`items.ITEM_TYPE_NAMES` position of "optionalDevice").
const ItemOptionalDevice = itemOptionalDevice

// ItemCustomization is the inventory section index for customization items
// (`items.ITEM_TYPE_NAMES` position of "customizationItem").
const ItemCustomization = itemCustomization

// ItemCrewSkin is the inventory section index for crew skins
// (`items.ITEM_TYPE_NAMES` position of "crewSkin").
const ItemCrewSkin = itemCrewSkin

// OptionalDevice is one mounted equipment from the client's
// optional_devices.xml: standard, deluxe (upgraded) and modernized
// (experimental) tiers all live in the same table.
type OptionalDevice struct {
	ID      uint16
	Credits int64
	Crystal int64
}

// OptionalDeviceIntCD is the compact descriptor of one mounted equipment:
// `makeIntCompactDescrByID('optionalDevice', NONE_INDEX, id)` =
// `(id << 8) + 9 + (15 << 4)`. Like consumables, optional devices are
// nation-less and carry the NONE_INDEX nibble — the live client's
// `g_cache.optionalDevices()[43].compactDescr` is 11257.
func OptionalDeviceIntCD(id uint16) int64 {
	return intCompactDescr(itemOptionalDevice, nationsNoneIndex, id)
}

// OptionalDeviceInventory is the optional-device section of the inventory:
// a flat `{intCD: count}` map, like consumables.
func OptionalDeviceInventory(count int64) map[int64]any {
	out := make(map[int64]any, len(AllOptionalDevices))
	for _, d := range AllOptionalDevices {
		out[OptionalDeviceIntCD(d.ID)] = count
	}
	return out
}

// Shell is one ammunition type from a nation's shells.xml.
type Shell struct {
	Nation uint8
	ID     uint16
	Price  int64
}

// ShellIntCD is the compact descriptor of one shell:
// `makeIntCompactDescrByID('shell', nation, id)` =
// `(id << 8) + 10 + nation << 4`. Shells are per-nation, unlike consumables.
func ShellIntCD(nation uint8, id uint16) int64 {
	return intCompactDescr(itemShell, nation, id)
}

// Equipment is one regular consumable from the client's equipments.xml.
type Equipment struct {
	ID    uint16
	Price int64
}

// nationsNoneIndex is `nations.NONE_INDEX`: the nation nibble a nation-less
// item carries.
const nationsNoneIndex = 15

// EquipmentIntCD is the compact descriptor of one consumable:
// `makeIntCompactDescrByID('equipment', NONE_INDEX, id)` =
// `(id << 8) + 11 + (15 << 4)`.
//
// Wire why the nation nibble is 15 and not 0: `artefacts.Equipment.id` is the
// pair `(nations.NONE_INDEX, id)` and `compactDescr` is built from it, so the
// client's own equipment intCDs are `(id << 8) + 251`. Keying the inventory
// and the price table with nation 0 puts every consumable at an intCD the
// client never asks for — the depot lists nothing and the loadout screen
// offers nothing to mount.
func EquipmentIntCD(id uint16) int64 {
	return intCompactDescr(itemEquipment, nationsNoneIndex, id)
}

// MaxItemCount is the stack size a seeded consumable carries. The inventory
// diff is pickled, so the count is a plain Python int with no wire width —
// this is simply "more than any battle can spend", the item-side twin of
// server.MaxCurrency.
const MaxItemCount = math.MaxInt32

// EquipmentInventory is the consumables section of the inventory:
// `{intCD: count}`. Unlike the garage and the barracks this section is a
// flat map — `InventoryRequester.__getItemsData` returns
// `cache[intCD]` for every simple item type, and `FittingItem.__init__`
// reads it as `inventory.getItems(itemTypeID, intCD)`.
func EquipmentInventory(count int64) map[int64]any {
	out := make(map[int64]any, len(AllEquipment))
	for _, e := range AllEquipment {
		out[EquipmentIntCD(e.ID)] = count
	}
	return out
}

// intCompactDescr builds the integer form of a compact descriptor:
// `itemType + (nation << 4) + (id << 8)` (items.parseIntCompactDescr's
// inverse, and what `makeIntCompactDescrByID` returns).
func intCompactDescr(itemType, nation uint8, id uint16) int64 {
	return int64(itemType) + int64(nation)<<4 + int64(id)<<8
}

// UnlockIntCDs returns the researched-item intCDs a garage implies: every
// vehicle's type intCD plus its stock modules' intCDs.
//
// Wire why: `stats.unlocks` is what the client reads to decide whether a
// vehicle or module is researched (`gui_items/vehicle.py isUnlocked` is
// `intCD in items.stats.unlocks`). With it empty the tech tree renders
// every vehicle greyed out as unresearched, and the modules panel asks for
// a price on an item it thinks is locked. The stock modules are exactly
// what a freshly built vehicle carries, so they are what a garage of
// freshly built vehicles has researched.
func UnlockIntCDs(vehicles []OwnableVehicle) []int64 {
	compDescrs := make([][]byte, 0, len(vehicles))
	for _, v := range vehicles {
		compDescrs = append(compDescrs, v.CompDescr)
	}
	return UnlockIntCDsFor(compDescrs)
}

// UnlockIntCDsFor is UnlockIntCDs over raw vehicle compact descriptors, so
// a caller holding an account's actual garage (not the generated list) gets
// the unlocks that garage implies.
func UnlockIntCDsFor(compDescrs [][]byte) []int64 {
	out := make([]int64, 0, len(compDescrs)*7)
	for _, cd := range compDescrs {
		nation, typeID, err := parseVehicleTypeCompDescr(cd)
		if err != nil {
			continue
		}
		out = append(out, intCompactDescr(itemVehicle, nation, typeID))
		at := 2
		if cd[0]&compactExtFlag != 0 {
			at = 3
		}
		if len(cd) < at+12 {
			continue
		}
		// Component order in the descriptor: chassis, engine, fuelTank,
		// radio, then one turret+gun pair per turret position.
		for i, kind := range []uint8{itemChassis, itemEngine, itemFuelTank, itemRadio, itemTurret, itemGun} {
			id := binary.LittleEndian.Uint16(cd[at+i*2:])
			out = append(out, intCompactDescr(kind, nation, id))
		}
	}
	return out
}

// ShopItemPrices builds the shop's `items.itemPrices` table for a garage:
// every vehicle's type intCD and its stock modules' intCDs, each mapped to
// a `(credits, gold)` pair.
//
// Wire why: `ShopRequester.getItemsData()` is `cache['items']`, and
// `vehicle_items_getter.getItemsIterator` walks `items['itemPrices']` to
// list vehicles for the tech tree and for any `getVehicles()` call that
// does NOT carry REQ_CRITERIA.INVENTORY. The hangar's carousel filter is
// exactly such a call (`RANDOM_MODE_CRITERIA` has no INVENTORY), so with an
// empty price table the carousel resolves to zero vehicles even though the
// inventory holds them all. The same table is what
// `Shop.__getPriceFromCache` reads, so it also fixes the `setReal(None)`
// crash in the tank details panel.
//
// Modules get a nominal price: the client only needs a number there, and
// the real per-module prices live in each vehicle's XML.
func ShopItemPrices(vehicles []OwnableVehicle) map[int64]map[string]int64 {
	const modulePrice = 100
	out := make(map[int64]map[string]int64, len(vehicles)*7)
	for _, v := range vehicles {
		nation, typeID, err := parseVehicleTypeCompDescr(v.CompDescr)
		if err != nil {
			continue
		}
		credits, gold := v.Price, int64(0)
		if v.GoldPrice {
			credits, gold = 0, v.Price
		}
		out[intCompactDescr(itemVehicle, nation, typeID)] = priceOf(credits, gold)
		at := 2
		if v.CompDescr[0]&compactExtFlag != 0 {
			at = 3
		}
		if len(v.CompDescr) < at+12 {
			continue
		}
		for i, kind := range []uint8{itemChassis, itemEngine, itemFuelTank, itemRadio, itemTurret, itemGun} {
			id := binary.LittleEndian.Uint16(v.CompDescr[at+i*2:])
			// The module's own price from the item defs, when the generated
			// table has it: the shop and the tech tree read it, and a flat
			// stand-in makes every module cost the same.
			price := int64(modulePrice)
			if byNation, ok := AllModulePrices[kind]; ok {
				if table, ok := byNation[nation]; ok {
					if p, ok := table[id]; ok && p > 0 {
						price = p
					}
				}
			}
			out[intCompactDescr(kind, nation, id)] = priceOf(price, 0)
		}
	}
	// Crew skins are listed the same way: the crew-skin screen walks the
	// shop's price table, so a skin with no price never appears even when
	// the inventory owns it.
	for _, id := range AllCrewSkinIDs {
		out[CrewSkinIntCD(id)] = priceOf(modulePrice, 0)
	}
	// Consumables too: `getItems` walks the shop's price table with
	// `onlyWithPrices=True` by default, so an equipment intCD with no
	// price is filtered out of the storage screen even when the
	// inventory owns it.
	for _, e := range AllEquipment {
		out[EquipmentIntCD(e.ID)] = priceOf(e.Price, 0)
	}
	// Shells too, and for a sharper reason: the hangar's shells presenter
	// reads `shell.buyPrices.itemPrice.price` for every shell of the mounted
	// gun and calls `setValue(value)` on the price model. With no price the
	// value is None, `setReal()` raises TypeError, and `_onLoading` aborts
	// before the loadout view finishes — the whole panel stays empty.
	for _, sh := range AllShells {
		out[ShellIntCD(sh.Nation, sh.ID)] = priceOf(sh.Price, 0)
	}
	// Optional devices. The deluxe tier is priced in crystal, which the
	// price dict carries under its own key (`ItemsPrices.__setitem__`
	// accepts a dict as-is).
	for _, d := range AllOptionalDevices {
		price := map[string]int64{}
		if d.Credits != 0 {
			price["credits"] = d.Credits
		}
		if d.Crystal != 0 {
			price["crystal"] = d.Crystal
		}
		out[OptionalDeviceIntCD(d.ID)] = price
	}
	// Customization items. The hangar's customize button is gated on
	// `items.getItems(STYLE, ...)` finding at least one non-3D style for the
	// current vehicle, and `getItems` walks this table with
	// `onlyWithPrices=True` — so with no customization prices the button is
	// greyed out on every tank.
	for _, cd := range CustomizationIntCDs() {
		out[cd] = priceOf(modulePrice, 0)
	}
	return out
}

// ItemsPricesNode builds the shop's `items.itemPrices` value.
//
// Wire why: `ShopRequester.getPrices()` returns `items['itemPrices']`
// AS-IS and `getItemPrice` then calls `.getPrices(intCD)` on it, so the
// value must be an `items.ItemsPrices` INSTANCE, not a plain dict — a dict
// raises `AttributeError: 'dict' object has no attribute 'getPrices'` and
// every vehicle construction fails. The client's own pickle of one is
//
//	\x80\x02 citems\nItemsPrices\n ) \x81 } U\x0f_itemsPriceInfo } ( …
//
// i.e. GLOBAL + EMPTY_TUPLE + NEWOBJ, then BUILD with the state dict
// `{'_itemsPriceInfo': {intCD: {'credits': c, 'gold': g}}}`. The inner
// values are dicts, not tuples.
func ItemsPricesNode(prices map[int64]map[string]int64) *FNode {
	var b []byte
	b = append(b, 'c')
	b = append(b, "items\nItemsPrices\n"...)
	b = append(b, ')', 0x81, '}') // EMPTY_TUPLE, NEWOBJ, EMPTY_DICT (state)
	b = append(b, 'U', byte(len("_itemsPriceInfo")))
	b = append(b, "_itemsPriceInfo"...)
	b = append(b, '}', '(') // EMPTY_DICT (the price map), MARK
	// Sorted so the pickle is reproducible; the client does not care about
	// order, but a stable document makes the tests and diffs readable.
	keys := make([]int64, 0, len(prices))
	for intCD := range prices {
		keys = append(keys, intCD)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, intCD := range keys {
		p := prices[intCD]
		b = appendBinInt(b, intCD)
		b = append(b, '}', '(') // one price dict
		currencies := make([]string, 0, len(p))
		for c := range p {
			currencies = append(currencies, c)
		}
		sort.Strings(currencies)
		for _, c := range currencies {
			b = append(b, 'U', byte(len(c)))
			b = append(b, c...)
			b = appendBinInt(b, p[c])
		}
		b = append(b, 'u') // SETITEMS: close the price dict
	}
	b = append(b, 'u') // SETITEMS: close the price map
	b = append(b, 's') // SETITEM: put it under _itemsPriceInfo
	b = append(b, 'b') // BUILD: apply the state to the instance
	return NewRaw(b)
}

// priceOf builds one price dict, omitting the currencies that are zero —
// `ItemsPrices.__setitem__` does the same for a tuple, and a zero entry
// would make `getCurrency()` pick a currency the item is not sold in.
func priceOf(credits, gold int64) map[string]int64 {
	out := map[string]int64{}
	if credits != 0 {
		out["credits"] = credits
	}
	if gold != 0 {
		out["gold"] = gold
	}
	return out
}

// appendBinInt writes a BININT (opcode 'J', signed 32-bit little-endian).
func appendBinInt(dst []byte, v int64) []byte {
	return append(dst, 'J', byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// CrewSkinIntCD is the shop key for one crew skin:
// `makeIntCompactDescrByID('crewSkin', CrewSkinType.CREW_SKIN, skinID)` =
// `itemType(13) + (CREW_SKIN(1) << 4) + (skinID << 8)`.
//
// This is the price-table key only. The inventory section is keyed by the
// bare skin id — see CrewSkinInventory.
func CrewSkinIntCD(skinID uint16) int64 {
	return intCompactDescr(itemCrewSkin, crewSkinType, skinID)
}

// CrewSkinInventory is the inventory's crew-skin section: `{1: {skinID: 1}}`,
// where `1` is `SkinInvData.ITEMS` (the owned items; `2` is the outfits).
//
// Wire why the key is the skin id and not the intCD: `CrewSkin.__init__` does
// `proxy.inventory.getItems(GUI_ITEM_TYPE.CREW_SKINS, self.__id)` where
// `self.__id` is the third field of `parseIntCompactDescr(intCD)` — the skin
// id — and `InventoryRequester.__getCrewSkinsData` returns
// `crewSkinsInvData[ITEMS].get(idx, 0)`. Keying by intCD leaves every skin
// unowned (`getFreeCount() == 0`), which disables every card in the tankman
// personal-data skin picker.
func CrewSkinInventory(skinIDs []uint16) map[int64]any {
	items := make(map[int64]any, len(skinIDs))
	for _, id := range skinIDs {
		items[int64(id)] = int64(1)
	}
	return map[int64]any{
		skinInvItems:   items,
		skinInvOutfits: map[int64]any{},
	}
}

// DogTagUnlockedComponents is the `dogTags.unlockedComponents` list: every
// component the client declares, so every background and engraving is
// available.
func DogTagUnlockedComponents(ids []uint16) []int64 {
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		out = append(out, int64(id))
	}
	return out
}
