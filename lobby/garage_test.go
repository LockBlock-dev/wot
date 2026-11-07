package lobby

import (
	"bytes"
	"strings"
	"testing"
)

// TestVehicleTypeCompDescr pins the inventory's vehicle descriptor against
// the client's own reader, `items/vehicles.pyc parseVehicleCompactDescr`:
//
//	header, vehicleTypeID = struct.unpack('2B', compactDescr[:2])
//	if header & EXTENDED_VEHICLE_TYPE_ID_FLAG:      # 2
//	    vehicleTypeID += unpackByte(compactDescr[2]) << 8
//	return (header >> 4 & 15, vehicleTypeID)
//
// The inventory entry is the vehicle TYPE descriptor, not the full module
// descriptor: InventoryRequester turns it back into a type id and
// InventoryVehiclesValidator builds a VehicleDescr from it, which fills in
// the stock modules itself.
func TestVehicleCompDescr(t *testing.T) {
	cases := []struct {
		nation uint8
		typeID uint16
		parts  [6]uint16
		want   []byte
	}{
		// ussr T-34: chassis 0, engine 2032, fuel 203, radio 5, turret 0,
		// gun 2038 — the values the client's own VehicleDescr round-trips.
		{0, 0, [6]uint16{0, 2032, 203, 5, 0, 2038},
			[]byte{0x01, 0x00, 0x00, 0x00, 0xf0, 0x07, 0xcb, 0x00, 0x05, 0x00, 0x00, 0x00, 0xf6, 0x07, 0x00}},
		// germany, extended typeID: the head gains the EXTENDED flag and a
		// third byte.
		{1, 0x1234, [6]uint16{1, 2, 3, 4, 5, 6},
			[]byte{0x13, 0x34, 0x12, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := VehicleCompDescr(c.nation, c.typeID, c.parts[0], c.parts[1], c.parts[2], c.parts[3], c.parts[4], c.parts[5])
		if string(got) != string(c.want) {
			t.Fatalf("VehicleCompDescr(%d, %d) = % x, want % x", c.nation, c.typeID, got, c.want)
		}
		// Round-trip through the client's own byte-form rule
		// (`parseVehicleCompactDescr`): nation and typeID, with the
		// EXTENDED flag carrying the typeID's high byte. The item type is
		// implicit (always vehicle) — the flag shares the low nibble, so
		// `head & 15` is 3 on an extended descriptor and says nothing
		// about the item type.
		nation, id, err := parseVehicleTypeCompDescr(got)
		if err != nil {
			t.Fatalf("parse(% x): %v", got, err)
		}
		if nation != c.nation || id != c.typeID {
			t.Fatalf("round-trip (%d, %d), want (%d, %d)", nation, id, c.nation, c.typeID)
		}
	}
}

// TestGarageCompDescrsAreDense pins the inventory ids: the garage carousel
// walks them, so they start at 1 and have no gaps.
func TestGarageCompDescrsAreDense(t *testing.T) {
	vs := []OwnableVehicle{{Nation: 0, TypeID: 0}, {Nation: 0, TypeID: 1}, {Nation: 2, TypeID: 300}}
	cds := GarageCompDescrs(vs)
	if len(cds) != len(vs) {
		t.Fatalf("%d entries, want %d", len(cds), len(vs))
	}
	for i := 1; i <= len(vs); i++ {
		if _, ok := cds[int64(i)]; !ok {
			t.Fatalf("no inventory id %d", i)
		}
	}
}

// TestAllOwnableVehicles pins the generated table: it must be populated,
// every entry must encode, and the training-mode bots must be gone (they
// are real vehicle types but not ownable — the client shows them as
// `#maps_training:` entries, not garage tanks).
func TestAllOwnableVehicles(t *testing.T) {
	if len(AllOwnableVehicles) < 1000 {
		t.Fatalf("%d ownable vehicles, want the full list (>1000)", len(AllOwnableVehicles))
	}
	if err := ValidateOwnableVehicles(AllOwnableVehicles); err != nil {
		t.Fatal(err)
	}
	seen := map[[2]uint16]bool{}
	for _, v := range AllOwnableVehicles {
		key := [2]uint16{uint16(v.Nation), v.TypeID}
		if seen[key] {
			t.Fatalf("duplicate vehicle nation %d typeID %d (%s)", v.Nation, v.TypeID, v.Name)
		}
		seen[key] = true
		if strings.Contains(v.Name, "MapsTraining") {
			t.Fatalf("%s is a training-mode vehicle, not ownable", v.Name)
		}
	}
}

// TestUnlockIntCDs pins the researched-item intCDs a garage implies.
//
// `stats.unlocks` is what `gui_items/vehicle.py isUnlocked` tests, so an
// empty one renders the whole tech tree greyed out as unresearched. The
// intCD form is `itemType + (nation << 4) + (id << 8)`.
func TestUnlockIntCDs(t *testing.T) {
	// ussr T-34: chassis 0, engine 2032, fuel 203, radio 5, turret 0, gun 2038.
	cd := VehicleCompDescr(0, 0, 0, 2032, 203, 5, 0, 2038)
	got := UnlockIntCDsFor([][]byte{cd})
	want := []int64{
		1,           // vehicle, nation 0, typeID 0
		2,           // chassis 0
		5 + 2032<<8, // engine
		6 + 203<<8,  // fuelTank
		7 + 5<<8,    // radio
		3,           // turret 0
		4 + 2038<<8, // gun
	}
	if len(got) != len(want) {
		t.Fatalf("%d intCDs, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("intCD %d = %d, want %d (all: %v)", i, got[i], want[i], got)
		}
	}
	// A nation and typeID that need the extended head still resolve.
	ext := VehicleCompDescr(5, 0x1234, 1, 2, 3, 4, 5, 6)
	got = UnlockIntCDsFor([][]byte{ext})
	if want := int64(1) + 5<<4 + 0x1234<<8; got[0] != want {
		t.Fatalf("extended vehicle intCD %d, want %d", got[0], want)
	}
	if want := int64(2) + 5<<4 + 1<<8; got[1] != want {
		t.Fatalf("extended chassis intCD %d, want %d", got[1], want)
	}
}

// TestAllOwnableVehiclesUnlockEverything is the whole-table check: every
// generated vehicle must contribute its type intCD, so no vehicle in the
// garage reads as unresearched.
func TestAllOwnableVehiclesUnlockEverything(t *testing.T) {
	unlocks := UnlockIntCDs(AllOwnableVehicles)
	if len(unlocks) != len(AllOwnableVehicles)*7 {
		t.Fatalf("%d intCDs for %d vehicles, want 7 each", len(unlocks), len(AllOwnableVehicles))
	}
	seen := make(map[int64]bool, len(unlocks))
	for _, cd := range unlocks {
		seen[cd] = true
	}
	for _, v := range AllOwnableVehicles {
		want := int64(1) + int64(v.Nation)<<4 + int64(v.TypeID)<<8
		if !seen[want] {
			t.Fatalf("vehicle %s (%d) has no type intCD %d in unlocks", v.Name, v.TypeID, want)
		}
	}
}

// TestShopItemPrices pins the shop's price table: every vehicle's type intCD
// and its stock modules' intCDs, each a (credits, gold) pair.
//
// `vehicle_items_getter.getItemsIterator` walks `items['itemPrices']`, and
// that is what lists vehicles for the tech tree AND for any `getVehicles()`
// call without REQ_CRITERIA.INVENTORY — which is the hangar carousel's own
// filter. An empty table is why the carousel resolved to zero vehicles
// while the inventory held them all.
func TestShopItemPrices(t *testing.T) {
	vs := []OwnableVehicle{{
		Nation: 0, TypeID: 0, Name: "R04_T-34", Price: 356700,
		CompDescr: VehicleCompDescr(0, 0, 0, 2032, 203, 5, 0, 2038),
	}}
	prices := ShopItemPrices(vs)
	// 7 for the vehicle and its stock modules, plus one per crew skin, one
	// per consumable, one per shell, one per optional device and one per
	// customization item.
	want := 7 + len(AllCrewSkinIDs) + len(AllEquipment) + len(AllShells) +
		len(AllOptionalDevices) + len(CustomizationIntCDs())
	if len(prices) != want {
		t.Fatalf("%d prices, want %d (vehicle + 6 modules + crew skins + consumables + shells + devices + customization)", len(prices), want)
	}
	if got := prices[int64(1)]; got["credits"] != 356700 || len(got) != 1 {
		t.Fatalf("vehicle price %v, want {credits: 356700}", got)
	}
	if got := prices[int64(4)+2038<<8]; got["credits"] != 100 || len(got) != 1 {
		t.Fatalf("gun price %v, want {credits: 100}", got)
	}
	// A gold-priced vehicle is priced in gold only.
	vs[0].GoldPrice = true
	if got := ShopItemPrices(vs)[int64(1)]; got["gold"] != 356700 || len(got) != 1 {
		t.Fatalf("gold vehicle price %v, want {gold: 356700}", got)
	}
}

// TestAllOwnableVehiclesHavePrices is the whole-table check: every vehicle
// in the generated list must contribute a price, so the carousel's shop
// branch can list it.
func TestAllOwnableVehiclesHavePrices(t *testing.T) {
	prices := ShopItemPrices(AllOwnableVehicles)
	if len(prices) < len(AllOwnableVehicles) {
		t.Fatalf("%d prices for %d vehicles", len(prices), len(AllOwnableVehicles))
	}
	for _, v := range AllOwnableVehicles {
		want := int64(1) + int64(v.Nation)<<4 + int64(v.TypeID)<<8
		if _, ok := prices[want]; !ok {
			t.Fatalf("vehicle %s (%d) has no price entry %d", v.Name, v.TypeID, want)
		}
	}
}

// TestItemsPricesNodeIsAnInstance pins the shop price table's pickle shape.
//
// `ShopRequester.getPrices()` returns `items['itemPrices']` AS-IS and
// `getItemPrice` then calls `.getPrices(intCD)` on it, so the value must be
// an `items.ItemsPrices` INSTANCE. A plain dict raises
// `AttributeError: 'dict' object has no attribute 'getPrices'` and every
// vehicle construction fails. The client's own pickle of one is
// GLOBAL + EMPTY_TUPLE + NEWOBJ, then BUILD with the state dict
// `{'_itemsPriceInfo': {intCD: {'credits': c, 'gold': g}}}`.
func TestItemsPricesNodeIsAnInstance(t *testing.T) {
	raw, err := EncodeDocument(NewDict().Set("itemPrices", ItemsPricesNode(map[int64]map[string]int64{1: {"credits": 100}})))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte("citems\nItemsPrices\n)\x81}")
	if !bytes.Contains(raw, want) {
		t.Fatalf("pickle lacks the ItemsPrices NEWOBJ head: % x", raw)
	}
	if !bytes.Contains(raw, []byte("_itemsPriceInfo")) {
		t.Fatalf("pickle lacks _itemsPriceInfo: % x", raw)
	}
	if !bytes.Contains(raw, []byte("credits")) {
		t.Fatalf("pickle lacks the price keys: % x", raw)
	}
	if raw[len(raw)-1] != '.' {
		t.Fatalf("pickle does not end with STOP: % x", raw[len(raw)-4:])
	}
	// The state must be applied with BUILD, not left as a bare dict.
	if !bytes.Contains(raw, []byte("sb")) {
		t.Fatalf("pickle lacks SETITEM+BUILD: % x", raw)
	}
}

// TestCrewSkinIntCD pins the shop key and the inventory key for a crew skin.
//
// The two differ: the shop price table is keyed by the intCD
// (`makeIntCompactDescrByID('crewSkin', CREW_SKIN, skinID)`), while the
// inventory section is keyed by the bare skin id, because
// `CrewSkin.__init__` calls `inventory.getItems(CREW_SKINS, skinID)`.
func TestCrewSkinIntCD(t *testing.T) {
	// Skin 2 (Rybalko) is intCD 541 in the live client.
	if got := CrewSkinIntCD(2); got != 541 {
		t.Fatalf("CrewSkinIntCD(2) = %d, want 541", got)
	}
	inv := CrewSkinInventory([]uint16{2, 3})
	items, ok := inv[skinInvItems].(map[int64]any)
	if !ok {
		t.Fatalf("no SkinInvData.ITEMS section: %v", inv)
	}
	if len(items) != 2 {
		t.Fatalf("%d skins, want 2", len(items))
	}
	if _, ok := items[2]; !ok {
		t.Fatalf("no entry for skin id 2: %v", items)
	}
	if _, ok := items[541]; ok {
		t.Fatalf("inventory keyed by intCD, want skin id: %v", items)
	}
	// `Tankman._equippedSkinID` indexes OUTFITS directly, so it must exist.
	if _, ok := inv[skinInvOutfits]; !ok {
		t.Fatalf("no SkinInvData.OUTFITS section: %v", inv)
	}
}

// TestAllCrewSkinsAndDogTags pins the generated tables.
func TestAllCrewSkinsAndDogTags(t *testing.T) {
	if len(AllCrewSkinIDs) < 50 {
		t.Fatalf("%d crew skins, want the full list", len(AllCrewSkinIDs))
	}
	if len(AllDogTagComponentIDs) < 100 {
		t.Fatalf("%d dog tag components, want the full list", len(AllDogTagComponentIDs))
	}
	seen := map[uint16]bool{}
	for _, id := range AllCrewSkinIDs {
		if seen[id] {
			t.Fatalf("duplicate crew skin id %d", id)
		}
		seen[id] = true
	}
	seen = map[uint16]bool{}
	for _, id := range AllDogTagComponentIDs {
		if seen[id] {
			t.Fatalf("duplicate dog tag component id %d", id)
		}
		seen[id] = true
	}
}

// TestEquipmentIntCD pins the consumable compact descriptor.
//
// The nation nibble is `nations.NONE_INDEX` (15), not 0: the live client's
// `vehicles.g_cache.equipments()[0].compactDescr` is 251 for handExtinguishers
// (id 0) and 507 for autoExtinguishers (id 1), i.e. `(id << 8) + 251`.
func TestEquipmentIntCD(t *testing.T) {
	if got := EquipmentIntCD(0); got != 251 {
		t.Fatalf("EquipmentIntCD(0) = %d, want 251", got)
	}
	if got := EquipmentIntCD(1); got != 507 {
		t.Fatalf("EquipmentIntCD(1) = %d, want 507", got)
	}
	if got := EquipmentIntCD(5); got != 5<<8+251 {
		t.Fatalf("EquipmentIntCD(5) = %d, want %d", got, 5<<8+251)
	}
}

// TestEquipmentInventory pins the consumables section: a flat
// `{intCD: count}` map, one entry per generated consumable, all at the
// requested stack size.
func TestEquipmentInventory(t *testing.T) {
	if len(AllEquipment) < 15 {
		t.Fatalf("%d consumables, want the client's full regular list", len(AllEquipment))
	}
	inv := EquipmentInventory(MaxItemCount)
	if len(inv) != len(AllEquipment) {
		t.Fatalf("%d entries, want %d", len(inv), len(AllEquipment))
	}
	for _, e := range AllEquipment {
		got, ok := inv[EquipmentIntCD(e.ID)]
		if !ok {
			t.Fatalf("consumable %d missing", e.ID)
		}
		if got != int64(MaxItemCount) {
			t.Fatalf("consumable %d count %v, want %d", e.ID, got, MaxItemCount)
		}
	}
	// The everyday consumables the hangar's loadout screen offers must be
	// in there: extinguishers, medkits, repair kits, cola, chocolate,
	// coffee, rations.
	for _, id := range []uint16{0, 1, 2, 3, 4, 5, 9, 11, 13, 100} {
		if _, ok := inv[EquipmentIntCD(id)]; !ok {
			t.Fatalf("consumable %d missing from the inventory", id)
		}
	}
}

// TestShellIntCD pins the shell compact descriptor against the live client:
// `vehicles.g_cache.shells(1)[0].compactDescr` is 26, i.e.
// `(id << 8) + 10 + nation << 4`.
func TestShellIntCD(t *testing.T) {
	if got := ShellIntCD(1, 0); got != 26 {
		t.Fatalf("ShellIntCD(1, 0) = %d, want 26", got)
	}
	if got := ShellIntCD(1, 1); got != 282 {
		t.Fatalf("ShellIntCD(1, 1) = %d, want 282", got)
	}
	if got := ShellIntCD(0, 0); got != 10 {
		t.Fatalf("ShellIntCD(0, 0) = %d, want 10", got)
	}
}

// TestAllShells pins the generated shell table: every nation present, and
// every shell carrying a price entry. The value may be 0 (the client itself
// declares some shells at 0) — what matters is that the entry exists, because
// the hangar's shells presenter calls `setValue` on it and a missing price
// arrives as None, which raises.
func TestAllShells(t *testing.T) {
	if len(AllShells) < 1000 {
		t.Fatalf("%d shells, want the client's full list", len(AllShells))
	}
	seen := map[uint8]bool{}
	for _, sh := range AllShells {
		seen[sh.Nation] = true
		if sh.Price < 0 {
			t.Fatalf("shell %d/%d has price %d", sh.Nation, sh.ID, sh.Price)
		}
	}
	if len(seen) != 11 {
		t.Fatalf("%d nations with shells, want 11", len(seen))
	}
}

// TestOptionalDeviceIntCD pins the mounted-equipment compact descriptor
// against the live client: `g_cache.optionalDevices()[43].compactDescr` is
// 11257, i.e. `(id << 8) + 9 + NONE_INDEX << 4`.
func TestOptionalDeviceIntCD(t *testing.T) {
	if got := OptionalDeviceIntCD(43); got != 11257 {
		t.Fatalf("OptionalDeviceIntCD(43) = %d, want 11257", got)
	}
	if got := OptionalDeviceIntCD(44); got != 11513 {
		t.Fatalf("OptionalDeviceIntCD(44) = %d, want 11513", got)
	}
}

// TestOptionalDeviceInventory pins the mounted-equipment section: a flat
// `{intCD: count}` map covering every tier the client declares.
func TestOptionalDeviceInventory(t *testing.T) {
	if len(AllOptionalDevices) < 80 {
		t.Fatalf("%d optional devices, want the client's full list", len(AllOptionalDevices))
	}
	inv := OptionalDeviceInventory(MaxItemCount)
	if len(inv) != len(AllOptionalDevices) {
		t.Fatalf("%d entries, want %d", len(inv), len(AllOptionalDevices))
	}
	for _, d := range AllOptionalDevices {
		got, ok := inv[OptionalDeviceIntCD(d.ID)]
		if !ok {
			t.Fatalf("optional device %d missing", d.ID)
		}
		if got != int64(MaxItemCount) {
			t.Fatalf("optional device %d count %v, want %d", d.ID, got, MaxItemCount)
		}
	}
	// The everyday devices the loadout screen offers must be in there:
	// rammer, vents, stabilizer, coated optics, camo net, toolbox, GLD.
	for _, id := range []uint16{43, 44, 45, 46, 47, 48, 50} {
		if _, ok := inv[OptionalDeviceIntCD(id)]; !ok {
			t.Fatalf("optional device %d missing from the inventory", id)
		}
	}
}

// TestEquipmentExcludesBattleAbilities pins that the avatar-driven battle
// abilities stay out of the consumables list: they carry `notInShop` and no
// depot icon, so the client renders a broken texture for them.
func TestEquipmentExcludesBattleAbilities(t *testing.T) {
	have := map[uint16]bool{}
	for _, e := range AllEquipment {
		have[e.ID] = true
	}
	// artillery_cw_tier6/8/10, bomber_cw_tier6/8/10, artillery_fallout,
	// bomber_fallout.
	for _, id := range []uint16{45, 47, 49, 55, 57, 59, 101, 102} {
		if have[id] {
			t.Fatalf("battle ability %d is in the consumables list", id)
		}
	}
	// The everyday consumables must still be there.
	for _, id := range []uint16{0, 1, 2, 3, 4, 5, 9, 11, 13, 100} {
		if !have[id] {
			t.Fatalf("consumable %d missing", id)
		}
	}
}

// TestVehicleMaxHealthIsTheHulls pins the hit points: the vehicle's HP is the
// hull section's own `<maxHealth>`, not a module's (the ammo bay and the
// turret carry their own, nested). The TOG II is 1248 and the Panhard EBR 105
// 1200, which is what the client's `typeDescriptor` reports for both.
func TestVehicleMaxHealthIsTheHulls(t *testing.T) {
	for _, want := range []struct {
		name string
		hp   int
	}{
		{"GB63_TOG_II", 1248},
		{"F108_Panhard_EBR_105", 1200},
	} {
		found := false
		for i := range AllOwnableVehicles {
			v := &AllOwnableVehicles[i]
			if v.Name != want.name {
				continue
			}
			found = true
			if v.MaxHealth != want.hp {
				t.Errorf("%s MaxHealth = %d, want %d", want.name, v.MaxHealth, want.hp)
			}
			if got := MaxHealthOf(v.CompDescr); got != want.hp {
				t.Errorf("%s MaxHealthOf = %d, want %d", want.name, got, want.hp)
			}
		}
		if !found {
			t.Errorf("%s not in the table", want.name)
		}
	}
}
