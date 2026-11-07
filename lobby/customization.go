package lobby

// Customization type indices (`items.components.c11n_constants.CustomizationType`).
const (
	c11nPaint           = 1
	c11nCamouflage      = 2
	c11nDecal           = 3
	c11nStyle           = 4
	c11nModification    = 5
	c11nProjectionDecal = 7
	c11nInsignia        = 8
	c11nPersonalNumber  = 9
	c11nFont            = 10
	c11nSequence        = 11
	c11nAttachment      = 12
	c11nStatTracker     = 13
)

// c11nInvItems is `CustomizationInvData.ITEMS`: the owned items. The sibling
// keys are OUTFITS (2), NOVELTY_DATA (3), DRESSED (4), PROGRESSION (5),
// OUTFITS_POOL (6) and SERIAL_NUMBERS (7).
const c11nInvItems = 1

// c11nUnboundVehicle is `UNBOUND_VEH_KEY`: the key an owned customization
// item carries when it is not bound to a particular vehicle. Every item the
// garage seeds is unbound, so the whole stock is usable on any tank.
const c11nUnboundVehicle = 0

// CustomizationIntCD is the compact descriptor of one customization item:
// `makeIntCompactDescrByID('customizationItem', cType, id)` =
// `(id << 8) + 12 + (cType << 4)`.
//
// The type nibble is the `CustomizationType`, not a nation — customization
// items are nation-less. Verified against the live client:
// `g_cache.customization20().styles[1].compactDescr` is 332, i.e.
// `(1 << 8) + 12 + (4 << 4)`.
func CustomizationIntCD(cType uint8, id uint16) int64 {
	return intCompactDescr(itemCustomization, cType, id)
}

// CustomizationInventory is the customization section of the inventory:
//
//	{ITEMS: {cType: {id: {UNBOUND_VEH_KEY: count}}}}
//
// `InventoryRequester.__getCustomizationsData` walks
// `cache[ITEMS][cType][id]` and `Customization.__init__` then iterates the
// result as `{vehicleIntCD: count}`, popping `UNBOUND_VEH_KEY` into
// `inventoryCount`. A missing entry reads as `{}`, so the item shows as
// unowned and cannot be applied.
func CustomizationInventory(count int64) map[int64]any {
	byType := make(map[int64]any, len(AllCustomizationIDs))
	for cType, ids := range AllCustomizationIDs {
		byID := make(map[int64]any, len(ids))
		for _, id := range ids {
			byID[int64(id)] = map[int64]any{c11nUnboundVehicle: count}
		}
		byType[int64(cType)] = byID
	}
	return map[int64]any{c11nInvItems: byType}
}

// CustomizationIntCDs is every customization item's compact descriptor, for
// the shop's price table.
func CustomizationIntCDs() []int64 {
	n := 0
	for _, ids := range AllCustomizationIDs {
		n += len(ids)
	}
	out := make([]int64, 0, n)
	for cType, ids := range AllCustomizationIDs {
		for _, id := range ids {
			out = append(out, CustomizationIntCD(cType, id))
		}
	}
	return out
}
