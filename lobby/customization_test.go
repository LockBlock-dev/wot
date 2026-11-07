package lobby

import "testing"

// TestCustomizationIntCD pins the customization compact descriptor against
// the live client: `g_cache.customization20().styles[1].compactDescr` is 332,
// i.e. `(1 << 8) + 12 + (4 << 4)`, and
// `makeIntCompactDescrByID('customizationItem', 4, 100)` is 25676.
func TestCustomizationIntCD(t *testing.T) {
	if got := CustomizationIntCD(c11nStyle, 1); got != 332 {
		t.Fatalf("CustomizationIntCD(style, 1) = %d, want 332", got)
	}
	if got := CustomizationIntCD(c11nStyle, 100); got != 25676 {
		t.Fatalf("CustomizationIntCD(style, 100) = %d, want 25676", got)
	}
	if got := CustomizationIntCD(c11nCamouflage, 5); got != 1324 {
		t.Fatalf("CustomizationIntCD(camouflage, 5) = %d, want 1324", got)
	}
}

// TestCustomizationInventory pins the section shape:
// `{ITEMS: {cType: {id: {UNBOUND_VEH_KEY: count}}}}`.
//
// `InventoryRequester.__getCustomizationsData` walks `cache[ITEMS][cType][id]`
// and `Customization.__init__` iterates the result as `{vehicleIntCD: count}`,
// popping `UNBOUND_VEH_KEY` into `inventoryCount`. A flat `{intCD: count}`
// section — the shape consumables use — reads as `{}` here and every item
// shows as unowned.
func TestCustomizationInventory(t *testing.T) {
	inv := CustomizationInventory(MaxItemCount)
	items, ok := inv[c11nInvItems].(map[int64]any)
	if !ok {
		t.Fatalf("no CustomizationInvData.ITEMS section: %T", inv[c11nInvItems])
	}
	if len(items) != len(AllCustomizationIDs) {
		t.Fatalf("%d type sections, want %d", len(items), len(AllCustomizationIDs))
	}
	for cType, ids := range AllCustomizationIDs {
		byID, ok := items[int64(cType)].(map[int64]any)
		if !ok {
			t.Fatalf("type %d is %T", cType, items[int64(cType)])
		}
		if len(byID) != len(ids) {
			t.Fatalf("type %d has %d items, want %d", cType, len(byID), len(ids))
		}
		for _, id := range ids {
			bound, ok := byID[int64(id)].(map[int64]any)
			if !ok {
				t.Fatalf("type %d id %d is %T", cType, id, byID[int64(id)])
			}
			if got := bound[c11nUnboundVehicle]; got != int64(MaxItemCount) {
				t.Fatalf("type %d id %d count %v, want %d", cType, id, got, MaxItemCount)
			}
		}
	}
}

// TestAllCustomizationIDs pins the generated table: every type present, and
// the counts the live client reports.
func TestAllCustomizationIDs(t *testing.T) {
	want := map[uint8]int{
		c11nPaint:           725,
		c11nCamouflage:      1675,
		c11nDecal:           2306,
		c11nStyle:           1480,
		c11nModification:    10,
		c11nProjectionDecal: 1510,
		c11nInsignia:        126,
		c11nPersonalNumber:  16,
		c11nFont:            16,
		c11nSequence:        77,
		c11nAttachment:      424,
		c11nStatTracker:     2,
	}
	if len(AllCustomizationIDs) != len(want) {
		t.Fatalf("%d types, want %d", len(AllCustomizationIDs), len(want))
	}
	for cType, n := range want {
		if got := len(AllCustomizationIDs[cType]); got != n {
			t.Fatalf("type %d has %d items, want %d", cType, got, n)
		}
	}
	if got := len(CustomizationIntCDs()); got != 8367 {
		t.Fatalf("%d intCDs, want 8367", got)
	}
}
