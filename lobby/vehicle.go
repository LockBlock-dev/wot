package lobby

import "fmt"

// Vehicle compact descriptor sectioning (offline, table-free).
//
// Wire why: `vehTypeCompDescr` dossier/battle values ARE vehicle
// compactDescrs (dossier `utils.getVehicleNationID` parses them via
// `vehicles.parseIntCompactDescr`; battle rosters carry the same
// blobs). Layout from shipped `items/vehicles.pyc`
// (`_splitVehicleCompactDescr` / `_combineVehicleCompactDescr` /
// `VehicleDescriptor.makeCompactDescr`):
//
//	[header u8: itemType lo4 (=1 vehicle) | nationID hi4, +2 EXTENDED]
//	[typeID lo8][ext u8 if EXTENDED (typeID hi8)]
//	[components: 8B (chassis,engine,fuel,radio LE u16) + 4B per turret]
//	[flags u8: optdev slot mask lo3 | 16 enh | 32 emb | 64 skip1 | 128 camo]
//	[optdev LE u16 × popcount(slot mask)]
//	[if enh: count u8 + 6B each]
//	[if emb: positions u8 + emblems 6B each + inscriptions 7B each]
//	[if skip1: +1B][if camo: rest]
//
// Nations (`nations.pyc`): ussr0 germany1 usa2 china3 france4 uk5
// japan6 czech7 sweden8 poland9 italy10. Component IDs resolve only
// against the vehicle XML cache, so this file sections without
// tables: the caller supplies the turret count (1 nearly always;
// multi-turret Carousel vehicles take 2+).
const (
	// compactItemVehicle is ITEM_TYPES.vehicle (shipped
	// common/items/__init__.pyc ITEM_TYPE_NAMES index 1);
	// compactExtFlag is EXTENDED_VEHICLE_TYPE_ID_FLAG (shipped
	// common/items/vehicles.pyc).
	compactItemVehicle = 1
	compactExtFlag     = 2

	// Header field layout. The game spells these inline as `& 15`
	// and `>> 4 & 15` (common/items/__init__.pyc
	// parseIntCompactDescr, common/items/vehicles.pyc
	// parseVehicleCompactDescr) with no named constant, so the names
	// are local.
	compactItemTypeMask = 15
	compactNationShift  = 4
	compactNationMask   = 15

	compactFlagEnh  = 16
	compactFlagEmb  = 32
	compactFlagSkip = 64
	compactFlagCamo = 128
)

// Nation names by header hi4 (nations.pyc NAMES order).
var compactNations = []string{
	"ussr", "germany", "usa", "china", "france", "uk",
	"japan", "czech", "sweden", "poland", "italy",
}

// IntDescr reads the descriptor head table-free (mirrors
// `items.parseIntCompactDescr`: lo4 itemType, bits4-7 nation,
// bits8-23 id). It covers the first 2 (or 3, extended) bytes.
func ParseIntDescr(b []byte) (itemType, nation uint8, id uint16, err error) {
	if len(b) < 2 {
		return 0, 0, 0, fmt.Errorf("lobby: compactDescr too short (%d B)", len(b))
	}
	head := uint(b[0])
	ext := head&compactExtFlag != 0
	if ext && len(b) < 3 {
		return 0, 0, 0, fmt.Errorf("lobby: extended compactDescr truncated")
	}
	itemType = uint8(head & compactItemTypeMask)
	nation = uint8(head >> compactNationShift & compactNationMask)
	id = uint16(b[1])
	if ext {
		id |= uint16(b[2]) << 8
	}
	if itemType == 0 {
		// Extended-int form (real type in a later byte,
		// `_splitIntCompactDescr`): out of scope for the vehicle
		// sectioner below, which needs lo4 == vehicle.
		return 0, 0, 0, fmt.Errorf("lobby: extended-int descr head")
	}
	return itemType, nation, id, nil
}

// Sections are the byte ranges of a sectioned compactDescr.
type CompactSections struct {
	ItemType uint8
	Nation   uint8
	TypeID   uint16
	// Offsets into the original blob:
	CompOff, CompEnd       int // components (8 + 4*turrets)
	Flags                  uint8
	OptDev                 []uint16
	EnhOff, EnhEnd         int
	EmbPos                 uint8
	EmblemsOff, EmblemsEnd int
	InscrOff, InscrEnd     int
	CamoOff                int // -1 when absent
	Total                  int
}

// NationName maps the header nation to the shipped name ("" beyond
// the known table — never guess).
func NationName(n uint8) string {
	if int(n) < len(compactNations) {
		return compactNations[n]
	}
	return ""
}

// SectionCompactDescr sections a vehicle compactDescr with turrets
// turret descriptors (1 nearly always). Overruns fail; trailing
// bytes after the last known section fail (strict — the writer emits
// no padding).
func SectionCompactDescr(b []byte, turrets int) (CompactSections, error) {
	var s CompactSections
	s.CamoOff = -1
	_, nation, id, err := ParseIntDescr(b)
	if err != nil {
		return s, err
	}
	off := 2
	if b[0]&compactExtFlag != 0 {
		off = 3
	}
	s.ItemType = b[0] & compactItemTypeMask
	s.Nation = nation
	s.TypeID = id
	if turrets < 1 {
		return s, fmt.Errorf("lobby: turret count %d", turrets)
	}
	s.CompOff = off
	s.CompEnd = off + 8 + 4*turrets
	if s.ItemType != compactItemVehicle {
		return s, fmt.Errorf("lobby: not a vehicle descr (type %d)", s.ItemType)
	}
	if len(b) < s.CompEnd+1 {
		return s, fmt.Errorf("lobby: components overrun (%d < %d)", len(b), s.CompEnd+1)
	}
	flags := b[s.CompEnd]
	s.Flags = flags
	off = s.CompEnd + 1
	// Optional devices: one LE u16 per set bit of the low-4 slot
	// mask (writer shifts per device, reader scans 4 bits).
	slots := flags & 15
	for i := 0; i < 4; i++ {
		if slots&(1<<uint(i)) != 0 {
			if len(b) < off+2 {
				return s, fmt.Errorf("lobby: optdev overrun")
			}
			s.OptDev = append(s.OptDev, uint16(b[off])|uint16(b[off+1])<<8)
			off += 2
		}
	}
	if flags&compactFlagEnh != 0 {
		if len(b) < off+1 {
			return s, fmt.Errorf("lobby: enh count overrun")
		}
		n := int(b[off])
		s.EnhOff = off + 1
		s.EnhEnd = s.EnhOff + n*6
		if len(b) < s.EnhEnd {
			return s, fmt.Errorf("lobby: enh overrun")
		}
		off = s.EnhEnd
	}
	if flags&compactFlagEmb != 0 {
		if len(b) < off+1 {
			return s, fmt.Errorf("lobby: embpos overrun")
		}
		pos := b[off]
		s.EmbPos = pos
		off++
		ne, ni := 0, 0
		for i := 0; i < 4; i++ {
			if pos&(1<<uint(i)) != 0 {
				ne++
			}
			if pos&(1<<uint(i+4)) != 0 {
				ni++
			}
		}
		s.EmblemsOff = off
		s.EmblemsEnd = off + ne*6
		s.InscrOff = s.EmblemsEnd
		s.InscrEnd = s.InscrOff + ni*7
		if len(b) < s.InscrEnd {
			return s, fmt.Errorf("lobby: emb/inscr overrun")
		}
		off = s.InscrEnd
	}
	if flags&compactFlagSkip != 0 {
		off++
		if len(b) < off {
			return s, fmt.Errorf("lobby: skip overrun")
		}
	}
	if flags&compactFlagCamo != 0 {
		s.CamoOff = off
		off = len(b)
	}
	if off != len(b) {
		return s, fmt.Errorf("lobby: %d trailing bytes", len(b)-off)
	}
	s.Total = off
	return s, nil
}
