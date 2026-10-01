package replay

import (
	"encoding/binary"
	"fmt"
)

// PropSig is one client-server property's wire signature: descriptor
// in DescribeDeep syntax (see values.go).
type PropSig struct {
	Name string
	Type string
}

// PropFor resolves (entity type ID 1-based, FullIndex) to a property
// signature. One table serves all versions so far (2.1.1–2.4.0 agree
// on every observed wire except 2.1.1 Vehicle idx26 — open).
func PropFor(typeID uint16, idx uint32) (PropSig, bool) {
	var tab []PropSig
	switch typeID {
	case 2:
		tab = avatarProps
	case 6:
		tab = vehicleProps
	default:
		return PropSig{}, false
	}
	if int(idx) >= len(tab) {
		return PropSig{}, false
	}
	return tab[idx], true
}

// DecodedProp is an EntityProperty (0x7) record: [entityID u32]
// [propIdx u32][valueLen u32][value] — the same envelope philosophy
// as EntityMethod (valueLen covers the tail exactly).
type DecodedProp struct {
	EntityID uint32
	PropIdx  uint32
	Sig      PropSig
	Value    any
	Raw      []byte // value bytes verbatim
}

// ParseProp splits one 0x7 payload into header + value bytes.
func ParseProp(data []byte) (DecodedProp, []byte, error) {
	var p DecodedProp
	if len(data) < 12 {
		return p, nil, fmt.Errorf("wotreplay: prop len=%d < 12", len(data))
	}
	p.EntityID = binary.LittleEndian.Uint32(data[0:4])
	p.PropIdx = binary.LittleEndian.Uint32(data[4:8])
	n := binary.LittleEndian.Uint32(data[8:12])
	if int(n) != len(data)-12 {
		return p, nil, fmt.Errorf("wotreplay: prop valueLen=%d, have %d", n, len(data)-12)
	}
	return p, data[12:], nil
}

// DecodeProp parses + decodes one 0x7 payload; value must consume
// its bytes exactly.
func DecodeProp(typeID uint16, data []byte) (DecodedProp, error) {
	p, raw, err := ParseProp(data)
	if err != nil {
		return p, err
	}
	sig, ok := PropFor(typeID, p.PropIdx)
	if !ok {
		return p, fmt.Errorf("wotreplay: no prop for type=%d idx=%d", typeID, p.PropIdx)
	}
	v, n, err := Decode(sig.Type, raw)
	if err != nil {
		return p, fmt.Errorf("wotreplay: %s: %w", sig.Name, err)
	}
	if n != len(raw) {
		return p, fmt.Errorf("wotreplay: %s: %d/%d bytes consumed", sig.Name, n, len(raw))
	}
	p.Sig = sig
	p.Value = v
	p.Raw = append([]byte{}, raw...)
	return p, nil
}

// TimedProp is a decoded EntityProperty call with its packet time.
type TimedProp struct {
	Time float32
	Prop DecodedProp
}

// DecodePropsLenient is DecodeProps but collects unknown-index
// properties into skipped instead of failing. Mapped properties
// must still decode exactly.
func DecodePropsLenient(tab EntityTable, pkts []Packet) ([]TimedProp, []SkippedCall, error) {
	var out []TimedProp
	var skipped []SkippedCall
	for _, p := range pkts {
		if p.Type != 0x7 {
			continue
		}
		if len(p.Data) < 12 {
			return out, skipped, fmt.Errorf("wotreplay: short prop packet")
		}
		eid := binary.LittleEndian.Uint32(p.Data[0:4])
		ty, ok := tab.Resolve(eid)
		if !ok {
			return out, skipped, fmt.Errorf("wotreplay: prop target %d unknown", eid)
		}
		idx := binary.LittleEndian.Uint32(p.Data[4:8])
		if _, ok := PropFor(ty, idx); !ok {
			skipped = append(skipped, SkippedCall{p.Time, p.Type, eid, idx, len(p.Data) - 12})
			continue
		}
		d, err := DecodeProp(ty, p.Data)
		if err != nil {
			return out, skipped, fmt.Errorf("wotreplay: t=%.2f eid=%d: %w", p.Time, eid, err)
		}
		out = append(out, TimedProp{p.Time, d})
	}
	return out, skipped, nil
}

// DecodeProps decodes every 0x7 packet exactly using tab for types.
func DecodeProps(tab EntityTable, pkts []Packet) ([]TimedProp, error) {
	var out []TimedProp
	for _, p := range pkts {
		if p.Type != 0x7 {
			continue
		}
		if len(p.Data) < 4 {
			return out, fmt.Errorf("wotreplay: short prop packet")
		}
		eid := binary.LittleEndian.Uint32(p.Data[0:4])
		ty, ok := tab.Resolve(eid)
		if !ok {
			return out, fmt.Errorf("wotreplay: prop target %d unknown", eid)
		}
		d, err := DecodeProp(ty, p.Data)
		if err != nil {
			return out, fmt.Errorf("wotreplay: t=%.2f eid=%d: %w", p.Time, eid, err)
		}
		out = append(out, TimedProp{p.Time, d})
	}
	return out, nil
}
