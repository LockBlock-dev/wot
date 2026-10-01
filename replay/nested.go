package replay

import (
	"encoding/binary"
	"fmt"
)

// Nested-property (0x24) records: [entityID u32][isSlice u8][len u32]
// [0,0,0][op u8][flags? u8][payload]. isSlice is 1 on 2.4.0, mostly 0
// on 2.1.1, same shapes under both (a bare flag — a=00 samples carry
// full payloads, so it is not a count). len covers op+flags+payload
// exactly. The op byte is NOT
// .def numbering (affine/declaration/FullIndex/name-hash readings
// all fail; IDA shows the live path in BWEntities entity virtuals
// with an isSlice param, symbols stripped) — channels below are
// shape+timing-identified per (entity type, op); the flags byte
// varies per event (hit-kind candidate for stickers).
//
// Proven channels (exact-consumption on fixtures):
//   - (Vehicle, 0xc2): damageStickers element: 16 B
//     {networkID U32, segment U64, params U32}, optionally prefixed
//     by a 0xc0 marker byte (append vs set — open).
//   - (Vehicle, 0xc4): engineMode element(s): 1–2 raw bytes
//     (Tuple[2]{UINT8} partial/full update).
//   - (AreaDestructibles, 0xa0/0xa9): destroyed-family Tuple[3]
//     ([idx u8] + tuple in the 0xa9 form).
//   - (AreaDestructibles, 0xe0/0xe9): fallenTrees Tuple[5]
//     ([idx u8] + tuple in the 0xe9 form).
// Open (structural only): (Vehicle, 0xba/0xbc) paired timer updates
// ([U16,U16,…][U32 mask][F32], ~7 s countdowns, same-tick pairs),
// (Vehicle/Area, 0xc0) varying shapes under tag 0.

// NestedUpdate is one 0x24 record with raw payload.
type NestedUpdate struct {
	EntityID uint32
	Level    uint8
	Op       uint8
	Payload  []byte // bytes after op, verbatim (len-1 bytes)
}

// ParseNested splits one 0x24 payload; len must cover the tail exactly.
func ParseNested(data []byte) (NestedUpdate, error) {
	var n NestedUpdate
	if len(data) < 10 {
		return n, fmt.Errorf("wotreplay: nested len=%d < 10", len(data))
	}
	n.EntityID = binary.LittleEndian.Uint32(data[0:4])
	n.Level = data[4]
	ln := int(data[5])
	if data[6] != 0 || data[7] != 0 || data[8] != 0 {
		return n, fmt.Errorf("wotreplay: nested reserved=%x", data[6:9])
	}
	if ln != len(data)-9 {
		return n, fmt.Errorf("wotreplay: nested len=%d, have %d", ln, len(data)-9)
	}
	if ln < 1 {
		return n, fmt.Errorf("wotreplay: nested empty payload")
	}
	n.Op = data[9]
	n.Payload = append([]byte{}, data[10:]...)
	return n, nil
}

// StickerHit is one damageStickers element: same 16 B dict as
// showDamageFromShot's array elements, optionally prefixed by a
// flags byte (observed: 00 90 a0 b4 c0 c2 f0, varying per hit —
// hit-kind candidate; the no-flags form appends).
type StickerHit struct {
	NetworkID uint64
	Segment   uint64
	Params    uint64
	Flags     byte
	HasFlags  bool
}

// ParseSticker decodes a (Vehicle, 0xc2) payload.
func ParseSticker(payload []byte) (StickerHit, error) {
	var s StickerHit
	off := 0
	if len(payload) == 17 {
		s.Flags, s.HasFlags = payload[0], true
		off = 1
	} else if len(payload) != 16 {
		return s, fmt.Errorf("wotreplay: sticker len=%d", len(payload))
	}
	if len(payload[off:]) != 16 {
		return s, fmt.Errorf("wotreplay: sticker len=%d", len(payload))
	}
	s.NetworkID = uint64(binary.LittleEndian.Uint32(payload[off : off+4]))
	s.Segment = binary.LittleEndian.Uint64(payload[off+4 : off+12])
	s.Params = uint64(binary.LittleEndian.Uint32(payload[off+12 : off+16]))
	return s, nil
}

// ParseTuple3 decodes an (Area, 0xa0/0xa9) payload: Tuple[3], with an
// index byte in the 0xa9 form.
func ParseTuple3(payload []byte) (idx int, tup []any, err error) {
	rest := payload
	idx = -1
	if len(rest) == 4 {
		idx = int(rest[0])
		rest = rest[1:]
	} else if len(rest) != 3 {
		return 0, nil, fmt.Errorf("wotreplay: tuple3 len=%d", len(payload))
	}
	v, n, err := Decode("Tuple[3]{UINT8}", rest)
	if err != nil {
		return 0, nil, err
	}
	if n != len(rest) {
		return 0, nil, fmt.Errorf("wotreplay: tuple3 %d/%d", n, len(rest))
	}
	return idx, v.([]any), nil
}

// ParseTuple5 decodes an (Area, 0xe0/0xe9) payload: Tuple[5], with an
// index byte in the 0xe9 form.
func ParseTuple5(payload []byte) (idx int, tup []any, err error) {
	rest := payload
	idx = -1
	if len(rest) == 6 {
		idx = int(rest[0])
		rest = rest[1:]
	} else if len(rest) != 5 {
		return 0, nil, fmt.Errorf("wotreplay: tuple5 len=%d", len(payload))
	}
	v, n, err := Decode("Tuple[5]{UINT8}", rest)
	if err != nil {
		return 0, nil, err
	}
	if n != len(rest) {
		return 0, nil, fmt.Errorf("wotreplay: tuple5 %d/%d", n, len(rest))
	}
	return idx, v.([]any), nil
}
