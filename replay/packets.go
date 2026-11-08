package replay

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Packet is one timestamped battle-stream record: [u32 size][u32 type]
// [f32 time][payload size bytes]. Verified chaining on 2.4.0.0
// fixtures (version record → digest record → …).
//
// The type is the REPLAY's own record kind, not the wire element id, even
// where the two coincide (0x0 base player create, 0x1 cell player create,
// 0x5 entity create, 0x7 property, 0x8 method all match). Measured on
// 10_hills: 0x18 carries the client version string ("2.3.1.0"), 0x30 the
// graphics mode ("hd"), and 0x0a — 49k records, the most frequent — a 45-byte
// `[entityID][?][position V3][direction V3]` update, which the wire's 0x0a
// (`removeSpaceGeometryMapping`) is not. So a replay cannot answer "did the
// server send element X": its type byte has to be mapped through the client's
// own replay table (`BWReplay`) first.
type Packet struct {
	Time float32
	Type uint32
	Data []byte
}

// Packets walks the decompressed stream, returning each record.
// It stops at the first framing break (returns what it has + error).
func Packets(stream []byte) ([]Packet, error) {
	var out []Packet
	for off := 0; off+12 <= len(stream); {
		sz := binary.LittleEndian.Uint32(stream[off : off+4])
		ty := binary.LittleEndian.Uint32(stream[off+4 : off+8])
		tm := binary.LittleEndian.Uint32(stream[off+8 : off+12])
		if sz > uint32(len(stream)-off-12) || sz > 1<<26 {
			return out, fmt.Errorf("wotreplay: packet %d bad size %d at %d", len(out), sz, off)
		}
		out = append(out, Packet{
			Time: math.Float32frombits(tm),
			Type: ty,
			Data: stream[off+12 : off+12+int(sz)],
		})
		off += 12 + int(sz)
		if len(out) > 1<<22 {
			return out, fmt.Errorf("wotreplay: packet count runaway")
		}
	}
	return out, nil
}
