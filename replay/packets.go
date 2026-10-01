package replay

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Packet is one timestamped battle-stream record: [u32 size][u32 type]
// [f32 time][payload size bytes]. Verified chaining on 2.4.0.0
// fixtures (version record → digest record → …).
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
