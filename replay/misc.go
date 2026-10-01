package replay

import (
	"encoding/binary"
	"fmt"
)

// Rare / once-per-battle / per-tick records. Structural pins only
// where values stay opaque (per-tick families, compound bodies);
// exact framing everywhere. See REPLAY.md §6.

// EidRecord is a 0x4 / 0x22 record: [entityID u32] (area disable
// notices; avatar session open/close).
type EidRecord struct {
	EntityID uint32
}

// ParseEid decodes a 4 B entity-ID record.
func ParseEid(data []byte) (EidRecord, error) {
	var e EidRecord
	if len(data) != 4 {
		return e, fmt.Errorf("wotreplay: eid record len=%d", len(data))
	}
	e.EntityID = binary.LittleEndian.Uint32(data[0:4])
	return e, nil
}

// CounterRecord is a 0x16 / 0x28 record: [u32 LE] (1,2,3…).
type CounterRecord struct {
	Value uint32
}

// ParseCounter decodes a 4 B counter record.
func ParseCounter(data []byte) (CounterRecord, error) {
	var c CounterRecord
	if len(data) != 4 {
		return c, fmt.Errorf("wotreplay: counter len=%d", len(data))
	}
	c.Value = binary.LittleEndian.Uint32(data[0:4])
	return c, nil
}

// FlagRecord is a 0x12 / 0x2e record: [u8] (00 observed).
type FlagRecord struct {
	Flag uint8
}

// ParseFlag decodes a 1 B flag record.
func ParseFlag(data []byte) (FlagRecord, error) {
	var f FlagRecord
	if len(data) != 1 {
		return f, fmt.Errorf("wotreplay: flag len=%d", len(data))
	}
	f.Flag = data[0]
	return f, nil
}

// StringRecord is a 0x1b record: [u32 len][ASCII] (debug names like
// "arcade").
type StringRecord struct {
	Text string
}

// ParseStringRecord decodes a counted-string record.
func ParseStringRecord(data []byte) (StringRecord, error) {
	var s StringRecord
	if len(data) < 4 {
		return s, fmt.Errorf("wotreplay: string record len=%d", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[0:4]))
	if n != len(data)-4 {
		return s, fmt.Errorf("wotreplay: string len=%d, have %d", n, len(data)-4)
	}
	s.Text = string(data[4:])
	return s, nil
}

// ChatRecord is a 0x23 record: [u32 len][HTML text][u8 flag]
// (battle feed + player chat; flag 01 on own messages, 00 else).
type ChatRecord struct {
	Text string
	Flag uint8
}

// ParseChat decodes a 0x23 record.
func ParseChat(data []byte) (ChatRecord, error) {
	var c ChatRecord
	if len(data) < 5 {
		return c, fmt.Errorf("wotreplay: chat len=%d", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[0:4]))
	if n+1 != len(data)-4 {
		return c, fmt.Errorf("wotreplay: chat len=%d, have %d", n, len(data)-4)
	}
	c.Text = string(data[4 : len(data)-1])
	c.Flag = data[len(data)-1]
	return c, nil
}

// NamedRecord is a 0x31 record: [u32 len][name][payload raw]
// (trace channel: client_vehicle_state_32, chat actions…).
type NamedRecord struct {
	Name    string
	Payload []byte
}

// ParseNamed decodes a 0x31 record (name must be short ASCII).
func ParseNamed(data []byte) (NamedRecord, error) {
	var n NamedRecord
	if len(data) < 4 {
		return n, fmt.Errorf("wotreplay: named len=%d", len(data))
	}
	ln := int(binary.LittleEndian.Uint32(data[0:4]))
	if ln < 0 || 4+ln > len(data) {
		return n, fmt.Errorf("wotreplay: named namelen=%d, have %d", ln, len(data)-4)
	}
	n.Name = string(data[4 : 4+ln])
	for i := 0; i < len(n.Name); i++ {
		c := n.Name[i]
		if (c < 32 || c > 126) && c != '.' && c != '_' {
			return n, fmt.Errorf("wotreplay: named non-ascii %q", n.Name)
		}
	}
	n.Payload = append([]byte{}, data[4+ln:]...)
	return n, nil
}

// SpaceRecord is a 0xd record: [spaceID u32][rest raw] (×3 at t=0:
// lens 13/16/20).
type SpaceRecord struct {
	SpaceID uint32
	Rest    []byte
}

// ParseSpace decodes a 0xd record.
func ParseSpace(data []byte) (SpaceRecord, error) {
	var s SpaceRecord
	if len(data) < 4 {
		return s, fmt.Errorf("wotreplay: space len=%d", len(data))
	}
	s.SpaceID = binary.LittleEndian.Uint32(data[0:4])
	s.Rest = append([]byte{}, data[4:]...)
	return s, nil
}

// SnapRecord is a 0x6 record: [entityID u32][blob raw] (session
// open/close snapshots; battle start + end).
type SnapRecord struct {
	EntityID uint32
	Blob     []byte
}

// ParseSnap decodes a 0x6 record.
func ParseSnap(data []byte) (SnapRecord, error) {
	var s SnapRecord
	if len(data) < 4 {
		return s, fmt.Errorf("wotreplay: snap len=%d", len(data))
	}
	s.EntityID = binary.LittleEndian.Uint32(data[0:4])
	s.Blob = append([]byte{}, data[4:]...)
	return s, nil
}

// CompoundRecord is a 0x32 / 0x37 record: [u32 n][n bytes body].
// The 0x37 body carries concatenated sub-records (`0a 21 …`
// headers); 0x32 bodies sometimes embed entity IDs. Bodies stay
// raw (open).
type CompoundRecord struct {
	Body []byte
}

// ParseCompound decodes a 0x32/0x37 envelope exactly.
func ParseCompound(data []byte) (CompoundRecord, error) {
	var c CompoundRecord
	if len(data) < 4 {
		return c, fmt.Errorf("wotreplay: compound len=%d", len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[0:4]))
	if n != len(data)-4 {
		return c, fmt.Errorf("wotreplay: compound n=%d, have %d", n, len(data)-4)
	}
	c.Body = append([]byte{}, data[4:]...)
	return c, nil
}

// ShortSub is one 0x37 short sync record: [tag][x][02][kind][id]
// [s][f] (7 B), kind 3 = one-shot init (f 01), kind 6 = sequenced
// update (f growing). IDs are 30 even values c0–fa in every battle;
// (tag,x) is constant per battle (0a21/0666/0c3d observed); groups
// close with 3 zero bytes. Semantics open (per-slot sync with
// staggered ends — NOT deaths; see REPLAY.md §6).
type ShortSub struct {
	Tag, X, Kind, ID, S, F byte
}

// WalkShortSubs parses a 0x37 body composed purely of short subs and
// 000000 trailers; ok=false when other sub-forms are present.
func WalkShortSubs(body []byte) (subs []ShortSub, ok bool) {
	for len(body) > 0 {
		if len(body) >= 3 && body[0] == 0 && body[1] == 0 && body[2] == 0 {
			body = body[3:]
			continue
		}
		if len(body) < 7 || body[2] != 0x02 || (body[3] != 3 && body[3] != 6) {
			return subs, false
		}
		subs = append(subs, ShortSub{body[0], body[1], body[3], body[4], body[5], body[6]})
		body = body[7:]
	}
	return subs, true
}

// TickSample is one per-tick-family record kept raw: 0x1a (60 B
// position-ish + trailer) / 0x1f (4 B toggle values, mostly paired)
// triplets with 0x39 at ~10 Hz ticks, 0x1c/0x1d (4 B counters),
// 0x26 (40 B), 0x39 (41/72 B envelope), 0x35/0x36 (empty).
// Values stay opaque (playback-adjacent tick model — open).
type TickSample struct {
	Type uint32
	Data []byte
}
