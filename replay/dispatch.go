package replay

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Typed battle-stream dispatch for the renderer data layer.
// Packet framing itself lives in packets.go; here each family gets a
// structural parse. Arg bodies stay raw bytes: typed decoding needs
// the full .def DataType machine (wot/entdef), which
// this standalone module must not import.

// Position is an EntityPosition (0xa) record. Layout pinned on the
// Prohorovka fixture (45 B): [entityID u32][reserved u32 = 0]
// [X,Y,Z f32][Aux 3×f32][Yaw,Pitch,Roll f32][flags u8]. Pos moves with
// the tank (driving +Z sample), Dir tracks small-angle orientation;
// Aux is nonzero only for some entities (turret-state candidate —
// open, kept raw).
type Position struct {
	EntityID uint32
	X, Y, Z  float32
	Aux      [3]float32
	Yaw      float32
	Pitch    float32
	Roll     float32
	Flags    uint8
}

// ParsePosition decodes a 0xa payload.
func ParsePosition(data []byte) (Position, error) {
	var p Position
	if len(data) != 45 {
		return p, fmt.Errorf("wotreplay: position len=%d, want 45", len(data))
	}
	p.EntityID = binary.LittleEndian.Uint32(data[0:4])
	p.X = math.Float32frombits(binary.LittleEndian.Uint32(data[8:12]))
	p.Y = math.Float32frombits(binary.LittleEndian.Uint32(data[12:16]))
	p.Z = math.Float32frombits(binary.LittleEndian.Uint32(data[16:20]))
	for i := 0; i < 3; i++ {
		p.Aux[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[20+4*i : 24+4*i]))
	}
	p.Yaw = math.Float32frombits(binary.LittleEndian.Uint32(data[32:36]))
	p.Pitch = math.Float32frombits(binary.LittleEndian.Uint32(data[36:40]))
	p.Roll = math.Float32frombits(binary.LittleEndian.Uint32(data[40:44]))
	p.Flags = data[44]
	return p, nil
}

// EntityMethod is an EntityMethod (0x8) record: [entityID u32]
// [methodID u32][argsLen u32][args]. methodID indexes own++iface
// client methods (see entities.go); Name resolves via the entity
// table ("" when the type or method is outside the embedded tables).
type EntityMethod struct {
	EntityID uint32
	MethodID uint32
	Name     string
	Args     []byte
}

// ParseEntityMethod decodes a 0x8 payload; resolve maps entityID to a
// 1-based entity type ID (nil = skip naming).
func ParseEntityMethod(data []byte, resolve func(entityID uint32) (uint16, bool)) (EntityMethod, error) {
	var m EntityMethod
	if len(data) < 12 {
		return m, fmt.Errorf("wotreplay: method len=%d < 12", len(data))
	}
	m.EntityID = binary.LittleEndian.Uint32(data[0:4])
	m.MethodID = binary.LittleEndian.Uint32(data[4:8])
	n := binary.LittleEndian.Uint32(data[8:12])
	if int(n) != len(data)-12 {
		return m, fmt.Errorf("wotreplay: method argsLen=%d, have %d", n, len(data)-12)
	}
	m.Args = data[12:]
	if resolve != nil {
		if ty, ok := resolve(m.EntityID); ok {
			m.Name = fixedMethodName(ty, m.MethodID)
		}
	}
	return m, nil
}

// EntityTable maps entity IDs to 1-based type IDs from EntityCreate
// (0x5) records: [entityID u32][typeID u16]... Last-write-win:
// duplicate creates re-target the same ID with a stable type.
type EntityTable map[uint32]uint16

// AddCreate records one 0x5 payload; false when the payload is too
// short to hold the ID pair.
func (t EntityTable) AddCreate(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	eid := binary.LittleEndian.Uint32(data[0:4])
	ty := binary.LittleEndian.Uint16(data[4:6])
	t[eid] = ty
	return true
}

// Resolve returns the type ID for an entity.
func (t EntityTable) Resolve(eid uint32) (uint16, bool) {
	ty, ok := t[eid]
	return ty, ok
}

// SkippedCall is a call without a table signature (open var wire or
// open property index): kept raw for fit analysis, not decoded.
type SkippedCall struct {
	Time     float32
	Type     uint32 // packet type (0x8 method, 0x7 property)
	EntityID uint32
	MethodID uint32 // wire method ID, or property FullIndex
	ArgsLen  int
}

// buildEntityTable maps entity IDs to 1-based type IDs: avatars
// from Base/CellPlayerCreate (0x0/0x1), rest from EntityCreate (0x5).
func buildEntityTable(pkts []Packet) EntityTable {
	tab := EntityTable{}
	for _, p := range pkts {
		if (p.Type == 0x0 || p.Type == 0x1) && len(p.Data) >= 4 {
			tab[binary.LittleEndian.Uint32(p.Data[0:4])] = 2 // Avatar
		}
		if p.Type == 0x5 {
			tab.AddCreate(p.Data)
		}
	}
	return tab
}

// TimedCall is a decoded EntityMethod call with its packet time.
type TimedCall struct {
	Time float32
	Call DecodedCall
}

// DecodeAllLenient is DecodeAll but collects unknown-signature calls
// into skipped instead of failing. Fixed-block and mapped calls must
// still decode exactly.
func DecodeAllLenient(clientVer string, pkts []Packet) (EntityTable, []TimedCall, []SkippedCall, error) {
	tab := buildEntityTable(pkts)
	var out []TimedCall
	var skipped []SkippedCall
	for _, p := range pkts {
		if p.Type != 0x8 {
			continue
		}
		if len(p.Data) < 4 {
			return tab, out, skipped, fmt.Errorf("wotreplay: short method packet")
		}
		eid := binary.LittleEndian.Uint32(p.Data[0:4])
		ty, ok := tab.Resolve(eid)
		if !ok {
			return tab, out, skipped, fmt.Errorf("wotreplay: method target %d unknown", eid)
		}
		mid := binary.LittleEndian.Uint32(p.Data[4:8])
		if _, ok := SigFor(clientVer, ty, mid); !ok {
			skipped = append(skipped, SkippedCall{p.Time, p.Type, eid, mid, len(p.Data) - 12})
			continue
		}
		c, err := DecodeCall(clientVer, ty, p.Data)
		if err != nil {
			return tab, out, skipped, fmt.Errorf("wotreplay: t=%.2f eid=%d: %w", p.Time, eid, err)
		}
		out = append(out, TimedCall{p.Time, c})
	}
	return tab, out, skipped, nil
}

// DecodeAll builds the entity table (avatars from Base/CellPlayer-
// Create 0x0/0x1, rest from EntityCreate 0x5) and decodes every
// EntityMethod call exactly. Unknown types or signatures are errors.
func DecodeAll(clientVer string, pkts []Packet) (EntityTable, []TimedCall, error) {
	tab := buildEntityTable(pkts)
	var out []TimedCall
	for _, p := range pkts {
		if p.Type != 0x8 {
			continue
		}
		if len(p.Data) < 4 {
			return tab, out, fmt.Errorf("wotreplay: short method packet")
		}
		eid := binary.LittleEndian.Uint32(p.Data[0:4])
		ty, ok := tab.Resolve(eid)
		if !ok {
			return tab, out, fmt.Errorf("wotreplay: method target %d unknown", eid)
		}
		c, err := DecodeCall(clientVer, ty, p.Data)
		if err != nil {
			return tab, out, fmt.Errorf("wotreplay: t=%.2f eid=%d: %w", p.Time, eid, err)
		}
		out = append(out, TimedCall{p.Time, c})
	}
	return tab, out, nil
}
