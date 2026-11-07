package login

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/LockBlock-dev/wot/entdef"
)

// NRL (network replication layer) framing.
//
// Dynamic components do not ride the entity stream. `CreateBasePlayer` carries
// only a COUNT of them — `PyEntity::initComponentsFromStream` checks that
// count against the entity description and then reads each component's data
// from the stream, but the component objects themselves are created by the NRL
// node tree. That is why `AvatarVehiclesInfo` cannot be delivered inside the
// Avatar: the count is satisfied and the component still does not exist.
//
// A message is `[msg_type u8][node_id u16 BE][body]`. The element id implies
// message type 0 for the FIRST message, so its type byte is absent; every
// later message in the same element carries its own.
//
// CreateNode's body is `[parent_id u16 BE][node_type u8][node payload]`.

const (
	// elNrlCreateNode is ClientInterface element 0x21, NRL_CREATE_NODE (VAR 2).
	elNrlCreateNode byte = 0x21

	// nrlRootNode is the root every entity node hangs under. The client has
	// it from the start, so it is never created.
	nrlRootNode uint16 = 1
	// nrlFirstNode is the first node id a space may hand out.
	nrlFirstNode uint16 = 2

	// ClientNode type bytes.
	nrlNodeRoot         byte = 0
	nrlNodeEntity       byte = 1
	nrlNodeDynComponent byte = 2
)

// EncodeNrlIdList writes a node-id list the way the client's `readIdList`
// reads it: signed bytes relative to a running id that starts at the owning
// node's id, so consecutive siblings cost one byte each.
//
//	1..=127    advance the running id by that much, emit it
//	0x80       the next two bytes are an absolute id, big-endian
//	0x81       emit the explicit null id, 0
//	0x82       end of list, then ceil(count/8) presence-bitmask bytes
//	-125..=-1  a run of byte+126 consecutive ids
//	0          end of list, no bitmask
//
// present is nil when every id is present, which is the encoding's own
// "no bitmask" form.
func EncodeNrlIdList(base uint32, ids []uint32, present []bool) []byte {
	var buf bytes.Buffer
	run := base
	for _, id := range ids {
		delta := int64(id) - int64(run)
		if delta >= 1 && delta <= 127 {
			buf.WriteByte(byte(delta))
		} else {
			buf.WriteByte(0x80)
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(id))
			buf.Write(b[:])
		}
		run = id
	}
	if present == nil {
		buf.WriteByte(0)
		return buf.Bytes()
	}
	buf.WriteByte(0x82)
	mask := make([]byte, (len(ids)+7)/8)
	for i, p := range present {
		if p {
			mask[i/8] |= 1 << (i % 8)
		}
	}
	buf.Write(mask)
	return buf.Bytes()
}

// EncodeNrlCreateEntityNode writes the message that creates an entity's NRL
// node under the root. It is the first message of an element, so its type byte
// is implied and absent.
func EncodeNrlCreateEntityNode(node uint16, entityID uint32) []byte {
	var buf bytes.Buffer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	buf.Write(b[:])
	binary.BigEndian.PutUint16(b[:], nrlRootNode)
	buf.Write(b[:])
	buf.WriteByte(nrlNodeEntity)
	var e [4]byte
	binary.LittleEndian.PutUint32(e[:], entityID)
	buf.Write(e[:])
	return buf.Bytes()
}

// EncodeNrlCreateComponent writes the message that attaches a dynamic
// component to an entity's node.
//
// children are the node ids created alongside the component: one per property
// in table order, then one per client method, then one trailing child. Only
// the children marked present in `present` carry anything, and `data` is their
// values in that order — a property its value, a method child its packed
// method index, the trailing child nothing.
func EncodeNrlCreateComponent(node, parent, componentTypeID uint16, name string, children []uint32, present []bool, data []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0) // msg_type 0: CreateNode
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	buf.Write(b[:])
	binary.BigEndian.PutUint16(b[:], parent)
	buf.Write(b[:])
	buf.WriteByte(nrlNodeDynComponent)
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], componentTypeID)
	buf.Write(t[:])
	writePackedLen(&buf, len(name))
	buf.WriteString(name)
	buf.Write(EncodeNrlIdList(uint32(node), children, present))
	buf.Write(data)
	return buf.Bytes()
}

// nrlNodeAlloc hands out NRL node ids for one arena entry. The root is 1 and
// the first id a space may hand out is 2; every entity node, component node and
// component child takes one.
type nrlNodeAlloc struct{ next uint16 }

func newNrlNodeAlloc() *nrlNodeAlloc { return &nrlNodeAlloc{next: nrlFirstNode} }

// take reserves n consecutive ids and returns the first.
func (a *nrlNodeAlloc) take(n int) uint16 {
	first := a.next
	a.next += uint16(n)
	return first
}

// nrlProp is one property of a dynamic component: its name and the alias type
// it is encoded as.
type nrlProp struct {
	Name string
	Type string
}

// EncodeNrlAttachComponent builds the element that creates an entity's NRL node
// and attaches one dynamic component to it, with every property at its zero
// value.
//
// The component's children are one per property in table order, then one per
// client method, then the trailing child every component has. All of them are
// present, so the data is one value per property, then one packed method index
// per client method, then nothing for the trailing child.
//
// The method children are not optional padding: the client maps a child's
// position in the list onto the component's own tables, so a list that stops
// after the properties makes the client read the trailing child as client
// method 0 and then run out of children for the rest. `OwnVehicle` declares 23
// properties and 11 client methods, so it takes 35 children, not 24.
//
// The index a method child carries is the method's exposed id, and the client
// resolves it against its own table — so emitting 0..methods-1 covers every
// method exactly once whatever order the def lists them in.
func EncodeNrlAttachComponent(alloc *nrlNodeAlloc, entityID uint32, nrlID uint16, props []nrlProp, methods int, overrides map[string]entdef.Value) ([]byte, error) {
	app, _, err := EncodeNrlAttachComponentAt(alloc, entityID, nrlID, props, methods, overrides)
	return app, err
}

// EncodeNrlAttachComponentAt is EncodeNrlAttachComponent, also returning the
// component's place in the node tree so its properties and methods can be
// updated later through the `0x26`/`0x25` stream.
func EncodeNrlAttachComponentAt(alloc *nrlNodeAlloc, entityID uint32, nrlID uint16, props []nrlProp, methods int, overrides map[string]entdef.Value) ([]byte, nrlComponent, error) {
	entityNode := alloc.take(1)
	compNode := alloc.take(1)
	children := make([]uint32, 0, len(props)+methods+1)
	present := make([]bool, 0, len(props)+methods+1)
	c := entdef.NewCodec()
	var data bytes.Buffer
	for _, p := range props {
		dt := entdef.Alias(p.Type)
		if dt == nil {
			return nil, nrlComponent{}, fmt.Errorf("nrl: component %d: no alias type %q for property %q", nrlID, p.Type, p.Name)
		}
		children = append(children, uint32(alloc.take(1)))
		present = append(present, true)
		v, ok := overrides[p.Name]
		if !ok {
			v = entdef.ZeroValue(dt)
		}
		if err := c.Write(&data, dt, v); err != nil {
			return nil, nrlComponent{}, fmt.Errorf("nrl: component %d: property %q: %w", nrlID, p.Name, err)
		}
	}
	for i := 0; i < methods; i++ {
		children = append(children, uint32(alloc.take(1)))
		present = append(present, true)
		writePackedU24(&data, uint32(i))
	}
	children = append(children, uint32(alloc.take(1)))
	present = append(present, true)

	msg := EncodeNrlCreateEntityNode(entityNode, entityID)
	msg = append(msg, EncodeNrlCreateComponent(compNode, entityNode, nrlID, "", children, present, data.Bytes())...)
	out, err := element(elNrlCreateNode, msg)
	if err != nil {
		return nil, nrlComponent{}, err
	}
	return out, nrlComponent{
		TypeID:     nrlID,
		Node:       compNode,
		FirstChild: uint16(children[0]),
		Props:      len(props),
		Methods:    methods,
	}, nil
}

// writePackedU24 writes a method index the way the NRL child data carries it:
// one byte below 255, otherwise 0xFF and then three bytes little-endian.
func writePackedU24(buf *bytes.Buffer, n uint32) {
	if n >= 255 {
		buf.WriteByte(0xFF)
		var b [3]byte
		b[0], b[1], b[2] = byte(n), byte(n>>8), byte(n>>16)
		buf.Write(b[:])
		return
	}
	buf.WriteByte(byte(n))
}

// The NRL "unreliable" node message: element 0x28,
// `NRL_UNRELIABLE_MSG_TO_CLIENT` (VAR 2). It is how the server tells the client
// where its gun is pointing, and it is the ONLY thing the captured server sends
// for the gun — it sends no `gunAnglesPacked` property update at all.
//
// The body is `[06 00 01][id_a u32][id_b u32][tick u32][prev_tick u32]
// [kind u8][d6 c3 c4 00 00 01][flags u8][00][payload_len u8][payload]`, all
// little-endian. Every constant below was read off
// `captures/proxy-20261031-1358.hex` and is the same in all five battle flows
// of that capture:
//
//   - the `06 00 01` header is message type 6 on node 1, the NRL root;
//   - the class tag `d6 c3 c4 00 00 01` never varied;
//   - `flags` is 0x20 on every message but the first of a battle, which has 0
//     and `prev_tick` 0 — bit 0x20 says `prev_tick` holds real data;
//   - `tick` is a 10 Hz counter, and `0x13` TickSync's byte is its low byte
//     (1126474 & 0xFF = 74, and the capture's `0x13` byte at that instant is
//     74). `prev_tick` trails it by one.
//
// `id_a`/`id_b` are constant within a battle and DIFFER between battles (five
// flows, five different pairs), so they are per-arena, not protocol constants.
// They are minted per arena from the arena's own identity; see
// `arenaNrlIds`.
const (
	elNrlUnreliableMsg byte = 0x28

	// nrlUnrelClassTag is the six bytes between `kind` and `flags`.
	nrlUnrelClassTag = "\xd6\xc3\xc4\x00\x00\x01"
	// nrlUnrelFlagsPrev is the `flags` byte: `prev_tick` holds real data.
	nrlUnrelFlagsPrev byte = 0x20

	// nrlUnrelKindGunMarker is the payload kind carrying the gun marker.
	nrlUnrelKindGunMarker byte = 0x30
	// nrlUnrelKindUnchanged is the payload kind meaning "no new marker this
	// tick". Its 8-byte payload never varied across the capture.
	nrlUnrelKindUnchanged byte = 0x11
	// nrlUnrelUnchangedPayload is that payload, verbatim.
	nrlUnrelUnchangedPayload = "\x20\x00\x00\x02\x01\x73\x20\x00"

	// nrlGunMarkerPrefix and nrlGunMarkerSuffix bracket the gun marker's
	// floats. Both are constant across every battle in the capture.
	nrlGunMarkerPrefix = "\x20\x00\x20\x02\x00\x83\x82\x01\x01"
	nrlGunMarkerSuffix = "\x01\x20"
)

// nrlGunMarker is the server's view of the player's gun: where it fires from,
// the shell's initial velocity, and the current dispersion angle. It is what
// the client's `Avatar.updateGunMarker(vehicleID, shotPos, shotVec,
// dispersionAngle)` receives, and `VehicleGunRotator.setShotPosition` draws the
// crosshair from it.
type nrlGunMarker struct {
	Position   [3]float32
	Velocity   [3]float32
	Dispersion float32
}

// EncodeNrlUnreliableGunMarker builds element 0x28 carrying a full gun marker.
//
// first says this is the battle's first marker: the captured server sends
// `prev_tick` 0 and `flags` 0 for it, and `tick-1` with `flags` 0x20 for every
// later one. It is NOT "tick == 0" — the capture's first marker carries tick
// 1126468, the counter having run since the server started.
func EncodeNrlUnreliableGunMarker(idA, idB, tick uint32, first bool, m nrlGunMarker) ([]byte, error) {
	payload := make([]byte, 0, len(nrlGunMarkerPrefix)+28+len(nrlGunMarkerSuffix))
	payload = append(payload, nrlGunMarkerPrefix...)
	payload = appendVec3(payload, m.Position)
	payload = appendVec3(payload, m.Velocity)
	payload = appendF32(payload, m.Dispersion)
	payload = append(payload, nrlGunMarkerSuffix...)
	return encodeNrlUnreliable(idA, idB, tick, first, nrlUnrelKindGunMarker, payload)
}

// EncodeNrlUnreliableUnchanged builds element 0x28 saying the gun marker has
// not moved since the last one. The captured server sends this instead of a
// full marker when nothing changed — 408 of 7591 ticks over one battle, in runs
// that reach 101 ticks (the pre-battle countdown).
func EncodeNrlUnreliableUnchanged(idA, idB, tick uint32, first bool) ([]byte, error) {
	return encodeNrlUnreliable(idA, idB, tick, first, nrlUnrelKindUnchanged, []byte(nrlUnrelUnchangedPayload))
}

// encodeNrlUnreliable frames one 0x28 body around a payload.
func encodeNrlUnreliable(idA, idB, tick uint32, first bool, kind byte, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte{0x06, 0x00, 0x01})
	// The first message of a battle has no previous tick to point at.
	prev, flags := tick-1, nrlUnrelFlagsPrev
	if first {
		prev, flags = 0, 0
	}
	var b [4]byte
	for _, v := range []uint32{idA, idB, tick, prev} {
		binary.LittleEndian.PutUint32(b[:], v)
		buf.Write(b[:])
	}
	buf.WriteByte(kind)
	buf.WriteString(nrlUnrelClassTag)
	buf.WriteByte(flags)
	buf.WriteByte(0x00)
	buf.WriteByte(byte(len(payload)))
	buf.Write(payload)
	return element(elNrlUnreliableMsg, buf.Bytes())
}

// appendVec3 and appendF32 write the little-endian floats the gun marker
// carries.
func appendVec3(dst []byte, v [3]float32) []byte {
	for _, f := range v {
		dst = appendF32(dst, f)
	}
	return dst
}

func appendF32(dst []byte, f float32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(f))
	return append(dst, b[:]...)
}

// gunMarkerFor builds the server's gun marker for one tick.
//
// The position is the gun's pivot: the hull's origin, `GunHeight` up. The
// captured server's marker sits about 2 m above the vehicle and within 2.5 m of
// it, which is what a pivot on the turret roof looks like.
//
// The velocity is the barrel's direction times the shell's muzzle velocity, so
// its length is the shell speed — the capture shows it constant at 792.00 m/s
// for a whole battle, switching only with the shell.
//
// The direction is the turret yaw plus the hull's own yaw, with the gun's
// elevation. `pitch` is positive downward, as `trackTurret` computes it
// (`-atan2(dy, hypot(dx, dz))` from the gun pivot), so the vertical component
// is `-sin(pitch)`.
func gunMarkerFor(h hull, yaw, pitch float64, spec gunSpec, dispFactor float64) nrlGunMarker {
	pos := [3]float32{h.Position[0], h.Position[1] + float32(spec.GunHeight), h.Position[2]}
	world := float64(h.Direction[2]) + yaw
	cp := math.Cos(pitch)
	dir := [3]float64{math.Sin(world) * cp, -math.Sin(pitch), math.Cos(world) * cp}
	speed := spec.Dispersion.ShotSpeed
	return nrlGunMarker{
		Position: pos,
		Velocity: [3]float32{
			float32(dir[0] * speed),
			float32(dir[1] * speed),
			float32(dir[2] * speed),
		},
		Dispersion: float32(spec.Dispersion.Angle * dispFactor),
	}
}

// nrlMarkerElement encodes the tick's `0x28`: the full gun marker when it moved
// since the last one, the 8-byte "unchanged" form when it did not.
func nrlMarkerElement(idA, idB, tick uint32, m, last nrlGunMarker, haveLast bool) ([]byte, error) {
	if haveLast && m == last {
		return EncodeNrlUnreliableUnchanged(idA, idB, tick, false)
	}
	return EncodeNrlUnreliableGunMarker(idA, idB, tick, !haveLast, m)
}

// stepDispersion advances the dispersion factor by dt seconds, on the client's
// own model (`Avatar.getOwnVehicleShotDispersionAngle`):
//
//	ideal = sqrt(1 + (speed*movement)^2 + (yawRate*rotation)^2
//	               + (turretRate*turretRotation)^2)
//	factor = max(ideal, ideal + (factor-ideal)*exp(-dt/aimingTime))
//
// The `max` is the client's own `if aimingFactor < idealFactor` branch: the
// factor snaps UP to the ideal immediately and only decays back down over the
// gun's aiming time. The capture agrees — 0.00365 at rest, 0.01185 while
// driving, back to 0.00367 once stopped.
func stepDispersion(factor float64, h hull, turretRate float64, d dispersionSpec, dt float64) float64 {
	if factor <= 0 {
		factor = 1
	}
	move := float64(h.Speed) * d.Movement
	rot := float64(h.YawRate) * d.Rotation
	turret := turretRate * d.TurretRotation
	ideal := math.Sqrt(1 + move*move + rot*rot + turret*turret)
	if ideal >= factor {
		return ideal
	}
	if d.AimingTime <= 0 {
		return ideal
	}
	return ideal + (factor-ideal)*math.Exp(-dt/d.AimingTime)
}

// arenaNrlIds mints the two per-arena ids the NRL gun marker carries.
//
// They are constant within a battle and differ between battles — five flows of
// the Oct-31 capture give five different pairs — so they are per-arena, not
// protocol constants. What the server derives them FROM is not known: they
// appear nowhere else in the stream, so they cannot be matched against the
// space id, the entity id or the arena id. They are minted here from the arena
// id so that they are stable for a battle and distinct between battles, which
// is the only property the capture establishes.
func arenaNrlIds(arenaID uint64) (uint32, uint32) {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := func(seed uint64) uint32 {
		v := offset64 ^ seed
		for i := 0; i < 8; i++ {
			v ^= (arenaID >> (8 * i)) & 0xFF
			v *= prime64
		}
		return uint32(v>>32) ^ uint32(v)
	}
	return h(0x9E3779B97F4A7C15), h(0xC2B2AE3D27D4EB4F)
}

// The NRL node-update stream.
//
// Component properties do not ride the entity stream. They are updated through
// the NRL node tree: `NrlData` (0x26) carries raw fragments of a byte stream,
// and `NrlUpdateNodeFlag` (0x25) consumes one record from it — `[node_id u16
// big-endian]` plus that node's update. `NrlUnlinkTreeFlag` (0x24) consumes
// just a node id. The self-contained forms `NrlUpdateNode` (0x23) and
// `NrlUnlinkTree` (0x22) carry the same bodies inline.
//
// A record's body depends on what the node is, which was said when it was
// created:
//
//	volatile property   the whole value, nothing else
//	property            [kind u8][len packed-u24][len bytes]
//	                      kind 0: the whole value
//	                      kind 1: a slice of a list inside it
//	                      kind 2: one value inside it, at a compressed path
//	method child        the method's arguments
//
// The captured server sends 2489 `0x26` fragments, 2152 `0x25` flags and 800
// `0x24` flags over one battle, so this is the normal path for component state.
const (
	elNrlUnlinkTree     byte = 0x22
	elNrlUpdateNode     byte = 0x23
	elNrlUnlinkTreeFlag byte = 0x24
	elNrlUpdateNodeFlag byte = 0x25
	elNrlData           byte = 0x26
)

// EncodeNrlData writes one fragment of the node-update stream. Fragments are
// concatenated by the client into one buffer; records straddle them freely, so
// a caller may split anywhere.
func EncodeNrlData(fragment []byte) ([]byte, error) {
	return element(elNrlData, fragment)
}

// EncodeNrlUpdateNodeFlag writes the payload-less element that consumes one
// record from the reassembled buffer.
func EncodeNrlUpdateNodeFlag() []byte { return []byte{elNrlUpdateNodeFlag} }

// EncodeNrlUnlinkTreeFlag writes the payload-less element that consumes one
// node id from the reassembled buffer and unlinks that node's subtree.
func EncodeNrlUnlinkTreeFlag() []byte { return []byte{elNrlUnlinkTreeFlag} }

// EncodeNrlUpdateNode writes a node update inline: `[node_id u16 BE][body]`.
func EncodeNrlUpdateNode(node uint16, body []byte) ([]byte, error) {
	var buf bytes.Buffer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	buf.Write(b[:])
	buf.Write(body)
	return element(elNrlUpdateNode, buf.Bytes())
}

// EncodeNrlUnlinkTree writes an inline unlink: `[node_id u16 BE]`.
func EncodeNrlUnlinkTree(node uint16) ([]byte, error) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	return element(elNrlUnlinkTree, b[:])
}

// nrlPropertyRecord builds the body of a whole-value property update: the
// `kind 0` form, `[0][len packed-u24][value]`.
func nrlPropertyRecord(value []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0)
	writePackedU24(&buf, uint32(len(value)))
	buf.Write(value)
	return buf.Bytes()
}

// nrlVolatileRecord is a volatile property's update: the value alone.
func nrlVolatileRecord(value []byte) []byte { return value }

// nrlMethodRecord is a method child's update: its arguments, already encoded.
func nrlMethodRecord(args []byte) []byte { return args }

// nrlComponent is one dynamic component as the node tree holds it: the node
// that carries it, the node of its first property child, and how many property
// children it has. Property i's node is FirstChild+i, because
// `EncodeNrlAttachComponent` allocates the children in table order.
type nrlComponent struct {
	TypeID     uint16
	Node       uint16
	FirstChild uint16
	Props      int
	Methods    int
}

// propertyNode is the node id of one property child.
func (c nrlComponent) propertyNode(index int) (uint16, bool) {
	if index < 0 || index >= c.Props {
		return 0, false
	}
	return c.FirstChild + uint16(index), true
}

// methodNode is the node id of one client-method child.
func (c nrlComponent) methodNode(index int) (uint16, bool) {
	if index < 0 || index >= c.Methods {
		return 0, false
	}
	return c.FirstChild + uint16(c.Props) + uint16(index), true
}

// EncodeNrlPropertyUpdate writes one component property's whole value as the
// `0x26` fragment plus the `0x25` flag that consumes it.
func EncodeNrlPropertyUpdate(c nrlComponent, index int, value []byte) ([]byte, error) {
	node, ok := c.propertyNode(index)
	if !ok {
		return nil, fmt.Errorf("nrl: component %d has no property %d", c.TypeID, index)
	}
	var buf bytes.Buffer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	buf.Write(b[:])
	buf.Write(nrlPropertyRecord(value))
	out, err := EncodeNrlData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return append(out, EncodeNrlUpdateNodeFlag()...), nil
}

// EncodeNrlMethodCall writes one component client-method call as the `0x26`
// fragment plus the `0x25` flag that consumes it.
func EncodeNrlMethodCall(c nrlComponent, index int, args []byte) ([]byte, error) {
	node, ok := c.methodNode(index)
	if !ok {
		return nil, fmt.Errorf("nrl: component %d has no client method %d", c.TypeID, index)
	}
	var buf bytes.Buffer
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], node)
	buf.Write(b[:])
	buf.Write(nrlMethodRecord(args))
	out, err := EncodeNrlData(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return append(out, EncodeNrlUpdateNodeFlag()...), nil
}
