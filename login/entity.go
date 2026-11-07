package login

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/LockBlock-dev/wot/entdef"
)

// Client-side element ids (BigWorld's client element table, WoT fork).
// The two ranges are what make the entity layer possible without a table
// per method: a client method call is ENTITY_METHOD_BASE + method id, and
// a property update is ENTITY_PROPERTY_BASE + property index.
const (
	elResetEntities    = 0x04 // FIXED 1 (bool keepPlayerOnBase)
	elCreateBasePlayer = 0x05 // VAR 2
	elCreateCellPlayer = 0x06 // VAR 2
	// elSpaceData is `spaceProperty` in the WoT fork's ClientInterface
	// table: `authenticate` occupies 0, so the entries after `createCellPlayer`
	// shift by one and 0x07 is `dummyPacket`. Writing the geometry mapping
	// on 0x07 is silently ignored, which leaves the battle space with no
	// terrain.
	elSpaceData = 0x08 // VAR 2
	// The rest of the WoT fork's ClientInterface table, cross-checked
	// against the client's own registered message names (the string table
	// at 0x143bc3298 in WorldOfTanks.exe) and the reference toolkit's
	// element ids. A non-player entity is created with
	// createEntityDetailed, brought into the client's AoI with enterAoI,
	// and then given its cell properties with updateEntity.
	elAddSpaceGeometryMapping = 0x09 // VAR 2
	elCreateEntity            = 0x0B // VAR 2
	elCreateEntityDetailed    = 0x0C // VAR 2
	elEnterAoI                = 0x10 // FIXED 5 (entityID u32, alias u8)
	elEnterAoIOnVehicle       = 0x11 // FIXED 9
	elLeaveAoI                = 0x12 // VAR 2
	elSetVehicle              = 0x17 // FIXED 8
	elSelectEntity            = 0x19 // FIXED 4
	elUpdateEntity            = 0x4B
	// elAvatarUpdateTargetingInfo is Avatar.updateTargetingInfo: nine FLOAT32,
	// fixed. The client's Python takes the entity id plus ten floats, so this
	// element cannot reach it — the gun is driven through the `OwnVehicle`
	// component's `targetingInfo` property, whose setter calls the method with
	// the id. Sending 44 bytes here leaves eight to be read as the next
	// element id and the client drops the packet.
	elAvatarUpdateTargetingInfo = 0x72 // FIXED 36 (nine FLOAT32)
	elTickSync                  = 0x13 // FIXED 1
	elSelectPlayerEntity        = 0x1A // FIXED 0
	elEnableEntities            = 0x0B // FIXED 0
	elRequestEntityUpdate       = 0x06 // VAR 2 (client -> server)
	elNrlMsgToCell              = 0x07 // VAR 2 (client -> server)

	entityMethodBase   = 0x4E // 0x4E..0xA6
	entityPropertyBase = 0xA7 // 0xA7..0xFE
)

// Entity is one live entity: its id, its type from the defs, and its
// property values.
//
// The values are keyed by the defs' property names, so a caller sets
// `name` or `incarnationID` and the encoder writes them in the defs'
// wire order with the defs' types — no hand-built byte layout.
type Entity struct {
	ID    uint32
	Type  *entdef.EntityDispatch
	Props map[string]entdef.Value
}

// NewEntity returns an entity of the given type with no properties set.
func NewEntity(id uint32, typ *entdef.EntityDispatch) *Entity {
	return &Entity{ID: id, Type: typ, Props: make(map[string]entdef.Value)}
}

// Set stores a property value.
func (e *Entity) Set(name string, v entdef.Value) *Entity {
	e.Props[name] = v
	return e
}

// SetInt stores an integer property.
func (e *Entity) SetInt(name string, v int64) *Entity {
	return e.Set(name, entdef.Value{Kind: entdef.VInt, Int: v})
}

// SetUint stores an unsigned property.
func (e *Entity) SetUint(name string, v uint64) *Entity {
	return e.Set(name, entdef.Value{Kind: entdef.VUint, Uint: v})
}

// SetString stores a string property.
func (e *Entity) SetString(name string, v string) *Entity {
	return e.Set(name, entdef.Value{Kind: entdef.VString, Str: v})
}

// encodeProps writes the named properties in the defs' wire order.
func (e *Entity) encodeProps(props []entdef.PropertyDef, only map[string]bool) ([]byte, error) {
	c := entdef.NewCodec()
	var buf bytes.Buffer
	for _, p := range props {
		if only != nil && !only[p.Name] {
			continue
		}
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		if err := c.Write(&buf, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return buf.Bytes(), nil
}

// EncodeCreateBasePlayer builds the CreateBasePlayer element: the entity
// id, its type id, an empty unknown blob, the entity's base-hosted
// client-visible properties in wire order, and the dynamic-component
// count.
//
// The component count is written as zero: WoT's static components fold
// into the entity's own tables, and the dynamic ones replicate over NRL
// rather than here.
func EncodeCreateBasePlayer(e *Entity) ([]byte, error) {
	return EncodeCreateBasePlayerWithComponents(e, 0)
}

// EncodeCreateBasePlayerWithComponents is EncodeCreateBasePlayer with an
// explicit dynamic-component count.
//
// The count is not zero in practice — the reference's capture shows 19 for
// Account — but no component data follows it: the element ends right after
// the byte. The components themselves replicate over NRL, not here.
func EncodeCreateBasePlayerWithComponents(e *Entity, components uint8) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: CreateBasePlayer: no entity type")
	}
	data, err := e.encodeProps(e.Type.BaseProps, nil)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], e.ID)
	body.Write(tmp[:])
	binary.LittleEndian.PutUint16(tmp[:2], uint16(e.Type.TypeID))
	body.Write(tmp[:2])
	body.WriteByte(0) // the unknown blob, empty in every capture
	body.Write(data)
	body.WriteByte(components)
	return element(elCreateBasePlayer, body.Bytes())
}

// EncodeCreateCellPlayer builds the CreateCellPlayer element: the space the
// player is entering, the vehicle it rides, its position and direction, and
// the entity's cell-to-client properties in wire order.
//
// Wire (BigWorld `ServerConnection::createCellPlayer`, which reads
// `spaceID >> vehicleID >> pos >> packedXZScale >> dir` and then hands the
// rest to `EntityDescription::readStreamToDict(FROM_CELL_TO_CLIENT_DATA)`):
//
//	[06][u16 len][u8][spaceID u32][u16][vehicleID u32][pos 3×f32]
//	[xzScale f32][dir 3×f32][cell props, no count]
//
// The property section has NO count prefix: the client walks the entity
// description and takes every property in the cell-to-client domain, so
// the server must write exactly those, in that order. `Entity.CellProps`
// is that list.
//
// The element is what makes the client leave the battle-loading screen: it
// creates the player entity in the space, and the engine calls
// `Avatar.onEnterWorld` once the space is loaded.
func EncodeCreateCellPlayer(e *Entity, spaceID, vehicleID uint32, pos [3]float32, xzScale float32, dir [3]float32, components uint8) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: CreateCellPlayer: no entity type")
	}
	if xzScale <= 0 {
		// The client asserts `packedXZScale_ > 0.f`.
		return nil, fmt.Errorf("wotlogin: CreateCellPlayer: xzScale must be positive")
	}
	data, err := e.encodeProps(e.Type.CellProps, nil)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	var tmp [4]byte
	// The WoT fork's `ServerConnection::createCellPlayer` (2.4.1.0
	// `sub_142CF7C20`) reads, in order: one byte, the space id, a u16, the
	// vehicle id, the position, the packed XZ scale, the direction, then
	// the cell properties. Stock BigWorld has neither the leading byte nor
	// the u16, and writing the stock shape shifts the space id by one byte
	// — the client then reads it as 0 and dies on
	// "Somebody tried to create space with NULL Space ID 0".
	body.WriteByte(0)
	binary.LittleEndian.PutUint32(tmp[:], spaceID)
	body.Write(tmp[:])
	var half [2]byte
	binary.LittleEndian.PutUint16(half[:], 0)
	body.Write(half[:])
	binary.LittleEndian.PutUint32(tmp[:], vehicleID)
	body.Write(tmp[:])
	for _, f := range pos {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(xzScale))
	body.Write(tmp[:])
	for _, f := range dir {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	body.Write(data)
	// The cell data ends with the entity's static-component count, then the
	// components' own data. Leaving the byte out makes the element one byte
	// short of what the client reads, and the handler drops it without a
	// word — which is why `createBasePlayer` was processed and
	// `createCellPlayer` never was.
	body.WriteByte(components)
	return element(elCreateCellPlayer, body.Bytes())
}

// SpaceDataMappingKey is SPACE_DATA_MAPPING_KEY_CLIENT_SERVER
// (`common/space_data_types.hpp`): the space-data key that maps geometry
// into a space. The value is a `SpaceData_MappingData` (a 4×4 float matrix)
// followed by the geometry path.
const SpaceDataMappingKey uint16 = 1

// EncodeSpaceData builds the spaceData element: one keyed entry in a
// space's data table.
//
// Wire (`ServerConnection::spaceData`, which reads
// `spaceID >> spaceEntryID >> key` and takes the rest as the value):
//
//	[07][u16 len][spaceID u32][entryID: ip u32, port u16, salt u16]
//	[key u16][value…]
//
// The entry id is a Mercury address (8 bytes), not a counter: the client
// keys its space-data map by it, so the same entry id must be reused to
// replace an entry.
func EncodeSpaceData(spaceID uint32, entryID [8]byte, key uint16, value []byte) ([]byte, error) {
	var body bytes.Buffer
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], spaceID)
	body.Write(tmp[:])
	body.Write(entryID[:])
	var k [2]byte
	binary.LittleEndian.PutUint16(k[:], key)
	body.Write(k[:])
	body.Write(value)
	return element(elSpaceData, body.Bytes())
}

// EncodeGeometryMapping builds the spaceData value that maps geometry into
// a space: an identity 4×4 matrix followed by the geometry path.
//
// `EntityManager::onGeometryMapping` matches the entry by comparing the
// matrix AND the trailing path, so both have to be exactly what the client
// expects: the matrix is the mapping's transform (identity for a battle
// map) and the path is the resource path, `spaces/<map>`.
func EncodeGeometryMapping(path string) []byte {
	out := make([]byte, 0, 16*4+len(path))
	// Identity, row-major, as the engine's Matrix stores it.
	identity := [16]float32{1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}
	var tmp [4]byte
	for _, f := range identity {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		out = append(out, tmp[:]...)
	}
	return append(out, path...)
}

// EncodeClientMethodCall builds a client method call element: the method's
// exposed id plus the base, then its arguments encoded from the defs.
func EncodeClientMethodCall(e *Entity, method string, args []entdef.Value) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: method call: no entity type")
	}
	id := -1
	for i := range e.Type.ClientMethods {
		if e.Type.ClientMethods[i].Name == method {
			id = i
			break
		}
	}
	if id < 0 {
		return nil, fmt.Errorf("wotlogin: %s has no client method %q", e.Type.Name, method)
	}
	m := &e.Type.ClientMethods[id]
	var buf bytes.Buffer
	if err := m.WriteArgs(&buf, args); err != nil {
		return nil, err
	}
	// The element length is as wide as the method's
	// VariableLengthHeaderSize — one byte for `update`, two for `showGUI`.
	// Writing a fixed u16 where the client reads a u8 shifts every
	// following field by one: the client takes the length's high byte as
	// the string length, decodes an empty argument, then walks the rest of
	// the bundle as elements and dies on
	// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
	// A FIXED-size method carries NO length field: the client knows the
	// size from the defs and reads exactly that many bytes after the id.
	// Writing one anyway leaves the length bytes on the stream, where the
	// client reads them as the next message id — `00` is `authenticate`,
	// and the bundle dies with "Not enough data on stream ... needed 4"
	// and "Got corrupted message header".
	if m.Length.Fixed {
		out := make([]byte, 0, 1+len(buf.Bytes()))
		out = append(out, byte(entityMethodBase+id))
		return append(out, buf.Bytes()...), nil
	}
	width := int(m.Length.Var)
	if width <= 0 {
		width = 1
	}
	return appendElement(nil, byte(entityMethodBase+id), width, buf.Bytes())
}

// EncodePropertyUpdate builds a STANDALONE property element: the property's
// client-server FullIndex plus the base, then its value encoded from the defs.
//
// The framing is the property's own declared element length, which is what the
// client's table carries:
//
//   - a FIXED-size property (`health`, INT16) is `[id][value]` with no length
//     field at all — the client reads exactly the type's size;
//   - a variable one (`damageStickers`, an ARRAY alias) is
//     `[id][len][value]` with the length header's width being the property's
//     `VariableLengthHeaderSize`, which is ONE for an ARRAY alias.
//
// Writing a u16 length where the client reads a u8 shifts every following
// element by one byte: the client walks the rest of the bundle as garbage and
// dies on `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_` (after first
// dropping a bundle as REASON_CORRUPTED_PACKET). That is the shell-hole
// update, so it crashed on the first PIERCED hit and not on a bounce.
//
// The id is the FullIndex: `EntityDispatch.Properties` is filled from
// `CSPropsOrdered()` (fixed sizes first, then variable by header width), so
// the position in that table is the index the client's `updateEntity` run
// addresses, not the property's position in the entity def.
func EncodePropertyUpdate(e *Entity, name string) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: property update: no entity type")
	}
	idx := -1
	for i := range e.Type.Properties {
		if e.Type.Properties[i].Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("wotlogin: %s has no client property %q", e.Type.Name, name)
	}
	p := &e.Type.Properties[idx]
	v, ok := e.Props[name]
	if !ok {
		return nil, fmt.Errorf("wotlogin: %s: property %q has no value", e.Type.Name, name)
	}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, p.Type, v); err != nil {
		return nil, fmt.Errorf("wotlogin: %s.%s: %w", e.Type.Name, name, err)
	}
	id := byte(entityPropertyBase + idx)
	if p.Length.Fixed {
		return append([]byte{id}, buf.Bytes()...), nil
	}
	width := p.Length.Var
	if width <= 0 {
		width = 1
	}
	return appendElement(nil, id, width, buf.Bytes())
}

// EncodeSelectPlayerEntity builds the SelectPlayerEntity element: FIXED 0,
// no payload. It tells the client which entity is its player, and follows
// CreateBasePlayer.
func EncodeSelectPlayerEntity() []byte {
	return []byte{elSelectPlayerEntity}
}

// EncodeTickSync builds a TICK_SYNC element, the one-byte message head the
// post-flood chain uses.
func EncodeTickSync(tag byte) []byte {
	return []byte{elTickSync, tag}
}

// elUpdateFrequency is `UPDATE_FREQUENCY_NOTIFICATION`: FIXED 7, the server
// telling the client how often it will send updates, plus the server game time.
const elUpdateFrequency = 0x02

// EncodeUpdateFrequency builds the `UPDATE_FREQUENCY_NOTIFICATION` element.
//
// Its own doc comment in the reference is "the server informs us how frequently
// it is going to send updates to the client, and also gives the server game
// time" — the one element in the protocol whose whole purpose is to tell the
// client the tick rate, which is the number it needs to interpolate between
// ticks. The real server sends it; this one did not.
func EncodeUpdateFrequency(frequency uint8, unknown uint16, gameTime uint32) []byte {
	b := []byte{elUpdateFrequency, frequency, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[2:4], unknown)
	binary.LittleEndian.PutUint32(b[4:8], gameTime)
	return b
}

// element frames a payload as [id][len u16 LE][payload].
func element(id byte, payload []byte) ([]byte, error) {
	if len(payload) > 0xFFFF {
		return elementOversize(id, payload)
	}
	out := make([]byte, 0, 3+len(payload))
	out = append(out, id)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...), nil
}

// elementOversize writes an element whose payload does not fit its
// 2-byte length field, using the engine's "special" length form
// (InterfaceElement::specialCompressLength, interface_element.cpp): the
// length field is filled with 0xFF, the real length goes in a u32 at the
// start of the body, and the four bytes it displaces are appended to the
// end of the element.
//
// The client reads it back in specialExpandLength: it sees the all-ones
// length, takes the u32 as the body length (counted from the u32 itself),
// and copies the element's last four bytes over the u32 before decoding.
// The element therefore occupies 1 + 2 + len(payload) + 4 bytes, and the
// iterator's advance (dataOffset + length + 4) lands exactly on the next
// element.
//
// This is how the flood's createBasePlayer carries the whole lobby
// bundle: its payload is the entity header plus the pickled
// initialServerSettings, ~250 KB.
func elementOversize(id byte, payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("wotlogin: element %#02x payload is %d B, too short for the oversize form", id, len(payload))
	}
	if len(payload) > 0x7FFFFFFF {
		return nil, fmt.Errorf("wotlogin: element %#02x payload is %d B, beyond the u32 length", id, len(payload))
	}
	out := make([]byte, 0, 3+len(payload)+4)
	out = append(out, id, 0xFF, 0xFF)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	out = append(out, payload[4:]...)
	return append(out, payload[:4]...), nil
}

// EntityRegistry allocates entity ids and holds the live entities.
type EntityRegistry struct {
	next     uint32
	byID     map[uint32]*Entity
	byType   map[string][]*Entity
	lastUsed uint32
}

// NewEntityRegistry returns an empty registry. Ids start at 1: zero is
// the "no entity" sentinel on the wire.
func NewEntityRegistry() *EntityRegistry {
	return &EntityRegistry{
		next:   1,
		byID:   make(map[uint32]*Entity),
		byType: make(map[string][]*Entity),
	}
}

// Create mints an entity of the given type.
func (r *EntityRegistry) Create(typ *entdef.EntityDispatch) *Entity {
	for {
		id := r.next
		r.next++
		if _, taken := r.byID[id]; taken {
			continue
		}
		e := NewEntity(id, typ)
		r.byID[id] = e
		r.byType[typ.Name] = append(r.byType[typ.Name], e)
		r.lastUsed = id
		return e
	}
}

// Get returns an entity by id, or nil.
func (r *EntityRegistry) Get(id uint32) *Entity { return r.byID[id] }

// OfType returns every live entity of a type, in creation order.
func (r *EntityRegistry) OfType(name string) []*Entity { return r.byType[name] }

// Destroy removes an entity.
func (r *EntityRegistry) Destroy(id uint32) {
	e, ok := r.byID[id]
	if !ok {
		return
	}
	delete(r.byID, id)
	list := r.byType[e.Type.Name]
	for i := range list {
		if list[i].ID == id {
			r.byType[e.Type.Name] = append(list[:i], list[i+1:]...)
			break
		}
	}
}

// Len reports how many entities are live.
func (r *EntityRegistry) Len() int { return len(r.byID) }

// DecodeCreateBasePlayer reads a CreateBasePlayer element back into an
// entity, resolving the type id against the dispatch. It is the inverse of
// EncodeCreateBasePlayer and exists so a built element can be checked
// against the same defs that produced it.
func DecodeCreateBasePlayer(elem []byte, d *entdef.Dispatch) (*Entity, error) {
	if len(elem) < 3 || elem[0] != elCreateBasePlayer {
		return nil, fmt.Errorf("wotlogin: not a CreateBasePlayer element")
	}
	n := int(binary.LittleEndian.Uint16(elem[1:3]))
	if len(elem) < 3+n {
		return nil, fmt.Errorf("wotlogin: CreateBasePlayer truncated")
	}
	body := elem[3 : 3+n]
	if len(body) < 7 {
		return nil, fmt.Errorf("wotlogin: CreateBasePlayer body too short")
	}
	id := binary.LittleEndian.Uint32(body[0:4])
	typeID := int(binary.LittleEndian.Uint16(body[4:6]))
	off := 6
	// The unknown blob: a 1-byte length then that many bytes.
	blobLen := int(body[off])
	off++
	if off+blobLen > len(body) {
		return nil, fmt.Errorf("wotlogin: CreateBasePlayer unknown blob overruns")
	}
	off += blobLen

	var typ *entdef.EntityDispatch
	for _, name := range d.Entities() {
		if e := d.Entity(name); e != nil && e.TypeID == typeID {
			typ = e
			break
		}
	}
	if typ == nil {
		return nil, fmt.Errorf("wotlogin: no entity type %d in the defs", typeID)
	}

	e := NewEntity(id, typ)
	c := entdef.NewCodec()
	r := bytes.NewReader(body[off:])
	for _, p := range typ.BaseProps {
		v, err := c.Read(r, p.Type)
		if err != nil {
			return nil, fmt.Errorf("wotlogin: %s.%s: %w", typ.Name, p.Name, err)
		}
		e.Props[p.Name] = v
	}
	// One byte of dynamic-component count must remain.
	if r.Len() != 1 {
		return nil, fmt.Errorf("wotlogin: CreateBasePlayer has %d trailing bytes, want 1", r.Len())
	}
	return e, nil
}

// writePackedLen writes BigWorld's packed length: one byte below 0xFE, then
// 0xFE + u16, then 0xFF + u24.
func writePackedLen(buf *bytes.Buffer, n int) {
	switch {
	case n < 0xFE:
		buf.WriteByte(byte(n))
	case n <= 0xFFFF:
		buf.WriteByte(0xFE)
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], uint16(n))
		buf.Write(tmp[:])
	default:
		buf.WriteByte(0xFF)
		buf.Write([]byte{byte(n), byte(n >> 8), byte(n >> 16)})
	}
}

// VolatilePackerType is the only volatile packer type the client accepts.
// `ServerConnection::createEntity` (sub_142CF7F60) compares the string it
// reads against this 10-byte literal and disconnects on any mismatch.
const VolatilePackerType = "bw.default"

// EncodeCreateEntityDetailed builds the element that creates a non-player
// entity. `ServerConnection::createEntity` reads, in order:
//
//	[00]                       compression selector (BW_COMPRESSION_NONE)
//	[entityID u32][typeID u16]
//	[resource name, packed-length string]
//	[u8]                       stored on the entity record
//	[volatile packer type, packed-length string]  must be "bw.default"
//	[position 3×f32]
//	[direction 3×f32]          raw floats in the *Detailed* variant
//	[client properties]
//
// The trailing run is the entity's base-hosted client-visible properties,
// which for a Vehicle is empty — every Vehicle property is cell-side.
func EncodeCreateEntityDetailed(id uint32, typeID uint16, resource string, pos, dir [3]float32, clientData []byte) ([]byte, error) {
	var body bytes.Buffer
	body.WriteByte(0) // BW_COMPRESSION_NONE
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], id)
	body.Write(tmp[:])
	binary.LittleEndian.PutUint16(tmp[:2], typeID)
	body.Write(tmp[:2])
	writePackedLen(&body, len(resource))
	body.WriteString(resource)
	// One byte the client stores on the entity record, then the entity's
	// volatile packer type as a string. The client refuses anything but
	// `bw.default` and drops the connection:
	// "createEntity( <id> ): Disconnecting due to non-default volatile
	// packer type detected". The check is `Size != 10 || memcmp(...)`
	// against the literal at 0x14387F8B0.
	body.WriteByte(0)
	writePackedLen(&body, len(VolatilePackerType))
	body.WriteString(VolatilePackerType)
	for _, f := range pos {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	for _, f := range dir {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	body.Write(clientData)
	return element(elCreateEntityDetailed, body.Bytes())
}

// EncodeEnterAoI builds the element that brings an entity into the client's
// area of interest: `[entityID u32][idAlias u8]`, five bytes, no length.
func EncodeEnterAoI(id uint32, alias uint8) ([]byte, error) {
	var body [5]byte
	binary.LittleEndian.PutUint32(body[:4], id)
	body[4] = alias
	return append([]byte{elEnterAoI}, body[:]...), nil
}

// Bare property elements.
//
// A property update has TWO wire forms. The one this server used first is the
// `updateEntity` run (`0x4b`, `[count][propIndex][value]...`). The other — the
// one the captured server actually uses in a battle — is the property's OWN
// element id, `entityPropertyBase + index`, followed by the value and nothing
// else: no length, no count, no wrapper. The length is the property's declared
// size, which is why a fixed-size property costs exactly its value.
//
// That is why the captured server looked like it sent no property updates at
// all: every search for them looked for `0x4b`, and it never sends one in a
// battle. It sends these instead, every tick.
const (
	// Avatar properties, by element id.
	elAvatarNumOfObservers        = 0xA8 // UINT8
	elAvatarKillcamSimData        = 0xB3 // UINT8
	elAvatarDenunciationsLeft     = 0xB4 // UINT16
	elAvatarHullAimingPitchPacked = 0xB5 // UINT16
	elAvatarBattleChatRestriction = 0xB6 // UINT16
	elAvatarArenaTypeID           = 0xB7 // UINT32
	// elAvatarAuxPhysicsData is `ownVehicleAuxPhysicsData`: the hull's
	// attitude, both tracks' speeds and the engine's relative RPM, packed into
	// one UINT64. The client's `__onSetOwnVehicleAuxPhysicsData` unpacks it and
	// calls `appearance.updateTracksScroll(left, right)`, and
	// `engineState.physicRPMLink` reads field 5 of the same word — so this one
	// element is what makes the tracks scroll and the tacho move.
	elAvatarAuxPhysicsData = 0xBA // UINT64

	// Vehicle properties, by element id.
	//
	// The id is `ENTITY_PROPERTY_BASE + FullIndex`, and the base is 0xA7 for
	// every entity (the reference toolkit's
	// `ElementIdRange::new(0xA7, 0xFE)`). FullIndex is the client's
	// `allocateClientServerFullIndexes` order — fixed sizes first, ascending,
	// then the variable ones in declaration order — which is
	// `entdef.Entity.CSPropsOrdered`. Measured against the capture, four ids
	// pin the base: `0xb3` is one byte (`botDisplayStatus`, 12), `0xb4` two
	// (`gunAnglesPacked`, 13), `0xb6` two (`engineMode`, 15) and `0xa8` one
	// (`isStrafing`, 1).
	elVehicleIsStrafing = 0xA8 // UINT8
	// elVehicleSiegeState is `siegeState` (property 4), the
	// `VEHICLE_SIEGE_STATE` the client's
	// `Avatar.__isOwnVehicleSwitchingSiegeMode` reads to block shooting while
	// the switch is in flight.
	elVehicleSiegeState = 0xAB // UINT8
	// elVehicleWheelsScroll is `wheelsScroll` (property 27): one packed byte
	// per scrollable wheel. `Vehicle.set_wheelsScroll` unpacks each with
	// `WoT.unpackWheelScroll` and feeds it to that wheel's scroll filter, so
	// without it no wheel on a wheeled vehicle turns at all.
	//
	// It is `Tuple[0]{UINT8}`, i.e. variable length with a ONE-byte header
	// (`VariableLengthHeaderSize` 1 → `ElementLength::Variable8`), so the
	// element is `c2 <len8> <len bytes>`.
	elVehicleWheelsScroll    = 0xC2 // Tuple[0]{UINT8}
	elVehicleBotDisplayState = 0xB3 // UINT8
	// elVehicleGunAnglesPacked is `gunAnglesPacked`: 10-bit turret yaw, then
	// the pitch's 6 bits. `VehicleGunRotator.__syncWithServerTurretYaw` reads
	// it back and snaps the turret to it.
	elVehicleGunAnglesPacked = 0xB4 // UINT16
	elVehicleHealth          = 0xB5 // UINT16
	// elVehicleEngineMode is `engineMode`: `[mode, flags]`, which the client's
	// `appearance.changeEngineMode` feeds to the track scroll controller.
	elVehicleEngineMode = 0xB6 // UINT16
	elVehicleAvatarID   = 0xB7 // UINT32
)

// EncodeBareProperty writes one property as its own element: the id, then the
// value, with no length and no wrapper.
func EncodeBareProperty(id byte, value []byte) []byte {
	out := make([]byte, 0, 1+len(value))
	out = append(out, id)
	return append(out, value...)
}

// EncodeBareU16 and EncodeBareU64 are the two widths a battle tick needs.
func EncodeBareU16(id byte, v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return EncodeBareProperty(id, b[:])
}

func EncodeBareU8(id byte, v uint8) []byte {
	return EncodeBareProperty(id, []byte{v})
}

func EncodeBareU64(id byte, v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return EncodeBareProperty(id, b[:])
}

// EncodeBareVar8 writes a variable-length property whose
// `VariableLengthHeaderSize` is 1: the id, a one-byte length, then the payload.
// That is `ElementLength::Variable8`, the width a def's `VarLen` 1 selects.
func EncodeBareVar8(id byte, payload []byte) []byte {
	if len(payload) > 0xFF {
		payload = payload[:0xFF]
	}
	out := make([]byte, 0, 2+len(payload))
	out = append(out, id, byte(len(payload)))
	return append(out, payload...)
}

// EncodeBareU8Tuple writes a `Tuple[0]{UINT8}` property: a variable-length
// tuple of bytes, as `Vehicle.wheelsScroll` is.
//
// A tuple with no fixed element count carries its count in the payload, ahead
// of the elements — `Codec::write` does `write_packed_u24(list.len())` then the
// elements, and `read` takes the count the same way. Omitting it makes the
// client read the first element as the count: measured, `c2 08 <8 bytes>` made
// it read 0x80 = 128 elements out of an 8-byte element and die on
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
//
// So the element is `id <len8> <count> <count bytes>`, with `len8` covering the
// count byte too.
func EncodeBareU8Tuple(id byte, values []byte) []byte {
	payload := make([]byte, 0, 1+len(values))
	// `write_packed_u24`: one byte below 255, else 0xFF and the value in three.
	if len(values) < 0xFF {
		payload = append(payload, byte(len(values)))
	} else {
		payload = append(payload, 0xFF, byte(len(values)), byte(len(values)>>8), byte(len(values)>>16))
	}
	payload = append(payload, values...)
	return EncodeBareVar8(id, payload)
}

// elControlEntity is `CONTROL_ENTITY`: FIXED 5, `[entityID u32][on bool]`.
//
// It tells the client whether it has control authority over an entity. While
// controlled the client is expected to locally predict and simulate the
// entity's movement and report it back, rather than only receiving
// server-driven position updates. The captured server never sends it, but this
// client's vehicle physics is never stepped without it — measured: the
// `subscribeBeforeSimulation`/`subscribeAfterSimulation` callbacks never fire,
// `movementSignals` stays 0 while driving at 10.3 m/s, and the track scroll and
// engine RPM (both physics outputs) stay pinned.
const elControlEntity = 0x41

// EncodeControlEntity grants or revokes control authority over one entity.
func EncodeControlEntity(id uint32, on bool) []byte {
	var body [5]byte
	binary.LittleEndian.PutUint32(body[:4], id)
	if on {
		body[4] = 1
	}
	return append([]byte{elControlEntity}, body[:]...)
}

// EntityPropertyRun encodes an entity's client-visible properties as the
// changed-properties run the client reads: `[count u8][exposed id u8]
// [value]…`, where the exposed id is the property's index in the entity's
// client property list.
//
// This is the run `createEntityDetailed` carries as its trailing payload —
// the entity's initial property values — and the same shape `updateEntity`
// uses later.
func EntityPropertyRun(e *Entity) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: property run: no entity type")
	}
	if len(e.Type.Properties) > 0xFF {
		return nil, fmt.Errorf("wotlogin: %s has %d client properties, more than fit",
			e.Type.Name, len(e.Type.Properties))
	}
	c := entdef.NewCodec()
	var body bytes.Buffer
	body.WriteByte(byte(len(e.Type.Properties)))
	for i := range e.Type.Properties {
		p := &e.Type.Properties[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return body.Bytes(), nil
}

// EncodeSelectEntity builds the element that makes an entity the client's
// current one: `[entityID u32]`, four bytes, no length.
//
// It is the companion of EncodeUpdateEntity: `updateEntity` carries no
// entity id of its own, it applies to whatever `selectEntity` selected.
func EncodeSelectEntity(id uint32) ([]byte, error) {
	var body [4]byte
	binary.LittleEndian.PutUint32(body[:], id)
	return append([]byte{elSelectEntity}, body[:]...), nil
}

// EncodeUpdateEntity builds the element that carries an entity's changed
// client-visible properties: `[count u8][exposed id u8][value]…`, where the
// exposed id is the property's index in the entity's client property list.
//
// There is no entity id in the element — it applies to the entity the
// preceding `selectEntity` selected. Writing one shifts the whole run and
// the client reads it as an entity-method target, which trips
// `MF_ASSERT_DEV FAILED: pEntity` in `BWEntities::getEntityMethodStreamSize`.
func EncodeUpdateEntity(e *Entity) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: UpdateEntity: no entity type")
	}
	if len(e.Type.Properties) > 0xFF {
		return nil, fmt.Errorf("wotlogin: %s has %d client properties, more than fit",
			e.Type.Name, len(e.Type.Properties))
	}
	run, err := EntityPropertyRun(e)
	if err != nil {
		return nil, err
	}
	return element(elUpdateEntity, run)
}

// EncodeUpdateEntityLevel is EncodeUpdateEntity restricted to one replication
// level: the detail-level properties when inner is true, the outer ones when it
// is false.
func EncodeUpdateEntityLevel(e *Entity, inner bool) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: UpdateEntity: no entity type")
	}
	run, err := EntityPropertyRunLevel(e, inner)
	if err != nil {
		return nil, err
	}
	return element(elUpdateEntity, run)
}

// EncodeAddSpaceGeometryMapping builds the element that attaches a geometry
// resource to a space: `[spaceID u32][entryID 8B][path varstr]
// [transform 16×f32][unk u8]`.
//
// This is the dedicated element (`0x09`), not `spaceProperty` (`0x08`): the
// reference toolkit writes geometry with this one, and the client's own
// `AddSpaceGeometryMapping` codec reads exactly this shape. Writing the
// mapping through the generic space-data key instead leaves the space with
// no terrain, which is what the battle loading screen sitting at zero
// progress looks like.
func EncodeAddSpaceGeometryMapping(spaceID uint32, entryID [8]byte, path string, transform [16]float32) ([]byte, error) {
	var body bytes.Buffer
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], spaceID)
	body.Write(tmp[:])
	body.Write(entryID[:])
	writePackedLen(&body, len(path))
	body.WriteString(path)
	for _, f := range transform {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	body.WriteByte(1) // the trailing byte, 0x01 in every observed mapping
	return element(elAddSpaceGeometryMapping, body.Bytes())
}

// IdentityTransform is the 4×4 placement matrix every observed geometry
// mapping carries.
func IdentityTransform() [16]float32 {
	return [16]float32{1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1}
}

// BasePropertyRun is EntityPropertyRun restricted to the entity's base-hosted
// properties.
//
// `createEntityDetailed` carries the BASE run, not the whole table: the client
// reads it against the entity's base property table and leaves the rest of the
// stream unread ("MemoryIStream: There are still N bytes left"). A Vehicle has
// no base properties at all, so its run is a single zero byte and its cell
// properties have to arrive through `updateEntity` — which means that update
// must be sent BEFORE `enterAoI`, because `Vehicle.onEnterWorld` builds the
// type descriptor from `publicInfo` and nothing rebuilds it afterwards.
func BasePropertyRun(e *Entity) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: base property run: no entity type")
	}
	if len(e.Type.BaseProps) > 0xFF {
		return nil, fmt.Errorf("wotlogin: %s has %d base properties, more than fit",
			e.Type.Name, len(e.Type.BaseProps))
	}
	c := entdef.NewCodec()
	var body bytes.Buffer
	body.WriteByte(byte(len(e.Type.BaseProps)))
	for i := range e.Type.BaseProps {
		p := &e.Type.BaseProps[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return body.Bytes(), nil
}

// EntityPropertyRunLevel encodes the half of an entity's client-visible
// properties that belongs to one replication level.
//
// The split is the defs' `<DetailLevel>`: a property with none is part of the
// entity's outer state and rides the creation message, and one with a level
// (MY_VEHICLE, ...) rides the update that follows. Sending both halves in the
// creation message makes the client read past what it expects and leave the
// rest of the stream unread, which is how a Vehicle ended up with an empty
// `publicInfo` and no type descriptor.
func EntityPropertyRunLevel(e *Entity, inner bool) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: property run: no entity type")
	}
	c := entdef.NewCodec()
	var body bytes.Buffer
	var ids []int
	for i := range e.Type.Properties {
		if (e.Type.Properties[i].DetailLevel != "") == inner {
			ids = append(ids, i)
		}
	}
	if len(ids) > 0xFF {
		return nil, fmt.Errorf("wotlogin: %s has %d properties at this level, more than fit",
			e.Type.Name, len(ids))
	}
	body.WriteByte(byte(len(ids)))
	for _, i := range ids {
		p := &e.Type.Properties[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return body.Bytes(), nil
}

// CreateEntityDirectionUnk is the byte WoT sends right after a packed
// yaw/pitch/roll in `createEntity`. It is not part of the packed triple: the
// reference found it by noticing that every `AVATAR_UPDATE_*_YAW_PITCH_ROLL`
// variant is exactly one byte longer than its three packed bytes account for,
// and that `createEntity` payloads only decode once it is modelled. As
// captured for a vehicle; the client crashes on a vehicle created with 0.
const CreateEntityDirectionUnk uint8 = 5

// EncodeCreateEntity builds element 0x0B, the aliased entity creation message.
//
// It is the one the genuine server uses for a vehicle (`alias: true` in the
// reference's `create_vehicle`), and it differs from `createEntityDetailed` in
// exactly one place: the direction is a packed yaw/pitch/roll triple plus one
// trailing byte, not three raw floats.
func EncodeCreateEntity(id uint32, typeID uint16, resource string, pos [3]float32, yaw, pitch, roll float32, clientData []byte) ([]byte, error) {
	var body bytes.Buffer
	body.WriteByte(0) // BW_COMPRESSION_NONE
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], id)
	body.Write(tmp[:])
	binary.LittleEndian.PutUint16(tmp[:2], typeID)
	body.Write(tmp[:2])
	body.Write([]byte{0, 0}) // unk_u16, always 0 in observed traffic
	writePackedLen(&body, len(resource))
	body.WriteString(resource)
	for _, f := range pos {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		body.Write(tmp[:])
	}
	body.Write(packYawPitchRoll(yaw, pitch, roll))
	body.WriteByte(CreateEntityDirectionUnk)
	body.Write(clientData)
	return element(elCreateEntity, body.Bytes())
}

// packYawPitchRoll packs a direction the way `PackedYawPitchRoll<false>` does:
// three bytes, one per angle, each a fraction of a full turn in 8 bits.
func packYawPitchRoll(yaw, pitch, roll float32) []byte {
	pack := func(v float32) byte {
		f := float64(v) / (2 * math.Pi)
		f -= math.Floor(f)
		return byte(int(f*256) & 0xFF)
	}
	return []byte{pack(yaw), pack(pitch), pack(roll)}
}

// EntityPropertyRunNames encodes a run holding exactly the named properties,
// in table order.
//
// It exists because the client applies a creation run property by property and
// ABANDONS the rest as soon as one setter throws. Several Vehicle setters need
// the entity to be in the world — `set_stunInfo` wants `entityGameObject`,
// `set_remoteCamera` wants `ownVehicle` — so sending them in the creation
// message kills every property after them, `publicInfo` included. Those ride
// the update that follows `enterAoI` instead.
func EntityPropertyRunNames(e *Entity, names ...string) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: property run: no entity type")
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	c := entdef.NewCodec()
	var body bytes.Buffer
	var ids []int
	for i := range e.Type.Properties {
		if want[e.Type.Properties[i].Name] {
			ids = append(ids, i)
		}
	}
	body.WriteByte(byte(len(ids)))
	for _, i := range ids {
		p := &e.Type.Properties[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return body.Bytes(), nil
}

// EntityPropertyRunExcept is EntityPropertyRunLevel with the named properties
// left out.
func EntityPropertyRunExcept(e *Entity, inner bool, skip ...string) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: property run: no entity type")
	}
	omit := make(map[string]bool, len(skip))
	for _, n := range skip {
		omit[n] = true
	}
	c := entdef.NewCodec()
	var body bytes.Buffer
	var ids []int
	for i := range e.Type.Properties {
		p := &e.Type.Properties[i]
		if omit[p.Name] || (p.DetailLevel != "") != inner {
			continue
		}
		ids = append(ids, i)
	}
	body.WriteByte(byte(len(ids)))
	for _, i := range ids {
		p := &e.Type.Properties[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q has no value",
				e.ID, e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, fmt.Errorf("wotlogin: entity %d (%s): property %q: %w",
				e.ID, e.Type.Name, p.Name, err)
		}
	}
	return body.Bytes(), nil
}

// EncodeUpdateEntityExcept is EncodeUpdateEntityLevel with the named properties
// left out.
func EncodeUpdateEntityExcept(e *Entity, inner bool, skip ...string) ([]byte, error) {
	if e == nil || e.Type == nil {
		return nil, fmt.Errorf("wotlogin: UpdateEntity: no entity type")
	}
	run, err := EntityPropertyRunExcept(e, inner, skip...)
	if err != nil {
		return nil, err
	}
	return element(elUpdateEntity, run)
}
