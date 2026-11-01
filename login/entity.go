package login

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/LockBlock-dev/wot/entdef"
)

// Client-side element ids (BigWorld's client element table, WoT fork).
// The two ranges are what make the entity layer possible without a table
// per method: a client method call is ENTITY_METHOD_BASE + method id, and
// a property update is ENTITY_PROPERTY_BASE + property index.
const (
	elCreateBasePlayer   = 0x05 // VAR 2
	elCreateCellPlayer   = 0x06 // VAR 2
	elTickSync           = 0x13 // FIXED 1
	elSelectPlayerEntity = 0x1A // FIXED 0
	elEnableEntities     = 0x0B // FIXED 0

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
	return element(byte(entityMethodBase+id), buf.Bytes())
}

// EncodePropertyUpdate builds a property update element: the property's
// index plus the base, then its value encoded from the defs.
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
	return element(byte(entityPropertyBase+idx), buf.Bytes())
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

// element frames a payload as [id][len u16 LE][payload].
func element(id byte, payload []byte) ([]byte, error) {
	if len(payload) > 0xFFFF {
		return nil, fmt.Errorf("wotlogin: element %#02x payload is %d B, beyond the u16 length", id, len(payload))
	}
	out := make([]byte, 0, 3+len(payload))
	out = append(out, id)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(payload)))
	return append(out, payload...), nil
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
