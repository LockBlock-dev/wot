package login

import (
	"fmt"

	"github.com/LockBlock-dev/wot/entdef"
)

// The client's bundle reader, re-implemented strictly.
//
// `UDPBundleProcessor::iterator::unpack` walks a bundle's app as a
// sequence of Mercury messages: `[id][payload]` for a FIXED-size message,
// `[id][len of the declared width][payload]` for a variable one. It has no
// way to resynchronise, so a stray length field is read as the next id —
// `00` is `authenticate`, which wants a 4-byte key, and the bundle dies
// with "Not enough data on stream ... needed 4" / "Got corrupted message
// header" / REASON_CORRUPTED_PACKET.
//
// CheckClientApp is that reader. It is used by the tests to prove the
// handoff offline, and by a live run (WOT_WIRE_CHECK=1) to catch a
// malformed packet before the client does.

// WireCheck, when set, is called with every app the server is about to
// put on the wire. A non-nil error means the client would drop the bundle.
var WireCheck func(app []byte) error

// clientMsg is one message the client's bundle reader yields.
type clientMsg struct {
	ID   byte
	Body []byte
}

// msgShape is what the client's element table says about an id.
type msgShape struct {
	fixed bool
	size  int // when fixed
	width int // when variable
}

func (s msgShape) String() string {
	if s.fixed {
		return fmt.Sprintf("fixed(%d)", s.size)
	}
	return fmt.Sprintf("var(%d)", s.width)
}

// clientShape resolves an element id the way the client's table does, for ONE
// entity. The method and property ranges are per-entity slots: the same byte
// is a different method on Account, Avatar and Vehicle, and the app does not
// say which entity it addresses. `ParseClientApp` therefore tries each entity
// and keeps the one that consumes the app exactly.
func clientShape(d *entdef.Dispatch, ent string, id byte) (msgShape, string, error) {
	switch id {
	case elResetEntities:
		return msgShape{fixed: true, size: 1}, "resetEntities", nil
	// `enableEntities` is 0x0B in the CLIENT->SERVER table, not this one; the
	// same value is `createEntity` here. It is never sent by the server, so it
	// has no shape to resolve.
	case elSelectPlayerEntity:
		return msgShape{fixed: true, size: 0}, "selectPlayerEntity", nil
	case 0x44:
		// switchBaseApp: FIXED 9, `[ip4][port BE][salt u16 LE][reset]`. It is
		// a connection-level element, not an entity one, so it is resolved
		// here rather than against the entity table.
		return msgShape{fixed: true, size: 9}, "switchBaseApp", nil
	case elUpdateFrequency:
		return msgShape{fixed: true, size: 7}, "updateFrequency", nil
	case elTickSync:
		return msgShape{fixed: true, size: 1}, "tickSync", nil
	case elCreateBasePlayer:
		return msgShape{width: 2}, "createBasePlayer", nil
	case elCreateCellPlayer:
		return msgShape{width: 2}, "createCellPlayer", nil
	case elSpaceData, elAddSpaceGeometryMapping,
		elCreateEntity, elCreateEntityDetailed, elLeaveAoI, elUpdateEntity:
		return msgShape{width: 2}, "spaceData", nil
	case elEnterAoI:
		return msgShape{fixed: true, size: 5}, "enterAoI", nil
	case elEnterAoIOnVehicle:
		return msgShape{fixed: true, size: 9}, "enterAoIOnVehicle", nil
	case elSetVehicle:
		return msgShape{fixed: true, size: 8}, "setVehicle", nil
	case elSelectEntity:
		return msgShape{fixed: true, size: 4}, "selectEntity", nil
	case elForcedPosition:
		return msgShape{fixed: true, size: 38}, "forcedPosition", nil
	case elRelativePosition:
		return msgShape{fixed: true, size: 12}, "relativePosition", nil
	case elAvatarUpdatePlayerDetailed:
		return msgShape{fixed: true, size: 25}, "avatarUpdatePlayerDetailed", nil
	case elAvatarUpdateAliasDetailed:
		return msgShape{fixed: true, size: 26}, "avatarUpdateAliasDetailed", nil
	case elAvatarUpdateTargetingInfo:
		// Avatar.updateTargetingInfo: nine FLOAT32, no entity id. The client's
		// Python takes the entity id plus ten floats, so this element cannot
		// reach it — the gun is driven through the `OwnVehicle` component's
		// `targetingInfo` property instead, whose setter calls the Python
		// method with the id. The size here is the def's, which is what the
		// client's own method table carries: sending 44 bytes leaves the
		// trailing eight to be read as the next element id and the client
		// drops the packet as REASON_CORRUPTED_PACKET.
		return msgShape{fixed: true, size: 36}, "updateTargetingInfo", nil
	case elNrlCreateNode:
		return msgShape{width: 2}, "nrlCreateNode", nil
	case elNrlUpdateNodeFlag:
		// Payload-less by design: it consumes one record from the NRL
		// stream, so it carries no length field at all.
		return msgShape{fixed: true, size: 0}, "nrlUpdateNodeFlag", nil
	case elNrlData:
		return msgShape{width: 2}, "nrlData", nil
	case 0x45:
		return msgShape{width: 2}, "resourceHeader", nil
	case 0x46:
		return msgShape{width: 2}, "resourceFragment", nil
	}
	e := d.Entity(ent)
	if e == nil {
		return msgShape{}, "", fmt.Errorf("element %#02x: no %s entity", id, ent)
	}
	switch {
	case id >= entityMethodBase && id < entityPropertyBase:
		i := int(id - entityMethodBase)
		if i >= len(e.ClientMethods) {
			return msgShape{}, "", fmt.Errorf("element %#02x: %s has no client method %d", id, ent, i)
		}
		m := e.ClientMethods[i]
		return msgShape{fixed: m.Length.Fixed, size: m.Length.Size, width: int(m.Length.Var)}, ent + "." + m.Name, nil
	case id >= entityPropertyBase:
		i := int(id - entityPropertyBase)
		if i >= len(e.Properties) {
			return msgShape{}, "", fmt.Errorf("element %#02x: %s has no property %d", id, ent, i)
		}
		// A STANDALONE property element is framed by the property's own
		// declared length: a fixed-size value (`health`, INT16) carries no
		// length field at all, a variable one (`damageStickers`, ARRAY) is
		// `[id][u16 len][value]`. Reading a length off a fixed property is
		// what made this checker reject a correct bundle — and the same
		// mistake in the encoder is what shifts every element after it and
		// crashes the client on `pCurr_ + nBytes <= pEnd_`.
		pr := e.Properties[i]
		return msgShape{fixed: pr.Length.Fixed, size: pr.Length.Size, width: int(pr.Length.Var)}, ent + "." + pr.Name, nil
	}
	return msgShape{}, "", fmt.Errorf("element %#02x is not in the %s table", id, ent)
}

// ParseClientApp walks an app exactly as the client does and returns the
// messages it yields, or the first byte it could not consume.
//
// The method and property slots are per-entity, and a bundle can address
// several entities in a row (`selectEntity(vehicle)` → a Vehicle method →
// `selectPlayerEntity` → an Avatar method, which is exactly what a shot
// sends), so the walk carries a current entity and may SWITCH it at any
// element. Because the app does not say which entity an id belongs to, the
// walk backtracks over the entity choice: the app is accepted only if some
// path consumes it to its last byte. A bundle the client would drop has no
// such path.
func ParseClientApp(d *entdef.Dispatch, app []byte) ([]clientMsg, error) {
	var ents []string
	for _, n := range []string{"Account", "Avatar", "Vehicle"} {
		if d.Entity(n) != nil {
			ents = append(ents, n)
		}
	}
	if len(ents) == 0 {
		return nil, fmt.Errorf("no entity table to read the app against")
	}
	type state struct{ off, ent int }
	seen := make(map[state]bool)
	var walk func(off, ent int, out []clientMsg) ([]clientMsg, error)
	walk = func(off, ent int, out []clientMsg) ([]clientMsg, error) {
		if off == len(app) {
			return out, nil
		}
		if off > len(app) {
			return nil, fmt.Errorf("at %d: ran past the end", off)
		}
		if seen[state{off, ent}] {
			return nil, fmt.Errorf("at %d: loop", off)
		}
		seen[state{off, ent}] = true
		// Try the entity the bundle is already addressing first, then the
		// others: a `selectEntity`/`selectPlayerEntity` may have switched it.
		order := []int{ent}
		for i := range ents {
			if i != ent {
				order = append(order, i)
			}
		}
		id := app[off]
		var lastErr error
		for _, e := range order {
			shape, name, err := clientShape(d, ents[e], id)
			if err != nil {
				if lastErr == nil {
					lastErr = err
				}
				continue
			}
			body := []byte(nil)
			next := off + 1
			if shape.fixed {
				if next+shape.size > len(app) {
					lastErr = fmt.Errorf("at %d: %s wants %d B, %d left", off, name, shape.size, len(app)-next)
					continue
				}
				body = app[next : next+shape.size]
				next += shape.size
			} else {
				width := shape.width
				if width <= 0 {
					width = 1
				}
				if next+width > len(app) {
					lastErr = fmt.Errorf("at %d: %s length header overruns", off, name)
					continue
				}
				n := 0
				for k := 0; k < width; k++ {
					n |= int(app[next+k]) << (8 * k)
				}
				next += width
				if next+n > len(app) {
					lastErr = fmt.Errorf("at %d: %s (%#02x): payload %d B, %d left", off, name, id, n, len(app)-next)
					continue
				}
				body = app[next : next+n]
				next += n
			}
			msgs, err := walk(next, e, append(out, clientMsg{ID: id, Body: body}))
			if err == nil {
				return msgs, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("at %d: element %#02x is not in any entity table", off, id)
		}
		return nil, lastErr
	}
	return walk(0, 0, nil)
}

// CheckClientApp is ParseClientApp as a pass/fail check.
func CheckClientApp(d *entdef.Dispatch, app []byte) error {
	_, err := ParseClientApp(d, app)
	return err
}

// checkWire runs the hook, if a live run asked for it.
func (s *BaseAppServer) checkWire(app []byte) {
	if WireCheck == nil {
		return
	}
	if err := WireCheck(app); err != nil {
		s.logf("WIRE CHECK FAILED (%d B app): %v", len(app), err)
	}
}
