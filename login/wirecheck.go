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

// clientShape resolves an element id the way the client's table does. The
// entity method and property ranges are per-entity slots, so they are
// resolved against every entity the handoff touches and the answers must
// agree — a disagreement is itself a bug (the client has one table).
func clientShape(d *entdef.Dispatch, id byte) (msgShape, string, error) {
	switch id {
	case elResetEntities:
		return msgShape{fixed: true, size: 1}, "resetEntities", nil
	// `enableEntities` is 0x0B in the CLIENT->SERVER table, not this one; the
	// same value is `createEntity` here. It is never sent by the server, so it
	// has no shape to resolve.
	case elSelectPlayerEntity:
		return msgShape{fixed: true, size: 0}, "selectPlayerEntity", nil
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
	case 0x45:
		return msgShape{width: 2}, "resourceHeader", nil
	case 0x46:
		return msgShape{width: 2}, "resourceFragment", nil
	}
	var found *msgShape
	var name string
	for _, ent := range []string{"Account", "Avatar"} {
		e := d.Entity(ent)
		if e == nil {
			continue
		}
		var s msgShape
		var n string
		switch {
		case id >= entityMethodBase && id < entityPropertyBase:
			i := int(id - entityMethodBase)
			if i >= len(e.ClientMethods) {
				continue
			}
			m := e.ClientMethods[i]
			s = msgShape{fixed: m.Length.Fixed, size: m.Length.Size, width: int(m.Length.Var)}
			n = ent + "." + m.Name
		case id >= entityPropertyBase:
			i := int(id - entityPropertyBase)
			if i >= len(e.Properties) {
				continue
			}
			s = msgShape{width: 2}
			n = ent + "." + e.Properties[i].Name
		default:
			continue
		}
		// The client resolves an element id against the entity it is
		// addressing, and the same slot means different things on different
		// entities (0x5f is Account.onCmdResponseExt and also the revisions
		// small; 0x69 is Account.update and Avatar.onSwitchViewpoint). The
		// app does not say which entity it is for, so take the first match —
		// the check is about framing, not about naming the method.
		if found == nil {
			found, name = &s, n
		}
	}
	if found == nil {
		return msgShape{}, "", fmt.Errorf("element %#02x is not in the client's table", id)
	}
	return *found, name, nil
}

// ParseClientApp walks an app exactly as the client does and returns the
// messages it yields, or the first byte it could not consume.
func ParseClientApp(d *entdef.Dispatch, app []byte) ([]clientMsg, error) {
	var out []clientMsg
	for i := 0; i < len(app); {
		id := app[i]
		shape, name, err := clientShape(d, id)
		if err != nil {
			return out, fmt.Errorf("at %d: %w", i, err)
		}
		i++
		var body []byte
		if shape.fixed {
			if i+shape.size > len(app) {
				return out, fmt.Errorf("%s (%#02x) at %d: %s, %d B left", name, id, i-1, shape, len(app)-i)
			}
			body = app[i : i+shape.size]
			i += shape.size
		} else {
			w := shape.width
			if w <= 0 {
				w = 2
			}
			if i+w > len(app) {
				return out, fmt.Errorf("%s (%#02x) at %d: length needs %d B, %d left", name, id, i-1, w, len(app)-i)
			}
			n := 0
			for k := 0; k < w; k++ {
				n |= int(app[i+k]) << (8 * k)
			}
			i += w
			if i+n > len(app) {
				return out, fmt.Errorf("%s (%#02x): payload %d B, %d left", name, id, n, len(app)-i)
			}
			body = app[i : i+n]
			i += n
		}
		out = append(out, clientMsg{ID: id, Body: body})
	}
	return out, nil
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
