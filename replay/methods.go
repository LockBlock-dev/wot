package replay

import (
	"fmt"
	"strings"
)

// MethodSig is one client method's wire signature: Arg descriptor
// strings in DescribeDeep syntax (see values.go) with parallel names.
type MethodSig struct {
	Name     string
	Args     []string
	ArgNames []string
}

// avatarVar240 maps 2.4.0 Avatar variable-size wire IDs to doc-order
// indexes into avatarVarDoc. Each proven by unique exact-consumption
// fit on the Prohorovka fixture; the var-block ORDER stays open.
var avatarVar240 = map[uint32]int{
	38: 0,  // onChatAction (4 samples, quest pickles)
	54: 17, // showShotResults (7 single-element arrays)
	58: 22, // updateArena (9 (u8,string-pickle), epic config t=0)
	62: 4,  // processInvitations (1 python zlib pickle)
	65: 7,  // updateSpawnList (1 string, scenario name)
	67: 19, // explodeProjectile (105, trailing u32 array)
}

// avatarVar231 maps 2.3.1 Avatar variable-size wire IDs (Mines
// fixture, same proof standard).
var avatarVar231 = map[uint32]int{
	54: 17, // showShotResults (13 single-element arrays)
	56: 19, // explodeProjectile (61, trailing u32 array)
	59: 22, // updateArena (9 (u8,string-pickle), epic config t=0)
	63: 4,  // processInvitations (1 python zlib pickle)
}

// avatarVar211 maps 2.1.1 Avatar variable-size wire IDs (Glacier
// fixture, same proof standard). 40/42/60 stay unmapped by measurement,
// not neglect: 40 is 5 B fitting 2 doc signatures, 42 is bare-Python
// fitting 9, and 60's 394 payloads each fit 4–25 (Array,Array) element
// combos with zero unique fits (small values fit U8/I16/I32/U32
// interchangeably) — shape alone cannot pin any of them, and no 2.1.1
// defs survive to name them. TestDecode211 pins exactly these three.
var avatarVar211 = map[uint32]int{
	38: 0,  // onChatAction (12 quest-pickle samples)
	54: 17, // showShotResults (39 single-element arrays)
	56: 19, // explodeProjectile (50, trailing u32 array)
	59: 22, // updateArena (38 (u8,string-pickle), epic config t=0)
	64: 4,  // processInvitations (1 python zlib pickle)
	68: 30, // setUpdatedGoodiesSnapshot (3 goodies snapshots)
}

// SigFor resolves (entity type ID 1-based, wire method ID) to a
// signature for the given client version ("2.4.0.0" style; "" =
// fit-only). Fixed tables are version-stable (proven on 2.3.1 +
// 2.4.0); var tables are per-version. ok=false when unknown.
func SigFor(clientVer string, typeID uint16, mid uint32) (MethodSig, bool) {
	switch typeID {
	case 2: // Avatar
		if int(mid) < len(avatarFixed) {
			return avatarFixed[mid], true
		}
		var tab map[uint32]int
		if strings.HasPrefix(clientVer, "2.4.") {
			tab = avatarVar240
		} else if strings.HasPrefix(clientVer, "2.3.") {
			tab = avatarVar231
		} else if strings.HasPrefix(clientVer, "2.1.") {
			tab = avatarVar211
		}
		if oi, ok := tab[mid]; ok && oi < len(avatarVarDoc) {
			return avatarVarDoc[oi], true
		}
	case 6: // Vehicle
		if int(mid) < len(vehicleFixed) {
			return vehicleFixed[mid], true
		}
		// The two variable-size methods follow in stable doc order.
		if mid == 9 && len(vehicleVarDoc) > 0 {
			return vehicleVarDoc[0], true // updateLaserSight
		}
		if mid == 10 && len(vehicleVarDoc) > 1 {
			return vehicleVarDoc[1], true // showDamageFromShot
		}
	}
	return MethodSig{}, false
}

// fixedMethodName resolves fixed-block wires without a version
// (var wires need the per-version table; see SigFor).
func fixedMethodName(typeID uint16, mid uint32) string {
	switch typeID {
	case 2:
		if int(mid) < len(avatarFixed) {
			return avatarFixed[mid].Name
		}
	case 6:
		if int(mid) < len(vehicleFixed) {
			return vehicleFixed[mid].Name
		}
	}
	return ""
}

// DecodedCall is an EntityMethod call with typed args.
type DecodedCall struct {
	EntityID uint32
	MethodID uint32
	Sig      MethodSig
	Args     []any
	Raw      []byte // args payload verbatim
}

// DecodeCall parses + decodes one 0x8 payload using the versioned
// wire table; args must consume the payload exactly.
func DecodeCall(clientVer string, typeID uint16, data []byte) (DecodedCall, error) {
	var c DecodedCall
	m, err := ParseEntityMethod(data, nil)
	if err != nil {
		return c, err
	}
	sig, ok := SigFor(clientVer, typeID, m.MethodID)
	if !ok {
		return c, fmt.Errorf("wotreplay: no sig for type=%d mid=%d ver=%q", typeID, m.MethodID, clientVer)
	}
	args, err := decodeArgs(sig, m.Args)
	if err != nil {
		return c, fmt.Errorf("wotreplay: %s: %w", sig.Name, err)
	}
	return DecodedCall{EntityID: m.EntityID, MethodID: m.MethodID, Sig: sig, Args: args, Raw: append([]byte{}, m.Args...)}, nil
}

func decodeArgs(sig MethodSig, buf []byte) ([]any, error) {
	out := make([]any, 0, len(sig.Args))
	off := 0
	for _, desc := range sig.Args {
		v, n, err := Decode(desc, buf[off:])
		if err != nil {
			return nil, err
		}
		off += n
		out = append(out, v)
	}
	if off != len(buf) {
		return nil, fmt.Errorf("wotreplay: %d/%d bytes consumed", off, len(buf))
	}
	return out, nil
}

// ClassifyVar tries every Avatar doc-order var signature and returns
// the indexes that consume args exactly. It validates the committed
// var-wire maps (expect exactly the mapped one) and decodes calls on
// versions without a table.
func ClassifyVar(args []byte) []int {
	var out []int
	for i := range avatarVarDoc {
		if _, err := decodeArgs(avatarVarDoc[i], args); err == nil {
			out = append(out, i)
		}
	}
	return out
}
