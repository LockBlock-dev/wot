package login

import (
	"encoding/binary"
	"fmt"
)

// FloodBundle is the stage-2 bulk bundle, AUTHORED from the entity defs
// instead of replayed from a capture.
//
// The bundle is not a bare pickle: it is a stream of ClientInterface
// elements, and the pickle rides inside the createBasePlayer element as
// the Account entity's `initialServerSettings` property. The client walks
// it with UDPBundleProcessor, so every element's length must be exact:
//
//	[02][freq u8][unknown u16][gameTime u32]   updateFrequencyNotification
//	[13][tag]                                  tickSync
//	[05][FF FF][u32 len] …                     createBasePlayer (oversize)
//
// createBasePlayer's payload is the entity header plus the Account
// entity's base-hosted client properties, in WIRE order (interfaces
// first, then declaration — see entdef.Entity.WireProps):
//
//	[entity id u32][type id u16][blob len 0]
//	[requiredVersion_2400 var1 string]
//	[name var1 string]
//	[incarnationID u64]
//	[initialServerSettings var1 python]
//	[component count u8]
//
// The payload is ~250 KB, far past the element's 2-byte length field, so
// it goes out in the engine's oversize form: the length field is filled
// with 0xFF, the real length is a u32 at the start of the body, and the
// four bytes it displaces are appended to the end
// (InterfaceElement::specialCompressLength). The client's
// specialExpandLength copies them back before decoding.
type FloodBundle struct {
	// EntityID is the Account entity's id. The client logs it as
	// "ServerConnection::createBasePlayer: id N" and addresses every
	// later client method call to it.
	EntityID uint32
	// TypeID is the Account entity's client index (1 on 2.4.x).
	TypeID uint16
	// Version is requiredVersion_2400: the build string the client
	// checks itself against ("eu_2.4.1_2").
	Version string
	// Name is the Account entity's `name` property (the account name).
	Name string
	// Incarnation is incarnationID, an opaque per-account counter.
	Incarnation uint64
	// Settings is the pickled `initialServerSettings` dict: the lobby's
	// server config. The client's ServerSettings.set() reads every key
	// with an `if key in settings` guard and falls back to its own
	// defaults, so an empty dict is valid.
	Settings []byte
	// Components is the dynamic-component count that closes the
	// element. No component data follows it; the components replicate
	// over NRL. The genuine Account carries 19.
	Components uint8
	// Frequency is updateFrequencyNotification's hertz value (10 on the
	// live capture).
	Frequency uint8
	// GameTime is updateFrequencyNotification's server game time, in
	// milliseconds.
	GameTime uint32
	// TickTag is tickSync's tag byte.
	TickTag byte
}

// Encode serialises the bundle: the leading elements, then the
// createBasePlayer element carrying the pickled settings.
func (f FloodBundle) Encode() ([]byte, error) {
	if f.Settings == nil {
		return nil, fmt.Errorf("wotlogin: flood bundle: no settings document")
	}
	if f.TypeID == 0 {
		return nil, fmt.Errorf("wotlogin: flood bundle: no entity type id")
	}
	var out []byte

	// updateFrequencyNotification (FIXED 7): frequency, an unknown u16
	// (1 in every capture), and the server game time.
	out = append(out, 0x02, f.Frequency)
	out = binary.LittleEndian.AppendUint16(out, 1)
	out = binary.LittleEndian.AppendUint32(out, f.GameTime)

	// tickSync (FIXED 1): the tag byte.
	out = append(out, 0x13, f.TickTag)

	// createBasePlayer: entity header, then the base-hosted client
	// properties in wire order.
	var body []byte
	body = binary.LittleEndian.AppendUint32(body, f.EntityID)
	body = binary.LittleEndian.AppendUint16(body, f.TypeID)
	body = append(body, 0) // the unknown blob, empty in every capture
	body = appendPacked(body, []byte(f.Version))
	body = appendPacked(body, []byte(f.Name))
	body = binary.LittleEndian.AppendUint64(body, f.Incarnation)
	body = appendPacked(body, f.Settings)
	body = append(body, f.Components)

	elem, err := element(elCreateBasePlayer, body)
	if err != nil {
		return nil, err
	}
	return append(out, elem...), nil
}

// appendPacked writes a variable-length value with the fork's length
// header: one byte, or — when the value does not fit — 0xFF followed by a
// 3-byte little-endian length.
//
// The 3-byte form is what the client's property decoder expects for an
// oversize value: the live 2.4.1 capture carries the 246 471 B settings
// pickle as `FF C7 C2 03` + pickle, and the 2.4.0 one carries its
// 209 900 B pickle as `FF EC 33 03` + pickle. Unlike the element-level
// oversize form there are no displaced bytes: the value follows the
// length directly.
func appendPacked(dst, val []byte) []byte {
	if len(val) < 0xFF {
		dst = append(dst, byte(len(val)))
		return append(dst, val...)
	}
	dst = append(dst, 0xFF, byte(len(val)), byte(len(val)>>8), byte(len(val)>>16))
	return append(dst, val...)
}

// FloodFrames splits an authored bundle into the stage-2 flood's fragment
// chain, encrypted under the session's block key.
func FloodFrames(blockKey string, stream []byte, firstSeq uint32) ([][]byte, error) {
	return BuildFrames(blockKey, stream, DefaultBulkPayload, firstSeq)
}
