package login

import (
	"encoding/binary"
	"fmt"
	"math"
)

// The client's element table, and the builders for the elements this server
// can send.
//
// The table is the whole of `ClientInterface`'s server-to-client message set,
// 0x00..0x4D: every id, its name, and how its payload is framed (a fixed size,
// or a 16-bit length). Ported from the reference's
// `wg-toolkit/src/app/client/element.rs`, whose lengths are pinned against the
// client's own length function.
//
// The elements this server sends have their own builders elsewhere
// (`EncodeCreateEntity`, `EncodeEnterAoI`, …); this file adds the ones it did
// not have, and the generic framing so any of them can be emitted and checked.

// elementLength is how an element's payload is framed.
type elementLength struct {
	// Fixed is the payload's size, or -1 when the element carries a 16-bit
	// length header.
	Fixed int
}

// varElement is the marker for a variable-length element.
var varElement = elementLength{Fixed: -1}

func fixedElement(n int) elementLength { return elementLength{Fixed: n} }

// clientElement is one element of the client's table.
type clientElement struct {
	ID     uint8
	Name   string
	Length elementLength
}

// clientElements is the client's server-to-client table, in id order.
var clientElements = []clientElement{
	{0x00, "authenticate", fixedElement(4)},
	{0x01, "bandwidthNotification", fixedElement(4)},
	{0x02, "updateFrequencyNotification", fixedElement(7)},
	{0x03, "setGameTime", fixedElement(4)},
	{0x04, "resetEntities", fixedElement(1)},
	{0x05, "createBasePlayer", varElement},
	{0x06, "createCellPlayer", varElement},
	{0x07, "dummyPacket", varElement},
	{0x08, "spaceProperty", varElement},
	{0x09, "addSpaceGeometryMapping", varElement},
	{0x0A, "removeSpaceGeometryMapping", varElement},
	{0x0B, "createEntity", varElement},
	{0x0C, "createEntityDetailed", varElement},
	{0x0D, "cellAppSuspended", fixedElement(0)},
	{0x0E, "cellAppResumed", fixedElement(0)},
	{0x0F, "clientSuspensionDetectionEnabled", fixedElement(4)},
	{0x10, "enterAoI", fixedElement(5)},
	{0x11, "enterAoIOnVehicle", fixedElement(9)},
	{0x12, "leaveAoI", varElement},
	{0x13, "tickSync", fixedElement(1)},
	{0x14, "tickSyncPeriodic", fixedElement(2)},
	{0x15, "relativePositionReference", fixedElement(1)},
	{0x16, "relativePosition", fixedElement(12)},
	{0x17, "setVehicle", fixedElement(8)},
	{0x18, "selectAliasedEntity", fixedElement(1)},
	{0x19, "selectEntity", fixedElement(4)},
	{0x1A, "selectPlayerEntity", fixedElement(0)},
	{0x1B, "forcedPosition", fixedElement(38)},
	{0x1C, "avatarUpdateNoAliasDetailed", fixedElement(29)},
	{0x1D, "avatarUpdateAliasDetailed", fixedElement(26)},
	{0x1E, "avatarUpdatePlayerDetailed", fixedElement(25)},
	{0x1F, "avatarUpdateVolatileProperties", varElement},
	{0x20, "changeVolatilePackerType", varElement},
	{0x21, "nrlCreateNode", varElement},
	{0x22, "nrlUnlinkTree", varElement},
	{0x23, "nrlUpdateNode", varElement},
	{0x24, "nrlUnlinkTreeFlag", fixedElement(0)},
	{0x25, "nrlUpdateNodeFlag", fixedElement(0)},
	{0x26, "nrlData", varElement},
	{0x27, "nrlMsgToClient", varElement},
	{0x28, "nrlUnreliableMsgToClient", varElement},
	{0x29, "avatarUpdateNoAliasFullPosYawPitchRoll", fixedElement(15)},
	{0x2A, "avatarUpdateNoAliasFullPosYawPitch", fixedElement(13)},
	{0x2B, "avatarUpdateNoAliasFullPosYaw", fixedElement(12)},
	{0x2C, "avatarUpdateNoAliasFullPosNoDir", fixedElement(11)},
	{0x2D, "avatarUpdateNoAliasOnGroundYawPitchRoll", fixedElement(12)},
	{0x2E, "avatarUpdateNoAliasOnGroundYawPitch", fixedElement(10)},
	{0x2F, "avatarUpdateNoAliasOnGroundYaw", fixedElement(9)},
	{0x30, "avatarUpdateNoAliasOnGroundNoDir", fixedElement(8)},
	{0x31, "avatarUpdateNoAliasNoPosYawPitchRoll", fixedElement(9)},
	{0x32, "avatarUpdateNoAliasNoPosYawPitch", fixedElement(7)},
	{0x33, "avatarUpdateNoAliasNoPosYaw", fixedElement(6)},
	{0x34, "avatarUpdateNoAliasNoPosNoDir", fixedElement(5)},
	{0x35, "avatarUpdateAliasFullPosYawPitchRoll", fixedElement(12)},
	{0x36, "avatarUpdateAliasFullPosYawPitch", fixedElement(10)},
	{0x37, "avatarUpdateAliasFullPosYaw", fixedElement(9)},
	{0x38, "avatarUpdateAliasFullPosNoDir", fixedElement(8)},
	{0x39, "avatarUpdateAliasOnGroundYawPitchRoll", fixedElement(9)},
	{0x3A, "avatarUpdateAliasOnGroundYawPitch", fixedElement(7)},
	{0x3B, "avatarUpdateAliasOnGroundYaw", fixedElement(6)},
	{0x3C, "avatarUpdateAliasOnGroundNoDir", fixedElement(5)},
	{0x3D, "avatarUpdateAliasNoPosYawPitchRoll", fixedElement(6)},
	{0x3E, "avatarUpdateAliasNoPosYawPitch", fixedElement(4)},
	{0x3F, "avatarUpdateAliasNoPosYaw", fixedElement(3)},
	{0x40, "avatarUpdateAliasNoPosNoDir", fixedElement(2)},
	{0x41, "controlEntity", fixedElement(5)},
	{0x42, "voiceData", varElement},
	{0x43, "restoreClient", varElement},
	{0x44, "switchBaseApp", fixedElement(9)},
	{0x45, "resourceHeader", varElement},
	{0x46, "resourceFragment", varElement},
	{0x47, "loggedOff", fixedElement(1)},
	{0x48, "detailedPosition", fixedElement(24)},
	{0x49, "nestedEntityProperty", varElement},
	{0x4A, "sliceEntityProperty", varElement},
	{0x4B, "updateEntity", varElement},
	{0x4C, "setCellAppExtAddress", varElement},
	{0x4D, "lastProxyMessageAfterDirectCellAppConnection", fixedElement(0)},
}

// clientElementByID is the table by id.
var clientElementByID = func() map[uint8]clientElement {
	m := make(map[uint8]clientElement, len(clientElements))
	for _, e := range clientElements {
		m[e.ID] = e
	}
	return m
}()

// ClientElementName is the element's name, or "".
func ClientElementName(id uint8) string { return clientElementByID[id].Name }

// EncodeElement frames one element: `[id][payload]` for a fixed one,
// `[id][len u16][payload]` for a variable one.
func EncodeElement(id uint8, body []byte) ([]byte, error) {
	spec, ok := clientElementByID[id]
	if !ok {
		return nil, fmt.Errorf("wotlogin: element %#02x is not in the client's table", id)
	}
	if spec.Length.Fixed >= 0 {
		if len(body) != spec.Length.Fixed {
			return nil, fmt.Errorf("wotlogin: element %#02x (%s) is fixed %d B, got %d",
				id, spec.Name, spec.Length.Fixed, len(body))
		}
		return append([]byte{id}, body...), nil
	}
	return appendElement(nil, id, 2, body)
}

// DecodeElement consumes one element from an app: its id, its body, and the
// bytes after it. It fails when the element is not in the table or its body
// runs past the end.
func DecodeElement(app []byte) (id uint8, body, rest []byte, err error) {
	if len(app) < 1 {
		return 0, nil, nil, fmt.Errorf("wotlogin: element: empty")
	}
	id = app[0]
	spec, ok := clientElementByID[id]
	if !ok {
		return 0, nil, nil, fmt.Errorf("wotlogin: element %#02x is not in the client's table", id)
	}
	off := 1
	n := spec.Length.Fixed
	if n < 0 {
		if len(app) < 3 {
			return 0, nil, nil, fmt.Errorf("wotlogin: element %#02x (%s): no length", id, spec.Name)
		}
		n = int(binary.LittleEndian.Uint16(app[1:3]))
		off = 3
	}
	if off+n > len(app) {
		return 0, nil, nil, fmt.Errorf("wotlogin: element %#02x (%s): wants %d B, %d left",
			id, spec.Name, n, len(app)-off)
	}
	return id, app[off : off+n], app[off+n:], nil
}

// --- The missing elements' builders. ---

// EncodeBandwidthNotification is the server's bandwidth estimate, in bytes per
// second.
func EncodeBandwidthNotification(bps uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], bps)
	return append([]byte{elBandwidthNotification}, b[:]...)
}

// EncodeSetGameTime is the server's game time, in seconds.
func EncodeSetGameTime(gameTime uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], gameTime)
	return append([]byte{elSetGameTime}, b[:]...)
}

// EncodeDummyPacket is a packet the client ignores: it exists so a bundle can
// be padded.
func EncodeDummyPacket(body []byte) ([]byte, error) {
	return EncodeElement(elDummyPacket, body)
}

// EncodeRemoveSpaceGeometryMapping takes a geometry mapping back out.
func EncodeRemoveSpaceGeometryMapping(spaceID uint32, key string) ([]byte, error) {
	var body []byte
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], spaceID)
	body = append(body, b[:]...)
	body = append(body, byte(len(key)))
	body = append(body, key...)
	return EncodeElement(elRemoveSpaceGeometryMapping, body)
}

// EncodeCellAppSuspended and EncodeCellAppResumed bracket a cell-app failover.
func EncodeCellAppSuspended() []byte { return []byte{elCellAppSuspended} }
func EncodeCellAppResumed() []byte   { return []byte{elCellAppResumed} }

// EncodeClientSuspensionDetectionEnabled turns the client's suspension
// detection on or off.
func EncodeClientSuspensionDetectionEnabled(enabled bool) []byte {
	var b [4]byte
	if enabled {
		binary.LittleEndian.PutUint32(b[:], 1)
	}
	return append([]byte{elClientSuspensionDetectionEnabled}, b[:]...)
}

// EncodeTickSyncPeriodic is the periodic form of the tick.
func EncodeTickSyncPeriodic(a, b byte) []byte {
	return []byte{elTickSyncPeriodic, a, b}
}

// EncodeRelativePositionReference sets the reference position's sequence
// number: the relative updates that follow are measured from it.
func EncodeRelativePositionReference(seq uint8) []byte {
	return []byte{elRelativePositionReference, seq}
}

// EncodeSelectAliasedEntity selects an entity by its AoI alias.
func EncodeSelectAliasedEntity(alias uint8) []byte {
	return []byte{elSelectAliasedEntity, alias}
}

// EncodeAvatarUpdate builds the smallest `AVATAR_UPDATE_*` element that carries
// the fields given: the alias form when alias is non-nil, the full position
// when pos is non-nil, and yaw/pitch/roll as far as dir is non-nil (one, two or
// three components).
//
// The layout is the reference's: `ref_num u8`, then the entity id (u32) or the
// alias (u8), the packed position (6 B full, 3 B on-ground), the packed
// direction (1 B yaw, 2 B yaw+pitch, 3 B yaw+pitch+roll), and one opaque byte
// for the yaw/pitch/roll form.
func EncodeAvatarUpdate(refNum uint8, entityID uint32, alias *uint8, pos *[3]float32, dir *[3]float32, dirComponents int, xzScale float32) ([]byte, error) {
	if pos == nil && (dir == nil || dirComponents <= 0) {
		return nil, fmt.Errorf("wotlogin: avatar update carries neither a position nor a direction")
	}
	if dirComponents < 0 || dirComponents > 3 {
		return nil, fmt.Errorf("wotlogin: avatar update direction has %d components", dirComponents)
	}
	hasAlias := alias != nil
	posKind := -1 // 0 full, 1 on-ground
	if pos != nil {
		posKind = 0
	}
	dirKind := -1 // 0 yaw, 1 yaw+pitch, 2 yaw+pitch+roll
	if dir != nil && dirComponents > 0 {
		dirKind = dirComponents - 1
	}
	// The variant id: each (alias, position) group runs ypr, yaw+pitch, yaw,
	// no-direction, so the base minus the direction kind names it.
	var base uint8
	switch {
	case !hasAlias && posKind == 0:
		base = 0x29
	case !hasAlias && posKind == 1:
		base = 0x2D
	case !hasAlias:
		base = 0x31
	case posKind == 0:
		base = 0x35
	case posKind == 1:
		base = 0x39
	default:
		base = 0x3D
	}
	id := base + uint8(2-dirKind)
	body := []byte{refNum}
	if hasAlias {
		body = append(body, *alias)
	} else {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], entityID)
		body = append(body, b[:]...)
	}
	if pos != nil {
		if posKind == 0 {
			body = append(body, packXyz(*pos, xzScale)...)
		} else {
			body = append(body, packXz(pos[0], pos[2], xzScale)...)
		}
	}
	if dir != nil {
		switch dirKind {
		case 0:
			body = append(body, packYaw(dir[0])...)
		case 1:
			body = append(body, packYawPitch(dir[0], dir[1])...)
		default:
			body = append(body, packAvatarYawPitchRoll(dir[0], dir[1], dir[2], true)...)
			body = append(body, 0) // the opaque trailing byte of the ypr form
		}
	}
	return EncodeElement(id, body)
}

// EncodeAvatarUpdateVolatileProperties carries an entity's volatile properties
// (the position and direction fields the `AVATAR_UPDATE_*` family otherwise
// carries).
func EncodeAvatarUpdateVolatileProperties(body []byte) ([]byte, error) {
	return EncodeElement(elAvatarUpdateVolatileProperties, body)
}

// EncodeChangeVolatilePackerType names the packer the volatile fields use.
func EncodeChangeVolatilePackerType(name string) ([]byte, error) {
	body := append([]byte{byte(len(name))}, name...)
	return EncodeElement(elChangeVolatilePackerType, body)
}

// EncodeNrlMsgToClient and EncodeNrlUnreliableMsgToClient carry an NRL message
// stream to the client.
func EncodeNrlMsgToClient(stream []byte) ([]byte, error) {
	return EncodeElement(elNrlMsgToClient, stream)
}

func EncodeNrlUnreliableMsgToClient(stream []byte) ([]byte, error) {
	return EncodeElement(elNrlUnreliableMsgToClient, stream)
}

// EncodeVoiceData carries voice-chat audio.
func EncodeVoiceData(body []byte) ([]byte, error) {
	return EncodeElement(elVoiceData, body)
}

// EncodeRestoreClient tells the client to restore its state after the server
// moved or recovered it.
func EncodeRestoreClient(body []byte) ([]byte, error) {
	return EncodeElement(elRestoreClient, body)
}

// EncodeResourceHeader announces a resource stream: its id and a description.
func EncodeResourceHeader(id uint16, description []byte) ([]byte, error) {
	var body []byte
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], id)
	body = append(body, b[:]...)
	body = append(body, byte(len(description)))
	body = append(body, description...)
	return EncodeElement(elResourceHeader, body)
}

// EncodeResourceFragment is one piece of a resource stream.
func EncodeResourceFragment(id uint16, seq uint8, last bool, data []byte) ([]byte, error) {
	var body []byte
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], id)
	body = append(body, b[:]...)
	body = append(body, seq)
	if last {
		body = append(body, 1)
	} else {
		body = append(body, 0)
	}
	body = append(body, data...)
	return EncodeElement(elResourceFragment, body)
}

// EncodeLoggedOff tells the client the server is closing the session, with the
// reason.
func EncodeLoggedOff(reason uint8) []byte {
	return []byte{elLoggedOff, reason}
}

// EncodeDetailedPosition is an accurate correction on top of the
// `AVATAR_UPDATE_*` stream, for the selected entity.
func EncodeDetailedPosition(pos, dir [3]float32) []byte {
	body := make([]byte, 0, 24)
	for _, v := range pos {
		body = appendF32(body, v)
	}
	for _, v := range dir {
		body = appendF32(body, v)
	}
	return append([]byte{elDetailedPosition}, body...)
}

// EncodeNestedEntityProperty and EncodeSliceEntityProperty are the standalone
// forms of a nested or sliced property change (the `updateEntity` run carries
// the same records).
func EncodeNestedEntityProperty(body []byte) ([]byte, error) {
	return EncodeElement(elNestedEntityProperty, body)
}

func EncodeSliceEntityProperty(body []byte) ([]byte, error) {
	return EncodeElement(elSliceEntityProperty, body)
}

// EncodeSetCellAppExtAddress is the CellApp's externally reachable address:
// `[ip4][port BE][salt u16 LE]`.
func EncodeSetCellAppExtAddress(ip [4]byte, port uint16, salt uint16) ([]byte, error) {
	var body []byte
	body = append(body, ip[:]...)
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], port)
	body = append(body, b[:]...)
	binary.LittleEndian.PutUint16(b[:], salt)
	body = append(body, b[:]...)
	return EncodeElement(elSetCellAppExtAddress, body)
}

// EncodeLastProxyMessage is the last message relayed through the BaseApp proxy
// before the client talks to the CellApp directly.
func EncodeLastProxyMessage() []byte {
	return []byte{elLastProxyMessage}
}

// --- BigWorld's packed position and direction codecs. ---

// The packed position's bit counts, from the client binary (see the
// reference's `app/math.rs`): 4 exponent + 12 mantissa bits for x and z, 4 + 9
// for y, which is 48 bits = 6 bytes.
const (
	exponentBitsXZ = 4
	xyzMantissaXZ  = 12
	xyzExponentY   = 4
	xyzMantissaY   = 9
	xzMantissaXZ   = 7
)

// packFloat is BigWorld's `packFloat<EXPONENT_BITS, MANTISSA_BITS>`: a sign
// bit, a biased exponent, then a rounded mantissa.
func packFloat(w *bitWriter, value float32, exponentBits, mantissaBits int) {
	maxMantissa := uint32(1)<<uint(mantissaBits) - 1
	w.add(1, math.Float32bits(value)>>31)
	bits := math.Float32bits(value + float32(2.0))
	if value < 0 {
		bits = math.Float32bits(-value + 2.0)
	}
	exponent := (bits >> 23) & 0xFF
	if exponent >= 128 {
		exponent -= 128
	} else {
		exponent = 0
	}
	mantissaRaw := bits & 0x007FFFFF
	mantissa := mantissaRaw >> (23 - mantissaBits)
	nextBit := (mantissaRaw >> (22 - mantissaBits)) & 1
	if nextBit == 1 {
		if mantissa != maxMantissa {
			mantissa++
		} else {
			exponent++
		}
	}
	w.add(exponentBits, exponent)
	w.add(mantissaBits, mantissa)
}

// bitReader reads the same MSB-first order back.
type bitReader struct {
	buf  []byte
	bits int
}

func (r *bitReader) get(n int) uint32 {
	var v uint32
	for i := 0; i < n; i++ {
		bit := uint32(0)
		if r.bits/8 < len(r.buf) {
			bit = uint32(r.buf[r.bits/8]>>uint(7-r.bits%8)) & 1
		}
		v = v<<1 | bit
		r.bits++
	}
	return v
}

// unpackFloat is the inverse.
func unpackFloat(r *bitReader, exponentBits, mantissaBits int) float32 {
	sign := r.get(1) << 31
	bits := (r.get(exponentBits) | 0x80) << 23
	bits |= r.get(mantissaBits) << uint(23-mantissaBits)
	value := math.Float32frombits(bits) - 2.0
	return math.Float32frombits(math.Float32bits(value) | sign)
}

// packXyz packs a position offset into the 6-byte full form.
func packXyz(offset [3]float32, xzScale float32) []byte {
	if xzScale == 0 {
		xzScale = 1
	}
	w := &bitWriter{}
	packFloat(w, offset[0]/xzScale, exponentBitsXZ, xyzMantissaXZ)
	packFloat(w, offset[2]/xzScale, exponentBitsXZ, xyzMantissaXZ)
	packFloat(w, offset[1], xyzExponentY, xyzMantissaY)
	return w.buf
}

// packXz packs the on-ground form (3 bytes).
func packXz(dx, dz, xzScale float32) []byte {
	if xzScale == 0 {
		xzScale = 1
	}
	w := &bitWriter{}
	packFloat(w, dx/xzScale, exponentBitsXZ, xzMantissaXZ)
	packFloat(w, dz/xzScale, exponentBitsXZ, xzMantissaXZ)
	return w.buf
}

// unpackXyz is the inverse of packXyz.
func unpackXyz(b []byte, xzScale float32) [3]float32 {
	r := &bitReader{buf: b}
	x := unpackFloat(r, exponentBitsXZ, xyzMantissaXZ) * xzScale
	z := unpackFloat(r, exponentBitsXZ, xyzMantissaXZ) * xzScale
	y := unpackFloat(r, xyzExponentY, xyzMantissaY)
	return [3]float32{x, y, z}
}

// angleToI8 packs an angle over [-pi, pi) into one signed byte.
func angleToI8(angle float32) int8 {
	return int8(int32(math.Floor(float64(angle)*128/math.Pi + 0.5)))
}

func i8ToAngle(b int8) float32 { return float32(b) * (math.Pi / 128) }

// halfAngleToI8 packs an angle over [-pi/2, pi/2) into one signed byte.
func halfAngleToI8(angle float32) int8 {
	v := math.Floor(float64(angle)*254/math.Pi + 0.5)
	if v < -128 {
		v = -128
	}
	if v > 127 {
		v = 127
	}
	return int8(int32(v))
}

func i8ToHalfAngle(b int8) float32 { return float32(b) * (math.Pi / 254) }

func packYaw(yaw float32) []byte { return []byte{byte(angleToI8(yaw))} }

func packYawPitch(yaw, pitch float32) []byte {
	return []byte{byte(angleToI8(yaw)), byte(angleToI8(pitch))}
}

func packAvatarYawPitchRoll(yaw, pitch, roll float32, halfPitch bool) []byte {
	p := angleToI8(pitch)
	if halfPitch {
		p = halfAngleToI8(pitch)
	}
	return []byte{byte(angleToI8(yaw)), byte(p), byte(angleToI8(roll))}
}

// The element ids this file's builders use, named once.
const (
	elBandwidthNotification            = 0x01
	elSetGameTime                      = 0x03
	elDummyPacket                      = 0x07
	elRemoveSpaceGeometryMapping       = 0x0A
	elCellAppSuspended                 = 0x0D
	elCellAppResumed                   = 0x0E
	elClientSuspensionDetectionEnabled = 0x0F
	elTickSyncPeriodic                 = 0x14
	elRelativePositionReference        = 0x15
	elSelectAliasedEntity              = 0x18
	elAvatarUpdateVolatileProperties   = 0x1F
	elChangeVolatilePackerType         = 0x20
	elNrlMsgToClient                   = 0x27
	elNrlUnreliableMsgToClient         = 0x28
	elVoiceData                        = 0x42
	elRestoreClient                    = 0x43
	elResourceHeader                   = 0x45
	elResourceFragment                 = 0x46
	elLoggedOff                        = 0x47
	elDetailedPosition                 = 0x48
	elNestedEntityProperty             = 0x49
	elSliceEntityProperty              = 0x4A
	elSetCellAppExtAddress             = 0x4C
	elLastProxyMessage                 = 0x4D
)
