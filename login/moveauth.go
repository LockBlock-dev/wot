package login

import (
	"encoding/binary"
	"math"
	"time"
)

// Movement authority: the client simulates its own tank and reports where it
// is, and the server accepts that — the official model. The reports are the
// base-app elements `avatarUpdateImplicit` (0x03, 17 B) and
// `avatarUpdateExplicit` (0x04, 22 B):
//
//	0x03: [position V3][direction PackedYawPitchRoll][ref u8][unk u8]
//	0x04: [vehicleID u32][position V3][direction PackedYawPitchRoll][flags u8][ref u8][unk u8]
//
// The direction is the packed yaw/pitch/roll (one byte each, the pitch over the
// half range). The server keeps the authority only for what the client cannot
// be trusted with — the map's edge and the static models — and corrects those.

const (
	// elAvatarUpdateImplicit is the client's position report without vehicle
	// context, and elAvatarUpdateExplicit the one that names it.
	elAvatarUpdateImplicit = 0x03
	elAvatarUpdateExplicit = 0x04
	// avatarUpdateImplicitLen and avatarUpdateExplicitLen are their fixed
	// sizes.
	avatarUpdateImplicitLen = 17
	avatarUpdateExplicitLen = 22
)

// parseAvatarUpdate reads one of the client's position reports from a
// post-flood datagram, if it is one.
func parseAvatarUpdate(clear []byte, key2 uint32) (pos [3]float32, yaw, pitch, roll float32, onGround, ok bool) {
	if len(clear) < 10 || clear[2] != 0x02 || binary.LittleEndian.Uint32(clear[3:7]) != key2 {
		return pos, 0, 0, 0, false, false
	}
	elem := clear[7]
	argLen := int(binary.LittleEndian.Uint16(clear[8:10]))
	body := clear[10:]
	if len(body) < argLen {
		return pos, 0, 0, 0, false, false
	}
	body = body[:argLen]
	switch {
	case elem == elAvatarUpdateImplicit && len(body) >= avatarUpdateImplicitLen:
		pos = readVec3(body[0:12])
		yaw, pitch, roll = unpackYawPitchRoll(body[12:15])
		return pos, yaw, pitch, roll, false, true
	case elem == elAvatarUpdateExplicit && len(body) >= avatarUpdateExplicitLen:
		pos = readVec3(body[4:16])
		yaw, pitch, roll = unpackYawPitchRoll(body[16:19])
		return pos, yaw, pitch, roll, body[19]&0x1 != 0, true
	}
	return pos, 0, 0, 0, false, false
}

// readVec3 reads three little-endian floats.
func readVec3(b []byte) [3]float32 {
	return [3]float32{
		math.Float32frombits(binary.LittleEndian.Uint32(b[0:4])),
		math.Float32frombits(binary.LittleEndian.Uint32(b[4:8])),
		math.Float32frombits(binary.LittleEndian.Uint32(b[8:12])),
	}
}

// unpackYawPitchRoll reads the packed direction: one byte each, the pitch over
// the half range (BigWorld's `YAWPITCHROLL_HALFPITCH`).
func unpackYawPitchRoll(b []byte) (yaw, pitch, roll float32) {
	return i8ToAngle(int8(b[0])), i8ToHalfAngle(int8(b[1])), i8ToAngle(int8(b[2]))
}

// clientMoveTimeout is how long the server trusts the client's own position
// report before it takes the hull back, in seconds: a client that stopped
// reporting (a lost connection, or one that never had control) is driven by
// the server again.
const clientMoveTimeout = 500 * time.Millisecond

// acceptClientMove takes the client's own report of where its tank is. The
// server keeps only the checks the client cannot be trusted with — the map's
// edge and the static models — applied as corrections in the tick.
func (s *BaseAppServer) acceptClientMove(st *clientState, pos [3]float32, yaw, pitch, roll float32, onGround bool) {
	if st == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st.hull.Position = pos
	st.hull.Direction = [3]float32{roll, pitch, yaw}
	st.hull.Airborne = !onGround
	if onGround {
		st.hull.VerticalVelocity = 0
	}
	st.clientMoveAt = time.Now()
}
