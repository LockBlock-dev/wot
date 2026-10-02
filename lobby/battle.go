package lobby

import (
	"encoding/binary"
	"math"
)

// Battle (CellApp arena) client→server application messages, Sep-29
// proxy session (decryptable arena capture, crafts game EU2 — all
// shapes below verified against it; tests stay synthetic).
//
// Wire why: every C>S battle packet opens `[02][8b 58 4a]` then a
// subtype byte selecting the arg layout (`0x1a` = avatar position at
// ~18 Hz; `0x07/0x12/0x13/0x14/0x18/0x1c` other control; `0x23` a
// separate 9B family). S>C battle traffic is tick + opaque entity
// blobs (NOT lobby smalls: the apparent `1a ba` is a misparse —
// neither body- nor total-length framing fits; entity records show
// `35 00` separators and a float tail, packed formats need engine
// tables). Lengths/hashes/names/counts on screen only — positions
// are gameplay data, never logged.
const (
	// BattleC2SHead is the 4B head of every C>S battle app bundle.
	BattleC2SHead0 = 0x02
	BattleC2SHead1 = 0x8b
	BattleC2SHead2 = 0x58
	BattleC2SHead3 = 0x4a
	// BattleSubPosition selects the avatar position layout (34B
	// app in 60B UDP): 16B header block + varying u32 + static u32
	// + xyz LE f32 at [20:32] + 2B tail.
	BattleSubPosition = 0x1a
	// BattlePosOff is the xyz offset inside a position app.
	BattlePosOff = 20
	// BattlePosLen is the position app length (60B UDP shape).
	BattlePosLen = 34
)

// AvatarUpdate is one decoded client position update: LE f32 arena
// coordinates (x right, y up, z forward-ish; own tank verified
// 60/60 sane + 59/59 smooth sub-5m steps at ~18 Hz).
type AvatarUpdate struct {
	X, Y, Z float32
}

// ParseAvatarUpdate decodes the 60B/34B C>S position shape. ok=false
// for any other shape (offsets unverified there — no guessing).
func ParseAvatarUpdate(app []byte) (AvatarUpdate, bool) {
	var u AvatarUpdate
	if len(app) != BattlePosLen {
		return u, false
	}
	if app[0] != BattleC2SHead0 || app[1] != BattleC2SHead1 || app[2] != BattleC2SHead2 || app[3] != BattleC2SHead3 {
		return u, false
	}
	if app[4] != 0x93 || app[5] != BattleSubPosition {
		return u, false
	}
	u.X = math.Float32frombits(binary.LittleEndian.Uint32(app[BattlePosOff:]))
	u.Y = math.Float32frombits(binary.LittleEndian.Uint32(app[BattlePosOff+4:]))
	u.Z = math.Float32frombits(binary.LittleEndian.Uint32(app[BattlePosOff+8:]))
	if math.IsNaN(float64(u.X)) || math.IsNaN(float64(u.Y)) || math.IsNaN(float64(u.Z)) {
		return AvatarUpdate{}, false
	}
	return u, true
}
