package lobby

import (
	"encoding/binary"
	"math"
)

// Battle (CellApp arena) client→server application messages, Sep-29
// proxy session (decryptable arena capture, crafts game EU2 — all
// shapes below verified against it; tests stay synthetic).
//
// Wire why: every C>S battle packet opens `[02][8b 58 4a]` then
// `[93][SUB]` selecting the Avatar cell method (SUB = own-cell index
// into Avatar.def order: 0x1a=26 vehicle_moveWith, 0x18=24
// reportClientStats, 0x07=7 discloseEntities(var-length array),
// 0x12=18 grantRagePoints, 0x06=6 forbidUnbindingFromVehicle,
// 0x10=16 setEquipmentApplicationPoint, 0x1c=28
// vehicle_trackWorldPointWithGun, 0x1d=29
// vehicle_trackRelativePointWithGun — 7214/7214 battle packets
// decrypt with the token2-login key and frame this way; method names
// are hypothesis-graded in ParseMoveWith docs, only 0x1a is CLOSED).
// Every position-carrying call ends with the trailer `[1a][1a00]
// [entity u32, battle-constant 0x20529314 here][payload][2B tail]`:
// standalone 0x1a carries only the trailer; other SUBs prepend their
// method args (e.g. 0x07/44 = 10B disclose head + 28B trailer).
// S>C battle traffic is tick + opaque entity blobs (NOT lobby smalls:
// the apparent `1a ba` is a misparse — neither body- nor
// total-length framing fits; snapshots are 276/292B alternating with
// 13B `[35 00][11B]` records per §14). Lengths/hashes/names/counts on
// screen only — positions are gameplay data, never logged.
const (
	// BattleC2SHead is the 4B head of every C>S battle app bundle.
	BattleC2SHead0 = 0x02
	BattleC2SHead1 = 0x8b
	BattleC2SHead2 = 0x58
	BattleC2SHead3 = 0x4a
	// BattleFamily tags Avatar cell calls (cf. lobby A1 tags).
	BattleFamily = 0x93
	// Battle SUBs (Avatar own-cell indices; see above for grading).
	BattleSubMoveWith      = 0x1a // 26 vehicle_moveWith(UINT8): CLOSED
	BattleSubReportStats   = 0x18 // 24 reportClientStats(6×f32): medium
	BattleSubDisclose      = 0x07 // 7 discloseEntities(Array): medium
	BattleSubRagePoints    = 0x12 // 18 grantRagePoints(U8,F32): weak
	BattleSubForbidUnbind  = 0x06 // 6 forbidUnbindingFromVehicle(I8): weak
	BattleSubEquipPoint    = 0x10 // 16 setEquipmentApplicationPoint: weak
	BattleSubTrackWorld    = 0x1c // 28 trackWorldPointWithGun(V3): medium
	BattleSubTrackRelative = 0x1d // 29 trackRelativePointWithGun(V3): medium
	// BattleTrailerTag opens the position trailer ending every
	// position-carrying call.
	BattleTrailerTag = 0x1a
	// BattlePosOff is the xyz offset inside a position app.
	BattlePosOff = 20
	// BattlePosLen is the position app length (60B UDP shape).
	BattlePosLen = 34
	// BattleMoveEntityOff is the entity-marker offset (u32 LE).
	BattleMoveEntityOff = 8
	// BattleMoveSpeedOff is the speed offset (f32 LE, ~7.14 cruise).
	BattleMoveSpeedOff = 16
)

// AvatarUpdate is one decoded client position update: LE f32 arena
// coordinates (x right, y up, z forward-ish; own tank verified
// 60/60 sane + 59/59 smooth sub-5m steps at ~18 Hz).
type AvatarUpdate struct {
	X, Y, Z float32
}

// MoveWith is a decoded 0x1a vehicle_moveWith call (34B app):
// `[02 8b 58 4a][93][1a][1a00][entity u32][F1 u32][speed f32]
// [xyz 3×f32][tail 2B]`. Entity is battle-constant (0x20529314 in
// the Sep-29 session — own-avatar marker, not yet proven to be the
// BW entity ID); F1 varies per packet (semantics open: not yaw —
// unwrapped values ±500k f32 — candidates: flags+pad, tick, or
// yawRate in a packed form); Speed reads 7.14 at cruise; Tail is
// 1900 modally but varies. Column-stability over 2535 samples:
// [0:13] constant, xyz smooth (median step 0.58 m).
type MoveWith struct {
	Entity uint32
	F1     uint32
	Speed  float32
	AvatarUpdate
	Tail [2]byte
}

// ParseMoveWith decodes the 34B C>S moveWith shape. ok=false for any
// other shape (offsets unverified there — no guessing).
func ParseMoveWith(app []byte) (MoveWith, bool) {
	var m MoveWith
	if len(app) != BattlePosLen {
		return m, false
	}
	if app[0] != BattleC2SHead0 || app[1] != BattleC2SHead1 || app[2] != BattleC2SHead2 || app[3] != BattleC2SHead3 {
		return m, false
	}
	if app[4] != BattleFamily || app[5] != BattleSubMoveWith {
		return m, false
	}
	if app[6] != 0x1a || app[7] != 0x00 {
		return m, false
	}
	m.Entity = binary.LittleEndian.Uint32(app[BattleMoveEntityOff:])
	m.F1 = binary.LittleEndian.Uint32(app[12:16])
	m.Speed = math.Float32frombits(binary.LittleEndian.Uint32(app[BattleMoveSpeedOff:]))
	u, ok := ParseAvatarUpdate(app)
	if !ok {
		return MoveWith{}, false
	}
	m.AvatarUpdate = u
	copy(m.Tail[:], app[32:34])
	return m, true
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
	if app[4] != BattleFamily || app[5] != BattleSubMoveWith {
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
