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
// Mercury messages, each length-prefixed: `[0x93][SUB][len16le]
// [args]` (base-routed Avatar cell call; SUB = Avatar own-cell doc
// index, interfaces excluded — 0x1a=26 moveWith (position smooth-track
// proven), 0x1d=29 trackRelative (relative-scale V3 proven), rest by
// shape/count: 0x18=24 reportClientStats, 0x07=7 discloseEntities,
// 0x12=18 grantRagePoints, 0x06=6 forbidUnbindingFromVehicle, 0x10=16
// setEquipmentApplicationPoint, 0x1c=28 trackWorldPointWithGun; IDA
// tables confirm the messaging layer beneath)
// and `[0x1a][len16le][26B position block]` (len always 26: entity +
// nonce + speed + xyz + tail; 3357/3357 exact). A standalone 0x1a
// bundle is one [93][1a][len 26][26B] message; other SUBs prepend
// their method args and usually append the position message (e.g.
// 0x07/44 = [93][07][len 7][7B] + [1a][len 26][29B]). Longer bundles
// (63B+) carry extra implicitly-framed records between args and
// trailer (per-SUB sizes open). vehicle_shoot is statically 0x1b
// (own[27]) and never appears in 7313 bundles.
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
	// BattleTrailerLen is the fixed trailer length: [1a][1a00]
	// [entity u32][nonce u32][speed f32][xyz 3×f32][tail 2B] = 29B.
	// Verified by marker-index linearity over 0x07 lens
	// (44→15, 52→23, 63→34, …, 383→354: trailer = len−marker = 29
	// every time) and trailer singularity (7179/7313 bundles carry
	// exactly one; 134 bare calls carry none).
	BattleTrailerLen = 29
	// BattleRecord07Len is the 0x07 companion record length:
	// [07][9B args incl. u8 sequence XX]. It rides standalone
	// (0x07-led bundles) and inside 0x18/0x12/0x06-led bundles —
	// lead-SUB census undercounts it. XX wraps mod 256 (~12 wraps
	// over 3019 records: packet sequence, not entity IDs).
	// Content is near-constant (only XX + one variant byte vary),
	// so 0x07 is ack/heartbeat-like, NOT discloseEntities (the 6B
	// element stride is refuted: head diffs 8,12,15,19,27,35).
	BattleRecord07Len = 10
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
// `[02 8b 58 4a][93][1a][1a00][entity u32][nonce u32][speed f32]
// [xyz 3×f32][tail 2B]`. Entity is battle-constant (0x20529314 in
// the Sep-29 session — own-avatar marker, not yet proven to be the
// BW entity ID); Nonce is per-packet uniform-random (distinct=n,
// halves uniform, lag-1 ≈ −0.17, zero correlation with turn rate —
// freshness, since the head is constant); Speed reads 7.15 at cruise;
// Tail is 1900 modally but varies. Column-stability over 2535 samples:
// [0:13] constant, xyz smooth (median step 0.58 m).
type MoveWith struct {
	Entity uint32
	Nonce  uint32
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
	m.Nonce = binary.LittleEndian.Uint32(app[12:16])
	m.Speed = math.Float32frombits(binary.LittleEndian.Uint32(app[BattleMoveSpeedOff:]))
	u, ok := ParseAvatarUpdate(app)
	if !ok {
		return MoveWith{}, false
	}
	m.AvatarUpdate = u
	copy(m.Tail[:], app[32:34])
	return m, true
}

// Trailer is the 29B position trailer ending every position-carrying
// battle bundle: `[1a][1a00][entity u32][nonce u32][speed f32]
// [xyz 3×f32][tail 2B]`. Nested xyz tracks own motion exactly like
// standalone (ranges and median steps match per class), so one parser
// serves all SUBs.
type Trailer struct {
	Entity uint32
	Nonce  uint32
	Speed  float32
	AvatarUpdate
	Tail [2]byte
}

// ParseTrailer decodes the trailer at the end of app (any length ≥
// head+record+trailer). ok=false when the marker is absent (bare
// calls: 07/15 and rare tiny event-like SUBs carry none).
func ParseTrailer(app []byte) (Trailer, bool) {
	var tr Trailer
	if len(app) < 5+1+BattleTrailerLen {
		return tr, false
	}
	t := app[len(app)-BattleTrailerLen:]
	if t[0] != BattleTrailerTag || t[1] != 0x1a || t[2] != 0x00 {
		return tr, false
	}
	tr.Entity = binary.LittleEndian.Uint32(t[3:7])
	tr.Nonce = binary.LittleEndian.Uint32(t[7:11])
	tr.Speed = math.Float32frombits(binary.LittleEndian.Uint32(t[11:15]))
	tr.X = math.Float32frombits(binary.LittleEndian.Uint32(t[15:19]))
	tr.Y = math.Float32frombits(binary.LittleEndian.Uint32(t[19:23]))
	tr.Z = math.Float32frombits(binary.LittleEndian.Uint32(t[23:27]))
	if math.IsNaN(float64(tr.X)) || math.IsNaN(float64(tr.Y)) || math.IsNaN(float64(tr.Z)) {
		return Trailer{}, false
	}
	copy(tr.Tail[:], t[27:29])
	return tr, true
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
