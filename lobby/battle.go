package lobby

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Battle (CellApp arena) client→server application messages, Sep-29
// proxy session (decryptable arena capture, crafts game EU2 — all
// shapes below verified against it; tests stay synthetic).
//
// Wire why: every C>S battle packet opens `[02][8b 58 4a]` then
// Mercury messages, each length-prefixed: `[0x93][SUB][len16le]
// [args]` (base-routed Avatar cell call; SUB = Avatar own-cell doc
// index for the mapped methods (interfaces excluded), except the shoot
// trigger (wire 0x10 ≠ doc 0x1b — see BattleSubShoot); 0x1a=26 moveWith (position smooth-track
// proven), 0x1d=29 trackRelative (relative-scale V3 proven), rest by
// shape/count: 0x18=24 reportClientStats, 0x07=7 discloseEntities,
// 0x12=18 grantRagePoints, 0x06=6 forbidUnbindingFromVehicle, 0x10=16
// shoot trigger (CLOSED, see BattleSubShoot — not doc-order 0x1b),
// 0x1c=28 trackWorldPointWithGun; IDA
// tables confirm the messaging layer beneath)
// and `[0x1a][len16le][26B position block]` (len always 26: entity +
// nonce + speed + xyz + tail; 3357/3357 exact). A standalone 0x1a
// bundle is one [93][1a][len 26][26B] message; other SUBs prepend
// their method args and usually append the position message (e.g.
// 0x07/44 = [93][07][len 7][7B] + [1a][len 26][29B]). Longer bundles
// (63B+) carry extra implicitly-framed records between args and
// trailer (per-SUB sizes open). The shoot trigger is wire SUB 0x10
// ([93][10][len 4][00000000], standalone or chained inner — 9/9 own
// shots 60–140 ms pre-tracer, zero baseline; behaviorally
// vehicle_shoot(), the only cell call in the decompiled Avatar.shoot
// path; the doc index (own[27]) and 0x1b never appear on wire).
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
	BattleSubTrackWorld    = 0x1c // 28 trackWorldPointWithGun(V3): medium
	BattleSubTrackRelative = 0x1d // 29 trackRelativePointWithGun(V3): medium
	// BattleSubShoot is the C>S shoot trigger SUB. It is NOT the doc
	// index (own[27] vehicle_shoot; 0x1b never appears on wire over
	// 7323 C>S despite 9 confirmed shots). Wire truth (Sep-29 Sweden,
	// 9/9 own tracers paired 60–140 ms later, zero occurrences
	// elsewhere in the battle): a [10][len 4][00000000] record, either
	// standalone-outer (0x10-led bundles) or chained-inner (inside
	// 07/18-led bundles). Behaviorally vehicle_shoot(): the decompiled
	// Avatar.shoot (Avatar.pyc) calls self.cell.vehicle_shoot() with no
	// args and no accompanying cell call, and no other client code
	// references vehicle_shoot; the only other 0x10 candidate
	// (setEquipmentApplicationPoint, whose callers live in
	// CombatEquipmentManager/MapCaseMode, single-use consumables with
	// varying args) cannot produce 9 identical zero-arg records at
	// exact pre-shot latency. The 4 zero bytes vs the defs' 0-arg
	// signature is recorded as build-specific framing, not smoothed
	// over; the index mismatch (16 vs 27) is open statically.
	BattleSubShoot = 0x10
	// BattleShootArgsLen is the trigger record's fixed arg length: 4
	// zero bytes (9/9 identical on wire).
	BattleShootArgsLen = 4
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
// the Sep-29 session — the recorder's own entity: battle-start head,
// S>C tracer a0 and this field all agree on 542282516); Nonce is per-packet uniform-random (distinct=n,
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

// TracerRanges is the accepted showTracer Range set (shell caliber in
// mm, fixed per gun): the Sweden live set plus an earlier replay
// extras (100/110/120/127/130). Template validated clean on lobby
// traffic (0/533 S>C bodies, Oct-01 session) — hits need the full
// 50B shape below, never Range alone.
var TracerRanges = []float64{57, 75, 76, 85, 88, 90, 100, 105, 110, 120, 122, 127, 128, 130, 150, 152, 155}

// TracerHit is one S>C showTracer candidate: shooter entity, shot ID,
// caliber, endpoints. Tail bytes must be 0000 (validated shape;
// non-0000 windows exist live and stay open, uncounted).
type TracerHit struct {
	A0    uint32
	Shot  uint32
	Range float64
	Start [3]float64
	End   [3]float64
}

// ScanBattleTracers slides the 50B showTracer template over one
// decrypted S>C battle app body (channel flags/trailer already
// stripped by the caller): `[I32 a0][shotID][flags×4][Range][start
// V3][end V3][A9][A10][00 00]`. Same serialization as replays
// (Avatar.client[17], mid 37). Windows holding denormal V3 components
// are rejected (1B-slide ghosts of neighboring real tracers: Sep-29
// Sweden yields 4, all reusing a real shotID with denormal dregs;
// game physics never emits denormals). Callers dedupe by Shot across
// packets; battle time comes from transport timestamps, not the wire.
func ScanBattleTracers(app []byte) []TracerHit {
	allow := func(r float64) bool {
		for _, v := range TracerRanges {
			if math.Round(r) == v {
				return true
			}
		}
		return false
	}
	inMap := func(o int) bool {
		x := math.Float32frombits(binary.LittleEndian.Uint32(app[o:]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(app[o+4:]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(app[o+8:]))
		fx, fy, fz := float64(x), float64(y), float64(z)
		if math.IsNaN(fx) || math.IsNaN(fy) || math.IsNaN(fz) {
			return false
		}
		if isDenormal(x) || isDenormal(y) || isDenormal(z) {
			return false
		}
		return fx > -1500 && fx < 1500 && fy > -500 && fy < 500 && fz > -1500 && fz < 1500
	}
	var out []TracerHit
	for o := 0; o+50 <= len(app); o++ {
		rng := float64(math.Float32frombits(binary.LittleEndian.Uint32(app[o+12:])))
		if !allow(rng) {
			continue
		}
		if !inMap(o+16) || !inMap(o+28) {
			continue
		}
		if app[o+48] != 0 || app[o+49] != 0 {
			continue
		}
		var h TracerHit
		h.A0 = binary.LittleEndian.Uint32(app[o:])
		h.Shot = binary.LittleEndian.Uint32(app[o+4:])
		h.Range = rng
		for i := 0; i < 3; i++ {
			h.Start[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(app[o+16+i*4:])))
			h.End[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(app[o+28+i*4:])))
		}
		out = append(out, h)
	}
	return out
}

// isDenormal reports IEEE-754 subnormal f32 (zero exponent, nonzero
// mantissa) — the signature of misaligned wire reads, never of game
// physics output.
func isDenormal(f float32) bool {
	b := math.Float32bits(f)
	return b&0x7f800000 == 0 && b&0x007fffff != 0
}

// VehicleRef is one battle entity's vehicle identity: nation index
// (compactNations order, see NationName) + per-nation type ID from
// that nation's vehicles/list.xml. Resolved to display names through
// a ComponentTable (Vehicle method).
type VehicleRef struct {
	Nation uint8
	TypeID uint16
}

// battleHead is one per-vehicle block opening in a creation bulk:
// the entity ID, its byte offset (block spans to the next head) and
// the paired player name. Only full triples (head framing +
// doubled name + ASCII ID) qualify, so component/state u32 echoes
// never become heads.
type battleHead struct {
	v    uint32
	o    int
	name string
}

// scanHeads lists per-vehicle block heads in a battle-start creation
// bulk: entity-LE openings whose block carries the doubled player
// name (see ParseBattleRoster). Shared by the roster and vehicle
// passes so both agree on block boundaries.
func scanHeads(bulk []byte) []battleHead {
	var out []battleHead
	for o := 0; o+6 <= len(bulk); o++ {
		v := binary.LittleEndian.Uint32(bulk[o:])
		if v < 100000 || v > 3000000000 || bulk[o+4] != 0x01 || bulk[o+5] > 32 {
			continue
		}
		name := headName(bulk, o)
		if name == "" {
			continue
		}
		digits := []byte(fmt.Sprint(v))
		found := false
		for s := o + 4; s+len(digits) <= o+320 && s+len(digits) <= len(bulk); s++ {
			match := true
			for k, d := range digits {
				if bulk[s+k] != d {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		dup := false
		for _, h := range out {
			if h.v == v {
				dup = true
			}
		}
		if !dup {
			out = append(out, battleHead{v, o, name})
		}
	}
	return out
}

// ParseBattleRoster pairs battle entities to player names from the
// concatenated battle-start creation bulk (S>C, decrypted, arrival
// order — e.g. the Sep-29 Sweden 1223B-run). The run must be
// concatenated VERBATIM (contiguous fragments; size-filtered subsets
// can split a vehicle block and lose its pair — seen live with a 90B
// gap). Per-vehicle blocks carry
// the entity ID twice: binary LE near the block head, then the player
// name (packed-string, always doubled back-to-back) and the same ID
// in ASCII digits within ~160B. Only triples matching all three
// survive; component blobs, config pickles, single clan tags and
// dotted section keys (bw.default etc.) are ignored by the doubling
// rule. Tank identity lives in the creation compDescr (open) — this
// returns names only.
func ParseBattleRoster(bulk []byte) map[uint32]string {
	out := map[uint32]string{}
	for _, h := range scanHeads(bulk) {
		if _, dup := out[h.v]; !dup {
			out[h.v] = h.name
		}
	}
	return out
}

// headName returns the doubled player name following a block head
// ("" when absent): the first 3–33B name-char run within 160B that
// repeats within 40B (packed-string doubling). Single clan tags,
// dotted section keys and digit runs never qualify.
func headName(bulk []byte, o int) string {
	name, _ := headNameAt(bulk, o)
	return name
}

// headNameAt is headName plus the end offset of the SECOND occurrence
// (0 when absent) — the anchor ParseBattleTeams reads the team byte
// from.
func headNameAt(bulk []byte, o int) (string, int) {
	isName := func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' ||
			b == '_' || b == '-' || b == '[' || b == ']' || b == '|'
	}
	for s := o + 4; s < o+160 && s < len(bulk); s++ {
		if !isName(bulk[s]) {
			continue
		}
		e := s
		for e < len(bulk) && e-s < 34 && isName(bulk[e]) {
			e++
		}
		cand := bulk[s:e]
		if len(cand) < 3 {
			continue
		}
		digits := true
		for _, b := range cand {
			if b < '0' || b > '9' {
				digits = false
			}
		}
		if digits {
			continue
		}
		for t := e; t+len(cand) <= e+40 && t+len(cand) <= len(bulk); t++ {
			match := true
			for k, d := range cand {
				if bulk[t+k] != d {
					match = false
					break
				}
			}
			if match {
				return string(cand), t + len(cand)
			}
		}
	}
	return "", 0
}

// ParseBattleTeams reads each block head's team byte: the u8 right
// after the doubled player name (1 or 2, replay `team` values; Sep-29
// Sweden 30/30, 15/15 split, own team = 2 with ExampleUser). The byte
// must be followed by 00 00 (next field's padding); anything else is
// skipped, never guessed.
func ParseBattleTeams(bulk []byte) map[uint32]uint8 {
	out := map[uint32]uint8{}
	for _, h := range scanHeads(bulk) {
		_, end := headNameAt(bulk, h.o)
		if end == 0 || end+3 > len(bulk) {
			continue
		}
		t := bulk[end]
		if t != 1 && t != 2 {
			continue
		}
		if bulk[end+1] != 0 || bulk[end+2] != 0 {
			continue
		}
		if _, dup := out[h.v]; !dup {
			out[h.v] = t
		}
	}
	return out
}

// ParseBattleVehicles resolves each block head's vehicle identity to
// a (nation, typeID) ref for lookup in the per-nation vehicles
// list.xml tables (ComponentTable.Vehicle). Layout (Sep-29 Sweden,
// 30/30 heads): head `[ent-LE][01][lenA][A...]` then a tag byte —
// 0x0f carries the 2-byte vehicle IntCD
// (`[type+nation<<4][id]`, BigWorld items rules), 0x10 the 3-byte
// extended form (`[type+ext+nation<<4][id-lo][id-hi]`, ids > 255:
// Sep-29 germany/265 Chi-Go). Only refs whose item type is vehicle
// (1, ext bit masked) and whose nation resolves are returned;
// anything else (component blobs, counters) is skipped, never
// guessed.
func ParseBattleVehicles(bulk []byte) map[uint32]VehicleRef {
	out := map[uint32]VehicleRef{}
	for _, h := range scanHeads(bulk) {
		if h.o+8 > len(bulk) {
			continue
		}
		ln := int(bulk[h.o+5])
		rend := h.o + 4 + 2 + ln
		if rend >= len(bulk) {
			continue
		}
		var nation uint8
		var id uint16
		switch bulk[rend] {
		case 0x0f:
			if rend+3 > len(bulk) {
				continue
			}
			cd := binary.LittleEndian.Uint16(bulk[rend+1:])
			if cd&15 != 1 {
				continue
			}
			nation, id = uint8(cd>>4&15), cd>>8
		case 0x10:
			if rend+4 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if lo := b0 & 15; lo != 1 && lo != 3 {
				continue
			}
			nation, id = uint8(b0>>4&15), uint16(bulk[rend+2])|uint16(bulk[rend+3])<<8
		default:
			continue
		}
		if NationName(nation) == "" {
			continue
		}
		if _, dup := out[h.v]; !dup {
			out[h.v] = VehicleRef{nation, id}
		}
	}
	return out
}

// MountedModules is a battle entity's mounted modules from its
// creation compactDescr: raw component IDs (display names via
// ComponentTable.Component with the matching CompKind).
type MountedModules struct {
	Chassis, Engine, FuelTank, Radio, Turret, Gun uint16
}

// ParseBattleMounts sections each block head's inline mounted-modules
// compactDescr and returns per-entity module IDs. Wire layout (Sep-29
// Sweden, 30/30): head `[ent-LE][01][lenA][A...]` then a tag byte —
// 0x0f carries the 2-byte vehicle IntCD, 0x10 the 3-byte extended
// form (ids > 255) — followed DIRECTLY by the mounted descriptor:
// `[chassis,engine,fuelTank,radio LE u16][turret,gun LE u16]`
// (12B, mounted pair only — the client owns the unlock tree locally,
// so the server sends what's fitted, not the full type), then the
// flags chain per SectionCompactDescr semantics and the packed-string
// player name. Every one of the six IDs must resolve in tab (chance
// heads die here), and the parsed end must land exactly on the
// doubled-name length prefix carrying this head's name (wire lengths,
// never blind offsets). Camo-tailed descrs (length-less tail) are
// skipped, never guessed.
func ParseBattleMounts(bulk []byte, tab ComponentTable) map[uint32]MountedModules {
	out := map[uint32]MountedModules{}
	for _, h := range scanHeads(bulk) {
		if h.o+8 > len(bulk) {
			continue
		}
		ln := int(bulk[h.o+5])
		rend := h.o + 4 + 2 + ln
		if rend >= len(bulk) {
			continue
		}
		var nation uint8
		var id uint16
		var hlen int
		switch bulk[rend] {
		case 0x0f:
			if rend+3 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if b0&15 != 1 || b0&compactExtFlag != 0 {
				continue
			}
			nation, id, hlen = uint8(b0>>4&15), uint16(bulk[rend+2]), 2
		case 0x10:
			if rend+4 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if lo := b0 & 15; lo != 1|compactExtFlag {
				continue
			}
			nation, id, hlen = uint8(b0>>4&15), uint16(bulk[rend+2])|uint16(bulk[rend+3])<<8, 3
		default:
			continue
		}
		if _, ok := tab.Vehicle(nation, id); !ok {
			continue
		}
		off := rend + 1 + hlen
		if off+13 > len(bulk) {
			continue
		}
		get := func(o int) uint16 { return uint16(bulk[o]) | uint16(bulk[o+1])<<8 }
		m := MountedModules{
			Chassis: get(off), Engine: get(off + 2), FuelTank: get(off + 4),
			Radio: get(off + 6), Turret: get(off + 8), Gun: get(off + 10),
		}
		if _, ok := tab.Component(nation, CompChassis, m.Chassis); !ok {
			continue
		}
		if _, ok := tab.Component(nation, CompEngine, m.Engine); !ok {
			continue
		}
		if _, ok := tab.Component(nation, CompFuelTank, m.FuelTank); !ok {
			continue
		}
		if _, ok := tab.Component(nation, CompRadio, m.Radio); !ok {
			continue
		}
		if _, ok := tab.Component(nation, CompTurret, m.Turret); !ok {
			continue
		}
		if _, ok := tab.Component(nation, CompGun, m.Gun); !ok {
			continue
		}
		end := off + 12 + 1
		flags := bulk[off+12]
		slots := flags & 15
		for i := 0; i < 4; i++ {
			if slots&(1<<uint(i)) != 0 {
				end += 2
			}
		}
		if end > len(bulk) {
			continue
		}
		if flags&compactFlagEnh != 0 {
			if end >= len(bulk) {
				continue
			}
			end += 1 + int(bulk[end])*6
		}
		if flags&compactFlagEmb != 0 {
			if end >= len(bulk) {
				continue
			}
			pos := bulk[end]
			end++
			ne, ni := 0, 0
			for i := 0; i < 4; i++ {
				if pos&(1<<uint(i)) != 0 {
					ne++
				}
				if pos&(1<<uint(i+4)) != 0 {
					ni++
				}
			}
			end += ne*6 + ni*7
		}
		if flags&compactFlagSkip != 0 {
			end++
		}
		if flags&compactFlagCamo != 0 {
			continue
		}
		if end >= len(bulk) || int(bulk[end]) != len(h.name) {
			continue
		}
		if end+1+len(h.name) > len(bulk) {
			continue
		}
		if string(bulk[end+1:end+1+len(h.name)]) != h.name {
			continue
		}
		if _, dup := out[h.v]; !dup {
			out[h.v] = m
		}
	}
	return out
}

// BuildShootTrigger emits the standalone C>S shoot-trigger bundle
// (41B app): `[02 8b 58 4a][93][10][0400][00000000]` + the 29B position
// trailer. Wire truth (Sep-29 Sweden: 9/9 own shots carry this record
// 60–140 ms before the server's S>C tracer — 4 standalone-outer like
// this, 5 chained-inner inside 07/18-led bundles; the 4 arg bytes are
// zero on all 9). Trailer fields mirror ParseTrailer (nonce/speed/xyz
// are the caller's live values; the server answers with a tracer, not
// an ack — unspotted/ground hits stay silent until battle results).
func BuildShootTrigger(entity, nonce uint32, speed, x, y, z float32, tail [2]byte) []byte {
	app := make([]byte, 0, 41)
	app = append(app, BattleC2SHead0, BattleC2SHead1, BattleC2SHead2, BattleC2SHead3)
	app = append(app, BattleFamily, BattleSubShoot, BattleShootArgsLen, 0x00)
	app = append(app, 0x00, 0x00, 0x00, 0x00)
	app = append(app, BattleTrailerTag, 0x1a, 0x00)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], entity)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], nonce)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(speed))
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(x))
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(y))
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(z))
	app = append(app, tmp[:]...)
	app = append(app, tail[0], tail[1])
	return app
}

// FindShootTrigger reports whether app carries the shoot-trigger
// record ([10][0400][00000000]) either standalone-outer or chained
// inside a longer bundle. Shape-only (args must be the 4 zero bytes);
// positions/trailer are not validated here.
func FindShootTrigger(app []byte) bool {
	if len(app) < 8 || app[0] != BattleC2SHead0 || app[4] != BattleFamily {
		return false
	}
	if app[5] == BattleSubShoot &&
		binary.LittleEndian.Uint16(app[6:8]) == BattleShootArgsLen &&
		len(app) >= 8+BattleShootArgsLen &&
		app[8] == 0 && app[9] == 0 && app[10] == 0 && app[11] == 0 {
		return true
	}
	ln := int(binary.LittleEndian.Uint16(app[6:8]))
	if 8+ln > len(app) {
		return false
	}
	rest := app[8+ln:]
	if len(rest) >= BattleTrailerLen && rest[0] == BattleTrailerTag {
		rest = rest[:len(rest)-BattleTrailerLen]
	}
	for len(rest) >= 3 {
		iln := int(binary.LittleEndian.Uint16(rest[1:3]))
		if 3+iln > len(rest) {
			return false
		}
		if rest[0] == BattleSubShoot && iln == BattleShootArgsLen &&
			rest[3] == 0 && rest[4] == 0 && rest[5] == 0 && rest[6] == 0 {
			return true
		}
		rest = rest[3+iln:]
	}
	return false
}
