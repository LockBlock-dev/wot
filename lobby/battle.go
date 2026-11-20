package lobby

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Battle (CellApp arena) client→server application messages, Sep-29
// proxy session + Oct-14 2.4.1.0 sessions (decryptable arena captures —
// all shapes below verified against genuine wire across versions;
// tests mix synthetic fixtures with pinned genuine vectors).
//
// Wire why: every C>S battle bundle opens `[02][key4]` then bare
// records, each length-prefixed: `[SUB][len16le][args]` (base-routed
// Avatar cell call; SUB = Avatar own-cell doc index for the mapped
// methods, interfaces excluded) and `[0x1a][len16le][26B position
// block]` (len always 26: entity + nonce + speed + xyz + tail;
// 3357/3357 exact). `key4` is the 4B value the server assigns per flow
// in the flow's first 36B S>C reply (same slot both versions); the
// client echoes it as every C>S bundle head, acks included (Sep-29
// `8b584a93`, Oct-14 `831e5b63`/`16e4d857`/`92062e02`). The Oct-12
// `0x93 family` model mistook the Sep-29 key's low byte for a
// per-record tag (corrected Oct-14: chained-inner records were bare
// all along; records were always bare, only the key varies).
// Except the shoot
// trigger (wire 0x10 ≠ doc 0x1b — see BattleSubShoot); 0x1a=26 moveWith (position smooth-track
// proven), 0x1d=29 trackRelative (relative-scale V3 proven), rest by
// shape/count: 0x18=24 reportClientStats, 0x07=7 discloseEntities,
// 0x12=18 grantRagePoints, 0x06=6 forbidUnbindingFromVehicle, 0x10=16
// shoot trigger (CLOSED, see BattleSubShoot — not doc-order 0x1b),
// 0x1c=28 trackWorldPointWithGun; IDA
// tables confirm the messaging layer beneath)
// A standalone 0x1a bundle is one [1a][len 26][26B] message; other SUBs
// prepend their method args and usually append the position message
// (e.g. 0x07/44 = [07][len 7][7B] + [1a][len 26][29B]). Longer bundles
// (63B+) carry extra implicitly-framed records between args and
// trailer (per-SUB sizes open). The shoot trigger is wire SUB 0x10
// ([10][len 4][00000000], lead or chained inner — 9/9 own shots
// 60–140 ms pre-tracer (Sep-29), 8/8 at 49–118 ms (Oct-14 b2), and
// 203/203 at 37–148 ms on the Oct-31 nine-battle session: 86 own
// shots in b2, 117 in b3, one 0x10 each, zero baseline in b1 where
// the observer fired 0 times; behaviorally vehicle_shoot(), the only
// cell call in the decompiled Avatar.shoot path). The doc index
// (own[27]) is NOT the wire index: 0x1b does appear (3× in Oct-31 b1)
// but carries another vehicle's ID and lands after the observer's
// death, so it is a per-entity call, not the 0-arg own shoot. The
// index space is the binary's registration order — it coincides with
// the .def order for the vehicle_* block (0x1a/0x1c/0x1d = 26/28/29)
// but not for the shoot (16 vs 27), still open statically.
// S>C battle traffic is tick + opaque entity blobs (NOT lobby smalls:
// the apparent `1a ba` is a misparse — neither body- nor
// total-length framing fits; snapshots are 276/292B alternating with
// 13B `[35 00][11B]` records per §14). Lengths/hashes/names/counts on
// screen only — positions are gameplay data, never logged.
const (
	// BattleC2SHead0 is the bundle tag opening every C>S battle app.
	BattleC2SHead0 = 0x02
	// BattleHeadLen is the bundle head length: tag + flow key.
	BattleHeadLen = 5
	// BattleKeyLen is the flow-key length: the 4B value the server
	// assigns per flow in the first 36B S>C reply, echoed by the
	// client (Sep-29 8b584a93, Oct-14 per-flow values). Opaque —
	// never parsed, never matched.
	BattleKeyLen = 4
	// Battle SUBs (Avatar own-cell indices; see above for grading).
	BattleSubMoveWith      = 0x1a // 26 vehicle_moveWith(UINT8): CLOSED
	BattleSubReportStats   = 0x18 // 24 reportClientStats(6×f32): medium
	BattleSubDisclose      = 0x07 // 7 discloseEntities(Array): medium
	BattleSubRagePoints    = 0x12 // 18 grantRagePoints(U8,F32): weak
	BattleSubForbidUnbind  = 0x06 // 6 forbidUnbindingFromVehicle(I8): weak
	BattleSubTrackWorld    = 0x1c // 28 trackWorldPointWithGun(V3): medium
	BattleSubTrackRelative = 0x1d // 29 trackRelativePointWithGun(V3): medium
	// BattleSubShoot is the C>S shoot trigger SUB. It is NOT the doc
	// index (own[27] vehicle_shoot): 0x1b does appear on wire (3× in
	// the Oct-31 b1) but carries another vehicle's ID after the
	// observer's death, so it is a per-entity call, not this 0-arg
	// own shoot. Wire truth (Sep-29 Sweden 9/9, Oct-14 b2 8/8, Oct-31
	// b2+b3 203/203 — one record per own shot, 37–148 ms pre-tracer,
	// zero baseline in battles where the observer never fired): a bare
	// [10][len 4][00000000] record,
	// either lead or chained-inner (inside 07/18-led bundles; records
	// carry no family tag — the Oct-12 `[93][10]` reading was the flow
	// key's low byte abutting a lead record, corrected Oct-14).
	// Behaviorally vehicle_shoot(): the decompiled
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
	// zero bytes (9/9 identical on Sep-29 wire, 8/8 on Oct-14 b2,
	// 203/203 on Oct-31).
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
// `[02][key4][1a][1a00][entity u32][nonce u32][speed f32]
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
	if app[0] != BattleC2SHead0 {
		return m, false
	}
	if app[BattleHeadLen] != BattleSubMoveWith {
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
// for any other shape (offsets unverified there — no guessing). Field
// offsets are head-length invariant (5B head in both versions), only
// the head bytes themselves are opaque.
func ParseAvatarUpdate(app []byte) (AvatarUpdate, bool) {
	var u AvatarUpdate
	if len(app) != BattlePosLen {
		return u, false
	}
	if app[0] != BattleC2SHead0 {
		return u, false
	}
	if app[BattleHeadLen] != BattleSubMoveWith {
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
// mm, fixed per gun): the Sweden live set plus an earlier replay's
// extras (100/110/120/127/130). Template validated clean on lobby
// traffic (0/533 S>C bodies, Oct-01 session) — hits need the full
// 50B shape below, never Range alone. Caliber and shell kind ride
// fixed slots (Range @+12, kind byte @+11); the kind decodes via
// ShellKindName.
var TracerRanges = []float64{57, 75, 76, 85, 88, 90, 100, 105, 110, 120, 122, 127, 128, 130, 150, 152, 155}

// TracerHit is one S>C showTracer candidate: shooter entity, shot ID,
// caliber, shell kind, endpoints. Tail bytes must be 0000 (validated shape;
// non-0000 windows exist live and stay open, uncounted).
type TracerHit struct {
	A0    uint32
	Shot  uint32
	Range float64
	Kind  uint8
	Start [3]float64
	End   [3]float64
}

// Shell kind values (tracer flag byte 3): pinned by triple dissociation
// across replay showShooting X plus defs shell <kind> (Prohorovka:
// X=1/2/4 ↔ Flags[3]=1/2/4; Sweden T34_100 gun holds exactly AP +
// HEAT + HE and its 7 tracers read exactly {2,0,1}).
const (
	ShellHEAT = 0
	ShellHE   = 1
	ShellAP   = 2
	ShellAPCR = 4
)

// ShellKindName maps a tracer kind byte to its display tag ("?" for
// unobserved values — never guess).
func ShellKindName(k uint8) string {
	switch k {
	case ShellHEAT:
		return "HEAT"
	case ShellHE:
		return "HE"
	case ShellAP:
		return "AP"
	case ShellAPCR:
		return "APCR"
	}
	return "?"
}

// ShellDefKind maps a tracer kind byte to the item-defs shell <kind>
// string for table lookup ("") when unobserved.
func ShellDefKind(k uint8) string {
	switch k {
	case ShellHEAT:
		return "HOLLOW_CHARGE"
	case ShellHE:
		return "HIGH_EXPLOSIVE"
	case ShellAP:
		return "ARMOR_PIERCING"
	case ShellAPCR:
		return "ARMOR_PIERCING_CR"
	}
	return ""
}

// MatchShell resolves a mounted gun plus fired kind to one shell
// spec: the highest default-portion entry of that kind (loadout
// majority — exact loadouts are account-side and unknowable;
// ok=false when the gun carries no shell of that kind).
func MatchShell(g GenGun, kind uint8) (GenShell, bool) {
	want := ShellDefKind(kind)
	var best GenShell
	found := false
	for _, s := range g.Shells {
		if s.Kind != want {
			continue
		}
		if !found || s.Portion > best.Portion {
			best, found = s, true
		}
	}
	return best, found
}

// FlightTime solves projectile time-of-flight for pure-gravity
// ballistics (the shipped PyBallisticsSimulator model: no drag) given
// muzzle/end points, muzzle velocity and gravity. Howitzers lob
// (shell gravity > 50 takes the high-arc root, e.g. 140 for SPG
// plunging fire); flat guns take the low root. ok=false when out of
// range (no real root).
func FlightTime(start, end [3]float64, v0, grav float64) (float64, bool) {
	if v0 <= 0 || grav <= 0 {
		return 0, false
	}
	dx := end[0] - start[0]
	dz := end[2] - start[2]
	dy := end[1] - start[1]
	r := math.Sqrt(dx*dx + dz*dz)
	f := func(t float64) float64 {
		vh := r / t
		vv := dy/t + grav*t/2
		return vh*vh + vv*vv - v0*v0
	}
	// bracket scan on a log grid, then bisect each sign change
	var roots []float64
	prevT, prevF := 1e-3, f(1e-3)
	for i := 1; i <= 400; i++ {
		t := 1e-3 * math.Pow(60000, float64(i)/400)
		fv := f(t)
		if (prevF < 0) != (fv < 0) {
			lo, hi := prevT, t
			for j := 0; j < 60; j++ {
				mid := (lo + hi) / 2
				if (f(lo) < 0) != (f(mid) < 0) {
					hi = mid
				} else {
					lo = mid
				}
			}
			roots = append(roots, (lo+hi)/2)
		}
		prevT, prevF = t, fv
	}
	if len(roots) == 0 {
		return 0, false
	}
	if grav > 50 {
		return roots[len(roots)-1], true
	}
	return roots[0], true
}

// IncomingShot evaluates one tracer against own position: impact
// distance (horizontal), shell flight ETA, and whether to warn.
// radius is the caller's danger radius (shell blast + displacement
// margin — the C>S position track is displaced/teleporty, so live
// callers pad generously); warn fires inside it.
func IncomingShot(tr TracerHit, sh GenShell, own [3]float64, radius float64) (dist, eta float64, warn bool) {
	dx := tr.End[0] - own[0]
	dz := tr.End[2] - own[2]
	dist = math.Sqrt(dx*dx + dz*dz)
	eta, _ = FlightTime(tr.Start, tr.End, sh.Speed, sh.Gravity)
	return dist, eta, dist <= radius
}

// ScanBattleTracers slides the 50B showTracer template over one
// decrypted S>C battle app body (channel flags/trailer already
// stripped by the caller): `[I32 a0][shotID][flags×4][Range][start
// V3][end V3][A9][A10][00 00]`. Flag byte 3 is the shell kind
// (ShellKindName: 0 HEAT, 1 HE, 2 AP, 4 APCR — same values as replay
// showShooting arg 2). Same serialization as replays
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
		h.Kind = app[o+11]
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
		case 0x0f, 0x11:
			// 0x11 carries the same 2-byte IntCD as 0x0f (pinned on
			// the genuine b1 own-Challenger block: flags 0x04 with
			// one optdev slot fitted; vehicle + flags walk land
			// exactly — single-sample shape, table-gated below).
			if rend+3 > len(bulk) {
				continue
			}
			cd := binary.LittleEndian.Uint16(bulk[rend+1:])
			if cd&compactItemTypeMask != compactItemVehicle {
				continue
			}
			nation, id = uint8(cd>>compactNationShift&compactNationMask), cd>>8
		case 0x10:
			if rend+4 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if lo := b0 & compactItemTypeMask; lo != compactItemVehicle && lo != compactItemVehicle|compactExtFlag {
				continue
			}
			nation, id = uint8(b0>>compactNationShift&compactNationMask), uint16(bulk[rend+2])|uint16(bulk[rend+3])<<8
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
// Sweden, 30/30; 0x11 form pinned Oct-14 b1): head
// `[ent-LE][01][lenA][A...]` then a tag byte — 0x0f carries the
// 2-byte vehicle IntCD (0x11 the same shape, seen with a fitted
// optdev flags byte), 0x10 the 3-byte extended
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
		case 0x0f, 0x11:
			// Same 2-byte IntCD under 0x11 (see ParseBattleVehicles).
			if rend+3 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if b0&compactItemTypeMask != compactItemVehicle || b0&compactExtFlag != 0 {
				continue
			}
			nation, id, hlen = uint8(b0>>compactNationShift&compactNationMask), uint16(bulk[rend+2]), 2
		case 0x10:
			if rend+4 > len(bulk) {
				continue
			}
			b0 := bulk[rend+1]
			if lo := b0 & compactItemTypeMask; lo != compactItemVehicle|compactExtFlag {
				continue
			}
			nation, id, hlen = uint8(b0>>compactNationShift&compactNationMask), uint16(bulk[rend+2])|uint16(bulk[rend+3])<<8, 3
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

// ExplodeHit is one S>C battle explode (acknowledged shell impact):
// the shot ID it answers, its caliber, the impact point, and the
// second triple. Live bodies are exactly 44B with TWO V3s after Range
// (same homology as replay explodeProjectile's Pos+End): the first is
// the map-scale impact (own-shot ground truth s2 (-133,0,284) and s5
// (426,53,-238); Glacier replay |pos-start|=17m at close range), the
// second a small near-origin triple (tens of units, semantics open —
// replay End looks identical). The old single-Pos reading took the
// SECOND triple (always near origin); corrected Oct-12. The caliber
// lives at the A2 slot. Verified against shape-matching windows, 8 of
// which are chance `1a 91 29 00` hits inside snapshot trains,
// separated cleanly by the caliber rule below.
type ExplodeHit struct {
	Shot  uint32
	Range float64
	Pos   [3]float64
	End   [3]float64
}

// ExplodeLen is the standard live explode app length: [1a][91][len8]
// + 41B body ([00][shotID u32][A1 f32][Range f32][Pos V3][End V3]
// [A8 f32] = 1+4+8+12+12+4). One live sample carries a 4B tail (len8
// = 45, total 48); both forms parse identically, tail bytes ignored.
const ExplodeLen = 44

// ExplodeLenTailed is the tailed live explode length (len8 = 45:
// standard body + one u32 tail).
const ExplodeLenTailed = 48

// ScanBattleExplodes slides the 44/48B explode template over one
// decrypted S>C battle app body: `[1a][91][len8=41|45][00][shotID]
// [A1][Range][Pos V3][End V3][A8][tail?]`. Range must be a known shell
// caliber (same set as tracers — chance `1a 91 29` windows inside
// snapshot trains carry garbage here and match no tracer); Pos must
// be in-map. Callers join Shot to tracer shot IDs; battle time comes
// from transport timestamps.
func ScanBattleExplodes(app []byte) []ExplodeHit {
	allow := func(r float64) bool {
		for _, v := range TracerRanges {
			if math.Round(r) == v {
				return true
			}
		}
		return false
	}
	var out []ExplodeHit
	for o := 0; o+ExplodeLen <= len(app); o++ {
		if app[o] != 0x1a || app[o+1] != 0x91 || (app[o+2] != 0x29 && app[o+2] != 0x2d) || app[o+3] != 0x00 {
			continue
		}
		if app[o+2] == 0x2d && o+ExplodeLenTailed > len(app) {
			continue
		}
		rng := float64(math.Float32frombits(binary.LittleEndian.Uint32(app[o+12:])))
		if !allow(rng) {
			continue
		}
		var p, e [3]float64
		ok := true
		for i := 0; i < 3; i++ {
			f := math.Float32frombits(binary.LittleEndian.Uint32(app[o+16+i*4:]))
			if math.IsNaN(float64(f)) || isDenormal(f) {
				ok = false
				break
			}
			p[i] = float64(f)
			e[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(app[o+28+i*4:])))
		}
		if !ok {
			continue
		}
		if p[0] < -1500 || p[0] > 1500 || p[2] < -1500 || p[2] > 1500 {
			continue
		}
		out = append(out, ExplodeHit{
			Shot:  binary.LittleEndian.Uint32(app[o+4:]),
			Range: rng,
			Pos:   p,
			End:   e,
		})
	}
	return out
}

// DeathHit is one battle kill: victim and killer battle entities plus
// the battle-wide death counter (1-based, gapless — Sep-29 runs
// #1–#24). Read off the `deathOrder` key framing below; names/teams
// join through the roster like tracers.
type DeathHit struct {
	Victim  uint32
	Killer  uint32
	Counter byte
}

// deathOrderKey is the ASCII key opening each server death broadcast.
var deathOrderKey = []byte("deathOrder")

// ParseBattleDeaths extracts kill events from one decrypted S>C
// battle app body. Wire framing (Sep-29 Sweden, 24/24 identical):
// `[55][0a]deathOrder[71 02][4b ctr][73 2e][VV WW 02 10][XX 78 01]
// [victim u32 LE][killer u32 LE]` — victim first (a body naming a
// survivor second never occurs; the counter runs 1,2,3… per death).
// VV WW is a per-battle pair, opaque: `0b a8` (Sep-29), `0c 23`
// (Oct-14 b2, 28/28), `0c 99` (Oct-14 b1, 2/2), `0c 92` and `08 b6`
// (Oct-14 1752 battles) — uniform within each battle, varying across
// battles on the same host and build, so it is matched by nothing.
// No mapping found yet (arenaTypeIDs 23/74/4 vs pairs 99/23/b6;
// tiers 8/7 vs 99/23 — single samples each; open).
// Hit confidence comes from the rest: 10B ASCII key + 8 anchor bytes
// + gapless counters + roster-sane nonzero IDs. XX varies per event
// (damage or timing, open — only the constant `78 01` tail is
// checked). Victim and killer must both be nonzero; otherwise the
// window is skipped, never guessed. Self-kills name the same entity
// twice (server records suicides that way).
func ParseBattleDeaths(app []byte) []DeathHit {
	var out []DeathHit
	for o := 0; o+10 <= len(app); o++ {
		match := true
		for k, b := range deathOrderKey {
			if app[o+k] != b {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if o < 2 || o+31 > len(app) {
			continue
		}
		if app[o-2] != 0x55 || app[o-1] != 0x0a ||
			app[o+10] != 0x71 || app[o+11] != 0x02 ||
			app[o+12] != 0x4b || app[o+14] != 0x73 || app[o+15] != 0x2e ||
			app[o+18] != 0x02 || app[o+19] != 0x10 ||
			app[o+21] != 0x78 || app[o+22] != 0x01 {
			continue
		}
		v := binary.LittleEndian.Uint32(app[o+23:])
		k := binary.LittleEndian.Uint32(app[o+27:])
		if v == 0 || k == 0 {
			continue
		}
		out = append(out, DeathHit{v, k, app[o+13]})
	}
	return out
}

// BitReader is an MSB-first bit reader over volatile-record bytes
// (mirrors BW::BitReader: ctor 0x142CA1860, unsigned 0x142CA1900,
// signed 0x142CA19A0, exact-consumption dtor check 0x142CA1880).
type BitReader struct {
	buf []byte
	pos int
}

// Read consumes n bits MSB-first as unsigned.
func (b *BitReader) Read(n int) uint32 {
	var v uint32
	for i := 0; i < n; i++ {
		by := b.buf[b.pos/8]
		v = (v << 1) | uint32((by>>(7-uint(b.pos%8)))&1)
		b.pos++
	}
	return v
}

// ReadSigned consumes n bits MSB-first as signed (two's complement).
func (b *BitReader) ReadSigned(n int) int32 {
	u := b.Read(n)
	if u&(1<<(n-1)) != 0 {
		return int32(u) - int32(uint32(1)<<n)
	}
	return int32(u)
}

// SnapshotRecord is one decoded S>C volatile snapshot record: the
// token byte plus prescale coordinates and direction. Coordinates are
// PRESCALE (custom float minus 2.0, no per-entity scale, no base) —
// sufficient for tracking; absolute mapping needs the runtime scale
// (open, see below).
type SnapshotRecord struct {
	Token byte
	// Prescale position (wire x,z,y order → x,y,z out; y absolute).
	PX, PY, PZ float64
	// Direction in radians.
	Yaw, Pitch, Roll float64
}

// decodePrescale reads one custom volatile float: sign + 4b exponent
// (forced 0b1000 high bits) + mantissa as f32 bits, then + (-2.0)
// (BW_unpackVolatilePosType0: COERCE_FLOAT(bits) + dword -2.0, sign
// OR-ed after, per-entity scale multiplied after — scale skipped
// here, caller fits it).
func decodePrescale(r *BitReader, mant int) float64 {
	sign := r.Read(1)
	exp := r.Read(4)
	m := r.Read(mant)
	bits := (uint32(0x80|exp) << 23) | (m << (23 - mant))
	f := float64(math.Float32frombits(bits)) - 2.0
	if sign != 0 {
		return -f
	}
	return f
}

// ParseSnapshotRecord decodes the 11B payload following a [35 00]
// marker: [token u8][pos 6B][dir 4B]. Position wire order is (x, z, y)
// → out (x, y, z): X/Z are 1+4+12b prescale, Y is 1+4+9b absolute.
// Direction wire order is (yaw, pitch, roll): 11b × 2π/2048, 11b ×
// π/2046 exact, 10b × 2π/1024 (BW_ClientDefaultVolatileUnpacker anti-
// slip: output order is also yaw-first; the old roll-first reading is
// withdrawn — mean |roll| would read 2.4 rad against flat physics,
// while yaw-first validates at turn-rate stats).
func ParseSnapshotRecord(payload []byte) (SnapshotRecord, bool) {
	var s SnapshotRecord
	if len(payload) < 11 {
		return s, false
	}
	s.Token = payload[0]
	r := &BitReader{buf: payload[1:7]}
	px := decodePrescale(r, 12)
	pz := decodePrescale(r, 12)
	py := decodePrescale(r, 9)
	s.PX, s.PY, s.PZ = px, py, pz
	d := &BitReader{buf: payload[7:11]}
	s.Yaw = float64(d.ReadSigned(11)) * 2 * math.Pi / 2048
	s.Pitch = float64(d.ReadSigned(11)) * math.Pi / 2046
	s.Roll = float64(d.ReadSigned(10)) * 2 * math.Pi / 1024
	return s, true
}

// ScanSnapshots extracts volatile snapshot records from one decrypted
// S>C battle app body: 13B `[35 00][11B]` trains. Only runs of 4+
// consecutive 13B-spaced markers parse (chance `35 00` pairs inside
// float blobs are dense); token must sit in EB–FE (the live
// namespace, F8 gap included — exact ID width stays open). Token→
// entity mapping stays OPEN (muzzle-fit overfits camp clusters; own
// C>S track is displaced; spawn anchors unmapped); presence is
// trackable per token meanwhile. Trains fragment: 324B datagrams
// interleave event smalls between records (Oct-14 b2: 269 dgs, ~8
// marks each, only 21% on a 13-stride), so runs under-harvest there
// (0.5/dg vs 5.7–5.9 on 276/292) — see ScanSnapshotTokens for the
// gate-free token harvest that covers them.
func ScanSnapshots(app []byte) []SnapshotRecord {
	var marks []int
	inRun := map[int]bool{}
	for o := 0; o+2 <= len(app); o++ {
		if app[o] == 0x35 && app[o+1] == 0x00 {
			marks = append(marks, o)
			inRun[o] = true
		}
	}
	var out []SnapshotRecord
	for _, o := range marks {
		if o+13 > len(app) {
			continue
		}
		run := 1
		for inRun[o+run*13] {
			run++
		}
		if run < 4 {
			continue
		}
		if id := app[o+2]; id < 0xEB || id > 0xFE {
			continue
		}
		if s, ok := ParseSnapshotRecord(app[o+2 : o+13]); ok {
			out = append(out, s)
		}
	}
	return out
}

// ScanSnapshotTokens harvests snapshot token bytes from one decrypted
// S>C battle app body without the run gate: every `35 00` mark with
// the token byte in EB–FE is reported in scan order. Rationale: marks
// run ~2500× over chance density (b2 276/292: ~11/dg vs ~0.004/dg
// random), so ~all marks are real record starts and only the spacing
// is irregular (fragmented 324 trains); token bytes sit at a fixed
// offset and survive framing errors that would corrupt payload
// decodes. For presence (counts/times per token) only — never for
// positions. Chance-pair singletons show up as n=1 tokens, trivially
// separable from real ones (n=400+).
func ScanSnapshotTokens(app []byte) []byte {
	var out []byte
	for o := 0; o+3 <= len(app); o++ {
		if app[o] == 0x35 && app[o+1] == 0x00 {
			if id := app[o+2]; id >= 0xEB && id <= 0xFE {
				out = append(out, id)
			}
		}
	}
	return out
}

// MarkerPair is one type-0x75 subtype-0x2a link record: two battle
// entities (Sweden: 5/5 enemy+ally, duel/spot-adjacent — members shoot
// each other ±11s or die ≤64s later). Semantics OPEN (spotting-link
// vs team target-ping; decisive test: operator ping + C>S
// correlation, or a second battle capture).
type MarkerPair struct {
	A, B uint32
}

// MarkerSpot is one type-0x75 subtype-0x1d single-entity record: a
// battle counter, the entity, and its map position (Sweden: 11×,
// allies Danil_380×8 + _KissMyTralala_×3). Positions are gameplay
// data — consumers log names/counts, never coordinates. Semantics
// OPEN (same hypotheses + test as MarkerPair).
type MarkerSpot struct {
	Counter uint32
	Ent     uint32
	Pos     [3]float64
}

// MarkerSmall is the type byte of the battle marker family.
const MarkerSmall = 0x75

// ScanBattleMarkers extracts type-0x75 marker records from one
// decrypted S>C battle app body (`[1a][75][len8][payload]`, records
// chain: validated live by back-to-back `[1a 75]` boundaries and
// `[13 xx]` tick boundaries). Accepted shapes only (chance `1a 75`
// bytes inside float blobs are dense):
//   - len 27, sub 0x2a: `[2a][000000][A u32][B u32][15×00]` — both
//     entities in battle range, 15 trailing zeros exact.
//   - len 39, sub 0x1d: `[1d][000000][counter u32][ent][12×00]`
//     `[00 0c][pos V3][00]` — entity in range.
//
// Other 0x75 subtypes (map-script text blobs at battle start) are
// skipped, never guessed.
func ScanBattleMarkers(app []byte) ([]MarkerPair, []MarkerSpot) {
	var pairs []MarkerPair
	var spots []MarkerSpot
	inEnt := func(v uint32) bool { return v >= 100000 && v <= 3000000000 }
	for o := 0; o+3 <= len(app); o++ {
		if app[o] != 0x1a || app[o+1] != MarkerSmall {
			continue
		}
		ln := int(app[o+2])
		if o+3+ln > len(app) {
			continue
		}
		pay := app[o+3 : o+3+ln]
		switch {
		case ln == 27 && pay[0] == 0x2a:
			if pay[1] != 0 || pay[2] != 0 || pay[3] != 0 {
				continue
			}
			a := binary.LittleEndian.Uint32(pay[4:])
			b := binary.LittleEndian.Uint32(pay[8:])
			if !inEnt(a) || !inEnt(b) {
				continue
			}
			zero := true
			for _, c := range pay[12:] {
				if c != 0 {
					zero = false
				}
			}
			if !zero {
				continue
			}
			pairs = append(pairs, MarkerPair{a, b})
		case ln == 39 && pay[0] == 0x1d:
			if pay[1] != 0 || pay[2] != 0 || pay[3] != 0 {
				continue
			}
			ent := binary.LittleEndian.Uint32(pay[8:])
			if !inEnt(ent) {
				continue
			}
			zero := true
			for _, c := range pay[12:24] {
				if c != 0 {
					zero = false
				}
			}
			if !zero || pay[24] != 0 || pay[25] != 0x0c || pay[38] != 0 {
				continue
			}
			var p [3]float64
			ok := true
			for i := 0; i < 3; i++ {
				f := math.Float32frombits(binary.LittleEndian.Uint32(pay[26+i*4:]))
				if math.IsNaN(float64(f)) || isDenormal(f) {
					ok = false
					break
				}
				p[i] = float64(f)
			}
			if !ok {
				continue
			}
			spots = append(spots, MarkerSpot{
				Counter: binary.LittleEndian.Uint32(pay[4:]),
				Ent:     ent,
				Pos:     p,
			})
		}
	}
	return pairs, spots
}

// BuildShootTrigger emits the standalone C>S shoot-trigger bundle
// (41B app): `[02][key4][10][0400][00000000]` + the 29B position
// trailer. key4 is the flow key from the flow's first 36B S>C reply
// (opaque here, echoed verbatim). Wire truth (Sep-29: 9/9 own shots
// carry this record 60–140 ms before the server's S>C tracer — 4 lead
// like this, 5 chained-inner inside 07/18-led bundles; Oct-14 b2:
// 8/8 at 49–118 ms; the 4 arg bytes are zero on all of them).
// Trailer fields mirror ParseTrailer (nonce/speed/xyz are the caller's
// live values; the server answers with a tracer, not an ack —
// unspotted/ground hits stay silent until battle results).
func BuildShootTrigger(key4 [BattleKeyLen]byte, entity, nonce uint32, speed, x, y, z float32, tail [2]byte) []byte {
	app := make([]byte, 0, 41)
	app = append(app, BattleC2SHead0)
	app = append(app, key4[:]...)
	app = append(app, BattleSubShoot, BattleShootArgsLen, 0x00)
	app = append(app, 0x00, 0x00, 0x00, 0x00)
	return appendTrailer(app, Trailer{
		Entity:       entity,
		Nonce:        nonce,
		Speed:        speed,
		AvatarUpdate: AvatarUpdate{X: x, Y: y, Z: z},
		Tail:         tail,
	})
}

// FindShootTrigger reports whether app carries the shoot-trigger
// record (bare `[10][0400][00000000]`) in lead or chained-inner
// position. Shape-only (args must be the 4 zero bytes);
// positions/trailer are not validated here. The trailer walks as an
// ordinary non-matching record, so no special-casing is needed.
func FindShootTrigger(app []byte) bool {
	if len(app) < BattleHeadLen+3 || app[0] != BattleC2SHead0 {
		return false
	}
	rest := app[BattleHeadLen:]
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
