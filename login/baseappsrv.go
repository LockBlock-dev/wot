package login

// BaseApp SERVER half (mirror of the client-side stage machine pinned
// by paired_replay_test.go and the flows3 / proxy-20261001 genuine
// decrypts). The client's script is the proven wire model; this file
// answers it shape-for-shape so a client LOGGED_ON by cmd/wotserver
// reaches stage-2 (rotation-2 → double-auth) and a decrypt-verified
// 1252B flood against US, and the game pointed here walks the same
// turns. Content honesty is layered:
//
//   - transport frames are genuine (rotation 36B, tick 28B, redirect
//     36B with the 0x44 core, flood frames verbatim from the capture);
//   - per-session smalls (v2.1, flows3-s2 decrypts): the stage-2 36B
//     info, the 76B descriptor (packed account name substituted per
//     session) and the 1a/76 session dict (four live fields patched:
//     serverUTC/aogasStartedAt/sessionStartedAt/databaseID) are
//     SERVED with minted channel footers; the stage-1 52B/44B infos,
//     entity bursts, the 1a/73 clan block the dict rode with, and the
//     1a/79 lobby offers stay v1-cut (acked-only in captures);
//   - the post-flood chain (v2/v2.1) is SERVED: the 332B terminator,
//     the [13][7b] rev answer to the client's sync, the 1a/5b stats
//     answer to every 501 poll, the 1a/5e "no such vehicle" error to
//     the 121 season select, and a 100 ms minted tick stream. Answer
//     bodies replay verbatim from the carrier (same staleness as the
//     bulk); every frame — ticks and answers alike — takes one slot
//     on the shared tag/seq/cumul walk, and cumul tracks the client's
//     reliable-seq watermark;
//   - the bulk carrier's chunk contents are a capture REFERENCE (the
//     flows3 stage-2 run — stale shop/offer defs): faithful frames,
//     wrong era. Per-session bulk heads stay stale until per-session
//     bulk minting lands.
//
// Channel crypto is the client's LogOnParams key for BOTH stages: the
// key rotation rides as app content (the [FF][len=8] reply and
// BaseApp.authenticate), the Blowfish channel key never changes
// (decrypt-proven on flows3 — post-rotation datagrams still decrypt
// with the login key).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// Manager port window every genuine [44] redirect target lands in
// (hijack.go validSessionRecord). Our stage-2 listener binds INSIDE
// the window so our client's parseRedirectAt guard accepts the hop —
// the game itself follows out-of-window targets (Oct-14 blackhole
// evidence); this window only constrains our own mint.
const (
	RedirectPortLo = 32810
	RedirectPortHi = 32999
)

// PendingTTL: how long an admitted-but-unhandshaken session stays
// pullable by a stage-1 22B. The live managers expire the pending
// record ~30 s after LOGGED_ON (hijack_portsteal_20260920: the steal
// at +83 s was past expiry); we stay generous.
const PendingTTL = 60 * time.Second

// SessionIdleTTL is how long a stage-2 session may stay silent before it is
// retired.
//
// A live client is never silent that long: it polls the lobby every 5 s and
// reports its position ~20 times a second in a battle. A session that is, is
// gone — and while it stays in byAddr the post-flood ticker keeps minting for
// it and every packet is retransmitted to its dead port until the attempt cap.
// That is the same leak a re-login causes (see Admit), reached the other way:
// the client closes instead of logging in again.
const SessionIdleTTL = 60 * time.Second

// PostTickPeriod is the post-flood tick cadence: the genuine tail runs
// 100 ms ([13][7a] at 1562.609 → [13][7c] at .810 → [13][7d] at .911,
// flows3-s2 idx 1007/1013/1015 — 201 ms then 101 ms, i.e. one tick per
// ~100 ms slot with the sync-answer ticks taking the next slot).
const PostTickPeriod = 100 * time.Millisecond

// LoggedOnSession is the LoginApp→BaseApp handoff for one finished
// login (the LOGGED_ON mint). The stage-1 22B handshake carries
// SessionKey; BlockKey is the Blowfish channel key for both stages.
type LoggedOnSession struct {
	SessionKey uint32
	BlockKey   string
	Name       string
	// AccountID is the stored account behind this login (0 when the
	// LoginApp runs without an account store).
	AccountID int64
	// FreeXP/Credits/Gold are the account's economy, served in the 1a/69
	// stats small and in the full-sync answer's `stats` diff.
	FreeXP  int64
	Credits int64
	Gold    int64
	// Crystal is the bond balance (the client's stats diff calls it
	// `crystal`; the UI shows bonds).
	Crystal int64
	// Slots is the garage capacity (`stats.slots`).
	Slots int64
	// Garage is the account's owned vehicles. The client's
	// InventoryRequester does `invData[GUI_ITEM_TYPE.VEHICLE]
	// ['compDescr']` unconditionally, so a full-sync answer with no item
	// type 1 raises KeyError(1) and the hangar never finishes loading.
	Garage []GarageItem
	// Berths is the barracks capacity (`stats.berths`).
	Berths int64
	// PremiumExpiry is the unix time the account's premium runs out
	// (`account.premiumExpiryTime` and the `premium` block).
	PremiumExpiry int64
	// PiggyBank and PiggyBankGold are the two reserves.
	PiggyBank     int64
	PiggyBankGold int64
	// Clan is the account's clan membership, or nil for a clanless
	// account. It rides the full-sync answer's `account.clanDBID` and
	// `stats.clanInfo`, and the motto/description go out separately
	// through `onClanInfoReceived`.
	Clan *ClanDoc
	// Version is the client build the login identified ("2.4.0",
	// "2.4.1", or "unknown" when the gates are off). The lobby content
	// is still the capture's, so this is informational for now.
	Version string
}

// GarageItem is one owned vehicle as the inventory diff carries it: the
// instance id the client addresses it by, and its compact descriptor
// (the packed nation|type|id header plus the component bytes).
type GarageItem struct {
	InvID        int64
	CompactDescr []byte
	// Crew is the tankman instance id in each crew slot, indexed by slot;
	// 0 is an empty slot. The client reads it as
	// `inventory[1].crew[vehInvID]` and builds the vehicle's crew from it,
	// so an absent list renders every slot empty.
	Crew []int64
	// CrewSize is how many slots the vehicle type has. The client's
	// `VehicleDescrCrew._validateAndComputeCrew` raises
	// `wrong number or tankmen` unless the list is exactly this long, so
	// every list sent is padded to it.
	CrewSize uint8
	// Shells is the flat `cd, count, …` ammunition layout, and Eqs the
	// flat `cd, …` consumables layout. The client reads them as
	// `inventory[1].shellsLayout[vehInvID][0]` and `inventory[1].eqsLayout
	// [vehInvID][0]`.
	Shells []int64
	Eqs    []int64
}

// BaseAppConfig configures the server. Redirect is required: the
// stage-2 endpoint our [44] mints into the client (bind it inside the
// RedirectPort window).
type BaseAppConfig struct {
	Redirect *net.UDPAddr

	// Stage1Space is the space name the stage-1 1a/50 small announces
	// (the genuine capture carries "default"). The client enters this
	// space after the redirect; an empty value falls back to "default".
	Stage1Space string

	// Frequency and TickTag are the flood bundle's leading elements:
	// updateFrequencyNotification's hertz value and tickSync's tag byte.
	// Zero means the defaults (10 Hz, tag 2).
	Frequency uint8
	TickTag   byte

	// Settings is the pickled `initialServerSettings` dict: the lobby's
	// server config, which the client's ServerSettings.set() reads key by
	// key with an `if key in settings` guard (every missing key falls
	// back to the client's own default). nil = an empty dict, which is a
	// valid lobby: the client then runs entirely on its defaults.
	Settings []byte

	// SettingsSmall is the same document restricted to the keys the client
	// needs on the wire: `initialServerSettings` rides the Account entity, so
	// it has to fit one packet, and the full document does not. It is what
	// `createBasePlayerApp` sends when the Account is re-created after a
	// battle. nil = an empty dict.
	SettingsSmall []byte

	// VerifyBulk receives the authored bundle once at startup. It is the
	// integrity gate: a bundle that does not decode fails here instead of
	// being served as garbage the client silently ACKs. nil = no check.
	VerifyBulk func(stream []byte) error

	// CreateBasePlayer sends the Account entity to the client after the
	// session dict and before the flood, so client method calls
	// (onEnqueued, receiveServerStats, …) have a target. It needs the
	// defs: without them the element cannot be built.
	//
	// No capture shows this element in a lobby session, so its position
	// here is a choice, not an observation: the client authenticates, the
	// entity is created, then the lobby data arrives.
	CreateBasePlayer bool
	// AccountComponents is the dynamic-component count CreateBasePlayer
	// carries. The reference's capture shows 19 for Account, and no
	// component data follows it — the element ends right after the count.
	AccountComponents uint8
	// ShowGUIArg is the STRING showGUI takes. The reference replays the
	// capture's; we have none, so it is empty by default.
	ShowGUIArg string

	// Queue lets the application layer own the matchmaking queue. nil =
	// the queue commands are recognised and left unanswered, and the
	// census replays the carrier's.
	Queue *QueueHooks

	// Dispatch is the script model's client-facing tables. When set, the
	// post-flood client calls are decoded from the defs instead of the
	// hand-written element reader: the element id maps to a base method
	// id by a fixed base, and the method's argument types come from the
	// defs. nil = the hand-written reader (kept so a server can run
	// without the defs on disk).
	Dispatch *entdef.Dispatch

	// Economy is the purchase surface (exchange, free XP, premium, slots,
	// berths, piggy bank). nil leaves those commands unanswered.
	Economy EconomyBackend

	// Crew is the crew-assignment surface (CMD_EQUIP_TMAN). nil leaves the
	// command unanswered, which is what the server did before the crew
	// layer existed — the client then shows the drag as a no-op.
	Crew CrewBackend

	// Layouts is the ammunition and consumables surface
	// (CMD_SET_AND_FILL_LAYOUTS). nil leaves the command unanswered, which
	// hangs the ammo panel on "loading".
	Layouts LayoutBackend

	// Arenas owns the battles. nil means the server never puts a client
	// into one, which is what it did before the arena layer existed.
	Arenas *ArenaHooks

	// Units is the squad state behind the accountUnitClient_* calls. nil
	// leaves them unanswered, which is what the server did before the
	// social layer existed (the squad window then never leaves its
	// "creating" state).
	Units UnitBackend

	// XMPPToken mints the chat credential for a client databaseID. The
	// client asks for it with `requestToken(id, TOKEN_TYPE.XMPPCS)` and
	// hands the answer to gloox as its SASL password, so this must be the
	// same value the XMPP service expects. nil leaves the request
	// unanswered, which is what the server did before the chat layer
	// existed (the client then never connects to XMPP).
	XMPPToken func(dbid int64) string

	// BulkFragSize is the flood datagram size the carrier selects
	// (1252 in every genuine capture).
	BulkFragSize int

	Verbose bool
}

// BaseAppServer answers the client's stage-1/stage-2 script for any
// number of clients. Sessions enter via Admit (the LoginApp
// OnLoggedOn hook).
type BaseAppServer struct {
	cfg BaseAppConfig

	// resend holds the reliable packets each peer has not acknowledged.
	// UDP does not retransmit, so a lost answer would stall the client
	// with no error on either side.
	resend *resendQueue

	// settings is the pickled initialServerSettings dict served inside
	// the flood's createBasePlayer element.
	settings      []byte
	settingsSmall []byte
	// startedAt is the process clock updateFrequencyNotification reports.
	startedAt time.Time

	// postTag/postSeq seed the per-session post-flood mint sequencer:
	// the tick tag ramp and the reliable seq the ticks start at (past
	// the flood chain and the session dict).
	postTag byte
	postSeq uint32

	mu sync.Mutex
	// pending is sessions awaiting their stage-1 handshake, keyed by
	// the login-minted sessionKey (what the 22B carries).
	pending map[uint32]*clientState
	// byStageKey is past-rotation sessions, keyed by the key we minted
	// (what the stage-2 22B carries) — also the 22B-resend recovery
	// path after a lost rotation.
	byStageKey map[uint32]*clientState
	// byAddr resolves stage-2 non-handshake datagrams (auth/acks carry
	// no session field); stage-2 sources are fresh sockets, so the
	// address is the only stable join.
	byAddr map[string]*clientState

	// stage1Seen bounds the stage-1 datagram trace: a client that never
	// gets an answer resends, and an unbounded trace would bury the log.
	stage1Seen int

	// stage2 is the bound stage-2 listener, kept so out-of-band pushes
	// (the matchmaker's arena handoff) can reach a session that is not the
	// one being served right now.
	stage2 Transport
}

type clientState struct {
	blockKey  string       // LogOnParams key (set once at admit)
	name      string       // login username (future per-session smalls)
	accountID int64        // stored account behind the login (0 = none)
	freeXP    int64        // account free XP for the 1a/69 stats small
	garage    []GarageItem // owned vehicles for the full-sync inventory
	credits   int64        // account credits, for the full-sync stats diff
	gold      int64        // account gold, for the full-sync stats diff
	crystal   int64        // account bonds, for the full-sync stats diff
	slots     int64        // garage capacity, for the full-sync stats diff
	clan      *ClanDoc     // clan membership, for the full-sync account/stats diff
	berths    int64        // barracks capacity, for the full-sync stats diff
	premium   int64        // premium expiry, for the full-sync account/premium diff
	piggy     int64        // piggy-bank credits
	piggyGold int64        // piggy-bank gold
	// arena is the battle this session is in, or nil. It is set by
	// enterArena and read by the enableEntities handler, which is where the
	// Avatar and the cell player go out.
	arena *ArenaHandoff
	// arenaNext is the rest of the arena entry, held back until the client
	// has rebound its socket. `NetworkInterface::recreateListeningSocket`
	// runs when the battle app is created, so a `createCellPlayer` sent in
	// the same burst as `createBasePlayer` goes to the port the client is
	// tearing down: it is acked and never processed, and the client dies
	// with no space. The genuine server sends it ~215 ms later, on the
	// client's first datagram from the new port.
	arenaNext *ArenaHandoff
	// arenaNextAt is when the held-back half is sent even if the client
	// has not spoken. The genuine server sends it ~215 ms after the
	// Avatar; waiting for a datagram alone would stall the entry forever
	// on a client that has nothing to say.
	arenaNextAt time.Time
	// lastSeen is when the client last spoke. A rebind leaves the old
	// address in byAddr, so the session lookup has to prefer the live one.
	lastSeen time.Time
	// avatar is the Avatar entity built for the battle, kept so the cell
	// player can be encoded from the same defs.
	avatar *Entity
	// vehicle is the player's own Vehicle entity, created alongside the
	// Avatar so the battle app has something to attach the camera and the
	// player panel to.
	vehicle *Entity
	// dummy is the synthetic opponent's Vehicle entity, when the battle has
	// one, and the server's copy of its spawn and health. The client only
	// learns the health from the updates `applyShot` sends.
	dummy          *Entity
	dummyID        uint32
	dummyPos       [3]float32
	dummyYaw       float32
	dummyHealth    int
	dummyMaxHealth int
	// dummyStickers is the dummy's accumulated `damageStickers` (the shell
	// holes); every pierced hit re-sends the whole list.
	dummyStickers []entdef.Value
	// infoComp is the arena's `AvatarVehiclesInfo` component and infoVehicles
	// its `vehicles` array: the team panel, the kill message and the kill
	// column all read it. infoDummy/infoPlayer are the victim's and the
	// shooter's indexes in that array; infoKills is the shooter's `stFrags`.
	infoComp     nrlComponent
	infoVehicles []entdef.Value
	infoDummy    int
	infoPlayer   int
	infoKills    int
	// shotID numbers the tracers this session fires.
	shotID int32
	// reloadGen numbers the reloads this session starts, so a completion
	// timer from an older reload does not close a newer one (a shell switch
	// restarts the full reload).
	reloadGen uint64
	// gunSpec is the mounted gun's rotation limits and yaw arc, read from
	// the vehicle's item defs when the arena is entered. It is what
	// `gunAnglesPacked` is clamped to.
	gunSpec gunSpec
	// ammoList is the `OwnVehicle.vehicleAmmoList` value sent at arena
	// entry. Every shot decrements the fired shell's `quantity` here and
	// re-sends it: the client's ammo panel reads the count from this
	// property and nothing else updates it.
	ammoList entdef.Value
	// loadedShell and nextShell are `VEHICLE_SETTING.CURRENT_SHELLS` (0)
	// and `NEXT_SHELLS` (1): the shell a shot consumes and the one the
	// client will load next. `vehicle_changeSetting` moves them.
	loadedShell int32
	nextShell   int32
	// gunYaw is the turret angle this server reports, and gunTarget the one
	// the client is aiming at. `trackTurret` walks one toward the other.
	gunYaw    float64
	gunTarget float64
	// gunPitch is the elevation this server reports, in radians, packed into
	// the low six bits of `gunAnglesPacked` against the gun's own
	// `pitchLimits`.
	gunPitch float64
	// hull is the player's tank as this server simulates it, driven by the
	// client's `vehicle_moveWith` flags. `lastEngineMode`, `lastGear` and
	// `lastAux` are what was last sent, so an unchanged value is not resent.
	hull           hull
	lastEngineMode [2]byte
	lastGear       byte
	lastAux        uint64
	lastAuxSet     bool
	// lastGun is the `gunAnglesPacked` value last sent, so an unchanged one
	// is not resent.
	lastGun    uint64
	lastGunSet bool
	// lastPos is the position last sent to the client, so a correction only
	// goes out once the server's hull has actually drifted from it.
	lastPos    [3]float32
	lastDir    [3]float32
	lastPosSet bool
	// hadGround says the terrain had ground under the hull on the last tick,
	// so a tick that finds none has stepped off the map and is refused.
	hadGround bool
	// aimWorld is the point the driver aims at, in world space, and aimSet
	// says whether it has been given yet.
	aimWorld [3]float32
	aimSet   bool
	// sendMu serialises reliable sends for this session. A multi-packet
	// sequence — `selectEntity(vehicle)`, the update, `selectEntity(avatar)` —
	// must not be interleaved with another sender's, or the update lands on the
	// wrong entity and the client asserts `result && pValue` in
	// `entity_description.cpp`.
	sendMu      sync.Mutex
	version     string // client build the login identified
	entityID    uint32 // the player entity id we mint for CreateBasePlayer
	accountName string // the Account entity's `name` property
	incarnation uint64 // incarnationID, minted per session
	entered     bool   // the Account entity has been created
	// resetSent is set when resetEntities has gone out and cleared once a
	// new player entity exists. Between the two the client holds no
	// entity at all, so any Account-level answer (onCmdResponseExt, the
	// Account `update`) would make it size an entity method for an entity
	// it no longer has: `MF_ASSERT_DEV FAILED: pEntity` in
	// BWEntities::getEntityMethodStreamSize (bw_entities.cpp:1103).
	resetSent  bool
	sentRev    int64        // the revision our last full sync carried
	sessionKey uint32       // login-minted
	stageKey   uint32       // our stage-1 rotation (0 = none yet)
	stage2Key  uint32       // our stage-2 rotation (0 = none yet)
	addr       *net.UDPAddr // stage-1 source (redirect receiver)
	stage2Addr *net.UDPAddr // stage-2 source
	// resendKey is this session's key in the reliable resend queue. The
	// queue is keyed by session, not by the address we send to: the client
	// rebinds its socket on battle entry and a re-login abandons the old
	// session outright, and an address-keyed queue outlived both (see
	// resendQueue).
	resendKey  string
	tailAt     time.Time // stage-1 tick+redirect deadline (zero = none)
	admittedAt time.Time // for PendingTTL expiry
	flooded    bool      // bulk burst already served

	// --- post-flood (v2) sequencer state -------------------------------
	// After the terminator the server runs a pure mint loop: one [13]
	// tick per period, tag +1, seq +1, cumul = our view of the client's
	// received reliable seq. All four values are read off the genuine
	// tail (terminator tail = [seq 502][cumul 502][3]; first tick =
	// [13][7a][seq 503][cumul 3]) and walked forward from there.
	postAt    time.Time // next post-flood tick deadline
	postTag   byte      // next [13] tag to mint (0x7a at the tail start)
	postSeq   uint32    // next server seq
	postCumul uint32    // our cumul watermark
	// tick is the 10 Hz counter the tick bundle opens with, and the same
	// counter the NRL gun marker carries in full. The captured server's
	// `0x13` TickSync byte is its LOW BYTE — at 14:17:38.143 the marker's
	// tick is 1126474 and the datagram's `0x13` byte is 74, and 1126474 &
	// 0xFF is 74 — so the two are one counter, not two.
	//
	// It must NOT start at 0. The marker's `seqNum` is this counter, and
	// `UnreliableSnapshotBufferReceiver::applyDelta` rejects a delta whose
	// `seqNum <= m_lastUsedSeqNum`, which starts at 0 — so a first marker with
	// seqNum 0 is dropped, no snapshot is ever created, and every later delta
	// then fails with "no base snapshot found". The captured server's counter
	// is a 10 Hz uptime, 1126468 at the first marker of the battle.
	tick uint32
	// nrlIDa and nrlIDb are the two per-arena ids the NRL gun marker carries.
	// They are constant within a battle and differ between battles (five
	// flows of the Oct-31 capture, five different pairs), so they are minted
	// per arena rather than being protocol constants.
	nrlIDa, nrlIDb uint32
	// dispFactor is the client's own dispersion factor: 1.0 fully aimed,
	// growing with hull speed, hull turn rate and turret rotation, and
	// decaying back over the gun's `aimingTime`. The gun marker's
	// `dispersionAngle` is the gun's `shotDispersionAngle` times this.
	dispFactor float64
	// ownVehicle is the player's `OwnVehicle` dynamic component as the NRL node
	// tree holds it, so its properties and client methods can be updated
	// through the `0x26`/`0x25` stream after it is created.
	ownVehicle nrlComponent
	// battleStarted is set once the BATTLE period has gone out, which is after
	// the client has finished loading. The aux word and the Vehicle's own
	// properties start from there: sending them during loading leaves the
	// client stuck on the loading screen with `isOnArena` false, measured.
	battleStarted bool
	// lastMarker is the gun marker last sent, so an unchanged one goes out as
	// the 8-byte "unchanged" form instead of a full 39-byte payload — which
	// is what the captured server does for 408 of 7591 ticks.
	lastMarker    nrlGunMarker
	lastMarkerSet bool
	// unrelSeq is the arena tick's UNRELIABLE sequence, its own counter
	// starting at 1. The client tracks the unreliable stream separately from
	// the reliable one and drops a packet whose sequence does not advance, so
	// it must never be the reliable seq (which jumps by however many reliable
	// sends happened in between).
	unrelSeq   uint32
	rev        int64 // the account's revision, echoed in the 1a/5f answer
	tickPeriod time.Duration
}

// NewBaseAppServer validates the config and preloads the bulk carrier.
func NewBaseAppServer(cfg BaseAppConfig) (*BaseAppServer, error) {
	if cfg.Stage1Space == "" {
		cfg.Stage1Space = "default"
	}
	if cfg.Redirect == nil {
		return nil, fmt.Errorf("wotserver: baseapp needs the stage-2 endpoint (the [44] redirect target)")
	}
	if p := cfg.Redirect.Port; p < RedirectPortLo || p > RedirectPortHi {
		return nil, fmt.Errorf("wotserver: baseapp stage-2 %s outside the manager window %d-%d (our client's parseRedirectAt guard skips it)",
			cfg.Redirect, RedirectPortLo, RedirectPortHi)
	}
	if cfg.BulkFragSize == 0 {
		cfg.BulkFragSize = 1252
	}
	if cfg.AccountComponents == 0 {
		// The reference's capture shows 19 for Account. Zero is the
		// "unset" value here, so a carrier that really wanted zero would
		// have to say so explicitly — which no capture does.
		cfg.AccountComponents = 19
	}
	s := &BaseAppServer{
		cfg:       cfg,
		startedAt: time.Now(),
		// The post-flood tick tag ramp starts at 0x7a (the stage-2 head
		// tags run 0x3e/0x3f/0x40 and the tail continues past them).
		postTag:    0x7a,
		resend:     newResendQueue(resendTimeout, resendGiveUp),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	if cfg.Settings == nil {
		empty, err := lobby.EncodeDocument(lobby.NewDict())
		if err != nil {
			return nil, fmt.Errorf("wotserver: empty settings: %w", err)
		}
		cfg.Settings = empty
	}
	s.settings = cfg.Settings
	s.settingsSmall = cfg.SettingsSmall
	if len(s.settingsSmall) == 0 {
		// A PYTHON property must carry a valid pickle, never an empty blob:
		// `PythonStreamElement::fromStreamToSink` treats a zero-length value as
		// a stream error and the entity read fails. This is protocol 2's empty
		// dict.
		s.settingsSmall = []byte("\x80\x02}\x2e")
	}
	if cfg.VerifyBulk != nil {
		// Build one bundle up front so a broken settings document or a
		// missing defs fails at startup, not on the first login.
		probe, err := s.buildFlood(&clientState{entityID: 1, name: "probe"})
		if err != nil {
			return nil, fmt.Errorf("wotserver: flood bundle: %w", err)
		}
		if err := cfg.VerifyBulk(probe); err != nil {
			return nil, fmt.Errorf("wotserver: flood bundle: %w", err)
		}
		s.logf("flood bundle authored: %d B (%d B settings)", len(probe), len(s.settings))
	}
	return s, nil
}

// logf is the BaseApp's lifecycle channel. It always prints: a silent
// BaseApp is indistinguishable from a dead one, and "the client hangs
// after LOGGED_ON" is exactly the symptom that needs these lines. The
// per-datagram detail stays behind -verbose (logVerbosef).
func (s *BaseAppServer) logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[wotserver] "+format+"\n", args...)
}

// traceStage1 prints the first few stage-1 datagrams that got no answer,
// with their bytes. A client stuck on "Connecting" resends the same
// handshake; without this the server looks dead while it is in fact
// dropping something it cannot read.
func (s *BaseAppServer) traceStage1(from *net.UDPAddr, pkt []byte, why string) {
	s.mu.Lock()
	n := s.stage1Seen
	s.stage1Seen++
	s.mu.Unlock()
	if n >= 8 {
		if n == 8 {
			s.logf("stage1 %s: further unanswered datagrams not traced", from)
		}
		return
	}
	head := pkt
	if len(head) > 32 {
		head = head[:32]
	}
	s.logf("stage1 %s: %dB %s: % x", from, len(pkt), why, head)
}

// logVerbosef is the noisy channel: per-packet detail, -verbose only.
func (s *BaseAppServer) logVerbosef(format string, args ...any) {
	if s.cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[wotserver] "+format+"\n", args...)
	}
}

// Admit registers a finished login for stage-1; wired to the LoginApp
// OnLoggedOn hook. Idempotent per session key, live stage state never
// reset by a stale admission.
func (s *BaseAppServer) Admit(sess LoggedOnSession) {
	if sess.SessionKey == 0 {
		return // zero keys never travel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.pending[sess.SessionKey]; ok && old.stageKey != 0 {
		return
	}
	// A second login for the same account is a reconnect: the old session
	// is gone. Retire it — its battle slot starts the reconnect window, and
	// its reliable queue goes with it.
	//
	// Leaving it in byAddr kept the post-flood ticker minting for a client
	// that no longer exists, and every one of those packets was
	// retransmitted to its dead port until the attempt cap: a live run
	// logged 15,344 resends, 13,429 of them 28 B lobby poll answers, all to
	// the previous session's port.
	if sess.AccountID > 0 {
		for addr, old := range s.byAddr {
			if old == nil || old.accountID != sess.AccountID {
				continue
			}
			delete(s.byAddr, addr)
			if old.stage2Key != 0 {
				delete(s.byStageKey, old.stage2Key)
			}
			delete(s.pending, old.sessionKey)
			s.resend.forget(old.resendKey)
			s.logf("session %08x retired: account %d logged in again", old.sessionKey, sess.AccountID)
			if s.cfg.Arenas != nil && s.cfg.Arenas.Disconnect != nil {
				s.cfg.Arenas.Disconnect(sess.AccountID)
			}
			break
		}
	}
	s.pending[sess.SessionKey] = &clientState{
		entityID:    sess.SessionKey, // unique per session, never zero
		resendKey:   fmt.Sprintf("session-%08x", sess.SessionKey),
		unrelSeq:    1, // the unreliable stream's own counter starts at 1
		blockKey:    sess.BlockKey,
		name:        sess.Name,
		accountName: sess.Name, // the Account entity's `name` property
		accountID:   sess.AccountID,
		freeXP:      sess.FreeXP,
		garage:      sess.Garage,
		credits:     sess.Credits,
		gold:        sess.Gold,
		crystal:     sess.Crystal,
		slots:       sess.Slots,
		clan:        sess.Clan,
		berths:      sess.Berths,
		premium:     sess.PremiumExpiry,
		piggy:       sess.PiggyBank,
		piggyGold:   sess.PiggyBankGold,
		version:     sess.Version,
		sessionKey:  sess.SessionKey,
		admittedAt:  time.Now(),
	}
	s.logf("admitted session key %08x (name %dB, blockKey %dB, client %s)",
		sess.SessionKey, len(sess.Name), len(sess.BlockKey), versionOrUnknown(sess.Version))
}

// versionOrUnknown labels a session whose build the login could not
// identify (the gates were off).
func versionOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// isTickHead reports a decrypted S>C frame whose [13] tick tag equals
// tag: clear = [flags 58 04][13][tag]... (the tick family; the middle
// byte is the tag/step counter, see tickApp).
func isTickHead(clear []byte, tag byte) bool {
	return len(clear) >= 4 && clear[0] == 0x58 && clear[1] == 0x04 &&
		clear[2] == 0x13 && clear[3] == tag
}

// hasSmall reports a decrypted frame carrying a [1a][type] smalls
// record anywhere past the flags (the lobby smalls taxonomy: 1a/5b =
// server-stats counters, 1a/5f = revisions).
// hasSmall reports whether a decrypted frame carries a small of the given
// family and type. It parses the frame's app and walks the smalls, so a
// coincidental tag pair inside a payload cannot match.
func hasSmall(clear []byte, fam, typ byte) bool {
	app, err := frameApp(clear)
	if err != nil {
		return false
	}
	return lobby.FindSmall(app, fam, typ) != nil
}

// frameApp returns a decrypted frame's app: everything between the flags
// word and the channel trailers.
func frameApp(clear []byte) ([]byte, error) {
	if len(clear) < 2 {
		return nil, fmt.Errorf("wotserver: frame too short")
	}
	tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
	if len(clear) < 2+tr {
		return nil, fmt.Errorf("wotserver: frame trailers overrun")
	}
	return clear[2 : len(clear)-tr], nil
}

// firstElement returns the id of the first element in a post-flood client
// datagram.
//
// A client that has been running prefixes its bundle with `02` and the
// channel key (`clear[2] == 0x02`, `clear[3:7]` the key), and the elements
// start at 7; the very first bundle after the flood carries no prefix and
// they start at 2. `postCalls` walks from 7, so this must agree with it —
// reading `frameApp`'s first byte instead silently misses every
// `enableEntities` that arrives with the prefix, which is what left the
// client on a black screen waiting for its battle entity.
func firstElement(clear []byte, key2 uint32) (byte, bool) {
	if len(clear) < 3 {
		return 0, false
	}
	tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
	end := len(clear) - tr
	start := 2
	if len(clear) >= 7 && clear[2] == 0x02 && binary.LittleEndian.Uint32(clear[3:7]) == key2 {
		start = 7
	}
	if start >= end {
		return 0, false
	}
	return clear[start], true
}

// answerApp builds a post-flood answer: the tick head, then a small.
func answerApp(small []byte) []byte {
	return append(EncodeTickSync(0), small...)
}

// Serve runs both listeners until ctx cancels.
func (s *BaseAppServer) Serve(ctx context.Context, stage1, stage2 Transport) error {
	if stage1 == nil || stage2 == nil {
		return fmt.Errorf("wotserver: baseapp needs both listeners")
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := serveStage1(s, ctx, stage1); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("stage1: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := serveStage2(s, ctx, stage2); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("stage2: %w", err)
		}
	}()
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// --- stage-1: 22B handshake → rotation → tick → [44] redirect. ---
//
// Genuine flows3 server order (seq 0..4): rotation(36) · 52B infos ·
// tick(28) · 44B · redirect(36). v1 sends rotation → tick → redirect;
// the two infos datagrams are cut (the client acts on the [44] alone,
// both are only acked in the captures).

func serveStage1(s *BaseAppServer, ctx context.Context, conn Transport) error {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Dead-wake: fire due tails and expire stale pendings —
			// the tick+redirect must land even if the client resends
			// nothing.
			s.sweepStage1(conn, time.Now())
			continue
		}
		if err := s.handleStage1(conn, from, buf[:n]); err != nil {
			s.logf("stage1 %s: %v", from, err)
		}
		s.sweepStage1(conn, time.Now())
	}
}

func (s *BaseAppServer) handleStage1(conn Transport, from *net.UDPAddr, pkt []byte) error {
	rq, ok := parseBaseAppLogin(pkt)
	if !ok {
		// Everything non-22B on stage-1 is walk tokens (acks, auth1,
		// post-redirect auth2): silence, like the live managers. A 22B
		// that does not parse is different — that is a handshake we
		// failed to read, and staying silent there hides a dead client.
		// Only a 22B is handshake-shaped. Everything else on stage-1 is
		// a walk token (ack/auth) — normal traffic, not a failure.
		if len(pkt) == 22 {
			s.traceStage1(from, pkt, "did not parse")
		} else {
			s.logVerbosef("stage1 %s: %dB walk token", from, len(pkt))
		}
		return nil
	}
	st := s.bySession(rq.sessionKey)
	if st == nil {
		// Unknown session key: silence (p5 validates keys: random-key
		// 22Bs draw zero bytes there) — but say so, or a client that
		// never gets an answer looks like a dead server.
		s.logf("stage1 %s: 22B for unknown session key %08x — silent", from, rq.sessionKey)
		s.traceStage1(from, pkt, "unknown session key")
		return nil
	}
	s.mu.Lock()
	nk := st.stageKey
	if nk == 0 {
		k, err := mintRotationKey(rq.sessionKey)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		nk = k
		// Register BEFORE touching from/rid: the stage-2 22B looks this
		// key up, so a stale map entry must never outlive the mint.
		st.stageKey = nk
		s.byStageKey[nk] = st
	}
	if st.addr == nil {
		st.addr = cloneAddr(from)
	}
	if st.tailAt.IsZero() {
		st.tailAt = time.Now().Add(300 * time.Millisecond)
	}
	s.mu.Unlock()
	// Per-request-id reply: a lost rotation is re-signaled with the
	// rid of the client's CURRENT handshake (stageKeyOf matches on
	// rid; the client resends with a FRESH rid each attempt).
	rot, err := buildChannelPacket(st.blockKey, flagsRel, replyMsg(rq.rid, nk), nil, 0, 0)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(rot, from); err != nil {
		return err
	}
	s.logf("stage1 %s: 22B rid=%d mtu=%d att=%d → rotation %dB", from, rq.rid, rq.mtu, rq.attempts, len(rot))
	return nil
}

// sweepStage1 fires due stage-1 tails (28B tick, then the [44]
// redirect) and expires PendingTTL admissions.
func (s *BaseAppServer) sweepStage1(conn Transport, now time.Time) {
	type tailJob struct {
		blockKey string
		addr     *net.UDPAddr
		st       *clientState
	}
	s.mu.Lock()
	var due []tailJob
	for _, st := range s.byStageKey {
		if st.stage2Addr != nil || st.tailAt.IsZero() || now.Before(st.tailAt) {
			continue
		}
		due = append(due, tailJob{blockKey: st.blockKey, addr: st.addr, st: st})
		st.tailAt = time.Time{} // fire once
	}
	for k, st := range s.pending {
		if now.Sub(st.admittedAt) > PendingTTL {
			delete(s.pending, k)
		}
	}
	// Retire stage-2 sessions that have gone silent. A session left in
	// byAddr keeps the post-flood ticker minting for it, and every one of
	// those packets is retransmitted to its dead port until the attempt cap.
	var retired []*clientState
	for addr, st := range s.byAddr {
		if st.lastSeen.IsZero() || now.Sub(st.lastSeen) <= SessionIdleTTL {
			continue
		}
		delete(s.byAddr, addr)
		if st.stage2Key != 0 {
			delete(s.byStageKey, st.stage2Key)
		}
		delete(s.pending, st.sessionKey)
		s.resend.forget(st.resendKey)
		// The arena tick stops on a nil arena, so a retired session's ticker
		// ends with it instead of stepping a hull nobody is watching.
		st.arena = nil
		retired = append(retired, st)
	}
	s.mu.Unlock()
	for _, st := range retired {
		s.logf("session %08x retired: silent for %s", st.sessionKey, SessionIdleTTL)
		if s.cfg.Arenas != nil && s.cfg.Arenas.Disconnect != nil && st.accountID > 0 {
			s.cfg.Arenas.Disconnect(st.accountID)
		}
	}
	for _, j := range due {
		if j.addr == nil {
			continue
		}
		// createBasePlayer: the genuine 52B, sent AFTER the client's
		// authenticate (capture order: rotation, client acks +
		// authenticate, then this). Creating the player entity before
		// the connection is authenticated leaves it unregistered and
		// the client asserts `pEntity` on the next entity message.
		s.mu.Lock()
		acct, name, ent := j.st.accountID, j.st.name, j.st.entityID
		s.mu.Unlock()
		info, err := buildChannelPacket(j.blockKey, flagsRel, stage1InfoApp(ent, accountIDFor(acct, name)), nil, 1, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(info, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		s.logf("stage1 %s: createBasePlayer %dB (entity %d, account %d)", j.addr, len(info), ent, accountIDFor(acct, name))
		// tick: genuine 28B `5804 133e <seq=2> <cumul=1>` — flagsRel +
		// [13][stage tag] (ClientInterface::tickSyncPeriodic, wire id
		// 19) + footers; the tag byte's semantics are open (stage-1
		// sessions show 0x3e; parked runs walk it) — copied from flow 10.
		tick, err := buildChannelPacket(j.blockKey, flagsRel, tickApp, nil, 2, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(tick, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		// space: genuine 44B `5804 133e 1a50 0d 07 "default" …` — the
		// 1a/50 small naming the space to enter. The client stalls after
		// the redirect without it.
		space, err := buildChannelPacket(j.blockKey, flagsRel, stage1SpaceApp(s.cfg.Stage1Space), nil, 3, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(space, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		red, err := redirectPacket(j.blockKey, s.cfg.Redirect)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(red, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		s.logf("stage1 %s: tick %dB + space %dB (%q) + redirect %dB → %s",
			j.addr, len(tick), len(space), s.cfg.Stage1Space, len(red), s.cfg.Redirect)
	}
}

// redirectApp mints the [44] application for one target: the 36B
// redirect shape is 2B flags + [13][3f] + [44][ip4][port BE][00 00 01]
// + footers (flows3 s1_srv_4 decrypts to exactly that; the 0x13 head
// is the piggy-backed tick, the 0x44 core trails 7 B, cumul 1 acks
// the client's reliable auth1 seq 0).
// stage1InfoApp mints the 52B stage-1 info app. The client reads it as
// ClientInterface::createBasePlayer — its own log says so:
//
//	ServerConnection::createBasePlayer: id 2881521
//
// so it carries the player entity id, and that id must be the SAME one
// stage-2's CreateBasePlayer uses. Two different ids leave the client
// with two player entities and it asserts `pEntity` when it enters the
// space (bw_entities.cpp:1103).
//
// Captured verbatim from the paired EU2 login (flows3 flow 14, seq 1,
// which decrypts to 58 04 | 02 0a 01 00 3e 8b 23 00 13 3e 05 12 00
// f1 f7 2b 00 0b 00 00 09 "123456789" 00 | 01 00 00 00 | 01 00 00 00).
// There f1 f7 2b 00 is that session's entity id and the 9 ASCII digits
// are its account id; both are substituted here. The account id is
// always 9 digits (accountIDFor), so the length byte and the frame size
// never move.
func stage1InfoApp(entityID uint32, accountID uint64) []byte {
	app := []byte{
		0x02, 0x0a, 0x01, 0x00, 0x3e, 0x8b, 0x23, 0x00, 0x13, 0x3e,
		0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00,
		0x09,
	}
	binary.LittleEndian.PutUint32(app[13:17], entityID)
	app = append(app, []byte(fmt.Sprintf("%09d", accountID))...)
	return append(app, 0x00)
}

// stage1SpaceApp mints the 44B stage-1 space app: tickSync(0x3e) + the
// 1a/50 small carrying the space name (flows3 flow 14, seq 3, decrypts
// to `58 04 13 3e 1a 50 0d 07 "default" 04 80 02 4e 2e 03 00 00 00
// 01 00 00 00`). Without it the client never learns which space to
// enter and stalls after the redirect.
func stage1SpaceApp(space string) []byte {
	app := append(EncodeTickSync(0x3e), 0x1a, 0x50, byte(len(space)+6))
	app = append(app, byte(len(space)))
	app = append(app, []byte(space)...)
	return append(app, 0x04, 0x80, 0x02, 0x4e, 0x2e)
}

func redirectApp(target *net.UDPAddr) ([]byte, error) {
	ip := target.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("wotserver: stage-2 endpoint %s is not IPv4 (ip4 redirect core)", target)
	}
	app := append(EncodeTickSync(0x3f), 0x44)
	app = append(app, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(target.Port))
	app = append(app, pb[:]...)
	app = append(app, 0x00, 0x00, 0x01)
	return app, nil
}

func redirectPacket(blockKey string, target *net.UDPAddr) ([]byte, error) {
	app, err := redirectApp(target)
	if err != nil {
		return nil, err
	}
	return buildChannelPacket(blockKey, flagsRel, app, nil, 4, 1)
}

// parseBaseAppLogin reads the 22B fixed handshake:
//
//	[prefix4][flags 01 00][00][rid u32][00 00][sessionKey u32]
//	[numAttempts u8][mtu u16][footer u16 = 2]
//
// The single request sits at body+2 (body = pkt[4:], §3 request
// chain); the msg is FIXED-7 = 14 B (baseAppLogin wire id 0, the
// buildBaseAppLoginMsg shape).
type baseAppLoginReq struct {
	sessionKey uint32
	rid        uint32
	mtu        int
	attempts   uint8
}

func parseBaseAppLogin(pkt []byte) (rq baseAppLoginReq, ok bool) {
	if len(pkt) != 22 || pkt[4] != 0x01 || pkt[5] != 0x00 {
		return rq, false
	}
	if pkt[6] != 0x00 { // BaseAppExt::baseAppLogin
		return rq, false
	}
	if off := binary.LittleEndian.Uint16(pkt[20:22]); off != 2 {
		return rq, false
	}
	rq.rid = binary.LittleEndian.Uint32(pkt[7:11])
	rq.sessionKey = binary.LittleEndian.Uint32(pkt[13:17])
	rq.attempts = pkt[17]
	rq.mtu = int(binary.LittleEndian.Uint16(pkt[18:20]))
	return rq, true
}

// mintRotationKey picks a stage token: newkey ≠ 0, ≠ old (the client
// fork fails a zero/echoed rotation, sub_140E5FF00 family).
func mintRotationKey(old uint32) (uint32, error) {
	var b [4]byte
	for i := 0; i < 100; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("wotserver: rotation key: %w", err)
		}
		k := binary.LittleEndian.Uint32(b[:])
		if k != 0 && k != old {
			return k, nil
		}
	}
	return 0, fmt.Errorf("wotserver: rotation key: no fresh value")
}

// replyMsg is the rotation app: [FF][len=8][rid u32][newkey u32] —
// the genuine flows3 rotation decrypts to
// `5804 ff 08000000 <rid> <newkey> <seq> <cumul>`; the client side
// stageKeyOf/extractStageKey match exactly this shape.
func replyMsg(rid, newkey uint32) []byte {
	var tmp [4]byte
	msg := []byte{0xFF, 0x08, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(tmp[:], rid)
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], newkey)
	return append(msg, tmp[:]...)
}

// bySession resolves a stage-1 handshake's session: pending first,
// then byStageKey (rotation minted but a resend raced in).
func (s *BaseAppServer) bySession(key uint32) *clientState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.pending[key]; ok {
		return st
	}
	return s.byStageKey[key]
}

// cloneAddr copies a UDP address (ReadFromUDP allocates per call;
// stored states keep their own).
func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

// --- stage-2: rotation-2 → double-auth watch → flood carrier. ---

func serveStage2(s *BaseAppServer, ctx context.Context, conn Transport) error {
	s.mu.Lock()
	s.stage2 = conn
	s.mu.Unlock()
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Dead-wake: post-flood sessions keep ticking even when the
			// client sends nothing (genuine: 100 ms tick cadence).
			s.sweepStage2(conn, time.Now())
			continue
		}
		if err := s.handleStage2(conn, from, buf[:n]); err != nil {
			s.logf("stage2 %s: %v", from, err)
		}
		s.sweepStage2(conn, time.Now())
	}
}

// handleStage2 walks the second stage: the 22B (its sessionKey slot
// carries our stage-1 rotation) → rotation-2 → then the client's
// double-auth ([02][key2] unreliable twin + [02][key2][0b] reliable
// one) → flood burst.
func (s *BaseAppServer) handleStage2(conn Transport, from *net.UDPAddr, pkt []byte) error {
	if rq, ok := parseBaseAppLogin(pkt); ok {
		st := s.byStageKey[rq.sessionKey]
		if st == nil {
			s.logf("stage2 %s: 22B for unknown stage key %08x — silent", from, rq.sessionKey)
			return nil
		}
		s.mu.Lock()
		if st.stage2Key == 0 {
			nk, err := mintRotationKey(rq.sessionKey)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			st.stage2Key = nk
			st.stage2Addr = cloneAddr(from)
			s.byAddr[from.String()] = st
		}
		nk := st.stage2Key
		s.mu.Unlock()
		// Same per-rid reply rule as stage-1 (resends carry fresh rids).
		rot, err := buildChannelPacket(st.blockKey, flagsRel, replyMsg(rq.rid, nk), nil, 0, 0)
		if err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(rot, from); err != nil {
			return err
		}
		s.resend.track(st.resendKey, from.String(), 0, rot)
		s.logf("stage2 %s: 22B rid=%d → rotation-2 %dB", from, rq.rid, len(rot))
		// Nothing else rides with the rotation: the flood chain's first
		// fragment carries the info elements (updateFrequencyNotification
		// + tickSync) and the createBasePlayer header, exactly as the
		// 2.4.1 flow does, and the session dict follows the burst.
		return nil
	}
	// Non-handshake: acks or the double-auth itself. Only sessions we
	// rotated on THIS socket qualify; ours is keyed by source address
	// (a fresh socket addr is the only stable join). Flooded sessions
	// stay live — they walk the post-flood chain.
	s.mu.Lock()
	st := s.byAddr[from.String()]
	reboundFrom := ""
	if st == nil {
		// A stage-2 datagram from an address we never rotated on. The client
		// moves sockets on its own — leaving a battle rebinds it — and the new
		// port is by definition unknown, so match it by decrypting against the
		// sessions we hold. The block key is per-session, so a successful
		// decrypt identifies the owner unambiguously.
		seen := make(map[*clientState]bool, len(s.byAddr))
		for _, cand := range s.byAddr {
			if cand == nil || seen[cand] {
				continue
			}
			seen[cand] = true
			if _, err := DecryptChannel(cand.blockKey, pkt); err != nil {
				continue
			}
			st = cand
			break
		}
		if st == nil {
			known := len(s.byAddr)
			s.mu.Unlock()
			s.logf("stage2 %s: %d B from an unknown address (known: %d)", from, len(pkt), known)
			return nil
		}
		if st.stage2Addr != nil {
			reboundFrom = st.stage2Addr.String()
		}
	}
	flooded := st.flooded
	// Follow the client when it rebinds its socket: the battle entry does
	// exactly that, and a stale address means every answer goes to a port
	// nobody is listening on.
	if st.stage2Addr == nil || st.stage2Addr.String() != from.String() {
		// The reliable queue is keyed by session, so the acks that now
		// arrive from the new address still retire it; this only moves
		// where the replays go, so a packet sent before the rebind is not
		// retransmitted to the port the client just left.
		s.resend.readdr(st.resendKey, from.String())
		st.stage2Addr = cloneAddr(from)
		s.byAddr[from.String()] = st
	}
	s.mu.Unlock()
	if reboundFrom != "" {
		s.logf("stage2 %s: session rebound from %s", from, reboundFrom)
	}
	if flooded {
		clear, err := DecryptChannel(st.blockKey, pkt)
		if err != nil {
			s.logf("stage2 %s: %d B undecryptable (%v)", from, len(pkt), err)
			return nil
		}
		s.noteReliable(st, from, clear)
		return s.servePostFlood(conn, from, st, clear)
	}
	clear, err := DecryptChannel(st.blockKey, pkt)
	if err != nil {
		return nil // not one of ours / undecryptable: ignore
	}
	s.noteReliable(st, from, clear)
	if isStageAuth(clear, st.stage2Key) {
		return s.serveBulk(conn, from, st)
	}
	return nil
}

// noteReliable reads the channel footers of one decrypted client datagram
// and does the two things they carry: retire our resend queue (the
// client's cumulative ack) and advance our own cumul watermark (the
// client's send counter).
//
// The two are INDEPENDENT and must not be gated on the same flag. The
// fork stamps cumul = last processed peer RELIABLE seq + 1 into every
// footer (UDPBundle finalise sub_142AD4D81; the genuine tail ramps 3 =
// token seq 2 + 1, 4 = sync seq 3 + 1, 7 = season seq 6 + 1), and
// RELIABLE is byte-0 bit 0x10 (flagsRel 58 04 has it, flagsUnrel 48 14
// does not). The client's ack-only datagrams are UNRELIABLE — they carry
// no RELIABLE bit — yet they are the only place the client says what it
// has received. Gating the ack on RELIABLE left every answer queued
// forever, and the queue then resent the whole stage-2 stream (ticks
// included) until the give-up deadline, which is what buried the client
// in duplicates while it sat on the dossier step.
func (s *BaseAppServer) noteReliable(st *clientState, from *net.UDPAddr, clear []byte) {
	s.mu.Lock()
	st.lastSeen = time.Now()
	s.mu.Unlock()
	if len(clear) < 6 {
		return
	}
	flags := binary.LittleEndian.Uint16(clear[0:2])
	tr := ChannelTrailerLen(flags)
	if len(clear) < 2+tr {
		return
	}
	// The trailer is [seq][cumul] (8B), [first][last][seq][cumul] (16B),
	// [seq] alone (4B) or [cumul] alone (4B). `seq` is the CLIENT's own
	// send counter (it feeds the cumulative ack WE send back); `cumul` is
	// the client's cumulative ack of OUR seqs (it retires our queue).
	var seq, cumul uint32
	hasSeq := flags&chFlagSequence != 0
	hasCumul := flags&chFlagCumulAck != 0
	switch {
	case hasSeq && hasCumul:
		seq = binary.LittleEndian.Uint32(clear[len(clear)-8 : len(clear)-4])
		cumul = binary.LittleEndian.Uint32(clear[len(clear)-4:])
	case hasSeq:
		seq = binary.LittleEndian.Uint32(clear[len(clear)-4:])
	case hasCumul:
		cumul = binary.LittleEndian.Uint32(clear[len(clear)-4:])
	}
	// The client's cumulative ack retires every reliable packet below it.
	//
	// The queue is keyed by the address we SEND to, so the ack must use the
	// same key. `st.stage2Addr` is frozen at session start, and the client
	// rebinds its UDP socket when the battle app is created
	// (`NetworkInterface::recreateListeningSocket`), so keying the ack on it
	// leaves the queue for the new address unretired: every packet is
	// resent every 400 ms for the whole 20 s give-up window, flooding the
	// channel exactly while the client is entering the battle.
	if cumul > 0 {
		s.resend.ack(st.resendKey, cumul)
	}
	if !hasSeq || clear[0]&0x10 == 0 {
		return
	}
	s.mu.Lock()
	// A reliable seq is a small monotonic counter. A frame whose trailer
	// we mis-sliced (a shape the fork adds later) would otherwise push
	// the watermark to a garbage value, and every frame we mint after
	// that carries an out-of-range cumulative ack the client rejects:
	//
	//   UDPChannel::handleCumulativeAck: Got out-of-range endSeq #...
	//   Error 'REASON_CORRUPTED_PACKET'
	if wm := seq + 1; wm > st.postCumul && wm <= st.postCumul+256 {
		st.postCumul = wm
	}
	s.mu.Unlock()
}

// QueueHooks is the matchmaking queue as the wire layer sees it: enqueue,
// dequeue, and the census the client polls.
//
// The wire layer does not own the queue — it parses the client's call,
// hands it over, and answers with the client method the defs name. Forming
// a battle is out of scope: that needs a cell app and a space.
type QueueHooks struct {
	// Enqueue adds a player — and their squad, when they lead one — to
	// the queue. args is the client's own selection, in its order:
	// [queueType, vehInvID, gameplaysMask, arenaTypeID, randomFlags];
	// veh is the compact descriptor of the vehicle the player queued
	// with, or nil when the inventory id is not in the garage.
	Enqueue func(accountID int64, name string, args []int32, veh []byte) QueueResult
	// Dequeue removes a player, reporting whether it was there.
	Dequeue func(accountID int64) bool
	// Census is the 1a/67 answer for ONE queue type: the total waiting
	// and the per-class breakdown.
	Census func(queueType uint8) (players int, classes []int)
	// Handoff runs the battle handoffs the last Enqueue deferred. The wire
	// layer calls it after sending the `onEnqueued` answer, so the client
	// is queued before it is pulled into a battle — the entry clears its
	// entity table, and doing that first leaves a queued callback holding
	// an entity that no longer exists.
	Handoff func()
}

// QueueResult is the outcome of one enqueue.
//
// Code is the client's JOIN_FAILURE code (`common/constants.pyc`): 0 on
// success, 4 wrong vehicle, 6 wrong args, 17 queue full, 18 queue failure,
// 19 queue forbidden, 20 not enough vehicles. The client turns it into the
// `#system_messages:arena_start_errors/join/<NAME>` line.
type QueueResult struct {
	Code    int32
	Message string
	// Added is how many players went in (a squad adds more than one).
	Added int
}

// Ok reports whether the enqueue applied.
func (r QueueResult) Ok() bool { return r.Code == 0 }

// enterAccount brings a client that enabled entities to its account, the
// way the reference's capture shows: the Account entity, then
// SelectPlayerEntity, then showGUI. showGUI is what makes the hangar
// appear; without it the entity exists but nothing is shown.
//
// The trigger is the client's own enableEntities element, not a point in
// the flood: the client says it is ready for entities, and only then does
// the server create one.
// enterAccount finishes the player's entry: SelectPlayerEntity, then the
// Account client method showGUI — the call that actually makes the hangar
// appear.
//
// The Account entity itself is created by the flood bundle's
// createBasePlayer element, so this does NOT send a second one: a
// duplicate would replace the entity the bundle just built (and the
// client asserts on two player entities). withCreate is for a carrier-less
// run that has no bundle to do it.
//
// seq is the next free reliable seq on the channel; the caller owns the
// numbering so the whole stage-2 stream stays contiguous.
func (s *BaseAppServer) enterAccount(conn Transport, from *net.UDPAddr, st *clientState, seq, cumul uint32, withCreate bool) (uint32, error) {
	if !s.cfg.CreateBasePlayer || s.cfg.Dispatch == nil {
		return seq, nil
	}
	s.mu.Lock()
	done := st.entered
	st.entered = true
	st.resetSent = false
	s.mu.Unlock()
	if done {
		return seq, nil // a repeated enableEntities is not a second entity
	}

	if withCreate {
		// The Account entity and the session dict go out in ONE reliable
		// packet, the way the real server's login reply does. The client's
		// `LoginReplyFilter` passes only the packet carrying the login-reply
		// flag; the `CreateBasePlayer` packet has it, but a second packet
		// (the `1a/76` pair) is dropped as "unexpected ... on external
		// interface" and the hangar never loads. The `0x13` heads alone do
		// not save it — measured after a `leaveArena`, the client created the
		// Account, then dropped the `showGUI` and went to
		// `HANGAR LOADING STATE: DISCONNECTED`.
		create, err := s.createBasePlayerApp(st)
		if err != nil {
			return seq, fmt.Errorf("CreateBasePlayer: %w", err)
		}
		app := append(EncodeTickSync(0), create...)
		pair, err := BuildSessionDict(int64(accountIDFor(st.accountID, st.name)), st.admittedAt, time.Now())
		if err != nil {
			return seq, err
		}
		// `serveBulk` frames the same `1a/76` small as
		// `EncodeTickSync(0x40) + dict`; keep that head inside the packet.
		app = append(app, EncodeTickSync(0x40)...)
		app = append(app, pair...)
		s.checkWire(app)
		if err := s.sendReliable(conn, from, st, app, seq, cumul); err != nil {
			return seq, err
		}
		s.logf("stage2 %s: CreateBasePlayer + showGUI %dB (entity %d, Account, %d components, seq %d) % x",
			from, len(app), st.entityID, s.cfg.AccountComponents, seq, app[:min(len(app), 24)])
		seq++
	}
	return seq, nil
}

// sendReliable frames an app as a reliable packet, sends it, and tracks it
// for retransmission.
func (s *BaseAppServer) sendReliable(conn Transport, to *net.UDPAddr, st *clientState, app []byte, seq, cumul uint32) error {
	st.sendMu.Lock()
	defer st.sendMu.Unlock()
	return s.sendReliableLocked(conn, to, st, app, seq, cumul)
}

// nextSeq mints the next reliable sequence number for this session.
//
// The client's reliable channel is a sliding window keyed on these numbers: a
// duplicate makes it drop the packet, and a gap makes it stall until the resend
// timer fires. Every sender therefore has to mint under the same lock and send
// in the order it minted, or two goroutines hand out the same number and the
// channel stalls — which is exactly the delay this removes. Callers hold
// `st.sendMu` across the mint and the send.
func (s *BaseAppServer) nextSeq(st *clientState) (seq, cumul uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, cumul = st.postSeq, st.postCumul
	st.postSeq++
	return seq, cumul
}

// sendReliableLocked is sendReliable for a caller that already holds
// `st.sendMu` because it is sending a sequence that must not be interleaved.
func (s *BaseAppServer) sendReliableLocked(conn Transport, to *net.UDPAddr, st *clientState, app []byte, seq, cumul uint32) error {
	pkt, err := buildChannelPacket(st.blockKey, flagsRel, app, nil, seq, cumul)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(pkt, to); err != nil {
		return err
	}
	s.resend.track(st.resendKey, to.String(), seq, pkt)
	return nil
}

// sendUnreliableLocked puts app on the unreliable stream.
//
// This is the channel the captured server sends the arena tick on (flags
// 0x1448 = ON|SEQ|CUMUL|AUX, no RELIABLE bit), and it is what makes a high
// tick rate usable: a lost tick is simply skipped, where on the reliable
// stream it head-of-line-blocks every tick behind it and the tank freezes and
// then jumps. Nothing is tracked for retransmission — that is the point.
//
// Three numbers have to be right or the client drops the packet:
//   - seq is the UNRELIABLE counter (`st.unrelSeq`), its own space. Reusing
//     the reliable seq makes it jump by however many reliable sends happened
//     in between, and the client discards a packet whose sequence does not
//     advance.
//   - the aux word is the reliable-send counter, as the exe's UDPBundle
//     finalise computes it (see auxFor).
//   - cumul is the client's own watermark, the same one the reliable sends
//     carry.
func (s *BaseAppServer) sendUnreliableLocked(conn Transport, to *net.UDPAddr, st *clientState, app []byte) error {
	s.mu.Lock()
	seq := st.unrelSeq
	st.unrelSeq++
	relSent := st.postSeq
	cumul := st.postCumul
	s.mu.Unlock()
	pkt, err := buildChannelPacket(st.blockKey, flagsUnrel, app, auxFor(relSent), seq, cumul)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(pkt, to)
	return err
}

// sendReliableEntity is sendReliable for an app that carries only entity
// elements, so the wire check can read it. The stage-1 apps mix in the
// "small" message range (0x44 redirect, 0x45/0x46 command answers), whose
// ids overlap the entity element range and cannot be told apart by shape
// alone — those go through sendReliable unchecked.
func (s *BaseAppServer) sendReliableEntity(conn Transport, to *net.UDPAddr, st *clientState, app []byte, seq, cumul uint32) error {
	s.checkWire(app)
	return s.sendReliable(conn, to, st, app, seq, cumul)
}

// AccountSettingsKeys is the part of the lobby's settings document that has to
// ride the Account entity when it is re-created after a battle.
//
// The first six are read through the client's schema manager, which raises if
// they are absent and stops the hangar app loading. `dog_tags_config` is here
// because `DogTagsController.__addDogTagMarker` reads it during
// `Avatar.setClientReady`; it is enabled, and the Vehicle carries a real
// `dogTag` (`defaultDogTagComponents`), which is what keeps that call from
// throwing. Everything else the client reads with an `if key in settings` guard
// and falls back to its own default.
var AccountSettingsKeys = []string{
	"prefab_effects_availability_config",
	"story_mode_settings",
	"regional_settings",
	"spgRedesignFeatures",
	"shop",
	"epic_config",
	"dog_tags_config",
}

// createBasePlayerApp builds the CreateBasePlayer element for a session:
// the Account entity with its four base-hosted client-visible properties.
//
// incarnationID identifies this incarnation of the entity, so it is fresh
// per session; the version string is the client's own; the server settings
// blob is empty (the capture's is a Python dict we do not model).
func (s *BaseAppServer) createBasePlayerApp(st *clientState) ([]byte, error) {
	if s.cfg.Dispatch == nil {
		return nil, fmt.Errorf("CreateBasePlayer needs the defs")
	}
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		return nil, fmt.Errorf("no Account entity in the defs")
	}
	var incarnation uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &incarnation); err != nil {
		return nil, fmt.Errorf("incarnation id: %w", err)
	}
	e := NewEntity(st.entityID, acct).
		SetUint("incarnationID", incarnation).
		SetString("name", st.name).
		Set("initialServerSettings", entdef.Value{Kind: entdef.VString, Str: string(s.settingsSmall)})
	// The version property is named after the build it belongs to, and the
	// name changes between versions: 2.4.0.0 declares `requiredVersion_2400`,
	// 2.4.1 `requiredVersion_2410`. Setting the wrong one leaves the real one
	// unset, and CreateBasePlayer then fails with "property has no value" —
	// which is what stopped the hangar loading after leaving a battle.
	for _, v := range []struct{ prop, version string }{
		{"requiredVersion_2410", "2.4.1.0"},
		{"requiredVersion_2400", "2.4.0.0"},
	} {
		if acct.PropertyByName(v.prop) == nil {
			continue
		}
		version := st.version
		if version == "" {
			version = v.version
		}
		e.SetString(v.prop, version)
		break
	}
	return EncodeCreateBasePlayerWithComponents(e, s.cfg.AccountComponents)
}

// vehicleByInvID returns the compact descriptor of the session's vehicle
// with this inventory id, or nil when the garage does not hold it.
//
// The enqueue carries only the inventory id; the census buckets by the
// vehicle's class and the matchmaker by its tier, and both live in the
// descriptor.
func (st *clientState) vehicleByInvID(invID int32) []byte {
	for _, v := range st.garage {
		if int32(v.InvID) == invID {
			return v.CompactDescr
		}
	}
	return nil
}

// argAt returns args[i], or 0 when the call is shorter.
func argAt(args []int32, i int) int32 {
	if i < 0 || i >= len(args) {
		return 0
	}
	return args[i]
}

// int32Args pulls one ARRAY<INT32> argument out of a decoded call.
func int32Args(args []entdef.Value, i int) []int32 {
	if i < 0 || i >= len(args) || args[i].Kind != entdef.VSeq {
		return nil
	}
	out := make([]int32, 0, len(args[i].Seq))
	for _, v := range args[i].Seq {
		out = append(out, int32(v.Int))
	}
	return out
}

// accountCall builds an Account client method call element from the defs.
func (s *BaseAppServer) accountCall(method string, args ...entdef.Value) ([]byte, error) {
	if s.cfg.Dispatch == nil {
		return nil, fmt.Errorf("wotserver: %s needs the defs", method)
	}
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		return nil, fmt.Errorf("wotserver: no Account entity in the defs")
	}
	return EncodeClientMethodCall(NewEntity(0, acct), method, args)
}

// Element ids of entity method calls. The client sends base method N as
// element 0x88+N and cell method N as 0x10+N, so the method id is the
// element id minus the base — no table needed.
const (
	baseMethodElementID = 0x88
	cellMethodElementID = 0x10
)

// postCall is one decoded post-flood client call.
type postCall struct {
	// Req is the call's request id (the first argument).
	Req uint16
	// Cmd is the command id (the second argument), which is what the
	// answer switch keys on.
	Cmd uint16
	// Method is the defs' view of the call, or nil when the server runs
	// without a dispatch.
	Method *entdef.MethodDef
	// Args is every argument, in declared order.
	Args []entdef.Value
	// Elem is the client element id the call arrived on, kept so a decode
	// that lands on the wrong method can be diagnosed from the log.
	Elem byte
	// Body is the element's payload as it arrived, kept so a call whose
	// element id maps to the wrong method can still be read off the wire.
	Body []byte
	// EntityID is the entity a client -> server cell method addresses, which
	// the call carries ahead of its arguments. Zero for base methods.
	EntityID uint32
}

// Name is the method's def name, or a placeholder without a dispatch.
func (c postCall) Name() string {
	if c.Method == nil {
		return fmt.Sprintf("cmd %d", c.Cmd)
	}
	return c.Method.Name
}

// postDoCmd reads the leading entity-method call of a post-flood client
// bundle. Wire: [flags 2][02][key2 u32 LE][elemID u8][len u16 LE][args].
//
// The element id is the method id plus a fixed base, and the length is
// the method's fixed argument size, so with a dispatch the whole call is
// decoded from the defs — argument types included. Without one it falls
// back to the two calls the lobby actually sends (doCmdInt3/doCmdInt2),
// which is what the hand-written reader always did.
//
// Sync and poll share the doCmdInt3 element, so ONLY the command field
// tells them apart — matching on the element id alone answers every poll
// as a sync.
func (s *BaseAppServer) postDoCmd(clear []byte, key2 uint32) (postCall, bool) {
	if len(clear) < 14 || clear[2] != 0x02 {
		return postCall{}, false
	}
	if binary.LittleEndian.Uint32(clear[3:7]) != key2 {
		return postCall{}, false
	}
	elemID := clear[7]
	argLen := int(binary.LittleEndian.Uint16(clear[8:10]))
	if len(clear) < 10+argLen {
		return postCall{}, false
	}
	body := clear[10 : 10+argLen]

	if s.cfg.Dispatch != nil {
		// Both entities the session owns: the lobby's Account and the battle's
		// Avatar. Only trying Account meant every Avatar base method — above
		// all `leaveArena`, which is what "back to hangar" calls — was
		// silently dropped, leaving the client in the battle forever.
		// `leaveArena` is an Avatar base method, and Account has its own method
		// at the same slot — so a plain Account-first lookup decodes the leave
		// request as something else and the client never gets an answer. Check
		// for it by name before the generic pass.
		if av := s.cfg.Dispatch.Entity("Avatar"); av != nil {
			if m := av.MethodByID(entdef.CompBase, int(elemID)-baseMethodElementID); m != nil {
				s.logf("post-flood base elem=%#02x argLen=%d avatarMethod=%q", elemID, len(body), m.Name)
				if m.Name == "leaveArena" || m.Name == "leaveArenaByAccount" {
					args, err := m.ReadArgs(bytes.NewReader(body))
					if err == nil {
						return postCall{Method: m, Args: args, Elem: elemID, Body: body}, true
					}
					s.logf("post-flood leaveArena args: %v", err)
				}
			} else {
				s.logf("post-flood base elem=%#02x argLen=%d avatarMethod=none", elemID, len(body))
			}
		}
		for _, name := range []string{"Account", "Avatar"} {
			if acct := s.cfg.Dispatch.Entity(name); acct != nil {
				if m := acct.MethodByID(entdef.CompBase, int(elemID)-baseMethodElementID); m != nil {
					// The defs say how long the call is; a mismatch means the
					// model and the wire disagree, which is worth refusing
					// rather than decoding garbage.
					if m.Length.Fixed && m.Length.Size != argLen {
						s.logf("post-flood %s: element %#02x carries %d B, the defs say %d",
							m.Name, elemID, argLen, m.Length.Size)
						return postCall{}, false
					}
					args, err := m.ReadArgs(bytes.NewReader(body))
					if err != nil {
						s.logf("post-flood %s: %v", m.Name, err)
						return postCall{}, false
					}
					call := postCall{Method: m, Args: args, Elem: elemID, Body: body}
					if len(args) > 0 && args[0].Kind == entdef.VInt {
						call.Req = uint16(args[0].Int)
					}
					if len(args) > 1 && args[1].Kind == entdef.VInt {
						call.Cmd = uint16(args[1].Int)
					}
					return call, true
				}
			}
		}
	}

	// No dispatch: the two calls the lobby sends, by their pinned element
	// ids and argument sizes.
	switch [2]byte{elemID, byte(argLen)} {
	case [2]byte{0x95, 0x1c}, [2]byte{0x93, 0x14}:
		return postCall{
			Req: binary.LittleEndian.Uint16(clear[10:12]),
			Cmd: binary.LittleEndian.Uint16(clear[12:14]),
		}, true
	}
	return postCall{}, false
}

// postCalls decodes EVERY entity-method call in a post-flood client
// bundle. Wire: [flags 2][02][key2 u32 LE] then a run of
// [elemID u8][len u16 LE][args], with a chat tail (0x98) or an ack
// ending the run.
//
// The opener carries three calls in one datagram — the account sync
// (100), the shop sync (300) and the dossier sync (600) — and each one
// has a waitForSync() on the client side, so all of them must be
// answered, not just the leading one.
func (s *BaseAppServer) postCalls(clear []byte, key2 uint32) []postCall {
	if len(clear) < 14 || clear[2] != 0x02 {
		return nil
	}
	if binary.LittleEndian.Uint32(clear[3:7]) != key2 {
		return nil
	}
	tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
	end := len(clear) - tr
	if end <= 7 {
		return nil
	}
	var out []postCall
	for off := 7; off+3 <= end; {
		elemID := clear[off]
		argLen := int(binary.LittleEndian.Uint16(clear[off+1 : off+3]))
		if off+3+argLen > end {
			break
		}
		if elemID == 0x98 {
			// The chat tail (chatCommandFromClient) rides the same bundle
			// but is not a base method; skip it and keep walking.
			off += 3 + argLen
			continue
		}
		// Client -> server cell methods share the 0x10..0x4D element space with
		// the server -> client ones; the direction tells them apart, so there
		// is no collision. Only the gun-tracking calls are decoded — they are
		// what keeps the client's turret from snapping back to the server's
		// stale `gunAnglesPacked`.
		if elemID >= cellMethodElementID && elemID < entityMethodBase {
			if call, ok := s.decodeCellCall(elemID, clear[off+3:off+3+argLen]); ok {
				out = append(out, call)
			}
			// A cell method this server does not model is skipped, not fatal:
			// the element carries its own length, so the rest of the run is
			// still parseable. Breaking here dropped everything after the
			// client's `setRemoteCamera` — including `leaveArena`, which is why
			// the leave button stopped answering.
			off += 3 + argLen
			continue
		}
		call, ok := s.decodeBaseCall(elemID, clear[off+3:off+3+argLen])
		if !ok {
			// Not a base method the defs decode: log the whole bundle so
			// the element can be identified, then stop (the rest of the
			// run is unparseable without knowing this one's size).
			app := clear[7:end]
			if len(app) > 96 {
				app = app[:96]
			}
			s.logf("post-flood element %#02x at %d (%d B) undecoded; bundle: % x",
				elemID, off, argLen, app)
			break
		}
		out = append(out, call)
		off += 3 + argLen
	}
	return out
}

// answerGunTrack keeps `Vehicle.gunAnglesPacked` following the client's turret.
//
// `VehicleGunRotator.__syncWithServerTurretYaw` compares the yaw it computed
// with the one the server last sent and SNAPS to the server's when they differ
// by more than `0.1396 + 0.4 * maxTurretRotationSpeed` radians. With the
// vehicle's real rotation speed that tolerance is about 18 degrees, so a server
// that never sends `gunAnglesPacked` leaves the client pinned to the default
// (-pi) and the turret jumps to a limit instead of tracking.
//
// The client sends the point it is aiming at, relative to the vehicle, every
// tick it changes; the yaw is that point's bearing in the hull frame, clamped
// to the turret's own arc.
func (s *BaseAppServer) answerGunTrack(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	s.mu.Lock()
	vehicle := st.vehicle
	s.mu.Unlock()
	if vehicle == nil || len(call.Args) == 0 {
		return nil
	}
	// The call names the entity it addresses; anything but the player's own
	// tank is not ours to answer. `trackRelativePointWithGun` is a Vehicle
	// cell method and carries the vehicle's id, but `vehicle_stopTrackingWithGun`
	// is an Avatar one and carries the Avatar's — rejecting it left the
	// server aiming at a stale world point for the rest of the battle.
	if call.EntityID != 0 && call.EntityID != vehicle.ID && call.EntityID != st.entityID {
		return nil
	}
	switch call.Method.Name {
	case "stopTrackingWithGun", "vehicle_stopTrackingWithGun":
		// Hold the turret where the SERVER has it, which is what the
		// reference's `hold_gun` does (`turret.hold(turret.yaw, turret.pitch)`
		// — its own angles, not the ones the client reports). The two step at
		// the same rate from the same aim, so they are already together;
		// adopting the client's number instead would import whatever drift it
		// has accumulated, and clearing `aimSet` stops the tick re-deriving a
		// bearing from a world point the client has stopped updating.
		s.mu.Lock()
		st.gunTarget = st.gunYaw
		st.aimSet = false
		s.mu.Unlock()
		return nil
	default:
		v := call.Args[0]
		if v.Kind != entdef.VSeq || len(v.Seq) != 3 {
			return nil
		}
		// The hull frame is X right, Y up, Z forward, so the bearing is
		// atan2(x, z). `vehicle_trackWorldPointWithGun` carries a world point,
		// which this server cannot turn into a hull bearing without the
		// vehicle's own yaw — it is only sent when the client is not attached
		// to the vehicle, which does not happen here.
		if call.Method.Name == "vehicle_trackWorldPointWithGun" {
			return nil
		}
		// The point is relative to the hull, so it is only valid for the pose
		// it was sent with: convert it to world now and re-derive the bearing
		// from the current hull on every tick, or the turret desyncs as soon
		// as the tank moves.
		local := [3]float32{float32(v.Seq[0].Float), float32(v.Seq[1].Float), float32(v.Seq[2].Float)}
		s.mu.Lock()
		st.aimWorld = st.hull.aimWorldPoint(local)
		st.aimSet = true
		s.mu.Unlock()
		return nil
	}
}

// answerMoveWith records the client's `vehicle_moveWith` flags. The hull is
// stepped on the arena tick, not here: the client sends a flag byte whenever the
// driver changes gear or direction, and the movement itself is continuous.
func (s *BaseAppServer) answerMoveWith(st *clientState, call postCall) error {
	if len(call.Args) == 0 || call.Args[0].Kind != entdef.VUint {
		return nil
	}
	flags := uint8(call.Args[0].Uint)
	s.mu.Lock()
	changed := st.hull.Flags != flags
	st.hull.Flags = flags
	s.mu.Unlock()
	if changed {
		s.logf("moveWith flags %#02x", flags)
	}
	return nil
}

// Siege mode states, from the client's `constants.VEHICLE_SIEGE_STATE`.
const (
	siegeDisabled     uint8 = 0
	siegeSwitchingOn  uint8 = 1
	siegeEnabled      uint8 = 2
	siegeSwitchingOff uint8 = 3
)

// siegeModeSetting is `VEHICLE_SETTING.SIEGE_MODE_ENABLED`.
const siegeModeSetting = 3

// ownVehiclePropIndex is a property's position in `ownVehicleProps`, which is
// the index an NRL property update addresses.
func ownVehiclePropIndex(name string) int {
	for i, p := range ownVehicleProps {
		if p.Name == name {
			return i
		}
	}
	return -1
}

// The two shell settings the client sends through `vehicle_changeSetting`.
const (
	settingCurrentShell uint8 = 0
	settingNextShell    uint8 = 1
)

// vehicleSettingsValue is `OwnVehicle.vehicleSettings`: the loaded shell
// (`CURRENT_SHELLS`, 0) and the next one (`NEXT_SHELLS`, 1). The reference
// sends both, and the ammo panel's next-shell slot reads the second.
func vehicleSettingsValue(vehicleID uint32, loaded, next int32) entdef.Value {
	setting := func(code uint8, value int32) entdef.Value {
		return entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
			{Name: "vehicleID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(vehicleID)}},
			{Name: "code", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(code)}},
			{Name: "value", Value: entdef.Value{Kind: entdef.VInt, Int: int64(value)}},
		}}
	}
	return entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{setting(settingCurrentShell, loaded), setting(settingNextShell, next)}}
}

// applyShellSetting updates the session's loaded/next shell.
func applyShellSetting(st *clientState, code uint8, value int32) {
	switch code {
	case settingCurrentShell:
		st.loadedShell = value
	case settingNextShell:
		st.nextShell = value
	}
}

// answerShellSetting handles `CURRENT_SHELLS` and `NEXT_SHELLS`: it moves the
// session's shell and sends the updated `vehicleSettings`, so the next
// `vehicle_shoot` consumes the shell the client shows as loaded.
func (s *BaseAppServer) answerShellSetting(conn Transport, from *net.UDPAddr, st *clientState, code uint8, value int32) error {
	s.mu.Lock()
	oldLoaded := st.loadedShell
	applyShellSetting(st, code, value)
	comp := st.ownVehicle
	loaded, next := st.loadedShell, st.nextShell
	vehicle := st.vehicle
	reload := st.gunSpec.Dispersion.ReloadTime
	arenaID := uint64(0)
	if st.arena != nil {
		arenaID = st.arena.ArenaID
	}
	s.mu.Unlock()
	if comp.TypeID == 0 || vehicle == nil {
		return nil
	}
	dt := entdef.Alias("VEHICLE_SETTINGS")
	if dt == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, vehicleSettingsValue(vehicle.ID, loaded, next)); err != nil {
		s.logf("shell setting: encode: %v", err)
		return nil
	}
	el, err := EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("vehicleSettings"), buf.Bytes())
	if err != nil {
		s.logf("shell setting: element: %v", err)
		return nil
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("shell setting: send: %v", err)
		return nil
	}
	s.logf("shell setting %d = %d (loaded %d, next %d)", code, value, loaded, next)
	// A new loaded shell starts the gun's FULL reload, even mid-reload: the
	// client's `AmmoController.changeCurrentShell` sets its own reload state
	// and waits for the server's `vehicleGunReloadTime`, so without this the
	// gun stays "reloading" forever.
	if code == settingCurrentShell && value != oldLoaded && reload > 0 {
		if err := s.sendReloadStart(conn, from, st, comp, arenaID, reload); err != nil {
			s.logf("shell setting: reload start: %v", err)
		}
	}
	return nil
}

// answerChangeSetting handles `Avatar.vehicle_changeSetting(code, value)`.
//
// The client's X key (`SiegeModeControl.__switchSiegeMode`) sends
// `player.cell.vehicle_changeSetting(VEHICLE_SETTING.SIEGE_MODE_ENABLED,
// enableSiegeMode)` — cell index 12, a UINT8 code and an INT32 value, fixed
// 5 bytes. Only the siege switch is modelled; every other setting is ignored.
//
// Two things have to go out, and both are needed:
//
//   - `Vehicle.siegeState` (property 4, bare element `0xac`), which
//     `Avatar.__isOwnVehicleSwitchingSiegeMode` reads to block shooting during
//     the switch;
//   - `OwnVehicle.siegeStateStatus` (`FixedDict{?status:UINT8, endTime:FLOAT32,
//     timeLeft:FLOAT32}`), whose setter is `OwnVehicleBase.update_siegeStateStatus`
//     → `Avatar.updateSiegeStateStatus` → `Vehicle.onSiegeStateUpdated`, which
//     is what actually changes the model, the gun's pitch limits and the sound.
func (s *BaseAppServer) answerChangeSetting(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if len(call.Args) < 2 || call.Args[0].Kind != entdef.VUint || call.Args[1].Kind != entdef.VInt {
		return nil
	}
	code := uint8(call.Args[0].Uint)
	value := int32(call.Args[1].Int)
	if code == settingCurrentShell || code == settingNextShell {
		return s.answerShellSetting(conn, from, st, code, value)
	}
	if code != siegeModeSetting {
		return nil
	}
	enable := value != 0
	s.mu.Lock()
	spec := st.gunSpec
	vehicle := st.vehicle
	tick := st.tick
	arenaID := uint64(0)
	if st.arena != nil {
		arenaID = st.arena.ArenaID
	}
	s.mu.Unlock()
	if vehicle == nil || !spec.Dispersion.HasSiege {
		return nil
	}
	target, switching, switchTime := siegeDisabled, siegeSwitchingOff, spec.Dispersion.SiegeOff
	if enable {
		target, switching, switchTime = siegeEnabled, siegeSwitchingOn, spec.Dispersion.SiegeOn
	}
	// On the wheeled French tanks siege mode is the FAST mode, so the hull's
	// envelope swaps with it: the EBR 105 is 70/50 km/h in travel and 91/65 in
	// siege. Without this the tank is capped at the travel limit whatever the
	// client shows.
	if spec.Dispersion.HasSiegeLimits {
		limits := spec.Limits
		if enable {
			limits = spec.Dispersion.SiegeLimits
		}
		s.mu.Lock()
		st.hull.Limits = limits
		s.mu.Unlock()
	}
	// With a zero switch time the client is told the end state directly: a
	// SWITCHING state with `timeLeft` 0 would leave
	// `__isOwnVehicleSwitchingSiegeMode` true and the gun blocked.
	if switchTime <= 0 {
		if err := s.sendSiegeState(conn, from, st, vehicle.ID, target, 0, 0); err != nil {
			return err
		}
		s.logf("arena %d: siege → %d (instant)", arenaID, target)
		return nil
	}
	if err := s.sendSiegeState(conn, from, st, vehicle.ID, switching, float64(tick)/10+switchTime, switchTime); err != nil {
		return err
	}
	s.logf("arena %d: siege → switching %d over %.2fs", arenaID, switching, switchTime)
	go s.finishSiege(conn, from, st, arenaID, vehicle.ID, target, switchTime)
	return nil
}

// finishSiege sends the settled siege state once the switch time has elapsed.
func (s *BaseAppServer) finishSiege(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, vehicleID uint32, target uint8, switchTime float64) {
	time.Sleep(time.Duration(switchTime * float64(time.Second)))
	s.mu.Lock()
	still := st.arena != nil && st.arena.ArenaID == arenaID
	s.mu.Unlock()
	if !still {
		return
	}
	if err := s.sendSiegeState(conn, from, st, vehicleID, target, 0, 0); err != nil {
		s.logf("arena %d: siege settle failed: %v", arenaID, err)
		return
	}
	s.logf("arena %d: siege → %d", arenaID, target)
}

// sendSiegeState pushes `Vehicle.siegeState` and `OwnVehicle.siegeStateStatus`.
func (s *BaseAppServer) sendSiegeState(conn Transport, from *net.UDPAddr, st *clientState, vehicleID uint32, status uint8, endTime, timeLeft float64) error {
	s.mu.Lock()
	comp := st.ownVehicle
	s.mu.Unlock()
	dt := entdef.Alias("SIEGE_STATE_STATUS")
	if dt == nil || comp.TypeID == 0 {
		return nil
	}
	value := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "status", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(status)}},
		{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat, Float: endTime}},
		{Name: "timeLeft", Value: entdef.Value{Kind: entdef.VFloat, Float: timeLeft}},
	}}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, value); err != nil {
		return err
	}
	// `OwnVehicle.siegeStateStatus` is the ONLY route to
	// `Avatar.updateSiegeStateStatus`, which is not a def method: its setter
	// `OwnVehicleBase.update_siegeStateStatus` calls it, and that is what
	// reaches `Vehicle.onSiegeStateUpdated`. Without it the client's
	// `SiegeModeControl.__currentState` never leaves DISABLED — measured live,
	// `Vehicle.siegeState` read 2 while `__currentState` was still 0 — so the
	// HUD never shows siege, the composite descriptor never switches to
	// `VEHICLE_MODE.SIEGE`, and pressing X can only ever ask to ENABLE again.
	//
	// It rides the NRL node update, like the reload: index 10 of
	// `ownVehicleProps`, which matches `OwnVehicle.def`'s `CSPropsOrdered`
	// (one fixed property, `syncVehicleAttrs`, then the variable ones in
	// declaration order).
	app := EncodeBareU8(elVehicleSiegeState, status)
	if el, err := EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("siegeStateStatus"), buf.Bytes()); err == nil {
		app = append(app, el...)
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
	st.sendMu.Unlock()
	return err
}

// sendReloadStart starts the gun's full reload and schedules its completion.
// Every start bumps `reloadGen`; the completion only closes the reload whose
// generation is still current, so a shell switch that restarts the reload is
// not cut short by the previous timer.
func (s *BaseAppServer) sendReloadStart(conn Transport, from *net.UDPAddr, st *clientState, comp nrlComponent, arenaID uint64, reload float64) error {
	s.mu.Lock()
	tick := st.tick
	st.reloadGen++
	gen := st.reloadGen
	s.mu.Unlock()
	dt := entdef.Alias("VEHICLE_GUN_RELOAD_TIME")
	if dt == nil {
		return nil
	}
	value := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat, Float: float64(tick)/10 + reload}},
		{Name: "baseTime", Value: entdef.Value{Kind: entdef.VFloat, Float: reload}},
		{Name: "timeLeft", Value: entdef.Value{Kind: entdef.VFloat, Float: reload}},
		{Name: "clipTime", Value: entdef.Value{Kind: entdef.VFloat}},
	}}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, value); err != nil {
		return err
	}
	el, err := EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("vehicleGunReloadTime"), buf.Bytes())
	if err != nil {
		return err
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		return err
	}
	s.logf("arena %d: reload %.2fs started (seq %d, %dB)", arenaID, reload, seq, len(el))
	go s.finishReload(conn, from, st, arenaID, reload, gen)
	return nil
}

// answerShoot starts the gun's reload.
//
// `Avatar.vehicle_shoot` is a CELL method on the Avatar with **no arguments**
// (cell index 0, fixed size 0), so there is nothing to decode: the shot's
// direction and dispersion are already in the NRL gun marker the client draws
// its crosshair from, and the client fires its own visual — tracer, muzzle
// flash, recoil — from `Avatar.__showTimedOutShooting` after a 0.12-0.2 s
// timeout whether or not the server answers. What the server owes it is the
// reload, or the gun fires once and never again.
//
// The reload rides `OwnVehicle.vehicleGunReloadTime`, an NRL dynamic-component
// property, so it goes out as a node update rather than a bare element.
// `OwnVehicleBase.__getTimeLeftBaseTime` reads `timeLeft` directly once the
// vehicle is attached, and `baseTime` is the reload's length, so both carry the
// gun's own `reloadTime`; `endTime` is in the seconds `BigWorld.serverTime()`
// is in, which is the same base `periodEndTime` uses.
func (s *BaseAppServer) answerShoot(conn Transport, from *net.UDPAddr, st *clientState) error {
	s.mu.Lock()
	comp := st.ownVehicle
	reload := st.gunSpec.Dispersion.ReloadTime
	arenaID := uint64(0)
	if st.arena != nil {
		arenaID = st.arena.ArenaID
	}
	s.mu.Unlock()
	if comp.TypeID == 0 || reload <= 0 {
		return nil
	}
	// The shot consumes a shell. This goes out before the reload so the
	// panel's count drops as the reload starts.
	s.decrementAmmo(conn, from, st, comp)
	if err := s.sendReloadStart(conn, from, st, comp, arenaID, reload); err != nil {
		s.logf("arena %d: shoot: reload start failed: %v", arenaID, err)
	}
	// The shell itself: trace it against the synthetic opponent and stream
	// the damage. A miss sends nothing, the client having drawn its own shot.
	s.applyShot(conn, from, st, arenaID)
	return nil
}

// takeAmmo removes one shell of `shell` from a `vehicleAmmoList` value and
// returns the new list and the remaining count. It reports false when the
// shell is not in the list or its count is already zero.
func takeAmmo(ammo entdef.Value, shell int32) (entdef.Value, uint64, bool) {
	if ammo.Kind != entdef.VSeq || len(ammo.Seq) == 0 || shell == 0 {
		return ammo, 0, false
	}
	for i := range ammo.Seq {
		cd, ok := ammo.Seq[i].Get("compactDescr")
		if !ok || cd.Int != int64(shell) {
			continue
		}
		q, ok := ammo.Seq[i].Get("quantity")
		if !ok || q.Uint == 0 {
			return ammo, 0, false
		}
		remaining := q.Uint - 1
		ammo.Seq[i] = dictSet(ammo.Seq[i], "quantity", entdef.Value{Kind: entdef.VUint, Uint: remaining})
		return ammo, remaining, true
	}
	return ammo, 0, false
}

// decrementAmmo takes one shell of the loaded round out of the session's
// `vehicleAmmoList` and re-sends the property. The list is the one
// `ownVehicleOverrides` built from the garage's saved layout; the client's
// ammo panel reads `quantity` from it and nothing else updates it.
func (s *BaseAppServer) decrementAmmo(conn Transport, from *net.UDPAddr, st *clientState, comp nrlComponent) {
	s.mu.Lock()
	ammo := st.ammoList
	shell := st.loadedShell
	s.mu.Unlock()
	if ammo.Kind != entdef.VSeq || len(ammo.Seq) == 0 || shell == 0 {
		return
	}
	ammo, remaining, changed := takeAmmo(ammo, shell)
	if !changed {
		return
	}
	dt := entdef.Alias("VEHICLE_AMMO_LIST")
	if dt == nil {
		return
	}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, ammo); err != nil {
		s.logf("shoot: ammo list encode: %v", err)
		return
	}
	el, err := EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("vehicleAmmoList"), buf.Bytes())
	if err != nil {
		s.logf("shoot: ammo list element: %v", err)
		return
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("shoot: ammo list send: %v", err)
		return
	}
	s.mu.Lock()
	st.ammoList = ammo
	s.mu.Unlock()
	s.logf("shoot: consumed a shell of %d (now %d)", shell, remaining)
}

// finishReload sends the zeroed `vehicleGunReloadTime` once the reload is over.
func (s *BaseAppServer) finishReload(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, reload float64, gen uint64) {
	time.Sleep(time.Duration(reload * float64(time.Second)))
	s.mu.Lock()
	comp := st.ownVehicle
	still := st.arena != nil && st.arena.ArenaID == arenaID && st.reloadGen == gen
	s.mu.Unlock()
	if !still || comp.TypeID == 0 {
		return
	}
	dt := entdef.Alias("VEHICLE_GUN_RELOAD_TIME")
	if dt == nil {
		return
	}
	value := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat}},
		{Name: "baseTime", Value: entdef.Value{Kind: entdef.VFloat, Float: reload}},
		{Name: "timeLeft", Value: entdef.Value{Kind: entdef.VFloat}},
		{Name: "clipTime", Value: entdef.Value{Kind: entdef.VFloat}},
	}}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, value); err != nil {
		return
	}
	el, err := EncodeNrlPropertyUpdate(comp, ownVehiclePropIndex("vehicleGunReloadTime"), buf.Bytes())
	if err != nil {
		return
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("arena %d: reload finish send failed: %v", arenaID, err)
		return
	}
	s.logf("arena %d: reload done (seq %d, %dB)", arenaID, seq, len(el))
}

// packGunAngles is `gun_rotation_shared.encodeGunAngles`: a 10-bit yaw over
// [-pi, pi) in the high bits and the pitch's 6 bits below it, the pitch packed
// over the gun's own `pitchLimits` (`encodeRestrictedValueToUint`).
//
// The captured server never sends this — it sends no property updates at all —
// but this client cannot derive the turret yaw on its own: its physics is
// inert (`Vehicle.mover` does not exist, so `physics_shared.updateConf()` is
// dead and `numTrackContacts` is 0/0), and `VehicleGunRotator` reads the yaw
// back out of this property. Without it the turret sits at the def's default
// of -pi and the gun points backwards into the hull.
func packGunAngles(yaw, pitch, pitchMin, pitchMax float64) uint64 {
	const bits = 10
	mask := uint64(1)<<bits - 1
	code := uint64(math.Round(float64(mask+1)*(yaw+math.Pi)/(2*math.Pi))) & mask
	t := 0.0
	if pitchMax != pitchMin {
		t = (pitch - pitchMin) / (pitchMax - pitchMin)
	}
	t = math.Min(math.Max(t, 0), 1)
	return code<<6 | uint64(math.Round(63*t))
}

// arenaTickApp builds one arena tick datagram, in the captured server's exact
// element order: `0x13` TickSync, `0x16` the metre-rounded reference point,
// `0x1e` the player's own entity on it, `0x1d` the Vehicle by alias at its
// absolute position, then `0x28` the NRL gun marker.
//
// That is the whole of a captured tick datagram — 7702 of them over the Oct-31
// battle, and not one carries a property update. The gun marker closes it:
// 7183 ticks carry the full 39-byte marker and 408 the 8-byte "unchanged" form,
// in runs up to 101 ticks (the pre-battle countdown).
//
// The marker is the ONLY thing the captured server sends for the gun. It sends
// no `gunAnglesPacked` property update at all, and the client does not need
// one: `Avatar.updateGunMarker` hands the marker to
// `VehicleGunRotator.setShotPosition`, which is what the crosshair and the
// turret sync are drawn from.
// noGunMarker, when set, drops the `0x28` from the tick. It exists to bisect a
// client that stops applying the position elements: if the tank moves with the
// marker off, the marker's framing is what the client is rejecting.
// noGunMarker drops the `0x28` NRL gun marker from the tick. WOT_NO_MARKER
// turns it off without a rebuild.
//
// It was off because the client rejected every one with "Received snapshot
// delta with no base snapshot found". The cause was the tick counter starting
// at 0: the marker's `seqNum` is that counter, and
// `UnreliableSnapshotBufferReceiver::applyDelta` drops a delta whose seqNum is
// not above the last one it used, so no snapshot was ever created and every
// later delta had no base. See `nrlTickEpoch`.
var noGunMarker = os.Getenv("WOT_NO_MARKER") != ""

// selfAliasOff drops the player's own `0x1d` AliasDetailed from the tick.
var selfAliasOff = os.Getenv("WOT_SELF_ALIAS_OFF") != ""

// controlEntityOn sends `controlEntity(vehicle, true)` at the arena entry.
var controlEntityOn = os.Getenv("WOT_CONTROL_ENTITY") != ""

// vehiclePropsOn sends the Vehicle's `gunAnglesPacked` and `engineMode` as bare
// property elements at the end of the tick.
var vehiclePropsOn = os.Getenv("WOT_NO_VEHICLE_PROPS") == ""

func arenaTickApp(tick uint32, pos, dir [3]float32, idA, idB uint32, marker, last nrlGunMarker, haveLast bool, avatarID, vehicleID uint32, aux uint64, gunAngles uint16, engineMode uint16, wheels []byte, battleStarted bool) []byte {
	// The captured server's tick datagram, element for element and in its
	// order. A steady-state sample (14:17:26.241, 81 B) walks as
	//
	//	13 d3                                  TickSync
	//	16 000011c4 0000a0c0 00000f43          RelativePosition (-580, -5, 143)
	//	1e 00 0…0 0…0                          PlayerDetailed, on the reference
	//	1d 00 fd <pos> <dir>                   AliasDetailed, alias 253
	//	35 00 fc <packed> <ypr> <unk>          AliasFullPosYawPitchRoll, alias 252
	//
	// and the 440 B sample at 14:18:44.647 adds the bare property elements:
	//
	//	13 e3 1a ba <8 B aux> 16 … 1e … 1d … b4 <2 B> 35 … b6 <2 B> b4 <2 B> …
	//
	// The ORDER is load-bearing, not cosmetic. A bare property element
	// (`0xba`, `0xb4`, `0xb6`) has no entity id: it applies to whatever entity
	// the last selection element named. `0x1a` selects the player, `0x1d` and
	// `0x35` select an alias. So the aux word must follow `0x1a` and precede
	// `0x1d`, and the Vehicle's two must follow `0x1d` — which is exactly what
	// the capture does. Sending the aux after `0x1d` (as this did) leaves the
	// player selected, and the Vehicle's `0xb4`/`0xb6` then land on the Avatar,
	// where those ids mean `denunciationsLeft` and `battleChatRestriction`.
	app := EncodeTickSync(byte(tick))
	// The hull's attitude, both tracks' speeds and the engine RPM, as a bare
	// property element on the player's own entity: `0x1a` SelectPlayerEntity,
	// then `0xba` and the eight-byte word. It is the ONLY thing that makes the
	// tracks scroll and the tacho move — the client's
	// `__onSetOwnVehicleAuxPhysicsData` unpacks it into
	// `appearance.updateTracksScroll`, and `physicRPMLink` reads field 5 of the
	// same word. Measured in the capture, the track speeds ramp 1.94 -> 4.94
	// m/s and the RPM 0.00 -> 0.65 as the tank pulls away.
	//
	// It starts only once the tank has MOVED. The capture's first aux is at
	// 14:17:37.942, the first tick after the tank pulls away, and there is none
	// during the loading screen; sending it from the first tick instead leaves
	// the client stuck on the loading screen with `isOnArena` false, measured.
	// After that it goes out every tick, parked or not (656 parked to 5210
	// moving over the battle).
	if battleStarted {
		app = append(app, EncodeSelectPlayerEntity()...)
		app = append(app, EncodeBareU64(elAvatarAuxPhysicsData, aux)...)
	}
	app = append(app, EncodeRelativePosition(roundVec3(pos))...)
	app = append(app, EncodeAvatarUpdatePlayerDetailed(0, [3]float32{}, [3]float32{})...)
	// selfAliasOff drops the player's own `0x1d`, leaving the client's physics
	// to drive its own tank. It is a switch because if the physics turns out to
	// be inert the tank freezes instead of driving — measured: it does.
	aliasSent := false
	if !selfAliasOff {
		app = append(app, EncodeAvatarUpdateAliasDetailed(0, VehicleAlias, pos, dir)...)
		aliasSent = true
	}
	// The turret yaw and the engine mode, as bare property elements on the
	// Vehicle — the alias `0x1d` just selected. `gunAnglesPacked` is what
	// `__syncWithServerTurretYaw` snaps the turret to (without it the turret
	// sits at the def's zero, which decodes to yaw -pi, i.e. the gun pointing
	// backwards into the hull), and `engineMode` is what
	// `appearance.changeEngineMode` feeds to the track scroll controller.
	_ = avatarID
	_ = vehicleID
	if vehiclePropsOn && battleStarted && aliasSent {
		app = append(app, EncodeBareU16(elVehicleGunAnglesPacked, gunAngles)...)
		app = append(app, EncodeBareU16(elVehicleEngineMode, engineMode)...)
		// `wheelsScroll` (`0xc2`, `Tuple[0]{UINT8}`): one packed angular
		// speed per non-track wheel, which `Vehicle.set_wheelsScroll` unpacks
		// with `WoT.unpackWheelScroll` and feeds to each wheel's scroll
		// filter. Without it a wheeled vehicle's wheels never turn.
		//
		// The element is `c2 <len8> <count> <count bytes>`: the property's
		// `VariableLengthHeaderSize` is 1, so the length is one byte
		// (`ElementLength::Variable8`), and a tuple with no fixed element
		// count carries that count in the payload. The count must equal
		// `getNonTrackWheelsCount()` — 8 on the EBR 105 — because the client
		// zips it against a filter list of exactly that length.
		if len(wheels) > 0 {
			app = append(app, EncodeBareU8Tuple(elVehicleWheelsScroll, wheels)...)
		}
	}
	if !noGunMarker {
		if el, err := nrlMarkerElement(idA, idB, tick, marker, last, haveLast); err == nil {
			app = append(app, el...)
		}
	}
	return app
}

// tickEpoch is the value a battle's tick counter starts at: the server's own
// 10 Hz uptime, floored at 1.
//
// The counter is a 10 Hz tick count, and the captured server's reads 1126468 at
// the first gun marker of a battle — 31.3 hours of uptime, which is what a
// long-running server's counter looks like, not a constant. It must be at least
// 1: the NRL gun marker's `seqNum` is this counter, and
// `UnreliableSnapshotBufferReceiver::applyDelta` drops a delta whose seqNum is
// not above the last one it used, which starts at 0 — so a first marker with
// seqNum 0 is rejected, no snapshot is ever created, and every later delta then
// fails with "no base snapshot found".
func (s *BaseAppServer) tickEpoch() uint32 {
	n := uint32(time.Since(s.startedAt) / arenaTickPeriod)
	if n == 0 {
		n = 1
	}
	return n
}

// arenaTickPeriod is how often the arena tick goes out.
//
// The client does not interpolate the player's vehicle: `WGVehicleFilter`'s
// per-frame update (`sub_142F022A0`) writes `bodyMatrix` straight from the
// entity position, and the only extrapolation in the filter
// (`sub_142EFF3D0`) is lag compensation — its blend factor is
// `(distance_to_server - 30) * 0.0333`, so it stays 0 until the client is
// more than 30 m behind, and it is additionally gated by
// `filter.allowStrafeCompensation`, which `Vehicle.startVisual` sets to
// `not isPlayerVehicle`. Measured live with a Frida probe: `bodyMatrix` and
// the entity position agree to the last digit at every sample, driving or
// not. Measured again on this server with a pyconsole sampler: 69 position
// changes in 12.4 s of driving, each a discrete jump of 1.4 m median, the
// position bit-identical in between. So the tank is drawn at whatever the
// last update said, and the only lever is the rate.
//
// 100 ms is the client's own `SERVER_TICK_LENGTH`, the reference's `TICK` and
// the official server's measured rate: exactly 10 S>C datagrams/s over the
// whole Oct-31 battle, one per tick. The captured server sends them on the
// RELIABLE stream — 7582 of 7702 `0x13`-led datagrams are `fl=0x0458`
// (ON|RELIABLE|SEQ|CUMUL) and 109 are the unreliable `fl=0x1448` — which only
// works because its reliable channel carries nothing else. Ours now carries
// nothing else either, so the tick rides the same stream; the unreliable form
// is the fallback for a deep backlog (see `arenaTickReliableBacklog`).
const arenaTickPeriod = 100 * time.Millisecond

// arenaTickReliableBacklog is how many of a session's reliable packets may be
// awaiting acknowledgement before the arena tick falls back to the unreliable
// stream. The captured server sends the tick reliably 98.6% of the time
// (7582 to 109 over one battle), so the fallback is the exception, not the
// rule.
const arenaTickReliableBacklog = 8

// stepTurret walks the turret yaw toward the target by at most step radians,
// the SHORTEST way round, as the reference's
// `wrap_angle(yaw - self.yaw).clamp(-max, max)` does.
//
// Without the wrap the difference across the +/-pi seam is nearly a full turn,
// so the turret swings the long way while the client — which takes the short
// way — snaps back to it: the gun desyncs as soon as the hull turns far enough
// for the bearing to cross the seam.
func stepTurret(cur, target, step float64) float64 {
	switch d := float64(wrapAngle(float32(target - cur))); {
	case d > step:
		cur += step
	case d < -step:
		cur -= step
	default:
		cur = target
	}
	return float64(wrapAngle(float32(cur)))
}

// trackTurret steps the server's turret yaw toward the client's aim and sends
// `gunAnglesPacked` at a fixed rate, until the session leaves the arena.
//
// This is what makes the turret swing instead of jump. `VehicleGunRotator`
// rotates at `maxTurretRotationSpeed` and then snaps to whatever the server
// last sent if the two differ by more than `0.1396 + 0.4 * speed` radians —
// about 18 degrees at a real turret speed. A server that echoes the aim point's
// bearing is therefore always a whole swing ahead, and the client jumps to it.
// Stepping the server's yaw at the same rate keeps the two within one tick.
func (s *BaseAppServer) trackTurret(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, spec gunSpec, terrain *Terrain) {
	// `SERVER_TICK_LENGTH` is 0.1 in the client's own `common/constants.pyc`
	// and the reference ticks at 100 ms, but the client draws the tank at
	// whatever the last position update said (see `arenaTickPeriod`), so the
	// period is the tank's frame rate and 100 ms is ten visible steps a
	// second. What matters for the turret is that the step is the *measured*
	// elapsed time and not a nominal one: the client advances its turret by
	// `maxTurretRotationSpeed * (BigWorld.time() - lastTick)`, so a server that
	// steps by a fixed amount drifts against it, and every time the drift
	// passes the sync tolerance the client snaps — which is the choppiness.
	const period = arenaTickPeriod
	t := time.NewTicker(period)
	defer t.Stop()
	last := time.Now()
	for range t.C {
		now := time.Now()
		dt := now.Sub(last).Seconds()
		last = now
		if dt > 0.2 {
			dt = 0.2 // the client caps its own timeDiff at __MAX_TIME_DIFF
		}

		s.mu.Lock()
		// Only leaving the arena ends the tick. A missing entity is a moment
		// in the entry or the teardown, not a reason to stop: a ticker that
		// returned there left the tank frozen for the rest of the battle.
		if st.arena == nil || st.arena.ArenaID != arenaID {
			s.mu.Unlock()
			s.logf("arena %d: tick stopped, the session left the arena", arenaID)
			return
		}
		if st.vehicle == nil || st.avatar == nil {
			s.mu.Unlock()
			continue
		}
		vehicle, cur, target := st.vehicle, st.gunYaw, st.gunTarget
		if st.aimSet {
			target = float64(st.hull.aimLocalBearing(st.aimWorld))
			if spec.YawMax > spec.YawMin {
				if target < spec.YawMin {
					target = spec.YawMin
				}
				if target > spec.YawMax {
					target = spec.YawMax
				}
			}
		}
		s.mu.Unlock()

		prevCur := cur
		cur = stepTurret(cur, target, spec.Turret*dt)
		// The turret's actual rotation rate, which is what the client's
		// dispersion model multiplies by the gun's `turretRotation` factor.
		turretRate := 0.0
		if dt > 0 {
			turretRate = float64(wrapAngle(float32(cur-prevCur))) / dt
		}
		// The elevation, as the reference's `Turret::step` does: the aim
		// point's angle above the hull, stepped at the gun's own rate and
		// clamped to the gun's pitch limits.
		pitch := st.gunPitch
		if st.aimSet {
			// From the gun's pivot, not the hull's origin: the gun sits
			// `GunHeight` above it, and measuring from the hull reads a level
			// aim as several degrees of depression.
			dx := float64(st.aimWorld[0] - st.hull.Position[0])
			dy := float64(st.aimWorld[1] - st.hull.Position[1] - float32(spec.GunHeight))
			dz := float64(st.aimWorld[2] - st.hull.Position[2])
			want := -math.Atan2(dy, math.Hypot(dx, dz))
			if spec.PitchMax > spec.PitchMin {
				want = math.Min(math.Max(want, spec.PitchMin), spec.PitchMax)
			}
			step := spec.Gun * dt
			switch d := want - pitch; {
			case d > step:
				pitch += step
			case d < -step:
				pitch -= step
			default:
				pitch = want
			}
		}

		// The hull moves on the same tick, at the vehicle's own limits, and
		// rests on the terrain. The client drives its own copy and corrects
		// toward what arrives here, so this is what makes the tank actually go
		// anywhere.
		s.mu.Lock()
		// The move is refused when it leaves the map: `settle` reports whether
		// it found the ground, and off the edge there is none — the tank would
		// keep its height and drive out into nothing, which is how it ended up
		// 9 km off the map and underground.
		before := st.hull
		moved := st.hull.step(float32(dt))
		// Refuse a move that steps OFF the map, and only that: the hull is
		// restored when the terrain had ground under it a moment ago and has
		// none now. Refusing whenever the ground is missing froze the tank at
		// spawn, where the terrain lookup can fail for reasons that have
		// nothing to do with the edge.
		if moved && terrain != nil {
			if st.hull.settle(terrain, float32(dt)) {
				st.hadGround = true
			} else if st.hadGround {
				st.hull = before
				st.hull.Speed = 0
				st.hull.Velocity = [2]float32{}
				st.hull.YawRate = 0
				moved = false
			}
		}
		pos, dir := st.hull.Position, st.hull.Direction
		// The hull is copied under the lock: `answerMoveWith` writes its
		// flags from the receive goroutine, and the gun marker below reads
		// the whole struct.
		hullNow := st.hull

		// The dispersion factor, on the client's own model
		// (`Avatar.getOwnVehicleShotDispersionAngle`): the ideal factor is
		// `sqrt(1 + (speed*movement)^2 + (yawRate*rotation)^2 +
		// (turretRate*turretRotation)^2)`, and the factor decays toward it
		// over the gun's `aimingTime` but snaps up to it immediately.
		st.dispFactor = stepDispersion(st.dispFactor, st.hull, turretRate, spec.Dispersion, dt)
		dispFactor := st.dispFactor
		st.gunYaw, st.gunPitch = cur, pitch
		s.mu.Unlock()

		// A failed write is one lost update, not the end of the battle: the
		// next tick carries the position again.
		//
		// Every tick, not on divergence: the client's own physics does not
		// move its tank here, so these updates are the only thing that does.
		// Gating them on a distance made the tank teleport in 3 m steps.
		//
		// Two datagrams per tick, split by what they are:
		//
		//   - the POSITION datagram: `TickSync`, the metre-rounded reference,
		//     the player entity on it, and the Vehicle by alias. Reliable by
		//     default with an unreliable fallback (see the send below), which
		//     is the captured server's own split.
		//   - the PROPERTY datagram, reliable, and only when one of the values
		//     actually changed. The captured server sends no property updates
		//     at all during a battle — 2463 `0x13`-led datagrams and zero
		//     `0x19`-led ones over 250 s — so this bundle is the one place we
		//     still add traffic it does not. Gating it on change is the
		//     closest we can get without dropping the values entirely, which
		//     the doc records as making the turret snap.
		//
		// The position datagram opens with `TickSync`, as the reference's
		// `write_tick` does: it is the first element of every tick, and the
		// client's witness needs it to know a tick has arrived. Without it the
		// position updates were applied in bursts — the tank sat still for
		// seconds and then jumped twenty metres.
		s.mu.Lock()
		tick := st.tick
		st.tick++
		idA, idB := st.nrlIDa, st.nrlIDb
		lastMarker, lastMarkerSet := st.lastMarker, st.lastMarkerSet
		s.mu.Unlock()
		// One datagram per tick, in the captured server's exact shape:
		// TickSync, the metre-rounded reference point, the player's own entity
		// on it, the Vehicle by alias at its absolute position, then the NRL
		// gun marker.
		//
		// The alias update is NOT decoration and must not be dropped: the
		// tank the client draws is the Vehicle entity, which is addressed by
		// the alias `enterAoI` gave it, and `AvatarUpdatePlayerDetailed`
		// alone leaves it where it was created — the tank does not move and
		// the gun, which aims from the hull matrix, cannot track either.
		// (The reference gets away without it because its player entity is
		// the vehicle; ours are separate entities.)
		// All three position elements go out EVERY tick.
		//
		// The captured server sends `0x16` RelativePosition and `0x1e`
		// PlayerDetailed only when the player's position changed (0/s parked,
		// 9-10/s driving) and `0x1d` AliasDetailed every tick. We send all
		// three every tick on purpose: the player ENTITY is driven by the
		// client's own `BigWorld.AvatarFilter`, and with the reference pair
		// withheld while parked that filter has no fresh input and the entity
		// drifts — measured live, `BigWorld.player().position` sat 500 m from
		// `vehicle.position` ((-134.8, 106.8, 131.7) against (370.3, 56.4,
		// 387.9), both in space 1) while the camera, which follows the vehicle
		// matrix, was correctly 12 m behind the tank. Re-anchoring it every
		// tick costs 39 B on a datagram the capture shows at 181-500 B.
		if tick%10 == 0 {
			s.logf("arena %d tick %d: hull pos=(%.2f,%.2f,%.2f) yaw=%.3f speed=%.2f flags=%#02x limits fwd=%.2f bwd=%.2f rot=%.2f hadGround=%v airborne=%v",
				arenaID, tick, hullNow.Position[0], hullNow.Position[1], hullNow.Position[2],
				hullNow.Direction[2], hullNow.Speed, hullNow.Flags,
				hullNow.Limits.SpeedForward, hullNow.Limits.SpeedBackward, hullNow.Limits.RotationSpeed, st.hadGround, hullNow.Airborne)
		}
		marker := gunMarkerFor(hullNow, cur, pitch, spec, dispFactor)
		mode := hullNow.engineMode()
		posApp := arenaTickApp(tick, pos, dir, idA, idB, marker, lastMarker, lastMarkerSet,
			st.entityID, vehicle.ID, hullNow.auxPhysicsData(),
			uint16(packGunAngles(cur, pitch, spec.PitchMin, spec.PitchMax)),
			uint16(mode[0])|uint16(mode[1])<<8, hullNow.wheelsScroll(spec.Dispersion.WheelRadii), st.battleStarted)
		s.mu.Lock()
		st.lastMarker, st.lastMarkerSet = marker, true
		s.mu.Unlock()
		// The datagram goes on the UNRELIABLE stream.
		//
		// The captured server puts it on the reliable one (7582 of 7702
		// `0x13`-led datagrams are `fl=0x0458`), but that only works because
		// its reliable channel carries nothing else. Ours carries the property
		// bundle every tick — which this client needs, see below — and the
		// positions then queue behind it: measured with the window focused at
		// 40 fps, the tank stepped at 3.10 Hz with 200 ms p50 / 300 ms p90
		// gaps and a 2.7 s stall while the camera moved smoothly at 5.64 Hz.
		// On the unreliable stream the same tick lands at 9.86 Hz with 104 ms
		// gaps. The bundle is the thing that has to go before the tick can
		// move to the reliable stream.
		st.sendMu.Lock()
		err := s.sendUnreliableLocked(conn, from, st, posApp)
		st.sendMu.Unlock()
		if err != nil {
			s.logf("arena %d: tick send failed: %v", arenaID, err)
		}
	}
}

// decodeCellCall decodes one client -> server cell method. Only the gun
// tracking calls are modelled; anything else is left to the base-method path
// (and then to the undecoded log line).
func (s *BaseAppServer) decodeCellCall(elemID byte, body []byte) (postCall, bool) {
	if s.cfg.Dispatch == nil {
		return postCall{}, false
	}
	// A client -> server cell method carries the entity it addresses first:
	// `[elemID][len u16][entityID u32][args]`. The id is what says which
	// entity's table the method index belongs to.
	if len(body) < 4 {
		return postCall{}, false
	}
	entityID := binary.LittleEndian.Uint32(body[0:4])
	args := body[4:]
	idx := int(elemID) - cellMethodElementID
	for _, name := range []string{"Vehicle", "Avatar"} {
		e := s.cfg.Dispatch.Entity(name)
		if e == nil {
			continue
		}
		m := e.MethodByID(entdef.CompCell, idx)
		if m == nil {
			continue
		}
		switch m.Name {
		case "trackRelativePointWithGun", "vehicle_trackWorldPointWithGun",
			"stopTrackingWithGun", "vehicle_stopTrackingWithGun",
			"vehicle_moveWith", "vehicle_shoot", "vehicle_changeSetting":
		default:
			continue
		}
		if m.Length.Fixed && m.Length.Size != len(args) {
			continue
		}
		vals, err := m.ReadArgs(bytes.NewReader(args))
		if err != nil {
			continue
		}
		return postCall{Method: m, Args: vals, Elem: elemID, Body: body, EntityID: entityID}, true
	}
	return postCall{}, false
}

// decodeBaseCall decodes one base-method element from the defs, falling
// back to the two calls the lobby sends when the server runs without a
// dispatch.
func (s *BaseAppServer) decodeBaseCall(elemID byte, body []byte) (postCall, bool) {
	if s.cfg.Dispatch != nil {
		// Both entities the session owns: the lobby's Account and the battle's
		// Avatar. Only trying Account meant every Avatar base method — above
		// all `leaveArena`, which is what "back to hangar" calls — was
		// silently dropped, leaving the client in the battle forever.
		// `leaveArena` is an Avatar base method, and Account has its own method
		// at the same slot — so a plain Account-first lookup decodes the leave
		// request as something else and the client never gets an answer. Check
		// for it by name before the generic pass.
		if av := s.cfg.Dispatch.Entity("Avatar"); av != nil {
			if m := av.MethodByID(entdef.CompBase, int(elemID)-baseMethodElementID); m != nil {
				s.logf("post-flood base elem=%#02x argLen=%d avatarMethod=%q", elemID, len(body), m.Name)
				if m.Name == "leaveArena" || m.Name == "leaveArenaByAccount" {
					args, err := m.ReadArgs(bytes.NewReader(body))
					if err == nil {
						return postCall{Method: m, Args: args, Elem: elemID, Body: body}, true
					}
					s.logf("post-flood leaveArena args: %v", err)
				}
			} else {
				s.logf("post-flood base elem=%#02x argLen=%d avatarMethod=none", elemID, len(body))
			}
		}
		for _, name := range []string{"Account", "Avatar"} {
			if acct := s.cfg.Dispatch.Entity(name); acct != nil {
				if m := acct.MethodByID(entdef.CompBase, int(elemID)-baseMethodElementID); m != nil {
					if m.Length.Fixed && m.Length.Size != len(body) {
						s.logf("post-flood %s: element %#02x carries %d B, the defs say %d",
							m.Name, elemID, len(body), m.Length.Size)
						return postCall{}, false
					}
					args, err := m.ReadArgs(bytes.NewReader(body))
					if err != nil {
						s.logf("post-flood %s: %v", m.Name, err)
						return postCall{}, false
					}
					call := postCall{Method: m, Args: args, Elem: elemID, Body: body}
					if len(args) > 0 && args[0].Kind == entdef.VInt {
						call.Req = uint16(args[0].Int)
					}
					if len(args) > 1 && args[1].Kind == entdef.VInt {
						call.Cmd = uint16(args[1].Int)
					}
					return call, true
				}
			}
		}
	}
	switch [2]byte{elemID, byte(len(body))} {
	case [2]byte{0x95, 0x1c}, [2]byte{0x93, 0x14}:
		return postCall{
			Req: binary.LittleEndian.Uint16(body[0:2]),
			Cmd: binary.LittleEndian.Uint16(body[2:4]),
		}, true
	}
	return postCall{}, false
}

// servePostFlood answers one decrypted post-flood client datagram and
// keeps the tick cadence. Genuine turn-taking (flows3-s2 tail):
//
//	terminator(332) → [13][7a] tick → client 84B sync → [13][7b] 60B
//	  rev answer → ticks → client 501 poll → [13][a4] 36B stats answer
//	  → … 100 ms cadence throughout; every frame (tick or answer) takes
//	  exactly ONE walk slot: tag = 7a+n mod 256, seq = 503+n (rev 7b/
//	  504, offer 7e/506 — offers are v1-cut, the walk just steps over
//	  their slots — poll a4/545 = 7a+42/503+42 ✓, 1a5e dd/602 = +99 ✓)
//
// Answer BODIES replay verbatim from the carrier (1a/5f revisions,
// 1a/5b stat counters — stale reference, same layering as the bulk);
// the [13][tag] head, the footers (seq; cumul = the live client
// watermark), and the 1a/5e error small's req echo are minted.
func (s *BaseAppServer) servePostFlood(conn Transport, from *net.UDPAddr, st *clientState, clear []byte) error {
	// The client's enableEntities says it is ready for its entity. The
	// flood bundle already created it (createBasePlayer), so this only
	// selects it and shows the GUI — on the next free seq, keeping the
	// channel contiguous.
	// The held-back half of an arena entry goes out on the first datagram
	// the client sends after the Avatar, which is the one from its rebound
	// socket.
	s.mu.Lock()
	pending := st.arenaNext
	// Only once the delay has passed: the client rebinds its socket when
	// the battle app is created, and a datagram that arrives before that
	// still comes from the port it is about to close.
	if pending != nil && !time.Now().Before(st.arenaNextAt) {
		st.arenaNext = nil
	} else {
		pending = nil
	}
	seq, cumul := st.postSeq, st.postCumul
	s.mu.Unlock()
	if pending != nil {
		next, err := s.enterArenaSpace(conn, from, st, pending, seq, cumul)
		if err != nil {
			s.logf("stage2 %s: arena space: %v", from, err)
			return nil
		}
		s.mu.Lock()
		if next > st.postSeq {
			st.postSeq = next
		}
		s.mu.Unlock()
		return nil
	}
	if elem, ok := firstElement(clear, st.stage2Key); ok && elem == elEnableEntities {
		s.mu.Lock()
		seq, cumul := st.postSeq, st.postCumul
		arena := st.arena
		s.mu.Unlock()
		// A battle entry is the same trigger as the lobby entry: the
		// client says it is ready for entities, and the server creates the
		// one it should have. The reset that enterArena sent cleared the
		// client's entities, so this is where the Avatar and the cell
		// player go out.
		// A returning client's rejoin does NOT happen here — see the poll
		// handler (`lobby.CmdReqServerStats`). `enableEntities` is the first
		// thing the client sends after a login, before its lobby sync, and
		// resetting it here dropped that sync on the floor.
		if arena != nil {
			next, err := s.enterArenaEntities(conn, from, st, arena, seq, cumul)
			if err != nil {
				s.logf("stage2 %s: arena entities: %v", from, err)
				return nil
			}
			s.mu.Lock()
			if next > st.postSeq {
				st.postSeq = next
			}
			s.mu.Unlock()
			return nil
		}
		// After a reset the Account entity is gone, so it has to be created
		// again — selecting an entity that does not exist is
		// `MF_ASSERT_DEV FAILED: pEntity`. On a fresh login the flood bundle
		// already created it, which is why this used to be false.
		s.mu.Lock()
		needCreate := st.resetSent
		s.mu.Unlock()
		next, err := s.enterAccount(conn, from, st, seq, cumul, needCreate)
		if err != nil {
			s.logf("stage2 %s: enterAccount: %v", from, err)
			return nil
		}
		s.mu.Lock()
		if next > st.postSeq {
			st.postSeq = next
		}
		s.mu.Unlock()
		return nil
	}
	// Chat rides its own A1 tag (0x98), not a doCmd* base call, so it is
	// checked first. The client sends initAck and requestLastSysMessages
	// here; we name them and stay silent (no chat backend yet).
	if tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2])); len(clear) > 2+tr {
		if cc, ok := lobby.ParseChatCommandFromClient(clear[2 : len(clear)-tr]); ok {
			s.logf("stage2 %s: chat %s (req %d, ch %d, arg %d)",
				from, cmdLabelChat(cc), cc.RequestID, cc.ChannelID, cc.Int64Arg)
			return nil
		}
	}
	if tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2])); len(clear) > 2+tr {
		app := clear[2 : len(clear)-tr]
		if len(app) > 96 {
			app = app[:96]
		}
		// The whole cleartext, not just the app: the footers are where
		// the client's cumulative ack lives, and a mis-sliced trailer is
		// invisible from the app alone.
		s.logf("stage2 %s: post-flood %d B flags=%#06x tr=%d app %d B: % x | clear: % x",
			from, len(clear), binary.LittleEndian.Uint16(clear[0:2]), tr, len(app), app, clear)
	}
	calls := s.postCalls(clear, st.stage2Key)
	if len(calls) == 0 {
		return nil // acks and anything else: no answer (genuine parity)
	}
	// A post-flood bundle carries SEVERAL calls: the opener is
	// doCmdInt3(221,100) + doCmdInt3(222,300) + doCmdInt3(223,600) + a
	// chat tail, i.e. the account sync, the shop sync and the dossier
	// sync in one datagram. Answering only the leading one leaves the
	// other two waitForSync() calls pending forever and the hangar never
	// advances past SHOW GUI.
	for _, call := range calls {
		if err := s.answerPostCall(conn, from, st, call); err != nil {
			return err
		}
	}
	return nil
}

// answerPostCall answers ONE decoded client call.
func (s *BaseAppServer) answerPostCall(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	req, cmd := call.Req, call.Cmd
	// The client has been reset into a battle and has not been given its
	// new entity yet. Everything below is an Account-level answer, and the
	// Account is gone: sending one makes the client size an entity method
	// for a null entity and assert. The requests are dropped rather than
	// queued — the client re-asks for the whole state once it is a player
	// again.
	s.mu.Lock()
	stranded := st.resetSent && !st.entered
	s.mu.Unlock()
	if stranded {
		s.logf("stage2 %s: dropped account call %d/%d — no entity between reset and re-entry",
			from, req, cmd)
		return nil
	}
	// Calls that are not account commands: their first argument is not a
	// request id followed by a CMD_* id, so they are dispatched by the
	// defs' method name before the command switch.
	if call.Method != nil {
		s.logf("post-flood dispatch method=%q elem=%#02x", call.Method.Name, call.Elem)
		switch call.Method.Name {
		case "requestToken":
			return s.answerRequestToken(conn, from, st, call)
		case "leaveArena", "leaveArenaByAccount":
			return s.answerLeaveArena(conn, from, st)
		case "trackRelativePointWithGun", "vehicle_trackWorldPointWithGun",
			"stopTrackingWithGun", "vehicle_stopTrackingWithGun":
			return s.answerGunTrack(conn, from, st, call)
		case "vehicle_moveWith":
			return s.answerMoveWith(st, call)
		case "vehicle_shoot":
			return s.answerShoot(conn, from, st)
		case "vehicle_changeSetting":
			return s.answerChangeSetting(conn, from, st, call)
		case "accountUnitClient_create", "accountUnitClient_join",
			"accountUnitClient_doCmd", "accountUnitClient_sendInvites",
			"accountUnitClient_setRosterSlots":
			return s.answerUnitCall(conn, from, st, call)
		}
	}
	switch cmd {
	case lobby.CmdSyncData:
		// The client asks TWICE per session, and both must be answered:
		// the first request pulls the state, and AccountSyncData's
		// __onSyncComplete ends with `self._synchronize()`, which asks
		// again with the revision the stream just delivered. Answering
		// only the first leaves the second parked in __onCmdResponse
		// forever — the hangar then stalls on "Synchronisation de
		// l'équipement" with no traffic and no error on either side.
		//
		// The client's sync request carries the revision it holds
		// (doCmdInt3's first int argument).
		//
		// The answer is the FULL state, and it rides the resource
		// stream rather than an inline 1a/5f element: a garage holding
		// every ownable vehicle is ~9 KB, far past the 1223-byte
		// bundle payload, and the resource mechanism is exactly what
		// the genuine server uses for the account cache (367 KB).
		//
		// AccountSyncData.isFullSyncDiff is `diff.get('prevRev') is
		// None`, so the absence of prevRev is what tells the client to
		// clear its caches and take the answer as the whole picture.
		// Answering a non-zero revision with a revision-only diff is
		// what made every resource read "-" after a relogin: the diff
		// carries no `stats`, so the client kept an empty Stats cache.
		var rev int64
		if len(call.Args) > 2 {
			rev = call.Args[2].Int
		}
		s.mu.Lock()
		st.rev = rev
		sentRev := st.sentRev
		s.mu.Unlock()
		// The follow-up: AccountSyncData.__onSyncComplete ends with
		// `self._synchronize()`, which asks again with the revision the
		// stream just gave it. That one is a cheap ack — the client
		// already holds the state.
		if rev != 0 && rev == sentRev {
			small, err := BuildRevisionsAnswer(uint32(req), rev, rev)
			if err != nil {
				return err
			}
			if err := s.mintPost(conn, from, st, answerApp(small)); err != nil {
				return err
			}
			s.logf("stage2 %s: post-flood sync → 1a/5f revision ack (rev %d)", from, rev)
			return nil
		}
		doc, err := FullSyncDoc(fullSyncRev, s.economy(st), s.inventory(st), s.unlocks(st), st.clan,
			&EconomyDoc{
				PremiumExpiry:    st.premium,
				PiggyBankCredits: st.piggy,
				PiggyBankGold:    st.piggyGold,
			})
		if err != nil {
			return err
		}
		small, err := BuildCommandResponse(req, 1, lobby.NewDict()) // RES_STREAM
		if err != nil {
			return err
		}
		if err := s.mintPost(conn, from, st, answerApp(small)); err != nil {
			return err
		}
		streams, err := BuildStreamElements(req, doc)
		if err != nil {
			return err
		}
		for _, el := range streams {
			if err := s.mintPost(conn, from, st, answerApp(el)); err != nil {
				return err
			}
		}
		s.mu.Lock()
		st.sentRev = fullSyncRev
		s.mu.Unlock()
		s.logf("stage2 %s: post-flood sync → RES_STREAM + %d stream elements (client rev %d, %d vehicles)",
			from, len(streams), rev, len(st.garage))
	case lobby.CmdSyncShop:
		// Shop is a SyncController request too, and its __onSyncResponse
		// clears __isSynchronizing on RES_SUCCESS (0). The answer carries
		// the item price table: the tech tree's vehicle list and the hangar
		// carousel's own filter both walk it, and the tank details panel
		// reads prices out of it.
		doc, err := ShopDoc(s.shopPrices(st))
		if err != nil {
			return err
		}
		small, err := BuildCommandResponse(req, 1, lobby.NewDict()) // RES_STREAM
		if err != nil {
			return err
		}
		if err := s.mintPost(conn, from, st, answerApp(small)); err != nil {
			return err
		}
		streams, err := BuildStreamElements(req, doc)
		if err != nil {
			return err
		}
		for _, el := range streams {
			if err := s.mintPost(conn, from, st, answerApp(el)); err != nil {
				return err
			}
		}
		s.logf("stage2 %s: post-flood %s → RES_STREAM + %d stream elements (req %d)", from, cmdLabel(cmd), len(streams), req)
	case lobby.CmdSyncDossiers:
		// DossierCache is different: its __onSyncResponse does NOT clear
		// __isSynchronizing on RES_SUCCESS, so the client re-requests in a
		// tight loop until it times out and disconnects. Only
		// __onSyncComplete clears it, and that needs RES_STREAM (1) plus
		// the stream element carrying `(cacheVersion, [(ownerID,
		// changeTime, compDescr)])`. We hold no dossiers, so the stream is
		// `(0, [])`.
		small, err := BuildCommandResponse(req, 1, lobby.NewDict())
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		streams, err := BuildStreamElements(req, lobby.NewTuple(
			lobby.NewInt(0),
			lobby.NewList(),
		))
		if err != nil {
			return err
		}
		// The header must land before the fragment: the client drops a
		// fragment whose id it has no header for, silently.
		for _, el := range streams {
			if err := s.mintPost(conn, from, st, answerApp(el)); err != nil {
				return err
			}
		}
		s.logf("stage2 %s: post-flood %s → 1a/5f RES_STREAM (req %d) % x", from, cmdLabel(cmd), req, small)
		for _, el := range streams {
			s.logf("stage2 %s: post-flood %s → stream element (req %d) % x", from, cmdLabel(cmd), req, el)
		}
	case lobby.CmdReqPlayerInfo:
		// The profile's data request. `Account.requestPlayerInfo` reads the
		// answer's ext dict and hands `ext['dossier']` to
		// `dossiers2.getAccountDossierDescr`, which is where the
		// achievements, medals and battle stats come from — with no answer
		// the profile and the achievements screen stay empty.
		//
		// The dossier is the client's own blob (see
		// lobby/account_dossier_gen.go): every achievement record at its
		// maximum. It is 845 B, so it rides one datagram; the post-flood
		// answer path has no fragment chain.
		ext := lobby.NewDict().
			Set("databaseID", lobby.NewInt(int64(accountIDFor(st.accountID, st.name)))).
			Set("dossier", lobby.NewString(string(lobby.AccountDossier))).
			Set("clanDBID", lobby.NewInt(0)).
			Set("clanInfo", lobby.NewNone()).
			Set("globalRating", lobby.NewInt(0)).
			Set("eSportSeasons", lobby.NewDict()).
			Set("ranked", lobby.NewDict()).
			Set("dogTag", lobby.NewDict()).
			Set("battleRoyaleStats", lobby.NewDict()).
			Set("wtr", lobby.NewNone()).
			Set("layout", lobby.NewNone()).
			Set("layoutState", lobby.NewNone()).
			Set("serviceRecordCustomization", lobby.NewDict())
		small, err := BuildCommandResponse(req, 0, ext)
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPostLarge(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood player info (req %d) → dossier %d B", from, req, len(lobby.AccountDossier))
	case lobby.CmdExchange, lobby.CmdFreeXPConv, lobby.CmdPremium,
		lobby.CmdBuySlot, lobby.CmdBuyBerths,
		lobby.CmdSetReservesPiggyBankDev, lobby.CmdSmashPiggyBankDev:
		return s.answerEconomy(conn, from, st, call)
	case lobby.CmdEquipTman:
		return s.answerEquipTman(conn, from, st, call)
	case lobby.CmdSetAndFillLayouts:
		return s.answerSetAndFillLayouts(conn, from, st, call)
	case lobby.CmdInvitationSend:
		return s.answerInvitationSend(conn, from, st, call)
	case lobby.CmdInvitationAccept, lobby.CmdInvitationDecline:
		return s.answerInvitationReply(conn, from, st, call)
	case lobby.CmdReqPlayerClanInfo:
		// The clan's motto and description. `Account.onClanInfoReceived`
		// hands them to `g_clanCache`, which is the only place the client
		// keeps them — the name, tag, role and join date come from the
		// account sync instead. A clanless account gets the same call with
		// a zero id, which is what clears a stale cache after a leave.
		if st.clan == nil {
			s.logf("stage2 %s: post-flood clan info (req %d) — no clan", from, req)
			return nil
		}
		app, err := s.accountCall("onClanInfoReceived",
			entdef.Value{Kind: entdef.VInt, Int: st.clan.DBID},
			entdef.Value{Kind: entdef.VString, Str: st.clan.Name},
			entdef.Value{Kind: entdef.VString, Str: st.clan.Abbrev},
			entdef.Value{Kind: entdef.VString, Str: st.clan.Motto},
			entdef.Value{Kind: entdef.VString, Str: st.clan.Description})
		if err != nil {
			s.logf("stage2 %s: onClanInfoReceived: %v", from, err)
			return nil
		}
		if err := s.mintPost(conn, from, st, answerApp(app)); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood clan info (req %d) → onClanInfoReceived [%s]", from, req, st.clan.Abbrev)
	case lobby.CmdReqServerStats:
		// A returning client goes back into the battle it dropped out of,
		// HERE and not on `enableEntities`.
		//
		// The poll is the first thing the client sends once its lobby is up:
		// `Account.onBecomePlayer` fans out to the sync subsystems
		// (221/100, 222/300, 223/600) and the poll follows them. Rejoining
		// on `enableEntities` put the reset in FRONT of those syncs, and
		// `answerPostCall` drops an Account call between the reset and the
		// re-entry — so the client entered the battle with no inventory,
		// `Vehicle.set_setupsIndexes` threw `KeyError: 'eqsLayout'`, and it
		// left the world 13 ms after entering and landed back on the login
		// screen. Every rejoin did that; a fresh battle entry (from the
		// matchmaker, with the client already synced) was fine.
		s.mu.Lock()
		rejoin := st.arena == nil
		s.mu.Unlock()
		if rejoin && s.cfg.Arenas != nil && s.cfg.Arenas.Rejoin != nil {
			if h := s.cfg.Arenas.Rejoin(st.accountID); h != nil {
				if err := s.enterArena(conn, from, st, h); err != nil {
					s.logf("stage2 %s: arena rejoin: %v", from, err)
				}
				return nil
			}
		}
		small, err := BuildServerStatsAnswer(uint32(st.accountID), uint32(len(s.byAddr)))
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood poll → 1a/5b stats answer", from)
	case lobby.CmdReqQueueInfo:
		// 1a/67 {players, classes}: the queue census. Server-wide, so the
		// carrier's body replays verbatim; only the [13][tag] head and the
		// footers are minted. Absent from a carrier that never saw a 502
		// (the flows3-s2 tail has none) — then stay silent, as the client
		// tolerates.
		// A live queue answers truthfully, PER QUEUE TYPE: the client
		// polls the census for the queue it is in, so a random-battle
		// poll must not count a ranked entry. Without a queue the
		// carrier's census replays.
		var players int64
		var classes []int64
		if s.cfg.Queue != nil && s.cfg.Queue.Census != nil {
			// doCmdInt3(queueType, intArg1, intArg2).
			queueType := uint8(argInt(call.Args, 2))
			p, c := s.cfg.Queue.Census(queueType)
			players = int64(p)
			for _, v := range c {
				classes = append(classes, int64(v))
			}
		}
		small, err := BuildQueueCensus(players, classes)
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood queue info → 1a/67 census (minted)", from)
	case lobby.CmdEnqueueInBattleQueue:
		// doCmdIntArr: [queueType, vehInvID, gameplaysMask, arenaTypeID,
		// randomFlags]. The answer is Account.onEnqueued(queueType), a
		// client method the defs name.
		if s.cfg.Queue == nil || s.cfg.Queue.Enqueue == nil {
			s.logf("stage2 %s: post-flood enqueue — no queue configured", from)
			return nil
		}
		args := int32Args(call.Args, 2)
		if len(args) == 0 {
			s.logf("stage2 %s: post-flood enqueue — no arguments", from)
			return nil
		}
		// The vehicle the player queued with, resolved from the session's
		// own garage: the census buckets by its class and the matchmaker
		// by its tier, and neither is on the wire.
		veh := st.vehicleByInvID(argAt(args, 1))
		res := s.cfg.Queue.Enqueue(st.accountID, st.name, args, veh)
		queueType := uint8(args[0])
		if !res.Ok() {
			s.logf("stage2 %s: post-flood enqueue type %d veh %d → JOIN_FAILURE %d (%s)",
				from, queueType, argAt(args, 1), res.Code, res.Message)
			app, err := s.accountCall("onEnqueueFailure",
				entdef.Value{Kind: entdef.VUint, Uint: uint64(queueType)},
				entdef.Value{Kind: entdef.VUint, Uint: uint64(uint8(res.Code))},
				entdef.Value{Kind: entdef.VString, Str: res.Message})
			if err != nil {
				s.logf("stage2 %s: onEnqueueFailure: %v", from, err)
				return nil
			}
			return s.mintPost(conn, from, st, answerApp(app))
		}
		s.logf("stage2 %s: post-flood enqueue type %d veh %d (added %d)",
			from, queueType, argAt(args, 1), res.Added)
		app, err := s.accountCall("onEnqueued", entdef.Value{Kind: entdef.VUint, Uint: uint64(queueType)})
		if err != nil {
			s.logf("stage2 %s: onEnqueued: %v", from, err)
			return nil
		}
		if err := s.mintPost(conn, from, st, answerApp(app)); err != nil {
			return err
		}
		// The battle handoff runs only now: `onArenaCreated` +
		// `resetEntities` clear the client's entity table, and doing that
		// before the client has seen its `onEnqueued` answer leaves a
		// queued callback holding an entity that no longer exists
		// (`MF_ASSERT_DEV FAILED: pEntity`).
		if s.cfg.Queue.Handoff != nil {
			s.cfg.Queue.Handoff()
		}
		return nil
	case lobby.CmdDequeueFromBattleQueue:
		if s.cfg.Queue == nil || s.cfg.Queue.Dequeue == nil {
			s.logf("stage2 %s: post-flood dequeue — no queue configured", from)
			return nil
		}
		// doCmdInt(queueType): the queue type is the third argument, not
		// an array element.
		qt := uint8(argInt(call.Args, 2))
		was := s.cfg.Queue.Dequeue(st.accountID)
		s.logf("stage2 %s: post-flood dequeue type %d (was queued %v)", from, qt, was)
		app, err := s.accountCall("onDequeued", entdef.Value{Kind: entdef.VUint, Uint: uint64(qt)})
		if err != nil {
			s.logf("stage2 %s: onDequeued: %v", from, err)
			return nil
		}
		return s.mintPost(conn, from, st, answerApp(app))
	case lobby.CmdReqBattleResults:
		// The live server answers with the 1a/5e error small, status 1
		// (the season-select path uses status 0): `[13][tag][1a 5e 05]
		// [req u16 LE][01 00 00]` + footers. We hold no battle history,
		// so the error is the faithful answer, not a stub.
		small, err := BuildCommandError(req, 1)
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood battle results (req %d) → 1a/5e error (minted)", from, req)
	case lobby.CmdSetActiveVehSeason:
		// We hold no garage, so answer the genuine failure small the
		// capture shows (~22 ms after the 52B season bundle, flows3-s2
		// idx 1209/1210): `[13][tag][1a 5e 05][req u16 LE][00 00 00]`
		// + footers. req echoes the client's request id (genuine 225).
		small, err := BuildCommandError(req, 0)
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood season select (req %d) → 1a/5e no-vehicle error (minted)", from, req)
	default:
		// Everything else is recognized but NOT answered: each wants
		// per-account inventory we don't hold. v1-cut: silence beats a
		// wrong-content answer (see §18 honesty layering). The name
		// comes from the shipped AccountCommands.pyc table so the log
		// says which command the client wanted.
		s.logf("stage2 %s: post-flood %s — no answer (v1-cut)", from, cmdLabel(cmd))
	}
	return nil
}

// answerRequestToken answers `requestToken(requestID, tokenType)`.
//
// The client's `TokenRequester` unpickles the third argument into
// `TokenResponse(**data)`, so the payload is a pickled dict with `token`
// and `databaseID`; the XMPP plugin then hands `token` to gloox as its
// SASL password. Only the XMPPCS type is served: the WGNI/shop token is
// a JWT minted by the web broker, and answering it with a fake would
// make the shop believe it has a session it does not.
func (s *BaseAppServer) answerRequestToken(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if len(call.Args) < 2 {
		return nil
	}
	reqID := uint16(uintOf(call.Args[0]))
	tokenType := uint8(uintOf(call.Args[1]))
	if tokenType != lobby.TokenTypeXMPPCS {
		s.logf("stage2 %s: post-flood requestToken type %d — no answer (web-broker token)", from, tokenType)
		return nil
	}
	if s.cfg.XMPPToken == nil {
		s.logf("stage2 %s: post-flood requestToken — no XMPP service configured", from)
		return nil
	}
	dbid := int64(accountIDFor(st.accountID, st.name))
	token := s.cfg.XMPPToken(dbid)
	doc, err := lobby.EncodeDocument(lobby.NewDict().
		Set("token", lobby.NewString(token)).
		Set("databaseID", lobby.NewInt(dbid)))
	if err != nil {
		return err
	}
	app, err := s.accountCall("onTokenReceived",
		entdef.Value{Kind: entdef.VUint, Uint: uint64(reqID)},
		entdef.Value{Kind: entdef.VUint, Uint: uint64(tokenType)},
		entdef.Value{Kind: entdef.VString, Str: string(doc)})
	if err != nil {
		s.logf("stage2 %s: onTokenReceived: %v", from, err)
		return nil
	}
	if err := s.mintPost(conn, from, st, answerApp(app)); err != nil {
		return err
	}
	s.logf("stage2 %s: post-flood requestToken → onTokenReceived (req %d, dbid %d, %d B)", from, reqID, dbid, len(doc))
	return nil
}

// uintOf reads an integer argument whether the defs typed it signed or
// unsigned. postCall.Req/Cmd only look at VInt, so a method whose
// arguments are UINT16/UINT8 (requestToken) has to read them itself.
func uintOf(v entdef.Value) uint64 {
	if v.Kind == entdef.VInt {
		return uint64(v.Int)
	}
	return v.Uint
}

// cmdLabelChat renders a chat command for logs.
func cmdLabelChat(c lobby.ChatCommand) string {
	if n := c.Name(); n != "" {
		return fmt.Sprintf("%s (%d)", n, c.Command)
	}
	return fmt.Sprintf("chat cmd %d", c.Command)
}

// cmdLabel renders an account command id for logs: the shipped name
// when known, else the bare number.
func cmdLabel(cmd uint16) string {
	if n := lobby.CmdName(cmd); n != "" {
		return fmt.Sprintf("%s (%d)", n, cmd)
	}
	return fmt.Sprintf("cmd %d", cmd)
}

// allocPost takes the next post-flood walk slot (caller holds s.mu).
// The three values are one counter triple shared by ticks and answers
// — the genuine tail consumes one slot per S>C frame, no exceptions.
func allocPost(st *clientState) (tag byte, seq, cumul uint32) {
	tag, seq, cumul = st.postTag, st.postSeq, st.postCumul
	st.postTag++
	st.postSeq++
	return
}

// mintPost allocates the walk slot, stamps its tag into app[1], and
// sends app as a reliable frame with the slot's seq/cumul.
func (s *BaseAppServer) mintPost(conn Transport, to *net.UDPAddr, st *clientState, app []byte) error {
	if len(app) < 2 {
		return fmt.Errorf("wotserver: post-flood frame missing its tag slot")
	}
	s.mu.Lock()
	tag, seq, cumul := allocPost(st)
	s.mu.Unlock()
	app[1] = tag
	s.checkWire(app)
	pkt, err := buildChannelPacket(st.blockKey, flagsRel, app, nil, seq, cumul)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(pkt, to); err != nil {
		return err
	}
	s.resend.track(st.resendKey, to.String(), seq, pkt)
	return nil
}

// mintPostUnreliable is mintPost on the unreliable stream: the tag is
// allocated the same way, but nothing is tracked for retransmission. The
// leave reset and the re-entered Account use it because the client's
// `LoginReplyFilter` drops a retransmitted login reply and disconnects.
func (s *BaseAppServer) mintPostUnreliable(conn Transport, to *net.UDPAddr, st *clientState, app []byte) error {
	if len(app) < 2 {
		return fmt.Errorf("wotserver: post-flood frame missing its tag slot")
	}
	s.mu.Lock()
	tag, _, _ := allocPost(st)
	s.mu.Unlock()
	app[1] = tag
	s.checkWire(app)
	return s.sendUnreliableLocked(conn, to, st, app)
}

// mintPostLarge sends app as a reliable frame, splitting it into a fragment
// chain when it does not fit one datagram.
//
// The post-flood answer path has no fragment chain of its own, so an answer
// past the channel MTU is silently lost. The flood's chain builder is the
// same shape the client already accepts (`bulkFlags` = ON|REL|SEQ|FRAG with
// the (first, last, seq) trailer), so a large answer reuses it: allocate the
// whole seq range up front, then emit the frames in order.
func (s *BaseAppServer) mintPostLarge(conn Transport, to *net.UDPAddr, st *clientState, app []byte) error {
	if len(app) <= DefaultBulkPayload {
		return s.mintPost(conn, to, st, app)
	}
	count := (len(app) + DefaultBulkPayload - 1) / DefaultBulkPayload
	s.mu.Lock()
	first := st.postSeq
	st.postSeq += uint32(count)
	st.postTag += byte(count)
	s.mu.Unlock()
	s.checkWire(app)
	frames, err := BuildFrames(st.blockKey, app, DefaultBulkPayload, first)
	if err != nil {
		return err
	}
	for i, frame := range frames {
		if _, err := conn.WriteToUDP(frame, to); err != nil {
			return err
		}
		s.resend.track(st.resendKey, to.String(), first+uint32(i), frame)
	}
	return nil
}

// sweepStage2 fires due post-flood ticks (genuine cadence 100 ms).
func (s *BaseAppServer) sweepStage2(conn Transport, now time.Time) {
	type tickJob struct {
		st    *clientState
		addr  *net.UDPAddr
		tag   byte
		seq   uint32
		cumul uint32
	}
	s.mu.Lock()
	var due []tickJob
	var arenaDue []struct {
		st   *clientState
		addr *net.UDPAddr
		h    *ArenaHandoff
		seq  uint32
		cum  uint32
	}
	for _, st := range s.byAddr {
		// The held-back half of an arena entry: send it once the client
		// has had time to rebind its socket, whether or not it spoke.
		if st.arenaNext != nil && !now.Before(st.arenaNextAt) {
			arenaDue = append(arenaDue, struct {
				st   *clientState
				addr *net.UDPAddr
				h    *ArenaHandoff
				seq  uint32
				cum  uint32
			}{st, st.stage2Addr, st.arenaNext, st.postSeq, st.postCumul})
			st.arenaNext = nil
		}
		// The post-flood tick is the LOGIN phase's cadence. Once the session
		// is in an arena the arena tick owns the stream, and this loop must
		// stop: it was minting another 10 reliable packets a second on top of
		// the arena tick's 10 (the client's cumulative ack advanced by exactly
		// 2 per 100 ms), and because it mints under `s.mu` but sends after
		// releasing it, its packets raced the arena tick's for sequence order.
		// A reliable packet that arrives after a later-minted one is buffered
		// behind the gap, which is how the BATTLE period update was lost and
		// the client stayed at PREBATTLE with `isOnArena` false — unable to
		// move or aim.
		if st.arena != nil {
			continue
		}
		if st.postAt.IsZero() || now.Before(st.postAt) {
			continue
		}
		st.postAt = now.Add(st.tickPeriod)
		// Advance AFTER capturing, so the first tail tick replays the
		// seed tick byte-exact (genuine idx 1007: tag 7a, seq 503).
		tag, seq, cumul := allocPost(st)
		due = append(due, tickJob{st: st, addr: st.stage2Addr, tag: tag, seq: seq, cumul: cumul})
	}
	s.mu.Unlock()
	for _, a := range arenaDue {
		if a.addr == nil {
			continue
		}
		next, err := s.enterArenaSpace(conn, a.addr, a.st, a.h, a.seq, a.cum)
		if err != nil {
			s.logf("stage2 %s: arena space (sweep): %v", a.addr, err)
			continue
		}
		s.mu.Lock()
		if next > a.st.postSeq {
			a.st.postSeq = next
		}
		s.mu.Unlock()
	}
	for _, j := range due {
		if j.addr == nil {
			continue
		}
		app := EncodeTickSync(j.tag)
		pkt, err := buildChannelPacket(j.st.blockKey, flagsRel, app, nil, j.seq, j.cumul)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(pkt, j.addr); err != nil {
			continue
		}
		s.resend.track(j.st.resendKey, j.addr.String(), j.seq, pkt)
	}
	// Retransmit reliable packets the client has not acknowledged. This
	// runs on the same sweep as the ticks, so a lost answer is repeated
	// within one cadence of its timeout.
	for _, job := range s.resend.due(now) {
		addr, err := net.ResolveUDPAddr("udp", job.Addr)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(job.Pkt, addr); err != nil {
			continue
		}
		s.logf("stage2 %s: resent reliable seq %d (%dB)", addr, job.Seq, len(job.Pkt))
	}
}

// isStageAuth reads the double-auth in a decrypted stage-2 datagram.
// clear = [flags2][app ...]: the reliable auth1 rides flags 58 04, the
// unreliable companion 48 14 (baseapp.go flagsRel/flagsUnrel); app[0]
// = 0x02 (BaseApp.authenticate, FIXED-4), app[1:5] = key2 LE. The
// 0x0b enableEntities trailer rides only the reliable twin and is not
// required here (either half proves the client spent key2).
func isStageAuth(clear []byte, key2 uint32) bool {
	if len(clear) < 7 || clear[2] != 0x02 {
		return false
	}
	rel := clear[0] == 0x58 && clear[1] == 0x04
	unrel := clear[0] == 0x48 && clear[1] == 0x14
	if !rel && !unrel {
		return false
	}
	return binary.LittleEndian.Uint32(clear[3:7]) == key2
}

// serveBulk emits the flood burst: genuine stage-2 floods run 476-489
// × 1252B (one ~6 s burst between the smalls-train windows — our
// client exits on the first decrypt-verified 1252B, the game reassembles
// the whole batch). Frames replay verbatim, re-keyed: fresh random
// prefix + encryptBlowfish under the live session's key over the
// capture's decrypted body. Contents stay the capture's (stale
// reference; per-session bulk heads are future work).
// floodFirstSeq is the reliable seq the flood chain starts at. The
// client's channel counts the chain by its [first,last] range, and the
// rotation-2 reply owns seq 0, so the chain opens at 1.
const floodFirstSeq = 1

// economy is the account's currency block for the full-sync answer: the
// keys account_helpers/Stats.py reads out of `diff['stats']`
// (Currency.ALL plus freeXP, see gui/shared/money.py).
func (s *BaseAppServer) economy(st *clientState) map[string]any {
	return map[string]any{
		"credits": st.credits,
		"gold":    st.gold,
		"crystal": st.crystal,
		"slots":   st.slots,
		// berths is the barracks capacity (`stats.berths`), the crew-side
		// twin of `slots`: the client shows "free beds" from it, and a
		// missing key reads as 0 free beds.
		"berths":    st.berths,
		"eventCoin": 0,
		"bpcoin":    0,
		"equipCoin": 0,
		"freeXP":    st.freeXP,
		// dossier is the packed account dossier, and it is a STAT, not a
		// command answer: `StatsRequester.accountDossier` is
		// `getCacheValue('dossier', '')` and `ItemsRequester` feeds it to
		// `dossiers2.getAccountDossierDescr`. That is where the
		// achievements, medals and the `playerBadges` unlock list come
		// from — the profile never sends CMD_REQ_PLAYER_INFO for its own
		// account.
		"dossier": lobby.AccountDossier,
	}
}

// shopPrices is the shop's item price table for this account's garage.
func (s *BaseAppServer) shopPrices(st *clientState) map[int64]map[string]int64 {
	vehicles := make([]lobby.OwnableVehicle, 0, len(st.garage))
	for _, v := range st.garage {
		vehicles = append(vehicles, lobby.OwnableVehicle{CompDescr: v.CompactDescr})
	}
	return lobby.ShopItemPrices(vehicles)
}

// unlocks is the researched-item intCDs the account's garage implies: each
// vehicle's type intCD plus its stock modules'. `stats.unlocks` is what the
// client tests to decide whether a vehicle or module is researched, so an
// empty one renders the whole tech tree greyed out.
func (s *BaseAppServer) unlocks(st *clientState) []int64 {
	compDescrs := make([][]byte, 0, len(st.garage))
	for _, v := range st.garage {
		compDescrs = append(compDescrs, v.CompactDescr)
	}
	return lobby.UnlockIntCDsFor(compDescrs)
}

// inventory is the account's garage as the sync diff carries it:
// `{1: {compDescr: {invID: compDescr}, crew: {invID: [tmanInvID]},
// postProgression: {}}}` — item type index 1 is vehicles
// (items.ITEM_TYPE_NAMES). The client's InventoryRequester reads
// `invData[1]['compDescr']` unconditionally, so the item type must be
// present even when the garage is empty.
//
// `crew` is the assignment: `InventoryRequester.__makeVehicle` builds a
// vehicle's crew from `value('crew', [])`, and `__makeTankman` reads the
// tankman's own vehicle from `invData[8]['vehicle'][tmanInvID]`. Both are
// derived from the same lists, so a tankman can never appear in two tanks.
func (s *BaseAppServer) inventory(st *clientState) map[int64]any {
	compDescr := map[int64]any{}
	crewLists := map[int64][]any{}
	shellsLayout := map[int64]any{}
	shellsInstalled := map[int64]any{}
	eqsLayout := map[int64]any{}
	eqsInstalled := map[int64]any{}
	// nationType is the vehicle type each nation's tankmen are nominally
	// trained for: `TankmanDescr` resolves `vehicles.g_list.getList(nation)
	// [vehicleTypeID]` and raises on an unknown type, so the barracks can
	// only use types the garage already owns.
	nationType := map[uint8]uint16{}
	for _, v := range st.garage {
		compDescr[v.InvID] = v.CompactDescr
		if len(v.Crew) > 0 {
			crewLists[v.InvID] = CrewNode(v.Crew, v.CrewSize)
		}
		// The ammunition layout is keyed by the vehicle's (turret, gun)
		// pair, not by the vehicle, and its value is a LIST OF LAYOUTS —
		// one per setup (`vehicle_equipment.pyc __parseLayout`). The
		// installed counts are the flat list itself.
		if len(v.Shells) > 0 {
			if turret, gun, ok := lobby.VehicleGunKey(v.CompactDescr); ok {
				keyed := lobby.NewDict()
				keyed.SetNode(
					lobby.NewTuple(lobby.NewInt(int64(turret)), lobby.NewInt(int64(gun))),
					lobby.NewList().Append(intList(v.Shells)))
				shellsLayout[v.InvID] = keyed
			}
			shellsInstalled[v.InvID] = v.Shells
		}
		if len(v.Eqs) > 0 {
			eqsLayout[v.InvID] = []any{v.Eqs}
			eqsInstalled[v.InvID] = v.Eqs
		}
		nation, typeID, err := lobby.VehicleTypeCompDescr(v.CompactDescr)
		if err != nil {
			continue
		}
		if _, ok := nationType[nation]; !ok {
			nationType[nation] = typeID
		}
	}
	barracks := lobby.TankmanInventory(func(nation uint8) (uint16, bool) {
		typeID, ok := nationType[nation]
		return typeID, ok
	})
	// The tankman -> vehicle map, derived from the crew lists above so the
	// two can never disagree. `InventoryRequester.__makeTankman` reads
	// `value('vehicle', VEHICLE_NO_INV_ID)`, and -1 is that sentinel: a
	// tankman in the barracks has no vehicle.
	crew := map[int64]any{}
	for invID, list := range crewLists {
		crew[invID] = list
	}
	vehicle := map[int64]any{}
	for invID, list := range crewLists {
		for _, entry := range list {
			if tman, ok := entry.(int64); ok && tman > 0 {
				vehicle[tman] = invID
			}
		}
	}
	return map[int64]any{
		lobby.ItemVehicle: map[string]any{
			"compDescr":       compDescr,
			"crew":            crew,
			"shellsLayout":    shellsLayout,
			"shells":          shellsInstalled,
			"eqsLayout":       eqsLayout,
			"eqs":             eqsInstalled,
			"postProgression": map[int64]any{},
		},
		// itemTankman: the barracks. `InventoryRequester.__getTankmenData`
		// reads `invData['compDescr']` and builds one Tankman per instance
		// id, so the section is the same shape as the garage's.
		lobby.ItemTankman: map[string]any{
			"compDescr": barracks,
			"vehicle":   vehicle,
		},
		// itemEquipment: consumables. Unlike the garage and the barracks
		// this section is a flat `{intCD: count}` map —
		// `InventoryRequester.__getItemsData` returns `cache[intCD]` for
		// every simple item type.
		lobby.ItemEquipment: lobby.EquipmentInventory(lobby.MaxItemCount),
		// itemOptionalDevice: mounted equipment (stabilizers, vents, camo
		// nets, rammers, …) across every tier. Same flat `{intCD: count}`
		// shape as consumables.
		lobby.ItemOptionalDevice: lobby.OptionalDeviceInventory(lobby.MaxItemCount),
		// itemCustomization: every 3D style, camouflage, decal, paint,
		// projection decal, insignia, personal number, font, sequence,
		// attachment and stat tracker the client declares, all unbound so
		// any of them can go on any tank.
		lobby.ItemCustomization: lobby.CustomizationInventory(lobby.MaxItemCount),
		// itemCrewSkin: `{ITEMS: {skinID: count}, OUTFITS: {}}`. The
		// inventory keys the owned skins by the BARE skin id, not by the
		// intCD — `CrewSkin.__init__` passes the third field of
		// `parseIntCompactDescr(intCD)`. OUTFITS must exist even when empty:
		// `Tankman._equippedSkinID` indexes it directly.
		lobby.ItemCrewSkin: lobby.CrewSkinInventory(lobby.AllCrewSkinIDs),
	}
}

// buildFlood authors one session's stage-2 bulk bundle: the Account
// entity (createBasePlayer) carrying the lobby's server settings.
//
// Nothing here comes from a capture. The element framing is the engine's
// (see FloodBundle), the property order and types are the entity defs'
// (entdef.Entity.WireProps), and the settings document is the server's
// own (BaseAppConfig.Settings).
func (s *BaseAppServer) buildFlood(st *clientState) ([]byte, error) {
	if s.cfg.Dispatch == nil {
		return nil, fmt.Errorf("the flood bundle needs the entity defs (set -defs)")
	}
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		return nil, fmt.Errorf("no Account entity in the defs")
	}
	freq := s.cfg.Frequency
	if freq == 0 {
		freq = 10
	}
	tag := s.cfg.TickTag
	if tag == 0 {
		tag = 2
	}
	components := s.cfg.AccountComponents
	if components == 0 {
		components = 19
	}
	name := st.accountName
	if name == "" {
		name = st.name
	}
	return FloodBundle{
		EntityID:    st.entityID,
		TypeID:      uint16(acct.TypeID),
		Version:     versionString(st.version),
		Name:        name,
		Incarnation: st.incarnation,
		Settings:    s.settings,
		Components:  components,
		Frequency:   freq,
		GameTime:    s.gameTime(),
		TickTag:     tag,
	}.Encode()
}

// gameTime is updateFrequencyNotification's server game time: the
// milliseconds since the process started.
func (s *BaseAppServer) gameTime() uint32 {
	return uint32(time.Since(s.startedAt).Milliseconds())
}

// versionString is requiredVersion_2400: the build string the client
// checks itself against. The client announces its build at login, so the
// bundle echoes it back.
func versionString(v string) string {
	switch v {
	case "2.4.0":
		return "eu_2.4.0_2"
	case "2.4.1":
		return "eu_2.4.1_2"
	}
	return "eu_2.4.1_2"
}

func (s *BaseAppServer) serveBulk(conn Transport, from *net.UDPAddr, st *clientState) error {
	s.mu.Lock()
	if st.flooded {
		s.mu.Unlock()
		return nil
	}
	st.flooded = true
	// The session dict acks the client's reliable auth1 (seq 0 → cumul
	// 1). The cumulative ack is "last processed peer reliable seq + 1",
	// so it can only ever be what THIS client has sent — st.postCumul is
	// the live watermark (noteReliable). A cumul ahead of the client's
	// own outbound seq makes it drop the frame outright:
	//
	//   UDPChannel::handleCumulativeAck: Received ACK for packets not
	//   yet sent. endSeq: #3 outSeq: #2
	//   Error 'REASON_CORRUPTED_PACKET'
	dictCumul := st.postCumul
	if dictCumul < 1 {
		dictCumul = 1
	}
	s.mu.Unlock()

	// Author this session's bundle and split it into the fragment chain.
	stream, err := s.buildFlood(st)
	if err != nil {
		return err
	}
	// A bundle that fits one datagram goes out as a plain reliable frame:
	// the client's Packet::stripFragInfo refuses a fragment chain of one
	// ("Illegal fragment count (1)"), so a single-fragment chain is not
	// an option. Bigger bundles ride the fragment chain.
	var frames [][]byte
	if len(stream) <= DefaultBulkPayload {
		pkt, err := buildChannelPacket(st.blockKey, flagsRel, stream, nil, floodFirstSeq, 0)
		if err != nil {
			return err
		}
		frames = [][]byte{pkt}
	} else {
		frames, err = FloodFrames(st.blockKey, stream, floodFirstSeq)
		if err != nil {
			return err
		}
	}
	lastSeq := floodFirstSeq + uint32(len(frames)) - 1
	for _, frame := range frames {
		if _, err := conn.WriteToUDP(frame, from); err != nil {
			return err
		}
	}

	// Session dict: the 1a/76 small behind a [13][40] tick head. It rides
	// AFTER the burst, on the next seq — the client's channel is reliable
	// and delivers IN ORDER, so a gap here stalls everything after it:
	// the dict and every tick would sit in the receive window forever and
	// the client would never ACK them (the server then resends until the
	// peer times out). Any seq inside the chain's range would instead be
	// a duplicate the client drops.
	dictSeq := lastSeq + 1
	dict, err := BuildSessionDict(int64(accountIDFor(st.accountID, st.name)), st.admittedAt, time.Now())
	if err != nil {
		return err
	}
	// The dict frame's tick tag is 0x40 (the stage-2 head tag the
	// genuine flow uses for its mid-burst smalls).
	dictApp := append(EncodeTickSync(0x40), dict...)
	dictPkt, err := buildChannelPacket(st.blockKey, flagsRel, dictApp, nil, dictSeq, dictCumul)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(dictPkt, from); err != nil {
		return err
	}
	s.resend.track(st.resendKey, from.String(), dictSeq, dictPkt)
	s.logf("stage2 %s: session dict %dB (seq %d cumul %d)", from, len(dictPkt), dictSeq, dictCumul)

	// 1a/69 stats small: the account's free XP, behind its own tick head.
	// It is the one per-account field the client reads out of a small
	// (the rest of the economy rides the sync diff).
	statsSeq := dictSeq + 1
	stats, err := BuildStatsSmall(st.freeXP, st.rev, st.rev)
	if err != nil {
		return err
	}
	statsPkt, err := buildChannelPacket(st.blockKey, flagsRel, answerApp(stats), nil, statsSeq, dictCumul)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(statsPkt, from); err != nil {
		return err
	}
	s.resend.track(st.resendKey, from.String(), statsSeq, statsPkt)
	s.logf("stage2 %s: 1a/69 stats %dB (seq %d, freeXP %d)", from, len(statsPkt), statsSeq, st.freeXP)

	// SelectPlayerEntity + showGUI: the calls that make the hangar
	// appear. The bundle already created the Account entity, so this
	// only selects it and shows the GUI.
	next, err := s.enterAccount(conn, from, st, statsSeq+1, dictCumul, false)
	if err != nil {
		return err
	}

	// Arm the post-flood tick stream: it starts one cadence after the
	// burst, on the seq after showGUI.
	s.mu.Lock()
	st.postTag = s.postTag
	st.postSeq = next
	st.tickPeriod = PostTickPeriod
	st.postAt = time.Now().Add(PostTickPeriod)
	s.mu.Unlock()
	s.logf("stage2 %s: flood burst %d frames, %d B bundle", from, len(frames), len(stream))
	return nil
}

// tickApp is the stage-1 tick body [13][3e]: the genuine tick 28B
// decrypts to `5804 133e <seq=2> <cumul=1>` (flows3). The tag byte
// steps per epoch/stage (0x3e stage-1 here, 0x3f/0x40 at the stage-2
// heads; parked runs walk it 0x00→0xfb) — semantics open, value copied
// from the capture.
var tickApp = EncodeTickSync(0x3e)
