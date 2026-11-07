package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
)

// Arena entry and re-entry.
//
// The client leaves the hangar for a battle in four steps, and every one of
// them is required — skipping any leaves it on the battle-loading screen
// forever:
//
//	1. Account.onArenaCreated()      sets isPlayerEntityChanging, which is
//	                                 what makes the app loader switch to the
//	                                 battle-loading space.
//	2. resetEntities(false)          clears the client's entities and makes
//	                                 it send enableEntities again. The
//	                                 engine asserts the player entity is
//	                                 NULL before a new one is created, so
//	                                 this is not optional.
//	3. CreateBasePlayer (Avatar)     the player entity, now an Avatar.
//	4. spaceData + CreateCellPlayer  the space geometry and the cell half of
//	                                 the entity. CreateCellPlayer is what
//	                                 ends the loading screen: the engine
//	                                 loads the space and calls
//	                                 Avatar.onEnterWorld.
//
// RECONNECT is the same sequence: the server keeps the player's slot for
// ArenaHooks.ReconnectWindow, and a returning client gets steps 1-4 again
// with the same arena id and space.

// AvatarComponents is how many dynamic components the Avatar's entity
// description declares. The client checks the count in CreateBasePlayer and
// refuses the entity on a mismatch; the components themselves replicate over
// NRL, not in this element.
const AvatarComponents uint8 = 2

// The client's own arena enums (`common/constants.pyc`).
const (
	// ArenaGuiTypeRandom is ARENA_GUI_TYPE.RANDOM.
	ArenaGuiTypeRandom uint64 = 1
	// ArenaBonusTypeRegular is ARENA_BONUS_TYPE.REGULAR.
	ArenaBonusTypeRegular uint64 = 1
)

// ArenaPlayerDoc is one player in a battle, as the wire layer needs it.
type ArenaPlayerDoc struct {
	AccountID int64
	Name      string
	Team      uint8
	// VehicleCompDescr is the tank the player brought.
	VehicleCompDescr []byte
	// CrewSize is how many crew slots the tank has. The client builds the
	// crew panel from `crewGroups`, so a zero-length list reads as no crew.
	CrewSize int
	// ClanAbbrev and ClanDBID are the player's clan, shown in the team panel
	// and the scoreboard.
	ClanAbbrev string
	ClanDBID   int64
	// MaxHealth is the vehicle's hit points; zero means the default 1000.
	MaxHealth int
}

// ArenaHandoff is everything needed to put a client into a battle.
type ArenaHandoff struct {
	ArenaID     uint64
	SpaceID     uint32
	ArenaTypeID int32
	// Map is the geometry path, `spaces/<map>`.
	Map string
	// Player is the client's own slot.
	Player ArenaPlayerDoc
	// Roster is every player in the battle, the client included.
	Roster []ArenaPlayerDoc
	// VehicleID is the entity id of the client's own Vehicle. The client
	// resolves `Avatar.playerVehicleID` through its entity table, so this
	// must be the id the Vehicle was created with.
	VehicleID uint32
	// InfoID is the entity id of the arena's AvatarInfo entity, which carries
	// the vehicle list. Zero picks one derived from VehicleID.
	InfoID uint32
	// Dummy is an optional synthetic opponent, so a solo battle still has a
	// tank in the other team. It gets its own Vehicle entity and its own
	// VEHICLES_INFO entry.
	Dummy *ArenaPlayerDoc
}

// BattleResultDoc is one player's battle result.
type BattleResultDoc struct {
	Credits  int64
	XP       int64
	Winner   uint8
	Survived bool
}

// ArenaHooks lets the application layer own the battles.
type ArenaHooks struct {
	// Rejoin returns the battle an account should be put back into, or nil
	// when it is in none. It is called on every enableEntities, so a
	// reconnect lands here.
	Rejoin func(accountID int64) *ArenaHandoff
	// Disconnect marks an account as dropped from its battle. The slot is
	// held for the reconnect window.
	Disconnect func(accountID int64)
	// Leave removes an account from its battle.
	Leave func(accountID int64)
	// Result returns an account's battle result, or nil when it has none.
	Result func(accountID int64) *BattleResultDoc
}

// arenaAvatarApp builds the CreateBasePlayer element for the player's Avatar.
//
// Every base property is written, because the element carries the whole
// domain with no count prefix: the ones this server does not model are the
// defs' zero values, which is exactly what the client would use for a
// property the server never set.
func (s *BaseAppServer) arenaAvatarApp(st *clientState, h *ArenaHandoff) (*Entity, []byte, error) {
	acct := s.cfg.Dispatch.Entity("Avatar")
	if acct == nil {
		return nil, nil, fmt.Errorf("wotserver: no Avatar entity in the defs")
	}
	e := NewEntity(st.entityID, acct)
	for _, p := range acct.BaseProps {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	for _, p := range acct.CellProps {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	e.SetString("name", h.Player.Name)
	e.SetString("sessionID", st.name)
	e.SetUint("arenaUniqueID", h.ArenaID)
	e.SetInt("arenaTypeID", int64(h.ArenaTypeID))
	// `ARENA_GUI_TYPE.RANDOM` and `ARENA_BONUS_TYPE.REGULAR`. Both are read
	// by `Avatar.onBecomePlayer` before the space exists: a 0 gui type
	// loads the wrong dynamic-object set, and a 0 bonus type is UNKNOWN.
	e.SetUint("arenaGuiType", ArenaGuiTypeRandom)
	e.SetUint("arenaBonusType", ArenaBonusTypeRegular)
	// The cell half. `team` is 1 or 2 — the client's
	// `avatar_getter.getPlayerTeam()` treats 0 as "not found" — and
	// `playerVehicleID` must name the Vehicle entity the arena created,
	// because the battle app builds its player panel and input handler
	// from it.
	// The arena's vehicle ids, as a pickled LIST. The PYTHON zero value is an
	// empty DICT, which is the wrong shape entirely — the client iterates this
	// to know which vehicles the arena holds.
	ids := []byte{0x80, 0x02, ']', '('}
	for _, id := range arenaVehicleIDs(h) {
		ids = append(ids, 'J')
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], id)
		ids = append(ids, b[:]...)
	}
	ids = append(ids, 'e', '.')
	e.SetString("arenaVehiclesIDs", string(ids))
	e.SetUint("team", uint64(h.Player.Team))
	e.SetInt("playerVehicleID", int64(h.VehicleID))
	// The Avatar's entity description declares two dynamic components, and
	// `PyEntity::initComponentsFromStream` refuses the entity when the
	// stream's count disagrees ("Wrong number of components in stream.
	// Expected 2, got 0"), which aborts the whole battle entry. The count
	// is all the element carries: no component data follows it, exactly as
	// the Account's 19 does in the reference capture.
	app, err := EncodeCreateBasePlayerWithComponents(e, AvatarComponents)
	if err != nil {
		return nil, nil, err
	}
	return e, app, nil
}

// arenaVehicleApp builds the client's own Vehicle entity.
//
// A Vehicle has no base-hosted client properties — all 50 are cell-side —
// so the entity is created empty and then filled by updateEntity. The
// values that matter are the ones the client reads before the first frame:
// the compact descriptor (which vehicle to build), a positive health (so it
// is alive), and isMyVehicle (so the camera and the player panel bind to
// it). Everything else is the type's zero value.
func (s *BaseAppServer) arenaVehicleApp(st *clientState, h *ArenaHandoff) (*Entity, error) {
	id := h.VehicleID
	if id == 0 {
		id = st.entityID + 1
	}
	return s.arenaVehicleFor(st, h, h.Player, id, true)
}

// vehicleDeltaSkip are the Vehicle properties the entry's `updateEntity` run
// leaves out.
//
// The run is a DELTA, not a full dump: the official server writes only the
// properties it has a value for (a 2.4.0 replay's Vehicle creation carries
// nine, and none of them is a setup), and the client keeps its own default
// for the rest. The four PYTHON ones have no value here, and their zero value
// is the empty-dict pickle — which is NOT "no value" to the client:
// `Vehicle.set_setupsIndexes` runs `updateInvInstalled` over the empty dict
// and raises `KeyError: 'eqsLayout'`, because `set_setups` never filled the
// layouts. Leaving them out is also what the official server does in a battle
// without switch-setups, so the prebattle setups controller stays IDLE
// instead of throwing on every entry.
var vehicleDeltaSkip = []string{
	// Already in the creation run, right before `selectEntity`: the client
	// builds its type descriptor from `publicInfo` there.
	"publicInfo", "health", "isCrewActive", "avatarID", "dogTag", "physicsMode",
	// PYTHON, and unmodelled: the garage's setups/enhancements/perks are not
	// part of the battle handoff.
	"setups", "setupsIndexes", "enhancements", "vehPerks",
}

// arenaVehicleFor builds one Vehicle entity for the given player slot. `own`
// marks the client's own tank, which is the one the camera and the player panel
// bind to.
func (s *BaseAppServer) arenaVehicleFor(st *clientState, h *ArenaHandoff, doc ArenaPlayerDoc, id uint32, own bool) (*Entity, error) {
	typ := s.cfg.Dispatch.Entity("Vehicle")
	if typ == nil {
		return nil, fmt.Errorf("wotserver: no Vehicle entity in the defs")
	}
	e := NewEntity(id, typ)
	for _, p := range typ.CellProps {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	// The client builds the vehicle from `publicInfo.compDescr`, not from a
	// property of its own: `Vehicle.getDescr` calls
	// `vehicles.VehicleDescr(compactDescr=self.publicInfo.compDescr)`, and
	// `_splitVehicleCompactDescr` indexes it as a string. A zeroed
	// publicInfo leaves it empty and the client raises
	// "IndexError: string index out of range" in `Vehicle.onEnterWorld`.
	maxHealth := doc.MaxHealth
	if maxHealth <= 0 {
		maxHealth = 1000
	}
	pi := entdef.ZeroValue(publicInfoType(typ))
	pi = dictSet(pi, "name", entdef.Value{Kind: entdef.VString, Str: doc.Name})
	pi = dictSet(pi, "compDescr", entdef.Value{Kind: entdef.VString, Str: string(doc.VehicleCompDescr)})
	pi = dictSet(pi, "team", entdef.Value{Kind: entdef.VUint, Uint: uint64(doc.Team)})
	pi = dictSet(pi, "maxHealth", entdef.Value{Kind: entdef.VUint, Uint: uint64(maxHealth)})
	// Its slot in the team, 1-based.
	pi = dictSet(pi, "index", entdef.Value{Kind: entdef.VUint, Uint: 1})
	// The crew panel is built from this list: one entry per crew slot, each a
	// packed tankman descriptor. An empty list reads as no crew at all.
	crew := make([]entdef.Value, 0, doc.CrewSize)
	for i := 0; i < doc.CrewSize; i++ {
		crew = append(crew, entdef.Value{Kind: entdef.VUint})
	}
	pi = dictSet(pi, "crewGroups", entdef.Value{Kind: entdef.VSeq, Seq: crew})
	e.Set("publicInfo", pi)
	e.SetInt("health", int64(maxHealth))
	// Without this the client treats the whole crew as incapacitated, which
	// greys out every module in the damage panel.
	e.SetUint("isCrewActive", 1)
	if own {
		e.SetUint("isMyVehicle", 1)
	}
	e.SetInt("arenaTypeID", int64(h.ArenaTypeID))
	e.SetUint("arenaUniqueID", h.ArenaID)
	e.SetUint("arenaBonusType", ArenaBonusTypeRegular)
	// The Avatar's ENTITY id, not the account id: the client compares it with
	// `BigWorld.player().id` (`BattleReplay`'s `hasEnteredAoI`), and the
	// reference sets it from `avatar.id()`.
	e.SetInt("avatarID", int64(st.entityID))
	// `physicsMode` is ALL_CLIENTS and this server never sent it, so it stayed
	// at its zero value. It is the one per-vehicle field that could plausibly
	// say who owns the simulation.
	e.SetUint("physicsMode", 1)
	// A real dog tag, so `Avatar.setClientReady` survives
	// `DogTagsController.__addDogTagMarker` — see defaultDogTagComponents.
	if dt := entdef.Alias("BATTLE_DOG_TAG"); dt != nil {
		e.Set("dogTag", battleDogTagValue(dt))
	}
	return e, nil
}

// publicInfoType returns the declared type of a Vehicle's `publicInfo`.
func publicInfoType(typ *entdef.EntityDispatch) entdef.DataType {
	for _, p := range typ.CellProps {
		if p.Name == "publicInfo" {
			return p.Type
		}
	}
	return nil
}

// defaultDogTagComponents are the two components the reference's
// `DEFAULT_DOG_TAG` carries, as (id, grade): 300 is an ENGRAVING and 66 a
// BACKGROUND (checked against the client's own `componentConfigAdapter`).
//
// They are not decoration. `DogTagsController.__addDogTagMarker` runs on
// `Avatar.onVehicleEnterWorld`, which `Avatar.setClientReady` calls for every
// vehicle, and it does
// `PlayerDogTag.fromDict(vehicle.dogTag['dogTag']).getComponentByType(BACKGROUND)
// .componentDefinition` — with no components that is `None`, the
// `AttributeError` unwinds through `__startVehicleVisual` and `setClientReady`
// never finishes: no `isOnArena`, no `onPeriodChange`, no battle. That is why
// this server used to disable dog tags in its settings instead.
var defaultDogTagComponents = [][2]int64{{300, 9}, {66, 0}}

// battleDogTagValue builds `Vehicle.dogTag`, a `BATTLE_DOG_TAG`: the player's
// tag, the default one, and whether the killer sees it.
func battleDogTagValue(typ entdef.DataType) entdef.Value {
	comps := make([]entdef.Value, 0, len(defaultDogTagComponents))
	for _, c := range defaultDogTagComponents {
		comps = append(comps, entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
			{Name: "id", Value: entdef.Value{Kind: entdef.VInt, Int: c[0]}},
			{Name: "progress", Value: entdef.Value{Kind: entdef.VFloat, Float: 0}},
			{Name: "grade", Value: entdef.Value{Kind: entdef.VInt, Int: c[1]}},
		}})
	}
	tag := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "components", Value: entdef.Value{Kind: entdef.VSeq, Seq: comps}},
	}}
	v := entdef.ZeroValue(typ)
	v = dictSet(v, "dogTag", tag)
	v = dictSet(v, "defaultDogTag", tag)
	// `showDogTagToKiller` keeps its zero value: the defs declare it BOOL but
	// the codec resolves it to UINT8, and zero is false either way.
	return v
}

// dictSet replaces one field of a FIXED_DICT value, leaving the rest of the
// zeroed dict in place.
func dictSet(v entdef.Value, name string, val entdef.Value) entdef.Value {
	for i := range v.Dict {
		if v.Dict[i].Name == name {
			v.Dict[i].Value = val
			return v
		}
	}
	return v
}

// enterArena puts a client into a battle: onArenaCreated, the entity reset,
// the Avatar, the space geometry and the cell player.
//
// The entity reset makes the client send enableEntities again, and the
// CreateBasePlayer/CreateCellPlayer pair is sent from that handler — the
// engine asserts the player entity is NULL before creating a new one, so the
// two cannot be in the same burst.
func (s *BaseAppServer) enterArena(conn Transport, from *net.UDPAddr, st *clientState, h *ArenaHandoff) error {
	// onArenaCreated is best-effort: the reset below is what actually moves
	// the client into the battle, and skipping it because a defs lookup
	// failed would strand the session in the lobby with a queued battle.
	app, err := s.accountCall("onArenaCreated")
	if err != nil {
		s.logf("stage2 %s: arena %d: onArenaCreated (%v); resetting anyway", from, h.ArenaID, err)
	} else if err := s.mintPost(conn, from, st, answerApp(app)); err != nil {
		return err
	}
	// resetEntities(keepPlayerOnBase=false): element 0x04, one bool.
	//
	// Everything queued before this refers to entities the client is about
	// to drop — Account `update` (0x69) and `onCmdResponseExt` (0x5f)
	// pushes above all. Replaying one after the reset makes the client size
	// an entity method for an entity it no longer has, which is
	// `MF_ASSERT_DEV FAILED: pEntity` in
	// `BWEntities::getEntityMethodStreamSize` (bw_entities.cpp:1103). The
	// queue is cleared first so only the reset and what follows it can be
	// resent.
	s.resend.forget(st.resendKey)
	resetApp := answerApp([]byte{elResetEntities, 0})
	s.logf("stage2 %s: leaveArena reset app % x", from, resetApp)
	if err := s.mintPost(conn, from, st, resetApp); err != nil {
		return err
	}
	s.mu.Lock()
	st.arena = h
	st.entered = false // the reset cleared the client's entities
	st.resetSent = true
	// Arm the ready signal for this battle. The client calls
	// `Avatar.setClientReady` once its init steps are done, and that is when
	// the period moves on to PREBATTLE/BATTLE.
	st.readyCh = make(chan struct{})
	st.readyDone = false
	s.mu.Unlock()
	s.logf("stage2 %s: arena %d entry — onArenaCreated + resetEntities (space %d, %s)",
		from, h.ArenaID, h.SpaceID, h.Map)
	return nil
}

// EnterArena pushes a battle entry to one account's live session. It
// reports false when the account has no session (it is not logged in, or it
// dropped and the reconnect window is still open).
//
// This is the matchmaker's handoff: the queue forms a battle, the
// application layer creates the arena, and this puts each player in it.
func (s *BaseAppServer) EnterArena(accountID int64, h *ArenaHandoff) bool {
	if h == nil {
		return false
	}
	st, addr := s.sessionForAccount(accountID)
	if st == nil {
		return false
	}
	s.mu.Lock()
	conn := s.stage2
	s.mu.Unlock()
	if conn == nil {
		return false
	}
	if err := s.enterArena(conn, addr, st, h); err != nil {
		s.logf("arena %d entry for account %d: %v", h.ArenaID, accountID, err)
		return false
	}
	return true
}

// sessionForAccount finds the live session for an account id.
func (s *BaseAppServer) sessionForAccount(accountID int64) (*clientState, *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A socket rebind leaves the old address in byAddr pointing at the same
	// session, so pick the one that spoke most recently rather than
	// whichever the map happens to yield first.
	var best *clientState
	for _, st := range s.byAddr {
		if st.accountID != accountID || st.stage2Addr == nil {
			continue
		}
		if best == nil || st.lastSeen.After(best.lastSeen) {
			best = st
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, best.stage2Addr
}

// enterArenaEntities sends the Avatar, the space geometry and the cell
// player. It runs on the enableEntities the reset provoked.
func (s *BaseAppServer) enterArenaEntities(conn Transport, from *net.UDPAddr, st *clientState, h *ArenaHandoff, seq, cumul uint32) (uint32, error) {
	// A repeated enableEntities is not a second Avatar, exactly as in the
	// lobby path.
	s.mu.Lock()
	done := st.entered
	st.entered = true
	st.resetSent = false
	s.mu.Unlock()
	if done {
		return seq, nil
	}
	entity, avatar, err := s.arenaAvatarApp(st, h)
	if err != nil {
		return seq, err
	}
	s.mu.Lock()
	st.avatar = entity
	s.mu.Unlock()
	if err := s.sendReliableEntity(conn, from, st, avatar, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	s.logf("stage2 %s: CreateBasePlayer %dB (entity %d, Avatar, arena %d)",
		from, len(avatar), st.entityID, h.ArenaID)
	// The rest waits for the client's next datagram: it rebinds its UDP
	// socket when the battle app is created, so anything sent now goes to
	// the port it is tearing down.
	s.mu.Lock()
	st.arenaNext = h
	st.arenaNextAt = time.Now().Add(arenaNextDelay)
	s.mu.Unlock()
	return seq, nil
}

// arenaNextDelay is how long the held-back half of an arena entry waits
// before going out regardless of whether the client spoke. The genuine
// server sends `createCellPlayer` ~215 ms after `createBasePlayer`, which
// is what the client's socket rebind needs; anything much shorter races
// the rebind, anything much longer leaves the battle app with no space.
const arenaNextDelay = 200 * time.Millisecond

// ArenaProbe, when set, stops the arena entry after the Avatar. See
// enterArenaSpace.
var ArenaProbe = func() int {
	switch os.Getenv("WOT_ARENA_PROBE") {
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	case "4":
		return 4
	case "5":
		return 5
	}
	return 0
}()

// enterArenaSpace sends the half of the arena entry that must follow the
// client's socket rebind: the geometry mapping, the cell player, and the
// player's own Vehicle.
func (s *BaseAppServer) enterArenaSpace(conn Transport, from *net.UDPAddr, st *clientState, h *ArenaHandoff, seq, cumul uint32) (uint32, error) {
	// WOT_ARENA_PROBE=1 stops the entry after the Avatar. It bisects a
	// client fault between "the battle app cannot be created at all" and
	// "one of the space/Vehicle elements kills it", which no amount of
	// reading the log can separate.
	if ArenaProbe == 1 {
		s.logf("stage2 %s: arena %d: probe 1, stopping after the Avatar", from, h.ArenaID)
		return seq, nil
	}

	// The cell half. The position is the map origin and the direction is
	// zero: there is no spawn logic behind it, and the client only needs a
	// finite, in-bounds transform to finish loading.
	// The vehicleID field is what registers the space -> vehicle mapping
	// the client's `createEntity` reads back for the player's own tank.
	// The spawn point. Y is up in BigWorld, and the map origin sits below the
	// terrain on every map, so a zero Y drops the player under the ground.
	// There is no spawn logic behind this: a finite, in-bounds transform above
	// the surface is all the client needs to finish loading.
	// The height comes from the map's own terrain, not a constant: the arena
	// defs give the spawn on the ground plane, and the heightmap gives the
	// ground there.
	// The positions come from the map's own arena definition, and the heights
	// from its terrain. The constants are only a fallback for a map whose
	// definition cannot be read.
	ownX, ownZ, enemyX, enemyZ := SpawnX, SpawnZ, EnemyX, EnemyZ
	if def := ArenaDefFor(h.Map); def != nil {
		ownX, ownZ = def.Spawns[0][0], def.Spawns[0][2]
		enemyX, enemyZ = def.Bases[1][0], def.Bases[1][2]
	}
	spawn := [3]float32{ownX, GroundHeight(h.Map, ownX, ownZ, SpawnHeight), ownZ}
	enemy := [3]float32{enemyX, GroundHeight(h.Map, enemyX, enemyZ, SpawnHeight), enemyZ}
	cell, err := EncodeCreateCellPlayer(st.avatar, h.SpaceID, h.VehicleID,
		spawn, PackedXZScale, [3]float32{0, 0, 0}, AvatarComponents)
	if err != nil {
		return seq, err
	}
	if err := s.sendReliableEntity(conn, from, st, cell, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	// The geometry mapping goes AFTER the cell player, not before: the
	// reference's `create_cell_player` writes `CreateCellPlayer` and then
	// the space's data, because the space only exists once the cell player
	// has created it. Mapping geometry into a space that does not exist yet
	// is what faults the client.
	entry := [8]byte{0, 0, 0, 1, 0, 0, 0, 1}
	space, err := EncodeAddSpaceGeometryMapping(h.SpaceID, entry, h.Map, IdentityTransform())
	if err != nil {
		return seq, err
	}
	if err := s.sendReliableEntity(conn, from, st, space, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	s.logf("stage2 %s: addSpaceGeometryMapping %dB (space %d, geometry %s)", from, len(space), h.SpaceID, h.Map)
	if ArenaProbe == 2 {
		s.logf("stage2 %s: arena %d: probe 2, stopping after the geometry", from, h.ArenaID)
		return seq, nil
	}
	// The exact bytes, so a client that drops the element can be diffed
	// against the genuine one without another guess.
	s.logf("stage2 %s: CreateCellPlayer %dB (entity %d, space %d): % x",
		from, len(cell), st.entityID, h.SpaceID, cell)

	// The player's own Vehicle entity comes last, and that order is not
	// cosmetic: `Vehicle.__init__` calls `refreshNationalVoice`, which does
	// `BigWorld.player().observedVehicleID`, so the Avatar must already
	// exist. `createCellPlayer`'s vehicleID field is what registers the
	// space -> vehicle mapping the client's `createEntity` reads back.
	// The Vehicle is best-effort: a defs or encoding problem there must not
	// cost the client its space, which is what actually makes the battle
	// load. A failure is logged and the entry continues.
	vehicle, err := s.arenaVehicleApp(st, h)
	if err != nil {
		s.logf("stage2 %s: arena %d: no Vehicle (%v); entering without one", from, h.ArenaID, err)
		return seq, nil
	}
	// The outer half of the property table: the properties with no
	// `<DetailLevel>`, which is where `publicInfo` lives. The MY_VEHICLE ones
	// ride the `updateEntity` below.
	// Only what the client can take before the entity is in the world. Its
	// creation run is applied property by property and ABANDONED at the first
	// setter that throws; `set_stunInfo` wants `entityGameObject` and
	// `set_remoteCamera` wants `ownVehicle`, so sending them here kills every
	// property after them — `publicInfo` included, which is what left the tank
	// with no descriptor. They ride the update below instead.
	props, err := EntityPropertyRunNames(vehicle, "publicInfo", "health", "isCrewActive", "avatarID", "dogTag", "physicsMode")
	// WOT_ARENA_PROBE=3 bisects the property run: the vehicle is created with
	// `publicInfo` alone. If the client then builds its descriptor, the run is
	// desyncing before it; if it still comes back empty, the dict's own
	// encoding is what the client rejects.
	if ArenaProbe == 3 {
		props, err = publicInfoOnlyRun(vehicle, false)
	} else if ArenaProbe == 4 {
		props, err = publicInfoOnlyRun(vehicle, true)
	}
	if err != nil {
		s.logf("stage2 %s: arena %d: Vehicle properties (%v); entering without one", from, h.ArenaID, err)
		return seq, nil
	}
	// `createEntity`, not `createEntityDetailed`: the genuine server creates a
	// vehicle with an alias, and that is the element it uses.
	create, err := EncodeCreateEntity(vehicle.ID, uint16(vehicle.Type.TypeID), VolatilePackerType,
		spawn, 0, 0, 0, props)
	if err != nil {
		s.logf("stage2 %s: arena %d: Vehicle element (%v); entering without one", from, h.ArenaID, err)
		return seq, nil
	}
	if err := s.sendReliableEntity(conn, from, st, create, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	// The cell properties BEFORE the entity enters the world:
	// `Vehicle.onEnterWorld` builds its type descriptor from `publicInfo`,
	// and `set_publicInfo` does not rebuild it, so an update that arrives
	// afterwards leaves the vehicle with no descriptor, no appearance and no
	// `VEHICLE_ENTERED` init step — the loading screen then never finishes.
	sel, err := EncodeSelectEntity(vehicle.ID)
	if err != nil {
		return seq, err
	}
	if err := s.sendReliableEntity(conn, from, st, sel, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	// The turret's rest angle, packed the way `gun_rotation_shared.encodeGunAngles`
	// does it. The def's zero value decodes to yaw -pi, i.e. the gun pointing
	// backwards into the hull, and `VehicleGunRotator.__syncWithServerTurretYaw`
	// then drags the turret there every rotation tick because the deviation is a
	// full pi. Yaw 0 is forward, which is where the turret starts.
	if spec, ok := vehicleGunSpeeds(h.Player.VehicleCompDescr); ok {
		vehicle.Props["gunAnglesPacked"] = entdef.Value{
			Kind: entdef.VUint,
			Uint: packGunAngles(0, 0, spec.PitchMin, spec.PitchMax),
		}
	}
	update, err := EncodeUpdateEntityExcept(vehicle, true, vehicleDeltaSkip...)
	if err != nil {
		return seq, err
	}
	if err := s.sendReliableEntity(conn, from, st, update, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	enter, err := EncodeEnterAoI(vehicle.ID, VehicleAlias)
	if err != nil {
		return seq, err
	}
	if err := s.sendReliableEntity(conn, from, st, enter, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	// Control authority over the player's own tank. The captured server never
	// sends this, but without it this client's vehicle physics is never
	// stepped: the simulation callbacks never fire, `movementSignals` stays 0
	// while driving, and the track scroll and engine RPM stay pinned. It is
	// behind a switch because it is traffic the official server does not send.
	if controlEntityOn {
		if ctl := EncodeControlEntity(vehicle.ID, true); len(ctl) > 0 {
			if err := s.sendReliableEntity(conn, from, st, ctl, seq, cumul); err != nil {
				return seq, err
			}
			seq++
			s.logf("stage2 %s: arena %d controlEntity(%d, true) (%dB)", from, h.ArenaID, vehicle.ID, len(ctl))
		}
	}
	spec, haveSpec := vehicleGunSpeeds(h.Player.VehicleCompDescr)
	if !haveSpec {
		s.logf("stage2 %s: arena %d: no gun spec for the vehicle; the turret will not track", from, h.ArenaID)
	}
	s.mu.Lock()
	st.vehicle = vehicle
	st.gunSpec = spec
	st.gunYaw, st.gunTarget = 0, 0
	st.hull = hull{
		Position:  spawn,
		Direction: [3]float32{0, 0, 0},
		Limits:    spec.Limits,
	}
	st.nrlIDa, st.nrlIDb = arenaNrlIds(h.ArenaID)
	st.tick = s.tickEpoch()
	// Per-battle, not per-session: `battleStarted` gates the aux word and the
	// Vehicle's two bare properties, and the captured server sends none of
	// them during the loading screen. Left set from a previous battle it
	// would put them on the first tick of the next one, while the client is
	// still loading — measured, that leaves it stuck on the loading screen
	// with `isOnArena` false.
	st.battleStarted = false
	st.hadGround = false
	st.lastMarkerSet = false
	s.mu.Unlock()
	// The hull and the turret are simulated here, not echoed: see
	// `trackTurret`. The terrain is what the hull rests on, so it is resolved
	// once for the battle rather than per tick.
	if haveSpec {
		go s.trackTurret(conn, from, st, h.ArenaID, spec, TerrainFor(h.Map))
	}
	s.logf("stage2 %s: Vehicle %d created (createEntityDetailed %dB, selectEntity, updateEntity %dB, enterAoI)",
		from, vehicle.ID, len(create), len(update))

	// One node allocator for the whole entry: NRL node ids are unique per
	// space, so every entity node, component node and component child in this
	// battle comes from here.
	alloc := newNrlNodeAlloc()

	// The vehicle list. `ClientArena.vehicles` is what the battle-loading
	// screen builds both team panels from, and the only thing that fills it
	// is the AvatarVehiclesInfo component on the arena's AvatarInfo entity.
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		s.logf("stage2 %s: arena %d: no VEHICLES_INFO type; the loading screen will stay empty", from, h.ArenaID)
		return seq, nil
	}
	vehicles := []entdef.Value{vehicleInfoValue(infoType, h.Player, vehicle.ID, 1, ownX, ownZ)}

	// The synthetic opponent, if the battle has one: its own Vehicle entity
	// first, so the client has something to draw, then its list entry.
	if h.Dummy != nil {
		dummyID := h.VehicleID + 1
		dv, err := s.arenaVehicleFor(st, h, *h.Dummy, dummyID, false)
		if err != nil {
			s.logf("stage2 %s: arena %d: no dummy Vehicle (%v)", from, h.ArenaID, err)
		} else if dprops, err := EntityPropertyRunNames(dv, "publicInfo", "health", "isCrewActive", "avatarID", "dogTag"); err != nil {
			s.logf("stage2 %s: arena %d: dummy Vehicle properties (%v)", from, h.ArenaID, err)
		} else if dcreate, err := EncodeCreateEntity(dv.ID, uint16(dv.Type.TypeID), VolatilePackerType,
			enemy, 0, 0, 0, dprops); err != nil {
			s.logf("stage2 %s: arena %d: dummy Vehicle element (%v)", from, h.ArenaID, err)
		} else {
			if err := s.sendReliableEntity(conn, from, st, dcreate, seq, cumul); err != nil {
				return seq, err
			}
			seq++
			// Same order as the player's own tank: the cell properties, then
			// the entity enters the world.
			if dsel, err := EncodeSelectEntity(dv.ID); err == nil {
				if err := s.sendReliableEntity(conn, from, st, dsel, seq, cumul); err != nil {
					return seq, err
				}
				seq++
			}
			if dupdate, err := EncodeUpdateEntityExcept(dv, true, vehicleDeltaSkip...); err == nil {
				if err := s.sendReliableEntity(conn, from, st, dupdate, seq, cumul); err != nil {
					return seq, err
				}
				seq++
			}
			if denter, err := EncodeEnterAoI(dv.ID, 0); err == nil {
				if err := s.sendReliableEntity(conn, from, st, denter, seq, cumul); err != nil {
					return seq, err
				}
				seq++
			}
			// The server's copy of the dummy: where it stands and how much
			// health it has left. `applyShot` updates the health and sends
			// the client the difference.
			s.mu.Lock()
			st.dummy = dv
			st.dummyID = dummyID
			st.dummyPos = enemy
			st.dummyYaw = 0
			if hv, ok := dv.Props["health"]; ok {
				st.dummyHealth = int(hv.Int)
			}
			st.dummyMaxHealth = st.dummyHealth
			s.mu.Unlock()
			vehicles = append(vehicles, vehicleInfoValue(infoType, *h.Dummy, dummyID, 1, enemyX, enemyZ))
			s.logf("stage2 %s: dummy Vehicle %d created (team %d, %d B)", from, dummyID, h.Dummy.Team, len(dcreate))
		}
	}

	info, infoApp, err := s.arenaInfoApp(st, h, alloc, vehicles)
	if err != nil {
		s.logf("stage2 %s: arena %d: no AvatarInfo (%v); the loading screen will stay empty", from, h.ArenaID, err)
		return seq, nil
	}
	s.mu.Lock()
	st.infoPlayer = 0
	if h.Dummy != nil {
		st.infoDummy = 1
	} else {
		st.infoDummy = -1
	}
	s.mu.Unlock()
	iprops, err := EntityPropertyRunLevel(info, false)
	if err != nil {
		s.logf("stage2 %s: arena %d: AvatarInfo properties (%v)", from, h.ArenaID, err)
		return seq, nil
	}
	icreate, err := EncodeCreateEntityDetailed(info.ID, uint16(info.Type.TypeID), "",
		[3]float32{0, 0, 0}, [3]float32{0, 0, 0}, iprops)
	if err != nil {
		s.logf("stage2 %s: arena %d: AvatarInfo element (%v)", from, h.ArenaID, err)
		return seq, nil
	}
	if err := s.sendReliableEntity(conn, from, st, icreate, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	if ienter, err := EncodeEnterAoI(info.ID, 0); err == nil {
		if err := s.sendReliableEntity(conn, from, st, ienter, seq, cumul); err != nil {
			return seq, err
		}
		seq++
	}
	if err := s.sendReliableEntity(conn, from, st, infoApp, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	s.logf("stage2 %s: AvatarInfo %d created (createEntityDetailed %dB, NRL %dB, %d vehicles)",
		from, info.ID, len(icreate), len(infoApp), len(vehicles))

	// The player's own tank gets its `OwnVehicle` component: the client only
	// turns its turret once it knows how fast it can, and it reads the
	// ammunition, the loaded shells, the reload and the health from here.
	// Best-effort — a missing alias type must not cost the battle.
	//
	// The allocator is the entry's, not a fresh one: NRL node ids are unique
	// per space, and a second allocator starting at 2 would hand out the ids
	// the AvatarInfo entity and its component already took. The client then
	// grafts the vehicle's component onto the info entity's node and the
	// vehicle list is lost.
	// The zero value of `vehicleHealthInfo` is health 0 and crew inactive,
	// which the client renders as every module destroyed and the whole crew
	// dead. It has to carry the real state.
	// The ammunition layout the player saved in the garage, so the in-battle
	// loadout is the one they chose rather than the gun's default shell.
	var savedShells []int64
	s.mu.Lock()
	for k := range st.garage {
		if bytes.Equal(st.garage[k].CompactDescr, h.Player.VehicleCompDescr) {
			savedShells = st.garage[k].Shells
			break
		}
	}
	s.mu.Unlock()
	overrides := ownVehicleOverrides(vehicle.ID, h.Player.VehicleCompDescr, savedShells)
	// Keep the ammo list so a shot can decrement it. The value is the same
	// one the OwnVehicle component is created with, so the first re-send
	// differs from the client's copy only by the fired shell. The loaded and
	// next shell come from the SAME helper the component used, so the
	// server's idea of the loaded shell cannot drift from the client's.
	s.mu.Lock()
	st.ammoList = overrides["vehicleAmmoList"]
	st.loadedShell = loadedShellFor(st.gunSpec.Dispersion, savedShells)
	st.nextShell = st.loadedShell
	s.mu.Unlock()

	// WOT_ARENA_PROBE=5 sweeps a range of NRL component ids onto the vehicle.
	// The client logs `createDynamicComponent: <Name> failed to load` for every
	// id that names a component it cannot build, which names each id in one
	// run — the only way to learn the mapping, since the defs' ordering does
	// not match the client's.
	if ArenaProbe == 5 {
		// One component per element, with the entity node created only in the
		// first: the client abandons the rest of an element as soon as one
		// component fails to build, so a single element can only ever name one
		// id. Separate elements each carrying their own entity node are
		// rejected outright, hence the split.
		entityNode := alloc.take(1)
		first := true
		for id := uint16(45); id <= 60; id++ {
			compNode := alloc.take(1)
			children := make([]uint32, 0, len(ownVehicleProps)+1)
			present := make([]bool, 0, len(ownVehicleProps)+1)
			for range ownVehicleProps {
				children = append(children, uint32(alloc.take(1)))
				present = append(present, true)
			}
			children = append(children, uint32(alloc.take(1)))
			present = append(present, true)
			var msg []byte
			if first {
				msg = EncodeNrlCreateEntityNode(entityNode, vehicle.ID)
				first = false
			}
			msg = append(msg, EncodeNrlCreateComponent(compNode, entityNode, id, "", children, present, nil)...)
			app, err := element(elNrlCreateNode, msg)
			if err != nil {
				return seq, err
			}
			if err := s.sendReliableEntity(conn, from, st, app, seq, cumul); err != nil {
				return seq, err
			}
			seq++
		}
		s.logf("stage2 %s: probe 5 sent component ids 45..60, one per element", from)
	} else {
		// The child list MUST match the component's own property count: the
		// client reads one value per declared property, so a mismatch — too
		// many or too few — runs off the end of the stream and crashes with
		// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`. That is why the
		// id cannot be swept blindly: only an id whose component declares
		// exactly len(ownVehicleProps) properties is safe to try.
		ownApp, ownComp, err := EncodeNrlAttachComponentAt(alloc, vehicle.ID, OwnVehicleNrlID, ownVehicleProps, ownVehicleClientMethods, overrides)
		if err != nil {
			s.logf("stage2 %s: arena %d: no OwnVehicle (%v)", from, h.ArenaID, err)
		} else if err := s.sendReliableEntity(conn, from, st, ownApp, seq, cumul); err != nil {
			return seq, err
		} else {
			seq++
			s.mu.Lock()
			st.ownVehicle = ownComp
			s.mu.Unlock()
			s.logf("stage2 %s: OwnVehicle attached to %d as NRL id %d (%dB, node %d, %d props, %d methods)",
				from, vehicle.ID, OwnVehicleNrlID, len(ownApp), ownComp.Node, ownComp.Props, ownComp.Methods)
		}
	}

	// The battle itself. `Avatar.setClientReady` only sets `isOnArena` when
	// the arena's period is BATTLE, so the client finishes loading and stays
	// out of the arena until this arrives.
	//
	// `updateArena` is an Avatar client method, and an entity method applies
	// to whatever `selectEntity` last selected — which is a Vehicle by now.
	// Without this the client resolves the element id against Vehicle, finds
	// it out of range, and drops the whole bundle as
	// REASON_CORRUPTED_PACKET.
	if sel, err := EncodeSelectEntity(st.entityID); err == nil {
		if err := s.sendReliableEntity(conn, from, st, sel, seq, cumul); err != nil {
			return seq, err
		}
		seq++
	}

	// The hull attitude the client feeds to `WoT.computeStabilisedVehicleMatrixU64`.
	// Its zero value is NOT level: it unpacks to yaw -pi, pitch -pi/2, roll -pi,
	// which rotates the stabilised matrix 90 degrees about X. `getShotAngles`
	// then aims in that rotated frame, so the turret only ever reaches its
	// limits instead of tracking. This is
	// `WoT.packAuxVehiclePhysicsData(0, 0, 0, 0, 0, 0)`.
	//
	// It has to arrive before the vehicle starts: `__startVehicleVisual` reads
	// it once, and `set_ownVehicleAuxPhysicsData` only re-applies it to a
	// vehicle that is already started.
	st.avatar.Props["ownVehicleAuxPhysicsData"] = entdef.Value{
		Kind: entdef.VUint, Uint: ownVehicleAuxPhysicsLevel,
	}
	if run, err := EntityPropertyRunNames(st.avatar, "ownVehicleAuxPhysicsData"); err != nil {
		s.logf("stage2 %s: arena %d: ownVehicleAuxPhysicsData (%v)", from, h.ArenaID, err)
	} else if el, err := element(elUpdateEntity, run); err != nil {
		s.logf("stage2 %s: arena %d: ownVehicleAuxPhysicsData element (%v)", from, h.ArenaID, err)
	} else if err := s.sendReliableEntity(conn, from, st, el, seq, cumul); err != nil {
		return seq, err
	} else {
		seq++
		s.logf("stage2 %s: arena %d ownVehicleAuxPhysicsData = %#x (%dB)", from, h.ArenaID, ownVehicleAuxPhysicsLevel, len(el))
	}

	// PREBATTLE first, BATTLE after the delay — the order the real server uses,
	// and the only one that reliably sets `isOnArena`.
	//
	// `Avatar.setClientReady` sets `isOnArena` only when the period is ALREADY
	// BATTLE at the moment it runs, and it registers `onPeriodChange` only
	// AFTER that check. So a BATTLE that arrives before the client is ready is
	// lost, and a second BATTLE after it is a no-op: `ClientArena` fires
	// `onPeriodChange` on a *change*, so re-sending the same period does
	// nothing and the client stays out of the arena with the gun frozen.
	// Sending PREBATTLE here and BATTLE later gives a real transition whichever
	// way the race goes: if the client is ready first it sees 1 then 2 and the
	// handler fires; if it is ready last it sees 2 and sets `isOnArena` itself.
	// Tell the client how often the tick will arrive, before the first one
	// does. `UPDATE_FREQUENCY_NOTIFICATION` is the element whose whole purpose
	// is that number, and it is what a client interpolates between ticks with;
	// the real server sends it and this one did not.
	// The game time goes with the frequency, and it is what the client's
	// `BigWorld.serverTime()` returns. The battle timer is
	// `BigWorld.serverTime() - (periodEndTime - periodLength)`
	// (`Avatar.__onArenaPeriodChange`), so a zero here makes the timer
	// meaningless however right the period tuple is.
	//
	// It is the RAW 10 Hz tick counter, NOT seconds, and the two units are
	// what the capture pins: at 14:17:25.943 the captured server's
	// `UPDATE_FREQUENCY_NOTIFICATION` carries game time 1126351 while the
	// period tuples are in seconds (`(2, 112646.6, 3, …)`), and the tick at
	// that instant is ~1126346. So `serverTime()` is `gameTime / 10 + elapsed`
	// — seconds, the same base `periodEndTime` uses.
	//
	// Sending seconds here instead makes `serverTime()` ten times too small,
	// and `battleTime` then carries a constant offset of
	// `(periodEndTime - periodLength) - serverTime` = -128 s: the battle timer
	// opens at 2:08 and the prebattle countdown is off by the same amount.
	gameTime := arenaGameTime(st.tick)
	if freq := EncodeUpdateFrequency(uint8(time.Second/arenaTickPeriod), 0, gameTime); len(freq) > 0 {
		if err := s.sendReliableEntity(conn, from, st, freq, seq, cumul); err != nil {
			return seq, err
		}
		seq++
		s.logf("stage2 %s: arena %d update frequency %d Hz (%dB)", from, h.ArenaID, time.Second/arenaTickPeriod, len(freq))
	}
	// The period sequence the captured server uses: WAITING, then PREBATTLE,
	// then BATTLE, each with a real end time, length and additional info. It
	// sends WAITING first and we did not, and its additional info is always a
	// sequence — `MapActivities.__setStartTimes` does `len(...)` on it and
	// throws on a None, which aborted the rest of the period handler.
	// `periodEndTime` is the END of the period: `MapActivities.__onArenaPeriodChange`
	// computes `periodStartTime = periodEndTime - periodLength`, and the
	// capture's BATTLE tuple is 114146.6 with length 1500, i.e. exactly its
	// PREBATTLE end time plus the length. The game time is the tick counter in
	// seconds — the capture's PREBATTLE end time 112646.6 against a tick of
	// 1126468.
	// The length is how long the period actually lasts, not the capture's 60:
	// the client counts down from `periodLength`, so a length that disagrees
	// with the delay shows a countdown that jumps when the period changes.
	// The capture has that mismatch (length 60, ended 8.4 s later) and there is
	// no reason to copy it.
	waitLen := uint32(arenaPeriodDelays[0] / time.Second)
	period, err := arenaPeriodUpdateFull(st.avatar, ArenaPeriodWaiting, arenaPeriodEnd(st.tick, waitLen), waitLen, []float64{1, 11})
	if err != nil {
		s.logf("stage2 %s: arena %d: period update (%v)", from, h.ArenaID, err)
		return seq, nil
	}
	if err := s.sendReliableEntity(conn, from, st, period, seq, cumul); err != nil {
		return seq, err
	}
	seq++
	s.logf("stage2 %s: arena %d period → WAITING (%dB)", from, h.ArenaID, len(period))

	// The player's TEAM entity. `ClientArena.teamInfo` is not the AvatarInfo:
	// it is whatever `TeamInfo.onEnterWorld` registers, and with no TeamInfo
	// entity it stays None. `prebattle_highlights/controller.__start` then
	// raises `AttributeError: 'NoneType' object has no attribute 'components'`
	// on every entry, and the chat's spam-protection lookup silently loses its
	// component. The official server creates one TeamInfo per team the client
	// sees — a replay's create table has exactly one, carrying `teamID` equal
	// to the player's — and only that one property is modelled here; the
	// client defaults the static components' properties.
	if tt := s.cfg.Dispatch.Entity("TeamInfo"); tt != nil {
		teamID := h.VehicleID + 3
		te := NewEntity(teamID, tt)
		for _, p := range tt.Properties {
			te.Set(p.Name, entdef.ZeroValue(p.Type))
		}
		te.SetInt("teamID", int64(h.Player.Team))
		tprops, terr := EntityPropertyRunNames(te, "teamID")
		if terr != nil {
			s.logf("stage2 %s: arena %d: TeamInfo properties (%v)", from, h.ArenaID, terr)
		} else if tcreate, terr := EncodeCreateEntity(teamID, uint16(tt.TypeID), VolatilePackerType,
			[3]float32{0, 0, 0}, 0, 0, 0, tprops); terr != nil {
			s.logf("stage2 %s: arena %d: TeamInfo element (%v)", from, h.ArenaID, terr)
		} else if err := s.sendReliableEntity(conn, from, st, tcreate, seq, cumul); err != nil {
			return seq, err
		} else {
			seq++
			if tenter, terr := EncodeEnterAoI(teamID, 0); terr == nil {
				if err := s.sendReliableEntity(conn, from, st, tenter, seq, cumul); err != nil {
					return seq, err
				}
				seq++
			}
			s.logf("stage2 %s: TeamInfo %d created (team %d, %dB)", from, teamID, h.Player.Team, len(tcreate))
		}
	}

	// Then the battle itself, but only once the CLIENT is ready.
	//
	// `Avatar.setClientReady` is a base method the client calls when its init
	// steps are done, and it registers its `onPeriodChange` handler only
	// AFTER the `period == BATTLE` check at the top of the same function. So
	// a BATTLE that lands before that call is dropped and the client never
	// enters the arena: loaded, in the battle, and frozen — the "cannot move
	// for 30 s" bug. Waiting for the call instead of for a timer is what the
	// official server does, and it is the only signal that cannot race the
	// load.
	//
	// PREBATTLE first and BATTLE three seconds later, the capture's own 3.0 s
	// prebattle: the countdown the player sees is then real, and `isOnArena`
	// flips exactly once.
	go func() {
		s.mu.Lock()
		ready := st.readyCh
		s.mu.Unlock()
		if ready != nil {
			select {
			case <-ready:
			case <-time.After(arenaReadyTimeout):
				s.logf("stage2 %s: arena %d: no setClientReady after %s; starting anyway",
					from, h.ArenaID, arenaReadyTimeout)
			}
		}
		preLen := uint32(arenaPeriodDelays[1] / time.Second)
		if err := s.sendArenaPeriod(conn, from, st, h, ArenaPeriodPrebattle, preLen, []float64{10, 10}); err != nil {
			return
		}
		time.Sleep(arenaPeriodDelays[1])
		if err := s.sendArenaPeriod(conn, from, st, h, ArenaPeriodBattle, 1500, []float64{10, 10}); err != nil {
			return
		}
	}()
	return seq, nil
}

// sendArenaPeriod sends one `updateArena(PERIOD, ...)` to the client's Avatar.
//
// `updateArena` is an Avatar client method, and an entity method applies to
// whatever `selectEntity` last selected — the tick and the answers to the
// client's own calls move that selection, so the Avatar is re-selected first.
// Measured: a period update sent without the select did not apply, leaving
// `arena.period` where it was and `isOnArena` false.
//
// The sequence number is minted under `sendMu` in the same order it is sent:
// the ticker sends every 100 ms, and a number read before it ran is a
// duplicate the client drops.
func (s *BaseAppServer) sendArenaPeriod(conn Transport, from *net.UDPAddr, st *clientState, h *ArenaHandoff, period uint8, length uint32, additional []float64) error {
	s.mu.Lock()
	// The client may have left the battle in the meantime. Sending an entity
	// method to a destroyed Avatar is `MF_ASSERT_DEV FAILED: pEntity` in
	// BWEntities::getEntityMethodStreamSize, which crashes the client — so
	// the arena has to still be the one we entered.
	if st.arena == nil || st.arena.ArenaID != h.ArenaID || st.avatar == nil {
		s.mu.Unlock()
		return nil
	}
	avatar := st.avatar
	tick := st.tick
	s.mu.Unlock()
	el, err := arenaPeriodUpdateFull(avatar, period, arenaPeriodEnd(tick, length), length, additional)
	if err != nil {
		return err
	}
	if sel, err := EncodeSelectEntity(st.entityID); err == nil {
		el = append(sel, el...)
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("stage2 %s: arena %d period → %d send failed: %v", from, h.ArenaID, period, err)
		return err
	}
	if period == ArenaPeriodBattle {
		s.mu.Lock()
		st.battleStarted = true
		s.mu.Unlock()
	}
	s.logf("stage2 %s: arena %d period → %d (len %d, seq %d, cumul %d, %dB)",
		from, h.ArenaID, period, length, seq, cumul, len(el))
	return nil
}

// AvatarVehiclesInfoNrlID is the NRL type id of the `AvatarVehiclesInfo`
// dynamic component.
//
// NRL ids are indices into the client's own `EntityType` table: entities first
// (0..52), then the dynamic components in `scripts/components.xml` order.
// `AvatarVehiclesInfo` is 126 and `ForcedReloadComponent` 127 — the two are
// adjacent in both lists, which is what pinned the base. The full table is in
// docs/ENTITY_TYPE_IDS.md.
const AvatarVehiclesInfoNrlID uint16 = 126

// OwnVehicleNrlID is the NRL type id of the `OwnVehicle` dynamic component.
//
// It is the index of the type in the client's own `EntityType` table, which is
// entities first (0..52, `GeneralSpaceData` through `SPGZone`) and then the
// dynamic components in `scripts/components.xml` order: `OwnVehicle` is 53,
// `InAoEZone` 54, `AvatarVehiclesInfo` 126. 50 is `HWDeathZone`, an entity —
// the client logs `createDynamicComponent: HWDeathZone failed to load` for it
// and the gun never learns its rotation speeds.
var OwnVehicleNrlID uint16 = func() uint16 {
	if v := os.Getenv("WOT_OWNVEHICLE_NRL"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 16); err == nil {
			return uint16(n)
		}
	}
	return 53
}()

// loadedShellFor is the shell the gun starts loaded with: the first shell of
// the saved loadout that has ammo left, which is what the reference's
// `Gun::new` does (`first_left`), falling back to the gun's default shell when
// the garage holds no layout.
//
// The ammo list and `vehicleSettings` must agree on it. `CURRENT_SHELLS` is
// only applied when the client already has an ammo entry for the shell
// (`Avatar.__updateVehicleSetting` returns early otherwise), so a loaded shell
// outside the list leaves the gun with no shell and `canShoot` at WAITING.
func loadedShellFor(disp dispersionSpec, savedShells []int64) int32 {
	for i := 0; i+1 < len(savedShells); i += 2 {
		if savedShells[i] != 0 && savedShells[i+1] > 0 {
			return int32(savedShells[i])
		}
	}
	return disp.ShellCD
}

// ownVehicleOverrides is the `OwnVehicle` property values this server sets,
// keyed by property name; anything absent keeps the alias's zero value.
//
// The zero values are wrong in three ways that each cost the gun, so they are
// spelled out here rather than left implicit.
func ownVehicleOverrides(vehicleID uint32, compDescr []byte, savedShells []int64) map[string]entdef.Value {
	overrides := map[string]entdef.Value{}
	// `smokeInfo` must be None, not its zero value.
	//
	// The zero value is a dict with `equipmentID: 0`, and
	// `OwnVehicle.update_smokeInfo` fires `VEHICLE_VIEW_STATE.SMOKE` with it.
	// `timers_panel.__updateSmokeTimer` then does
	// `vehicles.g_cache.equipments()[0].totalDuration`, which is an
	// `Extinguisher` with no such attribute — the `AttributeError` unwinds
	// through `onVehicleControlling` and aborts `_VehicleUpdater._setup`
	// before `updater.start()`. That updater is what polls
	// `VEHICLE_VIEW_STATE.SPEED`, so the km/h digits next to the cruise-mode
	// indicator stay at 0 for the whole battle. `SMOKE_INFO` is `AllowNone`,
	// and `None` takes the `_hideTimer` branch.
	overrides["smokeInfo"] = entdef.Value{Kind: entdef.VNone}
	hiType := entdef.Alias("VEHICLE_HEALTH_INFO")
	if hiType != nil {
		hi := entdef.ZeroValue(hiType)
		hi = dictSet(hi, "id", entdef.Value{Kind: entdef.VInt, Int: int64(vehicleID)})
		hi = dictSet(hi, "health", entdef.Value{Kind: entdef.VInt, Int: 1000})
		hi = dictSet(hi, "isCrewActive", entdef.Value{Kind: entdef.VUint, Uint: 1})
		overrides["vehicleHealthInfo"] = hi
	}
	// The gun's aiming state. Its zero value has maxTurretRotationSpeed and
	// maxGunRotationSpeed at 0, which means the turret cannot turn at all —
	// the gun is frozen. The two speeds are the vehicle's own, from its item
	// defs: they are the rate limit `getNextTurretYaw` applies, so a large
	// constant here makes the turret snap instead of swing.
	turretSpeed, gunSpeed := 0.5, 0.5 // rad/s, a mid-tier tank, if the defs miss
	disp := dispersionSpec{AimingTime: 2, Movement: 1, Rotation: 1, TurretRotation: 1, AfterShot: 1}
	if sp, ok := vehicleGunSpeeds(compDescr); ok {
		turretSpeed, gunSpeed = sp.Turret, sp.Gun
		disp = sp.Dispersion
	}
	if tiType := entdef.Alias("TARGETING_INFO"); tiType != nil {
		ti := entdef.ZeroValue(tiType)
		setF := func(field string, v float64) {
			ti = dictSet(ti, field, entdef.Value{Kind: entdef.VFloat, Float: v})
		}
		setF("turretYaw", 0)
		setF("gunPitch", 0)
		setF("maxTurretRotationSpeed", turretSpeed)
		setF("maxGunRotationSpeed", gunSpeed)
		// The client's own dispersion model reads these five from here
		// (`Avatar.getOwnVehicleShotDispersionAngle` takes them out of
		// `self.__dispersionInfo`, which `OwnVehicle.update_targetingInfo`
		// fills from this dict). Hardcoding 1.0 made every tank disperse as if
		// it were a different vehicle: the factors are the gun's and the
		// chassis's own, from the item defs.
		setF("shotDispMultiplierFactor", 1)
		setF("gunShotDispersionFactorsTurretRotation", disp.TurretRotation)
		setF("chassisShotDispersionFactorsMovement", disp.Movement)
		setF("chassisShotDispersionFactorsRotation", disp.Rotation)
		setF("aimingTime", disp.AimingTime)
		setF("gunShotDispersionFactorsAfterShot", disp.AfterShot)
		overrides["targetingInfo"] = ti
	}
	// `fixAngles` must be None, not its zero value. `OwnVehicleBase.
	// update_fixAngles` does `if self.fixAngles: gunRotator.fixShotPosition(...)`
	// else `unFixShotPosition()`, and the zero value of `GUN_ROTOR_FIX_ANGLES`
	// is a dict of two zero floats — truthy — so the turret gets pinned to
	// (0, 0) and `VehicleGunRotator.__rotate` never turns it. The alias is
	// `AllowNone`, so None is the value that means "no fixed angles".
	overrides["fixAngles"] = entdef.Value{Kind: entdef.VNone}
	// `drownLevel` and `overturnLevel` carry a `times` ARRAY that the client
	// indexes unconditionally: `OwnVehicleBase.__getDestroyTimes` reads
	// `times[0]` and `times[1]`, so the alias's zero value — an EMPTY array —
	// raises `IndexError: Array index out of range` out of
	// `update_drownLevel` and `update_overturnLevel` on every battle (seen in
	// the client's `game.log` at 23:26:59.346, twice, right after the vehicle
	// attaches). The pair is (startTime, endTime); level 0 is "not drowning"
	// and "not overturned", which is the state a tank spawns in.
	for _, p := range []struct{ prop, alias string }{
		{"drownLevel", "DROWN_LEVEL"},
		{"overturnLevel", "OVERTURN_LEVEL"},
	} {
		t := entdef.Alias(p.alias)
		if t == nil {
			continue
		}
		v := entdef.ZeroValue(t)
		v = dictSet(v, "level", entdef.Value{Kind: entdef.VUint})
		v = dictSet(v, "times", entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
			{Kind: entdef.VFloat},
			{Kind: entdef.VFloat},
		}})
		overrides[p.prop] = v
	}
	// The ammunition and the loaded shell, which is what decides whether the
	// gun fires at all.
	//
	// `AmmoController.canShoot` returns `(False, CANT_SHOOT_ERROR.WAITING)`
	// while `__currShellCD` is None, and `__currShellCD` is only ever set from
	// `Avatar.__updateVehicleSetting` on `VEHICLE_SETTING.CURRENT_SHELLS` —
	// which first requires `ammoCtrl.shellInAmmo(value)`, i.e. the shell must
	// already be in `vehicleAmmoList`. With both left at their zero values
	// (empty arrays) the client refuses every shot before it ever reaches
	// `cell.vehicle_shoot`, so nothing is sent and nothing fires.
	//
	// `vehicleGunReloadTime` is the loaded state: `timeLeft` 0 means ready,
	// and `baseTime` is the gun's own `reloadTime`, which the client uses as
	// the reload's length once a shot starts it.
	if loaded := loadedShellFor(disp, savedShells); loaded != 0 {
		// One entry per shell in the SAVED layout, in its order: the client
		// shows exactly this list, so sending only the gun's default shell
		// makes a 16/10/10 loadout read as 30 of the default.
		type ammoEntry struct {
			cd    int64
			count uint64
		}
		var entries []ammoEntry
		for i := 0; i+1 < len(savedShells); i += 2 {
			if savedShells[i] == 0 || savedShells[i+1] <= 0 {
				continue
			}
			entries = append(entries, ammoEntry{savedShells[i], uint64(savedShells[i+1])})
		}
		if len(entries) == 0 {
			entries = []ammoEntry{{int64(loaded), 30}}
		}
		if t := entdef.Alias("VEHICLE_AMMO_LIST"); t != nil {
			seq := make([]entdef.Value, 0, len(entries))
			for i, e := range entries {
				seq = append(seq, entdef.Value{
					Kind: entdef.VDict,
					Dict: []entdef.DictField{
						{Name: "compactDescr", Value: entdef.Value{Kind: entdef.VInt, Int: e.cd}},
						{Name: "quantity", Value: entdef.Value{Kind: entdef.VUint, Uint: e.count}},
						{Name: "quantityInClip", Value: entdef.Value{Kind: entdef.VUint, Uint: 1}},
						{Name: "previousStage", Value: entdef.Value{Kind: entdef.VUint}},
						{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat}},
						{Name: "totalTime", Value: entdef.Value{Kind: entdef.VInt}},
						{Name: "index", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(i)}},
					},
				})
			}
			overrides["vehicleAmmoList"] = entdef.Value{Kind: entdef.VSeq, Seq: seq}
		}
		if t := entdef.Alias("VEHICLE_SETTINGS"); t != nil {
			// `CURRENT_SHELLS` (0) is the loaded shell and `NEXT_SHELLS` (1)
			// the one the gun loads once its magazine is empty. BOTH are the
			// loaded shell at entry, and that is not cosmetic: the reference
			// constructs its gun with `next_shell: loaded` and only
			// `select_next` moves it when the player picks a shell ONCE
			// (`change_loaded` is the twice-picked one). Sending the first
			// OTHER shell here pre-highlights it in the ammo panel — the
			// player enters the battle with the next-shell marker already one
			// press in, and the two presses that should reach the third shell
			// only reach the second.
			overrides["vehicleSettings"] = vehicleSettingsValue(vehicleID, loaded, loaded)
		}
	}
	if t := entdef.Alias("VEHICLE_GUN_RELOAD_TIME"); t != nil {
		overrides["vehicleGunReloadTime"] = entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
			{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat}},
			{Name: "baseTime", Value: entdef.Value{Kind: entdef.VFloat, Float: disp.ReloadTime}},
			{Name: "timeLeft", Value: entdef.Value{Kind: entdef.VFloat}},
			{Name: "clipTime", Value: entdef.Value{Kind: entdef.VFloat}},
		}}
	}
	// The view range and the gun's two multipliers: zero would mean the tank
	// sees nothing and its shells do nothing.
	if saType := entdef.Alias("VEHICLE_SYNC_ATTRS"); saType != nil {
		sa := entdef.ZeroValue(saType)
		sa = dictSet(sa, "circularVisionRadius", entdef.Value{Kind: entdef.VUint, Uint: 445})
		// The shell's own penetration and muzzle velocity, from the gun's
		// default shell. A 1.0 here is a shell that penetrates nothing and
		// flies at 1 m/s.
		sa = dictSet(sa, "gunPiercing", entdef.Value{Kind: entdef.VFloat, Float: disp.Piercing})
		sa = dictSet(sa, "gunShotsSpeed", entdef.Value{Kind: entdef.VFloat, Float: disp.ShotSpeed})
		overrides["syncVehicleAttrs"] = sa
	}
	// Every remaining `AllowNone` property is None, not its zero dict.
	//
	// `OwnVehicleBase.__set` runs an `update_*` handler only for a NON-None
	// value (`if prop is not None or getattr(func, '__isNoneAccepted', False)`),
	// so None is how the official server keeps a handler from running at all.
	// The zero dict is not None and does run it, and two of them throw on
	// every entry:
	//
	//   - `update_dualGunState` indexes `gunStates[activeGun]` and raises
	//     `IndexError: Array index out of range` on a tank without a dual gun
	//     (the zero `gunStates` is an empty array);
	//   - `update_welcomeToSector` calls
	//     `ClientArenaComponentSystem.sectorComponent`, which only exists in
	//     Frontline, and raises `AttributeError` in every random battle.
	//
	// Both were in the client's `game.log` on every battle entry. The rest of
	// the None ones are the handlers the official server also leaves unset
	// (siege state, burnout, target, battle events summary, ...).
	for _, p := range ownVehicleProps {
		if _, ok := overrides[p.Name]; ok {
			continue
		}
		if dt := entdef.Alias(p.Type); dt != nil && entdef.AllowsNone(dt) {
			overrides[p.Name] = entdef.Value{Kind: entdef.VNone}
		}
	}
	return overrides
}

// ownVehicleClientMethods is how many client methods `OwnVehicle.def` declares,
// which is how many method children its NRL node carries after the properties.
//
// Read from the game's own def rather than counted by hand: the child list has
// to line up with the component's tables exactly, and a def change would
// silently shift it. The fallback is the 2.4.1 count.
var ownVehicleClientMethods = func() int {
	const fallback = 11
	pkg := FindScriptsPkg()
	if pkg == "" {
		return fallback
	}
	raw, err := readFromZip(pkg, "scripts/component_defs/OwnVehicle.def")
	if err != nil {
		return fallback
	}
	f, err := entdef.ParseFile(raw)
	if err != nil || f.Root == nil {
		return fallback
	}
	sec := f.Root.Child("ClientMethods")
	if sec == nil {
		return 0
	}
	seen := make(map[string]bool, len(sec.Children))
	n := 0
	for _, m := range sec.Children {
		if seen[m.Name] {
			continue
		}
		seen[m.Name] = true
		n++
	}
	return n
}()

// ownVehicleProps is `OwnVehicle.def`'s property table, in the order the client
// reads it: sorted by element length, fixed sizes first and ascending, then the
// variable ones in declaration order. That is BigWorld's
// `allocateClientServerFullIndexes`, and it is NOT the def's declaration order —
// `syncVehicleAttrs` is the only fixed-size property here (10 B), so it comes
// first and everything else follows as declared. Getting this wrong shifts
// every value by the size difference and the client dies on
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
//
// The client only turns its turret once it knows how fast it can, and it reads
// the ammunition, the loaded shells, the reload and the health from here.
var ownVehicleProps = []nrlProp{
	{"syncVehicleAttrs", "VEHICLE_SYNC_ATTRS"},
	{"vehicleAmmoList", "VEHICLE_AMMO_LIST"},
	{"vehicleGunReloadTime", "VEHICLE_GUN_RELOAD_TIME"},
	{"vehicleClipReloadTime", "VEHICLE_CLIP_RELOAD_TIME"},
	{"vehicleSettings", "VEHICLE_SETTINGS"},
	{"destroyedDevicesIsRepairing", "DESTROYED_DEVICES_IS_REPAIRING"},
	{"vehicleDamageInfoList", "VEHICLE_DAMAGE_INFO_LIST"},
	{"vehicleOptionalDeviceStatusList", "VEHICLE_OPTIONAL_DEVICE_STATUS_LIST"},
	{"dualGunStatus", "DUAL_GUN_STATUS"},
	{"dualGunState", "DUAL_GUN_STATE"},
	{"siegeStateStatus", "SIEGE_STATE_STATUS"},
	{"burnoutWarning", "BURNOUT_WARNING"},
	{"burnoutUnavailable", "BURNOUT_UNAVAILABLE"},
	{"drownLevel", "DROWN_LEVEL"},
	{"isOtherVehicleDamagedDevicesVisible", "IS_OTHER_VEHICLE_DAMAGED_DEVICES_VISIBLE"},
	{"overturnLevel", "OVERTURN_LEVEL"},
	{"smokeInfo", "SMOKE_INFO"},
	{"targetVehicleID", "TARGET_VEHICLE_ID"},
	{"targetingInfo", "TARGETING_INFO"},
	{"vehicleHealthInfo", "VEHICLE_HEALTH_INFO"},
	{"welcomeToSector", "WELCOME_TO_SECTOR"},
	{"battleEventsSummary", "BATTLE_EVENTS_SUMMARY"},
	{"fixAngles", "GUN_ROTATOR_FIX_ANGLES"},
}

// arenaGameTime is the game time `UPDATE_FREQUENCY_NOTIFICATION` carries, which
// is what the client's `BigWorld.serverTime()` is built from.
//
// It is the RAW 10 Hz tick counter, not seconds. The capture pins the two
// units against each other: at 14:17:25.943 the captured server's element
// carries game time 1126351 while its period tuples are in seconds
// (`(2, 112646.6, 3, [10.0, 10.0])`), and the tick at that instant is ~1126346.
// So `serverTime()` is `gameTime / 10 + elapsed` — seconds, the same base
// `periodEndTime` uses, which is why `arenaPeriodEnd` divides by ten and this
// does not.
//
// Sending seconds here instead makes `serverTime()` ten times too small, and
// `Avatar.__onArenaPeriodChange`'s
// `battleTime = serverTime - (periodEndTime - periodLength)` then carries a
// constant -128 s offset: the battle timer opens at 2:08 instead of 0:00 and
// the prebattle countdown is wrong by the same amount.
func arenaGameTime(tick uint32) uint32 { return tick }

// arenaPeriodEnd is a period's end time, in the seconds `serverTime()` is in.
func arenaPeriodEnd(tick, length uint32) float64 {
	return float64(tick)/10 + float64(length)
}

// ArenaUpdatePeriod is `ARENA_UPDATE.PERIOD` (common/constants.pyc). It is the
// code `Avatar.updateArena` dispatches on, and the one that reaches
// `ClientArena.__onPeriodInfoUpdate`.
const ArenaUpdatePeriod uint8 = 3

// SpawnHeight is how far above the map origin the player is placed. The origin
// is below the terrain on every map, so this is what keeps the tank on the
// surface rather than under it — but it is a constant, not a terrain query:
// the map's heightmap lives in `spaces/<map>/patches/*/heightmap.bin` inside
// the map package, and reading it is what would put the tank exactly on the
// ground at its team's base instead of at a fixed height over the origin.
// The team spawn points, from the game's own `scripts/arena_defs/<map>.xml`:
// `gameplayTypes/ctf/teamSpawnPoints/teamN/position`, a base64 pair of floats
// on the ground plane. Karelia's are (316.2, 266.0) and (-283.8, -372.7); its
// bases are (397.5, 402.6) and (-401.3, -400.0), and its playable area is
// (-500,-500)..(500,500).
//
// These are NOT in the map package — `res/packages/<map>.pkg` has no
// `arena_defs` — they are in the scripts package, which is why the map package
// alone could never place a tank.
const (
	SpawnX float32 = 316.2
	SpawnZ float32 = 266.0
	// EnemyX, EnemyZ are the other team's BASE, not its spawn point: the
	// dummy sits on the flag it is defending, which is where the enemy column
	// of the loading screen and the minimap expect it. Karelia's team 2 base
	// is (-401.3, -400.0); its spawn point is (-283.8, -372.7).
	EnemyX float32 = -401.3
	EnemyZ float32 = -400.0
)

// SpawnHeight is the height the tank is placed at. The real answer is the
// terrain height at the spawn point, read from the map package's
// `spaces/<map>/patches/*/heightmap.bin`; until that is decoded this is a
// constant that keeps the tank above the surface rather than under it.
const SpawnHeight float32 = 60

// ownVehicleAuxPhysicsLevel is `WoT.packAuxVehiclePhysicsData(0, 0, 0, 0, 0, 0)`,
// the packed level attitude: yaw 0, pitch 0, roll 0, both track scrolls 0.
//
// `Avatar.ownVehicleAuxPhysicsData` is an OWN_CLIENT UINT64, and zero is not
// the neutral value — it unpacks to (-pi, -pi/2, -pi), which tilts the
// stabilised vehicle matrix 90 degrees about X and leaves the gun aiming in a
// rotated frame.
const ownVehicleAuxPhysicsLevel uint64 = 0x55558004004000

// ArenaPeriodPrebattle and ArenaPeriodBattle are `ARENA_PERIOD.PREBATTLE` and
// `ARENA_PERIOD.BATTLE` from the client's own `common/constants.pyc`:
//
//	IDLE = 0, WAITING = 1, PREBATTLE = 2, BATTLE = 3, AFTERBATTLE = 4
//
// The numbers matter. `Avatar.setClientReady` sets `isOnArena` only when the
// period is BATTLE, and `__onArenaPeriodChange` sets it to `period == BATTLE`,
// so announcing 2 leaves the client in PREBATTLE — loaded, in the battle, and
// with the gun frozen because `VehicleGunRotator.start()` refuses to run.
const (
	ArenaPeriodWaiting   uint8 = 1
	ArenaPeriodPrebattle uint8 = 2
	ArenaPeriodBattle    uint8 = 3
)

// arenaPeriodDelays are the waits the period sequence uses: the WAITING length
// the loading screen counts down with, and the PREBATTLE length before BATTLE.
// Both come from the capture (8.4 s and 3.0 s).
//
// They are LENGTHS now, not send timers: the transition to PREBATTLE is
// triggered by the client's own `Avatar.setClientReady`, which is the only
// signal that its `onPeriodChange` handler is registered.
var arenaPeriodDelays = []time.Duration{
	8400 * time.Millisecond, // WAITING, the capture's 8.4 s
	3000 * time.Millisecond, // PREBATTLE, the capture's 3.0 s
}

// arenaReadyTimeout is how long the entry waits for `Avatar.setClientReady`
// before starting the battle anyway. The client's load took 4.4 s in the
// measured run; the fallback exists for a rejoin path that skips the call, and
// it must stay well under the 30 s the old timer-based entry parked for.
const arenaReadyTimeout = 12 * time.Second

// vehicleInfoValue builds one `VEHICLES_INFO` entry.
//
// The dict's field order is the def's, and `entdef.ZeroValue` fills the ones
// this server does not model — including the three PYTHON fields, which must
// carry a valid pickle rather than an empty blob.
func vehicleInfoValue(typ entdef.DataType, doc ArenaPlayerDoc, id uint32, index int, x, z float32) entdef.Value {
	v := entdef.ZeroValue(typ)
	set := func(field string, val entdef.Value) { v = dictSet(v, field, val) }
	set("vehicleID", entdef.Value{Kind: entdef.VInt, Int: int64(id)})
	set("isAlive", entdef.Value{Kind: entdef.VUint, Uint: 1})
	// The team panel greys a player out until this is set: it is the
	// "loaded / connected" flag the listing reads.
	set("isAvatarReady", entdef.Value{Kind: entdef.VUint, Uint: 1})
	set("compDescr", entdef.Value{Kind: entdef.VString, Str: string(doc.VehicleCompDescr)})
	set("fakeName", entdef.Value{Kind: entdef.VString, Str: doc.Name})
	set("name", entdef.Value{Kind: entdef.VString, Str: doc.Name})
	set("team", entdef.Value{Kind: entdef.VInt, Int: int64(doc.Team)})
	set("accountDBID", entdef.Value{Kind: entdef.VUint, Uint: uint64(doc.AccountID)})
	set("clanAbbrev", entdef.Value{Kind: entdef.VString, Str: doc.ClanAbbrev})
	set("clanDBID", entdef.Value{Kind: entdef.VInt, Int: doc.ClanDBID})
	// A string, not a number: the client's DAAPI casts it into
	// `DAAPIVehicleInfoPO.sessionID` and refuses a numeric value.
	set("avatarSessionID", entdef.Value{Kind: entdef.VString, Str: fmt.Sprintf("%d", id)})
	maxHealth := doc.MaxHealth
	if maxHealth <= 0 {
		maxHealth = 1000
	}
	set("maxHealth", entdef.Value{Kind: entdef.VInt, Int: int64(maxHealth)})
	// Its slot in the team, 1-based: the scoreboard sorts on it.
	set("index", entdef.Value{Kind: entdef.VUint, Uint: uint64(index)})
	// `badges` is a PYTHON field, and the zero value for those is an empty
	// DICT — but the scoreboard does `vehicleInfo['badges'][0]`, which on a
	// dict is a KeyError and takes the whole tab view down. It wants a tuple
	// of two lists: the prefix badges and the suffix ones.
	set("badges", entdef.Value{Kind: entdef.VString, Str: "\x80\x02(]]t."})
	// `ranked` is a TUPLE with no declared size, so the zero value is empty;
	// the client reads two entries out of it.
	set("ranked", entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VUint}, {Kind: entdef.VUint},
	}})
	// Where the tank is, on the ground plane, as the packed pair the client's
	// minimap and team panel read.
	set("position", entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VInt, Int: int64(int16(x))},
		{Kind: entdef.VInt, Int: int64(int16(z))},
	}})
	return v
}

// arenaInfoApp builds the arena's info entity and the NRL element that attaches
// its vehicle list.
//
// This is the only thing that fills `ClientArena.vehicles`: the component's
// `__init__` is the sole caller of `arena.updateVehiclesList`, and it only
// takes the component when `self.avatar.id == self.entity.avatarID`. Without
// it the battle-loading screen has no tanks in either team and never finishes.
//
// The component is NOT on the Avatar. It is a dynamic component on a separate
// `AvatarInfo` entity, and it replicates over NRL rather than in the entity
// stream — `CreateBasePlayer` carries only the component COUNT.
func (s *BaseAppServer) arenaInfoApp(st *clientState, h *ArenaHandoff, alloc *nrlNodeAlloc, vehicles []entdef.Value) (*Entity, []byte, error) {
	typ := s.cfg.Dispatch.Entity("AvatarInfo")
	if typ == nil {
		return nil, nil, fmt.Errorf("wotserver: no AvatarInfo entity in the defs")
	}
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		return nil, nil, fmt.Errorf("wotserver: no VEHICLES_INFO type in alias.xml")
	}
	id := h.InfoID
	if id == 0 {
		id = h.VehicleID + 2
	}
	e := NewEntity(id, typ)
	for _, p := range typ.Properties {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	// OBJECT_ID is a signed 32-bit id in the defs' type system.
	e.SetInt("avatarID", int64(st.entityID))

	var data bytes.Buffer
	if err := entdef.EncodeArray(&data, infoType, vehicles); err != nil {
		return nil, nil, fmt.Errorf("wotserver: vehiclesInfo: %w", err)
	}
	// The component's children: one per property (it declares exactly one,
	// `vehiclesInfo`), then one per client method (none), then the trailing
	// child every component has. All of them are present.
	entityNode := alloc.take(1)
	compNode := alloc.take(1)
	children := []uint32{uint32(alloc.take(1)), uint32(alloc.take(1))}
	present := []bool{true, true}
	msg := EncodeNrlCreateEntityNode(entityNode, id)
	msg = append(msg, EncodeNrlCreateComponent(compNode, entityNode,
		AvatarVehiclesInfoNrlID, "", children, present, data.Bytes())...)
	app, err := element(elNrlCreateNode, msg)
	if err != nil {
		return nil, nil, err
	}
	comp := nrlComponent{
		TypeID:     AvatarVehiclesInfoNrlID,
		Node:       uint16(compNode),
		FirstChild: uint16(children[0]),
		Props:      1,
	}
	s.mu.Lock()
	st.infoComp = comp
	st.infoVehicles = vehicles
	s.mu.Unlock()
	return e, app, nil
}

// arenaPeriodUpdate builds the `updateArena(PERIOD, ...)` call that starts the
// battle.
//
// `ClientArena.__onPeriodInfoUpdate` unpickles a zlib-compressed
// `(period, periodEndTime, periodLength, periodAdditionalInfo)` tuple and
// fires `onPeriodChange`, which is what `Avatar.__onArenaPeriodChange` listens
// to. `Avatar.setClientReady` only sets `isOnArena` when the period is BATTLE,
// so without this the client finishes loading and stays out of the arena.
func arenaPeriodUpdate(e *Entity, period uint8) ([]byte, error) {
	return arenaPeriodUpdateFull(e, period, 0, 0, nil)
}

// arenaPeriodUpdateFull builds the period update with the whole tuple the
// client unpickles: `(period, periodEndTime, periodLength, periodAdditionalInfo)`.
//
// The captured server sends real values in all four, and the fourth is a
// sequence, never None: `MapActivities.__setStartTimes` does
// `len(periodAdditionalInfo)` and throws `TypeError: object of type 'NoneType'
// has no len()` on a None, which aborts the rest of the period handler. Its
// three updates over one battle were
//
//	(1, 112695.1, 60.0, (1, 11))        WAITING
//	(2, 112646.6, 3,    [10.0, 10.0])   PREBATTLE
//	(3, 114146.6, 1500, [10.0, 10.0])   BATTLE
func arenaPeriodUpdateFull(e *Entity, period uint8, endTime float64, length uint32, additional []float64) ([]byte, error) {
	// pickle protocol 2: proto, MARK, BININT1 period, the end time as a
	// BINFLOAT, the length as a BININT, the additional info as a list of
	// BINFLOATs, TUPLE, STOP. The MARK is not optional — TUPLE pops to it, and
	// without it the client's unpickle fails and the period never moves.
	raw := []byte{0x80, 0x02, '(', 'K', period}
	raw = append(raw, 'G')
	var f [8]byte
	binary.BigEndian.PutUint64(f[:], math.Float64bits(endTime))
	raw = append(raw, f[:]...)
	// BININT2 for a length that fits 16 bits, BININT otherwise — the capture
	// uses BININT2 for 1500 and BININT for 60.
	if length < 0x10000 {
		var u [2]byte
		binary.LittleEndian.PutUint16(u[:], uint16(length))
		raw = append(raw, 'M')
		raw = append(raw, u[:]...)
	} else {
		var u [4]byte
		binary.LittleEndian.PutUint32(u[:], length)
		raw = append(raw, 'J')
		raw = append(raw, u[:]...)
	}
	// The list is EMPTY_LIST, BINPUT, MARK, the items, APPENDS — the capture's
	// own order (`] q\x01 ( G… G… e`). The list has to exist before its MARK:
	// APPENDS pops to the MARK and appends to the item below it, so a MARK
	// first would append to whatever was pushed before, which is the length.
	raw = append(raw, ']', 'q', 0x01, '(')
	for _, v := range additional {
		raw = append(raw, 'G')
		binary.BigEndian.PutUint64(f[:], math.Float64bits(v))
		raw = append(raw, f[:]...)
	}
	raw = append(raw, 'e')
	raw = append(raw, 't', '.')
	var packed bytes.Buffer
	zw := zlib.NewWriter(&packed)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return EncodeClientMethodCall(e, "updateArena", []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(ArenaUpdatePeriod)},
		{Kind: entdef.VString, Str: packed.String()},
	})
}

// publicInfoOnlyRun encodes a property run holding `publicInfo`, for the
// WOT_ARENA_PROBE=3/4 bisect. With withFixed it also carries every fixed-size
// outer property declared before it, which separates "a fixed property is
// mis-sized" from "one of the two variable ones ahead of it desyncs".
func publicInfoOnlyRun(e *Entity, withFixed bool) ([]byte, error) {
	target := -1
	for i := range e.Type.Properties {
		if e.Type.Properties[i].Name == "publicInfo" {
			target = i
			break
		}
	}
	if target < 0 {
		return nil, fmt.Errorf("wotserver: %s has no publicInfo property", e.Type.Name)
	}
	var ids []int
	if withFixed {
		for i := 0; i < target; i++ {
			p := &e.Type.Properties[i]
			if p.DetailLevel == "" && p.Length.Fixed {
				ids = append(ids, i)
			}
		}
	}
	ids = append(ids, target)
	c := entdef.NewCodec()
	var body bytes.Buffer
	body.WriteByte(byte(len(ids)))
	for _, i := range ids {
		p := &e.Type.Properties[i]
		v, ok := e.Props[p.Name]
		if !ok {
			return nil, fmt.Errorf("wotserver: %s has no %s value", e.Type.Name, p.Name)
		}
		body.WriteByte(byte(i))
		if err := c.Write(&body, p.Type, v); err != nil {
			return nil, err
		}
	}
	return body.Bytes(), nil
}

// markClientReady releases the arena entry's period sequence.
//
// `Avatar.setClientReady` is a base method the client calls once its init steps
// are done; the entry's goroutine waits on the channel this closes before it
// announces PREBATTLE and then BATTLE. Guarded by the server mutex, and
// re-armed per battle by `enterArena`, so a second call in the same battle is
// a no-op rather than a double close.
func (s *BaseAppServer) markClientReady(st *clientState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.readyCh == nil || st.readyDone {
		return
	}
	st.readyDone = true
	close(st.readyCh)
	s.logf("stage2 %s: client ready — starting the battle period", st.stage2Addr)
}

// answerLeaveArena takes a client out of its battle and back to the lobby.
//
// "Back to hangar" ends in `Avatar.leaveArena` → `self.base.leaveArena()`, a
// base method on the Avatar. Nothing answered it, so the client sat in the
// battle forever. The way out is the way in, in reverse: reset the entities,
// drop the arena, and let the `enableEntities` the reset provokes take the
// lobby path.
func (s *BaseAppServer) answerLeaveArena(conn Transport, from *net.UDPAddr, st *clientState) error {
	s.mu.Lock()
	arena := st.arena
	if arena == nil {
		s.mu.Unlock()
		return nil // not in a battle: nothing to leave
	}
	// Stop the ticker BEFORE dropping the resend queue. A tick that lands
	// between the forget and the arena clear is tracked again and then
	// resent for the whole give-up window; the client, now back in its login
	// state, drops those resends as "unexpected packet on external
	// interface" and disconnects.
	st.arena = nil
	st.entered = false
	st.resetSent = true
	st.vehicle = nil
	st.avatar = nil
	s.mu.Unlock()
	// Everything queued refers to entities the client is about to drop.
	s.resend.forget(st.resendKey)
	resetApp := answerApp([]byte{elResetEntities, 0})
	s.logf("stage2 %s: leaveArena reset app % x", from, resetApp)
	// RELIABLE, like the arena-entry reset. An unreliable one is dropped by
	// the client's packet receiver as out-of-order (`Dropping out-of-order
	// unreliable packet seq=…`) because it shares the unreliable counter with
	// the arena ticks, and then the client never processes the reset: it
	// never sends `enableEntities`, our Account re-entry never happens, the
	// lobby sync calls are dropped as "no entity between reset and
	// re-entry", the 10 Hz ticks pile up unacked and the client's channel
	// overflows ("Disconnecting since channel … has overflowed").
	if err := s.mintPost(conn, from, st, resetApp); err != nil {
		return err
	}
	// Drop the slot as well as the session's view of it. The reset makes the
	// client send `enableEntities`, and the rejoin hook answers that — so
	// without this the client is dragged straight back into the battle it just
	// left, mid-teardown, and asserts `pEntity`.
	if s.cfg.Arenas != nil && s.cfg.Arenas.Leave != nil {
		s.cfg.Arenas.Leave(st.accountID)
	}
	s.logf("stage2 %s: left arena %d — reset sent, back to the lobby", from, arena.ArenaID)
	return nil
}

// arenaVehicleIDs is every vehicle entity id in the battle: the player's own,
// then the dummy's when there is one.
func arenaVehicleIDs(h *ArenaHandoff) []uint32 {
	ids := []uint32{h.VehicleID}
	if h.Dummy != nil {
		ids = append(ids, h.VehicleID+1)
	}
	return ids
}
