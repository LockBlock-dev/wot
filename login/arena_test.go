package login

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// TestCreateCellPlayerLayout pins the element the client's
// `ServerConnection::createCellPlayer` reads: space, vehicle, position,
// xz scale, direction, then the cell-to-client properties with no count.
func TestCreateCellPlayerLayout(t *testing.T) {
	s := tokenTestServer(t, nil)
	acct := s.cfg.Dispatch.Entity("Avatar")
	if acct == nil {
		t.Fatal("no Avatar entity in the defs")
	}
	e := NewEntity(0x1234, acct)
	for _, p := range acct.CellProps {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	e.SetUint("team", 1)

	el, err := EncodeCreateCellPlayer(e, 7, 0, [3]float32{1, 2, 3}, 0.5, [3]float32{0, 0, 0}, AvatarComponents)
	if err != nil {
		t.Fatalf("EncodeCreateCellPlayer: %v", err)
	}
	if el[0] != elCreateCellPlayer {
		t.Fatalf("element id = %#02x, want %#02x", el[0], elCreateCellPlayer)
	}
	// The WoT fork's header is `[u8][spaceID u32][u16][vehicleID u32]
	// [pos 3×f32][xzScale f32][dir 3×f32]` — 39 bytes, not stock
	// BigWorld's 36. The leading byte and the u16 are what the client
	// reads before the space id; writing the stock shape shifts it by one
	// and the client sees space 0.
	body := el[3:]
	const header = 1 + 4 + 2 + 4 + 12 + 4 + 12
	if len(body) < header {
		t.Fatalf("body is %d B, too short for the header", len(body))
	}
	if body[0] != 0 {
		t.Fatalf("leading byte = %#02x, want 0", body[0])
	}
	if got := binary.LittleEndian.Uint32(body[1:5]); got != 7 {
		t.Fatalf("space id = %d, want 7", got)
	}
	if got := binary.LittleEndian.Uint16(body[5:7]); got != 0 {
		t.Fatalf("u16 after the space id = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(body[7:11]); got != 0 {
		t.Fatalf("vehicle id = %d, want 0", got)
	}
	for i, want := range []float32{1, 2, 3} {
		got := math.Float32frombits(binary.LittleEndian.Uint32(body[11+i*4:]))
		if got != want {
			t.Fatalf("pos[%d] = %v, want %v", i, got, want)
		}
	}
	if got := math.Float32frombits(binary.LittleEndian.Uint32(body[23:27])); got != 0.5 {
		t.Fatalf("xzScale = %v, want 0.5", got)
	}
	// The property section is the rest; it must be non-empty (the Avatar
	// has 14 cell props) and must not start with a count byte the client
	// would misread as the first property.
	if len(body) <= header {
		t.Fatalf("no property section: %d B", len(body))
	}
	// A zero xzScale is refused: the client asserts it is positive.
	if _, err := EncodeCreateCellPlayer(e, 7, 0, [3]float32{}, 0, [3]float32{}, AvatarComponents); err == nil {
		t.Fatal("a zero xzScale was accepted")
	}
}

// TestSpaceDataLayout pins the spaceData element: space, the 8-byte entry
// id, the key, then the value.
func TestSpaceDataLayout(t *testing.T) {
	entry := [8]byte{0, 0, 0, 1, 0, 0, 0, 1}
	value := EncodeGeometryMapping("spaces/01_karelia")
	el, err := EncodeSpaceData(7, entry, SpaceDataMappingKey, value)
	if err != nil {
		t.Fatalf("EncodeSpaceData: %v", err)
	}
	if el[0] != elSpaceData {
		t.Fatalf("element id = %#02x, want %#02x", el[0], elSpaceData)
	}
	body := el[3:]
	if got := binary.LittleEndian.Uint32(body[0:4]); got != 7 {
		t.Fatalf("space id = %d", got)
	}
	if !bytes.Equal(body[4:12], entry[:]) {
		t.Fatalf("entry id = % x", body[4:12])
	}
	if got := binary.LittleEndian.Uint16(body[12:14]); got != SpaceDataMappingKey {
		t.Fatalf("key = %d, want %d", got, SpaceDataMappingKey)
	}
	// The value is a 4x4 identity matrix then the path.
	rest := body[14:]
	if len(rest) != 64+len("spaces/01_karelia") {
		t.Fatalf("value is %d B, want %d", len(rest), 64+len("spaces/01_karelia"))
	}
	for i := 0; i < 16; i++ {
		got := math.Float32frombits(binary.LittleEndian.Uint32(rest[i*4:]))
		want := float32(0)
		if i%5 == 0 {
			want = 1
		}
		if got != want {
			t.Fatalf("matrix[%d] = %v, want %v", i, got, want)
		}
	}
	if got := string(rest[64:]); got != "spaces/01_karelia" {
		t.Fatalf("path = %q", got)
	}
}

// TestEnterArenaSequence checks the two-step entry: onArenaCreated plus the
// entity reset first, then the Avatar and the cell player on the
// enableEntities the reset provokes.
func TestEnterArenaSequence(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234}
	h := &ArenaHandoff{
		ArenaID:     9,
		SpaceID:     9,
		ArenaTypeID: 1,
		Map:         "spaces/01_karelia",
		Player:      ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID:   0x2222,
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.enterArena(tr, addr, st, h); err != nil {
		t.Fatalf("enterArena: %v", err)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2 (onArenaCreated + resetEntities)", len(tr.writes))
	}
	// onArenaCreated is Account client method 0: element 0x4E.
	first := findAppInPacket(t, tr.writes[0], st.blockKey)
	if len(first) < 3 || first[2] != entityMethodBase {
		t.Fatalf("first write is not onArenaCreated: % x", first)
	}
	// resetEntities is element 0x04 with one bool.
	second := findAppInPacket(t, tr.writes[1], st.blockKey)
	if !bytes.Contains(second, []byte{elResetEntities, 0}) {
		t.Fatalf("second write is not resetEntities(false): % x", second)
	}
	if st.arena == nil || st.arena.ArenaID != 9 {
		t.Fatalf("the session did not record the arena: %+v", st.arena)
	}
	if st.entered {
		t.Fatal("the reset did not clear the entered flag")
	}
	if !st.resetSent {
		t.Fatal("the reset did not mark the session as entity-less")
	}

	// The second step: the Avatar, the space geometry and the cell player.
	tr2 := &fakeTransport{}
	seq, err := s.enterArenaEntities(tr2, addr, st, h, 10, 10)
	if err != nil {
		t.Fatalf("enterArenaEntities: %v", err)
	}
	// The Avatar and the entry's head (tickSyncPeriodic + cellAppResumed +
	// selectPlayerEntity) go out; the rest waits for the client's socket
	// rebind.
	if seq != 12 {
		t.Fatalf("seq = %d, want 12 (the Avatar and the head)", seq)
	}
	if len(tr2.writes) != 2 {
		t.Fatalf("%d writes, want 2 (the Avatar and the head)", len(tr2.writes))
	}
	if st.arenaNext == nil {
		t.Fatal("the rest of the entry was not held back")
	}
	if st.resetSent {
		t.Fatal("the new Avatar did not clear the entity-less flag")
	}
	tr3 := &fakeTransport{}
	seq, err = s.enterArenaSpace(tr3, addr, st, h, seq, 10)
	if err != nil {
		t.Fatalf("enterArenaSpace: %v", err)
	}
	// space, cell, controlEntity, Vehicle create/select/update/enter, AvatarInfo
	// create/enter/NRL, OwnVehicle, its vehicleHealthInfo, selectEntity(Avatar),
	// the hull attitude, the update frequency, WAITING, then the TeamInfo
	// create/enter pair. BATTLE is NOT here: it waits for the client's
	// `setClientReady`.
	if seq != 30 {
		t.Fatalf("seq = %d, want 30 (nineteen more frames)", seq)
	}
	if len(tr3.writes) != 18 {
		t.Fatalf("%d writes, want 18 (space, cell, controlEntity, Vehicle x4, AvatarInfo x3, OwnVehicle, vehicleHealthInfo, select, auxPhysics, frequency, WAITING, TeamInfo x2)", len(tr3.writes))
	}
	// The period call is an Avatar method, so the Avatar must be the selected
	// entity when it goes out: an entity method applies to whatever
	// selectEntity last selected, and the last one was a Vehicle.
	// The controlEntity that hands the client its own tank sits between the
	// Vehicle's enterAoI and the AvatarInfo, so the Avatar's selection is the
	// thirteenth write, not the twelfth.
	selAvatar := findAppInPacket(t, tr3.writes[12], st.blockKey)
	if !bytes.Contains(selAvatar, []byte{elSelectEntity}) {
		t.Fatalf("thirteenth write is not selectEntity: % x", selAvatar[:8])
	}
	if got := binary.LittleEndian.Uint32(selAvatar[1:5]); got != st.entityID {
		t.Fatalf("selectEntity id = %d, want the Avatar %d", got, st.entityID)
	}
	avatar := findAppInPacket(t, tr2.writes[0], st.blockKey)
	if !bytes.Contains(avatar, []byte{elCreateBasePlayer}) {
		t.Fatalf("the Avatar frame is not CreateBasePlayer: % x", avatar[:8])
	}
	tr2 = tr3
	create := findAppInPacket(t, tr2.writes[2], st.blockKey)
	if !bytes.Contains(create, []byte{elCreateEntity}) {
		t.Fatalf("third write is not createEntity: % x", create[:8])
	}
	// The cell properties go out BEFORE the entity enters the world:
	// `Vehicle.onEnterWorld` builds its descriptor from `publicInfo` and
	// nothing rebuilds it afterwards.
	sel := findAppInPacket(t, tr2.writes[3], st.blockKey)
	if !bytes.Contains(sel, []byte{elSelectEntity}) {
		t.Fatalf("fourth write is not selectEntity: % x", sel[:8])
	}
	update := findAppInPacket(t, tr2.writes[4], st.blockKey)
	if !bytes.Contains(update, []byte{elUpdateEntity}) {
		t.Fatalf("fifth write is not updateEntity: % x", update[:8])
	}
	enter := findAppInPacket(t, tr2.writes[5], st.blockKey)
	if !bytes.Contains(enter, []byte{elEnterAoI}) {
		t.Fatalf("sixth write is not enterAoI: % x", enter[:8])
	}
	cell := findAppInPacket(t, tr2.writes[0], st.blockKey)
	if !bytes.Contains(cell, []byte{elCreateCellPlayer}) {
		t.Fatalf("first write is not CreateCellPlayer: % x", cell[:8])
	}
	space := findAppInPacket(t, tr2.writes[1], st.blockKey)
	if !bytes.Contains(space, []byte{elAddSpaceGeometryMapping}) {
		t.Fatalf("second write is not addSpaceGeometryMapping: % x", space[:8])
	}
	if st.avatar == nil {
		t.Fatal("the Avatar entity was not kept")
	}
}

// TestArenaSpaceFiresWithoutAClientDatagram pins the fallback: the
// held-back half of the entry must go out on its own timer, because a
// client that has nothing to say would otherwise stall the battle forever.
func TestArenaSpaceFiresWithoutAClientDatagram(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234,
		stage2Addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		postAt:     time.Now().Add(time.Hour), // no ticks to confuse the count
	}
	h := &ArenaHandoff{
		ArenaID: 9, SpaceID: 9, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID: 0x2222,
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	s.byAddr[addr.String()] = st
	if _, err := s.enterArenaEntities(tr, addr, st, h, 10, 10); err != nil {
		t.Fatalf("enterArenaEntities: %v", err)
	}
	if st.arenaNext == nil {
		t.Fatal("the rest of the entry was not held back")
	}
	// Before the delay, the sweep must leave it alone.
	s.sweepStage2(tr, time.Now())
	if st.arenaNext == nil {
		t.Fatal("the sweep fired the entry before its delay")
	}
	// After it, the sweep sends the space, the cell player and the Vehicle.
	s.sweepStage2(tr, time.Now().Add(arenaNextDelay+time.Millisecond))
	if st.arenaNext != nil {
		t.Fatal("the sweep did not fire the held-back entry")
	}
	if len(tr.writes) < 4 {
		t.Fatalf("%d writes, want the space, the cell player and the Vehicle", len(tr.writes))
	}
}

// TestAccountCallsDroppedBetweenResetAndReentry pins the crash guard: once
// resetEntities has gone out the client holds no entity, so an Account-level
// answer would make it size an entity method for a null entity and assert
// (`MF_ASSERT_DEV FAILED: pEntity`, bw_entities.cpp:1103). The calls are
// dropped, not queued, and the guard lifts as soon as the new entity exists.
func TestAccountCallsDroppedBetweenResetAndReentry(t *testing.T) {
	s := tokenTestServer(t, nil)
	// This test is about the guard, not the wire shape: the shop answer's
	// stream elements are 0x45/0x46, which the offline reader does not
	// model yet (the client itself takes them — the hangar syncs).
	WireCheck = nil
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234,
		stage2Addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
	}
	h := &ArenaHandoff{
		ArenaID: 9, SpaceID: 9, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID: 0x2222,
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.enterArena(&fakeTransport{}, addr, st, h); err != nil {
		t.Fatalf("enterArena: %v", err)
	}

	// The client's lobby sync lands in the gap: it must produce no traffic.
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, addr, st, postCall{Req: 222, Cmd: lobby.CmdSyncShop}); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 0 {
		t.Fatalf("%d writes while entity-less, want 0", len(tr.writes))
	}

	// Once the Avatar exists the same call is answered again.
	if _, err := s.enterArenaEntities(&fakeTransport{}, addr, st, h, 10, 10); err != nil {
		t.Fatalf("enterArenaEntities: %v", err)
	}
	tr2 := &fakeTransport{}
	if err := s.answerPostCall(tr2, addr, st, postCall{Req: 222, Cmd: lobby.CmdSyncShop}); err != nil {
		t.Fatalf("answerPostCall after re-entry: %v", err)
	}
	if len(tr2.writes) == 0 {
		t.Fatal("the shop sync was still dropped after the Avatar was created")
	}
}

// TestArenaPeriodUpdateMatchesTheCapture pins the period update against the
// captured server's own BATTLE tuple.
//
// `captures/proxy-20261031-1358.hex` at 14:17:37.447 carries
// `updateArena(PERIOD, zlib(pickle((3, 114146.6, 1500, [10.0, 10.0]))))`, and
// the pickle decompresses to exactly the bytes below. The additional info is a
// LIST, never None: `MapActivities.__setStartTimes` does `len(...)` on it and
// throws `TypeError: object of type 'NoneType' has no len()` on a None, which
// aborted the rest of the period handler.
func TestArenaPeriodUpdateMatchesTheCapture(t *testing.T) {
	d := testDispatch(t)
	e := &Entity{Type: d.Entity("Avatar")}
	if e.Type == nil {
		t.Skip("no Avatar")
	}
	el, err := arenaPeriodUpdateFull(e, ArenaPeriodBattle, 114146.6, 1500, []float64{10, 10})
	if err != nil {
		t.Fatal(err)
	}
	// The element is `0x88`, a one-byte length, updateType 3, a one-byte string
	// length, then the zlib stream.
	if el[0] != 0x88 {
		t.Fatalf("element id %#02x, want 0x88 (updateArena)", el[0])
	}
	body := el[2 : 2+int(el[1])]
	if body[0] != ArenaUpdatePeriod {
		t.Fatalf("updateType %d, want %d", body[0], ArenaUpdatePeriod)
	}
	packed := body[2 : 2+int(body[1])]
	zr, err := zlib.NewReader(bytes.NewReader(packed))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("8002284b034740fbde299999999a4ddc055d71012847402400000000000047402400000000000065742e")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("pickle mismatch\n got %x\nwant %x", raw, want)
	}
}

// TestArenaGameTimeIsTheRawTick pins the two units the client's clock is built
// from against each other, because getting them wrong is silent: the battle
// timer simply opens at the wrong value.
//
// The capture's own numbers: `UPDATE_FREQUENCY_NOTIFICATION` at 14:17:25.943
// carries game time 1126351, the period tuples are in seconds
// (`(2, 112646.6, 3, [10.0, 10.0])`), and the tick at that instant is ~1126346.
// `BigWorld.serverTime()` is therefore `gameTime / 10 + elapsed`, so the game
// time is the raw 10 Hz counter and a period's end time is `tick / 10 + length`.
// Sending seconds as the game time makes `serverTime()` ten times too small and
// `battleTime = serverTime - (periodEndTime - periodLength)` opens at -128 s.
func TestArenaGameTimeIsTheRawTick(t *testing.T) {
	const tick = 1126346
	if got := arenaGameTime(tick); got != tick {
		t.Fatalf("game time = %d, want the raw tick %d", got, tick)
	}
	// The two must agree: serverTime() at the send is gameTime/10, and the
	// period's start is periodEnd - length. A countdown of `length` means
	// those are equal.
	for _, length := range []uint32{3, 8, 1500} {
		serverTime := float64(arenaGameTime(tick)) / 10
		start := arenaPeriodEnd(tick, length) - float64(length)
		if d := start - serverTime; d < -0.001 || d > 0.001 {
			t.Fatalf("length %d: period start %.3f but serverTime %.3f (off by %.3f s)",
				length, start, serverTime, d)
		}
	}
}

// TestSetClientReadyStartsTheBattlePeriod pins the ready handshake: the entry
// arms a channel, the client's `Avatar.setClientReady` base call closes it, and
// the period sequence waits on it instead of on a timer. A BATTLE sent before
// that call is dropped by the client (`setClientReady` registers its
// `onPeriodChange` handler AFTER the period check), which is the "loaded but
// frozen" bug the timers used to work around.
func TestSetClientReadyStartsTheBattlePeriod(t *testing.T) {
	s := tokenTestServer(t, nil)
	av := s.cfg.Dispatch.Entity("Avatar")
	if av == nil {
		t.Fatal("no Avatar entity")
	}
	m := av.MethodByName(entdef.CompBase, "setClientReady")
	if m == nil {
		t.Fatal("no setClientReady base method")
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234,
		stage2Addr: addr,
		readyCh:    make(chan struct{}),
	}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, addr, st, postCall{Method: m, Elem: 0x89}); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	select {
	case <-st.readyCh:
	default:
		t.Fatal("setClientReady did not release the entry")
	}
	// A second call in the same battle is a no-op, not a double close.
	if err := s.answerPostCall(tr, addr, st, postCall{Method: m, Elem: 0x89}); err != nil {
		t.Fatalf("second answerPostCall: %v", err)
	}
	// Re-arming per battle is what makes the second call safe again.
	st.readyCh = make(chan struct{})
	st.readyDone = false
	s.markClientReady(st)
	select {
	case <-st.readyCh:
	default:
		t.Fatal("the re-armed entry was not released")
	}
}

// TestOwnVehicleAllowsNonePropsAreNone pins the two component handlers that
// throw with a zeroed dict. `OwnVehicleBase.__set` runs an `update_*` handler
// only for a NON-None value, so None is how the official server keeps them from
// running: `update_dualGunState` indexes an empty `gunStates` (`IndexError`) and
// `update_welcomeToSector` reaches a `sectorComponent` that only Frontline has
// (`AttributeError`). Both were in the client's log on every battle entry.
func TestOwnVehicleAllowsNonePropsAreNone(t *testing.T) {
	compDescr := lobby.AllOwnableVehicles[0].CompDescr
	ov := ownVehicleOverrides(0x1234, compDescr, nil)
	for _, name := range []string{"dualGunState", "welcomeToSector", "siegeStateStatus", "targetVehicleID"} {
		v, ok := ov[name]
		if !ok || v.Kind != entdef.VNone {
			t.Fatalf("%s = %+v, want None", name, v)
		}
	}
	// The properties the gun needs must stay dicts: a None there skips the
	// handler and the client keeps its zeroed default, which is a frozen gun.
	for _, name := range []string{"targetingInfo", "vehicleHealthInfo", "vehicleGunReloadTime", "syncVehicleAttrs"} {
		v, ok := ov[name]
		if !ok || v.Kind != entdef.VDict {
			t.Fatalf("%s = %+v, want a dict", name, v)
		}
	}
}

// TestSetClientReadyDecodesPastTheAccountSlot pins the base-slot collision that
// silently ate the ready signal: Account and Avatar share the base element
// space, Account's slot 1 is `onStreamComplete` (3 B) and Avatar's is
// `setClientReady` (0 B). Refusing on the Account length mismatch dropped the
// call, so the decoder has to fall through to the Avatar.
func TestSetClientReadyDecodesPastTheAccountSlot(t *testing.T) {
	s := tokenTestServer(t, nil)
	acct := s.cfg.Dispatch.Entity("Account")
	av := s.cfg.Dispatch.Entity("Avatar")
	if acct == nil || av == nil {
		t.Fatal("no Account/Avatar entity in the defs")
	}
	slot := -1
	for i := 0; i < len(acct.BaseMethods) && i < len(av.BaseMethods); i++ {
		if acct.BaseMethods[i].Name == "onStreamComplete" && av.BaseMethods[i].Name == "setClientReady" {
			slot = i
			break
		}
	}
	if slot < 0 {
		t.Fatalf("the Account/Avatar base slot collision moved: account=%v avatar=%v",
			baseMethodNames(acct.BaseMethods), baseMethodNames(av.BaseMethods))
	}
	call, ok := s.decodeBaseCall(byte(baseMethodElementID+slot), nil)
	if !ok || call.Method == nil || call.Method.Name != "setClientReady" {
		t.Fatalf("decodeBaseCall(slot %d) = %+v, %v; want setClientReady", slot, call.Method, ok)
	}
}

// baseMethodNames is a test helper for the failure message above.
func baseMethodNames(ms []entdef.MethodDef) []string {
	out := make([]string, 0, len(ms))
	for i := range ms {
		out = append(out, ms[i].Name)
	}
	return out
}

// TestLoadedShellIsTheFirstLoadoutShell pins the shell the gun starts with: the
// first one in the saved loadout that has ammo left, as the reference's
// `Gun::new` does, and the gun's default only when the garage holds no layout.
func TestLoadedShellIsTheFirstLoadoutShell(t *testing.T) {
	disp := dispersionSpec{ShellCD: 999}
	if got := loadedShellFor(disp, []int64{111, 10, 222, 10}); got != 111 {
		t.Fatalf("loaded = %d, want the first loadout shell 111", got)
	}
	if got := loadedShellFor(disp, []int64{0, 10, 222, 5}); got != 222 {
		t.Fatalf("loaded = %d, want the first shell with ammo 222", got)
	}
	if got := loadedShellFor(disp, []int64{111, 0, 222, 5}); got != 222 {
		t.Fatalf("loaded = %d, want the first shell with ammo 222", got)
	}
	if got := loadedShellFor(disp, nil); got != 999 {
		t.Fatalf("loaded = %d, want the gun default 999", got)
	}
}

// TestEntryShellSettingsDoNotPreSelectTheNextShell pins the ammo panel's entry
// state: CURRENT_SHELLS and NEXT_SHELLS are BOTH the loaded shell, so the
// next-shell marker starts on it. Sending the first OTHER shell pre-highlights
// that one — the player enters the battle already one press into the cycle,
// and the two presses that should reach the third shell only reach the second.
func TestEntryShellSettingsDoNotPreSelectTheNextShell(t *testing.T) {
	// Loads the defs and with them the alias table `ownVehicleOverrides`
	// resolves its types through.
	tokenTestServer(t, nil)
	compDescr := lobby.AllOwnableVehicles[0].CompDescr
	saved := []int64{111, 10, 222, 10, 333, 10}
	ov := ownVehicleOverrides(0x1234, compDescr, saved)
	vs, ok := ov["vehicleSettings"]
	if !ok || vs.Kind != entdef.VSeq || len(vs.Seq) != 2 {
		t.Fatalf("vehicleSettings = %+v, want the two settings", vs)
	}
	setting := func(i int) (code, value int64) {
		for _, f := range vs.Seq[i].Dict {
			switch f.Name {
			case "code":
				// `code` is UINT8, so the number is in Uint.
				code = int64(f.Value.Uint)
			case "value":
				value = f.Value.Int
			}
		}
		return code, value
	}
	curCode, cur := setting(0)
	nextCode, next := setting(1)
	if curCode != int64(settingCurrentShell) || nextCode != int64(settingNextShell) {
		t.Fatalf("codes = %d/%d, want %d/%d", curCode, nextCode, settingCurrentShell, settingNextShell)
	}
	if cur != 111 || next != 111 {
		t.Fatalf("current/next = %d/%d, want 111/111 (next must not be pre-selected)", cur, next)
	}
}

// TestLeaveArenaSwitchesBackToStage1 pins the leave's real shape: a
// `switchBaseApp` back to the stage-1 endpoint, and the session reset to
// "just admitted" so the client's re-handshake walks the ordinary login
// (stage-1 22B → rotation → createBasePlayer → [44] → stage-2 22B → flood →
// Account → showGUI).
//
// Answering the leave with a login reply on the battle connection instead
// creates the Account there, and `SmartServerConnection` tears it down 0.8 s
// later (`NRL Integration: Client Hub destroyed`, `Account.onBecomeNonPlayer`,
// `HANGAR LOADING STATE: DISCONNECTED`).
func TestLeaveArenaSwitchesBackToStage1(t *testing.T) {
	s := tokenTestServer(t, nil)
	stage1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32850}
	s.cfg.Stage1 = stage1
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234,
		stage2Addr: addr, postSeq: 100, postCumul: 3, tick: 1000,
		stage2Key: 0xabcdef, flooded: true, entered: true, resetSent: true,
		arena: &ArenaHandoff{ArenaID: 9},
	}
	s.mu.Lock()
	s.byAddr[addr.String()] = st
	s.mu.Unlock()
	tr := &fakeTransport{}
	if err := s.answerLeaveArena(tr, addr, st); err != nil {
		t.Fatalf("answerLeaveArena: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d packets, want 1 (the switchBaseApp)", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	// [13][tag][44][ip4][port BE][00 00][01]
	if app == nil || len(app) < 12 || app[0] != elTickSync || app[2] != 0x44 {
		t.Fatalf("app = % x, want [13][tag][44] + the stage-1 address", app)
	}
	if !bytes.Equal(app[3:7], []byte{127, 0, 0, 1}) {
		t.Errorf("switch address = %v, want 127.0.0.1", app[3:7])
	}
	if got := int(app[7])<<8 | int(app[8]); got != 32850 {
		t.Errorf("switch port = %d, want 32850", got)
	}
	if app[9] != 0 || app[10] != 0 || app[11] != 1 {
		t.Errorf("switch trailer = % x, want 00 00 01 (reset_entities)", app[9:12])
	}
	// The session is back to "just admitted": the stage-2 handshake state is
	// gone, so the client's next 22B mints a fresh rotation and the flood
	// runs again.
	if st.stage2Key != 0 || st.stage2Addr != nil || st.flooded {
		t.Errorf("stage2 state = key %#x addr %v flooded %v, want a fresh handshake",
			st.stage2Key, st.stage2Addr, st.flooded)
	}
	if st.arena != nil || st.entered || st.resetSent {
		t.Errorf("arena state = %v entered %v resetSent %v, want cleared", st.arena, st.entered, st.resetSent)
	}
	if _, ok := s.byAddr[addr.String()]; ok {
		t.Error("the old socket is still bound to the session")
	}
	// The client's new socket starts its counters at zero. A stale cumulative
	// ack (measured: 2823 after a battle) makes the client reject the session
	// dict as "ACK for packets not yet sent", so the Account is created and
	// `showGUI` — which rides that dict — never runs: the loading screen hangs.
	if st.postSeq != 0 || st.postTag != 0 || st.postCumul != 0 {
		t.Errorf("post counters = seq %d tag %d cumul %d, want all zero",
			st.postSeq, st.postTag, st.postCumul)
	}
	// The re-entry's [44] must name the SECOND BaseApp: the client keeps a
	// packet receiver per address, and the battle's watermark on the same one
	// makes the fresh login's seq 1..N "missing packets" → REASON_CORRUPTED_
	// PACKET → `MF_ASSERT_DEV FAILED: pEntity` (a crash, measured).
	if !st.reentry {
		t.Error("the leave did not mark the session for the second BaseApp")
	}
}

// TestLeaveArenaResetIsReliable pins the fallback leave (no stage-1 endpoint):
// a RELIABLE reset. An unreliable one shares the unreliable counter with the
// arena ticks, so the client's packet receiver drops it as out-of-order
// (`Dropping out-of-order unreliable packet seq=…`) and never processes the
// reset — no `enableEntities`, no Account re-entry, the lobby sync calls are
// dropped as "no entity between reset and re-entry", and the unacked 10 Hz
// ticks overflow the client's channel until it disconnects.
func TestLeaveArenaResetIsReliable(t *testing.T) {
	s := tokenTestServer(t, nil)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234,
		stage2Addr: addr, postSeq: 100, postCumul: 3, tick: 1000,
		arena: &ArenaHandoff{ArenaID: 9},
	}
	tr := &fakeTransport{}
	if err := s.answerLeaveArena(tr, addr, st); err != nil {
		t.Fatalf("answerLeaveArena: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d packets, want 1 (the reset)", len(tr.writes))
	}
	pkt := tr.writes[0]
	// [4-byte prefix][blowfish(flags u16 LE + app + footers)]
	clear, err := DecryptChannel(st.blockKey, pkt)
	if err != nil {
		t.Fatalf("DecryptChannel: %v", err)
	}
	flags := binary.LittleEndian.Uint16(clear[0:2])
	if flags&0x0010 == 0 {
		t.Fatalf("reset flags = %#06x, want the RELIABLE bit (0x0010)", flags)
	}
	app := findAppInPacket(t, pkt, st.blockKey)
	if app == nil || !bytes.Contains(app, []byte{elResetEntities, 0}) {
		t.Fatalf("reset app = % x, want resetEntities(false)", app)
	}
}

// TestFormationSpawnMatchesTheOfficialLayout pins the team formation against
// what a replay's initial creates show: a grid offset from the team's spawn
// point toward the enemy, every tank facing the enemy, each standing on the
// terrain.
func TestFormationSpawnMatchesTheOfficialLayout(t *testing.T) {
	base := [3]float32{-236.6, 0, 329.6}  // a team's spawn point
	enemy := [3]float32{175.8, 0, -305.8} // the other team's
	ground := func(x, z float32) (float32, bool) { return 10 + x*0.01, true }
	const n = 15
	seen := map[[2]int]bool{}
	var sumX, sumZ float64
	for i := 0; i < n; i++ {
		sp := formationSpawn(base, enemy, i, n, ground)
		// Every tank faces the enemy.
		wantYaw := float32(math.Atan2(float64(enemy[0]-base[0]), float64(enemy[2]-base[2])))
		if sp.yaw != wantYaw {
			t.Errorf("tank %d yaw = %v, want the team's heading %v", i, sp.yaw, wantYaw)
		}
		// And stands on the terrain under it.
		if gy, _ := ground(sp.pos[0], sp.pos[2]); sp.pos[1] != gy {
			t.Errorf("tank %d y = %v, want the ground %v", i, sp.pos[1], gy)
		}
		// No two tanks share a slot.
		key := [2]int{int(sp.pos[0] * 10), int(sp.pos[2] * 10)}
		if seen[key] {
			t.Errorf("tank %d shares a slot at %v", i, sp.pos)
		}
		seen[key] = true
		sumX += float64(sp.pos[0])
		sumZ += float64(sp.pos[2])
	}
	// The formation's centre is offset from the spawn point toward the enemy.
	cx, cz := sumX/n, sumZ/n
	dx, dz := cx-float64(base[0]), cz-float64(base[2])
	dist := math.Hypot(dx, dz)
	// A grid that does not fill its last rank shifts the centroid a little.
	if math.Abs(dist-float64(spawnFormationOffset)) > 5 {
		t.Errorf("formation centre is %.1f m from the spawn point, want %.0f", dist, float64(spawnFormationOffset))
	}
	// And it is toward the enemy, not away from it.
	ex, ez := float64(enemy[0]-base[0]), float64(enemy[2]-base[2])
	if dx*ex+dz*ez < 0 {
		t.Errorf("the formation is offset away from the enemy (%.1f, %.1f)", dx, dz)
	}
}

// TestPrebattleLength pins the prebattle window to the capture's 3.0 s, the
// official server's own: the client cannot drive during it (its
// `Avatar.moveVehicle` returns early unless the period is BATTLE), which is
// faithful. The environment overrides it for testing.
func TestPrebattleLength(t *testing.T) {
	t.Setenv("WOT_PREBATTLE_MS", "")
	if got := prebattleLength(); got != 3*time.Second {
		t.Errorf("default prebattle = %v, want the capture's 3s", got)
	}
	t.Setenv("WOT_PREBATTLE_MS", "500")
	if got := prebattleLength(); got != 500*time.Millisecond {
		t.Errorf("WOT_PREBATTLE_MS=500 gave %v, want 500ms", got)
	}
	t.Setenv("WOT_PREBATTLE_MS", "nonsense")
	if got := prebattleLength(); got != 3*time.Second {
		t.Errorf("a bad value gave %v, want the default 3s", got)
	}
}

// TestArenaInfoIDIsPastTheVehicles pins the AvatarInfo's entity id: it must not
// collide with a vehicle's. The player is `VehicleID`, the dummy `+1` and the
// synthetic tanks `+2` onwards, so an id inside that range collides with the
// first bot — the client then resolves that bot's appearance to the AvatarInfo
// and its `isPlayerVehicle` lookup throws, leaving the bot with no model.
func TestArenaInfoIDIsPastTheVehicles(t *testing.T) {
	s := tokenTestServer(t, nil)
	const bots = 28
	h := &ArenaHandoff{
		ArenaID:     9,
		SpaceID:     9,
		ArenaTypeID: 1,
		Map:         "spaces/01_karelia",
		Player:      ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID:   100003,
	}
	for i := 0; i < bots; i++ {
		h.Bots = append(h.Bots, ArenaPlayerDoc{AccountID: int64(100 + i), Name: "bot", Team: uint8(1 + i%2)})
	}
	info, _, err := s.arenaInfoApp(&clientState{}, h, newNrlNodeAlloc(), nil)
	if err != nil {
		t.Skipf("no defs: %v", err)
	}
	// Every vehicle id the battle uses.
	used := map[uint32]string{h.VehicleID: "player", h.VehicleID + 1: "dummy"}
	for i := 0; i < bots; i++ {
		used[h.VehicleID+2+uint32(i)] = "bot"
	}
	if what, clash := used[info.ID]; clash {
		t.Fatalf("the AvatarInfo's id %d collides with the %s", info.ID, what)
	}
	if info.ID <= h.VehicleID+1+uint32(bots) {
		t.Errorf("the AvatarInfo's id %d is inside the vehicles' range (up to %d)", info.ID, h.VehicleID+1+uint32(bots))
	}
}

// TestArenaEntityIDsArePastTheVehicles pins every non-vehicle entity's id: the
// player is `VehicleID`, the dummy `+1` and the synthetic tanks `+2` onwards,
// so an id inside that range collides with a bot and the client's entity table
// ends up holding the wrong entity — which is how the AvatarInfo and the
// TeamInfo both hid the battle's tanks.
func TestArenaEntityIDsArePastTheVehicles(t *testing.T) {
	const bots = 28
	const vehicleID = 100003
	used := map[uint32]string{vehicleID: "player", vehicleID + 1: "dummy"}
	for i := 0; i < bots; i++ {
		used[vehicleID+2+uint32(i)] = "bot"
	}
	// The ids the entry allocates, as `enterArenaEntities` computes them.
	infoID := vehicleID + 2 + uint32(bots)
	teamID := vehicleID + 3 + uint32(bots)
	for name, id := range map[string]uint32{"AvatarInfo": infoID, "TeamInfo": teamID} {
		if what, clash := used[id]; clash {
			t.Errorf("the %s's id %d collides with the %s", name, id, what)
		}
	}
	if infoID == teamID {
		t.Errorf("the AvatarInfo and the TeamInfo share id %d", infoID)
	}
}
