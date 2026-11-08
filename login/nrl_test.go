package login

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestNrlIdListEncoding pins the node-id list the client's `readIdList` reads:
// signed bytes relative to a running id that starts at the owning node's id.
func TestNrlIdListEncoding(t *testing.T) {
	// Two consecutive children of node 3: advance by one twice, then the
	// end marker and a one-byte presence mask with both bits set.
	got := EncodeNrlIdList(3, []uint32{4, 5}, []bool{true, true})
	want := []byte{0x01, 0x01, 0x82, 0x03}
	if !bytes.Equal(got, want) {
		t.Fatalf("id list = % x, want % x", got, want)
	}
	// No mask: the plain end marker.
	got = EncodeNrlIdList(3, []uint32{4}, nil)
	if want := []byte{0x01, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("id list without mask = % x, want % x", got, want)
	}
	// A jump too far for one byte falls back to the absolute form.
	got = EncodeNrlIdList(3, []uint32{400}, nil)
	if want := []byte{0x80, 0x01, 0x90, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("absolute id list = % x, want % x", got, want)
	}
}

// TestNrlCreateEntityNode pins the message that creates an entity's NRL node:
// the element id implies message type 0, so the type byte is absent.
func TestNrlCreateEntityNode(t *testing.T) {
	got := EncodeNrlCreateEntityNode(2, 0x1234)
	want := []byte{
		0x00, 0x02, // node id 2, big-endian
		0x00, 0x01, // parent: the root
		0x01,                   // node type: entity
		0x34, 0x12, 0x00, 0x00, // entity id, little-endian
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("entity node = % x, want % x", got, want)
	}
}

// TestNrlCreateComponent pins the component message: a leading type byte
// (only the first message of an element omits it), the component's NRL type id
// little-endian, an empty instance name, the child id list, then the data.
func TestNrlCreateComponent(t *testing.T) {
	got := EncodeNrlCreateComponent(3, 2, AvatarVehiclesInfoNrlID, "",
		[]uint32{4, 5}, []bool{true, true}, []byte{0xAA})
	want := []byte{
		0x00,       // msg type 0: CreateNode
		0x00, 0x03, // node id 3
		0x00, 0x02, // parent: the entity node
		0x02,       // node type: dynamic component
		0x7E, 0x00, // component type id 126, little-endian
		0x00,                   // empty instance name
		0x01, 0x01, 0x82, 0x03, // children 4 and 5, both present
		0xAA, // the component's data
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("component node = % x, want % x", got, want)
	}
}

// TestVehicleInfoRoundTrip is the check that matters: the VEHICLES_INFO dict
// this server builds must decode back through the defs' own codec, field for
// field. A field written in the wrong order or with the wrong type still
// produces bytes, and the client would read them as something else.
func TestVehicleInfoRoundTrip(t *testing.T) {
	s := tokenTestServer(t, nil)
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		t.Fatal("VEHICLES_INFO is not in the alias table")
	}
	compDescr := []byte{0x51, 0xd2, 0x3f, 0x00, 0x36, 0x00}
	v := vehicleInfoValue(infoType, ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: compDescr}, 100003, 1, 316.2, 266.0)

	var buf bytes.Buffer
	if err := entdef.EncodeArray(&buf, infoType, []entdef.Value{v}); err != nil {
		t.Fatalf("EncodeArray: %v", err)
	}
	// The array header is the element count, one byte for a small list.
	if buf.Bytes()[0] != 1 {
		t.Fatalf("array header = %#x, want 1", buf.Bytes()[0])
	}
	buf.Next(1) // step over the count: the dict follows it
	back, err := entdef.NewCodec().Read(&buf, infoType)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes left after the dict, want 0", buf.Len())
	}
	for _, want := range []struct {
		field string
		check func(entdef.Value) bool
	}{
		{"vehicleID", func(x entdef.Value) bool { return x.Int == 100003 }},
		{"name", func(x entdef.Value) bool { return x.Str == "admin" }},
		{"team", func(x entdef.Value) bool { return x.Int == 1 }},
		{"compDescr", func(x entdef.Value) bool { return x.Str == string(compDescr) }},
		{"accountDBID", func(x entdef.Value) bool { return x.Uint == 2 }},
		{"maxHealth", func(x entdef.Value) bool { return x.Int == 1000 }},
		{"isAlive", func(x entdef.Value) bool { return x.Uint == 1 }},
		{"avatarSessionID", func(x entdef.Value) bool { return x.Str == "100003" }},
		{"ranked", func(x entdef.Value) bool { return len(x.Seq) == 2 }},
	} {
		got, ok := back.Get(want.field)
		if !ok {
			t.Fatalf("%s missing from the decoded dict", want.field)
		}
		if !want.check(got) {
			t.Fatalf("%s decoded as %+v", want.field, got)
		}
	}
	_ = s
}

// TestArenaInfoCarriesTheVehicleList checks the element the client actually
// receives: an NRL create-node carrying the component, with the vehicle list
// inside it.
func TestArenaInfoCarriesTheVehicleList(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234}
	h := &ArenaHandoff{
		ArenaID: 9, SpaceID: 9, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte{0x51, 0x64}},
		VehicleID: 0x2222,
	}
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		t.Fatal("VEHICLES_INFO is not in the alias table")
	}
	vehicles := []entdef.Value{
		vehicleInfoValue(infoType, h.Player, h.VehicleID, 1, 316.2, 266.0),
		vehicleInfoValue(infoType, ArenaPlayerDoc{Name: "Dummy", Team: 2, VehicleCompDescr: []byte{0x51, 0xd2}}, h.VehicleID+1, 1, -283.8, -372.7),
	}
	info, app, err := s.arenaInfoApp(st, h, newNrlNodeAlloc(), vehicles)
	if err != nil {
		t.Fatalf("arenaInfoApp: %v", err)
	}
	if info.ID != h.VehicleID+2 {
		t.Fatalf("AvatarInfo id = %d, want %d", info.ID, h.VehicleID+2)
	}
	if app[0] != elNrlCreateNode {
		t.Fatalf("element id = %#x, want %#x", app[0], elNrlCreateNode)
	}
	// The component's type id, little-endian, must be in the payload.
	if !bytes.Contains(app, []byte{0x7E, 0x00}) {
		t.Fatalf("component type id 126 is not in the element: % x", app)
	}
	// Both names ride the list, so both teams have a tank.
	if !bytes.Contains(app, []byte("admin")) || !bytes.Contains(app, []byte("Dummy")) {
		t.Fatalf("the vehicle list does not carry both names: % x", app)
	}
	// The entity's own property run carries avatarID, which is what the
	// client compares against its avatar before taking the component.
	props, err := EntityPropertyRun(info)
	if err != nil {
		t.Fatalf("EntityPropertyRun: %v", err)
	}
	if len(props) < 2 || props[0] != 1 {
		t.Fatalf("AvatarInfo property run = % x, want one property", props)
	}
}

// TestArenaPeriodUpdateIsAPeriodChange checks the call that starts the battle:
// `updateArena(ARENA_UPDATE.PERIOD, zlib(pickle((BATTLE, 0, 0, None))))`.
func TestArenaPeriodUpdateIsAPeriodChange(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234}
	h := &ArenaHandoff{
		ArenaID: 9, SpaceID: 9, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID: 0x2222,
	}
	avatar, _, err := s.arenaAvatarApp(st, h)
	if err != nil {
		t.Fatalf("arenaAvatarApp: %v", err)
	}
	app, err := arenaPeriodUpdate(avatar, ArenaPeriodBattle)
	if err != nil {
		t.Fatalf("arenaPeriodUpdate: %v", err)
	}
	if len(app) < 3 || app[0] < entityMethodBase {
		t.Fatalf("not an entity method call: % x", app[:8])
	}
	// The first payload byte is the ARENA_UPDATE code.
	if app[2] != ArenaUpdatePeriod {
		t.Fatalf("update code = %d, want %d", app[2], ArenaUpdatePeriod)
	}
	// The compressed tuple is in there; its first byte is zlib's 0x78.
	if !bytes.Contains(app, []byte{0x78}) {
		t.Fatalf("no zlib payload in the call: % x", app)
	}
}

// TestOwnVehicleComponent checks the player's own tank gets its OwnVehicle
// component: 23 properties, then one child per client method, then the trailing
// child — 35 in all for 2.4.1's 11 methods.
func TestOwnVehicleComponent(t *testing.T) {
	s := tokenTestServer(t, nil)
	_ = s
	if ownVehicleClientMethods != 11 {
		t.Fatalf("OwnVehicle declares %d client methods, want 11", ownVehicleClientMethods)
	}
	alloc := newNrlNodeAlloc()
	app, err := EncodeNrlAttachComponent(alloc, 100003, OwnVehicleNrlID, ownVehicleProps, ownVehicleClientMethods, nil)
	if err != nil {
		t.Fatalf("EncodeNrlAttachComponent: %v", err)
	}
	if app[0] != elNrlCreateNode {
		t.Fatalf("element id = %#x, want %#x", app[0], elNrlCreateNode)
	}
	// The component's type id, little-endian: 53 is `OwnVehicle` in the
	// client's EntityType table.
	if !bytes.Contains(app, []byte{0x35, 0x00}) {
		t.Fatalf("component type id 53 is not in the element: % x", app)
	}
	// 35 children: 23 properties, 11 client methods, the trailing child.
	if got, want := alloc.next-nrlFirstNode, uint16(2+35); got != want {
		t.Fatalf("%d node ids taken, want %d (entity, component, 35 children)", got, want)
	}
	// Every property's alias type has to resolve, or the component cannot be
	// encoded at all — that is the check that matters here.
	for _, p := range ownVehicleProps {
		if entdef.Alias(p.Type) == nil {
			t.Fatalf("no alias type %q for OwnVehicle.%s", p.Type, p.Name)
		}
	}
}

// TestOwnVehicleOverridesAreNotZeroValues pins the three OwnVehicle properties
// whose zero value is actively wrong. Each one silently costs the gun:
//
//   - `fixAngles` zero is a dict of two zero floats, which is truthy, so
//     `OwnVehicleBase.update_fixAngles` calls `fixShotPosition(0, 0)` and the
//     turret is pinned; it has to be None.
//   - `targetingInfo` zero has both rotation speeds at 0, so the turret cannot
//     turn at all.
//   - `vehicleHealthInfo` zero is health 0 and crew inactive, which the client
//     draws as every module destroyed and the whole crew dead.
func TestOwnVehicleOverridesAreNotZeroValues(t *testing.T) {
	// The overrides are built from the alias types, which the dispatch
	// loader does not register on its own.
	if err := entdef.InitAliasesFromDir("../../scripts-2.4.1/entity_defs"); err != nil {
		t.Skipf("no aliases: %v", err)
	}
	o := ownVehicleOverrides(100003, nil, nil)

	fix, ok := o["fixAngles"]
	if !ok {
		t.Fatal("no fixAngles override: the turret would be pinned to (0, 0)")
	}
	if fix.Kind != entdef.VNone {
		t.Fatalf("fixAngles kind = %d, want VNone", fix.Kind)
	}

	ti, ok := o["targetingInfo"]
	if !ok {
		t.Fatal("no targetingInfo override: the turret could not turn")
	}
	for _, f := range ti.Dict {
		if f.Name == "maxTurretRotationSpeed" && f.Value.Float == 0 {
			t.Fatal("maxTurretRotationSpeed is 0")
		}
		if f.Name == "maxGunRotationSpeed" && f.Value.Float == 0 {
			t.Fatal("maxGunRotationSpeed is 0")
		}
	}

	// `drownLevel`/`overturnLevel` zero `times` is an EMPTY array, and
	// `OwnVehicleBase.__getDestroyTimes` reads `times[0]` and `times[1]`
	// unconditionally — the client logs `IndexError: Array index out of
	// range` out of `update_drownLevel`/`update_overturnLevel` every battle.
	for _, name := range []string{"drownLevel", "overturnLevel"} {
		v, ok := o[name]
		if !ok {
			t.Fatalf("no %s override: the client indexes an empty times array", name)
		}
		times, ok := v.Get("times")
		if !ok || times.Kind != entdef.VSeq || len(times.Seq) < 2 {
			t.Fatalf("%s.times = %+v, want a sequence of at least 2 floats", name, times)
		}
	}

	hi, ok := o["vehicleHealthInfo"]
	if !ok {
		t.Fatal("no vehicleHealthInfo override: every module would show destroyed")
	}
	for _, f := range hi.Dict {
		if f.Name == "health" && f.Value.Int == 0 {
			t.Fatal("health is 0")
		}
		if f.Name == "isCrewActive" && f.Value.Uint == 0 {
			t.Fatal("isCrewActive is 0")
		}
	}
}

// TestOwnVehiclePropsAreInClientOrder pins the property order against the rule
// the client uses: sorted by element length, fixed sizes first and ascending,
// then the variable ones in declaration order. A table in the def's declaration
// order shifts every value by the size difference and the client dies on
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
func TestOwnVehiclePropsAreInClientOrder(t *testing.T) {
	key := func(p nrlProp) (int, int) {
		dt := entdef.Alias(p.Type)
		if dt == nil {
			t.Fatalf("no alias type %q for OwnVehicle.%s", p.Type, p.Name)
		}
		if size := dt.StreamSize(); size >= 0 {
			return 0, size
		}
		return 1, 0
	}
	for i := 1; i < len(ownVehicleProps); i++ {
		pa, sa := key(ownVehicleProps[i-1])
		pb, sb := key(ownVehicleProps[i])
		if pa > pb || (pa == pb && sa > sb) {
			t.Fatalf("OwnVehicle.%s (%d,%d) sorts after %s (%d,%d)",
				ownVehicleProps[i-1].Name, pa, sa, ownVehicleProps[i].Name, pb, sb)
		}
	}
	// The one fixed-size property has to lead, or nothing else lines up.
	if ownVehicleProps[0].Name != "syncVehicleAttrs" {
		t.Fatalf("first property is %q, want syncVehicleAttrs", ownVehicleProps[0].Name)
	}
}

// TestNrlNodeIdsAreUniquePerEntry is the regression for a real failure: giving
// OwnVehicle its own allocator made it hand out the node ids the AvatarInfo
// entity and its component had already taken, the client grafted the vehicle's
// component onto the info entity's node, and the vehicle list came back empty.
//
// NRL node ids are unique per space, so every element the entry emits must
// claim a disjoint set.
func TestNrlNodeIdsAreUniquePerEntry(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234}
	h := &ArenaHandoff{
		ArenaID: 9, SpaceID: 9, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte{0x51, 0x64}},
		VehicleID: 0x2222,
		Dummy:     &ArenaPlayerDoc{AccountID: 0, Name: "Dummy", Team: 2, VehicleCompDescr: []byte{0x51, 0xd2}},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	// The Avatar first: enterArenaSpace needs it for the cell player and for
	// the period call.
	if _, err := s.enterArenaEntities(&fakeTransport{}, addr, st, h, 10, 10); err != nil {
		t.Fatalf("enterArenaEntities: %v", err)
	}
	tr := &fakeTransport{}
	if _, err := s.enterArenaSpace(tr, addr, st, h, 11, 10); err != nil {
		t.Fatalf("enterArenaSpace: %v", err)
	}
	seen := map[uint16]string{}
	for i, w := range tr.writes {
		app := findAppInPacket(t, w, st.blockKey)
		if len(app) < 3 || app[0] != elNrlCreateNode {
			continue
		}
		// [element id][length u16][payload]; the first message of an element
		// omits its type byte, so the payload starts with the node id.
		node := binary.BigEndian.Uint16(app[3:5])
		if prev, ok := seen[node]; ok {
			t.Fatalf("write %d reuses NRL node %d, already claimed by %s", i, node, prev)
		}
		seen[node] = fmt.Sprintf("write %d", i)
	}
	if len(seen) < 2 {
		t.Fatalf("only %d NRL elements in the entry, want at least 2 (OwnVehicle, AvatarInfo)", len(seen))
	}
}

// `smokeInfo` must be None, not its zero value.
//
// The zero value is a dict with `equipmentID: 0`, and
// `OwnVehicle.update_smokeInfo` fires `VEHICLE_VIEW_STATE.SMOKE` with it.
// `timers_panel.__updateSmokeTimer` then reads
// `vehicles.g_cache.equipments()[0].totalDuration` — an `Extinguisher` with no
// such attribute — and the `AttributeError` unwinds through
// `onVehicleControlling`, aborting `_VehicleUpdater._setup` before
// `updater.start()`. That updater is what polls `VEHICLE_VIEW_STATE.SPEED`, so
// the km/h digits stay at 0 for the whole battle.
func TestOwnVehicleSmokeInfoIsNone(t *testing.T) {
	o := ownVehicleOverrides(0x2222, []byte{1, 0, 0, 0, 240, 7, 203, 0, 5, 0, 0, 0, 246, 7, 0}, nil)
	si, ok := o["smokeInfo"]
	if !ok {
		t.Fatal("no smokeInfo override: its zero value breaks the speed updater")
	}
	if si.Kind != entdef.VNone {
		t.Fatalf("smokeInfo kind %d, want VNone", si.Kind)
	}
}

// The captured server's first NRL gun marker of the Oct-31 EU2 battle
// (`captures/proxy-20261031-1358.hex`, flow 127.0.0.1:50475, 14:17:37.543),
// verbatim. It is the first message of the battle, so `flags` is 0 and
// `prev_tick` is 0; every later one carries 0x20 and `tick-1`.
const capturedGunMarkerHex = "2844000600010b7e6ac9d0581987443011000000000030d6c3c40000010000272000200200838201014dc310c4989e0ec0e8450f43498f194464fd2e40cdfbf943c0c46e3b0120"

// The captured "no new marker this tick" form, verbatim (14:19:10.446). Its
// 8-byte payload never varied across the whole capture.
const capturedUnchangedHex = "2825000600010b7e6ac9d0581987e5331100e433110011d6c3c40000012000082000000201732000"

// TestNrlGunMarkerMatchesCapture pins the encoder against the captured bytes:
// same element id, same length, same per-arena ids, same class tag, same
// prefix/suffix, same floats. If this test fails the client is being sent
// something the official server never sent.
func TestNrlGunMarkerMatchesCapture(t *testing.T) {
	want, err := hex.DecodeString(capturedGunMarkerHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeNrlUnreliableGunMarker(0xC96A7E0B, 0x871958D0, 1126468, true, nrlGunMarker{
		Position:   [3]float32{-579.0515747070312, -2.2284297943115234, 143.2730712890625},
		Velocity:   [3]float32{614.2388305664062, 2.73421573638916, 499.9671936035156},
		Dispersion: 0.003643319010734558,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("gun marker mismatch\n got %x\nwant %x", got, want)
	}
}

// TestNrlUnchangedMatchesCapture pins the 8-byte "unchanged" form.
func TestNrlUnchangedMatchesCapture(t *testing.T) {
	want, err := hex.DecodeString(capturedUnchangedHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeNrlUnreliableUnchanged(0xC96A7E0B, 0x871958D0, 1127397, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unchanged form mismatch\n got %x\nwant %x", got, want)
	}
}

// TestNrlMarkerTickIsTheTickSyncCounter pins the relationship the capture
// establishes: `0x13` TickSync's byte is the LOW BYTE of the same 10 Hz counter
// the gun marker carries in full. At 14:17:38.143 the marker's tick is 1126474
// and the datagram's `0x13` byte is 74.
func TestNrlMarkerTickIsTheTickSyncCounter(t *testing.T) {
	tick := uint32(1126474)
	if got := byte(tick); got != 74 {
		t.Fatalf("byte(%d) = %d, want 74 (the capture's 0x13 byte)", tick, got)
	}
	el, err := EncodeNrlUnreliableGunMarker(1, 2, tick, false, nrlGunMarker{})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(el[3+11 : 3+15]); got != tick {
		t.Fatalf("marker tick = %d, want %d", got, tick)
	}
	if got := binary.LittleEndian.Uint32(el[3+15 : 3+19]); got != tick-1 {
		t.Fatalf("marker prev_tick = %d, want %d", got, tick-1)
	}
}

// TestNrlMarkerFirstOfBattleHasNoPrevTick pins the flags byte: the first
// message of a battle carries 0 and `prev_tick` 0, every later one 0x20.
func TestNrlMarkerFirstOfBattleHasNoPrevTick(t *testing.T) {
	first, err := EncodeNrlUnreliableGunMarker(1, 2, 1126468, true, nrlGunMarker{})
	if err != nil {
		t.Fatal(err)
	}
	if got := first[3+26]; got != 0 {
		t.Errorf("first marker flags = %#02x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(first[3+15 : 3+19]); got != 0 {
		t.Errorf("first marker prev_tick = %d, want 0", got)
	}
	later, err := EncodeNrlUnreliableGunMarker(1, 2, 1126469, false, nrlGunMarker{})
	if err != nil {
		t.Fatal(err)
	}
	if got := later[3+26]; got != nrlUnrelFlagsPrev {
		t.Errorf("later marker flags = %#02x, want %#02x", got, nrlUnrelFlagsPrev)
	}
}

// TestGunMarkerVelocityIsTheShellSpeed pins the marker's velocity: its length
// is the shell's muzzle velocity, which the capture shows constant at 792.00
// for a whole battle, and its heading follows the turret plus the hull.
func TestGunMarkerVelocityIsTheShellSpeed(t *testing.T) {
	spec := gunSpec{Dispersion: dispersionSpec{Angle: 0.004, ShotSpeed: 792}}
	h := hull{Position: [3]float32{10, 5, 20}, Direction: [3]float32{0, 0, 0}}
	m := gunMarkerFor(h, 0, 0, spec, 1)
	if got := math.Hypot(math.Hypot(float64(m.Velocity[0]), float64(m.Velocity[1])), float64(m.Velocity[2])); math.Abs(got-792) > 1e-3 {
		t.Errorf("|velocity| = %v, want the shell speed 792", got)
	}
	// Yaw 0 faces +Z, so a level gun points straight down +Z.
	if math.Abs(float64(m.Velocity[0])) > 1e-3 || math.Abs(float64(m.Velocity[2])-792) > 1e-3 {
		t.Errorf("velocity = %v, want (0, 0, 792)", m.Velocity)
	}
	// A quarter turn to the right points down +X.
	m = gunMarkerFor(h, math.Pi/2, 0, spec, 1)
	if math.Abs(float64(m.Velocity[0])-792) > 1e-3 || math.Abs(float64(m.Velocity[2])) > 1e-3 {
		t.Errorf("velocity at yaw pi/2 = %v, want (792, 0, 0)", m.Velocity)
	}
	// The hull's own yaw adds to the turret's.
	m = gunMarkerFor(hull{Position: [3]float32{10, 5, 20}, Direction: [3]float32{0, 0, math.Pi / 2}}, 0, 0, spec, 1)
	if math.Abs(float64(m.Velocity[0])-792) > 1e-3 {
		t.Errorf("velocity with the hull at pi/2 = %v, want (792, 0, 0)", m.Velocity)
	}
	// The position is the gun's pivot, `GunHeight` above the hull's origin.
	spec.GunHeight = 2.3
	m = gunMarkerFor(h, 0, 0, spec, 1)
	if want := [3]float32{10, 7.3, 20}; m.Position != want {
		t.Errorf("position = %v, want %v", m.Position, want)
	}
	// The dispersion is the gun's own angle times the factor.
	if got, want := m.Dispersion, float32(0.004*1); got != want {
		t.Errorf("dispersion = %v, want %v", got, want)
	}
}

// TestStepDispersionFollowsTheClientModel pins the dispersion factor against
// the client's own `Avatar.getOwnVehicleShotDispersionAngle`: 1.0 at rest,
// growing with speed and turn rate, and decaying back over `aimingTime`.
func TestStepDispersionFollowsTheClientModel(t *testing.T) {
	d := dispersionSpec{AimingTime: 2.5, Movement: 0.14 / 3.6, Rotation: 0.14 * math.Pi / 180, TurretRotation: 0.16 * math.Pi / 180}
	// At rest the ideal factor is sqrt(1) = 1, so a fresh factor stays 1.
	if got := stepDispersion(1, hull{}, 0, d, 0.1); math.Abs(got-1) > 1e-9 {
		t.Errorf("at rest = %v, want 1", got)
	}
	// Driving at 10 m/s: sqrt(1 + (10*0.14/3.6)^2).
	moving := hull{Speed: 10}
	want := math.Sqrt(1 + math.Pow(10*0.14/3.6, 2))
	if got := stepDispersion(1, moving, 0, d, 0.1); math.Abs(got-want) > 1e-9 {
		t.Errorf("at 10 m/s = %v, want %v", got, want)
	}
	// It snaps UP immediately, not over time.
	if got := stepDispersion(1, moving, 0, d, 0.001); math.Abs(got-want) > 1e-9 {
		t.Errorf("snap up = %v, want %v", got, want)
	}
	// And decays back down over the aiming time, never below the ideal.
	got := stepDispersion(want, hull{}, 0, d, 0.1)
	if got <= 1 || got >= want {
		t.Errorf("decay = %v, want between 1 and %v", got, want)
	}
	// After several aiming times it is back at the ideal. 20 s is eight time
	// constants, so it is within exp(-8) of it, not exactly on it.
	got = want
	for i := 0; i < 200; i++ {
		got = stepDispersion(got, hull{}, 0, d, 0.1)
	}
	if math.Abs(got-1) > 1e-3 {
		t.Errorf("after 20 s = %v, want ~1", got)
	}
}

// TestArenaNrlIdsArePerArena pins the only property the capture establishes
// about the marker's two ids: constant within a battle, different between
// battles.
func TestArenaNrlIdsArePerArena(t *testing.T) {
	a1, b1 := arenaNrlIds(1)
	a1b, b1b := arenaNrlIds(1)
	if a1 != a1b || b1 != b1b {
		t.Fatalf("ids are not stable for one arena: (%#x,%#x) then (%#x,%#x)", a1, b1, a1b, b1b)
	}
	seen := map[[2]uint32]bool{{a1, b1}: true}
	for id := uint64(2); id < 40; id++ {
		a, b := arenaNrlIds(id)
		if seen[[2]uint32{a, b}] {
			t.Fatalf("arena %d reuses the pair (%#x,%#x)", id, a, b)
		}
		seen[[2]uint32{a, b}] = true
	}
}

// TestArenaTickAppMatchesTheCapturedShape pins the element sequence of one
// arena tick datagram against the capture: `0x13` TickSync, `0x16` the
// metre-rounded reference, `0x1e` the player's own entity, `0x1d` the Vehicle
// by alias, then `0x28` the gun marker — and nothing else.
//
// The "nothing else" is the point. The captured server sends no property
// updates at all during a battle, so a `0x4b` (updateEntity) or a `0x19`
// (selectEntity) in here would be traffic it never sends. The walk has to
// consume the app exactly, which is also what the client's own bundle reader
// requires: it has no way to resynchronise.
func TestArenaTickAppMatchesTheCapturedShape(t *testing.T) {
	noGunMarker = false
	defer func() { noGunMarker = false }()
	pos := [3]float32{336.83, -5.05, 686.5}
	dir := [3]float32{0.02, -0.004, 3.13}
	marker := nrlGunMarker{
		Position:   [3]float32{336.83, -2.75, 686.5},
		Velocity:   [3]float32{0, 0, 792},
		Dispersion: 0.0036,
	}
	tick := uint32(1126474)
	app := arenaTickApp(tick, pos, dir, 0xC96A7E0B, 0x871958D0, marker, nrlGunMarker{}, false, false,
		100003, 100004, 0x55558004004000, 0x6be7, 0x0103, nil, true)

	// The fixed sizes the client's element table gives these ids. The bare
	// property elements carry exactly their property's declared size: the
	// Avatar's aux word is a UINT64, the Vehicle's gun angles and engine mode
	// are UINT16s.
	size := map[byte]int{0x13: 2, 0x16: 13, 0x1e: 26, 0x1d: 27, 0x1a: 1, 0xba: 9, 0xb4: 3, 0xb6: 3}
	var got []byte
	for i := 0; i < len(app); {
		id := app[i]
		var n int
		if s, ok := size[id]; ok {
			n = s
		} else if id == 0x28 {
			n = 3 + int(binary.LittleEndian.Uint16(app[i+1:i+3]))
		} else {
			t.Fatalf("unexpected element %#02x at offset %d", id, i)
		}
		if i+n > len(app) {
			t.Fatalf("element %#02x at %d overruns the app (%d > %d)", id, i, i+n, len(app))
		}
		got = append(got, id)
		i += n
	}
	// The captured server's own order (14:18:44.647): the player is selected
	// and given its aux word BEFORE the position elements, and the Vehicle's
	// two bare properties follow the `0x1d` that selects its alias. A bare
	// property element carries no entity id, so this order is what decides
	// which entity each one lands on.
	want := []byte{0x13, 0x1a, 0xba, 0x16, 0x1e, 0x1d, 0xb4, 0xb6, 0x28}
	if !bytes.Equal(got, want) {
		t.Fatalf("element sequence %x, want %x", got, want)
	}
	// The TickSync byte is the low byte of the same counter the marker carries.
	if app[1] != byte(tick) {
		t.Errorf("TickSync byte %d, want %d", app[1], byte(tick))
	}
	// The marker carries the full form here, so it ends in the captured suffix.
	markerAt := bytes.IndexByte(app, 0x28)
	if markerAt < 0 {
		t.Fatal("no marker element")
	}
	markerLen := 3 + int(binary.LittleEndian.Uint16(app[markerAt+1:markerAt+3]))
	if got := app[markerAt+markerLen-1]; got != 0x20 {
		t.Errorf("marker does not end in the captured suffix: %x", app[markerAt:markerAt+markerLen])
	}
}

// TestArenaTickAppSendsTheUnchangedMarkerWhenNothingMoved pins the other half:
// an unchanged marker goes out as the 8-byte form, which is 31 B shorter.
func TestArenaTickAppSendsTheUnchangedMarkerWhenNothingMoved(t *testing.T) {
	noGunMarker = false
	defer func() { noGunMarker = false }()
	pos := [3]float32{1, 2, 3}
	dir := [3]float32{0, 0, 0}
	marker := nrlGunMarker{Position: [3]float32{1, 4.3, 3}, Velocity: [3]float32{0, 0, 792}, Dispersion: 0.0036}
	full := arenaTickApp(10, pos, dir, 1, 2, marker, nrlGunMarker{}, false, false, 100003, 100004, 0, 0, 0, nil, false)
	same := arenaTickApp(11, pos, dir, 1, 2, marker, marker, true, false, 100003, 100004, 0, 0, 0, nil, false)
	if len(full)-len(same) != 31 {
		t.Fatalf("unchanged form is %d B shorter, want 31", len(full)-len(same))
	}
	// The unchanged form's kind byte is 0x11, the full one's 0x30. The kind
	// sits 22 B into the element body, and the element is 3 B of header plus
	// its body, so it is at len-3-bodyLen+22 from the end of the app.
	if got := same[len(same)-(3+37)+22]; got != nrlUnrelKindUnchanged {
		t.Errorf("unchanged kind %#02x, want %#02x", got, nrlUnrelKindUnchanged)
	}
	if got := full[len(full)-(3+68)+22]; got != nrlUnrelKindGunMarker {
		t.Errorf("full kind %#02x, want %#02x", got, nrlUnrelKindGunMarker)
	}
}

// TestNrlPropertyUpdateMatchesTheCapturedRecord pins the node-update framing
// against a record from the capture: `26 0c00 00d3 01 08 8035296401030000`
// is `NrlData` (0x26), length 12, then node `00d3` (big-endian), kind 1, a
// one-byte packed length of 8, and 8 bytes of data.
//
// The whole-value form we send is kind 0, so the same shape with `00` for the
// kind: `[node u16 BE][00][packed-u24 len][value]`, wrapped in `0x26` and
// followed by the payload-less `0x25` that consumes it.
func TestNrlPropertyUpdateMatchesTheCapturedRecord(t *testing.T) {
	c := nrlComponent{TypeID: 53, Node: 100, FirstChild: 101, Props: 3, Methods: 2}
	value := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := EncodeNrlPropertyUpdate(c, 1, value)
	if err != nil {
		t.Fatal(err)
	}
	// Property 1's node is FirstChild+1 = 102 = 0x0066, big-endian. The body is
	// node(2) + kind(1) + length(1) + value(4) = 8 bytes.
	want := []byte{
		0x26, 0x08, 0x00, // NrlData, length 8
		0x00, 0x66, // node 102, big-endian
		0x00,                   // kind 0: the whole value
		0x04,                   // packed-u24 length, one byte
		0xde, 0xad, 0xbe, 0xef, // the value
		0x25, // NrlUpdateNodeFlag
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("property update mismatch\n got %x\nwant %x", got, want)
	}
}

// TestNrlNodeIdsFollowTheCreationOrder pins the child numbering: property i's
// node is FirstChild+i and method j's is FirstChild+Props+j, because
// `EncodeNrlAttachComponent` allocates the children in table order.
func TestNrlNodeIdsFollowTheCreationOrder(t *testing.T) {
	c := nrlComponent{TypeID: 53, Node: 100, FirstChild: 101, Props: 3, Methods: 2}
	for i := 0; i < 3; i++ {
		if got, ok := c.propertyNode(i); !ok || got != uint16(101+i) {
			t.Errorf("property %d node = %d (ok %v), want %d", i, got, ok, 101+i)
		}
	}
	if _, ok := c.propertyNode(3); ok {
		t.Error("property 3 exists on a 3-property component")
	}
	for j := 0; j < 2; j++ {
		if got, ok := c.methodNode(j); !ok || got != uint16(104+j) {
			t.Errorf("method %d node = %d (ok %v), want %d", j, got, ok, 104+j)
		}
	}
	if _, ok := c.methodNode(2); ok {
		t.Error("method 2 exists on a 2-method component")
	}
}

// TestNrlAttachComponentReportsItsPlace pins that the creation element and the
// component record agree: the record's FirstChild is the first child the
// creation element allocated.
func TestNrlAttachComponentReportsItsPlace(t *testing.T) {
	alloc := newNrlNodeAlloc()
	props := []nrlProp{{Name: "a", Type: "VEHICLE_GUN_RELOAD_TIME"}, {Name: "b", Type: "VEHICLE_GUN_RELOAD_TIME"}}
	app, c, err := EncodeNrlAttachComponentAt(alloc, 100003, 53, props, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(app) == 0 {
		t.Fatal("no creation element")
	}
	if c.TypeID != 53 || c.Props != 2 || c.Methods != 2 {
		t.Fatalf("component record = %+v", c)
	}
	// The entity node, the component node, then 2 properties + 2 methods + 1
	// trailing child.
	if want := uint16(2 + 2); c.FirstChild != want {
		t.Errorf("FirstChild = %d, want %d", c.FirstChild, want)
	}
	if got, ok := c.propertyNode(1); !ok || got != c.FirstChild+1 {
		t.Errorf("property 1 node = %d (ok %v), want %d", got, ok, c.FirstChild+1)
	}
}

// TestTickEpochIsTheServersUptime pins the tick counter's starting value: it is
// the server's own 10 Hz uptime, never a constant, and never 0.
//
// The counter is the NRL gun marker's `seqNum`, and
// `UnreliableSnapshotBufferReceiver::applyDelta` drops a delta whose seqNum is
// not above the last one it used — which starts at 0 — so a first marker with
// seqNum 0 is rejected and no snapshot is ever created.
func TestTickEpochIsTheServersUptime(t *testing.T) {
	s := &BaseAppServer{}
	// A server that has just started still gets a usable epoch.
	s.startedAt = time.Now()
	if got := s.tickEpoch(); got != 1 {
		t.Errorf("fresh server epoch = %d, want 1", got)
	}
	// An hour of uptime is 36000 ticks at 10 Hz.
	s.startedAt = time.Now().Add(-time.Hour)
	if got := s.tickEpoch(); got < 35999 || got > 36001 {
		t.Errorf("one hour of uptime = %d ticks, want ~36000", got)
	}
	// And it grows with uptime, so two battles never share a seqNum range.
	s.startedAt = time.Now().Add(-2 * time.Hour)
	if got := s.tickEpoch(); got < 71999 || got > 72001 {
		t.Errorf("two hours of uptime = %d ticks, want ~72000", got)
	}
}

// TestOwnVehicleCarriesTheAmmoAndTheReload pins the three values that decide
// whether the gun fires at all.
//
// `AmmoController.canShoot` returns `(False, CANT_SHOOT_ERROR.WAITING)` while
// `__currShellCD` is None, and `__currShellCD` is only ever set from
// `Avatar.__updateVehicleSetting` on `VEHICLE_SETTING.CURRENT_SHELLS` — which
// first requires `ammoCtrl.shellInAmmo(value)`, i.e. the shell must already be
// in `vehicleAmmoList`. Left at their zero values (empty arrays) the client
// refuses every shot before it reaches `cell.vehicle_shoot`, so nothing is sent
// and nothing fires.
func TestOwnVehicleCarriesTheAmmoAndTheReload(t *testing.T) {
	if err := entdef.InitAliasesFromDir("../../scripts-2.4.1/entity_defs"); err != nil {
		t.Skipf("no aliases: %v", err)
	}
	// A real descriptor, so the gun's shell and reload resolve from the defs:
	// the SU-85, whose 85 mm D-5S gives shell CD 101386 and a 4.46 s reload.
	compDescr := []byte{1, 1, 2, 0, 17, 1, 203, 0, 5, 0, 2, 0, 7, 0, 0}
	sp, ok := vehicleGunSpeeds(compDescr)
	if !ok || sp.Dispersion.ShellCD == 0 {
		t.Skip("no gun spec for this descriptor")
	}
	o := ownVehicleOverrides(0x2222, compDescr, nil)

	ammo, ok := o["vehicleAmmoList"]
	if !ok || ammo.Kind != entdef.VSeq || len(ammo.Seq) == 0 {
		t.Fatalf("vehicleAmmoList = %+v, want at least one shell", ammo)
	}
	cd, ok := ammo.Seq[0].Get("compactDescr")
	if !ok || cd.Int != int64(sp.Dispersion.ShellCD) {
		t.Fatalf("ammo compactDescr = %+v, want %d", cd, sp.Dispersion.ShellCD)
	}
	if q, ok := ammo.Seq[0].Get("quantity"); !ok || q.Uint == 0 {
		t.Fatalf("ammo quantity = %+v, want > 0", q)
	}
	if q, ok := ammo.Seq[0].Get("quantityInClip"); !ok || q.Uint == 0 {
		t.Fatalf("ammo quantityInClip = %+v, want > 0 (0 is EMPTY_CLIP)", q)
	}

	set, ok := o["vehicleSettings"]
	if !ok || set.Kind != entdef.VSeq || len(set.Seq) == 0 {
		t.Fatalf("vehicleSettings = %+v, want a CURRENT_SHELLS entry", set)
	}
	if code, ok := set.Seq[0].Get("code"); !ok || code.Uint != 0 {
		t.Fatalf("setting code = %+v, want 0 (VEHICLE_SETTING.CURRENT_SHELLS)", code)
	}
	if v, ok := set.Seq[0].Get("value"); !ok || v.Int != int64(sp.Dispersion.ShellCD) {
		t.Fatalf("setting value = %+v, want the shell CD %d", v, sp.Dispersion.ShellCD)
	}

	rl, ok := o["vehicleGunReloadTime"]
	if !ok {
		t.Fatal("no vehicleGunReloadTime override: the gun would never reload")
	}
	if b, ok := rl.Get("baseTime"); !ok || b.Float <= 0 {
		t.Fatalf("reload baseTime = %+v, want the gun's reloadTime", b)
	}
	if tl, ok := rl.Get("timeLeft"); !ok || tl.Float != 0 {
		t.Fatalf("reload timeLeft = %+v, want 0 (loaded)", tl)
	}
}

// TestArenaTickAppCarriesWheelsScroll pins the wheel element's id, its header
// width and its position in the tick.
//
// `wheelsScroll` is `Tuple[0]{UINT8}` — variable length with a ONE-byte header
// (`VariableLengthHeaderSize` 1 → `ElementLength::Variable8`) — so the element
// is `c2 <len8> <bytes>`. The id is `ENTITY_PROPERTY_BASE + FullIndex` with the
// base at 0xA7 and `wheelsScroll` at FullIndex 27. It has to follow the `0x1d`
// that selects the Vehicle alias, like the other two bare Vehicle properties,
// because a bare element applies to whatever entity was selected last.
func TestArenaTickAppCarriesWheelsScroll(t *testing.T) {
	noGunMarker = true
	vehiclePropsOn = true
	defer func() { noGunMarker = false; vehiclePropsOn = true }()
	pos := [3]float32{1, 2, 3}
	dir := [3]float32{0, 0, 0}
	wheels := []byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87}
	app := arenaTickApp(10, pos, dir, 1, 2, nrlGunMarker{}, nrlGunMarker{}, false, false,
		100003, 100004, 0, 0x6be7, 0x0103, wheels, true)

	size := map[byte]int{0x13: 2, 0x1a: 1, 0xba: 9, 0x16: 13, 0x1e: 26, 0x1d: 27, 0xb4: 3, 0xb6: 3}
	var got []byte
	for i := 0; i < len(app); {
		id := app[i]
		var n int
		if s, ok := size[id]; ok {
			n = s
		} else if id == elVehicleWheelsScroll {
			// `c2 <len8> <count> <count bytes>`: the length covers the count.
			if app[i+1] != byte(1+len(wheels)) {
				t.Fatalf("wheelsScroll length byte %d, want %d", app[i+1], 1+len(wheels))
			}
			if app[i+2] != byte(len(wheels)) {
				t.Fatalf("wheelsScroll count %d, want %d", app[i+2], len(wheels))
			}
			if !bytes.Equal(app[i+3:i+3+len(wheels)], wheels) {
				t.Fatalf("wheelsScroll payload % x, want % x", app[i+3:i+3+len(wheels)], wheels)
			}
			n = 3 + len(wheels)
		} else {
			t.Fatalf("unexpected element %#02x at offset %d", id, i)
		}
		if i+n > len(app) {
			t.Fatalf("element %#02x at %d overruns the app (%d > %d)", id, i, i+n, len(app))
		}
		got = append(got, id)
		i += n
	}
	// The aux word is unconditional, so the player is selected and given it
	// before the position elements; the Vehicle's three follow the `0x1d`.
	want := []byte{0x13, 0x1a, 0xba, 0x16, 0x1e, 0x1d, 0xb4, 0xb6, elVehicleWheelsScroll}
	if !bytes.Equal(got, want) {
		t.Fatalf("element sequence %x, want %x", got, want)
	}
}

// TestSiegeStateStatusUpdateIsWellFormed pins the one message that makes siege
// mode work at all.
//
// `OwnVehicle.siegeStateStatus` is the only route to
// `Avatar.updateSiegeStateStatus` — its setter
// `OwnVehicleBase.update_siegeStateStatus` calls it, and that is not a def
// method. Without it the client's `SiegeModeControl.__currentState` never leaves
// DISABLED (measured live: `Vehicle.siegeState` read 2 while `__currentState`
// was still 0), so the HUD never shows siege, the composite descriptor never
// switches to `VEHICLE_MODE.SIEGE`, and pressing X can only ever ask to ENABLE.
//
// The update is an NRL node record: the node id big-endian, then kind 0 (whole
// value), then the value's length as a packed u24, then the value.
func TestSiegeStateStatusUpdateIsWellFormed(t *testing.T) {
	if err := entdef.InitAliasesFromDir("../../scripts-2.4.1/entity_defs"); err != nil {
		t.Skipf("no aliases: %v", err)
	}
	idx := ownVehiclePropIndex("siegeStateStatus")
	if idx != 10 {
		t.Fatalf("siegeStateStatus index = %d, want 10 (OwnVehicle.def declaration order)", idx)
	}
	dt := entdef.Alias("SIEGE_STATE_STATUS")
	if dt == nil {
		t.Fatal("no SIEGE_STATE_STATUS alias")
	}
	value := entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "status", Value: entdef.Value{Kind: entdef.VUint, Uint: 2}},
		{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat}},
		{Name: "timeLeft", Value: entdef.Value{Kind: entdef.VFloat}},
	}}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, value); err != nil {
		t.Fatal(err)
	}
	// AllowNone presence byte, UINT8 status, two FLOAT32s.
	if buf.Len() != 10 {
		t.Fatalf("encoded value is %d B, want 10", buf.Len())
	}
	if buf.Bytes()[1] != 2 {
		t.Fatalf("status byte = %d, want 2 (ENABLED)", buf.Bytes()[1])
	}
	comp := nrlComponent{TypeID: OwnVehicleNrlID, Node: 7, FirstChild: 8, Props: len(ownVehicleProps)}
	el, err := EncodeNrlPropertyUpdate(comp, idx, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// `0x26 <len16>` wraps the fragment, then the node id (2, big-endian),
	// kind 0 (whole value), the value's length as a packed u24, the value, and
	// finally the `0x25` flag that consumes the record.
	if el[0] != elNrlData {
		t.Fatalf("element id %#02x, want %#02x (NRL data)", el[0], elNrlData)
	}
	wantNode := []byte{byte((8 + idx) >> 8), byte(8 + idx)}
	if !bytes.Equal(el[3:5], wantNode) {
		t.Fatalf("node id % x, want % x", el[3:5], wantNode)
	}
	if el[5] != 0 {
		t.Fatalf("record kind = %d, want 0 (whole value)", el[5])
	}
	if el[6] != 10 {
		t.Fatalf("record length = %d, want 10", el[6])
	}
	if !bytes.Equal(el[7:17], buf.Bytes()) {
		t.Fatalf("record value % x, want % x", el[7:17], buf.Bytes())
	}
	if el[len(el)-1] != elNrlUpdateNodeFlag {
		t.Fatalf("trailing flag %#02x, want %#02x", el[len(el)-1], elNrlUpdateNodeFlag)
	}
}

// TestNrlMarkerBaseIsRepeated pins the fix for a lost base snapshot.
//
// The unreliable stream has no retransmission, and the client drops a packet
// whose "last reliable sequence number" footer does not equal its own counter
// at that instant — a race it cannot avoid. Measured, the first tick of a
// battle was dropped that way, it carried the only base, and every later delta
// then failed with "no base snapshot found". The first few markers therefore
// carry the "first" form (prev_tick 0, flags 0) even when the marker has not
// moved, so one lost packet costs nothing.
func TestNrlMarkerBaseIsRepeated(t *testing.T) {
	m := nrlGunMarker{Position: [3]float32{1, 2, 3}, Dispersion: 0.1}
	short, err := nrlMarkerElement(1, 2, 100, m, m, true, false)
	if err != nil {
		t.Fatalf("unchanged: %v", err)
	}
	full, err := nrlMarkerElement(1, 2, 100, m, m, true, true)
	if err != nil {
		t.Fatalf("forced base: %v", err)
	}
	if len(full) <= len(short) {
		t.Fatalf("forced base is %d B, the unchanged form %d B: the base was not resent", len(full), len(short))
	}
	// Body: [06 00 01][idA][idB][tick][prev][kind][class tag 6][flags][00][len][payload]
	if prev := binary.LittleEndian.Uint32(full[3+15 : 3+19]); prev != 0 {
		t.Fatalf("prev_tick = %d, want 0 (a base snapshot)", prev)
	}
	if flags := full[3+26]; flags != 0 {
		t.Fatalf("flags = %#x, want 0 (a base snapshot)", flags)
	}
	// The unchanged form keeps the previous-tick flag.
	if flags := short[3+26]; flags != nrlUnrelFlagsPrev {
		t.Fatalf("unchanged flags = %#x, want %#x", flags, nrlUnrelFlagsPrev)
	}
}
