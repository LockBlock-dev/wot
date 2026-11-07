package login

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// The client's bundle reader, re-implemented strictly.
//
// `UDPBundleProcessor::iterator::unpack` walks a bundle's app as a
// sequence of Mercury messages: `[id][payload]` for a FIXED-size message,
// `[id][len of the declared width][payload]` for a variable one. It has no
// way to resynchronise, so a stray length field is read as the next id —
// `00` is `authenticate`, which wants a 4-byte key, and the bundle dies
// with "Not enough data on stream ... needed 4" / "Got corrupted message
// header" / REASON_CORRUPTED_PACKET.
//
// This parser fails on exactly that, so the queue → arena handoff can be
// checked offline instead of by crashing a client.

// enableWireCheck makes every packet this server emits go through the
// client's bundle reader, so any test that drives the handoff also proves
// the client can consume it.
func enableWireCheck(t *testing.T, s *BaseAppServer) {
	t.Helper()
	d := s.cfg.Dispatch
	if d == nil {
		return
	}
	WireCheck = func(app []byte) error {
		if err := CheckClientApp(d, app); err != nil {
			t.Errorf("the client would drop this bundle: %v (app % x)", err, app)
		}
		return nil
	}
	t.Cleanup(func() { WireCheck = nil })
}

// parseClientPacket decrypts one server packet and walks its app.
func parseClientPacket(t *testing.T, d *entdef.Dispatch, pkt []byte, key string) []clientMsg {
	t.Helper()
	app := findAppInPacket(t, pkt, key)
	if app == nil {
		t.Fatalf("packet has no app: % x", pkt)
	}
	msgs, err := ParseClientApp(d, app)
	if err != nil {
		t.Fatalf("the client would drop this bundle: %v (app % x)", err, app)
	}
	return msgs
}

// TestArenaHandoffIsConsumedExactly is the whole queue → arena chain read
// back the way the client reads it: every packet the server emits on the
// way into the battle must be consumed to its last byte, with no unknown
// element and no leftover length field.
func TestArenaHandoffIsConsumedExactly(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef", entityID: 0x1234}
	h := &ArenaHandoff{
		ArenaID:     9,
		SpaceID:     9,
		ArenaTypeID: 1,
		Map:         "spaces/01_karelia",
		Player:      ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID:   0x2222,
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

	// Step 1: onArenaCreated, then the entity reset.
	tr := &fakeTransport{}
	if err := s.enterArena(tr, addr, st, h); err != nil {
		t.Fatalf("enterArena: %v", err)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d packets, want 2", len(tr.writes))
	}
	first := parseClientPacket(t, d, tr.writes[0], st.blockKey)
	if len(first) != 2 || first[0].ID != elTickSync || first[1].ID != entityMethodBase {
		t.Fatalf("onArenaCreated packet = %v, want tick + onArenaCreated", ids(first))
	}
	if len(first[1].Body) != 0 {
		t.Fatalf("onArenaCreated carries %d B, want 0", len(first[1].Body))
	}
	second := parseClientPacket(t, d, tr.writes[1], st.blockKey)
	if len(second) != 2 || second[1].ID != elResetEntities || len(second[1].Body) != 1 || second[1].Body[0] != 0 {
		t.Fatalf("reset packet = %v, want tick + resetEntities(false)", ids(second))
	}

	// Step 2: the Avatar, the geometry mapping, the cell player.
	tr2 := &fakeTransport{}
	if _, err := s.enterArenaEntities(tr2, addr, st, h, 10, 10); err != nil {
		t.Fatalf("enterArenaEntities: %v", err)
	}
	// The Avatar goes out alone; the rest waits for the client's socket
	// rebind, which is what the genuine server does.
	if len(tr2.writes) != 1 {
		t.Fatalf("%d packets, want 1 (the Avatar)", len(tr2.writes))
	}
	tr3 := &fakeTransport{}
	if _, err := s.enterArenaSpace(tr3, addr, st, h, 11, 10); err != nil {
		t.Fatalf("enterArenaSpace: %v", err)
	}
	// space, cell, Vehicle create/select/update/enter, AvatarInfo
	// create/enter/NRL, OwnVehicle, selectEntity(Avatar), the hull attitude,
	// the update frequency, then the period change.
	if len(tr3.writes) != 14 {
		t.Fatalf("%d packets, want 14", len(tr3.writes))
	}
	avatar := parseClientPacket(t, d, tr2.writes[0], st.blockKey)
	avatar = withoutTick(avatar)
	if len(avatar) != 1 || avatar[0].ID != elCreateBasePlayer {
		t.Fatalf("avatar packet = %v, want createBasePlayer", ids(avatar))
	}
	tr2 = tr3
	// The player's Vehicle: created empty, brought into the AoI, then given
	// its cell properties.
	// A vehicle is created with `createEntity` (0x0B), the aliased form: the
	// genuine server creates it with an alias, and that is the element it uses.
	create := withoutTick(parseClientPacket(t, d, tr2.writes[2], st.blockKey))
	if len(create) != 1 || create[0].ID != elCreateEntity {
		t.Fatalf("vehicle create = %v, want createEntity", ids(create))
	}
	if got := binary.LittleEndian.Uint32(create[0].Body[1:5]); got != h.VehicleID {
		t.Fatalf("vehicle id = %d, want %d", got, h.VehicleID)
	}
	if got, want := binary.LittleEndian.Uint16(create[0].Body[5:7]), uint16(d.Entity("Vehicle").TypeID); got != want {
		t.Fatalf("vehicle type id = %d, want %d", got, want)
	}
	// The volatile packer type is a string right after the resource name;
	// the client drops the connection on anything but "bw.default".
	if !bytes.Contains(create[0].Body, append([]byte{byte(len(VolatilePackerType))}, VolatilePackerType...)) {
		t.Fatalf("createEntityDetailed carries no %q packer type: % x", VolatilePackerType, create[0].Body)
	}
	// createEntityDetailed carries the client-server property run, which is
	// where the client builds the tank from.
	if !bytes.Contains(create[0].Body, h.Player.VehicleCompDescr) {
		t.Fatalf("createEntityDetailed carries no compact descriptor: % x", create[0].Body)
	}

	sel := withoutTick(parseClientPacket(t, d, tr2.writes[3], st.blockKey))
	if len(sel) != 1 || sel[0].ID != elSelectEntity || len(sel[0].Body) != 4 {
		t.Fatalf("selectEntity = %v, want a 4-byte selectEntity", ids(sel))
	}
	if got := binary.LittleEndian.Uint32(sel[0].Body); got != h.VehicleID {
		t.Fatalf("selectEntity id = %d, want %d", got, h.VehicleID)
	}
	update := withoutTick(parseClientPacket(t, d, tr2.writes[4], st.blockKey))
	if len(update) != 1 || update[0].ID != elUpdateEntity {
		t.Fatalf("updateEntity = %v, want updateEntity", ids(update))
	}
	// The client builds the tank from publicInfo.compDescr, which rides this
	// run; an empty one raises IndexError in Vehicle.onEnterWorld.
	if !bytes.Contains(update[0].Body, h.Player.VehicleCompDescr) {
		t.Fatalf("updateEntity carries no compact descriptor: % x", update[0].Body)
	}
	enter := withoutTick(parseClientPacket(t, d, tr2.writes[5], st.blockKey))
	if len(enter) != 1 || enter[0].ID != elEnterAoI || len(enter[0].Body) != 5 {
		t.Fatalf("vehicle enterAoI = %v, want a 5-byte enterAoI", ids(enter))
	}
	// updateEntity carries no entity id: it applies to the selected entity.
	// It carries the detail-level half of the table, not all of it — the
	// outer half rode createEntityDetailed.
	wantInner := 0
	for _, p := range d.Entity("Vehicle").Properties {
		if p.DetailLevel != "" {
			wantInner++
		}
	}
	if n := int(update[0].Body[0]); n != wantInner {
		t.Fatalf("updateEntity count = %d, want %d (the detail-level properties)", n, wantInner)
	}

	// CreateBasePlayer: [entityID u32][typeID u16][00][base props][components u8].
	body := avatar[0].Body
	if len(body) < 8 {
		t.Fatalf("createBasePlayer body is %d B, too short", len(body))
	}
	if got := binary.LittleEndian.Uint32(body); got != st.entityID {
		t.Fatalf("entity id = %d, want %d", got, st.entityID)
	}
	if n := body[len(body)-1]; n != AvatarComponents {
		t.Fatalf("component count = %d, want %d", n, AvatarComponents)
	}
	space := withoutTick(parseClientPacket(t, d, tr2.writes[1], st.blockKey))
	if len(space) != 1 || space[0].ID != elAddSpaceGeometryMapping {
		t.Fatalf("space packet = %v, want addSpaceGeometryMapping", ids(space))
	}
	// [spaceID u32][entryID 8B][path varstr][transform 64B][unk u8]
	if got := binary.LittleEndian.Uint32(space[0].Body[:4]); got != h.SpaceID {
		t.Fatalf("geometry space id = %d, want %d", got, h.SpaceID)
	}
	if !bytes.Contains(space[0].Body, []byte(h.Map)) {
		t.Fatalf("geometry carries no path: % x", space[0].Body)
	}
	cell := withoutTick(parseClientPacket(t, d, tr2.writes[0], st.blockKey))
	if len(cell) != 1 || cell[0].ID != elCreateCellPlayer {
		t.Fatalf("cell packet = %v, want createCellPlayer", ids(cell))
	}
	// The cell player's header is the WoT fork's 39 bytes; the props follow
	// with no count, so the body must be strictly longer than the header.
	const cellHeader = 1 + 4 + 2 + 4 + 12 + 4 + 12
	if len(cell[0].Body) <= cellHeader {
		t.Fatalf("createCellPlayer body is %d B, want more than the %d B header", len(cell[0].Body), cellHeader)
	}
	if got := binary.LittleEndian.Uint32(cell[0].Body[1:5]); got != h.SpaceID {
		t.Fatalf("cell space id = %d, want %d", got, h.SpaceID)
	}
	if got := binary.LittleEndian.Uint32(cell[0].Body[7:11]); got != h.VehicleID {
		t.Fatalf("cell vehicle id = %d, want %d", got, h.VehicleID)
	}
}

// TestQueueAnswersAreConsumedExactly reads the matchmaker answers back the
// same way: onEnqueued and onDequeued are fixed-size, so they must carry
// no length field.
func TestQueueAnswersAreConsumedExactly(t *testing.T) {
	q := &fakeQueue{result: QueueResult{Added: 1}}
	s := queueServer(t, q)
	d := s.cfg.Dispatch
	veh := lobby.AllOwnableVehicles[0].CompDescr
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		garage: []GarageItem{{InvID: 42, CompactDescr: veh}},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}

	call := queueCall(t, s, "doCmdIntArr",
		entdef.Value{Kind: entdef.VInt, Int: 202},
		entdef.Value{Kind: entdef.VInt, Int: 700},
		intArr(1, 42, 0, 0, 0),
	)
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, addr, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d packets, want 1", len(tr.writes))
	}
	msgs := parseClientPacket(t, d, tr.writes[0], st.blockKey)
	if len(msgs) != 2 || msgs[1].ID != clientElemID(t, s, "onEnqueued") {
		t.Fatalf("enqueue answer = %v, want tick + onEnqueued", ids(msgs))
	}
	if len(msgs[1].Body) != 1 || msgs[1].Body[0] != 1 {
		t.Fatalf("onEnqueued body = % x, want 01", msgs[1].Body)
	}
}

// withoutTick drops a leading tickSync, which the server may or may not
// prepend to a packet.
func withoutTick(msgs []clientMsg) []clientMsg {
	if len(msgs) > 0 && msgs[0].ID == elTickSync {
		return msgs[1:]
	}
	return msgs
}

// ids renders a message list for a failure message.
func ids(msgs []clientMsg) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%#02x(%dB)", m.ID, len(m.Body))
	}
	return out
}
