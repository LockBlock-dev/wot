package login

import (
	"bytes"
	"net"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// fakeCrew records the calls and returns a fixed result.
type fakeCrew struct {
	calls  []string
	result CrewResult
	veh    int64
	slot   int
	tman   int64
}

func (f *fakeCrew) EquipCrew(_ int64, vehInvID int64, slot int, tmanInvID int64) CrewResult {
	f.calls = append(f.calls, "equip")
	f.veh, f.slot, f.tman = vehInvID, slot, tmanInvID
	return f.result
}

// crewServer builds a server with the Account dispatch and a fake crew
// backend.
func crewServer(t *testing.T, crew CrewBackend) *BaseAppServer {
	t.Helper()
	s := tokenTestServer(t, nil)
	s.cfg.Crew = crew
	return s
}

// equipTmanCall builds the CMD_EQUIP_TMAN call the client sends:
// doCmdIntArr(105, [vehInvID, slot, tmanInvID, groupID, groupSize]).
func equipTmanCall(t *testing.T, s *BaseAppServer, req int64, vehInvID, slot, tmanInvID int64) postCall {
	t.Helper()
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, "doCmdIntArr")
	if m == nil {
		t.Fatal("no doCmdIntArr in the Account base methods")
	}
	seq := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VInt, Int: vehInvID},
		{Kind: entdef.VInt, Int: slot},
		{Kind: entdef.VInt, Int: tmanInvID},
		{Kind: entdef.VInt, Int: 0},
		{Kind: entdef.VInt, Int: 1},
	}}
	return postCall{
		Method: m,
		Req:    uint16(req),
		Cmd:    105,
		Args: []entdef.Value{
			{Kind: entdef.VInt, Int: req},
			{Kind: entdef.VInt, Int: 105},
			seq,
		},
	}
}

// TestEquipTmanAnswersAndPushes checks the two-part answer: the command
// response clears the client's request, then Account.update carries the new
// crew list and the tankman's vehicle.
func TestEquipTmanAnswersAndPushes(t *testing.T) {
	crew := &fakeCrew{result: CrewResult{
		Vehicles: map[int64][]int64{7: {0, 42, 0, 0, 0}},
		Tankmen:  map[int64]int64{42: 7},
	}}
	s := crewServer(t, crew)
	call := equipTmanCall(t, s, 9, 7, 1, 42)
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		garage: []GarageItem{{InvID: 7, CompactDescr: []byte{1, 1, 2}}},
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerPostCall(tr, addr, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(crew.calls) != 1 {
		t.Fatalf("calls = %v", crew.calls)
	}
	if crew.veh != 7 || crew.slot != 1 || crew.tman != 42 {
		t.Fatalf("backend got veh=%d slot=%d tman=%d, want 7/1/42", crew.veh, crew.slot, crew.tman)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2 (response + push)", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if !bytes.Contains(app, []byte{0x1a, smallRevisions}) {
		t.Fatalf("first write is not a command response: % x", app)
	}
	push := findAppInPacket(t, tr.writes[1], st.blockKey)
	for _, want := range []string{"prevRev", "rev", "inventory", "crew", "vehicle"} {
		if !bytes.Contains(push, []byte(want)) {
			t.Fatalf("push is missing %q: % x", want, push)
		}
	}
	// The session's copy must follow, or a later full sync would serve the
	// old crew back.
	if got := st.garage[0].Crew; len(got) != 5 || got[1] != 42 {
		t.Fatalf("session crew = %v, want slot 1 = 42", got)
	}
}

// TestEquipTmanFailureSendsNoPush checks that a refused assignment answers
// with the negative result and pushes nothing.
func TestEquipTmanFailureSendsNoPush(t *testing.T) {
	crew := &fakeCrew{result: CrewResult{Code: -1, Message: "no such vehicle"}}
	s := crewServer(t, crew)
	call := equipTmanCall(t, s, 10, 99, 0, 42)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes, want 1 (response only)", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if !bytes.Contains(app, []byte("no such vehicle")) {
		t.Fatalf("response is missing the error text: % x", app)
	}
}

// TestEquipTmanNoBackendIsSilent checks that a server without a crew
// backend leaves the command unanswered rather than answering wrongly.
func TestEquipTmanNoBackendIsSilent(t *testing.T) {
	s := tokenTestServer(t, nil)
	call := equipTmanCall(t, s, 11, 7, 0, 42)
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 0 {
		t.Fatalf("%d writes, want 0", len(tr.writes))
	}
}

// TestEquipTmanReadsArrayFromBody pins the fallback: when the element id
// lands on a method that is not doCmdIntArr, the array is read off the body
// instead of the command being dropped.
func TestEquipTmanReadsArrayFromBody(t *testing.T) {
	crew := &fakeCrew{result: CrewResult{
		Vehicles: map[int64][]int64{7: {0, 42}},
		Tankmen:  map[int64]int64{42: 7},
	}}
	s := crewServer(t, crew)
	// The element id maps to doCmdInt2Str, whose reader yields no array.
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, "doCmdInt2Str")
	if m == nil {
		t.Fatal("no doCmdInt2Str in the Account base methods")
	}
	body := []byte{9, 0, 105, 0, 5}
	for _, v := range []int32{7, 1, 42, 0, 1} {
		body = append(body, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	call := postCall{
		Method: m,
		Req:    9,
		Cmd:    105,
		Elem:   0x9e,
		Body:   body,
		Args: []entdef.Value{
			{Kind: entdef.VInt, Int: 9},
			{Kind: entdef.VInt, Int: 105},
			{Kind: entdef.VInt, Int: 7},
			{Kind: entdef.VInt, Int: 1},
		},
	}
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if crew.veh != 7 || crew.slot != 1 || crew.tman != 42 {
		t.Fatalf("backend got veh=%d slot=%d tman=%d, want 7/1/42", crew.veh, crew.slot, crew.tman)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2 (response + push)", len(tr.writes))
	}
}

// TestInt32ArrayBody pins the wire shape: [req u16][cmd u16][count][i32…].
func TestInt32ArrayBody(t *testing.T) {
	body := []byte{1, 0, 105, 0, 3}
	for _, v := range []int32{5, -1, 70000} {
		body = append(body, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	got := int32ArrayBody(body)
	want := []int64{5, -1, 70000}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if int32ArrayBody([]byte{1, 0, 105, 0}) != nil {
		t.Fatal("a truncated body must not decode")
	}
	if int32ArrayBody([]byte{1, 0, 105, 0, 9, 0, 0}) != nil {
		t.Fatal("a count past the body must not decode")
	}
}

// TestPadCrew pins the length rule: the client's VehicleDescrCrew raises
// `wrong number or tankmen` unless the list is exactly the vehicle's slot
// count, so a short list is padded with empty slots and a long one is cut.
func TestPadCrew(t *testing.T) {
	if got := PadCrew([]int64{42}, 4); len(got) != 4 || got[0] != 42 || got[1] != 0 {
		t.Fatalf("PadCrew([42], 4) = %v", got)
	}
	if got := PadCrew(nil, 3); len(got) != 3 {
		t.Fatalf("PadCrew(nil, 3) = %v", got)
	}
	if got := PadCrew([]int64{1, 2, 3, 4, 5}, 2); len(got) != 2 {
		t.Fatalf("PadCrew(5 entries, 2) = %v", got)
	}
	// An unknown size leaves the list alone: the client then falls back to
	// its own all-empty default.
	if got := PadCrew([]int64{7}, 0); len(got) != 1 || got[0] != 7 {
		t.Fatalf("PadCrew([7], 0) = %v", got)
	}
}

// TestInventoryPadsCrew checks the sync document: a vehicle with one
// assigned slot must still carry a full-length list.
func TestInventoryPadsCrew(t *testing.T) {
	s := tokenTestServer(t, nil)
	st := &clientState{
		garage: []GarageItem{{
			InvID:        7,
			CompactDescr: []byte{1, 1, 2},
			Crew:         []int64{42},
			CrewSize:     4,
		}},
	}
	inv := s.inventory(st)
	veh, ok := inv[lobby.ItemVehicle].(map[string]any)
	if !ok {
		t.Fatalf("vehicle section = %T", inv[lobby.ItemVehicle])
	}
	crew, ok := veh["crew"].(map[int64]any)
	if !ok {
		t.Fatalf("crew = %T", veh["crew"])
	}
	list, ok := crew[7].([]any)
	if !ok {
		t.Fatalf("crew[7] = %T", crew[7])
	}
	if len(list) != 4 || list[0] != int64(42) {
		t.Fatalf("crew[7] = %v, want 4 slots with 42 first", list)
	}
	// An empty slot must be None, not 0: `Vehicle._buildCrew` looks every
	// non-None id up in the tankman inventory and raises on the miss.
	for i := 1; i < len(list); i++ {
		if list[i] != nil {
			t.Fatalf("crew[7][%d] = %v, want nil", i, list[i])
		}
	}
}

// TestCrewNodeEmitsNoneForEmptySlots pins the wire shape of one list.
func TestCrewNodeEmitsNoneForEmptySlots(t *testing.T) {
	got := CrewNode([]int64{0, 42, 0}, 3)
	if len(got) != 3 {
		t.Fatalf("CrewNode = %v", got)
	}
	if got[0] != nil || got[1] != int64(42) || got[2] != nil {
		t.Fatalf("CrewNode = %v, want [nil 42 nil]", got)
	}
}

// fakeLayouts records the call and returns a fixed result.
type fakeLayouts struct {
	shells, eqs []int64
	veh         int64
	result      LayoutResult
}

func (f *fakeLayouts) SetLayouts(_ int64, vehInvID int64, shells, eqs []int64) LayoutResult {
	f.veh, f.shells, f.eqs = vehInvID, shells, eqs
	return f.result
}

// TestSetAndFillLayoutsAnswersAndPushes checks the ammo panel's command: the
// answer clears the pending request and the push carries the layout back.
func TestSetAndFillLayoutsAnswersAndPushes(t *testing.T) {
	lay := &fakeLayouts{result: LayoutResult{
		Vehicle: 7,
		Turret:  2034,
		Gun:     203,
		Shells:  []int64{100, 30, 200, 15},
	}}
	s := tokenTestServer(t, nil)
	s.cfg.Layouts = lay
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, "doCmdIntArr")
	if m == nil {
		t.Fatal("no doCmdIntArr")
	}
	// [shopRev, vehInvID, nShells, cd, count, cd, count, equipmentType, nEqs]
	vals := []int64{1, 7, 4, 100, 30, 200, 15, 0, 0}
	seq := entdef.Value{Kind: entdef.VSeq}
	for _, v := range vals {
		seq.Seq = append(seq.Seq, entdef.Value{Kind: entdef.VInt, Int: v})
	}
	call := postCall{
		Method: m, Req: 12, Cmd: 108,
		Args: []entdef.Value{
			{Kind: entdef.VInt, Int: 12},
			{Kind: entdef.VInt, Int: 108},
			seq,
		},
	}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		garage: []GarageItem{{InvID: 7, CompactDescr: []byte{1, 1, 2}}},
	}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if lay.veh != 7 {
		t.Fatalf("vehicle = %d, want 7", lay.veh)
	}
	if len(lay.shells) != 4 || lay.shells[0] != 100 || lay.shells[3] != 15 {
		t.Fatalf("shells = %v", lay.shells)
	}
	if lay.eqs != nil {
		t.Fatalf("eqs = %v, want nil for a zero count", lay.eqs)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2 (response + push)", len(tr.writes))
	}
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if !bytes.Contains(app, []byte{0x1a, smallRevisions}) {
		t.Fatalf("first write is not a command response: % x", app)
	}
	if !bytes.Contains(app, []byte("shells")) {
		t.Fatalf("response ext is missing the purchase list: % x", app)
	}
	push := findAppInPacket(t, tr.writes[1], st.blockKey)
	for _, want := range []string{"prevRev", "inventory", "shellsLayout", "shells"} {
		if !bytes.Contains(push, []byte(want)) {
			t.Fatalf("push is missing %q: % x", want, push)
		}
	}
	if got := st.garage[0].Shells; len(got) != 4 || got[0] != 100 {
		t.Fatalf("session shells = %v", got)
	}
}

// TestFirstElement pins where a post-flood bundle's elements start: a
// running client prefixes its bundle with `02` and the channel key, and the
// elements begin at 7; the first bundle after the flood has no prefix and
// they begin at 2. Reading the wrong offset misses every `enableEntities`
// that carries the prefix, which leaves the client waiting for its entity.
func TestFirstElement(t *testing.T) {
	const key = 0x231f061f
	// A prefixed bundle: flags, 02, key, then the element.
	prefixed := []byte{0x58, 0x04, 0x02, 0x1f, 0x06, 0x1f, 0x23, 0x0b}
	// Eight trailer bytes for flags 0x0458.
	prefixed = append(prefixed, make([]byte, 8)...)
	if got, ok := firstElement(prefixed, key); !ok || got != 0x0b {
		t.Fatalf("prefixed first element = %#02x (ok %v), want 0x0b", got, ok)
	}
	// An unprefixed bundle: flags, then the element.
	plain := []byte{0x58, 0x04, 0x0b}
	plain = append(plain, make([]byte, 8)...)
	if got, ok := firstElement(plain, key); !ok || got != 0x0b {
		t.Fatalf("plain first element = %#02x (ok %v), want 0x0b", got, ok)
	}
	// A different key is not the prefix.
	other := []byte{0x58, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0b}
	other = append(other, make([]byte, 8)...)
	if got, ok := firstElement(other, key); !ok || got != 0x02 {
		t.Fatalf("mismatched key first element = %#02x (ok %v), want 0x02", got, ok)
	}
}
