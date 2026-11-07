package login

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

func enterTestServer(t *testing.T) *BaseAppServer {
	t.Helper()
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	return &BaseAppServer{
		cfg: BaseAppConfig{
			Dispatch:          d,
			CreateBasePlayer:  true,
			AccountComponents: 19,
		},
		resend:     newResendQueue(400*time.Millisecond, 20*time.Second),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
}

// TestEnterAccountSendsTheSequence pins the carrier-less path: the Account
// entity, then ONE frame carrying `selectPlayerEntity + showGUI` in the
// genuine framing `[1a][76][u16 elementLen][u8 stringLen][pickle]`. The
// flood bundle normally creates the entity AND sends that same pair as the
// session-dict frame, so the post-flood call passes false and sends
// nothing.
func TestEnterAccountSendsTheSequence(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{entityID: 0x1234, name: "playerone", blockKey: "0123456789abcdef"}

	tr := &fakeTransport{}
	if _, err := s.enterAccount(tr, addr, st, 3, 0, true); err != nil {
		t.Fatalf("enterAccount: %v", err)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d packets, want 2 (CreateBasePlayer, selectPlayerEntity + showGUI)", len(tr.writes))
	}

	// Decrypt each and check the element it carries.
	//
	// The second packet opens with a `0x13` TickSync head, exactly as
	// `serveBulk` frames the same `1a/76` small on a fresh login
	// (`EncodeTickSync(0x40) + dict`) and as `answerApp` frames every other
	// stage-2 datagram. Sent bare, the client refuses it: after a
	// `leaveArena` it ACKs `CreateBasePlayer` and then never ACKs this one,
	// logging `REASON_GENERAL_NETWORK` and dropping to
	// `HANGAR LOADING STATE: DISCONNECTED`.
	want := []byte{0x13, 0x13}
	for i, pkt := range tr.writes {
		clear, err := decryptBlowfish(st.blockKey, pkt[4:])
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		app, err := frameApp(clear)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if len(app) == 0 || app[0] != want[i] {
			t.Fatalf("packet %d element = %#02x, want %#02x", i, app[0], want[i])
		}
	}
	// And the selectPlayerEntity must still follow the head.
	clear, err := decryptBlowfish(st.blockKey, tr.writes[1][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err := frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	if len(app) < 3 || app[2] != elSelectPlayerEntity {
		t.Fatalf("second packet = % x, want a 0x13 head then %#02x", app, elSelectPlayerEntity)
	}

	// The first is a decodable Account entity with the capture's component
	// count. Skip its two-byte `0x13` head.
	clear, err = decryptBlowfish(st.blockKey, tr.writes[0][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err = frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	app = app[2:]
	back, err := DecodeCreateBasePlayer(app, s.cfg.Dispatch)
	if err != nil {
		t.Fatalf("DecodeCreateBasePlayer: %v", err)
	}
	if back.ID != 0x1234 || back.Props["name"].Str != "playerone" {
		t.Errorf("entity = %+v", back)
	}
	// The component count is the last byte of the element.
	if got := app[len(app)-1]; got != 19 {
		t.Errorf("component count = %d, want 19", got)
	}

	// The second frame is `selectPlayerEntity` (FIXED 0, one byte) followed
	// by showGUI, whose STRING argument is a pickled dict: the client does
	// `pickle.loads(ctx)` and reads databaseID out of it, so an empty
	// string raises inside the handler. The method's
	// VariableLengthHeaderSize is the ELEMENT length width; the string's
	// own header is one byte.
	clear, err = decryptBlowfish(st.blockKey, tr.writes[1][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err = frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	// Skip the two-byte `0x13` tick head.
	app = app[2:]
	if len(app) < 4 || app[0] != elSelectPlayerEntity {
		t.Fatalf("frame % x, want a leading selectPlayerEntity", app)
	}
	if app[1] != byte(entityMethodBase+40) {
		t.Fatalf("showGUI element %#02x, want %#02x", app[1], byte(entityMethodBase+40))
	}
	n := int(app[2]) | int(app[3])<<8
	strLen := int(app[4])
	if n != 1+strLen {
		t.Fatalf("showGUI element length %d, string length %d (want 1+%d)", n, strLen, strLen)
	}
	if got, want := 5+strLen, len(app); got != want {
		t.Fatalf("showGUI string ends at %d, element ends at %d", got, want)
	}
	stk, _, err := lobby.DecodePrefix(app[5 : 5+strLen])
	if err != nil {
		t.Fatalf("showGUI arg pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("showGUI arg is %T, want *PDict", stk[len(stk)-1])
	}
	found := false
	for _, e := range d.Entries {
		if k, isStr := e.Key.(string); isStr && k == "databaseID" {
			found = true
		}
	}
	if !found {
		t.Fatalf("showGUI arg has no databaseID: %v", d.Entries)
	}
}

// TestEnterAccountIsOnce keeps a repeated enableEntities from creating a
// second entity.
func TestEnterAccountIsOnce(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{entityID: 1, name: "x", blockKey: "0123456789abcdef"}

	tr := &fakeTransport{}
	if _, err := s.enterAccount(tr, addr, st, 3, 0, true); err != nil {
		t.Fatal(err)
	}
	first := len(tr.writes)
	if _, err := s.enterAccount(tr, addr, st, 6, 0, true); err != nil {
		t.Fatal(err)
	}
	if len(tr.writes) != first {
		t.Fatalf("%d packets after a repeat, want %d", len(tr.writes), first)
	}
}

// TestEnterAccountIsOffByDefault keeps the flag honest.
func TestEnterAccountIsOffByDefault(t *testing.T) {
	s := enterTestServer(t)
	s.cfg.CreateBasePlayer = false
	tr := &fakeTransport{}
	if _, err := s.enterAccount(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&clientState{entityID: 1, blockKey: "0123456789abcdef"}, 3, 0, true); err != nil {
		t.Fatal(err)
	}
	if len(tr.writes) != 0 {
		t.Fatalf("%d packets with the flag off", len(tr.writes))
	}
}

// TestShowGUIUsesTheMethodsVarLen is the encoding bug the reference
// exposed: showGUI's STRING arg has a 2-byte length header, so an empty
// string is two bytes, not one.
func TestShowGUIUsesTheMethodsVarLen(t *testing.T) {
	s := enterTestServer(t)
	acct := s.cfg.Dispatch.Entity("Account")
	m := acct.MethodByName(entdef.CompClient, "showGUI")
	if m == nil {
		t.Fatal("no showGUI")
	}
	if m.Length.Fixed || m.Length.Var != 2 {
		t.Fatalf("showGUI length = %s, want var2", m.Length)
	}
	if c := m.Codec(); c.VarLen != 2 {
		t.Errorf("showGUI codec VarLen = %d, want 2", c.VarLen)
	}
	call, err := s.accountCall("showGUI", entdef.Value{Kind: entdef.VString, Str: ""})
	if err != nil {
		t.Fatal(err)
	}
	// [id][len u16][2-byte string length]
	if !bytes.Equal(call[3:], []byte{0, 0}) {
		t.Errorf("showGUI payload = % x, want 00 00", call[3:])
	}
}
