package login

import (
	"bytes"
	"net"
	"os"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
)

func enterTestServer(t *testing.T) *BaseAppServer {
	t.Helper()
	const defs = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
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

// TestEnterAccountSendsTheSequence pins the three messages the reference's
// capture shows: the Account entity, SelectPlayerEntity, then showGUI.
func TestEnterAccountSendsTheSequence(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{entityID: 0x1234, name: "playerone", blockKey: "0123456789abcdef"}

	tr := &fakeTransport{}
	if err := s.enterAccount(tr, addr, st); err != nil {
		t.Fatalf("enterAccount: %v", err)
	}
	if len(tr.writes) != 3 {
		t.Fatalf("%d packets, want 3 (CreateBasePlayer, SelectPlayerEntity, showGUI)", len(tr.writes))
	}

	// Decrypt each and check the element it carries.
	want := []byte{elCreateBasePlayer, elSelectPlayerEntity, byte(entityMethodBase + 40)}
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

	// The first is a decodable Account entity with the capture's component
	// count.
	clear, err := decryptBlowfish(st.blockKey, tr.writes[0][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err := frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
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

	// SelectPlayerEntity is FIXED 0: one byte, no payload.
	clear, err = decryptBlowfish(st.blockKey, tr.writes[1][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err = frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	if len(app) != 1 {
		t.Errorf("SelectPlayerEntity is %d B, want 1", len(app))
	}

	// showGUI is a client method call with a 2-byte string length header.
	clear, err = decryptBlowfish(st.blockKey, tr.writes[2][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err = frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	if n := int(app[1]) | int(app[2])<<8; n != 2 {
		t.Errorf("showGUI payload = %d B, want 2 (a 2-byte empty string)", n)
	}
}

// TestEnterAccountIsOnce keeps a repeated enableEntities from creating a
// second entity.
func TestEnterAccountIsOnce(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{entityID: 1, name: "x", blockKey: "0123456789abcdef"}

	tr := &fakeTransport{}
	if err := s.enterAccount(tr, addr, st); err != nil {
		t.Fatal(err)
	}
	first := len(tr.writes)
	if err := s.enterAccount(tr, addr, st); err != nil {
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
	if err := s.enterAccount(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&clientState{entityID: 1, blockKey: "0123456789abcdef"}); err != nil {
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
