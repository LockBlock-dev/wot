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

// TestEnterAccountSendsTheSequence pins the carrier-less path: ONE packet
// carrying the Account entity and then `selectPlayerEntity + showGUI` in the
// genuine framing `[1a][76][u16 elementLen][u8 stringLen][pickle]`. The
// client's `LoginReplyFilter` only passes the login-reply packet, so the two
// must not be split. The flood bundle normally creates the entity AND sends
// that same pair as the session-dict frame, so the post-flood call passes
// false and sends nothing.
func TestEnterAccountSendsTheSequence(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{entityID: 0x1234, name: "playerone", blockKey: "0123456789abcdef"}

	tr := &fakeTransport{}
	if _, err := s.enterAccount(tr, addr, st, 3, 0, true); err != nil {
		t.Fatalf("enterAccount: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d packets, want 1 (the login reply: CreateBasePlayer + showGUI)", len(tr.writes))
	}

	// The whole login reply is ONE packet: the client's `LoginReplyFilter`
	// passes only the packet carrying the login-reply flag, so a second
	// packet (the `1a/76` pair) is dropped as "unexpected ... on external
	// interface" and the hangar never loads.
	clear, err := decryptBlowfish(st.blockKey, tr.writes[0][4:])
	if err != nil {
		t.Fatal(err)
	}
	app, err := frameApp(clear)
	if err != nil {
		t.Fatal(err)
	}
	if len(app) < 2 || app[0] != 0x13 || app[1] != 0x00 {
		t.Fatalf("app = % x, want a 0x13 0x00 head", app)
	}

	// The Account entity follows the head.
	back, err := DecodeCreateBasePlayer(app[2:], s.cfg.Dispatch)
	if err != nil {
		t.Fatalf("DecodeCreateBasePlayer: %v", err)
	}
	if back.ID != 0x1234 || back.Props["name"].Str != "playerone" {
		t.Errorf("entity = %+v", back)
	}

	// The `1a/76` pair follows in the same packet, with the `0x13 0x40`
	// head `serveBulk` uses for the same small.
	marker := []byte{0x13, 0x40, elSelectPlayerEntity, byte(entityMethodBase + 40)}
	at := bytes.Index(app, marker)
	if at < 0 {
		t.Fatalf("app = % x, want % x after the CreateBasePlayer", app, marker)
	}
	// [1a][76][u16 elementLen][u8 stringLen][pickle]
	n := int(app[at+4]) | int(app[at+5])<<8
	strLen := int(app[at+6])
	if n != 1+strLen {
		t.Fatalf("showGUI element length %d, string length %d", n, strLen)
	}
	if got, want := at+7+strLen, len(app); got != want {
		t.Fatalf("showGUI string ends at %d, packet ends at %d", got, want)
	}
	stk, _, err := lobby.DecodePrefix(app[at+7 : at+7+strLen])
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

// TestLoginReplyHoldsTheTicksUntilTheClientSpeaks pins the tick gate after a
// login reply.
//
// The client's `LoginReplyFilter` (`sub_142D32190`) passes only packets whose
// byte 146 is the login-reply flag while the login is in flight, and drops
// everything else as "unexpected packet on external interface" — which the
// channel reports as REASON_GENERAL_NETWORK and the client disconnects. A
// 28 B tick has no byte 146 at all, so the 10 Hz login-phase ticker must stay
// quiet until the client's own next datagram ends the login.
func TestLoginReplyHoldsTheTicksUntilTheClientSpeaks(t *testing.T) {
	s := enterTestServer(t)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	st := &clientState{
		entityID: 0x1234, name: "playerone", blockKey: "0123456789abcdef",
		stage2Addr: addr, tickPeriod: PostTickPeriod,
	}
	tr := &fakeTransport{}
	if _, err := s.enterAccount(tr, addr, st, 3, 0, true); err != nil {
		t.Fatalf("enterAccount: %v", err)
	}
	if !st.postHold {
		t.Fatal("the login reply did not hold the ticks")
	}
	s.mu.Lock()
	s.byAddr[addr.String()] = st
	s.mu.Unlock()
	// A tick is due, but the client has not spoken: nothing goes out.
	s.mu.Lock()
	st.postAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	before := len(tr.writes)
	s.sweepStage2(tr, time.Now())
	if len(tr.writes) != before {
		t.Fatalf("%d packets after the login reply, want none (the filter would drop them)",
			len(tr.writes)-before)
	}
	// An ACK is not enough: the client acks the login reply at once, while
	// its filter stays armed for another second.
	ack := []byte{0x48, 0x14, 0x02, 0x00, 0x00, 0x00}
	ack = append(ack, make([]byte, 12)...)
	s.noteReliable(st, addr, ack)
	if !st.postHold {
		t.Fatal("an ack-only datagram released the ticks")
	}
	// A battle call is not enough either: the client's in-flight
	// `setRemoteCamera` datagrams keep arriving right after leaveArena.
	battle := []byte{0x58, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x1a, 0x00}
	battle = append(battle, make([]byte, 26+8)...)
	s.noteReliable(st, addr, battle)
	if !st.postHold {
		t.Fatal("a battle call released the ticks")
	}
	// A lobby base call is: the client is back in the hangar.
	call := []byte{0x58, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x95, 0x1c, 0x00, 0xdd, 0x00, 0x42}
	call = append(call, make([]byte, 8)...)
	s.noteReliable(st, addr, call)
	if st.postHold {
		t.Fatal("the client's app call did not release the ticks")
	}
	// The filter's window still holds them for a moment after the reply.
	s.mu.Lock()
	st.postAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	s.sweepStage2(tr, time.Now())
	if len(tr.writes) != before {
		t.Fatalf("%d packets inside the post-login window, want none", len(tr.writes)-before)
	}
	// Once the window has passed, they resume.
	s.mu.Lock()
	st.postHoldAt = time.Now().Add(-postHoldWindow - time.Second)
	st.postAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	s.sweepStage2(tr, time.Now())
	if len(tr.writes) == before {
		t.Fatal("the ticks did not resume after the client spoke")
	}
}
