package login

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// tokenTestServer builds a server with the Account dispatch loaded, so
// the client-method answers can be encoded.
func tokenTestServer(t *testing.T, mint func(int64) string) *BaseAppServer {
	t.Helper()
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account", "Avatar", "AvatarInfo", "Vehicle", "TeamInfo"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	s := &BaseAppServer{
		cfg:        BaseAppConfig{Dispatch: d, XMPPToken: mint},
		resend:     newResendQueue(0, 0),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	enableWireCheck(t, s)
	return s
}

// TestRequestTokenAnswersXMPPCS checks the chat credential handoff: the
// client asks for the XMPPCS token and must get a pickled
// {token, databaseID} dict back through onTokenReceived.
func TestRequestTokenAnswersXMPPCS(t *testing.T) {
	s := tokenTestServer(t, func(dbid int64) string { return "tok-" + string(rune('0'+dbid%10)) })
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, "requestToken")
	if m == nil {
		t.Fatal("no requestToken in the Account base methods")
	}
	call := postCall{
		Method: m,
		Args: []entdef.Value{
			{Kind: entdef.VUint, Uint: 7},
			{Kind: entdef.VUint, Uint: uint64(lobby.TokenTypeXMPPCS)},
		},
	}
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerPostCall(tr, addr, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes, want 1", len(tr.writes))
	}
	// The answer is a channel packet; the app inside it must carry the
	// onTokenReceived element with the pickled dict.
	app := findAppInPacket(t, tr.writes[0], st.blockKey)
	if len(app) == 0 {
		t.Fatal("no app in the answer packet")
	}
	if !bytes.Contains(app, []byte("databaseID")) || !bytes.Contains(app, []byte("token")) {
		t.Fatalf("answer does not carry the token dict: % x", app)
	}
	// The databaseID is pickled as a binary int (100000002 = 0x05f5e102),
	// so match the little-endian bytes rather than the decimal text.
	if !bytes.Contains(app, []byte{0x02, 0xe1, 0xf5, 0x05}) {
		t.Fatalf("answer does not carry the client databaseID: % x", app)
	}
}

// TestRequestTokenIgnoresWebBrokerTypes checks that the WGNI/shop token
// request is left unanswered rather than faked.
func TestRequestTokenIgnoresWebBrokerTypes(t *testing.T) {
	s := tokenTestServer(t, func(int64) string { return "tok" })
	m := s.cfg.Dispatch.Entity("Account").MethodByName(entdef.CompBase, "requestToken")
	call := postCall{
		Method: m,
		Args: []entdef.Value{
			{Kind: entdef.VUint, Uint: 8},
			{Kind: entdef.VUint, Uint: uint64(lobby.TokenTypeWGNIJWT)},
		},
	}
	st := &clientState{accountID: 2, name: "admin", blockKey: "0123456789abcdef"}
	tr := &fakeTransport{}
	if err := s.answerPostCall(tr, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}, st, call); err != nil {
		t.Fatalf("answerPostCall: %v", err)
	}
	if len(tr.writes) != 0 {
		t.Fatalf("%d writes, want 0", len(tr.writes))
	}
}

// findAppInPacket strips the channel framing from one written packet and
// returns the app bytes.
func findAppInPacket(t *testing.T, pkt []byte, key string) []byte {
	t.Helper()
	clear, err := DecryptChannel(key, pkt)
	if err != nil {
		t.Fatalf("DecryptChannel: %v", err)
	}
	tr := ChannelTrailerLen(uint16(clear[0]) | uint16(clear[1])<<8)
	if len(clear) < 2+tr {
		return nil
	}
	return clear[2 : len(clear)-tr]
}
