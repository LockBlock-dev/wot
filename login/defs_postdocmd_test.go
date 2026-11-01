package login

import (
	"os"
	"strings"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// TestPostDoCmdFromDefs is the point of moving the reader onto the defs:
// the same call decodes to the same request and command ids, and the
// method is named by the defs rather than by a hand-written table.
func TestPostDoCmdFromDefs(t *testing.T) {
	const defs = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	srv := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	k2 := uint32(0x78128370)

	cases := []struct {
		name   string
		call   []byte
		req    uint16
		cmd    uint16
		method string
	}{
		{"sync", lobby.DoCmdInt3(224, lobby.CmdSyncData, 88, 0x699a133b, 0), 224, 100, "doCmdInt3"},
		{"poll", lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0), 202, 501, "doCmdInt3"},
		{"season", lobby.DoCmdInt2(225, lobby.CmdSetActiveVehSeason, 0, 0), 225, 121, "doCmdInt2"},
	}
	for _, c := range cases {
		clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, c.call)...)
		call, ok := srv.postDoCmd(clear, k2)
		if !ok {
			t.Fatalf("%s: not decoded", c.name)
		}
		if call.Req != c.req || call.Cmd != c.cmd {
			t.Errorf("%s: %d/%d, want %d/%d", c.name, call.Req, call.Cmd, c.req, c.cmd)
		}
		if call.Method == nil {
			t.Fatalf("%s: no method from the defs", c.name)
		}
		if call.Method.Name != c.method {
			t.Errorf("%s: method = %q, want %q", c.name, call.Method.Name, c.method)
		}
		if call.Name() != c.method {
			t.Errorf("%s: Name() = %q", c.name, call.Name())
		}
		// The defs say how long the call is; the wire must agree. The
		// call bytes are [elemID][len u16][args], so the args are len-3.
		if !call.Method.Length.Fixed || call.Method.Length.Size != len(c.call)-3 {
			t.Errorf("%s: defs length %s, wire %d", c.name, call.Method.Length, len(c.call)-3)
		}
	}

	// A foreign stage key must not resolve, with or without the defs.
	clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, lobby.DoCmdInt3(1, 2, 3, 4, 5))...)
	if _, ok := srv.postDoCmd(clear, k2^1); ok {
		t.Error("foreign key accepted")
	}
}

// TestPostDoCmdDefsAndFallbackAgree keeps the two readers from drifting:
// every call the fallback recognises must decode identically from the
// defs.
func TestPostDoCmdDefsAndFallbackAgree(t *testing.T) {
	const defs = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	withDefs := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	plain := &BaseAppServer{}
	k2 := uint32(0x11223344)

	calls := [][]byte{
		lobby.DoCmdInt3(224, lobby.CmdSyncData, 88, 0x699a133b, 0),
		lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0),
		lobby.DoCmdInt2(225, lobby.CmdSetActiveVehSeason, 0, 0),
		lobby.DoCmdInt3(7, 1500, 1, 2, 3),
	}
	for i, c := range calls {
		clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, c)...)
		a, okA := withDefs.postDoCmd(clear, k2)
		b, okB := plain.postDoCmd(clear, k2)
		if okA != okB {
			t.Fatalf("call %d: defs ok=%v, fallback ok=%v", i, okA, okB)
		}
		if !okA {
			continue
		}
		if a.Req != b.Req || a.Cmd != b.Cmd {
			t.Errorf("call %d: defs %d/%d, fallback %d/%d", i, a.Req, a.Cmd, b.Req, b.Cmd)
		}
	}
}

// TestPostDoCmdRejectsLengthMismatch keeps a defs/wire disagreement from
// decoding garbage.
func TestPostDoCmdRejectsLengthMismatch(t *testing.T) {
	const defs = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	k2 := uint32(0x55667788)

	clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, lobby.DoCmdInt3(1, 2, 3, 4, 5))...)
	// Corrupt the element length: the defs say 28, the wire now says 20.
	clear[8] = 0x14
	clear[9] = 0x00
	if _, ok := srv.postDoCmd(clear, k2); ok {
		t.Fatal("a length the defs contradict was accepted")
	}
}

// TestPostDoCmdNamesFromDefs checks the log line names the method.
func TestPostDoCmdNamesFromDefs(t *testing.T) {
	const defs = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	srv := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	k2 := uint32(0x99aabbcc)
	clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, lobby.DoCmdInt3(1, 100, 0, 0, 0))...)
	call, ok := srv.postDoCmd(clear, k2)
	if !ok {
		t.Fatal("not decoded")
	}
	if !strings.Contains(call.Name(), "doCmdInt3") {
		t.Errorf("Name() = %q", call.Name())
	}
}
