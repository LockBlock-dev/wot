package login

import (
	"bytes"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestCreateBasePlayerAppRoundTrip is the point of sending the element: the
// Account entity it builds decodes back to the session's values.
func TestCreateBasePlayerAppRoundTrip(t *testing.T) {
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	s := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	st := &clientState{entityID: 0x1234, name: "playerone"}

	app, err := s.createBasePlayerApp(st)
	if err != nil {
		t.Fatalf("createBasePlayerApp: %v", err)
	}
	if app[0] != elCreateBasePlayer {
		t.Fatalf("element id = %#02x, want %#02x", app[0], elCreateBasePlayer)
	}

	back, err := DecodeCreateBasePlayer(app, d)
	if err != nil {
		t.Fatalf("DecodeCreateBasePlayer: %v", err)
	}
	if back.ID != 0x1234 {
		t.Errorf("entity id = %#x, want 0x1234", back.ID)
	}
	if back.Type.Name != "Account" {
		t.Errorf("type = %q, want Account", back.Type.Name)
	}
	if v := back.Props["name"]; v.Str != "playerone" {
		t.Errorf("name = %q", v.Str)
	}
	// The version property is named after the build: 2.4.0.0 declares
	// `requiredVersion_2400`, 2.4.1 `requiredVersion_2410`. Whichever the defs
	// carry has to be set, or CreateBasePlayer fails outright.
	versionProp := ""
	for _, name := range []string{"requiredVersion_2410", "requiredVersion_2400"} {
		if _, ok := back.Props[name]; ok {
			versionProp = name
			break
		}
	}
	if versionProp == "" {
		t.Fatal("the Account defs declare no requiredVersion property")
	}
	if v := back.Props[versionProp]; v.Str == "" {
		t.Errorf("%s is empty", versionProp)
	}
	if v := back.Props["incarnationID"]; v.Uint == 0 {
		t.Error("incarnationID is zero")
	}
	t.Logf("CreateBasePlayer: %d B for entity %#x", len(app), back.ID)
}

// TestCreateBasePlayerIncarnationIsFresh keeps two sessions from sharing an
// incarnation id: it identifies this incarnation of the entity.
func TestCreateBasePlayerIncarnationIsFresh(t *testing.T) {
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	s := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	st := &clientState{entityID: 1, name: "x"}

	seen := map[uint64]bool{}
	for i := 0; i < 8; i++ {
		app, err := s.createBasePlayerApp(st)
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeCreateBasePlayer(app, d)
		if err != nil {
			t.Fatal(err)
		}
		id := back.Props["incarnationID"].Uint
		if seen[id] {
			t.Fatalf("incarnation id %#x repeated", id)
		}
		seen[id] = true
	}
}

// TestCreateBasePlayerNeedsDefs keeps a server without the defs from
// sending a half-built element.
func TestCreateBasePlayerNeedsDefs(t *testing.T) {
	s := &BaseAppServer{cfg: BaseAppConfig{}}
	if _, err := s.createBasePlayerApp(&clientState{entityID: 1}); err == nil {
		t.Fatal("built an element without the defs")
	}
}

// TestCreateBasePlayerIsStableInShape keeps the element the same size for
// the same name, so a session's frame budget does not move.
func TestCreateBasePlayerIsStableInShape(t *testing.T) {
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	s := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	st := &clientState{entityID: 1, name: "playerone"}

	first, err := s.createBasePlayerApp(st)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := s.createBasePlayerApp(st)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != len(first) {
			t.Fatalf("length moved: %d -> %d", len(first), len(again))
		}
		// Only the incarnation id may differ.
		diff := 0
		for j := range first {
			if first[j] != again[j] {
				diff++
			}
		}
		if diff > 8 {
			t.Errorf("%d bytes differ, want at most the 8-byte incarnation id", diff)
		}
	}
}

// TestCreateBasePlayerElementIsWellFormed pins the framing.
func TestCreateBasePlayerElementIsWellFormed(t *testing.T) {
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatal(err)
	}
	s := &BaseAppServer{cfg: BaseAppConfig{Dispatch: d}}
	app, err := s.createBasePlayerApp(&clientState{entityID: 7, name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	// [id][len u16][payload]
	n := int(app[1]) | int(app[2])<<8
	if n != len(app)-3 {
		t.Fatalf("declared length %d, payload %d", n, len(app)-3)
	}
	// The payload opens with the entity id and the type id.
	if !bytes.Equal(app[3:7], []byte{7, 0, 0, 0}) {
		t.Errorf("entity id bytes = % x", app[3:7])
	}
}
