package replay

import (
	"math"
	"testing"
)

// TestDispatch pins typed packet parsing on the Prohorovka fixture:
// Position field split, EntityMethod framing + name resolution,
// EntityCreate table build. Offline.
func TestDispatch(t *testing.T) {
	r, err := Open("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	ver := r.ClientVersion()
	if ver != "2.4.0.0" {
		t.Fatalf("version=%q", ver)
	}
	tab, calls, err := DecodeAll(ver, pkts)
	if err != nil {
		t.Fatal(err)
	}
	_ = tab
	if len(calls) != 549 {
		t.Fatalf("methods=%d, want 549", len(calls))
	}
	nPos := 0
	for _, p := range pkts {
		if p.Type == 0xa {
			nPos++
		}
	}
	if nPos != 53918 {
		t.Fatalf("positions=%d, want 53918", nPos)
	}
	// Spot pins (wire method IDs index own++iface client methods for
	// fixed-size methods; see REPLAY.md §6).
	if got := avatarFixed[37].Name; got != "showTracer" {
		t.Fatalf("avatar mid 37 = %q", got)
	}
	if got := EntityTypeName(6); got != "Vehicle" {
		t.Fatalf("type 6 = %q", got)
	}
	// Driving sample: entity 4730080 at t≈31.03 heads +Z.
	for _, p := range pkts {
		if p.Type != 0xa || len(p.Data) != 45 {
			continue
		}
		pos, _ := ParsePosition(p.Data)
		if pos.EntityID == 4730080 && p.Time > 31 && p.Time < 31.1 {
			if math.Abs(float64(pos.X)-15.45) > 0.01 || math.Abs(float64(pos.Z)+453.4) > 0.2 {
				t.Fatalf("pos=%g,%g,%g", pos.X, pos.Y, pos.Z)
			}
			if pos.Flags != 1 {
				t.Fatalf("flags=%d", pos.Flags)
			}
			break
		}
	}
}

// TestDecodeMines decodes every EntityMethod call of the 2.3.1 Mines
// fixture with its versioned var table. Offline.
func TestDecodeMines(t *testing.T) {
	r, err := Open("../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	ver := r.ClientVersion()
	if ver != "2.3.1.0" {
		t.Fatalf("version=%q", ver)
	}
	_, calls, err := DecodeAll(ver, pkts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("mines calls=%d", len(calls))
}

// TestDecode211 decodes the 2.1.1 Glacier fixture (third player):
// fixed block must decode exactly (version-stability proof), mapped
// var wires must decode, and skipped calls must be exactly the open
// wires 40/42/60. Offline.
func TestDecode211(t *testing.T) {
	r, err := Open("../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if ver := r.ClientVersion(); ver != "2.1.1.0" {
		t.Fatalf("version=%q", ver)
	}
	tab, calls, skipped, err := DecodeAllLenient("2.1.1.0", pkts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("211: decoded=%d skipped=%d", len(calls), len(skipped))
	skippedMids := map[uint32]int{}
	for _, s := range skipped {
		skippedMids[s.MethodID]++
	}
	for mid := range skippedMids {
		if mid != 40 && mid != 42 && mid != 60 {
			t.Fatalf("unexpected skipped mid=%d", mid)
		}
	}
	if len(skippedMids) != 3 {
		t.Fatalf("skipped wires=%v, want 40/42/60", skippedMids)
	}
	// Mapped var wires must agree with fit classification.
	for _, c := range calls {
		mid := c.Call.MethodID
		if mid != 38 && mid != 56 && mid != 59 {
			continue
		}
		fits := ClassifyVar(c.Call.Raw)
		found := false
		for _, i := range fits {
			if avatarVarDoc[i].Name == c.Call.Sig.Name {
				found = true
			}
		}
		if !found {
			t.Fatalf("211 mid=%d sig=%s not in fits=%v", mid, c.Call.Sig.Name, fitNames(fits))
		}
	}
	// Events sanity on the third battle.
	var ev Events
	for _, c := range calls {
		ev.Collect(c.Time, c.Call.EntityID, c.Call)
	}
	t.Logf("211 events: damage=%d tracers=%d explodes=%d shotresults=%d",
		len(ev.Damage), len(ev.Tracers), len(ev.Explodes), len(ev.ShotResults))
	if len(ev.Damage) == 0 || len(ev.Explodes) == 0 || len(ev.ShotResults) == 0 {
		t.Fatal("missing 211 event families")
	}
	for _, d := range ev.Damage {
		if ty, ok := tab.Resolve(d.Target); !ok || ty != 6 {
			t.Fatalf("211 damage target %d type=%d", d.Target, ty)
		}
	}
}

// TestVarMapsAgree requires each committed var-wire map to agree with
// fit classification: the mapped signature must consume exactly, and
// (where the shape is unique) be the only fit.
func TestVarMapsAgree(t *testing.T) {
	r, err := Open("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	_, calls, err := DecodeAll("2.4.0.0", pkts)
	if err != nil {
		t.Fatal(err)
	}
	// Unique-shape var mids must classify to exactly their map entry.
	// mid67's 57 B sample additionally fits receiveAccountStats and
	// onCmdResponse by framing; content (shotID from the tracer
	// family) picks explodeProjectile — see REPLAY.md §6.
	unique := map[uint32]string{38: "onChatAction", 54: "showShotResults"}
	// Ambiguous shapes: the table pick is content-backed (epic-config
	// strings → updateArena, invitation pickle → processInvitations,
	// scenario name → updateSpawnList); both/all fits recorded here.
	multi := map[uint32][]string{
		58: {"showDevelopmentInfo", "updateArena"},
		62: {"processInvitations", "updateTeamsHealthPercentage", "updateSpawnList", "update", "onIGRTypeChanged", "receivePhysicsDebugInfo", "receiveNotification", "updateAvatarPrivateStats", "onRandomEvent"},
		65: {"processInvitations", "updateTeamsHealthPercentage", "updateSpawnList", "update", "onIGRTypeChanged", "receivePhysicsDebugInfo", "receiveNotification", "updateAvatarPrivateStats", "onRandomEvent"},
	}
	for _, c := range calls {
		raw := rawArgs(c)
		if want, ok := unique[c.Call.MethodID]; ok {
			fits := ClassifyVar(raw)
			if len(fits) != 1 || avatarVarDoc[fits[0]].Name != want {
				t.Fatalf("mid=%d fits=%v want %s", c.Call.MethodID, fitNames(fits), want)
			}
			continue
		}
		if c.Call.MethodID == 67 {
			// Small samples are framing-ambiguous (byte arrays and
			// string pairs split many ways); every sample must fit
			// explodeProjectile, picked by content (shotID from the
			// tracer family, map-plausible endpoints).
			fits := ClassifyVar(raw)
			found := false
			for _, i := range fits {
				if avatarVarDoc[i].Name == "explodeProjectile" {
					found = true
				}
			}
			if !found {
				t.Fatalf("mid=67 fits=%v without explodeProjectile", fitNames(fits))
			}
			continue
		}
		if want, ok := multi[c.Call.MethodID]; ok {
			fits := ClassifyVar(raw)
			if len(fits) != len(want) {
				t.Fatalf("mid=%d fits=%v want %v", c.Call.MethodID, fitNames(fits), want)
			}
			for i, n := range want {
				if avatarVarDoc[fits[i]].Name != n {
					t.Fatalf("mid=%d fits=%v want %v", c.Call.MethodID, fitNames(fits), want)
				}
			}
		}
	}
}

func rawArgs(c TimedCall) []byte { return c.Call.Raw }

func fitNames(fits []int) []string {
	var out []string
	for _, i := range fits {
		out = append(out, avatarVarDoc[i].Name)
	}
	return out
}

// TestEvents extracts battle events from the Prohorovka fixture and
// pins counts plus attacker/target sanity. Offline.
func TestEvents(t *testing.T) {
	r, err := Open("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	tab, calls, err := DecodeAll("2.4.0.0", pkts)
	if err != nil {
		t.Fatal(err)
	}
	var ev Events
	for _, c := range calls {
		ev.Collect(c.Time, c.Call.EntityID, c.Call)
	}
	t.Logf("damage=%d explosions=%d health=%d avatarHealth=%d tracers=%d explodes=%d shotresults=%d",
		len(ev.Damage), len(ev.Explosions), len(ev.Health), len(ev.AvatarHealth),
		len(ev.Tracers), len(ev.Explodes), len(ev.ShotResults))
	if len(ev.Damage) == 0 || len(ev.Tracers) == 0 || len(ev.Explodes) == 0 || len(ev.ShotResults) == 0 {
		t.Fatal("missing event families")
	}
	for _, d := range ev.Damage {
		if ty, ok := tab.Resolve(d.Target); !ok || ty != 6 {
			t.Fatalf("damage target %d type=%d", d.Target, ty)
		}
		// Attackers are vehicle entity IDs; a few (never-in-AOI)
		// have no EntityCreate in the stream, so range-check.
		if d.Attacker < 4730053 || d.Attacker > 4730082 {
			t.Fatalf("damage attacker %d out of range", d.Attacker)
		}
		if len(d.Hits) == 0 {
			t.Fatal("damage without hits")
		}
	}
	for _, s := range ev.ShotResults {
		if ty, ok := tab.Resolve(uint32(s.VehicleID)); !ok || ty != 6 {
			t.Fatalf("shotresult vehicle %d type=%d", s.VehicleID, ty)
		}
	}
}
