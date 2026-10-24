package lobby

// Streaming live-feed tests (synthetic vectors only — no captures).

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"
)

func liveTracer(a0, shot uint32) []byte {
	app := make([]byte, 60)
	binary.LittleEndian.PutUint32(app[0:], a0)
	binary.LittleEndian.PutUint32(app[4:], shot)
	copy(app[8:12], []byte{0x00, 0x10, 0x02, 0x02})
	binary.LittleEndian.PutUint32(app[12:], math.Float32bits(152.0))
	binary.LittleEndian.PutUint32(app[16:], math.Float32bits(275.0))
	binary.LittleEndian.PutUint32(app[20:], math.Float32bits(23.0))
	binary.LittleEndian.PutUint32(app[24:], math.Float32bits(-2.0))
	binary.LittleEndian.PutUint32(app[28:], math.Float32bits(-507.0))
	binary.LittleEndian.PutUint32(app[32:], math.Float32bits(-24.0))
	binary.LittleEndian.PutUint32(app[36:], math.Float32bits(320.0))
	binary.LittleEndian.PutUint32(app[40:], math.Float32bits(6.28))
	binary.LittleEndian.PutUint32(app[44:], math.Float32bits(720.0))
	return app
}

func liveDeath(ctr byte, v, k uint32) []byte {
	app := []byte{0x55, 0x0a}
	app = append(app, []byte("deathOrder")...)
	app = append(app, 0x71, 0x02, 0x4b, ctr, 0x73, 0x2e, 0x0b, 0xa8, 0x02, 0x10, 0xe4, 0x78, 0x01)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], k)
	app = append(app, tmp[:]...)
	return append(app, 0, 0, 0, 0, 0)
}

// liveObs injects a resolved observer into a feed (bulk bypass).
func liveObs(f *LiveFeed) {
	f.obs = testObserver()
	f.t0 = time.Date(2026, 9, 29, 20, 45, 42, 0, time.UTC)
	f.presence = NewPresence()
}

func TestLiveBulkReject(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	if s := f.Status(); !strings.Contains(s, "waiting") {
		t.Fatalf("status=%q, want waiting", s)
	}
	t0 := time.Date(2026, 9, 29, 20, 45, 40, 0, time.UTC)
	if out := f.FeedSC(t0, make([]byte, 100)); len(out) != 0 {
		t.Fatalf("pre-bulk rows=%v, want none", out)
	}
	t1 := t0.Add(1 * time.Second)
	if out := f.FeedSC(t1, make([]byte, 1200)); len(out) != 0 {
		t.Fatalf("bulk-open rows=%v, want none", out)
	}
	if s := f.Status(); !strings.Contains(s, "collecting") {
		t.Fatalf("status=%q, want collecting", s)
	}
	f.FeedSC(t1.Add(1*time.Second), make([]byte, 500))
	var diag []string
	for i := 0; i < 3; i++ {
		diag = f.FeedSC(t1.Add(time.Duration(2+i)*time.Second), make([]byte, 100))
	}
	if len(diag) != 1 || !strings.Contains(diag[0], "bulk rejected") {
		t.Fatalf("diag=%v, want one bulk-rejected line", diag)
	}
	// a later app re-opens a window (no latch — the next battle's
	// creation bulk re-collects on its own)
	if out := f.FeedSC(t1.Add(9*time.Second), make([]byte, 1200)); len(out) != 0 {
		t.Fatalf("re-open rows=%v, want none", out)
	}
	if s := f.Status(); !strings.Contains(s, "collecting") {
		t.Fatalf("status=%q, want collecting after re-open", s)
	}
}

func TestLiveShotDedup(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	liveObs(f)
	at := time.Date(2026, 9, 29, 20, 46, 59, 0, time.UTC)
	rows := f.FeedSC(at, liveTracer(1, 7))
	found := false
	for _, r := range rows {
		if strings.Contains(r, "ALLY AllyOne [SU-152|AP] SHOT") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rows=%v, want SHOT", rows)
	}
	// same shot ID again: no duplicate SHOT
	rows = f.FeedSC(at.Add(1*time.Second), liveTracer(1, 7))
	for _, r := range rows {
		if strings.Contains(r, "SHOT") {
			t.Fatalf("rows=%v, want no duplicate SHOT", rows)
		}
	}
}

func TestLiveShotFilter(t *testing.T) {
	f := NewLiveFeed(LiveConfig{Side: "enemy", Watch: "Ally"})
	liveObs(f)
	at := time.Date(2026, 9, 29, 20, 46, 59, 0, time.UTC)
	rows := f.FeedSC(at, liveTracer(1, 7)) // ALLY shot, side=enemy
	for _, r := range rows {
		if strings.Contains(r, "SHOT") {
			t.Fatalf("rows=%v, ally SHOT must be filtered", rows)
		}
	}
	f2 := NewLiveFeed(LiveConfig{Watch: "Nobody"})
	liveObs(f2)
	rows = f2.FeedSC(at, liveTracer(1, 7))
	for _, r := range rows {
		if strings.Contains(r, "SHOT") {
			t.Fatalf("rows=%v, watch must filter", rows)
		}
	}
}

func TestLiveDeathDedup(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	liveObs(f)
	at := time.Date(2026, 9, 29, 20, 47, 0, 0, time.UTC)
	rows := f.FeedSC(at, liveDeath(4, 2, 1))
	found := false
	for _, r := range rows {
		if strings.Contains(r, "KILLED") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rows=%v, want KILL", rows)
	}
	rows = f.FeedSC(at.Add(1*time.Second), liveDeath(4, 2, 1))
	for _, r := range rows {
		if strings.Contains(r, "KILLED") {
			t.Fatalf("rows=%v, want no duplicate KILL", rows)
		}
	}
}

func TestLiveMarkers(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	liveObs(f)
	f.obs.Ents[542264110] = &EntityDesc{Name: "DrumTwo", Team: 1, Tank: "AMX"}
	f.obs.Ents[542282516] = &EntityDesc{Name: "AllyOne", Team: 2, Tank: "SU-152"}
	var tmp [4]byte
	put32 := func(app []byte, v uint32) []byte {
		binary.LittleEndian.PutUint32(tmp[:], v)
		return append(app, tmp[:]...)
	}
	app := []byte{0x1a, 0x75, 27, 0x2a, 0, 0, 0}
	app = put32(app, 542264110)
	app = put32(app, 542282516)
	app = append(app, make([]byte, 15)...)
	at := time.Date(2026, 9, 29, 20, 48, 1, 0, time.UTC)
	rows := f.FeedSC(at, app)
	found := false
	for _, r := range rows {
		if strings.Contains(r, "LINK") && strings.Contains(r, "DrumTwo") && strings.Contains(r, "AllyOne") {
			found = true
		}
		if strings.Contains(r, "452") || strings.Contains(r, "-13.4") {
			t.Fatalf("row=%q carries coordinates", r)
		}
	}
	if !found {
		t.Fatalf("rows=%v, want LINK", rows)
	}
	// duplicate pair stays silent
	if rows = f.FeedSC(at.Add(1*time.Second), app); len(rows) != 0 {
		t.Fatalf("rows=%v, want no duplicate LINK", rows)
	}
}

func TestLiveFeedCS(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	// bare call without trailer: no track, no panic
	f.FeedCS(time.Now(), []byte{0x02, 0x16, 0xe4, 0xd8})
	if _, ok := f.ownAt(time.Now()); ok {
		t.Fatal("empty track must miss")
	}
}

func TestLiveRearmAfterBattle(t *testing.T) {
	f := NewLiveFeed(LiveConfig{})
	liveObs(f)
	at := time.Date(2026, 9, 29, 20, 47, 0, 0, time.UTC)
	kill := func(rows []string) bool {
		for _, r := range rows {
			if strings.Contains(r, "KILLED") {
				return true
			}
		}
		return false
	}
	// battle 1: death counter 4 prints once
	if rows := f.FeedSC(at, liveDeath(4, 2, 1)); !kill(rows) {
		t.Fatalf("rows=%v, want KILL for battle 1", rows)
	}
	// the next battle's bulk head (≥1000B) retires the live observer
	if rows := f.FeedSC(at.Add(1*time.Second), make([]byte, 1200)); len(rows) != 0 {
		t.Fatalf("retire rows=%v, want none", rows)
	}
	if s := f.Status(); strings.Contains(s, "live roster") {
		t.Fatalf("status=%q, want retired (collecting/waiting)", s)
	}
	// battle 2 observer resolved: the SAME death counter must print
	// again — the dedup maps retired with battle 1
	liveObs(f)
	if rows := f.FeedSC(at.Add(2*time.Second), liveDeath(4, 2, 1)); !kill(rows) {
		t.Fatalf("rows=%v, want KILL for battle 2 (maps must reset)", rows)
	}
	// per-battle diagnostics retired too: presence restarts empty
	f.mu.Lock()
	p := f.presence
	f.mu.Unlock()
	if p == nil || p.Total != 0 {
		t.Fatalf("presence=%v, want fresh empty presence after retire", p)
	}
}
