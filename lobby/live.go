package lobby

// Live battle feed: streaming twin of cmd/wotbattlefeed's offline
// replay. The proxy already holds the session key at battle time
// (MITM leg), so the caller decrypts each datagram and hands the
// battle app body here; this type owns the creation-bulk buffering,
// the Observer lifecycle, and per-packet scans.
//
// Wire why: battle start is a verbatim S>C creation run (first app
// ≥1000B, 2s lookback for sub-1000B arena docs, close at 3
// consecutive <400B heartbeat smalls — same rule as the offline CLI,
// proven live by a missing-head regression when size-filtered).
// Roster/teams/vehicles/mounts resolve once via NewObserver; then
// ScanBattleTracers runs per S>C packet (50B sliding window —
// negligible vs forward) and rows print in arrival order. The feed
// re-arms across battles: a ≥1000B S>C app while an observer is live
// is the next battle's bulk head — the old observer retires with its
// dedup maps (death counters/shot IDs restart per battle) and the
// window re-opens; lobby floods between battles close as rejected
// bulks (roster <10) and re-arm the same way. Explodes
// use past-only attribution (ObserveExplode: no future evidence by
// construction — the offline two-sided refinement is unavailable
// live). Deaths and explodes share arrival order, so a HIT printed
// just before its victim's death misses the dead-candidate exclusion
// (accepted v1 skew, noted, never patched with guesses).
// Lengths/hashes/names/counts on screen only — positions are
// gameplay data, never logged (rows carry names, never coordinates).

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// LiveConfig tunes one LiveFeed. Side is all|ally|enemy (SHOT filter;
// HIT/KILL/READY always print). Watch filters SHOT rows by name
// substring. Margin pads INCOMING warnings over shell blast (the C>S
// track is teleporty).
type LiveConfig struct {
	Own    string
	Side   string
	Watch  string
	Margin float64
}

// liveBulk bounds mirror the offline CLI: open 2s before the first
// S>C app ≥1000B, close 8s after it at the latest.
const (
	liveBulkMin   = 1000
	liveBulkSmall = 400
	liveBulkSpan  = 8 * time.Second
	liveBulkPre   = 2 * time.Second
)

// liveMinRoster rejects lobby-flood false triggers: the 1252B lobby
// bulk parses to ~zero roster entries, a battle bulk to ~30. Partial
// bulks (late start) still pass at ≥10.
const liveMinRoster = 10

type liveApp struct {
	ts  time.Time
	app []byte
}

type liveOwnPt struct {
	t time.Time
	p [3]float64
}

// LiveFeed is a streaming battle observer. FeedSC/FeedCS take one
// decrypted battle app body each (channel framing already stripped
// by the caller); returned strings are printable feed rows (possibly
// empty). Diagnostic lifecycle lines carry a "battle: " prefix to
// distinguish them from feed rows. Safe for concurrent use (the
// relay calls from per-flow goroutines).
type LiveFeed struct {
	mu  sync.Mutex
	cfg LiveConfig

	obs      *Observer
	presence *Presence
	t0       time.Time

	// creation-bulk collection (pre-observer)
	pre        []liveApp // lookback ring: recent S>C apps before tFirst
	haveFirst  bool
	tFirst     time.Time
	bulk       []liveApp
	smallRun   int
	bulkStart  time.Time
	rejected   bool
	nBulkApps  int
	nBulkBytes int

	seenShot  map[uint32]bool
	seenDeath map[byte]bool
	seenPair  map[[2]uint32]bool
	seenSpot  map[[2]uint32]bool

	track []liveOwnPt
}

// NewLiveFeed returns an empty streaming feed.
func NewLiveFeed(cfg LiveConfig) *LiveFeed {
	if cfg.Side == "" {
		cfg.Side = "all"
	}
	if cfg.Margin == 0 {
		cfg.Margin = 25
	}
	return &LiveFeed{
		cfg:       cfg,
		seenShot:  map[uint32]bool{},
		seenDeath: map[byte]bool{},
		seenPair:  map[[2]uint32]bool{},
		seenSpot:  map[[2]uint32]bool{},
	}
}

// FeedCS folds one decrypted C>S app into the own-position track
// (ParseTrailer; bare calls without a trailer are skipped).
func (f *LiveFeed) FeedCS(ts time.Time, app []byte) {
	tr, ok := ParseTrailer(app)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.track = append(f.track, liveOwnPt{ts, [3]float64{float64(tr.X), float64(tr.Y), float64(tr.Z)}})
	if len(f.track) > 1024 {
		// compact: keep the newest 512 (old points only pad the
		// nearest-in-time search).
		cp := make([]liveOwnPt, 512)
		copy(cp, f.track[len(f.track)-512:])
		f.track = cp
	}
}

// FeedSC folds one decrypted S>C app into the feed and returns rows
// to print (readies, shots, incoming, hits, kills, markers — in that
// order within the packet).
func (f *LiveFeed) FeedSC(ts time.Time, app []byte) []string {
	// Scans are pure over app bytes; run them outside the lock so
	// the relay path never holds feed state while sliding windows.
	tracers := ScanBattleTracers(app)
	explodes := ScanBattleExplodes(app)
	deaths := ParseBattleDeaths(app)
	pairs, spots := ScanBattleMarkers(app)

	f.mu.Lock()
	defer f.mu.Unlock()

	// Presence needs no observer (tokens are anonymous until the
	// map closes), so it folds every packet — including creation-bulk
	// windows the offline CLI also counts.
	if toks := ScanSnapshotTokens(app); len(toks) > 0 {
		if f.presence == nil {
			f.presence = NewPresence()
		}
		f.presence.UpdateTokens(ts, toks)
	}
	// A ≥liveBulkMin S>C app while an observer is live is the NEXT
	// battle's creation-bulk head (same size rule as the offline CLI,
	// which held for whole battles — mid-battle apps stay below the
	// line): retire the old battle here, or battle N+1 would scan
	// against a stale roster with battle-N dedup maps (death counters
	// and shot IDs restart every battle — rows would be suppressed).
	if f.obs != nil && len(app) >= liveBulkMin {
		f.retire()
	}
	if f.obs == nil {
		// Stay armed: every closed window either builds a roster or
		// rejects; the next battle's creation bulk re-opens a window
		// on its own (no polling — nothing flows between battles).
		if diag, done := f.collect(ts, app); done {
			return diag
		}
		return nil
	}
	// Live observer: keep the 2s lookback ring warm so the next
	// battle's bulk head seeds sub-1000B pre-apps exactly like the
	// offline CLI (collect() consumes the ring at window open).
	f.notePre(ts, app)
	var out []string
	for _, r := range f.obs.FlushReady(ts) {
		out = append(out, r)
	}
	for _, h := range tracers {
		if f.seenShot[h.Shot] {
			continue
		}
		f.seenShot[h.Shot] = true
		row, readies := f.obs.ObserveShot(ts, h)
		out = append(out, readies...)
		if f.showShot(row, h.A0) {
			out = append(out, row)
		}
		if in, ok := f.incomingRow(ts, h); ok {
			out = append(out, in)
		}
	}
	for _, e := range explodes {
		out = append(out, f.obs.ObserveExplode(ts, e))
	}
	for _, d := range deaths {
		if f.seenDeath[d.Counter] {
			continue
		}
		f.seenDeath[d.Counter] = true
		out = append(out, f.obs.ObserveDeath(ts, d))
	}
	for _, m := range pairs {
		k := [2]uint32{m.A, m.B}
		if f.seenPair[k] {
			continue
		}
		f.seenPair[k] = true
		sa, na, ta := f.mname(m.A)
		sb, nb, tb := f.mname(m.B)
		el := int(ts.Sub(f.t0).Seconds())
		out = append(out, fmt.Sprintf("[%s] [%02d:%02d] LINK %s %s [%s] <-> %s %s [%s]",
			ts.Format("15:04:05.000"), el/60, el%60, sa, na, ta, sb, nb, tb))
	}
	for _, m := range spots {
		k := [2]uint32{m.Ent, m.Counter}
		if f.seenSpot[k] {
			continue
		}
		f.seenSpot[k] = true
		s, nm, tank := f.mname(m.Ent)
		el := int(ts.Sub(f.t0).Seconds())
		out = append(out, fmt.Sprintf("[%s] [%02d:%02d] SPOT #%d %s %s [%s]",
			ts.Format("15:04:05.000"), el/60, el%60, m.Counter, s, nm, tank))
	}
	return out
}

// notePre appends one app to the 2s lookback ring (bounded copy —
// callers may reuse the slice).
func (f *LiveFeed) notePre(ts time.Time, app []byte) {
	f.pre = append(f.pre, liveApp{ts, append([]byte(nil), app...)})
	for len(f.pre) > 0 && ts.Sub(f.pre[0].ts) > liveBulkPre {
		f.pre = f.pre[1:]
	}
	if len(f.pre) > 128 {
		f.pre = f.pre[len(f.pre)-128:]
	}
}

// collect buffers pre-observer S>C apps; returns (diagnostic rows,
// done=true) when the bulk closes (built or rejected).
func (f *LiveFeed) collect(ts time.Time, app []byte) ([]string, bool) {
	cp := append([]byte(nil), app...)
	if !f.haveFirst {
		if len(app) >= liveBulkMin {
			f.haveFirst = true
			f.rejected = false
			f.tFirst = ts
			f.bulkStart = ts
			// seed with lookback apps inside [tFirst-2s, tFirst)
			for _, p := range f.pre {
				if !p.ts.Before(ts.Add(-liveBulkPre)) {
					f.bulk = append(f.bulk, p)
					if p.ts.Before(f.bulkStart) {
						f.bulkStart = p.ts
					}
				}
			}
			f.pre = nil
			f.bulk = append(f.bulk, liveApp{ts, cp})
			if len(app) < liveBulkSmall {
				f.smallRun = 1
			}
			return nil, false
		}
		f.notePre(ts, app)
		return nil, false
	}
	if ts.After(f.tFirst.Add(liveBulkSpan)) {
		return f.build(ts), true
	}
	f.bulk = append(f.bulk, liveApp{ts, cp})
	if len(app) < liveBulkSmall {
		f.smallRun++
		if f.smallRun >= 3 {
			f.bulk = f.bulk[:len(f.bulk)-3] // drop the heartbeat smalls
			return f.build(ts), true
		}
	} else {
		f.smallRun = 0
	}
	return nil, false
}

// build resolves the buffered bulk verbatim into an Observer.
func (f *LiveFeed) build(ts time.Time) []string {
	var bulk []byte
	for _, a := range f.bulk {
		bulk = append(bulk, a.app...)
	}
	f.nBulkApps = len(f.bulk)
	f.nBulkBytes = len(bulk)
	t0 := f.bulkStart
	// Reset collection state so the next window opens fresh (a
	// stale haveFirst/tFirst/smallRun here re-triggers an immediate
	// empty build or a negative slice on the next collect call).
	f.haveFirst = false
	f.tFirst = time.Time{}
	f.bulkStart = time.Time{}
	f.smallRun = 0
	f.bulk = nil
	f.pre = nil
	obs := NewObserver(bulk, f.cfg.Own)
	if len(obs.Ents) < liveMinRoster {
		f.rejected = true
		return []string{fmt.Sprintf("battle: bulk rejected apps=%d bytes=%d roster=%d (lobby-shaped, re-armed)",
			f.nBulkApps, f.nBulkBytes, len(obs.Ents))}
	}
	obs.SetT0(t0)
	f.obs = obs
	f.t0 = t0
	guns := 0
	for _, d := range obs.Ents {
		if d != nil && d.HasGun {
			guns++
		}
	}
	return []string{fmt.Sprintf("battle: roster=%d guns=%d bulk apps=%d bytes=%d",
		len(obs.Ents), guns, f.nBulkApps, f.nBulkBytes)}
}

// retire drops the live observer and all per-battle state. Death
// counters and shot IDs restart every battle, so carrying the dedup
// maps over would suppress battle N+1 rows; presence and the own
// track are per-battle diagnostics and restart with them.
func (f *LiveFeed) retire() {
	f.obs = nil
	f.t0 = time.Time{}
	f.presence = nil
	f.track = nil
	f.seenShot = map[uint32]bool{}
	f.seenDeath = map[byte]bool{}
	f.seenPair = map[[2]uint32]bool{}
	f.seenSpot = map[[2]uint32]bool{}
}

func (f *LiveFeed) showShot(line string, ent uint32) bool {
	if f.cfg.Watch != "" {
		d := mapEnt(f.obs, ent)
		nm := ""
		if d != nil {
			nm = d.Name
		}
		if !strings.Contains(nm, f.cfg.Watch) {
			return false
		}
	}
	switch f.cfg.Side {
	case "ally", "enemy":
		want := "ALLY"
		if f.cfg.Side == "enemy" {
			want = "ENEMY"
		}
		if !strings.Contains(line, "] "+want+" ") {
			return false
		}
	}
	return true
}

func mapEnt(o *Observer, ent uint32) *EntityDesc {
	if o == nil {
		return nil
	}
	return o.Ents[ent]
}

func (f *LiveFeed) mname(ent uint32) (string, string, string) {
	side, nm, tank := "?", "?", "?"
	if d := mapEnt(f.obs, ent); d != nil {
		nm, tank = d.Name, d.Tank
		if f.obs.HasOwn && d.Team != 0 {
			side = "ENEMY"
			if d.Team == f.obs.OwnTeam {
				side = "ALLY"
			}
		}
	}
	return side, nm, tank
}

func (f *LiveFeed) ownAt(t time.Time) ([3]float64, bool) {
	if len(f.track) == 0 {
		return [3]float64{}, false
	}
	best := f.track[0].p
	bd := 1e18
	for _, k := range f.track {
		dd := k.t.Sub(t).Seconds()
		if dd < 0 {
			dd = -dd
		}
		if dd < bd {
			bd, best = dd, k.p
		}
	}
	return best, true
}

func (f *LiveFeed) incomingRow(ts time.Time, h TracerHit) (string, bool) {
	ownP, ok := f.ownAt(ts)
	if !ok {
		return "", false
	}
	d, eta, warn, sh, ok := f.obs.Incoming(h, ownP, f.cfg.Margin)
	if !ok || !warn {
		return "", false
	}
	nm, tank := "?", "?"
	if e, ok := f.obs.Ents[h.A0]; ok {
		nm, tank = e.Name, e.Tank
	}
	el := int(ts.Sub(f.t0).Seconds())
	return fmt.Sprintf("[%s] [%02d:%02d] INCOMING %.0fmm %s from %s [%s] dist=%.0fm impact ~%.1fs",
		ts.Format("15:04:05.000"), el/60, el%60, sh.Caliber, ShellKindName(h.Kind), nm, tank, d, eta), true
}

// Status reports lifecycle counts for the operator (no positions).
func (f *LiveFeed) Status() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.obs != nil {
		toks := 0
		recs := 0
		if f.presence != nil {
			toks = len(f.presence.Count)
			recs = f.presence.Total
		}
		shots := len(f.seenShot)
		return fmt.Sprintf("battle: live roster=%d shots=%d presence=%d/%d",
			len(f.obs.Ents), shots, recs, toks)
	}
	if f.rejected {
		return fmt.Sprintf("battle: rejected bulk apps=%d bytes=%d", f.nBulkApps, f.nBulkBytes)
	}
	if f.haveFirst {
		return fmt.Sprintf("battle: collecting bulk apps=%d", len(f.bulk))
	}
	return "battle: waiting for creation bulk"
}

// SortedBulkApps is a test hook: apps buffered so far (copies).
func SortedBulkApps(f *LiveFeed) []liveApp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]liveApp(nil), f.bulk...)
	sort.Slice(out, func(i, j int) bool { return out[i].ts.Before(out[j].ts) })
	return out
}
