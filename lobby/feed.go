package lobby

// Live battle observer: per-shot feed engine over decrypted CellApp
// traffic (SHOT/HIT/KILL/READY rows) plus per-token presence.
//
// Wire why: S>C tracers (ScanBattleTracers) broadcast every shot
// incl. own; explodes (ScanBattleExplodes) ack spotted non-fatal
// hits only; kills ride deathOrder (ParseBattleDeaths); snapshots
// (ScanSnapshots) track presence per token while token→entity names
// stay open. Reloads are nominal-stock from the generated gun table
// (GunSpec over battle mounts); nobody outshoots their gun, so the
// min inter-shot gap per entity calibrates buffs online (running,
// past-evidence only — unlike offline two-pass replays). Row grammar
// follows docs/C_PLAN.md §6. Lengths/hashes/names/counts on screen
// only — positions are gameplay data, never logged.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// DisplayTank shortens a vehicles/list.xml tag ("R18_SU-152") to its
// friendly suffix ("SU-152"): after the nation prefix colon when
// present, then after the first underscore. "?" stays "?".
func DisplayTank(tag string) string {
	if i := strings.Index(tag, ":"); i >= 0 {
		tag = tag[i+1:]
	}
	if i := strings.Index(tag, "_"); i >= 0 {
		tag = tag[i+1:]
	}
	return tag
}

// fmtDur renders seconds with one decimal, trimming ".0" on whole
// values ("16s", "9.4s") — the feed's reload spelling.
func fmtDur(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%ds", int64(v))
	}
	return fmt.Sprintf("%.1fs", v)
}

// EntityDesc is one battle entity's resolved feed identity. Missing
// pieces stay zero/"" — formatters print "?" and never guess.
type EntityDesc struct {
	Name   string
	Team   uint8
	Tank   string // display tag ("SU-152"), "?" when unresolved
	Gun    GenGun
	HasGun bool
}

// drumFull returns the nominal full-reload wait: autoreloader chain
// sum from empty (P44-style tuple), else the drum/stock reload.
func drumFull(g GenGun) float64 {
	if len(g.Autoreload) > 0 {
		sum := 0.0
		for _, v := range g.Autoreload {
			sum += v
		}
		return sum
	}
	return g.Reload
}

// twinFull is the per-barrel full wait; twinIntra the switch wait
// after firing with one barrel left (TwinDelay, default 1s).
func twinFull(g GenGun) float64 {
	if g.TwinReloadTime > 0 {
		return g.TwinReloadTime
	}
	if len(g.DualTimes) > 0 {
		return g.DualTimes[0]
	}
	return g.Reload
}

func twinIntra(g GenGun) float64 {
	if g.TwinDelay > 0 {
		return g.TwinDelay
	}
	if g.DualDelay > 0 {
		return g.DualDelay
	}
	return 1.0
}

// isTwinLike reports twin and dual (volley-capable) guns: both run
// per-barrel timers with a ~1s switch (Black Prince dualGun verified
// twin-identical on wire; the volley penalty value stays open).
func isTwinLike(g GenGun) bool { return g.TwinGun || g.DualGun }

// isDrum reports clip-fed guns (drums and autoreloaders alike).
func isDrum(g GenGun) bool { return g.ClipCount > 1 }

// shotSnap freezes a fired shot's display state for the HIT join.
type shotSnap struct {
	side   string
	name   string
	tank   string // "tank|kind"
	state  string
	next   string
	buff   string
	reload string
	shell  uint8
}

// Observer holds battle feed state: roster from the creation bulk
// plus running mag/twin timers and buff calibration. Times are
// transport wall times; battle clock is elapsed since SetT0.
type Observer struct {
	Ents    map[uint32]*EntityDesc
	OwnTeam uint8
	HasOwn  bool
	t0      time.Time
	hasT0   bool

	lastShot  map[uint32]time.Time
	magLeft   map[uint32]int
	twinReady map[uint32][2]time.Time
	calFull   map[uint32]float64
	calIntra  map[uint32]float64
	byShot    map[uint32]shotSnap
	pending   []readyEv
}

type readyEv struct {
	at  time.Time
	ent uint32
}

// NewObserver resolves the creation bulk (S>C decrypted apps,
// concatenated verbatim) to per-entity feed identity via the
// generated table. ownName selects the observer's side ("" leaves
// sides "?"). Unresolved pieces stay "?" — never guessed.
func NewObserver(bulk []byte, ownName string) *Observer {
	o := &Observer{
		Ents:      map[uint32]*EntityDesc{},
		lastShot:  map[uint32]time.Time{},
		magLeft:   map[uint32]int{},
		twinReady: map[uint32][2]time.Time{},
		calFull:   map[uint32]float64{},
		calIntra:  map[uint32]float64{},
		byShot:    map[uint32]shotSnap{},
	}
	tab := GeneratedTable()
	names := ParseBattleRoster(bulk)
	teams := ParseBattleTeams(bulk)
	vehs := ParseBattleVehicles(bulk)
	mounts := ParseBattleMounts(bulk, tab)
	for ent, nm := range names {
		d := &EntityDesc{Name: nm, Team: teams[ent], Tank: "?"}
		if vr, ok := vehs[ent]; ok {
			if vi, ok := tab.Vehicle(vr.Nation, vr.TypeID); ok {
				d.Tank = DisplayTank(vi.Name)
			}
			if mm, ok := mounts[ent]; ok {
				tur, _ := tab.Component(vr.Nation, CompTurret, mm.Turret)
				gun, _ := tab.Component(vr.Nation, CompGun, mm.Gun)
				if g, ok := GunSpec(vr.Nation, vr.TypeID, tur, gun); ok {
					d.Gun, d.HasGun = g, true
				}
			}
		}
		o.Ents[ent] = d
		if ownName != "" && nm == ownName {
			if t, ok := teams[ent]; ok {
				o.OwnTeam, o.HasOwn = t, true
			}
		}
	}
	return o
}

// SetT0 anchors the battle clock (wire-relative: first battle-flow
// datagram; the in-game countdown offset stays open).
func (o *Observer) SetT0(t time.Time) { o.t0, o.hasT0 = t, true }

func (o *Observer) elapsed(at time.Time) (int, string) {
	el := 0
	if o.hasT0 {
		el = int(at.Sub(o.t0).Seconds())
	}
	return el, at.Format("15:04:05.000")
}

func (o *Observer) side(ent uint32) string {
	if !o.HasOwn {
		return "?"
	}
	d, ok := o.Ents[ent]
	if !ok || d.Team == 0 {
		return "?"
	}
	if d.Team == o.OwnTeam {
		return "ALLY"
	}
	return "ENEMY"
}

// nominalFull/Intra give the stock waits for an entity (0 without a
// resolved gun — callers print "?" then).
func (o *Observer) nominalFull(ent uint32) float64 {
	d, ok := o.Ents[ent]
	if !ok || !d.HasGun {
		return 0
	}
	if isTwinLike(d.Gun) {
		return twinFull(d.Gun)
	}
	if isDrum(d.Gun) {
		return drumFull(d.Gun)
	}
	return d.Gun.Reload
}

func (o *Observer) nominalIntra(ent uint32) float64 {
	d, ok := o.Ents[ent]
	if !ok || !d.HasGun {
		return 0
	}
	if isTwinLike(d.Gun) {
		return twinIntra(d.Gun)
	}
	return d.Gun.Intra()
}

// reloadStr renders the nominal reload cell: "17.7s", drums
// "1.0s fullreload=16s [5/8]", twins "6s fullreload=6s [1/2] twin".
func (o *Observer) reloadStr(ent uint32) string {
	d, ok := o.Ents[ent]
	if !ok || !d.HasGun {
		return "?"
	}
	g := d.Gun
	base := fmtDur(g.Reload)
	switch {
	case isTwinLike(g):
		left := 0
		if rt, ok := o.twinReady[ent]; ok {
			for _, t := range rt {
				if !t.After(o.lastShot[ent]) {
					left++
				}
			}
		}
		_ = left
		return fmt.Sprintf("%s fullreload=%s", fmtDur(twinIntra(g)), fmtDur(twinFull(g)))
	case isDrum(g):
		return fmt.Sprintf("%s fullreload=%s", fmtDur(g.Intra()), fmtDur(drumFull(g)))
	default:
		return base
	}
}

// buffed folds a running-calibrated wait in: gaps beating nominal by
// ≥max(0.3s, 5%) switch that entity to measured (upper-bound proof:
// nobody outshoots their gun).
func buffed(nominal, measured float64) (float64, bool) {
	thr := 0.3
	if t := 0.05 * nominal; t > thr {
		thr = t
	}
	if nominal-measured >= thr {
		return measured, true
	}
	return nominal, false
}

// nextWait computes the post-shot wait plus buff flag from live mag
// state (magAfter/twinAfter <0 when n/a).
func (o *Observer) nextWait(ent uint32, magAfter, twinAfter int) (string, string) {
	nomFull := o.nominalFull(ent)
	if nomFull == 0 {
		return "?", ""
	}
	if d := o.Ents[ent]; d != nil && d.HasGun {
		switch {
		case isDrum(d.Gun):
			if magAfter > 0 {
				nom := o.nominalIntra(ent)
				if c, ok := o.calIntra[ent]; ok {
					if v, b := buffed(nom, c); b {
						return fmt.Sprintf("%.1fs", v), " buff"
					}
				}
				return fmt.Sprintf("%.1fs", nom), ""
			}
			if c, ok := o.calFull[ent]; ok {
				if v, b := buffed(nomFull, c); b {
					return fmt.Sprintf("%.1fs", v), " buff"
				}
			}
			return fmt.Sprintf("%.1fs", nomFull), ""
		case isTwinLike(d.Gun):
			if twinAfter > 0 {
				nom := o.nominalIntra(ent)
				if c, ok := o.calIntra[ent]; ok {
					if v, b := buffed(nom, c); b {
						return fmt.Sprintf("%.1fs", v), " buff"
					}
				}
				return fmt.Sprintf("%.1fs", nom), ""
			}
			if c, ok := o.calFull[ent]; ok {
				if v, b := buffed(nomFull, c); b {
					return fmt.Sprintf("%.1fs", v), " buff"
				}
			}
			return fmt.Sprintf("%.1fs", nomFull), ""
		}
	}
	if c, ok := o.calFull[ent]; ok {
		if v, b := buffed(nomFull, c); b {
			return fmt.Sprintf("%.1fs", v), " buff"
		}
	}
	return fmt.Sprintf("%.1fs", nomFull), ""
}

// ObserveShot consumes one tracer hit and returns the SHOT row plus
// any READY rows due at `at` (printed first). Unknown entities print
// "?" — identity is never invented.
func (o *Observer) ObserveShot(at time.Time, h TracerHit) (shot string, readies []string) {
	for _, e := range o.popDue(at) {
		readies = append(readies, e)
	}
	// superseded: fired again before the wait elapsed
	keep := o.pending[:0]
	for _, e := range o.pending {
		if e.ent != h.A0 {
			keep = append(keep, e)
		}
	}
	o.pending = keep

	d, known := o.Ents[h.A0]
	nm, tank := "?", "?"
	if known {
		nm, tank = d.Name, d.Tank
	}
	el, rt := o.elapsed(at)
	side := o.side(h.A0)
	kind := ShellKindName(h.Kind)

	// gap classification + running calibration (past evidence only)
	gap := -1.0
	class := ""
	if lt, seen := o.lastShot[h.A0]; seen {
		gap = at.Sub(lt).Seconds()
		class = "full"
		switch {
		case known && d.HasGun && isDrum(d.Gun):
			if o.magLeft[h.A0] > 0 {
				class = "intra"
			}
		case known && d.HasGun && isTwinLike(d.Gun):
			if rt2, ok := o.twinReady[h.A0]; ok {
				loaded := 0
				for _, t := range rt2 {
					if !t.After(lt) {
						loaded++
					}
				}
				if loaded > 0 {
					class = "intra"
				}
			}
		}
		nom := o.nominalFull(h.A0)
		if class == "intra" {
			nom = o.nominalIntra(h.A0)
		}
		if nom > 0 {
			if _, b := buffed(nom, gap); b {
				if class == "intra" {
					if c, ok := o.calIntra[h.A0]; !ok || gap < c {
						o.calIntra[h.A0] = gap
					}
				} else if c, ok := o.calFull[h.A0]; !ok || gap < c {
					o.calFull[h.A0] = gap
				}
			}
		}
	}
	o.lastShot[h.A0] = at

	// mag / twin state
	magAfter, twinAfter := -1, -1
	if known && d.HasGun {
		switch {
		case isDrum(d.Gun):
			n := d.Gun.ClipCount
			left, seen := o.magLeft[h.A0]
			if !seen {
				left = n
			} else if gap >= drumFull(d.Gun) {
				left = n
			}
			left--
			o.magLeft[h.A0] = left
			magAfter = left
		case isTwinLike(d.Gun):
			rtw := o.twinReady[h.A0] // zero times = loaded
			pick := 0
			for i := range rtw {
				if rtw[i].Before(rtw[pick]) {
					pick = i
				}
			}
			rtw[pick] = at.Add(time.Duration(twinFull(d.Gun) * float64(time.Second)))
			o.twinReady[h.A0] = rtw
			loaded := 0
			for _, t := range rtw {
				if !t.After(at) {
					loaded++
				}
			}
			twinAfter = loaded
		}
	}

	state := "RELOAD"
	if magAfter > 0 || twinAfter > 0 {
		state = "READY"
	}
	rl := o.reloadStr(h.A0)
	if magAfter >= 0 {
		if d.HasGun {
			rl += fmt.Sprintf(" [%d/%d]", magAfter, d.Gun.ClipCount)
		}
	} else if twinAfter >= 0 {
		rl += fmt.Sprintf(" [%d/2] twin", twinAfter)
	}
	nxt, buff := o.nextWait(h.A0, magAfter, twinAfter)
	shot = fmt.Sprintf("[%s] [%02d:%02d] %s %s [%s|%s] SHOT -> %s | next_in=%s%s reload=%s",
		rt, el/60, el%60, side, nm, tank, kind, state, nxt, buff, rl)
	o.byShot[h.Shot] = shotSnap{side, nm, tank + "|" + kind, state, nxt, buff, rl, h.Kind}
	if state == "RELOAD" {
		if w := o.nominalFull(h.A0); w > 0 {
			if c, ok := o.calFull[h.A0]; ok {
				if v, b := buffed(w, c); b {
					w = v
				}
			}
			o.pending = append(o.pending, readyEv{at.Add(time.Duration(w * float64(time.Second))), h.A0})
		}
	}
	_ = gap
	_ = class
	return shot, readies
}

// popDue emits READY rows due at `now` (printed before later rows).
func (o *Observer) popDue(now time.Time) []string {
	var out []string
	keep := o.pending[:0]
	for _, e := range o.pending {
		if !e.at.After(now) {
			el, rt := o.elapsed(e.at)
			d, known := o.Ents[e.ent]
			nm, tank, side := "?", "?", o.side(e.ent)
			if known {
				nm, tank = d.Name, d.Tank
			}
			out = append(out, fmt.Sprintf("[%s] [%02d:%02d] %s %s [%s] RELOAD -> READY | next_in=0.0s",
				rt, el/60, el%60, side, nm, tank))
		} else {
			keep = append(keep, e)
		}
	}
	o.pending = keep
	return out
}

// FlushReady emits READY rows due at `now` (end of stream or packet
// tick); rows past the caller's horizon are never emitted.
func (o *Observer) FlushReady(now time.Time) []string { return o.popDue(now) }

// ObserveExplode joins an explode to its tracer shot: joined HIT rows
// reuse the shot's frozen state, tracerless ones print caliber-only
// (single-candidate calibers earn a marked attribution, never a
// guess).
func (o *Observer) ObserveExplode(at time.Time, e ExplodeHit) string {
	el, rt := o.elapsed(at)
	if s, ok := o.byShot[e.Shot]; ok {
		return fmt.Sprintf("[%s] [%02d:%02d] %s %s [%s] HIT -> %s | next_in=%s%s reload=%s",
			rt, el/60, el%60, s.side, s.name, s.tank, s.state, s.next, s.buff, s.reload)
	}
	if ent, single := o.caliberUnique(e.Range); single {
		d := o.Ents[ent]
		full := o.nominalFull(ent)
		ws := "?"
		if full > 0 {
			ws = fmt.Sprintf("%.1fs", full)
		}
		return fmt.Sprintf("[%s] [%02d:%02d] %s %s [%s] HIT -> RELOAD | next_in=? reload=%s (%.0fmm-unique, tracer lost)",
			rt, el/60, el%60, o.side(ent), d.Name, d.Tank, ws, e.Range)
	}
	return fmt.Sprintf("[%s] [%02d:%02d] ? ? [? %.0fmm] HIT (tracer lost)",
		rt, el/60, el%60, e.Range)
}

// caliberUnique reports the single observed shooter whose gun carries
// a shell of that caliber (round mm); anything else is ambiguous.
func (o *Observer) caliberUnique(cal float64) (uint32, bool) {
	var found uint32
	n := 0
	for ent, d := range o.Ents {
		if d == nil || !d.HasGun {
			continue
		}
		for _, s := range d.Gun.Shells {
			if float64(int64(s.Caliber+0.5)) == float64(int64(cal+0.5)) {
				found, n = ent, n+1
				break
			}
		}
	}
	return found, n == 1
}

// ObserveDeath formats one kill row (counters stay authoritative;
// mechanism stays open).
func (o *Observer) ObserveDeath(at time.Time, d DeathHit) string {
	el, rt := o.elapsed(at)
	vn, kn := "?", "?"
	vt, kt := "?", "?"
	if e, ok := o.Ents[d.Victim]; ok {
		vn, vt = e.Name, e.Tank
	}
	if e, ok := o.Ents[d.Killer]; ok {
		kn, kt = e.Name, e.Tank
	}
	return fmt.Sprintf("[%s] [%02d:%02d] #%d %s %s [%s] KILLED by %s %s [%s]",
		rt, el/60, el%60, d.Counter, o.side(d.Victim), vn, vt, o.side(d.Killer), kn, kt)
}

// Incoming evaluates one tracer against own position (radius =
// shell blast floored at 8m plus the caller's displacement margin —
// the C>S track is teleporty, so live callers pad generously).
func (o *Observer) Incoming(h TracerHit, own [3]float64, margin float64) (dist, eta float64, warn bool, sh GenShell, ok bool) {
	d, known := o.Ents[h.A0]
	if !known || !d.HasGun {
		return 0, 0, false, GenShell{}, false
	}
	sh, ok = MatchShell(d.Gun, h.Kind)
	if !ok {
		return 0, 0, false, GenShell{}, false
	}
	rad := sh.ExplosionRadius
	if rad < 8 {
		rad = 8
	}
	rad += margin
	dist, eta, warn = IncomingShot(h, sh, own, rad)
	return dist, eta, warn, sh, true
}

// Presence tracks snapshot sightings per token (counts/times only —
// token→entity names stay open, so no names here).
type Presence struct {
	Count map[byte]int
	First map[byte]time.Time
	Last  map[byte]time.Time
	Total int
}

// NewPresence returns an empty tracker.
func NewPresence() *Presence {
	return &Presence{Count: map[byte]int{}, First: map[byte]time.Time{}, Last: map[byte]time.Time{}}
}

// Update folds one packet's snapshot records into the tracker.
func (p *Presence) Update(at time.Time, recs []SnapshotRecord) {
	for _, r := range recs {
		p.Count[r.Token]++
		p.Total++
		if _, ok := p.First[r.Token]; !ok {
			p.First[r.Token] = at
		}
		p.Last[r.Token] = at
	}
}

// Tokens lists observed tokens in ascending order (deterministic —
// / map iteration is random).
func (p *Presence) Tokens() []byte {
	var out []byte
	for t := range p.Count {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
