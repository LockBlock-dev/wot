// Command wotbattlefeed replays a wotproxy battle dump as a live
// battle feed: per-shot SHOT rows with reload/mag/next_in context,
// READY predictions, acknowledged HITs, INCOMING shell warnings,
// KILLs, and per-token presence.
//
// The dump format is wotproxy -dump lines (<ts> <dir> <addr> <len>
// <hex>); channel decrypt mirrors the proxy path (XOR-chain +
// Blowfish under the session key, login/crypto.go); the key travels
// via -keyfile or -recover-key like wotflood (lengths/hashes only,
// never values). All battle parsing lives in lobby (feed.go);
// this main only moves bytes and prints rows.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotbattlefeed:", err)
	os.Exit(1)
}

type pkt struct {
	ts   time.Time
	rt   string
	dir  string
	app  []byte // decrypted battle app body (channel framing stripped)
	alen int    // decrypted app length (bulk-size heuristic input)
}

func main() {
	dump := flag.String("dump", "", "wotproxy -dump file")
	flow := flag.String("flow", "", "flow substring (e.g. 45507)")
	keyFile := flag.String("keyfile", "", "hex block-key file (in)")
	recoverKey := flag.Bool("recover-key", false, "MITM-recover the login key from -dump into -keyfile")
	mitmPriv := flag.String("mitm-privkey", "", "MITM private key (with -recover-key)")
	mitmPub := flag.String("mitm-pubkey", "", "server public key (with -recover-key)")
	loginAddr := flag.String("login-addr", "", "login source prefix (with -recover-key, \"\" = any)")
	own := flag.String("own", "", "observer player name (sets ALLY side; empty leaves sides ?)")
	side := flag.String("side", "all", "SHOT filter: all|ally|enemy")
	watch := flag.String("watch", "", "SHOT filter: name substring (HIT/KILL/READY always print)")
	margin := flag.Float64("margin", 25, "incoming danger margin (m) over shell blast (displaced-track pad)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wotbattlefeed -dump FILE [-flow SUB] [-keyfile F | -recover-key -mitm-privkey P -mitm-pubkey S] [-own NAME] [-side all|ally|enemy] [-watch SUB] [-margin M]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *dump == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *side != "all" && *side != "ally" && *side != "enemy" {
		fatal(fmt.Errorf("-side must be all|ally|enemy"))
	}

	f, err := os.Open(*dump)
	if err != nil {
		fatal(err)
	}
	dd, err := login.ParseWotproxyDump(f)
	if err != nil {
		fatal(err)
	}
	f.Close()
	key := ""
	if *recoverKey {
		if *keyFile == "" || *mitmPriv == "" || *mitmPub == "" {
			fatal(fmt.Errorf("-recover-key needs -keyfile -mitm-privkey -mitm-pubkey"))
		}
		key, err = login.RecoverLoginKey(dd, *mitmPriv, *mitmPub, *loginAddr)
		if err != nil {
			fatal(err)
		}
		if err := login.WriteKeyFile(*keyFile, key); err != nil {
			fatal(err)
		}
		fmt.Printf("key: len=%d id=%s -> %s\n", len(key), login.KeyID(key), *keyFile)
		return
	}
	if *keyFile == "" {
		fatal(fmt.Errorf("need -keyfile (or -recover-key)"))
	}
	key, err = login.ReadKeyFile(*keyFile)
	if err != nil {
		// stage recorders write the key RAW; keyfiles hex.
		raw, rerr := os.ReadFile(*keyFile)
		if rerr != nil {
			fatal(err)
		}
		key = string(raw)
	}

	// Timestamps live only in the dump text (ParseWotproxyDump drops
	// them), so re-scan lines for <ts> like the capture harness.
	ff, err := os.Open(*dump)
	if err != nil {
		fatal(err)
	}
	defer ff.Close()
	var pkts []pkt
	nskip := 0
	sc := bufio.NewScanner(ff)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		flds := strings.Fields(sc.Text())
		if len(flds) != 5 {
			continue
		}
		if flds[1] != "C>S" && flds[1] != "S>C" {
			continue
		}
		if *flow != "" && !strings.Contains(flds[2], *flow) {
			continue
		}
		raw, err := hex.DecodeString(flds[4])
		if err != nil {
			nskip++
			continue
		}
		ts, err := time.Parse("15:04:05.000", flds[0])
		if err != nil {
			nskip++
			continue
		}
		cl, err := login.DecryptChannel(key, raw)
		if err != nil {
			nskip++
			continue
		}
		// channel footers: length is additive over the flag bits
		// (login.ChannelTrailerLen); app sits past the 2B head.
		trl := login.ChannelTrailerLen(binary.LittleEndian.Uint16(cl[0:2]))
		if len(cl) < 2+trl {
			nskip++
			continue
		}
		app := append([]byte{}, cl[2:len(cl)-trl]...)
		pkts = append(pkts, pkt{ts, flds[0], flds[1], app, len(app)})
	}
	if err := sc.Err(); err != nil {
		fatal(err)
	}
	if len(pkts) == 0 {
		fatal(fmt.Errorf("no decryptable battle packets (flow=%q skips=%d)", *flow, nskip))
	}

	// Creation bulk: the battle-start creation burst, concatenated
	// VERBATIM (every S>C app, any size — size-filtered subsets split
	// vehicle blocks: ParseBattleRoster's ASCII-ID search reaches past
	// app ends, so even the interleaved 90B small belongs in the run).
	// The run opens 2s before the first S>C app ≥1000B (sub-1000B
	// arena docs carry blocks) and closes at 3 consecutive S>C apps
	// <400B (the snapshot heartbeat; a lone mid-burst small never
	// trips it). Counts print below for verification.
	tFirst := time.Time{}
	for _, p := range pkts {
		if p.dir == "S>C" && p.alen >= 1000 {
			tFirst = p.ts
			break
		}
	}
	var run [][]byte
	smallRun := 0
	for _, p := range pkts {
		if p.dir != "S>C" || p.ts.Before(tFirst.Add(-2*time.Second)) {
			continue
		}
		if p.ts.After(tFirst.Add(8 * time.Second)) {
			break
		}
		run = append(run, p.app)
		if p.alen < 400 {
			if smallRun++; smallRun >= 3 {
				run = run[:len(run)-3] // drop the heartbeat smalls
				break
			}
		} else {
			smallRun = 0
		}
	}
	var bulk []byte
	for _, app := range run {
		bulk = append(bulk, app...)
	}
	nbulk := len(run)
	obs := lobby.NewObserver(bulk, *own)
	obs.SetT0(pkts[0].ts)
	fmt.Printf("packets=%d skipped=%d bulk apps=%d bytes=%d roster=%d guns=%d\n",
		len(pkts), nskip, nbulk, len(bulk), len(obs.Ents), countGuns(obs))

	// Shots in time order (deduped by shot ID across packets).
	type shotEv struct {
		t time.Time
		h lobby.TracerHit
	}
	var shots []shotEv
	seen := map[uint32]bool{}
	for _, p := range pkts {
		if p.dir != "S>C" {
			continue
		}
		for _, h := range lobby.ScanBattleTracers(p.app) {
			if seen[h.Shot] {
				continue
			}
			seen[h.Shot] = true
			shots = append(shots, shotEv{p.ts, h})
		}
	}
	sort.Slice(shots, func(i, j int) bool { return shots[i].t.Before(shots[j].t) })
	fmt.Printf("feed shots=%d\n", len(shots))
	showShot := func(line string, ent uint32) bool {
		d := obs.Ents[ent]
		nm := ""
		if d != nil {
			nm = d.Name
		}
		if *watch != "" && !strings.Contains(nm, *watch) {
			return false
		}
		switch *side {
		case "ally", "enemy":
			want := "ALLY"
			if *side == "enemy" {
				want = "ENEMY"
			}
			if !strings.Contains(line, "] "+want+" ") {
				return false
			}
		}
		return true
	}
	for _, s := range shots {
		row, readies := obs.ObserveShot(s.t, s.h)
		for _, r := range readies {
			fmt.Println(r)
		}
		if showShot(row, s.h.A0) {
			fmt.Println(row)
		}
	}
	for _, r := range obs.FlushReady(pkts[len(pkts)-1].ts) {
		fmt.Println(r)
	}

	// Kills collected BEFORE hits (death times exclude dead
	// candidates from victim attribution); printed after incoming.
	type killEv struct {
		t time.Time
		d lobby.DeathHit
	}
	var kills []killEv
	for _, p := range pkts {
		if p.dir != "S>C" {
			continue
		}
		for _, d := range lobby.ParseBattleDeaths(p.app) {
			kills = append(kills, killEv{p.ts, d})
		}
	}
	sort.Slice(kills, func(i, j int) bool { return kills[i].t.Before(kills[j].t) })
	var killRows []string
	for _, k := range kills {
		killRows = append(killRows, obs.ObserveDeath(k.t, k.d))
	}

	// Acknowledged hits (explodes joined to shots by shot ID).
	// Offline two-sided victims (post-hit muzzles count — campers hold
	// still; live callers use past-only ObserveExplode).
	type hitEv struct {
		t time.Time
		e lobby.ExplodeHit
	}
	var hits []hitEv
	for _, p := range pkts {
		if p.dir != "S>C" {
			continue
		}
		for _, e := range lobby.ScanBattleExplodes(p.app) {
			hits = append(hits, hitEv{p.ts, e})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].t.Before(hits[j].t) })
	fmt.Printf("hits=%d\n", len(hits))
	for _, h := range hits {
		fmt.Println(obs.ObserveExplodeFull(h.t, h.e))
	}

	// Incoming warnings need the own C>S position track (nearest in
	// time; displaced/teleporty — the margin pads it).
	type ownPt struct {
		t time.Time
		p [3]float64
	}
	var track []ownPt
	for _, p := range pkts {
		if p.dir != "C>S" {
			continue
		}
		if tr, ok := lobby.ParseTrailer(p.app); ok {
			track = append(track, ownPt{p.ts, [3]float64{float64(tr.X), float64(tr.Y), float64(tr.Z)}})
		}
	}
	sort.Slice(track, func(i, j int) bool { return track[i].t.Before(track[j].t) })
	ownAt := func(t time.Time) ([3]float64, bool) {
		if len(track) == 0 {
			return [3]float64{}, false
		}
		best := track[0].p
		bd := 1e18
		for _, k := range track {
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
	type inEv struct {
		t    time.Time
		line string
	}
	var inrows []inEv
	seenIn := map[uint32]bool{}
	for _, s := range shots {
		if seenIn[s.h.Shot] {
			continue
		}
		seenIn[s.h.Shot] = true
		ownP, ok := ownAt(s.t)
		if !ok {
			continue
		}
		d, eta, warn, sh, ok := obs.Incoming(s.h, ownP, *margin)
		if !ok || !warn {
			continue
		}
		nm, tank := "?", "?"
		if e, ok := obs.Ents[s.h.A0]; ok {
			nm, tank = e.Name, e.Tank
		}
		el := int(s.t.Sub(pkts[0].ts).Seconds())
		inrows = append(inrows, inEv{s.t, fmt.Sprintf("[%s] [%02d:%02d] INCOMING %.0fmm %s from %s [%s] dist=%.0fm impact ~%.1fs",
			s.t.Format("15:04:05.000"), el/60, el%60, sh.Caliber, lobby.ShellKindName(s.h.Kind), nm, tank, d, eta)})
	}
	sort.Slice(inrows, func(i, j int) bool { return inrows[i].t.Before(inrows[j].t) })
	fmt.Printf("incoming=%d\n", len(inrows))
	for _, r := range inrows {
		fmt.Println(r.line)
	}

	// Kills (deathOrder counters stay authoritative; recorded above
	// so victim attribution excludes the dead).
	fmt.Printf("kills=%d\n", len(killRows))
	for _, r := range killRows {
		fmt.Println(r)
	}

	// Markers (type-0x75 links + position reports; semantics open —
	// spotting-link vs team-ping — so names/counts only, no coordinates).
	type markPair struct {
		t    time.Time
		a, b uint32
	}
	type markSpot struct {
		t   time.Time
		ctr uint32
		ent uint32
	}
	var mpairs []markPair
	var mspots []markSpot
	seenPair := map[[2]uint32]bool{}
	seenSpot := map[[2]uint32]bool{}
	for _, p := range pkts {
		if p.dir != "S>C" {
			continue
		}
		prs, sps := lobby.ScanBattleMarkers(p.app)
		for _, m := range prs {
			k := [2]uint32{m.A, m.B}
			if seenPair[k] {
				continue
			}
			seenPair[k] = true
			mpairs = append(mpairs, markPair{p.ts, m.A, m.B})
		}
		for _, m := range sps {
			k := [2]uint32{m.Ent, m.Counter}
			if seenSpot[k] {
				continue
			}
			seenSpot[k] = true
			mspots = append(mspots, markSpot{p.ts, m.Counter, m.Ent})
		}
	}
	sort.Slice(mpairs, func(i, j int) bool { return mpairs[i].t.Before(mpairs[j].t) })
	sort.Slice(mspots, func(i, j int) bool { return mspots[i].t.Before(mspots[j].t) })
	mname := func(ent uint32) (string, string, string) {
		side, nm, tank := "?", "?", "?"
		if d, ok := obs.Ents[ent]; ok {
			nm, tank = d.Name, d.Tank
		}
		if obs.HasOwn {
			if d, ok := obs.Ents[ent]; ok && d.Team != 0 {
				side = "ENEMY"
				if d.Team == obs.OwnTeam {
					side = "ALLY"
				}
			}
		}
		return side, nm, tank
	}
	fmt.Printf("markers pairs=%d spots=%d\n", len(mpairs), len(mspots))
	for _, m := range mpairs {
		sa, na, ta := mname(m.a)
		sb, nb, tb := mname(m.b)
		el := int(m.t.Sub(pkts[0].ts).Seconds())
		fmt.Printf("[%s] [%02d:%02d] LINK %s %s [%s] <-> %s %s [%s]\n",
			m.t.Format("15:04:05.000"), el/60, el%60, sa, na, ta, sb, nb, tb)
	}
	for _, m := range mspots {
		s, nm, tank := mname(m.ent)
		el := int(m.t.Sub(pkts[0].ts).Seconds())
		fmt.Printf("[%s] [%02d:%02d] SPOT #%d %s %s [%s]\n",
			m.t.Format("15:04:05.000"), el/60, el%60, m.ctr, s, nm, tank)
	}

	// Presence per snapshot token (counts/times only — names open).
	pr := lobby.NewPresence()
	for _, p := range pkts {
		if p.dir != "S>C" {
			continue
		}
		if toks := lobby.ScanSnapshotTokens(p.app); len(toks) > 0 {
			pr.UpdateTokens(p.ts, toks)
		}
	}
	fmt.Printf("presence records=%d tokens=%d\n", pr.Total, len(pr.Count))
	for _, tok := range pr.Tokens() {
		fmt.Printf("  tok=%02x n=%d first=%s last=%s\n",
			tok, pr.Count[tok],
			pr.First[tok].Format("15:04:05.000"), pr.Last[tok].Format("15:04:05.000"))
	}
}

func countGuns(obs *lobby.Observer) int {
	n := 0
	for _, d := range obs.Ents {
		if d != nil && d.HasGun {
			n++
		}
	}
	return n
}
