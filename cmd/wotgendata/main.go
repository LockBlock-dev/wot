// Command wotgendata generates wot/lobby/vehicle_data_gen.go from an
// UNPACKED item_defs tree (packed .xml/.def first through wotunpack).
// Same pattern as replay/methods_gen.go: the output is committed,
// runtime code must never touch XML.
//
//	educt: go run ./cmd/wotgendata -item-defs <dir> -out lobby/vehicle_data_gen.go
//
// Input layout per nation dir vehicles/<nation>/: list.xml
// (<Name><id>N…), components/<kind>.xml (<ids><Name>id…), vehicle
// <V>.xml (turret definitions are top-level <Turret…> blocks in
// <turrets0>; per-turret gun entries carry reload/clip/autoreload).
// Shells resolve through components/shells.xml (kind, caliber,
// damage, penetration, speed). Only the 11 shipped nations emit;
// anything else is skipped, never guessed. Stdlib only.
package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var nations = []string{
	"ussr", "germany", "usa", "china", "france", "uk",
	"japan", "czech", "sweden", "poland", "italy",
}

var compFiles = []struct {
	kind int // lobby.CompKind order: chassis0 engine1 fuel2 radio3 turret4 gun5 optdev6
	file string
}{
	{0, "chassis.xml"},
	{1, "engines.xml"},
	{2, "fuelTanks.xml"},
	{3, "radios.xml"},
	{4, "turrets.xml"},
	{5, "guns.xml"},
	{6, "optionalDevices.xml"},
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

var tagRe = regexp.MustCompile(`<([\w.\-]+)>([^<>]*)</`)

// idsIn returns name→id for direct <ids> children only.
func idsIn(txt string) map[string]int {
	out := map[string]int{}
	m := regexp.MustCompile(`(?s)<ids>(.*?)</ids>`).FindStringSubmatch(txt)
	if m == nil {
		return out
	}
	for _, mm := range tagRe.FindAllStringSubmatch(m[1], -1) {
		if id, err := strconv.Atoi(strings.TrimSpace(mm[2])); err == nil {
			out[mm[1]] = id
		}
	}
	return out
}

// listRows returns vehicle name→typeID for top-level <Name><id>N rows
// (stdlib token scan — top-level element name with a direct <id>
// child, mirroring lobby.loadListFile).
func listRows(txt string) map[string]int {
	out := map[string]int{}
	dec := xml.NewDecoder(strings.NewReader(txt))
	depth := 0
	var top string
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				top = t.Name.Local
			} else if depth == 2 && top != "" && t.Name.Local == "id" {
				var id int
				if err := dec.DecodeElement(&id, &t); err == nil {
					out[top] = id
				}
				depth--
			}
		case xml.EndElement:
			depth--
			if depth == 0 {
				top = ""
			}
		}
	}
	return out
}

// block extracts the first <name>…</name> span (non-greedy, no nesting
// of the same tag — true of turret/gun definition blocks).
func block(txt, name string) string {
	re := regexp.MustCompile(`(?s)<` + regexp.QuoteMeta(name) + `>(.*?)</` + regexp.QuoteMeta(name) + `>`)
	m := re.FindStringSubmatch(txt)
	if m == nil {
		return ""
	}
	return m[1]
}

func firstFloat(body, tag string) float64 {
	m := regexp.MustCompile(`<` + tag + `>([\d.]+)</`).FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	return f
}

func firstInt(body, tag string) int {
	m := regexp.MustCompile(`<` + tag + `>(\d+)</`).FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func floatList(body, tag string) []float64 {
	m := regexp.MustCompile(`<` + tag + `>([\d. ]+)</`).FindStringSubmatch(body)
	if m == nil {
		return nil
	}
	var out []float64
	for _, f := range strings.Fields(m[1]) {
		v, err := strconv.ParseFloat(f, 64)
		if err == nil {
			out = append(out, v)
		}
	}
	return out
}

type shell struct {
	name            string
	kind            string
	caliber         float64
	dmgArmor        int
	dmgDevices      int
	explosionRadius float64
	hasStun         bool
	stunDuration    float64
}

type shotStat struct {
	name    string
	speed   float64
	gravity float64
	maxDist float64
	pen     []float64
	portion float64
}

func parseShell(name, body string) shell {
	s := shell{name: name}
	if m := regexp.MustCompile(`<kind>(.*?)</`).FindStringSubmatch(body); m != nil {
		s.kind = strings.TrimSpace(m[1])
	}
	s.caliber = firstFloat(body, "caliber")
	s.dmgArmor = firstInt(body, "armor")
	s.explosionRadius = firstFloat(body, "explosionRadius")
	s.hasStun = strings.Contains(body, "<hasStun>true")
	s.stunDuration = firstFloat(body, "stunDuration")
	if m := regexp.MustCompile(`(?s)<damage>(.*?)</damage>`).FindStringSubmatch(body); m != nil {
		s.dmgArmor = firstInt(m[1], "armor")
		s.dmgDevices = firstInt(m[1], "devices")
	}
	return s
}

// parseShotStat reads one <shots> child (shell ballistics lived with
// the gun item, not the shell def): speed, gravity, maxDistance,
// penetration pair, default ammo portion.
func parseShotStat(name, body string) shotStat {
	s := shotStat{name: name}
	s.speed = firstFloat(body, "speed")
	s.gravity = firstFloat(body, "gravity")
	s.maxDist = firstFloat(body, "maxDistance")
	s.portion = firstFloat(body, "defaultPortion")
	if m := regexp.MustCompile(`<piercingPower>([\d. ]+)</`).FindStringSubmatch(body); m != nil {
		for _, f := range strings.Fields(m[1]) {
			if v, err := strconv.ParseFloat(f, 64); err == nil {
				s.pen = append(s.pen, v)
			}
		}
	}
	return s
}

type gun struct {
	name        string
	reload      float64
	maxAmmo     int
	clipCount   int
	clipRate    float64
	chargeable  bool
	stationary  bool
	extraShot   bool
	extraReload float64
	auto        []float64
	autoBoost   bool
	burstSize   int
	burstRate   float64
	autoShoot   bool
	dual        bool
	dualChg     float64
	dualLock    float64
	dualRate    float64
	dualDelay   float64
	dualTimes   []float64
	twin        bool
	twinRel     float64
	twinDelay   float64
	shells      []shotStat
}

func parseGun(name, body string) gun {
	g := gun{name: name}
	g.reload = firstFloat(body, "reloadTime")
	g.maxAmmo = firstInt(body, "maxAmmo")
	if m := regexp.MustCompile(`(?s)<clip>(.*?)</clip>`).FindStringSubmatch(body); m != nil {
		g.clipCount = firstInt(m[1], "count")
		g.clipRate = firstFloat(m[1], "rate")
	}
	if m := regexp.MustCompile(`(?s)<autoreload>(.*?)</autoreload>`).FindStringSubmatch(body); m != nil {
		g.auto = floatList(m[1], "reloadTime")
		g.autoBoost = strings.Contains(m[1], "boostStartTime") &&
			strings.Contains(m[1], "boostResidueTime") &&
			strings.Contains(m[1], "boostFraction")
	}
	if m := regexp.MustCompile(`(?s)<burst>(.*?)</burst>`).FindStringSubmatch(body); m != nil {
		// NOTE: burst blocks use count/rate tags like clip, not
		// size/interval (verified on Covenanter/TKS/StrvM38).
		g.burstSize = firstInt(m[1], "count")
		g.burstRate = firstFloat(m[1], "rate")
	}
	g.autoShoot = strings.Contains(body, "<autoShoot>")
	if m := regexp.MustCompile(`(?s)<dualGun>(.*?)</dualGun>`).FindStringSubmatch(body); m != nil {
		g.dual = true
		g.dualChg = firstFloat(m[1], "chargeTime")
		g.dualLock = firstFloat(m[1], "reloadLockTime")
		g.dualRate = firstFloat(m[1], "rateTime")
		g.dualDelay = firstFloat(m[1], "afterShotDelay")
		g.dualTimes = floatList(m[1], "reloadTimes")
	}
	if m := regexp.MustCompile(`(?s)<twinGun>(.*?)</twinGun>`).FindStringSubmatch(body); m != nil {
		g.twin = true
		g.twinRel = firstFloat(m[1], "twinGunReloadTime")
		g.twinDelay = firstFloat(m[1], "afterShotDelay")
	}
	g.chargeable = strings.Contains(body, "<chargeableBurst>")
	g.stationary = strings.Contains(body, "<stationaryReload>") || strings.Contains(body, "<controllableReload>")
	if m := regexp.MustCompile(`(?s)<extraShotClip>(.*?)</extraShotClip>`).FindStringSubmatch(body); m != nil {
		g.extraShot = true
		g.extraReload = firstFloat(m[1], "extraReloadTime")
	}
	return g
}

func q(s string) string { return strconv.Quote(s) }

// sortedKeys returns a map's keys in byte order (map iteration is
// random; generated output must be byte-stable).
func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func floats(fs []float64) string {
	if len(fs) == 0 {
		return "nil"
	}
	var b strings.Builder
	b.WriteString("[]float64{")
	for i, f := range fs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%v", f)
	}
	b.WriteString("}")
	return b.String()
}

func main() {
	itemDefs := flag.String("item-defs", "", "unpacked item_defs directory")
	out := flag.String("out", "", "output .go path")
	flag.Parse()
	if *itemDefs == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: wotgendata -item-defs DIR -out lobby/vehicle_data_gen.go")
		os.Exit(2)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "// Code generated from 2.4.0.0 item_defs by wotgendata; DO NOT EDIT.\n")
	fmt.Fprintf(&sb, "// Static vehicle/gun/shell tables so runtime code never touches XML\n")
	fmt.Fprintf(&sb, "// (same pattern as replay/methods_gen.go). Regenerate after client updates.\n\npackage lobby\n\n")
	// components + shell tables first (needed for gun shell resolution)
	compIDs := map[string]map[int]map[string]int{} // nation -> kind -> name -> id
	shells := map[string]shell{}                   // shell name -> spec (first nation wins)
	for _, n := range nations {
		nd := filepath.Join(*itemDefs, "vehicles", n)
		if st, err := os.Stat(nd); err != nil || !st.IsDir() {
			continue
		}
		compIDs[n] = map[int]map[string]int{}
		for _, cf := range compFiles {
			compIDs[n][cf.kind] = idsIn(readFile(filepath.Join(nd, "components", cf.file)))
		}
		stxt := readFile(filepath.Join(nd, "components", "shells.xml"))
		// shell defs are top-level blocks carrying <kind>
		seenShell := map[string]bool{}
		for _, sm := range regexp.MustCompile(`<(_[A-Za-z0-9_\.\-]+)>`).FindAllStringSubmatch(stxt, -1) {
			name := sm[1]
			if seenShell[name] {
				continue
			}
			seenShell[name] = true
			body := block(stxt, name)
			if !strings.Contains(body, "<kind>") {
				continue
			}
			if _, dup := shells[name]; !dup {
				shells[name] = parseShell(name, body)
			}
		}
	}
	// components emit
	fmt.Fprintf(&sb, "// GeneratedComponents mirrors StaticTable.Comps: nation -> kind\n")
	fmt.Fprintf(&sb, "// (lobby.CompKind order) -> component id -> name.\n")
	fmt.Fprintf(&sb, "var GeneratedComponents = map[uint16]map[int]map[uint16]string{\n")
	for ni, n := range nations {
		if _, ok := compIDs[n]; !ok {
			continue
		}
		fmt.Fprintf(&sb, "\t%d: {\n", ni)
		var kinds []int
		for k := range compIDs[n] {
			kinds = append(kinds, k)
		}
		sort.Ints(kinds)
		for _, k := range kinds {
			inv := map[int]string{}
			for name, id := range compIDs[n][k] {
				inv[id] = name
			}
			var ids []int
			for id := range inv {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			fmt.Fprintf(&sb, "\t\t%d: {\n", k)
			for _, id := range ids {
				fmt.Fprintf(&sb, "\t\t\t%d: %s,\n", id, q(inv[id]))
			}
			fmt.Fprintf(&sb, "\t\t},\n")
		}
		fmt.Fprintf(&sb, "\t},\n")
	}
	fmt.Fprintf(&sb, "}\n\n")
	// vehicles
	type vrow struct {
		nation       int
		id           int
		tag          string
		turrets      []string
		guns         map[string][]gun // turret -> guns (document order)
		missingShell int
	}
	var vrows []vrow
	nWarn := 0
	warn := func(f string, a ...any) {
		nWarn++
		fmt.Fprintf(os.Stderr, "wotgendata: "+f+"\n", a...)
	}
	for ni, n := range nations {
		lids := map[string]int{}
		if txt := readFile(filepath.Join(*itemDefs, "vehicles", n, "list.xml")); txt != "" {
			lids = listRows(txt)
		}
		turretIDs := compIDs[n][4]
		// ordered per-shell ballistics per gun, from the gun component
		// item sections (vehicle files carry stats, not ammo lists).
		// NOTE: the first same-name span is the ids stub — every
		// occurrence is tried, shots append whenever present.
		compShots := map[string][]shotStat{}
		if gtxt := readFile(filepath.Join(*itemDefs, "vehicles", n, "components", "guns.xml")); gtxt != "" {
			for _, loc := range regexp.MustCompile(`<(_[A-Za-z0-9_\.\-]+)>`).FindAllStringIndex(gtxt, -1) {
				gn := gtxt[loc[0]+1 : loc[1]-1]
				rest := gtxt[loc[1]:]
				end := strings.Index(rest, "</"+gn+">")
				if end < 0 {
					continue
				}
				body := rest[:end]
				if sm := regexp.MustCompile(`(?s)<shots>(.*?)</shots>`).FindStringSubmatch(body); sm != nil {
					shotsBody := sm[1]
					for _, sloc := range regexp.MustCompile(`<(_[A-Za-z0-9_\.\-]+)>`).FindAllStringIndex(shotsBody, -1) {
						sn := shotsBody[sloc[0]+1 : sloc[1]-1]
						srest := shotsBody[sloc[1]:]
						send := strings.Index(srest, "</"+sn+">")
						if send < 0 {
							continue
						}
						dup := false
						for _, s := range compShots[gn] {
							if s.name == sn {
								dup = true
							}
						}
						if !dup {
							compShots[gn] = append(compShots[gn], parseShotStat(sn, srest[:send]))
						}
					}
				}
			}
		}
		var tags []string
		for tag := range lids {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			if tag == "list" || tag == "customization" || tag == "Observer" {
				continue
			}
			vxml := readFile(filepath.Join(*itemDefs, "vehicles", n, tag+".xml"))
			row := vrow{nation: ni, id: lids[tag], tag: tag, guns: map[string][]gun{}}
			// Gun stats live in the per-turret entries (turret-level
			// reload wins by construction); there is no shared
			// <guns> section at top level in these files.
			if t0 := block(vxml, "turrets0"); t0 != "" {
				for _, tm := range regexp.MustCompile(`<([\w.\-]+)>`).FindAllStringSubmatch(t0, -1) {
					tn := tm[1]
					if _, ok := turretIDs[tn]; !ok {
						continue
					}
					dup := false
					for _, t := range row.turrets {
						if t == tn {
							dup = true
						}
					}
					if dup {
						continue
					}
					row.turrets = append(row.turrets, tn)
					tb := block(t0, tn)
					// gun entries: names in the gun ids table (sorted:
					// map order is random, output must be stable)
					for _, gname := range sortedKeys(compIDs[n][5]) {
						gb := block(tb, gname)
						if gb == "" {
							continue
						}
						g := parseGun(gname, gb)
						g.shells = compShots[gname]
						for _, sh := range g.shells {
							if _, ok := shells[sh.name]; !ok {
								row.missingShell++
								warn("%s/%s turret %s gun %s: unknown shell %s", n, tag, tn, gname, sh.name)
							}
						}
						row.guns[tn] = append(row.guns[tn], g)
					}
				}
			}
			vrows = append(vrows, row)
		}
	}
	sort.Slice(vrows, func(i, j int) bool {
		if vrows[i].nation != vrows[j].nation {
			return vrows[i].nation < vrows[j].nation
		}
		return vrows[i].id < vrows[j].id
	})
	fmt.Fprintf(&sb, "// GeneratedVehicles: nation -> vehicle typeID -> descriptor\n")
	fmt.Fprintf(&sb, "// (turret/gun stats are per-turret mounted values).\n")
	fmt.Fprintf(&sb, "var GeneratedVehicles = map[uint16]map[uint16]GenVehicle{\n")
	// regroup (keeps nation blocks tidy)
	byNation := map[int][]vrow{}
	for _, r := range vrows {
		byNation[r.nation] = append(byNation[r.nation], r)
	}
	// rewrite: emit per nation
	sb.Reset()
	fmt.Fprintf(&sb, "// Code generated from 2.4.0.0 item_defs by wotgendata; DO NOT EDIT.\n")
	fmt.Fprintf(&sb, "// Static vehicle/gun/shell tables so runtime code never touches XML\n")
	fmt.Fprintf(&sb, "// (same pattern as replay/methods_gen.go). Regenerate after client updates.\n\npackage lobby\n\n")
	fmt.Fprintf(&sb, "// GeneratedComponents mirrors StaticTable.Comps: nation -> kind\n")
	fmt.Fprintf(&sb, "// (lobby.CompKind order) -> component id -> name.\n")
	fmt.Fprintf(&sb, "var GeneratedComponents = map[uint16]map[int]map[uint16]string{\n")
	for ni, n := range nations {
		if _, ok := compIDs[n]; !ok {
			continue
		}
		fmt.Fprintf(&sb, "\t%d: {\n", ni)
		var kinds []int
		for k := range compIDs[n] {
			kinds = append(kinds, k)
		}
		sort.Ints(kinds)
		for _, k := range kinds {
			inv := map[int]string{}
			for name, id := range compIDs[n][k] {
				inv[id] = name
			}
			var ids []int
			for id := range inv {
				ids = append(ids, id)
			}
			sort.Ints(ids)
			fmt.Fprintf(&sb, "\t\t%d: {\n", k)
			for _, id := range ids {
				fmt.Fprintf(&sb, "\t\t\t%d: %s,\n", id, q(inv[id]))
			}
			fmt.Fprintf(&sb, "\t\t},\n")
		}
		fmt.Fprintf(&sb, "\t},\n")
	}
	fmt.Fprintf(&sb, "}\n\n")
	fmt.Fprintf(&sb, "// GeneratedVehicles: nation -> vehicle typeID -> descriptor\n")
	fmt.Fprintf(&sb, "// (turret/gun stats are per-turret mounted values).\n")
	fmt.Fprintf(&sb, "var GeneratedVehicles = map[uint16]map[uint16]GenVehicle{\n")
	var nats []int
	for nn := range byNation {
		nats = append(nats, nn)
	}
	sort.Ints(nats)
	emitGun := func(g gun) string {
		var b strings.Builder
		fmt.Fprintf(&b, "{Name: %s, Reload: %v, MaxAmmo: %d, ClipCount: %d, ClipRate: %v, Autoreload: %s, AutoReloadBoost: %v, ",
			q(g.name), g.reload, g.maxAmmo, g.clipCount, g.clipRate, floats(g.auto), g.autoBoost)
		fmt.Fprintf(&b, "DualGun: %v, DualCharge: %v, DualLock: %v, DualRate: %v, DualDelay: %v, DualTimes: %s, ",
			g.dual, g.dualChg, g.dualLock, g.dualRate, g.dualDelay, floats(g.dualTimes))
		fmt.Fprintf(&b, "TwinGun: %v, TwinReloadTime: %v, TwinDelay: %v, BurstSize: %d, BurstRate: %v, AutoShoot: %v, Chargeable: %v, Stationary: %v, ExtraShot: %v, ExtraReload: %v, Shells: []GenShell{", g.twin, g.twinRel, g.twinDelay, g.burstSize, g.burstRate, g.autoShoot, g.chargeable, g.stationary, g.extraShot, g.extraReload)
		for _, sh := range g.shells {
			s, ok := shells[sh.name]
			if !ok {
				continue
			}
			fmt.Fprintf(&b, "{Name: %s, Kind: %s, Caliber: %v, DamageArmor: %d, DamageDevices: %d, Pen: %s, Speed: %v, Gravity: %v, MaxDistance: %v, Portion: %v, ExplosionRadius: %v, HasStun: %v, StunDuration: %v}, ",
				q(s.name), q(s.kind), s.caliber, s.dmgArmor, s.dmgDevices, floats(sh.pen), sh.speed, sh.gravity, sh.maxDist, sh.portion, s.explosionRadius, s.hasStun, s.stunDuration)
		}
		b.WriteString("}}")
		return b.String()
	}
	for _, nn := range nats {
		fmt.Fprintf(&sb, "\t%d: {\n", nn)
		for _, r := range byNation[nn] {
			fmt.Fprintf(&sb, "\t\t%d: {Tag: %s, Turrets: []GenTurret{", r.id, q(r.tag))
			for _, tn := range r.turrets {
				fmt.Fprintf(&sb, "{Name: %s, Guns: []GenGun{", q(tn))
				for _, g := range r.guns[tn] {
					fmt.Fprintf(&sb, "%s, ", emitGun(g))
				}
				fmt.Fprintf(&sb, "}}, ")
			}
			fmt.Fprintf(&sb, "}},\n")
		}
		fmt.Fprintf(&sb, "\t},\n")
	}
	fmt.Fprintf(&sb, "}\n")
	if err := os.WriteFile(*out, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "wotgendata: write:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wotgendata: %d vehicles, %d warnings\n", len(vrows), nWarn)
}
