package entdef

// walk241_test.go — live 2.4.1.0 probe comparators. Paste the
// ce/walkfinal_241.lua output (walk lines + optional merged [r8probe]
// tag stream) into ce/walkfinal_241_RUN.txt; these tests diff it
// against the offline model visit-for-visit (entry order, pass/fail,
// names, FullIndex, legacy indexes, flags, volatile, and the
// gate85/varlen inputs of the conditional varLen u32) and mechanically
// close the login digest if the observed entry pass-set was the delta
// (TestWalk241DigestFromObserved). All skip when the run file or the
// external 2.4.1 def trees (uncommitted siblings) are absent, so CI
// stays green.
//
// The former TestWalk241TagsFromObserved (live strlen+append tag stream
// vs the model's putTag order) is gone. It was a digest-hunt diagnostic
// and is superseded: the digest now reproduces the client truth, which
// is a strictly stronger guarantee. It could never go green because the
// r8 helper fires at MORE call sites than putTag — the streams diverge
// at tag #2048 with extra `Uint` tags (the first is
// STANCE_DANCE_STATE.state, UINT8, inside
// StanceDanceController.abilityState). Modelling those extra sites
// would buy nothing the digest does not already prove.
//
// The model here mirrors entityMD5's traversal exactly (same
// interfaces-before-own merge, first-wins name dedup, per-domain
// legacy counters, statics in manifest order) — keep the two in sync.

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	testWotdefs241Dir = "../../wotdefs-2.4.1"
	testDefs241Dir    = "../../scripts-2.4.1/entity_defs"
	testRun241File    = "../../ce/walkfinal_241_RUN.txt"
)

type w241Visit struct {
	kind  string // "prop" | "meth"
	name  string
	idx   int
	flags int
	vol   int
	// gate/varlen: from a capture, the live descriptor's +0x55/+0x58
	// reads; from model241, the model's effective isForClient gate and
	// VariableLengthHeaderSize.
	gate   int
	varlen int
	// write/varT are model-side only: whether memberMD5 hashes the
	// conditional varLen u32 here (isForClient && streamSize<0 &&
	// varLen!=1) and whether the stream size is negative. Keep model241
	// in sync with memberMD5/methodMD5 when the toggles matter.
	write bool
	varT  bool
}

func (v w241Visit) String() string {
	if v.kind == "prop" {
		return fmt.Sprintf("prop idx=%d flags=0x%X vol=%d gate85=%d varlen=%d name=%q",
			v.idx, v.flags, v.vol, v.gate, v.varlen, v.name)
	}
	return fmt.Sprintf("meth idx=%d flags=0x%X gate85=%d varlen=%d name=%q",
		v.idx, v.flags, v.gate, v.varlen, v.name)
}

type w241Block struct {
	name   string
	pass   int
	visits []w241Visit
}

type w241Capture struct {
	blocks []w241Block
	tags   []string // [r8probe] str="..." in fire order
}

var (
	re241Entry = regexp.MustCompile(`\[walkfinal\] #\d+ t=[0-9.]+ kind=entry pass=(\d+|nil) name="([^"]*)"`)
	re241Prop  = regexp.MustCompile(`\[walkfinal\] #\d+ t=[0-9.]+ kind=prop idx=(\d+|nil) flags=0x([0-9A-Fa-f]+) vol=(\d+|nil)(?: gate85=(\d+|nil))? varlen=(\d+|nil) name="([^"]*)"`)
	re241Meth  = regexp.MustCompile(`\[walkfinal\] #\d+ t=[0-9.]+ kind=meth idx=(\d+|nil) flags=0x([0-9A-Fa-f]+) gate85=(\d+|nil) varlen=(\d+|nil) name="([^"]*)"`)
	re241Tag   = regexp.MustCompile(`\[r8probe\] #\d+ t=[0-9.]+ ret=[0-9A-Fa-f]+ R8=[0-9A-Fa-f]+ str="([^"]*)"`)
)

func num241(t *testing.T, s string) int {
	t.Helper()
	if s == "nil" || s == "" { // "" = optional field absent (pre-gate85 prop captures)
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("walk241: bad probe number %q", s)
	}
	return n
}

func parseWalk241(t *testing.T, raw []byte) *w241Capture {
	t.Helper()
	c := &w241Capture{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if m := re241Entry.FindStringSubmatch(ln); m != nil {
			c.blocks = append(c.blocks, w241Block{name: m[2], pass: num241(t, m[1])})
			continue
		}
		if m := re241Prop.FindStringSubmatch(ln); m != nil {
			if len(c.blocks) == 0 {
				t.Fatalf("walk241: prop visit before any entry line: %s", ln)
			}
			idx := num241(t, m[1])
			if idx == 4294967295 {
				idx = -1
			}
			fl, _ := strconv.ParseInt(m[2], 16, 64)
			b := &c.blocks[len(c.blocks)-1]
			b.visits = append(b.visits, w241Visit{
				kind: "prop", name: m[6], idx: idx, flags: int(fl),
				vol: num241(t, m[3]), gate: num241(t, m[4]), varlen: num241(t, m[5]),
			})
			continue
		}
		if m := re241Meth.FindStringSubmatch(ln); m != nil {
			if len(c.blocks) == 0 {
				t.Fatalf("walk241: meth visit before any entry line: %s", ln)
			}
			idx := num241(t, m[1])
			if idx == 4294967295 {
				idx = -1
			}
			fl, _ := strconv.ParseInt(m[2], 16, 64)
			b := &c.blocks[len(c.blocks)-1]
			b.visits = append(b.visits, w241Visit{
				kind: "meth", name: m[5], idx: idx, flags: int(fl),
				gate: num241(t, m[3]), varlen: num241(t, m[4]),
			})
			continue
		}
		if m := re241Tag.FindStringSubmatch(ln); m != nil {
			c.tags = append(c.tags, m[1])
		}
	}
	return c
}

func readWalk241(t *testing.T) *w241Capture {
	t.Helper()
	raw, err := os.ReadFile(testRun241File)
	if err != nil {
		t.Skipf("241 walk run unavailable (%v); paste the walkfinal_241.lua log into %s", err, testRun241File)
	}
	return parseWalk241(t, raw)
}

// open241 loads the external 2.4.1 map under the 2.4.1 scripts defs.
// Parsed structs are independent of the globals afterwards.
func open241(t *testing.T) []MapEntry {
	t.Helper()
	if _, err := os.Stat(testWotdefs241Dir); err != nil {
		t.Skipf("241 def trees unavailable: %v", err)
	}
	if _, err := os.Stat(testDefs241Dir); err != nil {
		t.Skipf("241 scripts defs unavailable: %v", err)
	}
	prevDir := ScriptsEntityDefsDir
	ResetAliases()
	ScriptsEntityDefsDir = testDefs241Dir
	defer func() {
		ScriptsEntityDefsDir = prevDir
		ResetAliases()
	}()
	entries, err := BuildMapOrder(testWotdefs241Dir, testDefs241Dir)
	if err != nil {
		t.Fatalf("walk241: BuildMapOrder: %v", err)
	}
	return entries
}

// model241 mirrors entityMD5's traversal as a visit list.
func model241(t *testing.T, entries []MapEntry) []w241Block {
	t.Helper()
	var out []w241Block
	for _, en := range entries {
		e := en.Ent
		b := w241Block{name: e.Name, pass: 1}
		if Skip241[e.Name] || !entryIncluded(e, en.Statics) {
			b.pass = 0
			out = append(out, b)
			continue
		}
		for i := range e.Props {
			p := &e.Props[i]
			cs := p.isClientServerData()
			idx := -1
			if cs {
				idx = p.FullIndex
			}
			vol := 0
			if p.Volatile {
				vol = 1
			}
			gate := 0
			if cs {
				gate = 1
			}
			varT := p.Type.StreamSize() < 0
			b.visits = append(b.visits, w241Visit{
				kind: "prop", name: p.Name, idx: idx, flags: p.Flags, vol: vol,
				gate: gate, varlen: int(p.VarLen), varT: varT,
				write: cs && varT && p.VarLen != 1,
			})
		}
		domain := func(iface, own []Method, stFn func(*Entity) ([]Method, []Method)) {
			seen := map[string]bool{}
			legacy := 0
			// mk mirrors methodMD5's member call (varLen u32 hashed iff
			// effective gate && streamSize<0 && varLen!=1).
			mk := func(m *Method) w241Visit {
				varLen := m.Var
				if !DigestMethodVarLen {
					varLen = 1
				}
				gate := true
				if VarLenGateUnsafe {
					gate = m.AllowUnsafe
				}
				g := 0
				if gate {
					g = 1
				}
				st := m.streamSize()
				return w241Visit{
					kind: "meth", name: m.Name, idx: legacy, flags: int(m.Flags),
					gate: g, varlen: int(varLen), varT: st < 0,
					write: gate && st < 0 && varLen != 1,
				}
			}
			emit := func(m *Method) {
				if !m.isExposed() || seen[m.Name] {
					return
				}
				seen[m.Name] = true
				b.visits = append(b.visits, mk(m))
				legacy++
			}
			emitRaw := func(m *Method) {
				if !m.isExposed() {
					return
				}
				b.visits = append(b.visits, mk(m))
				legacy++
			}
			for i := range iface {
				emit(&iface[i])
			}
			for i := range own {
				emit(&own[i])
			}
			for _, st := range en.Statics {
				sif, sow := stFn(st)
				for i := range sif {
					emitRaw(&sif[i])
				}
				for i := range sow {
					emitRaw(&sow[i])
				}
			}
		}
		domain(e.IfaceClientMethods, e.ClientMethods, func(s *Entity) ([]Method, []Method) {
			return s.IfaceClientMethods, s.ClientMethods
		})
		domain(e.IfaceBaseMethods, e.BaseMethods, func(s *Entity) ([]Method, []Method) {
			return s.IfaceBaseMethods, s.BaseMethods
		})
		domain(e.IfaceCellMethods, e.CellMethods, func(s *Entity) ([]Method, []Method) {
			return s.IfaceCellMethods, s.CellMethods
		})
		out = append(out, b)
	}
	return out
}

func capNames241(xs []string) []string {
	if len(xs) > 12 {
		out := make([]string, 13)
		copy(out, xs[:12])
		out[12] = fmt.Sprintf("...(%d more)", len(xs)-12)
		return out
	}
	return xs
}

// diff241 classifies every divergence between the model and a capture;
// an empty result is an exact visit-for-visit match.
func diff241(model []w241Block, c *w241Capture) []string {
	var problems []string
	add := func(f string, a ...interface{}) {
		if len(problems) < 40 {
			problems = append(problems, fmt.Sprintf(f, a...))
		}
	}
	modelSet := map[string]int{}
	for i, b := range model {
		modelSet[b.name] = i
	}
	obsSet := map[string]bool{}
	for _, b := range c.blocks {
		obsSet[b.name] = true
	}
	var modelOnly, obsOnly []string
	for _, b := range model {
		if !obsSet[b.name] {
			modelOnly = append(modelOnly, b.name)
		}
	}
	for _, b := range c.blocks {
		if _, ok := modelSet[b.name]; !ok {
			obsOnly = append(obsOnly, b.name)
		}
	}
	if len(modelOnly) > 0 {
		add("model entries not observed (%d): %v", len(modelOnly), capNames241(modelOnly))
	}
	if len(obsOnly) > 0 {
		add("observed entries not in model (%d): %v", len(obsOnly), capNames241(obsOnly))
	}
	n := len(model)
	if len(c.blocks) < n {
		n = len(c.blocks)
	}
	for i := 0; i < n; i++ {
		mb, ob := model[i], c.blocks[i]
		if mb.name != ob.name {
			add("entry[%d]: model %q vs observed %q", i, mb.name, ob.name)
			continue
		}
		if mb.pass != ob.pass {
			add("entry %q: pass model=%d observed=%d", mb.name, mb.pass, ob.pass)
		}
		if mb.pass == 0 {
			if len(ob.visits) > 0 {
				add("entry %q: pass=0 but %d observed visits", mb.name, len(ob.visits))
			}
			continue
		}
		if len(mb.visits) != len(ob.visits) {
			add("entry %q: visit count model=%d observed=%d", mb.name, len(mb.visits), len(ob.visits))
		}
		vn := len(mb.visits)
		if len(ob.visits) < vn {
			vn = len(ob.visits)
		}
		for j := 0; j < vn; j++ {
			mv, ov := mb.visits[j], ob.visits[j]
			mf, of := mv.flags, ov.flags
			if mv.kind == "prop" {
				mf &= 0x5F
				of &= 0x5F
			}
			if mv.kind != ov.kind || mv.name != ov.name || mv.idx != ov.idx || mf != of ||
				(mv.kind == "prop" && mv.vol != ov.vol) {
				add("entry %q visit[%d]:\n  model    %s\n  observed %s", mb.name, j, mv, ov)
				break // one divergence per entry is enough to localize
			}
			if ov.varlen < 0 {
				continue // unreadable in the capture
			}
			// Digest-impact checks the basic compare cannot see: the
			// conditional varLen u32 (memberMD5: isForClient &&
			// streamSize<0 && varLen!=1) and its inputs. Live
			// streamSize<0 is unknowable from the capture, so the
			// model's type variability stands in (a live divergence
			// there already shows in the r8 tag stream / flags).
			if mv.varlen != ov.varlen {
				add("entry %q visit[%d] %s %q: varLen model=%d observed=%d (hashed iff gate && variable)",
					mb.name, j, mv.kind, mv.name, mv.varlen, ov.varlen)
			}
			liveGate := ov.gate != 0
			if mv.kind == "prop" && ov.gate < 0 {
				liveGate = ov.flags&0x106 != 0 // pre-gate85 prop captures
			}
			liveWrite := liveGate && mv.varT && ov.varlen != 1
			if mv.write != liveWrite {
				add("entry %q visit[%d] %s %q: varLen-u32 hash model=%v observed=%v (gate model=%d live=%v, varLen model=%d observed=%d)",
					mb.name, j, mv.kind, mv.name, mv.write, liveWrite, mv.gate, liveGate, mv.varlen, ov.varlen)
			}
		}
	}
	if len(model) != len(c.blocks) {
		add("block count model=%d observed=%d", len(model), len(c.blocks))
	}
	return problems
}

// synth241 renders a capture exactly like walkfinal_241.lua prints it
// (entry/prop/meth lines; visits only for walked entries) so the
// parser/diff pipeline is self-tested without a live run.
func synth241(model []w241Block) string {
	var sb strings.Builder
	h := 0
	for _, b := range model {
		h++
		fmt.Fprintf(&sb, "[walkfinal] #%d t=0.001 kind=entry pass=%d name=%q desc=0x1\n", h, b.pass, b.name)
		for _, v := range b.visits {
			h++
			switch v.kind {
			case "prop":
				idx := v.idx
				if idx < 0 {
					idx = 4294967295
				}
				fmt.Fprintf(&sb, "[walkfinal] #%d t=0.001 kind=prop idx=%d flags=0x%X vol=%d gate85=%d varlen=%d name=%q desc=0x2\n",
					h, idx, v.flags, v.vol, v.gate, v.varlen, v.name)
			case "meth":
				fmt.Fprintf(&sb, "[walkfinal] #%d t=0.001 kind=meth idx=%d flags=0x%X gate85=%d varlen=%d name=%q desc=0x3\n",
					h, v.idx, v.flags, v.gate, v.varlen, v.name)
			}
		}
	}
	return sb.String()
}

// TestWalk241ComparatorSelfCheck proves the comparator pipeline
// (synthesis -> regex parse -> diff) is exact, and that each class of
// mutation is caught.
func TestWalk241ComparatorSelfCheck(t *testing.T) {
	entries := open241(t)
	model := model241(t, entries)
	visits := 0
	for _, b := range model {
		visits += len(b.visits)
	}
	t.Logf("selfcheck model: %d entries, %d visits", len(model), visits)
	raw := synth241(model)
	c := parseWalk241(t, []byte(raw))
	if got, want := len(c.blocks), len(model); got != want {
		t.Fatalf("selfcheck: parsed blocks=%d want %d", got, want)
	}
	if p := diff241(model, c); len(p) != 0 {
		t.Fatalf("selfcheck: diff on exact capture: %v", p)
	}
	// mutation 1: wrong visit name
	mut := parseWalk241(t, []byte(raw))
	for i := range mut.blocks {
		if len(mut.blocks[i].visits) > 0 {
			mut.blocks[i].visits[0].name = mut.blocks[i].visits[0].name + "X"
			break
		}
	}
	if p := diff241(model, mut); len(p) == 0 {
		t.Fatalf("selfcheck: name mutation not caught")
	}
	// mutation 2: flipped pass on a walked entry
	mut = parseWalk241(t, []byte(raw))
	for i := range mut.blocks {
		if mut.blocks[i].pass == 1 {
			mut.blocks[i].pass = 0
			break
		}
	}
	if p := diff241(model, mut); len(p) == 0 {
		t.Fatalf("selfcheck: pass mutation not caught")
	}
	// mutation 3: dropped last block
	mut = parseWalk241(t, []byte(raw))
	mut.blocks = mut.blocks[:len(mut.blocks)-1]
	if p := diff241(model, mut); len(p) == 0 {
		t.Fatalf("selfcheck: dropped block not caught")
	}
	// mutation 4: reordered adjacent blocks (when the model has >=2)
	if len(model) >= 2 {
		mut = parseWalk241(t, []byte(raw))
		mut.blocks[0], mut.blocks[1] = mut.blocks[1], mut.blocks[0]
		if p := diff241(model, mut); len(p) == 0 {
			t.Fatalf("selfcheck: reorder not caught")
		}
	}
	// mutation 5: varLen drift on an observed visit
	mut = parseWalk241(t, []byte(raw))
	bumped := false
	for bi := range mut.blocks {
		if len(mut.blocks[bi].visits) == 0 {
			continue
		}
		mut.blocks[bi].visits[0].varlen++
		bumped = true
		break
	}
	if !bumped {
		t.Fatalf("selfcheck: no visits to mutate")
	}
	if p := diff241(model, mut); len(p) == 0 {
		t.Fatalf("selfcheck: varLen mutation not caught")
	}
	// mutation 6: varLen-u32 gate flip, on a doctored model so the
	// check runs even if the real 2.4.1 tree has no writing meth visit
	doc := make([]w241Block, len(model))
	copy(doc, model)
	bi := -1
	for i := range doc {
		for j := range doc[i].visits {
			if doc[i].visits[j].kind == "meth" {
				v := doc[i].visits[j]
				v.varT, v.varlen, v.gate, v.write = true, 3, 1, true
				doc[i].visits[j] = v
				bi = i
				break
			}
		}
		if bi >= 0 {
			break
		}
	}
	if bi < 0 {
		t.Fatalf("selfcheck: no meth visits in model")
	}
	raw2 := synth241(doc)
	c2 := parseWalk241(t, []byte(raw2))
	if p := diff241(doc, c2); len(p) != 0 {
		t.Fatalf("selfcheck: doctored writing visit inconsistent: %v", p)
	}
	gateFlipped := false
	for j := range c2.blocks[bi].visits {
		if c2.blocks[bi].visits[j].kind == "meth" {
			c2.blocks[bi].visits[j].gate = 0
			gateFlipped = true
			break
		}
	}
	if !gateFlipped {
		t.Fatalf("selfcheck: doctored visit not found after reparse")
	}
	if p := diff241(doc, c2); len(p) == 0 {
		t.Fatalf("selfcheck: gate flip not caught")
	}
}

func TestWalk241MatchesProbe(t *testing.T) {
	c := readWalk241(t)
	entries := open241(t)
	model := model241(t, entries)
	problems := diff241(model, c)
	for _, p := range problems {
		t.Errorf("%s", p)
	}
	if len(problems) > 0 {
		t.Fatalf("walk241 probe mismatches: %d finding(s)", len(problems))
	}
	visits := 0
	for _, b := range model {
		visits += len(b.visits)
	}
	t.Logf("walk241 probe matches: %d entries, %d visits", len(model), visits)
}

// observedPass241 returns the capture's pass bit per entry name
// (first-wins; reports duplicates).
func observedPass241(t *testing.T, c *w241Capture) map[string]int {
	t.Helper()
	pass := map[string]int{}
	dups := 0
	for _, b := range c.blocks {
		if _, ok := pass[b.name]; ok {
			dups++
			continue
		}
		pass[b.name] = b.pass
	}
	if dups > 0 {
		t.Errorf("walk241: %d duplicate entry names in capture", dups)
	}
	return pass
}

// TestWalk241DigestFromObserved recomputes the login digest with the
// OBSERVED entry pass-set and the model's streams. If it equals the
// live truth, the pass-set (membership) was the whole delta and the
// gap is CLOSED. A clean walk match with a miss here localizes the
// remainder to per-visit stream content (see the tag test) or to type
// numbers the probes cannot see.
func TestWalk241DigestFromObserved(t *testing.T) {
	c := readWalk241(t)
	entries := open241(t)
	pass := observedPass241(t, c)
	modelNames := map[string]bool{}
	incl := 0
	h := md5.New()
	for _, en := range entries {
		modelNames[en.Ent.Name] = true
		p, ok := pass[en.Ent.Name]
		if !ok || p == 0 {
			continue
		}
		entityMD5(h, en.Ent, en.Statics)
		incl++
	}
	var unknown []string
	for _, b := range c.blocks {
		if !modelNames[b.name] {
			unknown = append(unknown, b.name)
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if len(unknown) > 0 {
		t.Errorf("walk241: %d observed entries unknown to the model (streams unhashable): %v",
			len(unknown), capNames241(unknown))
	}
	if got == Truth241 {
		t.Logf("CLOSED: observed pass-set + model streams == truth %s (%d included entries)", got, incl)
		return
	}
	plain, err := DigestVersion(testWotdefs241Dir, testDefs241Dir, Skip241)
	if err != nil {
		t.Fatalf("walk241: DigestVersion: %v", err)
	}
	t.Errorf("walk241: observed-pass digest %s != truth %s (model best %s): the pass-set is not the (whole) delta",
		got, Truth241, hex.EncodeToString(plain[:]))
}
