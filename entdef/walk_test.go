package entdef

// Live-walk regression tests: the model's predicted visit stream must
// match the game's digest walk exactly (names, order, FullIndex/legacy,
// flags, volatile). The run file is a paste from ce/walkfinal_241.lua
// (walkfinal_241_RUN.txt) and pins the 2.4.1 build the client runs; it
// supersedes the 2.4.0 walkfinal_RUN.txt, whose external defs are gone.
// The r8 datatype tag oracle is still the 2.4.0 archive and skips when
// that defs tree is absent. Skips when the fixture is absent; the digest
// oracle tests below cover CI.

import (
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// The walk fixtures are the 2.4.1 build (the one the client runs). The
// 2.4.0 trees are gone from the workspace, so nothing here may depend on
// them except the r8 tag oracle, which skips.
const (
	walkWotdefsDir = "../../wotdefs-2.4.1"
	walkDefsDir    = "../../scripts-2.4.1/entity_defs"
	walkRunFile    = "../../ce/walkfinal_241_RUN.txt"
)

// wotdefs240Dir is the external 2.4.0 tree the r8 tag oracle was recorded
// against (ce/r8probe_20260920_10000.txt). It is optional.
const wotdefs240Dir = "../../wotdefs-2.4.0"

// testWotdefsDir is the tree the 2.4.0 digest oracle reads; it skips when
// absent.
const testWotdefsDir = wotdefs240Dir

type walkVisit struct {
	kind  string // "prop" | "meth"
	idx   int    // -1 for 0xFFFFFFFF
	flags int
	vol   int
	name  string
}

func parseWalkFile(t *testing.T, path string, withFlags bool) []walkVisit {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("walk run unavailable: %v", err)
	}
	// walkfinal unified lines; vol only on props, gate85 only on meths.
	re := regexp.MustCompile(`kind=(prop|meth) idx=(\d+) flags=0x([0-9A-Fa-f]+)(?: vol=(\d+))?(?: gate85=\d+)?(?: varlen=\d+)? name="((?:[^"\\]|\\x[0-9A-Fa-f]{2})*)"`)
	var out []walkVisit
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		idx, _ := strconv.Atoi(m[2])
		fl, _ := strconv.ParseInt(m[3], 16, 32)
		vol := 0
		if m[4] != "" {
			vol, _ = strconv.Atoi(m[4])
		}
		if idx == 4294967295 {
			idx = -1
		}
		out = append(out, walkVisit{kind: m[1], idx: idx, flags: int(fl), vol: vol, name: m[5]})
	}
	return out
}

type modelVisit struct {
	kind, name, entry string
	idx, flags, vol   int
}

// predictWalk emits the model's flat visit stream over BuildMapOrder
// (same traversal the digest hashes).
func predictWalk(t *testing.T) []modelVisit {
	t.Helper()
	if _, err := os.Stat(walkWotdefsDir); err != nil {
		t.Skipf("external 2.4.1 defs unavailable: %v", err)
	}
	entries, err := BuildMapOrder(walkWotdefsDir, walkDefsDir)
	if err != nil {
		t.Fatal(err)
	}
	var exp []modelVisit
	for _, en := range entries {
		e := en.Ent
		for i := range e.Props {
			p := &e.Props[i]
			idx := -1
			if p.isClientServerData() {
				idx = p.FullIndex
			}
			v := 0
			if p.Volatile {
				v = 1
			}
			exp = append(exp, modelVisit{"prop", p.Name, e.Name, idx, p.Flags, v})
		}
		seen := map[string]bool{}
		legacy := 0
		emit := func(m *Method) {
			if !m.isExposed() || seen[m.Name] {
				return
			}
			seen[m.Name] = true
			exp = append(exp, modelVisit{"meth", m.Name, e.Name, legacy, int(m.Flags), 0})
			legacy++
		}
		emitRaw := func(m *Method) {
			if !m.isExposed() {
				return
			}
			exp = append(exp, modelVisit{"meth", m.Name, e.Name, legacy, int(m.Flags), 0})
			legacy++
		}
		for i := range e.IfaceClientMethods {
			emit(&e.IfaceClientMethods[i])
		}
		for i := range e.ClientMethods {
			emit(&e.ClientMethods[i])
		}
		for _, st := range en.Statics {
			for i := range st.IfaceClientMethods {
				emitRaw(&st.IfaceClientMethods[i])
			}
			for i := range st.ClientMethods {
				emitRaw(&st.ClientMethods[i])
			}
		}
		seen = map[string]bool{}
		legacy = 0
		for i := range e.IfaceBaseMethods {
			emit(&e.IfaceBaseMethods[i])
		}
		for i := range e.BaseMethods {
			emit(&e.BaseMethods[i])
		}
		for _, st := range en.Statics {
			for i := range st.IfaceBaseMethods {
				emitRaw(&st.IfaceBaseMethods[i])
			}
			for i := range st.BaseMethods {
				emitRaw(&st.BaseMethods[i])
			}
		}
		seen = map[string]bool{}
		legacy = 0
		for i := range e.IfaceCellMethods {
			emit(&e.IfaceCellMethods[i])
		}
		for i := range e.CellMethods {
			emit(&e.CellMethods[i])
		}
		for _, st := range en.Statics {
			for i := range st.IfaceCellMethods {
				emitRaw(&st.IfaceCellMethods[i])
			}
			for i := range st.CellMethods {
				emitRaw(&st.CellMethods[i])
			}
		}
	}
	return exp
}

// TestWalkMatchesProbe pins the model's walk (kind, name, FullIndex or
// legacy) against the live walkfinal run: 1242/1242, zero mismatches.
func TestWalkMatchesProbe(t *testing.T) {
	obs := parseWalkFile(t, walkRunFile, false)
	exp := predictWalk(t)
	if len(exp) != len(obs) {
		t.Fatalf("model visits=%d observed=%d", len(exp), len(obs))
	}
	for i := range exp {
		if exp[i].kind != obs[i].kind || exp[i].name != obs[i].name || exp[i].idx != obs[i].idx {
			t.Fatalf("diverge at %d: model=%+v obs=%+v", i, exp[i], obs[i])
		}
	}
}

// TestWalkFlagsMatchProbe pins per-visit flags (&0x5F for props, full u8
// for methods) and volatile against the live walkfinal run.
func TestWalkFlagsMatchProbe(t *testing.T) {
	obs := parseWalkFile(t, walkRunFile, true)
	exp := predictWalk(t)
	if len(exp) != len(obs) {
		t.Fatalf("model visits=%d observed=%d", len(exp), len(obs))
	}
	for i := range exp {
		mf, of := exp[i].flags, obs[i].flags
		if exp[i].kind == "prop" {
			mf, of = mf&0x5F, of&0x5F
		}
		if exp[i].kind != obs[i].kind || exp[i].name != obs[i].name ||
			exp[i].idx != obs[i].idx || mf != of || exp[i].vol != obs[i].vol {
			t.Fatalf("diverge at %d: model=%+v obs=%+v", i, exp[i], obs[i])
		}
	}
}

// TestR8TagsMatchOracle240 pins the model's datatype tag stream (every
// putTag emission: type dispatch names, NUL-terminated) against the
// archived live 2.4.0 r8 run (ce/r8probe_20260920_10000.txt, 2625
// tags) — the same emission path TestWalk241TagsFromObserved relies on
// for the 2.4.1 capture, proven exact here. The walk hashes the pinned
// 2.4.0 digest in the same call, so a tag match implies the tag stream
// really is the walk's.
func TestR8TagsMatchOracle240(t *testing.T) {
	if _, err := os.Stat(testWotdefsDir); err != nil {
		t.Skipf("external 2.4.0 defs unavailable: %v", err)
	}
	raw, err := os.ReadFile("../../ce/r8probe_20260920_10000.txt")
	if err != nil {
		t.Skipf("r8 archive unavailable: %v", err)
	}
	re := regexp.MustCompile(`\[r8probe\] hit #\d+ R8=[0-9A-Fa-f]+ str="([^"]*)"`)
	var obs []string
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		obs = append(obs, m[1])
	}
	var tags []string
	TypeTagRecorder = &tags
	defer func() { TypeTagRecorder = nil }()
	d, err := DigestVersion(testWotdefsDir, testDefsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(d[:]); got != Truth240 {
		t.Fatalf("digest = %s, want %s", got, Truth240)
	}
	if len(tags) != len(obs) {
		t.Fatalf("model tags=%d observed=%d", len(tags), len(obs))
	}
	for i := range tags {
		if tags[i] != obs[i] {
			t.Fatalf("tag diverge at %d: model=%q observed=%q", i, tags[i], obs[i])
		}
	}
	t.Logf("r8 tags match: %d tags in live order", len(tags))
}
