package entdef

// Live-walk regression tests: the model's predicted visit stream must
// match the game's digest walk exactly (names, order, FullIndex/legacy,
// flags, volatile). The run file is a paste from ce/walkfinal.lua
// (walkfinal_RUN.txt), which supersedes the walkprobe/walkprobe2/
// walkprobe3 runs (same visits plus entry pass/fail, gate85, varlen,
// descriptor pointers). Skips when absent; the digest oracle test
// below covers CI.

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

const testWotdefsDir = "../testdata/wotdefs"

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
	entries, err := BuildMapOrder(testWotdefsDir, testDefsDir)
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
	obs := parseWalkFile(t, "../../ce/walkfinal_RUN.txt", false)
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
	obs := parseWalkFile(t, "../../ce/walkfinal_RUN.txt", true)
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
