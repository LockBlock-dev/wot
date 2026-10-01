// SCRATCH (delete after EU5-hangar iteration): merged base-method indices.
package entdef

import (
	"testing"
)

func TestScratchMethodIndices(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	if _, err := l.LoadEntities(); err != nil {
		t.Fatal(err)
	}
	e, err := l.ParseEntity("Account")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	legacy := 0
	emit := func(m *Method, own bool) {
		tag := "iface"
		if own {
			tag = "own"
		}
		if !m.isExposed() {
			t.Logf("  [skip-nonexposed %s] %s", tag, m.Name)
			return
		}
		if seen[m.Name] {
			t.Logf("  [skip-dup %s] %s", tag, m.Name)
			return
		}
		seen[m.Name] = true
		t.Logf("  [%d %s] %s nargs=%d", legacy, tag, m.Name, len(m.Args))
		legacy++
	}
	for i := range e.IfaceBaseMethods {
		emit(&e.IfaceBaseMethods[i], false)
	}
	for i := range e.BaseMethods {
		emit(&e.BaseMethods[i], true)
	}
	t.Logf("total merged exposed base methods: %d", legacy)
}
