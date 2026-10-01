package entdef

import (
	"testing"
)

func TestEntityCounts(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		e, err := l.ParseEntity(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: props=%d methods=%d", name, len(e.CSProps), len(e.ClientMethods))
	}
}
