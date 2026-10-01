package entdef

import (
	"testing"
)

func TestZZM3(t *testing.T) {
	l := &Loader{Dir: "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"}
	for _, name := range []string{"AreaDestructibles", "OfflineEntity", "DestructibleEntity", "Vehicle", "Avatar"} {
		e, err := l.ParseEntity(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("== %s own=%d iface=%d ==", name, len(e.ClientMethods), len(e.IfaceClientMethods))
		n := 0
		for _, m := range append(e.ClientMethods, e.IfaceClientMethods...) {
			if n == 37 || n == 67 || n == 28 || n == 10 {
				t.Logf("  [%d] %s nargs=%d", n, m.Name, len(m.Args))
			}
			n++
		}
	}
}
