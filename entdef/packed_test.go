package entdef

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, path string) *File {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no file: %v", err)
	}
	f, err := ParseFile(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return f
}

func dump(s *Section, depth int, b *strings.Builder) {
	if depth > 3 {
		return
	}
	val := s.AsString()
	if len(val) > 60 {
		val = val[:60] + "..."
	}
	b.WriteString(strings.Repeat("  ", depth) + s.Name + " [" + typeName(s.Type) + "] " + val + "\n")
	for _, c := range s.Children {
		dump(c, depth+1, b)
	}
}

func typeName(t uint32) string {
	switch t {
	case TypeDataSection:
		return "section"
	case TypeString:
		return "str"
	case TypeInt:
		return "int"
	case TypeFloat:
		return "float"
	case TypeBool:
		return "bool"
	case TypeBlob:
		return "blob"
	}
	return "?"
}

func TestParseLoginDef(t *testing.T) {
	f := load(t, "../../World_of_Tanks_EU/res/scripts/entity_defs/Login.def")
	var b strings.Builder
	dump(f.Root, 0, &b)
	t.Logf("\n%s", b.String())
	if len(f.Root.Children) == 0 {
		t.Fatal("no children decoded")
	}
	// Spot-checks against Login.def's known sections.
	if f.Root.Child("Properties") == nil {
		t.Error("missing Properties")
	}
	if f.Root.Child("ClientMethods") == nil {
		t.Error("missing ClientMethods")
	}
}

func TestParseEntities(t *testing.T) {
	f := load(t, "../../World_of_Tanks_EU/res/scripts/entities.xml")
	cs := f.Root.Child("ClientServerEntities")
	if cs == nil {
		t.Fatal("missing ClientServerEntities")
	}
	t.Logf("client-server entities: %d", len(cs.Children))
	if len(cs.Children) < 30 {
		t.Fatalf("only %d entities", len(cs.Children))
	}
}
