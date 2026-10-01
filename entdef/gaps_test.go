package entdef

// Trivial accessors over synthetic sections (no fixture files).
import (
	"encoding/binary"
	"math"
	"testing"
)

func TestChildrenByNameSynthetic(t *testing.T) {
	s := &Section{Children: []*Section{{Name: "a"}, {Name: "b"}, {Name: "a"}}}
	got := s.ChildrenByName("a")
	if len(got) != 2 {
		t.Fatalf("ChildrenByName(a) = %d, want 2", len(got))
	}
	if len(s.ChildrenByName("zzz")) != 0 {
		t.Fatal("unknown name must yield none")
	}
}

func TestF32leRoundTrip(t *testing.T) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(1.5))
	if got := f32le(b[:]); got != 1.5 {
		t.Fatalf("f32le = %v, want 1.5", got)
	}
}
