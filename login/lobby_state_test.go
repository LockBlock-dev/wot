package login

// Offline lobby-state conversion tests (synthetic fixtures only).
import (
	"testing"
)

func TestPlainValue(t *testing.T) {
	doc := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01sX\x01\x00\x00\x00b](K\x02K\x03es.")
	v, _, err := DecodeOne(doc)
	if err != nil {
		t.Fatal(err)
	}
	var dropped int
	p := PlainValue(v, &dropped)
	m, ok := p.(map[string]interface{})
	if !ok || dropped != 0 {
		t.Fatalf("plain=%T dropped=%d", p, dropped)
	}
	if m["a"] != int64(1) {
		t.Fatalf("a=%v", m["a"])
	}
	l, ok := m["b"].([]interface{})
	if !ok || len(l) != 2 || l[0] != int64(2) || l[1] != int64(3) {
		t.Fatalf("b=%v", m["b"])
	}
	// Non-string keys drop (counted, never logged).
	mixed := &PDict{Entries: []PEntry{{Key: 7, Value: int64(1)}, {Key: "x", Value: nil}}}
	var d2 int
	p2 := PlainValue(mixed, &d2).(map[string]interface{})
	if d2 != 1 || len(p2) != 1 || p2["x"] != nil {
		t.Fatalf("mixed=%v dropped=%d", p2, d2)
	}
	// Depth cap terminates adversarial nesting.
	deep := interface{}(int64(0))
	for i := 0; i < 20; i++ {
		deep = &PList{Items: []interface{}{deep}}
	}
	if PlainValue(deep, nil) == nil {
		t.Fatal("top must survive")
	}
}

func TestSalvageChunk(t *testing.T) {
	doc := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	junk := []byte("\xff\xfe\xfd")
	b := SalvageChunk(append(append([]byte(nil), doc...), junk...))
	if b.Prefix != len(doc) {
		t.Fatalf("prefix=%d", b.Prefix)
	}
	if len(b.Items) != 1 {
		t.Fatalf("items=%d", len(b.Items))
	}
	m, ok := b.Items[0].(map[string]interface{})
	if !ok || m["a"] != int64(1) {
		t.Fatalf("item=%v", b.Items[0])
	}
	// Empty/random chunk salvages to nothing (barren by design).
	if b2 := SalvageChunk([]byte{0x13, 0x53, 0x46}); len(b2.Items) != 0 {
		t.Fatalf("random=%v", b2.Items)
	}
}
