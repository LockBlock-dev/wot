package login

// Offline lobby-pickle decoding: hand-crafted protocol-2 fixtures
// only (no captures — values here are synthetic).
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func dictFixture() []byte {
	// Real CPython 3 output for
	// {'name':'Alice','age':42,'tags':['a','b'],'tup':(1,2)}
	// (protocol 2, pasted as emitted — MARK + SETITEMS form).
	return []byte("\x80\x02}q\x00(X\x04\x00\x00\x00nameq\x01" +
		"X\x05\x00\x00\x00Aliceq\x02X\x03\x00\x00\x00ageq\x03K*" +
		"X\x04\x00\x00\x00tagsq\x04]q\x05(X\x01\x00\x00\x00aq\x06" +
		"X\x01\x00\x00\x00bq\x07eX\x03\x00\x00\x00tupq\x08K\x01K\x02\x86q\x09u.")
}

func dictLookup(t *testing.T, d *PDict, key string) interface{} {
	t.Helper()
	for _, e := range d.Entries {
		if e.Key == key {
			return e.Value
		}
	}
	t.Fatalf("key %q missing", key)
	return nil
}

func TestPickleDict(t *testing.T) {
	v, err := DecodeLobbyPickle(dictFixture())
	if err != nil {
		t.Fatal(err)
	}
	d, ok := v.(*PDict)
	if !ok {
		t.Fatalf("top %T", v)
	}
	if got := dictLookup(t, d, "name"); got != "Alice" {
		t.Fatalf("name=%v", got)
	}
	if got := fmt.Sprintf("%d", dictLookup(t, d, "age")); got != "42" {
		t.Fatalf("age=%v", got)
	}
	tags, ok := dictLookup(t, d, "tags").(*PList)
	if !ok || len(tags.Items) != 2 {
		t.Fatalf("tags=%v", dictLookup(t, d, "tags"))
	}
	tup, ok := dictLookup(t, d, "tup").(*PTuple)
	if !ok || len(tup.Items) != 2 {
		t.Fatalf("tup=%v", dictLookup(t, d, "tup"))
	}
	if s := PickleSummary(v); s != "dict{age,name,tags,tup}" {
		t.Fatalf("summary=%q", s)
	}
	// Batched MARK + SETITEMS form (what CPython emits for dicts).
	v2, err := DecodeLobbyPickle([]byte("\x80\x02}(X\x01\x00\x00\x00aK\x01X\x01\x00\x00\x00bK\x02u."))
	if err != nil {
		t.Fatal(err)
	}
	d2, ok := v2.(*PDict)
	if !ok || len(d2.Entries) != 2 {
		t.Fatalf("batched=%v", v2)
	}
}

func TestPickleDeque(t *testing.T) {
	// Real CPython form: GLOBAL(collections deque) + EMPTY_TUPLE +
	// REDUCE (empty deque) + MARK + items + APPENDS.
	raw := []byte("ccollections\ndeque\nq\x00)Rq\x01(K\x01K\x02e.")
	v, err := DecodeLobbyPickle(raw)
	if err != nil {
		t.Fatal(err)
	}
	dq, ok := v.(*Deque)
	if !ok {
		t.Fatalf("top %T", v)
	}
	if len(dq.Items) != 2 || fmt.Sprintf("%d", dq.Items[0]) != "1" {
		t.Fatalf("items=%v", dq.Items)
	}
	if s := PickleSummary(v); s != "deque[2]" {
		t.Fatalf("summary=%q", s)
	}
}

func TestPickleGenericClass(t *testing.T) {
	// Unknown GLOBAL + empty-tuple REDUCE: data holder, not failure.
	raw := []byte("cmy.mod\nMyClass\n)Rq\x00.")
	v, err := DecodeLobbyPickle(raw)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := v.(*GenericValue)
	if !ok {
		t.Fatalf("top %T", v)
	}
	if g.Module != "my.mod" || g.Name != "MyClass" {
		t.Fatalf("generic=%+v", g)
	}
	if s := PickleSummary(v); s != "my.mod.MyClass" {
		t.Fatalf("summary=%q", s)
	}
}

func TestHarvestStream(t *testing.T) {
	docA := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	docB := []byte("\x80\x02]K\x02aK\x03a.")
	// Case 1: pure-garbage gap (nothing to salvage, resync recovers).
	junk := []byte("\xff\xfe\xfd\xfc\xfb")
	stream := append(append(append([]byte(nil), docA...), junk...), docB...)
	counts, docs, gaps, valid := HarvestStream(stream)
	if docs != 2 || gaps != 1 {
		t.Fatalf("docs=%d gaps=%d", docs, gaps)
	}
	if counts["a"] != 1 || valid != 25 {
		t.Fatalf("counts=%v valid=%d", counts, valid)
	}
	// Case 2: truncated-doc gap (salvage recovers the partial dict).
	junk2 := []byte("\x80\x02}q\x00X\x01\x00\x00\x00bK\x02\xff")
	stream2 := append(append(append([]byte(nil), docA...), junk2...), docB...)
	counts2, docs2, gaps2, valid2 := HarvestStream(stream2)
	if docs2 != 2 || gaps2 != 1 {
		t.Fatalf("docs=%d gaps=%d", docs2, gaps2)
	}
	// Salvage harvests closed entries only (in-progress key/value
	// pairs still on the stack are values, not schema).
	if counts2["a"] != 1 || valid2 != 38 {
		t.Fatalf("counts=%v valid=%d", counts2, valid2)
	}
	// HarvestKeys depth-caps and skips non-string keys silently.
	deep := &PDict{Entries: []PEntry{{Key: 42, Value: &PList{Items: []interface{}{&PDict{Entries: []PEntry{{Key: "x", Value: nil}}}}}}}}
	c2 := map[string]int{}
	HarvestKeys(deep, c2)
	if len(c2) != 1 || c2["x"] != 1 {
		t.Fatalf("deep=%v", c2)
	}
}

func TestPickleLongSign(t *testing.T) {
	// Real CPython 3 protocol-2 outputs (past tense verified).
	vecs := map[string]int64{
		"\x80\x02J\xff\xff\xff\xff.":                -1,
		"\x80\x02J\x80\xff\xff\xff.":                -128,
		"\x80\x02J\x7f\xff\xff\xff.":                -129,
		"\x80\x02\x8a\x06\x00\x00\x00\x00\x00\x01.": 1 << 40,
		"\x80\x02\x8a\x06\x00\x00\x00\x00\x00\xff.": -(1 << 40),
		"\x80\x02M\x00\x01.":                        256,
		"\x80\x02\x8b\x02\x00\x00\x00\xff\xff.":     -1,
		"\x80\x02\x8b\x02\x00\x00\x00\x00\x80.":     -32768,
	}
	for raw, want := range vecs {
		v, err := DecodeLobbyPickle([]byte(raw))
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		got, ok := v.(int64)
		if !ok || got != want {
			t.Fatalf("%q: got %v (%T), want %d", raw, v, v, want)
		}
	}
}

func TestPickleTruncated(t *testing.T) {
	if _, err := DecodeLobbyPickle(dictFixture()[:10]); err == nil {
		t.Fatal("truncated pickle must fail")
	}
	if _, err := DecodeLobbyPickle([]byte("not a pickle")); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestDecodeAt(t *testing.T) {
	doc := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	padded := append([]byte("HEADR!"), doc...)
	v, off, n, err := DecodeAt(padded, 15)
	if err != nil {
		t.Fatal(err)
	}
	if off != 6 || n != len(doc) {
		t.Fatalf("off=%d n=%d want 6,%d", off, n, len(doc))
	}
	if s := PickleSummary(v); s != "dict{a}" {
		t.Fatalf("summary=%q", s)
	}
	if _, _, _, err := DecodeAt([]byte("garbage-nothing-here!"), 15); err == nil {
		t.Fatal("garbage must fail")
	}
}

func TestDecodeBundle(t *testing.T) {
	docA := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	docB := []byte("\x80\x02]K\x02a.")
	hole := []byte("\xff\xfe\xfd\xfc\xfb")
	frags := []Frag{
		{Seq: 1, Payload: docA[:8]},
		{Seq: 2, Payload: append(append([]byte(nil), docA[8:]...), hole...)},
		{Seq: 3, Payload: docB},
	}
	docs := DecodeBundle(frags)
	if len(docs) != 2 {
		t.Fatalf("docs=%d", len(docs))
	}
	if s := PickleSummary(docs[0]); s != "dict{a}" {
		t.Fatalf("doc0=%q", s)
	}
}

func mkFrag(t *testing.T, seq uint32, payload []byte) DumpDatagram {
	t.Helper()
	full := make([]byte, 2)
	binary.LittleEndian.PutUint16(full, 0x0078)
	full = append(full, payload...)
	var s, c [4]byte
	binary.LittleEndian.PutUint32(s[:], seq)
	binary.LittleEndian.PutUint32(c[:], 0)
	full = append(full, s[:]...)
	full = append(full, s[:]...)
	full = append(full, c[:]...)
	enc, err := encryptBlowfish(floodTestKey, full)
	if err != nil {
		t.Fatal(err)
	}
	return DumpDatagram{Dir: "S>C", Addr: "f->t", Data: append([]byte{1, 2, 3, 4}, enc...)}
}

func TestInventory(t *testing.T) {
	docA := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	docB := []byte("\x80\x02]K\x02aK\x03a.")
	junk := []byte("\xff\xfe\xfd\xfc\xfb\x80\x09garbage")
	stream := append(append(append([]byte(nil), docA...), junk...), docB...)
	segs := Inventory(stream)
	if len(segs) != 2 {
		t.Fatalf("segs=%d", len(segs))
	}
	if segs[0].Summary != "dict{a}" || segs[0].Gap != 0 {
		t.Fatalf("seg0=%+v", segs[0])
	}
	if segs[1].Summary != "list[2]int64" || segs[1].Gap != 14 || segs[1].Offset != 29 {
		t.Fatalf("seg1=%+v", segs[1])
	}
	// Trailing gap reported, not hidden.
	segs2 := Inventory(append(docA, 0xFF, 0xFE))
	if len(segs2) != 2 || segs2[1].Consumed != 0 || segs2[1].Gap != 2 {
		t.Fatalf("trailing=%+v", segs2)
	}
}

func TestReassembleBaseVote(t *testing.T) {
	// Sep-17 style: odd-shape base 0x51 voted from dd00 heads.
	mk := func(seq uint32, head []byte, bodyLen int) DumpDatagram {
		p := append(append([]byte(nil), head...), bytes.Repeat([]byte{0x41}, bodyLen)...)
		return mkFrag(t, seq, p)
	}
	d0 := mk(1, []byte{0xFF, 0x18, 0x46, 0x03}, 104)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mk(2, []byte{0x13, 0x53, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x02}, 100),
		mk(3, []byte{0x13, 0x55, 0x1A, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 100),
		mk(4, []byte{0x13, 0x56, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x05}, 100),
	}
	frags, _, _, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 4 {
		t.Fatalf("frags=%d", len(frags))
	}
	for i, want := range []int{1, 2, 4, 5} {
		if frags[i].NN != want {
			t.Fatalf("frag%d NN=%d want %d", i, frags[i].NN, want)
		}
	}
}

func TestReassembleGapFill(t *testing.T) {
	mk := func(seq uint32, head []byte, bodyLen int) DumpDatagram {
		p := append(append([]byte(nil), head...), bytes.Repeat([]byte{0x41}, bodyLen)...)
		return mkFrag(t, seq, p)
	}
	d0 := mk(1, []byte{0xFF, 0x18, 0x46, 0x03}, 104)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mk(9, []byte{0x13, 0x7B, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x03}, 100),
		mk(3, []byte{0xFE, 0x7B, 0x71, 0xC5, 0xAB, 0x0C, 0x86, 0xF1}, 100),
	}
	frags, _, _, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 3 {
		t.Fatalf("frags=%d", len(frags))
	}
	if frags[0].NN != 1 || frags[1].NN != 3 {
		t.Fatalf("nns=%d,%d", frags[0].NN, frags[1].NN)
	}
	if frags[2].NN != 2 {
		t.Fatalf("gap-filled NN=%d, want 2", frags[2].NN)
	}
	if len(frags[2].Payload) != 100 {
		t.Fatalf("unknown head not stripped 8: len=%d", len(frags[2].Payload))
	}
}

func TestReassembleFrags(t *testing.T) {
	// Chunk model: same-seq datagrams are one chunk's burst (head +
	// continuations), concatenated — not dropped as retransmits.
	p0 := append([]byte{0xFF, 0x18, 0x46, 0x03}, bytes.Repeat([]byte{0x41}, 100)...)
	p0cont := bytes.Repeat([]byte{0x43}, 104) // same wire size as p0
	p1 := append([]byte{0x13, 0x50, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x07}, bytes.Repeat([]byte{0x42}, 100)...)
	d0 := mkFrag(t, 7, p0)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mkFrag(t, 7, p0cont), // same seq: continuation, appended raw
		mkFrag(t, 9, p1),
		mkFrag(t, 3, p1),
	}
	frags, offsets, st, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frags != 4 || len(frags) != 3 {
		t.Fatalf("frags=%d st=%+v", len(frags), st)
	}
	if len(frags[0].Payload) != 204 || frags[0].Payload[0] != 0x41 || frags[0].Payload[100] != 0x43 {
		t.Fatalf("frag0 not concatenated: len=%d", len(frags[0].Payload))
	}
	if frags[0].NN != 1 {
		t.Fatalf("frag0 NN=%d", frags[0].NN)
	}
	if len(frags[1].Payload) != 100 || frags[1].Payload[0] != 0x42 {
		t.Fatalf("frag1 head not stripped: %x", frags[1].Payload[:4])
	}
	if frags[1].NN != 7 {
		t.Fatalf("frag1 NN=%d", frags[1].NN)
	}
	if len(offsets) != 3 || offsets[0] != 0 || offsets[1] != 204 || offsets[2] != 304 {
		t.Fatalf("offsets=%v", offsets)
	}
}

func TestPickleSummarySecrets(t *testing.T) {
	v, err := DecodeLobbyPickle(dictFixture())
	if err != nil {
		t.Fatal(err)
	}
	s := PickleSummary(v)
	for _, leak := range []string{"Alice", "42"} {
		if strings.Contains(s, leak) {
			t.Fatalf("summary leaks value %q: %q", leak, s)
		}
	}
}
