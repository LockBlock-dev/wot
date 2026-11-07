package lobby

import (
	"bytes"
	"errors"
	"testing"
)

// TestSmallRoundTrip covers every family the lobby uses.
func TestSmallRoundTrip(t *testing.T) {
	cases := []Small{
		{Family: 0x1a, Type: 0x5e, Body: []byte{1, 0, 0, 0, 0}},
		{Family: 0x1a, Type: 0x69, Body: []byte{0x42, 0x80, 0x02, 0x7d}},
		{Family: 0x1a, Type: 0x76, Body: bytes.Repeat([]byte{0xab}, 156)},
		{Family: 0x1a, Type: SmallStatsType, Body: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{Family: 0x13, Body: []byte{0x7a}},
		{Family: 0x45, Body: []byte{9, 9}},
		{Family: 0xff, Body: []byte{1, 0, 0, 0, 'h', 'i'}},
	}
	for _, want := range cases {
		raw, err := want.Encode()
		if err != nil {
			t.Fatalf("%#02x/%#02x: Encode: %v", want.Family, want.Type, err)
		}
		got, n, err := ParseSmall(raw)
		if err != nil {
			t.Fatalf("%#02x/%#02x: ParseSmall: %v", want.Family, want.Type, err)
		}
		if n != len(raw) {
			t.Errorf("%#02x/%#02x: consumed %d of %d", want.Family, want.Type, n, len(raw))
		}
		if got.Family != want.Family || got.Type != want.Type || !bytes.Equal(got.Body, want.Body) {
			t.Errorf("%#02x/%#02x round-trip = %#02x/%#02x % x", want.Family, want.Type, got.Family, got.Type, got.Body)
		}
	}
}

// TestSmallStatsHasNoLengthByte pins the 1a/5b exception: its body is
// fixed and the len8 position carries the low counter byte, so writing a
// length there would corrupt the counters.
func TestSmallStatsHasNoLengthByte(t *testing.T) {
	s := Small{Family: 0x1a, Type: SmallStatsType, Body: []byte{0x08, 0x91, 0, 0, 0x27, 0x36, 1, 0}}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 10 {
		t.Fatalf("1a/5b is %d B, want 10 (no length byte)", len(raw))
	}
	if raw[2] != 0x08 {
		t.Errorf("byte 2 = %#02x, want the first counter byte", raw[2])
	}
	// A wrong body size is refused rather than silently framed.
	if _, err := (Small{Family: 0x1a, Type: SmallStatsType, Body: []byte{1}}).Encode(); err == nil {
		t.Error("short 1a/5b accepted")
	}
}

// TestParseSmallsWalksBackToBack covers a datagram carrying several
// smalls, which is the case that made reading app[0] wrong.
func TestParseSmallsWalksBackToBack(t *testing.T) {
	a, _ := Small{Family: 0x13, Body: []byte{1}}.Encode()
	b, _ := Small{Family: 0x1a, Type: 0x76, Body: []byte("abc")}.Encode()
	c, _ := Small{Family: 0x1a, Type: 0x5e, Body: []byte{0, 0, 0, 0, 0}}.Encode()
	all := append(append(append([]byte{}, a...), b...), c...)

	got, err := ParseSmalls(all)
	if err != nil {
		t.Fatalf("ParseSmalls: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("%d smalls, want 3", len(got))
	}
	if got[1].Type != 0x76 || string(got[1].Body) != "abc" {
		t.Errorf("second small = %+v", got[1])
	}
}

// TestFindSmallIgnoresCoincidentalTags is why the typed lookup replaced a
// byte scan: a tag pair inside a payload must not match.
func TestFindSmallIgnoresCoincidentalTags(t *testing.T) {
	// A 1a/76 whose body happens to contain 1a 67.
	body := []byte{0x00, 0x1a, 0x67, 0x99}
	raw, _ := Small{Family: 0x1a, Type: 0x76, Body: body}.Encode()
	if FindSmall(raw, 0x1a, 0x67) != nil {
		t.Fatal("a tag pair inside a payload matched")
	}
	if FindSmall(raw, 0x1a, 0x76) == nil {
		t.Fatal("the real small did not match")
	}
}

// TestParseSmallUnknownFamily keeps an unmapped family distinguishable
// from corruption, so a walker can hand the rest back.
func TestParseSmallUnknownFamily(t *testing.T) {
	_, _, err := ParseSmall([]byte{0xbb, 0x02})
	if !errors.Is(err, ErrUnknownSmall) {
		t.Fatalf("err = %v, want ErrUnknownSmall", err)
	}
	// Truncation is a different error.
	if _, _, err := ParseSmall([]byte{0x1a, 0x76, 0x40}); errors.Is(err, ErrUnknownSmall) {
		t.Fatal("truncation reported as an unknown family")
	}
}

// TestSmallEncodeRefusesBadShapes keeps a malformed small from reaching
// the wire.
func TestSmallEncodeRefusesBadShapes(t *testing.T) {
	if _, err := (Small{Family: 0x13, Body: []byte{1, 2}}).Encode(); err == nil {
		t.Error("2-byte tick accepted")
	}
	// 1a/76 is the one 0x1a small with a u16 length, so 256 B is fine
	// there; every other 0x1a type is capped at the u8 field.
	if _, err := (Small{Family: 0x1a, Type: 0x76, Body: bytes.Repeat([]byte{0}, 256)}).Encode(); err != nil {
		t.Errorf("256-byte 1a/76 body refused: %v", err)
	}
	if _, err := (Small{Family: 0x1a, Type: 0x69, Body: bytes.Repeat([]byte{0}, 256)}).Encode(); err == nil {
		t.Error("256-byte 1a/69 body accepted")
	}
	if _, err := (Small{Family: 0x46}).Encode(); err == nil {
		t.Error("0x46 built from a payload")
	}
	if _, err := (Small{Family: 0x99}).Encode(); err == nil {
		t.Error("unknown family encoded")
	}
}
