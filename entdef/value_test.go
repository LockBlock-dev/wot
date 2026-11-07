package entdef

import (
	"bytes"
	"strings"
	"testing"
)

// roundTrip encodes v as dt and decodes it back, requiring the bytes to
// survive unchanged.
func roundTrip(t *testing.T, c Codec, dt DataType, v Value) Value {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Write(&buf, dt, v); err != nil {
		t.Fatalf("Write %s: %v", dt.Describe(), err)
	}
	got, err := c.Read(bytes.NewReader(buf.Bytes()), dt)
	if err != nil {
		t.Fatalf("Read %s: %v", dt.Describe(), err)
	}
	return got
}

// TestValueScalars covers the fixed-width types.
func TestValueScalars(t *testing.T) {
	c := NewCodec()

	for _, size := range []int{1, 2, 4, 8} {
		dt := &intType{signed: true, size: size}
		v := Value{Kind: VInt, Int: -3}
		if got := roundTrip(t, c, dt, v); got.Int != -3 {
			t.Errorf("INT%d round-trip = %d", size*8, got.Int)
		}
		dtu := &intType{signed: false, size: size}
		vu := Value{Kind: VUint, Uint: 7}
		if got := roundTrip(t, c, dtu, vu); got.Uint != 7 {
			t.Errorf("UINT%d round-trip = %d", size*8, got.Uint)
		}
	}

	for _, bits := range []int{32, 64} {
		dt := &floatType{bits: bits}
		if got := roundTrip(t, c, dt, Value{Kind: VFloat, Float: 1.5}); got.Float != 1.5 {
			t.Errorf("FLOAT%d round-trip = %v", bits, got.Float)
		}
	}

	if got := roundTrip(t, c, &stringType{tag: "String"}, Value{Kind: VString, Str: "hello"}); got.Str != "hello" {
		t.Errorf("STRING round-trip = %q", got.Str)
	}
}

// TestValueVector covers VECTOR2/3/4, which are n little-endian float32s.
func TestValueVector(t *testing.T) {
	c := NewCodec()
	for _, n := range []int{2, 3, 4} {
		dt := &vectorType{n: n}
		seq := make([]Value, n)
		for i := range seq {
			seq[i] = Value{Kind: VFloat, Float: float64(i) + 0.5}
		}
		got := roundTrip(t, c, dt, Value{Kind: VSeq, Seq: seq})
		if len(got.Seq) != n {
			t.Fatalf("VECTOR%d round-trip has %d elements", n, len(got.Seq))
		}
		for i := range got.Seq {
			if got.Seq[i].Float != float64(i)+0.5 {
				t.Errorf("VECTOR%d[%d] = %v", n, i, got.Seq[i].Float)
			}
		}
	}
}

// TestValueSequences covers fixed and variable ARRAY/TUPLE.
func TestValueSequences(t *testing.T) {
	c := NewCodec()
	elem := &intType{signed: true, size: 4}

	// Fixed: no count prefix.
	fixed := &seqType{kind: "Array", elem: elem, size: 3}
	got := roundTrip(t, c, fixed, Value{Kind: VSeq, Seq: []Value{
		{Kind: VInt, Int: 1}, {Kind: VInt, Int: 2}, {Kind: VInt, Int: 3},
	}})
	if len(got.Seq) != 3 || got.Seq[2].Int != 3 {
		t.Errorf("fixed ARRAY round-trip = %+v", got.Seq)
	}

	// Variable: a 1-byte count prefix.
	variable := &seqType{kind: "Array", elem: elem, size: 0}
	got = roundTrip(t, c, variable, Value{Kind: VSeq, Seq: []Value{
		{Kind: VInt, Int: 9}, {Kind: VInt, Int: 8},
	}})
	if len(got.Seq) != 2 || got.Seq[0].Int != 9 {
		t.Errorf("variable ARRAY round-trip = %+v", got.Seq)
	}

	// A fixed sequence of the wrong length is refused, not truncated.
	var buf bytes.Buffer
	if err := c.Write(&buf, fixed, Value{Kind: VSeq, Seq: []Value{{Kind: VInt, Int: 1}}}); err == nil {
		t.Error("short fixed ARRAY accepted")
	}
}

// TestValueFixedDict covers field order and the allowNone prefix.
func TestValueFixedDict(t *testing.T) {
	c := NewCodec()
	dt := &fixedDictType{fields: []fixedDictField{
		{name: "id", typ: &intType{signed: true, size: 4}},
		{name: "name", typ: &stringType{tag: "String"}},
	}}
	v := Value{Kind: VDict, Dict: []DictField{
		{Name: "id", Value: Value{Kind: VInt, Int: 42}},
		{Name: "name", Value: Value{Kind: VString, Str: "tank"}},
	}}
	got := roundTrip(t, c, dt, v)
	if id, ok := got.Get("id"); !ok || id.Int != 42 {
		t.Errorf("id = %+v", id)
	}
	if name, ok := got.Get("name"); !ok || name.Str != "tank" {
		t.Errorf("name = %+v", name)
	}

	// A missing field is an error, not a zero value.
	var buf bytes.Buffer
	if err := c.Write(&buf, dt, Value{Kind: VDict, Dict: []DictField{
		{Name: "id", Value: Value{Kind: VInt, Int: 1}},
	}}); err == nil {
		t.Error("incomplete FIXED_DICT accepted")
	}

	// allowNone writes a leading flag byte.
	opt := &fixedDictType{allowNone: true, fields: dt.fields}
	var b bytes.Buffer
	if err := c.Write(&b, opt, Value{Kind: VNone}); err != nil {
		t.Fatalf("Write none: %v", err)
	}
	if b.Len() != 1 || b.Bytes()[0] != 0 {
		t.Errorf("allowNone None = % x, want 00", b.Bytes())
	}
	if got := roundTrip(t, c, opt, v); got.Kind != VDict {
		t.Errorf("allowNone round-trip kind = %d", got.Kind)
	}
}

// TestValueTypeMismatch keeps a wrong tag from being coerced.
func TestValueTypeMismatch(t *testing.T) {
	c := NewCodec()
	var buf bytes.Buffer
	if err := c.Write(&buf, &intType{signed: true, size: 4}, Value{Kind: VString, Str: "x"}); err == nil {
		t.Error("string written as INT32")
	}
	if err := c.Write(&buf, &stringType{tag: "String"}, Value{Kind: VInt, Int: 1}); err == nil {
		t.Error("int written as STRING")
	}
}

// TestValueVarLenHeader covers a site with a wider length header.
func TestValueVarLenHeader(t *testing.T) {
	c := Codec{VarLen: 2}
	var buf bytes.Buffer
	if err := c.Write(&buf, &stringType{tag: "String"}, Value{Kind: VString, Str: "ab"}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4 {
		t.Fatalf("2-byte header + 2 bytes = %d, want 4", buf.Len())
	}
	got, err := c.Read(bytes.NewReader(buf.Bytes()), &stringType{tag: "String"})
	if err != nil || got.Str != "ab" {
		t.Fatalf("round-trip = %q, %v", got.Str, err)
	}
}

// A PYTHON property is `AllowUnsafeData`: once it outgrows the
// variable-length header the engine writes `[0xFF][u24 length][data]`, not
// `[len][data]`. The lobby's `initialServerSettings` is a pickled dict of
// several hundred bytes and always takes that form — writing it with a 1-byte
// header is what made `CreateBasePlayer` fail with "length 802 does not fit a
// 1-byte header" and left a re-login stuck at the login screen.
func TestPythonBlobUsesTheUnsafeLength(t *testing.T) {
	dt := &stringType{"Python"}
	blob := strings.Repeat("x", 802)
	var buf bytes.Buffer
	if err := (Codec{}).Write(&buf, dt, Value{Kind: VString, Str: blob}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := buf.Bytes()
	if len(got) != 4+len(blob) {
		t.Fatalf("%d B, want %d", len(got), 4+len(blob))
	}
	if got[0] != 0xFF {
		t.Fatalf("first byte %#02x, want 0xFF (the unsafe marker)", got[0])
	}
	if n := int(got[1]) | int(got[2])<<8 | int(got[3])<<16; n != len(blob) {
		t.Fatalf("u24 length %d, want %d", n, len(blob))
	}
	// A short one keeps the plain header.
	var small bytes.Buffer
	if err := (Codec{}).Write(&small, dt, Value{Kind: VString, Str: "abc"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := small.Bytes(); len(got) != 4 || got[0] != 3 {
		t.Fatalf("short blob = % x, want 03 61 62 63", got)
	}
}
