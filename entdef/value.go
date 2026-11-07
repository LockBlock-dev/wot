package entdef

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// Value is one entity-def value: the Go side of a property or a method
// argument, tagged with the shape the def gave it.
//
// It is deliberately loose — a def type decides how a Value is read and
// written, so the same struct carries an int, a string, a vector or a
// nested dict. Read and Write check the tag against the type and fail
// loud on a mismatch rather than coercing.
type Value struct {
	Kind ValueKind

	Int   int64
	Uint  uint64
	Float float64
	Str   string
	Bool  bool

	// Seq holds ARRAY/TUPLE elements, in order.
	Seq []Value
	// Dict holds FIXED_DICT fields, in the def's declared order.
	Dict []DictField
}

// ValueKind tags a Value.
type ValueKind uint8

const (
	VNone ValueKind = iota
	VBool
	VInt
	VUint
	VFloat
	VString
	VSeq
	VDict
)

// DictField is one FIXED_DICT entry.
type DictField struct {
	Name  string
	Value Value
}

// Get returns the named field of a dict value.
func (v Value) Get(name string) (Value, bool) {
	for _, f := range v.Dict {
		if f.Name == name {
			return f.Value, true
		}
	}
	return Value{}, false
}

// Codec reads and writes entity-def values.
//
// VarLen is the variable-length header size the defs use for strings and
// variable sequences (BigWorld's VariableLengthHeaderSize, 1 in every
// 2.4.x def). It is a property of the *site*, not the type, so it lives
// here rather than on DataType.
type Codec struct {
	VarLen int
}

// NewCodec returns a codec with the default 1-byte variable header.
func NewCodec() Codec { return Codec{VarLen: 1} }

func (c Codec) varLen() int {
	if c.VarLen <= 0 {
		return 1
	}
	return c.VarLen
}

// Read decodes one value of type dt.
func (c Codec) Read(r io.Reader, dt DataType) (Value, error) {
	switch t := dt.(type) {
	case *intType:
		return c.readInt(r, t)
	case *floatType:
		return c.readFloat(r, t)
	case *stringType:
		return c.readString(r)
	case *vectorType:
		return c.readVector(r, t)
	case *mailboxType:
		return c.readMailbox(r)
	case *seqType:
		return c.readSeq(r, t)
	case *fixedDictType:
		return c.readFixedDict(r, t)
	}
	return Value{}, fmt.Errorf("entdef: no value codec for %s", dt.Describe())
}

// Write encodes v as type dt.
func (c Codec) Write(w io.Writer, dt DataType, v Value) error {
	switch t := dt.(type) {
	case *intType:
		return c.writeInt(w, t, v)
	case *floatType:
		return c.writeFloat(w, t, v)
	case *stringType:
		return c.writeString(w, t, v)
	case *vectorType:
		return c.writeVector(w, t, v)
	case *mailboxType:
		return c.writeMailbox(w, v)
	case *seqType:
		return c.writeSeq(w, t, v)
	case *fixedDictType:
		return c.writeFixedDict(w, t, v)
	}
	return fmt.Errorf("entdef: no value codec for %s", dt.Describe())
}

// --- integers ---

func (c Codec) readInt(r io.Reader, t *intType) (Value, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:t.size]); err != nil {
		return Value{}, err
	}
	if t.signed {
		var n int64
		switch t.size {
		case 1:
			n = int64(int8(buf[0]))
		case 2:
			n = int64(int16(binary.LittleEndian.Uint16(buf[:2])))
		case 4:
			n = int64(int32(binary.LittleEndian.Uint32(buf[:4])))
		case 8:
			n = int64(binary.LittleEndian.Uint64(buf[:8]))
		default:
			return Value{}, fmt.Errorf("entdef: bad int size %d", t.size)
		}
		return Value{Kind: VInt, Int: n}, nil
	}
	var n uint64
	switch t.size {
	case 1:
		n = uint64(buf[0])
	case 2:
		n = uint64(binary.LittleEndian.Uint16(buf[:2]))
	case 4:
		n = uint64(binary.LittleEndian.Uint32(buf[:4]))
	case 8:
		n = binary.LittleEndian.Uint64(buf[:8])
	default:
		return Value{}, fmt.Errorf("entdef: bad uint size %d", t.size)
	}
	return Value{Kind: VUint, Uint: n}, nil
}

func (c Codec) writeInt(w io.Writer, t *intType, v Value) error {
	var buf [8]byte
	if t.signed {
		if v.Kind != VInt {
			return fmt.Errorf("entdef: %s wants an int, got kind %d", t.Describe(), v.Kind)
		}
		switch t.size {
		case 1:
			buf[0] = byte(int8(v.Int))
		case 2:
			binary.LittleEndian.PutUint16(buf[:2], uint16(int16(v.Int)))
		case 4:
			binary.LittleEndian.PutUint32(buf[:4], uint32(int32(v.Int)))
		case 8:
			binary.LittleEndian.PutUint64(buf[:8], uint64(v.Int))
		default:
			return fmt.Errorf("entdef: bad int size %d", t.size)
		}
		_, err := w.Write(buf[:t.size])
		return err
	}
	if v.Kind != VUint && v.Kind != VInt {
		return fmt.Errorf("entdef: %s wants a uint, got kind %d", t.Describe(), v.Kind)
	}
	n := v.Uint
	if v.Kind == VInt {
		n = uint64(v.Int)
	}
	switch t.size {
	case 1:
		buf[0] = byte(n)
	case 2:
		binary.LittleEndian.PutUint16(buf[:2], uint16(n))
	case 4:
		binary.LittleEndian.PutUint32(buf[:4], uint32(n))
	case 8:
		binary.LittleEndian.PutUint64(buf[:8], n)
	default:
		return fmt.Errorf("entdef: bad uint size %d", t.size)
	}
	_, err := w.Write(buf[:t.size])
	return err
}

// --- floats ---

func (c Codec) readFloat(r io.Reader, t *floatType) (Value, error) {
	if t.bits == 32 {
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Value{}, err
		}
		return Value{Kind: VFloat, Float: float64(math.Float32frombits(binary.LittleEndian.Uint32(buf[:])))}, nil
	}
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Value{}, err
	}
	return Value{Kind: VFloat, Float: math.Float64frombits(binary.LittleEndian.Uint64(buf[:]))}, nil
}

func (c Codec) writeFloat(w io.Writer, t *floatType, v Value) error {
	if v.Kind != VFloat {
		return fmt.Errorf("entdef: %s wants a float, got kind %d", t.Describe(), v.Kind)
	}
	if t.bits == 32 {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], math.Float32bits(float32(v.Float)))
		_, err := w.Write(buf[:])
		return err
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(v.Float))
	_, err := w.Write(buf[:])
	return err
}

// --- strings ---

func (c Codec) readString(r io.Reader) (Value, error) {
	n, err := c.readLen(r)
	if err != nil {
		return Value{}, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Value{}, err
	}
	return Value{Kind: VString, Str: string(buf)}, nil
}

func (c Codec) writeString(w io.Writer, t *stringType, v Value) error {
	if v.Kind != VString {
		return fmt.Errorf("entdef: string wants a string, got kind %d", v.Kind)
	}
	// A PYTHON property is `AllowUnsafeData`, and the engine writes those with
	// the "unsafe" length form once they outgrow the variable-length header:
	// `[0xFF][u24 length][data]` instead of `[len][data]`. The lobby's
	// `initialServerSettings` is a pickled dict of several hundred bytes, so it
	// always takes that form — `appendPacked` in `flood_build.go` is the same
	// rule, and it is what the client's `PythonStreamElement` reads.
	if t.tag == "Python" && len(v.Str) >= 0xFF {
		if len(v.Str) > 0xFFFFFF {
			return fmt.Errorf("entdef: python blob is %d B, beyond the u24 length", len(v.Str))
		}
		n := len(v.Str)
		if _, err := w.Write([]byte{0xFF, byte(n), byte(n >> 8), byte(n >> 16)}); err != nil {
			return err
		}
		_, err := io.WriteString(w, v.Str)
		return err
	}
	if err := c.writeLen(w, len(v.Str)); err != nil {
		return err
	}
	_, err := io.WriteString(w, v.Str)
	return err
}

// --- vectors ---

func (c Codec) readVector(r io.Reader, t *vectorType) (Value, error) {
	out := make([]Value, t.n)
	for i := range out {
		v, err := c.readFloat(r, &floatType{bits: 32})
		if err != nil {
			return Value{}, err
		}
		out[i] = v
	}
	return Value{Kind: VSeq, Seq: out}, nil
}

func (c Codec) writeVector(w io.Writer, t *vectorType, v Value) error {
	if v.Kind != VSeq || len(v.Seq) != t.n {
		return fmt.Errorf("entdef: %s wants %d floats, got kind %d with %d", t.Describe(), t.n, v.Kind, len(v.Seq))
	}
	for _, f := range v.Seq {
		if err := c.writeFloat(w, &floatType{bits: 32}, f); err != nil {
			return err
		}
	}
	return nil
}

// --- mailbox ---

func (c Codec) readMailbox(r io.Reader) (Value, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Value{}, err
	}
	id := int64(int32(binary.LittleEndian.Uint32(buf[:])))
	s, err := c.readString(r)
	if err != nil {
		return Value{}, err
	}
	return Value{Kind: VDict, Dict: []DictField{
		{Name: "id", Value: Value{Kind: VInt, Int: id}},
		{Name: "addr", Value: s},
	}}, nil
}

func (c Codec) writeMailbox(w io.Writer, v Value) error {
	id, ok := v.Get("id")
	if !ok {
		return fmt.Errorf("entdef: MAILBOX wants an id field")
	}
	addr, ok := v.Get("addr")
	if !ok {
		return fmt.Errorf("entdef: MAILBOX wants an addr field")
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(int32(id.Int)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	return c.writeString(w, &stringType{"String"}, addr)
}

// --- sequences ---

func (c Codec) readSeq(r io.Reader, t *seqType) (Value, error) {
	n := t.size
	if n <= 0 {
		var err error
		if n, err = c.readLen(r); err != nil {
			return Value{}, err
		}
	}
	out := make([]Value, n)
	for i := range out {
		v, err := c.Read(r, t.elem)
		if err != nil {
			return Value{}, err
		}
		out[i] = v
	}
	return Value{Kind: VSeq, Seq: out}, nil
}

func (c Codec) writeSeq(w io.Writer, t *seqType, v Value) error {
	if v.Kind != VSeq {
		return fmt.Errorf("entdef: %s wants a sequence, got kind %d", t.Describe(), v.Kind)
	}
	if t.size > 0 {
		if len(v.Seq) != t.size {
			return fmt.Errorf("entdef: %s wants %d elements, got %d", t.Describe(), t.size, len(v.Seq))
		}
	} else if err := c.writeLen(w, len(v.Seq)); err != nil {
		return err
	}
	for _, e := range v.Seq {
		if err := c.Write(w, t.elem, e); err != nil {
			return err
		}
	}
	return nil
}

// --- fixed dicts ---

func (c Codec) readFixedDict(r io.Reader, t *fixedDictType) (Value, error) {
	if t.allowNone {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Value{}, err
		}
		if b[0] == 0 {
			return Value{Kind: VNone}, nil
		}
	}
	out := make([]DictField, 0, len(t.fields))
	for _, f := range t.fields {
		v, err := c.Read(r, f.typ)
		if err != nil {
			return Value{}, fmt.Errorf("entdef: FIXED_DICT field %q: %w", f.name, err)
		}
		out = append(out, DictField{Name: f.name, Value: v})
	}
	return Value{Kind: VDict, Dict: out}, nil
}

func (c Codec) writeFixedDict(w io.Writer, t *fixedDictType, v Value) error {
	if t.allowNone {
		var b [1]byte
		if v.Kind == VNone {
			_, err := w.Write(b[:])
			return err
		}
		b[0] = 1
		if _, err := w.Write(b[:]); err != nil {
			return err
		}
	}
	if v.Kind != VDict {
		return fmt.Errorf("entdef: FIXED_DICT wants a dict, got kind %d", v.Kind)
	}
	for _, f := range t.fields {
		fv, ok := v.Get(f.name)
		if !ok {
			return fmt.Errorf("entdef: FIXED_DICT is missing field %q", f.name)
		}
		if err := c.Write(w, f.typ, fv); err != nil {
			return fmt.Errorf("entdef: FIXED_DICT field %q: %w", f.name, err)
		}
	}
	return nil
}

// --- variable-length headers ---

func (c Codec) readLen(r io.Reader) (int, error) {
	n := c.varLen()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(buf[i])
	}
	return int(v), nil
}

func (c Codec) writeLen(w io.Writer, n int) error {
	size := c.varLen()
	if n < 0 || (size < 8 && n >= 1<<(8*size)) {
		return fmt.Errorf("entdef: length %d does not fit a %d-byte header", n, size)
	}
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = byte(n >> (8 * i))
	}
	_, err := w.Write(buf)
	return err
}

// ZeroValue returns the default value for a datatype: the value the client
// itself would use for a property the server never set.
//
// It exists so an entity can be built from the defs alone — CreateBasePlayer
// and CreateCellPlayer write EVERY property in their domain, with no count
// prefix and no "absent" marker, so a server that only cares about three of
// the Avatar's fourteen base properties still has to write the other
// eleven.
func ZeroValue(dt DataType) Value {
	switch t := dt.(type) {
	case *intType:
		if t.signed {
			return Value{Kind: VInt}
		}
		return Value{Kind: VUint}
	case *floatType:
		return Value{Kind: VFloat}
	case *stringType:
		if t.tag == "Python" {
			// A PYTHON property must carry a VALID pickle, never an empty
			// blob: `PythonStreamElement::fromStreamToSink` treats a
			// zero-length value as a stream error ("Not enough data on
			// stream to read value") and the entity read fails. This is
			// the protocol-2 pickle of an empty dict.
			return Value{Kind: VString, Str: "\x80\x02}\x2e"}
		}
		return Value{Kind: VString}
	case *mailboxType:
		return Value{Kind: VDict, Dict: []DictField{
			{Name: "id", Value: Value{Kind: VInt}},
			{Name: "addr", Value: Value{Kind: VString}},
		}}
	case *vectorType:
		seq := make([]Value, t.n)
		for i := range seq {
			seq[i] = Value{Kind: VFloat}
		}
		return Value{Kind: VSeq, Seq: seq}
	case *seqType:
		// A TUPLE has a fixed element count and the codec refuses a
		// shorter run, so the zero value has to be that long. An ARRAY
		// (size 0) is empty.
		seq := make([]Value, t.size)
		for i := range seq {
			seq[i] = ZeroValue(t.elem)
		}
		return Value{Kind: VSeq, Seq: seq}
	case *fixedDictType:
		fields := make([]DictField, 0, len(t.fields))
		for _, f := range t.fields {
			fields = append(fields, DictField{Name: f.name, Value: ZeroValue(f.typ)})
		}
		return Value{Kind: VDict, Dict: fields}
	}
	return Value{}
}

// EncodeArray writes an ARRAY of the given element type: the element count in
// the codec's variable-length header, then each element in order.
//
// It exists because an array type is not reachable from the alias table on
// its own — a component property declared ARRAY<X> has no named type to look
// up, only the element's.
func EncodeArray(w io.Writer, elem DataType, items []Value) error {
	c := NewCodec()
	if err := c.writeLen(w, len(items)); err != nil {
		return err
	}
	for _, it := range items {
		if err := c.Write(w, elem, it); err != nil {
			return err
		}
	}
	return nil
}
