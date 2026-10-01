// DataType model and LogOnParams-digest hashing, ported from
// programming/bigworld/lib/entitydef/ (14.4.1 OSE): each type appends a
// tag (WITH trailing NUL, i.e. sizeof("...")) plus its parameters to the
// MD5. Only types occurring in 2.4.0 entity defs are implemented; anything
// else is a loud error (a fork divergence the oracle would otherwise hide).
package entdef

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
)

// DataType is one entity-def datatype.
type DataType interface {
	AddToMD5(h hash.Hash)
	StreamSize() int // fixed bytes, or -1 if variable
	Describe() string
	Equal(other DataType) bool
}

func putU8(h hash.Hash, v uint8) { h.Write([]byte{v}) }
func putI32(h hash.Hash, v int) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(int32(v)))
	h.Write(b[:])
}
func putU32(h hash.Hash, v uint) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	h.Write(b[:])
}
func putStr(h hash.Hash, s string) { h.Write([]byte(s)) }
func putTag(h hash.Hash, s string) { h.Write([]byte(s)); h.Write([]byte{0}) } // sizeof("...") incl NUL
func putBool(h hash.Hash, v bool) {
	if v {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}

// --- integers ---

type intType struct {
	signed bool
	size   int
}

func (t *intType) AddToMD5(h hash.Hash) {
	if t.signed {
		putTag(h, "Int")
	} else {
		putTag(h, "Uint")
	}
	putI32(h, t.size)
}
func (t *intType) StreamSize() int { return t.size }
func (t *intType) Describe() string {
	s := "UINT"
	if t.signed {
		s = "INT"
	}
	return fmt.Sprintf("%s%d", s, t.size*8)
}
func (t *intType) Equal(o DataType) bool {
	x, ok := o.(*intType)
	return ok && x.signed == t.signed && x.size == t.size
}

// --- floats ---

type floatType struct{ bits int }

func (t *floatType) AddToMD5(h hash.Hash) {
	if t.bits == 32 {
		putTag(h, "Float")
	} else {
		putTag(h, "Float64")
	}
}
func (t *floatType) StreamSize() int { return t.bits / 8 }
func (t *floatType) Describe() string {
	if t.bits == 32 {
		return "FLOAT32"
	}
	return "FLOAT64"
}
func (t *floatType) Equal(o DataType) bool {
	x, ok := o.(*floatType)
	return ok && x.bits == t.bits
}

// --- strings / blobs / python / unicode ---

type stringType struct{ tag string }

func (t *stringType) AddToMD5(h hash.Hash) { putTag(h, t.tag) }
func (t *stringType) StreamSize() int      { return -1 }
func (t *stringType) Describe() string     { return t.tag }
func (t *stringType) Equal(o DataType) bool {
	x, ok := o.(*stringType)
	return ok && x.tag == t.tag
}

// --- mailbox (EntityID u32 + Address 4+2+2 = 12 bytes) ---

type mailboxType struct{}

func (t *mailboxType) AddToMD5(h hash.Hash) { putTag(h, "MailBox") }
func (t *mailboxType) StreamSize() int      { return 12 }
func (t *mailboxType) Describe() string     { return "MAILBOX" }
func (t *mailboxType) Equal(o DataType) bool {
	_, ok := o.(*mailboxType)
	return ok
}

// --- vectors ---

type vectorType struct{ n int }

func (t *vectorType) AddToMD5(h hash.Hash) {
	putTag(h, "Vector")
	putI32(h, t.n)
}
func (t *vectorType) StreamSize() int { return 4 * t.n }
func (t *vectorType) Describe() string {
	return fmt.Sprintf("VECTOR%d", t.n)
}
func (t *vectorType) Equal(o DataType) bool {
	x, ok := o.(*vectorType)
	return ok && x.n == t.n
}

// --- sequences (ARRAY / TUPLE) ---

type seqType struct {
	kind  string // "Array" or "Tuple"
	elem  DataType
	size  int
	dbLen int
}

func (t *seqType) AddToMD5(h hash.Hash) {
	putTag(h, t.kind)
	putI32(h, t.size)
	if t.dbLen > 0 {
		putI32(h, t.dbLen)
	}
	if DigestTypeLabels >= 3 {
		putName(h, "type")
	}
	t.elem.AddToMD5(h)
}
func (t *seqType) StreamSize() int {
	s := t.size * t.elem.StreamSize()
	if s <= 0 {
		return -1
	}
	return s
}
func (t *seqType) Describe() string { return t.kind }
func (t *seqType) Equal(o DataType) bool {
	x, ok := o.(*seqType)
	return ok && x.kind == t.kind && x.size == t.size && x.dbLen == t.dbLen &&
		x.elem.Equal(t.elem)
}

// --- fixed dicts ---

type fixedDictField struct {
	name string
	typ  DataType
}

type fixedDictType struct {
	fields    []fixedDictField
	allowNone bool
}

func (t *fixedDictType) AddToMD5(h hash.Hash) {
	putTag(h, "FixedDict")
	// No <implementedBy> anywhere in 2.4.0 defs: module/instance are empty,
	// so both branches (append empties vs skip) contribute zero bytes.
	putBool(h, t.allowNone)
	putLabel(h, "fields")
	for _, f := range t.fields {
		putFieldName(h, f.name)
		putTypeLabel(h, false)
		f.typ.AddToMD5(h)
	}
}
func (t *fixedDictType) StreamSize() int {
	if t.allowNone {
		return -1
	}
	s := 0
	for _, f := range t.fields {
		fs := f.typ.StreamSize()
		if fs < 0 {
			return -1
		}
		s += fs
	}
	return s
}
func (t *fixedDictType) Describe() string { return "FIXED_DICT" }
func (t *fixedDictType) Equal(o DataType) bool {
	x, ok := o.(*fixedDictType)
	if !ok || x.allowNone != t.allowNone || len(x.fields) != len(t.fields) {
		return false
	}
	for i := range t.fields {
		if x.fields[i].name != t.fields[i].name || !x.fields[i].typ.Equal(t.fields[i].typ) {
			return false
		}
	}
	return true
}

// --- registry ---

// metaBuilder builds a datatype from its spec section.
type metaBuilder func(sec *Section) (DataType, error)

var metaTypes = map[string]metaBuilder{}

func init() {
	metaTypes["INT8"] = func(*Section) (DataType, error) { return &intType{true, 1}, nil }
	metaTypes["INT16"] = func(*Section) (DataType, error) { return &intType{true, 2}, nil }
	metaTypes["INT32"] = func(*Section) (DataType, error) { return &intType{true, 4}, nil }
	metaTypes["INT64"] = func(*Section) (DataType, error) { return &intType{true, 8}, nil }
	metaTypes["UINT8"] = func(*Section) (DataType, error) { return &intType{false, 1}, nil }
	metaTypes["UINT16"] = func(*Section) (DataType, error) { return &intType{false, 2}, nil }
	metaTypes["UINT32"] = func(*Section) (DataType, error) { return &intType{false, 4}, nil }
	metaTypes["UINT64"] = func(*Section) (DataType, error) { return &intType{false, 8}, nil }
	metaTypes["FLOAT"] = func(*Section) (DataType, error) { return &floatType{32}, nil }
	metaTypes["FLOAT32"] = func(*Section) (DataType, error) {
		return &floatType{32}, nil
	} // internal alias FLOAT32->FLOAT
	metaTypes["FLOAT64"] = func(*Section) (DataType, error) { return &floatType{64}, nil }
	metaTypes["STRING"] = func(*Section) (DataType, error) { return &stringType{"String"}, nil }
	metaTypes["BLOB"] = func(*Section) (DataType, error) { return &stringType{"Blob"}, nil }
	metaTypes["UNICODE_STRING"] = func(*Section) (DataType, error) { return &stringType{"UnicodeString"}, nil }
	metaTypes["PYTHON"] = func(*Section) (DataType, error) { return &stringType{"Python"}, nil }
	metaTypes["MAILBOX"] = func(*Section) (DataType, error) { return &mailboxType{}, nil }
	metaTypes["VECTOR2"] = func(*Section) (DataType, error) { return &vectorType{2}, nil }
	metaTypes["VECTOR3"] = func(*Section) (DataType, error) { return &vectorType{3}, nil }
	metaTypes["VECTOR4"] = func(*Section) (DataType, error) { return &vectorType{4}, nil }
	metaTypes["ARRAY"] = buildSeq("Array")
	metaTypes["TUPLE"] = buildSeq("Tuple")
	metaTypes["FIXED_DICT"] = buildFixedDict
}

func buildSeq(kind string) metaBuilder {
	return func(sec *Section) (DataType, error) {
		of := sec.Child("of")
		if of == nil {
			return nil, fmt.Errorf("entdef: %s missing <of>", kind)
		}
		elem, err := BuildDataType(of)
		if err != nil {
			return nil, err
		}
		size := 0
		if s := sec.Child("size"); s != nil {
			size = int(s.AsInt())
		}
		return &seqType{kind: kind, elem: elem, size: size}, nil
	}
}

func buildFixedDict(sec *Section) (DataType, error) {
	var fields []fixedDictField
	if parent := sec.Child("Parent"); parent != nil && parent.AsString() != "" {
		return nil, fmt.Errorf("entdef: fixed-dict <Parent> unsupported here")
	}
	props := sec.Child("Properties")
	if props == nil {
		return nil, fmt.Errorf("entdef: fixed-dict missing <Properties>")
	}
	for _, f := range props.Children {
		ts := f.Child("Type")
		if ts == nil {
			return nil, fmt.Errorf("entdef: fixed-dict field %s missing <Type>", f.Name)
		}
		typ, err := BuildDataType(ts)
		if err != nil {
			return nil, err
		}
		fields = append(fields, fixedDictField{name: f.Name, typ: typ})
	}
	allowNone := false
	if an := sec.Child("AllowNone"); an != nil {
		allowNone = an.AsString() == "true" || an.AsInt() != 0
	}
	return &fixedDictType{fields: fields, allowNone: allowNone}, nil
}

// DescribeDeep renders the full structural type: primitives as
// Describe, sequences as Array[size]{elem} / Tuple[size]{elem},
// fixed dicts as FixedDict{allowNone,name:type,...}. Aliases are
// already resolved at build time, so this is the wire structure.
func DescribeDeep(dt DataType) string {
	switch t := dt.(type) {
	case *seqType:
		return fmt.Sprintf("%s[%d]{%s}", t.kind, t.size, DescribeDeep(t.elem))
	case *fixedDictType:
		s := "FixedDict{"
		if t.allowNone {
			s += "?"
		}
		for i, f := range t.fields {
			if i > 0 {
				s += ","
			}
			s += f.name + ":" + DescribeDeep(f.typ)
		}
		return s + "}"
	default:
		return dt.Describe()
	}
}

// aliases maps alias name -> built datatype (alias.xml, file order).
var aliases = map[string]DataType{}

// InitAliases builds all alias.xml entries in order (OSE single pass;
// std::map::insert keeps the FIRST definition on duplicates).
func InitAliases(root *Section) error {
	for _, a := range root.Children {
		if _, exists := aliases[a.Name]; exists {
			continue
		}
		dt, err := BuildDataType(a)
		if err != nil {
			return fmt.Errorf("entdef: alias %s: %w", a.Name, err)
		}
		aliases[a.Name] = dt
	}
	return nil
}

// BuildDataType resolves a <Type>/<Arg> section: own-data kind name,
// aliases first, then the metatype registry (OSE DataType::buildDataType).
// Short base64-roundtripping names (INT8, BOOL, ...) pack as decoded BLOBs;
// recover them by re-encoding (the fork's packer optimization).
func BuildDataType(sec *Section) (DataType, error) {
	name := sec.StrVal()
	if sec.OwnType == TypeBlob {
		name = base64.StdEncoding.EncodeToString(sec.Raw)
	}
	if name == "" {
		// Composite nodes carry the kind in own-data; a missing one with
		// children is a fork divergence worth shouting about.
		return nil, fmt.Errorf("entdef: %s: empty type name (%d children)", sec.Name, len(sec.Children))
	}
	if dt, ok := aliases[name]; ok {
		return dt, nil
	}
	mb, ok := metaTypes[name]
	if !ok {
		return nil, fmt.Errorf("entdef: unknown datatype %q", name)
	}
	return mb(sec)
}
