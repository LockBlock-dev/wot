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
	"strings"
)

// DataType is one entity-def datatype.
type DataType interface {
	AddToMD5(h hash.Hash)
	StreamSize() int // fixed bytes, or -1 if variable
	Describe() string
	Equal(other DataType) bool
}

func putU8(h hash.Hash, v uint8) { h.Write([]byte{v}) }
func putU16(h hash.Hash, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	h.Write(b[:])
}
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

// TypeTagRecorder, when non-nil, collects type tags in emission order.
// Oracle probing only: tests diff it against ce/r8probe captures
// (live strlen+append fires). The digest path never sets it.
var TypeTagRecorder *[]string

func putTag(h hash.Hash, s string) {
	if TypeTagRecorder != nil {
		*TypeTagRecorder = append(*TypeTagRecorder, s)
	}
	h.Write([]byte(s))
	h.Write([]byte{0}) // sizeof("...") incl NUL
}
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

// ClearImpl recursively clears hasImpl on all FixedDicts under dt
// (brute-force gate probing; not used in production).
func ClearImpl(dt DataType) {
	switch t := dt.(type) {
	case *fixedDictType:
		t.hasImpl = false
		for _, f := range t.fields {
			ClearImpl(f.typ)
		}
	case *seqType:
		ClearImpl(t.elem)
	}
}

// ClearEntityImpl clears hasImpl on every type reachable from e
// (props + all method args/returns, own and iface).
func ClearEntityImpl(e *Entity) {
	for i := range e.Props {
		ClearImpl(e.Props[i].Type)
	}
	all := [][]Method{e.ClientMethods, e.BaseMethods, e.CellMethods,
		e.IfaceClientMethods, e.IfaceBaseMethods, e.IfaceCellMethods}
	for _, ms := range all {
		for i := range ms {
			for _, a := range ms[i].Args {
				ClearImpl(a)
			}
			for _, r := range ms[i].ReturnValues {
				ClearImpl(r)
			}
		}
	}
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
	// module/instance from <implementedBy>module.instance</implementedBy>
	// (2.4.1.0: true_dict.instance on two FixedDicts). IDA 2.4.1.0
	// sub_142CC25F0 hashes them (visitor +0x60, "moduleName" then
	// "instanceName") iff the implementedBy helper ran (hasImpl); absent
	// FixedDicts skip both. Labels themselves hash nothing (stub slots).
	module   string
	instance string
	hasImpl  bool
	// encOverride selects a per-object encoding for mixed per-site
	// probing (-1 = follow ImplEncoding).
	encOverride int
}

// ImplEncoding selects the moduleName/instanceName byte form for the
// implementedBy brute-force matrix (0 = raw/raw default per stub-label
// model). Reset to 0 after probing.
var ImplEncoding int

// encOverride selects a per-object ImplEncoding (mixed per-site probing).
// -1 = follow ImplEncoding.
func (t *fixedDictType) setEncOverride(e int) { t.encOverride = e }

func (t *fixedDictType) AddToMD5(h hash.Hash) {
	putTag(h, "FixedDict")
	if t.hasImpl {
		enc := ImplEncoding
		if t.encOverride >= 0 {
			enc = t.encOverride
		}
		switch enc {
		case 1:
			putTag(h, t.module)
			putTag(h, t.instance)
		case 2:
			putStr(h, t.module)
			putTag(h, t.instance)
		case 3:
			putTag(h, t.module)
			putStr(h, t.instance)
		case 4:
			putStr(h, t.instance)
			putStr(h, t.module)
		case 5:
			putTag(h, t.instance)
			putTag(h, t.module)
		case 6:
			putStr(h, "moduleName")
			putStr(h, t.module)
			putStr(h, "instanceName")
			putStr(h, t.instance)
		case 7:
			putTag(h, "moduleName")
			putStr(h, t.module)
			putTag(h, "instanceName")
			putStr(h, t.instance)
		case 8:
			putTag(h, "moduleName")
			putTag(h, t.module)
			putTag(h, "instanceName")
			putTag(h, t.instance)
		case 9:
			putStr(h, "moduleName")
			putTag(h, t.module)
			putStr(h, "instanceName")
			putTag(h, t.instance)
		case 10:
			putU32(h, uint(len(t.module)))
			putStr(h, t.module)
			putU32(h, uint(len(t.instance)))
			putStr(h, t.instance)
		case 11:
			putU32(h, uint(len(t.module)+1))
			putTag(h, t.module)
			putU32(h, uint(len(t.instance)+1))
			putTag(h, t.instance)
		case 12:
			putTag(h, "String")
			putStr(h, t.module)
			putTag(h, "String")
			putStr(h, t.instance)
		case 13:
			putTag(h, "String")
			putTag(h, t.module)
			putTag(h, "String")
			putTag(h, t.instance)
		case 14:
			putStr(h, t.module+"."+t.instance)
		case 15:
			putTag(h, t.module+"."+t.instance)
		case 16:
			putBool(h, t.allowNone)
			putStr(h, t.module)
			putStr(h, t.instance)
			putLabel(h, "fields")
			for _, f := range t.fields {
				putFieldName(h, f.name)
				putTypeLabel(h, false)
				f.typ.AddToMD5(h)
			}
			return
		case 17:
			putBool(h, t.allowNone)
			putTag(h, t.module)
			putTag(h, t.instance)
			putLabel(h, "fields")
			for _, f := range t.fields {
				putFieldName(h, f.name)
				putTypeLabel(h, false)
				f.typ.AddToMD5(h)
			}
			return
		case 18:
			putStr(h, t.module)
			putStr(h, t.module)
			putStr(h, t.instance)
			putStr(h, t.instance)
		case 19:
			putTag(h, t.module)
			putTag(h, t.module)
			putTag(h, t.instance)
			putTag(h, t.instance)
		case 20:
			putU16(h, uint16(len(t.module)))
			putStr(h, t.module)
			putU16(h, uint16(len(t.instance)))
			putStr(h, t.instance)
		case 99:
			// skip impl bytes (per-site gate probing)
		default:
			putStr(h, t.module)
			putStr(h, t.instance)
		}
	}
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
	if !ok || x.allowNone != t.allowNone || len(x.fields) != len(t.fields) ||
		x.module != t.module || x.instance != t.instance || x.hasImpl != t.hasImpl {
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
	fd := &fixedDictType{fields: fields, allowNone: allowNone, encOverride: -1}
	if ib := sec.Child("implementedBy"); ib != nil && ib.AsString() != "" {
		parts := strings.SplitN(ib.AsString(), ".", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("entdef: fixed-dict <implementedBy> %q must contain a '.'", ib.AsString())
		}
		fd.module, fd.instance, fd.hasImpl = parts[0], parts[1], true
	}
	return fd, nil
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

// ResetAliases clears the global alias cache so successive offline digest
// computations for different client versions (2.4.0 vs 2.4.1) don't reuse
// each other's types. Tests computing multiple versions in one process
// must call this when switching versions (along with ScriptsEntityDefsDir).
func ResetAliases() {
	for k := range aliases {
		delete(aliases, k)
	}
}

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

// Alias returns a named type from alias.xml, or nil when it is not declared.
//
// The alias table is the only place a script dict such as VEHICLES_INFO is
// defined: it is not a property of any entity, so it cannot be reached
// through a dispatch table.
func Alias(name string) DataType {
	return aliases[name]
}
