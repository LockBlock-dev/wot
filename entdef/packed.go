// Package entdef reads BigWorld packed-section files (the binary form of
// .def/.xml under res/scripts) and walks entity definitions to compute the
// login "defs digest" (DBApp rejects mismatches with status 70).
//
// Wire format ported from programming/bigworld/lib/resmgr/packed_section.cpp
// (14.4.1 OSE): magic u32 0x62a14e45, version u8, null-terminated string
// table ending in an empty string, then recursive sections:
// [numChildren i16][records: dataPos i32 + keyPos i16][finalPos i32][blob].
// A child's data spans blob[start_i:start_{i+1}], its name is strings[key],
// its type rides in the high bits of the NEXT record's dataPos.
package entdef

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
)

// Section types (high bits of DataPos), mirroring PackedSectionData.
const (
	TypeDataSection   = 0x00000000
	TypeString        = 0x10000000
	TypeInt           = 0x20000000
	TypeFloat         = 0x30000000
	TypeBool          = 0x40000000
	TypeBlob          = 0x50000000
	TypeEncryptedBlob = 0x60000000

	posMask  = 0x0fffffff
	typeMask = ^uint32(posMask)

	magic = 0x62a14e45
)

// Section is one node of a packed data section tree.
type Section struct {
	Name     string
	Type     uint32 // container type (DATA_SECTION when it has children)
	OwnType  uint32 // type of the node's own data (rec0/final type bits)
	Int      int64  // decoded own data when OwnType == TypeInt
	Str      string // decoded own data when OwnType == TypeString
	Raw      []byte // raw own-data bytes
	Bool     bool   // decoded own data when OwnType == TypeBool
	Children []*Section
}

// Child returns the first child with the given name, or nil.
func (s *Section) Child(name string) *Section {
	for _, c := range s.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ChildrenByName returns all children with the given name.
func (s *Section) ChildrenByName(name string) []*Section {
	var out []*Section
	for _, c := range s.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// AsString renders the section value as text, mirroring the XML form the
// entity parser works with (strings raw; ints decimal; bools true/false).
func (s *Section) AsString() string {
	switch s.OwnType {
	case TypeString:
		return s.Str
	case TypeInt:
		return fmt.Sprintf("%d", s.Int)
	case TypeBool:
		if s.Bool {
			return "true"
		}
		return "false"
	case TypeFloat:
		if len(s.Raw) == 4 {
			return fmt.Sprintf("%v", f32le(s.Raw))
		}
		return ""
	default:
		return ""
	}
}

// AsInt decodes integer sections with OSE getIntegerVal width rules
// (0 bytes = 0; 1/2/4/8 bytes = signed LE of that width).
func (s *Section) AsInt() int64 {
	if s.OwnType == TypeInt {
		return s.Int
	}
	return 0
}

// AsBool mirrors PackedSection::asBool (TYPE_BOOL is nonzero length).
func (s *Section) AsBool() bool {
	if s.OwnType == TypeBool {
		return s.Bool
	}
	return false
}

// StrVal reads a name/value string from a spec node: decoded own text
// first (leaf strings and composite kind markers alike), packed BLOBs
// re-encoded (the fork's packer stores base64-roundtripping names like
// INT8, BOOL, Chat as decoded blobs).
func (s *Section) StrVal() string {
	if s.Str != "" {
		return s.Str
	}
	if s.OwnType == TypeBlob {
		return base64.StdEncoding.EncodeToString(s.Raw)
	}
	return s.AsString()
}

func f32le(b []byte) float32 {
	return math.Float32frombits(binary.LittleEndian.Uint32(b))
}

// File holds the decoded string table plus the root section.
type File struct {
	Strings []string
	Root    *Section
}

type reader struct {
	data []byte
	strs []string
}

// ParseFile decodes a whole packed-section file (magic + version + string
// table + root section).
func ParseFile(data []byte) (*File, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("entdef: too short (%d)", len(data))
	}
	if binary.LittleEndian.Uint32(data[:4]) != magic {
		return nil, fmt.Errorf("entdef: bad magic %08x", binary.LittleEndian.Uint32(data[:4]))
	}
	off := 5 // magic u32 + version u8
	var strs []string
	for {
		if off >= len(data) {
			return nil, fmt.Errorf("entdef: truncated string table")
		}
		end := off
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end >= len(data) {
			return nil, fmt.Errorf("entdef: unterminated string table")
		}
		if end == off {
			off++ // empty terminator
			break
		}
		strs = append(strs, string(data[off:end]))
		off = end + 1
	}
	r := &reader{data: data, strs: strs}
	root, err := r.section("root", off, len(data)-off, TypeDataSection)
	if err != nil {
		return nil, err
	}
	return &File{Strings: strs, Root: root}, nil
}

// section decodes one section with children (total-data block).
func (r *reader) section(name string, off, totalLen int, typ uint32) (*Section, error) {
	s := &Section{Name: name, Type: typ}
	if typ != TypeDataSection {
		return r.leaf(s, off, totalLen)
	}
	if totalLen < 2 {
		return nil, fmt.Errorf("entdef: %s: no room for child count", name)
	}
	n := int(int16(binary.LittleEndian.Uint16(r.data[off : off+2])))
	recOff := off + 2
	end := recOff + n*6 + 4
	if end > off+totalLen {
		return nil, fmt.Errorf("entdef: %s: %d children need %d bytes, have %d",
			name, n, end-off, totalLen)
	}
	type rec struct {
		start uint32
		key   int
		typ   uint32
	}
	recs := make([]rec, 0, n)
	for i := 0; i < n; i++ {
		pos := binary.LittleEndian.Uint32(r.data[recOff+i*6 : recOff+i*6+4])
		key := int(int16(binary.LittleEndian.Uint16(r.data[recOff+i*6+4 : recOff+i*6+6])))
		recs = append(recs, rec{start: pos & posMask, key: key, typ: pos & uint32(typeMask)})
	}
	final := binary.LittleEndian.Uint32(r.data[recOff+n*6 : recOff+n*6+4])
	base := end // blob starts here
	if n > 0 {
		// Own data runs blob[0:start_0]; its type rides in rec0.
		// (Type must be set BEFORE decoding.)
		own, err := r.leaf(&Section{Name: name, Type: recs[0].typ}, base, int(recs[0].start))
		if err != nil {
			return nil, err
		}
		s.OwnType, s.Int, s.Str, s.Raw, s.Bool = own.OwnType, own.Int, own.Str, own.Raw, own.Bool
		for i := 0; i < n; i++ {
			estart := recs[i].start
			eend := final & posMask
			etyp := final & uint32(typeMask)
			if i+1 < n {
				eend = recs[i+1].start
				etyp = recs[i+1].typ
			}
			cname := fmt.Sprintf("#%d", recs[i].key)
			if recs[i].key >= 0 && recs[i].key < len(r.strs) {
				cname = r.strs[recs[i].key]
			}
			child, err := r.section(cname, base+int(estart), int(eend-estart), etyp)
			if err != nil {
				return nil, fmt.Errorf("entdef: %s/%s: %w", name, cname, err)
			}
			s.Children = append(s.Children, child)
		}
	} else {
		// No children: whole block is own data of the final type.
		own, err := r.leaf(&Section{Name: name, Type: final & uint32(typeMask)}, base, int(final&posMask))
		if err != nil {
			return nil, err
		}
		s.OwnType, s.Int, s.Str, s.Raw, s.Bool = own.OwnType, own.Int, own.Str, own.Raw, own.Bool
	}
	return s, nil
}

// leaf decodes a typeless blob into a value section.
func (r *reader) leaf(s *Section, off, ln int) (*Section, error) {
	if off < 0 || ln < 0 || off+ln > len(r.data) {
		return nil, fmt.Errorf("entdef: %s: blob [%d:%d) out of range", s.Name, off, off+ln)
	}
	s.OwnType = s.Type
	raw := r.data[off : off+ln]
	s.Raw = append([]byte{}, raw...)
	switch s.Type {
	case TypeString:
		s.Str = string(raw)
	case TypeInt:
		v, ok := intVal(raw)
		if !ok {
			return nil, fmt.Errorf("entdef: %s: bad int len %d", s.Name, ln)
		}
		s.Int = v
	case TypeBool:
		s.Bool = len(raw) > 0
	case TypeEncryptedBlob:
		return nil, fmt.Errorf("entdef: %s: encrypted blob unsupported", s.Name)
	}
	return s, nil
}

// intVal mirrors getIntegerVal width rules (signed LE of stored width).
func intVal(raw []byte) (int64, bool) {
	switch len(raw) {
	case 0:
		return 0, true
	case 1:
		return int64(int8(raw[0])), true
	case 2:
		return int64(int16(binary.LittleEndian.Uint16(raw))), true
	case 4:
		return int64(int32(binary.LittleEndian.Uint32(raw))), true
	case 8:
		return int64(binary.LittleEndian.Uint64(raw)), true
	}
	return 0, false
}
