package login

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

// Havok tagfiles, the format WoT ships its collision models in.
//
// A tagfile is a tree of sections: each a big-endian u32 holding its size
// (header included) in its low 30 bits, then a 4-byte tag. `TAG0` holds `SDKV`
// (the SDK version), `DATA` (the objects' bytes), `TYPE` (the type
// descriptions) and `INDX` (the items). Objects are laid out as their types
// describe, except that every pointer, string and variable-length array is a
// u32 index into the items.
//
// Ported from the reference's `havok/tagfile.rs`.

const (
	hkFmtBool       = 2
	hkFmtString     = 3
	hkFmtInt        = 4
	hkFmtFloat      = 5
	hkFmtPointer    = 6
	hkFmtRecord     = 7
	hkFmtArray      = 8
	hkFmtFixedArray = 0x20
	hkFmtSigned     = 0x200
)

// hkType is one type description.
type hkType struct {
	name    string
	parent  int
	format  int // -1 when inherited
	pointee int
	size    int // -1 when inherited
	members []hkMember
}

type hkMember struct {
	name   string
	offset int
	ty     int
}

// hkItem is an object or array in DATA.
type hkItem struct {
	ty     int
	single bool
	offset int
	count  int
}

// hkFile is a whole tagfile.
type hkFile struct {
	sdkVersion string
	data       []byte
	types      []hkType
	items      []hkItem
}

// hkNode is one value in a tagfile.
type hkNode struct {
	f      *hkFile
	ty     int
	offset int
}

// hkSection is one section of a tagfile.
type hkSection struct {
	tag     string
	content []byte
}

// hkSections splits a byte range into its sections.
func hkSections(b []byte) ([]hkSection, error) {
	var out []hkSection
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errors.New("tagfile: truncated section header")
		}
		size := int(binary.BigEndian.Uint32(b[0:4]) & 0x3FFFFFFF)
		if size < 8 || size > len(b) {
			return nil, fmt.Errorf("tagfile: section size %d of %d bytes", size, len(b))
		}
		out = append(out, hkSection{tag: string(b[4:8]), content: b[8:size]})
		b = b[size:]
	}
	return out, nil
}

// hkVarints reads the variable-length integers of a types section.
type hkVarints struct{ b []byte }

func (v *hkVarints) next() (uint64, error) {
	if len(v.b) == 0 {
		return 0, errors.New("tagfile: truncated varint")
	}
	first := v.b[0]
	var length int
	var mask uint64
	switch {
	case first <= 0x7F:
		length, mask = 1, 0x7F
	case first <= 0xBF:
		length, mask = 2, 0x3FFF
	case first <= 0xDF:
		length, mask = 3, 0x1FFFFF
	case first <= 0xE7:
		length, mask = 4, 0x7FFFFFF
	case first <= 0xEF:
		length, mask = 5, 0x7FFFFFFFF
	case first <= 0xF7:
		length, mask = 6, 0x7FFFFFFFFFF
	default:
		length, mask = 9, math.MaxUint64
	}
	if len(v.b) < length {
		return 0, errors.New("tagfile: truncated varint")
	}
	start := 0
	if length == 9 {
		start = 1
	}
	var value uint64
	for _, c := range v.b[start:length] {
		value = value<<8 | uint64(c)
	}
	v.b = v.b[length:]
	return value & mask, nil
}

// hkStrings splits a strings section on its NULs.
func hkStrings(b []byte) []string {
	parts := strings.Split(string(b), "\x00")
	return parts
}

// parseTagfile reads a whole tagfile.
func parseTagfile(raw []byte) (*hkFile, error) {
	root, err := hkSections(raw)
	if err != nil {
		return nil, err
	}
	if len(root) != 1 || root[0].tag != "TAG0" {
		return nil, errors.New("tagfile: not a TAG0 file")
	}
	var sdk string
	var data, typeSection, index []byte
	var haveData, haveType, haveIndex bool
	sub, err := hkSections(root[0].content)
	if err != nil {
		return nil, err
	}
	for _, s := range sub {
		switch s.tag {
		case "SDKV":
			sdk = string(s.content)
		case "DATA":
			data, haveData = s.content, true
		case "TYPE":
			typeSection, haveType = s.content, true
		case "INDX":
			index, haveIndex = s.content, true
		}
	}
	if !haveData || !haveType || !haveIndex {
		return nil, errors.New("tagfile: missing DATA/TYPE/INDX")
	}
	var typeStrings, fieldStrings []string
	var typeNames, typeBodies []byte
	var haveTST, haveFST, haveTNA, haveTBD bool
	typeSub, err := hkSections(typeSection)
	if err != nil {
		return nil, err
	}
	for _, s := range typeSub {
		switch s.tag {
		case "TST1":
			typeStrings, haveTST = hkStrings(s.content), true
		case "FST1":
			fieldStrings, haveFST = hkStrings(s.content), true
		case "TNA1":
			typeNames, haveTNA = s.content, true
		case "TBDY":
			typeBodies, haveTBD = s.content, true
		}
	}
	if !haveTST || !haveFST || !haveTNA || !haveTBD {
		return nil, errors.New("tagfile: missing type sections")
	}
	str := func(list []string, i uint64) (string, error) {
		if i >= uint64(len(list)) {
			return "", fmt.Errorf("tagfile: no string %d", i)
		}
		return list[i], nil
	}
	names := &hkVarints{b: typeNames}
	count, err := names.next()
	if err != nil {
		return nil, err
	}
	types := make([]hkType, count)
	for i := 1; i < int(count); i++ {
		nameIdx, err := names.next()
		if err != nil {
			return nil, err
		}
		name, err := str(typeStrings, nameIdx)
		if err != nil {
			return nil, err
		}
		types[i].name = name
		types[i].format = -1
		types[i].size = -1
		// Template arguments: the layouts don't use them.
		args, err := names.next()
		if err != nil {
			return nil, err
		}
		for j := uint64(0); j < args; j++ {
			if _, err := names.next(); err != nil {
				return nil, err
			}
			if _, err := names.next(); err != nil {
				return nil, err
			}
		}
	}
	bodies := &hkVarints{b: typeBodies}
	for len(bodies.b) > 0 {
		id, err := bodies.next()
		if err != nil {
			return nil, err
		}
		if id == 0 {
			continue
		}
		parent, err := bodies.next()
		if err != nil {
			return nil, err
		}
		flags, err := bodies.next()
		if err != nil {
			return nil, err
		}
		if id >= uint64(len(types)) {
			return nil, fmt.Errorf("tagfile: no type %d", id)
		}
		ty := &types[id]
		ty.parent = int(parent)
		if flags&0x01 != 0 {
			f, err := bodies.next()
			if err != nil {
				return nil, err
			}
			ty.format = int(f)
		}
		if flags&0x02 != 0 && ty.format >= 0 && ty.format&0xF >= hkFmtPointer {
			p, err := bodies.next()
			if err != nil {
				return nil, err
			}
			ty.pointee = int(p)
		}
		if flags&0x04 != 0 {
			if _, err := bodies.next(); err != nil {
				return nil, err
			}
		}
		if flags&0x08 != 0 {
			sz, err := bodies.next()
			if err != nil {
				return nil, err
			}
			ty.size = int(sz)
			if _, err := bodies.next(); err != nil {
				return nil, err
			}
		}
		if flags&0x10 != 0 {
			if _, err := bodies.next(); err != nil {
				return nil, err
			}
		}
		if flags&0x20 != 0 {
			n, err := bodies.next()
			if err != nil {
				return nil, err
			}
			for j := uint64(0); j < n&0xFFFF; j++ {
				nameIdx, err := bodies.next()
				if err != nil {
					return nil, err
				}
				name, err := str(fieldStrings, nameIdx)
				if err != nil {
					return nil, err
				}
				if _, err := bodies.next(); err != nil {
					return nil, err
				}
				off, err := bodies.next()
				if err != nil {
					return nil, err
				}
				mty, err := bodies.next()
				if err != nil {
					return nil, err
				}
				types[id].members = append(types[id].members, hkMember{name: name, offset: int(off), ty: int(mty)})
			}
		}
		if flags&0x40 != 0 {
			n, err := bodies.next()
			if err != nil {
				return nil, err
			}
			for j := uint64(0); j < n; j++ {
				if _, err := bodies.next(); err != nil {
					return nil, err
				}
				if _, err := bodies.next(); err != nil {
					return nil, err
				}
			}
		}
		if flags&0x80 != 0 {
			if _, err := bodies.next(); err != nil {
				return nil, err
			}
		}
	}
	var items []hkItem
	idxSections, err := hkSections(index)
	if err != nil {
		return nil, err
	}
	for _, s := range idxSections {
		if s.tag != "ITEM" {
			continue
		}
		for off := 0; off+12 <= len(s.content); off += 12 {
			word := func(i int) int { return int(binary.LittleEndian.Uint32(s.content[off+i : off+i+4])) }
			items = append(items, hkItem{
				ty:     word(0) & 0xFFFFFF,
				single: word(0)>>24&0x10 != 0,
				offset: word(4),
				count:  word(8),
			})
		}
	}
	return &hkFile{sdkVersion: sdk, data: data, types: types, items: items}, nil
}

// ty returns a type, none for id 0.
func (f *hkFile) ty(id int) *hkType {
	if id <= 0 || id >= len(f.types) {
		return nil
	}
	return &f.types[id]
}

// format walks the parent chain for a type's format.
func (f *hkFile) format(id int) int {
	for {
		ty := f.ty(id)
		if ty == nil {
			return 0
		}
		if ty.format >= 0 {
			return ty.format
		}
		id = ty.parent
	}
}

// size walks the parent chain for a type's size.
func (f *hkFile) size(id int) int {
	for {
		ty := f.ty(id)
		if ty == nil {
			return 0
		}
		if ty.size >= 0 {
			return ty.size
		}
		id = ty.parent
	}
}

// pointee walks the parent chain for what a pointer or array points to.
func (f *hkFile) pointee(id int) int {
	for {
		ty := f.ty(id)
		if ty == nil {
			return 0
		}
		if ty.pointee != 0 {
			return ty.pointee
		}
		id = ty.parent
	}
}

// member finds a record's member by name, its own or a parent's.
func (f *hkFile) member(id int, name string) *hkMember {
	for {
		ty := f.ty(id)
		if ty == nil {
			return nil
		}
		for i := range ty.members {
			if ty.members[i].name == name {
				return &ty.members[i]
			}
		}
		id = ty.parent
	}
}

// item returns an item's elements, none for the null item 0.
func (f *hkFile) item(index int) *hkElements {
	if index <= 0 || index >= len(f.items) {
		return nil
	}
	it := f.items[index]
	count := it.count
	if it.single {
		count = 1
	}
	return &hkElements{f: f, ty: it.ty, offset: it.offset, count: count}
}

// hkElements is an array's elements.
type hkElements struct {
	f      *hkFile
	ty     int
	offset int
	count  int
}

func (e *hkElements) get(i int) *hkNode {
	if i < 0 || i >= e.count {
		return nil
	}
	return &hkNode{f: e.f, ty: e.ty, offset: e.offset + i*e.f.size(e.ty)}
}

// root is the tagfile's root object, the first item's.
func (f *hkFile) root() *hkNode {
	els := f.item(1)
	if els == nil {
		return nil
	}
	return els.get(0)
}

// bytes reads n bytes at an offset.
func (f *hkFile) bytes(offset, n int) ([]byte, bool) {
	if offset < 0 || offset+n > len(f.data) {
		return nil, false
	}
	return f.data[offset : offset+n], true
}

// typeName is the node's type name.
func (n *hkNode) typeName() string {
	if ty := n.f.ty(n.ty); ty != nil {
		return ty.name
	}
	return ""
}

// get returns a record's member.
func (n *hkNode) get(name string) *hkNode {
	m := n.f.member(n.ty, name)
	if m == nil {
		return nil
	}
	return &hkNode{f: n.f, ty: m.ty, offset: n.offset + m.offset}
}

// unwrapRecord follows single-member records to the value they wrap.
func (n *hkNode) unwrapRecord() *hkNode {
	node := n
	for node.f.format(node.ty)&0xF == hkFmtRecord {
		ty := node.f.ty(node.ty)
		if ty == nil || len(ty.members) != 1 {
			break
		}
		m := ty.members[0]
		node = &hkNode{f: node.f, ty: m.ty, offset: node.offset + m.offset}
	}
	return node
}

// deref follows a pointer to the object it points at.
func (n *hkNode) deref() *hkNode {
	node := n.unwrapRecord()
	if node.f.format(node.ty)&0xF != hkFmtPointer {
		return nil
	}
	idx, ok := node.index()
	if !ok {
		return nil
	}
	els := node.f.item(idx)
	if els == nil {
		return nil
	}
	return els.get(0)
}

// elements returns an array's elements, inline or as an item.
func (n *hkNode) elements() *hkElements {
	format := n.f.format(n.ty)
	if format&0xF != hkFmtArray {
		return nil
	}
	if format&hkFmtFixedArray != 0 {
		return &hkElements{f: n.f, ty: n.f.pointee(n.ty), offset: n.offset, count: format >> 8}
	}
	idx, ok := n.index()
	if !ok {
		return nil
	}
	if els := n.f.item(idx); els != nil {
		return els
	}
	return &hkElements{f: n.f}
}

// index is the item index a pointer, string or array holds.
func (n *hkNode) index() (int, bool) {
	b, ok := n.f.bytes(n.offset, 4)
	if !ok {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(b)), true
}

// asInt reads an integer.
func (n *hkNode) asInt() (int64, bool) {
	format := n.f.format(n.ty)
	if format&0xF != hkFmtInt {
		return 0, false
	}
	signed := format&hkFmtSigned != 0
	size := n.f.size(n.ty)
	b, ok := n.f.bytes(n.offset, size)
	if !ok {
		return 0, false
	}
	switch size {
	case 1:
		if signed {
			return int64(int8(b[0])), true
		}
		return int64(b[0]), true
	case 2:
		v := binary.LittleEndian.Uint16(b)
		if signed {
			return int64(int16(v)), true
		}
		return int64(v), true
	case 4:
		v := binary.LittleEndian.Uint32(b)
		if signed {
			return int64(int32(v)), true
		}
		return int64(v), true
	case 8:
		return int64(binary.LittleEndian.Uint64(b)), true
	}
	return 0, false
}

// asF32 reads a float.
func (n *hkNode) asF32() (float32, bool) {
	if n.f.format(n.ty)&0xF != hkFmtFloat || n.f.size(n.ty) != 4 {
		return 0, false
	}
	b, ok := n.f.bytes(n.offset, 4)
	if !ok {
		return 0, false
	}
	return math.Float32frombits(binary.LittleEndian.Uint32(b)), true
}

// asStr reads a string.
func (n *hkNode) asStr() (string, bool) {
	node := n.unwrapRecord()
	if node.f.format(node.ty)&0xF != hkFmtString {
		return "", false
	}
	idx, ok := node.index()
	if !ok || idx <= 0 || idx >= len(node.f.items) {
		return "", false
	}
	it := node.f.items[idx]
	b, ok := node.f.bytes(it.offset, it.count)
	if !ok {
		return "", false
	}
	return strings.TrimSuffix(string(b), "\x00"), true
}

// asF32s reads N floats from an array of floats or a vector.
func (n *hkNode) asF32s(count int) ([]float32, bool) {
	els := n.unwrapRecord().elements()
	if els == nil {
		return nil, false
	}
	out := make([]float32, count)
	for i := 0; i < count; i++ {
		e := els.get(i)
		if e == nil {
			return nil, false
		}
		v, ok := e.asF32()
		if !ok {
			return nil, false
		}
		out[i] = v
	}
	return out, true
}
