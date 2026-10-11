package lobby

// Minimal cPickle protocol 0-2 decoder for lobby traffic.
//
// A general-purpose pickle library (e.g. nlpodyssey/gopickle) does
// strict whole-document decoding and dies on the first bad byte; the
// lobby workload needs the opposite: prefix salvage of truncated UDP
// captures, consumed-byte accounting for concatenated streams, and
// schema census over noisy bundles (DecodePrefix, DecodeAt,
// Inventory, DecodeBundle, HarvestStream below). This decoder also
// never executes anything: classes resolve to inert markers/holders,
// and unknown/unsafe opcodes (EXT*, PERSID, INST) error fail-open.
//
// Opcode bytes per CPython pickletools (verified, not memorized).
// Class registry is SAFE: collections.deque and a few builtins decode
// to real holders; every other class becomes a GenericValue data
// holder (module+name, constructor args, state) — never executed.
// Unknown/unsafe opcodes (EXT*, PERSID, INST) error fail-open.
//
// Values may carry account data: this package returns them, it does
// not print them. PickleSummary logs types, key NAMES and lengths
// only — never scalar values.

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

// Containers (pointer identity matters for memo/BINPUT aliasing).
type PList struct{ Items []any }
type PTuple struct{ Items []any }
type PEntry struct {
	Key   any
	Value any
}
type PDict struct{ Entries []PEntry }
type PSet struct{ Items []any }

// Deque is our stand-in for collections.deque (ordered items).
type Deque struct {
	Items []any
}

// GenericValue holds an unknown pickled class instance as pure data.
type GenericValue struct {
	Module string
	Name   string
	Args   []any
	State  any
	Attrs  map[string]any
}

// decoder state.
type pun struct {
	data []byte
	pos  int
	stk  []any
	memo map[int]any
}

type marker struct{}

func (p *pun) push(v any) { p.stk = append(p.stk, v) }

func (p *pun) pop() (any, error) {
	if len(p.stk) == 0 {
		return nil, fmt.Errorf("wotlogin: pickle stack underflow")
	}
	v := p.stk[len(p.stk)-1]
	p.stk = p.stk[:len(p.stk)-1]
	return v, nil
}

func (p *pun) read(n int) ([]byte, error) {
	if p.pos+n > len(p.data) {
		return nil, fmt.Errorf("wotlogin: pickle truncated (need %d @%d of %d)", n, p.pos, len(p.data))
	}
	b := p.data[p.pos : p.pos+n]
	p.pos += n
	return b, nil
}

func (p *pun) readByte() (byte, error) {
	b, err := p.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *pun) readLine() ([]byte, error) {
	i := p.pos
	for i < len(p.data) && p.data[i] != '\n' {
		i++
	}
	if i >= len(p.data) {
		return nil, fmt.Errorf("wotlogin: pickle line unterminated @%d", p.pos)
	}
	b := p.data[p.pos:i]
	p.pos = i + 1
	return b, nil
}

func (p *pun) u16() (uint16, error) {
	b, err := p.read(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (p *pun) u32() (uint32, error) {
	b, err := p.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// popMark pops through the topmost MARK (inclusive), oldest-first.
func (p *pun) popMark() ([]any, error) {
	var out []any
	for {
		if len(p.stk) == 0 {
			return nil, fmt.Errorf("wotlogin: pickle MARK missing")
		}
		v := p.stk[len(p.stk)-1]
		p.stk = p.stk[:len(p.stk)-1]
		if _, ok := v.(marker); ok {
			break
		}
		out = append([]any{v}, out...)
	}
	return out, nil
}

func dictSet(obj, key, value any) error {
	switch d := obj.(type) {
	case *PDict:
		d.Entries = append(d.Entries, PEntry{Key: key, Value: value})
		return nil
	case *GenericValue:
		if ks, ok := key.(string); ok {
			if d.Attrs == nil {
				d.Attrs = map[string]any{}
			}
			d.Attrs[ks] = value
			return nil
		}
		return fmt.Errorf("wotlogin: generic dict key not a string: %T", key)
	}
	return fmt.Errorf("wotlogin: not a dict target: %T", obj)
}

// setitems implements SETITEMS ('u'): MARK-delimited batches. The
// MARK is mandatory (CPython itself errors without one — verified),
// so no parity fallback: pop through MARK, apply pairs oldest-first.
func setitems(p *pun) error {
	items, err := p.popMark()
	if err != nil {
		return err
	}
	if len(items)%2 != 0 {
		return fmt.Errorf("wotlogin: pickle SETITEMS odd items")
	}
	if len(p.stk) == 0 {
		return fmt.Errorf("wotlogin: pickle SETITEMS target missing")
	}
	tgt := p.stk[len(p.stk)-1]
	for i := 0; i < len(items); i += 2 {
		if err := dictSet(tgt, items[i], items[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func appendItems(p *pun) error {
	items, err := p.popMark()
	if err != nil {
		return err
	}
	if len(p.stk) == 0 {
		return fmt.Errorf("wotlogin: pickle append target missing")
	}
	switch t := p.stk[len(p.stk)-1].(type) {
	case *PList:
		t.Items = append(t.Items, items...)
		return nil
	case *Deque:
		t.Items = append(t.Items, items...)
		return nil
	}
	return fmt.Errorf("wotlogin: pickle append target %T", p.stk[len(p.stk)-1])
}

// Class markers returned by resolveGlobal (never code).
type dequeMarker struct{}

type genericMarker struct {
	module, name string
}

type builtinMarker struct {
	name string
}

// callClass invokes a marker with an arg tuple.
func callClass(fn any, args []any) (any, error) {
	switch c := fn.(type) {
	case *dequeMarker:
		d := &Deque{}
		if len(args) == 0 {
			return d, nil
		}
		if len(args) == 1 {
			switch l := args[0].(type) {
			case *PList:
				d.Items = append(d.Items, l.Items...)
				return d, nil
			case *PTuple:
				d.Items = append(d.Items, l.Items...)
				return d, nil
			}
		}
		return nil, fmt.Errorf("wotlogin: deque args not a sequence")
	case *genericMarker:
		return &GenericValue{Module: c.module, Name: c.name, Args: args, Attrs: map[string]any{}}, nil
	case *builtinMarker:
		switch c.name {
		case "list":
			return &PList{}, nil
		case "dict":
			return &PDict{}, nil
		case "tuple":
			return &PTuple{}, nil
		case "set", "frozenset":
			s := &PSet{}
			if len(args) == 0 {
				return s, nil
			}
			if len(args) == 1 {
				if l, ok := args[0].(*PList); ok {
					s.Items = append(s.Items, l.Items...)
					return s, nil
				}
			}
			return nil, fmt.Errorf("wotlogin: %s args not a sequence", c.name)
		case "object":
			return &GenericValue{Module: "builtins", Name: "object", Args: args, Attrs: map[string]any{}}, nil
		}
	}
	return nil, fmt.Errorf("wotlogin: pickle call of %T", fn)
}

// resolveGlobal maps pickle globals to SAFE markers (never code).
func resolveGlobal(module, name string) (any, error) {
	if module == "collections" && name == "deque" {
		return &dequeMarker{}, nil
	}
	switch module {
	case "builtins", "__builtin__":
		switch name {
		case "list", "dict", "tuple", "set", "frozenset", "object":
			return &builtinMarker{name: name}, nil
		}
	}
	return &genericMarker{module: module, name: name}, nil
}

func unescapeASCII(b []byte) (string, error) {
	// Python string-escape subset for text opcodes (game strings are
	// ASCII identifiers); exotic escapes fail loud, never silent.
	var sb strings.Builder
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			sb.WriteByte(b[i])
			continue
		}
		i++
		switch b[i] {
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		case '\\':
			sb.WriteByte('\\')
		case '\'':
			sb.WriteByte('\'')
		case '"':
			sb.WriteByte('"')
		default:
			return "", fmt.Errorf("wotlogin: pickle bad escape %q", string(b))
		}
	}
	return sb.String(), nil
}

func unescapeUnicode(b []byte) (string, error) {
	// Raw-unicode-escape: ASCII passthrough + \uXXXX / \UXXXXXXXX.
	var sb strings.Builder
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			sb.WriteByte(b[i])
			continue
		}
		i++
		if b[i] != 'u' && b[i] != 'U' {
			s, err := unescapeASCII([]byte{'\\', b[i]})
			if err != nil {
				return "", err
			}
			sb.WriteString(s)
			continue
		}
		n := 4
		if b[i] == 'U' {
			n = 8
		}
		if i+n >= len(b) {
			return "", fmt.Errorf("wotlogin: pickle bad \\u escape")
		}
		var v int
		for _, c := range b[i+1 : i+1+n] {
			v *= 16
			switch {
			case c >= '0' && c <= '9':
				v += int(c - '0')
			case c >= 'a' && c <= 'f':
				v += int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v += int(c-'A') + 10
			default:
				return "", fmt.Errorf("wotlogin: pickle bad \\u escape")
			}
		}
		sb.WriteRune(rune(v))
		i += n
	}
	return sb.String(), nil
}

func decodeTextInt(b []byte) (any, error) {
	s := string(b)
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("wotlogin: pickle bad int %q", s)
}

// decodeOne runs one pickle document, returning value + consumed bytes.
func decodeOne(data []byte) (v any, n int, err error) {
	v, n, _, err = decodePrefix(data)
	return v, n, err
}

// DecodePrefix runs the decoder and returns the live stack at the
// first error (or completed value): UDP loss truncates lobby pickles
// mid-document, but nested containers that CLOSED before the cut are
// fully recovered.
func DecodePrefix(data []byte) (stk []any, n int, err error) {
	_, n, stk, err = decodePrefix(data)
	return stk, n, err
}

func decodePrefix(data []byte) (v any, n int, stk []any, err error) {
	p := &pun{data: data, memo: map[int]any{}}
	for p.pos < len(p.data) {
		var op byte
		if op, err = p.readByte(); err != nil {
			return nil, p.pos, append([]any(nil), p.stk...), err
		}
		if err = stepPickle(p, op); err != nil {
			if stop, ok := err.(pickleStop); ok {
				return stop.value, p.pos, append([]any(nil), p.stk...), nil
			}
			return nil, p.pos, append([]any(nil), p.stk...), fmt.Errorf("%w (op %02x @%d)", err, op, p.pos)
		}
	}
	return nil, p.pos, append([]any(nil), p.stk...), fmt.Errorf("wotlogin: pickle missing STOP")
}

type pickleStop struct{ value any }

func (p pickleStop) Error() string { return "STOP" }

func stepPickle(p *pun, op byte) error {
	switch op {
	case '\x80': // PROTO
		v, err := p.readByte()
		if err != nil {
			return err
		}
		if v > 5 {
			return fmt.Errorf("wotlogin: pickle proto %d", v)
		}
		return nil
	case '\x95': // FRAME
		n, err := p.u32()
		if err != nil {
			return err
		}
		if p.pos+int(n) > len(p.data) {
			return fmt.Errorf("wotlogin: pickle frame overrun")
		}
		return nil
	case '.': // STOP
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle empty STOP")
		}
		return pickleStop{p.stk[len(p.stk)-1]}
	case 'N': // NONE
		p.push(nil)
		return nil
	case '\x88': // NEWTRUE
		p.push(true)
		return nil
	case '\x89': // NEWFALSE
		p.push(false)
		return nil
	case 'I': // INT text
		b, err := p.readLine()
		if err != nil {
			return err
		}
		v, err := decodeTextInt(b)
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case 'L': // LONG text
		b, err := p.readLine()
		if err != nil {
			return err
		}
		s := strings.TrimSuffix(string(b), "L")
		v, err := decodeTextInt([]byte(s))
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case 'K': // BININT1
		b, err := p.readByte()
		if err != nil {
			return err
		}
		p.push(int64(b))
		return nil
	case 'M': // BININT2
		v, err := p.u16()
		if err != nil {
			return err
		}
		p.push(int64(v))
		return nil
	case 'J': // BININT
		v, err := p.u32()
		if err != nil {
			return err
		}
		p.push(int64(int32(v)))
		return nil
	case 'G': // BINFLOAT
		b, err := p.read(8)
		if err != nil {
			return err
		}
		p.push(math.Float64frombits(binary.BigEndian.Uint64(b)))
		return nil
	case 'F': // FLOAT text
		b, err := p.readLine()
		if err != nil {
			return err
		}
		f, err := strconv.ParseFloat(string(b), 64)
		if err != nil {
			return err
		}
		p.push(f)
		return nil
	case 'X': // BINUNICODE
		n, err := p.u32()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(string(b))
		return nil
	case '\x8c': // SHORT_BINUNICODE
		n, err := p.readByte()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(string(b))
		return nil
	case '\x8d': // BINUNICODE8
		nb, err := p.read(8)
		if err != nil {
			return err
		}
		n := binary.LittleEndian.Uint64(nb)
		if n > 1<<26 {
			return fmt.Errorf("wotlogin: pickle string too long")
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(string(b))
		return nil
	case 'U': // SHORT_BINSTRING
		n, err := p.readByte()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(string(b))
		return nil
	case 'S': // BINSTRING (repr-quoted)
		b, err := p.readLine()
		if err != nil {
			return err
		}
		if len(b) >= 2 && (b[0] == '\'' || b[0] == '"') {
			b = b[1 : len(b)-1]
		}
		s, err := unescapeASCII(b)
		if err != nil {
			return err
		}
		p.push(s)
		return nil
	case 'V': // UNICODE raw-unicode-escape
		b, err := p.readLine()
		if err != nil {
			return err
		}
		s, err := unescapeUnicode(b)
		if err != nil {
			return err
		}
		p.push(s)
		return nil
	case 'T': // BINBYTES
		n, err := p.u32()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(append([]byte(nil), b...))
		return nil
	case 'C': // SHORT_BINBYTES
		n, err := p.readByte()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(append([]byte(nil), b...))
		return nil
	case '\x8e': // BINBYTES8
		nb, err := p.read(8)
		if err != nil {
			return err
		}
		n := binary.LittleEndian.Uint64(nb)
		if n > 1<<26 {
			return fmt.Errorf("wotlogin: pickle bytes too long")
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		p.push(append([]byte(nil), b...))
		return nil
	case ']': // EMPTY_LIST
		p.push(&PList{})
		return nil
	case 'l': // LIST (MARK-based)
		items, err := p.popMark()
		if err != nil {
			return err
		}
		p.push(&PList{Items: items})
		return nil
	case '\x8f': // EMPTY_SET
		p.push(&PSet{})
		return nil
	case '\x91': // FROZENSET (MARK-based)
		items, err := p.popMark()
		if err != nil {
			return err
		}
		p.push(&PSet{Items: items})
		return nil
	case 'e': // APPENDS
		return appendItems(p)
	case 'a': // APPEND
		v, err := p.pop()
		if err != nil {
			return err
		}
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle APPEND target missing")
		}
		switch t := p.stk[len(p.stk)-1].(type) {
		case *PList:
			t.Items = append(t.Items, v)
			return nil
		case *Deque:
			t.Items = append(t.Items, v)
			return nil
		}
		return fmt.Errorf("wotlogin: pickle APPEND target %T", p.stk[len(p.stk)-1])
	case '}': // EMPTY_DICT
		p.push(&PDict{})
		return nil
	case 'd': // DICT (MARK-based, any key types)
		items, err := p.popMark()
		if err != nil {
			return err
		}
		if len(items)%2 != 0 {
			return fmt.Errorf("wotlogin: pickle DICT odd items")
		}
		d := &PDict{}
		for i := 0; i < len(items); i += 2 {
			d.Entries = append(d.Entries, PEntry{Key: items[i], Value: items[i+1]})
		}
		p.push(d)
		return nil
	case 's': // SETITEM (singular: key+value onto dict-top)
		v, err := p.pop()
		if err != nil {
			return err
		}
		k, err := p.pop()
		if err != nil {
			p.push(v)
			return err
		}
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle SETITEM target missing")
		}
		return dictSet(p.stk[len(p.stk)-1], k, v)
	case 'u': // SETITEMS (batch: MARK or MARK-less parity form)
		return setitems(p)
	case ')': // EMPTY_TUPLE
		p.push(&PTuple{})
		return nil
	case 't': // TUPLE (MARK-based)
		items, err := p.popMark()
		if err != nil {
			return err
		}
		p.push(&PTuple{Items: items})
		return nil
	case '\x85': // TUPLE1
		v, err := p.pop()
		if err != nil {
			return err
		}
		p.push(&PTuple{Items: []any{v}})
		return nil
	case '\x86': // TUPLE2
		b, err := p.pop()
		if err != nil {
			return err
		}
		a, err := p.pop()
		if err != nil {
			p.push(b)
			return err
		}
		p.push(&PTuple{Items: []any{a, b}})
		return nil
	case '\x87': // TUPLE3
		c, err := p.pop()
		if err != nil {
			return err
		}
		b, err := p.pop()
		if err != nil {
			p.push(c)
			return err
		}
		a, err := p.pop()
		if err != nil {
			p.push(b)
			p.push(c)
			return err
		}
		p.push(&PTuple{Items: []any{a, b, c}})
		return nil
	case '\x8a': // LONG1
		n, err := p.readByte()
		if err != nil {
			return err
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		if len(b) > 8 {
			return fmt.Errorf("wotlogin: pickle long too big")
		}
		var v int64
		for i := len(b) - 1; i >= 0; i-- {
			v = v*256 + int64(b[i])
		}
		if len(b) > 0 && b[len(b)-1] >= 0x80 {
			v -= int64(1) << uint(8*len(b))
		}
		p.push(v)
		return nil
	case '\x8b': // LONG4
		n, err := p.u32()
		if err != nil {
			return err
		}
		if n > 8 {
			return fmt.Errorf("wotlogin: pickle long too big")
		}
		b, err := p.read(int(n))
		if err != nil {
			return err
		}
		var v int64
		for i := len(b) - 1; i >= 0; i-- {
			v = v*256 + int64(b[i])
		}
		if len(b) > 0 && b[len(b)-1] >= 0x80 {
			v -= int64(1) << uint(8*len(b))
		}
		p.push(v)
		return nil
	case '\x90': // NEWOBJ
		args, err := p.pop()
		if err != nil {
			return err
		}
		klass, err := p.pop()
		if err != nil {
			p.push(args)
			return err
		}
		at, ok := args.(*PTuple)
		if !ok {
			return fmt.Errorf("wotlogin: pickle NEWOBJ args %T", args)
		}
		v, err := callClass(klass, at.Items)
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case '\x92': // NEWOBJ_EX (kwargs form)
		kwargs, err := p.pop()
		if err != nil {
			return err
		}
		args, err := p.pop()
		if err != nil {
			p.push(kwargs)
			return err
		}
		klass, err := p.pop()
		if err != nil {
			p.push(args)
			p.push(kwargs)
			return err
		}
		at, ok := args.(*PTuple)
		if !ok {
			return fmt.Errorf("wotlogin: pickle NEWOBJ_EX args %T", args)
		}
		v, err := callClass(klass, at.Items)
		if err != nil {
			return err
		}
		if gv, ok := v.(*GenericValue); ok {
			if kd, ok := kwargs.(*PDict); ok {
				for _, e := range kd.Entries {
					ks, ok := e.Key.(string)
					if !ok {
						return fmt.Errorf("wotlogin: pickle NEWOBJ_EX kwarg %T", e.Key)
					}
					if gv.Attrs == nil {
						gv.Attrs = map[string]any{}
					}
					gv.Attrs[ks] = e.Value
				}
			}
		}
		p.push(v)
		return nil
	case 'o': // OBJ (old-style instantiate)
		args, err := p.pop()
		if err != nil {
			return err
		}
		klass, err := p.pop()
		if err != nil {
			p.push(args)
			return err
		}
		at, ok := args.(*PTuple)
		if !ok {
			return fmt.Errorf("wotlogin: pickle OBJ args %T", args)
		}
		v, err := callClass(klass, at.Items)
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case 'R': // REDUCE
		args, err := p.pop()
		if err != nil {
			return err
		}
		fn, err := p.pop()
		if err != nil {
			p.push(args)
			return err
		}
		at, ok := args.(*PTuple)
		if !ok {
			return fmt.Errorf("wotlogin: pickle REDUCE args %T", args)
		}
		v, err := callClass(fn, at.Items)
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case 'b': // BUILD
		state, err := p.pop()
		if err != nil {
			return err
		}
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle BUILD target missing")
		}
		switch t := p.stk[len(p.stk)-1].(type) {
		case *GenericValue:
			if d, ok := state.(*PDict); ok {
				for _, e := range d.Entries {
					ks, ok := e.Key.(string)
					if !ok {
						return fmt.Errorf("wotlogin: pickle BUILD key %T", e.Key)
					}
					if t.Attrs == nil {
						t.Attrs = map[string]any{}
					}
					t.Attrs[ks] = e.Value
				}
				return nil
			}
			t.State = state
			return nil
		}
		return fmt.Errorf("wotlogin: pickle BUILD target %T", p.stk[len(p.stk)-1])
	case 'c': // GLOBAL (text lines)
		mb, err := p.readLine()
		if err != nil {
			return err
		}
		nb, err := p.readLine()
		if err != nil {
			p.push(string(mb))
			return err
		}
		v, err := resolveGlobal(string(mb), string(nb))
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case '\x93': // STACK_GLOBAL (module+name from stack)
		nv, err := p.pop()
		if err != nil {
			return err
		}
		mv, err := p.pop()
		if err != nil {
			p.push(nv)
			return err
		}
		ms, ok1 := mv.(string)
		ns, ok2 := nv.(string)
		if !ok1 || !ok2 {
			return fmt.Errorf("wotlogin: pickle STACK_GLOBAL not strings")
		}
		v, err := resolveGlobal(ms, ns)
		if err != nil {
			return err
		}
		p.push(v)
		return nil
	case '(': // MARK
		p.push(marker{})
		return nil
	case 'g', 'h', 'j': // GET/BINGET/LONG_BINGET
		var idx int
		switch op {
		case 'g':
			b, err := p.readLine()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(string(b))
			if err != nil {
				return err
			}
			idx = n
		case 'h':
			b, err := p.readByte()
			if err != nil {
				return err
			}
			idx = int(b)
		default:
			n, err := p.u32()
			if err != nil {
				return err
			}
			idx = int(n)
		}
		v, ok := p.memo[idx]
		if !ok {
			return fmt.Errorf("wotlogin: pickle memo miss %d", idx)
		}
		p.push(v)
		return nil
	case 'p', 'q', 'r': // PUT/BINPUT/LONG_BINPUT
		var idx int
		switch op {
		case 'p':
			b, err := p.readLine()
			if err != nil {
				return err
			}
			n, err := strconv.Atoi(string(b))
			if err != nil {
				return err
			}
			idx = n
		case 'q':
			b, err := p.readByte()
			if err != nil {
				return err
			}
			idx = int(b)
		default:
			n, err := p.u32()
			if err != nil {
				return err
			}
			idx = int(n)
		}
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle memo put on empty stack")
		}
		p.memo[idx] = p.stk[len(p.stk)-1]
		return nil
	case '\x94': // MEMOIZE
		if len(p.stk) == 0 {
			return fmt.Errorf("wotlogin: pickle memoize on empty stack")
		}
		p.memo[len(p.memo)] = p.stk[len(p.stk)-1]
		return nil
	default:
		return fmt.Errorf("wotlogin: pickle unsupported opcode %02x", op)
	}
}

// DecodeLobbyPickle decodes one cPickle protocol 0-5 document
// (trailing bytes after STOP are ignored).
func DecodeLobbyPickle(data []byte) (any, error) {
	v, _, err := decodeOne(data)
	return v, err
}

// DecodeAt decodes a pickle hidden behind a small per-message header
// (observed 0-6B on 1a bodies): it tries offsets 0..15 and returns
// the first success consuming >= 8 bytes (kills tiny accidental
// decodes; real lobby docs are 30B+).
func DecodeAt(data []byte, maxOff int) (any, int, int, error) {
	if maxOff > len(data) {
		maxOff = len(data)
	}
	var firstErr error
	for off := 0; off <= maxOff; off++ {
		v, n, err := decodeOne(data[off:])
		if err == nil && n >= 8 {
			return v, off, n, nil
		}
		if firstErr == nil && err != nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("wotlogin: no pickle at offsets 0..%d", maxOff)
	}
	return nil, 0, 0, firstErr
}

// DocSeg is one inventoried segment of a lobby bundle stream:
// either a decoded doc or the gap skipped to reach the next one.
// Summaries carry types/key names/counts only — never values.
type DocSeg struct {
	Offset   int    // stream offset of the segment start
	Consumed int    // decoded bytes (0 for a trailing gap)
	Summary  string // PickleSummary of the doc ("" for a gap)
	Gap      int    // skipped bytes before this segment (0 if contiguous)
	Err      string // decoder error that opened the gap ("" if none)
}

// Inventory walks a bundle stream doc by doc for offline analysis:
// DecodeOne at pos; on success record and advance; on failure
// resynchronize by scanning forward for the next \x80 proto prefix
// (proto <= 5, the lobby's framing) that decodes >= 8 bytes.
// Per-capture noise edits (a few bytes per 625KB, Sep 27) surface as
// small gaps, never hidden and never aborting the walk.
func Inventory(app []byte) []DocSeg {
	var out []DocSeg
	pos := 0
	for pos < len(app) {
		v, n, err := decodeOne(app[pos:])
		if err == nil {
			out = append(out, DocSeg{Offset: pos, Consumed: n, Summary: PickleSummary(v)})
			pos += n
			continue
		}
		firstErr := err
		next := -1
		var nv any
		var nn int
		for i := pos + 1; i+1 < len(app); i++ {
			if app[i] != 0x80 || app[i+1] > 5 {
				continue
			}
			v2, n2, err2 := decodeOne(app[i:])
			if err2 == nil && n2 >= 8 {
				next, nv, nn = i, v2, n2
				break
			}
		}
		if next < 0 {
			out = append(out, DocSeg{Offset: pos, Gap: len(app) - pos, Err: firstErr.Error()})
			break
		}
		out = append(out, DocSeg{Offset: next, Consumed: nn, Summary: PickleSummary(nv), Gap: next - pos, Err: firstErr.Error()})
		pos = next + nn
	}
	return out
}

// Frag is one stage-2 bulk chunk: the server sends each chunk as a
// burst of same-seq datagrams (first = header, rest = continuations;
// bursts arrive contiguously — audited 48/48 runs on two captures).
type Frag struct {
	Seq     uint32
	NN      int // 1-based chunk index from the head header (0 if unrecognized)
	Payload []byte
}

// DecodeBundle decodes a fragmented multi-document stream (lobby bulk
// bundle with UDP-loss holes): it decodes docs sequentially and, on
// failure, resynchronizes at the next frag start at or past the error.
// Returns decoded docs in order. Memo state resets per resync (never
// shared across a hole).
func DecodeBundle(frags []Frag) []any {
	var app []byte
	var starts []int
	off := 0
	for _, fr := range frags {
		starts = append(starts, off)
		app = append(app, fr.Payload...)
		off += len(fr.Payload)
	}
	var out []any
	pos := 0
	for pos < len(app) {
		v, n, err := decodeOne(app[pos:])
		if err == nil {
			out = append(out, v)
			pos += n
			continue
		}
		// Error or degenerate (< 8B) match: resynchronize at the
		// next frag start (frag payloads may begin mid-document).
		next := -1
		for _, s := range starts {
			if s >= pos {
				next = s
				break
			}
		}
		if next < 0 || next == pos {
			// At or past the last frag start with no progress:
			// step one byte to guarantee termination.
			pos++
			continue
		}
		pos = next
	}
	return out
}

// DecodeOne decodes one document and reports bytes consumed (for
// concatenated multi-document streams like the lobby bulk bundle).
func DecodeOne(data []byte) (any, int, error) {
	return decodeOne(data)
}

// HarvestKeys walks a decoded value collecting string dict-key NAMES
// (schema only — never values) into counts. Depth-capped; cycles
// impossible (decoder builds trees).
func HarvestKeys(v any, counts map[string]int) {
	var walk func(x any, depth int)
	walk = func(x any, depth int) {
		if depth > 8 {
			return
		}
		switch t := x.(type) {
		case *PDict:
			for _, e := range t.Entries {
				if ks, ok := e.Key.(string); ok && schemaKey(ks) {
					counts[ks]++
				}
				walk(e.Value, depth+1)
			}
		case *PList:
			for _, e := range t.Items {
				walk(e, depth+1)
			}
		case *PTuple:
			for _, e := range t.Items {
				walk(e, depth+1)
			}
		case *Deque:
			for _, e := range t.Items {
				walk(e, depth+1)
			}
		case *GenericValue:
			for _, e := range t.Attrs {
				walk(e, depth+1)
			}
		case *PSet:
			for _, e := range t.Items {
				walk(e, depth+1)
			}
		}
	}
	walk(v, 0)
}

// HarvestStream runs a resilient walk over a bundle stream for
// offline schema mapping: single shared-memo decoder state, STOPs
// harvested as docs, any other error opens a coalesced gap (bad byte
// skipped, stack+memo intact) and the walk continues. Per-capture
// noise edits thus cost small gaps instead of killing the stream.
// Returns key-name counts (identifier-shaped schema names only),
// doc/gap totals, and valid (non-gap) bytes. Schema only — never
// values.
func HarvestStream(app []byte) (counts map[string]int, docs, gaps, valid int) {
	counts = map[string]int{}
	p := &pun{data: app, memo: map[int]any{}}
	inGap := false
	gapStart := 0
	gapBytes := 0
	flushGap := func(end int) {
		if inGap {
			gapBytes += end - gapStart
			inGap = false
		}
	}
	for p.pos < len(p.data) {
		opPos := p.pos
		op, err := p.readByte()
		if err != nil {
			break
		}
		if err := stepPickle(p, op); err != nil {
			if stop, ok := err.(pickleStop); ok {
				HarvestKeys(stop.value, counts)
				docs++
				// Pop the value like Unpickler.load; stack+memo live on.
				if len(p.stk) > 0 {
					p.stk = p.stk[:len(p.stk)-1]
				}
				flushGap(opPos)
				continue
			}
			if !inGap {
				inGap = true
				gapStart = opPos
				gaps++
			}
			if p.pos <= opPos {
				p.pos = opPos + 1
			}
			continue
		}
		flushGap(opPos)
	}
	flushGap(len(app))
	valid = len(app) - gapBytes
	return counts, docs, gaps, valid
}

// schemaKey reports whether s looks like a lobby schema name
// (dotted/colon identifiers); binary garbage misparsed as strings
// is schema noise, never signal.
func schemaKey(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
			continue
		}
		if i > 0 && (c >= '0' && c <= '9' || c == '.' || c == ':' || c == '-') {
			continue
		}
		return false
	}
	return true
}

// PickleSummary sketches a decoded value for logs: container types,
// string key NAMES (schema, not secrets), lengths — never scalars.
func PickleSummary(v any) string {
	return summarize(v, 0)
}

func summarize(v any, depth int) string {
	if depth > 4 {
		return "…"
	}
	switch t := v.(type) {
	case *PDict:
		keys := make([]string, 0, len(t.Entries))
		for _, e := range t.Entries {
			if ks, ok := e.Key.(string); ok {
				keys = append(keys, ks)
			} else {
				keys = append(keys, fmt.Sprintf("<%T>", e.Key))
			}
		}
		slices.Sort(keys)
		if len(keys) > 12 {
			keys = append(keys[:12], fmt.Sprintf("+%d", len(keys)-12))
		}
		return fmt.Sprintf("dict{%s}", strings.Join(keys, ","))
	case *PList:
		inner := ""
		if len(t.Items) > 0 {
			inner = summarize(t.Items[0], depth+1)
		}
		return fmt.Sprintf("list[%d]%s", len(t.Items), inner)
	case *PTuple:
		parts := make([]string, 0, len(t.Items))
		for _, e := range t.Items {
			parts = append(parts, summarize(e, depth+1))
		}
		return fmt.Sprintf("(%s)", strings.Join(parts, ","))
	case *Deque:
		return fmt.Sprintf("deque[%d]", len(t.Items))
	case *GenericValue:
		return fmt.Sprintf("%s.%s", t.Module, t.Name)
	case *PSet:
		return fmt.Sprintf("set[%d]", len(t.Items))
	case string:
		return fmt.Sprintf("str[%d]", len(t))
	case []byte:
		return fmt.Sprintf("bytes[%d]", len(t))
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprintf("%T", v)
	case nil:
		return "nil"
	default:
		return fmt.Sprintf("%T", v)
	}
}
