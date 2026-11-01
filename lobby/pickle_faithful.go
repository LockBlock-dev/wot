package lobby

// Faithful cPickle protocol-2 codec: decode to a node tree that remembers
// HOW each value was encoded, so re-encoding reproduces the original bytes
// exactly.
//
// Why a second codec: pickle.go is a salvage decoder — it flattens values
// and drops encoding detail, which is right for census work but cannot
// round-trip. The private server needs the opposite: mutate a lobby bundle
// and emit something the client accepts, with a byte-identical round-trip
// as the regression oracle.
//
// What is preserved:
//   - the exact opcode per scalar (BININT1 vs BININT2 vs BININT vs INT,
//     SHORT_BINSTRING vs BINSTRING vs BINUNICODE, ...) via Node.Raw;
//   - str vs unicode (the distinction pickle.go loses);
//   - container build recipes (APPEND vs APPENDS, SETITEM vs SETITEMS,
//     TUPLE vs TUPLE1/2/3);
//   - memo indices and the BINPUT vs LONG_BINPUT / BINGET vs LONG_BINGET
//     choice, with shared objects kept as shared *Node pointers.
//
// Mutation: set Node.Dirty on a scalar and the encoder re-encodes it
// canonically instead of replaying Raw. Untouched nodes replay verbatim.

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

// Pickle opcodes used by the lobby bundle (protocol 2 subset).
const (
	opProto          = 0x80
	opStop           = '.'
	opMark           = '('
	opNone           = 'N'
	opNewTrue        = 0x88
	opNewFalse       = 0x89
	opInt            = 'I'
	opBinInt         = 'J'
	opBinInt1        = 'K'
	opBinInt2        = 'M'
	opBinFloat       = 'G'
	opShortBinString = 'U'
	opBinString      = 'T'
	opBinUnicode     = 'X'
	opEmptyList      = ']'
	opAppend         = 'a'
	opAppends        = 'e'
	opEmptyDict      = '}'
	opSetItem        = 's'
	opSetItems       = 'u'
	opEmptyTuple     = ')'
	opTuple          = 't'
	opTuple1         = 0x85
	opTuple2         = 0x86
	opTuple3         = 0x87
	opBinPut         = 'q'
	opLongBinPut     = 'r'
	opBinGet         = 'h'
	opLongBinGet     = 'j'
	opGlobal         = 'c'
	opReduce         = 'R'
)

// FKind is a faithful node's type.
type FKind uint8

const (
	FNone FKind = iota
	FBool
	FInt
	FFloat
	FString  // str (bytes)
	FUnicode // unicode
	FList
	FTuple
	FDict
	FGlobal // module.name reference
	FReduce // callable(args)
)

// FNode is one pickled value plus the encoding detail needed to reproduce
// it byte-for-byte.
type FNode struct {
	Kind FKind

	// Raw is the exact opcode bytes that produced this scalar (opcode +
	// args). The encoder replays it unless Dirty is set.
	Raw   []byte
	Dirty bool

	// Parsed value (kept in sync with Raw; authoritative when Dirty).
	I int64
	F float64
	S string
	B bool

	// Containers. For FDict, Keys[i] pairs with Items[i].
	Keys  []*FNode
	Items []*FNode
	// Recipe is the sequence of add-steps used to build the container,
	// in order. Each step records the opcode AND how many items it
	// consumed: a list can be built by several APPENDS calls, and
	// collapsing them into one changes the bytes.
	Recipe []FStep

	// FGlobal / FReduce.
	Module, Name string
	Callable     *FNode
	Args         *FNode

	// Memos holds every memo index this object was stored at, in wire
	// order, with the opcode form used for each (BINPUT vs LONG_BINPUT).
	// A node can be memoised more than once; keeping only the last index
	// loses entries and makes re-encoding shorter than the input.
	Memos   []int
	MemoOps []byte
}

// FStep is one container-building step: the opcode and the number of
// items (or key/value pairs) it consumed.
type FStep struct {
	Op byte
	N  int
}

// SetInt rewrites an integer node, marking it for canonical re-encoding.
func (n *FNode) SetInt(v int64) {
	n.Kind, n.I, n.Dirty = FInt, v, true
}

// SetString rewrites a string node (str, not unicode).
func (n *FNode) SetString(v string) {
	n.Kind, n.S, n.Dirty = FString, v, true
}

// keepOp is a container opcode to emit at a given stack index.
type KeepOp struct {
	at int
	op byte
}

// fmarker is the MARK sentinel on the decode stack.
type fmarker struct{}

// DecodeFaithful decodes one pickle document into its final stack. It
// returns the stack and the number of bytes consumed (through STOP).
func DecodeFaithful(data []byte) ([]*FNode, int, error) {
	stack, _, n, err := DecodeFaithfulMarks(data)
	return stack, n, err
}

// DecodeFaithfulMarks is DecodeFaithful plus the stack indices where a
// MARK is still open at STOP.
//
// The lobby bundle is a *stream*: its outer dict is never closed, so the
// MARK that opened it is still pending when the document ends. Those
// positions have to be replayed for the encoding to match.
func DecodeFaithfulMarks(data []byte) ([]*FNode, []int, int, error) {
	stack, marks, _, n, err := DecodeFaithfulOps(data)
	return stack, marks, n, err
}

// DecodeFaithfulOps is DecodeFaithfulMarks plus the container opcodes
// that must follow items the malformed-region fallback left on the
// stack, as {stack index, opcode} pairs.
func DecodeFaithfulOps(data []byte) ([]*FNode, []int, []KeepOp, int, error) {
	d := &fdecoder{data: data, memo: map[int]*FNode{}}
	if err := d.run(); err != nil {
		return nil, nil, nil, d.pos, err
	}
	marks := append(append([]int(nil), d.marks...), d.keepMarks...)
	sort.Ints(marks)
	return d.stack, marks, d.keepOps, d.pos, nil
}

type fdecoder struct {
	data  []byte
	pos   int
	stack []*FNode
	marks []int // stack depths at each MARK
	// markOwner[i] is the node that was on top when marks[i] was pushed:
	// the container a following SETITEMS/APPENDS fills.
	markOwner []*FNode
	memo      map[int]*FNode
	// lastOwner is the container the most recent markItems belonged to.
	lastOwner *FNode
	// keepMarks records MARKs whose items could not be attached (the
	// malformed-region fallback). They stay on the stack, so the encoder
	// must re-emit their MARK.
	keepMarks []int
	// keepOps records a container opcode that must follow the items the
	// fallback left on the stack: {stack index to emit at, opcode}.
	keepOps []KeepOp
}

func (d *fdecoder) push(n *FNode) { d.stack = append(d.stack, n) }

func (d *fdecoder) pop() (*FNode, error) {
	if len(d.stack) == 0 {
		return nil, fmt.Errorf("lobby: pickle stack underflow")
	}
	n := d.stack[len(d.stack)-1]
	d.stack = d.stack[:len(d.stack)-1]
	return n, nil
}

func (d *fdecoder) read(n int) ([]byte, error) {
	if d.pos+n > len(d.data) {
		return nil, fmt.Errorf("lobby: pickle truncated at %d (+%d)", d.pos, n)
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

func (d *fdecoder) byte1() (byte, error) {
	b, err := d.read(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *fdecoder) u32() (uint32, error) {
	b, err := d.read(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// line reads through the next newline (protocol-0 text args).
func (d *fdecoder) line() ([]byte, error) {
	start := d.pos
	for d.pos < len(d.data) {
		if d.data[d.pos] == '\n' {
			b := d.data[start : d.pos+1]
			d.pos++
			return b, nil
		}
		d.pos++
	}
	return nil, fmt.Errorf("lobby: pickle unterminated line at %d", start)
}

// markItems returns the items above the most recent MARK and pops it.
func (d *fdecoder) markItems() ([]*FNode, error) {
	if len(d.marks) == 0 {
		return nil, fmt.Errorf("lobby: pickle MARK missing")
	}
	mi := d.marks[len(d.marks)-1]
	d.marks = d.marks[:len(d.marks)-1]
	owner := d.markOwner[len(d.markOwner)-1]
	d.markOwner = d.markOwner[:len(d.markOwner)-1]
	items := append([]*FNode(nil), d.stack[mi:]...)
	d.stack = d.stack[:mi]
	d.lastOwner = owner
	return items, nil
}

func (d *fdecoder) run() error {
	for d.pos < len(d.data) {
		start := d.pos
		op, err := d.byte1()
		if err != nil {
			return err
		}
		switch op {
		case opProto:
			if _, err := d.byte1(); err != nil {
				return err
			}
		case opStop:
			return nil
		case opMark:
			// A MARK is a stack delimiter, not a value: record the
			// current depth and push nothing, so no sentinel can leak
			// into the decoded stack. Remember the container on top —
			// that is what a following SETITEMS/APPENDS fills, even if
			// the stack has moved on by then.
			d.marks = append(d.marks, len(d.stack))
			var owner *FNode
			if len(d.stack) > 0 {
				owner = d.stack[len(d.stack)-1]
			}
			d.markOwner = append(d.markOwner, owner)
		case opNone:
			d.push(&FNode{Kind: FNone, Raw: d.data[start:d.pos]})
		case opNewTrue:
			d.push(&FNode{Kind: FBool, B: true, Raw: d.data[start:d.pos]})
		case opNewFalse:
			d.push(&FNode{Kind: FBool, B: false, Raw: d.data[start:d.pos]})
		case opInt:
			ln, err := d.line()
			if err != nil {
				return err
			}
			var v int64
			fmt.Sscanf(string(ln), "%d", &v)
			d.push(&FNode{Kind: FInt, I: v, Raw: d.data[start:d.pos]})
		case opBinInt:
			b, err := d.read(4)
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FInt, I: int64(int32(binary.LittleEndian.Uint32(b))), Raw: d.data[start:d.pos]})
		case opBinInt1:
			b, err := d.byte1()
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FInt, I: int64(b), Raw: d.data[start:d.pos]})
		case opBinInt2:
			b, err := d.read(2)
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FInt, I: int64(binary.LittleEndian.Uint16(b)), Raw: d.data[start:d.pos]})
		case opBinFloat:
			b, err := d.read(8)
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FFloat, F: math.Float64frombits(binary.BigEndian.Uint64(b)), Raw: d.data[start:d.pos]})
		case opShortBinString:
			n, err := d.byte1()
			if err != nil {
				return err
			}
			b, err := d.read(int(n))
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FString, S: string(b), Raw: d.data[start:d.pos]})
		case opBinString:
			n, err := d.u32()
			if err != nil {
				return err
			}
			b, err := d.read(int(n))
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FString, S: string(b), Raw: d.data[start:d.pos]})
		case opBinUnicode:
			n, err := d.u32()
			if err != nil {
				return err
			}
			b, err := d.read(int(n))
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FUnicode, S: string(b), Raw: d.data[start:d.pos]})
		case opEmptyList:
			d.push(&FNode{Kind: FList, Raw: d.data[start:d.pos]})
		case opEmptyDict:
			d.push(&FNode{Kind: FDict, Raw: d.data[start:d.pos]})
		case opEmptyTuple:
			d.push(&FNode{Kind: FTuple, Raw: d.data[start:d.pos]})
		case opAppend:
			v, err := d.pop()
			if err != nil {
				return err
			}
			if len(d.stack) == 0 {
				return fmt.Errorf("lobby: APPEND with no list")
			}
			l := d.stack[len(d.stack)-1]
			l.Items = append(l.Items, v)
			l.Recipe = append(l.Recipe, FStep{Op: opAppend, N: 1})
		case opAppends:
			items, err := d.markItems()
			if err != nil {
				return err
			}
			l := d.lastOwner
			if l == nil || (l.Kind != FList && l.Kind != FReduce) {
				// Malformed region (the capture has a string that
				// swallowed a document start): keep the items on the
				// stack rather than attaching them to a non-list, and
				// remember the MARK so the encoder re-emits it.
				d.keepMarks = append(d.keepMarks, len(d.stack))
				d.stack = append(d.stack, items...)
				d.keepOps = append(d.keepOps, KeepOp{at: len(d.stack), op: opAppends})
				break
			}
			l.Items = append(l.Items, items...)
			l.Recipe = append(l.Recipe, FStep{Op: opAppends, N: len(items)})
		case opSetItem:
			v, err := d.pop()
			if err != nil {
				return err
			}
			k, err := d.pop()
			if err != nil {
				return err
			}
			if len(d.stack) == 0 {
				return fmt.Errorf("lobby: SETITEM with no dict")
			}
			m := d.stack[len(d.stack)-1]
			m.Keys = append(m.Keys, k)
			m.Items = append(m.Items, v)
			m.Recipe = append(m.Recipe, FStep{Op: opSetItem, N: 1})
		case opSetItems:
			items, err := d.markItems()
			if err != nil {
				return err
			}
			m := d.lastOwner
			if m == nil || (m.Kind != FDict && m.Kind != FReduce) {
				// Same malformed-region fallback as APPENDS.
				d.keepMarks = append(d.keepMarks, len(d.stack))
				d.stack = append(d.stack, items...)
				d.keepOps = append(d.keepOps, KeepOp{at: len(d.stack), op: opSetItems})
				break
			}
			for i := 0; i+1 < len(items); i += 2 {
				m.Keys = append(m.Keys, items[i])
				m.Items = append(m.Items, items[i+1])
			}
			m.Recipe = append(m.Recipe, FStep{Op: opSetItems, N: len(items) / 2})
		case opTuple:
			items, err := d.markItems()
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FTuple, Items: items, Raw: d.data[start:d.pos]})
		case opTuple1, opTuple2, opTuple3:
			n := int(op-opTuple1) + 1
			if len(d.stack) < n {
				return fmt.Errorf("lobby: TUPLE%d underflow", n)
			}
			items := append([]*FNode(nil), d.stack[len(d.stack)-n:]...)
			d.stack = d.stack[:len(d.stack)-n]
			d.push(&FNode{Kind: FTuple, Items: items, Raw: d.data[start:d.pos]})
		case opBinPut, opLongBinPut:
			var idx int
			if op == opBinPut {
				b, err := d.byte1()
				if err != nil {
					return err
				}
				idx = int(b)
			} else {
				v, err := d.u32()
				if err != nil {
					return err
				}
				idx = int(v)
			}
			if len(d.stack) == 0 {
				return fmt.Errorf("lobby: BINPUT with empty stack")
			}
			top := d.stack[len(d.stack)-1]
			top.Memos = append(top.Memos, idx)
			top.MemoOps = append(top.MemoOps, op)
			d.memo[idx] = top
		case opBinGet, opLongBinGet:
			var idx int
			if op == opBinGet {
				b, err := d.byte1()
				if err != nil {
					return err
				}
				idx = int(b)
			} else {
				v, err := d.u32()
				if err != nil {
					return err
				}
				idx = int(v)
			}
			n, ok := d.memo[idx]
			if !ok {
				return fmt.Errorf("lobby: BINGET %d not in memo", idx)
			}
			d.push(n)
		case opGlobal:
			mod, err := d.line()
			if err != nil {
				return err
			}
			name, err := d.line()
			if err != nil {
				return err
			}
			d.push(&FNode{
				Kind:   FGlobal,
				Module: string(mod[:len(mod)-1]),
				Name:   string(name[:len(name)-1]),
				Raw:    d.data[start:d.pos],
			})
		case opReduce:
			args, err := d.pop()
			if err != nil {
				return err
			}
			call, err := d.pop()
			if err != nil {
				return err
			}
			d.push(&FNode{Kind: FReduce, Callable: call, Args: args, Raw: d.data[start:d.pos]})
		default:
			return fmt.Errorf("lobby: unsupported pickle opcode 0x%02x at %d", op, start)
		}
	}
	return fmt.Errorf("lobby: pickle exhausted before STOP")
}

// EncodeFaithful re-encodes a stack produced by DecodeFaithful. Untouched
// nodes replay their original bytes; dirty scalars are re-encoded
// canonically. The result is byte-identical to the input when nothing was
// mutated.
func EncodeFaithful(stack []*FNode) ([]byte, error) {
	return EncodeFaithfulMarks(stack, nil)
}

// EncodeFaithfulMarks re-encodes a stack, emitting a MARK before each
// stack index listed in marks (the positions DecodeFaithfulMarks
// reported as still open).
func EncodeFaithfulMarks(stack []*FNode, marks []int) ([]byte, error) {
	return EncodeFaithfulOps(stack, marks, nil)
}

// EncodeFaithfulOps is EncodeFaithfulMarks plus the container opcodes
// DecodeFaithfulOps reported.
func EncodeFaithfulOps(stack []*FNode, marks []int, ops []KeepOp) ([]byte, error) {
	e := &fencoder{seen: map[*FNode]bool{}}
	e.out = append(e.out, opProto, 2)
	next, nextOp := 0, 0
	flushOps := func(at int) {
		for nextOp < len(ops) && ops[nextOp].at == at {
			e.out = append(e.out, ops[nextOp].op)
			nextOp++
		}
	}
	for i, n := range stack {
		for next < len(marks) && marks[next] == i {
			e.out = append(e.out, opMark)
			next++
		}
		if err := e.emit(n); err != nil {
			return nil, err
		}
		flushOps(i + 1)
	}
	for ; next < len(marks); next++ {
		e.out = append(e.out, opMark)
	}
	flushOps(len(stack))
	e.out = append(e.out, opStop)
	return e.out, nil
}

type fencoder struct {
	out  []byte
	seen map[*FNode]bool // node body already emitted
}

func (e *fencoder) emit(n *FNode) error {
	// A memoised node emits its body once, then BINGET.
	if len(n.Memos) > 0 {
		if e.seen[n] {
			idx := n.Memos[0]
			if n.MemoOps[0] == opBinPut && idx < 256 {
				e.out = append(e.out, opBinGet, byte(idx))
			} else {
				e.out = append(e.out, opLongBinGet)
				e.out = binary.LittleEndian.AppendUint32(e.out, uint32(idx))
			}
			return nil
		}
		e.seen[n] = true
	}

	switch n.Kind {
	case FNone, FBool, FInt, FFloat, FString, FUnicode:
		if !n.Dirty && len(n.Raw) > 0 {
			e.out = append(e.out, n.Raw...)
		} else if err := e.emitScalar(n); err != nil {
			return err
		}
		e.putMemo(n)
		return nil

	case FList:
		// The memo put follows the empty constructor, before the items,
		// so a self-referential list can refer to itself.
		e.out = append(e.out, opEmptyList)
		e.putMemo(n)
		return e.emitItems(n, n.Items, opAppend, opAppends)

	case FDict:
		e.out = append(e.out, opEmptyDict)
		e.putMemo(n)
		return e.emitPairs(n)

	case FTuple:
		if !n.Dirty && len(n.Raw) > 0 && n.Raw[0] != opTuple {
			// TUPLE1/2/3: items first, then the opcode.
			for _, it := range n.Items {
				if err := e.emit(it); err != nil {
					return err
				}
			}
			e.out = append(e.out, n.Raw[0])
		} else {
			e.out = append(e.out, opMark)
			for _, it := range n.Items {
				if err := e.emit(it); err != nil {
					return err
				}
			}
			e.out = append(e.out, opTuple)
		}
		e.putMemo(n)
		return nil

	case FGlobal:
		e.out = append(e.out, opGlobal)
		e.out = append(e.out, n.Module...)
		e.out = append(e.out, '\n')
		e.out = append(e.out, n.Name...)
		e.out = append(e.out, '\n')
		e.putMemo(n)
		return nil

	case FReduce:
		if err := e.emit(n.Callable); err != nil {
			return err
		}
		if err := e.emit(n.Args); err != nil {
			return err
		}
		e.out = append(e.out, opReduce)
		e.putMemo(n)
		// The reduced object can then be filled like a dict or a list
		// (OrderedDict() followed by SETITEMS is the common case).
		if len(n.Recipe) > 0 {
			if n.Recipe[0].Op == opSetItem || n.Recipe[0].Op == opSetItems {
				return e.emitPairs(n)
			}
			return e.emitItems(n, n.Items, opAppend, opAppends)
		}
		return nil
	}
	return fmt.Errorf("lobby: cannot encode node kind %d", n.Kind)
}

// putMemo writes the memo assignment for a node, if it has one.
func (e *fencoder) putMemo(n *FNode) {
	for i, idx := range n.Memos {
		if n.MemoOps[i] == opBinPut && idx < 256 {
			e.out = append(e.out, opBinPut, byte(idx))
			continue
		}
		e.out = append(e.out, opLongBinPut)
		e.out = binary.LittleEndian.AppendUint32(e.out, uint32(idx))
	}
}

// emitItems replays a list recipe: each opAppend adds one item, each
// opAppends adds all remaining.
func (e *fencoder) emitItems(n *FNode, items []*FNode, one, many byte) error {
	i := 0
	for _, st := range n.Recipe {
		switch st.Op {
		case one:
			if i >= len(items) {
				return fmt.Errorf("lobby: list recipe overruns items")
			}
			if err := e.emit(items[i]); err != nil {
				return err
			}
			e.out = append(e.out, one)
			i++
		case many:
			if i+st.N > len(items) {
				return fmt.Errorf("lobby: list recipe overruns items")
			}
			e.out = append(e.out, opMark)
			for k := 0; k < st.N; k++ {
				if err := e.emit(items[i]); err != nil {
					return err
				}
				i++
			}
			e.out = append(e.out, many)
		default:
			return fmt.Errorf("lobby: bad list recipe op 0x%02x", st.Op)
		}
	}
	if i != len(items) {
		return fmt.Errorf("lobby: list recipe covered %d of %d items", i, len(items))
	}
	return nil
}

// emitPairs replays a dict recipe.
func (e *fencoder) emitPairs(n *FNode) error {
	i := 0
	for _, st := range n.Recipe {
		switch st.Op {
		case opSetItem:
			if i >= len(n.Items) {
				return fmt.Errorf("lobby: dict recipe overruns items")
			}
			if err := e.emit(n.Keys[i]); err != nil {
				return err
			}
			if err := e.emit(n.Items[i]); err != nil {
				return err
			}
			e.out = append(e.out, opSetItem)
			i++
		case opSetItems:
			if i+st.N > len(n.Items) {
				return fmt.Errorf("lobby: dict recipe overruns items")
			}
			e.out = append(e.out, opMark)
			for k := 0; k < st.N; k++ {
				if err := e.emit(n.Keys[i]); err != nil {
					return err
				}
				if err := e.emit(n.Items[i]); err != nil {
					return err
				}
				i++
			}
			e.out = append(e.out, opSetItems)
		default:
			return fmt.Errorf("lobby: bad dict recipe op 0x%02x", st.Op)
		}
	}
	if i != len(n.Items) {
		return fmt.Errorf("lobby: dict recipe covered %d of %d pairs", i, len(n.Items))
	}
	return nil
}

// emitScalar canonically encodes a dirty scalar, choosing the smallest
// integer form the way cPickle does.
func (e *fencoder) emitScalar(n *FNode) error {
	switch n.Kind {
	case FNone:
		e.out = append(e.out, opNone)
	case FBool:
		if n.B {
			e.out = append(e.out, opNewTrue)
		} else {
			e.out = append(e.out, opNewFalse)
		}
	case FInt:
		switch {
		case n.I >= 0 && n.I < 256:
			e.out = append(e.out, opBinInt1, byte(n.I))
		case n.I >= 0 && n.I < 65536:
			e.out = append(e.out, opBinInt2)
			e.out = binary.LittleEndian.AppendUint16(e.out, uint16(n.I))
		case n.I >= math.MinInt32 && n.I <= math.MaxInt32:
			e.out = append(e.out, opBinInt)
			e.out = binary.LittleEndian.AppendUint32(e.out, uint32(int32(n.I)))
		default:
			e.out = append(e.out, opInt)
			e.out = append(e.out, []byte(fmt.Sprintf("%d\n", n.I))...)
		}
	case FFloat:
		e.out = append(e.out, opBinFloat)
		e.out = binary.BigEndian.AppendUint64(e.out, math.Float64bits(n.F))
	case FString:
		if len(n.S) < 256 {
			e.out = append(e.out, opShortBinString, byte(len(n.S)))
		} else {
			e.out = append(e.out, opBinString)
			e.out = binary.LittleEndian.AppendUint32(e.out, uint32(len(n.S)))
		}
		e.out = append(e.out, n.S...)
	case FUnicode:
		e.out = append(e.out, opBinUnicode)
		e.out = binary.LittleEndian.AppendUint32(e.out, uint32(len(n.S)))
		e.out = append(e.out, n.S...)
	default:
		return fmt.Errorf("lobby: not a scalar kind %d", n.Kind)
	}
	return nil
}
