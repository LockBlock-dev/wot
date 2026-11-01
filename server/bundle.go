package server

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// Bundle is a decoded lobby bundle: the stream of pickled objects the
// stage-2 flood carries.
//
// The flood is one shared-memo proto-2 pickle spread over fragment
// chains. Once reassembled in sequence order (login.ReassembleFrags) it
// decodes to a stack of objects — on the Oct-14 capture, 375 of them,
// mostly lobby config dicts. This type is the mutable view of that
// stream: decode once, patch values, re-encode.
//
// Round-trip is byte-identical when nothing is mutated, because the
// faithful codec replays each node's original opcode bytes. That is the
// property the private server relies on: a patched bundle differs from
// the capture only where we meant it to.
type Bundle struct {
	// Docs are the pickle documents the stream carries, in wire order.
	// The flood is a sequence of them: the static lobby config first,
	// then the per-account document (sessionStats, inventory, …).
	Docs []BundleDoc
	// Stack is every document's objects flattened, in wire order. It is
	// the view Find and the setters work on.
	Stack []*lobby.FNode
	// Raw is the reassembled bundle these documents came from.
	Raw []byte
	// Tail is whatever follows the last document. The flood carries
	// trailing bytes after the pickle; they are not ours to interpret,
	// so they ride along verbatim.
	Tail []byte
	// Decoded is how many bytes of Raw the documents cover; Raw[Decoded:]
	// is Tail. The encoder must reproduce exactly Decoded+len(Tail) bytes.
	Decoded int
}

// BundleDoc is one pickle document inside the flood.
type BundleDoc struct {
	// Stack is this document's objects, in wire order.
	Stack []*lobby.FNode
	// Marks are the stack indices where a MARK is still open at STOP.
	// The lobby bundle's outer dict is never closed, so these must be
	// replayed for the encoding to match.
	Marks []int
	// ops are container opcodes that follow items the decoder left on
	// the stack (malformed-region fallback).
	ops []lobby.KeepOp
	// stopped records whether the document ended at STOP. A document cut
	// short by non-pickle bytes must not gain one.
	stopped bool
}

// DecodeBundle parses a reassembled lobby bundle: every pickle document
// it carries, in order.
//
// A document ends at STOP, or where the next document's PROTO begins, or
// at the first byte that is not pickle at all (the flood's later chunks
// carry channel-framed packets). Whatever is left over is Tail.
func DecodeBundle(raw []byte) (*Bundle, error) {
	b := &Bundle{Raw: raw}
	off := 0
	for off < len(raw) {
		stack, marks, ops, n, stopped, err := lobby.DecodeFaithfulStream(raw[off:])
		if err != nil {
			if len(b.Docs) == 0 {
				return nil, fmt.Errorf("server: bundle decode: %w", err)
			}
			// A later document that will not decode is not ours to
			// interpret: keep it verbatim as tail.
			break
		}
		if n <= 0 {
			break
		}
		b.Docs = append(b.Docs, BundleDoc{Stack: stack, Marks: marks, ops: ops, stopped: stopped})
		b.Stack = append(b.Stack, stack...)
		off += n
		// A STOP closes one document, not the stream: a bundle built in
		// code writes each document with its own STOP. Keep going while
		// the next bytes decode; the loop ends on a decode error (the
		// capture's non-pickle tail) or at the end of the stream.
	}
	b.Decoded = off
	b.Tail = raw[off:]
	return b, nil
}

// Encode re-serialises the bundle. Untouched nodes replay verbatim, so
// an unmodified bundle encodes back to its input bytes.
func (b *Bundle) Encode() ([]byte, error) {
	var out []byte
	for i, d := range b.Docs {
		enc, err := lobby.EncodeFaithfulOpsStop(d.Stack, d.Marks, d.ops, d.stopped)
		if err != nil {
			return nil, fmt.Errorf("server: bundle encode doc %d: %w", i, err)
		}
		out = append(out, enc...)
	}
	return append(out, b.Tail...), nil
}

// Find returns every value stored under key, anywhere in the stream.
//
// Keys are matched by name, so a caller does not need to know which
// object in the stream holds the value. The returned nodes are live:
// mutating one changes the bundle.
func (b *Bundle) Find(key string) []*lobby.FNode {
	var out []*lobby.FNode
	for _, n := range b.Stack {
		findIn(n, key, &out, 0)
	}
	return out
}

// findIn walks one node looking for dict entries named key.
func findIn(n *lobby.FNode, key string, out *[]*lobby.FNode, depth int) {
	if n == nil || depth > 32 {
		return
	}
	if n.Kind == lobby.FDict {
		for i, k := range n.Keys {
			if nodeKey(k) == key {
				*out = append(*out, n.Items[i])
			}
			findIn(n.Items[i], key, out, depth+1)
		}
		return
	}
	for _, it := range n.Items {
		findIn(it, key, out, depth+1)
	}
}

// nodeKey renders a dict key as a plain string. CPython 3 pickles a
// bytes key as _codecs.encode(u'...', 'latin1'), so that wrapper is
// unwrapped too.
func nodeKey(k *lobby.FNode) string {
	if k == nil {
		return ""
	}
	if k.Kind == lobby.FString || k.Kind == lobby.FUnicode {
		return k.S
	}
	if k.Kind == lobby.FReduce && k.Callable != nil && k.Callable.Kind == lobby.FGlobal &&
		k.Callable.Name == "encode" && k.Args != nil && len(k.Args.Items) == 2 &&
		k.Args.Items[0].Kind == lobby.FUnicode {
		return k.Args.Items[0].S
	}
	return ""
}

// SetInt sets every value stored under key to v, reporting how many were
// changed. Values that are not integers are skipped.
func (b *Bundle) SetInt(key string, v int64) int {
	n := 0
	for _, node := range b.Find(key) {
		if node.Kind == lobby.FInt {
			node.SetInt(v)
			n++
		}
	}
	return n
}

// SetString sets every string value stored under key to v.
func (b *Bundle) SetString(key, v string) int {
	n := 0
	for _, node := range b.Find(key) {
		if node.Kind == lobby.FString || node.Kind == lobby.FUnicode {
			node.SetString(v)
			n++
		}
	}
	return n
}
