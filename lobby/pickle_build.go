package lobby

import "fmt"

// Builders for pickle documents that do not come from a capture.
//
// A node made here has no Raw and no Recipe, so the encoder writes it
// canonically — the same bytes cPickle produces for a literal. That is
// the difference between patching a captured bundle and authoring one:
// DecodeFaithful replays what the wire said, these construct what it
// should say.

// NewDict returns an empty dict.
func NewDict() *FNode { return &FNode{Kind: FDict} }

// NewList returns a list of the given items.
func NewList(items ...*FNode) *FNode { return &FNode{Kind: FList, Items: items} }

// NewTuple returns a tuple of the given items.
func NewTuple(items ...*FNode) *FNode { return &FNode{Kind: FTuple, Items: items} }

// NewInt returns an integer.
func NewInt(v int64) *FNode { return &FNode{Kind: FInt, I: v} }

// NewFloat returns a float.
func NewFloat(v float64) *FNode { return &FNode{Kind: FFloat, F: v} }

// NewString returns a str (bytes), which is what the lobby uses for keys.
func NewString(s string) *FNode { return &FNode{Kind: FString, S: s} }

// NewUnicode returns a unicode string. Python 2 keeps the distinction, so
// a value the client compares against a unicode literal must be one.
func NewUnicode(s string) *FNode { return &FNode{Kind: FUnicode, S: s} }

// NewBool returns True or False.
func NewBool(v bool) *FNode { return &FNode{Kind: FBool, B: v} }

// NewNone returns None.
func NewNone() *FNode { return &FNode{Kind: FNone} }

// Set adds or replaces a string-keyed entry and returns the dict, so
// calls chain.
func (n *FNode) Set(key string, v *FNode) *FNode {
	return n.SetNode(NewString(key), v)
}

// SetNode is Set with a non-string key.
func (n *FNode) SetNode(key, v *FNode) *FNode {
	for i, k := range n.Keys {
		if k == key || (k.Kind == key.Kind && k.S == key.S && k.I == key.I) {
			n.Items[i] = v
			return n
		}
	}
	n.Keys = append(n.Keys, key)
	n.Items = append(n.Items, v)
	return n
}

// Append adds items to a list or tuple and returns it.
func (n *FNode) Append(items ...*FNode) *FNode {
	n.Items = append(n.Items, items...)
	return n
}

// Get returns the value stored under key, or nil.
func (n *FNode) Get(key string) *FNode {
	if n == nil || n.Kind != FDict {
		return nil
	}
	for i, k := range n.Keys {
		if k.S == key {
			return n.Items[i]
		}
	}
	return nil
}

// Len reports the number of items (or key/value pairs).
func (n *FNode) Len() int {
	if n == nil {
		return 0
	}
	return len(n.Items)
}

// EncodeDocument serialises nodes as one proto-2 pickle document: PROTO,
// the nodes in order, STOP.
//
// The lobby's outer dict is never closed on the wire, so a document built
// here is a stack of nodes rather than one root value — pass the dicts
// the client expects to find, in the order it expects them.
func EncodeDocument(nodes ...*FNode) ([]byte, error) {
	out, err := EncodeFaithfulOpsStop(nodes, nil, nil, true)
	if err != nil {
		return nil, fmt.Errorf("lobby: build document: %w", err)
	}
	return out, nil
}

// NewRaw wraps pre-built pickle opcodes as a value. The encoder replays them
// verbatim, so the caller owns their correctness — it exists for values the
// client only accepts as an instance of one of its own classes.
func NewRaw(b []byte) *FNode { return &FNode{Kind: FRaw, Raw: b} }
