package server

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// VerifyBundle is the login.BaseAppConfig.VerifyBulk gate: it decodes the
// reassembled carrier bundle and re-encodes it, requiring a byte-identical
// result. A carrier that fails this is a truncated capture, a wrong key or
// the wrong flow, and the server refuses to start rather than serve a
// bundle the client would silently ACK and then render as an empty hangar.
func VerifyBundle(stream []byte) error {
	b, err := DecodeBundle(stream)
	if err != nil {
		return fmt.Errorf("bulk: %w", err)
	}
	if len(b.Stack) == 0 {
		return fmt.Errorf("bulk: bundle decoded to nothing")
	}
	out, err := b.Encode()
	if err != nil {
		return fmt.Errorf("bulk: %w", err)
	}
	// The encoder must reproduce exactly the bytes the decoder claims to
	// cover plus the verbatim tail. A stream that ends in non-pickle
	// bytes (the flood's later chunks carry framed packets) has a tail,
	// so comparing against len(stream) alone would be wrong.
	if want := b.Decoded + len(b.Tail); len(out) != want {
		return fmt.Errorf("bulk: re-encode is %d bytes, want %d (decoded %d + tail %d)",
			len(out), want, b.Decoded, len(b.Tail))
	}
	return nil
}

// BulkPatcher returns a login.BaseAppConfig.PatchBulk implementation: it
// decodes the reassembled bundle, lets mutate edit it, and re-encodes it.
//
// The re-encode must keep the length, because the frames are rebuilt in
// place — a length change would desynchronise the client's fragment
// accounting. A mutation that cannot hold that invariant is an error, not
// a silent skip.
func BulkPatcher(mutate func(*Bundle) error) func([]byte) ([]byte, error) {
	return func(stream []byte) ([]byte, error) {
		b, err := DecodeBundle(stream)
		if err != nil {
			return nil, fmt.Errorf("bulk: %w", err)
		}
		if mutate != nil {
			if err := mutate(b); err != nil {
				return nil, err
			}
		}
		out, err := b.Encode()
		if err != nil {
			return nil, fmt.Errorf("bulk: %w", err)
		}
		if len(out) != len(stream) {
			return nil, fmt.Errorf("bulk: re-encode changed the length (%d -> %d)", len(stream), len(out))
		}
		return out, nil
	}
}

// AccountDoc returns the index of the document that carries the account
// state, or -1.
//
// The flood is a sequence of documents: the static lobby config first,
// then the per-account one. The account document is the one holding a
// `stats` dict with a `credits` entry — the player's balance, as opposed
// to the price tables the config document is full of.
func (b *Bundle) AccountDoc() int {
	for i, d := range b.Docs {
		if stats := d.pair("stats"); stats != nil && stats.Kind == lobby.FDict {
			for _, k := range stats.Keys {
				if k.S == "credits" {
					return i
				}
			}
		}
	}
	return -1
}

// pair resolves a key inside one document, in either shape the flood
// uses.
//
// A captured account document is a stream of `key, value` pairs whose
// outer dict is never closed (the flood is cut short before its
// SETITEMS), so the pairs are siblings on the stack. A document built in
// code is a proper dict, so the key is an entry. Both are supported, so a
// generated bundle and a captured one are interchangeable.
func (d BundleDoc) pair(key string) *lobby.FNode {
	for i := 0; i+1 < len(d.Stack); i++ {
		n := d.Stack[i]
		if (n.Kind == lobby.FString || n.Kind == lobby.FUnicode) && n.S == key {
			return d.Stack[i+1]
		}
	}
	for _, n := range d.Stack {
		if n.Kind == lobby.FDict {
			if v := n.Get(key); v != nil {
				return v
			}
		}
	}
	return nil
}

// ApplyState writes the account's economy into the bundle's account
// document: `stats.credits` and `stats.freeXP`.
//
// Both are length-preserving only while the new value encodes to the same
// number of bytes as the captured one (BININT1 < 256, BININT2 < 65536,
// BININT otherwise). A value that would need a wider opcode is refused
// rather than silently resizing the bundle.
func ApplyState(b *Bundle, st *PlayerState) error {
	if st == nil {
		return nil
	}
	doc := b.AccountDoc()
	if doc < 0 {
		// A carrier without the account document (the config-only
		// captures) has nothing to patch: the client keeps whatever the
		// bundle already says.
		return nil
	}
	stats := b.Docs[doc].pair("stats")
	if stats == nil || stats.Kind != lobby.FDict {
		return fmt.Errorf("bulk: account document has no stats dict")
	}
	if err := setDictInt(stats, "credits", st.Credits); err != nil {
		return err
	}
	if err := setDictInt(stats, "freeXP", st.FreeXP); err != nil {
		return err
	}
	return nil
}

// setDictInt rewrites one integer entry of a dict, refusing a value that
// would change the encoded width.
func setDictInt(d *lobby.FNode, key string, v int64) error {
	for i, k := range d.Keys {
		if k.S != key {
			continue
		}
		n := d.Items[i]
		if n.Kind != lobby.FInt {
			return fmt.Errorf("bulk: %q is not an int", key)
		}
		want := encodedIntLen(v)
		if got := len(n.Raw); got != want {
			return fmt.Errorf("bulk: %q = %d encodes to %d bytes, the capture's slot is %d (value out of range for an in-place patch)",
				key, v, want, got)
		}
		n.SetInt(v)
		return nil
	}
	return fmt.Errorf("bulk: %q not in the account stats", key)
}

// encodedIntLen mirrors the encoder's integer width choice.
func encodedIntLen(v int64) int {
	switch {
	case v >= 0 && v < 256:
		return 2 // BININT1
	case v >= 0 && v < 65536:
		return 3 // BININT2
	case v >= -1<<31 && v < 1<<31:
		return 5 // BININT
	}
	return 1 + len(fmt.Sprintf("%d\n", v)) // INT
}
