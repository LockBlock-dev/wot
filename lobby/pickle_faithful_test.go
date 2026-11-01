package lobby

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// faithfulSample is a protocol-2 pickle produced by CPython covering the
// opcode set the lobby bundle uses: dict/list/tuple (all three tuple
// forms), BININT1/BININT2/BININT, BINFLOAT, SHORT_BINSTRING, BINUNICODE,
// NEWTRUE, NONE, memo put/get, and GLOBAL+REDUCE (OrderedDict).
const faithfulSample = "80027d710028635f636f646563730a656e636f64650a7101580400000073686f70710258060000006c6174696e3171038671045271057d71062868015804000000686f7374710768038671085271096801580100000078710a680386710b52710c680158050000006974656d73710d680386710e52710f5d7110284b014b024d2c014a701101004afbffffff65680158010000006671116803867112527113473ff800000000000068015801000000747114680386711552711688680158010000006e711768038671185271194e7568015803000000756e69711a680386711b52711c5805000000636166c3a9711d68015803000000747570711e680386711f5271204b014b024b038771216801580400000074757032712268038671235271244b014b028671256801580400000074757031712668038671275271284b0185712968015805000000656d707479712a680386712b52712c7d712d680158030000006c7374712e680386712f5271305d7131680158020000006f647132680386713352713463636f6c6c656374696f6e730a4f726465726564446963740a713529527136286801580100000061713768038671385271394b016801580100000062713a680386713b52713c4b0275752e"

func faithfulHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestFaithfulRoundTrip is the oracle: decode then encode must reproduce
// the original bytes exactly, including opcode choices and memo indices.
func TestFaithfulRoundTrip(t *testing.T) {
	want := faithfulHex(t, faithfulSample)

	stack, n, err := DecodeFaithful(want)
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}
	if n != len(want) {
		t.Fatalf("consumed %d of %d bytes", n, len(want))
	}

	got, err := EncodeFaithful(stack)
	if err != nil {
		t.Fatalf("EncodeFaithful: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip differs\n got %s\nwant %s", hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

// asStr unwraps the _codecs.encode(u'...', 'latin1') wrapper CPython 3
// uses to pickle a bytes object at protocol 2, and returns plain strs
// directly.
func asStr(n *FNode) (string, bool) {
	if n.Kind == FString {
		return n.S, true
	}
	if n.Kind == FReduce && n.Callable != nil && n.Callable.Kind == FGlobal &&
		n.Callable.Name == "encode" && n.Args != nil && len(n.Args.Items) == 2 &&
		n.Args.Items[0].Kind == FUnicode {
		return n.Args.Items[0].S, true
	}
	return "", false
}

// TestFaithfulPreservesStrVsUnicode proves the distinction pickle.go
// loses is kept: the sample has both a str and a unicode value.
func TestFaithfulPreservesStrVsUnicode(t *testing.T) {
	stack, _, err := DecodeFaithful(faithfulHex(t, faithfulSample))
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}
	root := stack[0]
	if root.Kind != FDict {
		t.Fatalf("root kind %d", root.Kind)
	}
	var sawStr, sawUni bool
	for i, k := range root.Keys {
		name, ok := asStr(k)
		if !ok {
			continue
		}
		switch name {
		case "shop":
			sawStr = true
		case "uni":
			sawUni = true
			if v := root.Items[i]; v.Kind != FUnicode {
				t.Fatalf("uni value kind %d, want FUnicode", v.Kind)
			}
		}
	}
	if !sawStr || !sawUni {
		t.Fatalf("missing keys: str=%v uni=%v", sawStr, sawUni)
	}
}

// TestFaithfulMutation proves a dirty scalar re-encodes and the result
// still decodes to the new value.
func TestFaithfulMutation(t *testing.T) {
	orig := faithfulHex(t, faithfulSample)
	stack, _, err := DecodeFaithful(orig)
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}

	// Find the 'items' list inside the 'shop' dict and bump its first item.
	root := stack[0]
	var target *FNode
	for i, k := range root.Keys {
		if name, ok := asStr(k); ok && name == "shop" {
			shop := root.Items[i]
			for j, sk := range shop.Keys {
				if name, ok := asStr(sk); ok && name == "items" {
					target = shop.Items[j]
				}
			}
		}
	}
	if target == nil || target.Kind != FList || len(target.Items) == 0 {
		t.Fatalf("did not find the items list")
	}
	target.Items[0].SetInt(42)

	out, err := EncodeFaithful(stack)
	if err != nil {
		t.Fatalf("EncodeFaithful: %v", err)
	}
	if bytes.Equal(out, orig) {
		t.Fatal("mutation produced identical bytes")
	}

	// Re-decode and confirm the new value landed.
	stack2, _, err := DecodeFaithful(out)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	root2 := stack2[0]
	for i, k := range root2.Keys {
		if name, ok := asStr(k); ok && name == "shop" {
			shop := root2.Items[i]
			for j, sk := range shop.Keys {
				if name, ok := asStr(sk); ok && name == "items" {
					lst := shop.Items[j]
					if len(lst.Items) == 0 || lst.Items[0].I != 42 {
						t.Fatalf("first item = %+v, want 42", lst.Items[0])
					}
					return
				}
			}
		}
	}
	t.Fatal("items list not found after re-decode")
}

// TestFaithfulRejectsGarbage keeps the decoder honest about bad input.
func TestFaithfulRejectsGarbage(t *testing.T) {
	if _, _, err := DecodeFaithful([]byte{0x80, 0x02, 0x00}); err == nil {
		t.Fatal("expected an error for an unknown opcode")
	}
	if _, _, err := DecodeFaithful([]byte{0x80, 0x02, 0x7d}); err == nil {
		t.Fatal("expected an error for a truncated pickle")
	}
}

// TestDecodeStreamStopsAtNonPickle pins the flood's real shape: the
// first chunk carries a document that never STOPs, and the next chunk
// starts with a channel-framed packet. The decoder must end the document
// at the first unreadable byte, report it, and the encoder must not add
// a STOP of its own — otherwise the round-trip grows by a byte.
func TestDecodeStreamStopsAtNonPickle(t *testing.T) {
	// A dict with one entry, no STOP, then a framed packet.
	doc := []byte{0x80, 0x02, '}', 'q', 0x00, 'U', 0x01, 'k', 'K', 0x07, 's'}
	framed := []byte{0x00, 0x1a, 0x5f, 0xff, 0x4f}
	raw := append(append([]byte(nil), doc...), framed...)

	stack, marks, ops, n, stopped, err := DecodeFaithfulStream(raw)
	if err != nil {
		t.Fatalf("DecodeFaithfulStream: %v", err)
	}
	if stopped {
		t.Error("stream reported a STOP it never saw")
	}
	if n != len(doc) {
		t.Fatalf("n = %d, want %d (the first framed byte)", n, len(doc))
	}
	if len(stack) != 1 || stack[0].Kind != FDict {
		t.Fatalf("stack = %d nodes, want one dict", len(stack))
	}

	out, err := EncodeFaithfulOpsStop(stack, marks, ops, stopped)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(out, doc) {
		t.Fatalf("document re-encode = %x, want %x", out, doc)
	}
	// With the tail appended the whole stream round-trips.
	if full := append(append([]byte(nil), out...), raw[n:]...); !bytes.Equal(full, raw) {
		t.Fatalf("stream round-trip = %x, want %x", full, raw)
	}

	// A stream that does STOP still reports it, and still emits one.
	withStop := append(append([]byte(nil), doc...), '.')
	stack, marks, ops, n, stopped, err = DecodeFaithfulStream(withStop)
	if err != nil {
		t.Fatalf("DecodeFaithfulStream: %v", err)
	}
	if !stopped || n != len(withStop) {
		t.Fatalf("stopped=%v n=%d, want true/%d", stopped, n, len(withStop))
	}
	out, err = EncodeFaithfulOpsStop(stack, marks, ops, stopped)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(out, withStop) {
		t.Fatalf("re-encode = %x, want %x", out, withStop)
	}
}

// TestDecodeStreamRejectsGarbageAtStart keeps the fallback from hiding a
// stream that is not pickle at all.
func TestDecodeStreamRejectsGarbageAtStart(t *testing.T) {
	if _, _, _, _, _, err := DecodeFaithfulStream([]byte{0x00, 0x1a, 0x5f}); err == nil {
		t.Fatal("garbage accepted as a document")
	}
}
