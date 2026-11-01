package lobby

import (
	"bytes"
	"testing"
)

// TestBuildDocumentRoundTrip is the builder's contract: a document made
// from scratch decodes back to the same values.
func TestBuildDocumentRoundTrip(t *testing.T) {
	shop := NewDict().
		Set("isEnabled", NewBool(true)).
		Set("version", NewInt(42)).
		Set("name", NewString("shop")).
		Set("ratio", NewFloat(1.5)).
		Set("nothing", NewNone()).
		Set("tiers", NewList(NewInt(1), NewInt(2), NewInt(3))).
		Set("pair", NewTuple(NewString("a"), NewInt(7)))

	raw, err := EncodeDocument(shop)
	if err != nil {
		t.Fatalf("EncodeDocument: %v", err)
	}
	if raw[0] != 0x80 || raw[1] != 0x02 {
		t.Fatalf("document does not start with PROTO 2: % x", raw[:2])
	}
	if raw[len(raw)-1] != '.' {
		t.Fatalf("document does not end with STOP: % x", raw[len(raw)-1:])
	}

	stack, n, err := DecodeFaithful(raw)
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}
	if n != len(raw) {
		t.Errorf("decoded %d of %d bytes", n, len(raw))
	}
	if len(stack) != 1 || stack[0].Kind != FDict {
		t.Fatalf("stack = %d nodes, want one dict", len(stack))
	}
	got := stack[0]
	if v := got.Get("isEnabled"); v == nil || v.Kind != FBool || !v.B {
		t.Errorf("isEnabled = %+v", v)
	}
	if v := got.Get("version"); v == nil || v.I != 42 {
		t.Errorf("version = %+v", v)
	}
	if v := got.Get("name"); v == nil || v.S != "shop" || v.Kind != FString {
		t.Errorf("name = %+v", v)
	}
	if v := got.Get("ratio"); v == nil || v.F != 1.5 {
		t.Errorf("ratio = %+v", v)
	}
	if v := got.Get("nothing"); v == nil || v.Kind != FNone {
		t.Errorf("nothing = %+v", v)
	}
	if v := got.Get("tiers"); v == nil || len(v.Items) != 3 || v.Items[2].I != 3 {
		t.Errorf("tiers = %+v", v)
	}
	if v := got.Get("pair"); v == nil || v.Kind != FTuple || len(v.Items) != 2 {
		t.Errorf("pair = %+v", v)
	}
}

// TestBuildDocumentIsStable pins that the same tree always encodes to the
// same bytes — a builder that reorders would make bundles unreproducible.
func TestBuildDocumentIsStable(t *testing.T) {
	build := func() []byte {
		d := NewDict().Set("a", NewInt(1)).Set("b", NewInt(2)).Set("c", NewInt(3))
		raw, err := EncodeDocument(d)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	first := build()
	for i := 0; i < 5; i++ {
		if !bytes.Equal(build(), first) {
			t.Fatal("encoding is not deterministic")
		}
	}
}

// TestBuildDocumentMultipleNodes covers the lobby's shape: a document is
// a stack of nodes, not one root.
func TestBuildDocumentMultipleNodes(t *testing.T) {
	raw, err := EncodeDocument(
		NewDict().Set("config", NewInt(1)),
		NewDict().Set("account", NewInt(2)),
	)
	if err != nil {
		t.Fatal(err)
	}
	stack, _, err := DecodeFaithful(raw)
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}
	if len(stack) != 2 {
		t.Fatalf("stack = %d nodes, want 2", len(stack))
	}
	if stack[0].Get("config") == nil || stack[1].Get("account") == nil {
		t.Errorf("nodes out of order: %+v %+v", stack[0], stack[1])
	}
}

// TestBuildNestedAndEmpty covers the shapes a hand-built tree gets wrong:
// empty containers and deep nesting.
func TestBuildNestedAndEmpty(t *testing.T) {
	root := NewDict().
		Set("emptyDict", NewDict()).
		Set("emptyList", NewList()).
		Set("deep", NewDict().Set("inner", NewDict().Set("leaf", NewInt(9))))
	raw, err := EncodeDocument(root)
	if err != nil {
		t.Fatal(err)
	}
	stack, _, err := DecodeFaithful(raw)
	if err != nil {
		t.Fatalf("DecodeFaithful: %v", err)
	}
	got := stack[0]
	if v := got.Get("emptyDict"); v == nil || v.Kind != FDict || len(v.Items) != 0 {
		t.Errorf("emptyDict = %+v", v)
	}
	if v := got.Get("emptyList"); v == nil || v.Kind != FList || len(v.Items) != 0 {
		t.Errorf("emptyList = %+v", v)
	}
	deep := got.Get("deep")
	if deep == nil || deep.Get("inner") == nil || deep.Get("inner").Get("leaf").I != 9 {
		t.Errorf("deep = %+v", deep)
	}
}

// TestBuildSetReplaces keeps Set from appending a duplicate key.
func TestBuildSetReplaces(t *testing.T) {
	d := NewDict().Set("k", NewInt(1)).Set("k", NewInt(2))
	if len(d.Keys) != 1 || len(d.Items) != 1 {
		t.Fatalf("Set appended a duplicate: %d keys", len(d.Keys))
	}
	if d.Get("k").I != 2 {
		t.Errorf("k = %d, want 2", d.Get("k").I)
	}
}
