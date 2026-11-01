package main

import (
	"encoding/json"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/server"
)

// TestJSONRoundTrip is the CLI's contract: a spec builds a bundle that
// decodes back to the same JSON.
func TestJSONRoundTrip(t *testing.T) {
	spec := `{"documents": [
	  [{"shop": {"isEnabled": true, "version": 42, "ratio": 1.5, "name": "shop"},
	    "tiers": [1, 2, 3], "nothing": null}],
	  [{"stats": {"credits": 500000, "freeXP": 12345}}]
	]}`
	var doc struct {
		Documents [][]any `json:"documents"`
	}
	if err := json.Unmarshal([]byte(spec), &doc); err != nil {
		t.Fatal(err)
	}
	b := server.NewBundle()
	for i, nodes := range doc.Documents {
		built := make([]*lobby.FNode, 0, len(nodes))
		for _, v := range nodes {
			n, err := jsonToNode(v)
			if err != nil {
				t.Fatalf("document %d: %v", i, err)
			}
			built = append(built, n)
		}
		b.Document(built...)
	}
	stream, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := server.DecodeBundle(stream)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	if len(dec.Docs) != 2 {
		t.Fatalf("%d documents, want 2", len(dec.Docs))
	}

	// The config document survives the trip.
	shop := dec.Docs[0].Stack[0].Get("shop")
	if shop == nil {
		t.Fatal("no shop dict")
	}
	if v := shop.Get("isEnabled"); v == nil || !v.B {
		t.Errorf("isEnabled = %+v", v)
	}
	if v := shop.Get("version"); v == nil || v.I != 42 {
		t.Errorf("version = %+v", v)
	}
	if v := shop.Get("ratio"); v == nil || v.F != 1.5 {
		t.Errorf("ratio = %+v", v)
	}
	if v := shop.Get("name"); v == nil || v.S != "shop" {
		t.Errorf("name = %+v", v)
	}
	if v := dec.Docs[0].Stack[0].Get("tiers"); v == nil || len(v.Items) != 3 {
		t.Errorf("tiers = %+v", v)
	}
	if v := dec.Docs[0].Stack[0].Get("nothing"); v == nil || v.Kind != lobby.FNone {
		t.Errorf("nothing = %+v", v)
	}

	// And the account document is recognised as such.
	if got := dec.AccountDoc(); got != 1 {
		t.Fatalf("AccountDoc = %d, want 1", got)
	}
	stats := dec.Docs[1].Stack[0].Get("stats")
	if v := stats.Get("credits"); v == nil || v.I != 500000 {
		t.Errorf("credits = %+v", v)
	}
}

// TestNodeToJSONIsInverse keeps the dump direction honest.
func TestNodeToJSONIsInverse(t *testing.T) {
	orig := lobby.NewDict().
		Set("i", lobby.NewInt(7)).
		Set("f", lobby.NewFloat(0.25)).
		Set("s", lobby.NewString("x")).
		Set("b", lobby.NewBool(false)).
		Set("n", lobby.NewNone()).
		Set("l", lobby.NewList(lobby.NewInt(1), lobby.NewInt(2)))

	asJSON := nodeToJSON(orig)
	back, err := jsonToNode(asJSON)
	if err != nil {
		t.Fatalf("jsonToNode: %v", err)
	}
	if v := back.Get("i"); v == nil || v.I != 7 {
		t.Errorf("i = %+v", v)
	}
	if v := back.Get("f"); v == nil || v.F != 0.25 {
		t.Errorf("f = %+v", v)
	}
	if v := back.Get("s"); v == nil || v.S != "x" {
		t.Errorf("s = %+v", v)
	}
	if v := back.Get("b"); v == nil || v.B {
		t.Errorf("b = %+v", v)
	}
	if v := back.Get("n"); v == nil || v.Kind != lobby.FNone {
		t.Errorf("n = %+v", v)
	}
	if v := back.Get("l"); v == nil || len(v.Items) != 2 {
		t.Errorf("l = %+v", v)
	}
}

// TestJSONToNodeRejectsUnknown keeps a bad spec from building silently.
func TestJSONToNodeRejectsUnknown(t *testing.T) {
	if _, err := jsonToNode(struct{}{}); err == nil {
		t.Fatal("unknown JSON value accepted")
	}
}
