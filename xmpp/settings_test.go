package xmpp

import (
	"math/rand"
	"testing"
)

func TestIteratorOrder(t *testing.T) {
	s := ServerSettings{
		Connections: []Endpoint{{"tcp1", 5222}, {"tcp2", 5222}, {"tcp3", 5222}},
		Alt:         []Endpoint{{"alt1", 5222}},
		Bosh:        []Endpoint{{"bosh1", 5280}, {"bosh2", 5280}, {"bosh3", 5280}},
	}
	it := NewIterator(s, nil)
	// Caps: 2 per list (TCP base 3→2, BOSH 3→2, alt untouched).
	if it.Len() != 2+1+2 {
		t.Fatalf("len=%d, want 5", it.Len())
	}
	var order []string
	var boshFlags []bool
	for it.HasNext() {
		e, bosh, ok := it.Next()
		if !ok {
			t.Fatal("HasNext lied")
		}
		order = append(order, e.Host)
		boshFlags = append(boshFlags, bosh)
	}
	want := []string{"tcp1", "tcp2", "alt1", "bosh1", "bosh2"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order=%v", order)
		}
	}
	for i, b := range boshFlags {
		if b != (i >= 3) {
			t.Fatalf("bosh flags=%v", boshFlags)
		}
	}
	if _, _, ok := it.Next(); ok {
		t.Fatal("Next past end")
	}
	it.Clear()
	if it.HasNext() || it.Len() != 0 {
		t.Fatal("Clear failed")
	}
}

func TestIteratorValidation(t *testing.T) {
	s := ServerSettings{
		Connections: []Endpoint{{"", 5222}, {"ok", 0}, {"ok", 70000}, {"tcp", 5222}},
		Bosh:        []Endpoint{{"bosh", -1}},
	}
	it := NewIterator(s, nil)
	if it.Len() != 1 {
		t.Fatalf("len=%d, want 1 (only tcp:5222 validates)", it.Len())
	}
	e, bosh, ok := it.Next()
	if !ok || bosh || e.Host != "tcp" || e.Port != 5222 {
		t.Fatalf("got %+v %v %v", e, bosh, ok)
	}
}

func TestIteratorSampling(t *testing.T) {
	s := ServerSettings{Bosh: []Endpoint{{"a", 1}, {"b", 1}, {"c", 1}, {"d", 1}}}
	seen := map[string]bool{}
	for seed := int64(0); seed < 20; seed++ {
		it := NewIterator(s, rand.New(rand.NewSource(seed)))
		if it.Len() != 2 {
			t.Fatalf("len=%d, want cap 2", it.Len())
		}
		for it.HasNext() {
			e, _, _ := it.Next()
			seen[e.Host] = true
		}
	}
	if len(seen) < 3 {
		t.Fatalf("sampling never varied: %v", seen)
	}
}

func TestBoshURL(t *testing.T) {
	if u := BoshURL(Endpoint{"woteu34.xmpp.wargaming.net", 5280}); u != "https://woteu34.xmpp.wargaming.net:5280/bosh/" {
		t.Fatalf("got %q", u)
	}
	if u := BoshURL(Endpoint{"woteu34.xmpp.wargaming.net", 443}); u != "https://woteu34.xmpp.wargaming.net/bosh/" {
		t.Fatalf("got %q", u)
	}
}
