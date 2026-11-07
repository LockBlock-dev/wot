package login

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// censusBody is the real 1a/67 body from proxy-20261014-1752:
// [status][pickle] where the pickle is
// {players: 924, classes: [186, 226, 209, 98, 205]}.
const censusBody = "2c80027d7101285507706c61796572734d9c035507636c61737365735d7102284bba4be24bd1" +
	"4b624bcd65752e"

// TestParseCensusReadsTheCapture pins the reader against the real census.
func TestParseCensusReadsTheCapture(t *testing.T) {
	body, err := hex.DecodeString(censusBody)
	if err != nil {
		t.Fatal(err)
	}
	small, err := lobby.Small{Family: 0x1a, Type: censusSmallType, Body: body}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	players, classes, err := ParseCensusSmall(small)
	if err != nil {
		t.Fatalf("ParseCensusSmall: %v", err)
	}
	if players != 924 {
		t.Errorf("players = %d, want 924", players)
	}
	want := []int{186, 226, 209, 98, 205}
	if len(classes) != len(want) {
		t.Fatalf("classes = %v, want %v", classes, want)
	}
	sum := 0
	for i := range want {
		if classes[i] != want[i] {
			t.Errorf("class %d = %d, want %d", i, classes[i], want[i])
		}
		sum += classes[i]
	}
	// The captured breakdown sums to the total, which is what makes it a
	// per-class count rather than something else.
	if sum != players {
		t.Errorf("classes sum to %d, players %d", sum, players)
	}
}

// TestBuildCensusSmallRoundTrip is the point: the census is built from a
// live queue.
func TestBuildCensusSmallRoundTrip(t *testing.T) {
	cases := []struct {
		players int
		classes []int
	}{
		{0, []int{0, 0, 0, 0, 0}},
		{1, []int{1, 0, 0, 0, 0}},
		{924, []int{186, 226, 209, 98, 205}},
		{5, []int{1, 1, 1, 1, 1}},
	}
	for _, c := range cases {
		small, err := BuildCensusSmall(c.players, c.classes)
		if err != nil {
			t.Fatalf("%d: %v", c.players, err)
		}
		players, classes, err := ParseCensusSmall(small)
		if err != nil {
			t.Fatalf("%d: parse back: %v", c.players, err)
		}
		if players != c.players {
			t.Errorf("players = %d, want %d", players, c.players)
		}
		for i := range c.classes {
			if classes[i] != c.classes[i] {
				t.Errorf("class %d = %d, want %d", i, classes[i], c.classes[i])
			}
		}
	}
}

// TestBuildCensusRejectsWrongClassCount keeps a malformed census off the
// wire.
func TestBuildCensusRejectsWrongClassCount(t *testing.T) {
	if _, err := BuildCensusSmall(1, []int{1, 0}); err == nil {
		t.Fatal("a 2-class census was accepted")
	}
}

// TestAccountQueueCallsAreValidElements pins the answers the queue sends:
// onEnqueued and onDequeued are Account client methods, so their element
// ids are ENTITY_METHOD_BASE + the exposed id.
func TestAccountQueueCallsAreValidElements(t *testing.T) {
	const defs = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	acct := d.Entity("Account")
	e := NewEntity(0, acct)

	for _, c := range []struct {
		method string
		slot   int
	}{
		{"onEnqueued", 3},
		{"onDequeued", 4},
		{"onKickedFromQueue", 5},
	} {
		m := acct.MethodByID(entdef.CompClient, c.slot)
		if m == nil || m.Name != c.method {
			t.Fatalf("client[%d] = %v, want %s", c.slot, m, c.method)
		}
		elem, err := EncodeClientMethodCall(e, c.method, []entdef.Value{
			{Kind: entdef.VUint, Uint: 0},
		})
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		if want := byte(entityMethodBase + c.slot); elem[0] != want {
			t.Errorf("%s element id = %#02x, want %#02x", c.method, elem[0], want)
		}
		// Fixed-size method: no length field, the payload follows the id.
		if len(elem) != 2 {
			t.Errorf("%s element = %d B, want 2 (id + 1-byte payload)", c.method, len(elem))
		}
	}
}

// TestCensusSmallIsStable keeps the answer reproducible.
func TestCensusSmallIsStable(t *testing.T) {
	first, err := BuildCensusSmall(3, []int{1, 1, 1, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := BuildCensusSmall(3, []int{1, 1, 1, 0, 0})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, first) {
			t.Fatal("the census builder is not deterministic")
		}
	}
}
