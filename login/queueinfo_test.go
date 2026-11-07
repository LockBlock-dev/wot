package login

import (
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestQueueCensusAnswer pins the 502 answer: CMD_REQ_QUEUE_INFO is
// answered with the 1a/67 small {players, classes}, authored from the
// live queue rather than replayed from a capture.
func TestQueueCensusAnswer(t *testing.T) {
	small, err := BuildQueueCensus(924, []int64{186, 226, 209, 98, 205})
	if err != nil {
		t.Fatalf("BuildQueueCensus: %v", err)
	}
	s, n, err := lobby.ParseSmall(small)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n != len(small) {
		t.Fatalf("%d trailing bytes", len(small)-n)
	}
	if s.Family != 0x1a || s.Type != 0x67 {
		t.Fatalf("small is %#02x/%#02x, want 1a/67", s.Family, s.Type)
	}
	// The body is [len][pickle]; the pickle must decode to the census.
	if int(s.Body[0]) != len(s.Body)-1 {
		t.Fatalf("body length byte %d, want %d", s.Body[0], len(s.Body)-1)
	}
	stk, _, err := lobby.DecodePrefix(s.Body[1:])
	if err != nil {
		t.Fatalf("pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("stack top %T, want *PDict", stk[len(stk)-1])
	}
	var players int64 = -1
	var classes []int64
	for _, e := range d.Entries {
		switch e.Key {
		case "players":
			players, _ = e.Value.(int64)
		case "classes":
			if tup, ok := e.Value.(*lobby.PTuple); ok {
				for _, v := range tup.Items {
					if i, ok := v.(int64); ok {
						classes = append(classes, i)
					}
				}
			}
		}
	}
	if players != 924 || len(classes) != 5 || classes[0] != 186 {
		t.Fatalf("census decoded as players=%d classes=%v", players, classes)
	}
}
