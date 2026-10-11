package replay

import (
	"bytes"
	"slices"
	"testing"
)

// TestPacketCensus walks the full Prohorovka battle stream: every
// packet must frame cleanly ([size][type][time]), the type census must
// match the BigWorld family (Monstrofil mapping), and the entity-defs
// digest recorded in-stream must equal the login ground truth.
func TestPacketCensus(t *testing.T) {
	r, err := Open("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatalf("walk stopped: %v", err)
	}
	if len(pkts) != 115464 {
		t.Fatalf("packets=%d, want 115464", len(pkts))
	}
	counts := map[uint32]int{}
	var tmin, tmax float32 = 1e9, -1e9
	var digestPkts int
	for _, p := range pkts {
		counts[p.Type]++
		if p.Time < tmin {
			tmin = p.Time
		}
		if p.Time > tmax {
			tmax = p.Time
		}
		// The entity-defs digest recorded in-stream must equal the
		// login ground truth (mod-read BigWorld.digest).
		if bytes.Contains(p.Data, []byte("5DF886F75E73B33CFF9D87FB9C69389C")) {
			digestPkts++
		}
	}
	for _, ty := range []uint32{0x0, 0x1, 0x5, 0x7, 0x8, 0xa, 0xf} {
		if counts[ty] == 0 {
			t.Fatalf("packet type %#x absent", ty)
		}
	}
	if digestPkts != 1 {
		t.Fatalf("digest recorded in %d packets, want 1", digestPkts)
	}
	if tmin != 0 || tmax < 600 || tmax > 3600 {
		t.Fatalf("time range %.1f..%.1f", tmin, tmax)
	}
	var types []uint32
	for ty := range counts {
		types = append(types, ty)
	}
	slices.Sort(types)
	for _, ty := range types {
		t.Logf("type=%#x n=%d", ty, counts[ty])
	}
	t.Logf("time range %.1f..%.1f", tmin, tmax)
}
