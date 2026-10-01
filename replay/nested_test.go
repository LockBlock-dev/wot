package replay

import (
	"encoding/binary"
	"testing"
)

// TestNested decodes every NestedProperty (0x24) envelope exactly on
// all fixtures, types the proven channels, and pins PlayerPosition
// (0x2b) as a 1 B boolean heartbeat. Offline.
func TestNested(t *testing.T) {
	for _, tc := range []string{
		"../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay",
		"../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay",
		"../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay",
	} {
		r, err := Open(tc)
		if err != nil {
			t.Skipf("no fixture: %v", err)
		}
		pkts, err := Packets(r.Stream)
		if err != nil {
			t.Fatal(err)
		}
		tab := buildEntityTable(pkts)
		var n24, n2b int
		for _, p := range pkts {
			switch p.Type {
			case 0x2b:
				n2b++
				// 1 B boolean flag (pairs at t=0/t=30, sparse
				// toggles later — alive/spectate candidate, open).
				if len(p.Data) != 1 || (p.Data[0] != 0 && p.Data[0] != 1) {
					t.Fatalf("%s: playerpos=%x", tc, p.Data)
				}
			case 0x24:
				n24++
				n, err := ParseNested(p.Data)
				if err != nil {
					t.Fatalf("%s: %v", tc, err)
				}
				eid := binary.LittleEndian.Uint32(p.Data[0:4])
				ty, ok := tab.Resolve(eid)
				if !ok {
					t.Fatalf("%s: nested target %d unknown", tc, eid)
				}
				switch {
				case ty == 6 && n.Op == 0xc2:
					if _, err := ParseSticker(n.Payload); err != nil {
						t.Fatalf("%s: %v", tc, err)
					}
				case ty == 6 && n.Op == 0xc4:
					if len(n.Payload) < 1 || len(n.Payload) > 2 {
						t.Fatalf("%s: engine payload=%x", tc, n.Payload)
					}
				case ty == 7 && (n.Op == 0xa0 || n.Op == 0xa9):
					if _, _, err := ParseTuple3(n.Payload); err != nil {
						t.Fatalf("%s: %v", tc, err)
					}
				case ty == 7 && (n.Op == 0xe0 || n.Op == 0xe9):
					if _, _, err := ParseTuple5(n.Payload); err != nil {
						t.Fatalf("%s: %v", tc, err)
					}
				}
			}
		}
		t.Logf("%s: nested=%d playerpos=%d", r.ClientVersion(), n24, n2b)
		if n24 == 0 || n2b == 0 {
			t.Fatalf("%s: missing families", tc)
		}
	}
}
