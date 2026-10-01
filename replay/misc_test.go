package replay

import (
	"strings"
	"testing"
)

// TestMisc pins every rarer packet family on all fixtures: exact
// framing for the decodable ones, counts + lens + pairing for the
// opaque per-tick families. Offline.
func TestMisc(t *testing.T) {
	for _, tc := range []struct {
		file     string
		n1a, n36 int
		n39      int
		namedMin int
		n37      int
		n37short int
		tagX     [2]byte
	}{
		{"../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay", 6329, 4622, 6169, 200, 1017, 117, [2]byte{0x0a, 0x21}},
		{"../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay", 2770, 2962, 2522, 200, 397, 200, [2]byte{0x06, 0x66}},
		{"../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay", 7595, 1006, 7634, 900, 552, 18, [2]byte{0x0c, 0x3d}},
	} {
		r, err := Open(tc.file)
		if err != nil {
			t.Skipf("no fixture: %v", err)
		}
		pkts, err := Packets(r.Stream)
		if err != nil {
			t.Fatal(err)
		}
		tab := buildEntityTable(pkts)
		var n1a, n1f, n36, n39, named, n37, n37short int
		for _, p := range pkts {
			var err error
			switch p.Type {
			case 0x4, 0x22:
				var e EidRecord
				if e, err = ParseEid(p.Data); err == nil {
					if _, ok := tab.Resolve(e.EntityID); !ok {
						t.Fatalf("%s: eid %d unknown", tc.file, e.EntityID)
					}
				}
			case 0x16, 0x28:
				var c CounterRecord
				_, err = ParseCounter(p.Data)
				_ = c
			case 0x12, 0x2e:
				_, err = ParseFlag(p.Data)
			case 0x35, 0x36:
				if len(p.Data) != 0 {
					t.Fatalf("%s: empty type=%#x len=%d", tc.file, p.Type, len(p.Data))
				}
				if p.Type == 0x36 {
					n36++
				}
			case 0x1b:
				var s StringRecord
				if s, err = ParseStringRecord(p.Data); err == nil && len(s.Text) == 0 {
					t.Fatalf("%s: empty string record", tc.file)
				}
			case 0x23:
				var c ChatRecord
				if c, err = ParseChat(p.Data); err == nil && !strings.Contains(c.Text, "<font") {
					t.Fatalf("%s: chat=%q", tc.file, c.Text[:min(40, len(c.Text))])
				}
			case 0x31:
				var nr NamedRecord
				if nr, err = ParseNamed(p.Data); err == nil {
					named++
					_ = nr
				}
			case 0xd:
				var s SpaceRecord
				if s, err = ParseSpace(p.Data); err == nil && s.SpaceID == 0 {
					t.Fatalf("%s: space id 0", tc.file)
				}
			case 0x6:
				var s SnapRecord
				if s, err = ParseSnap(p.Data); err == nil {
					if _, ok := tab.Resolve(s.EntityID); !ok {
						t.Fatalf("%s: snap eid %d unknown", tc.file, s.EntityID)
					}
				}
			case 0x32, 0x37, 0x39:
				c, err := ParseCompound(p.Data)
				if err != nil {
					t.Fatalf("%s type=%#x: %v", tc.file, p.Type, err)
				}
				_ = c
				if p.Type == 0x39 {
					n39++
					if l := len(p.Data); l != 41 && l != 72 {
						t.Fatalf("%s: 0x39 len=%d", tc.file, l)
					}
				}
				if p.Type == 0x37 {
					n37++
					if subs, ok := WalkShortSubs(c.Body); ok {
						n37short++
						for _, s := range subs {
							if s.ID%2 != 0 {
								t.Fatalf("%s: odd sub id %02x", tc.file, s.ID)
							}
							if s.Kind == 3 && s.F != 1 {
								t.Fatalf("%s: init f=%02x", tc.file, s.F)
							}
						}
						if len(subs) > 0 && (subs[0].Tag != tc.tagX[0] || subs[0].X != tc.tagX[1]) {
							t.Fatalf("%s: tagx=%02x%02x", tc.file, subs[0].Tag, subs[0].X)
						}
					}
				}
			case 0x1a:
				n1a++
				if len(p.Data) != 60 {
					t.Fatalf("%s: 0x1a len=%d", tc.file, len(p.Data))
				}
			case 0x1f:
				n1f++
				if len(p.Data) != 4 {
					t.Fatalf("%s: 0x1f len=%d", tc.file, len(p.Data))
				}
			case 0x1c, 0x1d:
				if len(p.Data) != 4 {
					t.Fatalf("%s: tick counter len=%d", tc.file, len(p.Data))
				}
			case 0x26:
				if len(p.Data) != 40 {
					t.Fatalf("%s: 0x26 len=%d", tc.file, len(p.Data))
				}
			}
			if err != nil {
				t.Fatalf("%s type=%#x: %v", tc.file, p.Type, err)
			}
		}
		if n1a != tc.n1a {
			t.Fatalf("%s: 0x1a=%d want %d", tc.file, n1a, tc.n1a)
		}
		if n1f != tc.n1a {
			t.Fatalf("%s: 0x1f=%d != 0x1a=%d (pairing)", tc.file, n1f, tc.n1a)
		}
		if n36 != tc.n36 {
			t.Fatalf("%s: 0x36=%d want %d", tc.file, n36, tc.n36)
		}
		if n39 != tc.n39 {
			t.Fatalf("%s: 0x39=%d want %d", tc.file, n39, tc.n39)
		}
		if named < tc.namedMin {
			t.Fatalf("%s: named=%d", tc.file, named)
		}
		if n37 != tc.n37 {
			t.Fatalf("%s: 0x37=%d want %d", tc.file, n37, tc.n37)
		}
		if n37short != tc.n37short {
			t.Fatalf("%s: 0x37short=%d want %d", tc.file, n37short, tc.n37short)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
