package replay

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

// TestOpenRecords pins the once-per-battle open records on all
// fixtures: version/arena-config/sub-version/digest exact bytes,
// spawn fields, control flag, map identity matrix, base strings +
// region framing, every create ≥42 B with sane spawn. Offline.
func TestOpenRecords(t *testing.T) {
	for _, tc := range []struct {
		file    string
		version string
		digest  string
		subtag  uint16
		mapName string
		avatar  uint32
		space   uint32
		vehicle uint32
		spawn   [3]float64
	}{
		{"../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay",
			"2.4.0.0", "5DF886F75E73B33CFF9D87FB9C69389C", 0x6468,
			"spaces/05_prohorovka", 4730140, 2122, 4730080,
			[3]float64{15.45, 5.62, -453.48}},
		{"../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay",
			"2.3.1.0", "743085C39B53EE1233F9EC64A144E885", 0x6468,
			"spaces/10_hills", 13788249, 9752, 13788239,
			[3]float64{-165.49, 10.11, 282.03}},
		{"../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay",
			"2.1.1.0", "984901D3872E361B236D5807A88760A8", 0x6473,
			"spaces/115_sweden", 7855137, 1168, 7688450,
			[3]float64{351.56, 23.67, 279.30}},
	} {
		r, err := Open(tc.file)
		if err != nil {
			t.Skipf("no fixture: %v", err)
		}
		pkts, err := Packets(r.Stream)
		if err != nil {
			t.Fatal(err)
		}
		if ver := r.ClientVersion(); ver != tc.version {
			t.Fatalf("%s: version=%q", tc.file, ver)
		}
		tab := buildEntityTable(pkts)
		var nCreate int
		for _, p := range pkts {
			var err error
			switch p.Type {
			case 0x18:
			case 0x2d:
				var a ArenaConfig
				if a, err = ParseArenaConfig(p.Data); err == nil && a.Text != "17, 1, 0, 5" {
					t.Fatalf("%s: arena=%q", tc.file, a.Text)
				}
			case 0x30:
				var s SubVersion
				if s, err = ParseSubVersion(p.Data); err == nil && s.Tag != tc.subtag {
					t.Fatalf("%s: subtag=%#x", tc.file, s.Tag)
				}
			case 0x3d:
				var d DigestRecord
				if d, err = ParseDigestRecord(p.Data); err == nil && d.Digest != tc.digest {
					t.Fatalf("%s: digest=%s", tc.file, d.Digest)
				}
			case 0x0:
				var b BaseRecord
				if b, err = ParseBase(p.Data); err == nil {
					if b.EntityID != tc.avatar || b.TypeID != 2 || b.Name != r.MetaField("playerName") {
						t.Fatalf("%s: base=%+v", tc.file, b)
					}
					// Roster pickle follows an 18 B header; account is
					// the player vehicle entity ID as a string.
					if len(b.Rest) < 100 || b.Account == "" {
						t.Fatalf("%s: base rest=%d account=%q", tc.file, len(b.Rest), b.Account)
					}
				}
			case 0x1:
				var s SpawnRecord
				if s, err = ParseSpawn(p.Data); err == nil {
					if s.EntityID != tc.avatar || s.SpaceID != tc.space || s.VehicleID != tc.vehicle {
						t.Fatalf("%s: spawn=%+v", tc.file, s)
					}
					if math.Abs(float64(s.X)-tc.spawn[0]) > 0.01 || math.Abs(float64(s.Z)-tc.spawn[2]) > 0.01 {
						t.Fatalf("%s: spawn pos=%g,%g,%g", tc.file, s.X, s.Y, s.Z)
					}
					if _, ok := tab.Resolve(s.VehicleID); !ok {
						t.Fatalf("%s: spawn vehicle %d unknown", tc.file, s.VehicleID)
					}
					// Tail: vehicle eid repeated at [67:71], (2,2) at
					// [86:90], zeros at end; A/CONST vary (open).
					if binary.LittleEndian.Uint32(p.Data[67:71]) != tc.vehicle {
						t.Fatalf("%s: spawn tail eid=%d", tc.file, binary.LittleEndian.Uint32(p.Data[67:71]))
					}
					if binary.LittleEndian.Uint16(p.Data[87:89]) != 2 || binary.LittleEndian.Uint16(p.Data[89:91]) != 2 {
						t.Fatalf("%s: spawn tail flags=%x", tc.file, p.Data[86:92])
					}
				}
			case 0x2:
				var c ControlRecord
				if c, err = ParseControl(p.Data); err == nil && (c.EntityID != tc.avatar || c.Flag != 0) {
					t.Fatalf("%s: control=%+v", tc.file, c)
				}
			case 0xf:
				var m MapRecord
				if m, err = ParseMap(p.Data); err == nil && (m.Name != tc.mapName || m.SpaceID != tc.space) {
					t.Fatalf("%s: map=%+v", tc.file, m)
				}
			case 0x5:
				var c CreateRecord
				if c, err = ParseCreate(p.Data); err == nil {
					if ty, ok := tab.Resolve(c.EntityID); !ok || ty != c.TypeID {
						t.Fatalf("%s: create eid=%d type=%d", tc.file, c.EntityID, c.TypeID)
					}
				}
				nCreate++
			}
			if err != nil {
				t.Fatalf("%s type=%#x: %v", tc.file, p.Type, err)
			}
		}
		if nCreate == 0 {
			t.Fatalf("%s: no creates", tc.file)
		}
		// Base pickle must name arena keys.
		for _, p := range pkts {
			if p.Type != 0x0 {
				continue
			}
			b, _ := ParseBase(p.Data)
			// Arena-dict pickle keys vary by version; battleLevel is
			// everywhere.
			if !strings.Contains(string(b.Rest), "battleLevel") {
				t.Fatalf("%s: base pickle lacks battleLevel", tc.file)
			}
			ro, err := SplitRoster(b.Rest)
			if err != nil {
				t.Fatalf("%s: roster: %v", tc.file, err)
			}
			if len(ro.Quests) == 0 || !ro.HasTail {
				t.Fatalf("%s: roster quests=%d tail=%v", tc.file, len(ro.Quests), ro.HasTail)
			}
			for _, q := range ro.Quests {
				if len(q) != 33 || q[0] != 0x01 {
					t.Fatalf("%s: quest entry %x", tc.file, q)
				}
			}
			t.Logf("%s: quests=%d special=%dB tail=%02x", tc.file, len(ro.Quests), len(ro.Special), ro.Trailer)
		}
	}
}
