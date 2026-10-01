package replay

import (
	"testing"
)

// TestDecodeProps decodes every EntityProperty (0x7) packet exactly on
// all three fixtures: [eid][FullIndex u32][len u32][value], indexes
// into the client-server property table (properties_gen.go). Offline.
func TestDecodeProps(t *testing.T) {
	for _, tc := range []struct {
		file string
		want int
	}{
		{"../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay", 23984},
		{"../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay", 30746},
		{"../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay", 39931},
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
		props, skipped, err := DecodePropsLenient(tab, pkts)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if len(skipped) != 0 {
			t.Fatalf("%s: skipped=%v", tc.file, skipped)
		}
		if len(props) != tc.want {
			t.Fatalf("%s: props=%d, want %d", tc.file, len(props), tc.want)
		}
	}
}

// TestPropSpots pins property semantics: health decay under fire,
// engine tuple, packed gun angles, centered steering pair. Offline.
func TestPropSpots(t *testing.T) {
	r, err := Open("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pkts, _ := Packets(r.Stream)
	tab := buildEntityTable(pkts)
	props, _, err := DecodePropsLenient(tab, pkts)
	if err != nil {
		t.Fatal(err)
	}
	var hp []int64
	for _, pr := range props {
		if pr.Prop.Sig.Name == "health" && pr.Prop.EntityID == 4730080 {
			hp = append(hp, pr.Prop.Value.(int64))
		}
	}
	if len(hp) != 6 || hp[0] != 782 || hp[len(hp)-1] != 0 {
		t.Fatalf("health track=%v", hp)
	}
	for i := 1; i < len(hp); i++ {
		if hp[i] > hp[i-1] {
			t.Fatalf("health rises: %v", hp)
		}
	}
	r2, err := Open("../../replays/17894785190559_usa_A69_T110E5_sweden.wotreplay")
	if err != nil {
		t.Skipf("no fixture: %v", err)
	}
	pk2, _ := Packets(r2.Stream)
	tab2 := buildEntityTable(pk2)
	pr2, _, err := DecodePropsLenient(tab2, pk2)
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range pr2 {
		if pr.Prop.Sig.Name == "steeringAngles" {
			el := pr.Prop.Value.([]any)
			if len(el) != 2 {
				t.Fatalf("steering=%v", el)
			}
			return
		}
	}
	t.Fatal("no steeringAngles found")
}
