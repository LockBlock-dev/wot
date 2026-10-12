package replay

// Offline shot-feed test (synthetic roster + synthetic tracers only).
import (
	"os"
	"testing"
)

func TestDisplayTank(t *testing.T) {
	for in, want := range map[string]string{
		"uk:GB41_Challenger": "Challenger",
		"usa:A69_T110E5":     "T110E5",
		"ussr:R159_SU_130PM": "SU_130PM",
		"plain":              "plain",
		"":                   "?",
	} {
		if got := DisplayTank(in); got != want {
			t.Fatalf("DisplayTank(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestShotFeedSynthetic(t *testing.T) {
	tl := &BattleTimeline{
		Setup: map[string]any{
			"vehicles": map[string]any{
				"4730080": map[string]any{"name": "ExampleUser", "vehicleType": "uk:GB41_Challenger"},
			},
		},
		Tracers: []TracerEvent{
			{Time: 69.3, A0: 4730080, ShotID: 1, Range: 76.2},
			{Time: 83.9, A0: 0, ShotID: 2, Range: 150},
		},
	}
	feed := ShotFeed(tl)
	if len(feed) != 2 {
		t.Fatalf("len=%d, want 2", len(feed))
	}
	if feed[0].Name != "ExampleUser" || feed[0].Tank != "Challenger" {
		t.Fatalf("row0=%+v", feed[0])
	}
	if feed[1].Name != "?" || feed[1].Tank != "?" {
		t.Fatalf("unrostered row should keep ?: %+v", feed[1])
	}
	if s := feed[0].String(); s != "[01:09] ExampleUser [Challenger] SHOT" {
		t.Fatalf("row=%q", s)
	}
}

func TestShotFeedProhorovka(t *testing.T) {
	raw, err := os.ReadFile("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay")
	if err != nil {
		t.Skip("no fixture")
	}
	r, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	tl, err := Extract("../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay", r, pkts)
	if err != nil {
		t.Fatal(err)
	}
	feed := ShotFeed(tl)
	if len(feed) != len(tl.Tracers) {
		t.Fatalf("feed=%d tracers=%d", len(feed), len(tl.Tracers))
	}
	own := 0
	for _, s := range feed {
		if s.Entity == 4730080 {
			own++
			if s.Name != "ExampleUser" || s.Tank != "Challenger" {
				t.Fatalf("own row=%+v", s)
			}
		}
	}
	if own != 11 {
		t.Fatalf("own=%d, want 11", own)
	}
}
