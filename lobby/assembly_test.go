package lobby

// Offline assembly tests: synthetic plain trees only (schemas mirror
// the Oct-01 offer census; values synthetic).
import (
	"testing"
)

func offerTree() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"offer:battle_pass:deluxe:paid:213:10": map[string]interface{}{
				"count": int64(3), "expires": map[string]interface{}{"at": int64(1780000000)},
			},
			"other": int64(1),
		},
		[]interface{}{
			map[string]interface{}{
				"offer:comp7_6_yearly:guide_gift:paid:213:5": map[string]interface{}{
					"count": int64(1), "expires": map[string]interface{}{"at": int64(1780000001)}, "limit": int64(0),
				},
			},
		},
		map[string]interface{}{
			"offer:comp7:deluxe": map[string]interface{}{
				"count": int64(2), "expires": map[string]interface{}{"at": int64(1780000002)},
			},
			"offer:bad": map[string]interface{}{"count": int64(1)},
			"offer:battle_pass:x:paid:1:2": map[string]interface{}{
				"expires": int64(9),
			},
		},
	}
}

func TestParseOffers(t *testing.T) {
	offers := ParseOffers(offerTree())
	if len(offers) != 3 {
		t.Fatalf("offers=%d, want 3 (malformed keys/skips)", len(offers))
	}
	var dlx, guide, shortDlx *Offer
	for i := range offers {
		switch {
		case offers[i].Kind == "deluxe" && offers[i].PaidN != "":
			dlx = &offers[i]
		case offers[i].Kind == "guide_gift":
			guide = &offers[i]
		case offers[i].Kind == "deluxe":
			shortDlx = &offers[i]
		}
	}
	if dlx == nil || dlx.Page != "battle_pass" || dlx.Count != 3 || dlx.HasLimit {
		t.Fatalf("deluxe = %+v", dlx)
	}
	if shortDlx == nil || shortDlx.Page != "comp7" || shortDlx.PaidN != "" || shortDlx.Count != 2 {
		t.Fatalf("short deluxe = %+v", shortDlx)
	}
	if guide == nil || guide.Limit != 0 || !guide.HasLimit {
		t.Fatalf("guide (zero limit present) = %+v", guide)
	}
	if pages := OfferPages(offers); pages["battle_pass"] != 1 || pages["comp7_6_yearly"] != 1 || pages["comp7"] != 1 {
		t.Fatalf("pages = %v", pages)
	}
}

func TestAccessors(t *testing.T) {
	m := map[string]interface{}{
		"s": "v", "n": int64(7),
		"d": map[string]interface{}{"x": int64(1)},
		"l": []interface{}{int64(2)},
		"f": 1.5,
	}
	if s, ok := Str(m, "s"); !ok || s != "v" {
		t.Fatal("Str")
	}
	if _, ok := Str(m, "missing"); ok {
		t.Fatal("Str missing must miss")
	}
	if n, ok := Int(m, "n"); !ok || n != 7 {
		t.Fatal("Int")
	}
	if _, ok := Int(m, "f"); ok {
		t.Fatal("float must not coerce to int")
	}
	if _, ok := Dict(m, "d"); !ok {
		t.Fatal("Dict")
	}
	if _, ok := List(m, "l"); !ok {
		t.Fatal("List")
	}
	if _, ok := List(m, "s"); ok {
		t.Fatal("type mismatch must miss")
	}
}

func questTree() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"quests": map[string]interface{}{
				"dq:6abe9630:QUEST_MEDIUM::c:218__2000::r:ett__1": map[string]interface{}{
					"expiryTime": int64(1780000000),
					"progress":   map[string]interface{}{},
				},
				"wq::6ABBEA70::1::c:30001": map[string]interface{}{
					"expiryTime": int64(1780000001),
				},
				"bogus": map[string]interface{}{"expiryTime": int64(1)},
				"dq:6abe9630:NOPE::c:1__1": map[string]interface{}{
					"expiryTime": int64(1),
				},
			},
		},
	}
}

func TestParseQuests(t *testing.T) {
	qs := ParseQuests(questTree())
	if len(qs) != 2 {
		t.Fatalf("quests=%d, want 2", len(qs))
	}
	var dq, wq *Quest
	for i := range qs {
		switch qs[i].Kind {
		case "dq":
			dq = &qs[i]
		case "wq":
			wq = &qs[i]
		}
	}
	if dq == nil || dq.Diff != "QUEST_MEDIUM" || len(dq.Conds) != 1 || len(dq.Rewards) != 1 {
		t.Fatalf("dq = %+v", dq)
	}
	if dq.Conds[0].ID != "218" || dq.Conds[0].Count != "2000" || dq.Rewards[0].Op != "r" {
		t.Fatalf("dq legs = %+v", dq)
	}
	if dq.Progress == nil {
		t.Fatal("empty progress must stay a present map")
	}
	if wq == nil || wq.Diff != "" || wq.Hash != "6ABBEA70" {
		t.Fatalf("wq = %+v", wq)
	}
}

func TestParsePiggyBank(t *testing.T) {
	items := []interface{}{
		map[string]interface{}{"piggyBank": map[string]interface{}{"credits": int64(5000)}},
	}
	pb, ok := ParsePiggyBank(items)
	if !ok || pb.Credits != 5000 {
		t.Fatalf("piggy = %+v ok=%v", pb, ok)
	}
	if _, ok := ParsePiggyBank([]interface{}{map[string]interface{}{}}); ok {
		t.Fatal("absent piggy must miss")
	}
}

func TestParseModeConfigs(t *testing.T) {
	items := []interface{}{
		map[string]interface{}{
			"configs": map[string]interface{}{
				"squad": map[string]interface{}{
					"allowedTankLevels":          int64(8),
					"isAssemblingEnabled":        true,
					"tankLevelPreferenceEnabled": false,
					"voiceChatPreferenceEnabled": true,
					"hardVoiceCheckTime":         1.5,
				},
			},
		},
	}
	mc := ParseModeConfigs(items)
	if len(mc) != 1 || mc[0].Mode != "squad" || mc[0].AllowedTankLevels != 8 {
		t.Fatalf("modes = %+v", mc)
	}
	if !mc[0].IsAssemblingEnabled || !mc[0].HardVoiceCheckTimeKnown {
		t.Fatalf("mode flags = %+v", mc[0])
	}
}

func TestParseSlotCharges(t *testing.T) {
	items := []interface{}{
		map[string]interface{}{
			"vehiclesSlotsConfig": map[string]interface{}{
				"ussr:R46_KV-13_SH": map[string]interface{}{
					"charge1": int64(1), "charge2": int64(2), "charge3": int64(3), "charge4": int64(4),
				},
				"broken": map[string]interface{}{"charge1": int64(1)},
			},
		},
	}
	sc := ParseSlotCharges(items)
	if len(sc) != 1 || sc[0].Vehicle != "ussr:R46_KV-13_SH" || sc[0].Charges != [4]int64{1, 2, 3, 4} {
		t.Fatalf("charges = %+v", sc)
	}
}
