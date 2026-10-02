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
