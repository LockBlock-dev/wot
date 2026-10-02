package lobby

import "strings"

// Typed lobby-state assembly (offline).
//
// Wire why: the bulk bundle decodes to plain maps/slices/scalars
// (SalvageChunk/PlainValue), but application code needs TYPED
// objects with presence booleans — the server omits absent fields
// rather than zeroing them, so every access reports ok. Schema from
// the Oct-01 lobby (throwaway census, key names only): offer dicts
// keyed `offer:<page>:<kind>:paid:<paidN>:<sub>` (pages
// battle_pass/comp7_6_yearly, kinds battle_booster_gift/
// blueprint_gift/deluxe/guide_gift/modernized_devices_t3) with
// `{count, expires[, limit]}` values.

// Str reads a string field (presence boolean, never a zero default).
func Str(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Int reads an int64 field (JSON ints decode as int64; float64 from
// other producers is rejected — never silently truncated).
func Int(m map[string]interface{}, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}

// Dict reads a nested map field.
func Dict(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	d, ok := v.(map[string]interface{})
	return d, ok
}

// List reads a nested slice field.
func List(m map[string]interface{}, key string) ([]interface{}, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	l, ok := v.([]interface{})
	return l, ok
}

// Offer is one shop offer: key segments + availability counters.
// Two key shapes: short `offer:<page>:<kind>` (PaidN/Sub empty) and
// long with `:paid:<paidN>:<sub>` legs. Expires/Limit use Unix-epoch
// ints when present (HasLimit distinguishes absent from zero —
// a zero limit is a real cap).
type Offer struct {
	Key      string
	Page     string
	Kind     string
	PaidN    string
	Sub      string
	Count    int64
	Expires  int64
	Limit    int64
	HasLimit bool
}

// ParseOffers collects offer entries from salvaged items (walks maps
// and slices recursively; non-offer content is skipped, never an
// error — partial sessions parse partially).
func ParseOffers(items []interface{}) []Offer {
	var out []Offer
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for k, e := range t {
				if sub, ok := e.(map[string]interface{}); ok && strings.HasPrefix(k, "offer:") {
					if o, ok := parseOffer(k, sub); ok {
						out = append(out, o)
					}
				}
				walk(e)
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, it := range items {
		walk(it)
	}
	return out
}

// parseOffer splits `offer:<page>:<kind>[:paid:<paidN>:<sub>]` and
// reads the counters. Two key shapes live (comp7 short without the
// paid legs, battle_pass long with them). Malformed keys or missing
// count/expires fail (the caller skips — schema drift, not data).
func parseOffer(key string, sub map[string]interface{}) (Offer, bool) {
	var o Offer
	parts := strings.Split(key, ":")
	o.Key = key
	switch {
	case len(parts) == 3 && parts[0] == "offer":
		o.Page, o.Kind = parts[1], parts[2]
	case len(parts) == 6 && parts[0] == "offer" && parts[3] == "paid":
		o.Page, o.Kind, o.PaidN, o.Sub = parts[1], parts[2], parts[4], parts[5]
	default:
		return o, false
	}
	var ok bool
	if o.Count, ok = Int(sub, "count"); !ok {
		return o, false
	}
	// Expires is a nested `{at: epoch}` dict (uniform 11/11 live).
	if ex, ok := Dict(sub, "expires"); ok {
		if o.Expires, ok = Int(ex, "at"); !ok {
			return o, false
		}
	} else if o.Expires, ok = Int(sub, "expires"); !ok {
		return o, false
	}
	if o.Limit, ok = Int(sub, "limit"); ok {
		o.HasLimit = true
	}
	return o, true
}

// OfferPages tallies offers per page (counts only — the shape census
// callers print).
func OfferPages(offers []Offer) map[string]int {
	pages := map[string]int{}
	for _, o := range offers {
		pages[o.Page]++
	}
	return pages
}
