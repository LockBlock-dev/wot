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
func Str(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// Int reads an int64 field (JSON ints decode as int64; float64 from
// other producers is rejected — never silently truncated).
func Int(m map[string]any, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	n, ok := v.(int64)
	return n, ok
}

// Dict reads a nested map field.
func Dict(m map[string]any, key string) (map[string]any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	d, ok := v.(map[string]any)
	return d, ok
}

// List reads a nested slice field.
func List(m map[string]any, key string) ([]any, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	l, ok := v.([]any)
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
func ParseOffers(items []any) []Offer {
	var out []Offer
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, e := range t {
				if sub, ok := e.(map[string]any); ok && strings.HasPrefix(k, "offer:") {
					if o, ok := parseOffer(k, sub); ok {
						out = append(out, o)
					}
				}
				walk(e)
			}
		case []any:
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
func parseOffer(key string, sub map[string]any) (Offer, bool) {
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

// QuestLeg is one condition (`c:<id>__<n>`) or reward (`r:<type>__<n>`)
// leg from a quest key. Empty legs (the `::` separators) never reach
// here — the key splitter drops them.
type QuestLeg struct {
	Op    string // "c" condition, "r" reward
	ID    string
	Count string
}

// Quest is one daily/weekly quest: key segments + expiry + progress
// subtree (progress is session-shaped and stays a raw map — empty on
// fresh sessions). Key form `dq:<hash>:QUEST_<DIFF>:<legs…>` /
// `wq:<hash>:<legs…>` (legs `c:<id>__<n>` / `r:<type>__<n>`).
type Quest struct {
	Key      string
	Kind     string // "dq" daily, "wq" weekly
	Hash     string
	Diff     string // QUEST_* or "" for wq
	Conds    []QuestLeg
	Rewards  []QuestLeg
	Expiry   int64
	Progress map[string]any
}

// ParseQuests collects quest entries from salvaged items (quest dicts
// keyed by quest ID inside a `quests` map, one level down from the
// top doc — matched structurally, never by position).
func ParseQuests(items []any) []Quest {
	var out []Quest
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if qm, ok := t["quests"]; ok {
				if qd, ok := qm.(map[string]any); ok {
					for k, e := range qd {
						if sub, ok := e.(map[string]any); ok {
							if q, ok := parseQuest(k, sub); ok {
								out = append(out, q)
							}
						}
					}
				}
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
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

// parseQuest splits the quest key and reads expiry/progress.
func parseQuest(key string, sub map[string]any) (Quest, bool) {
	var q Quest
	parts := strings.Split(key, ":")
	if len(parts) < 3 || (parts[0] != "dq" && parts[0] != "wq") {
		return q, false
	}
	q.Key, q.Kind = key, parts[0]
	idx := 1
	for idx < len(parts) && parts[idx] == "" {
		idx++
	}
	if idx >= len(parts) {
		return q, false
	}
	q.Hash = parts[idx]
	idx++
	legs := parts[idx:]
	if q.Kind == "dq" {
		if len(legs) == 0 || !strings.HasPrefix(legs[0], "QUEST_") {
			return q, false
		}
		q.Diff = legs[0]
		legs = legs[1:]
	} else if len(legs) > 0 && isDigits(legs[0]) {
		legs = legs[1:] // wq version segment
	}
	for i := 0; i < len(legs); i++ {
		leg := legs[i]
		if leg == "" {
			continue
		}
		// Legs span two segments: op (`c`/`r`) then `<id>__<n>`.
		if leg != "c" && leg != "r" {
			continue
		}
		if i+1 >= len(legs) || legs[i+1] == "" {
			continue
		}
		id, n, _ := strings.Cut(legs[i+1], "__")
		i++
		l := QuestLeg{Op: leg, ID: id, Count: n}
		if leg == "c" {
			q.Conds = append(q.Conds, l)
		} else {
			q.Rewards = append(q.Rewards, l)
		}
	}
	var ok bool
	if q.Expiry, ok = Int(sub, "expiryTime"); !ok {
		return q, false
	}
	if p, ok := Dict(sub, "progress"); ok {
		q.Progress = p
	}
	return q, true
}

// isDigits reports all-decimal (quest version segments).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// PiggyBank is the credit reserve (`{credits}`).
type PiggyBank struct {
	Credits int64
}

// ParsePiggyBank reads the piggyBank block (absent → miss, never zero
// — a zero reserve is real data).
func ParsePiggyBank(items []any) (PiggyBank, bool) {
	var out PiggyBank
	found := false
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if pb, ok := t["piggyBank"]; ok {
				if pm, ok := pb.(map[string]any); ok {
					if c, ok := Int(pm, "credits"); ok {
						out, found = PiggyBank{Credits: c}, true
					}
				}
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for _, it := range items {
		walk(it)
	}
	return out, found
}

// ModeConfig is one matchmaker mode block (`configs/<mode>`:
// allowedTankLevels + voice/assembly toggles, shared shape across
// epic/last_stand/squad).
type ModeConfig struct {
	Mode                    string
	AllowedTankLevels       int64
	IsAssemblingEnabled     bool
	TankLevelPreference     bool
	VoiceChatPreference     bool
	HardVoiceCheckTime      float64
	HardVoiceCheckTimeKnown bool
}

// ParseModeConfigs collects `configs/<mode>` blocks.
func ParseModeConfigs(items []any) []ModeConfig {
	var out []ModeConfig
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if cm, ok := t["configs"]; ok {
				if cd, ok := cm.(map[string]any); ok {
					for mode, e := range cd {
						if em, ok := e.(map[string]any); ok {
							out = append(out, parseModeConfig(mode, em))
						}
					}
				}
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
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

func parseModeConfig(mode string, m map[string]any) ModeConfig {
	c := ModeConfig{Mode: mode}
	if v, ok := Int(m, "allowedTankLevels"); ok {
		c.AllowedTankLevels = v
	}
	if v, ok := m["isAssemblingEnabled"].(bool); ok {
		c.IsAssemblingEnabled = v
	}
	if v, ok := m["tankLevelPreferenceEnabled"].(bool); ok {
		c.TankLevelPreference = v
	}
	if v, ok := m["voiceChatPreferenceEnabled"].(bool); ok {
		c.VoiceChatPreference = v
	}
	if v, ok := m["hardVoiceCheckTime"].(float64); ok {
		c.HardVoiceCheckTime, c.HardVoiceCheckTimeKnown = v, true
	}
	return c
}

// SlotCharges is one `vehiclesSlotsConfig/<nation>:<vehicle>` entry
// (four charge counters).
type SlotCharges struct {
	Vehicle string
	Charges [4]int64
}

// ParseSlotCharges collects vehiclesSlotsConfig entries.
func ParseSlotCharges(items []any) []SlotCharges {
	var out []SlotCharges
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if sm, ok := t["vehiclesSlotsConfig"]; ok {
				if sd, ok := sm.(map[string]any); ok {
					for veh, e := range sd {
						if em, ok := e.(map[string]any); ok {
							var sc SlotCharges
							sc.Vehicle = veh
							okAll := true
							for i, k := range []string{"charge1", "charge2", "charge3", "charge4"} {
								v, ok := Int(em, k)
								if !ok {
									okAll = false
									break
								}
								sc.Charges[i] = v
							}
							if okAll {
								out = append(out, sc)
							}
						}
					}
				}
			}
			for _, e := range t {
				walk(e)
			}
		case []any:
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
