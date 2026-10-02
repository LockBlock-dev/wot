package lobby

// Lobby application state from the stage-2 bulk bundle (offline).
//
// Wire why: the 1252B flood is one ~625KB shared-memo proto-2 pickle
// with per-capture few-byte noise sites, so strict full-stream decode
// is brittle by nature. What survives reliably is prefix salvage:
// DecodePrefix returns the closed containers before the first noise
// site (chunk 1: hundreds of stack items, ~800 schema keys —
// shop/offer/goodie/vehicle defs). This file converts those decoded
// trees into plain Go values (maps/slices/scalars) for application
// use. Chunks 2+ are second-layer-or-pad (near-random under every
// key/mode tried: pickle, zlib, raw/newkey ECB, chained Blowfish,
// varint, floats) and harvest to nothing by design.
//
// Privacy: converters never log. Callers print schema (key names,
// counts, sizes) only — never values.

// PlainValue converts a decoded pickle tree to plain Go values:
// *PDict with all-string keys -> map[string]interface{}, *PList /
// *PTuple / *PSet / *Deque -> []interface{}, scalars pass through.
// Non-string dict keys are dropped (counted in dropped). Depth is
// capped; deeper subtrees become nil.
func PlainValue(v interface{}, dropped *int) interface{} {
	return plain(v, 0, dropped)
}

func plain(v interface{}, depth int, dropped *int) interface{} {
	if depth > 10 {
		return nil
	}
	switch t := v.(type) {
	case *PDict:
		m := make(map[string]interface{}, len(t.Entries))
		for _, e := range t.Entries {
			ks, ok := e.Key.(string)
			if !ok {
				if dropped != nil {
					*dropped++
				}
				continue
			}
			m[ks] = plain(e.Value, depth+1, dropped)
		}
		return m
	case *PList:
		out := make([]interface{}, 0, len(t.Items))
		for _, e := range t.Items {
			out = append(out, plain(e, depth+1, dropped))
		}
		return out
	case *PTuple:
		out := make([]interface{}, 0, len(t.Items))
		for _, e := range t.Items {
			out = append(out, plain(e, depth+1, dropped))
		}
		return out
	case *PSet:
		out := make([]interface{}, 0, len(t.Items))
		for _, e := range t.Items {
			out = append(out, plain(e, depth+1, dropped))
		}
		return out
	case *Deque:
		out := make([]interface{}, 0, len(t.Items))
		for _, e := range t.Items {
			out = append(out, plain(e, depth+1, dropped))
		}
		return out
	case *GenericValue:
		m := make(map[string]interface{}, len(t.Attrs)+2)
		m[".class"] = t.Module + "." + t.Name
		for k, e := range t.Attrs {
			m[k] = plain(e, depth+1, dropped)
		}
		return m
	default:
		return v
	}
}

// LobbyBundle is one chunk's salvaged application state: the closed
// containers as plain values plus the valid-prefix size. Schema
// (key names) comes from HarvestKeys; values stay in-memory.
type LobbyBundle struct {
	Items  []interface{}
	Prefix int
}

// SalvageChunk decodes one bulk chunk's valid prefix and converts
// every closed stack item to plain values. Never shares memo across
// chunks (fresh state per call, like HarvestChunks).
func SalvageChunk(payload []byte) LobbyBundle {
	stk, n, _ := DecodePrefix(payload)
	var dropped int
	b := LobbyBundle{Prefix: n}
	for _, s := range stk {
		b.Items = append(b.Items, PlainValue(s, &dropped))
	}
	return b
}
