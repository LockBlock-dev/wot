package keydump

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// ParsePattern parses a space-separated hex signature where "??" marks a
// wildcard byte, e.g. "48 89 5C ?? 08". It returns the needle bytes and a
// mask with 0xFF per literal byte, 0x00 per wildcard.
func ParsePattern(s string) (needle, mask []byte, err error) {
	for _, tok := range strings.Fields(s) {
		switch {
		case tok == "??" || tok == "?":
			needle = append(needle, 0x00)
			mask = append(mask, 0x00)
		case len(tok) == 2:
			b, err := hex.DecodeString(tok)
			if err != nil {
				return nil, nil, fmt.Errorf("keydump: bad pattern token %q: %w", tok, err)
			}
			needle = append(needle, b[0])
			mask = append(mask, 0xFF)
		default:
			return nil, nil, fmt.Errorf("keydump: bad pattern token %q", tok)
		}
	}
	if len(needle) == 0 {
		return nil, nil, fmt.Errorf("keydump: empty pattern")
	}
	return needle, mask, nil
}

// Scan returns every offset in haystack where needle matches under mask.
// The search anchors on the longest literal run via bytes.Index, so a
// tens-of-MB .text scan stays linear-ish instead of O(n*m).
func Scan(haystack, needle, mask []byte) []int {
	if len(needle) == 0 || len(needle) != len(mask) || len(haystack) < len(needle) {
		return nil
	}
	// Longest run of literal bytes to anchor candidates.
	bestStart, bestLen := 0, 0
	for i := 0; i < len(mask); {
		if mask[i] == 0x00 {
			i++
			continue
		}
		j := i
		for j < len(mask) && mask[j] != 0x00 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	matchAt := func(off int) bool {
		for i := range needle {
			if mask[i] == 0x00 {
				continue
			}
			if haystack[off+i] != needle[i] {
				return false
			}
		}
		return true
	}
	if bestLen == 0 { // all wildcards: degenerate, refuse
		return nil
	}
	var out []int
	anchor := needle[bestStart : bestStart+bestLen]
	base := 0
	for {
		rel := bytes.Index(haystack[base:], anchor)
		if rel < 0 {
			return out
		}
		off := base + rel - bestStart
		if off >= 0 && off+len(needle) <= len(haystack) && matchAt(off) {
			out = append(out, off)
		}
		base += rel + 1
		if base+len(needle) > len(haystack)+bestStart {
			return out
		}
	}
}
