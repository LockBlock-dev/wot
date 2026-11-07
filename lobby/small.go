package lobby

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrUnknownSmall is returned by ParseSmall for a family it does not know.
// A walker should stop and hand the remaining bytes back rather than treat
// it as corruption: the taxonomy is still being mapped.
var ErrUnknownSmall = errors.New("lobby: unknown small family")

// Small is one BigWorld "small" message: a family byte, an optional type
// byte, and a body. The framing between them depends on the family, which
// is why this type exists — the parser and the builder share one
// description instead of each hardcoding the layout.
//
// The families the lobby uses:
//
//	0x1a  [1a][type][len8][body]      the lobby's own smalls
//	0x1a/5b  [1a][5b][u32][u32]       server stats: NO length byte
//	0x13  [13][tag]                   tick, fixed 1
//	0x45  [45][len8][body]
//	0x46  [46][len u16][declen u32][zlib]
//	0xff  [ff][len u32][rid u32][body]
type Small struct {
	Family byte
	// Type is the 0x1a subtype; zero for the other families.
	Type byte
	// Body is the payload after the framing.
	Body []byte
}

// SmallStatsType is the 0x1a subtype whose body is fixed and carries no
// length byte.
const SmallStatsType = 0x5b

// SmallSessionDictType is the 0x1a subtype whose length field is a u16
// rather than a u8 (the session dict's pickle is longer than 255 B).
const SmallSessionDictType = 0x76

// Encode renders the small with its family's framing.
//
// 0x46 is refused: its body is a compressed pickle whose declared length
// has to be computed from the inflated form, which is a different
// operation from framing a payload.
func (s Small) Encode() ([]byte, error) {
	switch s.Family {
	case 0x1a:
		if s.Type == SmallStatsType {
			if len(s.Body) != 8 {
				return nil, fmt.Errorf("lobby: 1a/%02x body is %d B, want 8", s.Type, len(s.Body))
			}
			return append([]byte{0x1a, s.Type}, s.Body...), nil
		}
		if s.Type == SmallSessionDictType {
			// 1a/76 is the one 0x1a small whose length is a u16: the
			// session dict's pickle outgrew the u8 field.
			if len(s.Body) > 0xFFFF {
				return nil, fmt.Errorf("lobby: 1a/%02x body is %d B, beyond the u16 length", s.Type, len(s.Body))
			}
			out := []byte{0x1a, s.Type}
			out = binary.LittleEndian.AppendUint16(out, uint16(len(s.Body)))
			return append(out, s.Body...), nil
		}
		if len(s.Body) > 0xFF {
			return nil, fmt.Errorf("lobby: 1a/%02x body is %d B, beyond the u8 length", s.Type, len(s.Body))
		}
		out := []byte{0x1a, s.Type, byte(len(s.Body))}
		return append(out, s.Body...), nil

	case 0x13:
		if len(s.Body) != 1 {
			return nil, fmt.Errorf("lobby: tick body is %d B, want 1", len(s.Body))
		}
		return append([]byte{0x13}, s.Body...), nil

	case 0x45:
		if len(s.Body) > 0xFF {
			return nil, fmt.Errorf("lobby: 45 body is %d B, beyond the u8 length", len(s.Body))
		}
		out := []byte{0x45, byte(len(s.Body))}
		return append(out, s.Body...), nil

	case 0xff:
		// The length covers everything after the 5-byte head, the 4-byte
		// request id included.
		if len(s.Body) < 4 {
			return nil, fmt.Errorf("lobby: ff body is %d B, needs a 4 B request id", len(s.Body))
		}
		out := []byte{0xff}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(s.Body)))
		return append(out, s.Body...), nil

	case 0x46:
		return nil, fmt.Errorf("lobby: 46 is a compressed pickle; build it with its declared length, not from a payload")
	}
	return nil, fmt.Errorf("lobby: no framing for small family %#02x", s.Family)
}

// ParseSmall reads one small from the front of b and reports how many
// bytes it consumed.
func ParseSmall(b []byte) (Small, int, error) {
	if len(b) == 0 {
		return Small{}, 0, fmt.Errorf("lobby: empty small")
	}
	switch b[0] {
	case 0x1a:
		if len(b) < 3 {
			return Small{}, 0, fmt.Errorf("lobby: truncated 1a head")
		}
		if b[1] == SmallStatsType {
			// Fixed [type][u32][u32]: the len8 position carries the low
			// counter byte, so there is no length to read.
			if len(b) < 2+8 {
				return Small{}, 0, fmt.Errorf("lobby: truncated 1a/%02x body", SmallStatsType)
			}
			return Small{Family: 0x1a, Type: b[1], Body: b[2:10]}, 10, nil
		}
		if b[1] == SmallSessionDictType {
			// 1a/76 carries a u16 length.
			if len(b) < 4 {
				return Small{}, 0, fmt.Errorf("lobby: truncated 1a/%02x head", SmallSessionDictType)
			}
			n := int(binary.LittleEndian.Uint16(b[2:4]))
			if len(b) < 4+n {
				return Small{}, 0, fmt.Errorf("lobby: truncated 1a/%02x body (%d < %d)", b[1], len(b)-4, n)
			}
			return Small{Family: 0x1a, Type: b[1], Body: b[4 : 4+n]}, 4 + n, nil
		}
		body, n, err := readElementBody(b[2:], 1)
		if err != nil {
			return Small{}, 0, fmt.Errorf("lobby: 1a/%02x: %w", b[1], err)
		}
		return Small{Family: 0x1a, Type: b[1], Body: body}, 2 + n, nil

	case 0x13:
		if len(b) < 2 {
			return Small{}, 0, fmt.Errorf("lobby: truncated tick")
		}
		return Small{Family: 0x13, Body: b[1:2]}, 2, nil

	case 0x45:
		if len(b) < 2 {
			return Small{}, 0, fmt.Errorf("lobby: truncated 45 head")
		}
		body, n, err := readElementBody(b[1:], 1)
		if err != nil {
			return Small{}, 0, fmt.Errorf("lobby: 45: %w", err)
		}
		return Small{Family: 0x45, Body: body}, 1 + n, nil

	case 0x46:
		if len(b) < 7 {
			return Small{}, 0, fmt.Errorf("lobby: truncated 46 head")
		}
		body, n, err := readElementBody(b[1:], 2)
		if err != nil {
			return Small{}, 0, fmt.Errorf("lobby: 46: %w", err)
		}
		return Small{Family: 0x46, Body: body}, 1 + n, nil

	case 0xff:
		if len(b) < 9 {
			return Small{}, 0, fmt.Errorf("lobby: truncated ff head")
		}
		n := int(binary.LittleEndian.Uint32(b[1:5]))
		if len(b) < 5+n {
			return Small{}, 0, fmt.Errorf("lobby: truncated ff body")
		}
		return Small{Family: 0xff, Body: b[5 : 5+n]}, 5 + n, nil
	}
	return Small{}, 0, fmt.Errorf("%w %#02x", ErrUnknownSmall, b[0])
}

// readElementBody reads an element length field of `width` bytes and the
// body that follows, returning the body and the bytes consumed (length
// field plus body).
//
// All-ones is not "the largest that fits", it is the ESCAPE. The client's
// own writer (InterfaceElement::compressLength) fills the field with ones,
// replaces the body's FIRST FOUR BYTES with the full u32 length, and moves
// those four displaced bytes to the END of the element; the reader reverses
// it. A parser that reads all-ones as a plain length mis-slices the element
// and, on the client, over-reads the bundle
// (`MF_ASSERT_DEV pCurr_ + nBytes <= pEnd_`).
func readElementBody(b []byte, width int) ([]byte, int, error) {
	if len(b) < width {
		return nil, 0, fmt.Errorf("truncated length field")
	}
	escape := uint64(1)<<(8*width) - 1
	var n uint64
	for i := 0; i < width; i++ {
		n |= uint64(b[i]) << (8 * i)
	}
	if n != escape {
		if uint64(len(b)) < uint64(width)+n {
			return nil, 0, fmt.Errorf("truncated body (%d < %d)", len(b)-width, n)
		}
		return b[width : width+int(n)], width + int(n), nil
	}
	if len(b) < width+4 {
		return nil, 0, fmt.Errorf("truncated oversized length")
	}
	total := int(binary.LittleEndian.Uint32(b[width : width+4]))
	if total < 4 || len(b) < width+4+total {
		return nil, 0, fmt.Errorf("truncated oversized body (%d < %d)", len(b)-width-4, total)
	}
	rest := b[width+4 : width+4+total]
	body := make([]byte, 0, total)
	body = append(body, rest[total-4:]...)
	body = append(body, rest[:total-4]...)
	return body, width + 4 + total, nil
}

// ParseSmalls walks a payload of back-to-back smalls.
func ParseSmalls(b []byte) ([]Small, error) {
	var out []Small
	for len(b) > 0 {
		s, n, err := ParseSmall(b)
		if err != nil {
			return out, err
		}
		if n <= 0 {
			return out, fmt.Errorf("lobby: small parser made no progress")
		}
		out = append(out, s)
		b = b[n:]
	}
	return out, nil
}

// FindSmall returns the first small of a family/type in a payload, or nil.
// It is the typed replacement for scanning for the two tag bytes.
func FindSmall(b []byte, family, typ byte) *Small {
	for len(b) > 0 {
		s, n, err := ParseSmall(b)
		if err != nil || n <= 0 {
			return nil
		}
		if s.Family == family && s.Type == typ {
			return &s
		}
		b = b[n:]
	}
	return nil
}
