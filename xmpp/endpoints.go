package xmpp

import (
	"encoding/binary"
	"fmt"
)

// Endpoint-list encoding (S>C, e.g. the genuine 124B datagram on the
// Sep-29 lobby #2 flow, login key MITM-recovered offline): after the
// channel flags the body is one small headed by list ID 0x68,
// followed by sections headed `[0x72 sub 0x21 0x00 0x00]` with sub
// running b8→bc. Strings are pascal (`0x55`, len8, bytes); the bosh
// hostname is `KP` (0x4b50)-terminated. Pinned byte-exact by the test
// vector below; a second sample may relax the constants.
//
// Ips/ports note: the sample carries NO port in any width or
// endianness (scanned for 5222/5280/443/80) — hosts pair with
// DefaultBOSHPort. That default is a client choice, not wire truth:
// override Hosts' Port per deployment.

// ListID is the endpoint-list small ID (single sample; cf. 0x35 for
// volatile records, 0x13 for ticks).
const ListID = 0x68

// SectionTag is the section introducer byte.
const SectionTag = 0x72

// StringTag introduces a pascal string (u8 length + bytes).
const StringTag = 0x55

// HostTerm terminates the bosh hostname ("KP").
var HostTerm = []byte{0x4B, 0x50}

// Section is one walked section: subtype byte + raw payload (up to
// the next section tag or body end). Payload internals stay raw
// except where decoded into EndpointList.
type Section struct {
	Sub     byte
	Payload []byte
}

// EndpointList is a decoded endpoint small: the settings key name
// (e.g. "xmpp_bosh_connections"), bosh hosts, and all raw sections.
type EndpointList struct {
	KeyName  string
	Hosts    []Endpoint
	Sections []Section
}

// readString parses `[0x55][len8][bytes]` at body[off:]. It returns
// the string and the offset past it.
func readString(body []byte, off int) (string, int, error) {
	if off+2 > len(body) || body[off] != StringTag {
		return "", 0, fmt.Errorf("xmpp: endpoints: no string tag at %d", off)
	}
	n := int(body[off+1])
	if off+2+n > len(body) {
		return "", 0, fmt.Errorf("xmpp: endpoints: string overruns at %d", off)
	}
	return string(body[off+2 : off+2+n]), off + 2 + n, nil
}

// ParseEndpointList decodes one endpoint-list body (channel flags and
// footers already stripped — see the test vector). No network.
func ParseEndpointList(body []byte) (EndpointList, error) {
	var out EndpointList
	if len(body) < 1 || body[0] != ListID {
		return out, fmt.Errorf("xmpp: endpoints: bad list ID (len %d)", len(body))
	}
	off := 1
	for off < len(body) {
		if off+5 > len(body) || body[off] != SectionTag ||
			body[off+2] != 0x21 || body[off+3] != 0x00 || body[off+4] != 0x00 {
			return out, fmt.Errorf("xmpp: endpoints: bad section head at %d", off)
		}
		sub := body[off+1]
		start := off + 5
		end := len(body)
		for i := start; i < len(body); i++ {
			if body[i] == SectionTag && i+4 < len(body) &&
				body[i+2] == 0x21 && body[i+3] == 0x00 && body[i+4] == 0x00 {
				end = i
				break
			}
		}
		out.Sections = append(out.Sections, Section{Sub: sub, Payload: append([]byte(nil), body[start:end]...)})
		off = end
	}
	if len(out.Sections) == 0 {
		return out, fmt.Errorf("xmpp: endpoints: no sections")
	}
	for _, s := range out.Sections {
		p := s.Payload
		if len(p) >= 3 && p[1] == StringTag {
			name, after, err := readString(p, 1)
			if err != nil {
				continue
			}
			_ = after
			if out.KeyName == "" {
				out.KeyName = name
				continue
			}
		}
		if len(p) >= 2 && p[0] == StringTag {
			host, after, err := readString(p, 0)
			if err != nil {
				continue
			}
			rest := p[after:]
			if len(rest) < 3 || rest[0] != HostTerm[0] || rest[1] != HostTerm[1] {
				continue
			}
			out.Hosts = append(out.Hosts, Endpoint{Host: host, Port: DefaultBOSHPort})
		}
	}
	if out.KeyName == "" {
		return out, fmt.Errorf("xmpp: endpoints: no key-name string")
	}
	if len(out.Hosts) == 0 {
		return out, fmt.Errorf("xmpp: endpoints: no KP-terminated host")
	}
	return out, nil
}

// SectionU32s reads a section payload as little-endian u32s (for the
// trailing reserved words, e.g. the bc section). Length must align.
func SectionU32s(s Section) ([]uint32, error) {
	if len(s.Payload)%4 != 0 {
		return nil, fmt.Errorf("xmpp: endpoints: section %x len %d", s.Sub, len(s.Payload))
	}
	out := make([]uint32, 0, len(s.Payload)/4)
	for i := 0; i < len(s.Payload); i += 4 {
		out = append(out, binary.LittleEndian.Uint32(s.Payload[i:]))
	}
	return out, nil
}
