package xmpp

import (
	"fmt"
	"math/rand"
)

// DefaultDomain is the live EU stream domain, proven by a live
// session open (the server answers `host-unknown` for
// `xmpp.wargaming.net` and friends; JIDs use it too:
// DBID@c2s.xmpp-wot-eu.wargaming.net/resource).
const DefaultDomain = "c2s.xmpp-wot-eu.wargaming.net"

// Default ports: the endpoint lists carry hosts only (proven on the
// genuine 124B vector, which holds no 5222/5280/443 in any width or
// endianness), so the client pairs hosts with these. They are
// defaults, not wire truth — override per deployment.
const (
	DefaultTCPPort  = 5222
	DefaultBOSHPort = 5280
)

// Endpoint is one (host, port) connection candidate. It mirrors the
// pairs `XmppServerSettings.update()` accepts after `_validate-
// Connection` (host non-empty, port an int).
type Endpoint struct {
	Host string
	Port int
}

// validateConnection mirrors shipped `XmppServerSettings.pyc`
// `_validateConnection`: a 2-tuple with non-empty host and int port.
func validateConnection(e Endpoint) bool {
	return e.Host != "" && e.Port > 0 && e.Port < 65536
}

// ServerSettings mirrors shipped `XmppServerSettings.pyc`: three
// candidate lists plus the session fields the login data provides.
// Connections holds TCP candidates, Alt spares, Bosh BOSH candidates.
type ServerSettings struct {
	Enabled     bool
	Connections []Endpoint
	Alt         []Endpoint
	Bosh        []Endpoint
	Domain      string
	Port        int
	Resource    string
	MUCServices map[string]string
}

// sampleCap is the per-list sample cap (`_NUMBER_OF_ITEMS_IN_SAMPLE`
// = 2 in the .pyc): each list contributes at most 2 candidates.
const sampleCap = 2

// sample returns up to sampleCap random entries of list, using rnd.
// A nil rnd keeps declaration order (deterministic offline use); the
// game always samples (connection choice is nondeterministic live).
func sample(list []Endpoint, rnd *rand.Rand) []Endpoint {
	if len(list) <= sampleCap {
		out := append([]Endpoint(nil), list...)
		if rnd != nil {
			rnd.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
		}
		return out
	}
	if rnd == nil {
		return append([]Endpoint(nil), list[:sampleCap]...)
	}
	perm := rnd.Perm(len(list))[:sampleCap]
	out := make([]Endpoint, 0, sampleCap)
	for _, i := range perm {
		out = append(out, list[i])
	}
	return out
}

// Iterator mirrors `ConnectionsIterator`: TCP candidates first (base
// then alt), BOSH after; each list pre-sampled to sampleCap. Length
// is the total remaining count.
type Iterator struct {
	tcp  []Endpoint
	bosh []Endpoint
}

// NewIterator builds the dial order from settings. Validated pairs
// only (mirrors the `filter(_validateConnection, ...)` in
// `update()`); pass rnd for game-like sampling, nil for order.
func NewIterator(s ServerSettings, rnd *rand.Rand) *Iterator {
	keep := func(in []Endpoint) []Endpoint {
		out := in[:0:0]
		for _, e := range in {
			if validateConnection(e) {
				out = append(out, e)
			}
		}
		return out
	}
	tcp := append(sample(keep(s.Connections), rnd), sample(keep(s.Alt), rnd)...)
	return &Iterator{tcp: tcp, bosh: sample(keep(s.Bosh), rnd)}
}

// Len reports remaining candidates (mirrors `__len__`).
func (it *Iterator) Len() int { return len(it.tcp) + len(it.bosh) }

// HasNext reports whether candidates remain (mirrors `hasNext`).
func (it *Iterator) HasNext() bool { return it.Len() > 0 }

// Next pops the next candidate: TCP first, then BOSH (mirrors
// `next`, including the TCP/BOSH type tag). ok is false when empty
// (mirrors `StopIteration`).
func (it *Iterator) Next() (e Endpoint, bosh bool, ok bool) {
	if len(it.tcp) > 0 {
		e, it.tcp = it.tcp[0], it.tcp[1:]
		return e, false, true
	}
	if len(it.bosh) > 0 {
		e, it.bosh = it.bosh[0], it.bosh[1:]
		return e, true, true
	}
	return Endpoint{}, false, false
}

// Clear drops all candidates (mirrors `clear`).
func (it *Iterator) Clear() { it.tcp, it.bosh = nil, nil }

// BoshPath is hardcoded client-side (shipped UI/mods reference the
// bosh host element with path `/bosh/`).
const BoshPath = "/bosh/"

// BoshURL renders https://host[:port]/bosh/ for an endpoint. Port 443
// omits the suffix (standard BOSH-over-TLS shape).
func BoshURL(e Endpoint) string {
	if e.Port == 443 {
		return fmt.Sprintf("https://%s%s", e.Host, BoshPath)
	}
	return fmt.Sprintf("https://%s:%d%s", e.Host, e.Port, BoshPath)
}
