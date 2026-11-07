package xmppserver

import (
	"context"
	"sort"
	"sync"
)

// Social is one account's social state: the roster, the block list and
// the contact notes.
//
// It is deliberately separate from server.PlayerState. The roster
// changes on a different cadence (every friend add, every group rename)
// and is only ever read by the chat layer, so folding it into the
// account document would make every friend add rewrite the garage.
type Social struct {
	Roster  []RosterItem     `json:"roster,omitempty"`
	Blocked []BlockItem      `json:"blocked,omitempty"`
	Notes   map[int64]string `json:"notes,omitempty"`
}

// RosterItem is one entry of the jabber:iq:roster list.
type RosterItem struct {
	// JID is the bare contact JID (node@domain).
	JID string `json:"jid"`
	// Name is the contact's display name as the client last saw it.
	Name string `json:"name,omitempty"`
	// Groups are the roster groups the contact belongs to.
	Groups []string `json:"groups,omitempty"`
	// Subscription is the XMPP subscription state: none, to, from or
	// both. The client derives the friend/ignored tags from it.
	Subscription string `json:"subscription,omitempty"`
	// Ask is "subscribe" while an outbound subscription request is
	// pending, empty otherwise.
	Ask string `json:"ask,omitempty"`
}

// BlockItem is one entry of the urn:xmpp:blocking list.
type BlockItem struct {
	JID  string `json:"jid"`
	Name string `json:"name,omitempty"`
}

// SocialStore persists one account's social state. A nil store keeps
// everything in memory for the lifetime of the process.
type SocialStore interface {
	// LoadSocial returns the account's state, or an empty one when the
	// account has never had any.
	LoadSocial(ctx context.Context, accountID int64) (*Social, error)
	// SaveSocial writes the account's state.
	SaveSocial(ctx context.Context, accountID int64, s *Social) error
}

// MemSocial is the in-memory SocialStore. It is what the server uses
// when no database is configured, and what the tests use.
type MemSocial struct {
	mu   sync.Mutex
	data map[int64]*Social
}

// NewMemSocial returns an empty in-memory store.
func NewMemSocial() *MemSocial { return &MemSocial{data: map[int64]*Social{}} }

// LoadSocial implements SocialStore.
func (m *MemSocial) LoadSocial(_ context.Context, accountID int64) (*Social, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.data[accountID]; ok {
		return s.clone(), nil
	}
	return &Social{}, nil
}

// SaveSocial implements SocialStore.
func (m *MemSocial) SaveSocial(_ context.Context, accountID int64, s *Social) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[accountID] = s.clone()
	return nil
}

// clone deep-copies the state so a caller cannot mutate the stored one.
func (s *Social) clone() *Social {
	if s == nil {
		return &Social{}
	}
	out := &Social{
		Roster:  append([]RosterItem(nil), s.Roster...),
		Blocked: append([]BlockItem(nil), s.Blocked...),
	}
	for i := range out.Roster {
		out.Roster[i].Groups = append([]string(nil), s.Roster[i].Groups...)
	}
	if len(s.Notes) > 0 {
		out.Notes = make(map[int64]string, len(s.Notes))
		for k, v := range s.Notes {
			out.Notes[k] = v
		}
	}
	return out
}

// rosterIndex returns the position of jid in the roster, or -1.
func (s *Social) rosterIndex(jid string) int {
	for i := range s.Roster {
		if s.Roster[i].JID == jid {
			return i
		}
	}
	return -1
}

// putRoster inserts or replaces one roster entry.
func (s *Social) putRoster(item RosterItem) {
	if i := s.rosterIndex(item.JID); i >= 0 {
		s.Roster[i] = item
		return
	}
	s.Roster = append(s.Roster, item)
}

// removeRoster drops one roster entry and reports whether it existed.
func (s *Social) removeRoster(jid string) bool {
	i := s.rosterIndex(jid)
	if i < 0 {
		return false
	}
	s.Roster = append(s.Roster[:i], s.Roster[i+1:]...)
	return true
}

// blockIndex returns the position of jid in the block list, or -1.
func (s *Social) blockIndex(jid string) int {
	for i := range s.Blocked {
		if s.Blocked[i].JID == jid {
			return i
		}
	}
	return -1
}

// putBlock inserts or replaces one block entry.
func (s *Social) putBlock(item BlockItem) {
	if i := s.blockIndex(item.JID); i >= 0 {
		s.Blocked[i] = item
		return
	}
	s.Blocked = append(s.Blocked, item)
}

// removeBlock drops one block entry and reports whether it existed.
func (s *Social) removeBlock(jid string) bool {
	i := s.blockIndex(jid)
	if i < 0 {
		return false
	}
	s.Blocked = append(s.Blocked[:i], s.Blocked[i+1:]...)
	return true
}

// groups returns the distinct roster groups in sorted order. The client
// keeps empty groups alive across a reconnect, so the server has to
// remember them: a group exists exactly as long as some roster item
// names it.
func (s *Social) groups() []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range s.Roster {
		for _, g := range item.Groups {
			if g == "" || seen[g] {
				continue
			}
			seen[g] = true
			out = append(out, g)
		}
	}
	sort.Strings(out)
	return out
}
