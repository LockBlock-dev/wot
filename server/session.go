package server

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// Session binds a wire session key to an account for the lifetime of one
// login. The LoginApp mints it; the BaseApp halves look it up by key.
type Session struct {
	Key       uint32
	AccountID int64
	Name      string
	Created   time.Time
	Expires   time.Time
}

// Expired reports whether the session is past its TTL at now.
func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.Expires)
}

// SessionManager holds live sessions in memory.
//
// Sessions are deliberately not persisted: a server restart invalidates
// them, which is what the client already expects (it re-logs in). The
// account state behind them is durable; the session is not.
type SessionManager struct {
	mu    sync.Mutex
	byKey map[uint32]*Session
	ttl   time.Duration
	now   func() time.Time
}

// NewSessionManager returns a manager whose sessions live for ttl.
func NewSessionManager(ttl time.Duration) *SessionManager {
	return &SessionManager{
		byKey: make(map[uint32]*Session),
		ttl:   ttl,
		now:   time.Now,
	}
}

// Issue mints a fresh session for the account. The key is random and
// never zero, so it cannot collide with the "no session" sentinel the
// wire uses.
func (m *SessionManager) Issue(accountID int64, name string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for attempt := 0; attempt < 8; attempt++ {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("server: session key: %w", err)
		}
		key := binary.LittleEndian.Uint32(buf[:])
		if key == 0 {
			continue
		}
		if _, taken := m.byKey[key]; taken {
			continue
		}
		s := &Session{
			Key:       key,
			AccountID: accountID,
			Name:      name,
			Created:   now,
			Expires:   now.Add(m.ttl),
		}
		m.byKey[key] = s
		return s, nil
	}
	return nil, fmt.Errorf("server: could not mint a unique session key")
}

// Get returns the live session for key, or nil when it is unknown or
// expired. An expired session is dropped on the way out.
func (m *SessionManager) Get(key uint32) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byKey[key]
	if !ok {
		return nil
	}
	if s.Expired(m.now()) {
		delete(m.byKey, key)
		return nil
	}
	return s
}

// Drop removes a session (logout, or a failed handshake).
func (m *SessionManager) Drop(key uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byKey, key)
}

// Sweep drops every expired session and reports how many went.
func (m *SessionManager) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	n := 0
	for k, s := range m.byKey {
		if s.Expired(now) {
			delete(m.byKey, k)
			n++
		}
	}
	return n
}

// Len reports the number of live sessions.
func (m *SessionManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byKey)
}
