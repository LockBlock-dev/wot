package server

import (
	"testing"
	"time"
)

// TestReconnectReplacesSession pins the reconnect contract: one live
// session per account, the old key stops working, and the manager does
// not grow when a client re-logs in repeatedly.
func TestReconnectReplacesSession(t *testing.T) {
	m := NewSessionManager(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }

	replaced, first, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	if replaced != nil {
		t.Fatalf("first issue reported a replacement: %+v", replaced)
	}

	// A reconnect: same account, new key.
	replaced, second, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	if replaced == nil || replaced.Key != first.Key {
		t.Fatalf("reconnect did not report the old session: %+v", replaced)
	}
	if second.Key == first.Key {
		t.Fatal("reconnect reused the session key")
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d after reconnect, want 1", m.Len())
	}
	if got := m.Get(first.Key); got != nil {
		t.Fatalf("old key still resolves: %+v", got)
	}
	if got := m.Get(second.Key); got == nil || got.AccountID != 7 {
		t.Fatalf("new key does not resolve: %+v", got)
	}

	// A reconnect loop must not accumulate sessions.
	for i := 0; i < 50; i++ {
		if _, _, err := m.Issue(7, "playerone"); err != nil {
			t.Fatal(err)
		}
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d after 50 reconnects, want 1", m.Len())
	}
}

// TestDropKeepsNewerSession guards the account index: dropping a stale
// key must not unregister the session that replaced it.
func TestDropKeepsNewerSession(t *testing.T) {
	m := NewSessionManager(time.Hour)
	_, first, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	m.Drop(first.Key) // stale key, already replaced
	if got := m.Get(second.Key); got == nil {
		t.Fatal("dropping the stale key removed the live session")
	}
	m.Drop(second.Key)
	if m.Len() != 0 {
		t.Fatalf("Len = %d after dropping the live session, want 0", m.Len())
	}
	// The account is free again: the next issue is not a takeover.
	replaced, _, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	if replaced != nil {
		t.Fatalf("issue after drop reported a replacement: %+v", replaced)
	}
}

// TestSweepClearsAccountIndex keeps the index consistent with expiry.
func TestSweepClearsAccountIndex(t *testing.T) {
	m := NewSessionManager(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }
	if _, _, err := m.Issue(7, "playerone"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if n := m.Sweep(); n != 1 {
		t.Fatalf("Sweep dropped %d, want 1", n)
	}
	replaced, _, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatal(err)
	}
	if replaced != nil {
		t.Fatalf("swept session still indexed: %+v", replaced)
	}
}
