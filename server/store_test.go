package server

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSQLiteAccountLifecycle(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	a := &Account{Name: "  PlayerOne ", PassHash: hash, Roles: []string{"admin"}}
	if err := st.CreateAccount(ctx, a); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if a.ID == 0 {
		t.Fatal("CreateAccount did not fill ID")
	}
	if a.Name != "playerone" {
		t.Fatalf("name not normalized: %q", a.Name)
	}

	// Lookup is case-insensitive and trims.
	got, err := st.AccountByName(ctx, "PLAYERONE")
	if err != nil {
		t.Fatalf("AccountByName: %v", err)
	}
	if got.ID != a.ID || !got.HasRole("admin") {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if !got.CheckPassword("hunter2") {
		t.Fatal("CheckPassword rejected the right password")
	}
	if got.CheckPassword("wrong") {
		t.Fatal("CheckPassword accepted a wrong password")
	}

	byID, err := st.AccountByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("AccountByID: %v", err)
	}
	if byID.Name != "playerone" {
		t.Fatalf("AccountByID name = %q", byID.Name)
	}

	// Duplicate name (any casing) is ErrExists.
	dup := &Account{Name: "PlayerOne", PassHash: hash}
	if err := st.CreateAccount(ctx, dup); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate CreateAccount = %v, want ErrExists", err)
	}

	// Missing lookups are ErrNotFound.
	if _, err := st.AccountByName(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing AccountByName = %v, want ErrNotFound", err)
	}
	if _, err := st.AccountByID(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing AccountByID = %v, want ErrNotFound", err)
	}

	// Update rewrites the hash.
	newHash, err := HashPassword("correcthorse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	a.PassHash = newHash
	if err := st.UpdateAccount(ctx, a); err != nil {
		t.Fatalf("UpdateAccount: %v", err)
	}
	got, err = st.AccountByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("AccountByID after update: %v", err)
	}
	if !got.CheckPassword("correcthorse") || got.CheckPassword("hunter2") {
		t.Fatal("UpdateAccount did not replace the password hash")
	}
}

func TestSQLiteStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	a := &Account{Name: "stateful", PassHash: hash}
	if err := st.CreateAccount(ctx, a); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	// No state yet.
	if _, err := st.LoadState(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadState before save = %v, want ErrNotFound", err)
	}

	want := DefaultPlayerState(a.ID)
	want.Garage = []GarageVehicle{{CompactDescr: []byte{0x11, 0x02}, XP: 1234}}
	want.Research = [][]byte{{0x11, 0x03}}
	if err := st.SaveState(ctx, a.ID, want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	got, err := st.LoadState(ctx, a.ID)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.Credits != want.Credits || got.Gold != want.Gold || got.FreeXP != want.FreeXP {
		t.Fatalf("economy mismatch: got %+v want %+v", got, want)
	}
	if len(got.Garage) != 1 || got.Garage[0].XP != 1234 ||
		string(got.Garage[0].CompactDescr) != string([]byte{0x11, 0x02}) {
		t.Fatalf("garage mismatch: %+v", got.Garage)
	}
	if len(got.Research) != 1 || string(got.Research[0]) != string([]byte{0x11, 0x03}) {
		t.Fatalf("research mismatch: %+v", got.Research)
	}

	// Second save updates in place rather than duplicating.
	got.Credits = 42
	if err := st.SaveState(ctx, a.ID, got); err != nil {
		t.Fatalf("SaveState (update): %v", err)
	}
	again, err := st.LoadState(ctx, a.ID)
	if err != nil {
		t.Fatalf("LoadState after update: %v", err)
	}
	if again.Credits != 42 {
		t.Fatalf("Credits = %d, want 42", again.Credits)
	}
}

func TestSessionManager(t *testing.T) {
	m := NewSessionManager(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return now }

	_, s, err := m.Issue(7, "playerone")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if s.Key == 0 {
		t.Fatal("session key must never be zero")
	}
	if got := m.Get(s.Key); got == nil || got.AccountID != 7 {
		t.Fatalf("Get = %+v", got)
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1", m.Len())
	}

	// Keys are unique across issues.
	seen := map[uint32]bool{s.Key: true}
	for i := 0; i < 64; i++ {
		_, o, err := m.Issue(int64(i), "x")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[o.Key] {
			t.Fatalf("duplicate session key %d", o.Key)
		}
		seen[o.Key] = true
	}

	// Expiry: past the TTL the session is gone and dropped.
	now = now.Add(2 * time.Hour)
	if got := m.Get(s.Key); got != nil {
		t.Fatalf("expired session still returned: %+v", got)
	}
	if m.Len() != 64 {
		t.Fatalf("Len after expiry = %d, want 64", m.Len())
	}

	// Sweep clears the rest.
	if n := m.Sweep(); n != 64 {
		t.Fatalf("Sweep = %d, want 64", n)
	}
	if m.Len() != 0 {
		t.Fatalf("Len after sweep = %d, want 0", m.Len())
	}

	// Drop is idempotent.
	m.Drop(s.Key)
	m.Drop(s.Key)
}

func TestNormalizeName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"PlayerOne", "playerone"},
		{"  spaced  ", "spaced"},
		{"", ""},
		{"MiXeD", "mixed"},
	} {
		if got := NormalizeName(c.in); got != c.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
