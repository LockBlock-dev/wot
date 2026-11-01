package server

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	st := openTestStore(t)
	return New(st, Config{
		DefaultUser:     "Admin",
		DefaultPassword: "secret",
		SessionTTL:      time.Hour,
	})
}

func TestProvisionCreatesDefaultAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)

	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	acct, err := s.Store.AccountByName(ctx, "admin")
	if err != nil {
		t.Fatalf("AccountByName: %v", err)
	}
	if !acct.CheckPassword("secret") {
		t.Fatal("provisioned account does not accept its password")
	}
	st, err := s.Store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if st.Credits == 0 {
		t.Fatal("provisioned state has no credits")
	}
}

func TestProvisionIsIdempotentAndKeepsProgress(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	acct, err := s.Store.AccountByName(ctx, "admin")
	if err != nil {
		t.Fatalf("AccountByName: %v", err)
	}

	// Simulate progress, then re-provision (a restart).
	st, err := s.Store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	st.Credits = 777
	if err := s.Store.SaveState(ctx, acct.ID, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision (second): %v", err)
	}

	again, err := s.Store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadState after re-provision: %v", err)
	}
	if again.Credits != 777 {
		t.Fatalf("Credits = %d after re-provision, want 777 (progress was reset)", again.Credits)
	}
	// And no duplicate account appeared.
	if _, err := s.Store.AccountByName(ctx, "admin"); err != nil {
		t.Fatalf("AccountByName after re-provision: %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	acct, err := s.Authenticate(ctx, "ADMIN", "secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if acct.Name != "admin" {
		t.Fatalf("account name %q", acct.Name)
	}

	// Wrong password and unknown account are indistinguishable.
	if _, err := s.Authenticate(ctx, "admin", "nope"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password = %v, want ErrBadCredentials", err)
	}
	if _, err := s.Authenticate(ctx, "ghost", "secret"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown account = %v, want ErrBadCredentials", err)
	}
	// The wire text is the live server's short 68 wording.
	if ErrBadCredentials.Error() != "Invalid password." {
		t.Fatalf("ErrBadCredentials text = %q", ErrBadCredentials.Error())
	}
}

func TestBeginSessionBindsAccount(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	acct, sess, err := s.BeginSession(ctx, "admin", "secret")
	if err != nil {
		t.Fatalf("BeginSession: %v", err)
	}
	if sess.Key == 0 || sess.AccountID != acct.ID || sess.Name != "admin" {
		t.Fatalf("session %+v", sess)
	}
	got := s.Sessions.Get(sess.Key)
	if got == nil || got.AccountID != acct.ID {
		t.Fatalf("session lookup %+v", got)
	}

	// A failed login mints nothing.
	before := s.Sessions.Len()
	if _, _, err := s.BeginSession(ctx, "admin", "bad"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("bad BeginSession = %v", err)
	}
	if s.Sessions.Len() != before {
		t.Fatal("a failed login minted a session")
	}
}

func TestStateProvisionsOnDemand(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	if err := s.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	acct, err := s.Store.AccountByName(ctx, "admin")
	if err != nil {
		t.Fatalf("AccountByName: %v", err)
	}

	// A brand-new account with no state row gets one.
	fresh := &Account{Name: "fresh", PassHash: "x"}
	if err := s.Store.CreateAccount(ctx, fresh); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	st, err := s.State(ctx, fresh.ID)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.AccountID != fresh.ID || st.Credits == 0 {
		t.Fatalf("provisioned state %+v", st)
	}
	// And it is now persisted.
	if _, err := s.Store.LoadState(ctx, fresh.ID); err != nil {
		t.Fatalf("LoadState after on-demand provision: %v", err)
	}

	// The existing account's state is returned unchanged.
	orig, err := s.Store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	got, err := s.State(ctx, acct.ID)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if got.Credits != orig.Credits {
		t.Fatalf("State changed existing credits: %d vs %d", got.Credits, orig.Credits)
	}
}
