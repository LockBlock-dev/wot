package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrBadCredentials is returned by Authenticate. Its text is the wire
// message the client displays, so it doubles as the status-68 body
// (login.textBadPassword).
var ErrBadCredentials = errors.New("Invalid password.")

// Config is the server's policy knobs.
type Config struct {
	// DefaultUser/DefaultPassword provision one account on startup when
	// the store is empty. This is the bootstrap path until account
	// management exists.
	DefaultUser     string
	DefaultPassword string

	// SessionTTL is how long a minted session stays valid.
	SessionTTL time.Duration

	// Logger receives structured lifecycle events (provisioning, auth
	// outcomes, session minting, sweeps). Nil means silent.
	Logger *slog.Logger
}

// Server ties the store, the session manager and the provisioning
// policy together. The CLIs talk to this, not to the pieces.
type Server struct {
	Store    Store
	Sessions *SessionManager
	cfg      Config
}

// New builds a Server over an existing store.
func New(st Store, cfg Config) *Server {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	return &Server{
		Store:    st,
		Sessions: NewSessionManager(cfg.SessionTTL),
		cfg:      cfg,
	}
}

// Provision creates the default account when it does not exist yet, and
// gives it a default player state. It is idempotent: an existing
// account is left untouched, so a restart never resets progress.
func (s *Server) Provision(ctx context.Context) error {
	if s.cfg.DefaultUser == "" {
		return nil
	}
	name := NormalizeName(s.cfg.DefaultUser)
	acct, err := s.Store.AccountByName(ctx, name)
	switch {
	case err == nil:
		// Already there: make sure it has state, then stop.
		if _, err := s.Store.LoadState(ctx, acct.ID); errors.Is(err, ErrNotFound) {
			s.log().Info("account state provisioned", "account", acct.Name, "account_id", acct.ID)
			return s.Store.SaveState(ctx, acct.ID, DefaultPlayerState(acct.ID))
		}
		s.log().Debug("default account present", "account", acct.Name, "account_id", acct.ID)
		return nil
	case !errors.Is(err, ErrNotFound):
		return fmt.Errorf("server: provision lookup: %w", err)
	}

	hash, err := HashPassword(s.cfg.DefaultPassword)
	if err != nil {
		return fmt.Errorf("server: provision hash: %w", err)
	}
	acct = &Account{Name: name, PassHash: hash}
	if err := s.Store.CreateAccount(ctx, acct); err != nil {
		return fmt.Errorf("server: provision create: %w", err)
	}
	if err := s.Store.SaveState(ctx, acct.ID, DefaultPlayerState(acct.ID)); err != nil {
		return fmt.Errorf("server: provision state: %w", err)
	}
	s.log().Info("default account created", "account", acct.Name, "account_id", acct.ID)
	return nil
}

// Authenticate checks a login against the store. It returns
// ErrBadCredentials for both an unknown account and a wrong password, so
// the wire reply does not reveal which one it was (the live server's
// short 68 wording does the same).
func (s *Server) Authenticate(ctx context.Context, user, pass string) (*Account, error) {
	acct, err := s.Store.AccountByName(ctx, user)
	if errors.Is(err, ErrNotFound) {
		s.log().Warn("login refused", "account", NormalizeName(user), "reason", "unknown account")
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("server: authenticate: %w", err)
	}
	if !acct.CheckPassword(pass) {
		s.log().Warn("login refused", "account", acct.Name, "account_id", acct.ID, "reason", "bad password")
		return nil, ErrBadCredentials
	}
	return acct, nil
}

// BeginSession authenticates and mints a session in one step, which is
// what the LoginApp needs.
func (s *Server) BeginSession(ctx context.Context, user, pass string) (*Account, *Session, error) {
	acct, err := s.Authenticate(ctx, user, pass)
	if err != nil {
		return nil, nil, err
	}
	sess, err := s.Sessions.Issue(acct.ID, acct.Name)
	if err != nil {
		return nil, nil, err
	}
	// The session key is a wire value, not a credential: it is logged so
	// a BaseApp-side event can be tied back to the login that made it.
	s.log().Info("session issued",
		"account", acct.Name, "account_id", acct.ID,
		"session", fmt.Sprintf("%08x", sess.Key), "expires", sess.Expires)
	return acct, sess, nil
}

// SweepLoop drops expired sessions every interval until ctx is done.
// Sessions are in-memory only, so without this they accumulate for the
// life of the process.
func (s *Server) SweepLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.Sessions.Sweep(); n > 0 {
				s.log().Info("sessions swept", "dropped", n, "live", s.Sessions.Len())
			}
		}
	}
}

// State loads an account's player state, provisioning a default one if
// the account has none yet.
func (s *Server) State(ctx context.Context, accountID int64) (*PlayerState, error) {
	st, err := s.Store.LoadState(ctx, accountID)
	if errors.Is(err, ErrNotFound) {
		st = DefaultPlayerState(accountID)
		if err := s.Store.SaveState(ctx, accountID, st); err != nil {
			return nil, err
		}
		s.log().Info("player state provisioned", "account_id", accountID)
		return st, nil
	}
	return st, err
}
