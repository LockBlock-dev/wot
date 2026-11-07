package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/LockBlock-dev/wot/login"
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
	if !LoginNameValid(name) {
		// The client's login form only accepts an email-shaped name, so
		// this account can never be typed in. Say so once, loudly.
		s.log().Warn("default account name is not a login the client accepts",
			"account", name,
			"hint", "the login form requires an email, e.g. admin@wot.test")
	}
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
	replaced, sess, err := s.Sessions.Issue(acct.ID, acct.Name)
	if err != nil {
		return nil, nil, err
	}
	// The session key is a wire value, not a credential: it is logged so
	// a BaseApp-side event can be tied back to the login that made it.
	attrs := []any{
		"account", acct.Name, "account_id", acct.ID,
		"session", fmt.Sprintf("%08x", sess.Key), "expires", sess.Expires,
	}
	if replaced != nil {
		// A reconnect: the client re-logged in and took over the account.
		attrs = append(attrs, "replaced", fmt.Sprintf("%08x", replaced.Key))
		s.log().Info("session reissued", attrs...)
	} else {
		s.log().Info("session issued", attrs...)
	}
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
	if err != nil {
		return nil, err
	}
	// A state written before a field existed decodes to its zero value,
	// and zero is not a valid capacity: `stats.berths = 0` reads as "no
	// free beds" and the barracks refuses every crew action. Fill the
	// capacities in on read, so an old database keeps working.
	if st.Berths <= 0 {
		st.Berths = DefaultBerths
	}
	if st.PremiumExpiry <= 0 {
		st.PremiumExpiry = MaxPremiumExpiry
	}
	return st, nil
}

// SeedGarage replaces an account's garage with the given vehicles and
// raises its slot count to fit them, so the client's own capacity check
// (`itemsCache.items.inventory.getFreeSlots(stats.vehicleSlots)`) never
// reports a full garage.
//
// It is a REPLACE, not a merge: the point is a known, reproducible garage,
// and merging would leave whatever a previous seed put there. The slot
// count keeps a margin above the vehicle count so buying one more still
// fits.
func (s *Server) SeedGarage(ctx context.Context, accountID int64, vehicles []GarageVehicle) (*PlayerState, error) {
	st, err := s.State(ctx, accountID)
	if err != nil {
		return nil, err
	}
	// The crew survives a re-seed: the assignment is the player's, not the
	// seed's, and a restart must not empty every tank. It is carried over by
	// compact descriptor rather than by index, because the generated list
	// can gain or lose vehicles between builds.
	crew := make(map[string][]int64, len(st.Garage))
	shells := make(map[string][]int64, len(st.Garage))
	eqs := make(map[string][]int64, len(st.Garage))
	for _, v := range st.Garage {
		if len(v.Crew) > 0 {
			crew[string(v.CompactDescr)] = v.Crew
		}
		if len(v.Shells) > 0 {
			shells[string(v.CompactDescr)] = v.Shells
		}
		if len(v.Eqs) > 0 {
			eqs[string(v.CompactDescr)] = v.Eqs
		}
	}
	for i := range vehicles {
		key := string(vehicles[i].CompactDescr)
		if kept, ok := crew[key]; ok {
			// A list stored before the slot count was known can be short;
			// the client rejects any length but the vehicle's own.
			vehicles[i].Crew = login.PadCrew(kept, vehicles[i].CrewSize)
		}
		// The ammo and consumables layouts are the player's too.
		vehicles[i].Shells = shells[key]
		vehicles[i].Eqs = eqs[key]
	}
	st.Garage = vehicles
	if want := int64(len(vehicles)) + GarageSlotMargin; st.Slots < want {
		st.Slots = want
	}
	if err := s.Store.SaveState(ctx, accountID, st); err != nil {
		return nil, err
	}
	s.log().Info("garage seeded", "account_id", accountID, "vehicles", len(vehicles), "slots", st.Slots)
	return st, nil
}

// GarageSlotMargin is the headroom SeedGarage leaves above the vehicle
// count, so the garage never reads as full.
const GarageSlotMargin = 100
