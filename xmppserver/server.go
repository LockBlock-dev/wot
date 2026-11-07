// Package xmppserver is the private server's XMPP chat service: the
// transport the client's contacts list, private messages, clan channel
// and system channels ride on.
//
// Why this exists at all: in 2.4 the friends list is XMPP-only.
// `messenger/proto/__init__.pyc` `ServerSettings.useToShowContacts`
// returns true for PROTO_TYPE.XMPP exactly when `xmpp_enabled` is set in
// the server-settings document, and the legacy BW fallback calls
// `BigWorld.player().addFriend(...)` / `requestUsersRoster()`, methods
// that do not exist in the 2.4 entity defs — so with XMPP off the
// contacts UI can never populate. The client's own transport is
// `BigWorld.XmppClient`, a gloox wrapper, so the wire is plain XMPP:
// stream negotiation, SASL PLAIN, resource binding, jabber:iq:roster,
// presence, XEP-0045 MUC and the Wargaming extensions
// (`http://wargaming.net/xmpp#v2` and friends).
//
// The package is a server: it owns sockets. The offline builders and
// parsers stay in wot/xmpp, which performs no I/O.
package xmppserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is what the server needs to run.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:5222".
	Addr string
	// Domain is the XMPP domain the client's JIDs use. It must match
	// `xmpp_host` in the server-settings document, because the client
	// builds `dbid@domain/resource` and gloox checks the stream's `to`.
	Domain string
	// Secret keys the per-account credential (see TokenFor). The BaseApp
	// hands the same value to the client as its XMPPCS token, so the
	// password the client sends is the one this server expects.
	Secret []byte
	// Store persists social state. Nil keeps it in memory.
	Store SocialStore
	// Nickname resolves a client databaseID to the account's display
	// name. Nil falls back to the bare databaseID.
	Nickname func(dbid int64) string
	// Clan returns the account's clan, or nil. It drives the clan MUC
	// channel and the `clanid`/`clantag` presence extension.
	Clan func(dbid int64) *Clan
	// MUCHosts are the conference service hosts. They must match
	// `xmpp_muc_services` in the server-settings document, because the
	// client joins `room@<hostname>/<nick>` with the hostname it was
	// given. Empty defaults to rooms.<domain> and clans.<domain>.
	MUCHosts []string
	// Logf receives one line per notable event. Nil discards.
	Logf func(format string, args ...any)
}

// Clan is the slice of clan data the chat layer needs.
type Clan struct {
	DBID    int64
	Abbrev  string
	Name    string
	Members []int64
}

// Server is the running XMPP service.
type Server struct {
	cfg Config

	mu       sync.Mutex
	ln       net.Listener
	sessions map[int64]*session // by client databaseID
	rooms    map[string]*room   // by bare room JID
	store    SocialStore
	closed   bool
}

// New returns a server for cfg. It does not listen yet.
func New(cfg Config) *Server {
	if cfg.Store == nil {
		cfg.Store = NewMemSocial()
	}
	if cfg.Domain == "" {
		cfg.Domain = "localhost"
	}
	return &Server{
		cfg:      cfg,
		sessions: map[int64]*session{},
		rooms:    map[string]*room{},
		store:    cfg.Store,
	}
}

// logf writes one line when a logger is configured.
func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// TokenFor returns the XMPP credential for a client databaseID: a
// per-run HMAC of the id, so the BaseApp can hand it out and this
// server can check it without either side holding shared mutable state.
func (s *Server) TokenFor(dbid int64) string {
	mac := hmac.New(sha256.New, s.cfg.Secret)
	fmt.Fprintf(mac, "xmpp:%d", dbid)
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// Addr reports the bound address, or "" before Listen.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Listen binds the configured address.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("xmppserver: listen %s: %w", s.cfg.Addr, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	return nil
}

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
		s.mu.Lock()
		ln = s.ln
		s.mu.Unlock()
	}
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("xmppserver: accept: %w", err)
		}
		go s.serveConn(conn)
	}
}

// Close stops the listener and drops every session.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	sessions := make([]*session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, sess := range sessions {
		sess.close()
	}
	return nil
}

// serveConn runs one connection's session.
func (s *Server) serveConn(conn net.Conn) {
	sess := &session{srv: s, conn: conn, writeAt: time.Now()}
	defer func() {
		sess.close()
		conn.Close()
	}()
	if err := sess.run(); err != nil && !errors.Is(err, errClosed) {
		s.logf("xmpp: %s: %v", conn.RemoteAddr(), err)
	}
}

// register adds a bound session, replacing any earlier one for the same
// account (the client reconnects without closing the old socket first).
func (s *Server) register(sess *session) *session {
	s.mu.Lock()
	prev := s.sessions[sess.dbid]
	s.sessions[sess.dbid] = sess
	s.mu.Unlock()
	if prev != nil && prev != sess {
		prev.close()
	}
	return prev
}

// unregister drops a session if it is still the registered one.
func (s *Server) unregister(sess *session) {
	s.mu.Lock()
	if s.sessions[sess.dbid] == sess {
		delete(s.sessions, sess.dbid)
	}
	s.mu.Unlock()
}

// sessionFor returns the live session for a databaseID, or nil.
func (s *Server) sessionFor(dbid int64) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[dbid]
}

// online reports whether the account has a bound session.
func (s *Server) online(dbid int64) bool { return s.sessionFor(dbid) != nil }

// nickname renders the display name for a databaseID.
func (s *Server) nickname(dbid int64) string {
	if s.cfg.Nickname != nil {
		if n := s.cfg.Nickname(dbid); n != "" {
			return n
		}
	}
	return strconv.FormatInt(dbid, 10)
}

// clan returns the account's clan, or nil.
func (s *Server) clan(dbid int64) *Clan {
	if s.cfg.Clan == nil {
		return nil
	}
	return s.cfg.Clan(dbid)
}

// jid renders a full JID for a databaseID and resource.
func (s *Server) jid(dbid int64, resource string) string {
	j := strconv.FormatInt(dbid, 10) + "@" + s.cfg.Domain
	if resource != "" {
		j += "/" + resource
	}
	return j
}

// bareJID renders the bare JID for a databaseID.
func (s *Server) bareJID(dbid int64) string { return s.jid(dbid, "") }

// dbidOf extracts the numeric node of a JID, or 0 when it is not one.
func dbidOf(jid string) int64 {
	node := jid
	if i := strings.IndexByte(node, '/'); i >= 0 {
		node = node[:i]
	}
	if i := strings.IndexByte(node, '@'); i >= 0 {
		node = node[:i]
	}
	n, err := strconv.ParseInt(node, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// domainOf extracts the domain part of a JID.
func domainOf(jid string) string {
	rest := jid
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		return rest[i+1:]
	}
	return rest
}

// resourceOf extracts the resource part of a JID, or "".
func resourceOf(jid string) string {
	if i := strings.IndexByte(jid, '/'); i >= 0 {
		return jid[i+1:]
	}
	return ""
}

// loadSocial reads one account's social state.
func (s *Server) loadSocial(ctx context.Context, accountID int64) (*Social, error) {
	st, err := s.store.LoadSocial(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = &Social{}
	}
	return st, nil
}

// saveSocial writes one account's social state.
func (s *Server) saveSocial(ctx context.Context, accountID int64, st *Social) error {
	return s.store.SaveSocial(ctx, accountID, st)
}
