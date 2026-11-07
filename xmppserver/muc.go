package xmppserver

import (
	"strings"
	"sync"
)

// room is one MUC channel: the clan channel, a user room, or a private
// channel the client created.
//
// The client's `messenger/proto/xmpp/messages/muc.pyc` joins with a
// standard XEP-0045 presence and expects the occupant list back as
// presence stanzas from `room@host/nick`, so the room only has to keep
// the occupant set and fan out.
type room struct {
	jid   string // bare room JID
	mu    sync.Mutex
	occup map[string]*session // by nickname
	order []string            // join order, so the occupant list is stable
}

// newRoom returns an empty room.
func newRoom(jid string) *room {
	return &room{jid: jid, occup: map[string]*session{}}
}

// isRoomJID reports whether to addresses one of the configured MUC
// hosts.
func (s *session) isRoomJID(to string) bool {
	host := domainOf(to)
	for _, h := range s.srv.mucHosts() {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// mucHosts returns the configured MUC service hosts.
func (s *Server) mucHosts() []string {
	if len(s.cfg.MUCHosts) > 0 {
		return s.cfg.MUCHosts
	}
	return []string{"rooms." + s.cfg.Domain, "clans." + s.cfg.Domain}
}

// roomFor returns the room for a bare JID, creating it on first use.
func (s *Server) roomFor(jid string) *room {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rooms[jid]
	if !ok {
		r = newRoom(jid)
		s.rooms[jid] = r
	}
	return r
}

// dropRoomIfEmpty removes a room once its last occupant leaves, so a
// rejoin starts from a clean occupant list.
func (s *Server) dropRoomIfEmpty(jid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rooms[jid]
	if !ok {
		return
	}
	r.mu.Lock()
	empty := len(r.occup) == 0
	r.mu.Unlock()
	if empty {
		delete(s.rooms, jid)
	}
}

// handleMUCPresence joins or leaves a room.
func (s *session) handleMUCPresence(n *Node, to string) error {
	bare := to
	nick := resourceOf(to)
	if i := strings.IndexByte(bare, '/'); i >= 0 {
		bare = bare[:i]
	}
	if nick == "" {
		nick = s.srv.nickname(s.dbid)
	}
	r := s.srv.roomFor(bare)
	if n.Attr("type") == "unavailable" {
		return s.leaveRoom(r, nick)
	}
	return s.joinRoom(r, nick)
}

// joinRoom adds this session to r and exchanges the occupant lists.
func (s *session) joinRoom(r *room, nick string) error {
	r.mu.Lock()
	// A rejoin with the same nick replaces the old session.
	r.occup[nick] = s
	if !containsStr(r.order, nick) {
		r.order = append(r.order, nick)
	}
	existing := append([]string(nil), r.order...)
	r.mu.Unlock()

	if s.rooms == nil {
		s.rooms = map[string]bool{}
	}
	s.rooms[r.jid] = true

	// The joining session sees every occupant, itself last (XEP-0045
	// §7.2.2), each with the muc#user item that carries the affiliation.
	for _, other := range existing {
		if other == nick {
			continue
		}
		if err := s.write(occupantPresence(r.jid, other, nick, s.srv.nickname(s.dbid))); err != nil {
			return err
		}
	}
	if err := s.write(occupantPresence(r.jid, nick, nick, s.srv.nickname(s.dbid))); err != nil {
		return err
	}
	// The room's subject, so the channel header is not blank.
	_ = s.write(tag("message", [][2]string{{"from", r.jid}, {"to", s.fullJID}, {"type", "groupchat"}},
		textTag("subject", "")))

	// Everyone already inside sees the newcomer.
	r.mu.Lock()
	others := make([]*session, 0, len(r.occup))
	for other, sess := range r.occup {
		if other != nick && sess != s {
			others = append(others, sess)
		}
	}
	r.mu.Unlock()
	for _, sess := range others {
		_ = sess.write(occupantPresence(r.jid, nick, sess.nickIn(r.jid), s.srv.nickname(s.dbid)))
	}
	s.srv.logf("xmpp: %d joined %s as %s (%d inside)", s.dbid, r.jid, nick, len(existing))
	return nil
}

// leaveRoom removes this session from r and tells the occupants.
func (s *session) leaveRoom(r *room, nick string) error {
	r.mu.Lock()
	if cur, ok := r.occup[nick]; ok && cur == s {
		delete(r.occup, nick)
		r.order = removeStr(r.order, nick)
	}
	others := make([]*session, 0, len(r.occup))
	for _, sess := range r.occup {
		others = append(others, sess)
	}
	r.mu.Unlock()
	delete(s.rooms, r.jid)
	for _, sess := range others {
		_ = sess.write(tag("presence", [][2]string{
			{"from", r.jid + "/" + nick}, {"to", sess.fullJID}, {"type", "unavailable"},
		}, tag("x", [][2]string{{"xmlns", nsMUCUser}},
			tag("item", [][2]string{{"affiliation", "none"}, {"role", "none"}}, ""))))
	}
	s.srv.dropRoomIfEmpty(r.jid)
	return nil
}

// nickIn returns the nickname this session uses in a room, or its
// account name.
func (s *session) nickIn(roomJID string) string {
	s.srv.mu.Lock()
	r := s.srv.rooms[roomJID]
	s.srv.mu.Unlock()
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		for nick, sess := range r.occup {
			if sess == s {
				return nick
			}
		}
	}
	return s.srv.nickname(s.dbid)
}

// occupantPresence renders one occupant's presence as seen by viewer.
func occupantPresence(roomJID, nick, viewer, realName string) string {
	item := tag("item", [][2]string{{"affiliation", "member"}, {"role", "participant"}},
		textTag("reason", ""))
	inner := tag("x", [][2]string{{"xmlns", nsMUCUser}}, item)
	if realName != "" {
		inner += tag("wgexts", [][2]string{{"xmlns", nsWG}}, textTag("nickname", realName))
	}
	return tag("presence", [][2]string{
		{"from", roomJID + "/" + nick},
		{"to", viewer},
	}, inner)
}

// handleMUCMessage fans a groupchat message out to the room.
func (s *session) handleMUCMessage(n *Node, to string) error {
	bare := to
	if i := strings.IndexByte(bare, '/'); i >= 0 {
		bare = bare[:i]
	}
	s.srv.mu.Lock()
	r := s.srv.rooms[bare]
	s.srv.mu.Unlock()
	if r == nil {
		return s.write(tag("message", [][2]string{
			{"from", to}, {"to", s.fullJID}, {"type", "error"},
		}, tag("error", [][2]string{{"type", "cancel"}}, textTag("item-not-found", ""))))
	}
	nick := s.nickIn(bare)
	var inner strings.Builder
	for _, c := range n.Children {
		inner.WriteString(renderNode(c))
	}
	out := tag("message", [][2]string{
		{"from", bare + "/" + nick},
		{"type", "groupchat"},
	}, inner.String())
	r.mu.Lock()
	occupants := make([]*session, 0, len(r.occup))
	for _, sess := range r.occup {
		occupants = append(occupants, sess)
	}
	r.mu.Unlock()
	for _, sess := range occupants {
		_ = sess.write(out)
	}
	return nil
}

// handleMUCIQ answers the room's owner/config queries. The client asks
// for the configuration form on join; an empty form is enough for it to
// treat the room as configured.
func (s *session) handleMUCIQ(n *Node, id, typ string, payload *Node) error {
	if payload.Name.Space != nsMUCOwner {
		return s.iqResult(id, n.Attr("to"), "")
	}
	if typ != "get" {
		return s.iqResult(id, n.Attr("to"), "")
	}
	form := tag("x", [][2]string{{"xmlns", nsDataForms}, {"type", "form"}},
		tag("field", [][2]string{{"var", "FORM_TYPE"}, {"type", "hidden"}},
			textTag("value", nsMUCOwner)))
	return s.iqResult(id, n.Attr("to"),
		tag("query", [][2]string{{"xmlns", nsMUCOwner}}, form))
}

// containsStr reports whether list holds s.
func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// removeStr drops the first occurrence of s from list.
func removeStr(list []string, s string) []string {
	for i, v := range list {
		if v == s {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}
