package xmppserver

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errClosed marks a session that was shut down on purpose, so the
// accept loop does not log it as a failure.
var errClosed = errors.New("xmppserver: session closed")

// Namespaces the client uses. They are the shipped constants from
// `messenger/proto/xmpp/extensions/ext_constants.pyc` (XML_NAME_SPACE)
// plus the three RFC ones.
const (
	nsClient    = "jabber:client"
	nsStream    = "http://etherx.jabber.org/streams"
	nsSASL      = "urn:ietf:params:xml:ns:xmpp-sasl"
	nsBind      = "urn:ietf:params:xml:ns:xmpp-bind"
	nsSession   = "urn:ietf:params:xml:ns:xmpp-session"
	nsRoster    = "jabber:iq:roster"
	nsDiscoInfo = "http://jabber.org/protocol/disco#info"
	nsDiscoItem = "http://jabber.org/protocol/disco#items"
	nsMUC       = "http://jabber.org/protocol/muc"
	nsMUCUser   = "http://jabber.org/protocol/muc#user"
	nsMUCOwner  = "http://jabber.org/protocol/muc#owner"
	nsBlocking  = "urn:xmpp:blocking"
	nsRSM       = "http://jabber.org/protocol/rsm"
	nsDataForms = "jabber:x:data"
	nsDelay     = "urn:xmpp:delay"
	nsStanzas   = "urn:ietf:params:xml:ns:xmpp-stanzas"

	// Wargaming extensions.
	nsWG        = "http://wargaming.net/xmpp#v2"
	nsWGClient  = "http://wargaming.net/xmpp#client"
	nsWGSPA     = "http://wargaming.net/xmpp#spa-resolver"
	nsWGStorage = "http://wargaming.net/xmpp#storage"
	nsWGMsgID   = "http://wargaming.net/xmpp#message-id"
)

// session is one client connection.
type session struct {
	srv  *Server
	conn net.Conn
	dec  *xml.Decoder

	// wmu serialises writes: MUC broadcasts and presence relays arrive
	// from other sessions' goroutines.
	wmu     sync.Mutex
	writeAt time.Time

	// dbid is the client databaseID from the JID node; accountID is the
	// store key (the same value — the social store is keyed by the id the
	// client knows itself by).
	dbid      int64
	resource  string
	fullJID   string
	bound     bool
	available bool
	// presenceInner is the raw inner XML of the last available presence,
	// replayed to contacts so the WG extension (nickname, userid, clan)
	// reaches them without this server having to model it.
	presenceInner string
	// rooms holds the bare JIDs of the MUC rooms this session is in.
	rooms map[string]bool

	closed bool
}

// close marks the session closed and drops its socket.
func (s *session) close() {
	s.wmu.Lock()
	if s.closed {
		s.wmu.Unlock()
		return
	}
	s.closed = true
	s.wmu.Unlock()
	s.conn.Close()
}

// write sends one already-rendered stanza.
func (s *session) write(x string) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.closed {
		return errClosed
	}
	s.writeAt = time.Now()
	_, err := io.WriteString(s.conn, x)
	return err
}

// run drives the connection: stream negotiation, SASL, then the stanza
// loop.
func (s *session) run() error {
	s.dec = xml.NewDecoder(s.conn)
	if err := s.negotiate(); err != nil {
		return err
	}
	return s.serve()
}

// negotiate reads the opening stream header, offers SASL and validates
// the credential.
func (s *session) negotiate() error {
	start, err := nextElement(s.dec)
	if err != nil {
		return err
	}
	if start.Name.Local != "stream" {
		return fmt.Errorf("xmpp: expected a stream open, got <%s>", start.Name.Local)
	}
	if err := s.writeStreamHeader(); err != nil {
		return err
	}
	features := tag("stream:features", [][2]string{{"xmlns:stream", nsStream}},
		tag("mechanisms", [][2]string{{"xmlns", nsSASL}},
			tag("mechanism", nil, "PLAIN")))
	if err := s.write(features); err != nil {
		return err
	}
	for {
		start, err = nextElement(s.dec)
		if err != nil {
			return err
		}
		switch start.Name.Local {
		case "auth":
			n, err := readElement(s.dec, start)
			if err != nil {
				return err
			}
			return s.authenticate(n)
		case "starttls":
			// Not offered; gloox only sends this when the server
			// advertises it, so treat it as a protocol error.
			return fmt.Errorf("xmpp: unexpected starttls")
		default:
			return fmt.Errorf("xmpp: unexpected <%s> before auth", start.Name.Local)
		}
	}
}

// writeStreamHeader emits the opening stream tag.
func (s *session) writeStreamHeader() error {
	h := `<?xml version='1.0'?><stream:stream xmlns='` + nsClient +
		`' xmlns:stream='` + nsStream + `' id='` + s.srv.cfg.Domain + `-` +
		strconv.FormatInt(time.Now().UnixNano(), 36) + `' from='` + escAttr(s.srv.cfg.Domain) +
		`' version='1.0' xml:lang='en'>`
	return s.write(h)
}

// authenticate validates one SASL PLAIN exchange.
func (s *session) authenticate(n *Node) error {
	if mech := n.Attr("mechanism"); mech != "PLAIN" {
		return s.failAuth("invalid-mechanism")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(n.Text))
	if err != nil {
		return s.failAuth("malformed-request")
	}
	// PLAIN is authzid NUL authcid NUL password.
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return s.failAuth("malformed-request")
	}
	dbid, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || dbid <= 0 {
		return s.failAuth("not-authorized")
	}
	if parts[2] != s.srv.TokenFor(dbid) {
		s.srv.logf("xmpp: auth rejected for %d (bad credential)", dbid)
		return s.failAuth("not-authorized")
	}
	s.dbid = dbid
	s.srv.logf("xmpp: %s authenticated as %d", s.conn.RemoteAddr(), dbid)
	return s.write(tag("success", [][2]string{{"xmlns", nsSASL}}, ""))
}

// failAuth sends a SASL failure and returns errClosed so the caller
// stops.
func (s *session) failAuth(cond string) error {
	_ = s.write(tag("failure", [][2]string{{"xmlns", nsSASL}}, textTag(cond, "")))
	return errClosed
}

// serve reads the post-auth stream restart, binds a resource and then
// handles stanzas until the peer goes away.
func (s *session) serve() error {
	start, err := nextElement(s.dec)
	if err != nil {
		return err
	}
	if start.Name.Local != "stream" {
		return fmt.Errorf("xmpp: expected a stream restart, got <%s>", start.Name.Local)
	}
	if err := s.writeStreamHeader(); err != nil {
		return err
	}
	features := tag("stream:features", [][2]string{{"xmlns:stream", nsStream}},
		tag("bind", [][2]string{{"xmlns", nsBind}}, "")+
			tag("session", [][2]string{{"xmlns", nsSession}}, ""))
	if err := s.write(features); err != nil {
		return err
	}
	for {
		start, err := nextElement(s.dec)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n, err := readElement(s.dec, start)
		if err != nil {
			return err
		}
		switch n.Name.Local {
		case "iq":
			if err := s.handleIQ(n); err != nil {
				return err
			}
		case "presence":
			if err := s.handlePresence(n); err != nil {
				return err
			}
		case "message":
			if err := s.handleMessage(n); err != nil {
				return err
			}
		case "auth":
			return fmt.Errorf("xmpp: re-auth after binding")
		}
	}
}

// handleIQ dispatches one info/query stanza.
func (s *session) handleIQ(n *Node) error {
	typ := n.Attr("type")
	id := n.Attr("id")
	to := n.Attr("to")
	if len(n.Children) == 0 {
		if typ == "get" || typ == "set" {
			return s.iqError(n, "service-unavailable")
		}
		return nil
	}
	payload := n.Children[0]
	switch payload.Name.Space {
	case nsBind:
		return s.handleBind(n, id, payload)
	case nsSession:
		return s.iqResult(id, to, "")
	case nsRoster:
		return s.handleRoster(n, id, typ, payload)
	case nsBlocking:
		return s.handleBlocking(n, id, typ, payload)
	case nsWGSPA:
		return s.handleSPA(n, id, typ, payload)
	case nsWGStorage:
		return s.handleNotes(n, id, typ, payload)
	case nsDiscoInfo:
		return s.handleDiscoInfo(n, id, to)
	case nsDiscoItem:
		return s.handleDiscoItems(n, id, to)
	case nsMUC, nsMUCUser, nsMUCOwner:
		return s.handleMUCIQ(n, id, typ, payload)
	}
	if typ == "get" || typ == "set" {
		return s.iqError(n, "service-unavailable")
	}
	return nil
}

// handleBind answers the resource-binding exchange.
func (s *session) handleBind(n *Node, id string, payload *Node) error {
	res := payload.TextOf(nsBind, "resource")
	if res == "" {
		res = "wot"
	}
	s.resource = res
	s.fullJID = s.srv.jid(s.dbid, res)
	s.bound = true
	s.srv.register(s)
	s.srv.logf("xmpp: %d bound as %s", s.dbid, s.fullJID)
	inner := tag("bind", [][2]string{{"xmlns", nsBind}}, textTag("jid", s.fullJID))
	return s.iqResult(id, n.Attr("to"), inner)
}

// iqResult sends an empty result for id.
func (s *session) iqResult(id, to, inner string) error {
	attrs := [][2]string{{"type", "result"}, {"id", id}}
	if to != "" {
		attrs = append(attrs, [2]string{"to", to})
	}
	return s.write(tag("iq", attrs, inner))
}

// iqError sends a stanza error for the request n.
func (s *session) iqError(n *Node, cond string) error {
	attrs := [][2]string{{"type", "error"}, {"id", n.Attr("id")}}
	if to := n.Attr("from"); to != "" {
		attrs = append(attrs, [2]string{"to", to})
	}
	inner := renderNode(n.Children[0]) +
		tag("error", [][2]string{{"type", "cancel"}}, textTag(cond, ""))
	return s.write(tag("iq", attrs, inner))
}

// handlePresence handles availability, subscription and MUC presence.
func (s *session) handlePresence(n *Node) error {
	to := n.Attr("to")
	typ := n.Attr("type")
	if to != "" && s.isRoomJID(to) {
		return s.handleMUCPresence(n, to)
	}
	switch typ {
	case "subscribe", "subscribed", "unsubscribe", "unsubscribed":
		return s.handleSubscription(n, typ)
	case "unavailable":
		s.available = false
		s.presenceInner = ""
		s.broadcastPresence(nil)
		return nil
	}
	// Available: remember the client's own children (priority, show,
	// status, the wgexts-client block). The identity extension is NOT
	// among them — the client's PresenceQuery only carries
	// WgClientExtension — so the server authors the `wgexts` block that
	// tells contacts who this is (see presenceFor).
	var inner strings.Builder
	for _, c := range n.Children {
		if c.Name.Space == nsWG {
			continue
		}
		inner.WriteString(renderNode(c))
	}
	s.presenceInner = inner.String()
	s.available = true
	s.broadcastPresence(nil)
	// Send the contacts' current presence back, so the roster shows who
	// is online without waiting for a change.
	s.sendContactPresence()
	return nil
}

// broadcastPresence relays this session's presence to every roster
// contact that is online. skip, when non-nil, is not sent to.
func (s *session) broadcastPresence(skip *session) {
	st, err := s.srv.loadSocial(context.Background(), s.dbid)
	if err != nil {
		return
	}
	for _, item := range st.Roster {
		peer := s.srv.sessionFor(dbidOf(item.JID))
		if peer == nil || peer == s || peer == skip || !peer.available {
			continue
		}
		_ = peer.write(s.presenceFor(peer))
	}
}

// presenceFor renders this session's presence addressed to peer.
//
// The identity extension is authored here rather than relayed: the
// client's own presence carries only `wgexts-client` (igr-id, game-host,
// arena-label), while the receiving side reads `nickname`, `userid`,
// `clanid` and `clantag` out of `wgexts`
// (`messenger/proto/xmpp/extensions/wg_items.pyc` WgSharedExtension).
// Without it every contact shows up as an unnamed, clan-less user.
func (s *session) presenceFor(peer *session) string {
	attrs := [][2]string{{"from", s.fullJID}, {"to", peer.fullJID}}
	if !s.available {
		attrs = append(attrs, [2]string{"type", "unavailable"})
		return tag("presence", attrs, "")
	}
	return tag("presence", attrs, s.srv.wgIdentity(s.dbid)+s.presenceInner)
}

// wgIdentity renders the `wgexts` block that identifies one account to
// its contacts.
func (s *Server) wgIdentity(dbid int64) string {
	inner := textTag("nickname", s.nickname(dbid)) +
		textTag("userid", strconv.FormatInt(dbid, 10))
	if clan := s.clan(dbid); clan != nil {
		inner += textTag("clanid", strconv.FormatInt(clan.DBID, 10)) +
			textTag("clantag", clan.Abbrev)
	}
	return tag("wgexts", [][2]string{{"xmlns", nsWG}}, inner)
}

// sendContactPresence pushes every online contact's presence to this
// session.
func (s *session) sendContactPresence() {
	st, err := s.srv.loadSocial(context.Background(), s.dbid)
	if err != nil {
		return
	}
	for _, item := range st.Roster {
		peer := s.srv.sessionFor(dbidOf(item.JID))
		if peer == nil || peer == s || !peer.available {
			continue
		}
		_ = s.write(peer.presenceFor(s))
	}
}

// handleSubscription relays a subscription stanza to its target and
// records the resulting roster state.
func (s *session) handleSubscription(n *Node, typ string) error {
	target := dbidOf(n.Attr("to"))
	if target == 0 {
		return nil
	}
	ctx := context.Background()
	// Our own side of the relationship.
	own, err := s.srv.loadSocial(ctx, s.dbid)
	if err != nil {
		return nil
	}
	ownJID := s.srv.bareJID(s.dbid)
	switch typ {
	case "subscribe":
		item := RosterItem{JID: s.srv.bareJID(target), Name: s.srv.nickname(target), Ask: "subscribe"}
		if i := own.rosterIndex(item.JID); i >= 0 {
			item.Groups = own.Roster[i].Groups
			item.Subscription = own.Roster[i].Subscription
		}
		own.putRoster(item)
	case "unsubscribe", "unsubscribed":
		if i := own.rosterIndex(s.srv.bareJID(target)); i >= 0 {
			own.Roster[i].Ask = ""
			if typ == "unsubscribed" {
				own.Roster[i].Subscription = downgradeSub(own.Roster[i].Subscription, "from")
			} else {
				own.Roster[i].Subscription = downgradeSub(own.Roster[i].Subscription, "to")
			}
		}
	}
	_ = s.srv.saveSocial(ctx, s.dbid, own)
	// The target's side.
	peer, err := s.srv.loadSocial(ctx, target)
	if err == nil {
		switch typ {
		case "subscribe":
			peer.putRoster(RosterItem{JID: ownJID, Name: s.srv.nickname(s.dbid)})
		case "subscribed":
			if i := peer.rosterIndex(ownJID); i >= 0 {
				peer.Roster[i].Subscription = upgradeSub(peer.Roster[i].Subscription, "from")
				peer.Roster[i].Ask = ""
			}
		case "unsubscribed":
			if i := peer.rosterIndex(ownJID); i >= 0 {
				peer.Roster[i].Subscription = downgradeSub(peer.Roster[i].Subscription, "to")
			}
		}
		_ = s.srv.saveSocial(ctx, target, peer)
	}
	// Relay the stanza itself.
	if sess := s.srv.sessionFor(target); sess != nil {
		attrs := [][2]string{{"from", s.fullJID}, {"to", sess.fullJID}, {"type", typ}}
		_ = sess.write(tag("presence", attrs, ""))
	}
	return nil
}

// upgradeSub adds one direction to a subscription state.
func upgradeSub(sub, dir string) string {
	switch sub {
	case "both":
		return "both"
	case "to":
		if dir == "from" {
			return "both"
		}
		return "to"
	case "from":
		if dir == "to" {
			return "both"
		}
		return "from"
	}
	return dir
}

// downgradeSub removes one direction from a subscription state.
func downgradeSub(sub, dir string) string {
	switch sub {
	case "both":
		if dir == "from" {
			return "to"
		}
		return "from"
	case "to":
		if dir == "to" {
			return "none"
		}
	case "from":
		if dir == "from" {
			return "none"
		}
	}
	return sub
}

// handleMessage routes a chat or groupchat stanza.
func (s *session) handleMessage(n *Node) error {
	to := n.Attr("to")
	if to == "" {
		return nil
	}
	if s.isRoomJID(to) {
		return s.handleMUCMessage(n, to)
	}
	target := dbidOf(to)
	if target == 0 {
		return nil
	}
	peer := s.srv.sessionFor(target)
	if peer == nil {
		return s.write(tag("message", [][2]string{
			{"from", to}, {"to", s.fullJID}, {"type", "error"},
		}, tag("error", [][2]string{{"type", "cancel"}}, textTag("service-unavailable", ""))))
	}
	attrs := [][2]string{{"from", s.fullJID}, {"to", peer.fullJID}}
	if typ := n.Attr("type"); typ != "" {
		attrs = append(attrs, [2]string{"type", typ})
	}
	if id := n.Attr("id"); id != "" {
		attrs = append(attrs, [2]string{"id", id})
	}
	var inner strings.Builder
	for _, c := range n.Children {
		inner.WriteString(renderNode(c))
	}
	return peer.write(tag("message", attrs, inner.String()))
}

// renderNode re-renders a parsed element with its namespace declared, so
// a relayed stanza keeps the extensions the client sent.
func renderNode(n *Node) string {
	if n == nil {
		return ""
	}
	attrs := make([][2]string, 0, len(n.Attrs)+1)
	if n.Name.Space != "" {
		attrs = append(attrs, [2]string{"xmlns", n.Name.Space})
	}
	for _, a := range n.Attrs {
		// The namespace is re-declared from Name.Space above, so the
		// original declaration would be a duplicate attribute.
		if a.Name.Space != "" || a.Name.Local == "xmlns" {
			continue
		}
		attrs = append(attrs, [2]string{a.Name.Local, a.Value})
	}
	var inner strings.Builder
	if n.Text != "" {
		inner.WriteString(escText(n.Text))
	}
	for _, c := range n.Children {
		inner.WriteString(renderNode(c))
	}
	return tag(n.Name.Local, attrs, inner.String())
}
