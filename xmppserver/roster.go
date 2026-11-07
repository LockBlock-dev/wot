package xmppserver

import (
	"context"
	"strconv"
	"strings"
)

// handleRoster answers jabber:iq:roster get/set.
//
// The client's `RosterResultTask` sends the get on connect and
// `AddRosterItemTask`/`RemoveRosterItemTask`/`ChangeRosterItemGroupsTask`
// send the set; every set must be answered with a result AND pushed to
// the account's other sessions, which is how gloox's `onNewRosterItem`
// fires.
func (s *session) handleRoster(n *Node, id, typ string, payload *Node) error {
	ctx := context.Background()
	st, err := s.srv.loadSocial(ctx, s.dbid)
	if err != nil {
		return s.iqError(n, "internal-server-error")
	}
	switch typ {
	case "get":
		return s.iqResult(id, n.Attr("to"), rosterQuery(st))
	case "set":
		item := payload.Child(nsRoster, "item")
		if item == nil {
			return s.iqError(n, "bad-request")
		}
		jid := item.Attr("jid")
		if jid == "" {
			return s.iqError(n, "bad-request")
		}
		if item.Attr("subscription") == "remove" {
			st.removeRoster(jid)
		} else {
			entry := RosterItem{
				JID:  jid,
				Name: item.Attr("name"),
				Ask:  item.Attr("ask"),
			}
			for _, g := range item.ChildrenNamed("group") {
				if g.Text != "" {
					entry.Groups = append(entry.Groups, g.Text)
				}
			}
			if i := st.rosterIndex(jid); i >= 0 {
				entry.Subscription = st.Roster[i].Subscription
			}
			if entry.Subscription == "" {
				entry.Subscription = "none"
			}
			st.putRoster(entry)
		}
		if err := s.srv.saveSocial(ctx, s.dbid, st); err != nil {
			return s.iqError(n, "internal-server-error")
		}
		if err := s.iqResult(id, n.Attr("to"), ""); err != nil {
			return err
		}
		s.pushRosterItem(jid, st)
		return nil
	}
	return s.iqError(n, "bad-request")
}

// rosterQuery renders the whole roster list.
func rosterQuery(st *Social) string {
	var inner strings.Builder
	for _, item := range st.Roster {
		inner.WriteString(rosterItemXML(item))
	}
	return tag("query", [][2]string{{"xmlns", nsRoster}}, inner.String())
}

// rosterItemXML renders one roster entry.
func rosterItemXML(item RosterItem) string {
	attrs := [][2]string{{"jid", item.JID}}
	if item.Name != "" {
		attrs = append(attrs, [2]string{"name", item.Name})
	}
	sub := item.Subscription
	if sub == "" {
		sub = "none"
	}
	attrs = append(attrs, [2]string{"subscription", sub})
	if item.Ask != "" {
		attrs = append(attrs, [2]string{"ask", item.Ask})
	}
	var inner strings.Builder
	for _, g := range item.Groups {
		inner.WriteString(textTag("group", g))
	}
	return tag("item", attrs, inner.String())
}

// pushRosterItem sends the roster push for one entry to every session of
// this account.
func (s *session) pushRosterItem(jid string, st *Social) {
	var item RosterItem
	found := false
	if i := st.rosterIndex(jid); i >= 0 {
		item, found = st.Roster[i], true
	}
	var inner string
	if found {
		inner = rosterItemXML(item)
	} else {
		inner = tag("item", [][2]string{{"jid", jid}, {"subscription", "remove"}}, "")
	}
	push := tag("iq", [][2]string{{"type", "set"}, {"id", "push-" + jid}},
		tag("query", [][2]string{{"xmlns", nsRoster}}, inner))
	for _, sess := range s.srv.sessionsOf(s.dbid) {
		_ = sess.write(push)
	}
}

// handleBlocking answers the urn:xmpp:blocking list and mutations.
//
// The client's `SyncBlockItemTask` runs right after the roster on
// connect, and `AddBlockItemTask`/`RemoveBlockItemTask` back the
// "ignore" action, so both directions have to work or the ignored list
// stays empty.
func (s *session) handleBlocking(n *Node, id, typ string, payload *Node) error {
	ctx := context.Background()
	st, err := s.srv.loadSocial(ctx, s.dbid)
	if err != nil {
		return s.iqError(n, "internal-server-error")
	}
	switch payload.Name.Local {
	case "blocklist":
		if typ != "get" {
			return s.iqError(n, "bad-request")
		}
		return s.iqResult(id, n.Attr("to"), blockListXML(st))
	case "block", "unblock":
		if typ != "set" {
			return s.iqError(n, "bad-request")
		}
		var changed []string
		for _, item := range payload.ChildrenNamed("item") {
			jid := item.Attr("jid")
			if jid == "" {
				continue
			}
			if payload.Name.Local == "block" {
				st.putBlock(BlockItem{JID: jid, Name: s.srv.nickname(dbidOf(jid))})
			} else {
				st.removeBlock(jid)
			}
			changed = append(changed, jid)
		}
		if err := s.srv.saveSocial(ctx, s.dbid, st); err != nil {
			return s.iqError(n, "internal-server-error")
		}
		if err := s.iqResult(id, n.Attr("to"), ""); err != nil {
			return err
		}
		// The push carries the same element the client sent, so its
		// handler sees the change without re-reading the list.
		push := tag("iq", [][2]string{{"type", "set"}, {"id", "push-block"}},
			blockPushXML(payload.Name.Local, changed, st))
		for _, sess := range s.srv.sessionsOf(s.dbid) {
			_ = sess.write(push)
		}
		return nil
	}
	return s.iqError(n, "bad-request")
}

// blockListXML renders the whole block list.
func blockListXML(st *Social) string {
	var inner strings.Builder
	for _, item := range st.Blocked {
		inner.WriteString(blockItemXML(item))
	}
	return tag("blocklist", [][2]string{{"xmlns", nsBlocking}}, inner.String())
}

// blockItemXML renders one block entry with the WG extension the client
// reads the display name from.
func blockItemXML(item BlockItem) string {
	wg := tag("wgexts", [][2]string{{"xmlns", nsWG}},
		textTag("nickname", item.Name)+
			textTag("userid", strconv.FormatInt(dbidOf(item.JID), 10)))
	return tag("item", [][2]string{{"jid", item.JID}}, wg)
}

// blockPushXML renders the block/unblock push for the changed JIDs.
func blockPushXML(kind string, jids []string, st *Social) string {
	var inner strings.Builder
	for _, jid := range jids {
		if kind == "block" {
			if i := st.blockIndex(jid); i >= 0 {
				inner.WriteString(blockItemXML(st.Blocked[i]))
				continue
			}
		}
		inner.WriteString(tag("item", [][2]string{{"jid", jid}}, ""))
	}
	return tag(kind, [][2]string{{"xmlns", nsBlocking}}, inner.String())
}

// handleSPA answers the nickname resolver: the client asks for the
// display names behind a list of databaseIDs whenever it has to show a
// contact it has never seen.
func (s *session) handleSPA(n *Node, id, typ string, payload *Node) error {
	if typ != "get" {
		return s.iqError(n, "bad-request")
	}
	var inner strings.Builder
	for _, item := range payload.ChildrenNamed("item") {
		dbid, err := strconv.ParseInt(item.Attr("id"), 10, 64)
		if err != nil || dbid <= 0 {
			continue
		}
		inner.WriteString(tag("item", [][2]string{
			{"id", strconv.FormatInt(dbid, 10)},
			{"nickname", s.srv.nickname(dbid)},
		}, ""))
	}
	return s.iqResult(id, n.Attr("to"),
		tag("query", [][2]string{{"xmlns", nsWGSPA}}, inner.String()))
}

// handleNotes answers the contact-notes storage: a paged list of
// (databaseID, note) pairs under `http://wargaming.net/xmpp#storage`.
func (s *session) handleNotes(n *Node, id, typ string, payload *Node) error {
	ctx := context.Background()
	st, err := s.srv.loadSocial(ctx, s.dbid)
	if err != nil {
		return s.iqError(n, "internal-server-error")
	}
	list := payload.Child(nsWGStorage, "list")
	if list == nil || list.Attr("name") != "contact-notes" {
		return s.iqError(n, "bad-request")
	}
	switch typ {
	case "get":
		return s.iqResult(id, n.Attr("to"), notesListXML(st))
	case "set":
		if st.Notes == nil {
			st.Notes = map[int64]string{}
		}
		for _, item := range list.ChildrenNamed("item") {
			dbid, err := strconv.ParseInt(item.TextOf(nsWGStorage, "key"), 10, 64)
			if err != nil || dbid <= 0 {
				continue
			}
			text := item.TextOf(nsWGStorage, "value")
			if text == "" {
				delete(st.Notes, dbid)
			} else {
				st.Notes[dbid] = text
			}
		}
		if err := s.srv.saveSocial(ctx, s.dbid, st); err != nil {
			return s.iqError(n, "internal-server-error")
		}
		return s.iqResult(id, n.Attr("to"), "")
	}
	return s.iqError(n, "bad-request")
}

// notesListXML renders the note list with the result-set count the
// client's paging loop reads.
func notesListXML(st *Social) string {
	var inner strings.Builder
	for dbid, text := range st.Notes {
		inner.WriteString(tag("item", nil,
			textTag("key", strconv.FormatInt(dbid, 10))+
				textTag("value", text)))
	}
	inner.WriteString(tag("set", [][2]string{{"xmlns", nsRSM}},
		textTag("count", strconv.Itoa(len(st.Notes)))))
	return tag("query", [][2]string{{"xmlns", nsWGStorage}},
		tag("list", [][2]string{{"name", "contact-notes"}}, inner.String()))
}

// handleDiscoInfo answers service discovery for the domain and for MUC
// rooms.
func (s *session) handleDiscoInfo(n *Node, id, to string) error {
	if to != "" && s.isRoomJID(to) {
		return s.iqResult(id, to, tag("query", [][2]string{{"xmlns", nsDiscoInfo}},
			tag("identity", [][2]string{
				{"category", "conference"}, {"type", "text"}, {"name", to},
			}, "")+
				tag("feature", [][2]string{{"var", nsMUC}}, "")+
				tag("feature", [][2]string{{"var", nsDiscoInfo}}, "")))
	}
	inner := tag("identity", [][2]string{
		{"category", "server"}, {"type", "im"}, {"name", s.srv.cfg.Domain},
	}, "")
	for _, f := range []string{nsDiscoInfo, nsDiscoItem, nsRoster, nsBlocking, nsWGSPA, nsWGStorage} {
		inner += tag("feature", [][2]string{{"var", f}}, "")
	}
	return s.iqResult(id, to, tag("query", [][2]string{{"xmlns", nsDiscoInfo}}, inner))
}

// handleDiscoItems lists the MUC services the domain hosts, which is how
// the client finds the clan and user-room hosts.
func (s *session) handleDiscoItems(n *Node, id, to string) error {
	var inner strings.Builder
	for _, host := range s.srv.mucHosts() {
		inner.WriteString(tag("item", [][2]string{{"jid", host}}, ""))
	}
	return s.iqResult(id, to, tag("query", [][2]string{{"xmlns", nsDiscoItem}}, inner.String()))
}

// sessionsOf returns every live session for one account.
func (s *Server) sessionsOf(dbid int64) []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessions[dbid]; sess != nil {
		return []*session{sess}
	}
	return nil
}
