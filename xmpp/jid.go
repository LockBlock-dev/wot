package xmpp

import (
	"fmt"
	"strings"
)

// JID is an XMPP address: node@domain/resource. On WoT the node is
// the numeric account databaseID, the domain is the XMPP domain and
// the resource identifies the session (shipped scripts build it from
// the login data; see docs/NETWORK_PROTOCOL.md §16).
type JID struct {
	Node     string
	Domain   string
	Resource string
}

// ParseJID splits "node@domain/resource". The resource is optional
// (bare JID); node and domain must be non-empty. No network involved.
func ParseJID(s string) (JID, error) {
	var j JID
	rest := s
	if i := strings.Index(rest, "/"); i >= 0 {
		j.Resource = rest[i+1:]
		rest = rest[:i]
	}
	i := strings.Index(rest, "@")
	if i < 0 {
		return JID{}, fmt.Errorf("xmpp: JID %q has no @domain", s)
	}
	j.Node, j.Domain = rest[:i], rest[i+1:]
	if j.Node == "" || j.Domain == "" {
		return JID{}, fmt.Errorf("xmpp: JID %q has empty node/domain", s)
	}
	return j, nil
}

// String renders the full JID (bare when Resource is empty).
func (j JID) String() string {
	s := j.Node + "@" + j.Domain
	if j.Resource != "" {
		s += "/" + j.Resource
	}
	return s
}

// Bare drops the resource (roster keys and MUC addressing use it).
func (j JID) Bare() string { return JID{Node: j.Node, Domain: j.Domain}.String() }
