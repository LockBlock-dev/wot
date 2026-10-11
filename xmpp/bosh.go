package xmpp

// BOSH (XEP-0124) session framing: the game falls back to BOSH when
// TCP fails (ConnectionsIterator yields BOSH candidates last; bosh
// path `/bosh/` hardcoded). These are pure frame builders/parsers —
// the HTTP transport itself is out of scope (see package doc).

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// BOSHBody is one <body> wrapper: session create, data, or
// terminate. RID is the client request counter, SID the session id
// (empty on session creation).
type BOSHBody struct {
	RID       uint64
	SID       string
	To        string
	Lang      string
	Hold      int
	Wait      int
	Ver       string
	Stanzas   string
	Terminate bool
}

// BuildBOSH renders the <body> wrapper. Session creation omits sid
// and carries hold/wait/ver; termination sets type="terminate".
func BuildBOSH(b BOSHBody) string {
	var sb strings.Builder
	sb.WriteString("<body")
	fmt.Fprintf(&sb, ` rid="%d"`, b.RID)
	if b.SID != "" {
		fmt.Fprintf(&sb, ` sid="%s"`, escAttr(b.SID))
	}
	if b.To != "" {
		fmt.Fprintf(&sb, ` to="%s"`, escAttr(b.To))
	}
	lang := b.Lang
	if lang == "" {
		lang = "en"
	}
	fmt.Fprintf(&sb, ` xml:lang="%s"`, escAttr(lang))
	if b.SID == "" {
		fmt.Fprintf(&sb, ` hold="%d" wait="%d" ver="%s"`, b.Hold, b.Wait, escAttr(b.Ver))
	}
	if b.Terminate {
		sb.WriteString(` type="terminate"`)
	}
	sb.WriteString(` xmlns="http://jabber.org/protocol/httpbind">`)
	sb.WriteString(b.Stanzas)
	sb.WriteString("</body>")
	return sb.String()
}

// BOSHReply is a decoded server wrapper: carried stanzas plus the
// session parameters the server assigns/confirms.
type BOSHReply struct {
	SID      string
	AuthID   string
	Stanzas  []Parsed
	Requests int
	Polling  int
}

// ParseBOSH decodes a server <body>: sid/authid/attrs plus each
// top-level child stanza parsed via ParseStanza.
func ParseBOSH(raw string) (BOSHReply, error) {
	var v struct {
		XMLName  xml.Name
		SID      string `xml:"sid,attr"`
		AuthID   string `xml:"authid,attr"`
		Requests int    `xml:"requests,attr"`
		Polling  int    `xml:"polling,attr"`
		Inner    string `xml:",innerxml"`
	}
	dec := xml.NewDecoder(strings.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return BOSHReply{}, fmt.Errorf("xmpp: bosh: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "body" {
			if err := dec.DecodeElement(&v, &se); err != nil {
				return BOSHReply{}, fmt.Errorf("xmpp: bosh: %w", err)
			}
			break
		}
	}
	var rep BOSHReply
	rep.SID, rep.AuthID = v.SID, v.AuthID
	rep.Requests, rep.Polling = v.Requests, v.Polling
	dec2 := xml.NewDecoder(strings.NewReader("<wrap>" + v.Inner + "</wrap>"))
	depth := 0
	for {
		tok, err := dec2.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			depth++
			if depth == 1 {
				continue // synthetic wrap root
			}
			var ch struct {
				Attrs  []xml.Attr `xml:",any,attr"`
				Inner  string     `xml:",innerxml"`
				Body   string     `xml:"body"`
				Show   string     `xml:"show"`
				Status string     `xml:"status"`
				Thread string     `xml:"thread"`
			}
			if err := dec2.DecodeElement(&ch, &se); err != nil {
				return BOSHReply{}, fmt.Errorf("xmpp: bosh stanza: %w", err)
			}
			name := se.Name.Local
			if se.Name.Space != "" {
				name = se.Name.Space + ":" + name
			}
			p := Parsed{Name: name, Attrs: map[string]string{}, Inner: ch.Inner}
			for _, a := range ch.Attrs {
				p.Attrs[a.Name.Local] = a.Value
			}
			for _, s := range []string{ch.Body, ch.Show, ch.Status, ch.Thread} {
				if s != "" {
					p.Text = s
					break
				}
			}
			rep.Stanzas = append(rep.Stanzas, p)
		}
	}
	return rep, nil
}
