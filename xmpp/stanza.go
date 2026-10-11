package xmpp

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// Stanza sizes stay small (chat/control); builders use plain string
// concatenation with escaping so output bytes are exact and obvious.
// Parsers accept gloox-shaped XML via encoding/xml. Vectors in the
// test are synthetic (shapes from the shipped messenger scripts and
// the WG extension vtables: MsgId, PrivateHistory, Muc/MucUser,
// WgExts) — no live stanza capture exists yet.

// escAttr escapes XML attribute values; escText escapes character data.
func escAttr(s string) string {
	r := strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `>`, "&gt;", `"`, "&quot;", `'`, "&apos;")
	return r.Replace(s)
}

func escText(s string) string {
	r := strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `>`, "&gt;")
	return r.Replace(s)
}

// Message is a chat/data stanza. Thread and Subject are optional;
// Ext carries raw WG extension elements (already-escaped XML).
type Message struct {
	From    string
	To      string
	Type    string
	ID      string
	Body    string
	Subject string
	Thread  string
	Ext     string
}

// BuildMessage renders <message>. Empty fields are omitted except
// from/to/type/id handling below: type defaults to "chat" like the
// game client; id is omitted when empty (server assigns).
func BuildMessage(m Message) string {
	var sb strings.Builder
	sb.WriteString("<message")
	if m.From != "" {
		fmt.Fprintf(&sb, ` from="%s"`, escAttr(m.From))
	}
	if m.To != "" {
		fmt.Fprintf(&sb, ` to="%s"`, escAttr(m.To))
	}
	typ := m.Type
	if typ == "" {
		typ = "chat"
	}
	fmt.Fprintf(&sb, ` type="%s"`, escAttr(typ))
	if m.ID != "" {
		fmt.Fprintf(&sb, ` id="%s"`, escAttr(m.ID))
	}
	sb.WriteString(">")
	if m.Subject != "" {
		fmt.Fprintf(&sb, "<subject>%s</subject>", escText(m.Subject))
	}
	fmt.Fprintf(&sb, "<body>%s</body>", escText(m.Body))
	if m.Thread != "" {
		fmt.Fprintf(&sb, "<thread>%s</thread>", escText(m.Thread))
	}
	sb.WriteString(m.Ext)
	sb.WriteString("</message>")
	return sb.String()
}

// Presence is an availability stanza (initial, away, MUC joins).
type Presence struct {
	From   string
	To     string
	Type   string
	Show   string
	Status string
}

// BuildPresence renders <presence>. Empty type = available (attribute
// omitted, per XMPP); show/status omitted when empty.
func BuildPresence(p Presence) string {
	var sb strings.Builder
	sb.WriteString("<presence")
	if p.From != "" {
		fmt.Fprintf(&sb, ` from="%s"`, escAttr(p.From))
	}
	if p.To != "" {
		fmt.Fprintf(&sb, ` to="%s"`, escAttr(p.To))
	}
	if p.Type != "" {
		fmt.Fprintf(&sb, ` type="%s"`, escAttr(p.Type))
	}
	sb.WriteString(">")
	if p.Show != "" {
		fmt.Fprintf(&sb, "<show>%s</show>", escText(p.Show))
	}
	if p.Status != "" {
		fmt.Fprintf(&sb, "<status>%s</status>", escText(p.Status))
	}
	sb.WriteString("</presence>")
	return sb.String()
}

// IQ is an info/query stanza. Payload is raw inner XML (query,
// roster, WG extensions) passed through verbatim.
type IQ struct {
	From    string
	To      string
	Type    string
	ID      string
	Payload string
}

// BuildIQ renders <iq>. Type has no default (get/set/result/error
// are all live); id is required by the protocol.
func BuildIQ(q IQ) string {
	var sb strings.Builder
	sb.WriteString("<iq")
	if q.From != "" {
		fmt.Fprintf(&sb, ` from="%s"`, escAttr(q.From))
	}
	if q.To != "" {
		fmt.Fprintf(&sb, ` to="%s"`, escAttr(q.To))
	}
	if q.Type != "" {
		fmt.Fprintf(&sb, ` type="%s"`, escAttr(q.Type))
	}
	if q.ID != "" {
		fmt.Fprintf(&sb, ` id="%s"`, escAttr(q.ID))
	}
	sb.WriteString(">")
	sb.WriteString(q.Payload)
	sb.WriteString("</iq>")
	return sb.String()
}

// BuildStreamOpen renders the client stream header (gloox shape,
// single quotes like the genuine client).
func BuildStreamOpen(domain string) string {
	return `<?xml version='1.0'?><stream:stream to='` + domain +
		`' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`
}

// SASLMechanisms extracts mechanism names from a <stream:features>
// blob (live EU advertises PLAIN only, no STARTTLS).
func SASLMechanisms(features string) []string {
	var out []string
	for _, m := range []string{"PLAIN", "XMPPCS", "DIGEST-MD5", "SCRAM-SHA-1", "ANONYMOUS"} {
		if strings.Contains(features, ">"+m+"<") {
			out = append(out, m)
		}
	}
	return out
}

// Parsed is a decoded stanza: name + attributes + raw inner XML +
// the text of a body/show/status child when present.
type Parsed struct {
	Name  string
	Attrs map[string]string
	Inner string
	Text  string
}

// ParseStanza decodes one stanza element. Text is the first
// body/show/status/thread child text found, if any.
func ParseStanza(raw string) (Parsed, error) {
	var v struct {
		XMLName xml.Name
		Attrs   []xml.Attr `xml:",any,attr"`
		Inner   string     `xml:",innerxml"`
		Body    string     `xml:"body"`
		Show    string     `xml:"show"`
		Status  string     `xml:"status"`
		Thread  string     `xml:"thread"`
	}
	if err := xml.Unmarshal([]byte(raw), &v); err != nil {
		return Parsed{}, fmt.Errorf("xmpp: stanza: %w", err)
	}
	p := Parsed{Name: v.XMLName.Local, Attrs: map[string]string{}, Inner: v.Inner}
	for _, a := range v.Attrs {
		p.Attrs[a.Name.Local] = a.Value
	}
	for _, s := range []string{v.Body, v.Show, v.Status, v.Thread} {
		if s != "" {
			p.Text = s
			break
		}
	}
	return p, nil
}
