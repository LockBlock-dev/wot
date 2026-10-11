package xmpp

import (
	"strings"
	"testing"
)

// Vectors below are synthetic (documented shapes, no live stanza
// capture on hand): gloox-style chat/iq/presence plus WG extension
// elements named by the exe vtables (MsgId, PrivateHistory, Muc).

func TestBuildMessage(t *testing.T) {
	got := BuildMessage(Message{
		From: "1@x/r", To: "2@x/r", ID: "m1",
		Body: "hi <there> & you", Thread: "t",
		Ext: `<msgid xmlns="wargaming:msg:id">7</msgid>`,
	})
	want := `<message from="1@x/r" to="2@x/r" type="chat" id="m1"><body>hi &lt;there&gt; &amp; you</body><thread>t</thread><msgid xmlns="wargaming:msg:id">7</msgid></message>`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	p, err := ParseStanza(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "message" || p.Attrs["to"] != "2@x/r" || p.Attrs["type"] != "chat" || p.Text != "hi <there> & you" {
		t.Fatalf("parsed %+v", p)
	}
	if !strings.Contains(p.Inner, "msgid") {
		t.Fatalf("ext lost: %q", p.Inner)
	}
}

func TestBuildPresence(t *testing.T) {
	if got := BuildPresence(Presence{From: "1@x/r"}); got != `<presence from="1@x/r"></presence>` {
		t.Fatalf("got %s", got)
	}
	got := BuildPresence(Presence{To: "room@muc/x", Type: "unavailable", Status: "gone"})
	p, err := ParseStanza(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "presence" || p.Attrs["type"] != "unavailable" || p.Text != "gone" {
		t.Fatalf("parsed %+v", p)
	}
}

func TestBuildIQ(t *testing.T) {
	got := BuildIQ(IQ{To: "x", Type: "get", ID: "r1", Payload: `<query xmlns="jabber:iq:roster"/>`})
	p, err := ParseStanza(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "iq" || p.Attrs["id"] != "r1" || !strings.Contains(p.Inner, "roster") {
		t.Fatalf("parsed %+v", p)
	}
	if _, err := ParseStanza("<message><body>unclosed"); err == nil {
		t.Fatal("bad xml accepted")
	}
}

func TestBuildBOSH(t *testing.T) {
	create := BuildBOSH(BOSHBody{RID: 100, To: "xmpp.wargaming.net", Hold: 1, Wait: 60, Ver: "1.6"})
	if !strings.HasPrefix(create, `<body rid="100" to="xmpp.wargaming.net" xml:lang="en" hold="1" wait="60" ver="1.6"`) {
		t.Fatalf("got %s", create)
	}
	if strings.Contains(create, "sid=") {
		t.Fatalf("create carries sid: %s", create)
	}
	term := BuildBOSH(BOSHBody{RID: 101, SID: "s", Terminate: true})
	if !strings.Contains(term, `type="terminate"`) || !strings.Contains(term, `sid="s"`) {
		t.Fatalf("got %s", term)
	}
	rep, err := ParseBOSH(`<body sid="s" authid="a" requests="2" polling="5"><message from="1@x" to="2@x" type="chat"><body>hi</body></message><presence/></body>`)
	if err != nil {
		t.Fatal(err)
	}
	if rep.SID != "s" || rep.AuthID != "a" || rep.Requests != 2 || rep.Polling != 5 {
		t.Fatalf("attrs %+v", rep)
	}
	if len(rep.Stanzas) != 2 || rep.Stanzas[0].Name != "message" || rep.Stanzas[0].Text != "hi" || rep.Stanzas[1].Name != "presence" {
		t.Fatalf("stanzas %+v", rep.Stanzas)
	}
	if _, err := ParseBOSH(`<body><message>unclosed`); err == nil {
		t.Fatal("bad xml accepted")
	}
}

func TestStreamOpenBuilder(t *testing.T) {
	got := BuildStreamOpen(DefaultDomain)
	want := `<?xml version='1.0'?><stream:stream to='c2s.xmpp-wot-eu.wargaming.net' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestLiveFeaturesMechanisms(t *testing.T) {
	// Genuine server bytes, EU live Oct-12 (stream id varies per
	// connection; mechanisms do not): PLAIN only, no STARTTLS.
	features := `<stream:features xmlns='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>PLAIN</mechanism></mechanisms></stream:features>`
	if m := SASLMechanisms(features); len(m) != 1 || m[0] != "PLAIN" {
		t.Fatalf("mechanisms=%v", m)
	}
	p, err := ParseStanza(features)
	if err != nil || p.Name != "features" { // prefix dropped by encoding/xml; see ParseBOSH for prefixed form
		t.Fatalf("parsed %+v %v", p, err)
	}
}

func TestGenuineRosterIQ(t *testing.T) {
	// Genuine client bytes, Sep-29 lobby #2 flow (own account only;
	// roster answers carry other players and stay out of tests):
	// roster pull with uid:hex:counter id shape.
	raw := `<iq id='uid:6aac8c76:00000003' type='get' from='123456789@c2s.xmpp-wot-eu.wargaming.net/wot' xmlns='jabber:client'><query xmlns='http://wargaming.net/xmpp#filter-roster'/></iq>`
	p, err := ParseStanza(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "iq" || p.Attrs["id"] != "uid:6aac8c76:00000003" || p.Attrs["type"] != "get" {
		t.Fatalf("parsed %+v", p)
	}
	from, err := ParseJID(p.Attrs["from"])
	if err != nil || from.Node != "123456789" || from.Domain != DefaultDomain || from.Resource != "wot" {
		t.Fatalf("from %+v %v", from, err)
	}
	if !strings.Contains(p.Inner, "filter-roster") {
		t.Fatalf("inner %q", p.Inner)
	}
}

func TestBuildSASLAuth(t *testing.T) {
	got := BuildSASLAuth("PLAIN", "AGxpbl9wYXNz")
	if got != `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGxpbl9wYXNz</auth>` {
		t.Fatalf("got %s", got)
	}
	if p := SASLPlainPayload("u", "p"); p != "\x00u\x00p" {
		t.Fatalf("got %q", p)
	}
	got = BuildSASLAuth("XMPPCS", "dG9rZW4=")
	p, err := ParseStanza(got)
	if err != nil || p.Name != "auth" || p.Attrs["mechanism"] != "XMPPCS" || p.Text != "" {
		t.Fatalf("parsed %+v %v", p, err)
	}
}
