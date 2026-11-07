package xmppserver

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// testClient is a minimal XMPP client: enough of the handshake to drive
// the server the way gloox does, and a stanza reader for the answers.
//
// The stream header is read as raw bytes rather than through the XML
// decoder: `<stream:stream>` is never closed while the session lives, so
// a decoder would block waiting for its end tag.
type testClient struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	dec  *xml.Decoder
}

// dialTest connects to addr and completes stream open + SASL + bind.
func dialTest(t *testing.T, addr, domain string, dbid int64, token string) *testClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := newTestClient(t, conn)
	c.openStream(domain)
	c.expectFeatures()
	payload := base64.StdEncoding.EncodeToString([]byte("\x00" + fmt.Sprint(dbid) + "\x00" + token))
	c.send(`<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>` + payload + `</auth>`)
	if got := c.readRaw(); !strings.Contains(got, "<success") {
		t.Fatalf("auth: want success, got %q", got)
	}
	c.openStream(domain)
	c.expectFeatures()
	c.send(`<iq type='set' id='bind1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>wot</resource></bind></iq>`)
	if got := c.readRaw(); !strings.Contains(got, "<jid") {
		t.Fatalf("bind: want a jid, got %q", got)
	}
	return c
}

// newTestClient wraps a connection.
func newTestClient(t *testing.T, conn net.Conn) *testClient {
	br := bufio.NewReader(conn)
	return &testClient{t: t, conn: conn, br: br, dec: xml.NewDecoder(br)}
}

// openStream sends the opening stream tag.
func (c *testClient) openStream(domain string) {
	c.t.Helper()
	c.send(`<?xml version='1.0'?><stream:stream to='` + domain +
		`' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`)
}

// expectFeatures reads the stream header (raw) and the features element.
func (c *testClient) expectFeatures() {
	c.t.Helper()
	if got := c.readStreamHeader(); !strings.Contains(got, "<stream:stream") {
		c.t.Fatalf("want a stream header, got %q", got)
	}
	if got := c.readRaw(); !strings.Contains(got, "features") {
		c.t.Fatalf("want features, got %q", got)
	}
}

// readStreamHeader reads bytes up to the end of the opening stream tag.
func (c *testClient) readStreamHeader() string {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var sb strings.Builder
	for {
		b, err := c.br.ReadByte()
		if err != nil {
			c.t.Fatalf("read header: %v (got %q)", err, sb.String())
		}
		sb.WriteByte(b)
		if b == '>' && strings.Contains(sb.String(), "<stream:stream") {
			return sb.String()
		}
	}
}

// send writes one stanza.
func (c *testClient) send(s string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, s); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// readRaw reads one element and returns its raw text.
func (c *testClient) readRaw() string {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start, err := nextElement(c.dec)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	n, err := readElement(c.dec, start)
	if err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	return renderNode(n)
}

// startTestServer runs a server on a loopback port and returns it.
func startTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Domain == "" {
		cfg.Domain = "localhost"
	}
	if cfg.Secret == nil {
		cfg.Secret = []byte("test-secret")
	}
	srv := New(cfg)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		srv.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return srv
}

// TestHandshakeAndRoster drives the full connect sequence the client
// performs: stream open, SASL PLAIN with the minted credential, bind,
// roster get, blocklist get, notes get, then presence.
func TestHandshakeAndRoster(t *testing.T) {
	srv := startTestServer(t, Config{})
	c := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	defer c.conn.Close()

	c.send(`<iq type='get' id='r1'><query xmlns='jabber:iq:roster'/></iq>`)
	got := c.readRaw()
	if !strings.Contains(got, `xmlns="jabber:iq:roster"`) || !strings.Contains(got, `type="result"`) {
		t.Fatalf("roster get: %q", got)
	}

	c.send(`<iq type='get' id='b1'><blocklist xmlns='urn:xmpp:blocking'/></iq>`)
	got = c.readRaw()
	if !strings.Contains(got, `xmlns="urn:xmpp:blocking"`) {
		t.Fatalf("blocklist get: %q", got)
	}

	c.send(`<iq type='get' id='n1'><query xmlns='http://wargaming.net/xmpp#storage'>` +
		`<list name='contact-notes'><set xmlns='http://jabber.org/protocol/rsm'><max>50</max></set></list></query></iq>`)
	got = c.readRaw()
	if !strings.Contains(got, "contact-notes") || !strings.Contains(got, ">0</count>") {
		t.Fatalf("notes get: %q", got)
	}

	c.send(`<presence><priority>0</priority><wgexts xmlns='http://wargaming.net/xmpp#v2'>` +
		`<nickname>admin</nickname><userid>100000002</userid></wgexts></presence>`)
	// Nothing to relay to (no contacts), so the next stanza is whatever
	// the test asks for; the presence must not error out.
	c.send(`<iq type='get' id='d1'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>`)
	got = c.readRaw()
	if !strings.Contains(got, "disco#info") {
		t.Fatalf("disco info: %q", got)
	}
}

// TestRosterSetPersists checks that a roster set is answered, pushed and
// survives a reconnect.
func TestRosterSetPersists(t *testing.T) {
	srv := startTestServer(t, Config{})
	c := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	c.send(`<iq type='set' id='s1'><query xmlns='jabber:iq:roster'>` +
		`<item jid='100000003@localhost' name='friend'><group>Friends</group></item></query></iq>`)
	if got := c.readRaw(); !strings.Contains(got, `type="result"`) {
		t.Fatalf("roster set result: %q", got)
	}
	if got := c.readRaw(); !strings.Contains(got, "100000003@localhost") {
		t.Fatalf("roster push: %q", got)
	}
	c.conn.Close()

	c2 := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	defer c2.conn.Close()
	c2.send(`<iq type='get' id='r2'><query xmlns='jabber:iq:roster'/></iq>`)
	got := c2.readRaw()
	if !strings.Contains(got, "100000003@localhost") || !strings.Contains(got, ">Friends<") {
		t.Fatalf("roster after reconnect: %q", got)
	}
}

// TestBlockListRoundTrip checks the ignore list: block, read back, then
// unblock.
func TestBlockListRoundTrip(t *testing.T) {
	srv := startTestServer(t, Config{})
	c := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	defer c.conn.Close()

	c.send(`<iq type='set' id='b1'><block xmlns='urn:xmpp:blocking'>` +
		`<item jid='100000004@localhost'/></block></iq>`)
	if got := c.readRaw(); !strings.Contains(got, `type="result"`) {
		t.Fatalf("block result: %q", got)
	}
	if got := c.readRaw(); !strings.Contains(got, "100000004@localhost") {
		t.Fatalf("block push: %q", got)
	}
	c.send(`<iq type='get' id='b2'><blocklist xmlns='urn:xmpp:blocking'/></iq>`)
	if got := c.readRaw(); !strings.Contains(got, "100000004@localhost") {
		t.Fatalf("blocklist: %q", got)
	}
	c.send(`<iq type='set' id='b3'><unblock xmlns='urn:xmpp:blocking'>` +
		`<item jid='100000004@localhost'/></unblock></iq>`)
	c.readRaw() // result
	c.readRaw() // push
	c.send(`<iq type='get' id='b4'><blocklist xmlns='urn:xmpp:blocking'/></iq>`)
	if got := c.readRaw(); strings.Contains(got, "100000004@localhost") {
		t.Fatalf("blocklist after unblock: %q", got)
	}
}

// TestPresenceRelay checks that two accounts see each other: the roster
// entry plus the presence carrying the WG nickname.
func TestPresenceRelay(t *testing.T) {
	srv := startTestServer(t, Config{
		Nickname: func(dbid int64) string {
			if dbid == 100000003 {
				return "friend"
			}
			return "admin"
		},
	})
	a := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	defer a.conn.Close()
	b := dialTest(t, srv.Addr(), "localhost", 100000003, srv.TokenFor(100000003))
	defer b.conn.Close()

	// Both sides list each other.
	a.send(`<iq type='set' id='a1'><query xmlns='jabber:iq:roster'>` +
		`<item jid='100000003@localhost' name='friend'/></query></iq>`)
	a.readRaw()
	a.readRaw()
	b.send(`<iq type='set' id='b1'><query xmlns='jabber:iq:roster'>` +
		`<item jid='100000002@localhost' name='admin'/></query></iq>`)
	b.readRaw()
	b.readRaw()

	// a must be available before b's presence is relayed to it: XMPP
	// only shows contacts that are online.
	a.send(`<presence><wgexts xmlns='http://wargaming.net/xmpp#v2'><nickname>admin</nickname></wgexts></presence>`)
	b.send(`<presence><wgexts xmlns='http://wargaming.net/xmpp#v2'><nickname>friend</nickname></wgexts></presence>`)
	got := a.readRaw()
	if !strings.Contains(got, "100000003@localhost/wot") || !strings.Contains(got, "friend") {
		t.Fatalf("presence relay: %q", got)
	}
}

// TestMUCJoinAndMessage checks the clan-channel path: join, occupant
// list, then a groupchat message fanned back out.
func TestMUCJoinAndMessage(t *testing.T) {
	srv := startTestServer(t, Config{})
	c := dialTest(t, srv.Addr(), "localhost", 100000002, srv.TokenFor(100000002))
	defer c.conn.Close()

	c.send(`<presence to='42@clans.localhost/admin'><x xmlns='http://jabber.org/protocol/muc'/></presence>`)
	got := c.readRaw()
	if !strings.Contains(got, "42@clans.localhost/admin") {
		t.Fatalf("muc self presence: %q", got)
	}
	// The room subject follows.
	if got := c.readRaw(); !strings.Contains(got, "<subject") {
		t.Fatalf("muc subject: %q", got)
	}

	c.send(`<message to='42@clans.localhost' type='groupchat'><body>hello</body></message>`)
	got = c.readRaw()
	if !strings.Contains(got, "42@clans.localhost/admin") || !strings.Contains(got, "hello") {
		t.Fatalf("groupchat relay: %q", got)
	}
}

// TestBadCredential checks that a wrong password is refused.
func TestBadCredential(t *testing.T) {
	srv := startTestServer(t, Config{})
	conn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := newTestClient(t, conn)
	c.openStream("localhost")
	c.expectFeatures()
	payload := base64.StdEncoding.EncodeToString([]byte("\x00" + fmt.Sprint(100000002) + "\x00wrong"))
	c.send(`<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>` + payload + `</auth>`)
	if got := c.readRaw(); !strings.Contains(got, "<failure") {
		t.Fatalf("want failure, got %q", got)
	}
}

// TestTokenIsStable checks the credential derivation: same account, same
// token; different account, different token.
func TestTokenIsStable(t *testing.T) {
	srv := New(Config{Secret: []byte("k")})
	a := srv.TokenFor(100000002)
	if a != srv.TokenFor(100000002) {
		t.Fatal("token is not stable")
	}
	if a == srv.TokenFor(100000003) {
		t.Fatal("token collides across accounts")
	}
	if len(a) != 32 {
		t.Fatalf("token length %d", len(a))
	}
}
