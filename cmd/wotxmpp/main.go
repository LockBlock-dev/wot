// Command wotxmpp exercises the wot/xmpp offline models against the
// live XMPP endpoints: TCP stream open + features (default, no auth),
// optional BOSH session create (-bosh), optional SASL PLAIN with
// live.env creds (-auth, read-only after: presence + roster IQ).
//
// Secrets live in a .env file, never on the command line or stdout
// (lengths and stanza names only; rosters are personal data).
//
//	wotxmpp [-host woteu34.xmpp.wargaming.net] [-domain xmpp.wargaming.net]
//	wotxmpp -auth -env live.env -dbid 123456789
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/xmpp"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotxmpp:", err)
	os.Exit(1)
}

// readUntil reads until substr appears, the deadline passes, or 64KB
// accumulates. It returns what arrived (stanza names, never bodies,
// are reported by callers).
func readUntil(c net.Conn, substr string, timeout time.Duration) (string, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), substr) || sb.Len() > 65536 {
				return sb.String(), nil
			}
		}
		if err != nil {
			return sb.String(), err
		}
	}
}

func streamOpen(domain string) string { return xmpp.BuildStreamOpen(domain) }

// mechanisms extracts SASL mechanism names from a features blob.
func mechanisms(features string) []string { return xmpp.SASLMechanisms(features) }

func tcpPing(host string, port int, domain string, timeout time.Duration) {
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	fmt.Fprintf(os.Stderr, "[wotxmpp] dial %s\n", addr)
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(streamOpen(domain))); err != nil {
		fatal(err)
	}
	// The server answers with a bare stream header first (no
	// <stream:features> yet — it waits for STARTTLS).
	head, err := readUntil(c, "</stream:features>", 8*time.Second)
	if err != nil && !strings.Contains(head, "</stream:features>") {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "[wotxmpp] features %dB mechanisms=%v starttls=%v\n",
		len(head), mechanisms(head), strings.Contains(head, "starttls"))
}

func saslAuth(host string, port int, domain, envPath, dbid, authcid string, timeout time.Duration) {
	cfg, err := login.LoadEnv(envPath)
	if err != nil {
		fatal(err)
	}
	if cfg.Login == "" || cfg.Password == "" {
		fatal(fmt.Errorf("live.env has no LOGIN/PASSWORD"))
	}
	jid := xmpp.JID{Node: dbid, Domain: domain, Resource: "wotxmpp"}
	if dbid == "" {
		jid.Node = fmt.Sprintf("%d-chars", len(cfg.Login))
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), timeout)
	if err != nil {
		fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(streamOpen(domain))); err != nil {
		fatal(err)
	}
	feat, err := readUntil(c, "</stream:features>", timeout)
	if err != nil && !strings.Contains(feat, "<stream:features>") {
		fatal(err)
	}
	mechs := mechanisms(feat)
	fmt.Fprintf(os.Stderr, "[wotxmpp] mechanisms=%v\n", mechs)
	if strings.Contains(feat, "starttls") {
		fmt.Fprintf(os.Stderr, "[wotxmpp] STARTTLS offered, upgrading\n")
		if _, err := c.Write([]byte(`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`)); err != nil {
			fatal(err)
		}
		proceed, err := readUntil(c, "proceed", timeout)
		if err != nil || !strings.Contains(proceed, "proceed") {
			fatal(fmt.Errorf("starttls not granted (%dB): %v", len(proceed), err))
		}
		c = tls.Client(c, &tls.Config{ServerName: host})
		if err := c.(*tls.Conn).Handshake(); err != nil {
			fatal(err)
		}
		if _, err := c.Write([]byte(streamOpen(domain))); err != nil {
			fatal(err)
		}
		feat, err = readUntil(c, "</stream:features>", timeout)
		if err != nil && !strings.Contains(feat, "<stream:features>") {
			fatal(err)
		}
		mechs = mechanisms(feat)
		fmt.Fprintf(os.Stderr, "[wotxmpp] post-TLS mechanisms=%v\n", mechs)
	}
	hasPlain := false
	for _, m := range mechs {
		if m == "PLAIN" {
			hasPlain = true
		}
	}
	if !hasPlain {
		fatal(fmt.Errorf("PLAIN not offered (offered=%v): password auth unavailable, XMPPCS needs a broker token", mechs))
	}
	user := cfg.Login
	if authcid != "" {
		user = authcid
	}
	raw := "\x00" + user + "\x00" + cfg.Password
	auth := `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>` +
		base64.StdEncoding.EncodeToString([]byte(raw)) + `</auth>`
	if _, err := c.Write([]byte(auth)); err != nil {
		fatal(err)
	}
	resp, err := readUntil(c, "/>", timeout)
	fmt.Fprintf(os.Stderr, "[wotxmpp] sasl %dB node-len=%d ok=%v err=%v\n",
		len(resp), len(jid.Node), strings.Contains(resp, "success"), err)
	if !strings.Contains(resp, "success") {
		head := resp
		if len(head) > 200 {
			head = head[:200]
		}
		fmt.Fprintf(os.Stderr, "[wotxmpp] head: %s\n", head)
		return
	}
	if _, err := c.Write([]byte(streamOpen(domain))); err != nil {
		fatal(err)
	}
	if _, err := readUntil(c, "</stream:features>", timeout); err != nil {
		fatal(err)
	}
	bind := xmpp.BuildIQ(xmpp.IQ{Type: "set", ID: "bind1",
		Payload: `<bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>wotxmpp</resource></bind>`})
	if _, err := c.Write([]byte(bind)); err != nil {
		fatal(err)
	}
	bound, err := readUntil(c, "</iq>", timeout)
	p, _ := xmpp.ParseStanza(bound)
	fmt.Fprintf(os.Stderr, "[wotxmpp] bind iq=%s err=%v\n", p.Name, err)
	pres := xmpp.BuildPresence(xmpp.Presence{})
	if _, err := c.Write([]byte(pres)); err != nil {
		fatal(err)
	}
	roster := xmpp.BuildIQ(xmpp.IQ{Type: "get", ID: "roster1",
		Payload: `<query xmlns="jabber:iq:roster"/>`})
	if _, err := c.Write([]byte(roster)); err != nil {
		fatal(err)
	}
	inbound, _ := readUntil(c, "</iq>", timeout)
	n := 0
	for _, tag := range []string{"<message", "<iq", "<presence"} {
		n += strings.Count(inbound, tag)
	}
	fmt.Fprintf(os.Stderr, "[wotxmpp] post-auth stanzas~%d bytes=%d (names only)\n", n, len(inbound))
}

func boshCreate(host string, port int, domain string, timeout time.Duration) {
	e := xmpp.Endpoint{Host: host, Port: port}
	body := xmpp.BuildBOSH(xmpp.BOSHBody{RID: 100000, To: domain, Hold: 1, Wait: 60, Ver: "1.6"})
	url := xmpp.BoshURL(e)
	fmt.Fprintf(os.Stderr, "[wotxmpp] POST %s (%dB)\n", url, len(body))
	httpc := &http.Client{Timeout: timeout}
	resp, err := httpc.Post(url, "text/xml; charset=utf-8", strings.NewReader(body))
	if err != nil {
		fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 65536)
	var sb strings.Builder
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if rerr != nil || sb.Len() > 65536 {
			break
		}
	}
	fmt.Fprintf(os.Stderr, "[wotxmpp] http=%d bytes=%d\n", resp.StatusCode, sb.Len())
	if resp.StatusCode/100 != 2 {
		head := sb.String()
		if len(head) > 200 {
			head = head[:200]
		}
		fmt.Fprintf(os.Stderr, "[wotxmpp] head: %s\n", head)
		return
	}
	rep, err := xmpp.ParseBOSH(sb.String())
	if err != nil {
		fatal(err)
	}
	names := []string{}
	for _, s := range rep.Stanzas {
		names = append(names, s.Name)
	}
	fmt.Fprintf(os.Stderr, "[wotxmpp] bosh sid-len=%d authid-len=%d stanzas=%v\n",
		len(rep.SID), len(rep.AuthID), names)
}

func main() {
	host := flag.String("host", "woteu34.xmpp.wargaming.net", "XMPP host")
	tcpPort := flag.Int("tcp-port", 5222, "XMPP TCP port")
	boshPort := flag.Int("bosh-port", 5280, "BOSH HTTPS port")
	domain := flag.String("domain", xmpp.DefaultDomain, "stream `to` domain")
	envPath := flag.String("env", "live.env", "KEY=VALUE secrets file (for -auth)")
	auth := flag.Bool("auth", false, "attempt SASL PLAIN with live.env creds (read-only after)")
	authcid := flag.String("authcid", "", "SASL username override (default LOGIN)")
	bosh := flag.Bool("bosh", false, "BOSH session create over HTTPS (framing only)")
	dbid := flag.String("dbid", "", "SASL authcid override (default: live.env LOGIN); JID node for display lengths")
	timeout := flag.Duration("timeout", 12*time.Second, "per-step timeout")
	flag.Parse()

	if *bosh {
		boshCreate(*host, *boshPort, *domain, *timeout)
		return
	}
	if *auth {
		saslAuth(*host, *tcpPort, *domain, *envPath, *dbid, *authcid, *timeout)
		return
	}
	tcpPing(*host, *tcpPort, *domain, *timeout)
}
