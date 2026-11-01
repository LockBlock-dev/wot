// Command wotserver runs the private server's BOTH wire halves:
//
//   - LoginApp (login/loginapp.go): the game RSA-encrypts LogOnParams
//     to the pubkey whose private half this CLI holds
//     (../loginapp_mitm.pubkey/.privkey) and walks the real handshake
//     — PoW challenge, digest gate, LOGGED_ON with a synthesized
//     session. Basics, no account database.
//   - BaseApp (login/baseappsrv.go): stage-1 (22B → rotation → tick →
//     [44] redirect) and stage-2 (rotation-2 → double-auth → flood
//     carrier → post-flood chain) listeners. The LOGGED_ON record points
//     at stage-1, so a logged-in client reaches the staged dance, a
//     decrypt-verified flood against us, and the tail turn-taking
//     (terminator, rev answer, per-poll stats, 100 ms ticks).
//
// Usage:
//
//	wotserver [-addr 127.0.0.1:20016] [-privkey P]
//	          [-s1 127.0.0.1:32850] [-s2 127.0.0.1:32851]
//	          [-flood FILE] [-floodkey FILE]
//	          [-baseapp host:port] [-maxnonce N] [-any-version]
//	          [-digest any] [-verbose]
//
// BaseApp runs by default: the record advertises stage-1 (-s1) unless
// -baseapp overrides it, and the redirect advertises -s2 (must bind
// inside the 32810-32999 manager window — our client's parseRedirectAt
// guard only follows in-window targets). `-s1 ""` runs the LoginApp
// alone (pre-BaseApp behavior: clients park on the record).
//
// The flood carrier replays genuine stage-2 bulk frames from
// -flood/-floodkey (the flows3 capture + its CE key by default).
// Frames are re-keyed per session; the CONTENT stays the capture's
// (stale shop/offer defs — per-session bulk minting is future work).
// Without a carrier the stage-2 dance answers but errors on the flood.
// The same carrier also supplies the post-flood chain frames (the 332B
// terminator, the rev-sync answer, the stats answer and the seed tick
// for the 100 ms mint) AND the per-session smalls (info app, descriptor
// with the session name substituted, 1a/76 session dict re-pickled per
// admission, season-select 1a/5e error) — so -flood/-floodkey gate the
// whole dress-up too (see docs/NETWORK_PROTOCOL.md §18.6/§18.7).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:20016", "LoginApp UDP listen address (host:port)")
	privkey := flag.String("privkey", "mitm/loginapp_mitm.privkey",
		"PEM RSA private key for LogOnParams decryption (pairs with mods/custom-server-mod)")
	s1 := flag.String("s1", "127.0.0.1:32850", "BaseApp stage-1 listener host:port (the LOGGED_ON record shows this; \"\" = LoginApp only)")
	s2 := flag.String("s2", "127.0.0.1:32851", "BaseApp stage-2 listener host:port (the [44] redirect target; bind inside 32810-32999)")
	flood := flag.String("flood", "../captures/flows3-s2.txt", "wotproxy-style stage-2 dump for the bulk carrier (\"\" = no carrier)")
	floodKey := flag.String("floodkey", "../captures/key3.txt", "hex block key file for the carrier dump")
	baseapp := flag.String("baseapp", "", "host:port minted into the LOGGED_ON record (overrides -s1; external-advertise mode)")
	maxnonce := flag.Int64("maxnonce", int64(login.DefaultMaxNonce), "PoW easiness bound announced in challenges")
	anyVersion := flag.Bool("any-version", false, "accept any client protocol version")
	digest := flag.String("digest", "", `"any" disables the entity-defs gate (default: the pinned client truths)`)
	verbose := flag.Bool("verbose", false, "per-datagram diagnostics to stderr")
	dbPath := flag.String("db", "wotserver.db", "SQLite database path (accounts + player state)")
	defUser := flag.String("user", "admin", "default account provisioned on startup when absent")
	defPass := flag.String("pass", "admin", "password for the default account")
	flag.Parse()

	priv, err := login.LoadRSAPrivateKey(*privkey)
	if err != nil {
		fatal(err)
	}

	// Application layer: accounts, sessions, player state. The store is
	// the only thing that knows SQL; swapping it for PostgreSQL means
	// another server.Store implementation.
	store, err := server.OpenSQLite(*dbPath)
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	core := server.New(store, server.Config{
		DefaultUser:     *defUser,
		DefaultPassword: *defPass,
	})
	if err := core.Provision(context.Background()); err != nil {
		fatal(err)
	}

	cfg := login.ServerConfig{
		MaxNonce:   uint64(*maxnonce),
		AnyVersion: *anyVersion,
		Verbose:    *verbose,
		// Every login is checked against the account store; a refusal
		// rides status 68 with the error's text.
		VerifyCredentials: func(user, pass string) error {
			_, err := core.Authenticate(context.Background(), user, pass)
			return err
		},
	}
	if *digest == "any" {
		cfg.AcceptAnyDigest = true
	} else if *digest != "" {
		fatal(fmt.Errorf("wotserver: unsupported -digest %q (use \"any\" or omit)", *digest))
	}

	// BaseApp half: bind stage-1 (+ stage-2) unless -s1 is empty.
	var base *login.BaseAppServer
	var s1conn, s2conn *net.UDPConn
	if *s1 != "" {
		base, s1conn, s2conn = startBaseApp(*s1, *s2, *flood, *floodKey, *verbose)
		// LoginApp→BaseApp handoff: every finished login feeds the
		// stage-1 pending record (SessionKey, BlockKey, Name).
		cfg.OnLoggedOn = base.Admit
		if cfg.Advertise == nil {
			// The record shows the ADDRESS a client should dial, so an
			// unspecified bind host (0.0.0.0) rides 127.0.0.1 like the
			// LoginApp mirror does; a real IP rides verbatim.
			cfg.Advertise = advertiseOf(s1conn)
		}
	}
	if *baseapp != "" {
		rec, err := net.ResolveUDPAddr("udp", *baseapp)
		if err != nil {
			fatal(fmt.Errorf("wotserver: -baseapp resolve: %w", err))
		}
		cfg.Advertise = rec
	}
	srv, err := login.NewLoginAppServer(cfg, priv)
	if err != nil {
		fatal(err)
	}
	listen, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		fatal(fmt.Errorf("wotserver: -addr resolve: %w", err))
	}
	conn, err := net.ListenUDP("udp", listen)
	if err != nil {
		fatal(err)
	}
	// Startup print is public wire facts only — the private key never
	// gets a line beyond its file path.
	fmt.Printf("wotserver: LoginApp on %s (key %d bits, maxNonce %d, digest gate %s, record %s)\n",
		conn.LocalAddr(), priv.PublicKey.N.BitLen(), cfg.MaxNonce,
		digestGateName(cfg), recordName(cfg))
	// Account name and DB path are not secrets; the password never
	// gets a line.
	fmt.Printf("wotserver: accounts in %s, default account %q\n", *dbPath, server.NormalizeName(*defUser))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ctx, conn); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("loginapp: %w", err)
		}
	}()
	if base != nil {
		fmt.Printf("wotserver: BaseApp stage-1 %s, stage-2 %s (redirect target)\n", s1conn.LocalAddr(), s2conn.LocalAddr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := base.Serve(ctx, s1conn, s2conn); err != nil && err != context.Canceled {
				errCh <- fmt.Errorf("baseapp: %w", err)
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-errCh:
		fatal(err)
	default:
	}
	fmt.Println("wotserver: stopped")
}

// startBaseApp binds both listeners and builds the server: stage-2 is
// the [44] redirect target, so the ADVERTISED address must carry a
// dialed IP (an unspecified bind host advertises 127.0.0.1; a real IP
// verbatim) and must sit in the manager window for our own client.
func startBaseApp(s1arg, s2arg, flood, floodKey string, verbose bool) (*login.BaseAppServer, *net.UDPConn, *net.UDPConn) {
	l1, err := net.ResolveUDPAddr("udp", s1arg)
	if err != nil {
		fatal(fmt.Errorf("wotserver: -s1 resolve: %w", err))
	}
	l2, err := net.ResolveUDPAddr("udp", s2arg)
	if err != nil {
		fatal(fmt.Errorf("wotserver: -s2 resolve: %w", err))
	}
	s1conn, err := net.ListenUDP("udp", l1)
	if err != nil {
		fatal(err)
	}
	s2conn, err := net.ListenUDP("udp", l2)
	if err != nil {
		fatal(err)
	}
	redirect := advertiseOf(s2conn)
	base, err := login.NewBaseAppServer(login.BaseAppConfig{
		Redirect:     redirect,
		FloodPath:    flood,
		FloodKeyPath: floodKey,
		Verbose:      verbose,
	})
	if err != nil {
		fatal(err)
	}
	return base, s1conn, s2conn
}

// advertiseOf converts a bound socket into the address to write into
// the wire directives (LOGGED_ON record / [44] core): an unspecified
// bind host rides 127.0.0.1 (ip4 fields hold literals, never 0.0.0.0).
func advertiseOf(conn *net.UDPConn) *net.UDPAddr {
	la := conn.LocalAddr().(*net.UDPAddr)
	ip := la.IP
	if ip == nil || ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	return &net.UDPAddr{IP: ip, Port: la.Port}
}

// digestGateName names the configured gate (allowlist count only, the
// values are public pinned truths).
func digestGateName(cfg login.ServerConfig) string {
	if cfg.AcceptAnyDigest {
		return "any"
	}
	return fmt.Sprintf("strict(%d)", len(cfg.Digests))
}

// recordName shows the effective record endpoint (nil = listener
// mirror, resolved by the server per login).
func recordName(cfg login.ServerConfig) string {
	if cfg.Advertise == nil {
		return "listener mirror"
	}
	return cfg.Advertise.String()
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wotserver: %v\n", err)
	os.Exit(1)
}
