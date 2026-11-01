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
//	          [-digest any] [-verbose] [-config FILE]
//
// -config reads a JSON object whose keys mirror the flags (see
// wotserver.example.json). A flag given on the command line always wins
// over the file, and the file wins over the built-in default, so the
// file is a base profile and the command line stays an override.
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
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/server"
)

// Flag targets live at package scope so -config can fill the ones the
// command line left alone (see config.go).
var (
	flagAddr       *string
	flagPrivKey    *string
	flagS1         *string
	flagS2         *string
	flagFlood      *string
	flagFloodKey   *string
	flagFloodFlow  *string
	flagPost       *string
	flagPostKey    *string
	flagPostFlow   *string
	flagDefs       *string
	flagCBP        *bool
	flagTokenAcct  *string
	flagBaseApp    *string
	flagMaxNonce   *int64
	flagAnyVersion *bool
	flagDigest     *string
	flagVerbose    *bool
	flagDB         *string
	flagUser       *string
	flagPass       *string
	flagConfig     *string
)

func main() {
	flagAddr = flag.String("addr", "127.0.0.1:20016", "LoginApp UDP listen address (host:port)")
	flagPrivKey = flag.String("privkey", "mitm/loginapp_mitm.privkey",
		"PEM RSA private key for LogOnParams decryption (pairs with mods/custom-server-mod)")
	flagS1 = flag.String("s1", "127.0.0.1:32850", "BaseApp stage-1 listener host:port (the LOGGED_ON record shows this; \"\" = LoginApp only)")
	flagS2 = flag.String("s2", "127.0.0.1:32851", "BaseApp stage-2 listener host:port (the [44] redirect target; bind inside 32810-32999)")
	flagFlood = flag.String("flood", "../captures/flows3-s2.txt", "wotproxy-style stage-2 dump for the bulk carrier (\"\" = no carrier)")
	flagFloodKey = flag.String("floodkey", "../captures/key3.txt", "hex block key file for the carrier dump")
	flagFloodFlow = flag.String("floodflow", "", "flow substring to select from a multi-flow carrier dump (\"\" = single-flow dump)")
	flagPost = flag.String("post", "", "dump for the post-flood chain + pre-flood smalls (\"\" = same as -flood)")
	flagPostKey = flag.String("postkey", "", "hex block key for -post (\"\" = same as -floodkey)")
	flagPostFlow = flag.String("postflow", "", "flow substring for -post (\"\" = same as -floodflow)")
	flagDefs = flag.String("defs", "../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs",
		"scripts/entity_defs directory: decodes post-flood client calls from the defs (\"\" = hand-written reader)")
	flagTokenAcct = flag.String("token-account", "",
		"account a token login with no username lands on (\"\" = the default account; a Steam client always sends one)")
	flagCBP = flag.Bool("createbaseplayer", true,
		"send the Account entity (CreateBasePlayer) so client method calls have a target; needs -defs")
	flagBaseApp = flag.String("baseapp", "", "host:port minted into the LOGGED_ON record (overrides -s1; external-advertise mode)")
	flagMaxNonce = flag.Int64("maxnonce", int64(login.DefaultMaxNonce), "PoW easiness bound announced in challenges")
	flagAnyVersion = flag.Bool("any-version", false, "accept any client protocol version")
	flagDigest = flag.String("digest", "", `"any" disables the entity-defs gate (default: the pinned client truths)`)
	flagVerbose = flag.Bool("verbose", false, "per-datagram diagnostics to stderr")
	flagDB = flag.String("db", "wotserver.db", "SQLite database path (accounts + player state)")
	flagUser = flag.String("user", "admin@wot.test",
		"default account provisioned on startup when absent (the client's login form only accepts an email)")
	flagPass = flag.String("pass", "admin", "password for the default account")
	flagConfig = flag.String("config", "", "JSON config file; flags given on the command line win")
	flag.Parse()
	// The file fills only what the command line did not set, so a flag
	// always beats the file and the file beats the built-in default.
	fileCfg, err := loadConfig(*flagConfig)
	if err != nil {
		fatal(err)
	}
	fileCfg.apply(func(name string) bool {
		seen := false
		flag.Visit(func(f *flag.Flag) {
			if f.Name == name {
				seen = true
			}
		})
		return seen
	})

	priv, err := login.LoadRSAPrivateKey(*flagPrivKey)
	if err != nil {
		fatal(err)
	}

	// Application layer: accounts, sessions, player state. The store is
	// the only thing that knows SQL; swapping it for PostgreSQL means
	// another server.Store implementation.
	store, err := server.OpenSQLite(*flagDB)
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	// Structured lifecycle events go to stderr as text; -verbose drops
	// the level to Debug so per-step detail is available on demand.
	level := slog.LevelInfo
	if *flagVerbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	core := server.New(store, server.Config{
		DefaultUser:     *flagUser,
		DefaultPassword: *flagPass,
		Logger:          logger,
	})
	if err := core.Provision(context.Background()); err != nil {
		fatal(err)
	}

	// A Steam build authenticates with a token and leaves `login` empty,
	// so there is no name to look up: land those logins on an account.
	tokenAccount := *flagTokenAcct
	if tokenAccount == "" {
		tokenAccount = *flagUser
	}
	cfg := login.ServerConfig{
		TokenAccount: tokenAccount,
		MaxNonce:     uint64(*flagMaxNonce),
		AnyVersion:   *flagAnyVersion,
		Verbose:      *flagVerbose,
		// Every login is checked against the account store; a refusal
		// rides status 68 with the error's text.
		VerifyCredentials: func(user, pass string) (int64, error) {
			acct, err := core.Authenticate(context.Background(), user, pass)
			if err != nil {
				return 0, err
			}
			return acct.ID, nil
		},
		// A token login carries no password, so the mapped account is
		// resolved by name alone.
		TokenLogin: func(name string) (int64, error) {
			acct, err := store.AccountByName(context.Background(), name)
			if err != nil {
				return 0, err
			}
			return acct.ID, nil
		},
	}
	if *flagDigest == "any" {
		cfg.AcceptAnyDigest = true
	} else if *flagDigest != "" {
		fatal(fmt.Errorf("wotserver: unsupported -digest %q (use \"any\" or omit)", *flagDigest))
	}

	// BaseApp half: bind stage-1 (+ stage-2) unless -s1 is empty.
	var base *login.BaseAppServer
	var s1conn, s2conn *net.UDPConn
	if *flagS1 != "" {
		// The bundle's account document is patched with the default
		// account's economy. The carrier is shared by every session, so
		// this is the single-account path; per-session patching needs a
		// per-session re-fragment (the frames are rebuilt in place).
		var patch func([]byte) ([]byte, error)
		if acct, err := core.Store.AccountByName(context.Background(), server.NormalizeName(*flagUser)); err == nil {
			if st, err := core.State(context.Background(), acct.ID); err == nil {
				patch = server.BulkPatcher(func(b *server.Bundle) error {
					return server.ApplyState(b, st)
				})
			}
		}
		// The matchmaking queue: the wire layer parses the client's call
		// and answers with the client method the defs name; the queue
		// itself lives here.
		queue := server.NewQueue()
		queueHooks := &login.QueueHooks{
			Enqueue: func(accountID int64, name string, args []int32) bool {
				e := server.QueueEntry{AccountID: accountID, Name: name}
				if len(args) > 0 {
					e.QueueType = uint8(args[0])
				}
				if len(args) > 1 {
					e.VehicleID = args[1]
				}
				if len(args) > 2 {
					e.GameplaysMask = args[2]
				}
				if len(args) > 3 {
					e.ArenaTypeID = args[3]
				}
				if len(args) > 4 {
					e.RandomFlags = args[4]
				}
				return queue.Enqueue(e)
			},
			Dequeue: func(accountID int64) bool {
				_, ok := queue.Dequeue(accountID)
				return ok
			},
			Census: queue.Census,
		}
		base, s1conn, s2conn = startBaseApp(baseAppArgs{
			s1: *flagS1, s2: *flagS2,
			flood: *flagFlood, floodKey: *flagFloodKey, floodFlow: *flagFloodFlow,
			post: *flagPost, postKey: *flagPostKey, postFlow: *flagPostFlow,
			defs:    *flagDefs,
			cbp:     *flagCBP,
			queue:   queueHooks,
			patch:   patch,
			verbose: *flagVerbose,
		})
		// LoginApp→BaseApp handoff: every finished login feeds the
		// stage-1 pending record (SessionKey, BlockKey, Name).
		// Every finished login feeds stage-1; the account's free XP
		// rides along so the 1a/69 stats small is per-account.
		cfg.OnLoggedOn = func(sess login.LoggedOnSession) {
			if sess.AccountID > 0 {
				if st, err := core.State(context.Background(), sess.AccountID); err == nil {
					sess.FreeXP = st.FreeXP
				}
			}
			base.Admit(sess)
		}
		if cfg.Advertise == nil {
			// The record shows the ADDRESS a client should dial, so an
			// unspecified bind host (0.0.0.0) rides 127.0.0.1 like the
			// LoginApp mirror does; a real IP rides verbatim.
			cfg.Advertise = advertiseOf(s1conn)
		}
	}
	if *flagBaseApp != "" {
		rec, err := net.ResolveUDPAddr("udp", *flagBaseApp)
		if err != nil {
			fatal(fmt.Errorf("wotserver: -baseapp resolve: %w", err))
		}
		cfg.Advertise = rec
	}
	srv, err := login.NewLoginAppServer(cfg, priv)
	if err != nil {
		fatal(err)
	}
	listen, err := net.ResolveUDPAddr("udp", *flagAddr)
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
	fmt.Printf("wotserver: accounts in %s, default account %q\n", *flagDB, server.NormalizeName(*flagUser))
	// Say which account fields actually reach the client: the rest are
	// stored and settable but have no wire slot in any capture.
	served := server.ServedFields()
	names := make([]string, 0, len(served))
	for k := range served {
		names = append(names, k)
	}
	sort.Strings(names)
	fmt.Printf("wotserver: player state served: %s; from the capture: %s; no wire slot: %s\n",
		strings.Join(names, ", "), strings.Join(sortedKeys(server.CaptureFields()), ", "),
		strings.Join(server.UnservedFields(), ", "))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Sessions are in-memory; drop expired ones for the life of the run.
	go core.SweepLoop(ctx, 10*time.Minute)
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
// baseAppArgs groups the carrier wiring so the call site stays readable.
type baseAppArgs struct {
	s1, s2    string
	flood     string
	floodKey  string
	floodFlow string
	post      string
	postKey   string
	postFlow  string
	defs      string
	cbp       bool
	queue     *login.QueueHooks
	patch     func([]byte) ([]byte, error)
	verbose   bool
}

func startBaseApp(a baseAppArgs) (*login.BaseAppServer, *net.UDPConn, *net.UDPConn) {
	s1arg, s2arg, verbose := a.s1, a.s2, a.verbose
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
		FloodPath:    a.flood,
		FloodKeyPath: a.floodKey,
		FloodFlow:    a.floodFlow,
		PostPath:     a.post,
		PostKeyPath:  a.postKey,
		PostFlow:     a.postFlow,
		// The bundle is decoded and re-encoded at load: a carrier that
		// does not decode fails here instead of being served as garbage.
		// No account field lives in the bundle (see server.StatePatches),
		// so the re-encode is byte-identical and the frames replay
		// verbatim.
		VerifyBulk:       server.VerifyBundle,
		PatchBulk:        a.patch,
		Dispatch:         loadDispatch(a.defs),
		CreateBasePlayer: a.cbp,
		Queue:            a.queue,
		Verbose:          verbose,
	})
	if err != nil {
		fatal(err)
	}
	return base, s1conn, s2conn
}

// sortedKeys returns a map's keys in order, for a stable log line.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadDispatch builds the script model's client-facing tables, so the
// post-flood client calls are decoded from the defs rather than by the
// hand-written element reader. A missing defs directory is not fatal: the
// server falls back to the hand-written reader and says so.
func loadDispatch(dir string) *entdef.Dispatch {
	if dir == "" {
		return nil
	}
	l := &entdef.Loader{Dir: dir}
	names, err := l.LoadEntities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotserver: defs unavailable (%v); using the hand-written reader\n", err)
		return nil
	}
	d, err := entdef.NewDispatch(l, names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotserver: defs dispatch (%v); using the hand-written reader\n", err)
		return nil
	}
	fmt.Printf("wotserver: defs loaded: %d entities from %s\n", len(d.Entities()), dir)
	return d
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

// digestGateName names the configured gate: the accepted builds, or
// "any" when the gate is off. The digests themselves are public pinned
// truths and are not printed.
func digestGateName(cfg login.ServerConfig) string {
	if cfg.AcceptAnyDigest {
		return "any"
	}
	// The default table is applied inside NewLoginAppServer, so a nil
	// slice here means "the pinned builds".
	versions := cfg.Versions
	if versions == nil {
		versions = login.KnownVersions()
	}
	names := make([]string, 0, len(versions))
	for _, v := range versions {
		names = append(names, v.Name)
	}
	return "strict(" + strings.Join(names, ",") + ")"
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
