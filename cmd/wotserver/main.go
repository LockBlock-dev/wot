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
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/server"
	"github.com/LockBlock-dev/wot/xmppserver"
)

// Flag targets live at package scope so -config can fill the ones the
// command line left alone (see config.go).
var (
	flagAddr        *string
	flagPrivKey     *string
	flagS1          *string
	flagS2          *string
	flagFlood       *string
	flagFloodKey    *string
	flagFloodFlow   *string
	flagPost        *string
	flagPostKey     *string
	flagPostFlow    *string
	flagDefs        *string
	flagSettings    *string
	flagCBP         *bool
	flagTokenAcct   *string
	flagBaseApp     *string
	flagMaxNonce    *int64
	flagAnyVersion  *bool
	flagDigest      *string
	flagVerbose     *bool
	flagDB          *string
	flagUser        *string
	flagGarageAll   *bool
	flagPass        *string
	flagConfig      *string
	flagXMPP        *string
	flagClanTag     *string
	flagClanName    *string
	flagBattleTeam  *int
	flagArenaRejoin *bool
)

func main() {
	flagAddr = flag.String("addr", "127.0.0.1:20016", "LoginApp UDP listen address (host:port)")
	flagPrivKey = flag.String("privkey", "mitm/loginapp_mitm.privkey",
		"PEM RSA private key for LogOnParams decryption (pairs with mods/custom-server-mod)")
	flagS1 = flag.String("s1", "127.0.0.1:32850", "BaseApp stage-1 listener host:port (the LOGGED_ON record shows this; \"\" = LoginApp only)")
	flagS2 = flag.String("s2", "127.0.0.1:32851", "BaseApp stage-2 listener host:port (the [44] redirect target; bind inside 32810-32999)")
	flagSettings = flag.String("settings", "wotserver.settings.json", "JSON lobby server-settings document (the client's initialServerSettings; \"\" = empty, the client's defaults)")
	// The defs must be the build the client runs: they are the property
	// tables the client decodes entity data against, and a type that
	// changed between builds shifts every field after it. `scripts-2.4.1`
	// is the client's own tree (extracted from its scripts.pkg).
	flagDefs = flag.String("defs", "../scripts-2.4.1/entity_defs",
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
	flagGarageAll = flag.Bool("garage-all", false,
		"seed the default account's garage with every ownable vehicle the client declares, and raise its slot count to fit")
	flagConfig = flag.String("config", "", "JSON config file; flags given on the command line win")
	flagBattleTeam = flag.Int("battle-team-size", 15,
		"players per side the matchmaker needs to form a battle (0 = solo: one queued player forms one, for testing the arena and reconnect with a single client)")
	flagClanTag = flag.String("clan-tag", "ADMIN",
		"clan tag the default account joins on startup (\"\" = no clan); the tag, role and join date ride the account sync and the clan chat channel is a MUC room")
	flagClanName = flag.String("clan-name", "Admin Clan", "clan name for -clan-tag")
	flagArenaRejoin = flag.Bool("arena-rejoin", true,
		"put a returning client straight back into the battle it dropped out of; -arena-rejoin=false makes every login start in the hangar")
	flagXMPP = flag.String("xmpp", "127.0.0.1:5222",
		"XMPP chat listener host:port (the contacts list, private messages and clan channel ride it; \"\" = no chat)")
	flag.Parse()
	// The map packages, for the terrain heights the spawn needs. Derived from
	// the scripts package the defs came from when it is not given.
	if dir := os.Getenv("WOT_MAP_PACKAGES"); dir != "" {
		login.MapPackagesDir = dir
	} else if pkg := login.FindScriptsPkg(); pkg != "" {
		login.MapPackagesDir = filepath.Dir(pkg)
	}
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
	if *flagGarageAll {
		if err := seedAllVehicles(core); err != nil {
			fatal(err)
		}
	}
	if *flagClanTag != "" {
		if err := seedClan(core); err != nil {
			fatal(err)
		}
	}

	// Chat layer: the contacts list, private messages and the clan
	// channel are XMPP-only in 2.4 (the legacy BW roster calls methods
	// that do not exist in the defs), so the client only ever populates
	// them when `xmpp_enabled` is set in the settings document AND a
	// server answers. The credential is a per-run HMAC: the BaseApp hands
	// it to the client as its XMPPCS token and this service checks it, so
	// neither side stores anything.
	var chat *xmppserver.Server
	var xmppToken func(int64) string
	if *flagXMPP != "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			fatal(err)
		}
		chat = xmppserver.New(xmppserver.Config{
			Addr:   *flagXMPP,
			Domain: xmppDomain(*flagSettings),
			Secret: secret,
			Store:  store,
			// The JID node is the client databaseID (100000000 + the
			// account id), which is the id the client knows itself by.
			Nickname: func(dbid int64) string {
				acct, err := store.AccountByID(context.Background(), dbid-100000000)
				if err != nil {
					return ""
				}
				return acct.Name
			},
			// The clan tag rides the presence extension, so contacts see
			// it next to the name.
			Clan: func(dbid int64) *xmppserver.Clan {
				st, err := store.LoadState(context.Background(), dbid-100000000)
				if err != nil || st.Clan == nil {
					return nil
				}
				return &xmppserver.Clan{
					DBID:   st.Clan.DBID,
					Abbrev: st.Clan.Abbrev,
					Name:   st.Clan.Name,
				}
			},
			Logf: func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, "wotserver: "+format+"\n", args...)
			},
		})
		xmppToken = chat.TokenFor
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
		// A token login carries no password. The token2 is the credential
		// when it is a stored one: the client's "remember me" sends back
		// what the last LOGGED_ON minted. A first Steam login has none, so
		// fall back to the operator's token account.
		TokenLogin: func(name, token2 string) (int64, error) {
			if token2 != "" {
				if acct, err := store.AccountByRememberToken(context.Background(), token2); err == nil {
					return acct.ID, nil
				}
			}
			acct, err := store.AccountByName(context.Background(), name)
			if err != nil {
				return 0, err
			}
			return acct.ID, nil
		},
		// Remember the token2 the LOGGED_ON just minted, so the client's
		// "remember me" can present it on the next login. Single-use-
		// forward: this overwrites the previous one.
		OnTokenIssued: func(accountID int64, token2 string) {
			if err := store.SetRememberToken(context.Background(), accountID, token2); err != nil {
				logger.Warn("remember token", "account", accountID, "err", err)
			}
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
		// Squads live in memory: a squad is a live session object, not
		// account state, so a restart drops them (the client re-creates
		// one from the hangar).
		units := server.NewUnitManager()
		// The matchmaker: a real per-queue-type queue, platoon grouping
		// and the formation rule. It does NOT hand a battle off — that
		// needs a cell app (TODO.md #1) — so a formed battle is logged
		// and the players stay queued.
		matchmaking := server.NewMatchmaking(units)
		matchmaking.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "wotserver: "+format+"\n", args...)
		}
		// A squad member's vehicle is not on the wire, so resolve it from
		// the account's own garage.
		matchmaking.VehicleOf = func(accountID int64, invID int32) []byte {
			st, err := core.State(context.Background(), accountID)
			if err != nil {
				return nil
			}
			if int(invID) < 1 || int(invID) > len(st.Garage) {
				return nil
			}
			return st.Garage[invID-1].CompactDescr
		}
		// The purchase surface: exchange, free XP, premium, slots, berths
		// and the piggy bank. It writes through the same store as the
		// rest of the account state.
		economy := server.NewEconomy(store)
		// The crew surface: the assignment lives in the vehicle's crew
		// list, so it writes through the same store as the garage.
		crew := server.NewCrew(store)
		// The ammo and consumables layouts: the same store, the same
		// per-vehicle record.
		layouts := server.NewLayouts(store)
		// The battles. A battle is formed by the MATCHMAKER, not at login:
		// the player starts in the hangar, queues, and the queue hands them
		// off. `-battle-team-size 0` makes one queued player enough, which
		// is how the arena and reconnect are exercised with one client.
		arenas := server.NewArenas()
		matchmaking.Matchmaker().TeamSize = *flagBattleTeam
		matchmaking.OnMatch = func(match *server.Match) {
			players := make([]server.ArenaPlayer, 0, len(match.Entries))
			for _, e := range match.Entries {
				players = append(players, server.ArenaPlayer{
					AccountID:        e.AccountID,
					Name:             e.Name,
					VehicleCompDescr: e.VehicleType,
				})
			}
			arena := arenas.Create(players, match.ArenaTypeID, match.QueueType, "spaces/01_karelia")
			fmt.Fprintf(os.Stderr, "wotserver: arena %d formed from match %d (%d players, %s)\n",
				arena.ID, match.ID, len(players), arena.Map)
			for _, p := range players {
				if !base.EnterArena(p.AccountID, arenaHandoff(arena, arena.Players[p.AccountID])) {
					fmt.Fprintf(os.Stderr, "wotserver: arena %d: account %d has no session to hand off to\n",
						arena.ID, p.AccountID)
				}
			}
		}
		arenaHooks := &login.ArenaHooks{
			Rejoin: func(accountID int64) *login.ArenaHandoff {
				// A dropped player's slot is held for ReconnectWindow, and a
				// returning client goes straight back into the same battle.
				// This used to crash the client: the reset that does it
				// destroys the Account entity the lobby sync was still
				// answering on. `clientState.resetSent` now drops those
				// answers until the new entity exists, so it is safe.
				if !*flagArenaRejoin {
					return nil
				}
				arena, player, ok := arenas.Reconnect(accountID)
				if !ok {
					return nil
				}
				fmt.Fprintf(os.Stderr, "wotserver: arena %d rejoin for account %d\n", arena.ID, accountID)
				return arenaHandoff(arena, player)
			},
			Disconnect: func(accountID int64) {
				// The queue entry goes with the session. Without this a
				// client that drops while queued is still "already in the
				// queue" when it comes back, and every Battle click is
				// answered JOIN_FAILURE 18 forever.
				if matchmaking.Dequeue(accountID) {
					fmt.Fprintf(os.Stderr, "wotserver: account %d dequeued on disconnect\n", accountID)
				}
				if arena, ok := arenas.Disconnect(accountID); ok {
					fmt.Fprintf(os.Stderr, "wotserver: arena %d: account %d dropped, slot held %s\n",
						arena.ID, accountID, arenas.ReconnectWindow)
				}
			},
			Leave: func(accountID int64) {
				arenas.Leave(accountID)
			},
		}
		queueHooks := &login.QueueHooks{
			Enqueue: func(accountID int64, name string, args []int32, veh []byte) login.QueueResult {
				res := matchmaking.Enqueue(accountID, name, args, veh)
				return login.QueueResult{Code: res.Code, Message: res.Message, Added: res.Added}
			},
			Dequeue: matchmaking.Dequeue,
			Census:  matchmaking.Census,
			Handoff: matchmaking.Handoff,
		}
		base, s1conn, s2conn = startBaseApp(baseAppArgs{
			s1: *flagS1, s2: *flagS2,
			defs:      *flagDefs,
			settings:  *flagSettings,
			cbp:       *flagCBP,
			queue:     queueHooks,
			verbose:   *flagVerbose,
			xmppToken: xmppToken,
			units:     units,
			economy:   economy,
			crew:      crew,
			layouts:   layouts,
			arenas:    arenaHooks,
		})
		// LoginApp→BaseApp handoff: every finished login feeds the
		// stage-1 pending record (SessionKey, BlockKey, Name).
		// Every finished login feeds stage-1; the account's free XP
		// rides along so the 1a/69 stats small is per-account.
		cfg.OnLoggedOn = func(sess login.LoggedOnSession) {
			if sess.AccountID > 0 {
				if st, err := core.State(context.Background(), sess.AccountID); err == nil {
					sess.FreeXP = st.FreeXP
					sess.Credits = st.Credits
					sess.Gold = st.Gold
					sess.Crystal = st.Crystal
					sess.Slots = st.Slots
					// The clan rides the full-sync answer's
					// account.clanDBID / stats.clanInfo.
					sess.Clan = clanDoc(st.Clan)
					// The economy outside the stats map: the premium
					// expiry and the two piggy-bank reserves.
					sess.Berths = st.Berths
					sess.PremiumExpiry = st.PremiumExpiry
					sess.PiggyBank = st.PiggyBank
					sess.PiggyBankGold = st.PiggyBankGold
					// The garage rides the full-sync answer's inventory;
					// the client reads item type 1 unconditionally.
					for _, v := range st.Garage {
						sess.Garage = append(sess.Garage, login.GarageItem{
							InvID:        int64(len(sess.Garage) + 1),
							CompactDescr: v.CompactDescr,
							Crew:         v.Crew,
							CrewSize:     v.CrewSize,
							Shells:       v.Shells,
							Eqs:          v.Eqs,
						})
					}
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
	fmt.Printf("wotserver: player state served: %s; carried by the bundle: %s; no wire slot: %s\n",
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
	if chat != nil {
		if err := chat.Listen(); err != nil {
			fatal(err)
		}
		fmt.Printf("wotserver: XMPP chat on %s (domain %s)\n", chat.Addr(), xmppDomain(*flagSettings))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := chat.Serve(ctx); err != nil && err != context.Canceled {
				errCh <- fmt.Errorf("xmpp: %w", err)
			}
		}()
	}
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
	s1, s2   string
	defs     string
	settings string
	cbp      bool
	queue    *login.QueueHooks
	patch    func([]byte) ([]byte, error)
	verbose  bool
	// xmppToken mints the chat credential the client asks for with
	// requestToken(XMPPCS); nil leaves the request unanswered.
	xmppToken func(int64) string
	// units is the squad state behind the accountUnitClient_* calls.
	units login.UnitBackend
	// economy is the purchase surface (exchange, free XP, premium, slots,
	// berths, piggy bank).
	economy login.EconomyBackend
	// crew is the crew-assignment surface (CMD_EQUIP_TMAN).
	crew login.CrewBackend
	// layouts is the ammunition and consumables surface
	// (CMD_SET_AND_FILL_LAYOUTS).
	layouts login.LayoutBackend
	// arenas owns the battles.
	arenas *login.ArenaHooks
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
	var settings, settingsSmall []byte
	if a.settings != "" {
		settings, err = server.SettingsFromJSON(a.settings)
		if err != nil {
			if !os.IsNotExist(err) {
				fatal(err)
			}
			// No document on disk: the client runs on its own defaults,
			// which is valid but leaves the schema-validated configs
			// raising (and the hangar app never loading).
			fmt.Fprintf(os.Stderr, "wotserver: no settings document at %s; serving an empty lobby config\n", a.settings)
		}
		// The subset that rides the Account entity when it is re-created after
		// a battle: the full document is ~4.5 KB and does not fit one packet.
		settingsSmall, err = server.SettingsSubsetFromJSON(a.settings, login.AccountSettingsKeys)
		if err != nil {
			if !os.IsNotExist(err) {
				fatal(err)
			}
			settingsSmall = nil
		}
	}
	dispatch := loadDispatch(a.defs)
	// WOT_WIRE_CHECK=1 re-reads every outgoing app with the client's own
	// bundle reader and logs the ones the client would drop. The reader has
	// no resynchronisation, so one stray length field costs the whole
	// bundle (REASON_CORRUPTED_PACKET) — this says which packet, offline.
	if os.Getenv("WOT_WIRE_CHECK") == "1" && dispatch != nil {
		login.WireCheck = func(app []byte) error { return login.CheckClientApp(dispatch, app) }
		fmt.Fprintf(os.Stderr, "wotserver: wire check on — every outgoing app is re-read as the client reads it\n")
	}
	base, err := login.NewBaseAppServer(login.BaseAppConfig{
		Redirect:      redirect,
		Stage1:        advertiseOf(s1conn),
		Settings:      settings,
		SettingsSmall: settingsSmall,
		// The bundle is authored from the defs and the server's own
		// settings document; the gate decodes it once at startup so a
		// broken document fails here instead of being served as garbage.
		VerifyBulk:       server.VerifyBundle,
		Dispatch:         dispatch,
		CreateBasePlayer: a.cbp,
		Queue:            a.queue,
		Verbose:          verbose,
		XMPPToken:        a.xmppToken,
		Units:            a.units,
		Economy:          a.economy,
		Crew:             a.crew,
		Layouts:          a.layouts,
		Arenas:           a.arenas,
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

// xmppDomain reads `xmpp_host` out of the settings document, so the chat
// service answers on the domain the client was told to use. The client
// builds `dbid@<xmpp_host>/<xmpp_resource>` and gloox checks the stream's
// `to` against it, so the two must agree. A missing document or key
// falls back to "localhost", which is what the generator writes.
func xmppDomain(settingsPath string) string {
	if settingsPath == "" {
		return "localhost"
	}
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		return "localhost"
	}
	var doc struct {
		Host string `json:"xmpp_host"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Host == "" {
		return "localhost"
	}
	return doc.Host
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

// seedAllVehicles fills the default account's garage with every ownable
// vehicle the client's own item_defs declares (lobby.AllOwnableVehicles,
// generated by cmd/wotgarage) and raises its slot count to fit.
//
// The inventory entry for a vehicle is its TYPE compact descriptor — the
// client's `parseVehicleCompactDescr` reads nation and typeID out of it and
// builds the stock modules itself — so no per-vehicle module data is
// needed here.
// arenaHandoff converts a battle and one player's slot into the wire
// document the arena entry needs.
func arenaHandoff(a *server.Arena, p *server.ArenaPlayer) *login.ArenaHandoff {
	if a == nil || p == nil {
		return nil
	}
	h := &login.ArenaHandoff{
		ArenaID:     a.ID,
		SpaceID:     a.SpaceID,
		ArenaTypeID: a.ArenaTypeID,
		Map:         a.Map,
		Player: login.ArenaPlayerDoc{
			AccountID: p.AccountID,
			Name:      p.Name,
			// The wire team is 1 or 2, not 0 or 1: the client's
			// `avatar_getter.getPlayerTeam()` treats 0 as "not found" and
			// `ArenaDataProvider.__tryToGetRequiredData` then falls back to
			// a name search that also fails, leaving the battle app with no
			// player team and no player vehicle.
			Team:             p.Team + 1,
			VehicleCompDescr: p.VehicleCompDescr,
			CrewSize:         4,
			ClanAbbrev:       *flagClanTag,
			ClanDBID:         8760142,
		},
		// The client's own Vehicle entity id. It only has to be stable
		// for the battle and distinct from the Avatar's, which is random.
		VehicleID: uint32(a.ID)*100000 + uint32(p.AccountID) + 1,
	}
	// A solo battle is filled with the synthetic roster: 15 per side once the
	// player is in, which is what the official server does when the queue is
	// short. The tanks are real vehicles from the generated table (stock
	// modules, default shell, default crew); the first enemy is the TOG II,
	// because the server's damage model is that tank's collision boxes.
	if len(a.Order) <= 1 {
		playerTeam := p.Team + 1
		enemyTeam := playerTeam ^ 3
		bots := login.BotRoster(29, 14, p.VehicleCompDescr)
		for i := range bots {
			if bots[i].Team == 1 {
				bots[i].Team = playerTeam
			} else {
				bots[i].Team = enemyTeam
			}
		}
		// The damage target: the first enemy, forced to the TOG II so
		// `applyShot`'s hull/turret boxes match the tank the client draws.
		for i := range bots {
			if bots[i].Team != enemyTeam {
				continue
			}
			bots[i].Name = "Dummy"
			bots[i].VehicleCompDescr = []byte{0x51, 0xd2, 0x3f, 0x00, 0x36, 0x00, 0xcd, 0x00, 0x02, 0x00, 0x3c, 0x00, 0x24, 0x00, 0x00}
			// The TOG II's own `hull/maxHealth` from its item defs.
			bots[i].MaxHealth = 1248
			doc := bots[i]
			h.Dummy = &doc
			bots = append(bots[:i], bots[i+1:]...)
			break
		}
		h.Bots = bots
	}
	for _, id := range a.Order {
		other := a.Players[id]
		if other == nil {
			continue
		}
		h.Roster = append(h.Roster, login.ArenaPlayerDoc{
			AccountID:        other.AccountID,
			Name:             other.Name,
			Team:             other.Team + 1,
			VehicleCompDescr: other.VehicleCompDescr,
		})
	}
	return h
}

// clanDoc converts the stored clan into the wire document the account
// sync carries, or nil for a clanless account.
func clanDoc(c *server.Clan) *login.ClanDoc {
	if c == nil {
		return nil
	}
	return &login.ClanDoc{
		DBID:            c.DBID,
		Name:            c.Name,
		Abbrev:          c.Abbrev,
		ChatChannelDBID: c.ChatChannelDBID,
		Role:            c.Role,
		Joined:          c.Joined,
		Motto:           c.Motto,
		Description:     c.Description,
	}
}

// seedClan puts the default account in a clan.
//
// The game protocol can carry a clan membership — the tag next to the
// player, the role and join date on the profile summary, the clan chat
// channel — but it cannot create one: clan creation, search and
// applications all go through the web API. So the private server seeds
// the membership directly, the same way it seeds the garage.
func seedClan(core *server.Server) error {
	acct, err := core.Store.AccountByName(context.Background(), server.NormalizeName(*flagUser))
	if err != nil {
		return fmt.Errorf("wotserver: -clan-tag: default account: %w", err)
	}
	st, err := core.State(context.Background(), acct.ID)
	if err != nil {
		return fmt.Errorf("wotserver: -clan-tag: %w", err)
	}
	// A stable id derived from the tag, so re-running does not mint a new
	// clan every time (the chat channel JID is built from it).
	var dbid int64 = 1000001
	for _, b := range []byte(*flagClanTag) {
		dbid = dbid*31 + int64(b)
	}
	dbid = 1000000 + dbid%9000000
	st.Clan = &server.Clan{
		DBID:            dbid,
		Name:            *flagClanName,
		Abbrev:          *flagClanTag,
		Motto:           "Private server",
		Description:     "A clan on a private World of Tanks server.",
		Role:            1, // CLAN_MEMBER_FLAGS.LEADER
		Joined:          time.Now().UTC().Unix(),
		ChatChannelDBID: dbid,
	}
	if err := core.Store.SaveState(context.Background(), acct.ID, st); err != nil {
		return fmt.Errorf("wotserver: -clan-tag: %w", err)
	}
	fmt.Printf("wotserver: clan [%s] %q (id %d) seeded for %s\n",
		st.Clan.Abbrev, st.Clan.Name, st.Clan.DBID, acct.Name)
	return nil
}

func seedAllVehicles(core *server.Server) error {
	if err := lobby.ValidateOwnableVehicles(lobby.AllOwnableVehicles); err != nil {
		return err
	}
	acct, err := core.Store.AccountByName(context.Background(), server.NormalizeName(*flagUser))
	if err != nil {
		return fmt.Errorf("wotserver: -garage-all: default account: %w", err)
	}
	vehicles := make([]server.GarageVehicle, 0, len(lobby.AllOwnableVehicles))
	for _, v := range lobby.AllOwnableVehicles {
		vehicles = append(vehicles, server.GarageVehicle{
			CompactDescr: v.CompDescr,
			CrewSize:     v.CrewSize,
		})
	}
	st, err := core.SeedGarage(context.Background(), acct.ID, vehicles)
	if err != nil {
		return fmt.Errorf("wotserver: -garage-all: %w", err)
	}
	fmt.Printf("wotserver: garage seeded with %d vehicles, %d slots\n", len(st.Garage), st.Slots)
	return nil
}
