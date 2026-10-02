// Command wotlogin performs the World of Tanks LoginApp handshake:
// version + RSA login, Cuckoo proof-of-work challenge, retry, and the
// Blowfish-encrypted session (BaseApp address + session key), with an
// optional baseAppLogin attempt.
//
// Secrets live in a .env file, never on the command line:
//
//	wotlogin [-env .env] [-solve-timeout 120s] [-baseapp]
//
// Without valid credentials the server still issues the PoW challenge
// (proving our framing), then rejects at the second step; with valid
// WGC token credentials it returns a session.
package main

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/LockBlock-dev/wot/login"
)

func main() {
	envPath := flag.String("env", ".env", "KEY=VALUE secrets file")
	hostOverride := flag.String("host", "", "override LOGIN_HOST (e.g. try another LoginApp cluster)")
	emptyKey := flag.Bool("empty-key", false, "send an empty Blowfish key (server unencrypted-fallback probe; also needs BLOCK_KEY_EMPTY=1 semantics: skips key generation)")
	sessionGuid := flag.String("session-guid", "", "override SESSION (stored session blob text): reuse one value across runs to emulate an established machine (stable session-md5) instead of minting fresh per run")
	solveTimeout := flag.Duration("solve-timeout", 0, "override PoW budget (default from .env)")
	doBaseApp := flag.Bool("baseapp", false, "attempt baseAppLogin after LoginApp success")
	relogin := flag.Bool("relogin", false, "re-login from zero with the token2 from the basic reply (NOT game behavior — the client never re-logs; diagnostic only)")
	temporary := flag.String("temporary", "", "override TEMPORARY (\"0\" = remembered session like the genuine client, \"1\" = throwaway)")
	clientCtx := flag.String("client-context", "", "override CLIENT_CONTEXT JSON (game sends {lang_id, publication})")
	rawKey := flag.Bool("raw-key", false, "use 16 full-range random bytes as Blowfish key (like the game's RAND_bytes) instead of alphanumeric")
	bareAuth := flag.Bool("bare-auth", false, "send authenticate as bare [02][key] without the 0b trailer (poison test)")
	lobbyFlag := flag.Bool("lobby", false, "stage-2: speak the genuine opening script (syncs, requestToken, stats polls) instead of heartbeat+probes")
	probePort := flag.Bool("probe-port", false, "only test if the BaseApp port is open (connected UDP socket surfaces ICMP refused vs timeout); needs a live session, so it logs in first and skips the handshake")
	baseDelay := flag.Duration("baseapp-delay", 0, "wait after LOGGED_ON before the first BaseApp packet (push-race probe: LoginApp->manager pending propagation may lose to an immediate stage-1; the game waits ~200ms+)")
	baseBudget := flag.Duration("baseapp-budget", 150*time.Second, "outer budget for the BaseApp attempt (shorten for delay-sweep probes)")
	hijack := flag.String("hijack", "", "wotproxy -dump FILE: skip LoginApp and run BaseApp stage-1 with the GAME's live session (dump's last LOGGED_ON reply, decrypted via BLOCK_KEY_HEX = the CE key from the .env) from OUR sockets — pending-record probe; use a short -baseapp-budget, the game's pending record expires ~30 s after its LOGGED_ON, and success consumes the game's session")
	hijackPort := flag.Int("hijack-port", 0, "with -hijack: bind the stage-1 socket to this local port (0 = auto-steal the game's login source port from the dump's last 534 B C>S line); the game must be DEAD, not frozen, or the bind fails loud — a frozen game still holds the port and voids the experiment")
	onlySolve := flag.Bool("solve", false, "only solve: args are PREFIX MAXNONCE, prints key + nonces hex")
	middleOut := flag.String("middle-out", "", "append sessionmd5,middle pairs (0600) for the token2-middle function fit; values never touch stdout (lengths only)")
	threads := flag.Int("threads", 0, "PoW workers: max concurrent key attempts (<=0 = auto, 4)")
	flag.Parse()

	if *onlySolve {
		if flag.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "usage: wotlogin -solve PREFIX MAXNONCE")
			os.Exit(2)
		}
		var maxNonce uint64
		if _, err := fmt.Sscanf(flag.Arg(1), "%d", &maxNonce); err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		key, nonces, iters, err := login.SolveRaw(ctx, flag.Arg(0), maxNonce, *threads)
		if err != nil {
			fatal(err)
		}
		fmt.Println(key)
		fmt.Println(login.NoncesHex(nonces))
		fmt.Fprintf(os.Stderr, "iters=%d\n", iters)
		return
	}

	cfg, err := login.LoadEnv(*envPath)
	if err != nil {
		fatal(err)
	}
	// CLI flag overrides compose as library options (verbatim sets;
	// unset flags contribute nothing). Order mirrors the old inline
	// block: empty-key then raw-key, so raw wins when both are given.
	var opts []login.Option
	if *hostOverride != "" {
		opts = append(opts, login.WithHost(*hostOverride))
	}
	if *emptyKey {
		opts = append(opts, login.WithBlockKey(""))
	}
	if *sessionGuid != "" {
		opts = append(opts, login.WithSession(*sessionGuid))
	}
	if *temporary != "" {
		opts = append(opts, login.WithTemporary(*temporary))
	}
	if *clientCtx != "" {
		opts = append(opts, login.WithClientContext(*clientCtx))
	}
	if *rawKey {
		var kb [16]byte
		if _, err := crand.Read(kb[:]); err != nil {
			fatal(err)
		}
		opts = append(opts, login.WithBlockKey(string(kb[:])))
	}
	if *threads > 0 {
		opts = append(opts, login.WithThreads(*threads))
	}
	if *solveTimeout > 0 {
		opts = append(opts, login.WithSolveTimeout(*solveTimeout))
	}
	cfg = login.ApplyOptions(cfg, opts...)
	login.StageBareAuth = *bareAuth
	login.StageLobby = *lobbyFlag
	if *hijack != "" {
		hijackSession(cfg, *hijack, *baseBudget, *hijackPort)
		return
	}
	pubkey, err := login.LoadRSAPublicKey(cfg.PubkeyPath)
	if err != nil {
		fatal(err)
	}
	// One unconnected socket for the login phase (LoginApp sees a single
	// source). BaseApp gets its own fresh socket below (2026 game
	// behavior). A socket connect()ed to LoginApp would drop other
	// peers' datagrams in-kernel, so never connect.
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	fmt.Printf("login %s (%s) via %s:%d prot=17.1.0.5\n", cfg.Login, cfg.AuthMethod, cfg.Host, cfg.Port)
	ctx := context.Background()
	client, err := login.NewClient(cfg, pubkey, login.SolveCuckoo(cfg.Threads), conn)
	if err != nil {
		fatal(err)
	}
	solveCtx, cancel := context.WithTimeout(ctx, cfg.SolveTimeout)
	defer cancel()
	session, err := client.Login(solveCtx)
	if err != nil {
		fatal(err)
	}
	// NOTE: session.ServerMsg is never printed: for upgraded logins it
	// carries token2/session_id SSO material.
	fmt.Printf("LOGGED_ON baseapp=%s:%d sessionKey=%08x\n",
		session.ServerAddr, session.ServerPort, session.SessionKey)
	// ServerMsg KEY NAMES only, never values (SSO material): a
	// restriction flag in the login message would explain BaseApp
	// silence with a valid record + key.
	// PLUS: security_msg and isDemoAccount VALUES — these are
	// user-visible display/type info (the client shows security_msg
	// in the UI), not credentials. An account notice here (verify
	// email, sanctions, demo restrictions) would explain everything.
	if cfg.Verbose {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(session.ServerMsg), &m); err == nil {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			fmt.Fprintf(os.Stderr, "[wotlogin] servermsg keys=%v\n", keys)
			fmt.Fprintf(os.Stderr, "[wotlogin] servermsg security_msg=%s isDemoAccount=%s\n",
				string(m["security_msg"]), string(m["isDemoAccount"]))
			var tok2 string
			if raw, ok := m["token2"]; ok {
				_ = json.Unmarshal(raw, &tok2)
			}
			if tok2 != "" {
				fmt.Fprintf(os.Stderr, "[wotlogin] token2-family-match=%v\n",
					login.Token2FamilyMatch(tok2))
				if *middleOut != "" {
					recordMiddle(*middleOut, cfg.Session, tok2)
				}
			}
		}
	}
	if !*doBaseApp {
		return
	}
	basePeer := &net.UDPAddr{IP: session.ServerAddr, Port: int(session.ServerPort)}
	if *probePort {
		// Connected socket: the kernel delivers ICMP port-unreachable as
		// ECONNREFUSED on read ("refused" = dead port, timeout = open but
		// silent). Counts only, never bytes.
		cconn, err := net.DialUDP("udp", nil, basePeer)
		if err != nil {
			fatal(err)
		}
		defer cconn.Close()
		msg, err := login.BuildBaseAppProbe(client.NextReplyID(), session.SessionKey, cfg.MTU)
		if err != nil {
			fatal(err)
		}
		if _, err := cconn.Write(msg); err != nil {
			fatal(err)
		}
		buf := make([]byte, 2048)
		cconn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := cconn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("PROBE %s: %v\n", basePeer.String(), err)
		} else {
			fmt.Printf("PROBE %s: %dB reply\n", basePeer.String(), n)
		}
		return
	}
	// Token2 relogin from zero is opt-in (-relogin) and NOT game-client
	// behavior — the client never re-logs. Default rides the first
	// (basic) session into BaseApp. With -relogin, when the basic reply
	// message carries token2, start over like a brand-new client
	// (fresh socket, ids, block key) with auth_method=token2 and empty
	// password, and use the token2-originated session below.
	if token2 := login.ExtractUpgradeToken(session.ServerMsg); token2 != "" && cfg.AuthMethod == "basic" && *relogin {
		fmt.Printf("relogin from zero with token2\n")
		conn.Close()
		cfg2, err := login.LoadEnv(*envPath)
		if err != nil {
			fatal(err)
		}
		if *solveTimeout > 0 {
			cfg2.SolveTimeout = *solveTimeout
		}
		cfg2 = login.ReloginConfig(cfg2, token2)
		conn2, err := net.ListenUDP("udp", nil)
		if err != nil {
			fatal(err)
		}
		defer conn2.Close()
		solveCtx2, cancel2 := context.WithTimeout(ctx, cfg2.SolveTimeout)
		defer cancel2()
		client2, err := login.NewClient(cfg2, pubkey, login.SolveCuckoo(cfg2.Threads), conn2)
		if err != nil {
			fatal(err)
		}
		session, err = client2.Login(solveCtx2)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("RELOGGED baseapp=%s:%d sessionKey=%08x\n",
			session.ServerAddr, session.ServerPort, session.SessionKey)
		conn = conn2
		cfg = cfg2
		client = client2
		basePeer = &net.UDPAddr{IP: session.ServerAddr, Port: int(session.ServerPort)}
	}
	// Stage-1 goes out on the LOGIN socket conn (the flows3 game reuses
	// it for the whole stage-1 exchange: login :63861 → stage-1 on
	// :63861; the login3 game uses a fresh socket per stage instead —
	// EU2 answers both, so socket identity is not a gate; exe
	// BaseAppLoginRequestProtocol::setUpInterface steals the
	// ServerConnection interface for the first request). Only stage-2
	// uses the fresh socket bconn. Stage-1 CONTINUES the login RID
	// sequence (the client owns it: login#1 = First, login#2 =
	// First+1 — the server always challenges first in every capture,
	// so NextReplyID here is exactly login#2+1; genuine stage-1 rids
	// 80358/82103/50983 are each exactly login#2+1). Stage-2 mints a
	// fresh RID (genuine 95197/53365/105623).
	if *baseDelay > 0 {
		fmt.Fprintf(os.Stderr, "[wotlogin] baseapp delayed %s after LOGGED_ON (push-race probe)\n", *baseDelay)
		time.Sleep(*baseDelay)
	}
	bconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fatal(err)
	}
	defer bconn.Close()
	baseReplyID := client.NextReplyID()
	// Outer budget covers BaseAppLogin's own retries and ladder (≤3 s per
	// try, up to 10 tries per the exe request profile, plus the
	// stage scripts).
	bctx, bcancel := context.WithTimeout(ctx, *baseBudget)
	defer bcancel()
	stage := login.NewBaseAppSession(session, cfg.BlockKey, cfg.MTU, bconn, conn, basePeer)
	if err := stage.Run(bctx, baseReplyID); err != nil {
		fatal(err)
	}
	fmt.Println("LOBBY flood reached (decrypted stage-2 burst)")
}

// upgradeToken reports the token2 SHAPE in a login reply message
// (prefix + raw length, never the value: SSO material) and returns the
// value for the opt-in -relogin path. Extraction lives in the library
// (login.ExtractUpgradeToken); this stays CLI-side for the shape log.
func upgradeToken(msg string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(msg), &m); err != nil {
		return ""
	}
	// Raw token2 shape only (prefix, never the value): distinguishes
	// absent / null / "" / real-string. A null (not "") explains why
	// the relogin path rarely triggers: map[string]string fails on it.
	raw, ok := m["token2"]
	if !ok {
		fmt.Fprintf(os.Stderr, "[wotlogin] servermsg token2 key ABSENT\n")
		return ""
	}
	pre := string(raw)
	if len(pre) > 14 {
		pre = pre[:14] + "…"
	}
	fmt.Fprintf(os.Stderr, "[wotlogin] servermsg token2 raw=%s len=%d\n", pre, len(raw))
	return login.ExtractUpgradeToken(msg)
}

// hijackSession runs BaseApp stage-1 against an externally supplied live
// session (the game's, CE-paused between LOGGED_ON and its own 22B): no
// LoginApp login, no fresh session of ours. This answers the
// pending-record question stock 14.4 cannot — LoginHandler::login never
// checks the source address, so a reply proves the game's pending record
// exists and accepts foreign sockets (our sessions' records are what is
// broken → LoginApp-side routing discrimination), while silence with a
// live record means a WoT-side endpoint gate. The pending record expires
// ~30 s after the game's LOGGED_ON (PendingLogins::add, PENDING_LOGINS_TIMEOUT)
// — check the dump's reply timestamp before trusting a silent outcome.
// Success consumes the game's session (the pending record is erased).
//
// Port steal: stage-1 rides the "login-role" socket, which hijack binds
// to the game's own login source port (auto-derived from the dump, or
// -hijack-port). The game must be KILLED after LOGGED_ON, not CE-frozen:
// a frozen game still holds the port (bind fails loud, no silent
// fallback to ephemeral — that would void the experiment), and a live
// session with two senders answers the game anyway. Same IP + same
// port + same bytes + login#2+1 rid = the strongest form of the probe:
// silence then is pure server-side session state, no header left.
func hijackSession(cfg login.Config, dumpPath string, budget time.Duration, portOverride int) {
	f, err := os.Open(dumpPath)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	dump, err := login.ParseWotproxyDump(f)
	if err != nil {
		fatal(err)
	}
	session, stageRID, err := login.SessionFromDump(dump, cfg.BlockKey)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("HIJACK baseapp=%s:%d sessionKey=%08x stageRID=%d\n",
		session.ServerAddr, session.ServerPort, session.SessionKey, stageRID)
	basePeer := &net.UDPAddr{IP: session.ServerAddr, Port: int(session.ServerPort)}
	// Stage-1 rides the "login-role" socket (BaseAppLogin sends the 22B on
	// its second argument); the probe steals the game's login source
	// port so L3/L4 are identical too (same IP, same port).
	port := portOverride
	if port == 0 {
		var err error
		port, err = login.LoginSourcePort(dump)
		if err != nil {
			fatal(err)
		}
	}
	fmt.Fprintf(os.Stderr, "[wotlogin] HIJACK binding stage-1 socket to :%d\n", port)
	lconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		fatal(fmt.Errorf("hijack port :%d busy — kill the game (don't freeze it), it still holds its login socket: %w", port, err))
	}
	defer lconn.Close()
	bconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fatal(err)
	}
	defer bconn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	stage := login.NewBaseAppSession(session, cfg.BlockKey, cfg.MTU, bconn, lconn, basePeer)
	if err := stage.Run(ctx, stageRID); err != nil {
		fatal(err)
	}
	fmt.Println("LOBBY flood reached (decrypted stage-2 burst)")
}

// recordMiddle appends one sessionmd5,middle pair for the offline
// token2-middle function fit (library owns the 0600 file write; here
// only the lengths-only log). Values never touch stdout.
func recordMiddle(path, sessionBlob, token2 string) {
	n, err := login.RecordMiddle(path, sessionBlob, token2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[wotlogin] middle-out: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[wotlogin] middle-out: pairs-file len grows (sessionmd5=32 middle=%d)\n", n)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotlogin:", err)
	os.Exit(1)
}
