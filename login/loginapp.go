package login

// LoginApp SERVER half. Kept in one package with the client so the
// wire truth (framing, statuses, packed strings) stays shared and
// single-sourced (NETWORK_PROTOCOL.md §§3-7):
//
//	login#1 (no PoW data)      → status 66 cuckoo challenge (55 B)
//	login#2 + challengeResponse → verify solution → status 1 LOGGED_ON
//	ping (16 B startRequest)    → 16 B rid/seq echo
//
// Every shape mirrors the live EU servers pinned in the repo (55 B
// challenge, 232 B-class success, plaintext error bodies with recorded
// 64/70 texts). What live servers mint server-side (challenge
// prefixes, session ids, token2, account ids) is SYNTHESIZED here
// shape-faithfully; whenever a value is ours rather than wargaming's
// the comment says so. There is no account database: any identity is
// accepted (private server), with the digest gate enforced like the
// live one (status 70 on mismatch, allowlist = both pinned client
// truths). The LOGGED_ON record points wherever the operator says
// (-baseapp); with no stage-1 responder yet the client parks there.
//
// Offline end-to-end proof: loginapp_test.go drives login.Client
// (SolveCuckoo) over loopback UDP. Live game testing: cmd/wotserver +
// mods/custom-server-mod (the game RSA-encrypts LogOnParams to
// ../mitm/loginapp_mitm.pubkey, so -privkey is that private key).
//
// Server logs never carry secrets: usernames, passwords, keys and
// token2 ride as lengths only (job of the flags, not the wire).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/internal/cuckoo"
)

const (
	// Server-side statuses beyond the client half's constants
	// (log_on_status.hpp; the 64/70 body texts are live-recorded in
	// NETWORK_PROTOCOL.md §5.4; 65's exact server wording is
	// unobserved — ours, and labeled).
	statusMalformed   = 64
	statusBadVersion  = 65
	statusBadPassword = 68
	statusBadDigest   = 70

	// LoginInterface members the server must recognize beyond the
	// client half's login(0x00)/challengeResponse(0x03): wire table
	// order login=0, probe=1, ping=2, challengeResponse=3, mtuProbe=4
	// (§5 interface table, IDA sub_1402425B0 area; pcap-pinned IDs).
	msgPing     = 0x02 // FIXED, 1-B seq arg (WGPinger requests, §8)
	msgProbe    = 0x01 // FIXED, 0 args
	msgMTUProbe = 0x04 // VARIABLE (addMTUProbeToBundle padding)

	// Non-success reply bodies. `Unencrypted connection is not
	// allowed.` (status 64) and `Defs digest mismatch` (status 70) are
	// the live server's own words (§5.4, captured); the 65 text is a
	// server choice (unobserved wire proof).
	textUnencrypted = "Unencrypted connection is not allowed."
	textBadParams   = "Bad login parameters."
	textBadVersion  = "Bad protocol version."
	textBadDigest   = "Defs digest mismatch"
	// textBadPassword is the live server's short 68 wording (the long
	// form, "Invalid login/password for basic authentication", is the
	// basic-auth variant; §5.4).
	textBadPassword = "Invalid password."
)

// DefaultMaxNonce is the genuine 2.4.0 challenge bound (every pinned
// vector: 576716 = 0x8cccc); easiness = maxNonce/SIZE (SIZESHIFT 20,
// 1048576) = 0.55, computed server-side, never on the wire.
const DefaultMaxNonce uint64 = 576716

// ServerConfig tunes the LoginApp server. Zero values take the
// defaults documented per field. Nothing here is secret.
type ServerConfig struct {
	// MaxNonce is the PoW easiness bound announced in every challenge
	// (default DefaultMaxNonce; the solver only scans nonces < 1<<32).
	MaxNonce uint64
	// Versions is the set of client builds the server serves, each
	// pairing the protocol bytes it announces with the entity-defs
	// digest it presents (see versions.go). nil → KnownVersions(), the
	// two pinned builds. AnyVersion accepts any protocol bytes and
	// AcceptAnyDigest any digest (probes only; the live server refuses
	// mismatches with status 65 and 70 respectively).
	Versions        []ClientVersion
	AnyVersion      bool
	AcceptAnyDigest bool
	// Advertise is the endpoint minted into the LOGGED_ON record (12 B
	// ip4 + port BE + salt + key). nil → mirror the listener (IP
	// unspecified → 127.0.0.1). With no stage-1 responder the record's
	// socket stays parked — point it somewhere real once stage-1
	// exists. IPv6 endpoints cannot ride the ip4 record (rejected at
	// construction).
	Advertise *net.UDPAddr
	// OnLoggedOn fires per finished login AFTER the LOGGED_ON reply
	// is built: the BaseApp server admits the mint (pending record
	// keyed by SessionKey — the 22B handshake carries it). nil = no
	// BaseApp (clients park on the record).
	OnLoggedOn func(LoggedOnSession)
	// TokenAccount is the account a token login maps to when the client
	// sends no username. A Steam build always authenticates with a token
	// and leaves `login` empty, so without this every such login is
	// refused as an unknown account. Empty = no mapping (the login is
	// refused as before).
	TokenAccount string
	// TokenLogin resolves a token login without a password. The token2 is
	// the credential when it is a stored one (the client's "remember me");
	// a first Steam login has none and falls back to TokenAccount. nil =
	// fall back to VerifyCredentials with the (empty) password.
	TokenLogin func(name, token2 string) (int64, error)

	// OnTokenIssued fires after a login with the token2 just minted into
	// the LOGGED_ON servermsg, so the account store can remember it for
	// the client's "remember me" (single-use-forward: the next login
	// overwrites it).
	OnTokenIssued func(accountID int64, token2 string)

	// VerifyCredentials authenticates a login. It receives the plain
	// account name (extracted from the client's JSON identity document)
	// and the password, both already peeled out of the RSA layer. A
	// non-nil error refuses the login with status 68 and the error's
	// text as the server message; nil admits it and the returned id
	// becomes the session's account (0 = anonymous, the pre-account
	// behaviour). nil hook = accept anything.
	//
	// The check runs after the digest gate, so a version/defs mismatch
	// still reports 70 rather than 68.
	VerifyCredentials func(username, password string) (accountID int64, err error)
	Verbose           bool
}

// pendingChallenge is the live per-client PoW state (one at a time; a
// new login#1 replaces, a verified solution consumes).
type pendingChallenge struct {
	prefix   string // "16-hex:"; the client appends its restart index
	maxNonce uint64
	issued   time.Time
}

// loginAppPing is one LoginInterface ping request (16 B: request shape
// pinned in ping/wotping.go and §8).
type loginAppPing struct {
	rid uint32
	seq uint8
}

// loginAppLoginReq is one `login` request message (data: version 4 +
// isEncrypted 1 + params; the len field covers DATA only, §5.1).
type loginAppLoginReq struct {
	rid       uint32
	version   [4]byte
	encrypted bool
	params    []byte
}

// loginAppChallengeResp is one `challengeResponse` message (duration
// f32 + key + 42 u32 nonces, §5.3; sent unreliably, NOT request-chained).
type loginAppChallengeResp struct {
	duration float32
	key      string
	nonces   []uint32
}

// loginAppDatagram collects one C>S packet's messages.
type loginAppDatagram struct {
	pings       []loginAppPing
	challenge   *loginAppChallengeResp
	login       *loginAppLoginReq
	extraLogins int // >1 login in one datagram: first processed, rest counted
	unknown     int // messages the walk could not frame (stops there)
}

// parseLoginAppDatagram walks one C>S LoginApp datagram. Semantics
// follow the engine reader (udp_bundle_processor.cpp: isRequest ⇔
// nextRequestOffset_ == offset_, offsets measured from the 4 B prefix
// + 2 B flags; a request's nextRequestOffset u16 REPLACES the target
// for later messages, 0 = no more requests; varlen body may not touch
// the 2 B footer). FIXED members carry no wire length — ping: 1-B
// seq, probe: empty; variable members (login, challengeResponse,
// mtuProbe) share the 2-B LE length (§5 interface table).
func parseLoginAppDatagram(pkt []byte) (*loginAppDatagram, error) {
	if len(pkt) < 6+3 {
		return nil, fmt.Errorf("wotserver: datagram too short (%d B)", len(pkt))
	}
	if pkt[4] != 0x01 || pkt[5] != 0x00 {
		return nil, fmt.Errorf("wotserver: not a request packet (flags %02x %02x)", pkt[4], pkt[5])
	}
	reqOff := int(binary.LittleEndian.Uint16(pkt[len(pkt)-2:]))
	end := len(pkt) - 2
	if reqOff < 2 || reqOff+1 > end {
		return nil, fmt.Errorf("wotserver: bad first-request offset %d", reqOff)
	}
	dg := &loginAppDatagram{}
	nxt := reqOff
	abs := 6 // = prefix 4 + flags 2; engine offset_ coordinate
	for abs < end {
		isReq := abs-4 == nxt
		id := pkt[abs]
		switch id {
		case msgLogin, msgChallengeResponse, msgMTUProbe:
			if abs+3 > end {
				return nil, fmt.Errorf("wotserver: truncated length header at %d", abs)
			}
			ln := int(binary.LittleEndian.Uint16(pkt[abs+1 : abs+3]))
			hdr := abs + 3
			var rid uint32
			if isReq {
				if hdr+6 > end {
					return nil, fmt.Errorf("wotserver: truncated request header at %d", hdr)
				}
				rid = binary.LittleEndian.Uint32(pkt[hdr : hdr+4])
				hdr += 4 // ReplyID u32 LE (startRequest reserves: §5.1)
				if nro := binary.LittleEndian.Uint16(pkt[hdr : hdr+2]); nro != 0 {
					nxt = int(nro) // absolute, same base as firstRequestOffset
				} else {
					nxt = 0
				}
				hdr += 2
			}
			if hdr+ln > end {
				return nil, fmt.Errorf("wotserver: truncated payload at %d (%d+%d > %d)", hdr, hdr, ln, end)
			}
			data := append([]byte(nil), pkt[hdr:hdr+ln]...)
			switch id {
			case msgLogin:
				if !isReq {
					return nil, fmt.Errorf("wotserver: login message outside the request chain at %d", abs)
				}
				req, err := parseLoginPayload(data, rid)
				if err != nil {
					return nil, err
				}
				if dg.login == nil {
					dg.login = &req
				} else {
					dg.extraLogins++
				}
			case msgChallengeResponse:
				sol, err := parseChallengeResp(data)
				if err != nil {
					return nil, err
				}
				if dg.challenge == nil {
					dg.challenge = &sol
				} // duplicate CR never occurs live; first wins silently
			case msgMTUProbe:
				// addMTUProbeToBundle padding: nothing server-side.
			}
			abs = hdr + ln
		case msgPing:
			// FIXED member, no wire length: [02][rid 4][next 2][seq 1]
			// (genuine 16 B vector in ping/wotping.go: id at +0, rid
			// +1, next +5, seq +7; footer follows). The request header
			// is reserved for fixed members too, so the next-request
			// link chains exactly like the varlen case.
			if !isReq {
				return nil, fmt.Errorf("wotserver: ping outside the request chain at %d", abs)
			}
			if abs+8 > end {
				return nil, fmt.Errorf("wotserver: truncated ping at %d", abs)
			}
			if nro := binary.LittleEndian.Uint16(pkt[abs+5 : abs+7]); nro != 0 {
				nxt = int(nro)
			} else {
				nxt = 0
			}
			dg.pings = append(dg.pings, loginAppPing{
				rid: binary.LittleEndian.Uint32(pkt[abs+1 : abs+5]),
				seq: pkt[abs+7],
			})
			abs += 8
		case msgProbe:
			// EMPTY fixed member (§5 table): bare [01] as a message,
			// [01][rid 4][next 2] as a request (startRequest reserves
			// the header regardless of args). No live sighting; parsed
			// and skipped to keep the walk sound.
			if isReq {
				if abs+7 > end {
					return nil, fmt.Errorf("wotserver: truncated probe request at %d", abs)
				}
				if nro := binary.LittleEndian.Uint16(pkt[abs+5 : abs+7]); nro != 0 {
					nxt = int(nro)
				} else {
					nxt = 0
				}
				abs += 7
			} else {
				abs++
			}
		default:
			dg.unknown++
			abs = end // stop: framing of the rest is unknowable
		}
	}
	return dg, nil
}

// parseLoginPayload splits [version 4][isEncrypted u8][params]. The
// version rides sub,patch,minor,major (IDA sub_140E6C650 writes them
// 5,0,1,17 in that order — §5.1); rid comes from the request header
// (ReplyID u32 LE read by the walk).
func parseLoginPayload(data []byte, rid uint32) (loginAppLoginReq, error) {
	var req loginAppLoginReq
	req.rid = rid
	if len(data) < 4+1 {
		return req, fmt.Errorf("wotserver: login data too short (%d B)", len(data))
	}
	copy(req.version[:], data[:4])
	req.encrypted = data[4] == 0x01
	req.params = append([]byte(nil), data[5:]...)
	return req, nil
}

// parseChallengeResp splits [duration f32][key][nonces u32 LE...]
// (genuine 194 B message: 4+1+18+168 — §5.3). Anything else: reject.
func parseChallengeResp(data []byte) (loginAppChallengeResp, error) {
	var sol loginAppChallengeResp
	if len(data) < 4 {
		return sol, fmt.Errorf("wotserver: challenge response too short (%d B)", len(data))
	}
	sol.duration = math.Float32frombits(binary.LittleEndian.Uint32(data[:4]))
	rest := data[4:]
	key, n, err := consumePackedString(rest)
	if err != nil {
		return sol, fmt.Errorf("wotserver: challenge key: %w", err)
	}
	rest = rest[n:]
	sol.key = key
	if len(rest)%4 != 0 {
		return sol, fmt.Errorf("wotserver: challenge nonce table %d B", len(rest))
	}
	sol.nonces = make([]uint32, 0, len(rest)/4)
	for i := 0; i+4 <= len(rest); i += 4 {
		sol.nonces = append(sol.nonces, binary.LittleEndian.Uint32(rest[i:i+4]))
	}
	return sol, nil
}

// LoginAppServer answers the login handshake on one UDP socket.
// Serve owns the socket I/O; handlePacket is the pure test surface
// (same-package tests drive it without sockets). State is tiny:
// one pending challenge per client address.
type LoginAppServer struct {
	cfg     ServerConfig
	priv    *rsa.PrivateKey
	mu      sync.Mutex
	pending map[string]*pendingChallenge // client addr.String() → state
}

// NewLoginAppServer applies the config defaults and validates what can
// fail fast (the RSA key size drives the LogOnParams chunk geometry —
// see logonparams.go partSize; the PoW bound must fit the solver's
// 32-bit nonces; the record endpoint must be IPv4 like the wire's
// 4-B ip field).
func NewLoginAppServer(cfg ServerConfig, priv *rsa.PrivateKey) (*LoginAppServer, error) {
	if priv == nil {
		return nil, fmt.Errorf("wotserver: no private key (RSA chunking unavailable)")
	}
	if partSize := priv.Size() - 41 - 1; partSize <= 0 {
		return nil, fmt.Errorf("wotserver: RSA key too small (%d B)", priv.Size())
	}
	if cfg.MaxNonce == 0 {
		cfg.MaxNonce = DefaultMaxNonce
	}
	if cfg.MaxNonce > 1<<32 {
		return nil, fmt.Errorf("wotserver: PoW bound %d above the 32-bit nonce range", cfg.MaxNonce)
	}
	if cfg.Versions == nil {
		cfg.Versions = KnownVersions()
	}
	if cfg.Advertise != nil {
		if cfg.Advertise.Port == 0 {
			return nil, fmt.Errorf("wotserver: record endpoint needs a port")
		}
		if cfg.Advertise.IP != nil && cfg.Advertise.IP.To4() == nil {
			return nil, fmt.Errorf("wotserver: record endpoint %s is not IPv4 (ip4 record)", cfg.Advertise)
		}
	}
	return &LoginAppServer{
		cfg:     cfg,
		priv:    priv,
		pending: make(map[string]*pendingChallenge),
	}, nil
}

// Serve runs the read loop until ctx closes. Per datagram: handle,
// answer (one reply per packet), continue on stray/errors.
func (s *LoginAppServer) Serve(ctx context.Context, conn *net.UDPConn) error {
	listen, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("wotserver: listener has %T address, want UDP", conn.LocalAddr())
	}
	s.logf("listening on %s", listen)
	buf := make([]byte, 4096) // above twice the biggest genuine login (984 B)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			return fmt.Errorf("wotserver: read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		resp, err := s.handlePacket(pkt, from, listen)
		if err != nil {
			s.logf("%s: %v", from, err)
			continue
		}
		if resp == nil {
			continue
		}
		if _, err := conn.WriteToUDP(resp, from); err != nil {
			s.logf("%s: reply write: %v", from, err)
			continue
		}
		s.logf("%s: reply %d B", from, len(resp))
	}
}

// isTimeout reports idle-window deadline errors (the ctx anchor).
func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// logf prints to stderr only when Verbose is on (default quiet).
// Account names are fine to log, they ride the wire in plaintext
// JSON; secret material is only ever sized here (the servermsg/token2
// never reach a log line).
func (s *LoginAppServer) logf(format string, args ...any) {
	if !s.cfg.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// handlePacket maps one datagram to zero or one reply. Pings always
// echo (they share the port with logins, wotping.go §8); a datagram
// with both shapes answers the ping (never observed live; logged).
func (s *LoginAppServer) handlePacket(pkt []byte, from, listen *net.UDPAddr) ([]byte, error) {
	dg, err := parseLoginAppDatagram(pkt)
	if err != nil {
		return nil, err
	}
	if dg.unknown > 0 {
		s.logf("%s: %d unrecognized message(s) skipped", from, dg.unknown)
	}
	if len(dg.pings) > 0 {
		if len(dg.pings) > 1 {
			s.logf("%s: %d pings in one datagram, echoing the first", from, len(dg.pings))
		}
		p := dg.pings[0]
		return buildReplyPacket(p.rid, p.seq, nil)
	}
	if dg.extraLogins > 0 {
		s.logf("%s: %d extra login(s) ignored", from, dg.extraLogins)
	}
	if dg.login == nil {
		s.logf("%s: no actionable request", from)
		return nil, nil
	}
	return s.processLogin(from, listen, dg.login, dg.challenge)
}

// processLogin runs one login request to a single reply, live-server
// order: version → encryption refusal → RSA/params → PoW → digest →
// success. Login#1 (no solution) always gets a fresh challenge; login#2
// (with one) verifies and either succeeds or gets a NEW challenge (the
// live server's reject-after-faithful-flow wording is unobserved; the
// reissue is our choice — the real client hierarchy ends its flow at
// any second reply, RetryingRequest-style, so a reissue surfaces as
// "rejected status=66" on their side and the NEXT attempt starts clean).
func (s *LoginAppServer) processLogin(from, listen *net.UDPAddr, req *loginAppLoginReq, sol *loginAppChallengeResp) ([]byte, error) {
	if !s.cfg.AnyVersion && !AcceptsProto(s.cfg.Versions, req.version) {
		s.logf("%s: login rid=%d version %v rejected (known: %s)", from, req.rid, req.version, versionNames(s.cfg.Versions))
		return refusePacket(req.rid, statusBadVersion, textBadVersion)
	}
	if !req.encrypted {
		// No plaintext negotiation exists (genuine 64: "-empty-key"
		// probe; EncryptionFilter::send drops keyless packets, §6).
		s.logf("%s: login rid=%d refused unencrypted", from, req.rid)
		return refusePacket(req.rid, statusMalformed, textUnencrypted)
	}
	clear, err := decryptChunks(req.params, s.priv)
	if err != nil {
		// Malformed/misaligned RSA body; key material never logged.
		s.logf("%s: login rid=%d RSA layer rejected (params %d B)", from, req.rid, len(req.params))
		return refusePacket(req.rid, statusMalformed, textBadParams)
	}
	params, err := parseLogOnParamsClear(clear)
	if err != nil {
		s.logf("%s: login rid=%d params rejected (clear %d B)", from, req.rid, len(clear))
		return refusePacket(req.rid, statusMalformed, textBadParams)
	}
	if params.EncKey == "" {
		s.logf("%s: login rid=%d empty block key", from, req.rid)
		return refusePacket(req.rid, statusMalformed, textUnencrypted)
	}
	s.logf("%s: login rid=%d ver=%d.%d.%d.%d params %d B key len %d user len %d",
		from, req.rid, req.version[0], req.version[1], req.version[2], req.version[3],
		len(req.params), len(params.EncKey), len(params.Username))
	if sol != nil {
		if !s.verifyChallenge(from, sol) {
			s.logf("%s: PoW unverifiable, rehashing", from)
			return s.issueChallenge(from, req.rid)
		}
	} else {
		return s.issueChallenge(from, req.rid)
	}
	if !s.acceptDigest(req.version, params.Digest) {
		s.logf("%s: digest %x rejected for version %v", from, params.Digest, req.version)
		return refusePacket(req.rid, statusBadDigest, textBadDigest)
	}
	// The account this login lands on. params.Username is the client's JSON
	// identity document ({"login": …, "auth_realm": …, "auth_method": …});
	// a token login leaves `login` empty and lands on the operator's token
	// account instead. This name is what the Account entity carries and the
	// hangar shows, so it must be a name — never the document.
	name := userNameOf(params.Username)
	if mapped := tokenLoginName(params.Username, s.cfg.TokenAccount); mapped != "" {
		// A token login with no username: land it on the account the
		// operator named, so a Steam client can test the server.
		s.logf("%s: login rid=%d token login (no username) → account %q", from, req.rid, mapped)
		name = mapped
	}
	token2 := token2Of(params.Username)
	var accountID int64
	if s.cfg.VerifyCredentials != nil {
		// A token2 the server has stored IS the credential: the client's
		// "remember me" presents it WITH the account's name and a bogus
		// password, so the password check must not run. A nameless token
		// login is the other shape — a Steam client with no stored tail,
		// which lands on the operator's account below.
		if token2 != "" && name != "" && s.cfg.TokenLogin != nil {
			if id, err := s.cfg.TokenLogin(name, token2); err == nil {
				s.logf("%s: login rid=%d remember-me token accepted", from, req.rid)
				return s.loggedOn(from, listen, req.rid, req.version, params, id, name)
			}
			s.logf("%s: login rid=%d remember-me token rejected, trying the password", from, req.rid)
		}
		if name != userNameOf(params.Username) && s.cfg.TokenLogin != nil {
			// The token is the credential; there is no password to check.
			id, err := s.cfg.TokenLogin(name, token2)
			if err != nil {
				s.logf("%s: login rid=%d token account %q rejected", from, req.rid, name)
				return refusePacket(req.rid, statusBadPassword, textBadPassword)
			}
			return s.loggedOn(from, listen, req.rid, req.version, params, id, name)
		}
		id, err := s.cfg.VerifyCredentials(name, params.Password)
		if err != nil {
			// Never log the password or the account name: lengths only.
			s.logf("%s: login rid=%d credentials rejected (user len %d)",
				from, req.rid, len(params.Username))
			text := err.Error()
			if text == "" {
				text = textBadPassword
			}
			return refusePacket(req.rid, statusBadPassword, text)
		}
		accountID = id
	}
	return s.loggedOn(from, listen, req.rid, req.version, params, accountID, name)
}

// issueChallenge mints the PoW state and answers status 66 (55 B for
// the genuine prefix/maxNonce values: §5.2).
func (s *LoginAppServer) issueChallenge(from *net.UDPAddr, rid uint32) ([]byte, error) {
	prefix, err := newChallengePrefix()
	if err != nil {
		return nil, fmt.Errorf("wotserver: challenge prefix: %w", err)
	}
	pend := &pendingChallenge{prefix: prefix, maxNonce: s.cfg.MaxNonce, issued: time.Now()}
	s.setPending(from, pend)
	s.logf("%s: challenge prefix=%s maxNonce=%d", from, prefix, pend.maxNonce)
	return buildReplyPacket(rid, statusChallengeIssued, challengeBody(prefix, pend.maxNonce))
}

// verifyChallenge checks a solution against this client's pending
// challenge and consumes it on success. The vendor Verify reads
// exactly PROOFSIZE=42 entries (cuckoo.go), so a short table is
// rejected before it can index out of range.
func (s *LoginAppServer) verifyChallenge(from *net.UDPAddr, sol *loginAppChallengeResp) bool {
	s.mu.Lock()
	pend := s.pending[from.String()]
	s.mu.Unlock()
	if pend == nil {
		s.logf("%s: no pending challenge (restart or dropped flow)", from)
		return false
	}
	if len(sol.nonces) != int(cuckoo.PROOFSIZE) {
		s.logf("%s: PoW nonce table %d (want %d)", from, len(sol.nonces), cuckoo.PROOFSIZE)
		return false
	}
	if !strings.HasPrefix(sol.key, pend.prefix) {
		s.logf("%s: PoW key is not our prefix", from)
		return false
	}
	if !cuckoo.NewCuckoo([]byte(sol.key)).Verify(toU64(sol.nonces), pend.maxNonce) {
		s.logf("%s: PoW verification failed", from)
		return false
	}
	s.consumePending(from)
	return true
}

// acceptDigest is the entity-defs gate (live semantics: never zero,
// never foreign — status 70 otherwise). The digest is checked against
// the version the client announced, so a build's protocol bytes paired
// with another build's digest is refused rather than accepted by a flat
// allowlist.
func (s *LoginAppServer) acceptDigest(proto [4]byte, d [16]byte) bool {
	if s.cfg.AcceptAnyDigest {
		return true
	}
	_, ok := Identify(s.cfg.Versions, proto, d)
	return ok
}

// versionName labels the build behind a login, or "unknown" when the
// gates are off and the pair matches nothing.
func (s *LoginAppServer) versionName(proto [4]byte, digest [16]byte) string {
	if v, ok := Identify(s.cfg.Versions, proto, digest); ok {
		return v.Name
	}
	return "unknown"
}

// versionNames renders the known builds for a log line.
func versionNames(versions []ClientVersion) string {
	if len(versions) == 0 {
		return "none"
	}
	out := ""
	for i, v := range versions {
		if i > 0 {
			out += ", "
		}
		out += v.Name
	}
	return out
}

// loggedOn builds the success reply: [FF][rid][status 1][Blowfish body]
// with the 12 B record + servermsg packed by the client's key
// (encryptLogin — the login path carries NO magic/wastage trailer,
// crypto.go): body total = record 12 + 1 + msg + zero pad to 8
// (genuine 216 B plaintext). Record endpoint mirrors the operator
// choice; salt stays 0 (its semantics are unobserved — our reader
// skips it). session_id/token2/account id are SYNTHESIZED shapes.
func (s *LoginAppServer) loggedOn(from, listen *net.UDPAddr, rid uint32, proto [4]byte, params LogOnParams, accountID int64, accountName string) ([]byte, error) {
	name := displayNameOf(accountName)
	token2, err := randToken2(accountIDFor(accountID, accountName))
	if err != nil {
		return nil, fmt.Errorf("wotserver: token2 mint: %w", err)
	}
	sessID, err := randSessionID()
	if err != nil {
		return nil, fmt.Errorf("wotserver: session_id mint: %w", err)
	}
	msg, err := serverMsgJSON(name, sessID, token2)
	if err != nil {
		return nil, fmt.Errorf("wotserver: servermsg: %w", err)
	}
	key, err := randSessionKey()
	if err != nil {
		return nil, fmt.Errorf("wotserver: session key: %w", err)
	}
	ip, port, err := recordAddr(s.cfg, listen)
	if err != nil {
		return nil, err
	}
	plain := loggedOnPlain(ip, port, key, msg)
	body, err := encryptLogin(params.EncKey, plain)
	if err != nil {
		return nil, fmt.Errorf("wotserver: reply encrypt: %w", err)
	}
	if s.cfg.OnLoggedOn != nil {
		s.cfg.OnLoggedOn(LoggedOnSession{
			SessionKey: key, BlockKey: params.EncKey, Name: name,
			AccountID: accountID, Version: s.versionName(proto, params.Digest),
		})
	}
	if s.cfg.OnTokenIssued != nil && accountID > 0 {
		s.cfg.OnTokenIssued(accountID, token2)
	}
	s.logf("%s: LOGGED_ON rid=%d %s:%d plain %d B msg %d B", from, rid, net.IP(ip[:]), port, len(plain), len(msg))
	return buildReplyPacket(rid, statusLoggedOn, body)
}

// setPending stores this client's challenge state (locked map, one entry).
func (s *LoginAppServer) setPending(from *net.UDPAddr, pend *pendingChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[from.String()] = pend
}

// consumePending drops the entry. Only a verified solution gets here:
// every rejection path reissues a fresh challenge, and issueChallenge
// OVERWRITES the pending entry, so stale state never lingers.
func (s *LoginAppServer) consumePending(from *net.UDPAddr) {
	s.mu.Lock()
	delete(s.pending, from.String())
	s.mu.Unlock()
}

// recordAddr resolves the LOGGED_ON record endpoint: explicit
// Advertise, else the listener (IP-unspecified addresses ride
// 127.0.0.1 — the ip4 field holds a literal address, never 0.0.0.0).
func recordAddr(cfg ServerConfig, listen *net.UDPAddr) ([4]byte, uint16, error) {
	var out [4]byte
	target := cfg.Advertise
	if target == nil {
		target = listen
	}
	if target.IP == nil {
		copy(out[:], net.IPv4(127, 0, 0, 1))
		return out, uint16(target.Port), nil
	}
	ip4 := target.IP.To4()
	if ip4 == nil {
		return out, 0, fmt.Errorf("wotserver: record endpoint %s is not IPv4 (ip4 record)", target)
	}
	copy(out[:], ip4)
	return out, uint16(target.Port), nil
}

// refusePacket renders a non-success reply: [FF][rid][status][packed
// text], PLAINTEXT (65/68/70 live bodies carry no Blowfish, §5.4).
func refusePacket(rid uint32, status uint8, text string) ([]byte, error) {
	return buildReplyPacket(rid, status, appendPackedString(nil, text))
}

// challengeBody packs [type][prefix][maxNonce u64 LE] — exactly the
// live 55 B body (§5.2, TestParseChallengeReply vectors).
func challengeBody(prefix string, maxNonce uint64) []byte {
	body := appendPackedString(nil, challengeCuckoo)
	body = appendPackedString(body, prefix)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], maxNonce)
	return append(body, tmp[:]...)
}

// buildReplyPacket: [prefix 4][flags 00 00][FF][len u32][rid][status]
// [body]. len covers rid(4)+status(1)+body; replies carry NO
// request-offset footer (genuine §5.2-§5.4; client parseReply insists
// on flags 00 00). The 4 B prefix is fresh per reply — server-origin
// prefixes vary per packet (§3) and must stay non-constant.
func buildReplyPacket(rid uint32, status uint8, body []byte) ([]byte, error) {
	var pfx [4]byte
	if _, err := rand.Read(pfx[:]); err != nil {
		return nil, fmt.Errorf("wotserver: reply prefix: %w", err)
	}
	pkt := make([]byte, 0, 16+len(body))
	pkt = append(pkt, pfx[:]...)
	pkt = append(pkt, 0x00, 0x00, msgReply)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(5+len(body)))
	pkt = append(pkt, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], rid)
	pkt = append(pkt, tmp[:]...)
	pkt = append(pkt, status)
	return append(pkt, body...), nil
}

// newChallengePrefix generates the genuine format: 16 hex chars + ':'
// (§5.2 samples fca223380bde7178:/39e832d014cceb66:); the client
// appends its restart index (":0" in every observed login#2).
func newChallengePrefix() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]) + ":", nil
}

// loggedOnPlain builds the pre-encryption body:
//
//	{ip4 4}{port u16 BE}{salt u16}{sessionKey u32 LE}{packed msg}{pad}
//
// Layout per parseSessionRecord/sub_142AD3580 (§5.4); the pad zeros
// the Blowfish block boundary (genuine: 12+1+199+4 = 216).
func loggedOnPlain(ip [4]byte, port uint16, sessionKey uint32, msg string) []byte {
	plain := make([]byte, 0, 12+1+len(msg)+8)
	plain = append(plain, ip[:]...)
	var tmp [4]byte
	binary.BigEndian.PutUint16(tmp[:2], port) // record port is network order
	plain = append(plain, tmp[0], tmp[1])
	plain = append(plain, 0, 0) // salt: value unobserved live; reader ignores it
	binary.LittleEndian.PutUint32(tmp[:], sessionKey)
	plain = append(plain, tmp[0], tmp[1], tmp[2], tmp[3])
	plain = appendPackedString(plain, msg)
	for len(plain)%8 != 0 {
		plain = append(plain, 0)
	}
	return plain
}

// randSessionKey mints the per-login u32 the game must echo into its
// 22 B stage-1 handshake (flows3 key-equality proof, wot/AGENTS.md).
func randSessionKey() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw[:]), nil
}

// ——— synthesized identity values (shape-faithful; VALUES are ours) ———

// userNameOf extracts the plain account name from params.Username
// (config.go JSON: {"login": "name", ...}) for the servermsg mirror.
// Non-JSON or wrong-shape input falls back to the raw string (probes,
// hijacks). No account database: any name is accepted.
//
// A token2 login sends the identity document with an EMPTY `login` — the
// credential is the token, not a name. Returning the raw blob in that case
// is what put the whole document (session id and token2 included) into the
// Account entity's `name`, which the hangar then renders in its top-left
// corner. An empty `login` means "no name here", so say so and let the
// caller fall back to the account the login lands on.
func userNameOf(usernameJSON string) string {
	var doc map[string]string
	if err := json.Unmarshal([]byte(usernameJSON), &doc); err == nil {
		return doc["login"]
	}
	return usernameJSON
}

// displayNameOf turns an account name into the in-game name the client
// shows: the local part of the login, since a WoT player name never
// carries the `@domain` the login form requires.
func displayNameOf(accountName string) string {
	if i := strings.IndexByte(accountName, '@'); i > 0 {
		return accountName[:i]
	}
	return accountName
}

// tokenLoginName returns the account a token login maps to, or "" when the
// login carries a real username.
//
// A Steam build authenticates with a token and leaves `login` empty: the
// identity document is {"auth_method": "token2", "token2": …, "login": ""}.
// There is no name to look up, so the operator names the account such a
// login lands on.
func tokenLoginName(usernameJSON, fallback string) string {
	if fallback == "" {
		return ""
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(usernameJSON), &doc); err != nil {
		return ""
	}
	if doc["login"] != "" {
		return ""
	}
	if doc["token2"] == "" && doc["token"] == "" {
		return ""
	}
	return fallback
}

// token2Of extracts the token2 from the client's JSON identity document.
// A token login carries it in `token2`; older shapes use `token`.
func token2Of(usernameJSON string) string {
	var doc map[string]string
	if err := json.Unmarshal([]byte(usernameJSON), &doc); err != nil {
		return ""
	}
	if t := doc["token2"]; t != "" {
		return t
	}
	return doc["token"]
}

// accountIDFor maps a stored account id into the 9-digit space the
// token2 head and the session dict's databaseID use (§5.4). The real id
// is authoritative, so two accounts always differ; id 0 (no account
// store, the pre-account behaviour) falls back to the name hash.
func accountIDFor(accountID int64, name string) uint64 {
	if accountID > 0 {
		return 100000000 + uint64(accountID)
	}
	return pseudoAccountID(name)
}

// pseudoAccountID mints the token2 account id from the name: FNV-1a64
// floor-biased into [1e8, 1e9) → always 9 digits (the genuine token2
// head; §5.4). Only used when no account store is configured.
func pseudoAccountID(name string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	return 100000000 + h.Sum64()%900000000
}

// randDigits returns n random decimal digits (crypto/rand).
func randDigits(n int) (string, error) {
	const digits = "0123456789"
	out := make([]byte, n)
	for i := range out {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		out[i] = digits[k.Int64()]
	}
	return string(out), nil
}

// randDigitsNonZero mints an n-digit decimal without a leading zero
// (head digit [1..9], tail digits [0..9]) — segments render as real
// decimals on the live wire.
func randDigitsNonZero(n int) (string, error) {
	var head string
	for {
		h, err := randDigits(1)
		if err != nil {
			return "", err
		}
		if h != "0" {
			head = h
			break
		}
	}
	rest, err := randDigits(n - 1)
	if err != nil {
		return "", err
	}
	return head + rest, nil
}

// randToken2 mints the 69-char token2 shape seen on EVERY live session
// and pinned from the genuine servermsg (§5.4,
// captures/game_20260920.log:413): head 9 digits + ":" + middle 19
// digits + ":" + tail 39 digits (9+1+19+1+39). Values are ours; live
// middles/tails are Wargaming-issued (families in wot/AGENTS.md).
func randToken2(accountID uint64) (string, error) {
	mid, err := randDigitsNonZero(19)
	if err != nil {
		return "", err
	}
	tail, err := randDigitsNonZero(39)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%s:%s", accountID, mid, tail), nil
}

// crockfordSession is the alphabet of the 32-char session ids in live
// servermsgs: digits + letters minus I/L/O/U (32 runes; census of the
// genuine ids, §5.4). The literal stretches ride the constants below.
const crockfordSession = "0123456789ABCDEFGHJKMNPQRSTUVWXYZ"

// sessionHead/sessionMid/sessionCore are the constant stretches of the
// three genuine EU2 session ids (captures/game_20260920.log:413,:4871 +
// login3-game.log: 06GC0TZYRM|06GC108Z8W|06GBB2YGPM then 00000041VPHF…):
// [0:3]="06G", [10:16]="000000", [16:22]="41VPHF", random elsewhere.
// Char-3 drifts B→C across days (suspected time field) — not
// reproduced; ids are SYNTHESIZED within the observed structural
// space, all three samples land inside it.
const (
	sessionHead = "06G"
	sessionMid  = "000000"
	sessionCore = "41VPHF"
)

// randSessionID mints the 32-char session_id (§5.4 shape): "06G" + 7
// random alphabet chars, "000000" at [10:16], "41VPHF" at [16:22],
// 10 more random.
func randSessionID() (string, error) {
	out := make([]byte, 0, 32)
	span := func(n int) error {
		for i := 0; i < n; i++ {
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(crockfordSession))))
			if err != nil {
				return err
			}
			out = append(out, crockfordSession[k.Int64()])
		}
		return nil
	}
	out = append(out, sessionHead...)
	if err := span(7); err != nil {
		return "", err
	}
	out = append(out, sessionMid...)
	out = append(out, sessionCore...)
	if err := span(10); err != nil {
		return "", err
	}
	return string(out), nil
}

// serverMsgJSON builds the LOGGED_ON servermsg exactly like the live
// one (§5.4, captures/game_20260920.log:413): flat compact JSON, field
// order isDemoAccount,name,security_msg,session_id,token2, no HTML
// escaping. security_msg stays "old_pass" (every recent live session;
// demo/maintenance accounts differ server-side). Names/ids may carry
// " safety: only token2/sessionID are ours and both are alnum.
func serverMsgJSON(name, sessionID, token2 string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	doc := struct {
		IsDemoAccount bool   `json:"isDemoAccount"`
		Name          string `json:"name"`
		SecurityMsg   string `json:"security_msg"`
		SessionID     string `json:"session_id"`
		Token2        string `json:"token2"`
	}{
		Name:        name,
		SecurityMsg: "old_pass",
		SessionID:   sessionID,
		Token2:      token2,
	}
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
