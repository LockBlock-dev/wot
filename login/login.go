// Package login speaks the World of Tanks LoginApp handshake.
//
// Wire framing per datagram (see NETWORK_PROTOCOL.md §§3-5): a 4-byte
// cleartext prefix the server ignores, 2-byte little-endian Mercury
// flags, then LoginInterface messages (login=0, probe=1, ping=2,
// challengeResponse=3, mtuProbe=4), then footers ending in the 2-byte
// first-request offset.
//
// The handshake this package implements:
//
//  1. login request: version 17.1.0.5 + RSA-OAEP-2048 LogOnParams.
//  2. server replies LOGIN_CHALLENGE_ISSUED (status 66) with a
//     "cuckoo_cycle" proof-of-work (prefix string + maxNonce u64).
//  3. client solves it (internal/cuckoo) and retries login with a
//     challengeResponse message prepended (duration float32 + key +
//     42 nonces).
//  4. server replies LOGGED_ON (status 1) with a Blowfish-encrypted
//     LoginReplyRecord (serverAddr + sessionKey), optionally followed
//     by baseAppLogin (plaintext, session key + attempts + MTU).
package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"time"

	"github.com/LockBlock-dev/wot/internal/cuckoo"
)

const (
	// DefaultPort is the LoginApp UDP port.
	DefaultPort = 20016

	// LoginInterface message IDs (IDA sub_142AD7A30 thunks + pcap).
	msgLogin             = 0x00
	msgChallengeResponse = 0x03

	// Mercury reply marker and flags.
	msgReply        = 0xFF
	flagHasRequests = 0x0001

	// Client-server protocol version 17.1.0.5, streamed as
	// sub, patch, minor, major (IDA sub_140E6C650).
	verSub, verPatch, verMinor, verMajor = 5, 0, 1, 17

	// Login reply statuses (log_on_status.hpp; only the ones we act on).
	statusLoggedOn        = 1
	statusChallengeIssued = 66

	challengeCuckoo = "cuckoo_cycle"
)

// Challenge is a parsed LOGIN_CHALLENGE_ISSUED reply.
type Challenge struct {
	ReplyID   uint32 // echoed in the follow-up login request
	Type      string // e.g. "cuckoo_cycle"
	Prefix    string // PoW key prefix, e.g. "fca223380bde7178:"
	MaxNonce  uint64 // easiness bound; solution nonces must be below it
	RawPrefix string // reserved for future challenge types
}

// Session is a successful login outcome.
type Session struct {
	ServerAddr net.IP // BaseApp address to continue with
	ServerPort uint16 // BaseApp port (ephemeral, e.g. 32814)
	SessionKey uint32 // authenticates baseAppLogin
	ServerMsg  string // optional greeting from LoginApp
}

// randomPrefix returns the 4-byte per-packet prefix. Live servers ignore
// its content (random bytes accepted); its generation is unresolved.
func randomPrefix() (p [4]byte, err error) {
	_, err = rand.Read(p[:])
	return p, err
}

// NewReplyID returns a fresh random Mercury ReplyID. The live client
// starts each new transport (e.g. a BaseApp on another host) with a fresh
// value (login2.pcapng: login sequence 50981→50982→50983 on the login
// host, then 105111 on the new BaseApp host) rather than continuing the
// old sequence. Values stay small like all genuine ReplyIDs (< 2^17).
func NewReplyID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]) & 0x1FFFF, nil
}

// requestFooter returns the 2-byte first-request-offset footer: the offset
// of the first request message header relative to the flags field.
func requestFooter(firstReqOff int) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(firstReqOff))
	return b
}

// buildChallengeResponseMsg builds [ID=3][len u16][duration f32][key blob].
// The blob is a packed string key followed by 42 little-endian u32 nonces.
func buildChallengeResponseMsg(duration time.Duration, key string, nonces []uint32) []byte {
	out := []byte{msgChallengeResponse, 0, 0}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(float32(duration.Seconds())))
	out = append(out, tmp[:]...)
	out = appendPackedString(out, key)
	for _, n := range nonces {
		binary.LittleEndian.PutUint32(tmp[:], n)
		out = append(out, tmp[:]...)
	}
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(out)-3))
	return out
}

// buildLoginMsg builds [ID=0][len u16][replyID u32][nextOff 00 00]
// [version 4][isEncrypted u8][params]. The len field covers the request
// DATA only (version+params), NOT the 6 request-header bytes
// (ReplyID+nextOff): Bundle::startRequest reserves those via newMessage's
// extra arg, and endMessage measures msgLen past them, so compressLength
// writes data length (OSE udp_bundle.cpp). Proof on the wire: real
// login#1 has len 517 = 4+1+512, i.e. two whole RSA-2048 blocks with the
// shipped key — the old code counted the 6 header bytes inside len
// (261+6), shifting the server's parse and corrupting decrypt.
// params is the RSA ciphertext when encrypted, else raw cleartext.
func buildLoginMsg(replyID uint32, version [4]byte, params []byte, encrypted bool) []byte {
	out := []byte{msgLogin, 0, 0}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], replyID)
	out = append(out, tmp[:]...)
	out = append(out, 0x00, 0x00) // next-request link: last request
	out = append(out, version[:]...)
	if encrypted {
		out = append(out, 0x01) // isEncrypted: RSA encoder present
	} else {
		out = append(out, 0x00) // plaintext LogOnParams (encoder absent)
	}
	out = append(out, params...)
	// Request len excludes the 6 header bytes (ReplyID + nextOff).
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(out)-3-6))
	return out
}

// buildLoginPacket assembles [prefix][flags][messages...][pad?][reqOff].
// reqOff points at the first *request* message (challengeResponse, sent
// unreliably via startMessage, is skipped when chaining — but still
// occupies bytes, so offsets advance past it; pcap pkt2 proves this:
// CR(194 B) at rel 2, login at rel 196, footer c4 00=196). footerPad
// prepends zero bytes before reqOff: 2022 captures show 6 unexplained
// bytes there that the current build may or may not require
// (Config.FooterPad, default 0).
func buildLoginPacket(prefix [4]byte, footerPad int, msgs ...[]byte) []byte {
	pkt := append([]byte{}, prefix[:]...)
	pkt = append(pkt, 0x01, 0x00) // flags = HAS_REQUESTS
	off := 2                      // relative to flags, like the client
	reqOff := 0
	for _, m := range msgs {
		if m[0] != msgChallengeResponse && reqOff == 0 {
			reqOff = off
		}
		off += len(m)
		pkt = append(pkt, m...)
	}
	if reqOff == 0 {
		reqOff = off // no requests (should not happen for login)
	}
	for i := 0; i < footerPad; i++ {
		pkt = append(pkt, 0x00)
	}
	return append(pkt, requestFooter(reqOff)...)
}

// parseReply splits [prefix][flags][FF][len u32][replyID][status][rest...].
func parseReply(pkt []byte) (replyID uint32, status uint8, rest []byte, err error) {
	if len(pkt) < 4+2+1+4+4+1 {
		return 0, 0, nil, fmt.Errorf("wotlogin: reply too short (%d B)", len(pkt))
	}
	if pkt[4] != 0x00 || pkt[5] != 0x00 {
		return 0, 0, nil, fmt.Errorf("wotlogin: reply flags %02x %02x", pkt[4], pkt[5])
	}
	if pkt[6] != msgReply {
		return 0, 0, nil, fmt.Errorf("wotlogin: not a reply (ID %02x)", pkt[6])
	}
	ln := int(binary.LittleEndian.Uint32(pkt[7:11]))
	if len(pkt) < 11+ln {
		return 0, 0, nil, fmt.Errorf("wotlogin: truncated reply (%d < %d)", len(pkt), 11+ln)
	}
	replyID = binary.LittleEndian.Uint32(pkt[11:15])
	status = pkt[15]
	return replyID, status, pkt[16 : 11+ln], nil
}

// parseChallenge reads status-66 bodies: [type str][prefix str][maxNonce u64].
func parseChallenge(rest []byte) (Challenge, error) {
	var c Challenge
	typ, n, err := consumePackedString(rest)
	if err != nil {
		return c, fmt.Errorf("wotlogin: challenge type: %w", err)
	}
	rest = rest[n:]
	prefix, n, err := consumePackedString(rest)
	if err != nil {
		return c, fmt.Errorf("wotlogin: challenge prefix: %w", err)
	}
	rest = rest[n:]
	if len(rest) < 8 {
		return c, errors.New("wotlogin: challenge missing maxNonce")
	}
	c.Type = typ
	c.Prefix = prefix
	c.MaxNonce = binary.LittleEndian.Uint64(rest[:8])
	return c, nil
}

// Login runs the full LoginApp handshake on a connected UDP socket:
// login, PoW challenge, login retry, success. Without valid credentials
// the server still issues the challenge (proving our framing), then
// rejects; with valid ones it returns the BaseApp Session.
func Login(ctx context.Context, conn *net.UDPConn, cfg Config, pubkey *RSAPublicKey, solve SolveFunc) (Session, error) {
	var zero Session
	peer, err := cfg.Peer()
	if err != nil {
		return zero, fmt.Errorf("wotlogin: resolve: %w", err)
	}
	nextReplyID := cfg.FirstReplyID
	// Attempt 1: bare login (no challenge data yet).
	params, err := encodeLogOnParams(cfg, pubkey)
	if err != nil {
		return zero, err
	}
	var ver = [4]byte{verSub, verPatch, verMinor, verMajor}
	prefix, err := randomPrefix()
	if err != nil {
		return zero, err
	}
	msg := buildLoginMsg(nextReplyID, ver, params, cfg.Encrypted)
	cfg.debugf("login#1: %d B (replyID %d)", 6+len(msg)+2+cfg.FooterPad, nextReplyID)
	pkt := buildLoginPacket(prefix, cfg.FooterPad, msg)
	data, err := roundTripRetry(ctx, conn, peer, pkt, cfg)
	if err != nil {
		return zero, err
	}
	replyID, status, rest, err := parseReply(data)
	if err != nil {
		return zero, err
	}
	if status == statusLoggedOn {
		return decryptSession(rest, cfg.BlockKey)
	}
	if status != statusChallengeIssued || replyID != nextReplyID {
		return zero, fmt.Errorf("wotlogin: unexpected login reply status=%d", status)
	}
	ch, err := parseChallenge(rest)
	if err != nil {
		return zero, err
	}
	if ch.Type != challengeCuckoo {
		return zero, fmt.Errorf("wotlogin: unsupported challenge %q", ch.Type)
	}
	// Solve and retry with the response prepended.
	started := time.Now()
	key, nonces, err := solve(ctx, ch)
	if err != nil {
		return zero, fmt.Errorf("wotlogin: pow(type=%s prefix=%q maxNonce=%d): %w", ch.Type, ch.Prefix, ch.MaxNonce, err)
	}
	if !cuckoo.NewCuckoo([]byte(key)).Verify(toU64(nonces), ch.MaxNonce) {
		return zero, fmt.Errorf("wotlogin: own PoW solution fails verify (key=%q)", key)
	}
	cfg.debugf("pow solved: key=%q nonces=%d in %v", key, len(nonces), time.Since(started))
	nextReplyID++
	params2, err := encodeLogOnParams(cfg, pubkey)
	if err != nil {
		return zero, err
	}
	respMsg := buildChallengeResponseMsg(time.Since(started), key, nonces)
	msg2 := buildLoginMsg(nextReplyID, ver, params2, cfg.Encrypted)
	prefix2, err := randomPrefix()
	if err != nil {
		return zero, err
	}
	pkt2 := buildLoginPacket(prefix2, cfg.FooterPad, respMsg, msg2)
	cfg.debugf("login#2: %d B (replyID %d)", len(pkt2), nextReplyID)
	data2, err := roundTripRetry(ctx, conn, peer, pkt2, cfg)
	if err != nil {
		return zero, err
	}
	replyID2, status2, rest2, err := parseReply(data2)
	if err != nil {
		return zero, err
	}
	cfg.debugf("login reply#2: replyID %d (want %d) status=%d", replyID2, nextReplyID, status2)
	cfg.debugf("fp key=%x blob=%x datagram=%x", sha256.Sum256([]byte(cfg.BlockKey)),
		sha256.Sum256(rest2), sha256.Sum256(data2))
	_ = replyID2
	if status2 != statusLoggedOn {
		msg := ""
		if len(rest2) > 0 {
			if s, _, serr := consumePackedString(rest2); serr == nil {
				msg = s
			}
		}
		return zero, fmt.Errorf("wotlogin: rejected status=%d msg=%q", status2, msg)
	}
	cfg.debugf("login reply body: %d B", len(rest2))
	if s, err := decryptSession(rest2, cfg.BlockKey); err == nil {
		return s, nil
	}
	// TEMPORARY probe: entity digest (16 B, known to both sides) as key.
	if s, err := decryptSession(rest2, string(cfg.Digest[:])); err == nil {
		cfg.debugf("session decrypted with digest key")
		return s, nil
	}
	return decryptSession(rest2, cfg.BlockKey)
}

// encodeLogOnParams returns the login parameters body: RSA-OAEP ciphertext
// when Config.Encrypted (the game path — publicKeyPath from serverSettings),
// else raw cleartext (the encoder-absent branch of LogOnParams::addToStream,
// IDA sub_140E6E100; useful to isolate RSA-layer from layout-layer faults
// against the live server oracle).
func encodeLogOnParams(cfg Config, pubkey *RSAPublicKey) ([]byte, error) {
	if !cfg.Encrypted {
		return buildLogOnParamsClear(cfg), nil
	}
	return encryptLogOnParams(cfg, pubkey)
}

// SolveFunc turns a Challenge into a response key + 42 nonces.
// Production use is SolveCuckoo below; tests inject fakes.
type SolveFunc func(ctx context.Context, ch Challenge) (key string, nonces []uint32, err error)

// toU64 widens nonces for the vendored verifier.
func toU64(in []uint32) []uint64 {
	out := make([]uint64, len(in))
	for i, v := range in {
		out[i] = uint64(v)
	}
	return out
}

// debugf prints stage diagnostics when Config.Verbose is set.
func (c Config) debugf(format string, args ...any) {
	if c.Verbose {
		fmt.Fprintf(os.Stderr, "[wotlogin] "+format+"\n", args...)
	}
}

// SolveCuckoo solves via the vendored simple miner (threads<=0 → 4
// concurrent key attempts; each attempt is one single-threaded scan).
func SolveCuckoo(threads int) SolveFunc {
	return func(ctx context.Context, ch Challenge) (string, []uint32, error) {
		key, nonces, _, err := cuckoo.SolveChallenge(ctx, ch.Prefix, ch.MaxNonce, threads)
		return key, nonces, err
	}
}

// SolveRaw is the bare solver used by the -solve subcommand.
func SolveRaw(ctx context.Context, prefix string, maxNonce uint64, threads int) (string, []uint32, int, error) {
	return cuckoo.SolveChallenge(ctx, prefix, maxNonce, threads)
}

// NoncesHex renders nonces as contiguous little-endian u32 hex.
func NoncesHex(nonces []uint32) string {
	var tmp [4]byte
	out := make([]byte, 0, len(nonces)*8)
	for _, n := range nonces {
		binary.LittleEndian.PutUint32(tmp[:], n)
		out = append(out, []byte(hex.EncodeToString(tmp[:]))...)
	}
	return string(out)
}

// roundTripRetry resends a login request like RetryingRequest until any
// reply arrives or attempts run out (LoginAttempts, default 10 per the
// exe LoginRequestProtocol ctor sub_140E68910).
func roundTripRetry(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, pkt []byte, cfg Config) ([]byte, error) {
	attempts := cfg.LoginAttempts
	if attempts < 1 {
		attempts = 1
	}
	var err error
	var data []byte
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		data, err = roundTrip(ctx, conn, peer, pkt, cfg.Timeout)
		if err == nil {
			return data, nil
		}
	}
	return nil, err
}

// roundTrip sends one datagram and waits for one reply datagram. The
// socket is unconnected (see main.go: one fd for LoginApp and BaseApp,
// like the real client), so the peer is addressed explicitly per packet.
func roundTrip(ctx context.Context, conn *net.UDPConn, peer *net.UDPAddr, pkt []byte, timeout time.Duration) ([]byte, error) {
	if _, err := conn.WriteToUDP(pkt, peer); err != nil {
		return nil, fmt.Errorf("wotlogin: send: %w", err)
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("wotlogin: no reply: %w", err)
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, nil
	}
}
