package login

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	"github.com/LockBlock-dev/wot/internal/cuckoo"
)

// Client owns one LoginApp exchange: config, server key, PoW solver,
// socket, resolved peer and the Mercury reply-ID sequence. It replaces
// threading (conn, cfg, pubkey, solve) through every call: build the
// client once, then Login and read the continuing sequence for stage-1
// (genuine stage-1 rids are exactly login#2+1).
type Client struct {
	cfg    Config
	auth   AuthProvider
	pubkey *RSAPublicKey
	solve  SolveFunc
	conn   Transport
	peer   *net.UDPAddr
	nextID uint32
}

// NewClient binds a login exchange to conn (usually a fresh unconnected
// *net.UDPConn: LoginApp must see a single source). It resolves the
// LoginApp peer now so Login fails fast on bad addresses, and seeds
// the reply-ID sequence from Config.FirstReplyID (genuine IDs stay
// small, < 2^17 — see LoadEnv).
func NewClient(cfg Config, pubkey *RSAPublicKey, solve SolveFunc, conn Transport) (*Client, error) {
	return NewClientWithProvider(cfg, ProviderForConfig(cfg), pubkey, solve, conn)
}

// NewClientWithProvider binds a login exchange with an explicit auth
// provider (tests pinning a method, token2 legs reusing a base config).
// The provider's username/password render the LogOnParams identity half.
func NewClientWithProvider(cfg Config, auth AuthProvider, pubkey *RSAPublicKey, solve SolveFunc, conn Transport) (*Client, error) {
	peer, err := cfg.Peer()
	if err != nil {
		return nil, fmt.Errorf("wotlogin: resolve: %w", err)
	}
	return &Client{cfg: cfg, auth: auth, pubkey: pubkey, solve: solve, conn: conn, peer: peer, nextID: cfg.FirstReplyID}, nil
}

// Provider returns the client's auth provider (method + identity).
func (c *Client) Provider() AuthProvider { return c.auth }

// Config returns the client's config (post-LoadEnv defaults included).
func (c *Client) Config() Config { return c.cfg }

// Conn exposes the login socket: stage-1 rides it (BaseAppLogin takes
// it as its login-role socket), so the caller keeps ownership.
func (c *Client) Conn() Transport { return c.conn }

// NextReplyID returns the next Mercury reply ID and advances the
// sequence. After Login it yields exactly login#2+1, the genuine
// stage-1 rid.
func (c *Client) NextReplyID() uint32 {
	id := c.nextID
	c.nextID++
	return id
}

// Login runs the full LoginApp handshake: login, PoW challenge, login
// retry, success. Without valid credentials the server still issues
// the challenge (proving our framing), then rejects; with valid ones
// it returns the BaseApp Session. Wire output is byte-identical to
// the former Login function (now a wrapper below).
func (c *Client) Login(ctx context.Context) (Session, error) {
	var zero Session
	cfg := c.cfg
	// Attempt 1: bare login (no challenge data yet).
	params, err := encodeLogOnParamsWithProvider(cfg, c.auth, c.pubkey)
	if err != nil {
		return zero, err
	}
	var ver = [4]byte{verSub, verPatch, verMinor, verMajor}
	prefix, err := randomPrefix()
	if err != nil {
		return zero, err
	}
	rid := c.NextReplyID()
	msg := buildLoginMsg(rid, ver, params, cfg.Encrypted)
	cfg.debugf("login#1: %d B (replyID %d)", 6+len(msg)+2+cfg.FooterPad, rid)
	pkt := buildLoginPacket(prefix, cfg.FooterPad, msg)
	data, err := roundTripRetry(ctx, c.conn, c.peer, pkt, cfg)
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
	if status != statusChallengeIssued || replyID != rid {
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
	key, nonces, err := c.solve(ctx, ch)
	if err != nil {
		return zero, fmt.Errorf("wotlogin: pow(type=%s prefix=%q maxNonce=%d): %w", ch.Type, ch.Prefix, ch.MaxNonce, err)
	}
	if !cuckoo.NewCuckoo([]byte(key)).Verify(toU64(nonces), ch.MaxNonce) {
		return zero, fmt.Errorf("wotlogin: own PoW solution fails verify (key=%q)", key)
	}
	cfg.debugf("pow solved: key=%q nonces=%d in %v", key, len(nonces), time.Since(started))
	params2, err := encodeLogOnParamsWithProvider(cfg, c.auth, c.pubkey)
	if err != nil {
		return zero, err
	}
	respMsg := buildChallengeResponseMsg(time.Since(started), key, nonces)
	rid2 := c.NextReplyID()
	msg2 := buildLoginMsg(rid2, ver, params2, cfg.Encrypted)
	prefix2, err := randomPrefix()
	if err != nil {
		return zero, err
	}
	pkt2 := buildLoginPacket(prefix2, cfg.FooterPad, respMsg, msg2)
	cfg.debugf("login#2: %d B (replyID %d)", len(pkt2), rid2)
	data2, err := roundTripRetry(ctx, c.conn, c.peer, pkt2, cfg)
	if err != nil {
		return zero, err
	}
	replyID2, status2, rest2, err := parseReply(data2)
	if err != nil {
		return zero, err
	}
	cfg.debugf("login reply#2: replyID %d (want %d) status=%d", replyID2, rid2, status2)
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
