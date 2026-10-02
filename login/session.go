package login

import (
	"context"
	"crypto/md5" //nolint:gosec // game-mandated session hashing
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// BaseAppSession owns one BaseApp exchange: the logged-on Session, the
// channel key, MTU, the two sockets and the redirect target. It replaces
// threading (conn, loginConn, peer, session, blockKey, mtu) through the
// stage scripts: build the session once, then Run the stage-1/stage-2
// script from a reply ID. Wire output is byte-identical to the former
// BaseAppLogin function (now a wrapper below).
//
// Socket roles (paired EU2 capture, Sep 2026): stage-1 rides the
// login-role socket (the game reuses it for the whole stage-1
// exchange; managers bind the pending session to the login endpoint),
// stage-2 rides a fresh socket. A socket connect()ed to one peer would
// drop the other's datagrams in-kernel, so both stay unconnected.
type BaseAppSession struct {
	session   Session
	blockKey  string
	mtu       int
	freshConn Transport
	loginConn Transport
	peer      *net.UDPAddr
}

// NewBaseAppSession binds a BaseApp exchange: freshConn carries
// stage-2, loginConn carries stage-1 (still-open login socket), peer
// is the manager endpoint from the login reply.
func NewBaseAppSession(s Session, blockKey string, mtu int, freshConn, loginConn Transport, peer *net.UDPAddr) *BaseAppSession {
	return &BaseAppSession{
		session: s, blockKey: blockKey, mtu: mtu,
		freshConn: freshConn, loginConn: loginConn, peer: peer,
	}
}

// Session returns the logged-on session this exchange rides.
func (b *BaseAppSession) Session() Session { return b.session }

// Peer returns the manager endpoint (mutated across redirect-follow).
func (b *BaseAppSession) Peer() *net.UDPAddr { return b.peer }

// Run executes the stage-1/stage-2 script from replyID: 22B handshake,
// key rotation, channel auth, redirect-follow, lobby flood.
func (b *BaseAppSession) Run(ctx context.Context, replyID uint32) error {
	return BaseAppLogin(ctx, b.freshConn, b.loginConn, b.peer, b.session, b.blockKey, b.mtu, replyID)
}

// UpgradeToken returns the token2 carried in the login reply ServerMsg
// ("" when absent): the input to the opt-in from-zero token2 relogin.
// SSO material — lengths/hashes only at call sites, never the value.
func (s Session) UpgradeToken() string { return ExtractUpgradeToken(s.ServerMsg) }

// RecordMiddle appends one sessionmd5,middle pair for the offline
// token2-middle function fit. The pairs file is 0600 (middles are auth
// material). Returns the middle length for the caller's lengths-only
// log, never values. The session md5 is wire-visible anyway (username
// JSON); the middle is the sensitive half. A malformed token2 (not
// three colon segments) records nothing.
func RecordMiddle(path, sessionBlob, token2 string) (int, error) {
	segs := strings.SplitN(token2, ":", 3)
	if len(segs) != 3 {
		return 0, nil
	}
	sum := md5.Sum([]byte(sessionBlob)) //nolint:gosec // game-mandated hashing
	line := hex.EncodeToString(sum[:]) + "," + segs[1] + "\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return 0, err
	}
	return len(segs[1]), nil
}
