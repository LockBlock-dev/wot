package login

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RewriteLoginReply decrypts a LOGGED_ON reply body with the session block
// cipher (LogOnParams.encryptionKey, recovered live by wotkeydump), swaps
// the BaseApp endpoint to a local listener, and re-encrypts. The rewrite
// is length-preserving: the record is ip u32 + port u16 BE + salt u16 +
// key u32 LE and only [0:6] change, so framing, Blowfish block alignment
// and the trailing packed-string server message are untouched.
//
// Wire refs: record layout IDA sub_140E6D3C0 / sub_142AD3580 and
// NETWORK_PROTOCOL.md §5.4; the game dials whatever endpoint this record
// carries, so pointing it at our BaseApp relay captures stage-1 with zero
// client cooperation (no firewall, no mod for BaseApp).
func RewriteLoginReply(blob []byte, blockKey string, newIP net.IP, newPort uint16) (out []byte, sess Session, err error) {
	clear, err := decryptLogin(blockKey, blob)
	if err != nil {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite decrypt: %w", err)
	}
	if len(clear) < 12 {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite record too short (%d B)", len(clear))
	}
	sess, err = parseSessionRecord(clear)
	if err != nil {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite parse: %w", err)
	}
	if !validSessionRecord(clear, sess) {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite rejected (stale key? endpoint %v:%d outside shape)", sess.ServerAddr, sess.ServerPort)
	}
	ip4 := newIP.To4()
	if ip4 == nil {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite needs IPv4, got %s", newIP)
	}
	patched := append([]byte(nil), clear...)
	copy(patched[0:4], ip4)
	binary.BigEndian.PutUint16(patched[4:6], newPort)
	out, err = encryptLogin(blockKey, patched)
	if err != nil {
		return nil, Session{}, fmt.Errorf("wotlogin: rewrite encrypt: %w", err)
	}
	return out, sess, nil
}

// RewriteRedirect patches a stage-1 channel REDIRECT ([44][ip4][port
// BE][00 00 01], IDA sub_140E54400 via parseRedirectAt) to a local
// relay: decrypt the datagram body with the login block key, swap the
// 6 endpoint bytes, re-encrypt. Length-preserving: the 10B core keeps
// its size and Blowfish re-padding of identical-length cleartext is
// identical length (asserted). Returns the replacement body and the
// real redirect target, or an error (fail-open upstream: no redirect,
// bad decrypt, loopback target — the game then follows the genuine
// target direct exactly as without us).
func RewriteRedirect(body []byte, blockKey string, newIP net.IP, newPort uint16) (out []byte, target *net.UDPAddr, err error) {
	if len(body)%8 != 0 {
		return nil, nil, fmt.Errorf("wotlogin: redirect body %d not a Blowfish multiple", len(body))
	}
	clear, err := decryptBlowfish(blockKey, body)
	if err != nil {
		return nil, nil, fmt.Errorf("wotlogin: redirect decrypt: %w", err)
	}
	target, at, ok := parseRedirectAt(clear)
	if !ok {
		return nil, nil, fmt.Errorf("wotlogin: no redirect in %d B channel cleartext", len(clear))
	}
	if target.IP.IsLoopback() || target.IP.IsUnspecified() {
		return nil, nil, fmt.Errorf("wotlogin: redirect target not routable: %s", target)
	}
	ip4 := newIP.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("wotlogin: redirect needs IPv4, got %s", newIP)
	}
	patched := append([]byte(nil), clear...)
	copy(patched[at+1:at+5], ip4)
	binary.BigEndian.PutUint16(patched[at+5:at+7], newPort)
	out, err = encryptBlowfish(blockKey, patched)
	if err != nil {
		return nil, nil, fmt.Errorf("wotlogin: redirect encrypt: %w", err)
	}
	if len(out) != len(body) {
		return nil, nil, fmt.Errorf("wotlogin: redirect length drift %d -> %d", len(body), len(out))
	}
	return out, target, nil
}
