package main

// RSA MITM support for wotproxy (explicit LoginApp mode).
//
// When the CUSTOM host entry names our public key, game login params
// arrive RSA-encrypted to us. mitmForward decrypts them, learns the
// per-login Blowfish key, re-encrypts to the real server key and
// returns the rebuilt datagram (same length). The recovered keys feed
// the 232B rewrite first (exact session); the -keyfile stays fallback.
//
// Fail-open throughout: anything unexpected returns nil (forward the
// original) and logs a one-line reason. Key bytes never reach logs —
// only a sha1 fingerprint prefix.

import (
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // fingerprint only, not security
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/login"
)

// mitmState is nil when the MITM is off (flags empty or keys unloadable).
type mitmState struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
	mu   sync.Mutex
	keys []string // recovered login keys, newest first, cap 3
}

// setupMitm loads the keypair or returns nil (loudly) to run plain.
func setupMitm(privPath, pubPath string) *mitmState {
	if privPath == "" && pubPath == "" {
		return nil
	}
	if privPath == "" || pubPath == "" {
		fmt.Fprintln(os.Stderr, "wotproxy: MITM needs both -mitm-privkey and -mitm-pubkey; running plain")
		return nil
	}
	priv, err := login.LoadRSAPrivateKey(privPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotproxy: MITM off:", err, "; running plain")
		return nil
	}
	srv, err := login.LoadRSAPublicKey(pubPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotproxy: MITM off:", err, "; running plain")
		return nil
	}
	fmt.Printf("wotproxy: RSA MITM armed (game key %d-bit -> server key %d-bit)\n",
		priv.Size()*8, srv.Size()*8)
	return &mitmState{priv: priv, pub: srv.Public()}
}

// latestKeys returns up to n recovered login keys, newest first.
func (m *mitmState) latestKeys(n int) []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keys) < n {
		n = len(m.keys)
	}
	return append([]string(nil), m.keys[:n]...)
}

func (m *mitmState) addKey(key string) {
	if m == nil || key == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keys) > 0 && m.keys[0] == key {
		return
	}
	m.keys = append([]string{key}, m.keys...)
	if len(m.keys) > 3 {
		m.keys = m.keys[:3]
	}
}

// mitmForward runs one C>S datagram through the MITM. Returns a
// replacement datagram to forward, or nil to forward the original.
// Pure log-and-forward when the MITM is off.
func mitmForward(pkt []byte, m *mitmState, ts string) []byte {
	if m == nil || !strings.Contains(describe(pkt), "login(") {
		return nil
	}
	out, key, err := login.MitmPacket(pkt, m.priv, m.pub)
	if err != nil {
		fmt.Printf("%s mitm: passthrough (%v)\n", ts, err)
		return nil
	}
	if key == "" {
		return nil
	}
	m.addKey(key)
	fp := sha1.Sum([]byte(key)) //nolint:gosec // fingerprint only
	if out != nil {
		fmt.Printf("%s mitm: re-encrypted %dB login, key fp %x\n", ts, len(pkt), fp[:4])
		return out
	}
	fmt.Printf("%s mitm: plaintext login, key fp %x\n", ts, fp[:4])
	return nil
}
