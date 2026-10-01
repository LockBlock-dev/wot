// Command wotproxy is a transparent UDP log-and-forward proxy for the
// World of Tanks LoginApp handshake. The game client is pointed at it
// via a custom_server-style scripts_config.xml override (CUSTOM host
// url/url_token = 127.0.0.1:20016); the proxy forwards every datagram
// to the real LoginApp and logs both directions with timestamps and a
// best-effort Mercury framing decode (offsets per NETWORK_PROTOCOL.md
// §§3-5; never logs payload plaintext beyond structure).
//
// Usage (on the game machine):
//
// Explicit LoginApp proxy (needs custom-server-mod):
//
//	wotproxy -upstream login.p2.worldoftanks.eu:20016 [-listen 127.0.0.1:20016]
//
// Transparent full-traffic proxy (no game mod; Linux/Proton host, run as
// its own user, pre-install DNAT once — rules in wot/tproxy/doc.go):
//
//	wotproxy -transparent 127.0.0.1:32900
//
// What it shows: exact login#1/#2 bytes, ReplyID sequences, PoW
// challenge/response timing, retry behavior, socket usage. What it
// cannot show: RSA-encrypted LogOnParams content, or BaseApp traffic
// (the server routes the client straight to BaseApp, bypassing us).
// -keyfile tails a wotkeydump/CE wotkeys.txt so key arrivals line up
// with the login flow in one console (lengths/hashes only).
package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/keydump"
	"github.com/LockBlock-dev/wot/login"
	"github.com/LockBlock-dev/wot/tproxy"
)

// describe parses one LoginApp datagram far enough to annotate the log:
// [prefix 4][flags 2][messages...]. Never panics on short/garbage input.
func describe(pkt []byte) string {
	if len(pkt) < 6 {
		return fmt.Sprintf("short(%d)", len(pkt))
	}
	flags := binary.LittleEndian.Uint16(pkt[4:6])
	out := fmt.Sprintf("flags=%04x", flags)
	off := 6
	for off < len(pkt) {
		// Terminal 2-byte first-request-offset footer (its value can
		// collide with message IDs, e.g. 0x0002 looks like a ping).
		if len(pkt)-off == 2 {
			foot := binary.LittleEndian.Uint16(pkt[off : off+2])
			return fmt.Sprintf("%s footer(reqOff=%d)", out, foot)
		}
		id := pkt[off]
		switch id {
		case 0xFF: // reply: [FF][len u32][replyID u32][status u8]
			if off+10 > len(pkt) {
				return out + " reply(trunc)"
			}
			ln := binary.LittleEndian.Uint32(pkt[off+1 : off+5])
			rid := binary.LittleEndian.Uint32(pkt[off+5 : off+9])
			return fmt.Sprintf("%s reply(len=%d,replyID=%d,status=%d)", out, ln, rid, pkt[off+9])
		case 0x00: // login: [00][len u16][replyID u32]
			if off+9 > len(pkt) {
				return out + " login(trunc)"
			}
			ln := binary.LittleEndian.Uint16(pkt[off+1 : off+3])
			rid := binary.LittleEndian.Uint32(pkt[off+3 : off+7])
			out += fmt.Sprintf(" login(len=%d,replyID=%d)", ln, rid)
			off += 9 + int(ln)
			// Heuristic: version(4)+isEnc(1) follow the 6 header bytes.
			continue
		case 0x01:
			out += " probe"
			off++
			continue
		case 0x02: // ping: [02][replyID u32][nextOff 2][seq 1]
			if off+8 > len(pkt) {
				return out + " ping(trunc)"
			}
			rid := binary.LittleEndian.Uint32(pkt[off+1 : off+5])
			out += fmt.Sprintf(" ping(replyID=%d,seq=%d)", rid, pkt[off+7])
			off += 8
			continue
		case 0x03: // challengeResponse: [03][len u16]...
			if off+3 > len(pkt) {
				return out + " cr(trunc)"
			}
			ln := binary.LittleEndian.Uint16(pkt[off+1 : off+3])
			out += fmt.Sprintf(" challengeResponse(len=%d)", ln)
			off += 3 + int(ln)
			continue
		case 0x04:
			out += " mtuProbe"
			off++
			continue
		default:
			// Unknown ID with >2 bytes left: trailing garbage.
			return fmt.Sprintf("%s (+%dB tail...)", out, len(pkt)-off)
		}
	}
	return out
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:20016", "local UDP address to listen on")
	upstream := flag.String("upstream", "", "real LoginApp address, e.g. login.p2.worldoftanks.eu:20016")
	dumpPath := flag.String("dump", "", "append raw datagrams as hex here (one line each: time dir addr len hex)")
	keyPath := flag.String("keyfile", "", "tail a wotkeydump/CE wotkeys.txt for live key arrivals (logs lengths/hashes only, never key bytes)")
	transparent := flag.String("transparent", "", "transparent mode: listen here for DNAT'd game traffic (Linux only, e.g. 127.0.0.1:32900); routes per-flow by original destination")
	baseListen := flag.String("baseapp-listen", "", "BaseApp MITM: listen here (e.g. 127.0.0.1:32901) and rewrite S>C 232B LOGGED_ON endpoints to it via -keyfile (explicit LoginApp mode only; fail-open without a key)")
	mitmPrivPath := flag.String("mitm-privkey", "", "RSA MITM: our private key (PEM) matching the public_key_path the CUSTOM host entry uses; enables live login-key recovery (explicit LoginApp mode only; fail-open)")
	mitmPubPath := flag.String("mitm-pubkey", "", "RSA MITM: the real server public key (PEM, e.g. res/loginapp_wot.pubkey) to re-encrypt toward; requires -mitm-privkey")
	flag.Parse()
	if *upstream == "" && *transparent == "" {
		fmt.Fprintln(os.Stderr, "wotproxy: need -upstream (explicit mode) or -transparent addr (DNAT mode)")
		os.Exit(2)
	}
	upAddr, err := net.ResolveUDPAddr("udp", *upstream)
	if err != nil && *upstream != "" {
		fmt.Fprintln(os.Stderr, "wotproxy: resolve upstream:", err)
		os.Exit(1)
	}
	if *upstream == "" && *transparent == "" {
		fmt.Fprintln(os.Stderr, "wotproxy: need -upstream (explicit mode) or -transparent addr (DNAT mode)")
		os.Exit(2)
	}

	// Optional raw hex dump: one line per datagram, shared by all
	// flows, flushed per write so Ctrl+C loses nothing.
	var dumpMu sync.Mutex
	var dump *bufio.Writer
	if *dumpPath != "" {
		f, err := os.OpenFile(*dumpPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wotproxy: open dump:", err)
			os.Exit(1)
		}
		defer f.Close()
		dump = bufio.NewWriter(f)
		fmt.Printf("wotproxy: dumping raw hex to %s\n", *dumpPath)
	}
	dumpLine := func(ts, dir, peer string, pkt []byte) {
		if dump == nil {
			return
		}
		dumpMu.Lock()
		defer dumpMu.Unlock()
		fmt.Fprintf(dump, "%s %s %-21s %4d %s\n", ts, dir, peer, len(pkt), hex.EncodeToString(pkt))
		dump.Flush() //nolint:errcheck // best effort; console log stays authoritative
	}
	if *keyPath != "" {
		fmt.Printf("wotproxy: tailing keyfile %s\n", *keyPath)
		go tailKeyfile(*keyPath)
	}

	// RSA MITM state (explicit mode): our private key decrypts the
	// CUSTOM login params, the server public key re-encrypts them.
	// Latest recovered login keys feed the 232B rewrite first (exact
	// session); the -keyfile stays the fallback. Any load problem
	// disables the MITM loudly and the proxy continues as before.
	mitm := setupMitm(*mitmPrivPath, *mitmPubPath)
	if *transparent != "" {
		runTransparent(*transparent, dumpLine)
		return
	}

	lconn, err := net.ListenUDP("udp", mustResolve(*listenAddr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotproxy: listen:", err)
		os.Exit(1)
	}
	defer lconn.Close()
	fmt.Printf("wotproxy: listening %s -> upstream %s (%s)\n", lconn.LocalAddr(), *upstream, upAddr)

	var mu sync.Mutex
	peers := map[string]*net.UDPConn{} // client addr -> upstream socket

	// BaseApp MITM relay, created on the first rewritten 232B (fail-open:
	// without -baseapp-listen or without a key the game flows direct and
	// only LoginApp is observed). The relay target follows stage-1, then
	// any stage-2 redirect chain (retargeted by the S>C rewrite below):
	// existing flows keep their dialed sockets; fresh game sockets
	// resolve to the latest target (single session at a time).
	var relayMu sync.Mutex
	var relayTarget *net.UDPAddr
	var relayListen *net.UDPAddr
	currentTarget := func() *net.UDPAddr {
		relayMu.Lock()
		defer relayMu.Unlock()
		return relayTarget
	}
	// rewriteStage2 attempts the S>C redirect rewrite on one relayed
	// datagram: needs the relay up, a recovered login key, and a
	// genuine redirect in the channel cleartext. Returns a replacement
	// datagram or nil (forward untouched). Logs key fingerprints only.
	rewriteStage2 := func(client, orig *net.UDPAddr, pkt []byte) []byte {
		relayMu.Lock()
		laddr := relayListen
		relayMu.Unlock()
		if laddr == nil || len(pkt) < 4+8 {
			return nil
		}
		body := pkt[4:]
		if len(body)%8 != 0 {
			return nil
		}
		var blockKey string
		for _, k := range mitm.latestKeys(1) {
			blockKey = k
			break
		}
		if blockKey == "" {
			return nil
		}
		out, target, err := login.RewriteRedirect(body, blockKey, laddr.IP, uint16(laddr.Port))
		if err != nil {
			return nil
		}
		if target.IP.Equal(laddr.IP) && target.Port == laddr.Port {
			fmt.Printf("%s redirect: already at relay, passing through\n", time.Now().Format("15:04:05.000"))
			return nil
		}
		relayMu.Lock()
		relayTarget = target
		relayMu.Unlock()
		fmt.Printf("%s redirect: stage-2 %s -> relay %s (retargeted, chains welcome)\n",
			time.Now().Format("15:04:05.000"), target, laddr)
		fwd := append([]byte(nil), pkt...)
		copy(fwd[4:4+len(out)], out)
		dumpLine(time.Now().Format("15:04:05.000"), "S>C",
			client.String()+"->"+laddr.String()+"-rewritten", fwd)
		return fwd
	}
	ensureRelay := func(real *net.UDPAddr) {
		if *baseListen == "" {
			return
		}
		relayMu.Lock()
		defer relayMu.Unlock()
		if relayTarget != nil {
			if !relayTarget.IP.Equal(real.IP) || relayTarget.Port != real.Port {
				fmt.Printf("wotproxy: new BaseApp target %s (relay stays on %s; restart for new sessions)\n", real, relayTarget)
			}
			return
		}
		relayTarget = real
		laddr := mustResolve(*baseListen)
		relayListen = laddr
		fmt.Printf("wotproxy: BaseApp relay %s -> real %s\n", laddr, real)
		fw := &tproxy.Forwarder{
			Listen:  laddr,
			Resolve: func(_ *net.UDPConn) (*net.UDPAddr, error) { return currentTarget(), nil },
			RewriteSC: func(client, orig *net.UDPAddr, pkt []byte) []byte {
				return rewriteStage2(client, orig, pkt)
			},
			OnDatagram: func(dir string, client, orig *net.UDPAddr, pkt []byte) {
				ts := time.Now().Format("15:04:05.000")
				peer := client.String() + "->" + orig.String()
				fmt.Printf("%s %s %-43s %4dB baseapp\n", ts, dir, peer, len(pkt))
				dumpLine(ts, dir, peer, pkt)
			},
		}
		go func() {
			if err := fw.ListenAndServe(); err != nil {
				fmt.Fprintln(os.Stderr, "wotproxy: baseapp relay:", err)
			}
		}()
	}

	getUpstream := func(caddr *net.UDPAddr) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		key := caddr.String()
		if uc, ok := peers[key]; ok {
			return uc
		}
		uc, err := net.DialUDP("udp", nil, upAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wotproxy: dial upstream:", err)
			return nil
		}
		// Windows-stack mimicry (C_PLAN.md relay fingerprint): best
		// effort, fail-open — failure keeps today's defaults.
		_ = tproxy.ShapeUpstream(uc)
		peers[key] = uc
		fmt.Printf("wotproxy: new flow %s <-> %s (via %s)\n", key, upAddr, uc.LocalAddr())
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := uc.Read(buf)
				if err != nil {
					return
				}
				pkt := append([]byte(nil), buf[:n]...)
				ts := time.Now().Format("15:04:05.000")
				fmt.Printf("%s S>C %-21s %4dB %s\n", ts, key, n, describe(pkt))
				if fwd := maybeRewrite(pkt, *keyPath, *baseListen, ensureRelay, mitm); fwd != nil {
					pkt = fwd
				}
				dumpLine(ts, "S>C", key, pkt)
				if _, err := lconn.WriteToUDP(pkt, caddr); err != nil {
					return
				}
			}
		}()
		return uc
	}

	buf := make([]byte, 4096)
	for {
		n, caddr, err := lconn.ReadFromUDP(buf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wotproxy: read:", err)
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		ts := time.Now().Format("15:04:05.000")
		fmt.Printf("%s C>S %-21s %4dB %s\n", ts, caddr, n, describe(pkt))
		dumpLine(ts, "C>S", caddr.String(), pkt)
		if fwd := mitmForward(pkt, mitm, ts); fwd != nil {
			pkt = fwd
		}
		if uc := getUpstream(caddr); uc != nil {
			uc.Write(pkt) //nolint:errcheck // best-effort forward; errors surface on read path
		}
	}
}

// maybeRewrite intercepts LOGGED_ON replies ([FF][len][rid][status=1]
// + Blowfish body, flags 0, no footers — 232B classic and shorter
// variants like the 208B token2 login) and swaps the BaseApp endpoint
// to the -baseapp-listen relay via the -keyfile block key. Returns the
// rewritten packet, or nil to forward untouched (fail-open: wrong
// shape, no key, bad decrypt — the game then flows direct exactly as
// without us). Server addresses are public, so the real endpoint is
// logged; key bytes never are.
func maybeRewrite(pkt []byte, keyPath, baseListen string, ensureRelay func(*net.UDPAddr), mitm *mitmState) []byte {
	if baseListen == "" || len(pkt) < 6+1+4+1+8 {
		return nil
	}
	if binary.LittleEndian.Uint16(pkt[4:6]) != 0 || pkt[6] != 0xFF {
		return nil
	}
	ln := int(binary.LittleEndian.Uint32(pkt[7:11]))
	if pkt[15] != 1 || len(pkt) != 6+1+4+ln {
		return nil
	}
	body := pkt[16 : 16+ln-5]
	if len(body)%8 != 0 {
		return nil
	}
	// First-valid-wins over recent keys: the scan passes trail the
	// reply, so the newest keyfile entry may belong to an older login
	// (a stale-key rewrite ships a garbage endpoint and kills the game
	// at parse — Sep 27, MF_ASSERT read-past-end, no stage-1).
	// RewriteLoginReply structurally validates (packed message, zero
	// pad, sessionKey, manager port window), so only a genuine key for
	// THIS session passes.
	var keys [][]byte
	for _, k := range mitm.latestKeys(3) {
		keys = append(keys, []byte(k))
	}
	if keyPath != "" {
		if fk, err := keydump.LatestKeys(keyPath, 3); err == nil {
			keys = append(keys, fk...)
		}
	}
	if len(keys) == 0 {
		return nil // no keys yet; game flows direct this run
	}
	laddr := mustResolve(baseListen)
	for _, key := range keys {
		out, sess, err := login.RewriteLoginReply(body, string(key), laddr.IP, uint16(laddr.Port))
		if err != nil {
			continue
		}
		real := &net.UDPAddr{IP: sess.ServerAddr, Port: int(sess.ServerPort)}
		fmt.Printf("%s rewrite: BaseApp %s -> relay %s (sessionKey ok)\n",
			time.Now().Format("15:04:05.000"), real, laddr)
		ensureRelay(real)
		fwd := append([]byte(nil), pkt...)
		copy(fwd[16:16+len(out)], out)
		return fwd
	}
	return nil
}

// runTransparent serves DNAT'd game traffic (LoginApp + BaseApp) with
// per-flow original-destination routing. LoginApp flows (orig port 20016)
// get Mercury framing annotation; BaseApp flows log sizes only — channel
// bytes are Blowfish (sidecar decrypt via -keyfile is a later step).
func runTransparent(listen string, dumpLine func(ts, dir, peer string, pkt []byte)) {
	laddr := mustResolve(listen)
	fmt.Printf("wotproxy: transparent %s (pre-install DNAT per wot/tproxy/doc.go; game runs stock)\n", laddr)
	fw := &tproxy.Forwarder{
		Listen: laddr,
		// No Resolve: the IP_ORIGDSTADDR cmsg is primary and race-free;
		// the SO_ORIGINAL_DST getsockopt fallback cannot work on UDP
		// listeners (ENOPROTOOPT) and must never shadow it.
		OnDatagram: func(dir string, client, orig *net.UDPAddr, pkt []byte) {
			ts := time.Now().Format("15:04:05.000")
			peer := client.String() + "->" + orig.String()
			note := describe(pkt)
			if orig.Port != 20016 {
				note = fmt.Sprintf("baseapp(%dB)", len(pkt))
			}
			fmt.Printf("%s %s %-43s %4dB %s\n", ts, dir, peer, len(pkt), note)
			dumpLine(ts, dir, peer, pkt)
		},
	}
	if err := fw.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "wotproxy: transparent:", err)
		os.Exit(1)
	}
}

func mustResolve(addr string) *net.UDPAddr {
	u, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotproxy: resolve listen:", err)
		os.Exit(1)
	}
	return u
}

// tailKeyfile polls a wotkeydump/CE keyfile and reports arrivals with
// lengths and hashes only — key bytes stay in the file, never in logs
// (repo secret rule, wot/AGENTS.md). Lets the operator confirm the
// key feed is alive next to the login#1/#2 flow in one console.
func tailKeyfile(path string) {
	var lastHash [20]byte
	for {
		time.Sleep(2 * time.Second)
		key, err := keydump.LatestKey(path)
		if err != nil {
			continue // no key yet; dump flow continues regardless
		}
		h := sha1.Sum(key)
		if h == lastHash {
			continue
		}
		lastHash = h
		fmt.Printf("%s keyfile: latest len=%d sha1=%x\n",
			time.Now().Format("15:04:05.000"), len(key), h)
	}
}
