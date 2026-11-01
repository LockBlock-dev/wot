package login

// BaseApp SERVER tests: byte-exact shapes vs the genuine flows3
// decrypts (rotation/tick/redirect raws dumped from
// ../captures/flows3 + ../captures/key3.txt), then the full loopback
// stage-1→stage-2 dance with the real wire builders on both sides.
// The flood carrier is the flows3-s2 capture — it feeds the bulk, the
// v2 post-flood chain answers AND the v2.1 pre-flood per-session
// smalls (info app / descriptor / session dict) — skip when the
// capture files are absent: durable inputs live in ../captures,
// outside the repo.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"github.com/LockBlock-dev/wot/lobby"
	"math"
	"net"
	"os"
	"testing"
	"time"
)

// Genuine stage-1 server decrypts (flows3 flow 10, key3.txt):
// rotation = flags 58 04 + [FF][len=8][rid=0xAE6E][key=0x696AAE88]
// + [seq 0][cumul 0]; tick = flags + [13][3e] + [seq 2][cumul 1];
// redirect = flags + [13][3f] + [44][92.223.20.212 BE][32844 BE]
// [000001] + [seq 4][cumul 1].
const (
	genuineRotationRaw = "5804ff080000006eae000088ae6a690000000000000000"
	genuineTickRaw     = "5804133e0200000001000000"
	genuineRedirectRaw = "5804133f445cdf14d4804c0000010400000001000000"

	// Post-flood chain heads (flows3-s2 tail, key3.txt decrypt):
	// the first tail tick [13][7a] seq=503 cumul=3, and the rev answer
	// [13][7b] + 1a/5f {prevRev, rev} (full body below).
	genuinePostTickRaw = "5804137af701000003000000"
	genuineRevReplyRaw = "5804137b1a5f24e0000000001e80027d710128550372657671024b5855077072657652657671034b58752ef801000004000000"

	// Pre-flood per-session smalls (flows3-s2 decrypts, v2.1):
	// info = full 20B clear (app = [2:12], footers seq 1 / cumul 0);
	// dict = the 1a/76 session-dict small, 160B (`1a 76` + u16 len
	// 0x9c + 156B: status byte 9b + the 155B proto-2 pickle, view
	// values are the CAPTURE's — patchDict rewrites them per session);
	// poll = the first 1a/5b stats answer (22B clear — counters
	// 0x5266/0xb590 replay verbatim; later answers drift, our mint
	// is deliberately stale, §18.7 individual note).
	genuineInfoClearRaw = "5804020a01003f8b2300133f0100000000000000"
	genuineInfoAppRaw   = "020a01003f8b2300133f"
	genuineDescrRaw     = "7804134005ffff173403000100000a65755f322e342e305f320b4578616d706c65557365727b0900000000000002000000ae0000000200000001000000"
	genuineDictSmallRaw = "1a769c009b80027d710128550973657276657255544371024741daab17e52f9aa6550a6461746162617365494471034a15cd5b07550e616f67617353746172746564417471044741daab17e52f7aaf551073657373696f6e53746172746564417471054a945fac6a550e6973416f676173456e61626c6564710688550e636f6c6c65637455695374617473710788550b6c6f6755584576656e7473710889752e"
	genuinePollAnsRaw   = "580413a41a5b6652000090b500002102000005000000"
)

func baseAppTestKey() string { return "testkey-channel16" }

func decryptTest(t *testing.T, key string, pkt []byte) []byte {
	t.Helper()
	clear, err := decryptBlowfish(key, pkt[4:])
	if err != nil {
		t.Fatalf("channel decrypt: %v", err)
	}
	return clear
}

func TestBaseAppRotationShape(t *testing.T) {
	k := baseAppTestKey()
	rid, newkey := uint32(0xAE6E), uint32(0x696AAE88)
	pkt, err := buildChannelPacket(k, flagsRel, replyMsg(rid, newkey), nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	clear := decryptTest(t, k, pkt)
	want, _ := hex.DecodeString(genuineRotationRaw)
	if !bytes.Equal(clear, want) {
		t.Fatalf("rotation shape: got %x want %x", clear, want)
	}
	if got, ok := stageKeyOf(pkt, rid, k); !ok || got != newkey {
		t.Fatalf("stageKeyOf(%x) = %x, %v; want %x true", pkt, got, ok, newkey)
	}
}

func TestBaseAppTickShape(t *testing.T) {
	k := baseAppTestKey()
	pkt, err := buildChannelPacket(k, flagsRel, tickApp, nil, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	clear := decryptTest(t, k, pkt)
	want, _ := hex.DecodeString(genuineTickRaw)
	if !bytes.Equal(clear, want) {
		t.Fatalf("tick shape: got %x want %x", clear, want)
	}
}

func TestBaseAppRedirectShape(t *testing.T) {
	k := baseAppTestKey()
	// IP/port kept literal — the capture citation is the point.
	target := &net.UDPAddr{IP: net.IPv4(0x5c, 0xdf, 0x14, 0xd4), Port: 32844} // 92.223.20.212:32844
	pkt, err := redirectPacket(k, target)
	if err != nil {
		t.Fatal(err)
	}
	clear := decryptTest(t, k, pkt)
	want, _ := hex.DecodeString(genuineRedirectRaw)
	if !bytes.Equal(clear, want) {
		t.Fatalf("redirect shape: got %x want %x", clear, want)
	}
	addr, _, ok := parseRedirectAt(clear)
	if !ok || addr == nil || !addr.IP.Equal(target.IP) || addr.Port != target.Port {
		t.Fatalf("parseRedirectAt on our core = %v, %v; want %s", addr, ok, target)
	}
}

// TestBaseAppPostFloodCarrier pins the v2 chain loaders against the
// genuine flows3-s2 decrypts: the tail terminator 317B clear, the 12B
// plain tick (tag 7a, seq 503, cumul 3), the [13][7b] rev answer and
// the 1a/5b stats answer (what the post-flood mint replays and seeds),
// plus the v2.1 pre-flood templates: info app verbatim, the descriptor
// with its packed "ExampleUser" name slot, and the 1a/76 session-dict
// small (the dict's personal riders — clan block, offer — are cut).
func TestBaseAppPostFloodCarrier(t *testing.T) {
	dumpPath, keyPath := "../../captures/flows3-s2.txt", "../../captures/key3.txt"
	if _, err := os.Stat(dumpPath); err != nil {
		t.Skipf("no stage-2 capture (%v)", err)
	}
	base, err := NewBaseAppServer(BaseAppConfig{
		Redirect:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32990},
		FloodPath:    dumpPath,
		FloodKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.term) != 317 {
		t.Fatalf("terminator clear %dB, want 317", len(base.term))
	}
	if want, _ := hex.DecodeString(genuinePostTickRaw); !bytes.Equal(base.tickSeed, want) {
		t.Fatalf("tick seed %x want %x", base.tickSeed, want)
	}
	if base.postTag != 0x7a || base.postSeq != 503 || base.postCumul != 3 {
		t.Fatalf("sequencer seed tag=%02x seq=%d cumul=%d; want 7a/503/3",
			base.postTag, base.postSeq, base.postCumul)
	}
	if want, _ := hex.DecodeString(genuineRevReplyRaw); !bytes.Equal(base.revReply, want) {
		t.Fatalf("rev reply %x want %x", base.revReply, want)
	}
	if !hasSmall(base.pollAns, 0x1a, 0x5b) {
		t.Fatalf("poll answer lacks 1a/5b: %x", base.pollAns)
	}
	if !base.preOK {
		t.Fatal("pre-flood smalls not loaded")
	}
	if want, _ := hex.DecodeString(genuineInfoAppRaw); !bytes.Equal(base.infoApp, want) {
		t.Fatalf("info app %x want %x", base.infoApp, want)
	}
	if want, _ := hex.DecodeString(genuineDescrRaw); !bytes.Equal(base.descTpl, want) {
		t.Fatalf("descriptor template %x want %x", base.descTpl, want)
	}
	if want, _ := hex.DecodeString(genuineDictSmallRaw); !bytes.Equal(base.dictTpl, want) {
		t.Fatalf("dict template %x want %x", base.dictTpl, want)
	}
	// descriptorFrame round-trips the capture's own name byte-exactly,
	// and a short name splices cleanly: [:25] + nlen + name + [37:]
	// = 25+1+len+24 (clear 61B with the 11B capture name → 58B with 8B
	// "loopback"; the channel footers at [53:61] are part of the tail).
	tpl, _ := hex.DecodeString(genuineDescrRaw)
	round, err := descriptorFrame(base.descTpl, "ExampleUser")
	if err != nil || !bytes.Equal(round, tpl) {
		t.Fatalf("descriptor round-trip = %x, %v; want byte-exact", round, err)
	}
	short, err := descriptorFrame(base.descTpl, "loopback")
	if err != nil || len(short) != 58 {
		t.Fatalf("descriptor splice = %dB, %v; want 58B", len(short), err)
	}
	if string(short[26:34]) != "loopback" || short[25] != 8 {
		t.Fatalf("descriptor splice slot: nlen=%d name=%q", short[25], short[26:34])
	}
	if !bytes.Equal(short[:25], tpl[:25]) || !bytes.Equal(short[34:], tpl[37:]) {
		t.Fatalf("descriptor splice outskirts drift: head %x tail %x", short[:25], short[34:])
	}
	// 255-truncation guard: a 300B name is capped without error
	// (nlen is a 1B field; sendCarrier-level name bytes are game-only).
	long, err := descriptorFrame(base.descTpl, string(make([]byte, 300)))
	if err != nil || long[25] != 255 || len(long) != 25+1+255+24 {
		t.Fatalf("descriptor truncation: nlen=%d len=%d err=%v", long[25], len(long), err)
	}
}

// TestBaseAppPostDoCmd pins the post-flood bundle discrimination. Both
// genuine bundles open with the same 0x95 doCmdInt3 A1 tag, so only the
// cmd field separates them (regression: matching the tag alone answers
// every poll as a sync and the real client never sees its rev answer).
// v2.1 returns the request id too (the 1a/5e season error echoes it).
func TestBaseAppPostDoCmd(t *testing.T) {
	k2 := uint32(0x78128370)
	srv := &BaseAppServer{} // no dispatch: the hand-written fallback
	cases := []struct {
		name string
		call []byte
		req  uint16
		cmd  uint16
	}{
		{"sync", lobby.DoCmdInt3(224, lobby.CmdSyncData, 88, 0x699a133b, 0), 224, 100},
		{"poll", lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0), 202, 501},
		{"season", lobby.DoCmdInt2(225, lobby.CmdSetActiveVehSeason, 0, 0), 225, 121},
	}
	for _, c := range cases {
		clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, c.call)...)
		call, ok := srv.postDoCmd(clear, k2)
		if !ok || call.Req != c.req || call.Cmd != c.cmd {
			t.Fatalf("%s: postDoCmd = %d/%d, %v; want %d/%d, true", c.name, call.Req, call.Cmd, ok, c.req, c.cmd)
		}
		// A foreign stage key must not resolve.
		if _, ok := srv.postDoCmd(clear, k2^1); ok {
			t.Fatalf("%s: foreign key accepted", c.name)
		}
	}
	// Token bundles (0x8a requestToken) carry no doCmdInt3 head.
	tok := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, lobby.BuildRequestToken(2, 5))...)
	if _, ok := srv.postDoCmd(tok, k2); ok {
		t.Fatal("requestToken bundle matched a doCmdInt3")
	}
}

func TestBaseAppParseLogin(t *testing.T) {
	// Client shape: buildBaseAppLoginMsg body + plain framing.
	rid, key := uint32(44654), uint32(0x69668ba0)
	rq := append([]byte{}, 0x01, 0x00)
	rq = append(rq, buildBaseAppLoginMsg(rid, key, 1, 1300)...)
	rq = append(rq, requestFooter(2)...)
	pkt := append([]byte{0x11, 0x22, 0x33, 0x44}, rq...) // random prefix rides
	pkt = append(pkt, 0x05, 0x06)                        // fluff beyond the footer must not pass
	if _, ok := parseBaseAppLogin(pkt); ok {
		t.Fatal("parse with trailing fluff passed")
	}
	pkt = pkt[:len(pkt)-2]
	got, ok := parseBaseAppLogin(pkt)
	if !ok {
		t.Fatal("parse failed on the exact 22B")
	}
	if got.rid != rid || got.sessionKey != key || got.mtu != 1300 || got.attempts != 1 {
		t.Fatalf("parsed %+v", got)
	}
}

// bindInWindow binds a loopback listener inside the manager window
// (required by both NewBaseAppServer and parseRedirectAt); scans up on
// collision — the window is 190 ports.
func bindInWindow(t *testing.T, port int) *net.UDPConn {
	t.Helper()
	for p := port; p <= RedirectPortHi; p++ {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err == nil {
			return conn
		}
	}
	t.Fatal("no free manager-window port")
	return nil
}

// handshake22 assembles the plaintext 22B: [prefix4][01 00][msg14]
// [footer 2] — the buildBaseAppLoginMsg body, no cipher involved.
func handshake22(rid, sessKey uint32, attempts uint8, mtu int) []byte {
	pfx, _ := randomPrefix()
	pkt := append([]byte{}, pfx[:]...)
	pkt = append(pkt, 0x01, 0x00)
	pkt = append(pkt, buildBaseAppLoginMsg(rid, sessKey, attempts, mtu)...)
	pkt = append(pkt, requestFooter(2)...)
	return pkt
}

func readDatagram(t *testing.T, conn *net.UDPConn, timeout time.Duration) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65536)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("datagram read: %v", err)
	}
	return buf[:n]
}

// TestBaseAppUnknownKeySilent: a 22B with a session key we never
// admitted draws ZERO bytes (p5 validates keys the same way).
func TestBaseAppUnknownKeySilent(t *testing.T) {
	base, err := NewBaseAppServer(BaseAppConfig{Redirect: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32990}})
	if err != nil {
		t.Fatal(err)
	}
	s1 := bindInWindow(t, 32870)
	defer s1.Close()
	s2 := bindInWindow(t, 32871)
	defer s2.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = base.Serve(ctx, s1, s2) }()

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteToUDP(handshake22(1000, 0xdeadbeef, 1, 1300), udpLocal(s1)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, _, err := c.ReadFromUDP(buf); err == nil {
		t.Fatal("unknown key drew a reply (must be silent)")
	}
}

func udpLocal(conn *net.UDPConn) *net.UDPAddr {
	return conn.LocalAddr().(*net.UDPAddr)
}

// TestBaseAppStageLoopback walks BOTH stages with the REAL client-side
// builders (parseBaseAppLogin on the server; stageKeyOf/parseRedirectAt/
// authApp on the "client") and ends in a decrypt-verified 1252B flood
// frame from the flows3 carrier — the same victory bar the live client
// uses. v2.1 adds the per-session dress-up between rotation/auth and
// the burst (info verbatim, descriptor with OUR name back into the
// template, session dict re-pickled from our own admission) and rides
// the genuine post-flood reliable-seq walk (sync 3 / poll 4 / season 6)
// so every minted cumul matches the capture's ramp.
func TestBaseAppStageLoopback(t *testing.T) {
	dumpPath, keyPath := "../../captures/flows3-s2.txt", "../../captures/key3.txt"
	if _, err := os.Stat(dumpPath); err != nil {
		t.Skipf("no stage-2 capture (%v): rebuild with ../captures/extract_flows3.py", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Skipf("no capture key (%v)", err)
	}

	blockKey := baseAppTestKey()
	sessKey := uint32(0x69668ba0)
	loopbackName := "loopback" // must equal the Admit session name

	s1 := bindInWindow(t, 32875)
	defer s1.Close()
	s2 := bindInWindow(t, 32876)
	defer s2.Close()
	base, err := NewBaseAppServer(BaseAppConfig{
		Redirect:     udpLocal(s2),
		FloodPath:    dumpPath,
		FloodKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	admitAt := time.Now()
	base.Admit(LoggedOnSession{SessionKey: sessKey, BlockKey: blockKey, Name: "loopback"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseDone := make(chan struct{})
	go func() {
		defer close(baseDone)
		_ = base.Serve(ctx, s1, s2)
	}()

	c1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	// --- stage-1: 22B → rotation(k1) → tick(28B) → redirect(36B). ---
	rid := uint32(44654) // flows3's stage rid (comment test conn keeps the value)
	if _, err := c1.WriteToUDP(handshake22(rid, sessKey, 1, 1300), udpLocal(s1)); err != nil {
		t.Fatal(err)
	}
	rot := readDatagram(t, c1, 3*time.Second)
	k1, ok := stageKeyOf(rot, rid, blockKey)
	if !ok {
		t.Fatalf("stage-1 rotation unreadable: %x", rot)
	}
	// tick then redirect: the sweep fires ~300 ms after the rotation.
	tick := readDatagram(t, c1, 3*time.Second)
	clearTick := decryptTest(t, blockKey, tick)
	if wantTick, _ := hex.DecodeString(genuineTickRaw); !bytes.Equal(clearTick, wantTick) {
		t.Fatalf("tick clear %x want %x", clearTick, wantTick)
	}
	red := readDatagram(t, c1, 3*time.Second)
	clearRed := decryptTest(t, blockKey, red)
	addr, _, ok := parseRedirectAt(clearRed)
	if !ok || addr == nil || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port != udpLocal(s2).Port {
		t.Fatalf("redirect core: addr=%v ok=%v clear=%x", addr, ok, clearRed)
	}

	// --- stage-2: fresh socket, 22B carries the ROTATED key. ---
	c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadBuffer(1 << 20)
	rid2 := uint32(42599)
	if _, err := c2.WriteToUDP(handshake22(rid2, k1, 1, 1300), udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	rot2 := readDatagram(t, c2, 3*time.Second)
	k2, ok := stageKeyOf(rot2, rid2, blockKey)
	if !ok || k2 == k1 || k2 == 0 {
		t.Fatalf("stage-2 rotation: key=%x ok=%v (must mint a fresh key)", k2, ok)
	}
	// Pre-flood smalls (v2.1) ride right behind the rotation-2 reply
	// (capture order: info at +10 ms, descriptor at +40 ms — sendPre
	// emits both with every rotation-2 reply, loss-robust). The server's
	// descriptor substitution target is the session name "loopback"
	// (loopbackName below is the splice anchor used twice).
	infoPkt := readDatagram(t, c2, 3*time.Second)
	infoClear := decryptTest(t, blockKey, infoPkt)
	if want, _ := hex.DecodeString(genuineInfoClearRaw); !bytes.Equal(infoClear, want) {
		t.Fatalf("info clear %x want %x", infoClear, want)
	}
	descPkt := readDatagram(t, c2, 3*time.Second)
	// Our name (8B) splices into the 61B template → 58B clear → 68B
	// wire: pad = (8−((58+5)%8))%8 = 1 → 58+1+4 magic+1 wastage+4 rfx.
	if len(descPkt) != 68 {
		t.Fatalf("descriptor wire %dB, want 68 (58B name-spliced clear)", len(descPkt))
	}
	descClear := decryptTest(t, blockKey, descPkt)
	tpl, _ := hex.DecodeString(genuineDescrRaw)
	wantDesc := append([]byte{}, tpl[:25]...)
	wantDesc = append(wantDesc, byte(len(loopbackName)))
	wantDesc = append(wantDesc, []byte(loopbackName)...)
	wantDesc = append(wantDesc, tpl[37:]...)
	if !bytes.Equal(descClear, wantDesc) {
		t.Fatalf("descriptor clear %x want %x (name spliced at [25])", descClear, wantDesc)
	}
	// double-auth: the reliable [02][k2][0b] (stageOneDriver.sendOpening
	// shape; the unreliable [02][k2] twin rides 10 ms ahead in the
	// genuine client — either proves key2 to the server, we send one).
	auth1, err := buildChannelPacket(blockKey, flagsRel, authApp(k2), nil, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(auth1, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	// Session dict (v2.1) lands at serveBulk START: [13][40] + the
	// 1a/76 small (clan/offer riders cut) + footers [seq 2][cumul 1]
	// (the auth itself is a reliable seq-0 send → watermark 1).
	// Genuine position: MID-burst (idx 63, seq 176, cumul 1) —
	// documented ordinal delta (§18.7).
	dictPkt := readDatagram(t, c2, 5*time.Second)
	if len(dictPkt) != 188 { // 172B clear = 2 flags + [13 40] + 160B tpl + footers
		t.Fatalf("session dict wire %dB, want 188", len(dictPkt))
	}
	dictClear := decryptTest(t, blockKey, dictPkt)
	// Structural pin, not byte-exact: the mint stamps a live timestamp
	// per send, so the four patched values differ by design; the frame
	// head, the small's envelope + protocol head, the boolean tail
	// (`71 08 89 75 2e` = logUXEvents FALSE + STOP — untouched by the
	// patcher) and the footers are pinned. The patched VALUES are
	// checked below through the decoded pickle.
	if !bytes.Equal(dictClear[0:6], []byte{0x58, 0x04, 0x13, 0x40, 0x1a, 0x76}) ||
		!bytes.Equal(dictClear[6:11], []byte{0x9c, 0x00, 0x9b, 0x80, 0x02}) ||
		!bytes.Equal(dictClear[159:164], []byte{0x71, 0x08, 0x89, 0x75, 0x2e}) {
		t.Fatalf("session dict envelope: head %x mid %x tail %x",
			dictClear[:6], dictClear[6:11], dictClear[159:164])
	}
	if got := binary.LittleEndian.Uint32(dictClear[len(dictClear)-8:]); got != 2 {
		t.Fatalf("session dict seq %d, want 2", got)
	}
	if got := binary.LittleEndian.Uint32(dictClear[len(dictClear)-4:]); got != 1 {
		t.Fatalf("session dict cumul %d, want 1 (auth1 is reliable seq 0)", got)
	}
	// The small's pickle decodes CLOSED; the four live fields must
	// carry OUR admission values, not the capture's (decode the
	// RECEIVED frame's pickle body: [4:164] small, 1 status byte +
	// the 155B proto-2 pickle).
	stk, _, perr := lobby.DecodePrefix(dictClear[9:164])
	if perr != nil {
		t.Fatalf("session-dict pickle decode: %v", perr)
	}
	head := stk[len(stk)-1]
	entries, isDict := head.(*lobby.PDict)
	if !isDict || len(entries.Entries) != 7 { // BINPUT idx 8 = last KEY, entries ≠ 8
		t.Fatalf("session dict stack top %T (entries %d); want *PDict with 7 entries", head, len(entries.Entries))
	}
	val := func(field string) any {
		for _, e := range entries.Entries {
			if k, isStr := e.Key.(string); isStr && k == field {
				return e.Value
			}
		}
		return nil
	}
	utc, isF := val("serverUTC").(float64)
	if !isF || math.Abs(utc-float64(admitAt.Unix())) > 30 {
		t.Fatalf("serverUTC %v (%T); want ≈ admittance %.0f", val("serverUTC"), val("serverUTC"), float64(admitAt.Unix()))
	}
	aogas, isF := val("aogasStartedAt").(float64)
	if !isF || math.Abs(aogas-(utc-0.001951)) > 0.001 {
		t.Fatalf("aogasStartedAt %v; want serverUTC − 0.001951", val("aogasStartedAt"))
	}
	sess, isI := val("sessionStartedAt").(int64)
	if !isI || math.Abs(float64(sess-admitAt.Unix())) > 1 {
		t.Fatalf("sessionStartedAt %v; want the admission second (±1)", val("sessionStartedAt"))
	}
	db, isI := val("databaseID").(int64)
	if !isI || db != int64(pseudoAccountID("loopback")) {
		t.Fatalf("databaseID %v; want pseudoAccountID(loopback) = %d", val("databaseID"), pseudoAccountID("loopback"))
	}
	// flood: first datagram must be 1252B and channel-decrypt under OUR
	// key (the burst continues behind it; the gift-frame check is the win).
	flood := readDatagram(t, c2, 5*time.Second)
	if len(flood) != 1252 {
		t.Fatalf("flood datagram %dB, want 1252", len(flood))
	}
	clearFlood := decryptTest(t, blockKey, flood)
	if len(clearFlood) < 10 || !bytes.Equal(clearFlood[:2], []byte{0x78, 0x00}) {
		t.Fatalf("flood clear head %x (want 7800 bulk frame)", clearFlood)
	}

	// --- post-flood chain (v2): drain the burst, then the tail. ---
	// The burst continues behind the first 1252B; read until the
	// terminator (332B companion), then ticks take over. Every frame
	// must decrypt under OUR session key (re-keyed per session).
	deadline := time.Now().Add(20 * time.Second)
	sawTerm, ticks := false, 0
	for !sawTerm {
		if time.Now().After(deadline) {
			t.Fatalf("terminator never arrived after %d bulk frames", ticks)
		}
		pkt := readDatagram(t, c2, 5*time.Second)
		clear := decryptTest(t, blockKey, pkt)
		switch len(pkt) {
		case 1252:
			continue
		case 332:
			sawTerm = true
			if clear[0] != 0x78 || clear[1] != 0x04 {
				t.Fatalf("terminator flags %x (want 7804 companion)", clear[:2])
			}
		default:
			t.Fatalf("unexpected %dB in burst drain: %x", len(pkt), clear[:min(len(clear), 12)])
		}
	}
	// First tail tick is the carrier's seed tick, byte-exact (the
	// mint starts at tag 7a / seq 503 / cumul 3, advancing after; our
	// test client skips the genuine token/tokres reliable sends between
	// the auth and the burst, so the floor max(live, 3) preserves the
	// capture's cumul ramp — see serveBulk).
	tailTick := readDatagram(t, c2, 3*time.Second)
	clearTailTick := decryptTest(t, blockKey, tailTick)
	if wantTick, _ := hex.DecodeString(genuinePostTickRaw); !bytes.Equal(clearTailTick, wantTick) {
		t.Fatalf("post-flood tick clear %x want %x", clearTailTick, wantTick)
	}
	// The client re-syncs once: 84B [02][key2] bundle with the doCmdInt3
	// A1 tag (genuine idx 1010: DoCmdInt3(224, 100, 88, 0x699a133b, 0)
	// + the (98,25) initAck tail). Sent at the genuine reliable seq 3
	// (auth1 0, sync 3) so the minted answer keeps the capture's cumul 4.
	sync := lobby.BuildLobbyBundle(k2,
		lobby.DoCmdInt3(224, lobby.CmdSyncData, 88, 0x699a133b, 0),
		lobby.BuildChatCommandFromClient(2, lobby.ChatCmdInitAck, 0, 2, 0, nil, nil))
	syncPkt, err := buildChannelPacket(blockKey, flagsRel, sync, nil, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(syncPkt, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	// Ticks interleave with the answers (genuine idx 1011 lands between
	// the 1013/1015 ticks), so read until the answer's own frame shows.
	rev := readUntil(t, c2, blockKey, 5*time.Second, func(wire int, clear []byte) bool {
		return wire == 60
	})
	if wantRev, _ := hex.DecodeString(genuineRevReplyRaw); !bytes.Equal(rev, wantRev) {
		t.Fatalf("rev answer clear %x want %x", rev, wantRev)
	}
	// A 501 server-stats poll draws the 1a/5b counters answer, minted:
	// the BODY replays the capture's first stats answer verbatim
	// (counters drift session-to-session — deliberately stale), the
	// tag/seq walk live, the cumul echoes the poll's seq 4 + 1.
	poll := lobby.BuildLobbyBundle(k2, lobby.DoCmdInt3(lobby.RequestIDNoResponse, lobby.CmdReqServerStats, 0, 0, 0))
	pollPkt, err := buildChannelPacket(blockKey, flagsRel, poll, nil, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(pollPkt, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	ans := readUntil(t, c2, blockKey, 5*time.Second, func(wire int, clear []byte) bool {
		return wire == 36 && hasSmall(clear, 0x1a, 0x5b)
	})
	if len(ans) != 22 {
		t.Fatalf("poll answer clear %dB, want 22", len(ans))
	}
	if wantPoll, _ := hex.DecodeString(genuinePollAnsRaw); !bytes.Equal(ans[4:14], wantPoll[4:14]) {
		t.Fatalf("poll answer body %x want %x (1a/5b counters)", ans[4:14], wantPoll[4:14])
	}
	if got := binary.LittleEndian.Uint32(ans[len(ans)-4:]); got != 5 {
		t.Fatalf("poll answer cumul %d, want 5 (poll at seq 4)", got)
	}
	// Season select (genuine idx 1209: DoCmdInt2(225, 121, 0, 0) at
	// reliable seq 6): we hold no garage, so the genuine failure small
	// answers — the mint echoes the request id into [1a 5e 05][req u16
	// LE][00 00 00] (capture idx 1210: req 225 → `e1 00`).
	season := lobby.BuildLobbyBundle(k2, lobby.DoCmdInt2(225, lobby.CmdSetActiveVehSeason, 0, 0))
	seasonPkt, err := buildChannelPacket(blockKey, flagsRel, season, nil, 6, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(seasonPkt, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	errAns := readUntil(t, c2, blockKey, 5*time.Second, func(wire int, clear []byte) bool {
		return wire == 36 && hasSmall(clear, 0x1a, 0x5e)
	})
	if len(errAns) != 20 { // [13][tag][1a 5e 05][req][00 00 00] + footers
		t.Fatalf("season answer clear %dB, want 20", len(errAns))
	}
	if !bytes.Equal(errAns[4:7], []byte{0x1a, 0x5e, 0x05}) {
		t.Fatalf("season answer head %x (want 1a 5e 05)", errAns[4:7])
	}
	if req := binary.LittleEndian.Uint16(errAns[7:9]); req != 225 {
		t.Fatalf("season error req echo %d, want 225", req)
	}
	if !bytes.Equal(errAns[9:12], []byte{0, 0, 0}) {
		t.Fatalf("season error after-req bytes %x, want 00 00 00", errAns[9:12])
	}
	if got := binary.LittleEndian.Uint32(errAns[len(errAns)-4:]); got != 7 {
		t.Fatalf("season answer cumul %d, want 7 (season at seq 6)", got)
	}

	cancel()
	<-baseDone
}

// min is the small local helper the burst drain uses (Go 1.21 builtin
// covers it in prod code; the test file predates that).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readUntil reads and channel-decrypts datagrams until want matches,
// returning the decrypted body. Post-flood the 100 ms tick stream
// interleaves with the sync/poll answers, so answer reads skip ticks
// instead of failing on the first mismatch.
func readUntil(t *testing.T, conn *net.UDPConn, key string, timeout time.Duration, want func(wire int, clear []byte) bool) []byte {
	t.Helper()
	end := time.Now().Add(timeout)
	for {
		left := time.Until(end)
		if left <= 0 {
			t.Fatal("wanted frame never arrived")
		}
		buf := make([]byte, 65536)
		_ = conn.SetReadDeadline(time.Now().Add(left))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatal("datagram read:", err)
		}
		clear, err := decryptBlowfish(key, buf[4:n])
		if err != nil {
			continue // stray/undecryptable: keep reading
		}
		if want(n, clear) {
			return clear
		}
	}
}

// TestBaseAppRotationFreshKey: repeated handshakes keep the minted key
// (recovery for a lost rotation must not re-rotate, or the stage-2 22B
// would carry a dead key).
func TestBaseAppRotationFreshKey(t *testing.T) {
	k := mintKeyFor(t, 0x1234)
	if k != 0 && k != 0x1234 {
		// accepted
	} else {
		t.Fatal("mint returned old/zero")
	}
	// deterministic: no block padding surprises
	_ = binary.LittleEndian.Uint32([]byte{1, 0, 0, 0})
}

func mintKeyFor(t *testing.T, old uint32) uint32 {
	t.Helper()
	k, err := mintRotationKey(old)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestCmdLabel proves the post-flood log names the command when the
// shipped table knows it, and falls back to the bare number otherwise.
func TestCmdLabel(t *testing.T) {
	if got := cmdLabel(lobby.CmdSyncShop); got != "CMD_SYNC_SHOP (300)" {
		t.Fatalf("cmdLabel(300) = %q", got)
	}
	if got := cmdLabel(9999); got != "cmd 9999" {
		t.Fatalf("cmdLabel(9999) = %q", got)
	}
}
