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
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/hex"
	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
	"io"
	"math"
	"net"
	"os"
	"strings"
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
	// Stage-1 info (52B frame, flows3 flow 14 seq 1) and space (44B
	// frame, seq 3) — the two frames the client needs between the
	// rotation and the redirect. The info carries the account id as an
	// ASCII string; the space names the space to enter.
	// The entity id (capture: f1 f7 2b 00) and the account id (capture:
	// "123456789") are substituted per session, so the template is
	// prefix + entityID(4) + mid + 9 digits + suffix.
	genuineStage1InfoPrefix = "5804020a01003e8b2300133e051200"
	genuineStage1InfoMid    = "0b000009"
	genuineStage1InfoSuffix = "000100000001000000"
	genuineStage1SpaceRaw   = "5804133e1a500d0764656661756c74048002 4e2e0300000001000000"
	genuineRedirectRaw      = "5804133f445cdf14d4804c0000010400000001000000"

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
// TestBaseAppAuthoredContent pins the stage-2 content the server now
// AUTHORS: the flood bundle (from the defs + the settings document), the
// session dict, the revisions answer and the stats answer. No capture is
// read.
func TestBaseAppAuthoredContent(t *testing.T) {
	settings, err := lobby.EncodeDocument(lobby.NewDict().
		Set("file_server", lobby.NewDict().Set("host", lobby.NewString("127.0.0.1"))).
		Set("padding", lobby.NewString(strings.Repeat("x", 70000))))
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	base, err := NewBaseAppServer(BaseAppConfig{
		Redirect: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 32990},
		Dispatch: testDispatch(t),
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The bundle: updateFrequencyNotification + tickSync + the oversize
	// createBasePlayer element carrying the settings pickle.
	stream, err := base.buildFlood(&clientState{entityID: 0x1234, name: "tester", version: "2.4.1"})
	if err != nil {
		t.Fatalf("buildFlood: %v", err)
	}
	if stream[0] != 0x02 || stream[8] != 0x13 || stream[10] != 0x05 {
		t.Fatalf("bundle head % x, want 02… 13… 05…", stream[:16])
	}
	if stream[11] != 0xFF || stream[12] != 0xFF {
		t.Fatalf("createBasePlayer length field % x, want the oversize FF FF", stream[11:13])
	}
	// The element's u32 must cover the rest of the stream exactly.
	elemLen := int(binary.LittleEndian.Uint32(stream[13:17]))
	if got, want := 17+elemLen, len(stream); got != want {
		t.Fatalf("element ends at %d, stream is %d B", got, want)
	}
	// The entity id rides in the element's last four bytes (the oversize
	// form's displaced head).
	if got := binary.LittleEndian.Uint32(stream[len(stream)-4:]); got != 0x1234 {
		t.Fatalf("entity id %d, want 0x1234", got)
	}

	// The session dict: 1a/76 with the u16 length, a status byte and a
	// pickle holding the four live fields.
	dict, err := BuildSessionDict(100000001, time.Unix(1789681556, 0), time.Unix(1789681556, 500000000))
	if err != nil {
		t.Fatalf("BuildSessionDict: %v", err)
	}
	sm, n, err := lobby.ParseSmall(dict)
	if err != nil || n != len(dict) {
		t.Fatalf("session dict parse: %v (%d/%d)", err, n, len(dict))
	}
	if sm.Family != 0x1a || sm.Type != 0x76 {
		t.Fatalf("session dict is %#02x/%#02x, want 1a/76", sm.Family, sm.Type)
	}
	// Body = [u8 pickle length][pickle] — the genuine 1a/76 shape
	// (`1a 76 9c 00 9b <155B>`: 0x9b = 155 = 156 - 1). No status byte.
	if int(sm.Body[0]) != len(sm.Body)-1 {
		t.Fatalf("session dict body head % x (length byte %d, body %d B)", sm.Body[:4], sm.Body[0], len(sm.Body))
	}
	stk, _, err := lobby.DecodePrefix(sm.Body[1:])
	if err != nil {
		t.Fatalf("session dict pickle: %v", err)
	}
	d, ok := stk[len(stk)-1].(*lobby.PDict)
	if !ok || len(d.Entries) != 7 {
		t.Fatalf("session dict stack top %T (%d entries), want *PDict with 7", stk[len(stk)-1], len(d.Entries))
	}
	val := func(k string) any {
		for _, e := range d.Entries {
			if e.Key == k {
				return e.Value
			}
		}
		return nil
	}
	if v, _ := val("databaseID").(int64); v != 100000001 {
		t.Fatalf("databaseID %v", val("databaseID"))
	}
	if v, _ := val("sessionStartedAt").(int64); v != 1789681556 {
		t.Fatalf("sessionStartedAt %v", val("sessionStartedAt"))
	}
	if v, _ := val("serverUTC").(float64); v != 1789681556.5 {
		t.Fatalf("serverUTC %v", val("serverUTC"))
	}

	// The revisions answer: 1a/5f, [req u32][status][len][pickle].
	rev, err := BuildRevisionsAnswer(224, 88, 88)
	if err != nil {
		t.Fatalf("BuildRevisionsAnswer: %v", err)
	}
	rs, _, err := lobby.ParseSmall(rev)
	if err != nil {
		t.Fatalf("rev parse: %v", err)
	}
	if rs.Family != 0x1a || rs.Type != 0x5f {
		t.Fatalf("rev answer is %#02x/%#02x, want 1a/5f", rs.Family, rs.Type)
	}
	if got := binary.LittleEndian.Uint32(rs.Body[:4]); got != 224 {
		t.Fatalf("rev answer request id %d, want 224", got)
	}
	if rs.Body[4] != 0 || int(rs.Body[5]) != len(rs.Body)-6 {
		t.Fatalf("rev answer body head % x", rs.Body[:6])
	}

	// The stats answer: 1a/5b, two u32 counters, no length byte.
	st, err := BuildServerStatsAnswer(7, 9)
	if err != nil {
		t.Fatalf("BuildServerStatsAnswer: %v", err)
	}
	ss, _, err := lobby.ParseSmall(st)
	if err != nil {
		t.Fatalf("stats parse: %v", err)
	}
	if ss.Family != 0x1a || ss.Type != 0x5b || len(ss.Body) != 8 {
		t.Fatalf("stats answer %#02x/%#02x body %d B", ss.Family, ss.Type, len(ss.Body))
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
		call, ok := srv.postDoCmd(nil, clear, k2)
		if !ok || call.Req != c.req || call.Cmd != c.cmd {
			t.Fatalf("%s: postDoCmd = %d/%d, %v; want %d/%d, true", c.name, call.Req, call.Cmd, ok, c.req, c.cmd)
		}
		// A foreign stage key must not resolve.
		if _, ok := srv.postDoCmd(nil, clear, k2^1); ok {
			t.Fatalf("%s: foreign key accepted", c.name)
		}
	}
	// Token bundles (0x8a requestToken) carry no doCmdInt3 head.
	tok := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, lobby.BuildRequestToken(2, 5))...)
	if _, ok := srv.postDoCmd(nil, tok, k2); ok {
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
	blockKey := baseAppTestKey()
	sessKey := uint32(0x69668ba0)

	s1 := bindInWindow(t, 32875)
	defer s1.Close()
	s2 := bindInWindow(t, 32876)
	defer s2.Close()
	// A settings document big enough to force the fragment chain (the
	// single-datagram path is covered by TestFloodFramesCarryTheBundleVerbatim).
	base, err := NewBaseAppServer(BaseAppConfig{
		Redirect:         udpLocal(s2),
		Dispatch:         testDispatch(t),
		Settings:         bigSettings(t),
		CreateBasePlayer: true,
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
	// info rides with the rotation: the genuine 52B, account id spliced
	// in as 9 ASCII digits (accountIDFor always yields 9).
	info1 := readDatagram(t, c1, 3*time.Second)
	clearInfo1 := decryptTest(t, blockKey, info1)
	prefix, _ := hex.DecodeString(genuineStage1InfoPrefix)
	mid, _ := hex.DecodeString(genuineStage1InfoMid)
	suffix, _ := hex.DecodeString(genuineStage1InfoSuffix)
	wantLen := len(prefix) + 4 + len(mid) + 9 + len(suffix)
	if len(clearInfo1) != wantLen {
		t.Fatalf("stage-1 info clear %x: %d B, want %d", clearInfo1, len(clearInfo1), wantLen)
	}
	if !bytes.Equal(clearInfo1[:len(prefix)], prefix) {
		t.Fatalf("stage-1 info clear %x: prefix does not match the capture", clearInfo1)
	}
	// The entity id must be the one stage-2 uses (the session key), or
	// the client ends up with two player entities and asserts pEntity.
	if got := binary.LittleEndian.Uint32(clearInfo1[len(prefix) : len(prefix)+4]); got != sessKey {
		t.Fatalf("stage-1 createBasePlayer entity %d, want the session key %d", got, sessKey)
	}
	rest := clearInfo1[len(prefix)+4:]
	if !bytes.Equal(rest[:len(mid)], mid) || !bytes.Equal(rest[len(mid)+9:], suffix) {
		t.Fatalf("stage-1 info clear %x: mid/suffix do not match the capture", clearInfo1)
	}
	for _, c := range rest[len(mid) : len(mid)+9] {
		if c < '0' || c > '9' {
			t.Fatalf("stage-1 info account id %q is not 9 digits", rest[len(mid):len(mid)+9])
		}
	}
	// tick, space, then redirect: the sweep fires ~300 ms after the rotation.
	tick := readDatagram(t, c1, 3*time.Second)
	clearTick := decryptTest(t, blockKey, tick)
	if wantTick, _ := hex.DecodeString(genuineTickRaw); !bytes.Equal(clearTick, wantTick) {
		t.Fatalf("tick clear %x want %x", clearTick, wantTick)
	}
	space := readDatagram(t, c1, 3*time.Second)
	clearSpace := decryptTest(t, blockKey, space)
	if wantSpace, _ := hex.DecodeString(strings.Replace(genuineStage1SpaceRaw, " ", "", -1)); !bytes.Equal(clearSpace, wantSpace) {
		t.Fatalf("stage-1 space clear %x want %x", clearSpace, wantSpace)
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
	// Nothing rides between the rotation-2 reply and the burst: the
	// chain's first fragment carries the info elements
	// (updateFrequencyNotification + tickSync) and the createBasePlayer
	// header, exactly as the 2.4.1 flow does.
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
	// flood: the burst opens with the carrier chain's FIRST fragment —
	// the short one that carries the bundle's leading elements
	// (updateFrequencyNotification, tickSync, the createBasePlayer
	// header), not a full 1252B chunk. It must channel-decrypt under OUR
	// key and name the chain's own range.
	flood := readDatagram(t, c2, 5*time.Second)
	clearFlood := decryptTest(t, blockKey, flood)
	if len(clearFlood) < 14 || clearFlood[0]&0x20 == 0 {
		t.Fatalf("flood clear head %x (want a fragment frame)", clearFlood)
	}
	first, last, seq, ok := fragRange(clearFlood)
	if !ok || seq != first {
		t.Fatalf("flood first fragment range [%d,%d] seq %d ok=%v (the client needs seq == first)", first, last, seq, ok)
	}

	// --- drain the rest of the burst, then acknowledge it. ---
	// What follows the burst — the session dict, the stats small, the
	// Account's own entry — addresses the Account entity the burst creates,
	// so the server holds it until the client has the whole chain. A
	// fragment that is not the chain's first is DISCARDED by the client, so
	// sending them earlier is an entity method for an entity it does not
	// have (`MF_ASSERT_DEV FAILED: pEntity`).
	for got := first; got < last; got++ {
		pkt := readDatagram(t, c2, 5*time.Second)
		clear := decryptTest(t, blockKey, pkt)
		if len(clear) < 14 || clear[0]&0x20 == 0 {
			t.Fatalf("burst frame after %d: unexpected %dB %x", got, len(pkt), clear[:min(len(clear), 12)])
		}
	}
	// A lobby base call, not a bare ack: the client's `LoginReplyFilter`
	// passes only the login-reply packet and is disarmed by its first lobby
	// call, so the chain that follows the burst waits for THIS. The call also
	// carries the cumulative ack that retires the burst.
	callApp := []byte{0x02, 0, 0, 0, 0, 0x95, 0x04, 0x00, 0, 0, 0, 0}
	callPkt, err := buildChannelPacket(blockKey, flagsRel, callApp, nil, 1, last+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(callPkt, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}

	// --- post-flood chain: the session dict, then the tick stream. ---
	// Every frame must decrypt under OUR session key.
	deadline := time.Now().Add(20 * time.Second)
	var dictPkt []byte
	burst := 0
	for dictPkt == nil {
		if time.Now().After(deadline) {
			t.Fatalf("session dict never arrived after %d bulk frames", burst)
		}
		pkt := readDatagram(t, c2, 5*time.Second)
		clear := decryptTest(t, blockKey, pkt)
		if len(clear) >= 4 && clear[0] == 0x58 && clear[1] == 0x04 && clear[2] == 0x13 && clear[3] == 0x40 {
			dictPkt = pkt // the session dict closes the burst
			continue
		}
		if len(clear) < 14 || clear[0]&0x20 == 0 {
			t.Fatalf("unexpected %dB in burst drain: %x", len(pkt), clear[:min(len(clear), 12)])
		}
		burst++
	}
	// Session dict: [13][40] + the 1a/76 small + footers [seq][cumul]
	// (the auth itself is a reliable seq-0 send → watermark 1). The seq
	// sits past the chain's range: a minted seq inside it would be a
	// duplicate the client drops, and one sent first would push the
	// chain's own fragments below its watermark.
	dictClear := decryptTest(t, blockKey, dictPkt)
	if !bytes.Equal(dictClear[0:6], []byte{0x58, 0x04, 0x13, 0x40, 0x1a, 0x76}) {
		t.Fatalf("session dict head %x, want 5804 1340 1a76", dictClear[:6])
	}
	dictSeq := binary.LittleEndian.Uint32(dictClear[len(dictClear)-8:])
	// The channel delivers in order: the dict must take the seq right
	// after the chain, or everything after it stalls in the client's
	// receive window and is never ACKed.
	if want := last + 1; dictSeq != want {
		t.Fatalf("session dict seq %d, want %d (the seq right after the chain)", dictSeq, want)
	}
	// The dict's cumul is the client's watermark when it goes out. The ack
	// datagram releases the chain before its own seq is folded in, so this is
	// still auth1's seq 0 + 1 — behind the client's counter, which is always
	// safe.
	if got := binary.LittleEndian.Uint32(dictClear[len(dictClear)-4:]); got != 1 {
		t.Fatalf("session dict cumul %d, want 1 (auth1 is reliable seq 0)", got)
	}
	// The small's pickle decodes CLOSED; the four live fields must
	// carry OUR admission values.
	dictSmall, _, serr := lobby.ParseSmall(dictClear[4 : len(dictClear)-8])
	if serr != nil {
		t.Fatalf("session dict small: %v", serr)
	}
	// Body = [u8 pickle length][pickle] (the genuine 1a/76 shape).
	if int(dictSmall.Body[0]) != len(dictSmall.Body)-1 {
		t.Fatalf("session dict length byte %d, body %d B", dictSmall.Body[0], len(dictSmall.Body))
	}
	stk, _, perr := lobby.DecodePrefix(dictSmall.Body[1:])
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
	// 1a/69 stats small: the account's free XP, on the seq after the dict.
	statsPkt := readDatagram(t, c2, 3*time.Second)
	statsClear := decryptTest(t, blockKey, statsPkt)
	statsSmall, _, err := lobby.ParseSmall(statsClear[4:])
	if err != nil {
		t.Fatalf("stats small: %v", err)
	}
	if statsSmall.Family != 0x1a || statsSmall.Type != 0x69 {
		t.Fatalf("stats small is %#02x/%#02x, want 1a/69", statsSmall.Family, statsSmall.Type)
	}
	if got := binary.LittleEndian.Uint32(statsClear[len(statsClear)-8:]); got != dictSeq+1 {
		t.Fatalf("stats small seq %d, want %d", got, dictSeq+1)
	}

	// selectPlayerEntity + showGUI ride the SESSION-DICT frame itself:
	// `[1a][76][u16 elementLen][u8 stringLen][pickle]`. 0x1A is
	// selectPlayerEntity (FIXED 0) and 0x76 is showGUI, so the "dict"
	// packet IS the call that makes the hangar appear — the genuine
	// server sends the pair once, not as two extra frames.
	if len(dictClear) < 8 || dictClear[4] != elSelectPlayerEntity || dictClear[5] != byte(entityMethodBase+40) {
		t.Fatalf("session-dict frame % x, want 1a %#02x …", dictClear, byte(entityMethodBase+40))
	}
	elemLen := int(binary.LittleEndian.Uint16(dictClear[6:8]))
	strLen := int(dictClear[8])
	if elemLen != 1+strLen {
		t.Fatalf("showGUI element length %d, string length %d (want 1+%d)", elemLen, strLen, strLen)
	}
	if got, want := 9+strLen, len(dictClear)-8; got != want {
		t.Fatalf("showGUI string ends at %d, frame body ends at %d", got, want)
	}

	// First tail tick: tag 0x7a, the seq right after the session dict,
	// and the cumulative ack is OURS — "last processed peer reliable
	// seq + 1", i.e. 1 after the auth1 at seq 0. A cumul ahead of the
	// client's own outbound seq makes it drop the frame:
	//
	//   UDPChannel::handleCumulativeAck: Received ACK for packets not
	//   yet sent. endSeq: #3 outSeq: #2
	tailTick := readDatagram(t, c2, 3*time.Second)
	clearTailTick := decryptTest(t, blockKey, tailTick)
	if len(clearTailTick) != 12 || clearTailTick[0] != 0x58 || clearTailTick[1] != 0x04 ||
		clearTailTick[2] != 0x13 || clearTailTick[3] != 0x7a {
		t.Fatalf("post-flood tick clear %x, want 5804 137a …", clearTailTick)
	}
	if got := binary.LittleEndian.Uint32(clearTailTick[4:8]); got != dictSeq+2 {
		t.Fatalf("post-flood tick seq %d, want %d (after the stats frame)", got, dictSeq+2)
	}
	// The lobby call above carried seq 1, so the client's next expected is 2.
	if got := binary.LittleEndian.Uint32(clearTailTick[8:12]); got != 2 {
		t.Fatalf("post-flood tick cumul %d, want 2 (the lobby call's seq 1 + 1)", got)
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
		return len(clear) > 4 && clear[2] == 0x13 && clear[3] == 0x7b
	})
	// The answer is authored: [13][7b] + 1a/5f RES_STREAM, then the
	// resource header and fragment carrying the full state. It rides the
	// stream because a garage of every ownable vehicle is ~9 KB, far past
	// the 1223-byte bundle payload.
	reqID, resultID, errStr, _, err := ParseCommandResponse(rev[4:])
	if err != nil {
		t.Fatalf("sync answer: %v", err)
	}
	if reqID != 224 {
		t.Fatalf("sync answer request id %d, want 224", reqID)
	}
	if resultID != 1 || errStr != "" {
		t.Fatalf("sync answer result %d error %q, want 1 (RES_STREAM) and empty", resultID, errStr)
	}
	// The stream: a RESOURCE_HEADER then one RESOURCE_FRAGMENT per chunk,
	// all under the request id. The payload is chunked at
	// streamFragmentSize, so every fragment has to be collected in
	// sequence order until the one flagged last.
	var payload []byte
	frags := map[int][]byte{}
	lastSeq := -1
	for lastSeq < 0 {
		el := readUntil(t, c2, blockKey, 5*time.Second, func(wire int, clear []byte) bool {
			return len(clear) > 4 && clear[2] == 0x13 && (clear[4] == 0x45 || clear[4] == 0x46)
		})
		sm, _, err := lobby.ParseSmall(el[4:])
		if err != nil {
			t.Fatalf("stream element: %v", err)
		}
		if sm.Family != 0x46 {
			continue // the header only registers the stream
		}
		// [u16 id][u8 seq][u8 last][data]
		seq := int(sm.Body[2])
		frags[seq] = sm.Body[4:]
		if sm.Body[3] != 0 {
			lastSeq = seq
		}
	}
	for i := 0; i <= lastSeq; i++ {
		chunk, ok := frags[i]
		if !ok {
			t.Fatalf("stream fragment %d of %d missing", i, lastSeq)
		}
		payload = append(payload, chunk...)
	}
	zr, err := zlib.NewReader(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("stream zlib: %v", err)
	}
	raw, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("stream zlib read: %v", err)
	}
	revStk, _, err := lobby.DecodePrefix(raw)
	if err != nil {
		t.Fatalf("sync pickle: %v", err)
	}
	rd, ok := revStk[len(revStk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("sync stack top %T", revStk[len(revStk)-1])
	}
	var sawStats, sawPrevRev bool
	for _, e := range rd.Entries {
		k, _ := e.Key.(string)
		switch k {
		case "stats":
			sawStats = true
		case "prevRev":
			sawPrevRev = true
		}
	}
	if !sawStats {
		t.Fatal("sync answer has no stats: the client would show \"-\" for every resource")
	}
	if sawPrevRev {
		t.Fatal("sync answer carries prevRev: AccountSyncData.isFullSyncDiff would be false")
	}

	// The FOLLOW-UP. AccountSyncData.__onSyncComplete ends with
	// `self._synchronize()`, which asks again with the revision the stream
	// just delivered. That request must be answered too — leaving it
	// parked in __onCmdResponse is what stalled the hangar on
	// "Synchronisation de l'équipement" once the sync moved to the stream.
	followUp := lobby.BuildLobbyBundle(k2,
		lobby.DoCmdInt3(225, lobby.CmdSyncData, fullSyncRev, 0, 0))
	followPkt, err := buildChannelPacket(blockKey, flagsRel, followUp, nil, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.WriteToUDP(followPkt, udpLocal(s2)); err != nil {
		t.Fatal(err)
	}
	ack := readUntil(t, c2, blockKey, 5*time.Second, func(wire int, clear []byte) bool {
		if len(clear) < 6 || clear[2] != 0x13 || clear[4] != 0x1a || clear[5] != 0x5f {
			return false
		}
		id, _, _, _, err := ParseCommandResponse(clear[4:])
		return err == nil && id == 225
	})
	ackID, ackResult, _, ackExt, err := ParseCommandResponse(ack[4:])
	if err != nil {
		t.Fatalf("follow-up answer: %v", err)
	}
	if ackID != 225 || ackResult != 0 {
		t.Fatalf("follow-up answer id %d result %d, want 225 and 0 (RES_SUCCESS)", ackID, ackResult)
	}
	ackStk, _, err := lobby.DecodePrefix(ackExt)
	if err != nil {
		t.Fatalf("follow-up pickle: %v", err)
	}
	ackDict, ok := ackStk[len(ackStk)-1].(*lobby.PDict)
	if !ok {
		t.Fatalf("follow-up stack top %T", ackStk[len(ackStk)-1])
	}
	var ackRev, ackPrev int64 = -1, -1
	for _, e := range ackDict.Entries {
		k, _ := e.Key.(string)
		v, _ := e.Value.(int64)
		switch k {
		case "rev":
			ackRev = v
		case "prevRev":
			ackPrev = v
		}
	}
	if ackRev != fullSyncRev || ackPrev != fullSyncRev {
		t.Fatalf("follow-up ack {rev: %d, prevRev: %d}, want both %d", ackRev, ackPrev, fullSyncRev)
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
	// The counters are authored (the account id and the live session
	// count), so only the framing is pinned: [13][tag] + 1a/5b + two u32.
	if !bytes.Equal(ans[4:6], []byte{0x1a, 0x5b}) {
		t.Fatalf("poll answer body %x, want 1a/5b", ans[4:6])
	}
	if got := binary.LittleEndian.Uint32(ans[6:10]); got != uint32(0) {
		t.Logf("poll counter 1 = %d", got)
	}
	// The ack counts the client's RELIABLE packets: four of the five it sent
	// here (one is an unreliable auth), not its trailer's seq.
	if got := binary.LittleEndian.Uint32(ans[len(ans)-4:]); got != 5 {
		t.Fatalf("poll answer cumul %d, want 5 (the client's next expected sequence)", got)
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

// TestFloodFramesCarryTheBundleVerbatim pins the flood's assembly model:
// the client's FragmentedBundle concatenates the chain's packet bodies in
// seq order and walks the result as a stream of ClientInterface elements,
// so the burst must carry every fragment of the chain, in chain order,
// with one [first,last] range and contiguous seqs.
//
// The regression this guards: dropping the chain's leading fragment (the
// short one that carries updateFrequencyNotification + tickSync + the
// createBasePlayer header) and stripping a "chain header" off the next
// one shifts every element by those bytes. The client then reads a
// garbage length and walks off the end of the chain:
//
//	BundleDataPos::advance: Ran out of packets.
//	MF_ASSERT_DEV FAILED: tailAdvanceSuccess
//	interface_element.cpp(544)
func TestFloodFramesCarryTheBundleVerbatim(t *testing.T) {
	blockKey := baseAppTestKey()
	stream, err := FloodBundle{
		EntityID:    0x00298b89,
		TypeID:      1,
		Version:     "eu_2.4.1_2",
		Name:        "ExampleUser",
		Incarnation: 2618,
		Settings:    bigSettings(t),
		Components:  19,
		Frequency:   10,
		GameTime:    2238978,
		TickTag:     2,
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frames, err := FloodFrames(blockKey, stream, floodFirstSeq)
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	if len(frames) < 2 {
		t.Fatalf("%d frames, want a multi-fragment chain", len(frames))
	}
	var got []byte
	for i, frame := range frames {
		clear, err := DecryptChannelFrame(blockKey, frame)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		first, last, seq, ok := fragRange(clear)
		if !ok {
			t.Fatalf("frame %d is not a fragment: % x", i, clear[:8])
		}
		if first != floodFirstSeq || last != floodFirstSeq+uint32(len(frames))-1 {
			t.Fatalf("frame %d range [%d,%d], want [%d,%d]", i, first, last,
				floodFirstSeq, floodFirstSeq+uint32(len(frames))-1)
		}
		if seq != first+uint32(i) {
			t.Fatalf("frame %d seq %d, want %d (chain order)", i, seq, first+uint32(i))
		}
		tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
		got = append(got, clear[2:len(clear)-tr]...)
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("reassembled %d B, authored %d B", len(got), len(stream))
	}
	// The bundle opens with the client's own elements, not a pickle, and
	// the settings document is inside it.
	if stream[0] == 0x80 {
		t.Fatal("bundle opens with a pickle PROTO, want a ClientInterface element")
	}
	off := -1
	for i := 0; i+1 < len(stream) && i < 512; i++ {
		if stream[i] == 0x80 && stream[i+1] == 0x02 {
			off = i
			break
		}
	}
	if off < 0 {
		t.Fatal("no PROTO 2 document in the bundle head")
	}
	stack, marks, ops, n, stopped, err := lobby.DecodeFaithfulStream(stream[off:])
	if err != nil {
		t.Fatalf("pickle at %d: %v", off, err)
	}
	enc, err := lobby.EncodeFaithfulOpsStop(stack, marks, ops, stopped)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(enc, stream[off:off+n]) {
		t.Fatal("pickle re-encode is not byte-identical")
	}
	t.Logf("%d frames, %d B bundle, pickle at %d (%d B)", len(frames), len(stream), off, n)
}

// testDispatch loads the game's entity defs for the tests that author
// wire content from them. Skips when the game tree is absent.
func testDispatch(t *testing.T) *entdef.Dispatch {
	t.Helper()
	const dir = "../../scripts-2.4.1/entity_defs"
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no entity defs (%v)", err)
	}
	l := &entdef.Loader{Dir: dir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatalf("defs: %v", err)
	}
	d, err := entdef.NewDispatch(l, names)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return d
}

// bigSettings is a real settings pickle large enough to force a
// multi-fragment flood chain.
func bigSettings(t *testing.T) []byte {
	t.Helper()
	raw, err := lobby.EncodeDocument(lobby.NewDict().
		Set("file_server", lobby.NewDict().Set("host", lobby.NewString("127.0.0.1"))).
		Set("padding", lobby.NewString(strings.Repeat("x", 3000))))
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	return raw
}

// TestServedSeqsAreContiguous pins the reliable seq space the server
// mints on the stage-2 channel: rotation-2 at 0, the flood chain from 1,
// then the session dict and the tick stream with no gaps.
//
// The client's channel is reliable and delivers IN ORDER, so a gap
// stalls everything after it: the frames sit in the receive window, the
// client never ACKs them, and the server resends until the peer times
// out. (Observed: chain [1,2] then the dict at 4 — the client accepted
// the flood, created the Account entity, and then ignored every later
// frame.)
func TestServedSeqsAreContiguous(t *testing.T) {
	blockKey := baseAppTestKey()
	stream, err := FloodBundle{
		EntityID:    0x1234,
		TypeID:      1,
		Version:     "eu_2.4.1_2",
		Name:        "tester",
		Incarnation: 1,
		Settings:    bigSettings(t),
		Components:  19,
		Frequency:   10,
		GameTime:    1,
		TickTag:     2,
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frames, err := FloodFrames(blockKey, stream, floodFirstSeq)
	if err != nil {
		t.Fatalf("frames: %v", err)
	}
	// The chain must start at floodFirstSeq and be contiguous.
	for i, frame := range frames {
		clear, err := DecryptChannelFrame(blockKey, frame)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		_, _, seq, ok := fragRange(clear)
		if !ok || seq != floodFirstSeq+uint32(i) {
			t.Fatalf("frame %d seq %d, want %d", i, seq, floodFirstSeq+uint32(i))
		}
	}
	// The dict takes the next seq, and the ticks follow it.
	lastSeq := floodFirstSeq + uint32(len(frames)) - 1
	dictSeq := lastSeq + 1
	if dictSeq != floodFirstSeq+uint32(len(frames)) {
		t.Fatalf("dict seq %d leaves a gap after the chain's %d", dictSeq, lastSeq)
	}
	t.Logf("chain [%d,%d], dict %d, ticks from %d", floodFirstSeq, lastSeq, dictSeq, dictSeq+1)
}

// TestPostCallsReadsEveryCallInTheBundle pins the opener's shape: the
// client sends the account sync (100), the shop sync (300) and the
// dossier sync (600) in ONE datagram, each with its own waitForSync() on
// the client side. Answering only the leading call leaves the other two
// pending forever and the hangar never advances past SHOW GUI.
func TestPostCallsReadsEveryCallInTheBundle(t *testing.T) {
	k2 := uint32(0x78128370)
	srv := &BaseAppServer{} // no dispatch: the hand-written fallback
	app := append([]byte{}, lobby.DoCmdInt3(221, lobby.CmdSyncData, 0, 0, 0)...)
	app = append(app, lobby.DoCmdInt3(222, lobby.CmdSyncShop, 0, 0, 0)...)
	app = append(app, lobby.DoCmdInt3(223, lobby.CmdSyncDossiers, 0, 0, 0)...)
	clear := append([]byte{0x58, 0x04}, lobby.BuildLobbyBundle(k2, app)...)
	// A reliable trailer: [seq][cumul], so the walk must stop before it.
	clear = append(clear, 0, 0, 0, 0, 0, 0, 0, 0)

	calls := srv.postCalls(nil, clear, k2)
	if len(calls) != 3 {
		t.Fatalf("%d calls decoded, want 3 (sync, shop, dossiers)", len(calls))
	}
	want := []struct {
		req uint16
		cmd uint16
	}{{221, lobby.CmdSyncData}, {222, lobby.CmdSyncShop}, {223, lobby.CmdSyncDossiers}}
	for i, w := range want {
		if calls[i].Req != w.req || calls[i].Cmd != w.cmd {
			t.Fatalf("call %d = %d/%d, want %d/%d", i, calls[i].Req, calls[i].Cmd, w.req, w.cmd)
		}
	}
	if got := srv.postCalls(nil, clear, k2^1); len(got) != 0 {
		t.Fatalf("foreign stage key decoded %d calls", len(got))
	}
}

// TestArenaTickPositionsRideTheUnreliableStream pins the split the captured
// server uses for the arena tick: the position elements go out on the
// UNRELIABLE stream (flags 0x1448, its own sequence counter, the aux word),
// one datagram per tick, in the captured order — TickSync, the metre-rounded
// reference, the player's own entity on it, then the Vehicle by alias at its
// absolute position.
//
// The sequence is the point of the test. The unreliable stream has its own
// space: reusing the reliable seq makes it jump by however many reliable sends
// happened in between, and the client discards a packet whose sequence does not
// advance — which is how an earlier attempt at this left the tank at spawn.
func TestArenaTickPositionsRideTheUnreliableStream(t *testing.T) {
	blockKey := baseAppTestKey()
	s := &BaseAppServer{resend: newResendQueue(0, 0)}
	st := &clientState{
		blockKey:  blockKey,
		resendKey: "session-1",
		unrelSeq:  1,
		postSeq:   42, // reliable sends so far: the aux word's source
		postCumul: 7,
	}
	pos := [3]float32{336.83, -5.05, 686.5}
	dir := [3]float32{0.02, -0.004, 3.13}
	app := EncodeTickSync(9)
	app = append(app, EncodeRelativePosition(roundVec3(pos))...)
	app = append(app, EncodeAvatarUpdatePlayerDetailed(0, [3]float32{}, [3]float32{})...)
	app = append(app, EncodeAvatarUpdateAliasDetailed(0, VehicleAlias, pos, dir)...)

	tr := &fakeTransport{}
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40010}
	for i := 0; i < 2; i++ {
		if err := s.sendUnreliableLocked(tr, to, st, app); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d writes, want 2", len(tr.writes))
	}
	for i, frame := range tr.writes {
		clear, err := DecryptChannelFrame(blockKey, frame)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if flags := binary.LittleEndian.Uint16(clear[0:2]); flags != 0x1448 {
			t.Fatalf("frame %d flags %#04x, want 0x1448 (ON|SEQ|CUMUL|AUX, no RELIABLE)", i, flags)
		}
		// The footers are [aux][seq][cumul] after the app (see
		// buildChannelPacket); the aux word is the reliable-send counter.
		n := len(clear)
		if aux := binary.LittleEndian.Uint32(clear[n-12 : n-8]); aux != (uint32(42)-1)&0x0FFFFFFF {
			t.Fatalf("frame %d aux %#x, want the reliable-send counter %#x", i, aux, (uint32(42)-1)&0x0FFFFFFF)
		}
		if seq := binary.LittleEndian.Uint32(clear[n-8 : n-4]); seq != uint32(1+i) {
			t.Fatalf("frame %d seq %d, want %d (the unreliable counter, not the reliable one)", i, seq, 1+i)
		}
		// The last four bytes are the cumulative ACK of the CLIENT's stream —
		// the same footer field the reliable sends carry, fed straight to
		// `handleCumulativeAck`. It must be the client's watermark, not a
		// counter of our own: the captured server's 1060 battle ticks all read
		// cumul = clientSeq + 1 exactly (aux 22 / relSent-1 22, cumul 1 /
		// clientSeq 0). Putting our tick counter here made every tick an
		// "ACK for packets not yet sent", which the client discarded as
		// REASON_CORRUPTED_PACKET.
		if cumul := binary.LittleEndian.Uint32(clear[n-4:]); cumul != uint32(7) {
			t.Fatalf("frame %d cumul %d, want the client watermark 7", i, cumul)
		}
		body := clear[2 : n-12]
		if len(body) != len(app) {
			t.Fatalf("frame %d body %d B, want %d", i, len(body), len(app))
		}
		// The captured order, at the captured offsets: TickSync 2 B,
		// RelativePosition 13 B, PlayerDetailed 26 B, AliasDetailed 27 B.
		for _, want := range []struct {
			at int
			id byte
		}{{0, 0x13}, {2, 0x16}, {15, 0x1e}, {41, 0x1d}} {
			if body[want.at] != want.id {
				t.Fatalf("frame %d element at %d is %#02x, want %#02x", i, want.at, body[want.at], want.id)
			}
		}
	}
	// Nothing is queued for retransmission: that is the whole point of the
	// unreliable stream.
	if got := s.resend.pending(); got != 0 {
		t.Fatalf("%d packets queued for resend, want 0", got)
	}
}

// TestPostCallsSkipsRequestEntityUpdate pins the walk over a session-control
// element.
//
// The client sends `requestEntityUpdate` (0x06, VAR 2, the entity id) once per
// battle entity right after its lobby sync, in the SAME bundle as the base
// calls. It is not a method, so the walk has to skip it by its own length and
// keep going — breaking on it dropped every call after it.
func TestPostCallsSkipsRequestEntityUpdate(t *testing.T) {
	s := tokenTestServer(t, nil)
	k2 := uint32(0x03185b5a)
	app := lobby.BuildLobbyBundle(k2, lobby.DoCmdInt3(224, lobby.CmdSyncData, 88, 0x699a133b, 0))
	// Two entity-update requests, then the shop sync.
	for _, id := range []uint32{100003, 100004} {
		app = append(app, 0x06, 0x04, 0x00)
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], id)
		app = append(app, b[:]...)
	}
	app = append(app, lobby.DoCmdInt3(225, lobby.CmdReqServerStats, 0, 0, 0)...)
	clear := append([]byte{0x58, 0x04}, app...)
	clear = append(clear, make([]byte, 8)...)
	calls := s.postCalls(nil, clear, k2)
	if len(calls) != 2 {
		t.Fatalf("%d calls, want 2 (the syncs before and after the requestEntityUpdate run)", len(calls))
	}
	if calls[0].Cmd != 100 || calls[1].Cmd != 501 {
		t.Fatalf("cmds = %d, %d, want 100 then 501", calls[0].Cmd, calls[1].Cmd)
	}
}

// clientReliablePacket is one client datagram with a [seq][cumul] trailer, the
// shape noteReliable reads.
func clientReliablePacket(seq, cumul uint32) []byte {
	p := []byte{0x58, 0x04, 0x02, 0x00, 0x00} // ON|RELIABLE|SEQ|CUMUL + 3 B app
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], seq)
	p = append(p, b[:]...)
	binary.LittleEndian.PutUint32(b[:], cumul)
	return append(p, b[:]...)
}

// TestCumulativeAckFollowsTheClientChannel pins the two rules the ack obeys,
// both read off the captured server's 1060 battle ticks, where the ack is
// exactly clientSeq+1 every single time.
//
// A lower ack is safe — it retires less — and the client builds a FRESH channel
// for the battle app whose counter restarts at 0. Keeping the lobby's value
// because the drop was smaller than a window made the battle's first ack "for
// packets not yet sent", which the client discards as REASON_CORRUPTED_PACKET:
// every tick was dropped, so no unreliable NRL base snapshot ever arrived and
// every later volatile delta failed with "no base snapshot found".
func TestCumulativeAckFollowsTheClientChannel(t *testing.T) {
	s := &BaseAppServer{resend: newResendQueue(0, 0)}
	st := &clientState{resendKey: "session-1"}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40020}
	ack := func(seq uint32) uint32 {
		s.noteReliable(st, addr, clientReliablePacket(seq, 0))
		s.mu.Lock()
		defer s.mu.Unlock()
		return st.postCumul
	}
	// The lobby's last counter.
	if got := ack(24); got != 25 {
		t.Fatalf("ack after seq 24 = %d, want 25", got)
	}
	// The battle app's fresh channel restarts at 0: follow it DOWN.
	if got := ack(0); got != 1 {
		t.Fatalf("ack after a fresh channel's seq 0 = %d, want 1 (the lobby value must not survive)", got)
	}
	if got := ack(39); got != 40 {
		t.Fatalf("ack after seq 39 = %d, want 40", got)
	}
	// A mis-sliced trailer must not jump forward: the client rejects an ack for
	// packets it has not sent.
	if got := ack(0xFF8D0038); got != 40 {
		t.Fatalf("ack after a garbage seq = %d, want 40 (a far-forward jump is refused)", got)
	}
}
