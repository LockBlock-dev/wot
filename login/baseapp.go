package login

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/LockBlock-dev/wot/lobby"
	"net"
	"os"
	"strings"
	"time"
)

// buildBaseAppLoginMsg builds the FIXED-7 baseAppLogin request body:
// [ID=0][replyID u32][nextOff 00 00][sessionKey u32][numAttempts u8][mtu u16]
// (IDA sub_140E6B740; fork: numAttempts = the 1-based attempt number).
// Fixed message: no length field, 14 B total — the genuine client's 22 B
// handshake is 4 prefix + 2 flags + these 14 + 2 footer (EU2 capture
// flow 10: rid 74099, key fb6289e6, mtu 1300).
func buildBaseAppLoginMsg(replyID, sessionKey uint32, numAttempts uint8, mtu int) []byte {
	var msg []byte
	msg = append(msg, 0x00) // BaseAppExtInterface::baseAppLogin ID
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], replyID)
	msg = append(msg, tmp[:]...)
	msg = append(msg, 0x00, 0x00) // next-request link
	binary.LittleEndian.PutUint32(tmp[:], sessionKey)
	msg = append(msg, tmp[:]...)
	msg = append(msg, numAttempts)
	var m16 [2]byte
	binary.LittleEndian.PutUint16(m16[:], uint16(mtu))
	msg = append(msg, m16[:]...)
	return msg
}

// BaseAppLogin sends BaseAppExtInterface::baseAppLogin (FIXED-7 args:
// sessionKey u32, numAttempts u8, mtu u16 — IDA sub_140E6B740) and waits
// for the session-key ROTATION (sub_140E5FF00 fails zero/unchanged).
// The request goes out plaintext (like the
// game's 22 B handshake); the reply arrives on the Blowfish channel,
// so the whole datagram past the prefix is decrypted before parsing.
// Like the game's RetryingRequest, the handshake is retransmitted
// (same ReplyID) a few times: the first datagram often only warms the
// NAT mapping, and single-shot UDP is fragile across the Internet.
//
// loginConn is the STILL-OPEN login socket, read alongside conn: the
// manager may answer on the session's recorded (login) endpoint rather
// than the 22B source (strict endpoint binding). The game's dispatcher
// reads all its sockets, so it catches replies wherever sent; a client
// reading only the baseapp socket would miss login-endpoint replies
// entirely (indistinguishable from silence!). Which socket answers is
// reported (counts only).
// roundTripBoth sends on conn but reads the first reply from EITHER conn
// or loginConn (see BaseAppLogin doc). Returns which socket answered.
func roundTripBoth(ctx context.Context, conn, loginConn Transport, peer *net.UDPAddr, pkt []byte, timeout time.Duration) ([]byte, bool, error) {
	if _, err := conn.WriteToUDP(pkt, peer); err != nil {
		return nil, false, fmt.Errorf("wotlogin: send: %w", err)
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return nil, false, fmt.Errorf("wotlogin: no reply: timeout")
		}
		for _, c := range []Transport{conn, loginConn} {
			if c == nil {
				continue
			}
			if err := c.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				continue
			}
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, c == loginConn, nil
		}
	}
}

// resendAfter is the stage-handshake retry cadence: the genuine client
// resends its 22B ~2Hz while the manager stays silent (logins.pcapng).
const resendAfter = 500 * time.Millisecond

func BaseAppLogin(ctx context.Context, conn Transport, loginConn Transport, peer *net.UDPAddr, s Session, blockKey string, mtu int, replyID uint32) error {
	// ID(1)+ReplyID(4)+Off(2)+args(7)=14; +4 prefix +2 flags +2 footer = 22.
	// Prefix is minted fresh per attempt (random per packet, §3).
	buildPkt := func(rid uint32, numAttempts uint8) ([]byte, error) {
		prefix, err := randomPrefix()
		if err != nil {
			return nil, err
		}
		m := buildBaseAppLoginMsg(rid, s.SessionKey, numAttempts, mtu)
		p := append([]byte{}, prefix[:]...)
		p = append(p, 0x01, 0x00) // flags = HAS_REQUESTS
		p = append(p, m...)
		return append(p, requestFooter(2)...), nil // first request at flags+0
	}
	// Phase 1: hammer the 22B handshake exactly like the game
	// (logins.pcapng: fresh rid AND att++ every ~0.5 s, unbounded —
	// 192 attempts seen against a silent manager) until the first
	// reply or ctx end. The handshake goes out on the LOGIN socket:
	// the game reuses it for the whole stage-1 exchange (setUpInterface
	// steals the ServerConnection interface; managers bind the pending
	// session to the login endpoint — a fresh socket reads as unknown
	// key). Outcomes are counts/sizes only, never packet bytes.
	var first []byte
	var firstRID uint32
	var outcomes []string
	noReply := 0
	rid, att := replyID, uint8(1)
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wotlogin: baseapp login silent after %d attempts: %w", noReply, ctx.Err())
		default:
		}
		pkt, err := buildPkt(rid, att)
		if err != nil {
			return err
		}
		data, fromLogin, err := roundTripBoth(ctx, loginConn, conn, peer, pkt, resendAfter)
		if err != nil {
			noReply++
			rid++
			att++ // uint8 wraps past 255; game behavior there unobserved
			continue
		}
		// NOTE: roundTripBoth's report names predate the socket swap:
		// sends go out on loginConn, so fromLogin==false ("base")
		// actually means "arrived on the login socket".
		where := "login-sock"
		if fromLogin {
			where = "fresh-sock"
		}
		// Rotation accepted → run the stage script below (the reply
		// is only the first message of stage-1, not the login). A
		// rejected rotation still breaks here: Phase 2 re-validates
		// (zero/unchanged) and reports the stall.
		if err := checkBaseAppReply(data, rid, s.SessionKey, blockKey); err == nil {
			outcomes = append(outcomes, fmt.Sprintf("%dB@%s(rotation-ok)", len(data), where))
		} else {
			outcomes = append(outcomes, fmt.Sprintf("%dB@%s(%v)", len(data), where, err))
		}
		first, firstRID = data, rid
		break
	}
	if first == nil {
		return fmt.Errorf("wotlogin: baseapp login silent after %d attempts", noReply)
	}
	// Phase 2: genuine stage-1 script (paired EU2 capture, Sep 2026).
	// `first` carries the key ROTATION (stageKeyOf proven on genuine
	// bytes): authenticate on the negotiation channel, ack every server
	// message, and follow the [13][3f] redirect to the game port.
	// Presence of the rotated key only; values never reported.
	newKey, hasKey := stageKeyOf(first, firstRID, blockKey)
	if hasKey {
		// Binary-faithful (LoginHandler::onBaseAppLoginSuccess): a zero
		// or unchanged rotation is a FAILURE, not a key (an echoing
		// manager would otherwise have us authenticate with garbage).
		if newKey == 0 || newKey == s.SessionKey {
			hasKey = false
		}
	}
	if hasKey {
		outcomes = append(outcomes, "newkey=yes")
	} else {
		outcomes = append(outcomes, "newkey=no")
		return fmt.Errorf("wotlogin: baseapp stage-1 stalled (%v)", outcomes)
	}
	target, err := stageOneScript(ctx, loginConn, conn, peer, newKey, blockKey, outcomes)
	if err != nil {
		return err
	}
	// Stage-2 runs on the FRESH socket (game behavior) with a fresh rid.
	return stageTwo(ctx, conn, target, newKey, blockKey, mtu)
}

// serverSeqOf returns the channel sequence number of a datagram (fork
// footer order [seq][cumul]); false when undecryptable or too short.
func serverSeqOf(data []byte, blockKey string) (uint32, bool) {
	if len(data) < 6 {
		return 0, false
	}
	c, err := decryptBlowfish(blockKey, data[4:])
	if err != nil {
		return 0, false
	}
	seq, _, ok := channelSeqs(c)
	return seq, ok
}

// stageKeyOf extracts the rotated stage token from a first reply (any
// successful decrypt mode); presence only, never the value.
func stageKeyOf(data []byte, replyID uint32, blockKey string) (uint32, bool) {
	if len(data) < 6 {
		return 0, false
	}
	if c, err := decryptBlowfish(blockKey, data[4:]); err == nil {
		if k, ok := extractStageKey(c, replyID); ok {
			return k, true
		}
	}
	if c, err := decryptLogin(blockKey, data[4:]); err == nil {
		if k, ok := extractStageKey(c, replyID); ok {
			return k, true
		}
	}
	return 0, false
}

// checkBaseAppReply decrypts one BaseApp datagram and verifies the
// session-key ROTATION for replyID: the manager answers the 22B with a
// fresh key ([FF][len=8][rid][newkey]), never an echo of the key we
// sent. Exe LoginHandler::onBaseAppLoginSuccess (sub_140E5FF00) FAILS
// a zero or unchanged rotation, so this accepts only newkey≠0,≠old.
// The first reply may come login-style (ECB+chain, NO magic — like
// the 232B session blob) rather than channel-style (magic+wastage):
// p5-manager 36B/28B replies fail the magic check but may still carry
// the rotation. So try channel-decrypt, then login-decrypt, then
// plaintext, and accept ONLY on an exact rid+rotation (no false
// positives possible). Outcomes name the modes tried (never bytes).
func checkBaseAppReply(data []byte, replyID, sessionKey uint32, blockKey string) error {
	if len(data) < 6 {
		return fmt.Errorf("wotlogin: baseapp reply too short")
	}
	type cand struct {
		mode  string
		clear []byte
	}
	cands := []cand{}
	// Empty key (BLOCK_KEY_EMPTY): server falls back to plaintext —
	// only the plaintext candidate applies, never the decrypts.
	if blockKey == "" {
		cands = append(cands, cand{"plain", data[4:]})
	} else {
		if c, err := decryptBlowfish(blockKey, data[4:]); err == nil {
			cands = append(cands, cand{"channel", c})
		} else {
			cands = append(cands, cand{"channel-" + errStr(err), nil})
		}
		if c, err := decryptLogin(blockKey, data[4:]); err == nil {
			cands = append(cands, cand{"login", c})
		}
		cands = append(cands, cand{"plain", data[4:]})
	}
	var tried []string
	for _, cd := range cands {
		if cd.clear == nil {
			tried = append(tried, cd.mode)
			continue
		}
		desc := fmt.Sprintf("%s%dB", cd.mode, len(cd.clear))
		if key, ok := extractStageKey(cd.clear, replyID); ok {
			// Exe LoginHandler::onBaseAppLoginSuccess
			// (sub_140E5FF00): zero or unchanged rotation is a
			// FAILURE ("Got zero/unchanged session key"), never
			// an echo to accept.
			if key == 0 || key == sessionKey {
				return fmt.Errorf("wotlogin: baseapp rotation rejected (%s)", cd.mode)
			}
			return nil // rotation accepted on BaseApp
		}
		// Channel footers (fork wire order [seq u32][cumul u32] at the very
		// end when flags carry CUMUL|SEQ) are counters, safe to show: they
		// reveal the server's sequence numbering for our ACKs.
		if cd.mode == "channel" {
			if seq, cumul, ok := channelSeqs(cd.clear); ok {
				desc += fmt.Sprintf(" seq=%d cumul=%d", seq, cumul)
			}
		}
		tried = append(tried, desc+structSig(cd.clear, replyID))
	}
	return fmt.Errorf("wotlogin: no baseapp echo (%s)", tried)
}

// BuildBaseAppProbe builds a complete 22B baseAppLogin datagram for the
// ICMP probe (dead port vs silent drop) and tests.
func BuildBaseAppProbe(replyID, sessionKey uint32, mtu int) ([]byte, error) {
	prefix, err := randomPrefix()
	if err != nil {
		return nil, err
	}
	msg := buildBaseAppLoginMsg(replyID, sessionKey, 1, mtu)
	pkt := append([]byte{}, prefix[:]...)
	pkt = append(pkt, 0x01, 0x00)
	pkt = append(pkt, msg...)
	return append(pkt, requestFooter(2)...), nil
}

// buildAuthenticate builds BaseApp.authenticate(newKey): [msgID=02]
// [key u32 LE], FIXED-4, no length field. Method order from the WoT
// binary's interface string table (baseAppLogin=0, pingDatacenter=1,
// authenticate=2 at 0x14368CAA8); the manager verifies the key
// ("authenticate: Unexpected key!") and proceeds to the switch on
// match. 14.4 ServerConnection::primeBundle puts exactly these 5 bytes
// on EVERY post-login bundle as RELIABLE_PASSENGER — the app layer
// carries nothing else (exe baseapp_ext_interface.hpp:
// BW_BEGIN_STRUCT_MSG_EX(BaseApp, authenticate), 4B key only).
func buildAuthenticate(newKey uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], newKey)
	return append([]byte{0x02}, tmp[:]...)
}

// hex2 formats a msgID for variant tags.
func hex2(b byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[b>>4], h[b&15]})
}

// channelSeqs reads the fork-order footers [seq u32][cumul u32] at the very
// end of a channel-decrypted packet (flags must carry CUMUL|SEQ).
func channelSeqs(clear []byte) (seq, cumul uint32, ok bool) {
	if len(clear) < 10 {
		return 0, 0, false
	}
	n := len(clear)
	return binary.LittleEndian.Uint32(clear[n-8 : n-4]),
		binary.LittleEndian.Uint32(clear[n-4 : n]), true
}

// extractStageKey reads the stage-1 reply's 4B session token: the
// [FF][len=8][rid][token] message (the manager ROTATES the key — EU2
// stage-2 used a different key than stage-1). Assumes the rotation is
// the sole message at offset 2 (genuine: first+alone on the channel,
// Proxy::attachToClient bundles it solo) — bails, not scans,
// otherwise. Presence only is ever reported; the value is live auth
// material.
func extractStageKey(clear []byte, replyID uint32) (uint32, bool) {
	for off := 2; off+13 <= len(clear); {
		if clear[off] != msgReply {
			break
		}
		ln := int(binary.LittleEndian.Uint32(clear[off+1 : off+5]))
		if ln != 8 || off+5+ln > len(clear) {
			break
		}
		if binary.LittleEndian.Uint32(clear[off+5:off+9]) != replyID {
			break
		}
		return binary.LittleEndian.Uint32(clear[off+9 : off+13]), true
	}
	return 0, false
}

// errStr classifies a decrypt error to a fixed token (never values —
// the bad-magic value would be decrypted bytes).
func errStr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "bad magic"):
		return "bad-magic"
	case strings.Contains(s, "bad wastage"):
		return "bad-wastage"
	case strings.Contains(s, "not a multiple"):
		return "bad-len"
	default:
		return "err"
	}
}

// structSig summarizes a decrypted-but-echo-less message for diagnosis:
// flags (2B framing), a walk of every message ([id len ridmatch?] with
// strict bounds checks — bails at the first inconsistency), the 4B status
// in a len-8 reply (server-generated cookie, not credentials), offsets
// where our own rid bytes appear, and the last-2B footer (offsets are
// framing). Payload bytes (keys/addresses) are never included, except a
// parsed redirect ADDRESS (server IP:port, public infrastructure —
// never the key/salt that may trail it).
func structSig(clear []byte, replyID uint32) string {
	if len(clear) < 3 {
		return ""
	}
	var rb [4]byte
	binary.LittleEndian.PutUint32(rb[:], replyID)
	var at []int
	for i := 0; i+4 <= len(clear); i++ {
		if clear[i] == rb[0] && clear[i+1] == rb[1] && clear[i+2] == rb[2] && clear[i+3] == rb[3] {
			at = append(at, i)
		}
	}
	sig := fmt.Sprintf(" flags=%02x%02x ridat=%v foot=%02x%02x", clear[0], clear[1], at, clear[len(clear)-2], clear[len(clear)-1])
	off := 2
	for off < len(clear)-1 {
		id := clear[off]
		if id == msgReply {
			if off+9 > len(clear) {
				break
			}
			ln := int(binary.LittleEndian.Uint32(clear[off+1 : off+5]))
			rid := binary.LittleEndian.Uint32(clear[off+5 : off+9])
			part := fmt.Sprintf(" [ff len=%d ridmatch=%v", ln, rid == replyID)
			if ln == 8 && off+13 <= len(clear) {
				part += fmt.Sprintf(" errcode=%08x", binary.LittleEndian.Uint32(clear[off+9:off+13]))
			}
			sig += part + "]"
			off += 1 + 4 + ln
			continue
		}
		// Server→client 0x13 is FIXED-1 (decrypt-proven: 2B "13 ba/bb"
		// bodies plus [13][XX] heads on 44B/52B/36B messages). It is NOT
		// [id][len16]-framed; walking it so prints garbage lens.
		if id == 0x13 {
			if off+2 > len(clear) {
				break
			}
			sig += " [id=13 fixed1]"
			off += 2
			continue
		}
		// Request-shaped: [id][len u16][rid?][payload...].
		if off+3 > len(clear) {
			break
		}
		ln := int(binary.LittleEndian.Uint16(clear[off+1 : off+3]))
		part := fmt.Sprintf(" [id=%02x len=%d", id, ln)
		if ln >= 4 && off+3+4 <= len(clear) {
			part += fmt.Sprintf(" ridmatch=%v", binary.LittleEndian.Uint32(clear[off+3:off+7]) == replyID)
		}
		// Redirect guess: an 8B payload shaped as ip(4)+port-BE(2)+salt(2).
		if ln == 8 && off+3+8 <= len(clear) {
			ip := net.IP(clear[off+3 : off+7])
			port := binary.BigEndian.Uint16(clear[off+7 : off+9])
			part += fmt.Sprintf(" addrguess=%s:%d", ip.String(), port)
		}
		sig += part + "]"
		if ln > len(clear) {
			break
		}
		off += 1 + 2 + ln
	}
	return sig
}

// --- Genuine stage-1/stage-2 script (paired EU2 capture, Sep 2026,
// fully decrypted via flows3+key3). ---
//
// The game reuses the LOGIN socket for the whole stage-1 exchange and a
// fresh socket only for stage-2. Packet anatomy (decrypt-proven over
// every stage-1+2 packet):
// flags(2) msgs... aux?(4, unreliable only) footers[seq][cumul] —
// encrypted past the 4B prefix; footers are fork order [seq][cumul].
// flagsRel = 58 04 = ON|RELIABLE|SEQ|CUMUL (0x0458, OSE enum);
// flagsUnrel = 48 14 = ON|SEQ|CUMUL|+0x1000 (0x1448, WoT bit12).
// The 0b after authenticate is NOT framing: it is enableEntities,
// BaseAppExt ID 11 (table order at 0x14368CAA8; MF_EMPTY = FIXED-0),
// queued with the first authenticate — the entities-ready trigger
// (bare-auth run: without it the server sends rotation+heartbeats but
// never infos). The 4B aux word on unreliable packets is the masked
// reliable-send counter minus one (exe UDPBundle finalise
// sub_142AD4D81: aux=(ch+0x158 - 1)&SEQ_MASK; flag bit12 0x1000 +
// reservation at sub_142AD4B1C): ack0 and stage-2-first carry
// all-bits, everything later carries 0 (only reliable seq 0 is ever
// sent here). Reliable packets carry no aux. Unreliable footer seq starts at 1 per channel; reliable seq
// stays 0; cumul = acked server seq + 1.
// StageBareAuth (CLI -bare-auth) drops the enableEntities message:
// without the entities-ready trigger the server never sends infos
// (proven live on p5). Default mirrors the genuine wire.
var StageBareAuth = false

// StageLobby (CLI -lobby) speaks the genuine stage-2 opening script
// (sync bundles, requestToken, server-stats polls — game vectors,
// primeBundled, reliable, no aux; replaces heartbeat+probes).
// Builders in lobbycalls.go; live effect under test.
var StageLobby = false

// parseRedirect scans a stage-2 cleartext for the 0x1a/type-0x79 redirect:
// [1a][79][len8][innerlen8][IP string][sep u8][port u16 BE][13B]. The
// server repeats it (~10 s cadence, rotating candidate hosts, constant
// port 32956) until the client follows (genuine: switchBaseApp).
// TEMPORARY experiment scaffolding (revert with recorder) — the parse
// itself documents §11 wire truth.
func parseLobbyRedirect(clear []byte) (string, int, bool) {
	for i := 0; i+4 < len(clear); i++ {
		if clear[i] != 0x1a || clear[i+1] != 0x79 {
			continue
		}
		ln := int(clear[i+2])
		if i+3+ln > len(clear) || ln < 18 {
			continue
		}
		pay := clear[i+3 : i+3+ln]
		ilen := int(pay[0])
		if ilen > 20 || 1+ilen+1+2 > len(pay) {
			continue
		}
		ip := string(pay[1 : 1+ilen])
		if net.ParseIP(ip) == nil {
			continue
		}
		rest := pay[1+ilen+1:]
		if len(rest) < 2 {
			continue
		}
		port := int(binary.BigEndian.Uint16(rest[:2]))
		if port < 1024 || port > 65535 {
			continue
		}
		return ip, port, true
	}
	return "", 0, false
}

// msgEnableEntities is the empty entities-ready message queued with the
// first authenticate (BaseAppExt ID 11).
const msgEnableEntities = 0x0b

var (
	flagsRel   = []byte{0x58, 0x04}
	flagsUnrel = []byte{0x48, 0x14}
	// Pinned byte shapes for tests (see auxFor for the live rule).
	midRotAck = []byte{0xff, 0xff, 0xff, 0x0f}
	midZero   = []byte{0x00, 0x00, 0x00, 0x00}
	// ack0Clear is the first client packet after a rotation: bare aux
	// word + footers, no app message (decrypt-proven 14B:
	// 4814 ffffff0f seq=1 cumul=1). Fully constant, no session material.
	ack0Clear = []byte{0x48, 0x14, 0xff, 0xff, 0xff, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
)

// auxFor renders the unreliable-packet aux word, exe-confirmed
// (UDPBundle finalise sub_142AD4D81): aux = (channelReliableSent - 1)
// & SEQ_MASK (0x0FFFFFFF, misc.hpp), written at msgEnd-4 just before
// the [seq][cumul] footers; the 0x1000 flag bit + 4B reservation are
// set at sub_142AD4B1C for packets with no reliable content on a
// channel. Fresh channel (none sent): all-bits; after reliable seq 0
// leaves: 0. Tracks the send counter like the game (channel+0x158).
func auxFor(relSent uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], (relSent-1)&0x0FFFFFFF)
	return append([]byte{}, tmp[:]...)
}

// buildChannelPacket builds [prefix4][flags2][app][aux][seq u32 LE]
// [cumul u32 LE], encrypted past the prefix. It is the single channel
// framer: aux is the unreliable-packet word (see relAux; nil on
// reliable packets, which carry none). Wire sizes mirror the genuine
// 28B packets exactly (auth1: 2+6+8=16→16; pure: 2+0+4+8=14→24;
// auth2/stage2first: 2+5+4+8=19→24).
func buildChannelPacket(blockKey string, flags, app, middle []byte, seq, cumul uint32) ([]byte, error) {
	prefix, err := randomPrefix()
	if err != nil {
		return nil, err
	}
	var tmp [4]byte
	raw := append([]byte{}, flags...)
	raw = append(raw, app...)
	raw = append(raw, middle...)
	binary.LittleEndian.PutUint32(tmp[:], seq)
	raw = append(raw, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], cumul)
	raw = append(raw, tmp[:]...)
	// Empty key: server falls back to plaintext (Proxy::attachToClient
	// with an empty encryptionKey_) — no Blowfish, no magic.
	if blockKey == "" {
		return append(append([]byte{}, prefix[:]...), raw...), nil
	}
	enc, err := encryptBlowfish(blockKey, raw)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, prefix[:]...), enc...), nil
}

// authApp builds the reliable-authenticate packet app: bare
// buildAuthenticate plus the empty enableEntities message (ID 0x0b,
// BaseAppExt #11) queued with the first authenticate — the
// entities-ready trigger (paired decisively: the server sends infos
// only with it). Dropped under StageBareAuth.
func authApp(newKey uint32) []byte {
	if StageBareAuth {
		return buildAuthenticate(newKey)
	}
	return append(buildAuthenticate(newKey), 0x0b)
}

// parseRedirect reads the game-port redirect out of stage-1 channel
// cleartext. Stable core (decrypt-proven in two sessions): [44][ip4 BE]
// [port BE][00 00 01] (10B) — the 9B payload is exe
// ServerConnection::switchBaseApp (sub_140E54400): [u32 ip][u16 port
// BE][u16 0000][u8 01] (trailing u8 stored to ServerConnection+32;
// BE proven by Address::str sub_142AD35E0). It travels after a
// [13][XX] two-byte head whose middle byte VARIES (0x3f in flows3,
// 0xbc in logins.pcapng — same 12B shape otherwise), so only the
// 0x44 core + trailer are matched, never the head byte.
func parseRedirect(clear []byte) (*net.UDPAddr, bool) {
	target, _, ok := parseRedirectAt(clear)
	return target, ok
}

// parseRedirectAt is parseRedirect plus the match offset (for the
// in-place endpoint swap in RewriteRedirect).
func parseRedirectAt(clear []byte) (*net.UDPAddr, int, bool) {
	for i := 0; i+10 <= len(clear); i++ {
		if clear[i] == 0x44 &&
			clear[i+7] == 0x00 && clear[i+8] == 0x00 && clear[i+9] == 0x01 {
			ip := net.IP(append([]byte{}, clear[i+1:i+5]...))
			if ip.IsUnspecified() {
				return nil, 0, false
			}
			port := int(binary.BigEndian.Uint16(clear[i+5 : i+7]))
			if port < 1024 {
				continue
			}
			return &net.UDPAddr{IP: ip, Port: port}, i, true
		}
	}
	return nil, 0, false
}

// smallRID mints a genuine-shaped small ReplyID (< 2^17, never zero).
func smallRID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 1
	}
	r := binary.LittleEndian.Uint32(b[:]) & 0x1FFFF
	if r == 0 {
		return 1
	}
	return r
}

// stageRead returns the next datagram from any of conns before end.
func stageRead(conns []Transport, end time.Time, buf []byte) []byte {
	for time.Now().Before(end) {
		for _, c := range conns {
			if c == nil {
				continue
			}
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := c.ReadFromUDP(buf)
			if err == nil {
				return append([]byte{}, buf[:n]...)
			}
		}
	}
	return nil
}

// stageOneScript runs the negotiation-channel script on the LOGIN
// socket: the rotation is already in hand (newKey), so the
// rotation-ack/ping + reliable authenticate go out immediately, every
// later server message gets a pure ack, and the [13][3f] redirect ends
// the stage. Counters mirror genuine: unreliable seq from 2, reliable
// seq 0, cumul = acked server seq + 1. The reliable authenticate is
// resent while the server stays silent (exe timer wheel keeps reliable
// in flight via sendNextRequest; exact interval unresolved, 1 s here),
// same reliable seq 0 with the latest cumul. Sizes only in errors.
func stageOneScript(ctx context.Context, sendConn, readConn Transport, peer *net.UDPAddr, newKey uint32, blockKey string, outcomes []string) (*net.UDPAddr, error) {
	got := append([]string{}, outcomes...)
	send := func(tag string, pkt []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, err := sendConn.WriteToUDP(pkt, peer)
		if err == nil {
			got = append(got, tag)
		}
		return err
	}
	prefix, err := randomPrefix()
	if err != nil {
		return nil, err
	}
	ack0enc, err := encryptBlowfish(blockKey, ack0Clear)
	if err != nil {
		return nil, err
	}
	if err := send("→ack0", append(append([]byte{}, prefix[:]...), ack0enc...)); err != nil {
		return nil, err
	}
	// GENUINE SHAPE (flows 38/10): the stage-1 authenticate is a second
	// UNRELIABLE 28B ([02][key], NO 0x0b — enableEntities belongs to the
	// stage-2 first authenticate), not a reliable 52B. The reliable
	// auth1 + early 0x0b was our invention; the server tolerates it
	// only sometimes (3/11 runs). Mirror the game exactly.
	// TEMPORARY no-auth1 experiment (revert after): maybe the game sends
	// NO authenticate at stage-1 at all (its 28B#2 = re-ack; the 0x0b
	// was never ours to send early) and our unsolicited auth1 parks us
	// when the server is strict. ack0 + pure acks until 0x44 redirect.
	const tempNoAuth1 = true
	auth1, err := buildChannelPacket(blockKey, flagsUnrel, buildAuthenticate(newKey), auxFor(0), 2, 1)
	if err != nil {
		return nil, err
	}
	// 1:1 MIRROR: the genuine client authenticates ~10ms after the
	// rotation (EU2 532→544, EU5 632→642 — Python/dispatcher lag).
	time.Sleep(10 * time.Millisecond)
	if !tempNoAuth1 {
		if err := send("→auth1", auth1); err != nil {
			return nil, err
		}
	} else {
		got = append(got, "→auth1 SKIPPED (tempNoAuth1)")
	}
	var relSent uint32 // reliable-send counter; aux word source (exe ch+0x158)
	// No reliable sends at stage-1 anymore (genuine shape): aux stays
	// all-bits, unreliable seq continues after auth1's seq 2.
	var unrel uint32 = 3
	var lastSeq uint32 // rotation reply was server seq 0
	buf := make([]byte, 2048)
	end := time.Now().Add(25 * time.Second)
	resends := 0 // reliable-auth1 retransmits after the first send
	for {
		wait := time.Now().Add(1 * time.Second)
		if wait.After(end) {
			wait = end
		}
		data := stageRead([]Transport{sendConn, readConn}, wait, buf)
		if data == nil {
			if !time.Now().Before(end) {
				return nil, fmt.Errorf("wotlogin: stage-1 no redirect (%v)", got)
			}
			if resends >= 9 {
				return nil, fmt.Errorf("wotlogin: stage-1 auth unacked (%v)", got)
			}
			if tempNoAuth1 {
				resends++
				continue
			}
			retry, err := buildChannelPacket(blockKey, flagsUnrel, buildAuthenticate(newKey), auxFor(relSent), unrel, lastSeq+1)
			if err != nil {
				return nil, err
			}
			unrel++
			if err := send(fmt.Sprintf("→auth1r%d(c%d)", resends+1, lastSeq+1), retry); err != nil {
				return nil, err
			}
			resends++
			continue
		}
		if len(data) < 6 {
			continue
		}
		clear, err := decryptBlowfish(blockKey, data[4:])
		if err != nil {
			got = append(got, fmt.Sprintf("%dB undecryptable", len(data)))
			continue
		}
		// TEMPORARY stage-1 forensics (revert after): cleartext of the
		// 40-60B infos only (rotation/key material excluded by size).
		if len(data) >= 40 && len(data) <= 60 {
			if sf, err := os.OpenFile("/tmp/opencode/stage1.hex", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
				fmt.Fprintf(sf, "S>C %d %x\n", len(data), clear)
				sf.Close()
			}
		}
		entry := fmt.Sprintf("%dB", len(data))
		if sq, cu, ok := channelSeqs(clear); ok {
			lastSeq = sq
			entry += fmt.Sprintf(" seq=%d cumul=%d", sq, cu)
		}
		entry += structSig(clear, 0)
		got = append(got, entry)
		if target, ok := parseRedirect(clear); ok {
			// Re-auth synchronizes BOTH footer longs to lastSeq+1
			// (decrypt-proven: flows3 (5,5) after a seq-4 redirect,
			// logins.pcapng (6,6) after a seq-5 redirect) — not the
			// unreliable counter (which would say 5 in the latter).
			auth2, err := buildChannelPacket(blockKey, flagsUnrel, buildAuthenticate(newKey), auxFor(relSent), lastSeq+1, lastSeq+1)
			if err != nil {
				return nil, err
			}
			if err := send(fmt.Sprintf("→auth2(s%d,c%d)", lastSeq+1, lastSeq+1), auth2); err != nil {
				return nil, err
			}
			return target, nil
		}
		ack, err := buildChannelPacket(blockKey, flagsUnrel, nil, auxFor(relSent), unrel, lastSeq+1)
		if err != nil {
			return nil, err
		}
		tag := fmt.Sprintf("→ack(s%d,c%d)", unrel, lastSeq+1)
		unrel++
		if err := send(tag, ack); err != nil {
			return nil, err
		}
	}
}

// stageTwo sends a fresh 22B to the redirect target on the FRESH socket,
// answers the second rotation with the double authenticate, and returns
// on the first lobby-flood datagram (≥1000B: the flood runs 1252B;
// stage-2 info is 76B, heartbeats top out at 68B — the old ≥76B gate
// accepted the pre-flood info as success).
func stageTwo(ctx context.Context, conn Transport, target *net.UDPAddr, key1 uint32, blockKey string, mtu int) error {
	// TEMPORARY burst-loss experiment (revert after): the lobby bundle
	// lands ~150×1252B in ~6 ms; a small rcvbuf drops fragments the
	// server then considers acked (cumul overshoot) and never resends.
	_ = conn.SetReadBuffer(4 << 20)
	rid2 := smallRID()
	build22 := func(rid uint32, att uint8) []byte {
		prefix, err := randomPrefix()
		if err != nil {
			return nil
		}
		p := append([]byte{}, prefix[:]...)
		p = append(p, 0x01, 0x00)
		p = append(p, buildBaseAppLoginMsg(rid, key1, att, mtu)...)
		return append(p, requestFooter(2)...)
	}
	send := func(pkt []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, err := conn.WriteToUDP(pkt, target)
		return err
	}
	var got []string
	var unrel uint32 = 2
	var relSent uint32 // fresh channel: no reliable sent yet
	var lastSeq uint32
	var rotated, progress bool
	var stageKey uint32 // rotation key (primeBundle auth for lobby sends)
	// StageLobby opener state (genuine script, game vectors Sep 27).
	var firstData time.Time
	var openStep int
	var openAt, lastPoll time.Time
	var poolID uint16 = 220 // client request-ID pool (MIN+20)
	var nredir int          // TEMPORARY redirect-follow experiment (revert after)
	// TEMPORARY flood recorder (revert after): dump stage-2 traffic.
	var recFile *os.File
	var recUntil time.Time
	// TEMPORARY heartbeat experiment (revert after): clientToServerHeartbeat
	// (BaseAppExt wire ID 14 = 0x0e, FIXED-0, registered with length 0 at
	// sub_140240640, sent via Bundle::addMessage at sub_140E50600) every 5 s.
	const tempHeartbeat = true
	const msgHeartbeat = 0x0e
	var lastBeat time.Time
	// TEMPORARY doCmd probe (revert after): genuine lobby sends 60B
	// doCmdInt3-shaped calls (A1 0x95 = 136 + rank13, codebook-closed).
	// Probe doCmdInt3(202, 501, 0, 0, 0) (server-stats query,
	// read-only), one per ~2 s after flood+3 s — watch for any 36B+
	// response.
	const tempProbe = true
	var probedAt time.Time
	var probeIdx int
	sendLogged := func(pkt []byte) error {
		if recFile != nil {
			fmt.Fprintf(recFile, "%.3f C>S %d %x\n", time.Since(recUntil).Seconds(), len(pkt), pkt)
		}
		return send(pkt)
	}
	buf := make([]byte, 2048)
	end := time.Now().Add(30 * time.Second)
	if tempHeartbeat {
		end = time.Now().Add(60 * time.Second)
	}
	if StageLobby {
		end = time.Now().Add(90 * time.Second)
	}
	// sendLobby frames one primeBundled reliable app bundle (game shape:
	// flags 0458, [02][newkey], concatenated base calls, no aux) and
	// reports its size only.
	sendLobby := func(tag string, calls ...[]byte) error {
		pkt, err := buildChannelPacket(blockKey, flagsRel, lobby.BuildLobbyBundle(stageKey, calls...), nil, unrel, lastSeq+1)
		if err != nil {
			return err
		}
		unrel++
		if err := sendLogged(pkt); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[wotlogin] lobby %s %dB\n", tag, len(pkt))
		return nil
	}
	att := uint8(1)
	if err := send(build22(rid2, att)); err != nil {
		return err
	}
	for {
		if time.Now().After(end) {
			if recFile != nil {
				recFile.Close()
				return nil // recorded full window
			}
			return fmt.Errorf("wotlogin: stage-2 stalled (%v)", got)
		}
		data := stageRead([]Transport{conn}, time.Now().Add(500*time.Millisecond), buf)
		if data == nil {
			// Resend the handshake (fresh rid AND att++, like the game)
			// only while the server never spoke.
			if !progress {
				att++
				rid2++
				if err := send(build22(rid2, att)); err != nil {
					return err
				}
				continue
			}
			continue
		}
		if len(data) < 6 {
			continue
		}
		progress = true
		got = append(got, fmt.Sprintf("%dB", len(data)))
		if len(data) >= 1000 {
			// Size alone is not proof (unconnected socket): the
			// flood must decrypt under our channel key.
			if _, err := decryptBlowfish(blockKey, data[4:]); err != nil {
				continue
			}
			if recFile == nil {
				recFile, _ = os.Create("/tmp/opencode/flood.hex")
				recUntil = time.Now()
				// TEMPORARY (revert with recorder): per-run channel key.
				os.WriteFile("/tmp/opencode/stage2.key", []byte(blockKey), 0600)
			}
		}
		if recFile != nil {
			fmt.Fprintf(recFile, "%.3f S>C %d %x\n", time.Since(recUntil).Seconds(), len(data), data)
			if time.Now().After(end) {
				recFile.Close()
				return nil // recorded full window
			}
		}
		if len(data) >= 1000 {
			continue
		}
		clear, err := decryptBlowfish(blockKey, data[4:])
		if err != nil {
			continue
		}
		if sq, _, ok := channelSeqs(clear); ok {
			lastSeq = sq
		}
		if firstData.IsZero() {
			firstData = time.Now()
		}
		// TEMPORARY redirect-policy experiment (revert after): follow the
		// FIRST redirect and STAY (log later ones without following) —
		// tests whether hop #1 serves entities on its own.
		if host, port, ok := parseLobbyRedirect(clear); ok {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
			if err == nil && (target == nil || addr.String() != target.String()) {
				if nredir < 1 {
					nredir++
					target = addr
					rid2 = smallRID()
					att = 1
					rotated = false
					relSent = 0
					unrel = 2
					lastSeq = 0
					progress = false
					stageKey = 0
					firstData = time.Time{}
					openStep = 0
					poolID = 220
					lastPoll = time.Time{}
					lastBeat = time.Now()
					fmt.Fprintf(os.Stderr, "[wotlogin] redirect #%d → %s\n", nredir, addr.String())
					if err := send(build22(rid2, att)); err != nil {
						return err
					}
					continue
				}
				fmt.Fprintf(os.Stderr, "[wotlogin] redirect ignored (staying) → %s\n", addr.String())
			}
		}
		if !rotated {
			if key2, ok := stageKeyOf(data, rid2, blockKey); ok {
				rotated = true
				stageKey = key2
				first, err := buildChannelPacket(blockKey, flagsUnrel, buildAuthenticate(key2), auxFor(relSent), 1, lastSeq+1)
				if err != nil {
					return err
				}
				if err := send(first); err != nil {
					return err
				}
				auth, err := buildChannelPacket(blockKey, flagsRel, authApp(key2), nil, 0, lastSeq+1)
				if err != nil {
					return err
				}
				if err := send(auth); err != nil {
					return err
				}
				relSent = 1 // s2auth went out (reliable seq 0)
				continue
			}
		}
		ack, err := buildChannelPacket(blockKey, flagsUnrel, nil, auxFor(relSent), unrel, lastSeq+1)
		if err != nil {
			return err
		}
		unrel++
		if err := sendLogged(ack); err != nil {
			return err
		}
		// TEMPORARY heartbeat experiment (revert after).
		if !StageLobby && tempHeartbeat && rotated && time.Since(lastBeat) > 5*time.Second {
			hb, err := buildChannelPacket(blockKey, flagsUnrel, []byte{msgHeartbeat}, auxFor(relSent), unrel, lastSeq+1)
			if err != nil {
				return err
			}
			unrel++
			if err := sendLogged(hb); err != nil {
				return err
			}
			lastBeat = time.Now()
		}
		// TEMPORARY doCmd probe (revert after).
		if !StageLobby && tempProbe && rotated && recFile != nil && probeIdx < 4 && (probedAt.IsZero() && time.Since(recUntil) > 3*time.Second || !probedAt.IsZero() && time.Since(probedAt) > 2*time.Second) {
			app := lobby.DoCmdInt3(202, 501, 0, 0, 0) // A1 0x95 inside
			pr, err := buildChannelPacket(blockKey, flagsUnrel, app, auxFor(relSent), unrel, lastSeq+1)
			if err != nil {
				return err
			}
			unrel++
			if err := sendLogged(pr); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "[wotlogin] probe #%d A1=0x95 doCmdInt3(202,501,0,0,0)\n", probeIdx)
			probedAt = time.Now()
			probeIdx++
		}
		// StageLobby opener (genuine script, game vectors Sep 27):
		// sync bundle ~1 s after first infos, requestToken +150 ms,
		// second sync +6 s, server-stats polls q5 s from +15 s.
		// Zero-state args (fresh client); sizes only on stderr.
		if StageLobby && rotated && stageKey != 0 && !firstData.IsZero() {
			switch {
			case openStep == 0 && time.Since(firstData) > time.Second:
				if err := sendLobby("sync1",
					lobby.DoCmdInt3(poolID, 100, 0, 0, 0),
					lobby.DoCmdInt3(poolID+1, 300, 0, 0, 0),
					lobby.DoCmdInt3(poolID+2, 600, 0, 0, 0)); err != nil {
					return err
				}
				poolID += 3
				openStep = 1
				openAt = time.Now()
			case openStep == 1 && time.Since(openAt) > 150*time.Millisecond:
				if err := sendLobby("token", lobby.BuildRequestToken(1, 1)); err != nil {
					return err
				}
				openStep = 2
			case openStep == 2 && time.Since(openAt) > 6*time.Second:
				if err := sendLobby("sync2", lobby.DoCmdInt3(poolID, 100, 0, 0, 0)); err != nil {
					return err
				}
				poolID++
				openStep = 3
			}
			if openStep >= 1 && time.Since(openAt) > 15*time.Second && time.Since(lastPoll) > 5*time.Second {
				if err := sendLobby("poll", lobby.DoCmdInt3(202, 501, 0, 0, 0)); err != nil {
					return err
				}
				lastPoll = time.Now()
			}
		}
	}
}
