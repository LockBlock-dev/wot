package login

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// DumpDatagram is one datagram line from a wotproxy -dump file
// (cmd/wotproxy dumpLine: "time dir addr len hex").
type DumpDatagram struct {
	Dir  string // "C>S" (game to server) | "S>C"
	Addr string // peer address the proxy recorded
	Data []byte
}

// ParseWotproxyDump reads a wotproxy dump: one datagram per line, five
// whitespace-separated fields (time dir addr len hex). The addr column is
// padded (%-21s) in the file, so parse by fields, not fixed offsets.
func ParseWotproxyDump(r io.Reader) ([]DumpDatagram, error) {
	var out []DumpDatagram
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 5 {
			continue
		}
		if f[1] != "C>S" && f[1] != "S>C" {
			continue
		}
		data, err := hex.DecodeString(f[4])
		if err != nil {
			return nil, fmt.Errorf("wotlogin: dump hex: %w", err)
		}
		out = append(out, DumpDatagram{Dir: f[1], Addr: f[2], Data: data})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("wotlogin: read dump: %w", err)
	}
	return out, nil
}

// SessionFromDump extracts the game's live session from a wotproxy dump:
// the LAST S>C reply with status 1 (LOGGED_ON) that decrypts under the
// CE block key to a sane LoginReplyRecord. Last-wins, so the most recent
// good login in the dump is the session probed. Replies that fail to
// decrypt (wrong/stale keys, other sessions) are skipped, not fatal.
// It also returns the stage-1 opening replyID: the login#2 retry rid + 1
// (genuine continuation, e.g. 80357→80358, 91400→91401). Sending any
// other rid (e.g. a fresh random one) voids the experiment — the
// Sep 19 hijack ran rid 0x96ac… against session 91400/91401 and tested
// nothing but rid mismatch. The rids are cleartext in the dump at fixed
// offsets (login msg = [ID=0][len u16][rid u32], challengeResponse msg =
// 1+2+191 = 194 B, so the 728's login-retry rid sits at [203:207]).
func SessionFromDump(dump []DumpDatagram, blockKey string) (Session, uint32, error) {
	for i := len(dump) - 1; i >= 0; i-- {
		dg := dump[i]
		if dg.Dir != "S>C" {
			continue
		}
		_, status, rest, err := parseReply(dg.Data)
		if err != nil || status != 1 {
			continue
		}
		s, ok := sessionFromReplyBody(rest, blockKey)
		if !ok {
			continue
		}
		stageRID, err := loginRIDs(dump, i)
		if err != nil {
			return Session{}, 0, err
		}
		return s, stageRID, nil
	}
	return Session{}, 0, fmt.Errorf("wotlogin: no decryptable LOGGED_ON reply in dump (BLOCK_KEY_HEX not the CE key of this login?)")
}

// loginSourcePort returns the game's login-socket source port from a
// wotproxy dump: the addr column of C>S lines is the client's source
// endpoint (wotproxy logs ReadFromUDP's caddr, cmd/wotproxy dumpLine),
// so the last 534 B login#1 line carries the port the game logged in
// from. Last-wins, matching SessionFromDump. Binding the hijack stage-1
// socket to this port (game killed, not frozen, so it is free) makes
// our probe indistinguishable from the game at L3/L4: same IP, same
// port, same bytes, same rid continuity.
func LoginSourcePort(dump []DumpDatagram) (int, error) {
	for i := len(dump) - 1; i >= 0; i-- {
		dg := dump[i]
		if dg.Dir != "C>S" || len(dg.Data) != 534 {
			continue
		}
		_, port, err := net.SplitHostPort(dg.Addr)
		if err != nil {
			return 0, fmt.Errorf("wotlogin: dump addr %q: %w", dg.Addr, err)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return 0, fmt.Errorf("wotlogin: dump port %q invalid", port)
		}
		return p, nil
	}
	return 0, fmt.Errorf("wotlogin: no login#1 (534 B C>S) in dump")
}

// loginRIDs finds the login#1 (534 B) and login#2-retry rids preceding
// dump[idx] and returns login#2rid + 1, the genuine stage-1 opening rid.
// Layouts (login.go): login msg = [ID=0][len u16][rid u32] so the 534's
// rid sits at [9:13]; the 728's challengeResponse msg is 1+2+191 = 194 B,
// so its login-retry msg starts at [200] ([00][len u16][rid u32]) with
// the rid at [203:207]. The login1/login2 consecutiveness check fails
// loud on retransmit/orphan pairings rather than firing a wrong rid.
func loginRIDs(dump []DumpDatagram, idx int) (uint32, error) {
	j728, ok2 := lastLen(dump, idx, "C>S", 728)
	j534, ok1 := lastLen(dump, j728, "C>S", 534)
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("wotlogin: no login#1/#2 pair before dump line %d (need the rids for stage-1)", idx)
	}
	d1, d2 := dump[j534].Data, dump[j728].Data
	if len(d1) < 13 || len(d2) < 207 || d2[200] != msgLogin {
		return 0, fmt.Errorf("wotlogin: bad login pair layout (534/%dB, 728/%dB id=%02x)", len(d1), len(d2), d2[200])
	}
	r1 := binary.LittleEndian.Uint32(d1[9:13])
	r2 := binary.LittleEndian.Uint32(d2[203:207])
	if r2 != r1+1 {
		return 0, fmt.Errorf("wotlogin: login#1 rid %d, login#2 rid %d (not consecutive — orphan/retry pairing?)", r1, r2)
	}
	return r2 + 1, nil
}

// lastLen finds the last datagram before dump[idx] with direction dir
// and wire length n; the second return is false when absent.
func lastLen(dump []DumpDatagram, idx int, dir string, n int) (int, bool) {
	for j := idx - 1; j >= 0; j-- {
		if dump[j].Dir == dir && len(dump[j].Data) == n {
			return j, true
		}
	}
	return 0, false
}

// sessionFromReplyBody decrypts one LOGGED_ON reply body and validates it
// structurally. A wrong key decrypts to garbage that STILL slices into a
// plausible-looking record (decryptLogin has no magic to check), so the
// record's own shape must gate acceptance — verified on a genuine login
// Sep 19 2026 (our own, via wotproxy + fixed key): clear = 12 B head
// (ip/port/salt/key) + exactly one packed servermsg + all-zero Blowfish
// block pad to the next multiple of 8, manager port in the observed
// 32810-32999 window (every genuine redirect target across all EU2+p5
// captures). Refusal is the safe direction: a false negative errors out,
// a false positive would fire the 22B at a garbage address.
func sessionFromReplyBody(rest []byte, blockKey string) (Session, bool) {
	if blockKey == "" {
		return Session{}, false
	}
	clear, err := decryptLogin(blockKey, rest)
	if err != nil {
		return Session{}, false
	}
	s, err := parseSessionRecord(clear)
	if err != nil {
		return Session{}, false
	}
	if !validSessionRecord(clear, s) {
		return Session{}, false
	}
	return s, true
}

// validSessionRecord gates acceptance on the record's own shape: a wrong
// key decrypts to garbage that STILL slices into a plausible-looking
// record (decryptLogin has no magic to check). Refusal is the safe
// direction — Sep 27 2026 proved it live: a stale-key rewrite passed
// parse, shipped a garbage endpoint (port outside the window), and the
// game died parsing the reply (MF_ASSERT read-past-end, no stage-1).
func validSessionRecord(clear []byte, s Session) bool {
	if len(clear) > 12 {
		_, n, err := consumePackedString(clear[12:])
		if err != nil || !allZero(clear[12+n:]) {
			return false
		}
	}
	if s.ServerAddr == nil || s.ServerAddr.IsUnspecified() || s.SessionKey == 0 {
		return false
	}
	if s.ServerPort < 32810 || s.ServerPort > 32999 {
		return false
	}
	return true
}

// allZero reports whether b is empty or all zero bytes.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
