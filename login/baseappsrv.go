package login

// BaseApp SERVER half (mirror of the client-side stage machine pinned
// by paired_replay_test.go and the flows3 / proxy-20261001 genuine
// decrypts). The client's script is the proven wire model; this file
// answers it shape-for-shape so a client LOGGED_ON by cmd/wotserver
// reaches stage-2 (rotation-2 → double-auth) and a decrypt-verified
// 1252B flood against US, and the game pointed here walks the same
// turns. Content honesty is layered:
//
//   - transport frames are genuine (rotation 36B, tick 28B, redirect
//     36B with the 0x44 core, flood frames verbatim from the capture);
//   - per-session smalls (v2.1, flows3-s2 decrypts): the stage-2 36B
//     info, the 76B descriptor (packed account name substituted per
//     session) and the 1a/76 session dict (four live fields patched:
//     serverUTC/aogasStartedAt/sessionStartedAt/databaseID) are
//     SERVED with minted channel footers; the stage-1 52B/44B infos,
//     entity bursts, the 1a/73 clan block the dict rode with, and the
//     1a/79 lobby offers stay v1-cut (acked-only in captures);
//   - the post-flood chain (v2/v2.1) is SERVED: the 332B terminator,
//     the [13][7b] rev answer to the client's sync, the 1a/5b stats
//     answer to every 501 poll, the 1a/5e "no such vehicle" error to
//     the 121 season select, and a 100 ms minted tick stream. Answer
//     bodies replay verbatim from the carrier (same staleness as the
//     bulk); every frame — ticks and answers alike — takes one slot
//     on the shared tag/seq/cumul walk, and cumul tracks the client's
//     reliable-seq watermark;
//   - the bulk carrier's chunk contents are a capture REFERENCE (the
//     flows3 stage-2 run — stale shop/offer defs): faithful frames,
//     wrong era. Per-session bulk heads stay stale until per-session
//     bulk minting lands.
//
// Channel crypto is the client's LogOnParams key for BOTH stages: the
// key rotation rides as app content (the [FF][len=8] reply and
// BaseApp.authenticate), the Blowfish channel key never changes
// (decrypt-proven on flows3 — post-rotation datagrams still decrypt
// with the login key).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"
)

// Manager port window every genuine [44] redirect target lands in
// (hijack.go validSessionRecord). Our stage-2 listener binds INSIDE
// the window so our client's parseRedirectAt guard accepts the hop —
// the game itself follows out-of-window targets (Oct-14 blackhole
// evidence); this window only constrains our own mint.
const (
	RedirectPortLo = 32810
	RedirectPortHi = 32999
)

// PendingTTL: how long an admitted-but-unhandshaken session stays
// pullable by a stage-1 22B. The live managers expire the pending
// record ~30 s after LOGGED_ON (hijack_portsteal_20260920: the steal
// at +83 s was past expiry); we stay generous.
const PendingTTL = 60 * time.Second

// PostTickPeriod is the post-flood tick cadence: the genuine tail runs
// 100 ms ([13][7a] at 1562.609 → [13][7c] at .810 → [13][7d] at .911,
// flows3-s2 idx 1007/1013/1015 — 201 ms then 101 ms, i.e. one tick per
// ~100 ms slot with the sync-answer ticks taking the next slot).
const PostTickPeriod = 100 * time.Millisecond

// LoggedOnSession is the LoginApp→BaseApp handoff for one finished
// login (the LOGGED_ON mint). The stage-1 22B handshake carries
// SessionKey; BlockKey is the Blowfish channel key for both stages.
type LoggedOnSession struct {
	SessionKey uint32
	BlockKey   string
	Name       string
}

// BaseAppConfig configures the server. Redirect is required: the
// stage-2 endpoint our [44] mints into the client (bind it inside the
// RedirectPort window).
type BaseAppConfig struct {
	Redirect *net.UDPAddr

	// Flood carrier: a wotproxy-style dump of a genuine stage-2
	// window plus its hex block key (ReadKeyFile format). 1252B S>C
	// frames are channel-decrypted once at load and re-encrypted per
	// session at serve time. Empty means no carrier: stage-2 answers
	// the dance but errors on the flood (loud, not a silent half-lobby).
	FloodPath    string
	FloodKeyPath string

	// BulkFragSize is the flood datagram size the carrier selects
	// (1252 in every genuine capture).
	BulkFragSize int

	Verbose bool
}

// BaseAppServer answers the client's stage-1/stage-2 script for any
// number of clients. Sessions enter via Admit (the LoginApp
// OnLoggedOn hook).
type BaseAppServer struct {
	cfg BaseAppConfig

	bulk   [][]byte // flood frame CLEAR bodies (flags+app+trailers)
	bulkOK bool

	// Post-flood chain frames (v2, flows3-s2 tail): the 332B
	// terminator ends the bulk burst, the [13][7b] 60B carries the
	// rev-sync answer to the client's post-flood sync bundle, and the
	// [13][a4] 36B is the stats answer template to every 501 poll.
	// All three replay verbatim (stale-reference content); only the
	// ticks and the poll-answer footers are minted per session.
	term     []byte // 332B terminator clear body
	revReply []byte // [13][7b] rev-sync answer clear body
	pollAns  []byte // [13][a4] 1a/5b stats answer clear body
	tickSeed []byte // 12B plain-tick clear body: tag/seq/cumul seeds
	postOK   bool

	// postTag/postSeq/postCumul seed the per-session mint sequencer
	// (read off the carrier's first post-flood plain tick).
	postTag   byte
	postSeq   uint32
	postCumul uint32

	// Pre-flood per-session smalls (v2.1, flows3-s2 decrypts): the 36B
	// info app (replayed verbatim), the 76B descriptor template (78 04
	// companion frame; the packed account name is substituted per
	// session), and the 1a/76 session-dict template (the 160B small
	// extracted from the genuine triple-small frame — the 1a/73 clan
	// block and the 1a/79 lobby offer it rode with stay v1-cut; the
	// offer's stale redirect target must not re-enter our wire).
	infoApp []byte // [02 0a 01 00 3f 8b 23 00 13 3f] app (10B)
	descTpl []byte // 61B companion clear body (78 04 ...)
	dictTpl []byte // `1a 76 9c 00` + 156B body (9b + 155B proto-2 pickle)
	preOK   bool

	mu sync.Mutex
	// pending is sessions awaiting their stage-1 handshake, keyed by
	// the login-minted sessionKey (what the 22B carries).
	pending map[uint32]*clientState
	// byStageKey is past-rotation sessions, keyed by the key we minted
	// (what the stage-2 22B carries) — also the 22B-resend recovery
	// path after a lost rotation.
	byStageKey map[uint32]*clientState
	// byAddr resolves stage-2 non-handshake datagrams (auth/acks carry
	// no session field); stage-2 sources are fresh sockets, so the
	// address is the only stable join.
	byAddr map[string]*clientState
}

type clientState struct {
	blockKey   string       // LogOnParams key (set once at admit)
	name       string       // login username (future per-session smalls)
	sessionKey uint32       // login-minted
	stageKey   uint32       // our stage-1 rotation (0 = none yet)
	stage2Key  uint32       // our stage-2 rotation (0 = none yet)
	addr       *net.UDPAddr // stage-1 source (redirect receiver)
	stage2Addr *net.UDPAddr // stage-2 source
	tailAt     time.Time    // stage-1 tick+redirect deadline (zero = none)
	admittedAt time.Time    // for PendingTTL expiry
	flooded    bool         // bulk burst already served

	// --- post-flood (v2) sequencer state -------------------------------
	// After the terminator the server runs a pure mint loop: one [13]
	// tick per period, tag +1, seq +1, cumul = our view of the client's
	// received reliable seq. All four values are read off the genuine
	// tail (terminator tail = [seq 502][cumul 502][3]; first tick =
	// [13][7a][seq 503][cumul 3]) and walked forward from there.
	postAt     time.Time // next post-flood tick deadline
	postTag    byte      // next [13] tag to mint (0x7a at the tail start)
	postSeq    uint32    // next server seq
	postCumul  uint32    // our cumul watermark
	synced     bool      // client 84B post-flood sync already answered
	tickPeriod time.Duration
}

// NewBaseAppServer validates the config and preloads the bulk carrier.
func NewBaseAppServer(cfg BaseAppConfig) (*BaseAppServer, error) {
	if cfg.Redirect == nil {
		return nil, fmt.Errorf("wotserver: baseapp needs the stage-2 endpoint (the [44] redirect target)")
	}
	if p := cfg.Redirect.Port; p < RedirectPortLo || p > RedirectPortHi {
		return nil, fmt.Errorf("wotserver: baseapp stage-2 %s outside the manager window %d-%d (our client's parseRedirectAt guard skips it)",
			cfg.Redirect, RedirectPortLo, RedirectPortHi)
	}
	if cfg.BulkFragSize == 0 {
		cfg.BulkFragSize = 1252
	}
	s := &BaseAppServer{
		cfg:        cfg,
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	if cfg.FloodPath != "" {
		n, err := s.loadBulk()
		if err != nil {
			return nil, fmt.Errorf("wotserver: flood carrier: %w", err)
		}
		s.logf("bulk carrier loaded %d frames from %s", n, cfg.FloodPath)
		if err := s.loadPost(); err != nil {
			return nil, fmt.Errorf("wotserver: post-flood carrier: %w", err)
		}
		if err := s.loadPre(); err != nil {
			return nil, fmt.Errorf("wotserver: pre-flood carrier: %w", err)
		}
	}
	return s, nil
}

func (s *BaseAppServer) logf(format string, args ...any) {
	if s.cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[wotserver] "+format+"\n", args...)
	}
}

// Admit registers a finished login for stage-1; wired to the LoginApp
// OnLoggedOn hook. Idempotent per session key, live stage state never
// reset by a stale admission.
func (s *BaseAppServer) Admit(sess LoggedOnSession) {
	if sess.SessionKey == 0 {
		return // zero keys never travel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.pending[sess.SessionKey]; ok && old.stageKey != 0 {
		return
	}
	s.pending[sess.SessionKey] = &clientState{
		blockKey:   sess.BlockKey,
		name:       sess.Name,
		sessionKey: sess.SessionKey,
		admittedAt: time.Now(),
	}
	s.logf("admitted session key %08x (name %dB, blockKey %dB)",
		sess.SessionKey, len(sess.Name), len(sess.BlockKey))
}

// loadBulk keeps every flood frame's DECRYPTED body for verbatim
// re-keyed replay (fresh prefix + session-key encryption at serve
// time). Bytes stay in memory (never logged): the carrier frames are
// the capture's stale-content reference.
func (s *BaseAppServer) loadBulk() (int, error) {
	key, err := ReadAnyKeyFile(s.cfg.FloodKeyPath)
	if err != nil {
		return 0, fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(s.cfg.FloodPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		return 0, err
	}
	for _, d := range dump {
		if d.Dir != "S>C" || len(d.Data) != s.cfg.BulkFragSize {
			continue
		}
		clear, err := decryptBlowfish(key, d.Data[4:])
		if err != nil {
			continue // mis-captured frame: drop silently
		}
		s.bulk = append(s.bulk, clear)
	}
	if len(s.bulk) == 0 {
		return 0, fmt.Errorf("no %dB S>C frames in %s", s.cfg.BulkFragSize, s.cfg.FloodPath)
	}
	s.bulkOK = true
	return len(s.bulk), nil
}

// loadPost keeps the three post-flood chain frames' DECRYPTED bodies for
// verbatim re-keyed replay, like loadBulk. Identified by their genuine
// heads (flows3-s2 tail, all decrypt-proven offline):
//
//	terminator — 332B wire, flags 78 04 companion, clear 317B. It is
//	  the frame that ENDS the bulk burst; the [80 02 4b] head is the
//	  packed-entity continuation prefix, contents stale reference.
//	rev reply — 60B wire, clear 51B, head [13][7b] then a 1a/5f
//	  {prevRev, rev} pickle: the server's answer to the client's
//	  post-flood 84B sync bundle (~40 ms after it).
//	poll answer — 36B wire, clear 22B, head [13][a4] then 1a/5b: the
//	  answer to a 501 server-stats poll (~100 ms after the poll).
//
// The tick tags/seq/cumul inside these bodies are capture counters; we
// replay the bodies verbatim (content honesty = same layering as the
// bulk) and mint only the pure-tick stream around them.
func (s *BaseAppServer) loadPost() error {
	key, err := ReadAnyKeyFile(s.cfg.FloodKeyPath)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(s.cfg.FloodPath)
	if err != nil {
		return err
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		return err
	}
	// The seed tick is the first plain 28B tick AFTER the terminator
	// (the tail resumes ticking the moment the burst ends): walk the
	// dump in arrival order and only accept ticks past the last 332B.
	sawTerm := false
	for _, d := range dump {
		if d.Dir != "S>C" {
			continue
		}
		switch len(d.Data) {
		case 332:
			if clear, err := decryptBlowfish(key, d.Data[4:]); err == nil && s.term == nil {
				s.term = clear
			}
			sawTerm = true
			s.tickSeed = nil
			continue
		}
		if !sawTerm {
			continue
		}
		switch len(d.Data) {
		case 28:
			if s.tickSeed != nil {
				continue
			}
			// Post-flood plain tick: clear = [flags][13][tag]
			// [seq u32][cumul u32] — 12B. Seeds the mint sequencer
			// (genuine first one: tag 7a, seq 503, cumul 3).
			if clear, err := decryptBlowfish(key, d.Data[4:]); err == nil && len(clear) == 12 && clear[2] == 0x13 {
				s.tickSeed = clear
			}
		case 60:
			if s.revReply != nil {
				continue
			}
			// 51B clear: [13][7b] + the 1a/5f pickle + footers; the
			// length is pinned so servePostFlood can slice the body.
			if clear, err := decryptBlowfish(key, d.Data[4:]); err == nil && len(clear) == 51 && isTickHead(clear, 0x7b) {
				s.revReply = clear
			}
		case 36:
			if s.pollAns != nil {
				continue
			}
			// 22B clear: [13][tag] + 1a/5b + two u32 counters (no len
			// byte) + footers (pinned for the same [4:len-8] slice).
			if clear, err := decryptBlowfish(key, d.Data[4:]); err == nil && len(clear) == 22 && hasSmall(clear, 0x1a, 0x5b) {
				s.pollAns = clear
			}
		}
	}
	if s.tickSeed != nil {
		s.postTag = s.tickSeed[3]
		s.postSeq = binary.LittleEndian.Uint32(s.tickSeed[4:8])
		s.postCumul = binary.LittleEndian.Uint32(s.tickSeed[8:12])
	}
	if s.term == nil || s.revReply == nil || s.pollAns == nil || s.tickSeed == nil {
		return fmt.Errorf("post-flood chain frames missing (term=%v rev=%v poll=%v tick=%v) in %s",
			s.term != nil, s.revReply != nil, s.pollAns != nil, s.tickSeed != nil, s.cfg.FloodPath)
	}
	s.postOK = true
	return nil
}

// loadPre keeps the pre-flood per-session smalls' TEMPLATES from the
// same carrier dump loadPost walks (all heads decrypt-proven flows3-s2):
//
//	info — 36B wire, clear 20B: flags 58 04 + app `02 0a 01 00 3f 8b 23
//	  00 13 3f` + footers seq 1 / cumul 0 (the client's auth1 seq 0 is
//	  not processed yet). The app replays verbatim; the footers are
//	  minted with the same values (server frames before auth1).
//	descriptor — 76B wire, companion flags 78 04 (no channel footers),
//	  clear 61B: [13][40] + [05 ff ff 17 34 03 00 01 00 00] + packed
//	  version (len byte at [14], chars 15..24 = "eu_2.4.0_2") + packed
//	  account name (len at [25], chars 26..36) + a 24B tail of counters
//	  (stale reference — structure pinned, values not minted).
//	session dict — 396B wire, clear 383B, frame [13][40] + THREE smalls
//	  (1a/76 session dict + 1a/73 clan block + 1a/79 offer). We extract
//	  ONLY the 1a/76 small (`1a 76 9c 00` + 156B body = leading status
//	  byte 0x9b + a 155B proto-2 pickle) and drop the riders (v1-cut:
//	  the clan block is personal data, the offer's 185.12.240.53:32956
//	  target must not re-enter our wire).
//
// All three templates are required when a carrier is configured
// (consistent with loadPost's strictness); each is re-checked at serve
// time by the patchers, which fail loud on shape drift.
func (s *BaseAppServer) loadPre() error {
	key, err := ReadAnyKeyFile(s.cfg.FloodKeyPath)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(s.cfg.FloodPath)
	if err != nil {
		return err
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		return err
	}
	for _, d := range dump {
		if d.Dir != "S>C" {
			continue
		}
		switch len(d.Data) {
		case 36:
			if s.infoApp != nil {
				continue
			}
			clear, err := decryptBlowfish(key, d.Data[4:])
			if err != nil || len(clear) != 20 || clear[0] != 0x58 || clear[1] != 0x04 {
				continue
			}
			if clear[2] == 0x02 && clear[3] == 0x0a && clear[4] == 0x01 && clear[5] == 0x00 {
				s.infoApp = append([]byte(nil), clear[2:12]...)
			}
		case 76:
			if s.descTpl != nil {
				continue
			}
			clear, err := decryptBlowfish(key, d.Data[4:])
			if err != nil || len(clear) != 61 {
				continue
			}
			if clear[0] == 0x78 && clear[1] == 0x04 && clear[2] == 0x13 && clear[3] == 0x40 && clear[14] == 10 {
				s.descTpl = append([]byte(nil), clear...)
			}
		case 396:
			if s.dictTpl != nil {
				continue
			}
			clear, err := decryptBlowfish(key, d.Data[4:])
			if err != nil || len(clear) != 383 {
				continue
			}
			// `1a 76` + u16 LE len 0x9c = 156 (status byte + 155B pickle).
			if i := bytes.Index(clear, []byte{0x1a, 0x76, 0x9c, 0x00}); i >= 0 && i+160 <= len(clear) {
				tpl := append([]byte(nil), clear[i:i+160]...)
				if tpl[4] == 0x9b && tpl[5] == 0x80 && tpl[6] == 0x02 {
					// Dry-run the patcher on a COPY: the stored
					// template keeps the capture's stale reference
					// values (the mint re-patches per send anyway;
					// a mutated template would hide shape drift at
					// load — caught by TestBaseAppPostFloodCarrier).
					if _, err := patchDict(append([]byte(nil), tpl...), "probe", time.Unix(1789681556, 0), time.Unix(1789681556, 0)); err == nil {
						s.dictTpl = tpl
					}
				}
			}
		}
	}
	if s.infoApp == nil || s.descTpl == nil || s.dictTpl == nil {
		return fmt.Errorf("pre-flood smalls missing (info=%v descr=%v dict=%v) in %s",
			s.infoApp != nil, s.descTpl != nil, s.dictTpl != nil, s.cfg.FloodPath)
	}
	s.preOK = true
	return nil
}

// patchDict rewrites the four live fields of the captured session-dict
// small (in place; the caller owns its copy). The pickle is proto 2,
// values are keyed SHORT_BINSTRING (55 len chars) + BINPUT (71 idx) +
// opcode: serverUTC/aogasStartedAt are BINFLOAT (47 + 8B BIG-endian
// IEEE754; capture 41daab17e52f9aa6 = 1789681556.7438), databaseID/
// sessionStartedAt are BININT (4a + 4B LITTLE-endian signed; capture
// 123456789 / 1789681556). started = the session's admission time,
// now = mint time.
func patchDict(tpl []byte, name string, started, now time.Time) ([]byte, error) {
	utc := float64(now.UnixNano()) / 1e9
	f, err := patchPickleValue(tpl, "serverUTC", 0x47, 8)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(f, math.Float64bits(utc))
	f, err = patchPickleValue(tpl, "aogasStartedAt", 0x47, 8)
	if err != nil {
		return nil, err
	}
	// Capture delta: serverUTC - aogasStartedAt = 1.951 ms (the aogas
	// playtime watcher starts a hair after the session UTC stamp).
	binary.BigEndian.PutUint64(f, math.Float64bits(utc-0.001951))
	f, err = patchPickleValue(tpl, "sessionStartedAt", 0x4a, 4)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(f, uint32(int32(started.Unix())))
	f, err = patchPickleValue(tpl, "databaseID", 0x4a, 4)
	if err != nil {
		return nil, err
	}
	// Same FNV-1a pseudo-account the LoginApp token2 head carries (9
	// digits, fits the int32 slot).
	binary.LittleEndian.PutUint32(f, uint32(int32(pseudoAccountID(name))))
	return tpl, nil
}

// patchPickleValue locates a proto-2 dict entry by key name and
// returns its value payload: the key bytes are followed by BINPUT
// (0x71 + 1B index) and the expected opcode; the remaining n bytes
// are the value. Fails loud on any shape drift (carrier mismatch).
func patchPickleValue(body []byte, key string, op byte, n int) ([]byte, error) {
	i := bytes.Index(body, []byte(key))
	if i < 0 {
		return nil, fmt.Errorf("wotserver: session dict: key %q not found", key)
	}
	j := i + len(key)
	if j+3+n > len(body) {
		return nil, fmt.Errorf("wotserver: session dict: key %q truncated", key)
	}
	if body[j] != 0x71 || body[j+2] != op {
		return nil, fmt.Errorf("wotserver: session dict: key %q: expected BINPUT+%#02x, got % x", key, op, body[j:j+3])
	}
	return body[j+3 : j+3+n], nil
}

// dictApp mints the session-dict frame APP: [13][40] + the 1a/76 small
// with the four live fields patched. The booleans keep the capture's
// values (isAogasEnabled=T, collectUiStats=T, logUXEvents=F — the
// playtime-telemetry flags; our server runs no telemetry scheduler, so
// replaying the capture's gate state is honest structure either way).
func dictApp(tpl []byte, name string, started, now time.Time) ([]byte, error) {
	body, err := patchDict(append([]byte(nil), tpl...), name, started, now)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x13, 0x40}, body...), nil
}

// descriptorFrame substitutes the packed account name in the 76B
// descriptor template; every other byte replays. Layout (clear 61B):
// [78 04][13 40][05 ff ff 17 34 03 00 01 00 00][vlen=0a][version
// "eu_2.4.0_2"][nlen][name][tail]. The name length byte is 1B, so a
// long login name truncates at 255 (wire-faithful would need the
// producer-side cap; ours is the same 1B field).
func descriptorFrame(tpl []byte, name string) ([]byte, error) {
	if len(tpl) < 38 || tpl[0] != 0x78 || tpl[1] != 0x04 || tpl[2] != 0x13 || tpl[3] != 0x40 {
		return nil, fmt.Errorf("wotserver: descriptor template malformed")
	}
	vlen := int(tpl[14])
	nl := 15 + vlen // index of the name length byte
	if nl+1 > len(tpl) {
		return nil, fmt.Errorf("wotserver: descriptor template: version overruns")
	}
	captured := int(tpl[nl])
	if nl+1+captured > len(tpl) {
		return nil, fmt.Errorf("wotserver: descriptor template: name overruns")
	}
	if len(name) > 255 {
		name = name[:255]
	}
	out := append([]byte{}, tpl[:nl]...)
	out = append(out, byte(len(name)))
	out = append(out, name...)
	return append(out, tpl[nl+1+captured:]...), nil
}

// isTickHead reports a decrypted S>C frame whose [13] tick tag equals
// tag: clear = [flags 58 04][13][tag]... (the tick family; the middle
// byte is the tag/step counter, see tickApp).
func isTickHead(clear []byte, tag byte) bool {
	return len(clear) >= 4 && clear[0] == 0x58 && clear[1] == 0x04 &&
		clear[2] == 0x13 && clear[3] == tag
}

// hasSmall reports a decrypted frame carrying a [1a][type] smalls
// record anywhere past the flags (the lobby smalls taxonomy: 1a/5b =
// server-stats counters, 1a/5f = revisions).
func hasSmall(clear []byte, fam, typ byte) bool {
	for i := 2; i+3 < len(clear); i++ {
		if clear[i] == fam && clear[i+1] == typ {
			return true
		}
	}
	return false
}

// Serve runs both listeners until ctx cancels.
func (s *BaseAppServer) Serve(ctx context.Context, stage1, stage2 Transport) error {
	if stage1 == nil || stage2 == nil {
		return fmt.Errorf("wotserver: baseapp needs both listeners")
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := serveStage1(s, ctx, stage1); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("stage1: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := serveStage2(s, ctx, stage2); err != nil && err != context.Canceled {
			errCh <- fmt.Errorf("stage2: %w", err)
		}
	}()
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// --- stage-1: 22B handshake → rotation → tick → [44] redirect. ---
//
// Genuine flows3 server order (seq 0..4): rotation(36) · 52B infos ·
// tick(28) · 44B · redirect(36). v1 sends rotation → tick → redirect;
// the two infos datagrams are cut (the client acts on the [44] alone,
// both are only acked in the captures).

func serveStage1(s *BaseAppServer, ctx context.Context, conn Transport) error {
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Dead-wake: fire due tails and expire stale pendings —
			// the tick+redirect must land even if the client resends
			// nothing.
			s.sweepStage1(conn, time.Now())
			continue
		}
		if err := s.handleStage1(conn, from, buf[:n]); err != nil {
			s.logf("stage1 %s: %v", from, err)
		}
		s.sweepStage1(conn, time.Now())
	}
}

func (s *BaseAppServer) handleStage1(conn Transport, from *net.UDPAddr, pkt []byte) error {
	rq, ok := parseBaseAppLogin(pkt)
	if !ok {
		// Everything non-22B on stage-1 is walk tokens (acks, auth1,
		// post-redirect auth2): silence, like the live managers.
		return nil
	}
	st := s.bySession(rq.sessionKey)
	if st == nil {
		// Unknown session key: silence (p5 validates keys: random-key
		// 22Bs draw zero bytes there).
		s.logf("stage1 %s: 22B for unknown session key %08x — silent", from, rq.sessionKey)
		return nil
	}
	s.mu.Lock()
	nk := st.stageKey
	if nk == 0 {
		k, err := mintRotationKey(rq.sessionKey)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		nk = k
		// Register BEFORE touching from/rid: the stage-2 22B looks this
		// key up, so a stale map entry must never outlive the mint.
		st.stageKey = nk
		s.byStageKey[nk] = st
	}
	if st.addr == nil {
		st.addr = cloneAddr(from)
	}
	if st.tailAt.IsZero() {
		st.tailAt = time.Now().Add(300 * time.Millisecond)
	}
	s.mu.Unlock()
	// Per-request-id reply: a lost rotation is re-signaled with the
	// rid of the client's CURRENT handshake (stageKeyOf matches on
	// rid; the client resends with a FRESH rid each attempt).
	rot, err := buildChannelPacket(st.blockKey, flagsRel, replyMsg(rq.rid, nk), nil, 0, 0)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(rot, from); err != nil {
		return err
	}
	s.logf("stage1 %s: 22B rid=%d mtu=%d att=%d → rotation %dB", from, rq.rid, rq.mtu, rq.attempts, len(rot))
	return nil
}

// sweepStage1 fires due stage-1 tails (28B tick, then the [44]
// redirect) and expires PendingTTL admissions.
func (s *BaseAppServer) sweepStage1(conn Transport, now time.Time) {
	type tailJob struct {
		blockKey string
		addr     *net.UDPAddr
	}
	s.mu.Lock()
	var due []tailJob
	for _, st := range s.byStageKey {
		if st.stage2Addr != nil || st.tailAt.IsZero() || now.Before(st.tailAt) {
			continue
		}
		due = append(due, tailJob{blockKey: st.blockKey, addr: st.addr})
		st.tailAt = time.Time{} // fire once
	}
	for k, st := range s.pending {
		if now.Sub(st.admittedAt) > PendingTTL {
			delete(s.pending, k)
		}
	}
	s.mu.Unlock()
	for _, j := range due {
		if j.addr == nil {
			continue
		}
		// tick: genuine 28B `5804 133e <seq=2> <cumul=1>` — flagsRel +
		// [13][stage tag] (ClientInterface::tickSyncPeriodic, wire id
		// 19) + footers; the tag byte's semantics are open (stage-1
		// sessions show 0x3e; parked runs walk it) — copied from flow 10.
		tick, err := buildChannelPacket(j.blockKey, flagsRel, tickApp, nil, 2, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(tick, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		red, err := redirectPacket(j.blockKey, s.cfg.Redirect)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(red, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		s.logf("stage1 %s: tick %dB + redirect %dB → %s", j.addr, len(tick), len(red), s.cfg.Redirect)
	}
}

// redirectApp mints the [44] application for one target: the 36B
// redirect shape is 2B flags + [13][3f] + [44][ip4][port BE][00 00 01]
// + footers (flows3 s1_srv_4 decrypts to exactly that; the 0x13 head
// is the piggy-backed tick, the 0x44 core trails 7 B, cumul 1 acks
// the client's reliable auth1 seq 0).
func redirectApp(target *net.UDPAddr) ([]byte, error) {
	ip := target.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("wotserver: stage-2 endpoint %s is not IPv4 (ip4 redirect core)", target)
	}
	app := []byte{0x13, 0x3f, 0x44}
	app = append(app, ip...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(target.Port))
	app = append(app, pb[:]...)
	app = append(app, 0x00, 0x00, 0x01)
	return app, nil
}

func redirectPacket(blockKey string, target *net.UDPAddr) ([]byte, error) {
	app, err := redirectApp(target)
	if err != nil {
		return nil, err
	}
	return buildChannelPacket(blockKey, flagsRel, app, nil, 4, 1)
}

// parseBaseAppLogin reads the 22B fixed handshake:
//
//	[prefix4][flags 01 00][00][rid u32][00 00][sessionKey u32]
//	[numAttempts u8][mtu u16][footer u16 = 2]
//
// The single request sits at body+2 (body = pkt[4:], §3 request
// chain); the msg is FIXED-7 = 14 B (baseAppLogin wire id 0, the
// buildBaseAppLoginMsg shape).
type baseAppLoginReq struct {
	sessionKey uint32
	rid        uint32
	mtu        int
	attempts   uint8
}

func parseBaseAppLogin(pkt []byte) (rq baseAppLoginReq, ok bool) {
	if len(pkt) != 22 || pkt[4] != 0x01 || pkt[5] != 0x00 {
		return rq, false
	}
	if pkt[6] != 0x00 { // BaseAppExt::baseAppLogin
		return rq, false
	}
	if off := binary.LittleEndian.Uint16(pkt[20:22]); off != 2 {
		return rq, false
	}
	rq.rid = binary.LittleEndian.Uint32(pkt[7:11])
	rq.sessionKey = binary.LittleEndian.Uint32(pkt[13:17])
	rq.attempts = pkt[17]
	rq.mtu = int(binary.LittleEndian.Uint16(pkt[18:20]))
	return rq, true
}

// mintRotationKey picks a stage token: newkey ≠ 0, ≠ old (the client
// fork fails a zero/echoed rotation, sub_140E5FF00 family).
func mintRotationKey(old uint32) (uint32, error) {
	var b [4]byte
	for i := 0; i < 100; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, fmt.Errorf("wotserver: rotation key: %w", err)
		}
		k := binary.LittleEndian.Uint32(b[:])
		if k != 0 && k != old {
			return k, nil
		}
	}
	return 0, fmt.Errorf("wotserver: rotation key: no fresh value")
}

// replyMsg is the rotation app: [FF][len=8][rid u32][newkey u32] —
// the genuine flows3 rotation decrypts to
// `5804 ff 08000000 <rid> <newkey> <seq> <cumul>`; the client side
// stageKeyOf/extractStageKey match exactly this shape.
func replyMsg(rid, newkey uint32) []byte {
	var tmp [4]byte
	msg := []byte{0xFF, 0x08, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(tmp[:], rid)
	msg = append(msg, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], newkey)
	return append(msg, tmp[:]...)
}

// bySession resolves a stage-1 handshake's session: pending first,
// then byStageKey (rotation minted but a resend raced in).
func (s *BaseAppServer) bySession(key uint32) *clientState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.pending[key]; ok {
		return st
	}
	return s.byStageKey[key]
}

// cloneAddr copies a UDP address (ReadFromUDP allocates per call;
// stored states keep their own).
func cloneAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

// --- stage-2: rotation-2 → double-auth watch → flood carrier. ---

func serveStage2(s *BaseAppServer, ctx context.Context, conn Transport) error {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Dead-wake: post-flood sessions keep ticking even when the
			// client sends nothing (genuine: 100 ms tick cadence).
			s.sweepStage2(conn, time.Now())
			continue
		}
		if err := s.handleStage2(conn, from, buf[:n]); err != nil {
			s.logf("stage2 %s: %v", from, err)
		}
		s.sweepStage2(conn, time.Now())
	}
}

// handleStage2 walks the second stage: the 22B (its sessionKey slot
// carries our stage-1 rotation) → rotation-2 → then the client's
// double-auth ([02][key2] unreliable twin + [02][key2][0b] reliable
// one) → flood burst.
func (s *BaseAppServer) handleStage2(conn Transport, from *net.UDPAddr, pkt []byte) error {
	if rq, ok := parseBaseAppLogin(pkt); ok {
		st := s.byStageKey[rq.sessionKey]
		if st == nil {
			s.logf("stage2 %s: 22B for unknown stage key %08x — silent", from, rq.sessionKey)
			return nil
		}
		s.mu.Lock()
		if st.stage2Key == 0 {
			nk, err := mintRotationKey(rq.sessionKey)
			if err != nil {
				s.mu.Unlock()
				return err
			}
			st.stage2Key = nk
			st.stage2Addr = cloneAddr(from)
			s.byAddr[from.String()] = st
		}
		nk := st.stage2Key
		s.mu.Unlock()
		// Same per-rid reply rule as stage-1 (resends carry fresh rids).
		rot, err := buildChannelPacket(st.blockKey, flagsRel, replyMsg(rq.rid, nk), nil, 0, 0)
		if err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(rot, from); err != nil {
			return err
		}
		s.logf("stage2 %s: 22B rid=%d → rotation-2 %dB", from, rq.rid, len(rot))
		// The pre-flood smalls ride right behind the rotation in the
		// genuine script (rotation → +10 ms info → +40 ms descriptor,
		// flows3-s2 idx 1/4/5). Sent with EVERY rotation-2 reply
		// (loss-robust: a duplicate is acked and census-counted, like
		// the genuine server's own channel resends).
		if s.preOK {
			return s.sendPre(conn, from, st)
		}
		return nil
	}
	// Non-handshake: acks or the double-auth itself. Only sessions we
	// rotated on THIS socket qualify; ours is keyed by source address
	// (a fresh socket addr is the only stable join). Flooded sessions
	// stay live — they walk the post-flood chain.
	s.mu.Lock()
	st := s.byAddr[from.String()]
	if st == nil {
		s.mu.Unlock()
		return nil
	}
	flooded := st.flooded
	s.mu.Unlock()
	if flooded {
		clear, err := DecryptChannel(st.blockKey, pkt)
		if err != nil {
			return nil // not one of ours / undecryptable: ignore
		}
		s.noteReliable(st, clear)
		return s.servePostFlood(conn, from, st, clear)
	}
	clear, err := DecryptChannel(st.blockKey, pkt)
	if err != nil {
		return nil // not one of ours / undecryptable: ignore
	}
	s.noteReliable(st, clear)
	if isStageAuth(clear, st.stage2Key) {
		return s.serveBulk(conn, from, st)
	}
	return nil
}

// noteReliable advances the session's cumul watermark: the fork stamps
// cumul = last processed peer RELIABLE seq + 1 into every footer
// (UDPBundle finalise sub_142AD4D81; the genuine tail ramps 3 = token
// seq 2 + 1, 4 = sync seq 3 + 1, 7 = season seq 6 + 1). RELIABLE is
// byte-0 bit 0x10 (flagsRel 58 04 has it, flagsUnrel 48 14 does not) —
// the client's ack datagrams are unreliable and must NOT move it:
// their seq field echoes OUR server seqs, not client sends.
func (s *BaseAppServer) noteReliable(st *clientState, clear []byte) {
	if len(clear) < 10 || clear[0]&0x10 == 0 {
		return
	}
	seq := binary.LittleEndian.Uint32(clear[len(clear)-8 : len(clear)-4])
	s.mu.Lock()
	if wm := seq + 1; wm > st.postCumul {
		st.postCumul = wm
	}
	s.mu.Unlock()
}

// sendPre emits the stage-2 pre-flood smalls: the 36B info (app
// verbatim, footers seq 1 / cumul 0 — no client reliable send is
// processed yet) and the 76B descriptor (companion frame, account name
// substituted). The session dict is NOT here: it belongs with the
// flood (serveBulk), where the auth1 watermark is already live.
func (s *BaseAppServer) sendPre(conn Transport, to *net.UDPAddr, st *clientState) error {
	info, err := buildChannelPacket(st.blockKey, flagsRel, s.infoApp, nil, 1, 0)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(info, to); err != nil {
		return err
	}
	desc, err := descriptorFrame(s.descTpl, st.name)
	if err != nil {
		return err
	}
	descWire, err := s.sendCarrier(conn, to, st, desc)
	if err != nil {
		return err
	}
	s.logf("stage2 %s: info %dB + descriptor %dB wire (name %dB)", to, len(info), descWire, len(st.name))
	return nil
}

// postDoCmd reads the leading doCmdInt* call of a post-flood client
// bundle. Wire (lobby.DoCmdInt3/Int2): [flags 2][02][key2 u32 LE]
// [A1 u8][len u16][reqID u16][cmd u16][int64 args...] — the arg block
// starts at the same offset for both variants, so reqID/cmd are always
// at clear[10:12]/clear[12:14]. The genuine tail bundles (flows3-s2,
// all decrypt-proven):
//
//	sync   (84B, idx 1010): `95 1c00 e000 6400 …` = doCmdInt3, reqID
//	  224, cmd 100 (CMD_SYNC_DATA) + the (98,25) initAck tail
//	poll   (60B, idx 1092/1196): `95 1c00 ca00 f501 …` = doCmdInt3,
//	  reqID 202 (REQUEST_ID_NO_RESPONSE), cmd 501 (CMD_REQ_SERVER_STATS)
//	season (52B, idx 1209): `93 1400 e100 7900 …` = doCmdInt2, reqID
//	  225, cmd 121 (CMD_SET_ACTIVE_VEH_SEASON)
//
// Sync and poll share the 0x95 tag, so ONLY the cmd field tells them
// apart — matching on the tag alone answers every poll as a sync.
func postDoCmd(clear []byte, key2 uint32) (req, cmd uint16, ok bool) {
	if len(clear) < 14 || clear[2] != 0x02 {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint32(clear[3:7]) != key2 {
		return 0, 0, false
	}
	// (A1, argLen) per the lobby call builders: 0x95/0x1c doCmdInt3,
	// 0x93/0x14 doCmdInt2 (ArgLength is the Mercury VARIABLE header).
	switch [2]byte{clear[7], clear[8]} {
	case [2]byte{0x95, 0x1c}, [2]byte{0x93, 0x14}:
		return binary.LittleEndian.Uint16(clear[10:12]), binary.LittleEndian.Uint16(clear[12:14]), true
	}
	return 0, 0, false
}

// servePostFlood answers one decrypted post-flood client datagram and
// keeps the tick cadence. Genuine turn-taking (flows3-s2 tail):
//
//	terminator(332) → [13][7a] tick → client 84B sync → [13][7b] 60B
//	  rev answer → ticks → client 501 poll → [13][a4] 36B stats answer
//	  → … 100 ms cadence throughout; every frame (tick or answer) takes
//	  exactly ONE walk slot: tag = 7a+n mod 256, seq = 503+n (rev 7b/
//	  504, offer 7e/506 — offers are v1-cut, the walk just steps over
//	  their slots — poll a4/545 = 7a+42/503+42 ✓, 1a5e dd/602 = +99 ✓)
//
// Answer BODIES replay verbatim from the carrier (1a/5f revisions,
// 1a/5b stat counters — stale reference, same layering as the bulk);
// the [13][tag] head, the footers (seq; cumul = the live client
// watermark), and the 1a/5e error small's req echo are minted.
func (s *BaseAppServer) servePostFlood(conn Transport, from *net.UDPAddr, st *clientState, clear []byte) error {
	req, cmd, ok := postDoCmd(clear, st.stage2Key)
	if !ok {
		return nil // acks and anything else: no answer (genuine parity)
	}
	switch cmd {
	case 100: // CmdSyncData — answered ONCE per session
		s.mu.Lock()
		synced := st.synced
		st.synced = true
		s.mu.Unlock()
		if !synced {
			app := append([]byte{0x13, 0}, s.revReply[4:len(s.revReply)-8]...)
			if err := s.mintPost(conn, from, st, app); err != nil {
				return err
			}
			s.logf("stage2 %s: post-flood sync → [13] rev answer (minted)", from)
		}
	case 501: // CmdReqServerStats
		app := append([]byte{0x13, 0}, s.pollAns[4:len(s.pollAns)-8]...)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood poll → 1a/5b stats answer (minted)", from)
	case 121: // CmdSetActiveVehSeason
		// We hold no garage, so answer the genuine failure small the
		// capture shows (~22 ms after the 52B season bundle, flows3-s2
		// idx 1209/1210): `[13][tag][1a 5e 05][req u16 LE][00 00 00]`
		// + footers. req echoes the client's request id (genuine 225).
		app := []byte{0x13, 0, 0x1a, 0x5e, 0x05, byte(req), byte(req >> 8), 0x00, 0x00, 0x00}
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood season select (req %d) → 1a/5e no-vehicle error (minted)", from, req)
	default:
		// Other cmds (226/600 dossier sync, doCmdStr) are recognized
		// but NOT answered: each wants per-account inventory we don't
		// hold. v1-cut: silence beats a wrong-content answer (see §18
		// honesty layering).
		s.logf("stage2 %s: post-flood cmd %d — no answer (v1-cut)", from, cmd)
	}
	return nil
}

// allocPost takes the next post-flood walk slot (caller holds s.mu).
// The three values are one counter triple shared by ticks and answers
// — the genuine tail consumes one slot per S>C frame, no exceptions.
func allocPost(st *clientState) (tag byte, seq, cumul uint32) {
	tag, seq, cumul = st.postTag, st.postSeq, st.postCumul
	st.postTag++
	st.postSeq++
	return
}

// mintPost allocates the walk slot, stamps its tag into app[1], and
// sends app as a reliable frame with the slot's seq/cumul.
func (s *BaseAppServer) mintPost(conn Transport, to *net.UDPAddr, st *clientState, app []byte) error {
	if len(app) < 2 {
		return fmt.Errorf("wotserver: post-flood frame missing its tag slot")
	}
	s.mu.Lock()
	tag, seq, cumul := allocPost(st)
	s.mu.Unlock()
	app[1] = tag
	pkt, err := buildChannelPacket(st.blockKey, flagsRel, app, nil, seq, cumul)
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDP(pkt, to)
	return err
}

// sweepStage2 fires due post-flood ticks (genuine cadence 100 ms).
func (s *BaseAppServer) sweepStage2(conn Transport, now time.Time) {
	type tickJob struct {
		st    *clientState
		addr  *net.UDPAddr
		tag   byte
		seq   uint32
		cumul uint32
	}
	s.mu.Lock()
	var due []tickJob
	for _, st := range s.byAddr {
		if st.postAt.IsZero() || now.Before(st.postAt) {
			continue
		}
		st.postAt = now.Add(st.tickPeriod)
		// Advance AFTER capturing, so the first tail tick replays the
		// seed tick byte-exact (genuine idx 1007: tag 7a, seq 503).
		tag, seq, cumul := allocPost(st)
		due = append(due, tickJob{st: st, addr: st.stage2Addr, tag: tag, seq: seq, cumul: cumul})
	}
	s.mu.Unlock()
	for _, j := range due {
		if j.addr == nil {
			continue
		}
		app := []byte{0x13, j.tag}
		pkt, err := buildChannelPacket(j.st.blockKey, flagsRel, app, nil, j.seq, j.cumul)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(pkt, j.addr); err != nil {
			continue
		}
	}
}

// sendCarrier re-keys one carrier clear body (fresh prefix + session
// Blowfish) and sends it — the verbatim-replay path used by the bulk
// burst and the post-flood chain answers.
func (s *BaseAppServer) sendCarrier(conn Transport, to *net.UDPAddr, st *clientState, clear []byte) (int, error) {
	var pfx [4]byte
	if _, err := rand.Read(pfx[:]); err != nil {
		return 0, fmt.Errorf("wotserver: frame prefix: %w", err)
	}
	out := append([]byte{}, pfx[:]...)
	if st.blockKey == "" {
		out = append(out, clear...)
	} else {
		enc, err := encryptBlowfish(st.blockKey, clear)
		if err != nil {
			return 0, fmt.Errorf("wotserver: frame rekey: %w", err)
		}
		out = append(out, enc...)
	}
	n, err := conn.WriteToUDP(out, to)
	return n, err
}

// isStageAuth reads the double-auth in a decrypted stage-2 datagram.
// clear = [flags2][app ...]: the reliable auth1 rides flags 58 04, the
// unreliable companion 48 14 (baseapp.go flagsRel/flagsUnrel); app[0]
// = 0x02 (BaseApp.authenticate, FIXED-4), app[1:5] = key2 LE. The
// 0x0b enableEntities trailer rides only the reliable twin and is not
// required here (either half proves the client spent key2).
func isStageAuth(clear []byte, key2 uint32) bool {
	if len(clear) < 7 || clear[2] != 0x02 {
		return false
	}
	rel := clear[0] == 0x58 && clear[1] == 0x04
	unrel := clear[0] == 0x48 && clear[1] == 0x14
	if !rel && !unrel {
		return false
	}
	return binary.LittleEndian.Uint32(clear[3:7]) == key2
}

// serveBulk emits the flood burst: genuine stage-2 floods run 476-489
// × 1252B (one ~6 s burst between the smalls-train windows — our
// client exits on the first decrypt-verified 1252B, the game reassembles
// the whole batch). Frames replay verbatim, re-keyed: fresh random
// prefix + encryptBlowfish under the live session's key over the
// capture's decrypted body. Contents stay the capture's (stale
// reference; per-session bulk heads are future work).
func (s *BaseAppServer) serveBulk(conn Transport, from *net.UDPAddr, st *clientState) error {
	if !s.bulkOK {
		return fmt.Errorf("no flood carrier configured (set -flood/-floodkey)")
	}
	s.mu.Lock()
	if st.flooded {
		s.mu.Unlock()
		return nil
	}
	st.flooded = true
	// The dict frame acks the client's reliable auth1 (seq 0 → cumul 1
	// in the genuine, idx 63) — read the LIVE watermark BEFORE the
	// seed floor is applied (the seed tick's cumul 3 belongs to the
	// post-flood walk, not to this mid-auth frame).
	dictCumul := st.postCumul
	// Arm the post-flood mint sequencer from the carrier seed tick now,
	// under the same lock as the flood flag: tag/seq/cumul start at the
	// capture's first tail tick and walk forward per session. The
	// watermark takes max(live, carrier): our client's ack stream may
	// already have advanced it past the capture's seed.
	if s.postOK {
		st.postTag = s.postTag
		st.postSeq = s.postSeq
		if st.postCumul < s.postCumul {
			st.postCumul = s.postCumul
		}
		st.tickPeriod = PostTickPeriod
	}
	s.mu.Unlock()
	// Session dict (v2.1): minted [13][40] frame carrying the 1a/76
	// small with the four live fields patched. Genuine position: mid-
	// burst (idx 63 of the flood, seq 176 cumul 1); we send it just
	// BEFORE the burst with our own pre-flood seq (2 = the third frame
	// we mint on this channel; the counter then jumps to the carrier's
	// 174 at the first flood frame — documented delta §18.7). Frame
	// tag 0x40 is the capture's.
	if s.preOK {
		if dictCumul < 1 {
			dictCumul = 1 // the auth itself is a reliable seq-0 send
		}
		app, err := dictApp(s.dictTpl, st.name, st.admittedAt, time.Now())
		if err != nil {
			return err
		}
		pkt, err := buildChannelPacket(st.blockKey, flagsRel, app, nil, 2, dictCumul)
		if err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(pkt, from); err != nil {
			return err
		}
		s.logf("stage2 %s: session dict %dB (seq %d cumul %d, databaseID/UTC patched)", from, len(pkt), 2, dictCumul)
	}
	var pfx [4]byte
	for _, clear := range s.bulk {
		if _, err := rand.Read(pfx[:]); err != nil {
			return fmt.Errorf("wotserver: frame prefix: %w", err)
		}
		out := append([]byte{}, pfx[:]...)
		if st.blockKey == "" {
			out = append(out, clear...) // BLOCK_KEY_EMPTY path (probe key only)
		} else {
			enc, err := encryptBlowfish(st.blockKey, clear)
			if err != nil {
				return fmt.Errorf("wotserver: frame rekey: %w", err)
			}
			out = append(out, enc...)
		}
		if _, err := conn.WriteToUDP(out, from); err != nil {
			return err
		}
	}
	// Burst end: the terminator closes the bulk document (genuine: the
	// 332B companion lands ~1 ms after the last chunk), then the tick
	// stream starts ~100 ms later (the [13][7a] tick, flows3-s2 idx
	// 1005 → 1007: 1562.513 → 1562.609).
	if s.postOK {
		if _, err := s.sendCarrier(conn, from, st, s.term); err != nil {
			return err
		}
		s.mu.Lock()
		st.postAt = time.Now().Add(PostTickPeriod)
		s.mu.Unlock()
	}
	s.logf("stage2 %s: flood burst %d frames (carrier %s)", from, len(s.bulk), s.cfg.FloodPath)
	return nil
}

// tickApp is the stage-1 tick body [13][3e]: the genuine tick 28B
// decrypts to `5804 133e <seq=2> <cumul=1>` (flows3). The tag byte
// steps per epoch/stage (0x3e stage-1 here, 0x3f/0x40 at the stage-2
// heads; parked runs walk it 0x00→0xfb) — semantics open, value copied
// from the capture.
var tickApp = []byte{0x13, 0x3e}
