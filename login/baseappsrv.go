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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
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
	// AccountID is the stored account behind this login (0 when the
	// LoginApp runs without an account store).
	AccountID int64
	// FreeXP is the account's free experience, served in the 1a/69
	// stats small. Zero means "not known": the capture's value replays.
	FreeXP int64
	// Version is the client build the login identified ("2.4.0",
	// "2.4.1", or "unknown" when the gates are off). The lobby content
	// is still the capture's, so this is informational for now.
	Version string
}

// BaseAppConfig configures the server. Redirect is required: the
// stage-2 endpoint our [44] mints into the client (bind it inside the
// RedirectPort window).
type BaseAppConfig struct {
	Redirect *net.UDPAddr

	// Stage1Space is the space name the stage-1 1a/50 small announces
	// (the genuine capture carries "default"). The client enters this
	// space after the redirect; an empty value falls back to "default".
	Stage1Space string

	// Flood carrier: a wotproxy-style dump of a genuine stage-2
	// window plus its hex block key (ReadKeyFile format). 1252B S>C
	// frames are channel-decrypted once at load and re-encrypted per
	// session at serve time. Empty means no carrier: stage-2 answers
	// the dance but errors on the flood (loud, not a silent half-lobby).
	FloodPath    string
	FloodKeyPath string
	// FloodFlow selects one flow out of a multi-flow dump (a substring
	// of the addr column, e.g. "35708->"). Empty means the dump holds a
	// single flow, which is the case for the flows3-s2 text dump. A
	// multi-flow capture interleaves flows in arrival order, so without
	// this the post-flood matcher would pair one flow's terminator with
	// another flow's ticks.
	FloodFlow string

	// PostPath/PostKeyPath/PostFlow select a DIFFERENT dump for the
	// post-flood chain (terminator, rev answer, poll answer, seed tick)
	// and the pre-flood smalls. Empty means "same as the flood source".
	//
	// The split exists because no single capture carries both halves:
	// the complete bulk bundle (proxy-20261014-1752 flow 35493->, 416
	// objects, 245 813 of 249 464 bytes decodable) has no 332B
	// terminator, and the capture that has the chain (flows3-s2) has a
	// bulk whose tail is not pickle. Serving the good bundle therefore
	// means taking the bulk from one dump and the chain from another.
	PostPath    string
	PostKeyPath string
	PostFlow    string

	// VerifyBulk receives the reassembled bulk stream (the lobby bundle)
	// once at load. It is the integrity gate: a carrier whose bundle does
	// not decode — a truncated capture, a wrong key, a flow that is not
	// the bulk — fails here instead of being served as garbage the client
	// silently ACKs. nil = no check.
	VerifyBulk func(stream []byte) error

	// PatchBulk rewrites the reassembled bulk stream before it is served.
	// It must return a stream of the SAME length: the frames are rebuilt
	// in place, so a length change would desynchronise the client's
	// fragment accounting. nil = serve the carrier verbatim.
	//
	// This is where the account's economy reaches the client: the flood
	// carries a second pickle document holding `stats.credits` and
	// `stats.freeXP` (see server.ApplyState).
	PatchBulk func(stream []byte) ([]byte, error)

	// CreateBasePlayer sends the Account entity to the client after the
	// session dict and before the flood, so client method calls
	// (onEnqueued, receiveServerStats, …) have a target. It needs the
	// defs: without them the element cannot be built.
	//
	// No capture shows this element in a lobby session, so its position
	// here is a choice, not an observation: the client authenticates, the
	// entity is created, then the lobby data arrives.
	CreateBasePlayer bool
	// AccountComponents is the dynamic-component count CreateBasePlayer
	// carries. The reference's capture shows 19 for Account, and no
	// component data follows it — the element ends right after the count.
	AccountComponents uint8
	// ShowGUIArg is the STRING showGUI takes. The reference replays the
	// capture's; we have none, so it is empty by default.
	ShowGUIArg string

	// Queue lets the application layer own the matchmaking queue. nil =
	// the queue commands are recognised and left unanswered, and the
	// census replays the carrier's.
	Queue *QueueHooks

	// Dispatch is the script model's client-facing tables. When set, the
	// post-flood client calls are decoded from the defs instead of the
	// hand-written element reader: the element id maps to a base method
	// id by a fixed base, and the method's argument types come from the
	// defs. nil = the hand-written reader (kept so a server can run
	// without the defs on disk).
	Dispatch *entdef.Dispatch

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

	// resend holds the reliable packets each peer has not acknowledged.
	// UDP does not retransmit, so a lost answer would stall the client
	// with no error on either side.
	resend *resendQueue

	bulk   [][]byte // flood frame CLEAR bodies (flags+app+trailers)
	bulkOK bool
	// bulkBytes is the reassembled bundle size the gate accepted.
	bulkBytes int
	// bulkPatched counts the bundle bytes PatchBulk changed.
	bulkPatched int

	// Post-flood chain frames (v2, flows3-s2 tail): the 332B
	// terminator ends the bulk burst, the [13][7b] 60B carries the
	// rev-sync answer to the client's post-flood sync bundle, and the
	// [13][a4] 36B is the stats answer template to every 501 poll.
	// All three replay verbatim (stale-reference content); only the
	// ticks and the poll-answer footers are minted per session.
	term     []byte // 332B terminator clear body
	revReply []byte // [13][7b] rev-sync answer clear body
	pollAns  []byte // [13][a4] 1a/5b stats answer clear body
	queueAns []byte // [13][tag] 1a/67 queue-info answer clear body
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
	infoApp  []byte // [02 0a 01 00 3f 8b 23 00 13 3f] app (10B)
	descTpl  []byte
	statsTpl []byte // 61B companion clear body (78 04 ...)
	// statsPrevRev/statsRev are the client's cache counters, read off the
	// carrier's 1a/69 once at load. They are not ours to invent: the
	// client compares them against its own cache.
	statsPrevRev int64
	statsRev     int64
	dictTpl      []byte // `1a 76 9c 00` + 156B body (9b + 155B proto-2 pickle)
	preOK        bool

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

	// stage1Seen bounds the stage-1 datagram trace: a client that never
	// gets an answer resends, and an unbounded trace would bury the log.
	stage1Seen int
}

type clientState struct {
	blockKey   string       // LogOnParams key (set once at admit)
	name       string       // login username (future per-session smalls)
	accountID  int64        // stored account behind the login (0 = none)
	freeXP     int64        // account free XP for the 1a/69 stats small
	version    string       // client build the login identified
	entityID   uint32       // the player entity id we mint for CreateBasePlayer
	entered    bool         // the Account entity has been created
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
	if cfg.Stage1Space == "" {
		cfg.Stage1Space = "default"
	}
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
	if cfg.AccountComponents == 0 {
		// The reference's capture shows 19 for Account. Zero is the
		// "unset" value here, so a carrier that really wanted zero would
		// have to say so explicitly — which no capture does.
		cfg.AccountComponents = 19
	}
	s := &BaseAppServer{
		cfg:        cfg,
		resend:     newResendQueue(resendTimeout, resendGiveUp),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	if cfg.FloodPath != "" {
		n, err := s.loadBulk()
		if err != nil {
			return nil, fmt.Errorf("wotserver: flood carrier: %w", err)
		}
		s.logf("bulk carrier loaded %d frames, %d B bundle, %d B patched, from %s",
			n, s.bulkBytes, s.bulkPatched, cfg.FloodPath)
		if err := s.loadPost(); err != nil {
			return nil, fmt.Errorf("wotserver: post-flood carrier: %w", err)
		}
		if err := s.loadPre(); err != nil {
			return nil, fmt.Errorf("wotserver: pre-flood carrier: %w", err)
		}
	}
	return s, nil
}

// logf is the BaseApp's lifecycle channel. It always prints: a silent
// BaseApp is indistinguishable from a dead one, and "the client hangs
// after LOGGED_ON" is exactly the symptom that needs these lines. The
// per-datagram detail stays behind -verbose (logVerbosef).
func (s *BaseAppServer) logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[wotserver] "+format+"\n", args...)
}

// traceStage1 prints the first few stage-1 datagrams that got no answer,
// with their bytes. A client stuck on "Connecting" resends the same
// handshake; without this the server looks dead while it is in fact
// dropping something it cannot read.
func (s *BaseAppServer) traceStage1(from *net.UDPAddr, pkt []byte, why string) {
	s.mu.Lock()
	n := s.stage1Seen
	s.stage1Seen++
	s.mu.Unlock()
	if n >= 8 {
		if n == 8 {
			s.logf("stage1 %s: further unanswered datagrams not traced", from)
		}
		return
	}
	head := pkt
	if len(head) > 32 {
		head = head[:32]
	}
	s.logf("stage1 %s: %dB %s: % x", from, len(pkt), why, head)
}

// logVerbosef is the noisy channel: per-packet detail, -verbose only.
func (s *BaseAppServer) logVerbosef(format string, args ...any) {
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
		entityID:   sess.SessionKey, // unique per session, never zero
		blockKey:   sess.BlockKey,
		name:       sess.Name,
		accountID:  sess.AccountID,
		freeXP:     sess.FreeXP,
		version:    sess.Version,
		sessionKey: sess.SessionKey,
		admittedAt: time.Now(),
	}
	s.logf("admitted session key %08x (name %dB, blockKey %dB, client %s)",
		sess.SessionKey, len(sess.Name), len(sess.BlockKey), versionOrUnknown(sess.Version))
}

// versionOrUnknown labels a session whose build the login could not
// identify (the gates were off).
func versionOrUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// postSource resolves the dump used for the post-flood chain and the
// pre-flood smalls: its own when configured, else the flood source.
func (s *BaseAppServer) postSource() (path, keyPath, flow string) {
	path, keyPath, flow = s.cfg.PostPath, s.cfg.PostKeyPath, s.cfg.PostFlow
	if path == "" {
		path = s.cfg.FloodPath
	}
	if keyPath == "" {
		keyPath = s.cfg.FloodKeyPath
	}
	// The flow selector belongs to a dump, so it is only inherited when
	// the post source IS the flood source. A separate dump has its own
	// flow names; inheriting would filter everything out.
	if flow == "" && path == s.cfg.FloodPath {
		flow = s.cfg.FloodFlow
	}
	return path, keyPath, flow
}

// inFlow reports whether a dump record belongs to the selected flow.
func (s *BaseAppServer) inFlow(addr string) bool {
	return s.cfg.FloodFlow == "" || strings.Contains(addr, s.cfg.FloodFlow)
}

// inPostFlow is inFlow against the post-flood source's selector.
func (s *BaseAppServer) inPostFlow(addr string) bool {
	_, _, flow := s.postSource()
	return flow == "" || strings.Contains(addr, flow)
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
		if d.Dir != "S>C" || len(d.Data) < 20 || !s.inFlow(d.Addr) {
			continue
		}
		clear, err := decryptBlowfish(key, d.Data[4:])
		if err != nil || len(clear) < 14 {
			continue // mis-captured frame: drop silently
		}
		// Only fragments belong to the burst. The LAST fragment of a
		// chain is short (the bundle does not end on a 1252B boundary),
		// so filtering on the full size drops the tail of every bundle
		// and the client assembles a short one:
		//
		//   BundleDataPos::advance: Ran out of packets.
		//   MF_ASSERT_DEV FAILED: tailAdvanceSuccess
		if binary.LittleEndian.Uint16(clear[0:2])&chFlagFragment == 0 {
			continue
		}
		s.bulk = append(s.bulk, clear)
	}
	if err := s.applyBulk(); err != nil {
		return 0, err
	}
	s.bulkOK = true
	return len(s.bulk), nil
}

// bulkFrame is one decrypted carrier frame plus where its payload sits
// in the reassembled stream.
type bulkFrame struct {
	clear []byte // [flags][app][trailers]
	pay   []byte // clear[2:len-trailer]
	head  int    // bytes of pay that are chain header, not bundle
	first uint32 // chain id (the range's first seq)
	rel   uint32 // position inside the chain
	order int    // arrival order, for the wire
}

// splitBulkFrames decrypts the carrier's bulk frames and works out each
// one's place in the fragment chains.
//
// The chain id is the range's first seq (IS_FRAGMENT puts an 8-byte
// first/last range at the front of the trailer); a frame without the flag
// is its own single-fragment chain. The chain header length follows from
// the frame's own shape, so no cross-frame state is needed.
func (s *BaseAppServer) splitBulkFrames() ([]bulkFrame, error) {
	key, err := ReadAnyKeyFile(s.cfg.FloodKeyPath)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(s.cfg.FloodPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		return nil, err
	}
	var out []bulkFrame
	for _, d := range dump {
		if d.Dir != "S>C" || len(d.Data) < 20 || !s.inFlow(d.Addr) {
			continue
		}
		clear, err := decryptBlowfish(key, d.Data[4:])
		if err != nil || len(clear) < 14 {
			continue // mis-captured frame: drop silently
		}
		if binary.LittleEndian.Uint16(clear[0:2])&chFlagFragment == 0 {
			continue // not a fragment: the burst is the fragment chain
		}
		n := len(clear)
		flags := binary.LittleEndian.Uint16(clear[0:2])
		tr := ChannelTrailerLen(flags)
		if n < 2+tr {
			continue
		}
		first, _, seq, ok := fragRange(clear)
		if !ok {
			continue
		}
		pay := clear[2 : n-tr]
		out = append(out, bulkFrame{clear: clear, pay: pay, first: first, rel: seq - first, order: len(out)})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %dB S>C frames in %s", s.cfg.BulkFragSize, s.cfg.FloodPath)
	}
	// The chain header rides on the chain's FIRST fragment, which is the
	// one with the smallest rel — not necessarily rel 0: the capture's
	// first fragment can be missing (the 1752 flow starts at rel 1).
	minRel := map[uint32]uint32{}
	for _, fr := range out {
		if cur, ok := minRel[fr.first]; !ok || fr.rel < cur {
			minRel[fr.first] = fr.rel
		}
	}
	for i := range out {
		if out[i].rel == minRel[out[i].first] {
			out[i].head = chainHeadLen(out[i].pay)
		}
	}
	return out, nil
}

// chainHeadLen is how many leading bytes of a chain's first fragment are
// header rather than bundle. Mirrors the shapes login.ReassembleFrags
// recognises; anything unrecognised is treated as an 8-byte header.
func chainHeadLen(pay []byte) int {
	switch {
	case len(pay) >= 4 && pay[0] == 0xFF && pay[3] == 0x03:
		return 4
	case len(pay) >= 8 && pay[5] == 0xDD && pay[6] == 0x00:
		return 8
	case len(pay) >= 8 && pay[0] == 0x13 && pay[2] == 0x1A:
		return 8
	case len(pay) >= 8:
		return 8
	}
	return 0
}

// applyBulk runs the load-time pass over the carrier: reassemble the
// bundle in chain order, hand it to the gate and the patcher, and write
// the result back into the frames in place.
func (s *BaseAppServer) applyBulk() error {
	frames, err := s.splitBulkFrames()
	if err != nil {
		return err
	}
	// The client reads a fragment's last 4 bytes as
	// [fragmentIndex u16][fragmentCount u16] and rejects a fragment whose
	// count differs from the bundle it is assembling:
	//
	//   FragmentedBundle::addPacket: Mangled fragment footers on packet
	//   #162, got [1,185], expecting [2,174]
	//
	// A capture can hold fragments of more than one bundle (a flow that
	// spans a reconnect). Keep the bundle with the most fragments and
	// drop the rest, or the client never accepts the burst.
	frames = keepBundleChain(frames)
	frames = keepBundleChain(frames)
	// Chain order: by chain id, then position inside the chain.
	order := make([]int, len(frames))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		fa, fb := frames[order[a]], frames[order[b]]
		if fa.first != fb.first {
			return fa.first < fb.first
		}
		return fa.rel < fb.rel
	})
	// The bundle starts at the fragment that carries its header
	// (ff + u24 total length), not at the chain's lowest seq: the chain
	// can open with a fragment of another message (the info app rides
	// seq 1 in the live capture), and starting the stream there feeds
	// the decoder a non-bundle byte (unsupported pickle opcode 0x13).
	start := 0
	for k, i := range order {
		if len(frames[i].pay) >= 4 && frames[i].pay[0] == 0xFF {
			start = k
			break
		}
	}
	order = order[start:]
	// The chain header rides on the frame the stream starts at, not on
	// the chain's lowest seq.
	if len(order) > 0 {
		frames[order[0]].head = chainHeadLen(frames[order[0]].pay)
	}
	var stream []byte
	for _, i := range order {
		stream = append(stream, frames[i].pay[frames[i].head:]...)
	}
	// The header's u24 is the bundle's exact length; the last fragment
	// carries padding past it (5 B in the live capture). Trim, or the
	// client walks a message into the padding.
	if len(order) > 0 {
		h := frames[order[0]].pay
		if len(h) >= 4 && h[0] == 0xFF {
			if n := int(h[1]) | int(h[2])<<8 | int(h[3])<<16; n > 0 && n <= len(stream) {
				stream = stream[:n]
			}
		}
	}
	if s.cfg.VerifyBulk != nil {
		if err := s.cfg.VerifyBulk(stream); err != nil {
			return fmt.Errorf("bulk verify: %w", err)
		}
	}
	s.bulkBytes = len(stream)
	if s.cfg.PatchBulk != nil {
		patched, err := s.cfg.PatchBulk(stream)
		if err != nil {
			return fmt.Errorf("bulk patch: %w", err)
		}
		if len(patched) != len(stream) {
			return fmt.Errorf("bulk patch changed the length (%d -> %d); frames are rebuilt in place",
				len(stream), len(patched))
		}
		off := 0
		for _, i := range order {
			body := frames[i].pay[frames[i].head:]
			copy(body, patched[off:off+len(body)])
			off += len(body)
		}
		for j := range patched {
			if patched[j] != stream[j] {
				s.bulkPatched++
			}
		}
	}
	// Serve in CHAIN order, not arrival order. A capture can interleave
	// fragments of several chains (a flow that spans a reconnect, or a
	// session that received two bundles); the client assembles one chain
	// at a time and rejects a fragment whose footer names another:
	//
	//   FragmentedBundle::addPacket: Mangled fragment footers on packet
	//   #162, got [1,185], expecting [2,174]
	//
	// Chain order keeps every chain contiguous, which is also the order
	// the stream above is built in.
	s.bulk = s.bulk[:0]
	for _, i := range order {
		s.bulk = append(s.bulk, frames[i].clear)
	}
	return nil
}

// fragRange reads a fragment frame's [first,last] range and its seq.
// The trailer is [first][last][seq][cumul], so the range sits at n-tr
// and the seq is the 4 bytes before cumul when CUMUL is set.
func fragRange(clear []byte) (first, last, seq uint32, ok bool) {
	n := len(clear)
	if n < 14 {
		return 0, 0, 0, false
	}
	flags := binary.LittleEndian.Uint16(clear[0:2])
	if flags&chFlagFragment == 0 {
		return 0, 0, 0, false
	}
	tr := ChannelTrailerLen(flags)
	if n < 2+tr || tr < 12 {
		return 0, 0, 0, false
	}
	first = binary.LittleEndian.Uint32(clear[n-tr : n-tr+4])
	last = binary.LittleEndian.Uint32(clear[n-tr+4 : n-tr+8])
	if flags&chFlagCumulAck != 0 {
		seq = binary.LittleEndian.Uint32(clear[n-8 : n-4])
	} else {
		seq = binary.LittleEndian.Uint32(clear[n-4:])
	}
	return first, last, seq, true
}

// keepBundleChain keeps the bundle's fragment chain plus its tail.
//
// The chain's fragments carry [first,last] in the footer, but the LAST
// fragment declares [last,last] — a single-fragment chain by the
// footer's own rule — and its seq counts from 1. The client keys a
// bundle by that pair, so it files the tail in a bundle of its own and
// the real one stays short by exactly those bytes:
//
//	BundleDataPos::advance: Ran out of packets.
//	MF_ASSERT_DEV FAILED: tailAdvanceSuccess
//
// The tail is rewritten into the chain: range [first,last], seq = last.
func keepBundleChain(frames []bulkFrame) []bulkFrame {
	counts := map[uint32]int{}
	last := map[uint32]uint32{}
	for _, fr := range frames {
		counts[fr.first]++
		if _, _, _, ok := fragRange(fr.clear); ok {
			if l := binary.LittleEndian.Uint32(fr.clear[len(fr.clear)-ChannelTrailerLen(binary.LittleEndian.Uint16(fr.clear[0:2]))+4:]); l > last[fr.first] {
				last[fr.first] = l
			}
		}
	}
	if len(counts) < 2 {
		return frames
	}
	var best uint32
	for id, n := range counts {
		if n > counts[best] {
			best = id
		}
	}
	tail := last[best]
	// The bundle's first fragment is the one carrying its header
	// (ff + u24 length); the chain can open with a fragment of another
	// message (the info app rides seq 1 in the live capture). The client
	// counts every fragment of the range, so the range is renumbered to
	// start there and the earlier frames are dropped — otherwise the
	// client assembles info-app bytes in front of the bundle and walks
	// off its end (BundleDataPos::advance: Ran out of packets).
	start := best
	for _, fr := range frames {
		if fr.first == best && len(fr.pay) >= 4 && fr.pay[0] == 0xFF {
			start = best + fr.rel
			break
		}
	}
	out := make([]bulkFrame, 0, len(frames))
	for i := range frames {
		fr := frames[i]
		if fr.first == best {
			if fr.rel < start-best {
				continue
			}
			n := len(fr.clear)
			tr := ChannelTrailerLen(binary.LittleEndian.Uint16(fr.clear[0:2]))
			if n >= 2+tr && tr >= 12 {
				binary.LittleEndian.PutUint32(fr.clear[n-tr:], start)
			}
			fr.first, fr.rel = start, fr.rel-(start-best)
			out = append(out, fr)
			continue
		}
		if fr.first != tail {
			continue
		}
		n := len(fr.clear)
		tr := ChannelTrailerLen(binary.LittleEndian.Uint16(fr.clear[0:2]))
		if n >= 2+tr && tr >= 12 {
			binary.LittleEndian.PutUint32(fr.clear[n-tr:], start)
			binary.LittleEndian.PutUint32(fr.clear[n-tr+4:], tail)
			if binary.LittleEndian.Uint16(fr.clear[0:2])&chFlagCumulAck != 0 {
				binary.LittleEndian.PutUint32(fr.clear[n-8:], tail)
			} else {
				binary.LittleEndian.PutUint32(fr.clear[n-4:], tail)
			}
			fr.first, fr.rel = start, tail-start
		}
		out = append(out, fr)
	}
	return out
}

// keepLargestBundle drops fragments that belong to a different bundle
// than the majority. The fragment count is the high u16 of the frame's
// last 4 bytes (the client's own footer split).
func keepLargestBundle(frames []bulkFrame) []bulkFrame {
	counts := map[uint16]int{}
	for _, fr := range frames {
		n := len(fr.clear)
		if n < 4 {
			continue
		}
		counts[uint16(binary.LittleEndian.Uint32(fr.clear[n-4:])>>16)]++
	}
	if len(counts) < 2 {
		return frames
	}
	var best uint16
	for c, n := range counts {
		if n > counts[best] {
			best = c
		}
	}
	out := frames[:0]
	for _, fr := range frames {
		n := len(fr.clear)
		if n >= 4 && uint16(binary.LittleEndian.Uint32(fr.clear[n-4:])>>16) == best {
			out = append(out, fr)
		}
	}
	return out
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
	path, keyPath, _ := s.postSource()
	key, err := ReadAnyKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(path)
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
		if d.Dir != "S>C" || !s.inPostFlow(d.Addr) {
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
		case 76:
			if s.queueAns != nil {
				continue
			}
			// 1a/67 {players, classes}: the answer to a 502
			// CMD_REQ_QUEUE_INFO. Server-wide, not per-account.
			if clear, err := decryptBlowfish(key, d.Data[4:]); err == nil && len(clear) >= 8 && hasSmall(clear, 0x1a, 0x67) {
				s.queueAns = clear
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
	// The queue-info template (1a/67) is server-wide and rides its own
	// frame, so it is often in the bulk capture rather than the tail one.
	// Fall back to the flood source when the post source has none.
	if s.queueAns == nil && path != s.cfg.FloodPath {
		if err := s.loadQueueTemplate(); err != nil {
			s.logf("queue-info template unavailable: %v", err)
		}
	}
	if s.term == nil || s.revReply == nil || s.pollAns == nil || s.tickSeed == nil {
		return fmt.Errorf("post-flood chain frames missing (term=%v rev=%v poll=%v tick=%v) in %s",
			s.term != nil, s.revReply != nil, s.pollAns != nil, s.tickSeed != nil, path)
	}
	s.postOK = true
	return nil
}

// loadQueueTemplate finds the 1a/67 queue-info answer in the flood
// source. It is the answer to a 502 CMD_REQ_QUEUE_INFO and is
// server-wide, so any capture that saw one carries it.
func (s *BaseAppServer) loadQueueTemplate() error {
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
		if d.Dir != "S>C" || len(d.Data) != 76 || !s.inFlow(d.Addr) {
			continue
		}
		clear, err := decryptBlowfish(key, d.Data[4:])
		if err != nil || len(clear) < 8 || !hasSmall(clear, 0x1a, 0x67) {
			continue
		}
		s.queueAns = clear
		return nil
	}
	return fmt.Errorf("no 76B 1a/67 frame in %s", s.cfg.FloodPath)
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
	path, keyPath, _ := s.postSource()
	key, err := ReadAnyKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("key file: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		return err
	}
	for _, d := range dump {
		if d.Dir != "S>C" || !s.inPostFlow(d.Addr) {
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
		case 92:
			// The 1a/69 stats small: {stats:{freeXP:N},prevRev,cache,rev}.
			// It is the only per-account field confirmed on the wire.
			if s.statsTpl != nil {
				continue
			}
			clear, err := decryptBlowfish(key, d.Data[4:])
			if err != nil || len(clear) < 8 || clear[2] != 0x1a || clear[3] != 0x69 {
				continue
			}
			tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
			if len(clear) < 2+tr {
				continue
			}
			s.statsTpl = append([]byte(nil), clear[2:len(clear)-tr]...)
			if _, prev, rev, perr := ParseStatsSmall(s.statsTpl); perr == nil {
				s.statsPrevRev, s.statsRev = prev, rev
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
					if _, err := patchDict(append([]byte(nil), tpl...), "probe", 0, time.Unix(1789681556, 0), time.Unix(1789681556, 0)); err == nil {
						s.dictTpl = tpl
					}
				}
			}
		}
	}
	if s.infoApp == nil || s.descTpl == nil || s.dictTpl == nil {
		return fmt.Errorf("pre-flood smalls missing (info=%v descr=%v dict=%v) in %s",
			s.infoApp != nil, s.descTpl != nil, s.dictTpl != nil, path)
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
func patchDict(tpl []byte, name string, accountID int64, started, now time.Time) ([]byte, error) {
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
	// Same account id the LoginApp token2 head carries (9 digits, fits
	// the int32 slot): the stored account when there is one, else the
	// FNV-1a name hash.
	binary.LittleEndian.PutUint32(f, uint32(int32(accountIDFor(accountID, name))))
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

// statsFrame mints the 1a/69 stats small with the account's free XP.
// freeXP <= 0 replays the capture's value.
// statsFrame builds the 1a/69 stats small for an account. The structure
// comes from the builder; only the revisions come from the carrier.
func statsFrame(prevRev, rev, freeXP int64) ([]byte, error) {
	return BuildStatsSmall(freeXP, prevRev, rev)
}

// dictApp mints the session-dict frame APP: [13][40] + the 1a/76 small
// with the four live fields patched. The booleans keep the capture's
// values (isAogasEnabled=T, collectUiStats=T, logUXEvents=F — the
// playtime-telemetry flags; our server runs no telemetry scheduler, so
// replaying the capture's gate state is honest structure either way).
func dictApp(tpl []byte, name string, accountID int64, started, now time.Time) ([]byte, error) {
	body, err := patchDict(append([]byte(nil), tpl...), name, accountID, started, now)
	if err != nil {
		return nil, err
	}
	return append(EncodeTickSync(0x40), body...), nil
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
	out = append(out, tpl[nl+1+captured:]...)
	// The template comes from a DIFFERENT capture than the flood burst
	// (flows3-s2 vs proxy-1752), and it carries that session's fragment
	// footer: flags 0x0478 (IS_FRAGMENT) with the range [2,174]. The
	// client stores the first footer it sees and rejects every later
	// fragment that disagrees:
	//
	//   FragmentedBundle::addPacket: Mangled fragment footers on packet
	//   #162, got [1,185], expecting [2,174]
	//
	// The descriptor is one complete message, not a fragment, so drop
	// the flag and the 8-byte range: flags 0x0478 -> 0x0458, trailer
	// [first][last][seq][cumul] -> [seq][cumul].
	if len(out) >= 16 && out[0] == 0x78 && out[1] == 0x04 {
		out[0], out[1] = 0x58, 0x04
		n := len(out)
		out = append(out[:n-16], out[n-8:]...)
	}
	return out, nil
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
// hasSmall reports whether a decrypted frame carries a small of the given
// family and type. It parses the frame's app and walks the smalls, so a
// coincidental tag pair inside a payload cannot match.
func hasSmall(clear []byte, fam, typ byte) bool {
	app, err := frameApp(clear)
	if err != nil {
		return false
	}
	return lobby.FindSmall(app, fam, typ) != nil
}

// frameApp returns a decrypted frame's app: everything between the flags
// word and the channel trailers.
func frameApp(clear []byte) ([]byte, error) {
	if len(clear) < 2 {
		return nil, fmt.Errorf("wotserver: frame too short")
	}
	tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
	if len(clear) < 2+tr {
		return nil, fmt.Errorf("wotserver: frame trailers overrun")
	}
	return clear[2 : len(clear)-tr], nil
}

// carrierSmall returns the small bytes a post-flood answer frame carries:
// its app after the tick head, without the channel trailers. It replaces
// slicing the carrier body by hand, and refuses a frame whose head is not
// the tick it expects.
func carrierSmall(clear []byte) ([]byte, error) {
	app, err := frameApp(clear)
	if err != nil {
		return nil, err
	}
	if len(app) < 2 || app[0] != elTickSync {
		return nil, fmt.Errorf("wotserver: carrier frame does not open with a tick")
	}
	return app[2:], nil
}

// answerApp builds a post-flood answer: the tick head, then a small.
func answerApp(small []byte) []byte {
	return append(EncodeTickSync(0), small...)
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
		// post-redirect auth2): silence, like the live managers. A 22B
		// that does not parse is different — that is a handshake we
		// failed to read, and staying silent there hides a dead client.
		// Only a 22B is handshake-shaped. Everything else on stage-1 is
		// a walk token (ack/auth) — normal traffic, not a failure.
		if len(pkt) == 22 {
			s.traceStage1(from, pkt, "did not parse")
		} else {
			s.logVerbosef("stage1 %s: %dB walk token", from, len(pkt))
		}
		return nil
	}
	st := s.bySession(rq.sessionKey)
	if st == nil {
		// Unknown session key: silence (p5 validates keys: random-key
		// 22Bs draw zero bytes there) — but say so, or a client that
		// never gets an answer looks like a dead server.
		s.logf("stage1 %s: 22B for unknown session key %08x — silent", from, rq.sessionKey)
		s.traceStage1(from, pkt, "unknown session key")
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
		st       *clientState
	}
	s.mu.Lock()
	var due []tailJob
	for _, st := range s.byStageKey {
		if st.stage2Addr != nil || st.tailAt.IsZero() || now.Before(st.tailAt) {
			continue
		}
		due = append(due, tailJob{blockKey: st.blockKey, addr: st.addr, st: st})
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
		// createBasePlayer: the genuine 52B, sent AFTER the client's
		// authenticate (capture order: rotation, client acks +
		// authenticate, then this). Creating the player entity before
		// the connection is authenticated leaves it unregistered and
		// the client asserts `pEntity` on the next entity message.
		s.mu.Lock()
		acct, name, ent := j.st.accountID, j.st.name, j.st.entityID
		s.mu.Unlock()
		info, err := buildChannelPacket(j.blockKey, flagsRel, stage1InfoApp(ent, accountIDFor(acct, name)), nil, 1, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(info, j.addr); err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		s.logf("stage1 %s: createBasePlayer %dB (entity %d, account %d)", j.addr, len(info), ent, accountIDFor(acct, name))
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
		// space: genuine 44B `5804 133e 1a50 0d 07 "default" …` — the
		// 1a/50 small naming the space to enter. The client stalls after
		// the redirect without it.
		space, err := buildChannelPacket(j.blockKey, flagsRel, stage1SpaceApp(s.cfg.Stage1Space), nil, 3, 1)
		if err != nil {
			s.logf("stage1 tail: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(space, j.addr); err != nil {
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
		s.logf("stage1 %s: tick %dB + space %dB (%q) + redirect %dB → %s",
			j.addr, len(tick), len(space), s.cfg.Stage1Space, len(red), s.cfg.Redirect)
	}
}

// redirectApp mints the [44] application for one target: the 36B
// redirect shape is 2B flags + [13][3f] + [44][ip4][port BE][00 00 01]
// + footers (flows3 s1_srv_4 decrypts to exactly that; the 0x13 head
// is the piggy-backed tick, the 0x44 core trails 7 B, cumul 1 acks
// the client's reliable auth1 seq 0).
// stage1InfoApp mints the 52B stage-1 info app. The client reads it as
// ClientInterface::createBasePlayer — its own log says so:
//
//	ServerConnection::createBasePlayer: id 2881521
//
// so it carries the player entity id, and that id must be the SAME one
// stage-2's CreateBasePlayer uses. Two different ids leave the client
// with two player entities and it asserts `pEntity` when it enters the
// space (bw_entities.cpp:1103).
//
// Captured verbatim from the paired EU2 login (flows3 flow 14, seq 1,
// which decrypts to 58 04 | 02 0a 01 00 3e 8b 23 00 13 3e 05 12 00
// f1 f7 2b 00 0b 00 00 09 "123456789" 00 | 01 00 00 00 | 01 00 00 00).
// There f1 f7 2b 00 is that session's entity id and the 9 ASCII digits
// are its account id; both are substituted here. The account id is
// always 9 digits (accountIDFor), so the length byte and the frame size
// never move.
func stage1InfoApp(entityID uint32, accountID uint64) []byte {
	app := []byte{
		0x02, 0x0a, 0x01, 0x00, 0x3e, 0x8b, 0x23, 0x00, 0x13, 0x3e,
		0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00,
		0x09,
	}
	binary.LittleEndian.PutUint32(app[13:17], entityID)
	app = append(app, []byte(fmt.Sprintf("%09d", accountID))...)
	return append(app, 0x00)
}

// stage1SpaceApp mints the 44B stage-1 space app: tickSync(0x3e) + the
// 1a/50 small carrying the space name (flows3 flow 14, seq 3, decrypts
// to `58 04 13 3e 1a 50 0d 07 "default" 04 80 02 4e 2e 03 00 00 00
// 01 00 00 00`). Without it the client never learns which space to
// enter and stalls after the redirect.
func stage1SpaceApp(space string) []byte {
	app := append(EncodeTickSync(0x3e), 0x1a, 0x50, byte(len(space)+6))
	app = append(app, byte(len(space)))
	app = append(app, []byte(space)...)
	return append(app, 0x04, 0x80, 0x02, 0x4e, 0x2e)
}

func redirectApp(target *net.UDPAddr) ([]byte, error) {
	ip := target.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("wotserver: stage-2 endpoint %s is not IPv4 (ip4 redirect core)", target)
	}
	app := append(EncodeTickSync(0x3f), 0x44)
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
		s.resend.track(from.String(), 0, rot)
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
	wm := st.postCumul
	s.mu.Unlock()
	// The client's watermark acknowledges every reliable packet below it.
	s.resend.ack(st.stage2Addr.String(), wm)
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
	s.resend.track(to.String(), 1, info)
	desc, err := descriptorFrame(s.descTpl, st.name)
	if err != nil {
		return err
	}
	descWire, err := s.sendCarrier(conn, to, st, desc)
	if err != nil {
		return err
	}
	// 1a/69 stats small: the account's free XP. Optional — a carrier
	// without one (flows3-s2) simply does not send it.
	statsNote := ""
	if s.statsTpl != nil {
		statsApp, err := statsFrame(s.statsPrevRev, s.statsRev, st.freeXP)
		if err != nil {
			return err
		}
		statsPkt, err := buildChannelPacket(st.blockKey, flagsRel, statsApp, nil, 2, 0)
		if err != nil {
			return err
		}
		if _, err := conn.WriteToUDP(statsPkt, to); err != nil {
			return err
		}
		s.resend.track(to.String(), 2, statsPkt)
		statsNote = fmt.Sprintf(" + 1a/69 stats %dB (freeXP %d)", len(statsApp), st.freeXP)
	}
	s.logf("stage2 %s: info %dB + descriptor %dB wire (name %dB)%s",
		to, len(info), descWire, len(st.name), statsNote)
	return nil
}

// QueueHooks is the matchmaking queue as the wire layer sees it: enqueue,
// dequeue, and the census the client polls.
//
// The wire layer does not own the queue — it parses the client's call,
// hands it over, and answers with the client method the defs name. Forming
// a battle is out of scope: that needs a cell app and a space.
type QueueHooks struct {
	// Enqueue adds a player. args is the client's own selection, in its
	// order: [queueType, vehInvID, gameplaysMask, arenaTypeID,
	// randomFlags]. It reports false when the player is already queued.
	Enqueue func(accountID int64, name string, args []int32) bool
	// Dequeue removes a player, reporting whether it was there.
	Dequeue func(accountID int64) bool
	// Census is the 1a/67 answer: the total waiting and the per-class
	// breakdown.
	Census func() (players int, classes []int)
}

// enterAccount brings a client that enabled entities to its account, the
// way the reference's capture shows: the Account entity, then
// SelectPlayerEntity, then showGUI. showGUI is what makes the hangar
// appear; without it the entity exists but nothing is shown.
//
// The trigger is the client's own enableEntities element, not a point in
// the flood: the client says it is ready for entities, and only then does
// the server create one.
func (s *BaseAppServer) enterAccount(conn Transport, from *net.UDPAddr, st *clientState) error {
	if !s.cfg.CreateBasePlayer || s.cfg.Dispatch == nil {
		return nil
	}
	s.mu.Lock()
	done := st.entered
	st.entered = true
	cumul := st.postCumul
	s.mu.Unlock()
	if done {
		return nil // a repeated enableEntities is not a second entity
	}

	app, err := s.createBasePlayerApp(st)
	if err != nil {
		return fmt.Errorf("CreateBasePlayer: %w", err)
	}
	if err := s.sendReliable(conn, from, st, app, 3, cumul); err != nil {
		return err
	}
	s.logf("stage2 %s: CreateBasePlayer %dB (entity %d, Account, %d components)",
		from, len(app), st.entityID, s.cfg.AccountComponents)

	// SelectPlayerEntity: FIXED 0, no payload.
	if err := s.sendReliable(conn, from, st, EncodeSelectPlayerEntity(), 4, cumul); err != nil {
		return err
	}
	s.logf("stage2 %s: SelectPlayerEntity (entity %d)", from, st.entityID)

	// showGUI: the Account client method that shows the hangar.
	call, err := s.accountCall("showGUI", entdef.Value{Kind: entdef.VString, Str: s.cfg.ShowGUIArg})
	if err != nil {
		return fmt.Errorf("showGUI: %w", err)
	}
	if err := s.sendReliable(conn, from, st, call, 5, cumul); err != nil {
		return err
	}
	s.logf("stage2 %s: showGUI %dB (arg %dB)", from, len(call), len(s.cfg.ShowGUIArg))
	return nil
}

// sendReliable frames an app as a reliable packet, sends it, and tracks it
// for retransmission.
func (s *BaseAppServer) sendReliable(conn Transport, to *net.UDPAddr, st *clientState, app []byte, seq, cumul uint32) error {
	pkt, err := buildChannelPacket(st.blockKey, flagsRel, app, nil, seq, cumul)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(pkt, to); err != nil {
		return err
	}
	s.resend.track(to.String(), seq, pkt)
	return nil
}

// createBasePlayerApp builds the CreateBasePlayer element for a session:
// the Account entity with its four base-hosted client-visible properties.
//
// incarnationID identifies this incarnation of the entity, so it is fresh
// per session; the version string is the client's own; the server settings
// blob is empty (the capture's is a Python dict we do not model).
func (s *BaseAppServer) createBasePlayerApp(st *clientState) ([]byte, error) {
	if s.cfg.Dispatch == nil {
		return nil, fmt.Errorf("CreateBasePlayer needs the defs")
	}
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		return nil, fmt.Errorf("no Account entity in the defs")
	}
	var incarnation uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &incarnation); err != nil {
		return nil, fmt.Errorf("incarnation id: %w", err)
	}
	e := NewEntity(st.entityID, acct).
		SetUint("incarnationID", incarnation).
		SetString("requiredVersion_2400", "2.4.0.0").
		SetString("name", st.name).
		Set("initialServerSettings", entdef.Value{Kind: entdef.VString, Str: ""})
	return EncodeCreateBasePlayerWithComponents(e, s.cfg.AccountComponents)
}

// argAt returns args[i], or 0 when the call is shorter.
func argAt(args []int32, i int) int32 {
	if i < 0 || i >= len(args) {
		return 0
	}
	return args[i]
}

// int32Args pulls one ARRAY<INT32> argument out of a decoded call.
func int32Args(args []entdef.Value, i int) []int32 {
	if i < 0 || i >= len(args) || args[i].Kind != entdef.VSeq {
		return nil
	}
	out := make([]int32, 0, len(args[i].Seq))
	for _, v := range args[i].Seq {
		out = append(out, int32(v.Int))
	}
	return out
}

// accountCall builds an Account client method call element from the defs.
func (s *BaseAppServer) accountCall(method string, args ...entdef.Value) ([]byte, error) {
	if s.cfg.Dispatch == nil {
		return nil, fmt.Errorf("wotserver: %s needs the defs", method)
	}
	acct := s.cfg.Dispatch.Entity("Account")
	if acct == nil {
		return nil, fmt.Errorf("wotserver: no Account entity in the defs")
	}
	return EncodeClientMethodCall(NewEntity(0, acct), method, args)
}

// Element ids of entity method calls. The client sends base method N as
// element 0x88+N and cell method N as 0x10+N, so the method id is the
// element id minus the base — no table needed.
const (
	baseMethodElementID = 0x88
	cellMethodElementID = 0x10
)

// postCall is one decoded post-flood client call.
type postCall struct {
	// Req is the call's request id (the first argument).
	Req uint16
	// Cmd is the command id (the second argument), which is what the
	// answer switch keys on.
	Cmd uint16
	// Method is the defs' view of the call, or nil when the server runs
	// without a dispatch.
	Method *entdef.MethodDef
	// Args is every argument, in declared order.
	Args []entdef.Value
}

// Name is the method's def name, or a placeholder without a dispatch.
func (c postCall) Name() string {
	if c.Method == nil {
		return fmt.Sprintf("cmd %d", c.Cmd)
	}
	return c.Method.Name
}

// postDoCmd reads the leading entity-method call of a post-flood client
// bundle. Wire: [flags 2][02][key2 u32 LE][elemID u8][len u16 LE][args].
//
// The element id is the method id plus a fixed base, and the length is
// the method's fixed argument size, so with a dispatch the whole call is
// decoded from the defs — argument types included. Without one it falls
// back to the two calls the lobby actually sends (doCmdInt3/doCmdInt2),
// which is what the hand-written reader always did.
//
// Sync and poll share the doCmdInt3 element, so ONLY the command field
// tells them apart — matching on the element id alone answers every poll
// as a sync.
func (s *BaseAppServer) postDoCmd(clear []byte, key2 uint32) (postCall, bool) {
	if len(clear) < 14 || clear[2] != 0x02 {
		return postCall{}, false
	}
	if binary.LittleEndian.Uint32(clear[3:7]) != key2 {
		return postCall{}, false
	}
	elemID := clear[7]
	argLen := int(binary.LittleEndian.Uint16(clear[8:10]))
	if len(clear) < 10+argLen {
		return postCall{}, false
	}
	body := clear[10 : 10+argLen]

	if s.cfg.Dispatch != nil {
		if acct := s.cfg.Dispatch.Entity("Account"); acct != nil {
			if m := acct.MethodByID(entdef.CompBase, int(elemID)-baseMethodElementID); m != nil {
				// The defs say how long the call is; a mismatch means the
				// model and the wire disagree, which is worth refusing
				// rather than decoding garbage.
				if m.Length.Fixed && m.Length.Size != argLen {
					s.logf("post-flood %s: element %#02x carries %d B, the defs say %d",
						m.Name, elemID, argLen, m.Length.Size)
					return postCall{}, false
				}
				args, err := m.ReadArgs(bytes.NewReader(body))
				if err != nil {
					s.logf("post-flood %s: %v", m.Name, err)
					return postCall{}, false
				}
				call := postCall{Method: m, Args: args}
				if len(args) > 0 && args[0].Kind == entdef.VInt {
					call.Req = uint16(args[0].Int)
				}
				if len(args) > 1 && args[1].Kind == entdef.VInt {
					call.Cmd = uint16(args[1].Int)
				}
				return call, true
			}
		}
	}

	// No dispatch: the two calls the lobby sends, by their pinned element
	// ids and argument sizes.
	switch [2]byte{elemID, byte(argLen)} {
	case [2]byte{0x95, 0x1c}, [2]byte{0x93, 0x14}:
		return postCall{
			Req: binary.LittleEndian.Uint16(clear[10:12]),
			Cmd: binary.LittleEndian.Uint16(clear[12:14]),
		}, true
	}
	return postCall{}, false
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
	// The client's enableEntities is the trigger for creating its entity:
	// it says it is ready, and only then does the server create one. It
	// is FIXED 0, so the element is a single byte.
	if app, err := frameApp(clear); err == nil && len(app) > 0 && app[0] == elEnableEntities {
		if err := s.enterAccount(conn, from, st); err != nil {
			s.logf("stage2 %s: enterAccount: %v", from, err)
		}
		return nil
	}
	// Chat rides its own A1 tag (0x98), not a doCmd* base call, so it is
	// checked first. The client sends initAck and requestLastSysMessages
	// here; we name them and stay silent (no chat backend yet).
	if tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2])); len(clear) > 2+tr {
		if cc, ok := lobby.ParseChatCommandFromClient(clear[2 : len(clear)-tr]); ok {
			s.logf("stage2 %s: chat %s (req %d, ch %d, arg %d)",
				from, cmdLabelChat(cc), cc.RequestID, cc.ChannelID, cc.Int64Arg)
			return nil
		}
	}
	call, ok := s.postDoCmd(clear, st.stage2Key)
	if !ok {
		return nil // acks and anything else: no answer (genuine parity)
	}
	req, cmd := call.Req, call.Cmd
	switch cmd {
	case lobby.CmdSyncData: // answered ONCE per session
		s.mu.Lock()
		synced := st.synced
		st.synced = true
		s.mu.Unlock()
		if !synced {
			small, err := carrierSmall(s.revReply)
			if err != nil {
				return err
			}
			app := answerApp(small)
			if err := s.mintPost(conn, from, st, app); err != nil {
				return err
			}
			s.logf("stage2 %s: post-flood sync → [13] rev answer (minted)", from)
		}
	case lobby.CmdReqServerStats:
		small, err := carrierSmall(s.pollAns)
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood poll → 1a/5b stats answer (minted)", from)
	case lobby.CmdReqQueueInfo:
		// 1a/67 {players, classes}: the queue census. Server-wide, so the
		// carrier's body replays verbatim; only the [13][tag] head and the
		// footers are minted. Absent from a carrier that never saw a 502
		// (the flows3-s2 tail has none) — then stay silent, as the client
		// tolerates.
		// A live queue answers truthfully; without one the carrier's
		// census replays.
		var small []byte
		if s.cfg.Queue != nil && s.cfg.Queue.Census != nil {
			players, classes := s.cfg.Queue.Census()
			built, err := BuildCensusSmall(players, classes)
			if err != nil {
				return err
			}
			small = built
		} else {
			if s.queueAns == nil {
				s.logf("stage2 %s: post-flood %s — no carrier template", from, cmdLabel(cmd))
				return nil
			}
			carried, err := carrierSmall(s.queueAns)
			if err != nil {
				return err
			}
			small = carried
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood queue info → 1a/67 census (minted)", from)
	case lobby.CmdEnqueueInBattleQueue:
		// doCmdIntArr: [queueType, vehInvID, gameplaysMask, arenaTypeID,
		// randomFlags]. The answer is Account.onEnqueued(queueType), a
		// client method the defs name.
		if s.cfg.Queue == nil || s.cfg.Queue.Enqueue == nil {
			s.logf("stage2 %s: post-flood enqueue — no queue configured", from)
			return nil
		}
		args := int32Args(call.Args, 2)
		if len(args) == 0 {
			s.logf("stage2 %s: post-flood enqueue — no arguments", from)
			return nil
		}
		added := s.cfg.Queue.Enqueue(st.accountID, st.name, args)
		s.logf("stage2 %s: post-flood enqueue type %d veh %d (added %v)",
			from, args[0], argAt(args, 1), added)
		app, err := s.accountCall("onEnqueued", entdef.Value{Kind: entdef.VUint, Uint: uint64(uint8(args[0]))})
		if err != nil {
			s.logf("stage2 %s: onEnqueued: %v", from, err)
			return nil
		}
		return s.mintPost(conn, from, st, app)
	case lobby.CmdDequeueFromBattleQueue:
		if s.cfg.Queue == nil || s.cfg.Queue.Dequeue == nil {
			s.logf("stage2 %s: post-flood dequeue — no queue configured", from)
			return nil
		}
		args := int32Args(call.Args, 2)
		was := s.cfg.Queue.Dequeue(st.accountID)
		s.logf("stage2 %s: post-flood dequeue (was queued %v)", from, was)
		var qt uint8
		if len(args) > 0 {
			qt = uint8(args[0])
		}
		app, err := s.accountCall("onDequeued", entdef.Value{Kind: entdef.VUint, Uint: uint64(qt)})
		if err != nil {
			s.logf("stage2 %s: onDequeued: %v", from, err)
			return nil
		}
		return s.mintPost(conn, from, st, app)
	case lobby.CmdReqBattleResults:
		// The live server answers with the 1a/5e error small, status 1
		// (the season-select path uses status 0): `[13][tag][1a 5e 05]
		// [req u16 LE][01 00 00]` + footers. We hold no battle history,
		// so the error is the faithful answer, not a stub.
		small, err := lobby.Small{Family: 0x1a, Type: 0x5e, Body: []byte{
			byte(req), byte(req >> 8), 0x01, 0x00, 0x00,
		}}.Encode()
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood battle results (req %d) → 1a/5e error (minted)", from, req)
	case lobby.CmdSetActiveVehSeason:
		// We hold no garage, so answer the genuine failure small the
		// capture shows (~22 ms after the 52B season bundle, flows3-s2
		// idx 1209/1210): `[13][tag][1a 5e 05][req u16 LE][00 00 00]`
		// + footers. req echoes the client's request id (genuine 225).
		small, err := lobby.Small{Family: 0x1a, Type: 0x5e, Body: []byte{
			byte(req), byte(req >> 8), 0x00, 0x00, 0x00,
		}}.Encode()
		if err != nil {
			return err
		}
		app := answerApp(small)
		if err := s.mintPost(conn, from, st, app); err != nil {
			return err
		}
		s.logf("stage2 %s: post-flood season select (req %d) → 1a/5e no-vehicle error (minted)", from, req)
	default:
		// Everything else is recognized but NOT answered: each wants
		// per-account inventory we don't hold. v1-cut: silence beats a
		// wrong-content answer (see §18 honesty layering). The name
		// comes from the shipped AccountCommands.pyc table so the log
		// says which command the client wanted.
		s.logf("stage2 %s: post-flood %s — no answer (v1-cut)", from, cmdLabel(cmd))
	}
	return nil
}

// cmdLabelChat renders a chat command for logs.
func cmdLabelChat(c lobby.ChatCommand) string {
	if n := c.Name(); n != "" {
		return fmt.Sprintf("%s (%d)", n, c.Command)
	}
	return fmt.Sprintf("chat cmd %d", c.Command)
}

// cmdLabel renders an account command id for logs: the shipped name
// when known, else the bare number.
func cmdLabel(cmd uint16) string {
	if n := lobby.CmdName(cmd); n != "" {
		return fmt.Sprintf("%s (%d)", n, cmd)
	}
	return fmt.Sprintf("cmd %d", cmd)
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
	if _, err := conn.WriteToUDP(pkt, to); err != nil {
		return err
	}
	s.resend.track(to.String(), seq, pkt)
	return nil
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
		app := EncodeTickSync(j.tag)
		pkt, err := buildChannelPacket(j.st.blockKey, flagsRel, app, nil, j.seq, j.cumul)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(pkt, j.addr); err != nil {
			continue
		}
		s.resend.track(j.addr.String(), j.seq, pkt)
	}
	// Retransmit reliable packets the client has not acknowledged. This
	// runs on the same sweep as the ticks, so a lost answer is repeated
	// within one cadence of its timeout.
	for _, job := range s.resend.due(now) {
		addr, err := net.ResolveUDPAddr("udp", job.Addr)
		if err != nil {
			continue
		}
		if _, err := conn.WriteToUDP(job.Pkt, addr); err != nil {
			continue
		}
		s.logf("stage2 %s: resent reliable seq %d (%dB)", addr, job.Seq, len(job.Pkt))
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
		app, err := dictApp(s.dictTpl, st.name, st.accountID, st.admittedAt, time.Now())
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
var tickApp = EncodeTickSync(0x3e)
