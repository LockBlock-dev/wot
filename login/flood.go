package login

// Stage-2 lobby flood reassembly + small-message taxonomy (genuine EU2
// capture, Sep 27 2026: 511x1252B bulk + 28/36/44/76B smalls, all
// Blowfish-channel decryptable with the login key).
//
// Bulk: S>C 1252B datagrams decrypt to [flags 2][chunk payload][M u32]
// [seq u32][cumul u32]; the channel seq is the chunk id and each
// chunk's datagrams arrive contiguously (audited: 48 runs for 48
// seqs on two captures), so arrival order is bundle order (~625KB
// single shared-memo pickle). The trailer length is additive over the
// channel flag bits (ChannelTrailerLen): 8B on reliable 0x0458, 12B on
// 0x0078, 16B on 0x0478. Strip per-datagram trailers plus the one head
// header per chunk and concatenate.
//
// Smalls: [flags 2][msgs...][trailer] with app IDs 0x13 (tick,
// FIXED-1), 0xFF ([len u32][rid][...]), 0x1a ([type8][len8]: 76
// session dict, 5e counters, 5c queue blob, 5f, 69
// {cache,prevRev,rev,stats}, 51 opaque-43B, 58 empty signal,
// 73 clan-text, 4d tiny, 79 redirect struct — plus 5b,
// the fixed [type8][u32][u32] server-stats reply with NO length),
// method invocation, value opaque), 0x46 ([len u16][declen u32][zlib]
// cPickle). Trailer length from ChannelTrailerLen. Unknown IDs stop
// the walk with the rest preserved
// (EU2-metal carries opaque binary families — bb/68/ce/24/7d-led
// 0478 smalls and a 564B class — mapped later, never dropped).
// Payload bytes never reach logs; this package returns values, it does
// not print them.

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/LockBlock-dev/wot/lobby"
	"io"
	"os"
	"sort"
	"strings"
)

// RecoverLoginKey scans a wotproxy dump for the latest C>S login
// (534B login#1) decryptable under the MITM key and returns the
// session block key for bulk/smalls decrypt. loginAddr optionally
// restricts to one login source (prefix match, "" = any). Last wins.
// The key is ephemeral (dead minutes after the session); it travels
// via key files, never logs (callers print lengths/hashes only).
func RecoverLoginKey(dump []DumpDatagram, mitmPrivPath, srvPubPath, loginAddr string) (string, error) {
	priv, err := LoadRSAPrivateKey(mitmPrivPath)
	if err != nil {
		return "", err
	}
	srv, err := LoadRSAPublicKey(srvPubPath)
	if err != nil {
		return "", err
	}
	for i := len(dump) - 1; i >= 0; i-- {
		d := dump[i]
		if d.Dir != "C>S" || (len(d.Data) != 534 && len(d.Data) != 790 && len(d.Data) != 984) {
			continue
		}
		if loginAddr != "" && !strings.HasPrefix(d.Addr, loginAddr) {
			continue
		}
		_, key, err := MitmPacket(d.Data, priv, srv.Public())
		if err != nil {
			continue
		}
		return key, nil
	}
	return "", fmt.Errorf("wotlogin: no decryptable 534/790/984 login in dump")
}

// WriteKeyFile stores a block key as hex (0600). ReadKeyFile reads
// the first hex line back. Sizes on disk, never values on screen.
func WriteKeyFile(path, key string) error {
	return os.WriteFile(path, []byte(hex.EncodeToString([]byte(key))+"\n"), 0600)
}

// ReadKeyFile reads a hex block key written by WriteKeyFile.
func ReadKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	b, err := hex.DecodeString(line)
	if err != nil {
		return "", fmt.Errorf("wotlogin: key file hex: %w", err)
	}
	return string(b), nil
}

// ReadCEKeyFile reads a CE/wotkeydump-style memory capture: comment
// lines (# …), spaced-hex runs, and the channel key as the FIRST 16 B
// of the LAST valid run (key3.txt's live line trails ASCII memory past
// the key — the game's Blowfish channel slot is exactly 16 B,
// ce/CE_KEY_HUNT.md; lines stripped of # comments decode as runs).
func ReadCEKeyFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var run []byte
	for _, line := range strings.Split(string(raw), "\n") {
		stripped := strings.TrimSpace(line) // CR from CRLF endings
		if i := strings.IndexByte(stripped, '#'); i >= 0 {
			stripped = stripped[:i]
		}
		stripped = strings.ReplaceAll(stripped, " ", "")
		if stripped == "" {
			continue
		}
		b, err := hex.DecodeString(stripped) // scratch var: a bad line never clobbers the last good run
		if err != nil || len(b) == 0 {
			continue // comment fragments / non-hex memory rows
		}
		run = b
	}
	if len(run) == 0 {
		return "", fmt.Errorf("wotlogin: no hex key run in %s", path)
	}
	if len(run) > 16 {
		run = run[:16] // trailing memory rides past the key slot
	}
	return string(run), nil
}

// ReadAnyKeyFile: clean keyfiles first, CE dumps second (both formats
// coexist in captures/).
func ReadAnyKeyFile(path string) (string, error) {
	key, err := ReadKeyFile(path)
	if err == nil && len(key) >= 8 {
		return key, nil
	}
	key, err2 := ReadCEKeyFile(path)
	if err2 != nil {
		return "", fmt.Errorf("wotlogin: key file: %v (last hex err: %v)", err2, err)
	}
	return key, nil
}

// KeyID hashes a block key for logs (lengths/hashes only, never key
// bytes).
func KeyID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// FloodStats counts a reassembly run (sizes only).
type FloodStats struct {
	Frags     int
	FragBytes int
	Skipped   int
}

// ReassembleFrags reassembles the stage-2 bulk bundle: S>C datagrams
// of fragSize on the flow, decrypted with blockKey, grouped by
// channel seq (chunk id) in first-arrival order with cumulative
// stream offsets. Only the group's head datagram carries a chunk
// header, stripped as follows: frag0's 4B ff XX YY 03 (NN=1); the
// standard 8B [13 .. .. .. .. dd 00 NN] (NN explicit); the alternate
// 8B [13 BB 1a .. .. .. .. ..] (NN = BB-base, base voted from the
// dd00 heads: 0x78 Sep 27, 0x51 Sep 17); unrecognized heads strip 8B
// by analogy (single Sep-17 sample, documented heuristic) with NN
// gap-filled from the missing indices in arrival order.
// Continuation payloads append raw. Per-datagram trailer length comes
// from ChannelTrailerLen.
// part is one datagram of a fragment chain: its position within the
// chain (seq - first) and its payload.
//
// A chain is identified by the FIRST sequence number in its range, and
// arrival order is NOT chain order — the capture shows out-of-order
// steps, and concatenating in arrival order scrambles the payload.
type part struct {
	rel uint32
	pay []byte
}

func ReassembleFrags(dump []DumpDatagram, flowSubstr string, fragSize int, blockKey string) (frags []lobby.Frag, offsets []int, st FloodStats, err error) {
	type group struct {
		seq     uint32
		head    []byte // trailer-stripped head payload (header incl.)
		shape   int    // 0=frag0 1=dd00 2=odd 3=unknown
		ddNN    int    // explicit NN (frag0=1, dd00=pay[7])
		oddB    int    // odd-shape pay[1] for base voting
		parts   []part // datagrams of this chain, ordered by rel
		payload []byte // stripped head + raw continuations
	}
	seen := map[uint32]int{} // chain first-seq -> group index
	var groups []group
	off := 0
	for _, d := range dump {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, flowSubstr) || len(d.Data) != fragSize {
			continue
		}
		clear, derr := decryptBlowfish(blockKey, d.Data[4:])
		if derr != nil || len(clear) < 14 {
			st.Skipped++
			continue
		}
		n := len(clear)
		flags := binary.LittleEndian.Uint16(clear[0:2])
		tr := ChannelTrailerLen(flags)
		if len(clear) < 2+tr {
			st.Skipped++
			continue
		}
		// IS_FRAGMENT (0x0020) puts an 8-byte (first, last) sequence
		// range at the front of the trailer, ahead of the packet's own
		// seq. Without it the packet is its own single-fragment chain.
		first := binary.LittleEndian.Uint32(clear[n-8 : n-4])
		seq := first
		if flags&chFlagFragment != 0 && tr >= 12 {
			first = binary.LittleEndian.Uint32(clear[n-12 : n-8])
			seq = binary.LittleEndian.Uint32(clear[n-4:])
		}
		pay := clear[2 : n-tr]
		if fi, ok := seen[first]; ok {
			groups[fi].parts = append(groups[fi].parts, part{rel: seq - first, pay: pay})
			st.Frags++
			continue
		}
		g := group{seq: first, shape: 3, parts: []part{{rel: seq - first, pay: pay}}}
		switch {
		case len(pay) >= 4 && pay[0] == 0xFF && pay[3] == 0x03:
			g.shape, g.ddNN = 0, 1
		case len(pay) >= 8 && pay[5] == 0xDD && pay[6] == 0x00:
			g.shape = 1
			// NN validity window 1..128 is a LOCAL sanity bound
			// (observed bundles run 40-48 chunks; 128 caps a
			// corrupt pay[7] from forging phantom chunks), not a
			// wire constant.
			if nn := int(pay[7]); nn >= 1 && nn <= 128 {
				g.ddNN = nn
			}
			g.oddB = int(pay[1])
		case len(pay) >= 8 && pay[0] == 0x13 && pay[2] == 0x1A:
			g.shape = 2
			g.oddB = int(pay[1])
		}
		seen[first] = len(groups)
		groups = append(groups, g)
		st.Frags++
	}
	if len(groups) == 0 {
		return nil, nil, st, fmt.Errorf("wotlogin: no bulk fragments for %q", flowSubstr)
	}
	// Vote the odd-shape base from dd00 heads (pay[1]-NN must agree).
	votes := map[int]int{}
	for _, g := range groups {
		if g.shape == 1 && g.ddNN > 0 {
			votes[g.oddB-g.ddNN]++
		}
	}
	base, best := 0, 1
	for b, c := range votes {
		if c > best {
			base, best = b, c
		}
	}
	// Order every chain by its fragment index, then take the head from
	// the first fragment.
	for i := range groups {
		g := &groups[i]
		sort.SliceStable(g.parts, func(a, b int) bool { return g.parts[a].rel < g.parts[b].rel })
		g.head = g.parts[0].pay
		g.payload = nil
		for _, pt := range g.parts[1:] {
			g.payload = append(g.payload, pt.pay...)
		}
	}
	// Strip heads, fill NN gaps in arrival order.
	known := map[int]bool{}
	for i := range groups {
		g := &groups[i]
		var nn int
		body := g.head
		switch g.shape {
		case 0:
			nn, body = 1, g.head[4:]
		case 1:
			nn, body = g.ddNN, g.head[8:]
		case 2:
			if base != 0 {
				// Same 1..128 local sanity bound as above.
				if n := g.oddB - base; n >= 1 && n <= 128 {
					nn = n
				}
			}
			body = g.head[8:]
		default:
			body = g.head
			if len(body) >= 8 {
				body = body[8:]
			}
		}
		g.payload = append(append([]byte(nil), body...), g.payload...)
		groups[i].ddNN = nn // reuse as final NN pre-gap-fill
		if nn > 0 {
			known[nn] = true
		}
	}
	maxNN := 0
	for nn := range known {
		if nn > maxNN {
			maxNN = nn
		}
	}
	next := 1
	for i := range groups {
		if groups[i].ddNN == 0 {
			for next <= maxNN && known[next] {
				next++
			}
			if next <= maxNN {
				groups[i].ddNN = next
				known[next] = true
			}
		}
	}
	off = 0
	for _, g := range groups {
		offsets = append(offsets, off)
		off += len(g.payload)
		frags = append(frags, lobby.Frag{Seq: g.seq, NN: g.ddNN, Payload: g.payload})
	}
	st.FragBytes = off
	return frags, offsets, st, nil
}

// ReassembleBulk concatenates the stage-2 bulk bundle: S>C datagrams
// of fragSize on the relay flow, decrypted with blockKey, stripped of
// flags(2)+seq/cumul(8), in arrival order. Returns the app stream.
func ReassembleBulk(dump []DumpDatagram, flowSubstr string, fragSize int, blockKey string) ([]byte, FloodStats, error) {
	var st FloodStats
	var app []byte
	for _, d := range dump {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, flowSubstr) || len(d.Data) != fragSize {
			continue
		}
		clear, err := decryptBlowfish(blockKey, d.Data[4:])
		if err != nil || len(clear) < 12 {
			st.Skipped++
			continue
		}
		trailer := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
		if len(clear) < 2+trailer {
			st.Skipped++
			continue
		}
		app = append(app, clear[2:len(clear)-trailer]...)
		st.Frags++
	}
	st.FragBytes = len(app)
	if len(app) == 0 {
		return nil, st, fmt.Errorf("wotlogin: no bulk fragments for %q", flowSubstr)
	}
	return app, st, nil
}

// BulkStream strips the frag0 bundle header ([ff XX YY 03], present
// once at the stream head) to the raw shared-memo pickle stream.
// Pass-through when absent (never fails).
func BulkStream(app []byte) []byte {
	if len(app) >= 4 && app[0] == 0xFF && app[3] == 0x03 {
		return app[4:]
	}
	return app
}

// ChunkHarvest is the per-chunk harvest result: each chunk walked in
// isolation with FRESH decoder state (memo/stack never span chunks).
// Chunk 1 is a TRUNCATED shared-memo pickle (no STOP in-chunk), so the
// harvest is prefix SALVAGE — closed containers before the first noise
// site via lobby.DecodePrefix — not STOP docs. Counts are schema key NAMES
// only.
type ChunkHarvest struct {
	NN       int
	Seq      uint32
	Bytes    int
	Prefix   int // valid-opcode prefix bytes before the noise site
	Stack    int // closed salvage stack items
	Distinct int
	Top      string // most-frequent key name ("" when none)
	TopN     int
}

// HarvestChunks salvages each frag payload in isolation and returns
// one result per chunk in input order. Chunk 1 of the lobby flood
// harvests to the schema map (dozens of keys up to its first noise
// site); chunks 2+ are second-layer-or-pad (near-random): they salvage
// to ~0 keys by design, which is the verdict — not a failure. The one
// exception is the standalone session dict riding a chunk head
// (flows3 nn=13: databaseID,token in 42B).
func HarvestChunks(frags []lobby.Frag) []ChunkHarvest {
	out := make([]ChunkHarvest, 0, len(frags))
	for _, fr := range frags {
		stk, n, _ := lobby.DecodePrefix(fr.Payload)
		counts := map[string]int{}
		for _, s := range stk {
			lobby.HarvestKeys(s, counts)
		}
		ch := ChunkHarvest{NN: fr.NN, Seq: fr.Seq, Bytes: len(fr.Payload), Prefix: n, Stack: len(stk), Distinct: len(counts)}
		for k, v := range counts {
			if v > ch.TopN {
				ch.Top, ch.TopN = k, v
			}
		}
		out = append(out, ch)
	}
	return out
}

// Entity-burst framing (flows3, 28x116B S>C on the stage-2 flow,
// Sep-28): flags 0478 + 88B packed-entity-opaque bodies. No plaintext
// framing (first bytes all distinct, bodies high-entropy); only the
// tail is structured: [counter u16 LE][0000] with the counter stepping
// exactly +9 per datagram in arrival order (249,258,… on flows3).
// Login-key plaintext (magic-validated decrypt), not pickle/zlib/
// double-wrap/deflate. Content stays parked as opaque; this parser
// validates the envelope and returns the counter series (structure
// only — never body bytes).
const entityBurstBodyLen = 88

// EntityBurstStep is the tail-counter step between consecutive burst
// datagrams (pinned on flows3: 27/27 deltas == 9).
const EntityBurstStep = 9

// ParseEntityBurst validates 88B burst bodies in arrival order and
// returns the tail-counter series. It errors on short bodies, nonzero
// tail words, or off-step counters — any of which means the capture
// is not the pinned burst shape.
func ParseEntityBurst(bodies [][]byte) ([]uint16, error) {
	out := make([]uint16, 0, len(bodies))
	for i, b := range bodies {
		if len(b) != entityBurstBodyLen {
			return nil, fmt.Errorf("wotlogin: entity burst body %d len=%d, want %d", i, len(b), entityBurstBodyLen)
		}
		if b[86] != 0 || b[87] != 0 {
			return nil, fmt.Errorf("wotlogin: entity burst body %d tail=%02x%02x, want 0000", i, b[86], b[87])
		}
		c := binary.LittleEndian.Uint16(b[84:86])
		if i > 0 && int(c)-int(out[i-1]) != EntityBurstStep {
			return nil, fmt.Errorf("wotlogin: entity burst counter step %d -> %d, want +%d", out[i-1], c, EntityBurstStep)
		}
		out = append(out, c)
	}
	return out, nil
}

// CensusEntityBursts collects the S>C 116B burst bodies on the flow:
// decrypt with blockKey, strip flags(2)+12B trailer (0478 carries
// bit5), validate the envelope via ParseEntityBurst. Returns the
// counter series and datagram/skip counts (sizes only).
func CensusEntityBursts(dump []DumpDatagram, flowSubstr, blockKey string) (counters []uint16, datagrams, skipped int, err error) {
	var bodies [][]byte
	for _, d := range dump {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, flowSubstr) || len(d.Data) != 116 {
			continue
		}
		clear, derr := decryptBlowfish(blockKey, d.Data[4:])
		if derr != nil || len(clear) < 2+12+entityBurstBodyLen {
			skipped++
			continue
		}
		trailer := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
		body := clear[2 : len(clear)-trailer]
		if len(body) != entityBurstBodyLen {
			skipped++
			continue
		}
		bodies = append(bodies, append([]byte(nil), body...))
		datagrams++
	}
	if len(bodies) == 0 {
		return nil, datagrams, skipped, fmt.Errorf("wotlogin: no 116B burst datagrams for %q", flowSubstr)
	}
	counters, err = ParseEntityBurst(bodies)
	if err != nil {
		return nil, datagrams, skipped, err
	}
	return counters, datagrams, skipped, nil
}

// SmallStat is one (ID, type) census row over small datagrams:
// counts and first-decode shape only — never values.
type SmallStat struct {
	ID      byte
	Type    byte // 0x1a subtype, else 0
	Count   int
	NLens   int // distinct body lengths
	Decoded int // bodies lobby.DecodeAt accepted (1a/46 only)
	Summary string
}

// CensusSmalls walks S>C non-bulk datagrams on the flow and classifies
// each via ClassifySmalls. Datagrams that fail decrypt/framing count
// as skipped, never fatal (mixed flows carry foreign traffic).
func CensusSmalls(dump []DumpDatagram, flowSubstr string, fragSize int, blockKey string) ([]SmallStat, FloodStats, error) {
	var st FloodStats
	rows := map[[2]byte]*SmallStat{}
	lens := map[[2]byte]map[int]bool{}
	for _, d := range dump {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, flowSubstr) || len(d.Data) == fragSize {
			continue
		}
		msgs, _, err := ClassifySmalls(d.Data, blockKey)
		if err != nil {
			st.Skipped++
			continue
		}
		st.Frags++
		for _, m := range msgs {
			k := [2]byte{m.ID, m.Type}
			r := rows[k]
			if r == nil {
				r = &SmallStat{ID: m.ID, Type: m.Type}
				rows[k] = r
				lens[k] = map[int]bool{}
			}
			r.Count++
			lens[k][m.Length] = true
			if m.ID != 0x1a && m.ID != 0x46 {
				continue
			}
			// DecodeAt's 15-byte scan cap is a LOCAL parse budget
			// (small bodies open with framing bytes, so a doc
			// starting past 15 is noise for census purposes),
			// not a wire constant.
			v, _, _, err := lobby.DecodeAt(m.Body, 15)
			if err != nil {
				continue
			}
			if r.Summary == "" {
				r.Summary = lobby.PickleSummary(v)
			}
			r.Decoded++
		}
	}
	var out []SmallStat
	for k, r := range rows {
		r.NLens = len(lens[k])
		out = append(out, *r)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].ID < out[i].ID || (out[j].ID == out[i].ID && out[j].Type < out[i].Type) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, st, nil
}

// SmallMsg is one classified stage-2 small message (header only;
// bodies stay opaque except zlib-inflated 0x46).
type SmallMsg struct {
	ID     byte
	Type   byte // 0x1a subtype, else 0
	Length int
	Body   []byte // raw body (0x46: inflated)
}

// ClassifySmalls decrypts one S>C small datagram and splits its app
// messages by ID. Trailer length comes from ChannelTrailerLen. Unknown
// IDs stop the walk (returned as rest, not an error — the EU2-metal
// taxonomy is still being mapped). Truncation of known framing errors.
func ClassifySmalls(pkt []byte, blockKey string) (msgs []SmallMsg, rest []byte, err error) {
	if len(pkt) < 4+8 {
		return nil, nil, fmt.Errorf("wotlogin: small too short (%d B)", len(pkt))
	}
	clear, err := decryptBlowfish(blockKey, pkt[4:])
	if err != nil {
		return nil, nil, err
	}
	trailer := 0
	if len(clear) >= 2 {
		trailer = ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
	}
	if len(clear) < 2+trailer {
		return nil, nil, fmt.Errorf("wotlogin: small cleartext too short (%d B)", len(clear))
	}
	body := clear[2 : len(clear)-trailer]
	var out []SmallMsg
	for len(body) > 0 {
		id := body[0]
		switch id {
		case 0xFF: // reply: [len u32][rid u32][payload...]
			if len(body) < 9 {
				return out, body, fmt.Errorf("wotlogin: truncated ff head")
			}
			ln := int(binary.LittleEndian.Uint32(body[1:5]))
			if len(body) < 5+ln {
				return out, body, fmt.Errorf("wotlogin: truncated ff body")
			}
			out = append(out, SmallMsg{ID: id, Length: ln, Body: append([]byte(nil), body[5:5+ln]...)})
			body = body[5+ln:]
		case 0x13: // tick, FIXED-1
			if len(body) < 2 {
				return out, body, fmt.Errorf("wotlogin: truncated tick")
			}
			out = append(out, SmallMsg{ID: id, Length: 1, Body: append([]byte(nil), body[1:2]...)})
			body = body[2:]
		case 0x1a: // [type8][len8][payload], except 0x5b: the
			// server-stats reply is fixed [type8][u32][u32] with NO
			// length — the len8 position carries the low counter byte
			// (Oct-01 session: 30/30 poll answers tick + 1a/5b + 8B,
			// two slow-drifting counters ~54k/~124k).
			if len(body) < 3 {
				return out, body, fmt.Errorf("wotlogin: truncated 1a head")
			}
			if body[1] == 0x5b {
				if len(body) < 2+8 {
					return out, body, fmt.Errorf("wotlogin: truncated 1a/5b body")
				}
				out = append(out, SmallMsg{ID: id, Type: body[1], Length: 8, Body: append([]byte(nil), body[2:10]...)})
				body = body[10:]
				continue
			}
			ln := int(body[2])
			if len(body) < 3+ln {
				return out, body, fmt.Errorf("wotlogin: truncated 1a body (%d < %d)", len(body)-3, ln)
			}
			out = append(out, SmallMsg{ID: id, Type: body[1], Length: ln, Body: append([]byte(nil), body[3:3+ln]...)})
			body = body[3+ln:]
		case 0x45: // [len u8][payload] (EU2-metal smalls use u8
			// lengths throughout; pinned empirically)
			if len(body) < 2 {
				return out, body, fmt.Errorf("wotlogin: truncated 45 head")
			}
			ln := int(body[1])
			if len(body) < 2+ln {
				return out, body, fmt.Errorf("wotlogin: truncated 45 body")
			}
			out = append(out, SmallMsg{ID: id, Length: ln, Body: append([]byte(nil), body[2:2+ln]...)})
			body = body[2+ln:]
		case 0x46: // zlib cPickle: [len u16][declen u32][zlib]
			// (pinned empirically: length covers declen+zlib,
			// declen must equal the inflated size).
			if len(body) < 7 {
				return out, body, fmt.Errorf("wotlogin: truncated 46 head")
			}
			ln := int(binary.LittleEndian.Uint16(body[1:3]))
			if len(body) < 3+ln {
				return out, body, fmt.Errorf("wotlogin: truncated 46 body")
			}
			raw := body[3 : 3+ln]
			if len(raw) < 4 {
				return out, body, fmt.Errorf("wotlogin: truncated 46 declen")
			}
			want := int(binary.LittleEndian.Uint32(raw[:4]))
			zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
			if err != nil {
				return out, body, fmt.Errorf("wotlogin: 46 zlib open: %w", err)
			}
			inflated, err := io.ReadAll(zr)
			zr.Close()
			if err != nil {
				return out, body, fmt.Errorf("wotlogin: 46 zlib inflate: %w", err)
			}
			if len(inflated) != want {
				return out, body, fmt.Errorf("wotlogin: 46 declen %d != inflated %d", want, len(inflated))
			}
			out = append(out, SmallMsg{ID: id, Length: len(inflated), Body: inflated})
			body = body[3+ln:]
		default:
			return out, body, nil
		}
	}
	return out, nil, nil
}
