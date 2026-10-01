// Package wotplay reads World of Tanks .wotreplay files: container
// framing, battle-setup JSON, and the encrypted battle stream.
//
// Verified container layout (vbaddict spec, confirmed on 2.0.0.0 /
// 2.3.1.0 / 2.4.0.0 replays Sep 2026):
//
//	[magic u32 = 0x11343212][block count u32]
//	([u32 len][data] * count; first = setup JSON, rest = extra JSONs)
//	[encrypted battle stream]
//
// The stream decrypts as: skip 8 bytes, Blowfish-ECB per 8-byte block,
// XOR each block with the previous PLAINTEXT block (same ECB+XOR-chain
// shape as the LoginApp session decrypt), then a single zlib inflate
// over the whole decrypted buffer (~5.3 MB of battle packets for a
// full 2.4 battle).
//
// The stream key is community-published (Phalynx/WoT-Replay-To-JSON,
// crediting benvanstaveren/marklr) and verified here against genuine
// replays (TestDecryptProhorovka decrypts to a valid zlib stream). It
// was NOT found verbatim in win64/WorldOfTanks.exe — not contiguous,
// not in halves, not single-byte-XORed, not nibble-swapped, not
// md5-of-any-obvious-string — so the client runtime-constructs or
// obfuscates it; the test is the proof, not the provenance.
//
// Packet-level parsing lives in packets.go (framing), dispatch.go
// (positions/methods/entity table), values.go (typed args) and
// events.go (damage/health/shot extraction).
package replay

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/blowfish"
)

// StreamKey is the fixed Blowfish key for the battle stream (16 B).
var StreamKey = []byte{0xDE, 0x72, 0xBE, 0xA0, 0xDE, 0x04, 0xBE, 0xB1, 0xDE, 0xFE, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF}

// HeaderLen is the fixed file-header size: magic + block count.
const HeaderLen = 8

// Magic is the replay signature all BigWorld replays start with.
var Magic = []byte{0x12, 0x32, 0x34, 0x11}

// SkipLen is the number of encrypted bytes skipped before decryption
// (the stream's first block is a header, not zlib data).
const SkipLen = 8

// Replay is a parsed .wotreplay file.
type Replay struct {
	Header   []byte         // 8 B file header as stored
	Meta     map[string]any // first-block battle-setup JSON
	SetupRaw []byte         // first-block bytes verbatim
	Extra    []any          // remaining JSON blocks (old files: results)
	ExtraRaw [][]byte       // remaining JSON blocks verbatim
	Stream   []byte         // decrypted + inflated battle packets
}

// MetaField reads a top-level string field from the setup JSON.
func (r *Replay) MetaField(key string) string {
	s, _ := r.Meta[key].(string)
	return s
}

// BlocksRaw returns all JSON blocks verbatim (setup + extras). The
// stream's tail MD5 covers exactly this concatenation (proven on
// 1-block 2.3/2.4 and 2-block 2.0/2.1 files).
func (r *Replay) BlocksRaw() []byte {
	out := append([]byte{}, r.SetupRaw...)
	for _, b := range r.ExtraRaw {
		out = append(out, b...)
	}
	return out
}

// VersionType is the version-record packet type (0x18): [u32 len][ascii].
const VersionType = 0x18

// ClientVersion returns the recording client's version ("2.4.0.0")
// from the stream's version record, "" when absent.
func (r *Replay) ClientVersion() string {
	pkts, err := Packets(r.Stream)
	if err != nil {
		return ""
	}
	for _, p := range pkts {
		if p.Type != VersionType || len(p.Data) < 4 {
			continue
		}
		n := int(binary.LittleEndian.Uint32(p.Data[:4]))
		if n < 0 || 4+n > len(p.Data) {
			continue
		}
		return string(p.Data[4 : 4+n])
	}
	return ""
}

// decrypt runs the battle-stream decrypt: Blowfish-ECB per block with
// plaintext chaining (block[i] ^= plain[i-1]).
func decrypt(key, src []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("wotreplay: key must be 16 bytes, got %d", len(key))
	}
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wotreplay: blowfish: %w", err)
	}
	n := len(src) / 8 * 8
	dst := make([]byte, n)
	for i := 0; i < n; i += 8 {
		c.Decrypt(dst[i:i+8], src[i:i+8])
	}
	var prev []byte
	for i := 0; i < n; i += 8 {
		if prev != nil {
			for j := 0; j < 8; j++ {
				dst[i+j] ^= prev[j]
			}
		}
		prev = append(prev[:0], dst[i:i+8]...)
	}
	return dst, nil
}

// Open reads, decrypts, and inflates path.
func Open(path string) (*Replay, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wotreplay: read: %w", err)
	}
	return Parse(raw)
}

// Parse decodes a .wotreplay container already in memory: magic,
// block count, then [u32 len][data] blocks (first = setup JSON,
// rest = extra JSONs), then the encrypted battle stream.
func Parse(raw []byte) (*Replay, error) {
	if len(raw) < HeaderLen+4 {
		return nil, fmt.Errorf("wotreplay: %d bytes too short", len(raw))
	}
	if !bytes.Equal(raw[:4], Magic) {
		return nil, fmt.Errorf("wotreplay: bad magic %x", raw[:4])
	}
	r := &Replay{Header: append([]byte{}, raw[:HeaderLen]...)}
	count := int(binary.LittleEndian.Uint32(raw[4:8]))
	off := HeaderLen
	var blocks [][]byte
	for i := 0; i < count && off+4 <= len(raw); i++ {
		ln := int(binary.LittleEndian.Uint32(raw[off : off+4]))
		off += 4
		if ln < 0 || off+ln > len(raw) {
			return nil, fmt.Errorf("wotreplay: block %d len %d overruns", i, ln)
		}
		blocks = append(blocks, raw[off:off+ln])
		off += ln
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("wotreplay: no data blocks")
	}
	dec := json.NewDecoder(bytes.NewReader(blocks[0]))
	dec.UseNumber()
	if err := dec.Decode(&r.Meta); err != nil {
		return nil, fmt.Errorf("wotreplay: setup JSON: %w", err)
	}
	r.SetupRaw = append([]byte{}, blocks[0]...)
	for _, b := range blocks[1:] {
		var v any
		if len(b) > 0 {
			if err := json.Unmarshal(b, &v); err != nil {
				return nil, fmt.Errorf("wotreplay: extra JSON: %w", err)
			}
		}
		r.Extra = append(r.Extra, v)
		r.ExtraRaw = append(r.ExtraRaw, append([]byte{}, b...))
	}
	blob := raw[off:]
	if len(blob) < SkipLen+8 {
		return nil, fmt.Errorf("wotreplay: %d-byte stream too short", len(blob))
	}
	clear, err := decrypt(StreamKey, blob[SkipLen:])
	if err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(clear))
	if err != nil {
		return nil, fmt.Errorf("wotreplay: zlib open (wrong key?): %w", err)
	}
	defer zr.Close()
	r.Stream, err = io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("wotreplay: zlib inflate: %w", err)
	}
	return r, nil
}
