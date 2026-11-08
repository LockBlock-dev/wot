package login

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// DefaultBulkPayload is the app payload every genuine 1252 B flood frame
// carries: 4 B prefix + 2 B flags + 1223 B payload + 12 B trailer, then
// Blowfish padding to the datagram size.
const DefaultBulkPayload = 1223

// bulkFlags is the flags word the flood's fragment frames use:
// RELIABLE | HAS_SEQUENCE | HAS_CUMULATIVE_ACK | IS_FRAGMENT (0x0078), whose
// trailer is the 12 B (first, last, seq) range.
//
// NOT on-channel: every genuine 1252 B flood frame in the captures carries
// 0x0078, while the entry's own frames carry 0x0478. Setting ON_CHANNEL here
// made our fragments 0x0470 and the client refused the chain.
const bulkFlags = chFlagReliable | chFlagSequence | chFlagCumulAck | chFlagFragment

// FrameSize is the datagram size a payload of n bytes produces: prefix,
// flags, payload, the 12 B fragment trailer, and the Blowfish magic +
// wastage + padding that rounds the cipher input up to a block.
func FrameSize(n int) int {
	// 16 B trailer: [first][last][seq][cumul] — the flags carry SEQ|CUMUL|FRAGMENT.
	pad := (bfBlockSize - ((n + 2 + 16 + 5) % bfBlockSize)) % bfBlockSize
	return 4 + 2 + n + 16 + pad + 5
}

// BuildFrames splits a bundle stream into the stage-2 flood's fragment
// chain: one chain, frames of payloadCap bytes, each encrypted with
// blockKey and prefixed with a fresh 4 B nonce.
//
// The chain's sequence range is [firstSeq, firstSeq+n-1] and every frame
// carries it, which is what lets the client reassemble by position rather
// than by arrival order. The last frame is short when the stream does not
// divide evenly.
func BuildFrames(blockKey string, stream []byte, payloadCap int, firstSeq uint32) ([][]byte, error) {
	return BuildFramesCumul(blockKey, stream, payloadCap, firstSeq, 0)
}

// BuildFramesCumul is BuildFrames with an explicit cumulative ack for the
// fragment trailer's last word.
func BuildFramesCumul(blockKey string, stream []byte, payloadCap int, firstSeq, cumul uint32) ([][]byte, error) {
	if payloadCap <= 0 {
		payloadCap = DefaultBulkPayload
	}
	if len(stream) == 0 {
		return nil, fmt.Errorf("wotlogin: build frames: empty stream")
	}
	count := (len(stream) + payloadCap - 1) / payloadCap
	if count > 1<<16 {
		return nil, fmt.Errorf("wotlogin: build frames: %d fragments is beyond the u16 chain index", count)
	}
	last := firstSeq + uint32(count) - 1

	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		lo := i * payloadCap
		hi := lo + payloadCap
		if hi > len(stream) {
			hi = len(stream)
		}
		payload := stream[lo:hi]

		clear := make([]byte, 0, 2+len(payload)+12)
		var tmp [4]byte
		binary.LittleEndian.PutUint16(tmp[:2], bulkFlags)
		clear = append(clear, tmp[:2]...)
		clear = append(clear, payload...)
		// Trailer order, read off the capture: (first, last, seq, cumul).
		// The flags carry SEQ|CUMUL|FRAGMENT, so the trailer is 16 B — the
		// cumulative ack is the last word.
		binary.LittleEndian.PutUint32(tmp[:], firstSeq)
		clear = append(clear, tmp[:]...)
		binary.LittleEndian.PutUint32(tmp[:], last)
		clear = append(clear, tmp[:]...)
		binary.LittleEndian.PutUint32(tmp[:], firstSeq+uint32(i))
		clear = append(clear, tmp[:]...)
		binary.LittleEndian.PutUint32(tmp[:], cumul)
		clear = append(clear, tmp[:]...)

		enc, err := encryptBlowfish(blockKey, clear)
		if err != nil {
			return nil, fmt.Errorf("wotlogin: build frames: frame %d: %w", i, err)
		}
		var prefix [4]byte
		if _, err := rand.Read(prefix[:]); err != nil {
			return nil, fmt.Errorf("wotlogin: build frames: prefix: %w", err)
		}
		frame := make([]byte, 0, 4+len(enc))
		frame = append(frame, prefix[:]...)
		frame = append(frame, enc...)
		out = append(out, frame)
	}
	return out, nil
}

// ReadFrames is the inverse of BuildFrames: it decrypts a chain of flood
// frames and returns the reassembled stream. It exists so a built bundle
// can be checked against the same reader the server uses on a capture.
func ReadFrames(blockKey string, frames [][]byte) ([]byte, error) {
	type frag struct {
		first, seq uint32
		payload    []byte
	}
	var frags []frag
	for i, f := range frames {
		if len(f) < 4 {
			return nil, fmt.Errorf("wotlogin: read frames: frame %d too short", i)
		}
		clear, err := decryptBlowfish(blockKey, f[4:])
		if err != nil {
			return nil, fmt.Errorf("wotlogin: read frames: frame %d: %w", i, err)
		}
		n := len(clear)
		flags := binary.LittleEndian.Uint16(clear[0:2])
		tr := ChannelTrailerLen(flags)
		if n < 2+tr {
			return nil, fmt.Errorf("wotlogin: read frames: frame %d truncated", i)
		}
		first := binary.LittleEndian.Uint32(clear[n-16 : n-12])
		seq := binary.LittleEndian.Uint32(clear[n-8 : n-4])
		frags = append(frags, frag{first: first, seq: seq, payload: clear[2 : n-tr]})
	}
	// Order by position in the chain, not by arrival.
	for i := 1; i < len(frags); i++ {
		for j := i; j > 0 && frags[j].seq < frags[j-1].seq; j-- {
			frags[j], frags[j-1] = frags[j-1], frags[j]
		}
	}
	var out []byte
	for _, fr := range frags {
		out = append(out, fr.payload...)
	}
	return out, nil
}
