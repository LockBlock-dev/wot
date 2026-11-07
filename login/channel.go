package login

import "encoding/binary"

// Mercury channel flag bits (WoT fork) and the footer-length rule they
// drive.
//
// The fork keeps the classic BigWorld bit layout for most flags but
// re-assigns two of them: 0x0010 is RELIABLE (not HAS_SEQUENCE) and
// 0x0040 is HAS_SEQUENCE. That is forced by the two pinned stage-1
// shapes in baseapp.go — flagsRel 0x0458 = ON|RELIABLE|SEQ|CUMUL and
// flagsUnrel 0x1448 = ON|SEQ|CUMUL|AUX — which only work if 0x10 is
// RELIABLE and 0x40 is SEQ.
const (
	chFlagOnChannel uint16 = 0x0008 // ON_CHANNEL
	chFlagReliable  uint16 = 0x0010 // RELIABLE (fork: not HAS_SEQUENCE)
	chFlagFragment  uint16 = 0x0020 // IS_FRAGMENT: 8B (first,last) seq range
	chFlagSequence  uint16 = 0x0040 // HAS_SEQUENCE (fork: not RELIABLE)
	chFlagRequests  uint16 = 0x0001 // HAS_REQUESTS: 2B first-request offset
	chFlagCumulAck  uint16 = 0x0400 // HAS_CUMULATIVE_ACK
	chFlagAux       uint16 = 0x1000 // AUX: unreliable reliable-send counter
)

// ChannelTrailerLen returns the byte count of the channel footers that
// follow the message stream in a decrypted channel datagram (the 2B
// flags word is not counted). The length is additive over the flag
// bits, which is what makes it derivable instead of guessed:
//
//	4B  HAS_SEQUENCE
//	4B  HAS_CUMULATIVE_ACK
//	4B  AUX
//	8B  IS_FRAGMENT (first,last sequence range)
//	2B  HAS_REQUESTS (first-request offset)
//
// Verified against every flags word observed in the Oct-31 EU2 battle
// capture (2806 S>C + 216 C>S datagrams, seq monotonicity + message
// walk):
//
//	0x0458 ->  8   ON|REL|SEQ|CUMUL
//	0x1448 -> 12   ON|SEQ|CUMUL|AUX
//	0x0078 -> 12   ON|REL|SEQ|FRAG
//	0x0478 -> 16   ON|REL|SEQ|FRAG|CUMUL
//	0x0058 ->  4   ON|REL|SEQ
//	0x045a ->  8   ON|REL|SEQ|CUMUL|0x02
//	0x144c -> 12   ON|SEQ|CUMUL|AUX|0x04
//
// The previous rule (12B when HAS_REQUESTS, else 8B) matched only
// 0x0458/0x0078/0x045a: it under-counted 0x0478 by 4B, over-counted
// 0x0058 by 4B and under-counted 0x1448/0x144c by 4B.
//
// The intra-trailer ORDER is a separate question and is not settled
// here; see docs/NETWORK_PROTOCOL.md §3.
func ChannelTrailerLen(flags uint16) int {
	n := 0
	if flags&chFlagSequence != 0 {
		n += 4
	}
	if flags&chFlagCumulAck != 0 {
		n += 4
	}
	if flags&chFlagAux != 0 {
		n += 4
	}
	if flags&chFlagFragment != 0 {
		n += 8
	}
	return n
}

// fragRange reads a fragment frame's [first,last] range and its seq.
// The trailer is [first][last][seq][cumul], so the range sits at n-tr and
// the seq is the 4 bytes before cumul when CUMUL is set.
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
