package lobby

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

// Battle chat, both directions. Two record classes carry it, one per
// direction (28 messages over 6 of the 16 proxy dumps; the Oct-31
// 2.4.1.0 nine-battle session is the only one with both directions
// and the only one with own submits):
//
//	C>S submit — a bare record in the `[02][key4]` bundle, framed
//	like every other C>S record: `[9d][len16le][payload]`.
//
//	S>C relay — a type-0x75 small, `[1a][75][len8][payload]`, the
//	same family as the marker records (ScanBattleMarkers, which
//	skips this subtype).
//
// Both payloads are one 24-byte header plus `[u8 len][text][u16 0]`:
//
//	[u16 eventType][u16 seq][u32 channel][u32 sender][u32 0]
//	[f64 time][u8 len][text][u16 0]
//
// eventType is 22 on submit and 23 on relay; the submit side leaves
// sender and time zero and the server fills them in the relay. sender
// is the speaker's arena entity ID — the Oct-31 value 0x016800ae is
// the arena login name in the client's handshake and
// the position trailer's own entity. time is a float64 unix timestamp
// in UTC: 1793453981.713 decodes to 2026-10-31T13:39:41.713Z, 28 ms
// before the relay packet that carries it. channel is 0 in all 28
// samples (battle-all); an ALL/TEAM split is unproven.
//
// The auto-spot callouts ("Im Spotted at F6!") ride the same relay, so
// a consumer cannot tell them from typed chat by shape alone.
const (
	// BattleChatSubC2S is the C>S record tag carrying a chat submit.
	BattleChatSubC2S = 0x9d
	// BattleChatEventC2S is the submit eventType.
	BattleChatEventC2S = 22
	// BattleChatEventS2C is the relay eventType (the 0x75 subtype).
	BattleChatEventS2C = 23
	// BattleChatHeadLen is the fixed header length before the text.
	BattleChatHeadLen = 24
	// BattleChatMaxText bounds the length-prefixed text (u8 length).
	BattleChatMaxText = 255
)

// BattleChat is one decoded battle chat message.
type BattleChat struct {
	// Seq is the submit-side counter (7 then 8 on the two live
	// submits); always 0 on a relay.
	Seq uint16
	// Channel is 0 in every sample (battle-all).
	Channel uint32
	// Sender is the speaker's arena entity ID; 0 on a submit.
	Sender uint32
	// Time is the server send time (UTC); zero on a submit.
	Time time.Time
	// Text is the message body.
	Text string
	// Outgoing is true for our own submit (C>S), false for a relay.
	Outgoing bool
}

// plausibleChatTime bounds the relay timestamp to 2001..2096 so a
// chance record cannot pass on a garbage double.
func plausibleChatTime(sec float64) bool {
	return sec > 1e9 && sec < 4e9
}

// parseBattleChat decodes one chat payload. outgoing selects the
// direction's eventType and the field expectations that go with it
// (a submit carries no sender and no time; a relay carries both).
func parseBattleChat(pay []byte, outgoing bool) (BattleChat, bool) {
	var c BattleChat
	if len(pay) < BattleChatHeadLen+3 {
		return c, false
	}
	want := uint16(BattleChatEventS2C)
	if outgoing {
		want = BattleChatEventC2S
	}
	if binary.LittleEndian.Uint16(pay[0:2]) != want {
		return c, false
	}
	c.Seq = binary.LittleEndian.Uint16(pay[2:4])
	c.Channel = binary.LittleEndian.Uint32(pay[4:8])
	c.Sender = binary.LittleEndian.Uint32(pay[8:12])
	if binary.LittleEndian.Uint32(pay[12:16]) != 0 {
		return c, false
	}
	sec := math.Float64frombits(binary.LittleEndian.Uint64(pay[16:24]))
	n := int(pay[BattleChatHeadLen])
	if BattleChatHeadLen+1+n+2 != len(pay) || n == 0 {
		return c, false
	}
	txt := pay[BattleChatHeadLen+1 : BattleChatHeadLen+1+n]
	if pay[BattleChatHeadLen+1+n] != 0 || pay[BattleChatHeadLen+2+n] != 0 {
		return c, false
	}
	if !utf8.Valid(txt) {
		return c, false
	}
	for _, b := range txt {
		if b < 0x20 || b == 0x7f {
			return c, false
		}
	}
	if outgoing {
		if c.Sender != 0 || c.Channel != 0 {
			return c, false
		}
		if sec != 0 && !plausibleChatTime(sec) {
			return c, false
		}
	} else {
		if c.Sender == 0 || c.Channel != 0 || !plausibleChatTime(sec) {
			return c, false
		}
	}
	if sec != 0 {
		s := int64(sec)
		c.Time = time.Unix(s, int64((sec-float64(s))*1e9)).UTC()
	}
	c.Text = string(txt)
	c.Outgoing = outgoing
	return c, true
}

// ScanBattleChatC2S extracts chat submits from one decrypted C>S
// battle app body. Scans rather than walks: the record chain is not
// walkable end to end (implicitly-framed records between args and
// trailer), and the payload validation is strict enough that a chance
// 0x9d byte cannot pass.
func ScanBattleChatC2S(app []byte) []BattleChat {
	var out []BattleChat
	for o := 0; o+3 <= len(app); o++ {
		if app[o] != BattleChatSubC2S {
			continue
		}
		ln := int(binary.LittleEndian.Uint16(app[o+1 : o+3]))
		if ln < BattleChatHeadLen+3 || o+3+ln > len(app) {
			continue
		}
		if c, ok := parseBattleChat(app[o+3:o+3+ln], true); ok {
			out = append(out, c)
		}
	}
	return out
}

// ScanBattleChatS2C extracts chat relays from one decrypted S>C battle
// app body (`[1a][75][len8][payload]` records).
func ScanBattleChatS2C(app []byte) []BattleChat {
	var out []BattleChat
	for o := 0; o+3 <= len(app); o++ {
		if app[o] != BattleTrailerTag || app[o+1] != MarkerSmall {
			continue
		}
		ln := int(app[o+2])
		if ln < BattleChatHeadLen+3 || o+3+ln > len(app) {
			continue
		}
		if c, ok := parseBattleChat(app[o+3:o+3+ln], false); ok {
			out = append(out, c)
		}
	}
	return out
}

// appendTrailer appends the 29B position trailer (see ParseTrailer).
func appendTrailer(app []byte, tr Trailer) []byte {
	app = append(app, BattleTrailerTag, 0x1a, 0x00)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], tr.Entity)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], tr.Nonce)
	app = append(app, tmp[:]...)
	for _, f := range [4]float32{tr.Speed, tr.X, tr.Y, tr.Z} {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		app = append(app, tmp[:]...)
	}
	return append(app, tr.Tail[0], tr.Tail[1])
}

// BuildBattleChat emits the C>S chat submit bundle: `[02][key4]
// [9d][len16][payload]` + the 29B position trailer, mirroring
// BuildShootTrigger. The submit header is all zero (sender and time
// are the server's to fill in the relay); seq is the caller's
// per-session counter. The trailer is the client's own position
// report, which every observed submit carried — the server answers
// with the relay, not an ack.
func BuildBattleChat(key4 [BattleKeyLen]byte, seq uint16, text string, tr Trailer) []byte {
	if len(text) > BattleChatMaxText {
		text = text[:BattleChatMaxText]
	}
	pay := make([]byte, BattleChatHeadLen, BattleChatHeadLen+1+len(text)+2)
	binary.LittleEndian.PutUint16(pay[0:], BattleChatEventC2S)
	binary.LittleEndian.PutUint16(pay[2:], seq)
	pay = append(pay, byte(len(text)))
	pay = append(pay, text...)
	pay = append(pay, 0, 0)

	app := make([]byte, 0, BattleHeadLen+3+len(pay)+BattleTrailerLen)
	app = append(app, BattleC2SHead0)
	app = append(app, key4[:]...)
	app = append(app, BattleChatSubC2S, byte(len(pay)), byte(len(pay)>>8))
	app = append(app, pay...)
	return appendTrailer(app, tr)
}

// ObserveChat formats one chat row. A relay names the speaker from the
// battle roster; a submit is our own and carries no sender.
func (o *Observer) ObserveChat(at time.Time, c BattleChat) string {
	el, rt := o.elapsed(at)
	if c.Outgoing {
		return fmt.Sprintf("[%s] [%02d:%02d] CHAT (you) %q", rt, el/60, el%60, c.Text)
	}
	nm, tank := "?", "?"
	if d, ok := o.Ents[c.Sender]; ok {
		nm, tank = d.Name, d.Tank
	}
	return fmt.Sprintf("[%s] [%02d:%02d] %s %s [%s] CHAT %q",
		rt, el/60, el%60, o.side(c.Sender), nm, tank, c.Text)
}
