package lobby

// Offline battle-chat tests: pinned genuine wire vectors (Oct-31
// 2.4.1.0 nine-battle session, flow key bf74b738, decrypted with the
// session login key) plus synthetic round-trip and rejection cases.
import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
	"time"
)

// Genuine C>S submits and the S>C relay of the first one, channel
// envelope already stripped.
const (
	genuineChatC2SLmao = "02bf74b738070700060001fd6311009d1f00160007000000000000000000000000000000000000000000046c6d616f00001a1a00ae006801f6b008922ed3fb40ea69ebc3d8136b418ac70dc31900"
	genuineChatC2SGG   = "02bf74b7389d1d0016000800000000000000000000000000000000000000000002676700001a1a00ae0068011df710def6d3fb404fe4e1c3f84517411bd26cc31900"
	genuineChatS2CLmao = "1a751b0000070000000000000000000000000000000000000000000000001a751f1700000000000000ae0068010000000065a76de77bb9da41046c6d616f000013fe1aba587f0c547c9f9f67160080ecc3000060410000c0c21e000000000000000000000000000000000000000000000000001d00fe7d8fecc395555d41dfb1bfc2a18fcbbd68cba53cbefd46403500f0566674b02288bc00d7f03500fad1afb5a0a17b7f401003b4347d3500f56218ab04e0028ee010163500e94fbb748b24ae04defc4ab47f7c3500e8d4e16e74a2313c201bff3500fbcd5ee909a1a4569f0bfd3500ef771bb2222600000000003500fc6cf5f82da401e0ffc801b4b47b3500f35e52ac34a310a1e000002844000600011ab29b1dc7d299defe631100fd63110030d6c3c40000012000272000200200838201015da6ecc397537b418ddbbec210d40e42e5db56c2bc931dc4f124013d0120"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestScanBattleChatGenuine(t *testing.T) {
	// C>S: two submits, seq 7 then 8, no sender, no time.
	for _, tc := range []struct {
		name string
		hex  string
		seq  uint16
		text string
	}{
		{"lmao", genuineChatC2SLmao, 7, "lmao"},
		{"gg", genuineChatC2SGG, 8, "gg"},
	} {
		got := ScanBattleChatC2S(mustHex(t, tc.hex))
		if len(got) != 1 {
			t.Fatalf("%s: %d submits, want 1", tc.name, len(got))
		}
		c := got[0]
		if !c.Outgoing || c.Text != tc.text || c.Seq != tc.seq {
			t.Fatalf("%s: %+v", tc.name, c)
		}
		if c.Sender != 0 || c.Channel != 0 || !c.Time.IsZero() {
			t.Fatalf("%s: submit carries server fields: %+v", tc.name, c)
		}
	}

	// S>C: the relay of "lmao" — speaker 0x016800ae, timestamp 28 ms
	// before the packet that carried it.
	got := ScanBattleChatS2C(mustHex(t, genuineChatS2CLmao))
	if len(got) != 1 {
		t.Fatalf("%d relays, want 1", len(got))
	}
	c := got[0]
	if c.Outgoing || c.Text != "lmao" || c.Sender != 0x016800ae || c.Seq != 0 {
		t.Fatalf("relay: %+v", c)
	}
	want := time.Date(2026, 10, 31, 13, 39, 41, 713342000, time.UTC)
	if d := c.Time.Sub(want); d > time.Millisecond || d < -time.Millisecond {
		t.Fatalf("relay time = %s, want %s", c.Time, want)
	}

	// The relay app also carries a 0x75 subtype-0x00 record and a
	// 0x13 tick; neither may be mistaken for chat.
	if n := len(ScanBattleChatC2S(mustHex(t, genuineChatS2CLmao))); n != 0 {
		t.Fatalf("relay app yielded %d C>S submits", n)
	}
	if n := len(ScanBattleChatS2C(mustHex(t, genuineChatC2SLmao))); n != 0 {
		t.Fatalf("submit app yielded %d relays", n)
	}
}

func TestBuildBattleChat(t *testing.T) {
	tr := Trailer{
		Entity:       0x016800ae,
		Nonce:        0x9208b0f6,
		Speed:        7.15,
		AvatarUpdate: AvatarUpdate{X: 275, Y: 23, Z: -2},
		Tail:         [2]byte{0x19, 0x00},
	}
	app := BuildBattleChat(testKey4, 7, "lmao", tr)
	// head 5 + record 3 + payload (24 + 1 + 4 + 2) + trailer 29
	if len(app) != 5+3+31+29 {
		t.Fatalf("len=%d, want 68", len(app))
	}
	if app[0] != BattleC2SHead0 || string(app[1:5]) != string(testKey4[:]) {
		t.Fatal("bad head")
	}
	if app[5] != BattleChatSubC2S || app[6] != 31 || app[7] != 0 {
		t.Fatalf("record head %02x %02x %02x", app[5], app[6], app[7])
	}
	got := ScanBattleChatC2S(app)
	if len(got) != 1 || got[0].Text != "lmao" || got[0].Seq != 7 || !got[0].Outgoing {
		t.Fatalf("round-trip: %+v", got)
	}
	back, ok := ParseTrailer(app)
	if !ok || back != tr {
		t.Fatalf("trailer: ok=%v %+v, want %+v", ok, back, tr)
	}

	// Over-long text is truncated to the u8 length, not wrapped.
	long := make([]byte, BattleChatMaxText+40)
	for i := range long {
		long[i] = 'a'
	}
	app = BuildBattleChat(testKey4, 1, string(long), tr)
	got = ScanBattleChatC2S(app)
	if len(got) != 1 || len(got[0].Text) != BattleChatMaxText {
		t.Fatalf("truncation: %d messages, text len %d", len(got), len(got[0].Text))
	}
}

func TestScanBattleChatRejects(t *testing.T) {
	// A well-formed submit payload, then one mutation per case.
	base := func() []byte {
		pay := make([]byte, BattleChatHeadLen)
		binary.LittleEndian.PutUint16(pay[0:], BattleChatEventC2S)
		binary.LittleEndian.PutUint16(pay[2:], 3)
		pay = append(pay, 2, 'h', 'i', 0, 0)
		return pay
	}
	wrap := func(pay []byte) []byte {
		app := []byte{BattleC2SHead0, 0x16, 0xe4, 0xd8, 0x57,
			BattleChatSubC2S, byte(len(pay)), byte(len(pay) >> 8)}
		return append(app, pay...)
	}
	if got := ScanBattleChatC2S(wrap(base())); len(got) != 1 || got[0].Text != "hi" {
		t.Fatalf("baseline: %+v", got)
	}

	cases := map[string]func([]byte){
		"relay eventType on submit": func(p []byte) { binary.LittleEndian.PutUint16(p[0:], BattleChatEventS2C) },
		"submit carries a sender":   func(p []byte) { binary.LittleEndian.PutUint32(p[8:], 0x016800ae) },
		"non-zero reserved word":    func(p []byte) { binary.LittleEndian.PutUint32(p[12:], 1) },
		"garbage timestamp":         func(p []byte) { binary.LittleEndian.PutUint64(p[16:], math.Float64bits(1e300)) },
		"control byte in text":      func(p []byte) { p[BattleChatHeadLen+1] = 0x07 },
		"empty text":                func(p []byte) { p[BattleChatHeadLen] = 0 },
		"trailing byte not zero":    func(p []byte) { p[len(p)-1] = 1 },
	}
	for name, mut := range cases {
		pay := base()
		mut(pay)
		if got := ScanBattleChatC2S(wrap(pay)); len(got) != 0 {
			t.Fatalf("%s: accepted %+v", name, got)
		}
	}

	// Length that overruns the app is skipped, not read past.
	app := wrap(base())
	app[6] = 0xff
	app[7] = 0xff
	if got := ScanBattleChatC2S(app); len(got) != 0 {
		t.Fatalf("overrun accepted: %+v", got)
	}

	// A relay needs a speaker and a plausible time.
	relay := func() []byte {
		pay := make([]byte, BattleChatHeadLen)
		binary.LittleEndian.PutUint16(pay[0:], BattleChatEventS2C)
		binary.LittleEndian.PutUint32(pay[8:], 0x016800ae)
		binary.LittleEndian.PutUint64(pay[16:], math.Float64bits(1793453981.713342))
		pay = append(pay, 2, 'g', 'g', 0, 0)
		return append([]byte{BattleTrailerTag, MarkerSmall, byte(len(pay))}, pay...)
	}
	if got := ScanBattleChatS2C(relay()); len(got) != 1 || got[0].Sender != 0x016800ae {
		t.Fatalf("relay baseline: %+v", got)
	}
	noSender := relay()
	binary.LittleEndian.PutUint32(noSender[3+8:], 0)
	if got := ScanBattleChatS2C(noSender); len(got) != 0 {
		t.Fatalf("senderless relay accepted: %+v", got)
	}
	badTime := relay()
	binary.LittleEndian.PutUint64(badTime[3+16:], math.Float64bits(42))
	if got := ScanBattleChatS2C(badTime); len(got) != 0 {
		t.Fatalf("timeless relay accepted: %+v", got)
	}
}

func TestObserveChat(t *testing.T) {
	obs := NewObserver(nil, "")
	at := time.Date(2026, 10, 31, 14, 39, 41, 0, time.UTC)
	if row := obs.ObserveChat(at, BattleChat{Text: "lmao", Outgoing: true}); row != `[14:39:41.000] [00:00] CHAT (you) "lmao"` {
		t.Fatalf("own row = %q", row)
	}
	row := obs.ObserveChat(at, BattleChat{Text: "gg", Sender: 0x016800ae})
	if row != `[14:39:41.000] [00:00] ? ? [?] CHAT "gg"` {
		t.Fatalf("relay row = %q", row)
	}
}
