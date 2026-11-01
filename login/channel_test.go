package login

import "testing"

// TestChannelTrailerLen pins the footer length for every flags word
// observed in the Oct-31 EU2 battle capture (2806 S>C + 216 C>S
// datagrams). The expected values come from seq monotonicity: the
// channel seq advances by exactly 1 between consecutive datagrams of
// the same direction, which only holds when the trailer boundary is
// right.
func TestChannelTrailerLen(t *testing.T) {
	cases := []struct {
		flags uint16
		want  int
		why   string
	}{
		{0x0458, 8, "ON|REL|SEQ|CUMUL — the stage-1 reliable shape"},
		{0x1448, 12, "ON|SEQ|CUMUL|AUX — the stage-1 unreliable shape"},
		{0x0078, 12, "ON|REL|SEQ|REQ"},
		{0x0478, 16, "ON|REL|SEQ|REQ|CUMUL"},
		{0x0058, 4, "ON|REL|SEQ"},
		{0x045a, 8, "ON|REL|SEQ|CUMUL|0x02"},
		{0x144c, 12, "ON|SEQ|CUMUL|AUX|0x04"},
		{0x0000, 0, "no flags, no footers"},
	}
	for _, c := range cases {
		if got := ChannelTrailerLen(c.flags); got != c.want {
			t.Errorf("ChannelTrailerLen(%#04x) = %d, want %d (%s)", c.flags, got, c.want, c.why)
		}
	}
}

// TestChannelTrailerLenAdditive checks the rule is a pure sum of the
// individual bits, so an unseen flags word still gets a sane length.
func TestChannelTrailerLenAdditive(t *testing.T) {
	bits := []uint16{chFlagSequence, chFlagCumulAck, chFlagAux, chFlagRequests}
	for _, b := range bits {
		var sum uint16
		for _, other := range bits {
			if other != b {
				sum |= other
			}
		}
		if got, want := ChannelTrailerLen(sum|b), ChannelTrailerLen(sum)+ChannelTrailerLen(b); got != want {
			t.Errorf("bit %#04x not additive: %d != %d", b, got, want)
		}
	}
}
