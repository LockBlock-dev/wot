package login

import (
	"bytes"
	"testing"
)

// TestFlagsDeriveFromConstants pins the two channel flag words to the
// bytes every capture carries. They used to be literals; deriving them
// from the named bits means a flag rename cannot silently desync the two.
func TestFlagsDeriveFromConstants(t *testing.T) {
	if got := flagsRel; !bytes.Equal(got, []byte{0x58, 0x04}) {
		t.Errorf("flagsRel = % x, want 58 04 (0x0458)", got)
	}
	if got := flagsUnrel; !bytes.Equal(got, []byte{0x48, 0x14}) {
		t.Errorf("flagsUnrel = % x, want 48 14 (0x1448)", got)
	}
	// The words must still decompose into the bits the trailer rule uses.
	if n := ChannelTrailerLen(0x0458); n != 8 {
		t.Errorf("ChannelTrailerLen(0x0458) = %d, want 8", n)
	}
	if n := ChannelTrailerLen(0x1448); n != 12 {
		t.Errorf("ChannelTrailerLen(0x1448) = %d, want 12", n)
	}
}

// TestAck0ClearIsDerived pins the first post-rotation packet: the
// unreliable flags word, the aux word, then seq and cumul of 1.
func TestAck0ClearIsDerived(t *testing.T) {
	want := []byte{0x48, 0x14, 0xff, 0xff, 0xff, 0x0f, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(ack0Clear, want) {
		t.Fatalf("ack0Clear = % x, want % x", ack0Clear, want)
	}
	if !bytes.HasPrefix(ack0Clear, flagsUnrel) {
		t.Error("ack0Clear does not start with the unreliable flags word")
	}
}

// TestTickSyncHeads pins the message heads the serving path builds, so
// replacing the literals with EncodeTickSync did not change the wire.
func TestTickSyncHeads(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want []byte
	}{
		{"session dict", EncodeTickSync(0x40), []byte{0x13, 0x40}},
		{"redirect", append(EncodeTickSync(0x3f), 0x44), []byte{0x13, 0x3f, 0x44}},
		{"answer", EncodeTickSync(0), []byte{0x13, 0x00}},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s head = % x, want % x", c.name, c.got, c.want)
		}
	}
}
