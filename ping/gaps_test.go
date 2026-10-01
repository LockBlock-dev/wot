package ping

// Gap coverage for offline-testable surface: request framing, client
// lifecycle, reply-ID mint. PingOnce stays untested by design (needs a
// live LoginApp).
import (
	"testing"
)

func TestEncodeRequestShape(t *testing.T) {
	b, err := encodeRequest(0xa11b0100, 0x02)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != reqLen {
		t.Fatalf("request %d B, want %d", len(b), reqLen)
	}
	if b[4] != 0x01 || b[5] != 0x00 || b[6] != msgPing {
		t.Fatalf("request flags/id %02x %02x %02x", b[4], b[5], b[6])
	}
	if b[13] != 0x02 {
		t.Fatalf("seq byte %02x, want 02", b[13])
	}
	// Deterministic twin decodes the shared fields identically.
	twin := encodeRequestWithPrefix([4]byte{b[0], b[1], b[2], b[3]}, 0xa11b0100, 0x02)
	for _, i := range []int{4, 5, 6, 7, 8, 9, 10, 13} {
		if b[i] != twin[i] {
			t.Fatalf("byte %d differs from deterministic build", i)
		}
	}
}

func TestClientLifecycle(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewReplyIDNoErr(t *testing.T) {
	if _, err := NewReplyID(); err != nil {
		t.Fatalf("NewReplyID: %v", err)
	}
}
