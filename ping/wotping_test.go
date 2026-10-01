package ping

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// Real framing from wot_server_ping.pcapng (Oct 2022); the reply vector
// below combines a captured request key (ReplyID a1 1b 01 00) with a
// captured trailer (seq 02, metric 3a b6) to stay self-consistent.
const (
	reqHex = "0cc01fc5010002a11b01000000000200"
	repHex = "9f4c1b990000ff05000000a11b0100023ab6"
)

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector: %v", err)
	}
	return b
}

func TestEncodeShape(t *testing.T) {
	var prefix [4]byte = [4]byte{0x0c, 0xc0, 0x1f, 0xc5}
	got := encodeRequestWithPrefix(prefix, 0x00011ba1, 0x00)
	if hex.EncodeToString(got) != reqHex {
		t.Fatalf("encode mismatch:\n got %x\nwant %s", got, reqHex)
	}
}

func TestDecodeReply(t *testing.T) {
	metric, hasMetric, err := decodeReply(mustDecode(t, repHex), 0x00011ba1, 0x02)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// ReplyID a1 1b 01 00, seq echo 02, trailer 3a b6.
	if !hasMetric || metric != 0x3ab6 {
		t.Fatalf("metric = %04x/%v, want 3ab6/true", metric, hasMetric)
	}
}

func TestDecodeReplyNoTrailer(t *testing.T) {
	// Current servers omit the trailer (16 B): live reply from
	// login.p2.worldoftanks.eu captured Sep 2026.
	rep := mustDecode(t, "9f4c1b990000ff05000000a11b010000")
	metric, hasMetric, err := decodeReply(rep, 0x00011ba1, 0x00)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hasMetric || metric != 0 {
		t.Fatalf("metric = %04x/%v, want 0/false", metric, hasMetric)
	}
}

func TestDecodeMismatch(t *testing.T) {
	rep := mustDecode(t, repHex)
	if _, _, err := decodeReply(rep, 0xdeadbeef, 0x02); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected ErrMismatch on replyID, got %v", err)
	}
	if _, _, err := decodeReply(rep, 0x00011ba1, 0x09); !errors.Is(err, ErrMismatch) {
		t.Fatalf("expected ErrMismatch on seq, got %v", err)
	}
	if _, _, err := decodeReply(rep[:10], 0x00011ba1, 0x02); !errors.Is(err, ErrShort) {
		t.Fatalf("expected ErrShort, got %v", err)
	}
}

func TestClassify(t *testing.T) {
	cases := map[int64]string{10: "LOW", 59: "LOW", 60: "NORM", 119: "NORM", 120: "HIGH"}
	for ms, want := range cases {
		if got := Classify(time.Duration(ms) * time.Millisecond); got != want {
			t.Fatalf("Classify(%dms) = %s, want %s", ms, got, want)
		}
	}
}
