package login

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestErrorSmallMatchesLiteral pins the 1a/5e error answer to the bytes
// the hand-built literal produced, so moving it onto lobby.Small did not
// change the wire.
func TestErrorSmallMatchesLiteral(t *testing.T) {
	for _, status := range []byte{0x00, 0x01} {
		for _, req := range []uint16{0, 225, 234, 0xFFFF} {
			small, err := lobby.Small{Family: 0x1a, Type: 0x5e, Body: []byte{
				byte(req), byte(req >> 8), status, 0x00, 0x00,
			}}.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			want := []byte{0x1a, 0x5e, 0x05, byte(req), byte(req >> 8), status, 0x00, 0x00}
			if !bytes.Equal(small, want) {
				t.Fatalf("req %d status %d: % x, want % x", req, status, small, want)
			}
			app := answerApp(small)
			wantApp := append([]byte{0x13, 0x00}, want...)
			if !bytes.Equal(app, wantApp) {
				t.Fatalf("answer app = % x, want % x", app, wantApp)
			}
		}
	}
}

// TestCarrierSmallMatchesHandSlice checks the principled extraction
// against the hand-sliced offsets it replaced, on the real answer frames.
//
// The three answers the server replays are 1a/5f (rev), 1a/5b (poll) and
// 1a/67 (queue). Where the frame's trailer is the 8 bytes the old code
// assumed, the two must agree exactly; a 16-byte trailer (0x0478) is where
// the hand slice was wrong, leaving 8 trailer bytes on the answer.
func TestCarrierSmallMatchesHandSlice(t *testing.T) {
	const (
		dump = "../../captures/flows3-s2.txt"
		key  = "/tmp/key3_plain.txt"
	)
	if _, err := os.Stat(dump); err != nil {
		t.Skipf("carrier unavailable: %v", err)
	}
	blockKey, err := ReadAnyKeyFile(key)
	if err != nil {
		t.Skipf("key unavailable: %v", err)
	}
	f, err := os.Open(dump)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := ParseWotproxyDump(f)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[byte]bool{}
	for _, rec := range recs {
		if rec.Dir != "S>C" {
			continue
		}
		clear, err := decryptBlowfish(blockKey, rec.Data[4:])
		if err != nil {
			continue
		}
		app, err := frameApp(clear)
		if err != nil || len(app) < 4 || app[0] != elTickSync {
			continue
		}
		// Only the three answer smalls.
		var typ byte
		for _, cand := range []byte{0x5f, 0x5b, 0x67} {
			if lobby.FindSmall(app[2:], 0x1a, cand) != nil {
				typ = cand
				break
			}
		}
		if typ == 0 || seen[typ] {
			continue
		}

		got, err := carrierSmall(clear)
		if err != nil {
			t.Fatalf("1a/%02x: carrierSmall: %v", typ, err)
		}
		if _, _, err := lobby.ParseSmall(got); err != nil {
			t.Fatalf("1a/%02x: extracted bytes are not a small: %v", typ, err)
		}
		tr := ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
		if tr == 8 && len(clear) >= 12 {
			want := clear[4 : len(clear)-8]
			if !bytes.Equal(got, want) {
				t.Fatalf("1a/%02x: carrierSmall = % x, hand slice = % x", typ, got, want)
			}
		}
		seen[typ] = true
		t.Logf("1a/%02x: %dB frame, %dB trailer, %dB small", typ, len(rec.Data), tr, len(got))
	}
	if len(seen) == 0 {
		t.Skip("no answer frames in the carrier")
	}
}
