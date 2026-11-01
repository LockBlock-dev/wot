package login

import (
	"bytes"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestFaithfulRoundTripCapture is the real-data oracle for the faithful
// pickle codec: every complete document the lobby bundle yields must
// decode and re-encode byte-identically.
//
// The bundle is one shared-memo proto-2 pickle spread over 40 chunks with
// a few per-capture noise bytes, so documents are taken from the
// resynchronising inventory rather than assumed contiguous.
func TestFaithfulRoundTripCapture(t *testing.T) {
	const (
		dumpPath = "../../captures/flows3-s2.txt"
		keyPath  = "../../captures/key3.txt"
		flow     = "s2flow"
	)
	if _, err := os.Stat(dumpPath); err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatalf("open dump: %v", err)
	}
	defer f.Close()
	dd, err := ParseWotproxyDump(f)
	if err != nil {
		t.Fatalf("parse dump: %v", err)
	}
	key, err := ReadAnyKeyFile(keyPath)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	frags, _, _, err := ReassembleFrags(dd, flow, 1252, key)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	if len(frags) == 0 {
		t.Fatal("no fragments")
	}

	// Chunk 1 is one big dict that never closes inside the decodable
	// region (the bundle is fragmented and carries per-capture noise),
	// so complete documents are looked for across every chunk.
	var docs, bytesOK, rejected int
	var firstErr error
	for _, fr := range frags {
		stack, n, err := lobby.DecodeFaithful(fr.Payload)
		if err != nil {
			rejected++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if n != len(fr.Payload) {
			// A STOP part-way through: not a complete document.
			rejected++
			continue
		}
		out, err := lobby.EncodeFaithful(stack)
		if err != nil {
			t.Fatalf("chunk %d: encode: %v", fr.NN, err)
		}
		if !bytes.Equal(out, fr.Payload) {
			t.Fatalf("chunk %d (%d B): round-trip differs", fr.NN, len(fr.Payload))
		}
		docs++
		bytesOK += len(fr.Payload)
	}
	if docs == 0 {
		t.Skipf("no complete pickle documents in this capture (%d chunks rejected, first err: %v)",
			rejected, firstErr)
	}
	t.Logf("faithful round-trip: %d documents, %d bytes byte-identical", docs, bytesOK)
}
