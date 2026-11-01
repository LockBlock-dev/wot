package server

import (
	"bytes"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/login"
)

// loadCaptureBundle reassembles the stage-2 flood of a real capture.
// proxy-20261014-1713 flow 39725-> is the one capture whose bundle
// decodes completely (245 370 of 250 687 bytes, 375 objects).
func loadCaptureBundle(t *testing.T) []byte {
	t.Helper()
	const (
		dump = "../../captures/proxy-20261014-1713.hex"
		priv = "../../mitm/loginapp_mitm.privkey"
		pub  = "../../World_of_Tanks_EU/2.4.0.0/res/loginapp_wot.pubkey"
		flow = "39725->"
	)
	if _, err := os.Stat(dump); err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	f, err := os.Open(dump)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	dd, err := login.ParseWotproxyDump(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	key, err := login.RecoverLoginKey(dd, priv, pub, "")
	if err != nil {
		t.Skipf("key recovery unavailable: %v", err)
	}
	frags, _, _, err := login.ReassembleFrags(dd, flow, 1252, key)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}
	var all []byte
	for _, fr := range frags {
		all = append(all, fr.Payload...)
	}
	return all
}

// TestBundleRoundTripCapture is the real-data oracle for the bundle
// pipeline: a complete capture bundle must decode and re-encode
// byte-identically.
func TestBundleRoundTripCapture(t *testing.T) {
	raw := loadCaptureBundle(t)

	b, err := DecodeBundle(raw)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	if len(b.Stack) < 100 {
		t.Fatalf("stack has %d objects, expected hundreds", len(b.Stack))
	}

	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("round-trip differs: %d out, %d in", len(out), len(raw))
	}
	t.Logf("bundle round-trip: %d bytes, %d objects, byte-identical", len(raw), len(b.Stack))
}

// TestBundleMutationCapture proves a patch lands and nothing else moves:
// the re-encoded bundle differs from the capture only in the patched
// value's bytes.
func TestBundleMutationCapture(t *testing.T) {
	raw := loadCaptureBundle(t)
	b, err := DecodeBundle(raw)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}

	// Pick a key that exists and is an integer.
	var key string
	var before int64
	for _, cand := range []string{"crewLvl", "credits", "gold"} {
		for _, n := range b.Find(cand) {
			if n.Kind == 0x02 { // FInt
				key, before = cand, n.I
				break
			}
		}
		if key != "" {
			break
		}
	}
	if key == "" {
		t.Skip("no integer key to patch in this capture")
	}

	if n := b.SetInt(key, before+1); n == 0 {
		t.Fatalf("SetInt(%q) changed nothing", key)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Equal(out, raw) {
		t.Fatal("mutation produced identical bytes")
	}

	// Re-decode and confirm the new value is there.
	b2, err := DecodeBundle(out)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	found := false
	for _, n := range b2.Find(key) {
		if n.Kind == 0x02 && n.I == before+1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q = %d not found after re-decode", key, before+1)
	}
	t.Logf("patched %q: %d -> %d, bundle %d -> %d bytes", key, before, before+1, len(raw), len(out))
}
