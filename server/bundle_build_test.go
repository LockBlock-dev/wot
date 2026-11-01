package server

import (
	"bytes"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
)

// TestBuildBundleEndToEnd is the point of the builder: a bundle authored
// in code, framed, and read back by the same path the server uses on a
// capture, decodes to what was built.
func TestBuildBundleEndToEnd(t *testing.T) {
	config := lobby.NewDict().
		Set("shop", lobby.NewDict().Set("isEnabled", lobby.NewBool(true))).
		Set("matchmaker", lobby.NewDict().Set("maxPlayersInQueue", lobby.NewInt(3)))
	account := lobby.NewDict().
		Set("stats", lobby.NewDict().
			Set("credits", lobby.NewInt(500000)).
			Set("freeXP", lobby.NewInt(12345))).
		Set("piggyBank", lobby.NewDict().Set("credits", lobby.NewInt(7)))

	stream, err := NewBundle().Document(config).Document(account).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Frame it the way the flood carries it, then read it back.
	const key = "0123456789abcdef"
	frames, err := login.BuildFrames(key, stream, login.DefaultBulkPayload, 1)
	if err != nil {
		t.Fatalf("BuildFrames: %v", err)
	}
	back, err := login.ReadFrames(key, frames)
	if err != nil {
		t.Fatalf("ReadFrames: %v", err)
	}
	if !bytes.Equal(back, stream) {
		t.Fatalf("framing round-trip differs: %d in, %d out", len(stream), len(back))
	}

	// And the bundle decodes to the two documents that were built.
	b, err := DecodeBundle(back)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	if len(b.Docs) != 2 {
		t.Fatalf("%d documents, want 2", len(b.Docs))
	}
	if got := b.Docs[0].Stack[0].Get("shop").Get("isEnabled"); got == nil || !got.B {
		t.Errorf("shop.isEnabled = %+v", got)
	}
	doc := b.AccountDoc()
	if doc != 1 {
		t.Fatalf("AccountDoc = %d, want 1", doc)
	}
	stats := b.Docs[doc].pair("stats")
	if stats == nil {
		t.Fatal("no stats dict")
	}
	if v := stats.Get("credits"); v == nil || v.I != 500000 {
		t.Errorf("stats.credits = %+v", v)
	}
	if v := stats.Get("freeXP"); v == nil || v.I != 12345 {
		t.Errorf("stats.freeXP = %+v", v)
	}
	t.Logf("built %d B bundle, %d frames, %d documents", len(stream), len(frames), len(b.Docs))
}

// TestBuiltBundleTakesApplyState proves a generated bundle is a first
// class citizen: the same per-account patch works on it.
func TestBuiltBundleTakesApplyState(t *testing.T) {
	// The widths the patch below keeps: 100000 is a 5-byte BININT,
	// 2000 a 3-byte BININT2.
	account := lobby.NewDict().
		Set("stats", lobby.NewDict().
			Set("credits", lobby.NewInt(100000)).
			Set("freeXP", lobby.NewInt(2000)))
	stream, err := NewBundle().Document(account).Encode()
	if err != nil {
		t.Fatal(err)
	}
	patched, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{Credits: 999999, FreeXP: 4242})
	})(stream)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	b, err := DecodeBundle(patched)
	if err != nil {
		t.Fatal(err)
	}
	stats := b.Docs[b.AccountDoc()].pair("stats")
	if v := stats.Get("credits"); v == nil || v.I != 999999 {
		t.Errorf("credits = %+v", v)
	}
	if v := stats.Get("freeXP"); v == nil || v.I != 4242 {
		t.Errorf("freeXP = %+v", v)
	}
}

// TestFromCaptureKeepsDocuments is the migration path: seed from a real
// capture, re-encode, and the account document survives.
func TestFromCaptureKeepsDocuments(t *testing.T) {
	raw := loadAccountBundle(t)
	b, err := FromCapture(raw)
	if err != nil {
		t.Fatalf("FromCapture: %v", err)
	}
	if b.Documents() != 2 {
		t.Fatalf("%d documents, want 2", b.Documents())
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	re, err := DecodeBundle(out)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if re.AccountDoc() < 0 {
		t.Fatal("the account document did not survive the rebuild")
	}
	stats := re.Docs[re.AccountDoc()].pair("stats")
	if stats == nil || stats.Get("credits") == nil {
		t.Fatal("stats.credits did not survive the rebuild")
	}
	t.Logf("rebuilt from capture: %d B -> %d B, %d documents", len(raw), len(out), len(re.Docs))
}

// TestBuildBundleRejectsEmpty keeps an empty builder from producing a
// stream the client would wait on.
func TestBuildBundleRejectsEmpty(t *testing.T) {
	if _, err := NewBundle().Encode(); err == nil {
		t.Fatal("empty builder produced a bundle")
	}
}
