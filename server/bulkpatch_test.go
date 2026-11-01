package server

import (
	"bytes"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// loadAccountBundle reassembles the one capture whose flood carries BOTH
// documents: proxy-20261014-1752 flow 35493-> decodes to 374 config
// objects followed by the 42-object account document.
func loadAccountBundle(t *testing.T) []byte {
	t.Helper()
	return loadCaptureFlow(t, "../../captures/proxy-20261014-1752.hex", "35493->")
}

// TestBundleCarriesAccountDocument is the finding the whole per-account
// path rests on: the flood is a SEQUENCE of pickle documents, and the
// second one is the account's state, not more config.
func TestBundleCarriesAccountDocument(t *testing.T) {
	raw := loadAccountBundle(t)
	b, err := DecodeBundle(raw)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	if len(b.Docs) < 2 {
		t.Fatalf("bundle has %d documents, want at least 2", len(b.Docs))
	}
	doc := b.AccountDoc()
	if doc < 0 {
		t.Fatal("no account document found")
	}
	if doc == 0 {
		t.Error("account document is the config document")
	}
	stats := b.Docs[doc].pair("stats")
	if stats == nil || stats.Kind != lobby.FDict {
		t.Fatal("account document has no stats dict")
	}
	// The captured balance is a real player value, not a price table.
	var credits, freeXP int64 = -1, -1
	for i, k := range stats.Keys {
		switch k.S {
		case "credits":
			credits = stats.Items[i].I
		case "freeXP":
			freeXP = stats.Items[i].I
		}
	}
	if credits <= 0 {
		t.Errorf("stats.credits = %d, want a positive balance", credits)
	}
	if freeXP <= 0 {
		t.Errorf("stats.freeXP = %d, want a positive balance", freeXP)
	}
	t.Logf("account document %d: credits %d, freeXP %d", doc, credits, freeXP)
}

// TestApplyStatePatchesCredits is the point of the phase: the account's
// stored economy reaches the bundle the client decodes.
func TestApplyStatePatchesCredits(t *testing.T) {
	raw := loadAccountBundle(t)

	patched, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{Credits: 500000, FreeXP: 12345})
	})(raw)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if len(patched) != len(raw) {
		t.Fatalf("patch changed the length: %d -> %d", len(raw), len(patched))
	}

	// Re-decode the patched stream: the values must be the account's.
	b, err := DecodeBundle(patched)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	stats := b.Docs[b.AccountDoc()].pair("stats")
	got := map[string]int64{}
	for i, k := range stats.Keys {
		got[k.S] = stats.Items[i].I
	}
	if got["credits"] != 500000 {
		t.Errorf("credits = %d, want 500000", got["credits"])
	}
	if got["freeXP"] != 12345 {
		t.Errorf("freeXP = %d, want 12345", got["freeXP"])
	}

	// Nothing else moved: the diff is confined to the patched values.
	diff := 0
	for i := range raw {
		if raw[i] != patched[i] {
			diff++
		}
	}
	if diff == 0 {
		t.Fatal("patch changed nothing")
	}
	if diff > 16 {
		t.Errorf("%d bytes changed, expected only the two patched values", diff)
	}
	t.Logf("patched %d bytes, length preserved at %d", diff, len(patched))
}

// TestApplyStateRefusesWidthChange keeps a value that would need a wider
// opcode from silently resizing the bundle.
func TestApplyStateRefusesWidthChange(t *testing.T) {
	raw := loadAccountBundle(t)
	// freeXP is captured as BININT2 (3 bytes); 70000 needs BININT (5).
	_, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{Credits: 500000, FreeXP: 70000})
	})(raw)
	if err == nil {
		t.Fatal("a width-changing value was accepted")
	}
}

// TestVerifyBundleRejectsGarbage keeps the load gate honest.
func TestVerifyBundleRejectsGarbage(t *testing.T) {
	if err := VerifyBundle([]byte{0x00, 0x1a, 0x5f}); err == nil {
		t.Fatal("garbage accepted as a bundle")
	}
	if err := VerifyBundle(nil); err == nil {
		t.Fatal("empty stream accepted")
	}
}

// TestVerifyBundleAcceptsCaptures is the gate against the real carriers.
func TestVerifyBundleAcceptsCaptures(t *testing.T) {
	for _, raw := range [][]byte{loadCaptureBundle(t), loadAccountBundle(t)} {
		if err := VerifyBundle(raw); err != nil {
			t.Errorf("VerifyBundle: %v", err)
		}
	}
}

// TestBundleRoundTripAccountCapture pins the byte-identical round-trip on
// the two-document capture, which the single-document decoder could not
// reproduce (it swallowed the second document's PROTO).
func TestBundleRoundTripAccountCapture(t *testing.T) {
	raw := loadAccountBundle(t)
	b, err := DecodeBundle(raw)
	if err != nil {
		t.Fatalf("DecodeBundle: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("round-trip differs: in %d B, out %d B", len(raw), len(out))
	}
	t.Logf("two-document round-trip: %d bytes, %d documents, %d objects, byte-identical",
		len(raw), len(b.Docs), len(b.Stack))
}

// TestServedFieldsIsHonest pins the account model's wire inventory: the
// fields claimed as served must be the ones ApplyState actually writes,
// and the unserved list must not overlap them.
func TestServedFieldsIsHonest(t *testing.T) {
	served := ServedFields()
	for _, want := range []string{"Credits", "FreeXP"} {
		if _, ok := served[want]; !ok {
			t.Errorf("%s is not listed as served", want)
		}
	}
	for _, f := range UnservedFields() {
		if _, ok := served[f]; ok {
			t.Errorf("%s is listed as both served and unserved", f)
		}
	}
	// ApplyState must write exactly the served economy fields.
	raw := loadAccountBundle(t)
	b, err := DecodeBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyState(b, &PlayerState{Credits: 500000, FreeXP: 12345}); err != nil {
		t.Fatalf("ApplyState: %v", err)
	}
	stats := b.Docs[b.AccountDoc()].pair("stats")
	got := map[string]int64{}
	for i, k := range stats.Keys {
		got[k.S] = stats.Items[i].I
	}
	if got["credits"] != 500000 || got["freeXP"] != 12345 {
		t.Errorf("stats = %v, want credits 500000 / freeXP 12345", got)
	}
}

// TestApplyStatePatchesPiggyBankAndRating covers the two scalars added
// after the first pass: the piggy bank balance and the account rating.
func TestApplyStatePatchesPiggyBankAndRating(t *testing.T) {
	raw := loadAccountBundle(t)
	patched, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{
			Credits: 500000, FreeXP: 12345,
			PiggyBank: 40000, GlobalRating: 1234.5,
		})
	})(raw)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	if len(patched) != len(raw) {
		t.Fatalf("length changed: %d -> %d", len(raw), len(patched))
	}
	b, err := DecodeBundle(patched)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	d := b.Docs[b.AccountDoc()]

	pb := d.pair("piggyBank")
	if pb == nil || pb.Kind != lobby.FDict {
		t.Fatal("no piggyBank dict")
	}
	if v := pb.Get("credits"); v == nil || v.I != 40000 {
		t.Errorf("piggyBank.credits = %+v, want 40000", v)
	}

	acct := d.pair("account")
	if acct == nil || acct.Kind != lobby.FDict {
		t.Fatal("no account dict")
	}
	if v := acct.Get("globalRating"); v == nil || v.F != 1234.5 {
		t.Errorf("account.globalRating = %+v, want 1234.5", v)
	}

	// The stats dict is untouched by the new fields.
	stats := d.pair("stats")
	if v := stats.Get("credits"); v == nil || v.I != 500000 {
		t.Errorf("stats.credits = %+v", v)
	}
}

// TestApplyStateFillsTheSlotWidth pins the width rule: a value that would
// canonically encode narrower still fills the capture's slot, so the
// bundle length never moves.
func TestApplyStateFillsTheSlotWidth(t *testing.T) {
	raw := loadAccountBundle(t)
	// piggyBank.credits is a 3-byte BININT2 in the capture; 0 would
	// canonically be a 2-byte BININT1.
	patched, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{Credits: 500000, FreeXP: 12345, PiggyBank: 0})
	})(raw)
	if err != nil {
		t.Fatalf("zero piggy bank: %v", err)
	}
	if len(patched) != len(raw) {
		t.Fatalf("length changed: %d -> %d", len(raw), len(patched))
	}
	b, err := DecodeBundle(patched)
	if err != nil {
		t.Fatal(err)
	}
	pb := b.Docs[b.AccountDoc()].pair("piggyBank")
	if v := pb.Get("credits"); v == nil || v.I != 0 {
		t.Errorf("piggyBank.credits = %+v, want 0", v)
	}
}

// TestApplyStateRefusesOverflow keeps a value too big for its slot from
// silently truncating.
func TestApplyStateRefusesOverflow(t *testing.T) {
	raw := loadAccountBundle(t)
	// piggyBank.credits is 3 bytes: 70000 does not fit.
	_, err := BulkPatcher(func(b *Bundle) error {
		return ApplyState(b, &PlayerState{Credits: 500000, FreeXP: 12345, PiggyBank: 70000})
	})(raw)
	if err == nil {
		t.Fatal("an overflowing piggy bank was accepted")
	}
}
