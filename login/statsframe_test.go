package login

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// statsBody is the real 1a/69 body from proxy-20261014-1713:
// [len-1][pickle] where the pickle is
// {stats:{freeXP:1936},prevRev:200,cache:{},rev:201}.
const statsBody = "4280027d7101285505737461747371027d7103550666726565585071044d900773" +
	"55077072657652657671054bc85505636163686571067d550372657671074bc9752e"

func statsBodyBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(statsBody)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestStatsFramePatchesFreeXP proves the 1a/69 stats small is minted per
// account: the freeXP integer is rewritten in place and nothing else
// moves.
func TestStatsFramePatchesFreeXP(t *testing.T) {
	tpl := statsBodyBytes(t)

	// Unpatched (freeXP <= 0) replays the capture verbatim.
	same, err := statsFrame(tpl, 0)
	if err != nil {
		t.Fatalf("statsFrame(0): %v", err)
	}
	if !bytes.Equal(same, tpl) {
		t.Fatal("freeXP<=0 must replay the template unchanged")
	}

	out, err := statsFrame(tpl, 5000)
	if err != nil {
		t.Fatalf("statsFrame(5000): %v", err)
	}
	if len(out) != len(tpl) {
		t.Fatalf("length changed: %d -> %d", len(tpl), len(out))
	}

	// Exactly the two BININT2 payload bytes differ.
	var diff []int
	for i := range tpl {
		if tpl[i] != out[i] {
			diff = append(diff, i)
		}
	}
	if len(diff) != 2 {
		t.Fatalf("expected 2 changed bytes, got %d at %v", len(diff), diff)
	}
	if got := binary.LittleEndian.Uint16(out[diff[0]:]); got != 5000 {
		t.Fatalf("freeXP = %d, want 5000", got)
	}

	// The template itself must not be mutated.
	if !bytes.Equal(tpl, statsBodyBytes(t)) {
		t.Fatal("statsFrame mutated its template")
	}
}

// TestPatchPickleIntRejectsOverflow keeps the patcher honest: a value
// that does not fit the original opcode width is an error, never a
// silent truncation.
func TestPatchPickleIntRejectsOverflow(t *testing.T) {
	body := statsBodyBytes(t)
	if err := patchPickleInt(body, "freeXP", 70000); err == nil {
		t.Fatal("expected an overflow error for BININT2")
	}
	if err := patchPickleInt(body, "nope", 1); err == nil {
		t.Fatal("expected a missing-key error")
	}
}
