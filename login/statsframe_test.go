package login

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// statsBody is the real 1a/69 body from proxy-20261014-1713:
// [status][pickle] where the pickle is
// {stats:{freeXP:1936},prevRev:200,cache:{},rev:201}.
const statsBody = "4280027d7101285505737461747371027d7103550666726565585071044d900773" +
	"55077072657652657671054bc85505636163686571067d550372657671074bc9752e"

func statsSmall(t *testing.T) []byte {
	t.Helper()
	body, err := hex.DecodeString(statsBody)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	small, err := lobby.Small{Family: 0x1a, Type: statsSmallType, Body: body}.Encode()
	if err != nil {
		t.Fatalf("frame the capture body: %v", err)
	}
	return small
}

// TestParseStatsSmallReadsTheCapture pins the reader against the real
// carrier: the revisions it yields are the ones the builder reuses.
func TestParseStatsSmallReadsTheCapture(t *testing.T) {
	freeXP, prevRev, rev, err := ParseStatsSmall(statsSmall(t))
	if err != nil {
		t.Fatalf("ParseStatsSmall: %v", err)
	}
	if freeXP != 1936 {
		t.Errorf("freeXP = %d, want 1936", freeXP)
	}
	if prevRev != 200 || rev != 201 {
		t.Errorf("revs = %d/%d, want 200/201", prevRev, rev)
	}
}

// TestBuildStatsSmallCarriesTheAccount is the point: the small is built
// from the account's free XP, not patched out of a capture.
func TestBuildStatsSmallCarriesTheAccount(t *testing.T) {
	for _, freeXP := range []int64{0, 1, 1936, 5000, 65535, 1 << 20} {
		small, err := BuildStatsSmall(freeXP, 200, 201)
		if err != nil {
			t.Fatalf("freeXP %d: %v", freeXP, err)
		}
		gotXP, gotPrev, gotRev, err := ParseStatsSmall(small)
		if err != nil {
			t.Fatalf("freeXP %d: parse back: %v", freeXP, err)
		}
		if gotXP != freeXP {
			t.Errorf("freeXP = %d, want %d", gotXP, freeXP)
		}
		if gotPrev != 200 || gotRev != 201 {
			t.Errorf("revs = %d/%d, want 200/201", gotPrev, gotRev)
		}
		// It must be a well-formed 1a/69 small.
		s, n, err := lobby.ParseSmall(small)
		if err != nil || n != len(small) {
			t.Fatalf("freeXP %d: not a clean small (%v, %d of %d)", freeXP, err, n, len(small))
		}
		if s.Family != 0x1a || s.Type != statsSmallType {
			t.Errorf("freeXP %d: family/type = %#02x/%#02x", freeXP, s.Family, s.Type)
		}
		if len(s.Body) < 2 || s.Body[0] != statsStatus {
			t.Errorf("freeXP %d: no status byte", freeXP)
		}
	}
}

// TestBuildStatsSmallIsStable keeps the answer reproducible.
func TestBuildStatsSmallIsStable(t *testing.T) {
	first, err := BuildStatsSmall(5000, 200, 201)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := BuildStatsSmall(5000, 200, 201)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, first) {
			t.Fatal("the builder is not deterministic")
		}
	}
}

// TestStatsFrameUsesTheBuilder keeps the serving path on the builder.
func TestStatsFrameUsesTheBuilder(t *testing.T) {
	got, err := statsFrame(200, 201, 5000)
	if err != nil {
		t.Fatalf("statsFrame: %v", err)
	}
	want, err := BuildStatsSmall(5000, 200, 201)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("statsFrame does not use the builder")
	}
}

// TestParseStatsSmallRejectsGarbage keeps a wrong small from decoding.
func TestParseStatsSmallRejectsGarbage(t *testing.T) {
	if _, _, _, err := ParseStatsSmall([]byte{0x1a, 0x5e, 0x05, 0, 0, 0, 0, 0}); err == nil {
		t.Error("a 1a/5e small parsed as stats")
	}
	if _, _, _, err := ParseStatsSmall(nil); err == nil {
		t.Error("empty input parsed")
	}
}
