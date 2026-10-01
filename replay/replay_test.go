package replay

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

const testReplay = "../../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay"

// TestDecryptProhorovka pins the whole pipeline against a genuine 2.4.0.0
// replay: container framing, setup JSON, stream key, zlib. Offline.
func TestDecryptProhorovka(t *testing.T) {
	r, err := Open(testReplay)
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if got := r.MetaField("mapDisplayName"); got != "Prokhorovka" {
		t.Fatalf("map = %q", got)
	}
	if got := r.MetaField("playerName"); got != "ExampleUser" {
		t.Fatalf("player = %q", got)
	}
	if len(r.Stream) != 5319705 {
		t.Fatalf("stream = %d bytes, want 5319705", len(r.Stream))
	}
	const wantHead = "0b000000180000000000000007000000322e342e302e300f"
	if got := hex.EncodeToString(r.Stream[:24]); got != wantHead {
		t.Fatalf("stream head = %s", got)
	}
}

// TestDecryptHills pins the same pipeline on a second fixture (2.3.1.0):
// same key and framing across versions.
func TestDecryptHills(t *testing.T) {
	r, err := Open("../../replays/20260830_1542_czech-Cz05_T34_100_10_hills.wotreplay")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if got := r.MetaField("mapDisplayName"); got != "Mines" {
		t.Fatalf("map = %q", got)
	}
	if len(r.Stream) != 4423484 {
		t.Fatalf("stream = %d bytes, want 4423484", len(r.Stream))
	}
}

// TestDecryptOld pins the surprise find that 2.0.0.0 streams take the
// SAME key+scheme: container, decrypt, packet chain, version record,
// and the tail-MD5-over-all-blocks rule. Method/property tables are
// NOT asserted (2.0 needs its own .defs — open). Offline.
func TestDecryptOld(t *testing.T) {
	r, err := Open("../../replays/17597555737214_ussr_R40_T-54_lost_paradise_v.wotreplay")
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	if ver := r.ClientVersion(); ver != "2.0.0.0" {
		t.Fatalf("version=%q", ver)
	}
	if len(r.Extra) != 1 || len(r.ExtraRaw) != 1 {
		t.Fatalf("extra blocks=%d", len(r.Extra))
	}
	if len(r.Stream) != 4674076 {
		t.Fatalf("stream=%d, want 4674076", len(r.Stream))
	}
	pkts, err := Packets(r.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 104907 {
		t.Fatalf("packets=%d, want 104907", len(pkts))
	}
	last := pkts[len(pkts)-1]
	if last.Type != 0xffffffff || len(last.Data) != 16 {
		t.Fatalf("tail type=%#x len=%d", last.Type, len(last.Data))
	}
	sum := md5.Sum(r.BlocksRaw())
	if string(sum[:]) != string(last.Data) {
		t.Fatal("tail MD5 mismatch over setup+results")
	}
}
