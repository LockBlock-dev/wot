package cuckoo

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// Real 2022 LoginApp challenge + client solution (wot_EU1_connection.pcapng).
const (
	prefix   = "fca223380bde7178:"
	key      = "fca223380bde7178:0"
	maxNonce = 576716 // ~55% of 2^20
	noncesHx = "0688000047ce000020010100e4960100f29f01006fc801000bfc0100c1810200ef8b0200b3990200a86e03008c800300b395030012a5030016aa0300fcaf0300deb20300b7b80300a5e3030044fe0300521e040010870400bae804002cf4040051150500902e050071450500b15a0500026e0500fd8a050071960500a6a2050097e80500094c0600df5d060015740600f06c07006c5d08000e680800d4820800f1a208004bb30800"
)

func testNonces(t *testing.T) []uint64 {
	t.Helper()
	raw, err := hex.DecodeString(noncesHx)
	if err != nil || len(raw) != 42*4 {
		t.Fatalf("bad vector: %v len=%d", err, len(raw))
	}
	out := make([]uint64, 42)
	for i := range out {
		out[i] = uint64(binary.LittleEndian.Uint32(raw[4*i:]))
	}
	return out
}

func TestVerifyPcapSolution(t *testing.T) {
	g := NewCuckoo([]byte(key))
	if !g.Verify(testNonces(t), maxNonce) {
		t.Fatal("pcap solution does not verify")
	}
}

func TestVerifyRejects(t *testing.T) {
	g := NewCuckoo([]byte(key))
	bad := testNonces(t)
	bad[41]++ // breaks ascending/cycle
	if g.Verify(bad, maxNonce) {
		t.Fatal("mutated solution verified")
	}
	dup := testNonces(t)
	dup[41] = dup[40] // breaks strictly-ascending rule
	if g.Verify(dup, maxNonce) {
		t.Fatal("non-ascending solution verified")
	}
}

func TestSolveChallenge(t *testing.T) {
	if testing.Short() {
		t.Skip("solver needs seconds")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	k, nonces, iters, err := SolveChallenge(ctx, prefix, maxNonce, 1)
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	t.Logf("solved in %v after %d key iteration(s): %s", time.Since(start), iters, k)
	if len(nonces) != int(PROOFSIZE) {
		t.Fatalf("got %d nonces", len(nonces))
	}
	u64 := make([]uint64, len(nonces))
	for i, n := range nonces {
		u64[i] = uint64(n)
	}
	if !NewCuckoo([]byte(k)).Verify(u64, maxNonce) {
		t.Fatal("own solution does not verify")
	}
}

// BenchmarkSolvePinned times a single-threaded scan on the pinned 2022
// vector key. Deterministic (single scan order); run with -bench.
func BenchmarkSolvePinned(b *testing.B) {
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := searchOnce(ctx, key, maxNonce); !ok {
			b.Fatal("no solution")
		}
	}
}
