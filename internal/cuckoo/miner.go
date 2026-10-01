// Cuckoo Cycle solver driver.
//
// The graph search below (path/tryNonce/recoverNonces) is adapted from
// ZiRo-/cuckgo/miner/miner_lib (MIT, (c) 2016 ZiRo — see LICENSE-THIRD-PARTY
// and the notice preserved on each adapted function). It implements John
// Tromp's original simple miner, the same algorithm BigWorld's
// CuckooCycleLoginChallenge uses client-side.
//
// Concurrency model (measured, not assumed): the simple miner needs the
// whole edge set in ONE union-find table, so partitioning nonces across
// threads misses cycles spanning partitions — overlapping full scans just
// burn N× CPU for the same discovery order (benchmarked: 1 thread 167 ms,
// 16 threads worse). Throughput instead comes from racing successive KEYS
// (SolveChallenge): most keys hold no cycle (full wasted scans), so the
// first verified win usually arrives long before a serial retry chain
// would finish it. Each key attempt is one single-threaded scan;
// first verified solution wins, the rest are canceled.
//
// Parameters match the LoginApp challenge: SIZESHIFT=20, PROOFSIZE=42,
// nonces ascending uint32 below maxNonce (easiness).
package cuckoo

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

const maxPathLen = 8192

// searchOnce runs one complete simple-miner scan for key and returns the
// first recovered 42-cycle. Nonces ascend from 0, so the same key always
// yields the same solution (deterministic).
func searchOnce(ctx context.Context, key string, maxNonce uint64) ([]uint32, bool) {
	if maxNonce > 1<<32 {
		return nil, false
	}
	graph := NewCuckoo([]byte(key))
	easiness := int(maxNonce)
	// Node values fit 20 bits: uint32 halves table memory (8→4 MB),
	// keeping the working set closer to L3.
	cuckoo := make([]uint32, 1+SIZE)
	us := make([]uint32, maxPathLen)
	vs := make([]uint32, maxPathLen)
	sol := make([]int, PROOFSIZE)
	for nonce := 0; nonce < easiness; nonce++ {
		// Context checks are hoisted out of the per-nonce path;
		// cancellation still lands within ~1k nonces (<1 ms).
		if nonce&1023 == 0 {
			select {
			case <-ctx.Done():
				return nil, false
			default:
			}
		}
		if tryNonce(graph, cuckoo, us, vs, sol, nonce, easiness) {
			out := make([]uint32, PROOFSIZE)
			for i, v := range sol {
				out[i] = uint32(v)
			}
			return out, true
		}
	}
	return nil, false
}

// SolveChallenge implements BigWorld's writeResponseToStream loop: it tries
// key = prefix+"0", prefix+"1", ... and returns the first key whose graph
// holds a cycle. Up to workers keys are mined concurrently (single scan
// each); the first verified solution wins and the rest are canceled, so
// failed full scans overlap instead of summing. workers<=0 defaults to 4
// (covers the usual 1–4 attempts with bounded burn); values above 16 are
// clamped. Returns the winning key, its nonces, and its 1-based attempt
// index (same meaning as the old serial counter).
func SolveChallenge(ctx context.Context, prefix string, maxNonce uint64, workers int) (key string, nonces []uint32, iters int, err error) {
	if workers <= 0 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}
	if maxNonce > 1<<32 {
		return "", nil, 0, fmt.Errorf("cuckoo: maxNonce %d exceeds uint32 range", maxNonce)
	}
	type res struct {
		idx    int
		key    string
		nonces []uint32
		ok     bool
	}
	base := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, base, err
		}
		cctx, cancel := context.WithCancel(ctx)
		ch := make(chan res, workers)
		var wg sync.WaitGroup
		for b := 0; b < workers; b++ {
			idx := base + b
			key := prefix + strconv.Itoa(idx)
			wg.Add(1)
			go func() {
				defer wg.Done()
				nonces, ok := searchOnce(cctx, key, maxNonce)
				if ok && !verifyU32(key, nonces, maxNonce) {
					ok = false
					nonces = nil
				}
				select {
				case ch <- res{idx, key, nonces, ok}:
				case <-cctx.Done():
				}
			}()
		}
		won := false
		for b := 0; b < workers; b++ {
			select {
			case <-ctx.Done():
				cancel()
				wg.Wait()
				return "", nil, base, ctx.Err()
			case r := <-ch:
				if r.ok && !won {
					won = true
					key, nonces, iters = r.key, r.nonces, r.idx+1
				}
			}
			if won {
				break
			}
		}
		cancel()
		wg.Wait()
		if won {
			return key, nonces, iters, nil
		}
		base += workers
	}
}

// verifyU32 self-checks a found solution before it is claimed (defense in
// depth; the caller re-verifies too).
func verifyU32(key string, nonces []uint32, maxNonce uint64) bool {
	u64 := make([]uint64, len(nonces))
	for i, n := range nonces {
		u64[i] = uint64(n)
	}
	return NewCuckoo([]byte(key)).Verify(u64, maxNonce)
}

// tryNonce inserts one edge and reports a recovered 42-cycle, if any.
// Adapted from worker() in ZiRo-/cuckgo/miner/miner_lib (MIT (c) 2016 ZiRo).
func tryNonce(graph *Cuckoo, cuckoo []uint32, us, vs []uint32, sol []int, nonce, easiness int) bool {
	us[0] = uint32(graph.Sipnode(uint64(nonce), 0))
	u := cuckoo[us[0]]
	vs[0] = uint32(HALFSIZE + graph.Sipnode(uint64(nonce), 1))
	v := cuckoo[vs[0]]
	if u == vs[0] || v == us[0] {
		return false // ignore duplicate edges
	}
	nu := path(cuckoo, u, us)
	nv := path(cuckoo, v, vs)
	if nu == -1 || nv == -1 {
		return false
	}
	if us[nu] == vs[nv] {
		min := nu
		if nv < min {
			min = nv
		}
		nu -= min
		nv -= min
		for us[nu] != vs[nv] {
			nu++
			nv++
		}
		if length := nu + nv + 1; length == int(PROOFSIZE) {
			return recoverNonces(graph, us, nu, vs, nv, sol, nonce)
		}
		return false
	}
	if nu < nv {
		for nu != 0 {
			nu--
			cuckoo[us[nu+1]] = us[nu]
		}
		cuckoo[us[0]] = vs[0]
	} else {
		for nv != 0 {
			nv--
			cuckoo[vs[nv+1]] = vs[nv]
		}
		cuckoo[vs[0]] = us[0]
	}
	return false
}

// path follows parent pointers to the root, recording the trail.
// Adapted from CuckooSolve.path in ZiRo-/cuckgo/miner/miner_lib
// (MIT (c) 2016 ZiRo).
func path(cuckoo []uint32, u uint32, us []uint32) int {
	nu := 0
	for nu = 0; u != 0; u = cuckoo[u] {
		nu++
		if nu >= maxPathLen {
			for nu != 0 && us[nu-1] != u {
				nu--
			}
			return -1
		}
		us[nu] = u
	}
	return nu
}

type edgeUV struct{ u, v uint64 }

// recoverNonces maps a found cycle back to its ascending edge nonces.
// Adapted from CuckooSolve.solution in ZiRo-/cuckgo/miner/miner_lib
// (MIT (c) 2016 ZiRo). Cycle edges are collected into a fixed array
// (exact compare, no map, no heap allocs), then matched by re-scanning
// nonces — but only up to hi, the just-inserted nonce: edges insert in
// nonce order, so every cycle edge sits at or below hi.
func recoverNonces(graph *Cuckoo, us []uint32, nu int, vs []uint32, nv int, sol []int, hi int) bool {
	var cyc [128]edgeUV
	nc := 0
	put := func(u, v uint64) {
		for i := 0; i < nc; i++ {
			if cyc[i].u == u && cyc[i].v == v {
				return
			}
		}
		if nc < len(cyc) {
			cyc[nc] = edgeUV{u, v}
			nc++
		}
	}
	put(uint64(us[0]), uint64(vs[0])-HALFSIZE)
	for nu != 0 { // u's in even position; v's in odd
		nu--
		put(uint64(us[(nu+1)&^1]), uint64(us[nu|1])-HALFSIZE)
	}
	for nv != 0 { // u's in odd position; v's in even
		nv--
		put(uint64(vs[nv|1]), uint64(vs[(nv+1)&^1])-HALFSIZE)
	}
	n := 0
	for nonce := 0; nonce <= hi; nonce++ {
		eu := graph.Sipnode(uint64(nonce), 0)
		ev := graph.Sipnode(uint64(nonce), 1)
		for i := 0; i < nc; i++ {
			if cyc[i].u == eu && cyc[i].v == ev {
				sol[n] = nonce
				n++
				cyc[i] = cyc[nc-1] // one-to-one: consume on match
				nc--
				break
			}
		}
	}
	return n == int(PROOFSIZE)
}
