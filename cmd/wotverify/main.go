package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/LockBlock-dev/wot/replay"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotverify:", err)
	os.Exit(1)
}

// TailType is the end-of-stream integrity packet: [md5(setup JSON)].
const TailType = 0xffffffff

func main() {
	wantDigest := flag.String("digest", "", "expected entity-defs digest hex (checked against the in-stream record)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: wotverify [-digest HEX] file.wotreplay
Checks structural genuineness: container, decrypt, inflate, packet
chain, setup+results-MD5 tail record, optional entity digest,
method/property table coverage where tables are proven.
NOT EC signature verification: 2.4 files carry no EC signature
blocks (see REPLAY.md); this catches corruption and naive forgery,
not a checksum recomputed by an attacker.
`)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	ok := true
	fail := func(format string, args ...any) {
		fmt.Printf("FAIL "+format+"\n", args...)
		ok = false
	}
	r, err := replay.Open(flag.Arg(0))
	if err != nil {
		fatal(err)
	}
	fmt.Println("OK container+decrypt+inflate")
	pkts, err := replay.Packets(r.Stream)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("OK packet chain: %d packets\n", len(pkts))
	ver := r.ClientVersion()
	// Coverage: every packet type known, every fixed-block method
	// and property index resolved. Open var wires (documented in
	// REPLAY.md §6) are reported, not failures.
	knownTypes := map[uint32]bool{
		0x0: true, 0x1: true, 0x2: true, 0x4: true, 0x5: true,
		0x6: true, 0x7: true, 0x8: true, 0xa: true, 0xd: true,
		0xf:  true,
		0x11: true, 0x12: true, 0x15: true, 0x16: true, 0x17: true,
		0x18: true, 0x1a: true, 0x1b: true, 0x1c: true, 0x1d: true,
		0x1e: true, 0x1f: true, 0x20: true, 0x22: true, 0x23: true,
		0x24: true, 0x26: true, 0x28: true, 0x2b: true, 0x2d: true,
		0x2e: true, 0x30: true, 0x31: true, 0x32: true, 0x35: true,
		0x36: true, 0x37: true, 0x39: true, 0x3d: true,
		TailType: true,
	}
	for _, p := range pkts {
		if !knownTypes[p.Type] {
			fail("unknown packet type=%#x len=%d", p.Type, len(p.Data))
		}
	}
	tab, _, skipped, err := replay.DecodeAllLenient(ver, pkts)
	if err != nil {
		// Versions without proven tables (2.0 streams decode but
		// need their own .defs) skip coverage with a warning;
		// tabled versions must decode exactly.
		if strings.HasPrefix(ver, "2.1.") || strings.HasPrefix(ver, "2.3.") || strings.HasPrefix(ver, "2.4.") {
			fail("method decode: %v", err)
		} else {
			fmt.Printf("WARN no method tables for %s (%v)\n", ver, err)
		}
	} else {
		seen := map[uint32]int{}
		for _, s := range skipped {
			seen[s.MethodID]++
		}
		for mid, n := range seen {
			fmt.Printf("WARN open var wire mid=%d n=%d\n", mid, n)
		}
		fmt.Println("OK method coverage")
		_, pskipped, err := replay.DecodePropsLenient(tab, pkts)
		if err != nil {
			fail("prop decode: %v", err)
		} else if len(pskipped) != 0 {
			fail("open prop indexes: %v", pskipped)
		} else {
			fmt.Println("OK property coverage")
		}
	}
	last := pkts[len(pkts)-1]
	if last.Type != TailType || len(last.Data) != 16 {
		fail("tail packet type=%#x len=%d, want ffffffff/16", last.Type, len(last.Data))
	} else if sum := md5.Sum(r.BlocksRaw()); string(sum[:]) != string(last.Data) {
		fail("tail MD5 mismatch: file=%x computed=%x", last.Data, sum)
	} else {
		fmt.Println("OK tail MD5 covers setup+results JSON")
	}
	if *wantDigest != "" {
		found := ""
		for _, p := range pkts {
			if p.Type == 0x3d && len(p.Data) == 36 {
				if n := int(p.Data[0]) | int(p.Data[1])<<8 | int(p.Data[2])<<16 | int(p.Data[3])<<24; n == 32 && isHex(p.Data[4:36]) {
					found = string(p.Data[4:36])
				}
			}
		}
		if found == "" {
			fail("no digest record in stream")
		} else if !strings.EqualFold(found, *wantDigest) {
			fail("digest record %s != %s", found, *wantDigest)
		} else {
			fmt.Println("OK entity digest matches")
		}
	}
	if !ok {
		os.Exit(1)
	}
	fmt.Println("GENUINE (structural)")
}

func isHex(b []byte) bool {
	for _, c := range b {
		if !(('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')) {
			return false
		}
	}
	return len(b) > 0
}
