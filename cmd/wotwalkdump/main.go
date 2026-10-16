// Command wotwalkdump records the login entity-defs digest walk live
// from a running WorldOfTanks.exe: entry names in visit order with
// pass/fail each (the runtime fail-set no offline reader can derive).
//
// Usage:
//
//	wotwalkdump [-pid PID] [-name WorldOfTanks.exe] [-out walkdump.txt]
//	            [-maxentries 800] [-timeout 15m] [-wait 5m] [-quiet 20s]
//	            [-wotdefs DIR -entitydefs DIR [-want DIGEST_HEX]]
//
// Start the game to the login screen first, then click Login: the walk
// fires once during loading. With -wotdefs/-entitydefs the captured
// fail-set feeds entdef.ComputeDigestFull and prints the recomputed
// digest (compare with -want, e.g. live.env DIGEST_HEX).
//
// Auto-login / mid-startup attach freezes: attaching during init churn
// can stall the game, and the walk fires once per launch. Reliable flow:
// set PROTON_WAIT_ATTACH=1 in the launch options (game spawns stopped
// pre-exec), start /tmp/wotwalkdump -force -wait 10m (attaches calmly,
// waits for the image, arms), then release the game — the walk is
// caught during init with no race.
//
// Linux/Wine only, same ptrace rules as wotkeydump (Yama scope,
// no sandboxed pressure-vessel targets). Read-only apart from the
// single int3 byte, always restored; threads detached + CONTed on
// every exit path.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/keydump"
)

func main() {
	pid := flag.Int("pid", 0, "target PID (0 = find by -name)")
	name := flag.String("name", "WorldOfTanks.exe", "game process/image name")
	pattern := flag.String("pattern", keydump.WalkDefaultPattern, "hex signature with ?? wildcards")
	out := flag.String("out", "walkdump.txt", "ordered walk dump (index pass name per line)")
	maxentries := flag.Int("maxentries", 800, "stop after this many walk hits")
	timeout := flag.Duration("timeout", 15*time.Minute, "overall deadline")
	wait := flag.Duration("wait", 0, "poll for the game process instead of failing when absent")
	quiet := flag.Duration("quiet", 20*time.Second, "end the walk after this long without a hit once started")
	force := flag.Bool("force", false, "attempt ptrace even on sandboxed targets (kernel decides; may briefly freeze the game)")
	wotdefs := flag.String("wotdefs", "", "wotdefs dir for digest recompute (empty = skip)")
	entitydefs := flag.String("entitydefs", "", "scripts entity_defs dir for digest recompute (empty = skip)")
	want := flag.String("want", "", "expected digest hex (compared, e.g. live.env DIGEST_HEX)")
	flag.Parse()

	needle, mask, err := keydump.ParsePattern(*pattern)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotwalkdump:", err)
		os.Exit(2)
	}
	entries, werr := keydump.Walk(keydump.WalkConfig{
		PID: *pid, ExeName: *name,
		Needle: needle, Mask: mask,
		OutPath: *out, MaxEntries: *maxentries,
		Timeout: *timeout, WaitFor: *wait, QuietAfter: *quiet,
		Force: *force,
	})
	var sb strings.Builder
	pass, fail := 0, 0
	for _, e := range entries {
		p := 0
		if e.Pass {
			p = 1
			pass++
		} else {
			fail++
		}
		fmt.Fprintf(&sb, "%d %d %s\n", e.Index, p, e.Name)
	}
	if len(entries) == 0 && werr != nil {
		// Pre-capture failure (no process, sandboxed target, ...):
		// don't leave a misleading empty dump behind.
		fmt.Fprintln(os.Stderr, "wotwalkdump:", werr)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "wotwalkdump: write dump:", err)
		os.Exit(1)
	}
	fmt.Printf("wotwalkdump: %d entries (%d pass, %d fail) -> %s\n", len(entries), pass, fail, *out)
	if *wotdefs != "" && *entitydefs != "" {
		skip := map[string]bool{}
		for _, e := range entries {
			if !e.Pass {
				skip[e.Name] = true
			}
		}
		d, err := entdef.ComputeDigestFull(*wotdefs, *entitydefs, skip)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wotwalkdump: digest:", err)
			os.Exit(1)
		}
		got := fmt.Sprintf("%x", d)
		fmt.Printf("wotwalkdump: digest %s\n", got)
		if *want != "" {
			if strings.EqualFold(got, *want) {
				fmt.Println("wotwalkdump: MATCH")
			} else {
				fmt.Println("wotwalkdump: MISMATCH")
				os.Exit(1)
			}
		}
	}
	if werr != nil {
		fmt.Fprintln(os.Stderr, "wotwalkdump:", werr, "(dump above is partial)")
		os.Exit(1)
	}
}
