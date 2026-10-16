// Command wotkeydump recovers the live LogOnParams Blowfish encryptionKey
// from a running WorldOfTanks.exe without Cheat Engine — the headless
// equivalent of ce/wotkeydump.lua. It pattern-scans the game image for
// LogOnParams::addToStreamInternal (IDA sub_140E6E210), breaks on entry
// where RCX is the LogOnParams object, and appends timestamped key lines
// (wotkeys.txt format) for wotproxy -keyfile / wotlogin -hijack.
//
// Usage:
//
//	wotkeydump [-pid PID] [-name WorldOfTanks.exe] [-keyfile wotkeys.txt]
//	           [-pattern "48 89 ..."] [-maxhits 20] [-timeout 10m]
//
// Start the game to the login screen first, note the wall-clock time, then
// click Login: each login build (login#1, login#2 after PoW — same key)
// appends one line. Reach the hangar to prove the session is live. Key
// bytes go to the keyfile only; the console logs lengths/hashes.
//
// On Linux the target is the Windows EXE running under Wine/Proton (a
// regular process: ptrace + /proc/pid/mem). Needs ptrace permission —
// if attach fails with EPERM, loosen kernel.yama.ptrace_scope or start
// the game from the same shell.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/keydump"
)

func main() {
	pid := flag.Int("pid", 0, "target PID (0 = find by -name)")
	name := flag.String("name", "WorldOfTanks.exe", "game process/image name")
	pattern := flag.String("pattern", keydump.DefaultPattern, "hex signature with ?? wildcards")
	keyfile := flag.String("keyfile", "wotkeys.txt", "append timestamped key lines here")
	maxhits := flag.Int("maxhits", 20, "stop after this many dumps (0 = default 20)")
	force := flag.Bool("force", false, "attempt ptrace even on sandboxed targets (kernel decides)")
	timeout := flag.Duration("timeout", 0, "overall deadline (0 = default 10m)")
	wait := flag.Duration("wait", 0, "poll for the game process/image instead of failing when absent (e.g. 5m)")
	flag.Parse()

	needle, mask, err := keydump.ParsePattern(*pattern)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wotkeydump:", err)
		os.Exit(2)
	}
	cfg := keydump.Config{
		PID:     *pid,
		ExeName: *name,
		Needle:  needle,
		Mask:    mask,
		KeyFile: *keyfile,
		MaxHits: *maxhits,
		Force:   *force,
		Timeout: *timeout,
		WaitFor: *wait,
	}
	if err := keydump.Run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "wotkeydump:", err)
		os.Exit(1)
	}
	fmt.Println("wotkeydump: done")
}
