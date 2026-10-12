// Command wotevents extracts a battle timeline from a .wotreplay
// file and prints it as JSON: damage, kills (derived from
// health→0 + recent attacker), explosions, tracers, projectile
// explodes, shot results, plus battle meta.
//
// Usage: wotevents [-pretty] [-shots] file.wotreplay
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/replay"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotevents:", err)
	os.Exit(1)
}

func main() {
	pretty := flag.Bool("pretty", false, "indent JSON output")
	shots := flag.Bool("shots", false, "print [mm:ss] [name] [tank] SHOT feed instead of JSON")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: wotevents [-pretty] [-shots] file.wotreplay")
		os.Exit(2)
	}
	path := flag.Arg(0)
	r, err := replay.Open(path)
	if err != nil {
		fatal(err)
	}
	pkts, err := replay.Packets(r.Stream)
	if err != nil {
		fatal(err)
	}
	tl, err := replay.Extract(path, r, pkts)
	if err != nil {
		fatal(err)
	}
	var out []byte
	if *shots {
		for _, s := range replay.ShotFeed(tl) {
			fmt.Println(s.String())
		}
		return
	}
	if *pretty {
		out, err = json.MarshalIndent(tl, "", "  ")
	} else {
		out, err = json.Marshal(tl)
	}
	if err != nil {
		fatal(err)
	}
	os.Stdout.Write(append(out, '\n'))
}
