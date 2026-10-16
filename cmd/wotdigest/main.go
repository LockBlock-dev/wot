// Command wotdigest computes the offline LoginApp entity-defs digest
// (the 16 B after the 4 LogOnParams strings when flags&1) for one client
// version. Game defs live outside this repo, uncommitted (sibling dirs
// wotdefs-2.4.0/, wotdefs-2.4.1/, scripts-2.4.1/); run from wot/.
//
// Usage: wotdigest [-version 2.4.0|2.4.1] [-wotdefs DIR] [-entitydefs DIR]
//
// Prints computed= hex, the pinned live truth, and MATCH/MISMATCH.
// Exit 1 on mismatch (a mismatching digest draws status 70), 2 on usage
// or I/O errors. 2.4.1 truth is still OPEN (see entdef.Skip241).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/entdef"
)

func main() {
	version := flag.String("version", "2.4.0", "client version: 2.4.0 or 2.4.1")
	wotdefs := flag.String("wotdefs", "", "wotdefs dir (components/extensions/mode_entities/space_defs)")
	entitydefs := flag.String("entitydefs", "", "scripts entity_defs dir (entities.xml + entity_defs)")
	flag.Parse()

	var skip map[string]bool
	var truth string
	switch *version {
	case "2.4.0":
		if *wotdefs == "" {
			*wotdefs = "../wotdefs-2.4.0"
		}
		if *entitydefs == "" {
			*entitydefs = "../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"
		}
		truth = entdef.Truth240
	case "2.4.1":
		if *wotdefs == "" {
			*wotdefs = "../wotdefs-2.4.1"
		}
		if *entitydefs == "" {
			*entitydefs = "../scripts-2.4.1/entity_defs"
		}
		skip = entdef.Skip241
		truth = entdef.Truth241
	default:
		fmt.Fprintf(os.Stderr, "wotdigest: unknown -version %q (want 2.4.0 or 2.4.1)\n", *version)
		os.Exit(2)
	}

	d, err := entdef.DigestVersion(*wotdefs, *entitydefs, skip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wotdigest: %v\n", err)
		os.Exit(2)
	}
	got := fmt.Sprintf("%x", d)
	fmt.Printf("version=%s computed=%s truth=%s\n", *version, got, truth)
	if got != truth {
		fmt.Printf("MISMATCH (truth still open for %s)\n", *version)
		os.Exit(1)
	}
	fmt.Println("MATCH")
}
