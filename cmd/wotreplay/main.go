package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/LockBlock-dev/wot/replay"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotreplay:", err)
	os.Exit(1)
}

func main() {
	dump := flag.String("dump", "", "write PREFIX.meta.json + PREFIX.stream.bin beside the outputs")
	metaOnly := flag.Bool("meta", false, "print only the setup JSON")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: wotreplay [-meta] [-dump PREFIX] file.wotreplay\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	r, err := replay.Open(flag.Arg(0))
	if err != nil {
		fatal(err)
	}
	if *metaOnly {
		printMeta(r)
		return
	}
	base := strings.TrimSuffix(filepath.Base(flag.Arg(0)), ".wotreplay")
	fmt.Printf("replay %s\n", base)
	fmt.Printf("  header: %x\n", r.Header)
	fmt.Printf("  map=%s player=%s vehicles=%d client=%s server=%s\n",
		r.MetaField("mapDisplayName"), r.MetaField("playerName"),
		len(vehicles(r)), r.MetaField("clientVersionFromExe"), r.MetaField("serverName"))
	fmt.Printf("  stream: %d bytes decrypted+inflated\n", len(r.Stream))
	if *dump != "" {
		if err := os.WriteFile(*dump+".stream.bin", r.Stream, 0644); err != nil {
			fatal(err)
		}
		fmt.Printf("  wrote %s.stream.bin\n", *dump)
	}
}

func vehicles(r *replay.Replay) map[string]any {
	m, _ := r.Meta["vehicles"].(map[string]any)
	return m
}

func printMeta(r *replay.Replay) {
	for _, k := range []string{"mapDisplayName", "playerName", "playerVehicle", "clientVersionFromExe", "serverName", "dateTime"} {
		if v := r.MetaField(k); v != "" {
			fmt.Printf("%s=%s\n", k, v)
		}
	}
	fmt.Printf("vehicles=%d\n", len(vehicles(r)))
}
