// Command wotdpapi unwraps one Wine-DPAPI hex blob (e.g. a
// user_info.xml node) using Wine's own crypt32 in-prefix: no
// network, no broker, no game. Plaintext goes to a 0600 file;
// stdout carries lengths only, never values.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/LockBlock-dev/wot/dpapi"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotdpapi:", err)
	os.Exit(1)
}

func main() {
	in := flag.String("in", "", "hex blob file (e.g. extracted user_info.xml node text)")
	out := flag.String("out", "", "plaintext output file (0600, required)")
	flag.Parse()
	if *in == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		fatal(err)
	}
	hexBlob := strings.TrimSpace(string(raw))
	plain, err := dpapi.Unprotect(hexBlob)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, plain, 0600); err != nil {
		fatal(err)
	}
	for i := range plain {
		plain[i] = 0
	}
	fmt.Printf("unprotected: in=%d hex chars out=%dB -> %s\n", len(hexBlob), len(plain), *out)
}
