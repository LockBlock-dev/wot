// Command wotunpack dumps BigWorld packed-section files (the binary form
// of .def/.xml under res/scripts, magic 0x62a14e45) as readable XML.
//
// Usage: wotunpack <file>...  (output goes to stdout, one file after
// another; redirect to capture)
//
// Values render like the XML originals: strings raw, ints decimal,
// bools true/false, floats plain, binary blobs base64 (or raw when the
// bytes are printable ASCII).
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/LockBlock-dev/wot/entdef"
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: wotunpack <file>...")
		os.Exit(2)
	}
	failed := false
	for _, path := range flag.Args() {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wotunpack: %s: %v\n", path, err)
			failed = true
			continue
		}
		f, err := entdef.ParseFile(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wotunpack: %s: %v\n", path, err)
			failed = true
			continue
		}
		// The packed root is synthetic ("root" with no own data):
		// print its children as top-level tags.
		for _, c := range f.Root.Children {
			writeSection(os.Stdout, c, 0)
		}
	}
	if failed {
		os.Exit(1)
	}
}

func writeSection(w *os.File, s *entdef.Section, depth int) {
	pad := strings.Repeat("  ", depth)
	val := valueText(s)
	if len(s.Children) == 0 {
		if val == "" {
			fmt.Fprintf(w, "%s<%s/>\n", pad, xmlEscape(s.Name))
		} else {
			fmt.Fprintf(w, "%s<%s>%s</%s>\n", pad, xmlEscape(s.Name), xmlEscape(val), xmlEscape(s.Name))
		}
		return
	}
	if val == "" {
		fmt.Fprintf(w, "%s<%s>\n", pad, xmlEscape(s.Name))
	} else {
		fmt.Fprintf(w, "%s<%s>%s\n", pad, xmlEscape(s.Name), xmlEscape(val))
	}
	for _, c := range s.Children {
		writeSection(w, c, depth+1)
	}
	fmt.Fprintf(w, "%s</%s>\n", pad, xmlEscape(s.Name))
}

// valueText renders own data: AsString covers string/int/bool/float;
// blobs show raw when printable ASCII, else base64.
func valueText(s *entdef.Section) string {
	if v := s.AsString(); v != "" {
		return v
	}
	if len(s.Raw) == 0 {
		return ""
	}
	if utf8.Valid(s.Raw) && printableASCII(s.Raw) {
		return string(s.Raw)
	}
	return base64.StdEncoding.EncodeToString(s.Raw)
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			if c != '\t' && c != '\n' && c != '\r' {
				return false
			}
		}
	}
	return true
}

func xmlEscape(s string) string {
	r := strings.ReplaceAll(s, "&", "&amp;")
	r = strings.ReplaceAll(r, "<", "&lt;")
	r = strings.ReplaceAll(r, ">", "&gt;")
	return r
}
