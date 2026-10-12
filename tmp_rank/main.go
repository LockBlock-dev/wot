package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/LockBlock-dev/wot/entdef"
)

func main() {
	l := &entdef.Loader{Dir: os.Args[1]}
	e, err := l.ParseEntity("Avatar")
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	type m struct {
		name string
		size int
	}
	var fixed []m
	seen := map[string]bool{}
	// exposed-only? entdef Method.Flags bit for exposed — dump flags to see
	show := func(tag string, ms []entdef.Method) {
		for _, mm := range ms {
			fmt.Printf("%s %-32s nargs=%d flags=%#02x\n", tag, mm.Name, len(mm.Args), mm.Flags)
		}
	}
	show("iface", e.IfaceCellMethods)
	show("own", e.CellMethods)
	_ = fixed
	_ = seen
	_ = sort.Ints
}
