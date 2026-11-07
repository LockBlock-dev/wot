package main

import (
	"fmt"
	"os"

	"github.com/LockBlock-dev/wot/entdef"
)

func main() {
	l := &entdef.Loader{Dir: "../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"}
	names, err := l.LoadEntities()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	d, err := entdef.NewDispatch(l, names)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	e := d.Entity("Avatar")
	fmt.Printf("Avatar TypeID=%d base props (%d):\n", e.TypeID, len(e.BaseProps))
	for _, p := range e.BaseProps {
		fmt.Printf("  %-40s %s\n", p.Name, p.Type.Describe())
	}
}
