// Command wotdefs prints the script model's client-facing tables: for
// each entity, the exposed method ids the client sends and the
// client-server property table in wire order.
//
//	wotdefs -defs DIR                 every entity, one line each
//	wotdefs -defs DIR -entity Account the full tables for one entity
//	wotdefs -defs DIR -json           the whole model as JSON
//
// The ids are the ones the client puts on the wire: exposed methods only,
// deduplicated by name, ordered by element length (fixed ascending, then
// variable by header width). That order is what makes an id mean the same
// thing on both sides.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/LockBlock-dev/wot/entdef"
)

func main() {
	defs := flag.String("defs", "../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs",
		"scripts/entity_defs directory")
	entity := flag.String("entity", "", "print the full tables for this entity")
	asJSON := flag.Bool("json", false, "print the whole model as JSON")
	flag.Parse()

	l := &entdef.Loader{Dir: *defs}
	names, err := l.LoadEntities()
	if err != nil {
		fatal(err)
	}
	d, err := entdef.NewDispatch(l, names)
	if err != nil {
		fatal(err)
	}

	if *entity != "" {
		e := d.Entity(*entity)
		if e == nil {
			fatal(fmt.Errorf("no entity %q", *entity))
		}
		printEntity(e)
		return
	}

	if *asJSON {
		out := map[string]any{}
		for _, name := range d.Entities() {
			e := d.Entity(name)
			ent := map[string]any{
				"client": methodsJSON(e.ClientMethods),
				"base":   methodsJSON(e.BaseMethods),
				"cell":   methodsJSON(e.CellMethods),
				"props":  propsJSON(e.Properties),
			}
			out[name] = ent
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fatal(err)
		}
		return
	}

	for _, name := range d.Entities() {
		e := d.Entity(name)
		fmt.Printf("%-28s client %3d  base %3d  cell %3d  props %3d\n",
			name, len(e.ClientMethods), len(e.BaseMethods), len(e.CellMethods), len(e.Properties))
	}
}

func printEntity(e *entdef.EntityDispatch) {
	fmt.Printf("%s\n", e.Name)
	for _, tbl := range []struct {
		name string
		list []entdef.MethodDef
	}{
		{"client", e.ClientMethods},
		{"base", e.BaseMethods},
		{"cell", e.CellMethods},
	} {
		fmt.Printf("\n  %s methods (%d)\n", tbl.name, len(tbl.list))
		for i, m := range tbl.list {
			fmt.Printf("    %3d  %-44s %-12s %d args\n", i, m.Name, m.Length, len(m.Args))
		}
	}
	fmt.Printf("\n  properties (%d)\n", len(e.Properties))
	for i, p := range e.Properties {
		fmt.Printf("    %3d  %-44s %-12s %s\n", i, p.Name, p.Length, p.Type.Describe())
	}
}

func methodsJSON(list []entdef.MethodDef) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for i, m := range list {
		args := make([]string, 0, len(m.Args))
		for _, a := range m.Args {
			args = append(args, a.Describe())
		}
		out = append(out, map[string]any{
			"id": i, "name": m.Name, "length": m.Length.String(), "args": args,
		})
	}
	return out
}

func propsJSON(list []entdef.PropertyDef) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for i, p := range list {
		out = append(out, map[string]any{
			"index": i, "name": p.Name, "length": p.Length.String(), "type": p.Type.Describe(),
		})
	}
	sort.SliceStable(out, func(a, b int) bool {
		return out[a]["index"].(int) < out[b]["index"].(int)
	})
	return out
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wotdefs: %v\n", err)
	os.Exit(1)
}
