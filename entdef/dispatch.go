package entdef

import (
	"fmt"
	"io"
	"sort"
)

// Method component domains, as the defs name them.
const (
	CompClient = compClient
	CompCell   = compCell
	CompBase   = compBase
)

// ElementLength is how a method's arguments or a property's value are
// framed on the wire: a fixed byte count, or a variable payload whose
// length is written in a 1..4 byte header.
type ElementLength struct {
	Fixed bool
	Size  int // when Fixed
	Var   int // header bytes when variable
}

// String renders the length for logs and errors.
func (e ElementLength) String() string {
	if e.Fixed {
		return fmt.Sprintf("fixed(%d)", e.Size)
	}
	return fmt.Sprintf("var%d", e.Var)
}

// sortKey orders a method table the way BigWorld assigns exposed ids:
// fixed-length methods first, shortest first, then the variable ones by
// header width. Getting this wrong shifts every slot after the mistake,
// which is why it is a named function rather than an inline comparison.
func (e ElementLength) sortKey() (int, int) {
	if e.Fixed {
		return 0, e.Size
	}
	return e.Var, 0
}

// MethodDef is one exposed method slot: the name the client knows it by,
// its argument types in declared order, and how the call is framed.
type MethodDef struct {
	Name     string
	Args     []DataType
	ArgNames []string
	Length   ElementLength
}

// Codec is the value codec this method's arguments use. The
// variable-length header width belongs to the method, not to the caller:
// showGUI's STRING arg is a 2-byte header, and encoding it with the
// default 1-byte one produces a call the client misreads.
func (m *MethodDef) Codec() Codec {
	if m.Length.Fixed {
		return NewCodec()
	}
	return Codec{VarLen: m.Length.Var}
}

// ReadArgs decodes this method's arguments, in declared order.
func (m *MethodDef) ReadArgs(r io.Reader) ([]Value, error) {
	c := m.Codec()
	out := make([]Value, len(m.Args))
	for i, dt := range m.Args {
		v, err := c.Read(r, dt)
		if err != nil {
			return nil, fmt.Errorf("entdef: %s arg %d (%s): %w", m.Name, i, dt.Describe(), err)
		}
		out[i] = v
	}
	return out, nil
}

// WriteArgs encodes this method's arguments, in declared order.
func (m *MethodDef) WriteArgs(w io.Writer, args []Value) error {
	if len(args) != len(m.Args) {
		return fmt.Errorf("entdef: %s takes %d args, got %d", m.Name, len(m.Args), len(args))
	}
	c := m.Codec()
	for i, dt := range m.Args {
		if err := c.Write(w, dt, args[i]); err != nil {
			return fmt.Errorf("entdef: %s arg %d (%s): %w", m.Name, i, dt.Describe(), err)
		}
	}
	return nil
}

// PropertyDef is one client-visible property slot.
type PropertyDef struct {
	Name   string
	Type   DataType
	Length ElementLength
	// DetailLevel is the property's <DetailLevel>, empty when it has none.
	// The entity creation message carries the properties WITHOUT one; the
	// ones with a level ride the update that follows.
	DetailLevel string
	// Audience is who the property reaches, from the defs' distribution
	// flags: `ALL_CLIENTS`, `OTHER_CLIENTS` or `OWN_CLIENT`.
	Audience Audience
}

// EntityDispatch is one entity's client-facing tables, with the exposed
// ids the client uses as indexes.
type EntityDispatch struct {
	Name string
	// TypeID is the entity's index in the load order (entities.xml, then
	// each extension's own entities) — the id the wire carries in
	// CreateBasePlayer.
	TypeID int

	// ClientMethods, BaseMethods and CellMethods are indexed by exposed
	// id: the position in the slice IS the id the client sends.
	ClientMethods []MethodDef
	BaseMethods   []MethodDef
	CellMethods   []MethodDef

	// Properties is the client-server property table in wire order.
	Properties []PropertyDef
	// BaseProps is the subset of Properties that is base-hosted
	// (DATA_BASE). CreateBasePlayer carries exactly these; the
	// cell-hosted ones ride CreateCellPlayer instead.
	BaseProps []PropertyDef
	// CellProps is the subset that is cell-to-client (OWN_CLIENT or
	// ALL_CLIENTS). CreateCellPlayer carries exactly these, in the same
	// wire order — the client reads them with
	// `EntityDescription::readStreamToDict(FROM_CELL_TO_CLIENT_DATA)`,
	// which walks the description and takes every property in that
	// domain, with no count prefix.
	CellProps []PropertyDef
}

// MethodByID returns the method at an exposed id, or nil.
func (e *EntityDispatch) MethodByID(comp int, id int) *MethodDef {
	t := e.table(comp)
	if id < 0 || id >= len(t) {
		return nil
	}
	return &t[id]
}

// MethodByName returns the method with this name in the given component
// domain, or nil.
func (e *EntityDispatch) MethodByName(comp int, name string) *MethodDef {
	t := e.table(comp)
	for i := range t {
		if t[i].Name == name {
			return &t[i]
		}
	}
	return nil
}

// PropertyByName returns the property with this name, or nil.
func (e *EntityDispatch) PropertyByName(name string) *PropertyDef {
	for i := range e.Properties {
		if e.Properties[i].Name == name {
			return &e.Properties[i]
		}
	}
	return nil
}

func (e *EntityDispatch) table(comp int) []MethodDef {
	switch comp {
	case compClient:
		return e.ClientMethods
	case compBase:
		return e.BaseMethods
	case compCell:
		return e.CellMethods
	}
	return nil
}

// Dispatch is the whole script model's client-facing view: every entity
// the defs declare, with its exposed method and property tables.
type Dispatch struct {
	byName map[string]*EntityDispatch
	names  []string
}

// NewDispatch builds the dispatch tables for the named entities.
//
// The exposed-id order is BigWorld's: the entity's own and inherited
// methods that are exposed, sorted by element length (fixed first,
// shortest first, then variable by header width). A method that is not
// exposed takes no slot, so it never shifts the ids after it.
func NewDispatch(l *Loader, names []string) (*Dispatch, error) {
	d := &Dispatch{byName: make(map[string]*EntityDispatch, len(names))}
	for _, name := range names {
		e, err := l.ParseEntity(name)
		if err != nil {
			return nil, fmt.Errorf("entdef: dispatch: %s: %w", name, err)
		}
		ed := &EntityDispatch{
			Name:          e.Name,
			ClientMethods: methodTable(e.ClientMethods, e.IfaceClientMethods),
			BaseMethods:   methodTable(e.BaseMethods, e.IfaceBaseMethods),
			CellMethods:   methodTable(e.CellMethods, e.IfaceCellMethods),
		}
		for _, p := range e.CSPropsOrdered() {
			ed.Properties = append(ed.Properties, PropertyDef{
				Name:        p.Name,
				Type:        p.Type,
				Length:      elementLength(p.StreamSize(), int(p.VarLen)),
				DetailLevel: p.DetailLevel,
				Audience:    p.Audience(),
			})
		}
		// BaseProps is the createBasePlayer payload, so it follows the
		// WIRE order (interfaces first, then declaration), not the
		// FullIndex order Properties uses for addressing.
		for _, p := range e.WireProps() {
			if p.Flags&flagBase != 0 {
				ed.BaseProps = append(ed.BaseProps, PropertyDef{
					Name:   p.Name,
					Type:   p.Type,
					Length: elementLength(p.StreamSize(), int(p.VarLen)),
				})
			}
			// Cell-to-client is pass 2 of EntityDescription::addToStream:
			// cell data (no BASE flag) that is client-visible. A
			// BASE_AND_CLIENT property carries OWN_CLIENT too, so the
			// BASE exclusion is what keeps it out.
			if p.Flags&flagBase == 0 && p.Flags&cellToClientMask != 0 {
				ed.CellProps = append(ed.CellProps, PropertyDef{
					Name:   p.Name,
					Type:   p.Type,
					Length: elementLength(p.StreamSize(), int(p.VarLen)),
				})
			}
		}
		// Entity type ids are 1-based on the wire: 0 is the "no entity"
		// sentinel, and entities.xml order (Account first) gives Account
		// id 1, which is what createBasePlayer carries.
		ed.TypeID = len(d.names) + 1
		d.byName[e.Name] = ed
		d.names = append(d.names, e.Name)
	}
	sort.Strings(d.names)
	return d, nil
}

// Entity returns one entity's tables, or nil.
func (d *Dispatch) Entity(name string) *EntityDispatch {
	return d.byName[name]
}

// Entities lists the loaded entity names, sorted.
func (d *Dispatch) Entities() []string { return d.names }

// methodTable builds one component domain's exposed-id table: the
// entity's own methods plus its interfaces', exposed only, deduplicated
// by name, ordered by element length.
//
// The dedup is load-bearing. Account declares `requestToken` itself and
// also inherits it from AccountAuthTokenProvider; counting it twice
// lengthens the table and shifts every slot after it, so the client's
// exposed id 13 lands on accountDebugger_registerDebugTaskResult (20 B)
// instead of doCmdInt3 (28 B) and every call leaves 8 bytes unread.
func methodTable(own, iface []Method) []MethodDef {
	var out []MethodDef
	seen := make(map[string]bool, len(own)+len(iface))
	// Interfaces first, then the entity's own methods: that is the order
	// `EntityDescription::addToStream` walks, and the sort below is STABLE,
	// so methods that compare equal keep this relative order. Getting it
	// backwards shifts every tied method's exposed id — which is how
	// `Account.update` ended up on the element the client reads as a
	// one-byte-argument method.
	for _, list := range [][]Method{iface, own} {
		for _, m := range list {
			if m.Flags&(expAllClients|expOwnClient) == 0 {
				continue
			}
			if seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			out = append(out, MethodDef{
				Name:     m.Name,
				Args:     m.Args,
				ArgNames: m.ArgNames,
				Length:   elementLength(m.ArgsStreamSize(), int(m.Var)),
			})
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		ka, sa := out[a].Length.sortKey()
		kb, sb := out[b].Length.sortKey()
		if ka != kb {
			return ka < kb
		}
		return sa < sb
	})
	return out
}

// elementLength turns a stream size into an element length: a
// non-negative size is fixed, -1 is variable with the site's header.
func elementLength(streamSize, varLen int) ElementLength {
	if streamSize >= 0 {
		return ElementLength{Fixed: true, Size: streamSize}
	}
	if varLen <= 0 {
		varLen = 1
	}
	return ElementLength{Var: varLen}
}
