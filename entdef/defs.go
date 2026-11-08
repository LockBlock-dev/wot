// Entity walk and digest driver, ported from
// programming/bigworld/lib/entitydef/entity_description{,_map}.cpp (14.4.1).
// Only digest-relevant state is modeled; presentation-only sections
// (Volatile, LoD, defaults, widgets) are tolerated and ignored.
package entdef

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Distribution flags (data_description.hpp).
const (
	flagGhosted     = 0x01
	flagOtherClient = 0x02
	flagOwnClient   = 0x04
	flagBase        = 0x08
	flagClientOnly  = 0x10
	flagPersistent  = 0x20
	flagEditorOnly  = 0x40
	flagID          = 0x80
	flagReplay      = 0x100 // DATA_REPLAY (ExposedForReplay)

	distMask = flagGhosted | flagOtherClient | flagOwnClient | flagBase | flagClientOnly | flagEditorOnly

	// cellToClientMask is EntityDescription::FROM_CELL_TO_CLIENT_DATA:
	// the properties CreateCellPlayer carries. OWN_CLIENT is the player's
	// own entity, ALL_CLIENTS is ghosted + other-client + own-client.
	cellToClientMask = flagOwnClient | flagGhosted | flagOtherClient
)

var flagTable = map[string]int{
	"CELL_PRIVATE":        0,
	"CELL_PUBLIC":         flagGhosted,
	"OTHER_CLIENTS":       flagGhosted | flagOtherClient,
	"OWN_CLIENT":          flagOwnClient,
	"BASE":                flagBase,
	"BASE_AND_CLIENT":     flagOwnClient | flagBase,
	"CELL_PUBLIC_AND_OWN": flagGhosted | flagOwnClient,
	"ALL_CLIENTS":         flagGhosted | flagOtherClient | flagOwnClient,
	"EDITOR_ONLY":         flagEditorOnly,
}

// Method components share MethodDescription::Component values.
const (
	compClient = 0
	compCell   = 1
	compBase   = 2
)

// Method exposure bits.
const (
	expAllClients = 0x4
	expOwnClient  = 0x8
)

// Bare-<Exposed/> bit ORs per domain (walkprobe2 verifies; IDA error
// text implies a token list, bare = exposed-to-all).
var (
	// ExposedBareBaseBits ORed for bare <Exposed/> on base methods.
	ExposedBareBaseBits = uint8(expAllClients | expOwnClient)
	// ExposedBareCellBits ORed for bare <Exposed/> on cell methods.
	ExposedBareCellBits = uint8(expAllClients | expOwnClient)
	// ExposedOwnCellBits ORed for <Exposed>OWN_CLIENT</Exposed> on cell.
	ExposedOwnCellBits = uint8(expOwnClient)
)

// Property is one parsed entity property.
type Property struct {
	Name      string
	Flags     int
	Type      DataType
	VarLen    uint // VariableLengthHeaderSize, default 1
	FullIndex int  // client-server full index (assigned after sorting)
	Volatile  bool // per-property volatile (fork addition; usually false)
	// DetailLevel is the property's <DetailLevel> (MY_VEHICLE, ...), empty
	// when it has none. It decides which half of the replication a property
	// rides: the ones with no detail level go in the entity creation
	// message, the ones with one ride the update that follows.
	DetailLevel string
}

// StreamSize mirrors DataDescription::streamSize (datatype size, or
// -varLenHeader when variable).
func (p *Property) StreamSize() int {
	if s := p.Type.StreamSize(); s >= 0 {
		return s
	}
	return -int(p.VarLen)
}

// Method is one parsed entity method.
type Method struct {
	Name         string
	Flags        uint8 // component low bits + exposure bits
	Args         []DataType
	ArgNames     []string   // parallel to Args (fork tuple visitor hashes them)
	ReturnValues []DataType // parsed for validation; hashed if non-empty
	ReturnNames  []string   // parallel to ReturnValues
	Var          uint       // VariableLengthHeaderSize, default 1
	AllowUnsafe  bool       // <AllowUnsafeData> (sets flag bit 0x10)
}

// ArgsStreamSize sums arg sizes with -1 propagation.
func (m *Method) ArgsStreamSize() int {
	s := 0
	for _, a := range m.Args {
		if s < 0 {
			break
		}
		as := a.StreamSize()
		if as < 0 {
			s = -1
		} else {
			s += as
		}
	}
	return s
}

// Entity accumulates one entity's digest-relevant state.
type Entity struct {
	Name          string
	Props         []Property
	propMap       map[string]int
	CSProps       []int // indexes into Props, client-server subset
	ClientMethods []Method
	methodMap     map[string]int
	BaseMethods   []Method // parsed for validation; hashed only if exposed
	CellMethods   []Method
	// Interface methods are stored separately (fork keeps own and iface
	// method arrays apart; the digest visits own first, then ifaces with
	// continuing per-domain legacy indexes — IDA sub_142A93420).
	IfaceClientMethods []Method
	IfaceBaseMethods   []Method
	IfaceCellMethods   []Method
	ifaceMethodMap     map[string]int
}

// CSPropsOrdered returns the client-server properties in FullIndex
// order: CSProps already holds Props indexes in that order after
// finish. This is the digest/addressing order (fixed sizes first, then
// variable by header width), used by the replay property table
// generator and by property-update element ids.
func (e *Entity) CSPropsOrdered() []Property {
	out := make([]Property, 0, len(e.CSProps))
	for _, pi := range e.CSProps {
		out = append(out, e.Props[pi])
	}
	return out
}

// WireProps returns the client-server properties in the order they are
// written on the wire, which is NOT the FullIndex order: an entity's
// property table is built interfaces-first (each interface's Implements
// then its Properties, recursively) and then the entity's own
// Properties in declaration order. Props already holds them in that
// order, so this is a filter, not a sort.
//
// The difference is load-bearing for createBasePlayer. Account's four
// client properties come out as requiredVersion_2400, name,
// incarnationID, initialServerSettings on the wire, while FullIndex
// puts the fixed-width incarnationID first. Encoding them in FullIndex
// order shifts every field and the client reads the version string as
// an entity id.
func (e *Entity) WireProps() []Property {
	out := make([]Property, 0, len(e.CSProps))
	for i := range e.Props {
		if e.Props[i].isClientServerData() {
			out = append(out, e.Props[i])
		}
	}
	return out
}

// Loader reads .def files from scripts/entity_defs.
type Loader struct {
	Dir string // .../scripts/entity_defs

	aliasesDone bool
}

// ensureAliases builds alias.xml once per Loader (OSE single-pass order).
func (l *Loader) ensureAliases() error {
	if l.aliasesDone {
		return nil
	}
	if err := InitAliasesFromDir(l.Dir); err != nil {
		return err
	}
	l.aliasesDone = true
	return nil
}

// LoadEntities parses entities.xml order then every entity.
func (l *Loader) LoadEntities() ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(l.Dir, "..", "entities.xml"))
	if err != nil {
		return nil, err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return nil, err
	}
	cs := f.Root.Child("ClientServerEntities")
	if cs == nil {
		return nil, fmt.Errorf("entdef: missing ClientServerEntities")
	}
	var names []string
	for _, c := range cs.Children {
		names = append(names, c.Name)
	}
	return names, nil
}

func (l *Loader) loadDef(name string) (*Section, error) {
	raw, err := os.ReadFile(filepath.Join(l.Dir, name+".def"))
	if err != nil {
		return nil, err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return nil, err
	}
	return f.Root, nil
}

func (l *Loader) loadInterface(name string) (*Section, error) {
	raw, err := os.ReadFile(filepath.Join(l.Dir, "interfaces", name+".def"))
	if err != nil {
		return nil, err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return nil, err
	}
	return f.Root, nil
}

// ParseEntity parses one entity (Parent recursion, interfaces, own sections).
func (l *Loader) ParseEntity(name string) (*Entity, error) {
	if err := l.ensureAliases(); err != nil {
		return nil, err
	}
	e := &Entity{Name: name, propMap: map[string]int{}, methodMap: map[string]int{}, ifaceMethodMap: map[string]int{}}
	sec, err := l.loadDef(name)
	if err != nil {
		return nil, err
	}
	if err := e.parseDef(l, sec); err != nil {
		return nil, fmt.Errorf("entdef: %s: %w", name, err)
	}
	e.finish()
	return e, nil
}

func (e *Entity) parseDef(l *Loader, sec *Section) error {
	if p := sec.Child("Parent"); p != nil && p.StrVal() != "" {
		if err := e.parseDef(l, mustLoad(l, p.StrVal())); err != nil {
			return err
		}
	}
	// Implements then own Properties (OSE parseInterface order).
	// Empty <Interface/> placeholders occur in 2.4.0 defs; the client
	// tolerates them (strict OSE would fail), so skip.
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			isec, err := l.loadInterface(ifc.StrVal())
			if err != nil {
				return err
			}
			if err := e.parseInterface(l, isec); err != nil {
				return err
			}
		}
	}
	if err := e.parseProperties(sec.Child("Properties")); err != nil {
		return err
	}
	e.applyVolatile(sec)
	// Methods (no services in our set).
	if err := e.parseMethodList(sec.Child("BaseMethods"), compBase); err != nil {
		return err
	}
	if err := e.parseMethodList(sec.Child("CellMethods"), compCell); err != nil {
		return err
	}
	if err := e.parseMethodList(sec.Child("ClientMethods"), compClient); err != nil {
		return err
	}
	return nil
}

func mustLoad(l *Loader, name string) *Section {
	sec, err := l.loadDef(name)
	if err != nil {
		panic(fmt.Sprintf("entdef: parent %s: %v", name, err))
	}
	return sec
}

// parseInterface merges an interface's Implements + Properties, plus its
// *Methods into the separate iface lists (fork storage; digest visits own
// first, then ifaces — IDA sub_142A93420).
func (e *Entity) parseInterface(l *Loader, sec *Section) error {
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			isec, err := l.loadInterface(ifc.StrVal())
			if err != nil {
				return err
			}
			if err := e.parseInterface(l, isec); err != nil {
				return err
			}
		}
	}
	if err := e.parseProperties(sec.Child("Properties")); err != nil {
		return err
	}
	if err := e.parseIfaceMethodList(sec.Child("BaseMethods"), compBase); err != nil {
		return err
	}
	if err := e.parseIfaceMethodList(sec.Child("CellMethods"), compCell); err != nil {
		return err
	}
	if err := e.parseIfaceMethodList(sec.Child("ClientMethods"), compClient); err != nil {
		return err
	}
	return nil
}

func (e *Entity) parseProperties(list *Section) error {
	if list == nil {
		return nil
	}
	for _, ps := range list.Children {
		tn := ps.Child("Type")
		if tn == nil {
			return fmt.Errorf("entdef: property %s missing <Type>", ps.Name)
		}
		typ, err := BuildDataType(tn)
		if err != nil {
			return fmt.Errorf("entdef: property %s: %w", ps.Name, err)
		}
		fs := ps.Child("Flags")
		if fs == nil {
			return fmt.Errorf("entdef: property %s missing <Flags>", ps.Name)
		}
		flags, ok := flagTable[fs.StrVal()]
		if !ok {
			return fmt.Errorf("entdef: property %s: unknown Flags %q", ps.Name, fs.StrVal())
		}
		if ps.Child("Persistent") != nil && ps.Child("Persistent").AsBool() {
			flags |= flagPersistent
		}
		if ps.Child("Identifier") != nil && ps.Child("Identifier").AsBool() {
			flags |= flagID
		}
		if r := ps.Child("ExposedForReplay"); r != nil && isTrueSection(r) {
			flags |= flagReplay
		}
		if flags&flagEditorOnly != 0 {
			continue // editor-only: skipped like the client
		}
		p := Property{Name: ps.Name, Flags: flags, Type: typ, VarLen: 1}
		if v := ps.Child("Volatile"); v != nil && isTrueSection(v) {
			p.Volatile = true
		}
		if dl := ps.Child("DetailLevel"); dl != nil {
			p.DetailLevel = dl.StrVal()
		}
		if vs := ps.Child("VariableLengthHeaderSize"); vs != nil {
			v, err := varLenValue(vs)
			if err != nil {
				return fmt.Errorf("entdef: property %s: %w", ps.Name, err)
			}
			p.VarLen = v
		}
		idx, exists := e.propMap[p.Name]
		oldCS := exists && e.Props[idx].isClientServerData()
		if !exists {
			idx = len(e.Props)
			e.Props = append(e.Props, p)
			e.propMap[p.Name] = idx
		} else {
			// Override: reuse the definition slot. A client-server slot
			// is reused only if the old property had one (else fresh).
			if oldCS {
				p.FullIndex = e.Props[idx].FullIndex
			}
			e.Props[idx] = p
			if !p.isClientServerData() {
				continue
			}
			if !oldCS {
				p.FullIndex = len(e.CSProps)
				e.Props[idx] = p
				e.CSProps = append(e.CSProps, idx)
			}
			continue
		}
		if p.isClientServerData() {
			p.FullIndex = len(e.CSProps)
			e.Props[idx] = p
			e.CSProps = append(e.CSProps, idx)
		}
	}
	return nil
}

func (p *Property) isClientServerData() bool {
	// OSE DataDescription::isClientServerData includes DATA_REPLAY, and
	// the fork's digest filter (IDA sub_142A9B870, mask 0x106) matches it.
	return p.Flags&(flagOtherClient|flagOwnClient|flagReplay) != 0
}

// applyVolatile marks props listed in a <Volatile> section (either bare
// names like position/yaw, or a <Properties> name list as in
// GunMarkerComponent). Only digest-walked props matter; engine builtins
// (position/yaw/roll/pitch) never appear in Properties.
func (e *Entity) applyVolatile(sec *Section) {
	v := sec.Child("Volatile")
	if v == nil {
		return
	}
	mark := func(name string) {
		if idx, ok := e.propMap[name]; ok {
			e.Props[idx].Volatile = true
		}
	}
	for _, c := range v.Children {
		if c.Name == "Properties" {
			for _, p := range c.Children {
				mark(p.Name)
			}
		} else {
			mark(c.Name)
		}
	}
}

// isTrueSection reads a boolean-ish section: explicit true/1/bool, or a
// present-but-empty marker. "false"/"0" never count as true.
func isTrueSection(s *Section) bool {
	if s == nil {
		return false
	}
	if s.OwnType == TypeBool {
		return s.AsBool()
	}
	v := s.AsString()
	if v == "" {
		v = s.StrVal()
	}
	switch v {
	case "true", "1":
		return true
	case "false", "0", "":
		return false
	}
	return false
}

func (e *Entity) parseMethodList(list *Section, comp int) error {
	return e.parseMethodListInto(list, comp, false)
}

// parseIfaceMethodList parses interface methods into the separate iface
// lists (fork storage; digest visits own first, then ifaces).
func (e *Entity) parseIfaceMethodList(list *Section, comp int) error {
	return e.parseMethodListInto(list, comp, true)
}

func (e *Entity) parseMethodListInto(list *Section, comp int, iface bool) error {
	if list == nil {
		return nil
	}
	var dst *[]Method
	var mmap map[string]int
	switch comp {
	case compClient:
		if iface {
			dst = &e.IfaceClientMethods
		} else {
			dst = &e.ClientMethods
		}
	case compBase:
		if iface {
			dst = &e.IfaceBaseMethods
		} else {
			dst = &e.BaseMethods
		}
	default:
		if iface {
			dst = &e.IfaceCellMethods
		} else {
			dst = &e.CellMethods
		}
	}
	if iface {
		mmap = e.ifaceMethodMap
	} else {
		mmap = e.methodMap
	}
	for _, ms := range list.Children {
		m := Method{Name: ms.Name, Var: 1}
		m.Flags = uint8(comp)
		if ex := ms.Child("Exposed"); ex != nil {
			if comp == compClient {
				return fmt.Errorf("entdef: client method %s has <Exposed>", ms.Name)
			}
			switch ex.StrVal() {
			case "ALL_CLIENTS":
				if comp != compCell {
					return fmt.Errorf("entdef: ALL_CLIENTS on non-cell method %s", ms.Name)
				}
				m.Flags |= expAllClients
			case "OWN_CLIENT":
				if comp == compCell {
					m.Flags |= ExposedOwnCellBits
				} else {
					m.Flags |= expOwnClient
				}
			case "":
				if comp == compBase {
					m.Flags |= ExposedBareBaseBits
				} else if comp == compCell {
					m.Flags |= ExposedBareCellBits
				} else {
					m.Flags |= expAllClients | expOwnClient
				}
			default:
				return fmt.Errorf("entdef: method %s: bad <Exposed> %q", ms.Name, ex.StrVal())
			}
		}
		// Args: new-style <Args> (all children) or old-style (<Arg> children).
		var argSecs []*Section
		if args := ms.Child("Args"); args != nil {
			argSecs = args.Children
		} else {
			for _, c := range ms.Children {
				if c.Name == "Arg" {
					argSecs = append(argSecs, c)
				}
			}
		}
		for _, a := range argSecs {
			dt, err := BuildDataType(a)
			if err != nil {
				return fmt.Errorf("entdef: method %s arg: %w", ms.Name, err)
			}
			m.Args = append(m.Args, dt)
			m.ArgNames = append(m.ArgNames, a.Name)
		}
		// ReturnValues: same shape as Args (named children or <Arg>
		// children); empty contributes nothing (IDA sub_142ABCBC0).
		if rv := ms.Child("ReturnValues"); rv != nil {
			for _, rc := range rv.Children {
				dt, err := buildReturnType(rc)
				if err != nil {
					return fmt.Errorf("entdef: method %s returnValues: %w", ms.Name, err)
				}
				m.ReturnValues = append(m.ReturnValues, dt)
				m.ReturnNames = append(m.ReturnNames, rc.Name)
			}
		}
		if vs := ms.Child("VariableLengthHeaderSize"); vs != nil {
			if comp != compClient {
				return fmt.Errorf("entdef: VariableLengthHeaderSize on non-client method %s", ms.Name)
			}
			v, err := varLenValue(vs)
			if err != nil {
				return fmt.Errorf("entdef: method %s: %w", ms.Name, err)
			}
			m.Var = v
		}
		if comp == compClient {
			m.Flags |= expAllClients // all client methods are exposed
		}
		// <AllowUnsafeData> sets bit 0x10 (walkprobe2: onChatAction 0x14
		// vs plain client 0x4; harmless to the 0xC exposure filter).
		if au := ms.Child("AllowUnsafeData"); au != nil && isTrueSection(au) {
			m.Flags |= 0x10
			m.AllowUnsafe = true
		}
		// Name dedup across parent/interface/own (signature-equal required).
		if at, ok := mmap[m.Name+string(rune(comp))]; ok {
			prev := (*dst)[at]
			if !argsEqual(prev.Args, m.Args) || !argsEqual(prev.ReturnValues, m.ReturnValues) {
				return fmt.Errorf("entdef: method %s redefined with different signature", ms.Name)
			}
			continue
		}
		mmap[m.Name+string(rune(comp))] = len(*dst)
		*dst = append(*dst, m)
	}
	return nil
}

// buildReturnType resolves one ReturnValues child: either a direct type
// spec (own-data holds the type name, e.g. "BOOL") or a wrapper with a
// <Type> sub-section.
func buildReturnType(sec *Section) (DataType, error) {
	if ts := sec.Child("Type"); ts != nil {
		return BuildDataType(ts)
	}
	return BuildDataType(sec)
}

// varLenValue reads <VariableLengthHeaderSize>: empty own-data means the
// default (1, WarnLevel-only form); otherwise a 1..4 integer.
func varLenValue(vs *Section) (uint, error) {
	if vs.Str == "" && len(vs.Raw) == 0 {
		return 1, nil
	}
	if vs.OwnType == TypeInt {
		if v := vs.AsInt(); v >= 1 && v <= 4 {
			return uint(v), nil
		}
		return 0, fmt.Errorf("bad VariableLengthHeaderSize %d", vs.AsInt())
	}
	n, err := strconv.Atoi(strings.TrimSpace(vs.StrVal()))
	if err != nil || n < 1 || n > 4 {
		return 0, fmt.Errorf("bad VariableLengthHeaderSize %q", vs.StrVal())
	}
	return uint(n), nil
}

func argsEqual(a, b []DataType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

// finish sorts client-server properties by stream size (stable) and assigns
// full indexes, mirroring allocateClientServerFullIndexes.
func (e *Entity) finish() {
	order := append([]int(nil), e.CSProps...)
	slices.SortStableFunc(order, func(x, y int) int {
		a := e.Props[x].StreamSize()
		b := e.Props[y].StreamSize()
		switch {
		case a < 0 && b < 0:
			return cmp.Compare(-a, -b)
		case a >= 0 && b >= 0:
			return cmp.Compare(a, b)
		case a >= 0:
			return -1
		default:
			return 1
		}
	})
	for i, pi := range order {
		e.Props[pi].FullIndex = i
	}
	e.CSProps = order
}

// Audience is who a client property or method reaches, from its distribution
// flags: the BigWorld `DATA_OTHER_CLIENT` / `DATA_OWN_CLIENT` pair, which the
// defs spell `ALL_CLIENTS`, `OTHER_CLIENTS` and `OWN_CLIENT`.
//
// A server that serves one client can ignore it; a roster cannot: a vehicle's
// `isMyVehicle` and the `OwnVehicle` component are the owner's, and sending
// them to every client tells each player that every tank is theirs.
type Audience uint8

const (
	// AudienceAll is `ALL_CLIENTS`: every client in the AoI.
	AudienceAll Audience = iota
	// AudienceOther is `OTHER_CLIENTS`: every client except the entity's owner.
	AudienceOther
	// AudienceOwn is `OWN_CLIENT`: the entity's owner only.
	AudienceOwn
	// AudienceNone is server-side only (BASE, CELL_PRIVATE): never on the wire.
	AudienceNone
)

func (a Audience) String() string {
	switch a {
	case AudienceAll:
		return "all"
	case AudienceOther:
		return "other"
	case AudienceOwn:
		return "own"
	}
	return "none"
}

// Audience is the property's audience.
func (p Property) Audience() Audience {
	switch {
	case p.Flags&flagOwnClient != 0 && p.Flags&flagOtherClient != 0:
		return AudienceAll
	case p.Flags&flagOtherClient != 0:
		return AudienceOther
	case p.Flags&flagOwnClient != 0:
		return AudienceOwn
	}
	return AudienceNone
}

// Audience is the client method's audience: `Exposed`'s all-clients and
// own-client bits.
func (m Method) Audience() Audience {
	switch {
	case m.Flags&expAllClients != 0 && m.Flags&expOwnClient != 0:
		return AudienceAll
	case m.Flags&expAllClients != 0:
		return AudienceOther
	case m.Flags&expOwnClient != 0:
		return AudienceOwn
	}
	return AudienceNone
}

// Reaches reports whether a client with this ownership receives the audience.
func (a Audience) Reaches(owner bool) bool {
	switch a {
	case AudienceAll:
		return true
	case AudienceOther:
		return !owner
	case AudienceOwn:
		return owner
	}
	return false
}
