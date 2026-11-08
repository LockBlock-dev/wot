package login

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/LockBlock-dev/wot/entdef"
)

// The game's destructible static models, from `scripts/destructibles.xml`.
//
// The client reads the same file (`DestructiblesCache.py`) and builds one
// descriptor list from it, in a fixed order: `fragiles`, `fallingAtoms`,
// `trees`, then `structures`. A destructible is named on the wire by its index
// in that list, and a structure's module by the material kind the client
// assigns it (`73 + i`, its modules sorted by the id in their `matName`).
//
// Ported from the reference's `space/destructibles.rs` and the client's
// `DestructiblesCache`.

// Destructible kinds, `DestructiblesCache.DESTR_TYPE_*`.
const (
	destrTypeTree        uint8 = 0
	destrTypeFallingAtom uint8 = 1
	destrTypeFragile     uint8 = 2
	destrTypeStructure   uint8 = 3
)

// destructibleMatKindNormalMin is `DESTRUCTIBLE_MATKIND.NORMAL_MIN`: the first
// material kind a structure's modules are given.
const destructibleMatKindNormalMin = 73

// destructibleDesc is one entry of the game's list.
type destructibleDesc struct {
	// Filename is the model path as the file gives it.
	Filename string
	// Type is the `DESTR_TYPE_*` kind.
	Type uint8
	// Modules maps a structure's body name (`n_stone_10`) to its material
	// kind. Empty for the whole-model kinds.
	Modules map[string]uint8
}

// destructibleTable is the parsed file.
type destructibleTable struct {
	Descs []destructibleDesc
	// ByModel maps a model path (without extension, lower case) to its index
	// in Descs.
	ByModel map[string]int
}

// destructibleTableCache holds the parsed file.
var destructibleTableCache sync.Map // map[string]*destructibleTable

// Destructibles returns the game's destructible table, or nil when the scripts
// package is not available.
func Destructibles() *destructibleTable {
	pkg := FindScriptsPkg()
	if pkg == "" {
		return nil
	}
	if v, ok := destructibleTableCache.Load(pkg); ok {
		t, _ := v.(*destructibleTable)
		return t
	}
	t, err := loadDestructibles(pkg)
	if err != nil {
		destructibleTableCache.Store(pkg, (*destructibleTable)(nil))
		return nil
	}
	destructibleTableCache.Store(pkg, t)
	return t
}

// loadDestructibles parses `scripts/destructibles.xml` into the client's order.
func loadDestructibles(pkg string) (*destructibleTable, error) {
	raw, err := readFromZip(pkg, "scripts/destructibles.xml")
	if err != nil {
		return nil, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return nil, fmt.Errorf("destructibles: %w", err)
	}
	if f.Root == nil {
		return nil, fmt.Errorf("destructibles: no root")
	}
	t := &destructibleTable{ByModel: map[string]int{}}
	// The client's order, `DestructiblesCache.__init__`: fragiles, then
	// fallingAtoms, trees and structures.
	for _, kind := range []struct {
		section string
		typ     uint8
	}{
		{"fragiles", destrTypeFragile},
		{"fallingAtoms", destrTypeFallingAtom},
		{"trees", destrTypeTree},
		{"structures", destrTypeStructure},
	} {
		sec := f.Root.Child(kind.section)
		if sec == nil {
			continue
		}
		for _, entry := range sec.Children {
			if entry.Name != "entry" {
				continue
			}
			fn := entry.Child("filename")
			if fn == nil {
				continue
			}
			d := destructibleDesc{Filename: strings.TrimSpace(fn.AsString()), Type: kind.typ}
			if kind.typ == destrTypeStructure {
				d.Modules = structureModules(entry)
			}
			t.ByModel[modelStem(d.Filename)] = len(t.Descs)
			t.Descs = append(t.Descs, d)
		}
	}
	return t, nil
}

// structureModules maps a structure's body names to the material kinds the
// client assigns them: its modules sorted by the id in their `matName`, then
// `73 + i`.
func structureModules(entry *entdef.Section) map[string]uint8 {
	mods := entry.Child("modules")
	if mods == nil {
		return nil
	}
	type module struct {
		name string
		id   int
	}
	var list []module
	for _, m := range mods.Children {
		if m.Name != "module" {
			continue
		}
		mn := m.Child("matName")
		if mn == nil {
			continue
		}
		name := strings.TrimSpace(mn.AsString())
		if _, id, ok := parseMaterialName(name); ok {
			list = append(list, module{name: name, id: id})
		}
	}
	// Sorted by the id, as `ids.sort()` does.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j].id < list[j-1].id; j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	out := make(map[string]uint8, len(list))
	for i, m := range list {
		out[m.name] = uint8(destructibleMatKindNormalMin + i)
	}
	return out
}

// parseMaterialName splits a structure module's `matName`, `n_stone_10`, the
// way `_parseMaterialName` does: the type, the surface and the id.
func parseMaterialName(name string) (surface string, id int, ok bool) {
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return "", 0, false
	}
	var letters strings.Builder
	for _, r := range parts[1] {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letters.WriteRune(r)
		}
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", 0, false
	}
	return letters.String(), n, true
}

// modelStem is a model path as the table keys it: no extension, lower case.
func modelStem(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		path = path[:i]
	}
	return strings.ToLower(path)
}

// desc returns the descriptor of a model path, or nil.
func (t *destructibleTable) desc(model string) *destructibleDesc {
	if t == nil {
		return nil
	}
	i, ok := t.ByModel[modelStem(model)]
	if !ok {
		return nil
	}
	return &t.Descs[i]
}

// bodyKind is what a static model's body is to a shell or a hull: solid, a
// destructible whole, a structure module, or what a destroyed module leaves.
type staticBodyKind uint8

const (
	bodySolid staticBodyKind = iota
	// bodyDestructible breaks or falls whole (a tree, a lamp post, a fence).
	bodyDestructible
	// bodyModule is one destructible module of a structure (a house's wall).
	bodyModule
	// bodyRemains is what a destroyed module leaves behind.
	bodyRemains
)

// bodyKindOf classifies one body of a static model, as the reference's
// `BodyKind::of` does, with the structure modules resolved too.
func (t *destructibleTable) bodyKindOf(model, body string) (staticBodyKind, uint8) {
	d := t.desc(model)
	if d == nil {
		// A `n_` body is destructible by its name alone; a `c_` one is what a
		// destroyed module leaves.
		switch {
		case strings.HasPrefix(body, "n_"):
			return bodyDestructible, 0
		case strings.HasPrefix(body, "c_"):
			return bodyRemains, 0
		}
		return bodySolid, 0
	}
	if d.Type == destrTypeStructure {
		if mk, ok := d.Modules[body]; ok {
			return bodyModule, mk
		}
		return bodySolid, 0
	}
	return bodyDestructible, 0
}

// The client notification: one `AreaDestructibles` entity per chunk that has
// lost a destructible, carrying the destroyed lists the client applies.
//
// The entity is the client's `AreaDestructibles` (a cell entity, which the
// base app proxies): `onEnterWorld` walks `fallenColumns`, `fallenTrees`,
// `destroyedFragiles` and `destroyedModules` and destroys each one, and the
// setters do the same for later updates. Its position names the chunk — the
// client reads it back with `chunkIDFromPosition` — and each entry is the
// chunk-local `destrID` plus the kind's parameters.

// destructibleChunk is one chunk's `AreaDestructibles` entity and the lists it
// has sent.
type destructibleChunk struct {
	entity *Entity
	id     uint32
	// The four ALL_CLIENTS arrays, in the client's tuple formats.
	fragiles []entdef.Value
	modules  []entdef.Value
	trees    []entdef.Value
	columns  []entdef.Value
}

// packAngleToUint is the client's `WoT.packAngleToUint`: the angle over
// [-pi, pi] as a `bits`-wide unsigned value.
func packAngleToUint(angle float64, bits uint) uint64 {
	mask := uint64(1)<<bits - 1
	v := math.Round(float64(mask+1) * (angle + math.Pi) / (2 * math.Pi))
	return uint64(int64(v)) & mask
}

// tuple3 and tuple5 build the wire tuples the client's decoders read.
func tuple3(a, b, c uint8) entdef.Value {
	return entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(a)},
		{Kind: entdef.VUint, Uint: uint64(b)},
		{Kind: entdef.VUint, Uint: uint64(c)},
	}}
}

func tuple5(a, b, c, d, e uint8) entdef.Value {
	return entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(a)},
		{Kind: entdef.VUint, Uint: uint64(b)},
		{Kind: entdef.VUint, Uint: uint64(c)},
		{Kind: entdef.VUint, Uint: uint64(d)},
		{Kind: entdef.VUint, Uint: uint64(e)},
	}}
}

// destroyStatic records one destroyed static body and tells the client.
//
// It is called from the shot path with the triangle the shell met: a whole
// destructible (a tree, a lamp post, a fence) or one module of a structure.
// The body's triangles leave the collision scene, so later shells and hulls
// pass through it.
func (s *BaseAppServer) destroyStatic(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, tri staticTriangle) error {
	s.mu.Lock()
	scene := st.statics
	s.mu.Unlock()
	if scene == nil {
		return nil
	}
	if !scene.destroy(tri.Instance, tri.Body) {
		return nil
	}
	chunkID := tri.Chunk
	idx := tri.DestrIndex
	hi, lo := uint8(idx>>8), uint8(idx&0xFF)
	var field string
	var entry entdef.Value
	switch tri.Kind {
	case bodyModule:
		// `encodeDestructibleModule`: the material kind and the shot flag.
		field = "destroyedModules"
		entry = tuple3(hi, lo, tri.MatKind<<1)
	case bodyDestructible:
		desc := Destructibles().desc(tri.Model)
		typ := destrTypeFragile
		if desc != nil {
			typ = desc.Type
		}
		switch typ {
		case destrTypeTree:
			// `encodeFallenTree`: a fall yaw of 0 and a pitch of 0, standing.
			field = "fallenTrees"
			entry = tuple5(hi, lo, 0x80, 0x00, uint8(packAngleToUint(0, 6)<<2))
		case destrTypeFallingAtom:
			field = "fallenColumns"
			entry = tuple3(hi, lo, uint8(packAngleToUint(0, 6)<<2))
		default:
			field = "destroyedFragiles"
			entry = tuple3(hi, lo, 0)
		}
	default:
		return nil
	}

	s.mu.Lock()
	if st.destrChunks == nil {
		st.destrChunks = map[uint16]*destructibleChunk{}
	}
	dc := st.destrChunks[chunkID]
	created := false
	if dc == nil {
		dc = &destructibleChunk{}
		st.destrChunks[chunkID] = dc
		created = true
	}
	switch field {
	case "destroyedModules":
		dc.modules = append(dc.modules, entry)
	case "fallenTrees":
		dc.trees = append(dc.trees, entry)
	case "fallenColumns":
		dc.columns = append(dc.columns, entry)
	default:
		dc.fragiles = append(dc.fragiles, entry)
	}
	s.mu.Unlock()
	s.logf("arena %d: destructible %s destroyed on chunk %d (index %d, matKind %d)",
		arenaID, field, chunkID, idx, tri.MatKind)

	if created {
		return s.createDestructibleChunk(conn, from, st, arenaID, chunkID, dc)
	}
	return s.updateDestructibleChunk(conn, from, st, dc, field)
}

// createDestructibleChunk puts one chunk's `AreaDestructibles` entity into the
// battle, with the lists it has lost so far.
func (s *BaseAppServer) createDestructibleChunk(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, chunkID uint16, dc *destructibleChunk) error {
	typ := s.cfg.Dispatch.Entity("AreaDestructibles")
	if typ == nil {
		return nil
	}
	s.mu.Lock()
	dc.id = st.vehicle.ID + 1000 + uint32(chunkID)
	id := dc.id
	fragiles := append([]entdef.Value(nil), dc.fragiles...)
	modules := append([]entdef.Value(nil), dc.modules...)
	trees := append([]entdef.Value(nil), dc.trees...)
	columns := append([]entdef.Value(nil), dc.columns...)
	s.mu.Unlock()

	e := NewEntity(id, typ)
	for _, p := range typ.CellProps {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	e.SetInt("arenaID", int64(arenaID))
	e.SetUint("chunkID", uint64(chunkID))
	setArray := func(name string, list []entdef.Value) {
		if _, ok := e.Props[name]; ok {
			e.Set(name, entdef.Value{Kind: entdef.VSeq, Seq: list})
		}
	}
	setArray("destroyedFragiles", fragiles)
	setArray("destroyedModules", modules)
	setArray("fallenTrees", trees)
	setArray("fallenColumns", columns)

	props, err := EntityPropertyRunNames(e, "arenaID", "chunkID", "destroyedFragiles", "destroyedModules", "fallenTrees", "fallenColumns")
	if err != nil {
		return err
	}
	pos := chunkCenter(chunkID)
	create, err := EncodeCreateEntity(id, uint16(typ.TypeID), VolatilePackerType, pos, 0, 0, 0, props)
	if err != nil {
		return err
	}
	// Two packets, two sequence numbers, minted and sent under one lock.
	// Minting one and sending two left the session's counter a number behind,
	// so the next sender re-used a sequence the client had already seen and
	// dropped it as a duplicate.
	sel, err := EncodeSelectEntity(id)
	if err != nil {
		return err
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeqN(st, 2)
	err = s.sendReliableLocked(conn, from, st, create, seq, cumul)
	if err == nil {
		err = s.sendReliableLocked(conn, from, st, sel, seq+1, cumul)
	}
	st.sendMu.Unlock()
	if err != nil {
		return err
	}
	// The chunk's entity is created here and entered when the client comes
	// near it, like every other entity.
	s.mu.Lock()
	dc.entity = e
	if st.interest != nil {
		st.interest.add(id, pos, false)
	}
	s.mu.Unlock()
	s.logf("arena %d: AreaDestructibles %d created for chunk %d (%d fragiles, %d modules, %d trees, %d columns)",
		arenaID, id, chunkID, len(fragiles), len(modules), len(trees), len(columns))
	return nil
}

// updateDestructibleChunk re-sends one of a chunk's lists after a destruction.
func (s *BaseAppServer) updateDestructibleChunk(conn Transport, from *net.UDPAddr, st *clientState, dc *destructibleChunk, field string) error {
	s.mu.Lock()
	e := dc.entity
	var list []entdef.Value
	switch field {
	case "destroyedModules":
		list = append([]entdef.Value(nil), dc.modules...)
	case "fallenTrees":
		list = append([]entdef.Value(nil), dc.trees...)
	case "fallenColumns":
		list = append([]entdef.Value(nil), dc.columns...)
	default:
		list = append([]entdef.Value(nil), dc.fragiles...)
	}
	s.mu.Unlock()
	if e == nil {
		return nil
	}
	e.Set(field, entdef.Value{Kind: entdef.VSeq, Seq: list})
	el, err := EncodePropertyUpdate(e, field)
	if err != nil {
		return err
	}
	var app []byte
	if sel, serr := EncodeSelectEntity(e.ID); serr == nil {
		app = append(app, sel...)
	}
	app = append(app, el...)
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, app, seq, cumul)
	st.sendMu.Unlock()
	return err
}
