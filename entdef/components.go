// Component + space description support for the login digest.
//
// The client EntityDescriptionMap walked by the digest (IDA
// sub_142A9B410/sub_142A93420 on WorldOfTanks.exe 2.4.0) contains, in
// order:
//  1. space types (scripts space_defs: GeneralSpaceData + SpaceRecording
//     iface; proven by walkprobe #1-5 preceding Account),
//  2. ClientServerEntities from scripts entities.xml (40, file order),
//  3. per-pkg ClientServerEntities from mode extension manifests
//     (battle_royale Mine/Loot/Placement/InfluenceZone/ThunderStrike,
//     comp7_core ApplicationPoint, comp7 Comp7Lighting, server_side_replay
//     ReplayAccount, story_mode SPGZone),
//  4. dynamic components: scripts components.xml order, then mode pkgs
//     alphabetical, each manifest's DynamicComponents order.
//
// StaticComponents (per manifest) merge their methods into their
// ofEntity entry's per-domain lists (continuing legacy indexes),
// filtered by the same 0xC exposure rule; their properties never walk.
// Component ClientMethods default to exposed (0x4, like entity client
// methods); Base/CellMethods need explicit <Exposed/>.
// Component/space FullIndex assignment reuses Entity.finish (stable
// stream-size sort = allocateClientServerFullIndexes); non-CS props
// keep FullIndex -1 (engine sentinel) and are skipped by the 0x106
// filter in sub_142A9B870.
package entdef

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Extension is one parsed feature manifest: scripts components.xml or a
// mode pkg extension.xml (packed, parsed with ParseFile).
type Extension struct {
	Pkg      string
	Enabled  bool
	Static   []string
	Dynamic  []string
	Entities []string
}

func parseExtension(raw []byte, pkg string) (*Extension, error) {
	f, err := ParseFile(raw)
	if err != nil {
		return nil, err
	}
	ex := &Extension{Pkg: pkg, Enabled: true}
	if en := f.Root.Child("IsEnabled"); en != nil {
		v := en.StrVal()
		ex.Enabled = v == "True" || v == "true" || v == "1"
	}
	if comps := f.Root.Child("Components"); comps != nil {
		if st := comps.Child("StaticComponents"); st != nil {
			for _, c := range st.Children {
				ex.Static = append(ex.Static, c.Name)
			}
		}
		if dy := comps.Child("DynamicComponents"); dy != nil {
			for _, c := range dy.Children {
				ex.Dynamic = append(ex.Dynamic, c.Name)
			}
		}
	}
	// scripts components.xml lists both sections at top level.
	if st := f.Root.Child("StaticComponents"); st != nil {
		for _, c := range st.Children {
			ex.Static = append(ex.Static, c.Name)
		}
	}
	if dy := f.Root.Child("DynamicComponents"); dy != nil {
		for _, c := range dy.Children {
			ex.Dynamic = append(ex.Dynamic, c.Name)
		}
	}
	if ents := f.Root.Child("Entities"); ents != nil {
		if cs := ents.Child("ClientServerEntities"); cs != nil {
			for _, c := range cs.Children {
				ex.Entities = append(ex.Entities, c.Name)
			}
		}
	}
	return ex, nil
}

// CompLoader loads component/space/mode-entity defs from an external
// wotdefs tree (sibling dirs wotdefs-2.4.0/, wotdefs-2.4.1/ — game data,
// kept outside this repo, never committed): components/<pkg>/,
// space_defs/, mode_entities/<pkg>/, extensions/.
type CompLoader struct {
	Root string

	ifaceDirs []string // interface lookup chain
	compDirs  []string // component lookup chain (pkg-alpha + scripts)
	exts      []*Extension
	extByPkg  map[string]*Extension
}

func NewCompLoader(root string) *CompLoader {
	return &CompLoader{Root: root, extByPkg: map[string]*Extension{}}
}

// LoadExtensions reads scripts components.xml then per-pkg extension
// manifests (alphabetical pkg order).
func (l *CompLoader) LoadExtensions() error {
	entries, err := os.ReadDir(filepath.Join(l.Root, "extensions"))
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	// scripts manifest first, then pkgs alphabetical.
	ordered := []string{"scripts_components.xml"}
	for _, n := range names {
		if n != "scripts_components.xml" {
			ordered = append(ordered, n)
		}
	}
	for _, n := range ordered {
		raw, err := os.ReadFile(filepath.Join(l.Root, "extensions", n))
		if err != nil {
			return err
		}
		pkg := strings.TrimSuffix(n, ".xml")
		pkg = strings.TrimSuffix(pkg, "_extension")
		pkg = strings.TrimSuffix(pkg, "_components")
		ex, err := parseExtension(raw, pkg)
		if err != nil {
			return fmt.Errorf("entdef: extension %s: %w", n, err)
		}
		if !ex.Enabled {
			continue
		}
		l.exts = append(l.exts, ex)
		l.extByPkg[pkg] = ex
	}
	// Interface chain: scripts entity interfaces, space interfaces.
	ifaceDefs := ScriptsEntityDefsDir
	if ifaceDefs == "" {
		ifaceDefs = filepath.Join(l.Root, "..", "..", "World_of_Tanks_EU", "2.4.0.0", "res", "scripts", "entity_defs")
	}
	l.ifaceDirs = []string{
		filepath.Join(ifaceDefs, "interfaces"),
		filepath.Join(l.Root, "space_defs", "interfaces"),
	}
	// Component chain: scripts components, then pkgs alphabetical.
	l.compDirs = []string{filepath.Join(l.Root, "components", "scripts")}
	var pkgs []string
	for _, ex := range l.exts {
		if ex.Pkg == "scripts" {
			continue
		}
		pkgs = append(pkgs, ex.Pkg)
	}
	slices.Sort(pkgs)
	for _, p := range pkgs {
		l.compDirs = append(l.compDirs, filepath.Join(l.Root, "components", p))
	}
	return nil
}

func (l *CompLoader) loadSectionFile(dir, name string) (*Section, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name+".def"))
	if err != nil {
		return nil, err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return nil, err
	}
	return f.Root, nil
}

// loadComponentFile finds a component def by name across the chain.
func (l *CompLoader) loadComponentFile(name string) (*Section, error) {
	for _, d := range l.compDirs {
		if sec, err := l.loadSectionFile(d, name); err == nil {
			return sec, nil
		}
	}
	return nil, fmt.Errorf("entdef: component %s not found", name)
}

func (l *CompLoader) loadComponentInterface(name string) (*Section, error) {
	// Component-local interfaces live beside components; fall back to
	// the entity interface chain.
	for _, d := range l.compDirs {
		if sec, err := l.loadSectionFile(d, name); err == nil {
			return sec, nil
		}
	}
	for _, d := range l.ifaceDirs {
		if sec, err := l.loadSectionFile(d, name); err == nil {
			return sec, nil
		}
	}
	return nil, fmt.Errorf("entdef: component interface %s not found", name)
}

// ParseComponent parses one component def into an Entity (props +
// methods + iface lists) plus its ofEntity attachment. Parent and
// Implements resolve across the component chain.
func (l *CompLoader) ParseComponent(name string) (*Entity, string, error) {
	sec, err := l.loadComponentFile(name)
	if err != nil {
		return nil, "", err
	}
	e := &Entity{Name: name, propMap: map[string]int{}, methodMap: map[string]int{}, ifaceMethodMap: map[string]int{}}
	if err := l.parseCompDef(e, sec); err != nil {
		return nil, "", fmt.Errorf("entdef: component %s: %w", name, err)
	}
	e.finish()
	of := ""
	if oe := sec.Child("ofEntity"); oe != nil && len(oe.Children) > 0 {
		of = oe.Children[0].Name
	}
	return e, of, nil
}

func (l *CompLoader) parseCompDef(e *Entity, sec *Section) error {
	if p := sec.Child("Parent"); p != nil && p.StrVal() != "" {
		ps, err := l.loadComponentFile(p.StrVal())
		if err != nil {
			// Parents may be entities (cross-dir); try the entity chain
			// via the shared entity loader is not available here, so
			// report precisely.
			return fmt.Errorf("entdef: component parent %s: %w", p.StrVal(), err)
		}
		if err := l.parseCompDef(e, ps); err != nil {
			return err
		}
	}
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			isec, err := l.loadComponentInterface(ifc.StrVal())
			if err != nil {
				return err
			}
			if err := l.parseCompInterface(e, isec); err != nil {
				return err
			}
		}
	}
	if err := e.parseProperties(sec.Child("Properties")); err != nil {
		return err
	}
	e.applyVolatile(sec)
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

func (l *CompLoader) parseCompInterface(e *Entity, sec *Section) error {
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			isec, err := l.loadComponentInterface(ifc.StrVal())
			if err != nil {
				return err
			}
			if err := l.parseCompInterface(e, isec); err != nil {
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

// ParseSpace parses a space def (space_defs dir): Properties use
// <Exposed/> instead of <Flags> (no Flags section in 2.4.0 space defs);
// <Exposed/> sets the OWN_CLIENT bit only (walkprobe2: itemsVisibilityMask
// flags 0x204). Non-exposed props keep flags 0x200 (skipped by the 0x106
// filter, FullIndex stays -1). High flag bits never reach the digest
// (masked with 0x5F); volatile is always false.
var SpaceExposedBits = 0x204 // 0x200 default | OWN_CLIENT

func (l *CompLoader) ParseSpace(name string) (*Entity, error) {
	sec, err := l.loadSectionFile(filepath.Join(l.Root, "space_defs"), name)
	if err != nil {
		return nil, err
	}
	e := &Entity{Name: name, propMap: map[string]int{}, methodMap: map[string]int{}, ifaceMethodMap: map[string]int{}}
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			isec, err := l.loadSectionFile(filepath.Join(l.Root, "space_defs", "interfaces"), ifc.StrVal())
			if err != nil {
				return nil, err
			}
			if err := e.parseSpaceProperties(secChildProps(isec)); err != nil {
				return nil, err
			}
			if err := e.parseIfaceMethodList(isec.Child("BaseMethods"), compBase); err != nil {
				return nil, err
			}
			if err := e.parseIfaceMethodList(isec.Child("CellMethods"), compCell); err != nil {
				return nil, err
			}
			if err := e.parseIfaceMethodList(isec.Child("ClientMethods"), compClient); err != nil {
				return nil, err
			}
		}
	}
	if err := e.parseSpaceProperties(sec.Child("Properties")); err != nil {
		return nil, err
	}
	if err := e.parseMethodList(sec.Child("BaseMethods"), compBase); err != nil {
		return nil, err
	}
	if err := e.parseMethodList(sec.Child("CellMethods"), compCell); err != nil {
		return nil, err
	}
	if err := e.parseMethodList(sec.Child("ClientMethods"), compClient); err != nil {
		return nil, err
	}
	e.finish()
	return e, nil
}

func secChildProps(sec *Section) *Section {
	if sec == nil {
		return nil
	}
	return sec.Child("Properties")
}

// parseSpaceProperties parses space properties: <Type> required,
// <Flags> absent (defaults 0), <Exposed/> marks client-server data.
func (e *Entity) parseSpaceProperties(list *Section) error {
	if list == nil {
		return nil
	}
	for _, ps := range list.Children {
		tn := ps.Child("Type")
		if tn == nil {
			return fmt.Errorf("entdef: space property %s missing <Type>", ps.Name)
		}
		typ, err := BuildDataType(tn)
		if err != nil {
			return fmt.Errorf("entdef: space property %s: %w", ps.Name, err)
		}
		flags := 0x200 // engine default (walkprobe2: recorderFragment)
		if ps.Child("Exposed") != nil {
			flags = SpaceExposedBits
		}
		p := Property{Name: ps.Name, Flags: flags, Type: typ, VarLen: 1, FullIndex: -1}
		if v := ps.Child("Volatile"); v != nil && isTrueSection(v) {
			p.Volatile = true
		}
		idx, exists := e.propMap[p.Name]
		if !exists {
			idx = len(e.Props)
			e.Props = append(e.Props, p)
			e.propMap[p.Name] = idx
		} else {
			e.Props[idx] = p
			if !p.isClientServerData() {
				continue
			}
			p.FullIndex = len(e.CSProps)
			e.Props[idx] = p
			e.CSProps = append(e.CSProps, idx)
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

// ParseModeEntity parses a mode-pkg entity (mode_entities/<pkg>/); Parent
// and Implements fall back to the scripts entity tree via resolve hooks
// set by the digest driver (entityLoader).
func (l *CompLoader) ParseModeEntity(pkg, name string, fallback *Loader) (*Entity, error) {
	sec, err := l.loadSectionFile(filepath.Join(l.Root, "mode_entities", pkg), name)
	if err != nil {
		return nil, err
	}
	e := &Entity{Name: name, propMap: map[string]int{}, methodMap: map[string]int{}, ifaceMethodMap: map[string]int{}}
	if err := l.parseModeDef(pkg, e, sec, fallback); err != nil {
		return nil, fmt.Errorf("entdef: mode entity %s/%s: %w", pkg, name, err)
	}
	e.finish()
	return e, nil
}

func (l *CompLoader) parentSection(pkg, name string, fallback *Loader) (*Section, error) {
	if ps, err := l.loadSectionFile(filepath.Join(l.Root, "mode_entities", pkg), name); err == nil {
		return ps, nil
	}
	for _, ex := range l.exts {
		if ex.Pkg == pkg {
			continue
		}
		if ps, err := l.loadSectionFile(filepath.Join(l.Root, "mode_entities", ex.Pkg), name); err == nil {
			return ps, nil
		}
	}
	if fallback == nil {
		return nil, fmt.Errorf("entdef: mode parent %s not found", name)
	}
	return fallback.loadDef(name)
}

func (l *CompLoader) parseModeDef(pkg string, e *Entity, sec *Section, fallback *Loader) error {
	if p := sec.Child("Parent"); p != nil && p.StrVal() != "" {
		ps, err := l.parentSection(pkg, p.StrVal(), fallback)
		if err != nil {
			return err
		}
		if err := l.parseModeDefShared(e, ps, fallback); err != nil {
			return err
		}
	}
	return l.parseModeDefShared(e, sec, fallback)
}

func (l *CompLoader) parseModeDefShared(e *Entity, sec *Section, fallback *Loader) error {
	if im := sec.Child("Implements"); im != nil {
		for _, ifc := range im.Children {
			if ifc.Name != "Interface" || ifc.StrVal() == "" {
				continue
			}
			var isec *Section
			var err error
			for _, d := range l.ifaceDirs {
				if isec, err = l.loadSectionFile(d, ifc.StrVal()); err == nil {
					break
				}
			}
			if isec == nil {
				if fallback != nil {
					isec, err = fallback.loadInterface(ifc.StrVal())
				}
				if err != nil || isec == nil {
					return fmt.Errorf("entdef: mode interface %s not found", ifc.StrVal())
				}
			}
			if err := e.parseInterface(fallback, isec); err != nil {
				return err
			}
		}
	}
	if err := e.parseProperties(sec.Child("Properties")); err != nil {
		return err
	}
	e.applyVolatile(sec)
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
