// Digest driver: full client description map in walk order — spaces,
// entities.xml entities, mode-pkg entities, then dynamics (scripts
// components.xml order, mode pkgs alphabetical) — following the fork's
// ClientServerTypesMD5Visitor (IDA sub_142A93420/sub_142A894E0/
// sub_142AA17D0/sub_142ABCBC0 on WorldOfTanks.exe 2.4.0). Visitor chain
// fully resolved Sep 20 2026 (NETWORK_PROTOCOL.md §7):
// labels/argNames/"type" never hashed (all label slots are stubs),
// type tags NUL-terminated via sub_1403E81E0, values raw; the toggles
// below remain for matrix probing, the committed defaults encode the
// proven truth (TestComputeDigestMatchesClient green: 5df886f7…).
package entdef

import (
	"crypto/md5"
	"hash"
	"os"
)

// Digest toggles for oracle matrix probing.
var (
	// DigestLabels hashes schema labels (properties, client/base/cell
	// Methods domains, args/returnValues, fields).
	DigestLabels = false
	// DigestLabelNUL NUL-terminates labels (else raw).
	DigestLabelNUL = false
	// DigestTypeLabels hashes "type" at datatype dispatch points:
	// 0 = none, 1 = top-level only (property + arg/return types),
	// 2 = also FixedDict field types, 3 = also sequence element types.
	DigestTypeLabels = 0
	// DigestArgNames hashes method arg/return element names.
	DigestArgNames = false
	// DigestDoubleNames hashes member/method/entity/field names twice
	// (fork +24 AND +96 handlers both appending).
	DigestDoubleNames = false
	// DigestVarLen hashes varLen header-size u32 values OSE-style
	// (fork +64 handler may be label-only/no-op instead).
	DigestVarLen = false
	// DigestMethodVarLen hashes method VariableLengthHeaderSize. The
	// member prelude is instruction-identical on both builds (IDA
	// sub_142ABC050 2.4.0 == sub_142CCAC10 2.4.1): gate [a1+0x55],
	// streamSize()<0, then `mov r8d,[a1+0x58]; cmp r8d,1; jz` and
	// writer slot +0x40 called with the "varLenHeaderSize" label and
	// r8d = varLen as a third arg the decompiler elides. 8 exposed
	// methods in 2.4.0 carry Var != 1 (Account.showGUI/setParticipants,
	// Avatar.updateSpawnList/explodeProjectile/updateQuestProgress/
	// setUpdatedGoodiesSnapshot, FLAvatarComponent.updateRespawnVehicles/
	// updateRespawnInfo); ce/walkfinal_RUN.txt shows all 8 firing
	// (varlen=2, gate85=1) and the closed digest confirms the writes.
	DigestMethodVarLen = true
	// DigestVarLenLabel hashes the "varLenHeaderSize" label when the
	// varLen condition holds (the fork's +64 call passes the label but
	// no value, so it cannot hash the value): 0 = off, 1 = raw,
	// 2 = NUL-terminated.
	DigestVarLenLabel = 0
	// DigestNamesNUL NUL-terminates names and "type" (else raw).
	DigestNamesNUL = false
)

// putNameOnce writes one copy of a name with the configured encoding.
func putNameOnce(h hash.Hash, s string) {
	if DigestNamesNUL {
		putTag(h, s)
	} else {
		putStr(h, s)
	}
}

// putName writes a defs-provided name (member/method/entity/arg/field,
// or the "type" dispatch label) honoring the name toggles.
func putName(h hash.Hash, s string) {
	n := 1
	if DigestDoubleNames {
		n = 2
	}
	for i := 0; i < n; i++ {
		putNameOnce(h, s)
	}
}

// putLabel writes a schema label honoring the label toggles.
func putLabel(h hash.Hash, s string) {
	if !DigestLabels {
		return
	}
	if DigestLabelNUL {
		putTag(h, s)
	} else {
		putStr(h, s)
	}
}

// putTypeLabel writes the "type" dispatch label (topLevel selects the
// FixedDict-field scope).
func putTypeLabel(h hash.Hash, topLevel bool) {
	if DigestTypeLabels == 0 {
		return
	}
	if topLevel || DigestTypeLabels >= 2 {
		putName(h, "type")
	}
}

// putFieldName writes a FixedDict field name (doubled iff
// DigestDoubleNames, mirroring the fork's +24/+96 pair per field).
func putFieldName(h hash.Hash, s string) {
	putNameOnce(h, s)
	if DigestDoubleNames {
		putNameOnce(h, s)
	}
}

// memberMD5 mirrors sub_142ABC050: conditional varLenHeaderSize VALUE
// (u32, md5obj+64 — the label is ignored), then the name RAW via
// md5obj+96 (the +24 string slot is a no-op stub). Labels are never
// hashed anywhere in this walk (all pair/section slots hash values).
func memberMD5(h hash.Hash, name string, isForClient bool, streamSize int, varLen uint) {
	if isForClient && streamSize < 0 && varLen != 1 {
		putU32(h, varLen)
	}
	putStr(h, name)
}

// propertyMD5 mirrors sub_142A894E0: member, flags&0x5F u32
// (md5obj+40, label ignored), isVolatile u8 (md5obj+88), datatype.
func propertyMD5(h hash.Hash, p *Property) {
	memberMD5(h, p.Name, p.isClientServerData(), p.StreamSize(), p.VarLen)
	putI32(h, p.Flags&flagMask())
	putBool(h, p.Volatile)
	p.Type.AddToMD5(h)
}

// methodMD5 mirrors sub_142AA17D0 (+ legacy index in sub_142A9B810,
// hashed AFTER the body): member, flags u8 (md5obj+80), args,
// returnValues (sub_142ABCBC0: non-empty lists hash per-element
// datatypes only — element names go through the no-op +24 slot),
// legacy index u32.
// The member varLen gate's isForClient (+85) is AllowUnsafe-gated in
// practice (only VarLen methods carrying <AllowUnsafeData> fire it);
// VarLenGateUnsafe selects that reading (default true).
var VarLenGateUnsafe = false

func methodMD5(h hash.Hash, m *Method, legacyIndex int) {
	varLen := m.Var
	if !DigestMethodVarLen {
		varLen = 1
	}
	isForClient := true
	if VarLenGateUnsafe {
		isForClient = m.AllowUnsafe
	}
	memberMD5(h, m.Name, isForClient, m.streamSize(), varLen)
	putU8(h, m.Flags)
	tupleMD5(h, m.Args)
	tupleMD5(h, m.ReturnValues)
	putI32(h, legacyIndex)
}

// tupleMD5 mirrors sub_142ABCBC0: empty lists contribute nothing;
// otherwise each element's datatype (names hit the no-op slot).
func tupleMD5(h hash.Hash, types []DataType) {
	for _, t := range types {
		t.AddToMD5(h)
	}
}

// streamSize mirrors MethodDescription::streamSize(isFromServer=true) for
// the digest's varLen check. Client methods here are all exposed without
// sub-IDs, so this reduces to the args sum (or -varLen when variable).
func (m *Method) streamSize() int {
	if s := m.ArgsStreamSize(); s >= 0 {
		return s
	}
	return -int(m.Var)
}

// entityMD5 mirrors sub_142A93420: the +135 entity filter
// (sub_142A9B6C0) admits only entities with client-server data and
// hashes the entity name RAW first (sub_142A9B6E0: +96 "name", the
// +24 slot is a stub), then per-CS-property FullIndex u32
// (sub_142A9B870, filtered 0x106) + body, then per-domain methods:
// interfaces merged BEFORE own in every domain (engine load merge;
// IDA visits merged-own lists a1[67]/[51]/[35] first, then per-component
// lists a1[94..95]), continuing legacy indexes with first-wins
// name dedup (Account own requestToken drops against iface index 19),
// then static components in manifest order (continuing legacy, no
// dedup: Avatar def + story-mode setDevelopmentFeature both hash).
// Exposure mask 0xC throughout (IDA sub_142A9B810 re-checks it even
// for client methods; all def client methods carry 0x4). Section
// labels hash nothing (stub slots).
func entityMD5(h hash.Hash, e *Entity, statics []*Entity) {
	putStr(h, e.Name)
	for i := range e.Props {
		p := &e.Props[i]
		if !p.isClientServerData() {
			continue
		}
		putI32(h, p.FullIndex)
		propertyMD5(h, p)
	}
	seen := map[string]bool{}
	emit := func(m *Method, legacy *int) {
		if !m.isExposed() {
			return
		}
		if seen[m.Name] {
			return
		}
		seen[m.Name] = true
		methodMD5(h, m, *legacy)
		*legacy++
	}
	legacy := 0
	putLabel(h, "clientMethods")
	for i := range e.IfaceClientMethods {
		emit(&e.IfaceClientMethods[i], &legacy)
	}
	for i := range e.ClientMethods {
		emit(&e.ClientMethods[i], &legacy)
	}
	for _, st := range statics {
		for i := range st.IfaceClientMethods {
			m := &st.IfaceClientMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
		for i := range st.ClientMethods {
			m := &st.ClientMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
	}
	// Static component methods never dedup (Avatar def + story-mode
	// setDevelopmentFeature hash twice); def iface/own dedup above.
	seen = map[string]bool{}
	legacy = 0
	putLabel(h, "baseMethods")
	for i := range e.IfaceBaseMethods {
		emit(&e.IfaceBaseMethods[i], &legacy)
	}
	for i := range e.BaseMethods {
		emit(&e.BaseMethods[i], &legacy)
	}
	for _, st := range statics {
		for i := range st.IfaceBaseMethods {
			m := &st.IfaceBaseMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
		for i := range st.BaseMethods {
			m := &st.BaseMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
	}
	seen = map[string]bool{}
	legacy = 0
	putLabel(h, "cellMethods")
	for i := range e.IfaceCellMethods {
		emit(&e.IfaceCellMethods[i], &legacy)
	}
	for i := range e.CellMethods {
		emit(&e.CellMethods[i], &legacy)
	}
	for _, st := range statics {
		for i := range st.IfaceCellMethods {
			m := &st.IfaceCellMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
		for i := range st.CellMethods {
			m := &st.CellMethods[i]
			if !m.isExposed() {
				continue
			}
			methodMD5(h, m, legacy)
			legacy++
		}
	}
}

func (m *Method) isExposed() bool {
	return m.Flags&(expAllClients|expOwnClient) != 0
}

// Oracle-probing variants (kept for live-server experiments).
var (
	// ScriptsEntityDefsDir overrides the scripts entity-defs
	// interfaces dir used by the component interface chain (default:
	// the 2.4.0.0 shipped tree the pinned tests walk). Set it when
	// computing the digest for another client version (e.g. 2.4.1.0
	// defs extracted from res/packages/scripts.pkg).
	ScriptsEntityDefsDir = ""
	// SkipEmptyEntities drops entities with no props and no methods.
	SkipEmptyEntities = true
	// FullFlagMask, when set, hashes all dataFlags bits (not just dist).
	FullFlagMask = false
	// ZeroVisitInclude overrides the failEntries denylist (matrix probe
	// for the +135 rule; default false = observed behavior).
	ZeroVisitInclude = false
)

func flagMask() int {
	if FullFlagMask {
		return 0x1FF
	}
	return distMask
}

// MapEntry is one digest map entry in walk order: an entity, space,
// mode entity, or dynamic component, plus merged static components.
type MapEntry struct {
	Ent     *Entity
	Statics []*Entity
}

// entryIncluded mirrors the +135 filter (sub_142A9B6C0). The walkfinal
// probe enumerated the map authoritatively (332 entries, pass/fail per
// entry): every entity/space passes, and every component passes EXCEPT
// 14 def-empty dynamics below (pass=0, names not hashed). No def-content
// rule separates them (passing AutocannonsShootingCounter and failing
// ExtendedSPG are structurally identical) — the filter is decided at
// runtime (Python-side registration), so the observed fail set is
// pinned here. LimitedVisibilityEntity (2 non-CS props, visited) passes.
var failEntries = map[string]bool{
	"ExtendedSPG": true, "EnemyShotPredictorController": true,
	"ArenaVehiclesInfo": true, "ArenaLootComponent": true,
	"ArenaDeathZonesComponent": true, "ArenaEntityPositionGridComponent": true,
	"SpawnKeyPointController": true, "FLReservesComponent": true,
	"FLArenaMinefieldComponent": true, "FLArenaBattleModifiersComponent": true,
	"ArenaAchievementsComponent": true, "LSArenaDropComponent": true,
	"LSArenaVehicleRemovalComponent": true, "LSArenaWatersComponent": true,
}

func entryIncluded(e *Entity, statics []*Entity) bool {
	if failEntries[e.Name] {
		return false
	}
	return true
}

// Skip241 lists the extra 2.4.1.0 walk fails beyond the built-in 14
// (ProbeWalk import-probe, game.log Oct-15: ok=385 fail=18 total=403).
// Pass it as skip to ComputeDigestFull with the external 2.4.1 defs
// (sibling dirs wotdefs-2.4.1/ + scripts-2.4.1/, kept out of this repo);
// the 14 built-ins are still skipped via failEntries. With this set the
// digest reproduces the client truth c0cc08a2… exactly.
var Skip241 = map[string]bool{
	"HWArenaDropComponent":             true,
	"HWArenaVehicleRemovalComponent":   true,
	"HWArenaPhaseProgressionComponent": true,
	"HWArenaSpawnInfoComponent":        true,
}

// BuildMapOrder assembles the full digest walk order: spaces, scripts
// entities.xml, mode-pkg entities (pkg-alpha, extension order),
// scripts dynamics (components.xml order), mode-pkg dynamics (pkg-alpha,
// extension order). Static components merge into their ofEntity entry
// (scripts statics in manifest order, then mode pkgs alpha).
func BuildMapOrder(wotdefsDir, defsDir string) ([]MapEntry, error) {
	el := &Loader{Dir: defsDir}
	if err := el.ensureAliases(); err != nil {
		return nil, err
	}
	cl := NewCompLoader(wotdefsDir)
	if err := cl.LoadExtensions(); err != nil {
		return nil, err
	}
	var entries []MapEntry
	// 1. spaces.
	space, err := cl.ParseSpace("GeneralSpaceData")
	if err != nil {
		return nil, err
	}
	entries = append(entries, MapEntry{Ent: space})
	// 2. scripts entities.
	names, err := el.LoadEntities()
	if err != nil {
		return nil, err
	}
	// Parse all static components once, grouped by ofEntity.
	staticsByEntity := map[string][]*Entity{}
	var scriptsStatics, modeStatics []string
	for _, ex := range cl.exts {
		if ex.Pkg == "scripts" {
			scriptsStatics = ex.Static
		}
	}
	for _, ex := range cl.exts {
		if ex.Pkg == "scripts" {
			continue
		}
		for _, s := range ex.Static {
			modeStatics = append(modeStatics, s)
		}
	}
	for _, s := range append(append([]string{}, scriptsStatics...), modeStatics...) {
		st, of, err := cl.ParseComponent(s)
		if err != nil {
			return nil, err
		}
		if of == "" {
			continue
		}
		staticsByEntity[of] = append(staticsByEntity[of], st)
	}
	for _, name := range names {
		e, err := el.ParseEntity(name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, MapEntry{Ent: e, Statics: staticsByEntity[name]})
	}
	// 3. mode entities (pkg-alpha via exts order).
	for _, ex := range cl.exts {
		if ex.Pkg == "scripts" {
			continue
		}
		for _, name := range ex.Entities {
			e, err := cl.ParseModeEntity(ex.Pkg, name, el)
			if err != nil {
				return nil, err
			}
			entries = append(entries, MapEntry{Ent: e, Statics: staticsByEntity[name]})
		}
	}
	// 4. dynamics: scripts manifest order, then mode pkgs alpha.
	var dynOrder []string
	seenDyn := map[string]bool{}
	for _, ex := range cl.exts {
		if ex.Pkg == "scripts" {
			dynOrder = append(dynOrder, ex.Dynamic...)
		}
	}
	for _, ex := range cl.exts {
		if ex.Pkg == "scripts" {
			continue
		}
		dynOrder = append(dynOrder, ex.Dynamic...)
	}
	for _, name := range dynOrder {
		if seenDyn[name] {
			continue // manifest repeats (scripts lists SecondaryGun +
			// NetworkReplication/NetworkVehicleHierarchy twice);
			// first registration wins.
		}
		seenDyn[name] = true
		st, _, err := cl.ParseComponent(name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, MapEntry{Ent: st})
	}
	return entries, nil
}

// Truth240 is the live 2.4.0 BigWorld.digest (digest-dumper mod,
// 2026-09-17, re-dumped 2026-09-20 identical). The LoginApp server
// accepts it (dummy creds then fail with status 68, not 70).
const Truth240 = "5df886f75e73b33cff9d87fb9c69389c"

// Truth241 is the live 2.4.1.0 BigWorld.digest (digest-dumper mod,
// game.log Oct-15; dummy-creds probe → status 68). The offline recompute
// reproduces it exactly (TestComputeDigest241Offline).
const Truth241 = "c0cc08a2f494f7087112009ce1d002db"

// DigestVersion computes the offline login digest for one client version
// from external (uncommitted) def trees. It owns the globals both inputs
// depend on (alias cache, ScriptsEntityDefsDir, ImplEncoding): it resets
// them, computes, and restores them, so back-to-back versions in one
// process stay isolated. wotdefsDir holds components/extensions/
// mode_entities/space_defs; entityDefsDir holds entities.xml +
// entity_defs. skip lists extra walk fails beyond the built-in 14
// (e.g. Skip241).
func DigestVersion(wotdefsDir, entityDefsDir string, skip map[string]bool) ([16]byte, error) {
	prevDir, prevImpl := ScriptsEntityDefsDir, ImplEncoding
	ResetAliases()
	ScriptsEntityDefsDir = entityDefsDir
	ImplEncoding = 0
	defer func() {
		ScriptsEntityDefsDir = prevDir
		ImplEncoding = prevImpl
		ResetAliases()
	}()
	return ComputeDigestFull(wotdefsDir, entityDefsDir, skip)
}

// ComputeDigestFull hashes the full client map (spaces + entities +
// statics + mode entities + dynamics) in walk order.
func ComputeDigestFull(wotdefsDir, defsDir string, skip map[string]bool) ([16]byte, error) {
	entries, err := BuildMapOrder(wotdefsDir, defsDir)
	if err != nil {
		return [16]byte{}, err
	}
	h := md5.New()
	for _, en := range entries {
		if skip[en.Ent.Name] {
			continue
		}
		incl := entryIncluded(en.Ent, en.Statics)
		if SkipEmptyEntities && !incl && !ZeroVisitInclude {
			continue
		}
		entityMD5(h, en.Ent, en.Statics)
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ComputeDigest parses every entity in order and returns the login defs
// digest (EntityDefConstants), hex-encoded by the caller as needed.
// Skip lists entity names to exclude (oracle probing of the digest scope).
func ComputeDigest(defsDir string, names []string, skip map[string]bool) ([16]byte, error) {
	l := &Loader{Dir: defsDir}
	if err := l.ensureAliases(); err != nil {
		return [16]byte{}, err
	}
	h := md5.New()
	for _, name := range names {
		if skip[name] {
			continue
		}
		e, err := l.ParseEntity(name)
		if err != nil {
			return [16]byte{}, err
		}
		if SkipEmptyEntities && len(e.CSProps) == 0 && len(e.ClientMethods) == 0 &&
			len(e.BaseMethods) == 0 && len(e.CellMethods) == 0 &&
			len(e.IfaceClientMethods) == 0 && len(e.IfaceBaseMethods) == 0 && len(e.IfaceCellMethods) == 0 {
			continue
		}
		entityMD5(h, e, nil)
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// InitAliasesFromDir loads scripts/entity_defs/alias.xml once.
func InitAliasesFromDir(defsDir string) error {
	raw, err := os.ReadFile(defsDir + "/alias.xml")
	if err != nil {
		return err
	}
	f, err := ParseFile(raw)
	if err != nil {
		return err
	}
	return InitAliases(f.Root)
}
