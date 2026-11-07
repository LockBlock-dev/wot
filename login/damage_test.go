package login

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestResolveShotHitsTheDummyFront checks the trace and the front-armour
// penetration: a shell with more penetration than the TOG II's 76.2 mm front
// pierces it and rolls damage.
func TestResolveShotHitsTheDummyFront(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Name: "test", Damage: 300, Pen: 200, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	// From 20 m in front of the tank, firing straight at it (-Z).
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, []hitBox{box})
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if !res.Pierced {
		t.Fatalf("pierced = false, want true (pen 200 vs armour %.1f)", res.Armor)
	}
	if math.Abs(float64(res.Armor-76.2)) > 0.01 {
		t.Fatalf("effective armour = %.2f, want 76.2", res.Armor)
	}
	if res.Damage < 225 || res.Damage > 375 {
		t.Fatalf("damage = %d, want 225..375 (300 ±25%%)", res.Damage)
	}
	if res.Effect != hitEffectPierced {
		t.Fatalf("effect = %d, want %d", res.Effect, hitEffectPierced)
	}
	if res.Flags != hitFlagsPierced {
		t.Fatalf("flags = %#x, want %#x", res.Flags, hitFlagsPierced)
	}
	// The front face is at +Z, so the hit point is there and the outward
	// normal points at the shooter. The face is the hull collision box's max
	// z, not a round number: 4.2737 from `Hull.havok`'s `HKBodyFlagsData`.
	if math.Abs(float64(res.Point[2]-dummyHullBounds[1][2])) > 0.01 {
		t.Fatalf("hit z = %v, want %v (the front face)", res.Point[2], dummyHullBounds[1][2])
	}
	if res.Normal[2] != 1 {
		t.Fatalf("normal = %v, want +Z", res.Normal)
	}
}

// TestResolveShotRearArmour checks that the same shell meets the thinner rear
// plate from behind.
func TestResolveShotRearArmour(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 200, KindIndex: 2, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, -20}, [3]float32{0, 0, 1}, []hitBox{box})
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if math.Abs(float64(res.Armor-50.8)) > 0.01 {
		t.Fatalf("effective armour = %.2f, want the 50.8 rear", res.Armor)
	}
	if !res.Pierced {
		t.Fatal("pen 200 should pierce the 50.8 rear")
	}
}

// TestResolveShotMisses checks that a shot beside the tank does nothing.
func TestResolveShotMisses(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 200, KindIndex: 2, Caliber: 76.2}
	if res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{1, 0, 0}, []hitBox{box}); res.Hit {
		t.Fatalf("shot beside the tank hit at %v", res.Point)
	}
}

// TestResolveShotAngleIncreasesArmour checks the impact-angle term: a 45°
// hit on the 76.2 mm front meets about 107.8 mm.
func TestResolveShotAngleIncreasesArmour(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 1000, KindIndex: 2, Caliber: 76.2}
	// 45° off the front normal, from far enough left that the ray meets
	// the front plate before the side.
	dir := [3]float32{float32(math.Sin(math.Pi / 4)), 0, -float32(math.Cos(math.Pi / 4))}
	res := resolveShot(sh, [3]float32{-15, 2, 20}, dir, []hitBox{box})
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	want := 76.2 / math.Cos(math.Pi/4)
	if math.Abs(float64(res.Armor)-want) > 0.5 {
		t.Fatalf("effective armour = %.2f, want %.2f", res.Armor, want)
	}
}

// TestResolveShotNotPierced checks a shell that cannot get through: no
// damage, the resisted effect and the not-pierced flags.
func TestResolveShotNotPierced(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 50, KindIndex: 2, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, []hitBox{box})
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	if res.Pierced {
		t.Fatal("pen 50 should not pierce 76.2 mm")
	}
	if res.Damage != 0 {
		t.Fatalf("damage = %d, want 0", res.Damage)
	}
	if res.Effect != hitEffectNotPierced {
		t.Fatalf("effect = %d, want %d", res.Effect, hitEffectNotPierced)
	}
	if res.Flags != hitFlagDirect|hitFlagArmorNotPierced {
		t.Fatalf("flags = %#x, want %#x", res.Flags, hitFlagDirect|hitFlagArmorNotPierced)
	}
}

// TestResolveShotHEExplodes checks an HE shell that does not pierce still
// deals its explosion damage and sets the explosion flag.
func TestResolveShotHEExplodes(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Damage: 300, Pen: 10, Kind: "HIGH_EXPLOSIVE", KindIndex: 1, Caliber: 76.2}
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, []hitBox{box})
	if !res.Hit || res.Pierced {
		t.Fatalf("hit=%v pierced=%v, want a non-piercing hit", res.Hit, res.Pierced)
	}
	if res.Damage <= 0 {
		t.Fatal("HE explosion did no damage")
	}
	if res.Flags&hitFlagExploded == 0 {
		t.Fatalf("flags = %#x, want the explosion bit", res.Flags)
	}
}

// TestEncodeHitSegment checks the hit-point segment's packing: the hull part
// and hit effect in the low bytes, the quantized enter/exit points above.
func TestEncodeHitSegment(t *testing.T) {
	bounds := dummyBounds()
	// The box's own centre, travelling -Z: the segment crosses the whole box,
	// so it enters at the front face and leaves at the rear.
	centre := [3]float32{
		(bounds[0][0] + bounds[1][0]) / 2,
		(bounds[0][1] + bounds[1][1]) / 2,
		(bounds[0][2] + bounds[1][2]) / 2,
	}
	seg := encodeHitSegment(bounds, centre, [3]float32{0, 0, -1}, 1, hitEffectPierced)
	if got := uint8(seg); got != hitEffectPierced {
		t.Fatalf("context = %d, want %d", got, hitEffectPierced)
	}
	if got := uint8(seg >> 8); got != 1 {
		t.Fatalf("part = %d, want 1 (hull)", got)
	}
	// The segment enters at the front (z = max → 255) and leaves at the rear
	// (z = min → 0); x and y are the box's middle (about 128).
	ax, ay, az := uint8(seg>>16), uint8(seg>>24), uint8(seg>>32)
	bx, by, bz := uint8(seg>>40), uint8(seg>>48), uint8(seg>>56)
	if az != 255 || bz != 0 {
		t.Fatalf("segment z = %d..%d, want 255..0", az, bz)
	}
	for _, v := range []uint8{ax, ay, bx, by} {
		if v < 126 || v > 130 {
			t.Fatalf("segment x/y = %d, want about 128", v)
		}
	}
}

// TestHitParams checks the `VEHICLE_HIT_POINT.params` word.
func TestHitParams(t *testing.T) {
	sh := shellSpec{Caliber: 76.2, KindIndex: 2}
	got := hitParams(sh, hitEffectPierced)
	want := uint32(762)<<8 | uint32(2)<<4 | uint32(hitEffectPierced)
	if got != want {
		t.Fatalf("params = %#x, want %#x", got, want)
	}
}

// TestDamageMethodCalls checks the client method calls against the shipped
// 2.4.1 defs: the exposed ids and the nine-argument showDamageFromShot.
func TestDamageMethodCalls(t *testing.T) {
	d := testDispatch(t)
	vehType := d.Entity("Vehicle")
	avatarType := d.Entity("Avatar")
	if vehType == nil || avatarType == nil {
		t.Fatal("defs have no Vehicle/Avatar")
	}
	vehicle := NewEntity(100, vehType)
	avatar := NewEntity(200, avatarType)

	point := hitPointValue(0x0102030405060708, hitParams(shellSpec{Caliber: 76.2, KindIndex: 2}, hitEffectPierced))
	el, err := showDamageFromShotElement(vehicle, 42, point, 3, 300, 61, 800)
	if err != nil {
		t.Fatalf("showDamageFromShot: %v", err)
	}
	if want := byte(entityMethodBase + 10); el[0] != want {
		t.Fatalf("showDamageFromShot id = %#x, want %#x", el[0], want)
	}
	if len(el) < 20 {
		t.Fatalf("showDamageFromShot = %d B, want the full nine-argument payload", len(el))
	}

	el, err = onHealthChangedElement(vehicle, 948, 1248, 42)
	if err != nil {
		t.Fatalf("onHealthChanged: %v", err)
	}
	if want := byte(entityMethodBase + 4); el[0] != want {
		t.Fatalf("onHealthChanged id = %#x, want %#x", el[0], want)
	}

	el, err = showShotResultsElement(avatar, 100, hitFlagsPierced)
	if err != nil {
		t.Fatalf("showShotResults: %v", err)
	}
	if want := byte(entityMethodBase + 54); el[0] != want {
		t.Fatalf("showShotResults id = %#x, want %#x", el[0], want)
	}

	el, err = showTracerElement(avatar, 42, 1, shellSpec{Caliber: 76.2, KindIndex: 2, Speed: 800, Gravity: 9.81, MaxDistance: 720}, [3]float32{0, 2, 20}, [3]float32{0, 0, -800})
	if err != nil {
		t.Fatalf("showTracer: %v", err)
	}
	// The live S>C tracers ride `1a 0x73`, i.e. exposed id 37 (the replay's
	// method id 17 is a different numbering).
	if want := byte(entityMethodBase + 37); el[0] != want {
		t.Fatalf("showTracer id = %#x, want %#x", el[0], want)
	}

	el, err = stopTracerElement(avatar, 1, [3]float32{0, 2, 5})
	if err != nil {
		t.Fatalf("stopTracer: %v", err)
	}
	if el[0] <= entityMethodBase || el[0] > entityMethodBase+0x58 {
		t.Fatalf("stopTracer id = %#x, outside the client method range", el[0])
	}

	el, err = showShootingElement(vehicle, 1, 0, 2)
	if err != nil {
		t.Fatalf("showShooting: %v", err)
	}
	if el[0] <= entityMethodBase || el[0] > entityMethodBase+0x58 {
		t.Fatalf("showShooting id = %#x, outside the client method range", el[0])
	}
	if len(el) < 4 {
		t.Fatalf("showShooting = %d B, want the three arguments", len(el))
	}
}

// TestDamageStickersUpdate pins the shell-hole property: the vehicle's
// `damageStickers` is an ALL_CLIENTS property, so it rides a property update
// (the `[id][u16 len][value]` form), not a client method call.
func TestDamageStickersUpdate(t *testing.T) {
	d := testDispatch(t)
	vehType := d.Entity("Vehicle")
	if vehType == nil {
		t.Fatal("defs have no Vehicle")
	}
	vehicle := NewEntity(100, vehType)
	sticker := hitPointValue(0x0102030405060708, hitParams(shellSpec{Caliber: 76.2, KindIndex: 2}, hitEffectPierced))
	vehicle.Set("damageStickers", entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{sticker}})
	el, err := EncodePropertyUpdate(vehicle, "damageStickers")
	if err != nil {
		t.Fatalf("damageStickers update: %v", err)
	}
	// The id is the client-server FullIndex (33), not the def position.
	if want := byte(entityPropertyBase + 33); el[0] != want {
		t.Fatalf("damageStickers id = %#x, want %#x (FullIndex 33)", el[0], want)
	}
	if len(el) < 12 {
		t.Fatalf("damageStickers = %d B, want the hit point payload", len(el))
	}
}

// TestDamageMethodCallsNeedTheDefs guards the argument shapes: a wrong count
// or type is an error, not a silently short element.
func TestDamageMethodCallsNeedTheDefs(t *testing.T) {
	d := testDispatch(t)
	vehType := d.Entity("Vehicle")
	if vehType == nil {
		t.Fatal("defs have no Vehicle")
	}
	vehicle := NewEntity(100, vehType)
	if _, err := EncodeClientMethodCall(vehicle, "showDamageFromShot", []entdef.Value{{Kind: entdef.VUint}}); err == nil {
		t.Fatal("showDamageFromShot accepted one argument")
	}
}

// TestDispersionShellData checks the shell's own def is read: damage, kind,
// penetration and the shot-effects index. It needs the game's scripts.pkg.
func TestDispersionShellData(t *testing.T) {
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no scripts.pkg")
	}
	d, err := dispersionIn(pkg,
		"scripts/item_defs/vehicles/uk/GB63_TOG_II.xml",
		"scripts/item_defs/vehicles/uk/components/guns.xml",
		"Chassis_GB63_TOG_II", "OQF_17pdr_Gun_Mk_VII_A")
	if err != nil {
		t.Fatalf("dispersionIn: %v", err)
	}
	if d.Shell.Name != "_17pdr_AP_Mk3T" {
		t.Fatalf("shell = %q, want the default AP", d.Shell.Name)
	}
	if d.Shell.Damage != 150 {
		t.Fatalf("damage = %v, want 150", d.Shell.Damage)
	}
	if d.Shell.Pen != 171 {
		t.Fatalf("pen = %v, want 171", d.Shell.Pen)
	}
	if d.Shell.KindIndex != 2 {
		t.Fatalf("kind = %d, want 2 (ARMOR_PIERCING)", d.Shell.KindIndex)
	}
	if d.Shell.Caliber != 76.2 {
		t.Fatalf("caliber = %v, want 76.2", d.Shell.Caliber)
	}
	if !d.Shell.HasPiercedSticker {
		t.Fatal("the AP shell has no pierced sticker")
	}
	t.Logf("pierced sticker index = %d", d.Shell.PiercedSticker)
	if d.Shell.EffectsIndex == 0 {
		t.Fatalf("effects index = 0, want the shot_effects position")
	}
}

// TestHealthIsABareProperty pins the `Vehicle.health` update: a bare
// `[0xA7+14][i16]`, not the `updateEntity` run's `[id][u16 len][value]`.
// With the length the client reads it as the health and the value's low
// byte as the next element id (health 926 = 0x039E → 0x9E = exposed method
// 80, out of range on the 11-method Vehicle).
func TestHealthIsABareProperty(t *testing.T) {
	got := EncodeBareU16(elVehicleHealth, 926)
	want := []byte{0xB5, 0x9E, 0x03}
	if !bytes.Equal(got, want) {
		t.Fatalf("health element = % x, want % x", got, want)
	}
	if elVehicleHealth != 0xB5 {
		t.Fatalf("elVehicleHealth = %#x, want 0xB5 (0xA7 + 14)", elVehicleHealth)
	}
}

// TestTakeAmmoDecrementsTheFiredShell pins the ammo count: only the fired
// shell's entry drops, and it never goes below zero.
func TestTakeAmmoDecrementsTheFiredShell(t *testing.T) {
	entry := func(cd int64, qty uint64) entdef.Value {
		return entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
			{Name: "compactDescr", Value: entdef.Value{Kind: entdef.VInt, Int: cd}},
			{Name: "quantity", Value: entdef.Value{Kind: entdef.VUint, Uint: qty}},
			{Name: "quantityInClip", Value: entdef.Value{Kind: entdef.VUint, Uint: 1}},
		}}
	}
	list := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{entry(100, 10), entry(200, 5)}}

	got, remaining, ok := takeAmmo(list, 100)
	if !ok || remaining != 9 {
		t.Fatalf("takeAmmo(100) = %d, %v; want 9, true", remaining, ok)
	}
	if q, _ := got.Seq[0].Get("quantity"); q.Uint != 9 {
		t.Fatalf("shell 100 quantity = %d, want 9", q.Uint)
	}
	if q, _ := got.Seq[1].Get("quantity"); q.Uint != 5 {
		t.Fatalf("shell 200 quantity = %d, want 5 (untouched)", q.Uint)
	}
	if _, _, ok := takeAmmo(got, 300); ok {
		t.Fatal("takeAmmo(300) succeeded for a shell not in the list")
	}
	// Drain shell 100: the last shell leaves 0, the next call refuses.
	for i := 0; i < 9; i++ {
		got, _, _ = takeAmmo(got, 100)
	}
	if q, _ := got.Seq[0].Get("quantity"); q.Uint != 0 {
		t.Fatalf("shell 100 quantity = %d, want 0", q.Uint)
	}
	if _, _, ok := takeAmmo(got, 100); ok {
		t.Fatal("takeAmmo succeeded with no shells left")
	}
}

// TestShellSettingTracksTheLoadedShell pins the `vehicle_changeSetting`
// shell codes: CURRENT_SHELLS moves the shell a shot consumes, NEXT_SHELLS
// the one the panel shows next, and the settings value carries both.
func TestShellSettingTracksTheLoadedShell(t *testing.T) {
	st := &clientState{loadedShell: 100, nextShell: 200}
	applyShellSetting(st, settingCurrentShell, 300)
	if st.loadedShell != 300 {
		t.Fatalf("loaded = %d, want 300", st.loadedShell)
	}
	applyShellSetting(st, settingNextShell, 400)
	if st.nextShell != 400 {
		t.Fatalf("next = %d, want 400", st.nextShell)
	}
	if st.loadedShell != 300 {
		t.Fatalf("loaded changed to %d by NEXT_SHELLS", st.loadedShell)
	}

	v := vehicleSettingsValue(7, st.loadedShell, st.nextShell)
	if v.Kind != entdef.VSeq || len(v.Seq) != 2 {
		t.Fatalf("settings = %+v, want two entries", v)
	}
	if code, _ := v.Seq[0].Get("code"); code.Uint != 0 {
		t.Fatalf("entry 0 code = %d, want 0 (CURRENT_SHELLS)", code.Uint)
	}
	if val, _ := v.Seq[0].Get("value"); val.Int != 300 {
		t.Fatalf("entry 0 value = %d, want 300", val.Int)
	}
	if code, _ := v.Seq[1].Get("code"); code.Uint != 1 {
		t.Fatalf("entry 1 code = %d, want 1 (NEXT_SHELLS)", code.Uint)
	}
	if val, _ := v.Seq[1].Get("value"); val.Int != 400 {
		t.Fatalf("entry 1 value = %d, want 400", val.Int)
	}
}

// TestShellSwitchRestartsTheReload pins the shell-change reload: switching
// the loaded shell sends the new vehicleSettings AND starts a full reload,
// and a completion timer from the old reload cannot close the new one.
func TestShellSwitchRestartsTheReload(t *testing.T) {
	d := testDispatch(t)
	s := &BaseAppServer{
		cfg:        BaseAppConfig{Dispatch: d},
		resend:     newResendQueue(400*time.Millisecond, 20*time.Second),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	st := &clientState{
		blockKey:    "0123456789abcdef",
		resendKey:   "test",
		vehicle:     NewEntity(7, d.Entity("Vehicle")),
		ownVehicle:  nrlComponent{TypeID: 53, Node: 7, FirstChild: 8, Props: 23, Methods: 11},
		gunSpec:     gunSpec{Dispersion: dispersionSpec{ReloadTime: 10, ShellCD: 100}},
		loadedShell: 100,
		nextShell:   100,
		tick:        100,
		arena:       &ArenaHandoff{ArenaID: 1},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	tr := &fakeTransport{}
	if err := s.answerShellSetting(tr, addr, st, settingCurrentShell, 200); err != nil {
		t.Fatalf("answerShellSetting: %v", err)
	}
	if st.loadedShell != 200 {
		t.Fatalf("loaded = %d, want 200", st.loadedShell)
	}
	if st.reloadGen != 1 {
		t.Fatalf("reloadGen = %d, want 1", st.reloadGen)
	}
	if len(tr.writes) != 2 {
		t.Fatalf("%d packets, want 2 (vehicleSettings + reload start)", len(tr.writes))
	}
	// An old completion must not close the reload the switch just started.
	before := len(tr.writes)
	st.reloadGen = 2
	s.finishReload(tr, addr, st, 1, 0.001, 1)
	if len(tr.writes) != before {
		t.Fatal("an old reload completion sent a packet")
	}
	// The current generation still closes it.
	s.finishReload(tr, addr, st, 1, 0.001, 2)
	if len(tr.writes) != before+1 {
		t.Fatalf("%d packets after the current completion, want %d", len(tr.writes), before+1)
	}
}

// TestKillUpdatesVehiclesInfo pins the kill: the victim's row goes dead with a
// deathInfo, the shooter's stFrags/frags count it, and the whole list is
// re-sent as an NRL property update.
func TestKillUpdatesVehiclesInfo(t *testing.T) {
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		t.Skip("no VEHICLES_INFO type")
	}
	player := vehicleInfoValue(infoType, ArenaPlayerDoc{Name: "me", Team: 1}, 100, 1, 0, 0)
	dummy := vehicleInfoValue(infoType, ArenaPlayerDoc{Name: "tog", Team: 2}, 101, 1, 0, 0)
	st := &clientState{
		infoComp:     nrlComponent{TypeID: AvatarVehiclesInfoNrlID, Node: 1, FirstChild: 2, Props: 1},
		infoVehicles: []entdef.Value{player, dummy},
		infoPlayer:   0,
	}
	s := &BaseAppServer{}
	el := s.killVehiclesInfo(st, 1, 100)
	if len(el) == 0 {
		t.Fatal("no vehiclesInfo update")
	}
	if st.infoKills != 1 {
		t.Fatalf("kills = %d, want 1", st.infoKills)
	}
	if alive, ok := st.infoVehicles[1].Get("isAlive"); !ok || alive.Uint != 0 {
		t.Fatalf("victim isAlive = %v (ok=%v), want 0", alive, ok)
	}
	if _, ok := st.infoVehicles[1].Get("deathInfo"); !ok {
		t.Fatal("victim has no deathInfo")
	}
	if frags, ok := st.infoVehicles[0].Get("stFrags"); !ok || frags.Uint != 1 {
		t.Fatalf("shooter stFrags = %v (ok=%v), want 1", frags, ok)
	}
	if frags, ok := st.infoVehicles[0].Get("frags"); !ok || frags.Int != 1 {
		t.Fatalf("shooter frags = %v (ok=%v), want 1", frags, ok)
	}
	// A second kill counts again.
	s.killVehiclesInfo(st, 1, 100)
	if st.infoKills != 2 {
		t.Fatalf("kills = %d, want 2", st.infoKills)
	}
}

// TestEBRSticker pins the packed-BLOB effects path: the EBR 105's shell
// names `mainAPCR` in a TypeBlob node, which `AsString` cannot read, and
// resolves to the `main_hole` sticker (7).
func TestEBRSticker(t *testing.T) {
	pkg := FindScriptsPkg()
	if pkg == "" {
		t.Skip("no scripts.pkg")
	}
	d, err := shellDataIn(pkg, "france", "_105mm_OFL_105_D_1504_EBR")
	if err != nil {
		t.Fatalf("shellDataIn: %v", err)
	}
	if !d.HasPiercedSticker {
		t.Fatal("the APCR shell has no pierced sticker")
	}
	if d.PiercedSticker != 7 {
		t.Fatalf("pierced sticker = %d, want 7 (main_hole)", d.PiercedSticker)
	}
	if d.EffectsIndex == 0 {
		t.Fatal("effects index = 0, want the mainAPCR slot")
	}
}

// TestShotPacketsSurviveTheClientReader fires a shot at the dummy and runs
// every packet the server emits through the client's own bundle reader.
//
// The shot is the one path that puts several elements with different shapes in
// one bundle (entity methods on two entities, a property update, a bare
// property, NRL component updates), and the client has no way to resynchronise:
// a stray length field is read as the next element id and the bundle dies as
// REASON_CORRUPTED_PACKET — on the next one it asserts
// `pCurr_ + nBytes <= pEnd_` and the game crashes. This is the regression test
// for that: nothing may be left over and every element must be in the table.
func TestShotPacketsSurviveTheClientReader(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	vehType := d.Entity("Vehicle")
	avatarType := d.Entity("Avatar")
	if vehType == nil || avatarType == nil {
		t.Fatal("defs have no Vehicle/Avatar")
	}
	// The EBR 105: a real vehicle whose gun spec resolves (turret speeds,
	// yaw arc, shell data), so the shot is resolved for real.
	const ebrCompDescr = "\x41\x4a\x9d\x00\x65\x00\xcd\x00\x22\x00\x82\x00\x63\x00\x00"
	spec, ok := vehicleGunSpeeds([]byte(ebrCompDescr))
	if !ok {
		t.Fatal("no gun spec for the EBR 105")
	}
	vehicle := NewEntity(100003, vehType)
	avatar := NewEntity(100001, avatarType)
	dummy := NewEntity(100004, vehType)
	for _, p := range vehType.CellProps {
		vehicle.Set(p.Name, entdef.ZeroValue(p.Type))
		dummy.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	for _, p := range avatarType.CellProps {
		avatar.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	shell := spec.Dispersion.ShellCD
	ammo := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "compactDescr", Value: entdef.Value{Kind: entdef.VInt, Int: int64(shell)}},
		{Name: "quantity", Value: entdef.Value{Kind: entdef.VUint, Uint: 30}},
		{Name: "quantityInClip", Value: entdef.Value{Kind: entdef.VUint, Uint: 1}},
		{Name: "previousStage", Value: entdef.Value{Kind: entdef.VUint}},
		{Name: "endTime", Value: entdef.Value{Kind: entdef.VFloat}},
		{Name: "totalTime", Value: entdef.Value{Kind: entdef.VInt}},
		{Name: "index", Value: entdef.Value{Kind: entdef.VUint}},
	}}}}
	hull := hull{Position: [3]float32{0, 0, 0}, Direction: [3]float32{0, 0, 0}, Limits: spec.Limits}
	marker := gunMarkerFor(hull, 0, 0, spec, 1)
	// Put the dummy 12 m down the barrel so the trace is a clean front hit.
	dir := [3]float32{marker.Velocity[0], marker.Velocity[1], marker.Velocity[2]}
	l := float32(math.Sqrt(float64(dir[0]*dir[0] + dir[1]*dir[1] + dir[2]*dir[2])))
	dummyPos := [3]float32{marker.Position[0] + dir[0]/l*12, marker.Position[1] + dir[1]/l*12, marker.Position[2] + dir[2]/l*12}

	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		entityID: avatar.ID, avatar: avatar, vehicle: vehicle,
		targets: []*botTarget{{entity: dummy, id: dummy.ID, pos: dummyPos, health: 1248, maxHealth: 1248, infoIndex: 1}},
		gunSpec: spec, hull: hull, ammoList: ammo, loadedShell: shell, nextShell: shell,
		ownVehicle: nrlComponent{TypeID: OwnVehicleNrlID, Node: 7, FirstChild: 8, Props: 23, Methods: 11},
		postSeq:    100, postCumul: 3, tick: 1000,
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerShoot(tr, addr, st); err != nil {
		t.Fatalf("answerShoot: %v", err)
	}
	if len(tr.writes) == 0 {
		t.Fatal("the shot emitted nothing")
	}
	for i, pkt := range tr.writes {
		app := findAppInPacket(t, pkt, st.blockKey)
		if app == nil {
			t.Fatalf("packet %d has no app", i)
		}
		if err := CheckClientApp(d, app); err != nil {
			t.Fatalf("packet %d: the client would drop this bundle: %v (app % x)", i, err, app)
		}
	}
}

// TestKillPacketsSurviveTheClientReader fires the killing shot and runs every
// packet through the client's reader, including the nested `vehiclesInfo`
// updates and the battle-events feedback.
//
// The kill is the one update that has to be NESTED: `AvatarVehiclesInfo` has no
// whole-value handler, so a re-sent list sets the attribute and calls nothing —
// the tab keeps the row alive, the kill count stays 0 and no kill message
// appears. The nested path is `[1][prop][1][elem][0][field]` bits, then the
// value, then a `__generation` bump that flushes the diff.
func TestKillPacketsSurviveTheClientReader(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	vehType := d.Entity("Vehicle")
	avatarType := d.Entity("Avatar")
	if vehType == nil || avatarType == nil {
		t.Fatal("defs have no Vehicle/Avatar")
	}
	const ebrCompDescr = "\x41\x4a\x9d\x00\x65\x00\xcd\x00\x22\x00\x82\x00\x63\x00\x00"
	spec, ok := vehicleGunSpeeds([]byte(ebrCompDescr))
	if !ok {
		t.Fatal("no gun spec for the EBR 105")
	}
	vehicle := NewEntity(100003, vehType)
	avatar := NewEntity(100001, avatarType)
	dummy := NewEntity(100004, vehType)
	for _, p := range vehType.CellProps {
		vehicle.Set(p.Name, entdef.ZeroValue(p.Type))
		dummy.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	for _, p := range avatarType.CellProps {
		avatar.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	shell := spec.Dispersion.ShellCD
	ammo := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "compactDescr", Value: entdef.Value{Kind: entdef.VInt, Int: int64(shell)}},
		{Name: "quantity", Value: entdef.Value{Kind: entdef.VUint, Uint: 30}},
		{Name: "quantityInClip", Value: entdef.Value{Kind: entdef.VUint, Uint: 1}},
	}}}}
	hull := hull{Position: [3]float32{0, 0, 0}, Direction: [3]float32{0, 0, 0}, Limits: spec.Limits}
	marker := gunMarkerFor(hull, 0, 0, spec, 1)
	dir := [3]float32{marker.Velocity[0], marker.Velocity[1], marker.Velocity[2]}
	l := float32(math.Sqrt(float64(dir[0]*dir[0] + dir[1]*dir[1] + dir[2]*dir[2])))
	// The dummy's ORIGIN is on the ground, not at the gun: its hull box sits
	// `hullPosition` above it, so placing the origin at the muzzle lifts the
	// box over the shell.
	dummyPos := [3]float32{marker.Position[0] + dir[0]/l*12, hull.Position[1], marker.Position[2] + dir[2]/l*12}

	// The arena's vehicle list, so the kill has a `vehiclesInfo` to update.
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		t.Fatal("no VEHICLES_INFO alias")
	}
	vehicles := []entdef.Value{
		vehicleInfoValue(infoType, ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte(ebrCompDescr)}, vehicle.ID, 1, 0, 0),
		vehicleInfoValue(infoType, ArenaPlayerDoc{AccountID: 3, Name: "dummy", Team: 2, VehicleCompDescr: dummyCompDescr()}, dummy.ID, 1, 0, 0),
	}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		entityID: avatar.ID, avatar: avatar, vehicle: vehicle,
		targets: []*botTarget{{entity: dummy, id: dummy.ID, pos: dummyPos, health: 10, maxHealth: 10, infoIndex: 1}},
		gunSpec: spec, hull: hull, ammoList: ammo, loadedShell: shell, nextShell: shell,
		ownVehicle:   nrlComponent{TypeID: OwnVehicleNrlID, Node: 7, FirstChild: 8, Props: 23, Methods: 11},
		infoComp:     nrlComponent{TypeID: AvatarVehiclesInfoNrlID, Node: 40, FirstChild: 41, Props: 1},
		infoVehicles: vehicles, infoPlayer: 0,
		postSeq: 100, postCumul: 3, tick: 1000,
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerShoot(tr, addr, st); err != nil {
		t.Fatalf("answerShoot: %v", err)
	}
	if st.targets[0].health != 0 {
		t.Fatalf("dummy health = %d, want 0 (the shot must kill it)", st.targets[0].health)
	}
	if st.infoKills != 1 {
		t.Fatalf("kills = %d, want 1", st.infoKills)
	}
	if st.damageDealt == 0 {
		t.Fatal("damage total was not accumulated")
	}
	if len(tr.writes) < 2 {
		t.Fatalf("%d packets, want the damage and the kill", len(tr.writes))
	}
	for i, pkt := range tr.writes {
		app := findAppInPacket(t, pkt, st.blockKey)
		if app == nil {
			t.Fatalf("packet %d has no app", i)
		}
		if err := CheckClientApp(d, app); err != nil {
			t.Fatalf("packet %d: the client would drop this bundle: %v (app % x)", i, err, app)
		}
	}
}

// dummyCompDescr is the TOG II's full descriptor, the dummy's vehicle.
func dummyCompDescr() []byte {
	return []byte{0x51, 0xd2, 0x3f, 0x00, 0x36, 0x00, 0xcd, 0x00, 0x02, 0x00, 0x3c, 0x00, 0x24, 0x00, 0x00}
}

// TestNrlNestedPathBits pins the compressed path of a nested `vehiclesInfo`
// update: `[1][prop][1][elem][0][field]`, each index as many bits as its
// container needs, MSB-first, then the value.
//
// The client decodes exactly this (`encode_compressed_path`'s inverse in
// `setNested_vehiclesInfo`), and a wrong bit count silently addresses the
// wrong field — the kill would land on some other attribute.
func TestNrlNestedPathBits(t *testing.T) {
	// Loads the defs and with them the alias table.
	tokenTestServer(t, nil)
	comp := nrlComponent{TypeID: AvatarVehiclesInfoNrlID, Node: 40, FirstChild: 41, Props: 1}
	// vehiclesInfo[1]['isAlive']: one component property (0 index bits), two
	// vehicles (1 bit), the FIXED_DICT's `isAlive` field.
	infoType := entdef.Alias("VEHICLES_INFO")
	if infoType == nil {
		t.Skip("no VEHICLES_INFO alias")
	}
	fields := entdef.FixedDictFields(infoType)
	isAlive := -1
	for i := range fields {
		if fields[i].Name == "isAlive" {
			isAlive = i
		}
	}
	if isAlive < 0 {
		t.Fatal("VEHICLES_INFO has no isAlive")
	}
	el, err := EncodeNrlNestedField(comp, 0, comp.Props, 1, 2, isAlive, len(fields), []byte{0})
	if err != nil {
		t.Fatalf("EncodeNrlNestedField: %v", err)
	}
	// [0x26][u16 len][node u16 BE][kind 1][len u24][path][value]
	if el[0] != elNrlData {
		t.Fatalf("element id = %#02x, want %#02x", el[0], elNrlData)
	}
	// The record addresses the PROPERTY child node, not the component node.
	if got := binary.BigEndian.Uint16(el[3:5]); got != comp.FirstChild {
		t.Fatalf("node = %d, want the property node %d", got, comp.FirstChild)
	}
	// Kind 2 is the nested change; 1 is a slice change, which the client
	// dispatches to setSlice_vehiclesInfo and which raises there.
	if el[5] != 2 {
		t.Fatalf("record kind = %d, want 2 (nested)", el[5])
	}
	// The record length is the NRL packed-u24: one byte below 255, else 0xFF
	// plus three little-endian bytes.
	off := 6
	n := int(el[off])
	off++
	if n == 0xFF {
		n = int(el[off]) | int(el[off+1])<<8 | int(el[off+2])<<16
		off += 3
	}
	path := el[off : off+n]
	// Bits: 1 (descend) | 1 (descend) | elem index 1 bit (1) | 0 (leaf) | field bits.
	var bits []int
	for _, b := range path[:len(path)-1] {
		for k := 7; k >= 0; k-- {
			bits = append(bits, int(b>>uint(k))&1)
		}
	}
	// The last path byte holds the field index; the value is the byte after.
	want := []int{1, 1, 1, 0}
	if len(bits) < len(want) {
		t.Fatalf("path too short: %v", bits)
	}
	for i := range want {
		if bits[i] != want[i] {
			t.Fatalf("path bits = %v, want prefix %v", bits, want)
		}
	}
	// The field index is the remaining bits of the path.
	fieldBits := bitsRequired(len(fields))
	got := 0
	for i := 0; i < fieldBits; i++ {
		got = got<<1 | bits[len(want)+i]
	}
	if got != isAlive {
		t.Fatalf("field index = %d, want %d", got, isAlive)
	}
	if path[len(path)-1] != 0 {
		t.Fatalf("value byte = %#02x, want 0 (isAlive false)", path[len(path)-1])
	}
}

// TestStickerDecodesWhereTheShellHit decodes the shell-hole segment exactly as
// the client's `DamageFromShotDecoder.decodeSegment` does and checks it runs
// through the hit point in the hull part's frame.
//
// This is the regression test for shell holes landing off the aim point: the
// segment's fractions are quantized over the hull's OWN collision bounds
// (`Hull.havok`'s `HKBodyFlagsData`) in the HULL PART's frame, and the client
// maps them back through the same box. Encoding over a centred guess put every
// hole a few tenths of a metre off, and over the wrong frame worse.
func TestStickerDecodesWhereTheShellHit(t *testing.T) {
	box := dummyBox([3]float32{0, 0, 0}, 0)
	sh := shellSpec{Name: "test", Damage: 300, Pen: 400, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	// From 20 m in front, aimed at the upper front plate.
	res := resolveShot(sh, [3]float32{0, 1.6, 20}, [3]float32{0, 0, -1}, []hitBox{box})
	if !res.Hit {
		t.Fatal("shot missed the dummy")
	}
	seg := encodeHitSegment(dummyBounds(), res.Local, res.LocalDir, 1, res.Effect)
	// The client's decode.
	min, max := dummyBounds()[0], dummyBounds()[1]
	delta := [3]float32{(max[0] - min[0]) / 255, (max[1] - min[1]) / 255, (max[2] - min[2]) / 255}
	start := [3]float32{
		min[0] + delta[0]*float32(seg>>16&255),
		min[1] + delta[1]*float32(seg>>24&255),
		min[2] + delta[2]*float32(seg>>32&255),
	}
	end := [3]float32{
		min[0] + delta[0]*float32(seg>>40&255),
		min[1] + delta[1]*float32(seg>>48&255),
		min[2] + delta[2]*float32(seg>>56&255),
	}
	// The hit point must lie on the decoded segment, within the quantization
	// step (one 8-bit cell of the box).
	segDir := [3]float32{end[0] - start[0], end[1] - start[1], end[2] - start[2]}
	segLen2 := segDir[0]*segDir[0] + segDir[1]*segDir[1] + segDir[2]*segDir[2]
	if segLen2 == 0 {
		t.Fatal("decoded segment has no length")
	}
	toPoint := [3]float32{res.Local[0] - start[0], res.Local[1] - start[1], res.Local[2] - start[2]}
	u := (toPoint[0]*segDir[0] + toPoint[1]*segDir[1] + toPoint[2]*segDir[2]) / segLen2
	closest := [3]float32{start[0] + segDir[0]*u, start[1] + segDir[1]*u, start[2] + segDir[2]*u}
	dist := math.Sqrt(float64(
		(closest[0]-res.Local[0])*(closest[0]-res.Local[0]) +
			(closest[1]-res.Local[1])*(closest[1]-res.Local[1]) +
			(closest[2]-res.Local[2])*(closest[2]-res.Local[2])))
	step := math.Sqrt(float64(delta[0]*delta[0] + delta[1]*delta[1] + delta[2]*delta[2]))
	if dist > step {
		t.Fatalf("decoded segment is %.3f m from the hit point (step %.3f)", dist, step)
	}
}

// TestResolveShotHitsTheTurret fires at the TOG II's turret, above the hull's
// 2.088 m top: the hull box cannot be hit there, so before the turret was a
// part of its own the shell passed over the tank and did nothing at all.
//
// The turret's box is `Turret_01.havok`'s, its origin at the chassis's
// `<turretPositions><turret>` — which is relative to the HULL, so the turret
// sits at 2.059 m and rises to 3.058 m.
func TestResolveShotHitsTheTurret(t *testing.T) {
	sh := shellSpec{Name: "test", Damage: 300, Pen: 400, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	boxes := dummyBoxes([3]float32{0, 0, 0}, 0)
	// The hull's own top, from its box; aim above the barrel, which covers
	// the turret's middle band.
	hullTop := dummyParts[0].Offset[1] + dummyParts[0].Bounds[1][1]
	res := resolveShot(sh, [3]float32{0, hullTop + 0.8, 20}, [3]float32{0, 0, -1}, boxes)
	if !res.Hit {
		t.Fatal("the shell passed over the tank: the turret is not a hit part")
	}
	if res.Part != 2 {
		t.Fatalf("part = %d, want 2 (TURRET)", res.Part)
	}
	if res.Bounds != dummyParts[1].Bounds {
		t.Fatalf("segment bounds = %v, want the turret's %v", res.Bounds, dummyParts[1].Bounds)
	}
	// The turret's front is armor_1, 114.3 mm, and the shot is square on.
	if math.Abs(float64(res.Armor-114.3)) > 0.01 {
		t.Fatalf("armour = %v, want 114.3 (the turret's front)", res.Armor)
	}
	if !res.Pierced || res.Damage <= 0 {
		t.Fatalf("pierced=%v damage=%d, want a penetrating hit", res.Pierced, res.Damage)
	}
	// The hull is still hit below its top, and reports the hull.
	res = resolveShot(sh, [3]float32{0, hullTop - 0.4, 20}, [3]float32{0, 0, -1}, boxes)
	if !res.Hit || res.Part != 1 {
		t.Fatalf("hull shot: hit=%v part=%d, want the hull (1)", res.Hit, res.Part)
	}
}

// TestFiringPromotesTheNextShell pins the shell the gun reloads after a shot.
//
// Load A, select B as the next shell, fire: the official server reloads B, not
// A. The client does not do it itself — its `AmmoController.setCurrentShellCD`
// is driven by the `vehicleSettings` property — so firing has to promote the
// next shell and re-send the settings.
func TestFiringPromotesTheNextShell(t *testing.T) {
	d := testDispatch(t)
	s := &BaseAppServer{
		cfg:        BaseAppConfig{Dispatch: d},
		resend:     newResendQueue(400*time.Millisecond, 20*time.Second),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	ammoType := entdef.Alias("VEHICLE_AMMO")
	if ammoType == nil {
		t.Skip("no VEHICLE_AMMO alias")
	}
	shell := func(cd, qty int64) entdef.Value {
		v := entdef.ZeroValue(ammoType)
		v = dictSet(v, "compactDescr", entdef.Value{Kind: entdef.VInt, Int: cd})
		v = dictSet(v, "quantity", entdef.Value{Kind: entdef.VUint, Uint: uint64(qty)})
		v = dictSet(v, "quantityInClip", entdef.Value{Kind: entdef.VUint, Uint: 1})
		return v
	}
	st := &clientState{
		blockKey:    "0123456789abcdef",
		resendKey:   "test",
		vehicle:     NewEntity(7, d.Entity("Vehicle")),
		ownVehicle:  nrlComponent{TypeID: 53, Node: 7, FirstChild: 8, Props: 23, Methods: 11},
		gunSpec:     gunSpec{Dispersion: dispersionSpec{ReloadTime: 10, ShellCD: 100}},
		ammoList:    entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{shell(100, 5), shell(200, 5)}},
		loadedShell: 100,
		nextShell:   200,
		tick:        100,
		arena:       &ArenaHandoff{ArenaID: 1},
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	tr := &fakeTransport{}
	if err := s.answerShoot(tr, addr, st); err != nil {
		t.Fatalf("answerShoot: %v", err)
	}
	if st.loadedShell != 200 || st.nextShell != 200 {
		t.Fatalf("loaded/next = %d/%d, want 200/200 (the selected shell is promoted)", st.loadedShell, st.nextShell)
	}
	// The fired shell is the one that went down, not the promoted one.
	for _, want := range []struct{ cd, qty int64 }{{100, 4}, {200, 5}} {
		for _, v := range st.ammoList.Seq {
			cd, _ := v.Get("compactDescr")
			q, _ := v.Get("quantity")
			if cd.Int == want.cd && int64(q.Uint) != want.qty {
				t.Fatalf("shell %d quantity = %d, want %d", want.cd, q.Uint, want.qty)
			}
		}
	}
	// One of the packets is the new `vehicleSettings` with CURRENT_SHELLS=200.
	dt := entdef.Alias("VEHICLE_SETTINGS")
	found := false
	for _, pkt := range tr.writes {
		app := findAppInPacket(t, pkt, st.blockKey)
		if len(app) < 9 || app[0] != elNrlData {
			continue
		}
		off := 3 + 2 + 1 // element header, node, kind
		n := int(app[off])
		off++
		if n == 0xFF {
			n = int(app[off]) | int(app[off+1])<<8 | int(app[off+2])<<16
			off += 3
		}
		val, err := entdef.NewCodec().Read(bytes.NewReader(app[off:off+n]), dt)
		if err != nil || val.Kind != entdef.VSeq || len(val.Seq) != 2 {
			continue
		}
		cur, _ := val.Seq[0].Get("value")
		nxt, _ := val.Seq[1].Get("value")
		if cur.Int == 200 && nxt.Int == 200 {
			found = true
		}
	}
	if !found {
		t.Fatal("no vehicleSettings with CURRENT_SHELLS=200 was sent")
	}
}

// TestResolveShotHitsTheGun pins the barrel as a DEVICE part.
//
// The gun is a real hit part in the client (`TankPartIndexes.GUN`, its own
// `Gun_01.havok` box and its own 25.4 mm in the item defs), and a shell that
// gets through it damages the gun module and does NO hull damage — the hull's
// health must not move, and the client's `VEHICLE_HIT_EFFECT`
// `ARMOR_PIERced_DEVICE_DAMAGED` (6) is what its feedback turns into a
// critical hit.
func TestResolveShotHitsTheGun(t *testing.T) {
	sh := shellSpec{Name: "test", Damage: 300, Pen: 400, Kind: "ARMOR_PIERCING", KindIndex: 2, Caliber: 76.2, Speed: 800}
	boxes := dummyBoxes([3]float32{0, 0, 0}, 0)
	gun := dummyParts[2]
	// Square on the barrel, at its own height.
	y := gun.Offset[1] + (gun.Bounds[0][1]+gun.Bounds[1][1])/2
	res := resolveShot(sh, [3]float32{0, y, 20}, [3]float32{0, 0, -1}, boxes)
	if !res.Hit {
		t.Fatal("the shell passed through the barrel")
	}
	if res.Part != 3 {
		t.Fatalf("part = %d, want 3 (GUN)", res.Part)
	}
	if res.Damage != 0 {
		t.Fatalf("damage = %d, want 0 (a device hit does no hull damage)", res.Damage)
	}
	if res.Effect != hitEffectDeviceDamaged {
		t.Fatalf("effect = %d, want %d (device damaged)", res.Effect, hitEffectDeviceDamaged)
	}
	if res.Flags&0x100 == 0 {
		t.Fatalf("flags = %#x, want DEVICE_PIERCED_BY_PROJECTILE (0x100)", res.Flags)
	}
}

// TestShotsHitWhicheverBotIsInThePath pins the multi-target trace: every
// synthetic tank is a target, so a shell resolves against the one in its path
// and the others keep their health and their shell holes.
func TestShotsHitWhicheverBotIsInThePath(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	vehType := d.Entity("Vehicle")
	avatarType := d.Entity("Avatar")
	if vehType == nil || avatarType == nil {
		t.Fatal("defs have no Vehicle/Avatar")
	}
	const ebrCompDescr = "\x41\x4a\x9d\x00\x65\x00\xcd\x00\x22\x00\x82\x00\x63\x00\x00"
	spec, ok := vehicleGunSpeeds([]byte(ebrCompDescr))
	if !ok {
		t.Fatal("no gun spec for the EBR 105")
	}
	vehicle := NewEntity(100003, vehType)
	avatar := NewEntity(100001, avatarType)
	near := NewEntity(100004, vehType)
	far := NewEntity(100005, vehType)
	for _, e := range []*Entity{vehicle, near, far} {
		for _, p := range vehType.CellProps {
			e.Set(p.Name, entdef.ZeroValue(p.Type))
		}
	}
	for _, p := range avatarType.CellProps {
		avatar.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	shell := spec.Dispersion.ShellCD
	ammo := entdef.Value{Kind: entdef.VSeq, Seq: []entdef.Value{{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "compactDescr", Value: entdef.Value{Kind: entdef.VInt, Int: int64(shell)}},
		{Name: "quantity", Value: entdef.Value{Kind: entdef.VUint, Uint: 30}},
		{Name: "quantityInClip", Value: entdef.Value{Kind: entdef.VUint, Uint: 1}},
	}}}}
	hull := hull{Position: [3]float32{0, 0, 0}, Direction: [3]float32{0, 0, 0}, Limits: spec.Limits}
	marker := gunMarkerFor(hull, 0, 0, spec, 1)
	dir := [3]float32{marker.Velocity[0], marker.Velocity[1], marker.Velocity[2]}
	l := float32(math.Sqrt(float64(dir[0]*dir[0] + dir[1]*dir[1] + dir[2]*dir[2])))
	// The far tank sits BEHIND the near one: the shell must stop at the near.
	at := func(m float32) [3]float32 {
		return [3]float32{marker.Position[0] + dir[0]/l*m, hull.Position[1], marker.Position[2] + dir[2]/l*m}
	}
	st := &clientState{
		accountID: 2, name: "admin", blockKey: "0123456789abcdef",
		entityID: avatar.ID, avatar: avatar, vehicle: vehicle,
		targets: []*botTarget{
			{entity: near, id: near.ID, pos: at(12), health: 1000, maxHealth: 1000, infoIndex: 1},
			{entity: far, id: far.ID, pos: at(30), health: 1000, maxHealth: 1000, infoIndex: 2},
		},
		gunSpec: spec, hull: hull, ammoList: ammo, loadedShell: shell, nextShell: shell,
		ownVehicle: nrlComponent{TypeID: OwnVehicleNrlID, Node: 7, FirstChild: 8, Props: 23, Methods: 11},
		postSeq:    100, postCumul: 3, tick: 1000,
	}
	tr := &fakeTransport{}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	if err := s.answerShoot(tr, addr, st); err != nil {
		t.Fatalf("answerShoot: %v", err)
	}
	if st.targets[0].health >= 1000 {
		t.Fatalf("the near tank took no damage (health %d)", st.targets[0].health)
	}
	if st.targets[1].health != 1000 {
		t.Fatalf("the far tank took damage through the near one (health %d)", st.targets[1].health)
	}
	// And the module state is per target: the near tank took a module hit, the
	// far one's state was never even created.
	damaged := false
	for i := range st.targets[0].modules {
		if st.targets[0].modules[i].HP < dummyModules[i].MaxHP {
			damaged = true
			break
		}
	}
	if !damaged {
		t.Fatal("the near tank took no module damage")
	}
	if st.targets[1].modules != nil {
		t.Fatal("the far tank's module state was touched")
	}
}
