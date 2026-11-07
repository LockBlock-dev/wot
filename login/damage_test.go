package login

import (
	"bytes"
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
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
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
	// normal points at the shooter.
	if math.Abs(float64(res.Point[2]-5)) > 0.01 {
		t.Fatalf("hit z = %v, want 5 (the front face)", res.Point[2])
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
	res := resolveShot(sh, [3]float32{0, 2, -20}, [3]float32{0, 0, 1}, box)
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
	if res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{1, 0, 0}, box); res.Hit {
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
	res := resolveShot(sh, [3]float32{-15, 2, 20}, dir, box)
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
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
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
	res := resolveShot(sh, [3]float32{0, 2, 20}, [3]float32{0, 0, -1}, box)
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
	// A point on the front face, travelling -Z.
	seg := encodeHitSegment(bounds, [3]float32{0, 0, 5}, [3]float32{0, 0, -1}, 1, hitEffectPierced)
	if got := uint8(seg); got != hitEffectPierced {
		t.Fatalf("context = %d, want %d", got, hitEffectPierced)
	}
	if got := uint8(seg >> 8); got != 1 {
		t.Fatalf("part = %d, want 1 (hull)", got)
	}
	// The segment enters at the front (z = 5 → 255) and leaves at the rear
	// (z = -5 → 0); x and y are the box's middle (about 128).
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
	if el[0] <= entityPropertyBase {
		t.Fatalf("damageStickers id = %#x, want above the property base %#x", el[0], entityPropertyBase)
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
		infoDummy:    1,
		infoPlayer:   0,
	}
	s := &BaseAppServer{}
	el := s.killVehiclesInfo(st, 101, 100)
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
	s.killVehiclesInfo(st, 101, 100)
	if st.infoKills != 2 {
		t.Fatalf("kills = %d, want 2", st.infoKills)
	}
}
