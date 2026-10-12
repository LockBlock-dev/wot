package lobby

// Offline battle parser tests (synthetic fixtures only).
import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

func TestParseAvatarUpdate(t *testing.T) {
	mk := func() []byte {
		app := make([]byte, BattlePosLen)
		app[0], app[1], app[2], app[3] = 0x02, 0x8b, 0x58, 0x4a
		app[4], app[5] = 0x93, 0x1a
		binary.LittleEndian.PutUint32(app[20:], math.Float32bits(373.3))
		binary.LittleEndian.PutUint32(app[24:], math.Float32bits(24.5))
		binary.LittleEndian.PutUint32(app[28:], math.Float32bits(252.3))
		return app
	}
	u, ok := ParseAvatarUpdate(mk())
	if !ok {
		t.Fatal("valid shape rejected")
	}
	if u.X < 373 || u.X > 374 || u.Y < 24 || u.Y > 25 || u.Z < 252 || u.Z > 253 {
		t.Fatalf("xyz=%v", u)
	}
	bad := mk()
	bad[0] = 0x00
	if _, ok := ParseAvatarUpdate(bad); ok {
		t.Fatal("bad head accepted")
	}
	short := mk()[:20]
	if _, ok := ParseAvatarUpdate(short); ok {
		t.Fatal("short accepted")
	}
	other := mk()
	other[5] = 0x07
	if _, ok := ParseAvatarUpdate(other); ok {
		t.Fatal("other subtype accepted")
	}
}

func TestParseMoveWith(t *testing.T) {
	mk := func() []byte {
		app := make([]byte, BattlePosLen)
		app[0], app[1], app[2], app[3] = 0x02, 0x8b, 0x58, 0x4a
		app[4], app[5] = BattleFamily, BattleSubMoveWith
		app[6], app[7] = 0x1a, 0x00
		binary.LittleEndian.PutUint32(app[8:], 0x20529314)
		binary.LittleEndian.PutUint32(app[12:], 0x3db2f5c8)
		binary.LittleEndian.PutUint32(app[16:], math.Float32bits(7.14))
		binary.LittleEndian.PutUint32(app[20:], math.Float32bits(373.3))
		binary.LittleEndian.PutUint32(app[24:], math.Float32bits(24.5))
		binary.LittleEndian.PutUint32(app[28:], math.Float32bits(252.3))
		app[32], app[33] = 0x19, 0x00
		return app
	}
	m, ok := ParseMoveWith(mk())
	if !ok {
		t.Fatal("valid shape rejected")
	}
	if m.Entity != 0x20529314 || m.Nonce != 0x3db2f5c8 {
		t.Fatalf("entity/nonce=%x/%x", m.Entity, m.Nonce)
	}
	if m.Speed < 7.13 || m.Speed > 7.15 {
		t.Fatalf("speed=%v", m.Speed)
	}
	if m.X < 373 || m.X > 374 || m.Tail != [2]byte{0x19, 0x00} {
		t.Fatalf("xyz/tail=%v/%x", m.AvatarUpdate, m.Tail)
	}
	bad := mk()
	bad[4] = 0x95
	if _, ok := ParseMoveWith(bad); ok {
		t.Fatal("bad family accepted")
	}
	bad = mk()
	bad[5] = 0x07
	if _, ok := ParseMoveWith(bad); ok {
		t.Fatal("other sub accepted")
	}
	if _, ok := ParseMoveWith(mk()[:20]); ok {
		t.Fatal("short accepted")
	}
}

func TestParseTrailer(t *testing.T) {
	// synthetic 0x07/44-shaped bundle: 5B head + 10B record + 29B trailer
	app := []byte{0x02, 0x8b, 0x58, 0x4a, 0x93,
		0x07, 0x07, 0x00, 0x06, 0x00, 0x01, 0x20, 0x77, 0x06, 0x00,
		0x1a, 0x1a, 0x00, 0x14, 0x93, 0x52, 0x20}
	payload := make([]byte, 20)
	binary.LittleEndian.PutUint32(payload[0:], 0x44332211)
	binary.LittleEndian.PutUint32(payload[4:], math.Float32bits(7.15))
	binary.LittleEndian.PutUint32(payload[8:], math.Float32bits(373.3))
	binary.LittleEndian.PutUint32(payload[12:], math.Float32bits(24.5))
	binary.LittleEndian.PutUint32(payload[16:], math.Float32bits(252.3))
	app = append(app, payload...)
	app = append(app, 0x19, 0x00)
	if len(app) != 44 {
		t.Fatalf("fixture len=%d", len(app))
	}
	tr, ok := ParseTrailer(app)
	if !ok {
		t.Fatal("valid trailer rejected")
	}
	if tr.Entity != 0x20529314 || tr.Nonce != 0x44332211 {
		t.Fatalf("entity/nonce=%x/%x", tr.Entity, tr.Nonce)
	}
	if tr.Speed < 7.14 || tr.Speed > 7.16 || tr.X < 373 || tr.X > 374 || tr.Tail != [2]byte{0x19, 0x00} {
		t.Fatalf("payload=%+v", tr)
	}
	if _, ok := ParseTrailer(make([]byte, 15)); ok {
		t.Fatal("short accepted")
	}
	bare := []byte{0x02, 0x8b, 0x58, 0x4a, 0x93, 0x07,
		0x07, 0x00, 0x06, 0x00, 0x01, 0x18, 0x85, 0x06, 0x00}
	if _, ok := ParseTrailer(bare); ok {
		t.Fatal("bare call accepted")
	}
}

func TestBuildShootTrigger(t *testing.T) {
	app := BuildShootTrigger(0x20529314, 0x6d9bcd97, 7.15, 275.0, 23.0, -2.0, [2]byte{0x08, 0x03})
	if len(app) != 41 {
		t.Fatalf("len=%d, want 41", len(app))
	}
	if app[0] != 0x02 || app[1] != 0x8b || app[2] != 0x58 || app[3] != 0x4a {
		t.Fatal("bad head")
	}
	if app[4] != BattleFamily || app[5] != BattleSubShoot {
		t.Fatalf("family/sub=%02x/%02x", app[4], app[5])
	}
	if app[6] != 0x04 || app[7] != 0x00 {
		t.Fatalf("len=%02x%02x, want 0400", app[6], app[7])
	}
	for i := 8; i < 12; i++ {
		if app[i] != 0x00 {
			t.Fatalf("arg byte %d = %02x, want 00", i, app[i])
		}
	}
	tr, ok := ParseTrailer(app)
	if !ok {
		t.Fatal("built bundle has no parseable trailer")
	}
	if tr.Entity != 0x20529314 || tr.Tail != [2]byte{0x08, 0x03} {
		t.Fatalf("trailer=%+v", tr)
	}
	if !FindShootTrigger(app) {
		t.Fatal("standalone trigger not recognized")
	}
}

func TestFindShootTriggerChained(t *testing.T) {
	// s1-shaped 07-led bundle: outer07 (7B) + inner 0x10 + trailer.
	var b []byte
	b = append(b, 0x02, 0x8b, 0x58, 0x4a, BattleFamily, 0x07, 0x07, 0x00)
	b = append(b, 0x06, 0x00, 0x01, 0xa5, 0x78, 0x06, 0x00)
	b = append(b, BattleSubShoot, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)
	for i := 0; i < 29; i++ {
		b = append(b, 0x00)
	}
	copy(b[len(b)-29:], []byte{0x1a, 0x1a, 0x00})
	if !FindShootTrigger(b) {
		t.Fatal("chained inner trigger not recognized")
	}
	// moveWith 34B carries no trigger.
	mv := BuildShootTrigger(1, 2, 7.0, 1.0, 2.0, 3.0, [2]byte{0x19, 0x00})
	mv[5] = BattleSubMoveWith
	if FindShootTrigger(mv) {
		t.Fatal("false positive on moveWith-shaped bundle")
	}
	// bare 07/44 without inner 0x10.
	plain := []byte{0x02, 0x8b, 0x58, 0x4a, BattleFamily, 0x07, 0x07, 0x00,
		0x06, 0x00, 0x01, 0xa5, 0x78, 0x06, 0x00}
	if FindShootTrigger(plain) {
		t.Fatal("false positive on trigger-less 07 bundle")
	}
}

func TestScanBattleTracers(t *testing.T) {
	mk := func(a0, shot uint32, rng float32, tail [2]byte) []byte {
		app := make([]byte, 60)
		binary.LittleEndian.PutUint32(app[0:], a0)
		binary.LittleEndian.PutUint32(app[4:], shot)
		copy(app[8:12], []byte{0x00, 0x10, 0x02, 0x02})
		binary.LittleEndian.PutUint32(app[12:], math.Float32bits(rng))
		binary.LittleEndian.PutUint32(app[16:], math.Float32bits(275.0))
		binary.LittleEndian.PutUint32(app[20:], math.Float32bits(23.0))
		binary.LittleEndian.PutUint32(app[24:], math.Float32bits(-2.0))
		binary.LittleEndian.PutUint32(app[28:], math.Float32bits(-507.0))
		binary.LittleEndian.PutUint32(app[32:], math.Float32bits(-24.0))
		binary.LittleEndian.PutUint32(app[36:], math.Float32bits(320.0))
		binary.LittleEndian.PutUint32(app[40:], math.Float32bits(6.28))
		binary.LittleEndian.PutUint32(app[44:], math.Float32bits(720.0))
		app[48], app[49] = tail[0], tail[1]
		return app
	}
	hits := ScanBattleTracers(mk(542282516, 27271648, 152.0, [2]byte{0, 0}))
	if len(hits) != 1 {
		t.Fatalf("hits=%d, want 1", len(hits))
	}
	h := hits[0]
	if h.A0 != 542282516 || h.Shot != 27271648 || h.Range != 152.0 {
		t.Fatalf("hit=%+v", h)
	}
	if h.Kind != ShellAP || ShellKindName(h.Kind) != "AP" {
		t.Fatalf("kind=%d (%s), want AP", h.Kind, ShellKindName(h.Kind))
	}
	if h.Start != [3]float64{275.0, 23.0, -2.0} {
		t.Fatalf("start=%v", h.Start)
	}
	if len(ScanBattleTracers(mk(1, 2, 999.0, [2]byte{0, 0}))) != 0 {
		t.Fatal("bad Range accepted")
	}
	if len(ScanBattleTracers(mk(1, 2, 152.0, [2]byte{0, 1}))) != 0 {
		t.Fatal("non-0000 tail accepted")
	}
	if len(ScanBattleTracers(mk(1, 2, 152.0, [2]byte{0, 0})[:40])) != 0 {
		t.Fatal("short app accepted")
	}
	offmap := mk(1, 2, 152.0, [2]byte{0, 0})
	binary.LittleEndian.PutUint32(offmap[16:], math.Float32bits(9999.0))
	if len(ScanBattleTracers(offmap)) != 0 {
		t.Fatal("out-of-map start accepted")
	}
}

func TestParseBattleRoster(t *testing.T) {
	var bulk []byte
	block := func(ent uint32, name, clan string) {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], ent)
		bulk = append(bulk, tmp[:]...)
		bulk = append(bulk, 0x01, 0x04, 0x04, 0x10, 0x81, 0x01, 0x0f, 0x01)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		if clan != "" {
			bulk = append(bulk, byte(len(clan)))
			bulk = append(bulk, clan...)
		}
		bulk = append(bulk, []byte(fmt.Sprint(ent))...)
		bulk = append(bulk, 0x00, 0x00)
	}
	bulk = append(bulk, []byte("epic_config}q inBattleModifiers bw.default compositionRootSlot")...)
	block(542282516, "ExampleUser", "")
	block(542264099, "AlphaTank", "LBP")
	bulk = append(bulk, []byte("0a bw.default")...)
	got := ParseBattleRoster(bulk)
	if len(got) != 2 {
		t.Fatalf("map=%v, want 2 entries", got)
	}
	if got[542282516] != "ExampleUser" || got[542264099] != "AlphaTank" {
		t.Fatalf("map=%v", got)
	}
}

func TestScanBattleTracersGhost(t *testing.T) {
	// 1B-slide ghost shape (denormal dregs, reused shotID): rejected.
	app := make([]byte, 60)
	binary.LittleEndian.PutUint32(app[0:], 1778384964)
	binary.LittleEndian.PutUint32(app[4:], 27312608)
	copy(app[8:12], []byte{0x00, 0x10, 0x02, 0x02})
	binary.LittleEndian.PutUint32(app[12:], math.Float32bits(57.0))
	binary.LittleEndian.PutUint32(app[16:], math.Float32bits(-395.5))
	app[20], app[21], app[22], app[23] = 0x01, 0x00, 0x00, 0x00 // true denormal
	binary.LittleEndian.PutUint32(app[24:], 0)
	binary.LittleEndian.PutUint32(app[28:], 0)
	binary.LittleEndian.PutUint32(app[32:], 0)
	binary.LittleEndian.PutUint32(app[36:], 0)
	if len(ScanBattleTracers(app)) != 0 {
		t.Fatal("denormal ghost accepted")
	}
}

func TestParseBattleVehicles(t *testing.T) {
	var bulk []byte
	block := func(ent uint32, name string, tag byte, ref ...byte) {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], ent)
		bulk = append(bulk, tmp[:]...)
		bulk = append(bulk, 0x01, 0x04, 0x04, 0x10, 0x81, 0x01)
		bulk = append(bulk, tag)
		bulk = append(bulk, ref...)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, []byte(fmt.Sprint(ent))...)
		bulk = append(bulk, 0x00, 0x00)
	}
	// ussr/9 = SU-152 shape: IntCD u16le 0x0901 (type 1, nation 0, id 9)
	block(542282516, "ExampleUser", 0x0f, 0x01, 0x09)
	// germany/265 EXT shape: head 0x13 (type 1 + ext), id 265
	block(542264089, "BravoTank", 0x10, 0x13, 0x09, 0x01)
	got := ParseBattleVehicles(bulk)
	if len(got) != 2 {
		t.Fatalf("map=%v, want 2 entries", got)
	}
	if got[542282516] != (VehicleRef{0, 9}) {
		t.Fatalf("516=%+v, want {0 9}", got[542282516])
	}
	if got[542264089] != (VehicleRef{1, 265}) {
		t.Fatalf("089=%+v, want {1 265}", got[542264089])
	}
	// names still resolve on the same bulk (shared heads)
	names := ParseBattleRoster(bulk)
	if names[542282516] != "ExampleUser" || names[542264089] != "BravoTank" {
		t.Fatalf("names=%v", names)
	}
}

func TestParseBattleTeams(t *testing.T) {
	var bulk []byte
	block := func(ent uint32, name string, team byte) {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], ent)
		bulk = append(bulk, tmp[:]...)
		bulk = append(bulk, 0x01, 0x04, 0x04, 0x10, 0x81, 0x01)
		bulk = append(bulk, 0x0f, 0x01, 0x09)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, team, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44)
		bulk = append(bulk, []byte(fmt.Sprint(ent))...)
		bulk = append(bulk, 0x00, 0x00)
	}
	block(542282516, "ExampleUser", 0x02)
	block(542264099, "AlphaTank", 0x01)
	// bad team byte (0x07) must be skipped, never guessed
	block(542264100, "branislavtotka", 0x07)
	got := ParseBattleTeams(bulk)
	if len(got) != 2 {
		t.Fatalf("map=%v, want 2 entries", got)
	}
	if got[542282516] != 2 {
		t.Fatalf("own=%d, want 2", got[542282516])
	}
	if got[542264099] != 1 {
		t.Fatalf("099=%d, want 1", got[542264099])
	}
}

func TestParseBattleMounts(t *testing.T) {
	tab := &StaticTable{
		Vehicles: map[uint16]map[uint16]VehicleInfo{
			0: {9: {Name: "R18_SU-152", Turrets: 1}},
		},
		Comps: map[uint16]map[CompKind]map[uint16]string{
			0: {
				CompChassis:  {19: "Chassis_R18_SU-152_2"},
				CompEngine:   {270: "V_2IS_SU"},
				CompFuelTank: {204: "Heavy"},
				CompRadio:    {9: "_12RT"},
				CompTurret:   {16: "Turret_1_R18_SU-152"},
				CompGun:      {32: "_152mm_ML-20_mod_1937"},
			},
		},
	}
	var bulk []byte
	block := func(ent uint32, name string, gun uint16) {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], ent)
		bulk = append(bulk, tmp[:]...)
		bulk = append(bulk, 0x01, 0x04, 0x04, 0x10, 0x81, 0x01)
		bulk = append(bulk, 0x0f, 0x01, 0x09)
		for _, id := range []uint16{19, 270, 204, 9, 16, gun} {
			bulk = append(bulk, byte(id), byte(id>>8))
		}
		bulk = append(bulk, 0x00) // flags: stock, no optdev/camo
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, byte(len(name)))
		bulk = append(bulk, name...)
		bulk = append(bulk, 0x02, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44)
		bulk = append(bulk, []byte(fmt.Sprint(ent))...)
		bulk = append(bulk, 0x00, 0x00)
	}
	block(542282516, "ExampleUser", 32)
	block(542264099, "AlphaTank", 0x00) // unknown gun id: skipped
	got := ParseBattleMounts(bulk, tab)
	if len(got) != 1 {
		t.Fatalf("map=%v, want 1 entry", got)
	}
	m := got[542282516]
	if m.Turret != 16 || m.Gun != 32 || m.Chassis != 19 {
		t.Fatalf("516=%+v, want turret 16 gun 32 chassis 19", m)
	}
}

func TestScanBattleExplodes(t *testing.T) {
	// wire truth (Sweden s2/s5 own-shot explodes): impact V3 at
	// +16/+20/+24, small second triple at +28/+32/+36.
	mk := func(shot uint32, rng float32) []byte {
		app := []byte{0x1a, 0x91, 0x29, 0x00}
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], shot)
		app = append(app, tmp[:]...)
		app = append(app, 0, 0, 0, 0)
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(rng))
		app = append(app, tmp[:]...)
		for _, f := range []float32{100, 2, 250, -23, -1.5, 16} {
			binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
			app = append(app, tmp[:]...)
		}
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(1.5))
		app = append(app, tmp[:]...)
		if len(app) != ExplodeLen {
			t.Fatalf("vector len=%d, want %d", len(app), ExplodeLen)
		}
		return app
	}
	app := append(mk(27261408, 75), mk(999, 62)...)
	got := ScanBattleExplodes(app)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (62mm must reject)", len(got))
	}
	if got[0].Shot != 27261408 || got[0].Range != 75 {
		t.Fatalf("got %+v", got[0])
	}
	if math.Abs(got[0].Pos[0]-100) > 1e-6 || math.Abs(got[0].Pos[2]-250) > 1e-6 {
		t.Fatalf("pos=%v, want impact triple", got[0].Pos)
	}
	if math.Abs(got[0].End[0]+23) > 1e-6 || math.Abs(got[0].End[2]-16) > 1e-6 {
		t.Fatalf("end=%v, want second triple", got[0].End)
	}
}

func TestScanBattleExplodesTailed(t *testing.T) {
	app := []byte{0x1a, 0x91, 0x2d, 0x00}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 27742688)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 0)
	app = append(app, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(150))
	app = append(app, tmp[:]...)
	for _, f := range []float32{100, 2, 250, 0, 0, 0, 1.5, 7} {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		app = append(app, tmp[:]...)
	}
	if len(app) != ExplodeLenTailed {
		t.Fatalf("vector len=%d, want %d", len(app), ExplodeLenTailed)
	}
	got := ScanBattleExplodes(app)
	if len(got) != 1 || got[0].Shot != 27742688 || got[0].Range != 150 {
		t.Fatalf("got %+v", got)
	}
	if math.Abs(got[0].Pos[0]-100) > 1e-6 {
		t.Fatalf("pos=%v, want impact triple", got[0].Pos)
	}
}

func TestParseBattleDeaths(t *testing.T) {
	mk := func(ctr byte, v, k uint32) []byte {
		app := []byte{0x55, 0x0a}
		app = append(app, []byte("deathOrder")...)
		app = append(app, 0x71, 0x02, 0x4b, ctr, 0x73, 0x2e, 0x0b, 0xa8, 0x02, 0x10, 0xe4, 0x78, 0x01)
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], v)
		app = append(app, tmp[:]...)
		binary.LittleEndian.PutUint32(tmp[:], k)
		app = append(app, tmp[:]...)
		return append(app, 0, 0, 0, 0, 0)
	}
	app := append(mk(9, 542264097, 542282516), mk(24, 542282516, 542264105)...)
	got := ParseBattleDeaths(app)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Victim != 542264097 || got[0].Killer != 542282516 || got[0].Counter != 9 {
		t.Fatalf("first=%+v", got[0])
	}
	if got[1].Victim != 542282516 || got[1].Killer != 542264105 || got[1].Counter != 24 {
		t.Fatalf("second=%+v", got[1])
	}
	// broken framing must not parse
	bad := []byte{0x55, 0x0a, 'd', 'e', 'a', 't', 'h', 'O', 'r', 'd', 'e', 'r'}
	if len(ParseBattleDeaths(bad)) != 0 {
		t.Fatal("broken key parsed")
	}
}

func TestFlightTime(t *testing.T) {
	// flat gun: 846 m at 750 m/s, g 9.81 → ~1.15 s low arc
	eta, ok := FlightTime([3]float64{0, 0, 0}, [3]float64{846, 0, 0}, 750, 9.81)
	if !ok || eta < 1.0 || eta > 1.5 {
		t.Fatalf("flat eta=%v,%v", eta, ok)
	}
	// howitzer: 300 m at 420 m/s, g 140 → high arc, multi-second
	eta, ok = FlightTime([3]float64{0, 0, 0}, [3]float64{300, 0, 0}, 420, 140)
	if !ok || eta < 1.5 || eta > 8 {
		t.Fatalf("lobbed eta=%v,%v", eta, ok)
	}
	// out of range: 2000 m at 100 m/s flat (max ~1019 m) → no root
	if _, ok = FlightTime([3]float64{0, 0, 0}, [3]float64{2000, 0, 0}, 100, 9.81); ok {
		t.Fatal("out-of-range accepted")
	}
	// degenerate inputs refuse
	if _, ok = FlightTime([3]float64{0, 0, 0}, [3]float64{1, 0, 0}, 0, 9.81); ok {
		t.Fatal("zero velocity accepted")
	}
}

func TestMatchShell(t *testing.T) {
	g, ok := GunSpec(0, 9, "Turret_1_R18_SU-152", "_152mm_ML-20_mod_1937")
	if !ok {
		t.Fatal("no ML-20 spec")
	}
	s, ok := MatchShell(g, ShellHEAT)
	if !ok || s.Caliber != 152 {
		t.Fatalf("heat=%+v,%v", s, ok)
	}
	// unknown kind never matches
	if _, ok = MatchShell(g, 7); ok {
		t.Fatal("bad kind matched")
	}
	// portion-majority: BP_530 (0.8) beats BP540 (0.0)
	if s.Portion < 0.5 {
		t.Fatalf("portion=%v, want majority shell", s.Portion)
	}
}

func TestParseSnapshotRecord(t *testing.T) {
	// hand-built payload from the decompiled formulas: token 0xf4,
	// X = +66.0 prescale (sign 0, exp adecodes below), dir zeros.
	// X bits: sign 0, exp 0x9 (f32 exp 0x89 → 2^10=1024 ×1.m), mant 12b.
	// f32(0x44800000) = 1024.0 → prescale 1022.0. mant for 1.0 fraction 0.
	payload := []byte{0xf4,
		0x48, 0x00, 0x00, 0x48, 0x00, 0x00, // X=+1022,Z=+1022 prescale
		0x00, 0x00, 0x00, 0x00, // dir zeros
	}
	_ = payload
	// construct properly bit by bit instead (6B: X=sign0/exp9/mant0,
	// Z=sign0/exp9/mant0, Y=sign0/exp9/mant0-9b)
	var bits uint64
	put := func(v uint32, n int) {
		bits = (bits << uint(n)) | uint64(v)
	}
	put(0, 1)
	put(9, 4)
	put(0, 12) // X mantissa 0 → f32 0x44800000 = 1024 → 1022.0
	put(0, 1)
	put(9, 4)
	put(0, 12) // Z same
	put(0, 1)
	put(9, 4)
	put(0, 9) // Y same (9b mantissa)
	var pos [6]byte
	for i := 0; i < 6; i++ {
		pos[5-i] = byte(bits >> (8 * uint(i)))
	}
	app := append([]byte{0xf4}, pos[:]...)
	app = append(app, 0, 0, 0, 0)
	s, ok := ParseSnapshotRecord(app)
	if !ok {
		t.Fatal("parse failed")
	}
	if s.Token != 0xf4 {
		t.Fatalf("token=%02x", s.Token)
	}
	if math.Abs(s.PX-1022.0) > 1e-6 || math.Abs(s.PZ-1022.0) > 1e-6 || math.Abs(s.PY-1022.0) > 1e-6 {
		t.Fatalf("pos=%v %v %v", s.PX, s.PY, s.PZ)
	}
	if s.Yaw != 0 || s.Pitch != 0 || s.Roll != 0 {
		t.Fatalf("dir=%v %v %v", s.Yaw, s.Pitch, s.Roll)
	}
	// short payload refuses
	if _, ok := ParseSnapshotRecord([]byte{1, 2, 3}); ok {
		t.Fatal("short payload accepted")
	}
}

func TestScanBattleMarkers(t *testing.T) {
	var tmp [4]byte
	put32 := func(app []byte, v uint32) []byte {
		binary.LittleEndian.PutUint32(tmp[:], v)
		return append(app, tmp[:]...)
	}
	putF := func(app []byte, f float32) []byte {
		binary.LittleEndian.PutUint32(tmp[:], math.Float32bits(f))
		return append(app, tmp[:]...)
	}
	// pair: [1a][75][27][2a][000000][A][B][15x00]
	app := []byte{0x1a, 0x75, 27, 0x2a, 0, 0, 0}
	app = put32(app, 542264110)
	app = put32(app, 542264106)
	app = append(app, make([]byte, 15)...)
	// single: [1a][75][39][1d][000000][ctr][ent][12x00][00 0c][pos][00]
	app = append(app, 0x1a, 0x75, 39, 0x1d, 0, 0, 0)
	app = put32(app, 21)
	app = put32(app, 542282512)
	app = append(app, make([]byte, 12)...)
	app = append(app, 0x00, 0x0c)
	for _, f := range []float32{452, 41.6, -13.4} {
		app = putF(app, f)
	}
	app = append(app, 0x00)
	// chance 1a 75 with bad length + bad entity must not parse
	app = append(app, 0x1a, 0x75, 27, 0x2a, 0, 0, 0)
	app = put32(app, 7)
	app = put32(app, 9)
	app = append(app, make([]byte, 15)...)
	pairs, spots := ScanBattleMarkers(app)
	if len(pairs) != 1 || pairs[0].A != 542264110 || pairs[0].B != 542264106 {
		t.Fatalf("pairs=%v, want one (110,106)", pairs)
	}
	if len(spots) != 1 || spots[0].Ent != 542282512 || spots[0].Counter != 21 {
		t.Fatalf("spots=%v, want one ent 512 ctr 21", spots)
	}
	if math.Abs(spots[0].Pos[0]-452) > 1e-3 || math.Abs(spots[0].Pos[2]+13.4) > 1e-3 {
		t.Fatalf("pos=%v", spots[0].Pos)
	}
}
