package lobby

// Offline battle parser tests (synthetic fixtures only).
import (
	"encoding/binary"
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
