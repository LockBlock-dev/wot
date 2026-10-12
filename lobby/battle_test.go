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
	if m.Entity != 0x20529314 || m.F1 != 0x3db2f5c8 {
		t.Fatalf("entity/f1=%x/%x", m.Entity, m.F1)
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
