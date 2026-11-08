package login

import (
	"encoding/binary"
	"math"
	"testing"
)

// TestParseAvatarUpdate pins the client's own position report: both the
// implicit (0x03, 17 B) and the explicit (0x04, 22 B) forms, with the packed
// direction.
func TestParseAvatarUpdate(t *testing.T) {
	const key2 = 0x11223344
	build := func(elem byte, body []byte) []byte {
		clear := make([]byte, 10+len(body))
		clear[2] = 0x02
		binary.LittleEndian.PutUint32(clear[3:7], key2)
		clear[7] = elem
		binary.LittleEndian.PutUint16(clear[8:10], uint16(len(body)))
		copy(clear[10:], body)
		return clear
	}
	putVec := func(b []byte, v [3]float32) {
		for i, f := range v {
			binary.LittleEndian.PutUint32(b[i*4:], math.Float32bits(f))
		}
	}
	// The implicit form: position, the packed yaw/pitch/roll, ref, unk.
	body := make([]byte, avatarUpdateImplicitLen)
	putVec(body, [3]float32{100, 20, -50})
	body[12] = byte(angleToI8(1.0))
	body[13] = byte(halfAngleToI8(0.2))
	body[14] = byte(angleToI8(-0.5))
	pos, yaw, pitch, roll, onGround, ok := parseAvatarUpdate(build(elAvatarUpdateImplicit, body), key2)
	if !ok {
		t.Fatal("the implicit report did not parse")
	}
	if math.Abs(float64(pos[0]-100)) > 1e-3 || math.Abs(float64(pos[2]+50)) > 1e-3 {
		t.Errorf("position = %v, want (100, 20, -50)", pos)
	}
	if math.Abs(float64(yaw-1.0)) > 0.03 || math.Abs(float64(pitch-0.2)) > 0.03 || math.Abs(float64(roll+0.5)) > 0.03 {
		t.Errorf("direction = %v/%v/%v, want 1.0/0.2/-0.5", yaw, pitch, roll)
	}
	if onGround {
		t.Error("the implicit form reported on-ground")
	}
	// The explicit form: the vehicle id first, then the same, with the
	// on-ground flag.
	body = make([]byte, avatarUpdateExplicitLen)
	binary.LittleEndian.PutUint32(body[0:4], 100004)
	putVec(body[4:], [3]float32{1, 2, 3})
	body[19] = 0x1
	pos, _, _, _, onGround, ok = parseAvatarUpdate(build(elAvatarUpdateExplicit, body), key2)
	if !ok || !onGround {
		t.Fatalf("the explicit report = %v/%v, want ok and on-ground", ok, onGround)
	}
	if pos != [3]float32{1, 2, 3} {
		t.Errorf("position = %v, want (1, 2, 3)", pos)
	}
	// A wrong key is not a report.
	if _, _, _, _, _, ok := parseAvatarUpdate(build(elAvatarUpdateImplicit, body), key2^1); ok {
		t.Error("a wrong key parsed")
	}
}
