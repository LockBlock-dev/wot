package login

import (
	"math"
	"testing"
)

// TestPitchCurveInterpolates pins the gun's per-yaw pitch limits: the defs
// write `position angle` pairs, the position a fraction of a turn, and the
// limit at a yaw is interpolated between the points around it.
func TestPitchCurveInterpolates(t *testing.T) {
	// The TOG II's own maxPitch.
	c, ok := parsePitchCurve("0 10 0.366894 10 0.430556 5 0.569444 5 0.633106 10 1 10")
	if !ok {
		t.Fatal("the curve did not parse")
	}
	deg := func(yaw float32) float64 {
		return float64(c.at(yaw)) * 180 / math.Pi
	}
	if got := deg(0); math.Abs(got-10) > 1e-3 {
		t.Fatalf("at yaw 0 = %v deg, want 10", got)
	}
	// The dip: 5 degrees between the two middle points.
	if got := deg(float32(0.5 * 2 * math.Pi)); math.Abs(got-5) > 1e-3 {
		t.Fatalf("at half a turn = %v deg, want 5 (the dip)", got)
	}
	// Interpolated inside the ramp.
	mid := float32((0.366894 + 0.430556) / 2 * 2 * math.Pi)
	if got := deg(mid); math.Abs(got-7.5) > 0.05 {
		t.Fatalf("mid-ramp = %v deg, want ~7.5", got)
	}
	if lo, hi := c.lowest(), c.highest(); math.Abs(float64(lo-hi)) < 1e-6 {
		t.Fatalf("lowest %v highest %v, want a dip", lo, hi)
	}
}

// TestPitchCurveFlat pins a flat curve: the TOG's minPitch is -20 all round.
func TestPitchCurveFlat(t *testing.T) {
	c, ok := parsePitchCurve("0 -20 1 -20")
	if !ok {
		t.Fatal("the curve did not parse")
	}
	for _, yaw := range []float32{0, 1, 2, -1, 3} {
		if got := float64(c.at(yaw)) * 180 / math.Pi; math.Abs(got+20) > 1e-6 {
			t.Fatalf("at %v = %v deg, want -20", yaw, got)
		}
	}
}
