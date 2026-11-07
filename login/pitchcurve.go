package login

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/LockBlock-dev/wot/entdef"
)

// A gun's pitch limits are curves, not a range: the elevation and depression
// change with the turret's yaw, so a gun that clears its own hull at the front
// can still depress over the side.
//
// The defs write them as `position angle` pairs: the position a fraction of a
// turn from the front, the angle in degrees. The reference's `PitchCurve`
// parses them the same way (`position * TAU`, degrees to radians) and
// interpolates between the points around the yaw.
//
//	<pitchLimits>
//	  <minPitch>0 -20 1 -20</minPitch>
//	  <maxPitch>0 10 0.366894 10 0.430556 5 0.569444 5 0.633106 10 1 10</maxPitch>
//	</pitchLimits>
type pitchCurve struct {
	// Points are (yaw in radians from the front, pitch in radians), in the
	// order the defs write them.
	Points []pitchPoint
}

type pitchPoint struct {
	Yaw   float32
	Pitch float32
}

// parsePitchCurve reads one curve, `None` when it is not a list of pairs.
func parsePitchCurve(s string) (pitchCurve, bool) {
	fields := strings.Fields(s)
	if len(fields) < 4 || len(fields)%2 != 0 {
		return pitchCurve{}, false
	}
	c := pitchCurve{Points: make([]pitchPoint, 0, len(fields)/2)}
	for i := 0; i < len(fields); i += 2 {
		pos, err1 := strconv.ParseFloat(fields[i], 32)
		deg, err2 := strconv.ParseFloat(fields[i+1], 32)
		if err1 != nil || err2 != nil {
			return pitchCurve{}, false
		}
		c.Points = append(c.Points, pitchPoint{
			Yaw:   float32(pos * 2 * math.Pi),
			Pitch: float32(deg * math.Pi / 180),
		})
	}
	return c, true
}

// at is the limit at a turret yaw, interpolated between the points around it.
func (c pitchCurve) at(yaw float32) float32 {
	if len(c.Points) == 0 {
		return 0
	}
	y := float32(math.Mod(float64(yaw), 2*math.Pi))
	if y < 0 {
		y += 2 * math.Pi
	}
	for i := 1; i < len(c.Points); i++ {
		from, to := c.Points[i-1], c.Points[i]
		if y <= to.Yaw {
			t := float32(0)
			if to.Yaw > from.Yaw {
				t = (y - from.Yaw) / (to.Yaw - from.Yaw)
			}
			return from.Pitch + (to.Pitch-from.Pitch)*t
		}
	}
	return c.Points[0].Pitch
}

// lowest and highest are the curve's extremes, for the gun marker's packed
// limits.
func (c pitchCurve) lowest() float32 {
	v := float32(math.Inf(1))
	for _, p := range c.Points {
		if p.Pitch < v {
			v = p.Pitch
		}
	}
	return v
}

func (c pitchCurve) highest() float32 {
	v := float32(math.Inf(-1))
	for _, p := range c.Points {
		if p.Pitch > v {
			v = p.Pitch
		}
	}
	return v
}

// pitchCurvesIn reads a gun's min and max pitch curves out of its def.
func pitchCurvesIn(pkg, name, turret, gun string) (pitchCurve, pitchCurve, error) {
	raw, err := readFromZip(pkg, name)
	if err != nil {
		return pitchCurve{}, pitchCurve{}, err
	}
	f, err := entdef.ParseFile(raw)
	if err != nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s: %w", name, err)
	}
	if f.Root == nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s: no root", name)
	}
	ts := findSection(f.Root, turret)
	if ts == nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s has no %s", name, turret)
	}
	gs := ts.Child("guns")
	if gs == nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s/%s has no guns", name, turret)
	}
	g := gs.Child(gun)
	if g == nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s/%s/guns has no %s", name, turret, gun)
	}
	pl := g.Child("pitchLimits")
	if pl == nil {
		return pitchCurve{}, pitchCurve{}, fmt.Errorf("vehiclespec: %s/%s/guns/%s has no pitchLimits", name, turret, gun)
	}
	var lo, hi pitchCurve
	if s := pl.Child("minPitch"); s != nil {
		lo, _ = parsePitchCurve(s.StrVal())
	}
	if s := pl.Child("maxPitch"); s != nil {
		hi, _ = parsePitchCurve(s.StrVal())
	}
	return lo, hi, nil
}
