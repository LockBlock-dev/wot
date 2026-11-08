package login

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// Replaying a captured drive through the hull.
//
// The reference's `drive_replay.rs` is a validation harness, not a server
// feature: it takes drives captured from the real server — the controls the
// client sent and the positions the server answered with — and runs them
// through `Hull` in windows, each starting from the real state, to measure how
// closely our physics follows the official one.
//
// A drive is a text file, one sample per line:
//
//	# descr,<compact descriptor bytes>
//	# space,<map>
//	<time>,flags,<vehicle_moveWith flags>
//	<time>,pos,<x>,<y>,<z>,<roll>,<pitch>,<yaw>
//
// The `#` header lines are informational; the replay only needs the controls
// and the positions.

// DriveSample is one line of a captured drive.
type DriveSample struct {
	// Time is the capture time in seconds.
	Time float64
	// Flags is the `vehicle_moveWith` byte the client sent, when HasFlags.
	Flags    uint8
	HasFlags bool
	// Pos and Dir are the position and attitude the server answered with,
	// when HasPos.
	Pos    [3]float32
	Dir    [3]float32
	HasPos bool
}

// ParseDrive reads a captured drive.
func ParseDrive(r io.Reader) ([]DriveSample, error) {
	var out []DriveSample
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, ",")
		if len(fields) < 3 {
			return nil, fmt.Errorf("drive line %d: %q is not a sample", line, text)
		}
		t, err := strconv.ParseFloat(strings.TrimSpace(fields[0]), 64)
		if err != nil {
			return nil, fmt.Errorf("drive line %d: time: %w", line, err)
		}
		s := DriveSample{Time: t}
		switch strings.TrimSpace(fields[1]) {
		case "flags":
			v, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 8)
			if err != nil {
				return nil, fmt.Errorf("drive line %d: flags: %w", line, err)
			}
			s.Flags, s.HasFlags = uint8(v), true
		case "pos":
			if len(fields) < 8 {
				return nil, fmt.Errorf("drive line %d: a position needs x,y,z,roll,pitch,yaw", line)
			}
			var v [6]float32
			for i := 0; i < 6; i++ {
				f, err := strconv.ParseFloat(strings.TrimSpace(fields[2+i]), 64)
				if err != nil {
					return nil, fmt.Errorf("drive line %d: %w", line, err)
				}
				v[i] = float32(f)
			}
			s.Pos, s.Dir, s.HasPos = [3]float32{v[0], v[1], v[2]}, [3]float32{v[3], v[4], v[5]}, true
		default:
			return nil, fmt.Errorf("drive line %d: unknown sample %q", line, fields[1])
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// DriveError is how far a replay drifts from the captured positions.
type DriveError struct {
	// Max is the largest position error, in metres.
	Max float32
	// Mean is the mean of the errors.
	Mean float32
	// Samples is how many positions were compared.
	Samples int
}

// ReplayDrive runs a captured drive through the hull and reports how far it
// drifts from the captured positions.
//
// The reference's windowing: each window starts from the real state — the
// position and attitude the server gave, and the speed and yaw rate inferred
// from the step before it — and the controls the client sent are stepped at
// the tick rate. A physics model that follows the official one stays within
// centimetres over a second; a wrong one drifts.
func ReplayDrive(h hull, samples []DriveSample, terrain *Terrain) DriveError {
	const dt = 0.1 // the server's tick
	var err DriveError
	var sum float32
	// The position samples, in order.
	var updates []*DriveSample
	for i := range samples {
		if samples[i].HasPos {
			updates = append(updates, &samples[i])
		}
	}
	// The controls, in order.
	flagsAt := func(t float64) uint8 {
		var flags uint8
		for i := range samples {
			if samples[i].HasFlags && samples[i].Time <= t {
				flags = samples[i].Flags
			}
		}
		return flags
	}
	for i := 1; i < len(updates); i++ {
		before, from := updates[i-1], updates[i]
		span := from.Time - before.Time
		if span <= 0 {
			continue
		}
		// The real state at the window's start.
		dt0 := span
		h.Position = from.Pos
		h.Direction = from.Dir
		yaw := from.Dir[2]
		fx, fz := sin32(yaw), cos32(yaw)
		rx, rz := cos32(yaw), -sin32(yaw)
		dx := from.Pos[0] - before.Pos[0]
		dz := from.Pos[2] - before.Pos[2]
		vLong := (dx*fx + dz*fz) / float32(dt0)
		vLat := (dx*rx + dz*rz) / float32(dt0)
		h.Velocity = [2]float32{fx*vLong + rx*vLat, fz*vLong + rz*vLat}
		h.Speed = vLong
		h.YawRate = wrapAngle(from.Dir[2]-before.Dir[2]) / float32(dt0)
		h.VerticalVelocity, h.Airborne = 0, false
		h.Flags = flagsAt(from.Time)
		// Step to the next captured position.
		steps := int(math.Round(span / dt))
		if steps < 1 {
			steps = 1
		}
		for k := 0; k < steps; k++ {
			ground := groundNone
			if terrain != nil {
				ground = terrain.GroundAt(h.Position[0], h.Position[2])
			}
			h.step(float32(span)/float32(steps), ground)
			if terrain != nil {
				h.settle(terrain, nil, float32(span)/float32(steps))
			}
		}
		if i+1 < len(updates) {
			real := updates[i+1]
			ex := h.Position[0] - real.Pos[0]
			ez := h.Position[2] - real.Pos[2]
			e := float32(math.Hypot(float64(ex), float64(ez)))
			if e > err.Max {
				err.Max = e
			}
			sum += e
			err.Samples++
		}
	}
	if err.Samples > 0 {
		err.Mean = sum / float32(err.Samples)
	}
	return err
}
