package login

import (
	"strings"
	"testing"
)

// TestParseDrive pins the captured-drive format: `time,flags,<byte>` and
// `time,pos,x,y,z,roll,pitch,yaw`, with `#` headers skipped.
func TestParseDrive(t *testing.T) {
	const text = `# descr,010203
# space,spaces/01_karelia
0.0,flags,1
0.1,pos,0,0,0,0,0,0
0.2,flags,1
0.3,pos,0,0,0.5,0,0,0
`
	samples, err := ParseDrive(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseDrive: %v", err)
	}
	if len(samples) != 4 {
		t.Fatalf("%d samples, want 4", len(samples))
	}
	if !samples[0].HasFlags || samples[0].Flags != 1 {
		t.Fatalf("sample 0 = %+v, want flags 1", samples[0])
	}
	if !samples[1].HasPos || samples[1].Pos[2] != 0 {
		t.Fatalf("sample 1 = %+v, want a position", samples[1])
	}
	if !samples[3].HasPos || samples[3].Pos[2] != 0.5 {
		t.Fatalf("sample 3 = %+v, want z 0.5", samples[3])
	}
}

// TestReplayDriveFollowsAStraightLine pins the harness: a captured drive that
// drives straight is followed within a few centimetres by the hull.
func TestReplayDriveFollowsAStraightLine(t *testing.T) {
	// The hull at 4 m/s² for a second covers 2 m; the "captured" positions
	// are the same model's own, so the replay must match them closely.
	h := hull{Limits: motionLimits{SpeedForward: 37, SpeedBackward: 14, RotationSpeed: 0.5}}
	var samples []DriveSample
	samples = append(samples, DriveSample{Time: 0, Flags: moveForward, HasFlags: true})
	samples = append(samples, DriveSample{Time: 0, Pos: [3]float32{0, 0, 0}, HasPos: true})
	// Step the same hull to produce the reference positions.
	ref := h
	ref.Flags = moveForward
	for i := 1; i <= 10; i++ {
		ref.step(0.1, groundFirm)
		samples = append(samples, DriveSample{Time: float64(i) * 0.1, Pos: ref.Position, Dir: ref.Direction, HasPos: true})
	}
	got := ReplayDrive(h, samples, nil)
	if got.Samples == 0 {
		t.Fatal("no samples compared")
	}
	if got.Max > 0.01 {
		t.Fatalf("max error = %v m, want the replay to follow its own model", got.Max)
	}
}
