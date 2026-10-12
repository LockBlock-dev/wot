package lobby

// Synthetic observer/presence tests (no captures, no keys — hand-built
// entities and timestamps only).

import (
	"strings"
	"testing"
	"time"
)

func testObserver() *Observer {
	o := &Observer{
		Ents:      map[uint32]*EntityDesc{},
		lastShot:  map[uint32]time.Time{},
		magLeft:   map[uint32]int{},
		twinReady: map[uint32][2]time.Time{},
		calFull:   map[uint32]float64{},
		calIntra:  map[uint32]float64{},
		byShot:    map[uint32]shotSnap{},
	}
	o.Ents[1] = &EntityDesc{Name: "AllyOne", Team: 2, Tank: "SU-152",
		Gun: GenGun{Name: "g", Reload: 9.4}, HasGun: true}
	o.Ents[2] = &EntityDesc{Name: "DrumTwo", Team: 1, Tank: "AMX",
		Gun: GenGun{Name: "g", Reload: 16, ClipCount: 8, ClipRate: 60}, HasGun: true}
	o.Ents[3] = &EntityDesc{Name: "TwinThree", Team: 1, Tank: "BP",
		Gun: GenGun{Name: "g", Reload: 6, TwinGun: true, TwinReloadTime: 6, TwinDelay: 1}, HasGun: true}
	o.OwnTeam, o.HasOwn = 2, true
	o.SetT0(time.Date(2026, 9, 29, 20, 45, 42, 0, time.UTC))
	return o
}

func TestDisplayTank(t *testing.T) {
	for in, want := range map[string]string{
		"R18_SU-152":      "SU-152",
		"ussr:R18_SU-152": "SU-152",
		"GB21_Cromwell":   "Cromwell",
		"?":               "?",
		"no’uscore":       "no’uscore",
	} {
		if got := DisplayTank(in); got != want {
			t.Fatalf("DisplayTank(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestObserverSingleShot(t *testing.T) {
	o := testObserver()
	at := time.Date(2026, 9, 29, 20, 46, 59, 0, time.UTC)
	shot, readies := o.ObserveShot(at, TracerHit{A0: 1, Shot: 7, Range: 152, Kind: ShellHEAT})
	if len(readies) != 0 {
		t.Fatalf("readies=%v, want none", readies)
	}
	if !strings.Contains(shot, "ALLY AllyOne [SU-152|HEAT] SHOT -> RELOAD") {
		t.Fatalf("shot=%q", shot)
	}
	if !strings.Contains(shot, "next_in=9.4s") || !strings.Contains(shot, "reload=9.4s") {
		t.Fatalf("shot=%q, want nominal waits", shot)
	}
	// ready fires at +9.4s
	due := o.FlushReady(at.Add(10 * time.Second))
	if len(due) != 1 || !strings.Contains(due[0], "RELOAD -> READY") {
		t.Fatalf("due=%v, want one READY", due)
	}
}

func TestObserverDrumMag(t *testing.T) {
	o := testObserver()
	o.Ents[2].Gun.ClipCount = 2 // small mag for the test
	t0 := time.Date(2026, 9, 29, 20, 46, 0, 0, time.UTC)
	s1, _ := o.ObserveShot(t0, TracerHit{A0: 2, Shot: 1, Range: 57, Kind: ShellAP})
	if !strings.Contains(s1, "SHOT -> READY") || !strings.Contains(s1, "[1/2]") {
		t.Fatalf("s1=%q, want READY [1/2]", s1)
	}
	if !strings.Contains(s1, "next_in=1.0s") {
		t.Fatalf("s1=%q, want intra wait", s1)
	}
	s2, _ := o.ObserveShot(t0.Add(1500*time.Millisecond), TracerHit{A0: 2, Shot: 2, Range: 57, Kind: ShellAP})
	if !strings.Contains(s2, "SHOT -> RELOAD") || !strings.Contains(s2, "[0/2]") {
		t.Fatalf("s2=%q, want RELOAD [0/2]", s2)
	}
	if !strings.Contains(s2, "next_in=16.0s") {
		t.Fatalf("s2=%q, want full wait", s2)
	}
}

func TestObserverTwin(t *testing.T) {
	o := testObserver()
	t0 := time.Date(2026, 9, 29, 20, 46, 0, 0, time.UTC)
	s1, _ := o.ObserveShot(t0, TracerHit{A0: 3, Shot: 1, Range: 57, Kind: ShellAP})
	if !strings.Contains(s1, "SHOT -> READY") || !strings.Contains(s1, "[1/2] twin") {
		t.Fatalf("s1=%q, want READY [1/2] twin", s1)
	}
	s2, _ := o.ObserveShot(t0.Add(1100*time.Millisecond), TracerHit{A0: 3, Shot: 2, Range: 57, Kind: ShellAP})
	if !strings.Contains(s2, "SHOT -> RELOAD") || !strings.Contains(s2, "next_in=6.0s") {
		t.Fatalf("s2=%q, want RELOAD next full", s2)
	}
	// dual (volley-capable) guns run the same per-barrel rhythm
	o.Ents[4] = &EntityDesc{Name: "DualFour", Team: 1, Tank: "BP2",
		Gun: GenGun{Name: "g", Reload: 6, DualGun: true, DualDelay: 1, DualTimes: []float64{6, 6}}, HasGun: true}
	d1, _ := o.ObserveShot(t0, TracerHit{A0: 4, Shot: 11, Range: 77, Kind: ShellAP})
	if !strings.Contains(d1, "SHOT -> READY") || !strings.Contains(d1, "[1/2] twin") || !strings.Contains(d1, "reload=1s fullreload=6s") {
		t.Fatalf("d1=%q, want twin-like dual display", d1)
	}
}

func TestObserverBuffCalibration(t *testing.T) {
	o := testObserver()
	t0 := time.Date(2026, 9, 29, 20, 46, 0, 0, time.UTC)
	o.ObserveShot(t0, TracerHit{A0: 1, Shot: 1, Range: 152, Kind: ShellHEAT})
	// 8.0s gap beats 9.4s nominal by 1.4 (≥max(0.3, 0.47)) → measured
	s2, _ := o.ObserveShot(t0.Add(8*time.Second), TracerHit{A0: 1, Shot: 2, Range: 152, Kind: ShellHEAT})
	_ = s2
	s3, _ := o.ObserveShot(t0.Add(16*time.Second), TracerHit{A0: 1, Shot: 3, Range: 152, Kind: ShellHEAT})
	if !strings.Contains(s3, "buff") || !strings.Contains(s3, "next_in=8.0s") {
		t.Fatalf("s3=%q, want buffed wait", s3)
	}
	// jitter-floor gaps never calibrate: 9.3 vs 9.4 (0.1 < 0.47)
	o2 := testObserver()
	o2.ObserveShot(t0, TracerHit{A0: 1, Shot: 1, Range: 152, Kind: ShellHEAT})
	o2.ObserveShot(t0.Add(9300*time.Millisecond), TracerHit{A0: 1, Shot: 2, Range: 152, Kind: ShellHEAT})
	s, _ := o2.ObserveShot(t0.Add(18600*time.Millisecond), TracerHit{A0: 1, Shot: 3, Range: 152, Kind: ShellHEAT})
	if strings.Contains(s, "buff") {
		t.Fatalf("s=%q, jitter must not calibrate", s)
	}
}

func TestObserverUnknownEntity(t *testing.T) {
	o := testObserver()
	at := time.Date(2026, 9, 29, 20, 46, 0, 0, time.UTC)
	shot, _ := o.ObserveShot(at, TracerHit{A0: 999, Shot: 1, Range: 152, Kind: ShellHEAT})
	if !strings.Contains(shot, "? ? [?|HEAT] SHOT") {
		t.Fatalf("shot=%q, want ? identity", shot)
	}
	if !strings.Contains(shot, "next_in=?") || !strings.Contains(shot, "reload=?") {
		t.Fatalf("shot=%q, want ? waits", shot)
	}
}

func TestObserverExplodeJoin(t *testing.T) {
	o := testObserver()
	at := time.Date(2026, 9, 29, 20, 46, 0, 0, time.UTC)
	o.ObserveShot(at, TracerHit{A0: 1, Shot: 77, Range: 152, Kind: ShellHEAT})
	hit := o.ObserveExplode(at.Add(time.Second), ExplodeHit{Shot: 77, Range: 152})
	if !strings.Contains(hit, "ALLY AllyOne [SU-152|HEAT] HIT -> RELOAD") {
		t.Fatalf("hit=%q", hit)
	}
	lost := o.ObserveExplode(at.Add(2*time.Second), ExplodeHit{Shot: 4242, Range: 130})
	if !strings.Contains(lost, "tracer lost") {
		t.Fatalf("lost=%q", lost)
	}
}

func TestObserverDeath(t *testing.T) {
	o := testObserver()
	at := time.Date(2026, 9, 29, 20, 47, 0, 0, time.UTC)
	row := o.ObserveDeath(at, DeathHit{Victim: 2, Killer: 1, Counter: 4})
	if !strings.Contains(row, "#4 ENEMY DrumTwo [AMX] KILLED by ALLY AllyOne [SU-152]") {
		t.Fatalf("row=%q", row)
	}
}

func TestPresence(t *testing.T) {
	p := NewPresence()
	t0 := time.Date(2026, 9, 29, 20, 45, 42, 0, time.UTC)
	p.Update(t0, []SnapshotRecord{{Token: 0xf4}, {Token: 0xf4}, {Token: 0xeb}})
	p.Update(t0.Add(time.Second), []SnapshotRecord{{Token: 0xf4}})
	if p.Total != 4 || p.Count[0xf4] != 3 || p.Count[0xeb] != 1 {
		t.Fatalf("presence=%+v", p)
	}
	if !p.First[0xf4].Equal(t0) || !p.Last[0xf4].Equal(t0.Add(time.Second)) {
		t.Fatalf("first/last wrong")
	}
	toks := p.Tokens()
	if len(toks) != 2 || toks[0] != 0xeb || toks[1] != 0xf4 {
		t.Fatalf("tokens=%x, want sorted", toks)
	}
}
