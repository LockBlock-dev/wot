//go:build linux

package keydump

import "testing"

func TestArgvMatches(t *testing.T) {
	const exe = "WorldOfTanks.exe"
	for _, tc := range []struct {
		argv0 string
		want  bool
	}{
		{`S:\steamapps\common\World of Tanks\eu\win64\WorldOfTanks.exe`, true}, // Wine
		{`/opt/wot/WorldOfTanks.exe`, true},
		{`WorldOfTanks.exe`, true},
		{`worldoftanks.exe`, true}, // case-insensitive (Windows)
		{`/usr/bin/python`, false},
		{`/home/u/bin/ida-nexus`, false}, // names exe only in ARGS (Sep 27)
		{`WorldOfTanks.exe.i64`, false},  // nearby file, not the process
		{``, false},
	} {
		if got := argvMatches(tc.argv0, exe); got != tc.want {
			t.Errorf("argvMatches(%q) = %v, want %v", tc.argv0, got, tc.want)
		}
	}
}

func TestParseSandboxed(t *testing.T) {
	sandboxed := []byte("Name:\tWorldOfTanks.exe\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n")
	singleMap := []byte("      1000       1000          1\n")
	fullMap := []byte("         0          0 4294967295\n")
	normal := []byte("Name:\tbash\nNoNewPrivs:\t0\n")
	if !parseSandboxed(sandboxed, singleMap) {
		t.Error("pressure-vessel style (NNP=1, single-UID map) must count as sandboxed")
	}
	if parseSandboxed(normal, fullMap) {
		t.Error("ordinary process must not count as sandboxed")
	}
	if parseSandboxed(sandboxed, fullMap) {
		t.Error("NNP alone without userns confinement must not count")
	}
}
