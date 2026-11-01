package entdef

import (
	"encoding/hex"
	"os"
	"testing"
)

const testDefsDir = "../../World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs"

func TestParseAllEntities(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("entities: %d", len(names))
	totalProps, totalMethods := 0, 0
	for _, name := range names {
		e, err := l.ParseEntity(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		totalProps += len(e.CSProps)
		totalMethods += len(e.ClientMethods)
	}
	t.Logf("client-server props: %d, client methods: %d", totalProps, totalMethods)
}

func TestComputeDigest(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatal(err)
	}
	d, err := ComputeDigest(testDefsDir, names, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("digest: %s", hex.EncodeToString(d[:]))
}

// TestComputeDigestMatchesClient pins the digest against ground truth read
// from the live 2.4.0 EU client via the digest-dumper mod
// (../../mods/digest-dumper-mod): BigWorld.digest on 2026-09-17,
// re-dumped 2026-09-20 (identical). The LoginApp server accepts this value
// (dummy creds then fail with status 68 "Invalid password" instead of 70
// "Defs digest mismatch"), so any deviation here is a bug in our
// entity-def walk, not a server mystery. Green since 2026-09-20: the full
// client map (spaces + 40 entities + static merge + 10 mode entities +
// 281 dynamics, walkprobe/r8probe/walkprobe2-verified visit-for-visit).
func TestComputeDigestMatchesClient(t *testing.T) {
	if _, err := os.Stat(testWotdefsDir); err != nil {
		t.Skipf("external 2.4.0 defs unavailable: %v", err)
	}
	d, err := DigestVersion(testWotdefsDir, testDefsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(d[:]); got != Truth240 {
		t.Fatalf("digest = %s, want client ground truth %s", got, Truth240)
	}
}

// TestComputeDigest241Offline proves the offline digest computes offline
// for 2.4.1.0 from external defs (sibling dirs wotdefs-2.4.1/ +
// scripts-2.4.1/, extracted from the live 2.4.1.0
// res/packages/scripts.pkg + mode pkgs, kept out of this repo).
// No network, no live game.
// Truth from the live client (digest-dumper, game.log Oct-15) is
// c0cc08a2f494f7087112009ce1d002db (dummy-creds probe → 68), and the
// offline model now reproduces it exactly (403 entries, 18 fails, 385
// included). The last gap was the mode-def <Parent> chain: a mode def's
// parent may itself be a scripts def that declares a parent
// (HWPersonalDeathZone → PersonalDeathZone → AreaOfEffect), which the
// parser used to stop after one level.
func TestComputeDigest241Offline(t *testing.T) {
	if _, err := os.Stat("../../wotdefs-2.4.1"); err != nil {
		t.Skipf("external 2.4.1 defs unavailable: %v", err)
	}
	d, err := DigestVersion("../../wotdefs-2.4.1", "../../scripts-2.4.1/entity_defs", Skip241)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(d[:]); got != Truth241 {
		t.Fatalf("241 digest = %s, want client ground truth %s", got, Truth241)
	}
}
