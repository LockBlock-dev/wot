package entdef

import (
	"encoding/hex"
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
	d, err := ComputeDigestFull(testWotdefsDir, testDefsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	const want = "5df886f75e73b33cff9d87fb9c69389c"
	if got := hex.EncodeToString(d[:]); got != want {
		t.Fatalf("digest = %s, want client ground truth %s", got, want)
	}
}
