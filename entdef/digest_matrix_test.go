package entdef

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// TestDigestMatrix sweeps the framework-encoding toggles against the
// pinned client oracle (768 combos, instant) on the entities-only
// sub-walk. Parse once, hash many ways. A MATCH prints the winning
// combination (as a test failure on purpose); "no match" just means the
// toggled space doesn't cover it — the full-map truth lives in
// TestComputeDigestMatchesClient (green).
func TestDigestMatrix(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.ensureAliases(); err != nil {
		t.Fatal(err)
	}
	var entities []*Entity
	for _, name := range names {
		e, err := l.ParseEntity(name)
		if err != nil {
			t.Fatal(err)
		}
		entities = append(entities, e)
	}
	const want = "5df886f75e73b33cff9d87fb9c69389c"
	hashAll := func() string {
		h := md5.New()
		for _, e := range entities {
			entityMD5(h, e, nil)
		}
		return hex.EncodeToString(h.Sum(nil))
	}
	dLabels, dLabelNUL, dType, dArgs := DigestLabels, DigestLabelNUL, DigestTypeLabels, DigestArgNames
	dDouble, dVar, dNamesNUL, dVarLabel := DigestDoubleNames, DigestVarLen, DigestNamesNUL, DigestVarLenLabel
	defer func() {
		DigestLabels, DigestLabelNUL, DigestTypeLabels, DigestArgNames = dLabels, dLabelNUL, dType, dArgs
		DigestDoubleNames, DigestVarLen, DigestNamesNUL, DigestVarLenLabel = dDouble, dVar, dNamesNUL, dVarLabel
	}()
	tried := 0
	for _, labels := range []bool{false, true} {
		for _, labelNUL := range []bool{false, true} {
			for _, typ := range []int{0, 1, 2, 3} {
				for _, args := range []bool{false, true} {
					for _, dbl := range []bool{false, true} {
						for _, vlen := range []bool{false, true} {
							for _, nnul := range []bool{false, true} {
								for _, vlab := range []int{0, 1, 2} {
									DigestLabels, DigestLabelNUL, DigestTypeLabels = labels, labelNUL, typ
									DigestArgNames, DigestDoubleNames = args, dbl
									DigestVarLen, DigestNamesNUL, DigestVarLenLabel = vlen, nnul, vlab
									tried++
									if got := hashAll(); got == want {
										t.Fatalf("MATCH labels=%v labelNUL=%v type=%d args=%v double=%v varlen=%v namesNUL=%v varlab=%d",
											labels, labelNUL, typ, args, dbl, vlen, nnul, vlab)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("no match in %d combos", tried)
}
