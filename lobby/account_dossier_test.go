package lobby

import (
	"encoding/binary"
	"testing"
)

// TestAccountDossierHeader pins the packed dossier's framing: a u16 version
// followed by one u16 size per block, and the sizes must account for exactly
// the rest of the blob. `DossierDescr.__init__` reads the header with
// `struct.unpack_from(headerFormat, compDescr)` and then slices each block out
// of `compDescr[offset:offset+size]`, so a size that does not add up shifts
// every later block and the client raises on the first record it reads.
func TestAccountDossierHeader(t *testing.T) {
	if len(AccountDossier) < 4 {
		t.Fatalf("dossier is %d B", len(AccountDossier))
	}
	version := binary.LittleEndian.Uint16(AccountDossier)
	if version == 0 {
		t.Fatal("dossier version is 0")
	}
	// The block count is not stored; it is implied by the layout the client
	// was built with. Recover it from the sizes: the header is
	// 2 + 2*N and the sizes must sum to the remainder.
	var sum, n int
	for off := 2; off+2 <= len(AccountDossier); off += 2 {
		sum += int(binary.LittleEndian.Uint16(AccountDossier[off:]))
		n++
		if 2+2*n+sum == len(AccountDossier) {
			break
		}
		if 2+2*n+sum > len(AccountDossier) {
			t.Fatalf("block sizes overrun the blob at block %d", n)
		}
	}
	if got := 2 + 2*n + sum; got != len(AccountDossier) {
		t.Fatalf("header %d blocks + %d B of blocks = %d, want %d", n, sum, got, len(AccountDossier))
	}
	if n < 50 {
		t.Fatalf("%d blocks, want the client's full account layout", n)
	}
}

// TestAccountDossierSize pins the size budget. The blob carries the
// achievement blocks, `total` and the whole `playerBadges` unlock list, which
// puts it past one datagram — so the answer rides the fragment chain
// (`BaseAppServer.mintPostLarge`). The chain's sequence number is one byte, so
// 256 fragments of `login.DefaultBulkPayload` (1223 B) is the hard ceiling.
func TestAccountDossierSize(t *testing.T) {
	const (
		fragmentPayload = 1223
		maxFragments    = 256
	)
	if len(AccountDossier) <= fragmentPayload {
		t.Fatalf("dossier is %d B, expected to need the fragment chain", len(AccountDossier))
	}
	if n := (len(AccountDossier) + fragmentPayload - 1) / fragmentPayload; n > maxFragments {
		t.Fatalf("dossier is %d B = %d fragments, past the %d-fragment ceiling", len(AccountDossier), n, maxFragments)
	}
}
