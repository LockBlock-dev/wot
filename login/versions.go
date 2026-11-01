package login

import (
	"encoding/hex"
	"fmt"

	"github.com/LockBlock-dev/wot/entdef"
)

// ClientVersion is one shipped game build the server knows how to serve:
// the protocol version bytes it announces in the login request and the
// entity-defs digest it presents.
//
// The two travel together. A 2.4.0 client never sends the 2.4.1 digest,
// so pairing them is stricter than a flat digest allowlist — a client
// claiming one build's protocol version while presenting another's
// digest is a mismatch, not a login.
type ClientVersion struct {
	// Name is the human label used in logs ("2.4.0", "2.4.1").
	Name string
	// Proto is ClientServerProtocolVersion, written sub, patch, minor,
	// major (§5.1). Both 2.4.0 and 2.4.1 announce {5,0,1,17}: the
	// protocol did not move between the two builds, only the defs did
	// (the 2.4.1.0 capture carries the same `05 00 01 11`).
	Proto [4]byte
	// Digest is the BigWorld.digest the build computes over its entity
	// defs. It is the only field that distinguishes the two builds.
	Digest [16]byte
}

// KnownVersions returns the builds the server serves by default. The
// digests are the pinned client truths from entdef: 2.4.0 recomputed
// offline byte-identically and dumped in-game, 2.4.1 dumped in-game.
func KnownVersions() []ClientVersion {
	return []ClientVersion{
		{Name: "2.4.0", Proto: [4]byte{verSub, verPatch, verMinor, verMajor}, Digest: mustDigest(entdef.Truth240)},
		{Name: "2.4.1", Proto: [4]byte{verSub, verPatch, verMinor, verMajor}, Digest: mustDigest(entdef.Truth241)},
	}
}

// mustDigest decodes a pinned digest constant. The constants are
// compile-time truths covered by entdef's own tests, so a malformed one
// is a programming error, not a runtime condition.
func mustDigest(hx string) [16]byte {
	b, err := hex.DecodeString(hx)
	if err != nil || len(b) != 16 {
		panic(fmt.Sprintf("wotserver: pinned digest %q is not 16 hex bytes", hx))
	}
	var d [16]byte
	copy(d[:], b)
	return d
}

// Identify returns the known version matching both the announced
// protocol bytes and the presented digest.
func Identify(versions []ClientVersion, proto [4]byte, digest [16]byte) (ClientVersion, bool) {
	for _, v := range versions {
		if v.Proto == proto && v.Digest == digest {
			return v, true
		}
	}
	return ClientVersion{}, false
}

// AcceptsProto reports whether any known version announces these
// protocol bytes. It is the version gate, which the live server applies
// before it looks at the digest (status 65 vs 70).
func AcceptsProto(versions []ClientVersion, proto [4]byte) bool {
	for _, v := range versions {
		if v.Proto == proto {
			return true
		}
	}
	return false
}
