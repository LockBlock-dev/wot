package login

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// The 1a/69 stats small is the account's economy on the wire:
//
//	{stats: {freeXP: N}, prevRev: P, cache: {}, rev: R}
//
// It used to be a carrier template with the freeXP bytes patched in place,
// which tied the answer to one capture's exact pickle layout. It is built
// here instead: the structure is known, and only the revisions come from
// the carrier (they are the client's cache counters, not ours to invent).
const (
	// statsStatus is the byte between the small's length and its pickle.
	statsStatus = 0x42
	// statsSmallType is the 1a subtype.
	statsSmallType = 0x69
)

// BuildStatsSmall renders the 1a/69 stats small for an account.
func BuildStatsSmall(freeXP, prevRev, rev int64) ([]byte, error) {
	root := lobby.NewDict().
		Set("stats", lobby.NewDict().Set("freeXP", lobby.NewInt(freeXP))).
		Set("prevRev", lobby.NewInt(prevRev)).
		Set("cache", lobby.NewDict()).
		Set("rev", lobby.NewInt(rev))
	pickle, err := lobby.EncodeDocument(root)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: stats small: %w", err)
	}
	body := append([]byte{statsStatus}, pickle...)
	small, err := lobby.Small{Family: 0x1a, Type: statsSmallType, Body: body}.Encode()
	if err != nil {
		return nil, fmt.Errorf("wotlogin: stats small: %w", err)
	}
	return small, nil
}

// ParseStatsSmall reads a 1a/69 stats small back into its values. It is
// the inverse of BuildStatsSmall, and also how the carrier's revisions are
// read at load.
func ParseStatsSmall(small []byte) (freeXP, prevRev, rev int64, err error) {
	s, n, err := lobby.ParseSmall(small)
	if err != nil {
		return 0, 0, 0, err
	}
	if n != len(small) {
		return 0, 0, 0, fmt.Errorf("wotlogin: stats small has %d trailing bytes", len(small)-n)
	}
	if s.Family != 0x1a || s.Type != statsSmallType {
		return 0, 0, 0, fmt.Errorf("wotlogin: not a 1a/%02x small", statsSmallType)
	}
	if len(s.Body) < 2 || s.Body[0] != statsStatus {
		return 0, 0, 0, fmt.Errorf("wotlogin: stats small has no status byte")
	}
	stack, _, err := lobby.DecodeFaithful(s.Body[1:])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("wotlogin: stats pickle: %w", err)
	}
	if len(stack) != 1 || stack[0].Kind != lobby.FDict {
		return 0, 0, 0, fmt.Errorf("wotlogin: stats pickle is not one dict")
	}
	root := stack[0]
	if v := root.Get("stats"); v != nil {
		if f := v.Get("freeXP"); f != nil {
			freeXP = f.I
		}
	}
	if v := root.Get("prevRev"); v != nil {
		prevRev = v.I
	}
	if v := root.Get("rev"); v != nil {
		rev = v.I
	}
	return freeXP, prevRev, rev, nil
}
