package login

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// The stats answer is the account's economy on the wire:
//
//	{stats: {freeXP: N}, prevRev: P, cache: {}, rev: R}
//
// It used to be a carrier template with the freeXP bytes patched in place,
// which tied the answer to one capture's exact pickle layout. It is built
// here instead: the structure is known, and only the revisions come from
// the carrier (they are the client's cache counters, not ours to invent).
//
// The element is NOT a "1a/69 small": 0x1A is `selectPlayerEntity` (the
// exe's message-name table puts tickSync at 19 = 0x13 and
// selectPlayerEntity at 26 = 0x1A), and the byte after it is a CLIENT
// METHOD CALL — 0x69 = entityMethodBase(0x4E) + 27 = Account's
// `onUnitBrowserResultsUpdate(STRING)`. Its framing is
// `[elemID][u8 elementLen][u8 stringLen][string]` (the method's
// VariableLengthHeaderSize is the ELEMENT length width; the string's own
// header is one byte). The genuine element is `69 44 43 <67B>`: 0x44 =
// 68 = 1 + 67, 0x43 = 67 = the pickle length.
//
// Writing a fixed "status" byte there instead made the client read a
// 66-byte string out of 53 remaining bytes — a MemoryIStream over-read,
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
const (
	// statsSmallType is the client method id (0x4E + 27).
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
	if len(pickle) > 0xFF {
		return nil, fmt.Errorf("wotlogin: stats pickle is %d B, beyond the u8 string length", len(pickle))
	}
	body := append([]byte{byte(len(pickle))}, pickle...)
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
	if len(s.Body) < 2 || int(s.Body[0]) != len(s.Body)-1 {
		return 0, 0, 0, fmt.Errorf("wotlogin: stats element string length %d, body %d B", s.Body[0], len(s.Body))
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
