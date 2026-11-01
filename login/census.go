package login

import (
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
)

// The 1a/67 queue census is the answer to a 502 CMD_REQ_QUEUE_INFO:
//
//	{players: N, classes: [c1, c2, c3, c4, c5]}
//
// The captured census is {players: 924, classes: [186 226 209 98 205]},
// whose classes sum to players — so the breakdown is per vehicle class,
// not per queue type.
const (
	censusStatus    = 0x2c
	censusSmallType = 0x67
	// censusClasses is how many vehicle classes the client expects.
	censusClasses = 5
)

// BuildCensusSmall renders the 1a/67 census for a live queue.
func BuildCensusSmall(players int, classes []int) ([]byte, error) {
	if len(classes) != censusClasses {
		return nil, fmt.Errorf("wotlogin: census wants %d classes, got %d", censusClasses, len(classes))
	}
	items := make([]*lobby.FNode, 0, censusClasses)
	for _, c := range classes {
		items = append(items, lobby.NewInt(int64(c)))
	}
	root := lobby.NewDict().
		Set("players", lobby.NewInt(int64(players))).
		Set("classes", lobby.NewList(items...))
	pickle, err := lobby.EncodeDocument(root)
	if err != nil {
		return nil, fmt.Errorf("wotlogin: census small: %w", err)
	}
	body := append([]byte{censusStatus}, pickle...)
	small, err := lobby.Small{Family: 0x1a, Type: censusSmallType, Body: body}.Encode()
	if err != nil {
		return nil, fmt.Errorf("wotlogin: census small: %w", err)
	}
	return small, nil
}

// ParseCensusSmall reads a 1a/67 census back into its values.
func ParseCensusSmall(small []byte) (players int, classes []int, err error) {
	s, n, err := lobby.ParseSmall(small)
	if err != nil {
		return 0, nil, err
	}
	if n != len(small) {
		return 0, nil, fmt.Errorf("wotlogin: census small has %d trailing bytes", len(small)-n)
	}
	if s.Family != 0x1a || s.Type != censusSmallType {
		return 0, nil, fmt.Errorf("wotlogin: not a 1a/%02x small", censusSmallType)
	}
	if len(s.Body) < 2 || s.Body[0] != censusStatus {
		return 0, nil, fmt.Errorf("wotlogin: census small has no status byte")
	}
	stack, _, err := lobby.DecodeFaithful(s.Body[1:])
	if err != nil {
		return 0, nil, fmt.Errorf("wotlogin: census pickle: %w", err)
	}
	if len(stack) != 1 || stack[0].Kind != lobby.FDict {
		return 0, nil, fmt.Errorf("wotlogin: census pickle is not one dict")
	}
	root := stack[0]
	if v := root.Get("players"); v != nil {
		players = int(v.I)
	}
	if v := root.Get("classes"); v != nil {
		for _, it := range v.Items {
			classes = append(classes, int(it.I))
		}
	}
	return players, classes, nil
}
