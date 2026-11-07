package server

import (
	"context"
	"fmt"

	"github.com/LockBlock-dev/wot/login"
)

// Crew is the crew-assignment surface.
//
// It implements login.CrewBackend, so the wire layer never touches the store
// and this file never touches a socket. The assignment lives in the vehicle's
// crew list (PlayerState.Garage[i].Crew): the client derives a tankman's
// vehicle from it, so there is no second place to keep in step.
type Crew struct {
	store Store
}

// NewCrew returns the crew surface over a store.
func NewCrew(store Store) *Crew { return &Crew{store: store} }

// EquipCrew puts tmanInvID in slot of vehInvID, taking it out of whatever
// vehicle held it before. tmanInvID < 0 empties the slot.
//
// The client only ever sends a slot its own vehicle descriptor declares, so
// the slot is not re-validated against the crew roles here — but the list is
// grown to fit, because a short list would silently drop the assignment.
func (c *Crew) EquipCrew(accountID int64, vehInvID int64, slot int, tmanInvID int64) login.CrewResult {
	if slot < 0 {
		return crewFail(login.CrewResult{}, "wrong slot")
	}
	ctx := context.Background()
	st, err := c.store.LoadState(ctx, accountID)
	if err != nil {
		return crewFail(login.CrewResult{}, "no account state: %v", err)
	}
	target := -1
	for i := range st.Garage {
		if garageInvID(st, i) == vehInvID {
			target = i
			break
		}
	}
	if target < 0 {
		return crewFail(login.CrewResult{}, "no such vehicle")
	}
	res := login.CrewResult{
		Vehicles: map[int64][]int64{},
		Tankmen:  map[int64]int64{},
	}
	// Take the tankman out of whatever vehicle holds it. A tankman can only
	// sit in one slot, so this is what makes a move a move rather than a
	// copy.
	if tmanInvID >= 0 {
		for i := range st.Garage {
			crew := st.Garage[i].Crew
			for s, held := range crew {
				if held != tmanInvID {
					continue
				}
				crew[s] = 0
				res.Vehicles[garageInvID(st, i)] = crew
			}
		}
	}
	// The list is kept at the vehicle's full slot count: the client raises
	// `wrong number or tankmen` on any other length, and it does so from
	// the hangar's parameter panel, not only in a battle.
	crew := login.PadCrew(st.Garage[target].Crew, st.Garage[target].CrewSize)
	for len(crew) <= slot {
		crew = append(crew, 0)
	}
	// The tankman that was in the slot goes back to the barracks.
	if displaced := crew[slot]; displaced > 0 && displaced != tmanInvID {
		res.Tankmen[displaced] = -1
	}
	if tmanInvID >= 0 {
		crew[slot] = tmanInvID
		res.Tankmen[tmanInvID] = vehInvID
	} else {
		crew[slot] = 0
	}
	st.Garage[target].Crew = crew
	res.Vehicles[vehInvID] = crew
	if err := c.store.SaveState(ctx, accountID, st); err != nil {
		return crewFail(login.CrewResult{}, "save: %v", err)
	}
	return res
}

// garageInvID is the instance id the client addresses a garage slot by.
//
// The store keeps the garage as an ordered list with no id of its own, and
// the lobby hands the client `index+1` (see the OnLoggedOn hook), so the id
// is positional. It is derived here rather than stored so the two can never
// disagree.
func garageInvID(st *PlayerState, i int) int64 { return int64(i + 1) }

// crewFail renders a refusal.
func crewFail(res login.CrewResult, format string, args ...any) login.CrewResult {
	res.Code = -1
	res.Message = fmt.Sprintf(format, args...)
	return res
}
