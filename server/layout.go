package server

import (
	"context"
	"fmt"

	"github.com/LockBlock-dev/wot/lobby"
	"github.com/LockBlock-dev/wot/login"
)

// Layouts stores a vehicle's ammunition and consumables layouts.
//
// It implements login.LayoutBackend, so the wire layer never touches the
// store. The layouts are the flat lists the client sends: `cd, count, …`
// for shells and `cd, …` for consumables.
type Layouts struct {
	store Store
}

// NewLayouts returns the layout surface over a store.
func NewLayouts(store Store) *Layouts { return &Layouts{store: store} }

// SetLayouts replaces the layouts of one vehicle. A nil slice leaves that
// half untouched, which is what the client means when it sends a count of 0
// for the half it is not changing.
func (l *Layouts) SetLayouts(accountID, vehInvID int64, shells, eqs []int64) login.LayoutResult {
	ctx := context.Background()
	st, err := l.store.LoadState(ctx, accountID)
	if err != nil {
		return layoutFail("no account state: %v", err)
	}
	target := -1
	for i := range st.Garage {
		if garageInvID(st, i) == vehInvID {
			target = i
			break
		}
	}
	if target < 0 {
		return layoutFail("no such vehicle")
	}
	if shells != nil {
		st.Garage[target].Shells = append([]int64(nil), shells...)
	}
	if eqs != nil {
		st.Garage[target].Eqs = append([]int64(nil), eqs...)
	}
	if err := l.store.SaveState(ctx, accountID, st); err != nil {
		return layoutFail("save: %v", err)
	}
	res := login.LayoutResult{
		Vehicle: vehInvID,
		Shells:  st.Garage[target].Shells,
		Eqs:     st.Garage[target].Eqs,
	}
	// The ammunition layout is keyed by the vehicle's (turret, gun) pair.
	if turret, gun, ok := lobby.VehicleGunKey(st.Garage[target].CompactDescr); ok {
		res.Turret, res.Gun = turret, gun
	}
	return res
}

// layoutFail renders a refusal.
func layoutFail(format string, args ...any) login.LayoutResult {
	res := login.LayoutResult{Code: -1}
	res.Message = fmt.Sprintf(format, args...)
	return res
}
