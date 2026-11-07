package login

import (
	"net"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// Ammunition and consumables layouts: CMD_SET_AND_FILL_LAYOUTS.
//
// The client's `account_helpers/Inventory.pyc setAndFillLayouts` sends
//
//	CMD_SET_AND_FILL_LAYOUTS  doCmdIntArr(108, [shopRev, vehInvID,
//	                          nShells, …shells, equipmentType, nEqs, …eqs])
//
// where the shells are flat `cd, count` pairs (`ShellsApplyProcessor
// .__getShellsRaw` chains each slot's `(intCD, count)`) and the eqs are
// plain `cd`s. Either half may be absent, and then its count is 0.
//
// The answer's ext is the list of purchases the server made on the way:
// `{shells: [(cd, price, count)], eqs: [(cd, price, count)]}`, which the
// client turns into "you bought N of X" messages. This server's inventory
// is unlimited, so nothing is bought and both lists are empty — but the
// answer itself is what clears the client's pending request, and without
// it the ammo panel hangs on "loading".

// LayoutResult is one vehicle's layouts after a set-and-fill.
type LayoutResult struct {
	// Code is the client's RES_* result: 0 success, negative failure.
	Code int32
	// Message is the error text the client shows.
	Message string
	// Vehicle is the instance id the layouts belong to.
	Vehicle int64
	// Turret and Gun are the compact descriptors the ammunition layout is
	// keyed by: the client indexes `shellsLayout` by that pair, not by
	// vehicle. They are compact descriptors, not component ids — a turret CD
	// overflows a u16.
	Turret int32
	Gun    int32
	// Shells is the flat `cd, count` ammunition layout.
	Shells []int64
	// Eqs is the flat consumables layout.
	Eqs []int64
}

// Ok reports whether the layouts applied.
func (r LayoutResult) Ok() bool { return r.Code == 0 }

// LayoutBackend stores a vehicle's ammunition and consumables layouts.
type LayoutBackend interface {
	// SetLayouts replaces the layouts of one vehicle. A nil slice leaves
	// that half untouched.
	SetLayouts(accountID, vehInvID int64, shells, eqs []int64) LayoutResult
}

// answerSetAndFillLayouts handles one CMD_SET_AND_FILL_LAYOUTS.
func (s *BaseAppServer) answerSetAndFillLayouts(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if s.cfg.Layouts == nil {
		s.logf("stage2 %s: post-flood %s — no layout backend", from, cmdLabel(call.Cmd))
		return nil
	}
	arr := int64Seq(call.Args, 2)
	if len(arr) < 3 {
		arr = int32ArrayBody(call.Body)
	}
	if len(arr) < 3 {
		return s.answerLayoutResult(conn, from, st, call, LayoutResult{
			Code:    resWrongArgs,
			Message: "wrong arguments",
		})
	}
	// [shopRev, vehInvID, nShells, …shells, equipmentType, nEqs, …eqs]
	vehInvID := arr[1]
	i := 2
	nShells := int(arr[i])
	i++
	if nShells < 0 || i+nShells > len(arr) {
		return s.answerLayoutResult(conn, from, st, call, LayoutResult{
			Code:    resWrongArgs,
			Message: "wrong shell layout",
		})
	}
	var shells []int64
	if nShells > 0 {
		shells = arr[i : i+nShells]
	}
	i += nShells
	// equipmentType, then the consumables.
	i++
	var eqs []int64
	if i < len(arr) {
		nEqs := int(arr[i])
		i++
		if nEqs < 0 || i+nEqs > len(arr) {
			return s.answerLayoutResult(conn, from, st, call, LayoutResult{
				Code:    resWrongArgs,
				Message: "wrong consumables layout",
			})
		}
		if nEqs > 0 {
			eqs = arr[i : i+nEqs]
		}
	}
	res := s.cfg.Layouts.SetLayouts(st.accountID, vehInvID, shells, eqs)
	if res.Ok() {
		s.mu.Lock()
		for k := range st.garage {
			if st.garage[k].InvID != vehInvID {
				continue
			}
			if shells != nil {
				st.garage[k].Shells = res.Shells
			}
			if eqs != nil {
				st.garage[k].Eqs = res.Eqs
			}
		}
		s.mu.Unlock()
	}
	return s.answerLayoutResult(conn, from, st, call, res)
}

// answerLayoutResult answers the command and, on success, pushes the new
// layouts.
func (s *BaseAppServer) answerLayoutResult(conn Transport, from *net.UDPAddr, st *clientState, call postCall, res LayoutResult) error {
	// The ext is the purchase list; this server buys nothing, so both
	// lists are empty. It must still be a dict: the client does
	// `ctx.get('shells', [])` on it.
	ext := lobby.NewDict().
		Set("shells", lobby.NewList()).
		Set("eqs", lobby.NewList())
	small, err := BuildCommandResponseErr(call.Req, uint16(int16(res.Code)), res.Message, ext)
	if err != nil {
		return err
	}
	if err := s.mintPost(conn, from, st, answerApp(small)); err != nil {
		return err
	}
	if !res.Ok() {
		s.logf("stage2 %s: post-flood %s → RES %d (%s)", from, cmdLabel(call.Cmd), res.Code, res.Message)
		return nil
	}
	if err := s.pushLayouts(conn, from, st, res); err != nil {
		return err
	}
	s.logf("stage2 %s: post-flood %s → ok (vehicle %d, %d shell value(s), %d consumable(s))",
		from, cmdLabel(call.Cmd), res.Vehicle, len(res.Shells), len(res.Eqs))
	return nil
}

// pushLayouts sends `Account.update(diff)` with the new layouts.
//
// The client reads them off the vehicle's own inventory record:
// `_ShellsCollector._parse` is handed the per-vehicle `invData` and does
// `invData.get('shellsLayout', {})` and `invData.get('shells', [])`, while
// `inventory[1]` is keyed by `vehInvID`. So the shape is
// `inventory[1][vehInvID]['shellsLayout'][(turretCD, gunCD)][layoutIdx]` — a
// LIST OF LAYOUTS, one per setup — and `inventory[1][vehInvID]['shells']` is
// the flat installed list.
func (s *BaseAppServer) pushLayouts(conn Transport, from *net.UDPAddr, st *clientState, res LayoutResult) error {
	shellsLayout := lobby.NewDict()
	shells := lobby.NewDict()
	eqsLayout := lobby.NewDict()
	eqs := lobby.NewDict()
	if res.Shells != nil {
		keyed := lobby.NewDict()
		keyed.SetNode(
			lobby.NewTuple(lobby.NewInt(int64(res.Turret)), lobby.NewInt(int64(res.Gun))),
			lobby.NewList().Append(intList(res.Shells)))
		shellsLayout = keyed
		shells = intList(res.Shells)
	}
	if res.Eqs != nil {
		eqsLayout = lobby.NewList().Append(intList(res.Eqs))
		eqs = intList(res.Eqs)
	}
	// The vehicle's own record, not the inventory's: `_ShellsCollector._parse`
	// is handed the per-vehicle `invData` and reads
	// `invData.get('shellsLayout')` / `invData.get('shells')` off it, while
	// `inventory[1]` is keyed by `vehInvID`. Putting `shellsLayout` at the
	// inventory level keyed by `vehInvID` — as this did — means the client
	// never reaches it and falls back to `__getDefaultShellsLayout`.
	vehicle := lobby.NewDict().
		Set("shellsLayout", shellsLayout).
		Set("shells", shells).
		Set("eqsLayout", eqsLayout).
		Set("eqs", eqs)
	diff := lobby.NewDict().
		Set("prevRev", lobby.NewInt(fullSyncRev)).
		Set("rev", lobby.NewInt(fullSyncRev)).
		Set("inventory", lobby.NewDict().
			SetNode(lobby.NewInt(lobby.ItemVehicle), lobby.NewDict().
				SetNode(lobby.NewInt(res.Vehicle), vehicle)))
	doc, err := lobby.EncodeDocument(diff)
	if err != nil {
		return err
	}
	app, err := s.accountCall("update",
		entdef.Value{Kind: entdef.VString, Str: string(doc)})
	if err != nil {
		s.logf("Account.update: %v", err)
		return nil
	}
	return s.mintPost(conn, from, st, answerApp(app))
}

// intList renders a flat int list.
func intList(vals []int64) *lobby.FNode {
	list := lobby.NewList()
	for _, v := range vals {
		list.Append(lobby.NewInt(v))
	}
	return list
}
