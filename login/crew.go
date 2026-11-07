package login

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// Crew assignment: CMD_EQUIP_TMAN.
//
// The client's `account_helpers/Inventory.pyc` sends
//
//	CMD_EQUIP_TMAN  doCmdIntArr(105, [vehInvID, slot, tmanInvID, groupID, groupSize])
//
// with `tmanInvID = -1` when the slot is being emptied (the drag-to-barracks
// path). The answer is the ordinary command response; the new assignment
// reaches the client through `Account.update(diff)`, because the client never
// reads state out of a command answer.
//
// The assignment lives in ONE place: the vehicle's crew list. The client's
// `InventoryRequester.__makeVehicle` reads `inventory[1].crew[vehInvID]` and
// `__makeTankman` reads `inventory[8].vehicle[tmanInvID]`, so a tankman's
// vehicle is derived from the vehicles' lists — the tankman's own compact
// descriptor only carries the vehicle TYPE it is trained for.

// The client's RES_* command results (`common/AccountCommands.pyc`).
const (
	resSuccess   int32 = 0
	resWrongArgs int32 = -2
)

// CrewResult is the account's crew state after one assignment.
type CrewResult struct {
	// Code is the client's RES_* result: 0 success, negative failure.
	Code int32
	// Message is the error text the client shows.
	Message string
	// Vehicles is every vehicle whose crew list changed, keyed by instance
	// id. The value is the whole list, because the client replaces it.
	Vehicles map[int64][]int64
	// Tankmen is every tankman whose vehicle changed, keyed by tankman
	// instance id; the value is the vehicle it now sits in, or -1 for the
	// barracks.
	Tankmen map[int64]int64
}

// Ok reports whether the assignment applied.
func (r CrewResult) Ok() bool { return r.Code == 0 }

// CrewBackend is the crew surface: the one flow the client can trigger that
// moves a tankman between vehicles.
//
// It implements the same shape as EconomyBackend: the wire layer never
// touches the store, and the backend never touches a socket.
type CrewBackend interface {
	// EquipCrew puts tmanInvID in slot of vehInvID, taking it out of
	// whatever vehicle held it before. tmanInvID < 0 empties the slot.
	EquipCrew(accountID int64, vehInvID int64, slot int, tmanInvID int64) CrewResult
}

// answerEquipTman handles one CMD_EQUIP_TMAN.
func (s *BaseAppServer) answerEquipTman(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if s.cfg.Crew == nil {
		s.logf("stage2 %s: post-flood %s — no crew backend", from, cmdLabel(call.Cmd))
		return nil
	}
	// (requestID, cmd, [vehInvID, slot, tmanInvID, groupID, groupSize])
	arr := int64Seq(call.Args, 2)
	if len(arr) < 3 {
		// The element id did not land on doCmdIntArr, so the defs' reader
		// produced the wrong argument list. The wire shape is still the
		// defs' — `[req u16][cmd u16][count][count × i32]` — so read it
		// off the body instead of dropping the command.
		arr = int32ArrayBody(call.Body)
	}
	if len(arr) < 3 {
		name := "?"
		if call.Method != nil {
			name = call.Method.Name
		}
		s.logf("stage2 %s: post-flood %s: element %#02x decoded as %s, %d arg(s) %s, array %d value(s)",
			from, cmdLabel(call.Cmd), call.Elem, name, len(call.Args), argKinds(call.Args), len(arr))
		return s.answerCrewResult(conn, from, st, call, CrewResult{
			Code:    resWrongArgs,
			Message: "wrong arguments",
		})
	}
	vehInvID, slot, tmanInvID := arr[0], int(arr[1]), arr[2]
	res := s.cfg.Crew.EquipCrew(st.accountID, vehInvID, slot, tmanInvID)
	// Keep the session's copy in step: a later full sync (a relogin in the
	// same process) is built from it.
	if res.Ok() {
		s.mu.Lock()
		for i := range st.garage {
			if crew, ok := res.Vehicles[st.garage[i].InvID]; ok {
				st.garage[i].Crew = crew
			}
		}
		s.mu.Unlock()
	}
	return s.answerCrewResult(conn, from, st, call, res)
}

// int32ArrayBody reads the ARRAY of INT32 that follows the two INT16
// arguments of a doCmdIntArr call: `[req u16][cmd u16][count u8][i32…]`.
//
// It exists because the element id the client uses for doCmdIntArr does not
// always land on that method in the defs' table, and a mis-mapped method
// yields an argument list with no array in it. The body is the wire truth
// either way.
func int32ArrayBody(body []byte) []int64 {
	if len(body) < 5 {
		return nil
	}
	n := int(body[4])
	if n < 0 || 5+n*4 > len(body) {
		return nil
	}
	out := make([]int64, n)
	for i := 0; i < n; i++ {
		out[i] = int64(int32(binary.LittleEndian.Uint32(body[5+i*4:])))
	}
	return out
}

// argKinds renders the decoded argument kinds for a log line.
func argKinds(args []entdef.Value) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, fmt.Sprintf("%d", a.Kind))
	}
	return "[" + strings.Join(out, " ") + "]"
}

// answerCrewResult answers the command and, on success, pushes the new
// assignment.
func (s *BaseAppServer) answerCrewResult(conn Transport, from *net.UDPAddr, st *clientState, call postCall, res CrewResult) error {
	small, err := BuildCommandResponseErr(call.Req, uint16(int16(res.Code)), res.Message, lobby.NewDict())
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
	if err := s.pushCrew(conn, from, st, res); err != nil {
		return err
	}
	s.logf("stage2 %s: post-flood %s → ok (%d vehicle(s), %d tankman/tankmen)",
		from, cmdLabel(call.Cmd), len(res.Vehicles), len(res.Tankmen))
	return nil
}

// pushCrew sends `Account.update(pickled_diff)` with the new crew lists.
//
// The diff is a PARTIAL sync, so it carries `prevRev`: without it the
// client's `AccountSyncData.isFullSyncDiff` treats the push as a full sync
// and clears every cache. `Inventory.synchronize` merges the `inventory`
// block with `synchronizeDicts`, which replaces non-dict values — so a crew
// list is sent whole, and a tankman's vehicle is a plain int.
func (s *BaseAppServer) pushCrew(conn Transport, from *net.UDPAddr, st *clientState, res CrewResult) error {
	crew := lobby.NewDict()
	for invID, list := range res.Vehicles {
		node := lobby.NewList()
		for _, tman := range list {
			// An empty slot is None, not 0: `Vehicle._buildCrew` looks
			// every non-None id up in the tankman inventory and raises on
			// the miss.
			if tman > 0 {
				node.Append(lobby.NewInt(tman))
			} else {
				node.Append(lobby.NewNone())
			}
		}
		crew.SetNode(lobby.NewInt(invID), node)
	}
	vehicle := lobby.NewDict()
	for tman, veh := range res.Tankmen {
		vehicle.SetNode(lobby.NewInt(tman), lobby.NewInt(veh))
	}
	diff := lobby.NewDict().
		Set("prevRev", lobby.NewInt(fullSyncRev)).
		Set("rev", lobby.NewInt(fullSyncRev)).
		Set("inventory", lobby.NewDict().
			SetNode(lobby.NewInt(lobby.ItemVehicle), lobby.NewDict().Set("crew", crew)).
			SetNode(lobby.NewInt(lobby.ItemTankman), lobby.NewDict().Set("vehicle", vehicle)))
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

// PadCrew returns a crew list padded to the vehicle's slot count.
//
// The client requires the list to be exactly as long as the vehicle's crew
// roles: `VehicleDescrCrew._validateAndComputeCrew` raises
// `wrong number or tankmen` on any other length, and the hangar's parameter
// panel reaches it on every vehicle selection — not just in a battle. An
// empty slot is 0, which the client reads as "no tankman here" and fills
// with a placeholder descriptor itself.
//
// A size of 0 means the vehicle type is unknown, and the list is returned
// unchanged: the client then falls back to its own all-empty default.
func PadCrew(list []int64, size uint8) []int64 {
	if size == 0 {
		return list
	}
	out := make([]int64, size)
	copy(out, list)
	return out
}

// CrewNode renders a crew list for the wire: one entry per slot, with an
// empty slot as None.
//
// None is not cosmetic. `Vehicle._buildCrew` tests `if tankmanID is not
// None` and then looks the id up in the tankman inventory, so a 0 in an
// empty slot is a lookup that returns None and a `TypeError: 'NoneType'
// object has no attribute '__getitem__'` that aborts the whole items
// cache — the hangar then never finishes loading.
func CrewNode(list []int64, size uint8) []any {
	padded := PadCrew(list, size)
	out := make([]any, len(padded))
	for i, tman := range padded {
		if tman > 0 {
			out[i] = tman
		}
	}
	return out
}
