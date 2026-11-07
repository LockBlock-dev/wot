package login

import (
	"net"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// UnitBackend is the squad state behind the client's unit RPC.
//
// The client's `ClientUnitMgr` (client_common/ClientUnitMgr.pyc) is a
// thin layer: every action is `account.base.accountUnitClient_<method>`
// and every answer is `Account.onUnitUpdate(unitMgrID, packedUnit,
// packedOps)`, with both blobs in the client's own binary format
// (lobby.PackUnit / lobby.Op*). This interface is the seam, so the wire
// layer never sees the model and the model never sees a socket.
//
// Every method returns the unit id, the packed unit and whether the call
// applied; ok=false means "no such unit", which the wire layer answers
// with onUnitError.
type UnitBackend interface {
	Create(p lobby.UnitPlayer, prebattleType uint8) (uint64, []byte, bool)
	Join(p lobby.UnitPlayer, unitID uint64) (uint64, []byte, bool)
	Leave(dbid int64) (uint64, []byte, bool)
	DoCmd(dbid int64, unitID uint64, cmd uint8, arg64 uint64, arg32 int32, argStr string) (uint64, []byte, bool)
	Invite(dbid int64, unitID uint64, targets []int64, comment string) (uint64, []byte, bool)
	Members(unitID uint64) []int64
}

// unitPlayerFor builds the packed player record for one session.
func (s *BaseAppServer) unitPlayerFor(st *clientState) lobby.UnitPlayer {
	dbid := int64(accountIDFor(st.accountID, st.name))
	p := lobby.UnitPlayer{
		AccountDBID: dbid,
		AccountID:   dbid,
		NickName:    st.name,
	}
	if st.clan != nil {
		p.ClanDBID = st.clan.DBID
		p.ClanAbbrev = st.clan.Abbrev
	}
	return p
}

// answerUnitCall dispatches one accountUnitClient_* call.
func (s *BaseAppServer) answerUnitCall(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if s.cfg.Units == nil {
		s.logf("stage2 %s: post-flood %s — no unit backend", from, call.Name())
		return nil
	}
	reqID := int32(uintOf(call.Args[0]))
	player := s.unitPlayerFor(st)
	var (
		unitID uint64
		packed []byte
		ok     bool
	)
	switch call.Method.Name {
	case "accountUnitClient_create":
		// (requestID, prebattleType, queueType, unitExtrasInitStr,
		// modeExtrasStr)
		prebattle := uint8(uintOf(call.Args[1]))
		unitID, packed, ok = s.cfg.Units.Create(player, prebattle)
	case "accountUnitClient_join":
		// (requestID, unitMgrID, slotIdx)
		unitID, packed, ok = s.cfg.Units.Join(player, uintOf(call.Args[1]))
	case "accountUnitClient_doCmd":
		// (requestID, unitMgrID, cmd, uint64Arg, int32Arg, strArg)
		unitID, packed, ok = s.cfg.Units.DoCmd(
			player.AccountDBID,
			uintOf(call.Args[1]),
			uint8(uintOf(call.Args[2])),
			uintOf(call.Args[3]),
			int32(uintOf(call.Args[4])),
			argString(call.Args, 5),
		)
	case "accountUnitClient_sendInvites":
		// (requestID, unitMgrID, accountsToInvite, comment)
		unitID, packed, ok = s.cfg.Units.Invite(
			player.AccountDBID,
			uintOf(call.Args[1]),
			int64Seq(call.Args, 2),
			argString(call.Args, 3),
		)
	case "accountUnitClient_setRosterSlots":
		// (requestID, unitMgrID, rosterSlotKeys, rosterSlotValues). The
		// squad roster has fixed slots, so this is acknowledged without
		// changing anything.
		unitID, packed, ok = s.cfg.Units.DoCmd(
			player.AccountDBID, uintOf(call.Args[1]), lobby.UnitCmdSetRosterSlot, 0, 0, "")
	default:
		return nil
	}
	if !ok {
		return s.unitError(conn, from, st, reqID, 0, "no unit")
	}
	// The caller gets the response ack, then every member (the caller
	// included) gets the new unit state.
	if err := s.unitCallOk(conn, from, st, reqID); err != nil {
		return err
	}
	s.pushUnit(conn, unitID, packed)
	s.logf("stage2 %s: post-flood %s → unit %d (%d B, %d members)",
		from, call.Name(), unitID, len(packed), len(s.cfg.Units.Members(unitID)))
	return nil
}

// unitCallOk sends Account.onUnitCallOk(requestID), which is what clears
// the client's pending request.
func (s *BaseAppServer) unitCallOk(conn Transport, from *net.UDPAddr, st *clientState, reqID int32) error {
	app, err := s.accountCall("onUnitCallOk",
		entdef.Value{Kind: entdef.VInt, Int: int64(reqID)})
	if err != nil {
		return err
	}
	return s.mintPost(conn, from, st, answerApp(app))
}

// unitError sends Account.onUnitError(requestID, unitMgrID, errorCode,
// errorString).
func (s *BaseAppServer) unitError(conn Transport, from *net.UDPAddr, st *clientState, reqID int32, unitID uint64, text string) error {
	app, err := s.accountCall("onUnitError",
		entdef.Value{Kind: entdef.VInt, Int: int64(reqID)},
		entdef.Value{Kind: entdef.VUint, Uint: unitID},
		entdef.Value{Kind: entdef.VInt, Int: int64(lobby.UnitErrorOK)},
		entdef.Value{Kind: entdef.VString, Str: text})
	if err != nil {
		return err
	}
	return s.mintPost(conn, from, st, answerApp(app))
}

// pushUnit sends Account.onUnitUpdate(unitMgrID, packedUnit, packedOps)
// to every member of the unit.
func (s *BaseAppServer) pushUnit(conn Transport, unitID uint64, packed []byte) {
	if s.cfg.Units == nil {
		return
	}
	app, err := s.accountCall("onUnitUpdate",
		entdef.Value{Kind: entdef.VUint, Uint: unitID},
		entdef.Value{Kind: entdef.VString, Str: string(packed)},
		entdef.Value{Kind: entdef.VString, Str: ""})
	if err != nil {
		s.logf("onUnitUpdate: %v", err)
		return
	}
	for _, dbid := range s.cfg.Units.Members(unitID) {
		st, addr := s.sessionForDBID(dbid)
		if st == nil {
			continue
		}
		if err := s.mintPost(conn, addr, st, answerApp(app)); err != nil {
			s.logf("onUnitUpdate → %d: %v", dbid, err)
		}
	}
}

// sessionForDBID finds the live session for a client databaseID.
func (s *BaseAppServer) sessionForDBID(dbid int64) (*clientState, *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.byAddr {
		if st.stage2Addr == nil {
			continue
		}
		if int64(accountIDFor(st.accountID, st.name)) == dbid {
			return st, st.stage2Addr
		}
	}
	return nil, nil
}

// argString reads a STRING argument, or "" when absent.
func argString(args []entdef.Value, i int) string {
	if i < 0 || i >= len(args) {
		return ""
	}
	return args[i].Str
}

// int64Seq reads an ARRAY<DB_ID> argument as int64s.
func int64Seq(args []entdef.Value, i int) []int64 {
	if i < 0 || i >= len(args) || args[i].Kind != entdef.VSeq {
		return nil
	}
	out := make([]int64, 0, len(args[i].Seq))
	for _, v := range args[i].Seq {
		out = append(out, int64(uintOf(v)))
	}
	return out
}
