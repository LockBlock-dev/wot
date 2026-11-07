package login

import (
	"net"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// Squad invitations.
//
// The client's `ClientInvitations` (client_common/shared_utils/
// account_helpers/ClientInvitations.pyc) sends `CMD_INVITATION_SEND`
// with `doCmdIntArrStrArr(cmd, accountsToInvite, [comment])`, and the
// receiving side gets `Account.processInvitations(invitations)` — one
// pickled list of dicts. Accept and decline are `doCmdInt3` calls whose
// answer is the ordinary command response, which is what
// `_onInvitationResponseReceived` reads.
//
// The dict keys are the ones `gui/prb_control/invites.pyc` reads:
// `id`, `type`, `status`, `sentAt`, `expiresAt`, `senderDBID`,
// `receiverDBID`, `senderVehID`, `receiverVehID` and `info`
// (`comment`, `unitMgrID`, `peripheryID`).

// invitationTTL is how long an invitation stays acceptable. The client
// schedules its expiry callback from `expiresAt`, so this is what the
// countdown in the invite popup shows.
const invitationTTL = 60 * time.Second

// invitationStatusPending is INVITATION_STATUS.PENDING.
const invitationStatusPending = 0

// answerInvitationSend records the invitations and pushes them to each
// target.
func (s *BaseAppServer) answerInvitationSend(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if s.cfg.Units == nil {
		s.logf("stage2 %s: post-flood invitation send — no unit backend", from)
		return nil
	}
	targets := int64Seq(call.Args, 2)
	comment := ""
	if strs := strSeq(call.Args, 3); len(strs) > 0 {
		comment = strs[0]
	}
	dbid := int64(accountIDFor(st.accountID, st.name))
	unitID, _, ok := s.cfg.Units.Invite(dbid, 0, targets, comment)
	if !ok {
		s.logf("stage2 %s: post-flood invitation send — sender is in no squad", from)
		return nil
	}
	now := float64(time.Now().UTC().UnixNano()) / 1e9
	expires := now + invitationTTL.Seconds()
	for _, target := range targets {
		peer, addr := s.sessionForDBID(target)
		if peer == nil {
			continue
		}
		inv := lobby.NewDict().
			Set("id", lobby.NewInt(int64(unitID))).
			Set("type", lobby.NewInt(int64(lobby.PrebattleSquad))).
			Set("status", lobby.NewInt(invitationStatusPending)).
			Set("sentAt", lobby.NewFloat(now)).
			Set("expiresAt", lobby.NewFloat(expires)).
			Set("senderDBID", lobby.NewInt(dbid)).
			Set("receiverDBID", lobby.NewInt(target)).
			Set("senderVehID", lobby.NewInt(0)).
			Set("receiverVehID", lobby.NewInt(0)).
			Set("info", lobby.NewDict().
				Set("comment", lobby.NewString(comment)).
				Set("unitMgrID", lobby.NewInt(int64(unitID))).
				Set("peripheryID", lobby.NewInt(0)))
		doc, err := lobby.EncodeDocument(lobby.NewList().Append(inv))
		if err != nil {
			return err
		}
		app, err := s.accountCall("processInvitations",
			entdef.Value{Kind: entdef.VString, Str: string(doc)})
		if err != nil {
			s.logf("processInvitations: %v", err)
			continue
		}
		if err := s.mintPost(conn, addr, peer, answerApp(app)); err != nil {
			s.logf("processInvitations → %d: %v", target, err)
		}
	}
	s.logf("stage2 %s: post-flood invitation send → unit %d, %d target(s)", from, unitID, len(targets))
	return nil
}

// answerInvitationReply answers accept/decline with the ordinary command
// response, which is what the client's callback reads.
func (s *BaseAppServer) answerInvitationReply(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	small, err := BuildCommandResponse(call.Req, 0, lobby.NewDict())
	if err != nil {
		return err
	}
	if err := s.mintPost(conn, from, st, answerApp(small)); err != nil {
		return err
	}
	s.logf("stage2 %s: post-flood %s (req %d) → RES_SUCCESS", from, cmdLabel(call.Cmd), call.Req)
	return nil
}

// strSeq reads an ARRAY<STRING> argument.
func strSeq(args []entdef.Value, i int) []string {
	if i < 0 || i >= len(args) || args[i].Kind != entdef.VSeq {
		return nil
	}
	out := make([]string, 0, len(args[i].Seq))
	for _, v := range args[i].Seq {
		out = append(out, v.Str)
	}
	return out
}
