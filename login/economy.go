package login

import (
	"net"

	"github.com/LockBlock-dev/wot/entdef"
	"github.com/LockBlock-dev/wot/lobby"
)

// EconomyResult is an account's balances after a purchase, so the wire
// layer can push them to the client.
//
// The client never reads a balance out of a command answer: `Stats`
// callbacks take `resultID` only, and the numbers arrive through
// `Account.update(diff)` — the unsolicited sync push. So every purchase
// answers with the ordinary command response AND pushes this.
type EconomyResult struct {
	Credits       int64
	Gold          int64
	FreeXP        int64
	Crystal       int64
	Slots         int64
	Berths        int64
	PremiumExpiry int64
	PiggyBank     int64
	PiggyBankGold int64
	// Code is the client's RES_* result: 0 success, negative failure
	// (RES_FAILURE = -1, RES_WRONG_ARGS = -2, RES_NOT_AVAILABLE = -10).
	Code int32
	// Message is the error text the client shows.
	Message string
}

// Ok reports whether the purchase applied.
func (r EconomyResult) Ok() bool { return r.Code == 0 }

// EconomyBackend is the purchase surface: every flow the client can
// trigger that moves money.
//
// The client's senders are in `account_helpers/Stats.pyc`:
//
//	CMD_EXCHANGE      doCmdInt4(202, shopRev, gold, credits, 0)
//	CMD_FREE_XP_CONV  doCmdIntArr(203, [shopRev, xp, gold, ...vehCDs])
//	CMD_PREMIUM       doCmdInt3(204, shopRev, days, arenaUniqueID)
//	CMD_BUY_SLOT      doCmdInt3(205, shopRev, 0, 0)
//	CMD_BUY_BERTHS    doCmdInt3(206, shopRev, packs, 0)
//
// and the piggy bank's are the dev pair in
// `gui/game_control/wot_plus_controller.pyc`:
//
//	CMD_SET_RESERVES_PIGGY_BANK_DEV  doCmdInt2(10084, credits, gold)
//	CMD_SMASH_PIGGY_BANK_DEV         doCmdInt(10088, 6)
type EconomyBackend interface {
	Exchange(accountID int64, gold, credits int64) EconomyResult
	ConvertFreeXP(accountID int64, xp, gold int64) EconomyResult
	BuyPremium(accountID int64, days int64) EconomyResult
	BuySlot(accountID int64) EconomyResult
	BuyBerths(accountID int64, packs int64) EconomyResult
	SetPiggyBank(accountID int64, credits, gold int64) EconomyResult
	SmashPiggyBank(accountID int64) EconomyResult
}

// answerEconomy handles one purchase command.
func (s *BaseAppServer) answerEconomy(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if s.cfg.Economy == nil {
		s.logf("stage2 %s: post-flood %s — no economy backend", from, cmdLabel(call.Cmd))
		return nil
	}
	accountID := st.accountID
	var res EconomyResult
	switch call.Cmd {
	case lobby.CmdExchange:
		// (requestID, cmd, shopRev, gold, credits, 0)
		res = s.cfg.Economy.Exchange(accountID, argInt(call.Args, 3), argInt(call.Args, 4))
	case lobby.CmdFreeXPConv:
		// (requestID, cmd, [shopRev, xp, gold, ...vehCDs])
		arr := int64Seq(call.Args, 2)
		if len(arr) < 3 {
			res = EconomyResult{Code: -2, Message: "wrong arguments"}
			break
		}
		res = s.cfg.Economy.ConvertFreeXP(accountID, arr[1], arr[2])
	case lobby.CmdPremium:
		// (requestID, cmd, shopRev, days, arenaUniqueID)
		res = s.cfg.Economy.BuyPremium(accountID, argInt(call.Args, 3))
	case lobby.CmdBuySlot:
		res = s.cfg.Economy.BuySlot(accountID)
	case lobby.CmdBuyBerths:
		// (requestID, cmd, shopRev, packs, 0)
		res = s.cfg.Economy.BuyBerths(accountID, argInt(call.Args, 3))
	case lobby.CmdSetReservesPiggyBankDev:
		// (requestID, cmd, credits, gold)
		res = s.cfg.Economy.SetPiggyBank(accountID, argInt(call.Args, 2), argInt(call.Args, 3))
	case lobby.CmdSmashPiggyBankDev:
		res = s.cfg.Economy.SmashPiggyBank(accountID)
	default:
		return nil
	}
	// The command answer first: it clears the client's pending request.
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
	// Then the balances, through the unsolicited push the client applies
	// with `Account.update(diff)` → `_update(True, diff)`.
	if err := s.pushEconomy(conn, from, st, res); err != nil {
		return err
	}
	s.logf("stage2 %s: post-flood %s → ok (credits %d, gold %d, freeXP %d, slots %d, berths %d)",
		from, cmdLabel(call.Cmd), res.Credits, res.Gold, res.FreeXP, res.Slots, res.Berths)
	return nil
}

// pushEconomy sends `Account.update(pickled_diff)` with the new balances.
//
// The diff is a PARTIAL sync, so it must carry `prevRev`: the client's
// `AccountSyncData.isFullSyncDiff` is `diff.get('prevRev') is None`, and a
// diff without it is taken as a full sync — which clears every cache and
// re-renders the hangar from scratch.
func (s *BaseAppServer) pushEconomy(conn Transport, from *net.UDPAddr, st *clientState, res EconomyResult) error {
	diff := lobby.NewDict().
		Set("prevRev", lobby.NewInt(fullSyncRev)).
		Set("rev", lobby.NewInt(fullSyncRev)).
		Set("stats", lobby.NewDict().
			Set("credits", lobby.NewInt(res.Credits)).
			Set("gold", lobby.NewInt(res.Gold)).
			Set("freeXP", lobby.NewInt(res.FreeXP)).
			Set("crystal", lobby.NewInt(res.Crystal)).
			Set("slots", lobby.NewInt(res.Slots)).
			Set("berths", lobby.NewInt(res.Berths))).
		Set("account", lobby.NewDict().
			Set("premiumExpiryTime", lobby.NewInt(res.PremiumExpiry))).
		// `Stats.synchronize` hands `diff['premium']` to
		// `PremiumInfo.update`, which merges into `_rawPremiumInfo` keyed
		// by PREMIUM TYPE id plus `premMask`.
		Set("premium", premiumNode(res.PremiumExpiry)).
		// `piggyBank` is a dict diff (`synchronizeDicts`), so only the
		// changed keys need to be here.
		Set("piggyBank", lobby.NewDict().
			Set("credits", lobby.NewInt(res.PiggyBank)).
			Set("gold", lobby.NewInt(res.PiggyBankGold)))
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

// premiumNode renders the `premium` block: every premium type stamped
// with the expiry and the mask saying all of them are on.
func premiumNode(expiry int64) *lobby.FNode {
	return lobby.NewDict().
		SetNode(lobby.NewInt(1), lobby.NewInt(expiry)).
		SetNode(lobby.NewInt(2), lobby.NewInt(expiry)).
		SetNode(lobby.NewInt(4), lobby.NewInt(expiry)).
		Set("premMask", lobby.NewInt(7))
}

// argInt reads an integer argument, or 0 when absent.
func argInt(args []entdef.Value, i int) int64 {
	if i < 0 || i >= len(args) {
		return 0
	}
	return int64(uintOf(args[i]))
}
