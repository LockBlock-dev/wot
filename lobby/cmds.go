package lobby

// Account command IDs — the numeric command port.
//
// Every C>S command rides inside a doCmd* base call (see
// lobbycalls.go) as [reqID u16][cmd u16][args...]. The A1 tag selects
// the *sender* (doCmdInt3 / doCmdInt2 / doCmdIntArr / doCmdStr …); the
// u16 that follows identifies the *command*. The numbers below are the
// CMD_* constants of the shipped scripts/common/AccountCommands.pyc
// (226 of them, 0..11000), which the client reaches through
// ClientCommandsPort's eight typed senders.
//
// Only the IDs this tree actually sends or answers are named here.

const (
	// Stage-2 lobby sync/stat commands.
	CmdSyncData           = 100 // CMD_SYNC_DATA
	CmdSetActiveVehSeason = 121 // CMD_SET_ACTIVE_VEH_SEASON
	CmdSyncShop           = 300 // CMD_SYNC_SHOP
	CmdReqServerStats     = 501 // CMD_REQ_SERVER_STATS
	// CmdReqPlayerInfo is CMD_REQ_PLAYER_INFO: the profile's data request.
	// `Account.requestPlayerInfo` sends it with doCmdInt3 and reads the
	// answer's ext dict — `dossier` is the packed account dossier, and
	// `DossierRequester` turns it into the achievements, medals and battle
	// stats the profile and the achievements screen render.
	CmdReqPlayerInfo = 503
	// CmdReqPlayerClanInfo is CMD_REQ_PLAYER_CLAN_INFO: the client asks
	// for a player's clan. The answer is `Account.onClanInfoReceived`
	// (clanDBID, name, abbrev, motto, description), which is where
	// `g_clanCache` gets the motto and description the profile shows —
	// the clan name, tag, role and join date ride the account sync's
	// `account.clanDBID` / `stats.clanInfo` instead.
	CmdReqPlayerClanInfo = 506

	// CmdEquipTman is CMD_EQUIP_TMAN: the crew assignment. The client's
	// `account_helpers/Inventory.pyc equipTankman` sends it with
	// doCmdIntArr as [vehInvID, slot, tmanInvID, groupID, groupSize], and
	// `tmanInvID = -1` empties the slot.
	CmdEquipTman = 105

	// CmdSetAndFillLayouts is CMD_SET_AND_FILL_LAYOUTS: the ammo and
	// consumables panels. `account_helpers/Inventory.pyc` sends it with
	// doCmdIntArr as
	// [shopRev, vehInvID, nShells, …shells, equipmentType, nEqs, …eqs],
	// where the shells are flat `cd, count` pairs and the eqs are `cd`s.
	// The answer's ext carries the purchases it made, `{shells: [(cd,
	// price, count)], eqs: […]}`.
	CmdSetAndFillLayouts = 108

	// The economy flows. `account_helpers/Stats.pyc` sends these; the
	// answers are the ordinary command response plus an unsolicited
	// `Account.update(diff)` carrying the new balances.
	CmdExchange   = 202 // CMD_EXCHANGE      doCmdInt4(shopRev, gold, credits, 0)
	CmdFreeXPConv = 203 // CMD_FREE_XP_CONV doCmdIntArr([shopRev, xp, gold, ...vehCDs])
	CmdPremium    = 204 // CMD_PREMIUM       doCmdInt3(shopRev, days, arenaUniqueID)
	CmdBuySlot    = 205 // CMD_BUY_SLOT      doCmdInt3(shopRev, 0, 0)
	CmdBuyBerths  = 206 // CMD_BUY_BERTHS    doCmdInt3(shopRev, packs, 0)

	// The piggy bank's dev pair (`gui/game_control/wot_plus_controller.pyc`).
	// The live server smashes the bank from a service-channel push; a
	// private server has no such push, so the dev commands are the honest
	// path to the same state.
	CmdSetReservesPiggyBankDev = 10084 // doCmdInt2(credits, gold)
	CmdSmashPiggyBankDev       = 10088 // doCmdInt(6)

	// Squad invitations. The client sends CMD_INVITATION_SEND with
	// doCmdIntArrStrArr(cmd, accountsToInvite, [comment]) and answers an
	// invitation with doCmdInt3(cmd, invitationID, senderID, 0); the
	// receiving side gets Account.processInvitations.
	CmdInvitationAccept  = 10010
	CmdInvitationDecline = 10011
	CmdInvitationSend    = 10012
	// CmdReqQueueInfo is CMD_REQ_QUEUE_INFO: the client asks for the
	// matchmaker queue census and the server answers with the 1a/67
	// small, {players: <int>, classes: <tuple>}. Server-wide, not
	// per-account.
	CmdReqQueueInfo = 502

	// CmdReqBattleResults is CMD_REQ_BATTLE_RESULTS: the client asks for
	// the results of its last battle. The live server answers with the
	// 1a/5e error small (status 1) — there is nothing to report.
	CmdReqBattleResults = 1500
	CmdSyncDossiers     = 600 // CMD_SYNC_DOSSIERS

	// CmdEnqueueInBattleQueue is CMD_ENQUEUE_IN_BATTLE_QUEUE, sent
	// with doCmdIntArr as [QUEUE_TYPE.RANDOMS, vehInvID,
	// gameplaysMask, arenaTypeID, randomFlags]. 2.4.0.x carries five
	// ints; 2.4.1.0 drops the trailing randomFlags (four).
	CmdEnqueueInBattleQueue = 700

	// CmdDequeueFromBattleQueue is CMD_DEQUEUE_FROM_BATTLE_QUEUE: the
	// player leaves the queue. The live server answers with
	// Account.onDequeued(queueType).
	CmdDequeueFromBattleQueue = 701

	// Request IDs. The STREAM_ID_ACCOUNT_CMDS range is 200..30000
	// (shipped scripts/common/streamIDs.pyc); the reserved low IDs
	// are named in scripts/common/accountcommands.pyc as
	// STREAM_ID_ACCOUNT_CMDS_MIN + n.
	RequestIDPrebattles      = 200   // REQUEST_ID_PREBATTLES
	RequestIDPrebattleRoster = 201   // REQUEST_ID_PREBATTLE_ROSTER
	RequestIDNoResponse      = 202   // REQUEST_ID_NO_RESPONSE
	RequestIDNonClient       = 203   // REQUEST_ID_NON_CLIENT
	RequestIDUnreservedMin   = 220   // REQUEST_ID_UNRESERVED_MIN
	RequestIDUnreservedMax   = 30000 // REQUEST_ID_UNRESERVED_MAX

	// Chat command ordinals (shipped scripts/common/chat_shared.pyc
	// CHAT_COMMANDS declaration order: initAck first, then 21 more
	// entries before requestLastSysMessages).
	ChatCmdInitAck                = 0
	ChatCmdRequestLastSysMessages = 22
)
