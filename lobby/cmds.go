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
	CmdSyncDossiers       = 600 // CMD_SYNC_DOSSIERS

	// CmdEnqueueInBattleQueue is CMD_ENQUEUE_IN_BATTLE_QUEUE, sent
	// with doCmdIntArr as [QUEUE_TYPE.RANDOMS, vehInvID,
	// gameplaysMask, arenaTypeID, randomFlags]. 2.4.0.x carries five
	// ints; 2.4.1.0 drops the trailing randomFlags (four).
	CmdEnqueueInBattleQueue = 700

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
