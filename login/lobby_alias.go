package login

// Lobby application-layer aliases (package split, Oct 2026).
//
// Canonical home of the offline lobby/battle application parsing is
// the lobby package (cPickle decoder, bundle salvage, C>S base-call
// builders, avatar parser — all stdlib-only, no transport). These
// aliases keep every existing login caller (stage scripts, flood
// census, CLIs, tests) compiling unchanged while new code imports
// lobby directly. Wire output is unaffected: same functions, new
// address.
import "github.com/LockBlock-dev/wot/lobby"

// Bulk-chunk datum (defined in lobby, aliased here for flood.go and
// its callers).
type Frag = lobby.Frag

// Pickle decoder surface.
type (
	PList        = lobby.PList
	PTuple       = lobby.PTuple
	PEntry       = lobby.PEntry
	PDict        = lobby.PDict
	PSet         = lobby.PSet
	Deque        = lobby.Deque
	GenericValue = lobby.GenericValue
	DocSeg       = lobby.DocSeg
)

var (
	DecodePrefix      = lobby.DecodePrefix
	DecodeLobbyPickle = lobby.DecodeLobbyPickle
	DecodeAt          = lobby.DecodeAt
	Inventory         = lobby.Inventory
	DecodeBundle      = lobby.DecodeBundle
	DecodeOne         = lobby.DecodeOne
	HarvestKeys       = lobby.HarvestKeys
	HarvestStream     = lobby.HarvestStream
	PickleSummary     = lobby.PickleSummary
)

// Lobby-state surface.
type LobbyBundle = lobby.LobbyBundle

var (
	PlainValue   = lobby.PlainValue
	SalvageChunk = lobby.SalvageChunk
)

// Base-call builder surface.
const (
	MsgDoCmdInt3            = lobby.MsgDoCmdInt3
	MsgDoCmdInt4            = lobby.MsgDoCmdInt4
	MsgDoCmdInt2            = lobby.MsgDoCmdInt2
	MsgDoCmdIntArr          = lobby.MsgDoCmdIntArr
	MsgRequestToken         = lobby.MsgRequestToken
	MsgDoCmdFamily          = lobby.MsgDoCmdFamily
	A1DoCmdInt3             = lobby.A1DoCmdInt3
	A1DoCmdInt4             = lobby.A1DoCmdInt4
	A1DoCmdStr              = lobby.A1DoCmdStr
	A1DoCmdInt2             = lobby.A1DoCmdInt2
	A1DoCmdIntArr           = lobby.A1DoCmdIntArr
	A1RequestToken          = lobby.A1RequestToken
	A1DoCmdFamily           = lobby.A1DoCmdFamily
	A1ChatCommandFromClient = lobby.A1ChatCommandFromClient
	A1Tail9825              = lobby.A1Tail9825
	MsgTail9825             = lobby.MsgTail9825
)

var (
	BuildTail9825              = lobby.BuildTail9825
	BuildChatCommandFromClient = lobby.BuildChatCommandFromClient
	BuildBaseCall              = lobby.BuildBaseCall
	DoCmdInt3                  = lobby.DoCmdInt3
	DoCmdInt2                  = lobby.DoCmdInt2
	DoCmdIntArr                = lobby.DoCmdIntArr
	DoCmdInt4                  = lobby.DoCmdInt4
	DoCmdStr                   = lobby.DoCmdStr
	BuildRequestToken          = lobby.BuildRequestToken
	BuildLobbyBundle           = lobby.BuildLobbyBundle
)

// Battle parser surface.
type AvatarUpdate = lobby.AvatarUpdate

const (
	BattleC2SHead0    = lobby.BattleC2SHead0
	BattleC2SHead1    = lobby.BattleC2SHead1
	BattleC2SHead2    = lobby.BattleC2SHead2
	BattleC2SHead3    = lobby.BattleC2SHead3
	BattleSubPosition = lobby.BattleSubPosition
	BattlePosOff      = lobby.BattlePosOff
	BattlePosLen      = lobby.BattlePosLen
)

var ParseAvatarUpdate = lobby.ParseAvatarUpdate

// Vehicle descr surface (structural, table-free).
type CompactSections = lobby.CompactSections

var (
	ParseIntDescr       = lobby.ParseIntDescr
	NationName          = lobby.NationName
	SectionCompactDescr = lobby.SectionCompactDescr
)
