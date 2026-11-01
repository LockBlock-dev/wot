package lobby

// Stage-2 lobby base-call builders (C>S, game-vector pinned Sep 27).
//
// Wire shape (genuine EU2 capture, decrypted with the login key):
// every C>S app bundle is [02][newkey u32 LE] (ServerConnection::
// primeBundle — the stage-1 rotation key on EVERY post-login bundle)
// followed by concatenated base calls, each
// [A1 u8][len u16 LE][args...], then channel [seq][cumul].
// A1 ALONE selects the method: it is the Mercury message ID =
// 136 + exposedID (baseEntityMethod range [136,254]; IDA init array
// at BaseAppExtInterface registration order: 16 fixed msgs 0..15,
// cellEntityMethod 16 with addRange portion 2 → cell [16,135],
// baseEntityMethod 136 with portion 1 → base [136,254]; engine
// ExposedMethodMessageRange math in
// programming/bigworld/lib/network/interface_minder.cpp +
// exposed_message_range.cpp). The u16 is the Mercury VARIABLE
// 2-byte payload length (= arg size on every observed vector), not a
// method index. Observed A1: 0x95 doCmdInt3 (rank13 → 149),
// 0x93 doCmdInt2 (rank11 → 147), 0x8a requestToken (rank2 → 138),
// 0x98 chatCommandFromClient (rank16 → 152), 0x9e doCmdIntArr.
// Ranks are the stable-size-sorted exposed index (fixed ascending,
// variable in declaration order, interfaces-first with first-wins
// name dedup — the own requestToken duplicate drops; engine
// entity_method_descriptions.cpp). No sub-IDs (max 39 exposed base
// methods on Account < 119 slots).
// Arg layouts come from entity_defs/interfaces/
// ClientCommandsPort.def (doCmdInt3(INT16,INT16,INT64,INT64,INT64),
// doCmdInt2(INT16,INT16,INT64,INT64),
// doCmdInt4(INT16,INT16,INT64,INT64,INT64,INT64),
// requestToken(UINT16,UINT8) per entity_defs/Account.def) and
// interfaces/Chat.def (chatCommandFromClient(INT64,UINT8,INT32,
// INT64,INT16,STRING,STRING) with packed-int string lengths per
// lib/cstdmf/binary_stream.hpp).
// Game vectors: 60B polls = doCmdInt3(202,501,0,0,0) (Account.py
// requestServerStats, every 5s); 148B opener = concatenated
// doCmdInt3(221,100,…)(222,300,…); 52B = doCmdInt2(225,121,…)
// (CMD_SET_ACTIVE_VEH_SEASON); first 36B = requestToken(1,1).
// Values here are caller-supplied; tests use synthetic args plus the
// fixed framing bytes (no session data in tree).

import (
	"encoding/binary"
)

const (
	// Base-call payload lengths (Mercury VARIABLE 2-byte header =
	// arg size; A1 alone selects the method).
	MsgDoCmdInt3 = 0x1c // 28B args
	MsgDoCmdInt4 = 0x24 // 36B args
	MsgDoCmdInt2 = 0x14 // A1 0x93, 20B args
	// MsgDoCmdIntArr is the observed 5-item payload length (0x19);
	// the builder writes the true length (see DoCmdIntArr).
	MsgDoCmdIntArr  = 0x19
	MsgRequestToken = 0x03 // A1 0x8a, args (UINT16, UINT8)

	// Kept aliases: the family constant equals the Int3 length.
	MsgDoCmdFamily = 0x1c

	// Broker token types (shipped scripts/common/constants.pyc
	// TOKEN_TYPE): the genuine opener requests XMPPCS first, then
	// WGNI_JWT inside the 68B poll bundle.
	TokenTypeXMPPCS  = 1
	TokenTypeWGNIJWT = 5

	// A1 method tags (Mercury IDs = 136 + exposed rank; codebook
	// above — one tag per method, no family sharing).
	A1DoCmdInt3    = 0x95 // rank13
	A1DoCmdInt4    = 0x97 // rank15 (UNOBSERVED, codebook-derived)
	A1DoCmdStr     = 0x9b // rank19 (OBSERVED Oct-05: doCmdStr gift claim, 52B UDP)
	A1DoCmdInt2    = 0x93 // rank11
	A1DoCmdIntArr  = 0x9e // rank22 (5-item call observed)
	A1RequestToken = 0x8a // rank2
	// A1DoCmdFamily aliases the Int3 tag (observed poll/sync
	// vector); Int4/Str have their own tags above.
	A1DoCmdFamily = 0x95
	// A1ChatCommandFromClient is Chat.chatCommandFromClient
	// (rank16 → 152): the sync-bundle tail, first variable-size
	// base method. Sole client sender is ClientChat.__baseChatCommand
	// (shipped ClientChat.pyc): (requestID INT64, command UINT8 =
	// CHAT_COMMANDS ordinal per chat_shared.pyc, channelID OBJECT_ID,
	// int64/int16 command extras, two STRING payloads). Game vectors:
	// (1,22,0,0,0,"","") = requestLastSysMessages (ordinal 22,
	// service-channel backlog pull via ServiceChannelManager on
	// LOBBY-scope switch), (2,0,0,2,0,"","") = initAck (ordinal 0)
	// for chat stream 2, decode OK.
	A1ChatCommandFromClient = 0x98
	// A1Tail9825 aliases the chat-command tag for the generic tail
	// framer below.
	A1Tail9825 = 0x98
)

// MsgTail9825 is the payload length of the sync-bundle tail (25B
// args → 0x19). Mercury VARIABLE framing carries the length, not a
// method index.
const MsgTail9825 = 0x19

// BuildTail9825 frames the 28B sync-bundle tail ([98][1900] + 25B
// args) verbatim. It is Chat.chatCommandFromClient — prefer the
// named builder; this generic framer stays for wire-faithful tests.
// Omitted from the v1 opener; structure only.
func BuildTail9825(args []byte) []byte {
	out := []byte{A1Tail9825}
	out = putU16(out, MsgTail9825)
	return append(out, args...)
}

// BuildChatCommandFromClient builds
// chatCommandFromClient(requestID INT64, command UINT8, channelID
// INT32/OBJECT_ID, int64Arg INT64, int16Arg INT16, s1, s2 STRING)
// app bytes (28B with empty strings). Sole client sender is
// ClientChat.__baseChatCommand (shipped ClientChat.pyc); command is
// the CHAT_COMMANDS ordinal (chat_shared.pyc: 22 =
// requestLastSysMessages, 0 = initAck). Strings use packed-int
// lengths (1 byte under 255 per lib/cstdmf/binary_stream.hpp), ints
// LE. Game vectors: the 148B opener tail = (1, 22, 0, 0, 0, "", "")
// (backlog pull), the 84B tail = (2, 0, 0, 2, 0, "", "") (ack of
// chat stream 2, decode OK).
func BuildChatCommandFromClient(a int64, b uint8, c int32, d int64, e int16, s1, s2 []byte) []byte {
	args := putI64(nil, a)
	args = append(args, b)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(c))
	args = append(args, tmp[:]...)
	args = putI64(args, d)
	args = putU16(args, uint16(e))
	args = putPackedStr(args, s1)
	args = putPackedStr(args, s2)
	out := []byte{A1ChatCommandFromClient}
	out = putU16(out, uint16(len(args)))
	return append(out, args...)
}

// putPackedStr appends a BigWorld string (packed-int length, 1 byte
// under 255, else 0xFF + 3 LE bytes).
func putPackedStr(b, s []byte) []byte {
	if len(s) >= 0xff {
		b = append(b, 0xff, byte(len(s)), byte(len(s)>>8), byte(len(s)>>16))
	} else {
		b = append(b, byte(len(s)))
	}
	return append(b, s...)
}

// putPackedCount appends a sequence count in BigWorld packed-int
// form (1 byte under 255, else 0xFF + 3 LE bytes — engine
// BinaryOStream::writePackedInt).
func putPackedCount(b []byte, n int) []byte {
	if n >= 0xff {
		return append(b, 0xff, byte(n), byte(n>>8), byte(n>>16))
	}
	return append(b, byte(n))
}

func putU16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func putI16(b []byte, v int16) []byte { return putU16(b, uint16(v)) }

func putI64(b []byte, v int64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(v))
	return append(b, tmp[:]...)
}

// sequenceIDHighBound is SequenceIDGenerator's default highBound
// (shipped scripts/common/ids_generators.pyc). The token and chat
// sequences both use the default 0..highBound range.
const sequenceIDHighBound = 32767

// RequestSequence mirrors helpers SequenceIDGenerator (shipped
// scripts/common/ids_generators.pyc): each Next increments, wrapping
// to the low bound at the high bound. Three independent sequences
// exist on the wire, and confusing them misattributes IDs:
//
//   - base calls allocate from the shared account repository, which
//     starts at RequestIDUnreservedMin and wraps at
//     RequestIDUnreservedMax (shipped Account.pyc
//     __getRequestID + common/AccountCommands.pyc). A fresh login's
//     first base calls are therefore 221, 222, 223, ... — the
//     "fixed" opener IDs are just the first allocations of a fixed
//     call order, not constants.
//   - requestToken calls allocate from TokenRequester's CLASS-level
//     generator (0..sequenceIDHighBound, shared across token types
//     AND with pre-lobby users), so the opener's token IDs depend on prior
//     in-session allocations (Oct-01: (1,1) then (2,5); Oct-05:
//     (3,1) then (4,5) after two earlier allocations).
//   - chat tails allocate from the per-ClientChat generator (also
//     0..sequenceIDHighBound), so the sync bundles' (1,22,…) then (2,0,0,2,0,…)
//     are its first two allocations.
type RequestSequence struct {
	cur   uint16
	max   uint16
	reset uint16
}

// next returns the next ID in the sequence.
func (s *RequestSequence) next() uint16 {
	s.cur++
	if s.cur >= s.max {
		s.cur = s.reset
	}
	return s.cur
}

// NewBaseRequestIDs starts the shared account-repository sequence
// (first allocation 221).
func NewBaseRequestIDs() *RequestSequence {
	return &RequestSequence{cur: RequestIDUnreservedMin, max: RequestIDUnreservedMax, reset: RequestIDUnreservedMin}
}

// NewTokenRequestIDs starts the shared TokenRequester sequence
// (first allocation 1).
func NewTokenRequestIDs() *RequestSequence {
	return &RequestSequence{cur: 0, max: sequenceIDHighBound, reset: 0}
}

// NewChatRequestIDs starts a ClientChat sequence (first allocation 1).
func NewChatRequestIDs() *RequestSequence {
	return &RequestSequence{cur: 0, max: sequenceIDHighBound, reset: 0}
}

// NextBaseID allocates one account-repository request ID.
func (s *RequestSequence) NextBaseID() uint16 { return s.next() }

// NextTokenID allocates one token-request ID.
func (s *RequestSequence) NextTokenID() uint16 { return s.next() }

// NextChatID allocates one chat-command request ID (INT64 on the wire).
func (s *RequestSequence) NextChatID() int64 { return int64(s.next()) }

// BuildBaseCall frames one base call: [A1][len u16 LE][args]
// (Mercury VARIABLE message; len must equal len(args)).
func BuildBaseCall(a1 byte, msg uint16, args []byte) []byte {
	out := []byte{a1}
	out = putU16(out, msg)
	return append(out, args...)
}

// DoCmdInt3 builds doCmdInt3(requestID, cmd, a, b, c) app bytes
// (31B). Game vector: (202, 501, 0, 0, 0) — the 5s server-stats poll.
func DoCmdInt3(reqID, cmd uint16, a, b, c int64) []byte {
	args := putI16(nil, int16(reqID))
	args = putI16(args, int16(cmd))
	args = putI64(args, a)
	args = putI64(args, b)
	args = putI64(args, c)
	return BuildBaseCall(A1DoCmdFamily, MsgDoCmdFamily, args)
}

// DoCmdInt2 builds doCmdInt2(requestID, cmd, a, b) app bytes (23B).
// Game vector family: (225, 121, …) = CMD_SET_ACTIVE_VEH_SEASON.
func DoCmdInt2(reqID, cmd uint16, a, b int64) []byte {
	args := putI16(nil, int16(reqID))
	args = putI16(args, int16(cmd))
	args = putI64(args, a)
	args = putI64(args, b)
	return BuildBaseCall(A1DoCmdInt2, MsgDoCmdInt2, args)
}

// DoCmdIntArr builds doCmdIntArr(requestID, cmd, vals) app bytes:
// (reqID u16, cmd u16, packed-int count, vals as INT32 LE).
// doCmdIntArr is ARRAY of INT32 with no <Size> → variable-size →
// packed-int count on the wire (engine sequence_data_type.cpp;
// 1 byte under 255, else 0xFF + 3 LE bytes). Game vector:
// enqueueRandom = (202, 700, [1=RANDOMS, vehInvID, gameplaysMask,
// arenaTypeID, randomFlags]) — the 52B battle-queue join (A1 0x9e,
// 25B args on the 5-item call).
func DoCmdIntArr(reqID, cmd uint16, vals []int32) []byte {
	args := putI16(nil, int16(reqID))
	args = putI16(args, int16(cmd))
	args = putPackedCount(args, len(vals))
	for _, v := range vals {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], uint32(v))
		args = append(args, tmp[:]...)
	}
	return BuildBaseCall(A1DoCmdIntArr, uint16(len(args)), args)
}

// DoCmdInt4 builds doCmdInt4(requestID, cmd, a, b, c, d) app bytes
// (39B). UNOBSERVED on the wire in 3 wired sessions (Sep-17, Sep-29
// ×2: every 68B there is Int3+token, never a 39B call) — the Sep-27
// attribution was likely an Int3+token misread. A1/len are
// codebook-derived (rank15 → 0x97, 36B → 0x24), not game-pinned;
// kept for the opener matrix, not fired.
func DoCmdInt4(reqID, cmd uint16, a, b, c, d int64) []byte {
	args := putI16(nil, int16(reqID))
	args = putI16(args, int16(cmd))
	args = putI64(args, a)
	args = putI64(args, b)
	args = putI64(args, c)
	args = putI64(args, d)
	return BuildBaseCall(A1DoCmdInt4, MsgDoCmdInt4, args)
}

// DoCmdStr builds doCmdStr(requestID, cmd, s) app bytes (STRING =
// packed-int length + bytes per lib/cstdmf/binary_stream.hpp).
// OBSERVED Oct-05 (genuine 52B shop gift-claim: requestID allocates
// from the base sequence, cmd is an AccountCommands ID, s is a JSON
// payload).
func DoCmdStr(reqID, cmd uint16, s []byte) []byte {
	args := putI16(nil, int16(reqID))
	args = putI16(args, int16(cmd))
	args = putPackedStr(args, s)
	return BuildBaseCall(A1DoCmdStr, uint16(len(args)), args)
}

// BuildRequestToken builds requestToken(requestID, tokenType) app
// bytes (5B). Game vector: (1, 1) right after the sync opener.
func BuildRequestToken(reqID uint16, tokenType uint8) []byte {
	args := putU16(nil, reqID)
	args = append(args, tokenType)
	return BuildBaseCall(A1RequestToken, MsgRequestToken, args)
}

// BuildLobbyBundle prefixes concatenated base calls with the
// primeBundle auth ([02][newkey]) for one channel packet's app.
func BuildLobbyBundle(newKey uint32, calls ...[]byte) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], newKey)
	out := append([]byte{0x02}, tmp[:]...)
	for _, c := range calls {
		out = append(out, c...)
	}
	return out
}
