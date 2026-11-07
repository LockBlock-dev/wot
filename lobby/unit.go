package lobby

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// Squad/platoon wire codec.
//
// The client's unit manager (`client_common/ClientUnitMgr.pyc`) is a thin
// RPC layer: every action is `account.base.accountUnitClient_<method>`
// and every answer is `Account.onUnitUpdate(unitMgrID, packedUnit,
// packedOps)`, where both blobs are the client's own binary format from
// `common/UnitBase.pyc` (`UnitBase.pack`) and `common/ops_pack.pyc`.
// There is no pickling in the unit path — the layouts below are the
// client's `struct.pack` format strings, reproduced field for field.
//
//	_IDS                     '<IBB'   rosterType u32, extrasHandler u8, prebattleType u8
//	roster                   u8 slotCount, then per slot: u8 idx + slot
//	  slot (mask form)       u8 vehClassMask, u16 nationMask, u8 levelMask
//	  slot (exact form)      0x00, u16 vehTypeCompDescr
//	  limits                 u16 mask, then the set limits in _ROSTER_LIMIT_NAMES order
//	_HEADER                  '<HHHHHHHHBiiiiii'
//	_PLAYER_VEHICLES_LIST    '<qH'    accountDBID i64, count u16
//	_PLAYER_VEHICLE_TUPLE    '<iI'    vehInvID i32, vehTypeCompDescr u32
//	_SLOT_PLAYERS            '<Bq'    slotIdx u8, accountDBID i64
//	_PLAYER_DATA             '<qiIHBHHHq?'
//	_VEHICLE_PROFILE_HEADER  '<qBBII'
//	_PLAYER_SEARCH_FLAGS     '<qH'
//	pascal string            u16 length + utf8 bytes
//
// The ops blob is `[opCode u8][args]`, with the per-op argument formats
// from `UnitBase._opsFormatDefs`.

// Unit roster types (ROSTER_TYPE in common/UnitBase.pyc). The squad
// roster is the one the random-battle platoon uses.
const (
	RosterTypeUnit      uint32 = 0
	RosterTypeSquad     uint32 = 64
	RosterTypeSpec      uint32 = 128
	RosterTypeEvent     uint32 = 64 | 4096
	RosterTypeEpic      uint32 = 64 | 8192
	RosterTypeMapBox    uint32 = 64 | 16384
	RosterTypeStronghol uint32 = 32768
)

// Extras handler types (EXTRAS_HANDLER_TYPE).
const (
	ExtrasEmpty  uint8 = 0
	ExtrasSquad  uint8 = 4
	ExtrasSpec   uint8 = 5
	ExtrasExtern uint8 = 6
)

// Prebattle types (PREBATTLE_TYPE in common/constants.pyc).
const (
	PrebattleNone   uint8 = 0
	PrebattleSquad  uint8 = 1
	PrebattleUnit   uint8 = 6
	PrebattleEvent  uint8 = 11
	PrebattleEpic   uint8 = 15
	PrebattleMapBox uint8 = 19
)

// Unit flags (UNIT_FLAGS).
const (
	UnitFlagLocked      uint16 = 1
	UnitFlagInviteOnly  uint16 = 2
	UnitFlagInQueue     uint16 = 4
	UnitFlagInSearch    uint16 = 8
	UnitFlagDevMode     uint16 = 16
	UnitFlagInArena     uint16 = 32
	UnitFlagDynamic     uint16 = 1024
	UnitFlagFinishAssem uint16 = 16384
)

// Unit roles (UNIT_ROLE). The client packs the role into a u16, so only
// the low bits survive the wire — mirror that rather than inventing a
// wider field.
const (
	UnitRoleDefault   uint16 = 0
	UnitRoleInvited   uint16 = 1
	UnitRoleCommander uint16 = 2
	UnitRoleChangeRos uint16 = 4
	UnitRoleLegionary uint16 = 16
	UnitRoleManager   uint16 = 32
	UnitRoleInArena   uint16 = 64
	UnitRoleOffline   uint16 = 128
	UnitRoleCanLead   uint16 = 256
	UnitRoleCreator   uint16 = UnitRoleCommander | UnitRoleChangeRos
)

// Unit ops (UNIT_OP).
const (
	UnitOpSetVehicle        uint8 = 1
	UnitOpSetMember         uint8 = 2
	UnitOpDelMember         uint8 = 3
	UnitOpAddPlayer         uint8 = 4
	UnitOpRemovePlayer      uint8 = 5
	UnitOpReadyMask         uint8 = 6
	UnitOpSetSlot           uint8 = 7
	UnitOpClearVehicle      uint8 = 8
	UnitOpVehicleDict       uint8 = 9
	UnitOpUnitFlags         uint8 = 10
	UnitOpCloseSlot         uint8 = 11
	UnitOpOpenSlot          uint8 = 12
	UnitOpSetComment        uint8 = 13
	UnitOpChangeRole        uint8 = 14
	UnitOpModalTimestamp    uint8 = 15
	UnitOpGiveLeadership    uint8 = 16
	UnitOpExtrasUpdate      uint8 = 18
	UnitOpExtrasReset       uint8 = 19
	UnitOpGameplaysMask     uint8 = 20
	UnitOpSetVehicleList    uint8 = 21
	UnitOpArenaType         uint8 = 23
	UnitOpSetPlayerProfile  uint8 = 24
	UnitOpDelPlayerProfile  uint8 = 25
	UnitOpEstimatedTime     uint8 = 26
	UnitOpRandomFlags       uint8 = 27
	UnitOpClearSearchFlags  uint8 = 28
	UnitOpRemoveSearchFlags uint8 = 29
	UnitOpSetSearchFlags    uint8 = 30
	UnitOpSquadSize         uint8 = 31
)

// Client unit commands (CLIENT_UNIT_CMD) — the `cmd` argument of
// accountUnitClient_doCmd.
const (
	UnitCmdNone             uint8 = 0
	UnitCmdLeaveUnit        uint8 = 1
	UnitCmdStartUnitBattle  uint8 = 2
	UnitCmdStopUnitBattle   uint8 = 3
	UnitCmdStartAutoSearch  uint8 = 4
	UnitCmdStopAutoSearch   uint8 = 5
	UnitCmdSetUnitMember    uint8 = 6
	UnitCmdSetUnitVehicle   uint8 = 7
	UnitCmdFitUnitMember    uint8 = 8
	UnitCmdAssignUnitMember uint8 = 9
	UnitCmdReassignUnitMem  uint8 = 10
	UnitCmdSetUnitMemberRdy uint8 = 11
	UnitCmdKickUnitPlayer   uint8 = 12
	UnitCmdLockUnit         uint8 = 13
	UnitCmdOpenUnit         uint8 = 14
	UnitCmdCloseUnitSlot    uint8 = 15
	UnitCmdSetRosterSlot    uint8 = 16
	UnitCmdSetUnitComment   uint8 = 17
	UnitCmdSetUnitDevMode   uint8 = 18
	UnitCmdGiveLeadership   uint8 = 19
	UnitCmdSetGameplaysMask uint8 = 22
	UnitCmdSetVehicleList   uint8 = 23
	UnitCmdSetUnitVehType   uint8 = 25
	UnitCmdSetArenaType     uint8 = 26
	UnitCmdSetRandomFlags   uint8 = 30
)

// Unit notify codes (UNIT_NOTIFY_CMD) — the `notifyCode` of
// Account.onUnitNotify.
const (
	UnitNotifySetVehicleList   uint8 = 1
	UnitNotifyPlayerOnline     uint8 = 2
	UnitNotifyTransferLeader   uint8 = 3
	UnitNotifyPublishState     uint8 = 4
	UnitNotifySetMemberReady   uint8 = 5
	UnitNotifyKickAll          uint8 = 6
	UnitNotifyExtrasUpdated    uint8 = 7
	UnitNotifyChangeSquadSize  uint8 = 19
	UnitNotifyPlayerLimitsExp  uint8 = 20
	UnitNotifyRemovedFromSquad uint8 = 21
)

// Unit errors (UNIT_ERROR). OK is the only one a working server sends.
const (
	UnitErrorOK uint8 = 0
)

// UnitPlayer is one squad member as the packed unit carries it.
type UnitPlayer struct {
	AccountDBID int64
	// AccountID is the client's `accountID` field (the DBID again on
	// this server).
	AccountID int64
	// TimeJoin is the unix time the player joined.
	TimeJoin uint32
	// Role is a UNIT_ROLE bit set.
	Role uint16
	// IGRType, Rating, AccountWTR and PeripheryID are the client's
	// remaining scalar fields; zero is valid for all of them.
	IGRType     uint8
	Rating      uint16
	AccountWTR  uint16
	PeripheryID uint16
	// ClanDBID and ClanAbbrev are shown next to the name.
	ClanDBID   int64
	ClanAbbrev string
	// IsPremium draws the premium marker.
	IsPremium bool
	// NickName is the display name.
	NickName string
}

// UnitVehicle is one vehicle a player brought to the squad.
type UnitVehicle struct {
	InvID         int32
	TypeCompDescr uint32
}

// UnitSlot is one roster slot. A zero TypeCompDescr means the slot is a
// mask slot (class/nation/level filters); otherwise it pins one vehicle
// type.
type UnitSlot struct {
	TypeCompDescr uint32
	VehClassMask  uint8
	NationMask    uint16
	LevelMask     uint8
}

// Unit is one squad/platoon.
type Unit struct {
	// ID is the unit manager id the client keys everything by.
	ID uint64
	// RosterType, ExtrasHandler and PrebattleType are the three ids the
	// packed blob starts with.
	RosterType    uint32
	ExtrasHandler uint8
	PrebattleType uint8

	// Slots is the roster, in slot order.
	Slots []UnitSlot
	// Limits is the roster's limits mask (0 = no limits).
	Limits uint16

	// Members maps a roster slot index to the account in it.
	Members map[uint8]int64
	// Players is the per-account data.
	Players map[int64]UnitPlayer
	// Vehicles is the per-account vehicle list.
	Vehicles map[int64][]UnitVehicle

	ReadyMask            uint16
	Flags                uint16
	ClosedSlotMask       uint8
	ModalTimestamp       int32
	EstimatedTimeInQueue int32
	GameplaysMask        int32
	ArenaType            int32
	SquadSize            int32
	RandomFlags          int32
	Comment              string
}

// NewSquadUnit returns an empty squad: three roster slots, the squad
// roster type and the squad extras handler, which is what the random
// battle platoon uses (`unit_roster_config.SquadRoster.MAX_SLOTS = 3`).
func NewSquadUnit(id uint64) *Unit {
	u := &Unit{
		ID:            id,
		RosterType:    RosterTypeSquad,
		ExtrasHandler: ExtrasSquad,
		PrebattleType: PrebattleSquad,
		Members:       map[uint8]int64{},
		Players:       map[int64]UnitPlayer{},
		Vehicles:      map[int64][]UnitVehicle{},
	}
	for i := 0; i < 3; i++ {
		// SquadRoster.SLOT_TYPE is RosterSlot11: levels 1..11, no class
		// or nation filter, so the mask is all zeros with the level
		// range packed into the nibbles.
		u.Slots = append(u.Slots, UnitSlot{LevelMask: 0x0a})
	}
	return u
}

// AddPlayer seats a player in the first free slot and returns the slot.
func (u *Unit) AddPlayer(p UnitPlayer) (uint8, bool) {
	for i := 0; i < len(u.Slots); i++ {
		slot := uint8(i)
		if _, taken := u.Members[slot]; taken {
			continue
		}
		u.Members[slot] = p.AccountDBID
		u.Players[p.AccountDBID] = p
		return slot, true
	}
	return 0, false
}

// RemovePlayer drops a player and frees the slot.
func (u *Unit) RemovePlayer(dbid int64) bool {
	for slot, member := range u.Members {
		if member == dbid {
			delete(u.Members, slot)
			delete(u.Players, dbid)
			delete(u.Vehicles, dbid)
			u.ReadyMask &^= 1 << slot
			return true
		}
	}
	return false
}

// SlotOf returns the roster slot a player occupies, or -1.
func (u *Unit) SlotOf(dbid int64) int {
	for slot, member := range u.Members {
		if member == dbid {
			return int(slot)
		}
	}
	return -1
}

// SetReady marks one player ready or not.
func (u *Unit) SetReady(dbid int64, ready bool) {
	slot := u.SlotOf(dbid)
	if slot < 0 {
		return
	}
	if ready {
		u.ReadyMask |= 1 << uint(slot)
	} else {
		u.ReadyMask &^= 1 << uint(slot)
	}
}

// PackUnit renders the unit blob the client's `ClientUnit(packedUnit=…)`
// constructor reads.
func PackUnit(u *Unit) []byte {
	var b bytes.Buffer
	unitPutU32(&b, u.RosterType)
	b.WriteByte(u.ExtrasHandler)
	b.WriteByte(u.PrebattleType)

	// Roster: slot count, then each (index, slot), then the limits.
	b.WriteByte(byte(len(u.Slots)))
	for i, slot := range u.Slots {
		b.WriteByte(byte(i))
		if slot.TypeCompDescr != 0 {
			b.WriteByte(0x00)
			unitPutU16(&b, uint16(slot.TypeCompDescr))
			continue
		}
		b.WriteByte(slot.VehClassMask)
		unitPutU16(&b, slot.NationMask)
		b.WriteByte(slot.LevelMask)
	}
	unitPutU16(&b, u.Limits)

	// Header: eight u16, one u8, six i32.
	unitPutU16(&b, uint16(len(u.Members)))
	unitPutU16(&b, uint16(len(u.Vehicles)))
	unitPutU16(&b, uint16(len(u.Players)))
	unitPutU16(&b, 0) // profile vehicles
	unitPutU16(&b, 0) // search flags
	unitPutU16(&b, 0) // extras length
	unitPutU16(&b, u.ReadyMask)
	unitPutU16(&b, u.Flags)
	b.WriteByte(u.ClosedSlotMask)
	unitPutI32(&b, u.ModalTimestamp)
	unitPutI32(&b, u.EstimatedTimeInQueue)
	unitPutI32(&b, u.GameplaysMask)
	unitPutI32(&b, u.ArenaType)
	unitPutI32(&b, u.SquadSize)
	unitPutI32(&b, u.RandomFlags)

	// Vehicles, in account order so the blob is deterministic.
	for _, dbid := range sortedKeys(u.Vehicles) {
		vehs := u.Vehicles[dbid]
		unitPutI64(&b, dbid)
		unitPutU16(&b, uint16(len(vehs)))
		for _, v := range vehs {
			unitPutI32(&b, v.InvID)
			unitPutU32(&b, v.TypeCompDescr)
		}
	}
	// Members, in slot order.
	for _, slot := range sortedSlots(u.Members) {
		b.WriteByte(slot)
		unitPutI64(&b, u.Members[slot])
	}
	// Players, in account order.
	for _, dbid := range sortedKeys(u.Players) {
		packPlayer(&b, u.Players[dbid])
	}
	// The trailing comment.
	unitPutPascal(&b, u.Comment)
	return b.Bytes()
}

// packPlayer renders one `_PLAYER_DATA` record plus its trailing
// pascal strings, badges and pickled extra data.
func packPlayer(b *bytes.Buffer, p UnitPlayer) {
	unitPutI64(b, p.AccountDBID)
	unitPutI32(b, int32(p.AccountID))
	unitPutU32(b, p.TimeJoin)
	unitPutU16(b, p.Role)
	b.WriteByte(p.IGRType)
	unitPutU16(b, p.Rating)
	unitPutU16(b, p.AccountWTR)
	unitPutU16(b, p.PeripheryID)
	unitPutI64(b, p.ClanDBID)
	if p.IsPremium {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	unitPutPascal(b, p.NickName)
	unitPutPascal(b, p.ClanAbbrev)
	// BadgesCommon.packPlayerBadges(([], [])): two zero length bytes.
	b.WriteByte(0)
	b.WriteByte(0)
	// The extra-data dict is a pickled empty dict, itself pascal-framed.
	unitPutPascal(b, string(emptyPickleDict))
}

// emptyPickleDict is `pickle.dumps({}, -1)`: PROTO 2, EMPTY_DICT, STOP.
var emptyPickleDict = []byte{0x80, 0x02, 0x7d, 0x71, 0x00, 0x2e}

// PackOps renders an ops blob from already-encoded ops.
func PackOps(ops ...[]byte) []byte {
	var out []byte
	for _, op := range ops {
		out = append(out, op...)
	}
	return out
}

// OpAddPlayer is UNIT_OP.ADD_PLAYER: the opcode then the packed player.
func OpAddPlayer(p UnitPlayer) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpAddPlayer)
	packPlayer(&b, p)
	return b.Bytes()
}

// OpRemovePlayer is UNIT_OP.REMOVE_PLAYER: the opcode then the account.
func OpRemovePlayer(dbid int64) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpRemovePlayer)
	unitPutI64(&b, dbid)
	return b.Bytes()
}

// OpSetMember is UNIT_OP.SET_MEMBER: account, slot.
func OpSetMember(dbid int64, slot uint8) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpSetMember)
	unitPutI64(&b, dbid)
	b.WriteByte(slot)
	return b.Bytes()
}

// OpDelMember is UNIT_OP.DEL_MEMBER: slot.
func OpDelMember(slot uint8) []byte {
	return []byte{UnitOpDelMember, slot}
}

// OpReadyMask is UNIT_OP.READY_MASK: the new mask.
func OpReadyMask(mask uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpReadyMask)
	unitPutU16(&b, mask)
	return b.Bytes()
}

// OpUnitFlags is UNIT_OP.UNIT_FLAGS: the new flags.
func OpUnitFlags(flags uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpUnitFlags)
	unitPutU16(&b, flags)
	return b.Bytes()
}

// OpChangeRole is UNIT_OP.CHANGE_ROLE: account, role.
func OpChangeRole(dbid int64, role uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpChangeRole)
	unitPutI64(&b, dbid)
	unitPutU16(&b, role)
	return b.Bytes()
}

// OpSetComment is UNIT_OP.SET_COMMENT: a pascal string.
func OpSetComment(text string) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpSetComment)
	unitPutPascal(&b, text)
	return b.Bytes()
}

// OpSetVehicleList is UNIT_OP.SET_VEHICLE_LIST: account, count, then
// (invID, compDescr) pairs.
func OpSetVehicleList(dbid int64, vehs []UnitVehicle) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpSetVehicleList)
	unitPutI64(&b, dbid)
	unitPutU16(&b, uint16(len(vehs)))
	for _, v := range vehs {
		unitPutI32(&b, v.InvID)
		unitPutU32(&b, v.TypeCompDescr)
	}
	return b.Bytes()
}

// OpClearVehicle is UNIT_OP.CLEAR_VEHICLE: account.
func OpClearVehicle(dbid int64) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpClearVehicle)
	unitPutI64(&b, dbid)
	return b.Bytes()
}

// OpSquadSize is UNIT_OP.SQUAD_SIZE.
func OpSquadSize(size int32) []byte {
	var b bytes.Buffer
	b.WriteByte(UnitOpSquadSize)
	unitPutI32(&b, size)
	return b.Bytes()
}

// putPascal writes a u16 length followed by the utf8 bytes.
func unitPutPascal(b *bytes.Buffer, s string) {
	if len(s) > 65535 {
		s = s[:65535]
	}
	unitPutU16(b, uint16(len(s)))
	b.WriteString(s)
}

func unitPutU16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func unitPutU32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func unitPutI32(b *bytes.Buffer, v int32) { unitPutU32(b, uint32(v)) }

func unitPutI64(b *bytes.Buffer, v int64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(v))
	b.Write(tmp[:])
}

// sortedKeys returns a map's int64 keys in ascending order.
func sortedKeys[V any](m map[int64]V) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sortedSlots returns a slot map's keys in ascending order.
func sortedSlots(m map[uint8]int64) []uint8 {
	out := make([]uint8, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// UnitCmdName returns the shipped CLIENT_UNIT_CMD name, for logs.
func UnitCmdName(cmd uint8) string {
	if n, ok := unitCmdNames[cmd]; ok {
		return n
	}
	return fmt.Sprintf("cmd %d", cmd)
}

var unitCmdNames = map[uint8]string{
	UnitCmdNone:             "NONE",
	UnitCmdLeaveUnit:        "LEAVE_UNIT",
	UnitCmdStartUnitBattle:  "START_UNIT_BATTLE",
	UnitCmdStopUnitBattle:   "STOP_UNIT_BATTLE",
	UnitCmdStartAutoSearch:  "START_AUTO_SEARCH",
	UnitCmdStopAutoSearch:   "STOP_AUTO_SEARCH",
	UnitCmdSetUnitMember:    "SET_UNIT_MEMBER",
	UnitCmdSetUnitVehicle:   "SET_UNIT_VEHICLE",
	UnitCmdFitUnitMember:    "FIT_UNIT_MEMBER",
	UnitCmdAssignUnitMember: "ASSIGN_UNIT_MEMBER",
	UnitCmdReassignUnitMem:  "REASSIGN_UNIT_MEMBER",
	UnitCmdSetUnitMemberRdy: "SET_UNIT_MEMBER_READY",
	UnitCmdKickUnitPlayer:   "KICK_UNIT_PLAYER",
	UnitCmdLockUnit:         "LOCK_UNIT",
	UnitCmdOpenUnit:         "OPEN_UNIT",
	UnitCmdCloseUnitSlot:    "CLOSE_UNIT_SLOT",
	UnitCmdSetRosterSlot:    "SET_ROSTER_SLOT",
	UnitCmdSetUnitComment:   "SET_UNIT_COMMENT",
	UnitCmdSetUnitDevMode:   "SET_UNIT_DEV_MODE",
	UnitCmdGiveLeadership:   "GIVE_LEADERSHIP",
	UnitCmdSetGameplaysMask: "SET_GAMEPLAYS_MASK",
	UnitCmdSetVehicleList:   "SET_VEHICLE_LIST",
	UnitCmdSetUnitVehType:   "SET_UNIT_VEHICLE_TYPE",
	UnitCmdSetArenaType:     "SET_ARENA_TYPE",
	UnitCmdSetRandomFlags:   "SET_RANDOM_FLAGS",
}
