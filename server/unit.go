package server

import (
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
)

// UnitManager owns the squads (the client's "dynamic squads").
//
// The client's unit manager is a thin RPC layer over the Account entity:
// `accountUnitClient_create/join/doCmd/sendInvites/setRosterSlots` in,
// `Account.onUnitUpdate(unitMgrID, packedUnit, packedOps)` out. This type
// is the state behind those calls — one squad per account, three roster
// slots, the ready mask and the comment — and it implements
// login.UnitBackend, so the wire layer never sees the model.
//
// It is in-memory on purpose: a squad is a live session object, not
// account state. A server restart drops every squad, which is what the
// client expects (it re-creates one from the hangar).
type UnitManager struct {
	mu        sync.Mutex
	nextID    uint64
	units     map[uint64]*lobby.Unit
	byAccount map[int64]uint64
	// invites holds the pending squad invitations per invited account.
	invites map[int64][]UnitInvite
}

// UnitInvite is one pending squad invitation.
type UnitInvite struct {
	UnitID   uint64
	FromDBID int64
	FromName string
	Comment  string
	Created  time.Time
}

// NewUnitManager returns an empty manager.
func NewUnitManager() *UnitManager {
	return &UnitManager{
		nextID:    1,
		units:     map[uint64]*lobby.Unit{},
		byAccount: map[int64]uint64{},
		invites:   map[int64][]UnitInvite{},
	}
}

// Create makes a squad with the creator in slot 0.
//
// `prebattleType` is the client's PREBATTLE_TYPE (1 = squad, 6 = unit,
// 15 = epic, 19 = mapbox); the roster type follows it, because the client
// picks the roster class from the packed blob's first field.
func (m *UnitManager) Create(p lobby.UnitPlayer, prebattleType uint8) (uint64, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// One squad per account: creating again replaces the old one.
	if old, ok := m.byAccount[p.AccountDBID]; ok {
		delete(m.units, old)
	}
	id := m.nextID
	m.nextID++
	u := lobby.NewSquadUnit(id)
	u.PrebattleType = prebattleType
	switch prebattleType {
	case lobby.PrebattleEpic:
		u.RosterType = lobby.RosterTypeEpic
		u.ExtrasHandler = lobby.ExtrasEmpty
	case lobby.PrebattleMapBox:
		u.RosterType = lobby.RosterTypeMapBox
		u.ExtrasHandler = lobby.ExtrasEmpty
	case lobby.PrebattleEvent:
		u.RosterType = lobby.RosterTypeEvent
		u.ExtrasHandler = lobby.ExtrasEmpty
	}
	p.Role = lobby.UnitRoleCreator
	p.TimeJoin = uint32(time.Now().Unix())
	u.AddPlayer(p)
	m.units[id] = u
	m.byAccount[p.AccountDBID] = id
	return id, lobby.PackUnit(u), true
}

// Join seats an account in a squad. ok is false when the squad does not
// exist or is full.
func (m *UnitManager) Join(p lobby.UnitPlayer, unitID uint64) (uint64, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.units[unitID]
	if !ok {
		return 0, nil, false
	}
	if old, ok := m.byAccount[p.AccountDBID]; ok && old != unitID {
		if prev := m.units[old]; prev != nil {
			prev.RemovePlayer(p.AccountDBID)
			if len(prev.Members) == 0 {
				delete(m.units, old)
			}
		}
	}
	p.Role = lobby.UnitRoleDefault
	p.TimeJoin = uint32(time.Now().Unix())
	if _, ok := u.AddPlayer(p); !ok {
		return 0, nil, false
	}
	m.byAccount[p.AccountDBID] = unitID
	delete(m.invites, p.AccountDBID)
	return unitID, lobby.PackUnit(u), true
}

// Leave removes an account from its squad. ok is false when it was in
// none; the unit is deleted once it is empty.
func (m *UnitManager) Leave(dbid int64) (uint64, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAccount[dbid]
	if !ok {
		return 0, nil, false
	}
	delete(m.byAccount, dbid)
	u := m.units[id]
	if u == nil {
		return 0, nil, false
	}
	u.RemovePlayer(dbid)
	if len(u.Members) == 0 {
		delete(m.units, id)
	}
	return id, lobby.PackUnit(u), true
}

// DoCmd applies one CLIENT_UNIT_CMD and returns the resulting unit.
func (m *UnitManager) DoCmd(dbid int64, unitID uint64, cmd uint8, arg64 uint64, arg32 int32, argStr string) (uint64, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAccount[dbid]
	if !ok || (unitID != 0 && unitID != id) {
		return 0, nil, false
	}
	u := m.units[id]
	if u == nil {
		return 0, nil, false
	}
	switch cmd {
	case lobby.UnitCmdLeaveUnit:
		delete(m.byAccount, dbid)
		u.RemovePlayer(dbid)
		if len(u.Members) == 0 {
			delete(m.units, id)
		}
	case lobby.UnitCmdSetUnitMemberRdy:
		u.SetReady(dbid, arg64 != 0)
	case lobby.UnitCmdSetUnitVehicle:
		// arg64 is the vehicle inventory id, arg32 the "set ready too"
		// flag. The vehicle TYPE is not on the wire here, so the squad
		// shows the inventory id only — the client resolves the type
		// from its own garage.
		if arg64 == 0 {
			delete(u.Vehicles, dbid)
		} else {
			u.Vehicles[dbid] = []lobby.UnitVehicle{{InvID: int32(arg64)}}
		}
		if arg32 != 0 {
			u.SetReady(dbid, true)
		}
	case lobby.UnitCmdSetUnitComment:
		u.Comment = argStr
	case lobby.UnitCmdLockUnit:
		if arg64 != 0 {
			u.Flags |= lobby.UnitFlagLocked
		} else {
			u.Flags &^= lobby.UnitFlagLocked
		}
	case lobby.UnitCmdOpenUnit:
		u.Flags &^= lobby.UnitFlagLocked
	case lobby.UnitCmdKickUnitPlayer:
		target := int64(arg64)
		if m.byAccount[target] == id {
			delete(m.byAccount, target)
			u.RemovePlayer(target)
		}
	case lobby.UnitCmdGiveLeadership:
		target := int64(arg64)
		if m.byAccount[target] == id {
			for other, p := range u.Players {
				if other == target {
					p.Role = lobby.UnitRoleCreator
				} else {
					p.Role = lobby.UnitRoleDefault
				}
				u.Players[other] = p
			}
		}
	case lobby.UnitCmdSetGameplaysMask:
		u.GameplaysMask = arg32
	case lobby.UnitCmdSetArenaType:
		u.ArenaType = arg32
	case lobby.UnitCmdSetRandomFlags:
		u.RandomFlags = arg32
	case lobby.UnitCmdStartUnitBattle, lobby.UnitCmdStopUnitBattle,
		lobby.UnitCmdStartAutoSearch, lobby.UnitCmdStopAutoSearch:
		// Queueing a squad is the matchmaker's job (see TODO.md #2); the
		// unit state itself does not change, so the answer is the unit
		// as it stands.
	}
	return id, lobby.PackUnit(u), true
}

// Invite records a pending invitation for each target and returns the
// squad.
func (m *UnitManager) Invite(dbid int64, unitID uint64, targets []int64, comment string) (uint64, []byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAccount[dbid]
	if !ok || (unitID != 0 && unitID != id) {
		return 0, nil, false
	}
	u := m.units[id]
	if u == nil {
		return 0, nil, false
	}
	from := u.Players[dbid].NickName
	for _, target := range targets {
		if target == dbid {
			continue
		}
		m.invites[target] = append(m.invites[target], UnitInvite{
			UnitID:   id,
			FromDBID: dbid,
			FromName: from,
			Comment:  comment,
			Created:  time.Now().UTC(),
		})
	}
	return id, lobby.PackUnit(u), true
}

// Members returns the accounts in a squad, in slot order.
func (m *UnitManager) Members(unitID uint64) []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.units[unitID]
	if u == nil {
		return nil
	}
	out := make([]int64, 0, len(u.Members))
	for slot := 0; slot < len(u.Slots); slot++ {
		if dbid, ok := u.Members[uint8(slot)]; ok {
			out = append(out, dbid)
		}
	}
	return out
}

// UnitOf returns the squad an account is in, or nil.
func (m *UnitManager) UnitOf(dbid int64) *lobby.Unit {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byAccount[dbid]
	if !ok {
		return nil
	}
	return m.units[id]
}

// Invites returns the pending invitations for an account.
func (m *UnitManager) Invites(dbid int64) []UnitInvite {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]UnitInvite(nil), m.invites[dbid]...)
}
