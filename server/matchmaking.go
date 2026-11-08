package server

import (
	"sync"

	"github.com/LockBlock-dev/wot/lobby"
)

// Matchmaking is the queue plus the matchmaker, wired to the squads.
//
// It is what `login.QueueHooks` talks to: the wire layer hands it the
// client's own selection and gets back either "queued" or a JOIN_FAILURE
// code, and it never sees the queue itself.
type Matchmaking struct {
	queue *Queue
	maker *Matchmaker
	units *UnitManager

	// VehicleOf resolves an account's vehicle by inventory id, so a
	// squad member's entry carries the same class and tier the leader's
	// does. nil leaves the squad members' vehicles unresolved.
	VehicleOf func(accountID int64, invID int32) []byte

	// Logf receives one line per notable event. Nil discards.
	Logf func(format string, args ...any)
	// OnMatch is called when the matchmaker forms a battle. It is where
	// the arena is created and the players are handed off; nil leaves the
	// battle logged and the players queued.
	//
	// It runs from Handoff, NOT from Enqueue: the handoff sends
	// `Account.onArenaCreated` and `resetEntities`, and the client must
	// have its `onEnqueued` answer first. Sending the entry before that
	// answer leaves the client with a cleared entity table and a queued
	// callback that still expects one, and it dies on
	// `MF_ASSERT_DEV FAILED: pEntity`.
	OnMatch func(*Match)

	mu sync.Mutex
	// pending holds the battles formed since the last Handoff, in order.
	pending []*Match
	// matches holds the battles the matchmaker has formed. They are not
	// handed off (that needs a cell app, see TODO.md #1), so this is the
	// record of what the queue could have produced.
	matches []*Match
}

// NewMatchmaking returns the queue service.
func NewMatchmaking(units *UnitManager) *Matchmaking {
	return &Matchmaking{
		queue: NewQueue(),
		maker: NewMatchmaker(),
		units: units,
	}
}

// Queue exposes the queue for tests and for the operator CLI.
func (m *Matchmaking) Queue() *Queue { return m.queue }

// Matchmaker exposes the formation rule, so the operator can set the team
// size the server runs with.
func (m *Matchmaking) Matchmaker() *Matchmaker { return m.maker }

// Matches returns the battles formed so far.
func (m *Matchmaking) Matches() []*Match {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*Match(nil), m.matches...)
}

// logf writes one line when a logger is configured.
func (m *Matchmaking) logf(format string, args ...any) {
	if m.Logf != nil {
		m.Logf(format, args...)
	}
}

// EnqueueResult is the outcome of one enqueue.
type EnqueueResult struct {
	// Code is the client's JOIN_FAILURE code, 0 on success.
	Code int32
	// Message is the error text the client shows.
	Message string
	// Added is how many players went in (a squad adds more than one).
	Added int
}

// Ok reports whether the enqueue applied.
func (r EnqueueResult) Ok() bool { return r.Code == 0 }

// The client's JOIN_FAILURE codes (`common/constants.pyc`).
const (
	joinFailureWrongVehicle      int32 = 4
	joinFailureWrongArgs         int32 = 6
	joinFailureQueueFull         int32 = 17
	joinFailureQueueFailure      int32 = 18
	joinFailureQueueForbidden    int32 = 19
	joinFailureNotEnoughVehicles int32 = 20
)

// queueTypeRandom is QUEUE_TYPE.RANDOMS, the only queue this server
// serves. The others (ranked, event, mapbox, …) need their own mode
// config and their own arena rules.
const queueTypeRandom uint8 = 1

// Enqueue adds a player — and their squad, when they lead one — to the
// queue.
//
// `args` is the client's own selection, in its order: [queueType,
// vehInvID, gameplaysMask, arenaTypeID, randomFlags]. `veh` is the
// compact descriptor of the vehicle the player queued with, or nil when
// the inventory id is not in the garage.
func (m *Matchmaking) Enqueue(accountID int64, name string, args []int32, veh []byte) EnqueueResult {
	if len(args) < 2 {
		return EnqueueResult{Code: joinFailureWrongArgs, Message: "wrong arguments"}
	}
	queueType := uint8(args[0])
	if queueType != queueTypeRandom {
		return EnqueueResult{
			Code:    joinFailureQueueForbidden,
			Message: "this queue is not available",
		}
	}
	if len(veh) == 0 {
		return EnqueueResult{
			Code:    joinFailureWrongVehicle,
			Message: "the vehicle is not in the garage",
		}
	}
	class, level, ok := ClassOf(veh)
	if !ok {
		return EnqueueResult{
			Code:    joinFailureWrongVehicle,
			Message: "unknown vehicle",
		}
	}
	entry := QueueEntry{
		AccountID:   accountID,
		Name:        name,
		QueueType:   queueType,
		VehicleID:   args[1],
		VehicleType: veh,
		Class:       class,
		Level:       level,
	}
	if len(args) > 2 {
		entry.GameplaysMask = args[2]
	}
	if len(args) > 3 {
		entry.ArenaTypeID = args[3]
	}
	if len(args) > 4 {
		entry.RandomFlags = args[4]
	}

	// A squad queues as one group, and only its leader may do it.
	group := []QueueEntry{entry}
	if m.units != nil {
		if u := m.units.UnitOf(accountID); u != nil {
			if !isUnitLeader(u, accountID) {
				return EnqueueResult{
					Code:    joinFailureQueueForbidden,
					Message: "only the squad leader can queue",
				}
			}
			group = m.squadEntries(u, entry)
		}
	}
	added, ok := m.queue.EnqueueGroup(group)
	if !ok {
		return EnqueueResult{
			Code:    joinFailureQueueFailure,
			Message: "already in the queue",
		}
	}
	m.logf("matchmaking: %d queued for type %d (vehicle class %d tier %d, group of %d)",
		accountID, queueType, class, level, added)
	m.tryForm(queueType)
	return EnqueueResult{Added: added}
}

// squadEntries builds the queue entries for a whole squad, using the
// leader's selection for the queue type and each member's own vehicle.
func (m *Matchmaking) squadEntries(u *lobby.Unit, leader QueueEntry) []QueueEntry {
	out := []QueueEntry{leader}
	for _, dbid := range m.units.Members(u.ID) {
		if dbid == leader.AccountID {
			continue
		}
		e := QueueEntry{
			AccountID:     dbid,
			Name:          u.Players[dbid].NickName,
			QueueType:     leader.QueueType,
			GameplaysMask: leader.GameplaysMask,
			ArenaTypeID:   leader.ArenaTypeID,
			RandomFlags:   leader.RandomFlags,
			Class:         ClassUnknown,
		}
		if vehs := u.Vehicles[dbid]; len(vehs) > 0 {
			e.VehicleID = vehs[0].InvID
			if m.VehicleOf != nil {
				e.VehicleType = m.VehicleOf(dbid, vehs[0].InvID)
			}
			if class, level, ok := ClassOf(e.VehicleType); ok {
				e.Class, e.Level = class, level
			}
		}
		out = append(out, e)
	}
	return out
}

// Dequeue removes a player — and their squad, when they lead one — from
// the queue.
func (m *Matchmaking) Dequeue(accountID int64) bool {
	e, ok := m.queue.Dequeue(accountID)
	if !ok {
		return false
	}
	if e.GroupID != 0 {
		m.queue.DequeueGroup(e.GroupID)
	}
	m.logf("matchmaking: %d left the queue (type %d)", accountID, e.QueueType)
	return true
}

// Census is the 1a/67 answer for one queue type.
func (m *Matchmaking) Census(queueType uint8) (int, []int) {
	return m.queue.Census(queueType)
}

// tryForm asks the matchmaker whether the queue can now produce a battle,
// takes the players it matched OUT of the queue, and records the battle.
//
// The dequeue is not optional. An entry that has been matched and left in the
// queue is matched again on the next sweep, and the client's own next enqueue
// is refused with JOIN_FAILURE 18 ("already in the queue") — which is what a
// player saw after leaving a battle and queueing again: the matchmaker would
// not take them, and the refusal is permanent because nothing ever removed
// the stale entry.
func (m *Matchmaking) tryForm(queueType uint8) {
	match := m.maker.TryForm(m.queue.EntriesOf(queueType))
	if match == nil {
		return
	}
	// A squad is one entry in the battle and several in the queue: drop it by
	// group id so no member is left behind.
	for _, e := range match.Entries {
		if e.GroupID != 0 {
			m.queue.DequeueGroup(e.GroupID)
			continue
		}
		m.queue.Dequeue(e.AccountID)
	}
	m.mu.Lock()
	m.matches = append(m.matches, match)
	m.mu.Unlock()
	m.logf("matchmaking: battle %d ready — %d players, type %d, arena %d",
		match.ID, match.Size(), match.QueueType, match.ArenaTypeID)
	m.mu.Lock()
	m.pending = append(m.pending, match)
	m.mu.Unlock()
}

// Handoff runs the battle handoffs the queue deferred, in the order the
// battles were formed. The wire layer calls it right after it has sent the
// `onEnqueued` answer, so the client is queued before it is pulled into a
// battle.
func (m *Matchmaking) Handoff() {
	m.mu.Lock()
	pending := m.pending
	m.pending = nil
	m.mu.Unlock()
	if m.OnMatch == nil {
		return
	}
	for _, match := range pending {
		m.OnMatch(match)
	}
}

// isUnitLeader reports whether dbid holds the creator role in u.
func isUnitLeader(u *lobby.Unit, dbid int64) bool {
	p, ok := u.Players[dbid]
	if !ok {
		return false
	}
	return p.Role&lobby.UnitRoleCreator != 0
}
