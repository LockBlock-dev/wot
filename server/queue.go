package server

import (
	"sort"
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
)

// Queue is the matchmaking queue: who is waiting, for what, and in which
// group.
//
// It is the state behind the client's three queue commands
// (`CMD_ENQUEUE_IN_BATTLE_QUEUE`, `CMD_DEQUEUE_FROM_BATTLE_QUEUE`,
// `CMD_REQ_QUEUE_INFO`), and it is per QUEUE TYPE: the client polls the
// census for the queue it is in, so a random-battle poll must not count a
// ranked entry.
//
// A squad queues as ONE group: the leader's enqueue puts every member in,
// and the census counts them all. That is what the client's own
// `PreQueueEntity` expects — it enqueues once, from the leader.
type Queue struct {
	mu      sync.Mutex
	entries map[int64]*QueueEntry
	order   []int64
	now     func() time.Time
	// nextGroup numbers the squads that queue together.
	nextGroup uint64
}

// QueueEntry is one player waiting in the queue.
type QueueEntry struct {
	AccountID int64
	Name      string
	// QueueType is the client's QUEUE_TYPE (1 = random battles).
	QueueType uint8
	// VehicleID is the inventory id of the vehicle the player queued
	// with.
	VehicleID int32
	// VehicleType is that vehicle's compact descriptor, or nil when the
	// inventory id is not in the garage. The census buckets by its class
	// and the matchmaker by its tier.
	VehicleType []byte
	// Class is the vehicle's class index in the client's own order
	// (`constants.VEHICLE_CLASSES`): 0 lightTank, 1 mediumTank,
	// 2 heavyTank, 3 SPG, 4 AT-SPG. 0xff means "unknown", which the
	// census does not bucket.
	Class uint8
	// Level is the vehicle's tier (1..11), 0 when unknown.
	Level uint8
	// GameplaysMask, ArenaTypeID and RandomFlags are the client's own
	// selection, carried through untouched.
	GameplaysMask int32
	ArenaTypeID   int32
	RandomFlags   int32
	// GroupID is the squad the entry belongs to (0 = solo).
	GroupID uint64
	// GroupSize is how many players the group holds.
	GroupSize int
	Since     time.Time
}

// ClassUnknown marks an entry whose vehicle could not be resolved.
const ClassUnknown uint8 = 0xff

// NewQueue returns an empty queue.
func NewQueue() *Queue {
	return &Queue{entries: make(map[int64]*QueueEntry), now: time.Now}
}

// Enqueue adds one player. It reports false when the player is already
// queued, which is what the client's own guard expects: a second enqueue
// is a no-op, not a second slot.
func (q *Queue) Enqueue(e QueueEntry) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.entries[e.AccountID]; ok {
		return false
	}
	if e.Since.IsZero() {
		e.Since = q.now()
	}
	cp := e
	q.entries[e.AccountID] = &cp
	q.order = append(q.order, e.AccountID)
	return true
}

// EnqueueGroup adds a whole squad atomically: either every member goes in
// or none does. It returns the number added and whether the group was
// accepted.
//
// The group id is minted here, so the caller does not have to know it.
func (q *Queue) EnqueueGroup(entries []QueueEntry) (int, bool) {
	if len(entries) == 0 {
		return 0, false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, e := range entries {
		if _, ok := q.entries[e.AccountID]; ok {
			return 0, false
		}
	}
	q.nextGroup++
	gid := q.nextGroup
	now := q.now()
	for _, e := range entries {
		e.GroupID = gid
		e.GroupSize = len(entries)
		if e.Since.IsZero() {
			e.Since = now
		}
		cp := e
		q.entries[e.AccountID] = &cp
		q.order = append(q.order, e.AccountID)
	}
	return len(entries), true
}

// Dequeue removes a player and returns the entry that was there.
func (q *Queue) Dequeue(accountID int64) (QueueEntry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[accountID]
	if !ok {
		return QueueEntry{}, false
	}
	delete(q.entries, accountID)
	q.dropOrderLocked(accountID)
	return *e, true
}

// DequeueGroup removes every member of a squad and returns them.
func (q *Queue) DequeueGroup(groupID uint64) []QueueEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []QueueEntry
	for id, e := range q.entries {
		if e.GroupID != groupID {
			continue
		}
		out = append(out, *e)
		delete(q.entries, id)
		q.dropOrderLocked(id)
	}
	return out
}

// dropOrderLocked removes one account from the arrival order (caller holds
// q.mu).
func (q *Queue) dropOrderLocked(accountID int64) {
	for i, id := range q.order {
		if id == accountID {
			q.order = append(q.order[:i], q.order[i+1:]...)
			return
		}
	}
}

// Len reports how many players are waiting, across every queue type.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// Entries returns the queue in arrival order.
func (q *Queue) Entries() []QueueEntry {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QueueEntry, 0, len(q.order))
	for _, id := range q.order {
		if e, ok := q.entries[id]; ok {
			out = append(out, *e)
		}
	}
	return out
}

// EntriesOf returns one queue type's entries in arrival order.
func (q *Queue) EntriesOf(queueType uint8) []QueueEntry {
	all := q.Entries()
	out := make([]QueueEntry, 0, len(all))
	for _, e := range all {
		if e.QueueType == queueType {
			out = append(out, e)
		}
	}
	return out
}

// Census is the 1a/67 answer for one queue type: the total waiting and the
// per-class breakdown.
//
// The captured census is {players: 924, classes: [186 226 209 98 205]},
// whose classes sum to players — so the breakdown is per vehicle class, in
// the client's own order (`constants.VEHICLE_CLASSES`), not per queue
// type. An entry whose vehicle could not be resolved still counts in
// `players` but lands in no bucket, which is why the two can differ.
func (q *Queue) Census(queueType uint8) (players int, classes []int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	classes = make([]int, 5)
	for _, e := range q.entries {
		if e.QueueType != queueType {
			continue
		}
		players++
		if e.Class < 5 {
			classes[e.Class]++
		}
	}
	return players, classes
}

// ClassOf reads a vehicle's class index and tier from its compact
// descriptor, using the generated vehicle table. It reports false when the
// descriptor is not a vehicle this server knows.
func ClassOf(compactDescr []byte) (class, level uint8, ok bool) {
	_, nation, id, err := lobby.ParseIntDescr(compactDescr)
	if err != nil {
		return ClassUnknown, 0, false
	}
	for _, v := range lobby.AllOwnableVehicles {
		if v.Nation == nation && v.TypeID == id {
			return v.Class, v.Level, true
		}
	}
	return ClassUnknown, 0, false
}

// SortedByArrival orders entries oldest first, which is the order the
// matchmaker fills a battle in.
func SortedByArrival(entries []QueueEntry) []QueueEntry {
	out := append([]QueueEntry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Since.Before(out[j].Since)
	})
	return out
}
