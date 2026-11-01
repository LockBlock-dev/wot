package server

import (
	"sync"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
)

// Queue is the matchmaking queue: who is waiting, for what.
//
// It is deliberately not a matchmaker. It tracks the entries, answers the
// client's census poll truthfully, and hands an entry back when the
// player leaves. Forming a battle is out of scope — that needs a cell app
// and a space, which no capture covers.
type Queue struct {
	mu      sync.Mutex
	entries map[int64]*QueueEntry
	order   []int64
	now     func() time.Time
}

// QueueEntry is one player waiting in the queue.
type QueueEntry struct {
	AccountID int64
	Name      string
	// QueueType is the client's QUEUE_TYPE (0 = random battles).
	QueueType uint8
	// VehicleID is the inventory id of the vehicle the player queued
	// with.
	VehicleID int32
	// GameplaysMask, ArenaTypeID and RandomFlags are the client's own
	// selection, carried through untouched.
	GameplaysMask int32
	ArenaTypeID   int32
	RandomFlags   int32
	// Class is the vehicle's type nibble from its compact descriptor
	// (1..5), or 0 when the descriptor could not be read.
	Class uint8
	Since time.Time
}

// NewQueue returns an empty queue.
func NewQueue() *Queue {
	return &Queue{entries: make(map[int64]*QueueEntry), now: time.Now}
}

// Enqueue adds a player. It reports false when the player is already
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

// Dequeue removes a player and returns the entry that was there.
func (q *Queue) Dequeue(accountID int64) (QueueEntry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.entries[accountID]
	if !ok {
		return QueueEntry{}, false
	}
	delete(q.entries, accountID)
	for i, id := range q.order {
		if id == accountID {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
	return *e, true
}

// Len reports how many players are waiting.
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

// Census is the 1a/67 answer: the total waiting and the per-class
// breakdown. The captured census is {players: 924, classes: [186 226 209
// 98 205]}, whose classes sum to players — so the breakdown is per vehicle
// class, not per queue type.
func (q *Queue) Census() (players int, classes []int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	classes = make([]int, 5)
	for _, e := range q.entries {
		players++
		if e.Class >= 1 && e.Class <= 5 {
			classes[e.Class-1]++
		}
	}
	return players, classes
}

// ClassOf reads a vehicle's class nibble from its compact descriptor.
// It needs no component table: the type is in the header.
func ClassOf(compactDescr []byte) uint8 {
	itemType, _, _, err := lobby.ParseIntDescr(compactDescr)
	if err != nil {
		return 0
	}
	return itemType
}
