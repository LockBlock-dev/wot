package server

import (
	"sync"
	"time"
)

// Arena is one battle: the space it runs in, who is in it, and how it ended.
//
// It is the minimum a battle needs to exist for RECONNECT: the server has to
// remember that a player is in a battle across a disconnect, and put them
// back when they return. Everything else a battle does — physics, other
// tanks, damage, the map logic — is the cell app, which this server does not
// have.
type Arena struct {
	ID uint64
	// SpaceID is the BigWorld space the client loads. Any non-zero id
	// works: the client creates the space by id and maps the geometry into
	// it from the spaceData entry.
	SpaceID uint32
	// ArenaTypeID is the client's arena type: `geometryID | gameplayID<<16`
	// (`ArenaType.buildArenaTypeID`). 1 is Karelia, ctf.
	ArenaTypeID int32
	// QueueType is the QUEUE_TYPE the battle came from.
	QueueType uint8
	// Map is the geometry path the spaceData entry maps, `spaces/<map>`.
	Map string
	// Players is the roster, keyed by account id.
	Players map[int64]*ArenaPlayer
	// Order is the roster in join order, so the teams are stable.
	Order []int64
	// State is where the battle is in its lifecycle.
	State ArenaState
	// Created and Finished bound the battle's life.
	Created  time.Time
	Finished time.Time
}

// ArenaState is where a battle is.
type ArenaState uint8

const (
	// ArenaWaiting is a battle that has been created but not started.
	ArenaWaiting ArenaState = iota
	// ArenaRunning is a battle the players are in.
	ArenaRunning
	// ArenaFinished is a battle whose result is ready.
	ArenaFinished
)

// String renders the state for logs.
func (s ArenaState) String() string {
	switch s {
	case ArenaWaiting:
		return "waiting"
	case ArenaRunning:
		return "running"
	case ArenaFinished:
		return "finished"
	}
	return "unknown"
}

// ArenaPlayer is one player in a battle.
type ArenaPlayer struct {
	AccountID int64
	Name      string
	// Team is 0 or 1.
	Team uint8
	// VehicleCompDescr is the tank the player brought.
	VehicleCompDescr []byte
	// Disconnected is when the player dropped, zero while connected. The
	// slot is held for ReconnectWindow so a returning client gets the same
	// battle back.
	Disconnected time.Time
	// Result is the battle result, set when the arena finishes.
	Result *BattleResult
}

// BattleResult is what one player earned in a battle.
type BattleResult struct {
	Credits  int64
	XP       int64
	Winner   uint8
	Survived bool
}

// Arenas is the arena registry.
type Arenas struct {
	mu        sync.Mutex
	nextID    uint64
	arenas    map[uint64]*Arena
	byAccount map[int64]uint64
	// ReconnectWindow is how long a disconnected player keeps its slot.
	// Past it the slot is freed and the player comes back to the hangar.
	ReconnectWindow time.Duration
	now             func() time.Time
}

// DefaultReconnectWindow is how long a dropped player may take to come back.
// The client's own reconnect backoff tops out at 20 s between attempts, so
// two minutes covers a handful of retries.
const DefaultReconnectWindow = 2 * time.Minute

// NewArenas returns an empty registry.
func NewArenas() *Arenas {
	return &Arenas{
		nextID:          1,
		arenas:          map[uint64]*Arena{},
		byAccount:       map[int64]uint64{},
		ReconnectWindow: DefaultReconnectWindow,
		now:             func() time.Time { return time.Now().UTC() },
	}
}

// DefaultArenaTypeID is the arena type a random battle falls back to:
// `geometryID | gameplayID<<16` for Karelia, ctf (`ArenaType
// .buildArenaTypeID`).
const DefaultArenaTypeID int32 = 1

// Create registers a battle with the given roster and starts it.
//
// The players are split into two teams in join order, alternating, so the
// sides stay even.
func (a *Arenas) Create(players []ArenaPlayer, arenaTypeID int32, queueType uint8, mapPath string) *Arena {
	// A random battle queues with arenaTypeID 0: the SERVER picks the map,
	// and 0 is not a valid type — `ArenaType.g_cache.get(0)` is None, and
	// `Avatar.onBecomePlayer` calls `game.abort()` on it, which tears the
	// client down before the cell player arrives.
	if arenaTypeID == 0 {
		arenaTypeID = DefaultArenaTypeID
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := a.nextID
	a.nextID++
	arena := &Arena{
		ID:          id,
		SpaceID:     uint32(id),
		ArenaTypeID: arenaTypeID,
		QueueType:   queueType,
		Map:         mapPath,
		Players:     map[int64]*ArenaPlayer{},
		State:       ArenaRunning,
		Created:     a.now(),
	}
	for i := range players {
		p := players[i]
		p.Team = uint8(i % 2)
		arena.Players[p.AccountID] = &p
		arena.Order = append(arena.Order, p.AccountID)
		a.byAccount[p.AccountID] = id
	}
	a.arenas[id] = arena
	return arena
}

// ArenaOf returns the battle an account is in, or nil.
func (a *Arenas) ArenaOf(accountID int64) *Arena {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.byAccount[accountID]
	if !ok {
		return nil
	}
	return a.arenas[id]
}

// Player returns one player's slot in a battle, or nil.
func (a *Arenas) Player(accountID int64) (*Arena, *ArenaPlayer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.byAccount[accountID]
	if !ok {
		return nil, nil
	}
	arena := a.arenas[id]
	if arena == nil {
		return nil, nil
	}
	return arena, arena.Players[accountID]
}

// Disconnect marks a player as dropped and reports the battle it is holding
// a slot in.
//
// The slot is NOT freed: that is the whole point of the reconnect window.
func (a *Arenas) Disconnect(accountID int64) (*Arena, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.byAccount[accountID]
	if !ok {
		return nil, false
	}
	arena := a.arenas[id]
	if arena == nil {
		return nil, false
	}
	p := arena.Players[accountID]
	if p == nil {
		return arena, false
	}
	p.Disconnected = a.now()
	return arena, true
}

// Reconnect clears a player's disconnect and returns the battle to rejoin.
//
// ok is false when the player is in no battle, or the battle has finished —
// in which case the caller sends the player back to the hangar.
func (a *Arenas) Reconnect(accountID int64) (*Arena, *ArenaPlayer, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.byAccount[accountID]
	if !ok {
		return nil, nil, false
	}
	arena := a.arenas[id]
	if arena == nil || arena.State == ArenaFinished {
		return nil, nil, false
	}
	p := arena.Players[accountID]
	if p == nil {
		return nil, nil, false
	}
	p.Disconnected = time.Time{}
	return arena, p, true
}

// Leave removes a player from its battle and reports the battle it left.
// The battle is dropped once it is empty.
func (a *Arenas) Leave(accountID int64) (*Arena, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id, ok := a.byAccount[accountID]
	if !ok {
		return nil, false
	}
	delete(a.byAccount, accountID)
	arena := a.arenas[id]
	if arena == nil {
		return nil, false
	}
	delete(arena.Players, accountID)
	for i, got := range arena.Order {
		if got == accountID {
			arena.Order = append(arena.Order[:i], arena.Order[i+1:]...)
			break
		}
	}
	if len(arena.Players) == 0 {
		delete(a.arenas, id)
	}
	return arena, true
}

// Finish ends a battle and stamps every player's result.
//
// The result is the minimum the client's battle-results screen reads: a
// credit and XP figure, the winning team and whether the player survived.
// There is no simulation behind it — a lobby-only server has no damage, no
// kills and no capture points — so the numbers are the flat participation
// award the client renders without complaint.
func (a *Arenas) Finish(arenaID uint64, winner uint8) *Arena {
	a.mu.Lock()
	defer a.mu.Unlock()
	arena := a.arenas[arenaID]
	if arena == nil || arena.State == ArenaFinished {
		return arena
	}
	arena.State = ArenaFinished
	arena.Finished = a.now()
	for _, p := range arena.Players {
		won := p.Team == winner
		res := &BattleResult{Winner: winner, Survived: won}
		if won {
			res.Credits = 10000
			res.XP = 500
		} else {
			res.Credits = 5000
			res.XP = 250
		}
		p.Result = res
	}
	return arena
}

// Sweep frees the slots of players whose reconnect window has expired and
// drops finished battles nobody is in. It returns how many slots it freed.
func (a *Arenas) Sweep(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	freed := 0
	for id, arena := range a.arenas {
		for accountID, p := range arena.Players {
			if p.Disconnected.IsZero() {
				continue
			}
			if now.Sub(p.Disconnected) < a.ReconnectWindow {
				continue
			}
			delete(arena.Players, accountID)
			delete(a.byAccount, accountID)
			for i, got := range arena.Order {
				if got == accountID {
					arena.Order = append(arena.Order[:i], arena.Order[i+1:]...)
					break
				}
			}
			freed++
		}
		if len(arena.Players) == 0 {
			delete(a.arenas, id)
		}
	}
	return freed
}

// Len reports how many battles are live.
func (a *Arenas) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.arenas)
}

// All returns every live battle, ordered by id.
func (a *Arenas) All() []*Arena {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Arena, 0, len(a.arenas))
	for id := uint64(1); id < a.nextID; id++ {
		if arena, ok := a.arenas[id]; ok {
			out = append(out, arena)
		}
	}
	return out
}
