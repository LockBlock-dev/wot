package server

import (
	"time"
)

// Matchmaker forms battles from the queue.
//
// It is the pure half of matchmaking: given the entries waiting for one
// queue type, it decides whether a battle can be formed and which players
// are in it. It does NOT hand the battle off — that needs a cell app and a
// space (`Account.onArenaCreated` makes the client wait for a
// CreateCellPlayer that a lobby-only server cannot send), which is
// `TODO.md` #1. So the server logs a formed battle and leaves the players
// queued; the queue itself is real, the census is real, and the formation
// rule is testable on its own.
type Matchmaker struct {
	// TeamSize is how many players each side needs. A random battle is
	// 15v15. Zero means SOLO: one queued player forms a battle on their
	// own, which is the only way to reach the arena path with a single
	// client.
	TeamSize int
	// MaxTierSpread is the widest tier gap a battle allows: the client's
	// own matchmaker bands by ±2 around the anchor.
	MaxTierSpread uint8
	// now is the clock, injectable for tests.
	now func() time.Time
	// nextID numbers the battles.
	nextID uint64
}

// NewMatchmaker returns a matchmaker for 15v15 random battles with the
// client's ±2 tier band.
func NewMatchmaker() *Matchmaker {
	return &Matchmaker{
		TeamSize:      15,
		MaxTierSpread: 2,
		now:           func() time.Time { return time.Now().UTC() },
	}
}

// Match is one formed battle.
type Match struct {
	ID          uint64
	QueueType   uint8
	ArenaTypeID int32
	// Teams holds the account ids of each side.
	Teams [2][]int64
	// Entries is the queue state the battle was formed from, so a caller
	// can log or hand it off without re-reading the queue.
	Entries []QueueEntry
	Created time.Time
}

// Size reports how many players the battle holds.
func (m *Match) Size() int { return len(m.Teams[0]) + len(m.Teams[1]) }

// TryForm returns the next battle the entries can support, or nil.
//
// The rule, in order:
//
//  1. Oldest entry first: it anchors the battle and fixes the tier band.
//  2. Only entries within MaxTierSpread of the anchor's tier are eligible.
//  3. A squad goes to ONE team — the client's platoon UI assumes it.
//  4. Fill team 0 then team 1, alternating, so the two sides stay even.
//
// It returns nil when the eligible set cannot fill both teams.
func (m *Matchmaker) TryForm(entries []QueueEntry) *Match {
	if len(entries) == 0 {
		return nil
	}
	if m.TeamSize <= 0 {
		// Solo: the oldest entry forms a battle alone. Test mode — a real
		// battle needs two full teams.
		anchor := SortedByArrival(entries)[0]
		m.nextID++
		return &Match{
			ID:          m.nextID,
			QueueType:   anchor.QueueType,
			ArenaTypeID: anchor.ArenaTypeID,
			Teams:       [2][]int64{{anchor.AccountID}, nil},
			Entries:     []QueueEntry{anchor},
			Created:     m.now(),
		}
	}
	if len(entries) < 2*m.TeamSize {
		return nil
	}
	ordered := SortedByArrival(entries)
	anchor := ordered[0]
	if anchor.Level == 0 {
		// An entry whose vehicle could not be resolved cannot anchor a
		// tier band; skip it and let the next one try.
		for _, e := range ordered[1:] {
			if e.Level != 0 {
				anchor = e
				break
			}
		}
		if anchor.Level == 0 {
			return nil
		}
	}
	lo, hi := tierBand(anchor.Level, m.MaxTierSpread)

	// Collect eligible entries, keeping each squad together.
	type group struct {
		id      uint64
		entries []QueueEntry
	}
	var groups []group
	byGroup := map[uint64]int{}
	for _, e := range ordered {
		if e.Level < lo || e.Level > hi {
			continue
		}
		if e.GroupID == 0 {
			groups = append(groups, group{entries: []QueueEntry{e}})
			continue
		}
		if idx, ok := byGroup[e.GroupID]; ok {
			groups[idx].entries = append(groups[idx].entries, e)
			continue
		}
		byGroup[e.GroupID] = len(groups)
		groups = append(groups, group{id: e.GroupID, entries: []QueueEntry{e}})
	}

	// Fill the two teams, alternating, never splitting a squad.
	var teams [2][]int64
	var picked []QueueEntry
	side := 0
	for _, g := range groups {
		if len(teams[0]) >= m.TeamSize && len(teams[1]) >= m.TeamSize {
			break
		}
		// A squad that does not fit the current side goes to the other
		// one; if it fits neither, it waits for the next battle.
		if len(teams[side])+len(g.entries) > m.TeamSize {
			side ^= 1
		}
		if len(teams[side])+len(g.entries) > m.TeamSize {
			continue
		}
		for _, e := range g.entries {
			teams[side] = append(teams[side], e.AccountID)
			picked = append(picked, e)
		}
		side ^= 1
	}
	if len(teams[0]) < m.TeamSize || len(teams[1]) < m.TeamSize {
		return nil
	}
	m.nextID++
	return &Match{
		ID:          m.nextID,
		QueueType:   anchor.QueueType,
		ArenaTypeID: anchor.ArenaTypeID,
		Teams:       teams,
		Entries:     picked,
		Created:     m.now(),
	}
}

// tierBand returns the inclusive tier range a battle anchored at level
// allows.
func tierBand(level, spread uint8) (lo, hi uint8) {
	lo, hi = 1, 11
	if level > spread {
		lo = level - spread
	}
	if level+spread < hi {
		hi = level + spread
	}
	return lo, hi
}
