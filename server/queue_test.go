package server

import (
	"testing"
	"time"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestQueueEnqueueDequeue covers the registry: one slot per account, and
// leaving hands the entry back.
func TestQueueEnqueueDequeue(t *testing.T) {
	q := NewQueue()
	if q.Len() != 0 {
		t.Fatalf("new queue has %d entries", q.Len())
	}
	if !q.Enqueue(QueueEntry{AccountID: 1, Name: "a", QueueType: 1, VehicleID: 42}) {
		t.Fatal("first enqueue refused")
	}
	// A second enqueue is a no-op, not a second slot.
	if q.Enqueue(QueueEntry{AccountID: 1, Name: "a"}) {
		t.Fatal("duplicate enqueue accepted")
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1", q.Len())
	}

	e, ok := q.Dequeue(1)
	if !ok {
		t.Fatal("dequeue missed")
	}
	if e.VehicleID != 42 {
		t.Errorf("entry = %+v, want vehicle 42", e)
	}
	if q.Len() != 0 {
		t.Fatalf("Len = %d after dequeue, want 0", q.Len())
	}
	if _, ok := q.Dequeue(1); ok {
		t.Fatal("dequeue of an absent player reported success")
	}
}

// TestQueueCensusIsPerQueueType pins the 1a/67 shape AND the filter: the
// client polls the census for the queue it is in, so a random-battle poll
// must not count a ranked entry.
func TestQueueCensusIsPerQueueType(t *testing.T) {
	q := NewQueue()
	players, classes := q.Census(1)
	if players != 0 || len(classes) != 5 {
		t.Fatalf("empty census = %d %v", players, classes)
	}

	// One player per class in the random queue, plus one unclassed, plus
	// one in a different queue type.
	for class := uint8(0); class < 5; class++ {
		q.Enqueue(QueueEntry{AccountID: int64(class) + 1, QueueType: 1, Class: class})
	}
	q.Enqueue(QueueEntry{AccountID: 6, QueueType: 1, Class: ClassUnknown})
	q.Enqueue(QueueEntry{AccountID: 7, QueueType: 17, Class: 2})

	players, classes = q.Census(1)
	if players != 6 {
		t.Errorf("players = %d, want 6 (the ranked entry is not counted)", players)
	}
	sum := 0
	for i, c := range classes {
		if c != 1 {
			t.Errorf("class %d = %d, want 1", i, c)
		}
		sum += c
	}
	if sum != 5 {
		t.Errorf("classes sum to %d, want 5 (the unclassed player is not bucketed)", sum)
	}
	// The ranked queue sees only its own entry.
	if p, _ := q.Census(17); p != 1 {
		t.Errorf("ranked census = %d, want 1", p)
	}
}

// TestQueueEntriesAreOrdered keeps the queue a queue.
func TestQueueEntriesAreOrdered(t *testing.T) {
	q := NewQueue()
	for _, id := range []int64{3, 1, 2} {
		q.Enqueue(QueueEntry{AccountID: id})
	}
	got := q.Entries()
	if len(got) != 3 {
		t.Fatalf("%d entries, want 3", len(got))
	}
	for i, want := range []int64{3, 1, 2} {
		if got[i].AccountID != want {
			t.Errorf("entry %d = %d, want %d (arrival order)", i, got[i].AccountID, want)
		}
	}
	// Removing the middle one keeps the rest in order.
	q.Dequeue(1)
	got = q.Entries()
	if len(got) != 2 || got[0].AccountID != 3 || got[1].AccountID != 2 {
		t.Errorf("after dequeue = %+v", got)
	}
}

// TestQueueGroupIsAtomic checks the squad path: either every member goes
// in or none does, and leaving takes the whole group.
func TestQueueGroupIsAtomic(t *testing.T) {
	q := NewQueue()
	// One member is already queued, so the group must be refused whole.
	q.Enqueue(QueueEntry{AccountID: 2, QueueType: 1})
	added, ok := q.EnqueueGroup([]QueueEntry{
		{AccountID: 1, QueueType: 1},
		{AccountID: 2, QueueType: 1},
	})
	if ok || added != 0 {
		t.Fatalf("group with a queued member accepted: added=%d ok=%v", added, ok)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (the group must not partially land)", q.Len())
	}

	q.Dequeue(2)
	added, ok = q.EnqueueGroup([]QueueEntry{
		{AccountID: 1, QueueType: 1},
		{AccountID: 2, QueueType: 1},
	})
	if !ok || added != 2 {
		t.Fatalf("group refused: added=%d ok=%v", added, ok)
	}
	entries := q.Entries()
	if entries[0].GroupID == 0 || entries[0].GroupID != entries[1].GroupID {
		t.Fatalf("group ids = %d/%d", entries[0].GroupID, entries[1].GroupID)
	}
	if entries[0].GroupSize != 2 {
		t.Fatalf("group size = %d, want 2", entries[0].GroupSize)
	}
	// Leaving as a group takes both.
	if got := q.DequeueGroup(entries[0].GroupID); len(got) != 2 {
		t.Fatalf("DequeueGroup returned %d entries, want 2", len(got))
	}
	if q.Len() != 0 {
		t.Fatalf("Len = %d after the group left, want 0", q.Len())
	}
}

// TestClassOfReadsTheVehicleTable checks the class/tier lookup against a
// real generated entry.
func TestClassOfReadsTheVehicleTable(t *testing.T) {
	if len(lobby.AllOwnableVehicles) == 0 {
		t.Skip("no generated vehicle table")
	}
	v := lobby.AllOwnableVehicles[0]
	class, level, ok := ClassOf(v.CompDescr)
	if !ok {
		t.Fatalf("ClassOf(%s) missed", v.Name)
	}
	if class != v.Class || level != v.Level {
		t.Fatalf("ClassOf(%s) = %d/%d, want %d/%d", v.Name, class, level, v.Class, v.Level)
	}
	if class, _, ok := ClassOf(nil); ok || class != ClassUnknown {
		t.Fatalf("ClassOf(nil) = %d/%v", class, ok)
	}
}

// TestClassOfCoversEveryVehicle is the regression guard for the extended
// type id: every ownable vehicle must resolve, and every class must be in
// the client's 0..4 range.
func TestClassOfCoversEveryVehicle(t *testing.T) {
	bad := 0
	for _, v := range lobby.AllOwnableVehicles {
		class, level, ok := ClassOf(v.CompDescr)
		if !ok || class > 4 || level == 0 {
			bad++
			if bad < 5 {
				t.Errorf("%s: class=%d level=%d ok=%v", v.Name, class, level, ok)
			}
		}
	}
	if bad != 0 {
		t.Fatalf("%d of %d vehicles did not resolve", bad, len(lobby.AllOwnableVehicles))
	}
}

// entry builds a queue entry at a tier, for the matchmaker tests.
func entry(id int64, level uint8, group uint64) QueueEntry {
	return QueueEntry{
		AccountID: id,
		QueueType: 1,
		Class:     1,
		Level:     level,
		GroupID:   group,
		Since:     time.Unix(1_700_000_000+id, 0),
	}
}

// TestMatchmakerNeedsTwoFullTeams checks the size gate.
func TestMatchmakerNeedsTwoFullTeams(t *testing.T) {
	m := NewMatchmaker()
	m.TeamSize = 2
	var entries []QueueEntry
	for i := int64(1); i <= 3; i++ {
		entries = append(entries, entry(i, 5, 0))
	}
	if got := m.TryForm(entries); got != nil {
		t.Fatalf("formed a battle from 3 players: %+v", got)
	}
	entries = append(entries, entry(4, 5, 0))
	got := m.TryForm(entries)
	if got == nil {
		t.Fatal("no battle from 4 players")
	}
	if got.Size() != 4 || len(got.Teams[0]) != 2 || len(got.Teams[1]) != 2 {
		t.Fatalf("battle = %+v", got)
	}
}

// TestMatchmakerBandsByTier checks the ±2 band around the anchor.
func TestMatchmakerBandsByTier(t *testing.T) {
	m := NewMatchmaker()
	m.TeamSize = 1
	// Anchor tier 5; a tier 9 player is out of band.
	entries := []QueueEntry{entry(1, 5, 0), entry(2, 9, 0)}
	if got := m.TryForm(entries); got != nil {
		t.Fatalf("formed across a 4-tier gap: %+v", got)
	}
	// Tier 7 is inside the band.
	entries = []QueueEntry{entry(1, 5, 0), entry(2, 7, 0)}
	if got := m.TryForm(entries); got == nil {
		t.Fatal("no battle across a 2-tier gap")
	}
}

// TestMatchmakerKeepsSquadsTogether checks that a squad lands on one team.
func TestMatchmakerKeepsSquadsTogether(t *testing.T) {
	m := NewMatchmaker()
	m.TeamSize = 2
	entries := []QueueEntry{
		entry(1, 5, 0),
		entry(2, 5, 7), // squad 7
		entry(3, 5, 7),
		entry(4, 5, 0),
	}
	got := m.TryForm(entries)
	if got == nil {
		t.Fatal("no battle")
	}
	onTeam := func(id int64) int {
		for side, team := range got.Teams {
			for _, got := range team {
				if got == id {
					return side
				}
			}
		}
		return -1
	}
	if onTeam(2) != onTeam(3) {
		t.Fatalf("squad split across teams: %+v", got.Teams)
	}
}

// TestMatchmakerSkipsUnresolvedAnchor checks that an entry with no tier
// cannot anchor a band.
func TestMatchmakerSkipsUnresolvedAnchor(t *testing.T) {
	m := NewMatchmaker()
	m.TeamSize = 1
	entries := []QueueEntry{
		{AccountID: 1, QueueType: 1, Class: ClassUnknown, Since: time.Unix(1, 0)},
		entry(2, 5, 0),
		entry(3, 5, 0),
	}
	got := m.TryForm(entries)
	if got == nil {
		t.Fatal("no battle: the unresolved entry should have been skipped")
	}
	for _, team := range got.Teams {
		for _, id := range team {
			if id == 1 {
				t.Fatalf("the unresolved entry was matched: %+v", got.Teams)
			}
		}
	}
}

// TestTierBand pins the clamp at the ends of the ladder.
func TestTierBand(t *testing.T) {
	if lo, hi := tierBand(1, 2); lo != 1 || hi != 3 {
		t.Fatalf("tier 1 band = %d..%d", lo, hi)
	}
	if lo, hi := tierBand(10, 2); lo != 8 || hi != 11 {
		t.Fatalf("tier 10 band = %d..%d", lo, hi)
	}
	if lo, hi := tierBand(5, 2); lo != 3 || hi != 7 {
		t.Fatalf("tier 5 band = %d..%d", lo, hi)
	}
}
