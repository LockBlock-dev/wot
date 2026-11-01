package server

import "testing"

// TestQueueEnqueueDequeue covers the registry: one slot per account, and
// leaving hands the entry back.
func TestQueueEnqueueDequeue(t *testing.T) {
	q := NewQueue()
	if q.Len() != 0 {
		t.Fatalf("new queue has %d entries", q.Len())
	}
	if !q.Enqueue(QueueEntry{AccountID: 1, Name: "a", QueueType: 0, VehicleID: 42}) {
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

// TestQueueCensus pins the 1a/67 shape: the total and a five-class
// breakdown that sums to it.
func TestQueueCensus(t *testing.T) {
	q := NewQueue()
	players, classes := q.Census()
	if players != 0 || len(classes) != 5 {
		t.Fatalf("empty census = %d %v", players, classes)
	}

	// Classes 1..5, one player each, plus one with an unreadable class.
	for i := 1; i <= 5; i++ {
		q.Enqueue(QueueEntry{AccountID: int64(i), Class: uint8(i)})
	}
	q.Enqueue(QueueEntry{AccountID: 6, Class: 0})

	players, classes = q.Census()
	if players != 6 {
		t.Errorf("players = %d, want 6", players)
	}
	sum := 0
	for i, c := range classes {
		if c != 1 {
			t.Errorf("class %d = %d, want 1", i+1, c)
		}
		sum += c
	}
	if sum != 5 {
		t.Errorf("classes sum to %d, want 5 (the unclassed player is not counted)", sum)
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

// TestClassOfReadsTheHeader pins the class nibble without a component
// table.
func TestClassOfReadsTheHeader(t *testing.T) {
	// A compact descriptor's first byte is [type nibble][nation nibble],
	// with bit 1 as the extended-id flag — which classes 2 and 3 set, so
	// their descriptors are three bytes.
	for class := uint8(1); class <= 5; class++ {
		descr := []byte{class | 0x40, 0x01, 0x00}
		if got := ClassOf(descr); got != class {
			t.Errorf("ClassOf(% x) = %d, want %d", descr, got, class)
		}
	}
	if got := ClassOf(nil); got != 0 {
		t.Errorf("ClassOf(nil) = %d, want 0", got)
	}
}
