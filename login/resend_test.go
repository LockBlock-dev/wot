package login

import (
	"net"
	"testing"
	"time"
)

func testQueue() (*resendQueue, *time.Time) {
	now := time.Unix(1_700_000_000, 0)
	q := newResendQueue(400*time.Millisecond, 20*time.Second)
	q.now = func() time.Time { return now }
	return q, &now
}

// TestResendAckDropsBelowWatermark pins the ack rule: the client's
// cumulative watermark acknowledges every packet with a lower sequence.
func TestResendAckDropsBelowWatermark(t *testing.T) {
	q, _ := testQueue()
	for seq := uint32(0); seq < 5; seq++ {
		q.track("peer", seq, []byte{byte(seq)})
	}
	if got := q.pending(); got != 5 {
		t.Fatalf("pending = %d, want 5", got)
	}
	q.ack("peer", 3) // 0,1,2 acknowledged
	if got := q.pending(); got != 2 {
		t.Fatalf("pending = %d after ack(3), want 2", got)
	}
	q.ack("peer", 5)
	if got := q.pending(); got != 0 {
		t.Fatalf("pending = %d after ack(5), want 0", got)
	}
}

// TestResendDueAfterTimeout pins the retransmit rule.
func TestResendDueAfterTimeout(t *testing.T) {
	q, now := testQueue()
	q.track("peer", 7, []byte("pkt"))

	if jobs := q.due(*now); len(jobs) != 0 {
		t.Fatalf("%d jobs at t=0, want 0", len(jobs))
	}
	*now = now.Add(399 * time.Millisecond)
	if jobs := q.due(*now); len(jobs) != 0 {
		t.Fatalf("%d jobs before the timeout, want 0", len(jobs))
	}
	*now = now.Add(2 * time.Millisecond)
	jobs := q.due(*now)
	if len(jobs) != 1 {
		t.Fatalf("%d jobs after the timeout, want 1", len(jobs))
	}
	if jobs[0].Seq != 7 || string(jobs[0].Pkt) != "pkt" || jobs[0].Addr != "peer" {
		t.Fatalf("job = %+v", jobs[0])
	}
	// The clock restarts, so it is not due again immediately.
	if jobs := q.due(*now); len(jobs) != 0 {
		t.Fatalf("%d jobs immediately after a resend, want 0", len(jobs))
	}
}

// TestResendGivesUp keeps a dead peer from leaking packets forever.
func TestResendGivesUp(t *testing.T) {
	q, now := testQueue()
	q.track("peer", 1, []byte("pkt"))
	*now = now.Add(21 * time.Second)
	if jobs := q.due(*now); len(jobs) != 0 {
		t.Fatalf("%d jobs past the give-up deadline, want 0", len(jobs))
	}
	if got := q.pending(); got != 0 {
		t.Fatalf("pending = %d after give-up, want 0", got)
	}
	_, _, _, abandoned := q.stats()
	if abandoned != 1 {
		t.Errorf("abandoned = %d, want 1", abandoned)
	}
}

// TestResendPerPeer keeps one peer's ack from clearing another's packets.
func TestResendPerPeer(t *testing.T) {
	q, _ := testQueue()
	q.track("a", 1, []byte("a1"))
	q.track("b", 1, []byte("b1"))
	q.ack("a", 2)
	if got := q.pending(); got != 1 {
		t.Fatalf("pending = %d, want 1 (b's packet)", got)
	}
	q.forget("b")
	if got := q.pending(); got != 0 {
		t.Fatalf("pending = %d after forget, want 0", got)
	}
}

// TestResendNilIsSafe keeps a server built without the queue working.
func TestResendNilIsSafe(t *testing.T) {
	var q *resendQueue
	q.track("peer", 1, []byte("x"))
	q.ack("peer", 1)
	q.forget("peer")
	if jobs := q.due(time.Now()); jobs != nil {
		t.Errorf("nil queue returned %d jobs", len(jobs))
	}
	if n := q.pending(); n != 0 {
		t.Errorf("nil queue pending = %d", n)
	}
}

// fakeTransport records what the server writes.
type fakeTransport struct {
	writes [][]byte
	addrs  []*net.UDPAddr
}

func (f *fakeTransport) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	f.writes = append(f.writes, append([]byte(nil), b...))
	f.addrs = append(f.addrs, addr)
	return len(b), nil
}
func (f *fakeTransport) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) { return 0, nil, nil }
func (f *fakeTransport) SetReadDeadline(t time.Time) error               { return nil }
func (f *fakeTransport) SetReadBuffer(bytes int) error                   { return nil }

// TestSweepResendsUnacked is the integration: a reliable packet the client
// never acknowledges goes back on the wire from the sweep.
func TestSweepResendsUnacked(t *testing.T) {
	s := &BaseAppServer{
		cfg:        BaseAppConfig{},
		resend:     newResendQueue(400*time.Millisecond, 20*time.Second),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	now := time.Unix(1_700_000_000, 0)
	s.resend.now = func() time.Time { return now }

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	s.resend.track(addr.String(), 5, []byte("reliable-answer"))

	tr := &fakeTransport{}
	s.sweepStage2(tr, now)
	if len(tr.writes) != 0 {
		t.Fatalf("%d writes before the timeout, want 0", len(tr.writes))
	}

	now = now.Add(500 * time.Millisecond)
	s.sweepStage2(tr, now)
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes after the timeout, want 1", len(tr.writes))
	}
	if string(tr.writes[0]) != "reliable-answer" {
		t.Errorf("resent %q", tr.writes[0])
	}
	if tr.addrs[0].String() != addr.String() {
		t.Errorf("resent to %s, want %s", tr.addrs[0], addr)
	}

	// Once acknowledged it stops.
	s.resend.ack(addr.String(), 6)
	now = now.Add(time.Second)
	s.sweepStage2(tr, now)
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes after the ack, want 1 (no more)", len(tr.writes))
	}
}
