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
		q.track("peer", "peer", seq, []byte{byte(seq)})
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
	q.track("peer", "peer", 7, []byte("pkt"))

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
	q.track("peer", "peer", 1, []byte("pkt"))
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
	q.track("a", "a", 1, []byte("a1"))
	q.track("b", "b", 1, []byte("b1"))
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
	q.track("peer", "peer", 1, []byte("x"))
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
	st := &clientState{resendKey: "session-1", stage2Addr: addr}
	s.resend.track(st.resendKey, addr.String(), 5, []byte("reliable-answer"))

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
	s.resend.ack(st.resendKey, 6)
	now = now.Add(time.Second)
	s.sweepStage2(tr, now)
	if len(tr.writes) != 1 {
		t.Fatalf("%d writes after the ack, want 1 (no more)", len(tr.writes))
	}
}

// TestNoteReliableRetiresFromTheClientsCumul pins the two numbers in a
// client frame's trailer apart: `seq` is the client's own send counter
// (it feeds the cumulative ack WE send), `cumul` is the client's
// cumulative ack of OUR seqs (it retires the resend queue). Feeding the
// send counter to the queue instead never retires anything, and the
// server resends the whole stage-2 stream until the give-up deadline.
func TestNoteReliableRetiresFromTheClientsCumul(t *testing.T) {
	key := baseAppTestKey()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001}
	s := &BaseAppServer{resend: newResendQueue(0, 0)}
	st := &clientState{blockKey: key, stage2Addr: addr, postCumul: 1}

	// Three reliable packets of ours are in flight, seqs 5..7.
	for seq := uint32(5); seq <= 7; seq++ {
		pkt, err := buildChannelPacket(key, flagsRel, []byte{0x13, byte(seq), 0, 0, 0, 0}, nil, seq, 1)
		if err != nil {
			t.Fatal(err)
		}
		s.resend.track(st.resendKey, addr.String(), seq, pkt)
	}

	// The client answers with its OWN seq 0 and a cumulative ack of 7:
	// it has received everything below 7.
	clear, err := buildChannelPacket(key, flagsRel, []byte{0x02, 0, 0, 0, 0, 0}, nil, 0, 7)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptChannelFrame(key, clear)
	if err != nil {
		t.Fatal(err)
	}
	s.noteReliable(st, st.stage2Addr, dec)

	// The ack counts the client's reliable packets, one per packet: this is
	// the first, so it moves to 2 from the setup's 1.
	if st.postCumul != 2 {
		t.Fatalf("our cumulative ack moved to %d, want 2 (one reliable packet counted)", st.postCumul)
	}
	if got := len(s.resend.byKey[st.resendKey]); got != 1 {
		t.Fatalf("%d packets still queued, want 1 (seq 7 is not below the client's ack of 7)", got)
	}
	if got := s.resend.byKey[st.resendKey][0].seq; got != 7 {
		t.Fatalf("queued seq %d, want 7", got)
	}
}

// TestNoteReliableAcksFromAnUnreliableFrame pins the other half of the
// same rule: the client's ack-only datagrams carry NO RELIABLE bit, and
// they are the only place it says what it has received. Gating the
// cumulative ack on RELIABLE left every answer queued forever, so the
// sweep resent the whole stage-2 stream (ticks included) until the
// give-up deadline — hundreds of duplicates a second at a client that
// was already stalled.
func TestNoteReliableAcksFromAnUnreliableFrame(t *testing.T) {
	key := baseAppTestKey()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002}
	s := &BaseAppServer{resend: newResendQueue(0, 0)}
	st := &clientState{blockKey: key, stage2Addr: addr, postCumul: 1}

	for seq := uint32(5); seq <= 7; seq++ {
		pkt, err := buildChannelPacket(key, flagsRel, []byte{0x13, byte(seq), 0, 0, 0, 0}, nil, seq, 1)
		if err != nil {
			t.Fatal(err)
		}
		s.resend.track(st.resendKey, addr.String(), seq, pkt)
	}

	// An unreliable frame (no RELIABLE bit) that still carries the
	// cumulative ack: ON_CHANNEL | HAS_CUMULATIVE_ACK.
	flagsUnrelAck := flagsBytes(chFlagOnChannel | chFlagCumulAck)
	clear, err := buildChannelPacket(key, flagsUnrelAck, []byte{0x02, 0, 0, 0, 0, 0}, nil, 0, 7)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptChannelFrame(key, clear)
	if err != nil {
		t.Fatal(err)
	}
	s.noteReliable(st, st.stage2Addr, dec)

	if got := len(s.resend.byKey[st.resendKey]); got != 1 {
		t.Fatalf("%d packets still queued, want 1 (the ack of 7 retires seqs 5 and 6)", got)
	}
	if st.postCumul != 1 {
		t.Fatalf("our cumulative ack moved to %d; an unreliable frame carries no client seq", st.postCumul)
	}
}

// TestResendQueueCapsPerPeer keeps a stalled peer from turning the sweep
// into a broadcast: the queue holds at most resendMaxPending packets and
// drops the oldest first.
func TestResendQueueCapsPerPeer(t *testing.T) {
	q := newResendQueue(0, 0)
	for i := 0; i < resendMaxPending+10; i++ {
		q.track("peer", "peer", uint32(i), []byte{byte(i)})
	}
	if got := len(q.byKey["peer"]); got != resendMaxPending {
		t.Fatalf("%d queued, want the cap %d", got, resendMaxPending)
	}
	// The newest survive, the oldest are gone.
	first := q.byKey["peer"][0].seq
	if first != 10 {
		t.Fatalf("oldest queued seq %d, want 10 (the first ten were dropped)", first)
	}
}

// TestResendReaddrFollowsTheRebind pins the rebind rule: the queue is keyed
// by session, so the client's acks still retire it after it rebinds its socket
// on battle entry, and the replays follow it to the new address instead of
// going to the port it just left.
func TestResendReaddrFollowsTheRebind(t *testing.T) {
	q, now := testQueue()
	const key, oldAddr, newAddr = "session-1", "127.0.0.1:37483", "192.168.1.82:37483"
	q.track(key, oldAddr, 5, []byte{1})
	q.track(key, oldAddr, 6, []byte{2})

	q.readdr(key, newAddr)
	if got := len(q.byKey[key]); got != 2 {
		t.Fatalf("session holds %d packets, want 2", got)
	}
	// The replays now go to the new address.
	*now = now.Add(time.Second)
	due := q.due(*now)
	if len(due) != 2 {
		t.Fatalf("due = %d packets, want 2", len(due))
	}
	for _, job := range due {
		if job.Addr != newAddr {
			t.Fatalf("replay to %s, want %s", job.Addr, newAddr)
		}
	}
	// The ack that arrives from the new address retires them.
	q.ack(key, 7)
	if got := len(q.byKey[key]); got != 0 {
		t.Fatalf("ack left %d packets", got)
	}
}

// TestResendQueueDiesWithTheSession pins the re-login rule: a second login for
// the same account retires the old session, and its queue goes with it. Left
// behind, the abandoned session kept being served — the post-flood ticker
// minted for it forever and every packet was retransmitted to its dead port
// until the attempt cap (15,344 resends in one live run).
func TestResendQueueDiesWithTheSession(t *testing.T) {
	s := &BaseAppServer{
		resend:     newResendQueue(0, 0),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	old := &clientState{sessionKey: 0x1111, accountID: 7, resendKey: "session-1111", stage2Key: 0x2222}
	s.byAddr["127.0.0.1:40000"] = old
	s.byStageKey[old.stage2Key] = old
	s.pending[old.sessionKey] = old
	s.resend.track(old.resendKey, "127.0.0.1:40000", 5, []byte("lobby answer"))

	s.Admit(LoggedOnSession{SessionKey: 0x3333, AccountID: 7, Name: "admin", BlockKey: "0123456789abcdef"})

	if len(s.byAddr) != 0 {
		t.Fatalf("the old session is still in byAddr: %d entries", len(s.byAddr))
	}
	if _, ok := s.byStageKey[old.stage2Key]; ok {
		t.Fatal("the old session is still in byStageKey")
	}
	if _, ok := s.pending[old.sessionKey]; ok {
		t.Fatal("the old session is still in pending")
	}
	if got := s.resend.pending(); got != 0 {
		t.Fatalf("%d packets still queued for the retired session, want 0", got)
	}
	if _, ok := s.pending[0x3333]; !ok {
		t.Fatal("the new session was not admitted")
	}
}

// TestSweepRetiresSilentSessions pins the other half of the same leak: a client
// that closes instead of logging in again leaves its session in byAddr, and the
// post-flood ticker keeps minting for it forever with every packet
// retransmitted to its dead port.
func TestSweepRetiresSilentSessions(t *testing.T) {
	s := &BaseAppServer{
		resend:     newResendQueue(0, 0),
		pending:    map[uint32]*clientState{},
		byStageKey: map[uint32]*clientState{},
		byAddr:     map[string]*clientState{},
	}
	now := time.Unix(1_700_000_000, 0)
	st := &clientState{
		sessionKey: 0x1111,
		accountID:  7,
		resendKey:  "session-1111",
		stage2Key:  0x2222,
		lastSeen:   now,
		arena:      &ArenaHandoff{},
	}
	s.byAddr["127.0.0.1:40000"] = st
	s.byStageKey[st.stage2Key] = st
	s.resend.track(st.resendKey, "127.0.0.1:40000", 5, []byte("tick"))

	tr := &fakeTransport{}
	s.sweepStage1(tr, now.Add(SessionIdleTTL-time.Second))
	if len(s.byAddr) != 1 {
		t.Fatal("retired a session that is still inside the idle window")
	}
	s.sweepStage1(tr, now.Add(SessionIdleTTL+time.Second))
	if len(s.byAddr) != 0 {
		t.Fatal("the silent session is still in byAddr")
	}
	if _, ok := s.byStageKey[st.stage2Key]; ok {
		t.Fatal("the silent session is still in byStageKey")
	}
	if got := s.resend.pending(); got != 0 {
		t.Fatalf("%d packets still queued, want 0", got)
	}
	if st.arena != nil {
		t.Fatal("the retired session still has an arena, so its ticker keeps running")
	}
}
