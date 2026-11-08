package login

import (
	"sync"
	"time"
)

// Reliable-delivery retransmission.
//
// The channel is reliable in the protocol's sense: every packet we send
// with the RELIABLE flag carries a sequence number, and the client
// acknowledges everything below its cumulative-ack watermark. UDP does
// not retransmit, so the sender has to: a reliable packet the client never
// acknowledges is resent until it is acked or the give-up deadline passes.
//
// Without this the server mints each answer once. On a lossy link the
// client waits for a packet that will never come, and the lobby stalls
// with no error on either side.
const (
	// resendTimeout is how long an unacknowledged reliable packet waits
	// before it is sent again.
	//
	// The client acks on its own send cadence, which in a battle is ~18 Hz
	// (measured: 18.1 Hz C>S against 10.0 Hz S>C in a 60 s window of
	// `captures/proxy-20261031-1358.hex`), so its cumulative watermark can be
	// ~220 ms behind. At 400 ms that lag was enough to retransmit a quarter of
	// all reliable packets — 9057 retransmissions over 4469 distinct sequence
	// numbers in one live run — and every one of them competes with the
	// position updates the client is waiting on. A second is five ack
	// cadences: past any real jitter, still far inside the give-up window.
	resendTimeout = 1 * time.Second
	// resendGiveUp is when we stop trying. A client that has not acked in
	// this long is gone; keeping the packet would leak memory for the
	// life of the process.
	resendGiveUp = 20 * time.Second
	// resendMaxPending caps the queue per peer. The post-flood cadence is
	// 100 ms and the timeout is four ticks, so a healthy session holds a
	// handful of packets; anything near this cap means the peer stopped
	// acking. Without the cap a stalled session keeps minting ticks and
	// the queue grows without bound, and every sweep then blasts the
	// whole backlog at a client that is already struggling.
	resendMaxPending = 256
	// resendMaxAttempts bounds how many times one packet is replayed. The
	// give-up deadline alone is not enough: a peer that has stopped acking
	// still gets the whole backlog every timeout for the full window, and
	// that flood lands exactly when the client is least able to take it
	// (entering a battle). Eight tries is far past any real loss.
	resendMaxAttempts = 8
)

// pendingSend is one reliable packet awaiting acknowledgement.
type pendingSend struct {
	seq  uint32
	pkt  []byte
	addr string // where to send it now; follows a socket rebind
	sent time.Time
	// attempts counts the replays so far.
	attempts int
}

// resendJob is one packet to put back on the wire.
type resendJob struct {
	Addr string
	Pkt  []byte
	Seq  uint32
}

// resendQueue holds the reliable packets each SESSION has not acknowledged.
//
// The key is the session, not the address we send to. Keying by address
// looked equivalent — a session had one address — but it is not: the client
// rebinds its UDP socket on battle entry, and a re-login abandons the old
// session entirely while the server keeps serving it. Either way the queue
// outlived the address it was keyed on, and its packets were retransmitted
// to a port nobody reads until the attempt cap: a live run logged 15,344
// resends, 13,429 of them 28 B lobby poll answers, all to the previous
// session's port. Keyed by session, the queue dies with the session and a
// rebind only moves where its packets are sent (see readdr).
type resendQueue struct {
	mu      sync.Mutex
	byKey   map[string][]*pendingSend
	timeout time.Duration
	giveUp  time.Duration
	now     func() time.Time

	// Counters for the log line (sizes only, never packet contents).
	tracked   int
	resent    int
	acked     int
	abandoned int
}

func newResendQueue(timeout, giveUp time.Duration) *resendQueue {
	if timeout <= 0 {
		timeout = resendTimeout
	}
	if giveUp <= 0 {
		giveUp = resendGiveUp
	}
	return &resendQueue{
		byKey:   make(map[string][]*pendingSend),
		timeout: timeout,
		giveUp:  giveUp,
		now:     time.Now,
	}
}

// track records a reliable packet just sent to addr on behalf of the session
// keyed by key.
//
// A packet with no sequence number cannot be acknowledged, so it is not
// tracked: resending it would duplicate an unnumbered message.
func (q *resendQueue) track(key, addr string, seq uint32, pkt []byte) {
	if q == nil || len(pkt) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	list := q.byKey[key]
	if len(list) >= resendMaxPending {
		// Drop the oldest: it is the least likely to still matter, and
		// keeping the newest preserves the answers the client is waiting
		// on right now.
		drop := len(list) - resendMaxPending + 1
		list = append([]*pendingSend(nil), list[drop:]...)
		q.abandoned += drop
	}
	q.byKey[key] = append(list, &pendingSend{
		seq:  seq,
		pkt:  append([]byte(nil), pkt...),
		addr: addr,
		sent: q.now(),
	})
	q.tracked++
}

// ack drops everything below the peer's cumulative-ack watermark: the
// client has received every packet with a lower sequence number.
func (q *resendQueue) ack(key string, cumul uint32) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	list := q.byKey[key]
	if len(list) == 0 {
		return
	}
	kept := list[:0]
	for _, p := range list {
		if p.seq < cumul {
			q.acked++
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		delete(q.byKey, key)
		return
	}
	q.byKey[key] = kept
}

// outstanding is how many reliable packets the session has sent and the peer
// has not acknowledged yet.
//
// This is the only honest measure of how far ahead of the client the server
// is. `postSeq - postCumul` is not: postCumul is the CLIENT's own reliable-out
// counter — the value our packets carry as their cumul field — so that
// difference grows with the client's traffic and never shrinks with its acks.
func (q *resendQueue) outstanding(key string) int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.byKey[key])
}

// readdr points a session's unacknowledged packets at a new address.
//
// The client rebinds its UDP socket on battle entry and exit
// (`NetworkInterface::recreateListeningSocket` binds to all interfaces, so its
// source becomes e.g. 192.168.1.82:37483 while we were sending to
// 127.0.0.1:37483). The queue is keyed by session, so the acks that arrive
// from the new address still retire it; this only moves where the replays go,
// so a packet sent before the rebind is not retransmitted to the old port.
func (q *resendQueue) readdr(key, addr string) {
	if q == nil || addr == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range q.byKey[key] {
		p.addr = addr
	}
}

// due returns the packets that need resending now, and forgets the ones
// past the give-up deadline.
func (q *resendQueue) due(now time.Time) []resendJob {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []resendJob
	for key, list := range q.byKey {
		kept := list[:0]
		for _, p := range list {
			age := now.Sub(p.sent)
			if age >= q.giveUp || p.attempts >= resendMaxAttempts {
				q.abandoned++
				continue
			}
			if age >= q.timeout {
				out = append(out, resendJob{Addr: p.addr, Pkt: p.pkt, Seq: p.seq})
				p.sent = now
				p.attempts++
				q.resent++
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			delete(q.byKey, key)
			continue
		}
		q.byKey[key] = kept
	}
	return out
}

// forget drops every pending packet for a session (session teardown).
func (q *resendQueue) forget(key string) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.byKey, key)
}

// pendingFor reports how many of one session's packets are awaiting
// acknowledgement. The arena tick uses it to decide whether to fall back to the
// unreliable stream (see trackTurret).
func (q *resendQueue) pendingFor(key string) int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.byKey[key])
}

// pending reports how many packets are awaiting acknowledgement.
func (q *resendQueue) pending() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, list := range q.byKey {
		n += len(list)
	}
	return n
}

// stats renders the counters for a log line.
func (q *resendQueue) stats() (tracked, resent, acked, abandoned int) {
	if q == nil {
		return 0, 0, 0, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.tracked, q.resent, q.acked, q.abandoned
}
