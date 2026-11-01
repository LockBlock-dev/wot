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
	// before it is sent again. The post-flood cadence is 100 ms, so this
	// is four ticks: long enough not to duplicate on ordinary jitter,
	// short enough that a lost answer does not visibly stall the client.
	resendTimeout = 400 * time.Millisecond
	// resendGiveUp is when we stop trying. A client that has not acked in
	// this long is gone; keeping the packet would leak memory for the
	// life of the process.
	resendGiveUp = 20 * time.Second
)

// pendingSend is one reliable packet awaiting acknowledgement.
type pendingSend struct {
	seq      uint32
	pkt      []byte
	sent     time.Time
	attempts int
}

// resendJob is one packet to put back on the wire.
type resendJob struct {
	Addr string
	Pkt  []byte
	Seq  uint32
}

// resendQueue holds the reliable packets each peer has not acknowledged.
type resendQueue struct {
	mu      sync.Mutex
	byAddr  map[string][]*pendingSend
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
		byAddr:  make(map[string][]*pendingSend),
		timeout: timeout,
		giveUp:  giveUp,
		now:     time.Now,
	}
}

// track records a reliable packet just sent to addr.
//
// A packet with no sequence number cannot be acknowledged, so it is not
// tracked: resending it would duplicate an unnumbered message.
func (q *resendQueue) track(addr string, seq uint32, pkt []byte) {
	if q == nil || len(pkt) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.byAddr[addr] = append(q.byAddr[addr], &pendingSend{
		seq:  seq,
		pkt:  append([]byte(nil), pkt...),
		sent: q.now(),
	})
	q.tracked++
}

// ack drops everything below the peer's cumulative-ack watermark: the
// client has received every packet with a lower sequence number.
func (q *resendQueue) ack(addr string, cumul uint32) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	list := q.byAddr[addr]
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
		delete(q.byAddr, addr)
		return
	}
	q.byAddr[addr] = kept
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
	for addr, list := range q.byAddr {
		kept := list[:0]
		for _, p := range list {
			age := now.Sub(p.sent)
			if age >= q.giveUp {
				q.abandoned++
				continue
			}
			if age >= q.timeout {
				out = append(out, resendJob{Addr: addr, Pkt: p.pkt, Seq: p.seq})
				p.sent = now
				p.attempts++
				q.resent++
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			delete(q.byAddr, addr)
			continue
		}
		q.byAddr[addr] = kept
	}
	return out
}

// forget drops every pending packet for a peer (session teardown).
func (q *resendQueue) forget(addr string) {
	if q == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.byAddr, addr)
}

// pending reports how many packets are awaiting acknowledgement.
func (q *resendQueue) pending() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, list := range q.byAddr {
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
