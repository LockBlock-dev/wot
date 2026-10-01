package tproxy

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Forwarder relays DNAT'd game datagrams upstream by original destination.
// One listener serves all flows; flows are keyed by client+origDst so
// LoginApp, stage-1, stage-2 and redirect targets multiplex safely.
// Reply traffic returns to the game's source address. Idle flows are
// reaped after IdleTimeout (0 = 5 min).
type Forwarder struct {
	Listen  *net.UDPAddr
	Resolve func(conn *net.UDPConn) (*net.UDPAddr, error)
	Dial    func(orig *net.UDPAddr) (*net.UDPConn, error)

	// OnDatagram observes a copy (dir is "C>S" or "S>C"); it must not
	// retain pkt. May be nil.
	OnDatagram func(dir string, client, orig *net.UDPAddr, pkt []byte)

	// RewriteSC optionally transforms upstream-to-client datagrams
	// (S>C) before delivery: return a replacement to send instead, or
	// nil to deliver the original. Used by wotproxy's stage-2
	// redirect rewrite (nil everywhere else, including transparent
	// mode — passthrough). Must be fast and non-blocking; errors are
	// signaled by returning nil (fail-open).
	RewriteSC func(client, orig *net.UDPAddr, pkt []byte) []byte

	IdleTimeout time.Duration
	ReadBuffer  int // SO_RCVBUF bytes; 0 = 4 MiB (lobby flood bursts lossy below)

	mu    sync.Mutex
	flows map[string]*flow
	lconn *net.UDPConn
	drops uint64

	stopOnce sync.Once
	stopCh   chan struct{}
	closed   atomic.Bool
}

type flow struct {
	up     *net.UDPConn
	client *net.UDPAddr
	orig   *net.UDPAddr
	last   time.Time
	done   chan struct{}
}

func (f *Forwarder) idleTimeout() time.Duration {
	if f.IdleTimeout > 0 {
		return f.IdleTimeout
	}
	return 5 * time.Minute
}

func (f *Forwarder) readBuffer() int {
	if f.ReadBuffer > 0 {
		return f.ReadBuffer
	}
	// Burst loss is real on the 400x1252B lobby flood (wot/login/baseapp.go
	// stageTwo: 175 frags vs ~150 with small buffers).
	return 4 << 20
}

func (f *Forwarder) dial(orig *net.UDPAddr) (*net.UDPConn, error) {
	if f.Dial != nil {
		up, err := f.Dial(orig)
		if err != nil {
			return nil, err
		}
		_ = ShapeUpstream(up) // best effort; failure keeps today's defaults
		return up, nil
	}
	// Fresh unconnected socket per flow; never connect() the listener
	// itself or other peers' datagrams die in-kernel (same lesson as
	// wot/login: one unconnected socket per peer set).
	up, err := net.DialUDP("udp", nil, orig)
	if err != nil {
		return nil, err
	}
	_ = ShapeUpstream(up) // best effort; failure keeps today's defaults
	return up, nil
}

// ListenAndServe runs until the listener errors. It returns nil only on
// close; per-flow errors are contained (flow closed, listener continues).
func (f *Forwarder) ListenAndServe() error {
	lconn, err := net.ListenUDP("udp", f.Listen)
	if err != nil {
		return fmt.Errorf("tproxy: listen: %w", err)
	}
	defer lconn.Close()
	f.mu.Lock()
	f.lconn = lconn
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.lconn = nil
		f.mu.Unlock()
	}()
	if err := lconn.SetReadBuffer(f.readBuffer()); err != nil {
		return fmt.Errorf("tproxy: rcvbuf: %w", err)
	}
	if err := f.enableRecv(lconn); err != nil {
		return fmt.Errorf("tproxy: recvopts: %w", err)
	}
	f.mu.Lock()
	f.flows = map[string]*flow{}
	f.stopCh = make(chan struct{})
	f.closed.Store(false)
	f.mu.Unlock()
	go f.reap()
	buf := make([]byte, 65535)
	for {
		client, orig, pkt, err := f.recv(lconn, buf)
		if err != nil {
			var de *dropError
			if errors.As(err, &de) {
				// Per-packet failure (no orig-dst info): NEVER forward
				// blindly — wrong upstream would spray game bytes at a
				// guessed host. Log loud (rate-limited) instead of
				// vanishing: silent drops cost a debug day (Sep 27: 7
				// DNAT'd packets, zero console lines).
				f.mu.Lock()
				f.drops++
				d := f.drops
				f.mu.Unlock()
				if d <= 10 || d%100 == 0 {
					fmt.Printf("tproxy: drop #%d: %v\n", d, de.msg)
				}
				continue
			}
			return fmt.Errorf("tproxy: read: %w", err)
		}
		caddr := client
		if f.OnDatagram != nil {
			f.OnDatagram("C>S", caddr, orig, pkt)
		}
		fl, err := f.flowFor(lconn, caddr, orig)
		if err != nil {
			f.mu.Lock()
			f.drops++
			d := f.drops
			f.mu.Unlock()
			if d <= 10 || d%100 == 0 {
				fmt.Printf("tproxy: drop #%d: %v\n", d, err)
			}
			continue
		}
		if _, err := fl.up.Write(pkt); err != nil {
			f.drop(key(caddr, orig))
		}
	}
}

// Close unblocks ListenAndServe. Flows drain via the reaper/expiry.
func (f *Forwarder) Close() error {
	f.stopOnce.Do(func() {
		f.mu.Lock()
		if f.stopCh != nil {
			close(f.stopCh)
		}
		f.mu.Unlock()
	})
	f.closed.Store(true)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lconn != nil {
		return f.lconn.Close()
	}
	return nil
}

// addrsEqual compares IP+port (nil-safe, for the dial-self guard).
func addrsEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

// dropError marks a per-packet failure (no orig-dst info): log loud,
// keep serving, never forward blindly.
type dropError struct{ msg string }

func (e *dropError) Error() string { return e.msg }

func key(client, orig *net.UDPAddr) string {
	return client.String() + "|" + orig.String()
}

func (f *Forwarder) flowFor(lconn *net.UDPConn, client, orig *net.UDPAddr) (*flow, error) {
	if addrsEqual(orig, lconn.LocalAddr().(*net.UDPAddr)) {
		// Belt-and-braces with recv's guard: dialing ourselves is a
		// geometric packet loop (Sep 27: 28k flows/s in the loopback
		// test before the guard existed).
		return nil, &dropError{"upstream is the listener itself"}
	}
	k := key(client, orig)
	f.mu.Lock()
	defer f.mu.Unlock()
	if fl, ok := f.flows[k]; ok {
		fl.last = time.Now()
		return fl, nil
	}
	up, err := f.dial(orig)
	if err != nil {
		// Blackhole so one bad target can't wedge the listener;
		// it expires via the reaper. Total socket failure (fd
		// exhaustion) is fatal, not a flow: say so loudly.
		up, _ = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
		if up == nil {
			up, _ = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}
		if up == nil {
			return nil, fmt.Errorf("tproxy: no sockets (fd exhaustion?) dialing %s: %w", orig, err)
		}
	}
	fl := &flow{up: up, client: client, orig: orig, last: time.Now(), done: make(chan struct{})}
	f.flows[k] = fl
	go f.relay(lconn, fl, k)
	return fl, nil
}

func (f *Forwarder) relay(lconn *net.UDPConn, fl *flow, k string) {
	defer func() {
		fl.up.Close() //nolint:errcheck // flow teardown
	}()
	buf := make([]byte, 65535)
	for {
		_ = fl.up.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := fl.up.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-fl.done:
					return
				default:
				}
				continue
			}
			f.drop(k)
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		if f.OnDatagram != nil {
			f.OnDatagram("S>C", fl.client, fl.orig, pkt)
		}
		if f.RewriteSC != nil {
			if fwd := f.RewriteSC(fl.client, fl.orig, pkt); fwd != nil {
				pkt = fwd
			}
		}
		if _, err := lconn.WriteToUDP(pkt, fl.client); err != nil {
			f.drop(k)
			return
		}
		f.mu.Lock()
		fl.last = time.Now()
		f.mu.Unlock()
	}
}

func (f *Forwarder) drop(k string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fl, ok := f.flows[k]; ok {
		close(fl.done)
		fl.up.Close() //nolint:errcheck // flow teardown
		delete(f.flows, k)
	}
}

func (f *Forwarder) reap() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-f.stopCh:
			return
		case <-t.C:
		}
		cut := time.Now().Add(-f.idleTimeout())
		f.mu.Lock()
		for k, fl := range f.flows {
			if fl.last.Before(cut) {
				close(fl.done)
				fl.up.Close() //nolint:errcheck // flow teardown
				delete(f.flows, k)
			}
		}
		f.mu.Unlock()
	}
}
