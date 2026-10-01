//go:build linux

package tproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	solIP         = 0x0
	soOriginalDst = 80 // SO_ORIGINAL_DST: pre-DNAT sockaddr for the last datagram
	ipOrigDstAddr = 20 // IP_ORIGDSTADDR cmsg type / IP_RECVORIGDSTADDR sockopt
)

// OriginalDst returns the pre-DNAT destination of the datagram most
// recently read on conn. NOTE: this only works on sockets with
// connection-tracked state (TCP accept sockets). On UDP listeners the
// kernel answers ENOPROTOOPT — use the IP_RECVORIGDSTADDR cmsg path
// (enableRecv + recv) instead, which is per-packet and race-free. Kept
// as the Forwarder.Resolve fallback for tests and non-Linux builds.
func OriginalDst(conn *net.UDPConn) (*net.UDPAddr, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("tproxy: syscallconn: %w", err)
	}
	var addr *net.UDPAddr
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		var raw [16]byte
		ln := uint32(len(raw))
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, solIP, soOriginalDst,
			uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&ln)), 0)
		if errno != 0 {
			callErr = fmt.Errorf("tproxy: SO_ORIGINAL_DST: %v", errno)
			return
		}
		addr, callErr = parseSockaddr(raw)
	}); err != nil {
		return nil, fmt.Errorf("tproxy: control: %w", err)
	}
	if callErr != nil {
		return nil, callErr
	}
	return addr, nil
}

var errClosed = errors.New("tproxy: stopped")

// enableRecv turns on per-packet original-destination ancillary data.
// Without it the cmsg below never arrives and every datagram drops.
func (f *Forwarder) enableRecv(lconn *net.UDPConn) error {
	rc, err := lconn.SyscallConn()
	if err != nil {
		return err
	}
	var rerr error
	if cerr := rc.Control(func(fd uintptr) {
		rerr = unix.SetsockoptInt(int(fd), solIP, ipOrigDstAddr, 1)
	}); cerr != nil {
		return cerr
	}
	return rerr
}

// recv reads one datagram with its pre-DNAT destination. Precedence:
//  1. f.Resolve when set — explicit override, used by offline tests
//     (production leaves it nil and never shadows the cmsg path);
//  2. IP_ORIGDSTADDR cmsg, unless it names the listener itself
//     (direct traffic double-delivery — dialing it would loop);
//  3. otherwise *dropError — never a guessed upstream.
func (f *Forwarder) recv(lconn *net.UDPConn, buf []byte) (*net.UDPAddr, *net.UDPAddr, []byte, error) {
	rc, err := lconn.SyscallConn()
	if err != nil {
		return nil, nil, nil, err
	}
	var client, orig *net.UDPAddr
	var out []byte
	var rerr error
	cerr := rc.Control(func(fd uintptr) {
		oob := make([]byte, 256)
		var n, oobn int
		var from unix.Sockaddr
		for {
			// The fd is Go-managed (non-blocking): Recvmsg raises EAGAIN
			// instead of sleeping, so park in poll until readable. This
			// keeps the single-reader loop race-free without touching
			// the runtime netpoller.
			var err error
			n, oobn, _, from, err = unix.Recvmsg(int(fd), buf, oob, 0)
			if err == unix.EINTR {
				// Go preemption signals: retry, but yield first — a bare
				// continue can livelock against the signal source while
				// holding Control, which also wedges Close() (Sep 27:
				// test teardown hung with a live callback in Control).
				time.Sleep(time.Millisecond)
				continue
			}
			if err == unix.EAGAIN {
				// Bounded wait (not infinite): Close() blocks until an
				// in-flight Control callback returns, so the callback
				// must observe shutdown itself — a raw Poll is NOT woken
				// by concurrent Close (Sep 27: teardown hung forever in
				// fw.Close with a live Poll(-1) inside Control).
				pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				_, perr := unix.Poll(pfds, 250)
				if perr == unix.EINTR {
					time.Sleep(time.Millisecond)
					continue // Go preemption signals: retry, not fatal
				}
				if perr != nil {
					rerr = perr
					return
				}
				if f.closed.Load() {
					rerr = errClosed
					return
				}
				continue
			}
			if err != nil {
				rerr = err
				return
			}
			break
		}
		sa, ok := from.(*unix.SockaddrInet4)
		if !ok {
			rerr = &dropError{"non-IPv4 source"}
			return
		}
		client = &net.UDPAddr{IP: append(net.IP(nil), sa.Addr[:]...), Port: sa.Port}
		if f.Resolve != nil {
			var r2 error
			orig, r2 = f.Resolve(lconn)
			if r2 != nil {
				rerr = &dropError{r2.Error()}
				return
			}
		} else {
			orig, rerr = origDstFromCmsg(oob[:oobn])
			if rerr == nil {
				if self, _ := lconn.LocalAddr().(*net.UDPAddr); addrsEqual(orig, self) {
					rerr = &dropError{"origdst is the listener itself (no pre-NAT dst reported here; see doc.go limitation)"}
					return
				}
			} else {
				rerr = &dropError{"no ORIGDSTADDR cmsg (packet not DNAT'd?)"}
				return
			}
		}
		out = append([]byte(nil), buf[:n]...)
	})
	if cerr != nil {
		return nil, nil, nil, cerr
	}
	if rerr != nil {
		return nil, nil, nil, rerr
	}
	return client, orig, out, nil
}

// origDstFromCmsg decodes struct sockaddr_in from an IP_ORIGDSTADDR
// control message (family native LE on x86_64, port network order).
func origDstFromCmsg(oob []byte) (*net.UDPAddr, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, m := range cmsgs {
		if m.Header.Level == solIP && m.Header.Type == ipOrigDstAddr && len(m.Data) >= 8 {
			if binary.LittleEndian.Uint16(m.Data[0:2]) != 2 { // AF_INET
				continue
			}
			return &net.UDPAddr{
				IP:   append(net.IP(nil), m.Data[4:8]...),
				Port: int(binary.BigEndian.Uint16(m.Data[2:4])),
			}, nil
		}
	}
	return nil, fmt.Errorf("no ORIGDSTADDR cmsg")
}

// parseSockaddr decodes struct sockaddr_in (family native LE on our
// x86_64 hosts, port network order) as returned by SO_ORIGINAL_DST.
func parseSockaddr(raw [16]byte) (*net.UDPAddr, error) {
	if fam := binary.LittleEndian.Uint16(raw[0:2]); fam != 2 { // AF_INET
		return nil, fmt.Errorf("tproxy: original dst family %d (only IPv4)", fam)
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), raw[4:8]...),
		Port: int(binary.BigEndian.Uint16(raw[2:4])),
	}, nil
}
