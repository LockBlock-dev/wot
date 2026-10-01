//go:build !linux

package tproxy

import (
	"errors"
	"net"
)

// OriginalDst needs Linux conntrack state; transparent mode runs on the
// Proton host. Explicit LoginApp proxying (wotproxy without -transparent)
// works anywhere.
func OriginalDst(_ *net.UDPConn) (*net.UDPAddr, error) {
	return nil, errors.New("tproxy: transparent mode needs linux")
}

// enableRecv is a no-op off Linux: no cmsg path, recv() falls back to
// f.Resolve (tests) or drops.
func (f *Forwarder) enableRecv(_ *net.UDPConn) error { return nil }

// recv reads one datagram and resolves its upstream via f.Resolve.
// Without a resolver it returns *dropError — never a guessed upstream.
func (f *Forwarder) recv(lconn *net.UDPConn, buf []byte) (*net.UDPAddr, *net.UDPAddr, []byte, error) {
	n, caddr, err := lconn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, nil, err
	}
	if f.Resolve == nil {
		return nil, nil, nil, &dropError{"tproxy: no resolver (transparent mode needs linux)"}
	}
	orig, err := f.Resolve(lconn)
	if err != nil {
		return nil, nil, nil, &dropError{err.Error()}
	}
	return caddr, orig, append([]byte(nil), buf[:n]...), nil
}
