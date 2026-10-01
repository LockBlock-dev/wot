//go:build linux

package tproxy

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Windows-stack mimicry for upstream-facing UDP sockets (C_PLAN.md relay
// fingerprint): the game on Windows sends TTL 128 + DF cleared (it clears
// DF explicitly via setsockopt(IPPROTO_IP, 14 /* IP_DONTFRAGMENT */),
// wot/AGENTS.md blockade 1), while a stock Linux socket sends TTL 64 +
// DF set. ShapeUpstream sets TTL 128 and clears DF (IP_PMTUDISC_DONT)
// on IPv4 sockets so relayed datagrams carry the game's L3 shape.
//
// Best effort by design: any failure returns an error and the caller
// keeps today's defaults (fail-open — shaping must never break relaying).
// Non-IPv4 remotes are skipped (nil): v6 has no DF bit.
func ShapeUpstream(conn *net.UDPConn) error {
	if conn == nil {
		return fmt.Errorf("tproxy: shape nil conn")
	}
	if ip := conn.RemoteAddr().(*net.UDPAddr).IP; ip.To4() == nil {
		return nil
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("tproxy: shape syscallconn: %w", err)
	}
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		// Windows default TTL 128 (Linux default 64).
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, 128); err != nil {
			callErr = fmt.Errorf("tproxy: shape TTL: %w", err)
			return
		}
		// Clear DF: stock Linux path-MTU discovery sets it, the game
		// clears it. DONT (0) = never set DF.
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT); err != nil {
			callErr = fmt.Errorf("tproxy: shape DF: %w", err)
		}
	}); err != nil {
		return fmt.Errorf("tproxy: shape control: %w", err)
	}
	return callErr
}
