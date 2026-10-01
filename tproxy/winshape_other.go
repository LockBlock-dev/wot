//go:build !linux

package tproxy

import "net"

// ShapeUpstream is a no-op off Linux: TTL/DF shaping uses Linux
// setsockopt constants (see winshape_linux.go). Callers ignore the
// error (fail-open), so behavior elsewhere is today's defaults.
func ShapeUpstream(_ *net.UDPConn) error { return nil }
