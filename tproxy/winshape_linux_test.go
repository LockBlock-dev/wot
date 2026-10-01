//go:build linux

package tproxy

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestShapeUpstream dials loopback (offline, no live packets) and checks
// the socket reads back TTL 128 + DF cleared after shaping.
func TestShapeUpstream(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	uc, err := net.DialUDP("udp", nil, echo.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if err := ShapeUpstream(uc); err != nil {
		t.Fatal(err)
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ttl, disc int
	if err := rc.Control(func(fd uintptr) {
		var err error
		ttl, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
		if err != nil {
			t.Errorf("get TTL: %v", err)
			return
		}
		disc, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER)
		if err != nil {
			t.Errorf("get MTUDISC: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if ttl != 128 {
		t.Fatalf("TTL = %d, want 128", ttl)
	}
	if disc != unix.IP_PMTUDISC_DONT {
		t.Fatalf("MTUDISC = %d, want DONT(%d)", disc, unix.IP_PMTUDISC_DONT)
	}
	if err := ShapeUpstream(nil); err == nil {
		t.Fatal("nil conn must fail")
	}
}
