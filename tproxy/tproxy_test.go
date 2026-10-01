package tproxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestParseSockaddr(t *testing.T) {
	var raw [16]byte
	binary.LittleEndian.PutUint16(raw[0:2], 2) // AF_INET
	binary.BigEndian.PutUint16(raw[2:4], 32838)
	copy(raw[4:8], net.ParseIP("92.223.20.215").To4())
	addr, err := parseSockaddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "92.223.20.215:32838" {
		t.Fatalf("got %v", addr)
	}
	raw[0] = 10 // AF_INET6: refuse
	if _, err := parseSockaddr(raw); err == nil {
		t.Fatal("non-IPv4 must fail")
	}
}

// TestForwardLoopback relays a datagram through the Forwarder to a local
// echo server with a stubbed resolver (no root/DNAT needed offline).
func TestForwardLoopback(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr) //nolint:errcheck // test echo
		}
	}()
	fw := &Forwarder{
		Listen:      &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		Resolve:     func(_ *net.UDPConn) (*net.UDPAddr, error) { return echo.LocalAddr().(*net.UDPAddr), nil },
		IdleTimeout: time.Minute,
	}
	done := make(chan error, 1)
	go func() { done <- fw.ListenAndServe() }()
	defer fw.Close() //nolint:errcheck // test teardown
	var laddr *net.UDPAddr
	for i := 0; i < 100 && laddr == nil; i++ {
		time.Sleep(10 * time.Millisecond)
		fw.mu.Lock()
		if fw.lconn != nil {
			laddr = fw.lconn.LocalAddr().(*net.UDPAddr)
		}
		fw.mu.Unlock()
	}
	if laddr == nil {
		t.Fatal("forwarder never listened")
	}
	c, err := net.DialUDP("udp", nil, laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping22")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping22" {
		t.Fatalf("got %q", buf[:n])
	}
}

// TestRewriteSCHook proves the S>C transform hook: the echo server's
// reply passes through RewriteSC and the client receives the patched
// bytes (wotproxy's stage-2 redirect rewrite rides this).
func TestRewriteSCHook(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr) //nolint:errcheck // test echo
		}
	}()
	var saw []byte
	fw := &Forwarder{
		Listen:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		Resolve: func(_ *net.UDPConn) (*net.UDPAddr, error) { return echo.LocalAddr().(*net.UDPAddr), nil },
		RewriteSC: func(_, _ *net.UDPAddr, pkt []byte) []byte {
			saw = append([]byte(nil), pkt...)
			out := append([]byte(nil), pkt...)
			copy(out, []byte("PONG"))
			return out
		},
		IdleTimeout: time.Minute,
	}
	done := make(chan error, 1)
	go func() { done <- fw.ListenAndServe() }()
	defer fw.Close() //nolint:errcheck // test teardown
	var laddr *net.UDPAddr
	for i := 0; i < 100 && laddr == nil; i++ {
		time.Sleep(10 * time.Millisecond)
		fw.mu.Lock()
		if fw.lconn != nil {
			laddr = fw.lconn.LocalAddr().(*net.UDPAddr)
		}
		fw.mu.Unlock()
	}
	if laddr == nil {
		t.Fatal("forwarder never listened")
	}
	c, err := net.DialUDP("udp", nil, laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping66")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "PONG66" {
		t.Fatalf("got %q (hook saw %q)", buf[:n], saw)
	}
}
