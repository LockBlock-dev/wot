//go:build linux

package tproxy

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestOrigDstFromCmsg decodes a hand-built IP_ORIGDSTADDR control message.
func TestOrigDstFromCmsg(t *testing.T) {
	payload := make([]byte, 16)
	binary.LittleEndian.PutUint16(payload[0:2], 2) // AF_INET
	binary.BigEndian.PutUint16(payload[2:4], 20016)
	copy(payload[4:8], net.ParseIP("185.12.240.40").To4())
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint64(hdr[0:8], uint64(16+len(payload)))
	binary.LittleEndian.PutUint32(hdr[8:12], 0)   // SOL_IP
	binary.LittleEndian.PutUint32(hdr[12:16], 20) // IP_ORIGDSTADDR
	addr, err := origDstFromCmsg(append(hdr, payload...))
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != "185.12.240.40:20016" {
		t.Fatalf("got %v", addr)
	}
	if _, err := origDstFromCmsg(nil); err == nil {
		t.Fatal("empty oob must fail")
	}
}
