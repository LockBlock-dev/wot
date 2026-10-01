package login

import (
	"net"
	"time"
)

// Transport is the UDP datagram surface the LoginApp handshake and the
// BaseApp stage scripts need: unconnected send plus deadline receive.
// *net.UDPConn is the production implementation (sockets stay
// unconnected: a connect()ed socket would drop other peers' datagrams
// in-kernel, and stage-1 reads from two sockets at once). Tests inject
// scripted fakes, which is what makes the LoginApp exchange
// unit-testable offline — every function below this surface that took
// *net.UDPConn now takes Transport, with zero call-site changes (the
// concrete type satisfies the interface implicitly) and byte-identical
// wire output.
type Transport interface {
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	SetReadDeadline(t time.Time) error
	// SetReadBuffer sizes the kernel receive buffer; stage-2 raises it
	// (burst loss is real: ~175 frags vs ~150). Fakes no-op it.
	SetReadBuffer(bytes int) error
}
