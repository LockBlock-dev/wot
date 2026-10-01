// Package ping speaks the World of Tanks LoginApp ping protocol.
//
// Wire format (see NETWORK_PROTOCOL.md §§4,8), all integers little-endian
// unless noted. Every datagram starts with a 4-byte cleartext prefix
// (random per packet, excluded from any encryption) followed by 2-byte
// Mercury flags, then one LoginInterface message with ID 2 ("ping",
// FIXED, 1-byte sequence argument):
//
//	Request (16 B, client -> server, port 20016):
//	  [prefix 4][01 00][02][replyID u32][00 00][seq u8][02 00]
//	              flags   ID  match key  link   arg  reqOff
//
//	Reply (18 B in 2022 captures, 16 B on current servers, server -> client):
//	  [prefix 4][00 00][FF][len u32 = 5][replyID u32][seq u8][metric 2?]
//	              flags   ID  length      echo      echo  server trailer
//
// Current servers omit the 2-byte trailer (16 B replies); 2022 servers
// appended it (18 B). The trailer is accepted when present and reported
// raw via Result.Metric (Result.HasMetric).
//
// The server echoes replyID+seq so the client can match replies to
// requests; round-trip time is measured client-side. The 2-byte trailing
// metric is server-supplied (zero for the first two samples per host,
// varying afterwards) and its encoding is still unresolved — it is
// reported raw and never used for matching.
package ping

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	// DefaultPort is the LoginApp UDP port ping targets share with logins.
	DefaultPort = 20016

	// Mercury message IDs on the LoginApp interface.
	msgPing  = 0x02
	msgReply = 0xFF

	// Mercury packet flags (little-endian on the wire in the WoT fork).
	flagHasRequests = 0x0001

	reqLen = 16
	repLen = 18

	// Status bands mirror predefined_hosts.py (_LOW_PING_BOUNDARY_VAL = 59,
	// _NORM_PING_BOUNDARY_VAL = 119, milliseconds).
	lowBoundaryMs  = 59
	normBoundaryMs = 119
)

var (
	// ErrShort is returned for datagrams shorter than a full reply.
	ErrShort = errors.New("wotping: datagram too short")
	// ErrMalformed is returned when framing fields do not match.
	ErrMalformed = errors.New("wotping: malformed reply framing")
	// ErrMismatch is returned when a reply does not match the request
	// (different replyID or sequence); callers should keep reading.
	ErrMismatch = errors.New("wotping: reply does not match request")
)

// Result is the outcome of a single ping exchange.
type Result struct {
	Host      string        // "ip:port" of the probed server
	Seq       int           // sequence number sent (and echoed)
	RTT       time.Duration // client-measured round-trip time
	Metric    uint16        // raw 2-byte server trailer (big-endian read)
	HasMetric bool          // true when the reply carried the trailer
	Status    string        // LOW, NORM or HIGH (see Classify)
	Err       error         // non-nil if no usable reply arrived
}

// Classify maps an RTT to the buckets used by the game client.
func Classify(rtt time.Duration) string {
	ms := rtt.Milliseconds()
	switch {
	case ms <= lowBoundaryMs:
		return "LOW"
	case ms <= normBoundaryMs:
		return "NORM"
	default:
		return "HIGH"
	}
}

// encodeRequest builds a 16-byte ping request. The prefix is random per
// packet, matching observed traffic (it is not a sequence number).
func encodeRequest(replyID uint32, seq uint8) ([]byte, error) {
	var prefix [4]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, fmt.Errorf("wotping: prefix rand: %w", err)
	}
	return encodeRequestWithPrefix(prefix, replyID, seq), nil
}

// encodeRequestWithPrefix is encodeRequest with a caller-chosen prefix;
// it exists so unit tests can use deterministic vectors.
func encodeRequestWithPrefix(prefix [4]byte, replyID uint32, seq uint8) []byte {
	b := make([]byte, 0, reqLen)
	b = append(b, prefix[:]...)
	b = append(b, 0x01, 0x00, msgPing) // flags = HAS_REQUESTS, ID = ping
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], replyID)
	b = append(b, tmp[:]...)       // match key, echoed by server
	b = append(b, 0x00, 0x00, seq) // next-offset link, 1-byte seq arg
	b = append(b, 0x02, 0x00)      // first-request offset footer
	return b
}

// decodeReply parses a ping reply and checks it against the outstanding
// request. It accepts both the current 16-byte form (no trailer) and the
// 2022 18-byte form (2-byte trailer), returning the trailer when present.
func decodeReply(b []byte, wantReplyID uint32, wantSeq uint8) (metric uint16, hasMetric bool, err error) {
	if len(b) != repLen && len(b) != repLen-2 {
		return 0, false, fmt.Errorf("%w: got %d bytes, want %d or %d", ErrShort, len(b), repLen-2, repLen)
	}
	if b[4] != 0x00 || b[5] != 0x00 {
		return 0, false, fmt.Errorf("%w: flags %02x %02x", ErrMalformed, b[4], b[5])
	}
	if b[6] != msgReply || binary.LittleEndian.Uint32(b[7:11]) != 5 {
		return 0, false, fmt.Errorf("%w: bad reply header", ErrMalformed)
	}
	if got := binary.LittleEndian.Uint32(b[11:15]); got != wantReplyID {
		return 0, false, fmt.Errorf("%w: replyID %08x", ErrMismatch, got)
	}
	if b[15] != wantSeq {
		return 0, false, fmt.Errorf("%w: seq %d", ErrMismatch, b[15])
	}
	if len(b) == repLen {
		// Byte order of the trailer is unresolved; report big-endian.
		return binary.BigEndian.Uint16(b[16:18]), true, nil
	}
	return 0, false, nil
}

// Client is a shared UDP socket for pinging one or more servers.
// Replies to other outstanding requests are skipped by (replyID, seq),
// so a single Client can serve sequential PingOnce calls per host;
// use one replyID base per host, as the game does.
type Client struct {
	conn *net.UDPConn
}

// New binds an unconnected UDP socket for sending pings.
func New() (*Client, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("wotping: listen: %w", err)
	}
	return &Client{conn: conn}, nil
}

// Close releases the socket.
func (c *Client) Close() error {
	return c.conn.Close()
}

// NewReplyID returns a fresh random match key for a ping run.
func NewReplyID() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("wotping: replyID rand: %w", err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

// PingOnce sends one ping (sequence seq under replyID) and waits for its
// reply until timeout. Stray datagrams (mismatch, short, malformed) are
// skipped, not failed.
func (c *Client) PingOnce(addr *net.UDPAddr, replyID uint32, seq uint8, timeout time.Duration) Result {
	res := Result{Host: addr.String(), Seq: int(seq)}
	req, err := encodeRequest(replyID, seq)
	if err != nil {
		res.Err = err
		return res
	}
	sent := time.Now()
	if _, err := c.conn.WriteToUDP(req, addr); err != nil {
		res.Err = fmt.Errorf("wotping: send: %w", err)
		return res
	}
	if err := c.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		res.Err = fmt.Errorf("wotping: deadline: %w", err)
		return res
	}
	buf := make([]byte, 512)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			res.Err = fmt.Errorf("wotping: no reply to seq %d: %w", seq, err)
			return res
		}
		metric, hasMetric, err := decodeReply(buf[:n], replyID, seq)
		if errors.Is(err, ErrMismatch) || errors.Is(err, ErrShort) || errors.Is(err, ErrMalformed) {
			continue // someone else's reply or stray traffic; keep waiting
		}
		if err != nil {
			res.Err = err
			return res
		}
		res.RTT = time.Since(sent)
		res.Metric = metric
		res.HasMetric = hasMetric
		res.Status = Classify(res.RTT)
		return res
	}
}
