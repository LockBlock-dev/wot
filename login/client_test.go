package login

// Offline LoginApp handshake through a scripted Transport: the fake
// server issues a PoW challenge (maxNonce wide open, so a canned
// all-zero solution verifies) then LOGGED_ON with an encrypted
// session record. This is the test the Transport interface exists
// for — Login had 0% coverage before it.
import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// scriptTransport replays canned replies in order and records writes.
type scriptTransport struct {
	mu     sync.Mutex
	writes [][]byte
	reads  [][]byte
}

func (f *scriptTransport) WriteToUDP(b []byte, _ *net.UDPAddr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (f *scriptTransport) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reads) == 0 {
		return 0, nil, errors.New("wotlogin: script exhausted")
	}
	r := f.reads[0]
	f.reads = f.reads[1:]
	copy(b, r)
	return len(r), &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 20016}, nil
}

func (f *scriptTransport) SetReadDeadline(_ time.Time) error { return nil }
func (f *scriptTransport) SetReadBuffer(_ int) error         { return nil }

// scriptReply builds [prefix4][00 00][FF][len][rid][status][body].
func scriptReply(rid uint32, status uint8, body []byte) []byte {
	out := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, msgReply, 0, 0, 0, 0}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], rid)
	out = append(out, tmp[:]...)
	out = append(out, status)
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[7:11], uint32(4+1+len(body)))
	return out
}

func fakeClientCfg() Config {
	return Config{
		Host: "203.0.113.9", Port: 20016,
		Login: "gapuser", Password: "fakepw", BlockKey: "0123456789abcdef",
		Session: "blob", Temporary: "1", AuthMethod: "basic",
		Publication: "0", Realm: "EU", Lang: "en", ClientContext: "{}",
		Encrypted: false, LoginAttempts: 1, Timeout: 2 * time.Second,
		FirstReplyID: 100,
	}
}

func fakeSolver() SolveFunc {
	// Fixed vector mined once (deterministic SipHash graph, first key
	// attempt): key "gaps-test:0" with maxNonce 2^32-1. The fake server
	// below issues exactly this prefix/bound, so verification is real
	// but no mining runs in the test.
	return func(_ context.Context, _ Challenge) (string, []uint32, error) {
		return "gaps-test:0", []uint32{4061, 10074, 19407, 22741, 36461, 36973, 60602, 66501, 67147, 67331, 69456, 74267, 79137, 139016, 152188, 162351, 170530, 230604, 236824, 261287, 273566, 287966, 320394, 322142, 323282, 339553, 359245, 379642, 380870, 398434, 425131, 482424, 498992, 502072, 513915, 518089, 519313, 527014, 532373, 534374, 535062, 559754}, nil
	}
}

func TestClientLoginOffline(t *testing.T) {
	const blockKey = "0123456789abcdef"
	chBody := appendPackedString(nil, challengeCuckoo)
	chBody = appendPackedString(chBody, "gaps-test:")
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], 1<<32-1)
	chBody = append(chBody, tmp[:]...)
	rec := loginReplyRecord([4]byte{92, 223, 20, 215}, 32838, 0x1234, 0x1327c898)
	enc, err := encryptLogin(blockKey, rec)
	if err != nil {
		t.Fatal(err)
	}
	fake := &scriptTransport{reads: [][]byte{
		scriptReply(100, statusChallengeIssued, chBody),
		scriptReply(101, statusLoggedOn, enc),
	}}
	cfg := fakeClientCfg()
	c, err := NewClient(cfg, nil, fakeSolver(), fake)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Login(ctx)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if s.ServerAddr.String() != "92.223.20.215" || s.ServerPort != 32838 || s.SessionKey != 0x1327c898 {
		t.Fatalf("session = %s:%d key=%08x", s.ServerAddr, s.ServerPort, s.SessionKey)
	}
	if len(fake.writes) != 2 {
		t.Fatalf("writes = %d, want 2 (login#1 + login#2)", len(fake.writes))
	}
	if len(fake.writes[1]) <= len(fake.writes[0]) {
		t.Fatal("login#2 must carry the challengeResponse prepend (longer than login#1)")
	}
	// Sequence continues exactly login#2+1 — the genuine stage-1 rid.
	if got := c.NextReplyID(); got != 102 {
		t.Fatalf("NextReplyID = %d, want 102", got)
	}
}

func TestClientLoginRejected(t *testing.T) {
	msg := appendPackedString(nil, "bad creds")
	fake := &scriptTransport{reads: [][]byte{scriptReply(100, 68, msg)}}
	c, err := NewClient(fakeClientCfg(), nil, fakeSolver(), fake)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Login(ctx); err == nil {
		t.Fatal("status 68 must reject")
	}
}

func TestNewClientBadPeer(t *testing.T) {
	cfg := fakeClientCfg()
	cfg.Host = "invalid..host..name..example"
	if _, err := NewClient(cfg, nil, fakeSolver(), &scriptTransport{}); err == nil {
		t.Fatal("unresolvable host must fail fast")
	}
}
