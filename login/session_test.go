package login

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A cancelled context runs no packets: the machine fails before the
// first send (offline proof the Run path owns its sockets).
func TestBaseAppSessionRunCancelled(t *testing.T) {
	fake := &scriptTransport{}
	peer := &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 32838}
	s := Session{ServerAddr: net.ParseIP("203.0.113.9"), ServerPort: 32838, SessionKey: 0x1327c898}
	b := NewBaseAppSession(s, "0123456789abcdef", 1300, fake, fake, peer)
	if got := b.Session(); got.SessionKey != s.SessionKey {
		t.Fatal("Session accessor mismatch")
	}
	if got := b.Peer().String(); got != peer.String() {
		t.Fatal("Peer accessor mismatch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Run(ctx, 102); err == nil {
		t.Fatal("cancelled Run must fail")
	}
	if len(fake.writes) != 0 {
		t.Fatalf("cancelled Run sent %d packets, want 0", len(fake.writes))
	}
	// The legacy wrapper stays equivalent (same failure, no packets).
	fake2 := &scriptTransport{}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := BaseAppLogin(ctx2, fake2, fake2, peer, s, "0123456789abcdef", 1300, 102); err == nil {
		t.Fatal("cancelled BaseAppLogin must fail")
	}
	if len(fake2.writes) != 0 {
		t.Fatalf("cancelled BaseAppLogin sent %d packets, want 0", len(fake2.writes))
	}
	_ = time.Now // keep time import if unused in future edits
}

func TestSessionUpgradeToken(t *testing.T) {
	const real = "1:22:333"
	s := Session{ServerMsg: `{"token2":"` + real + `"}`}
	if got := s.UpgradeToken(); got != real {
		t.Fatalf("UpgradeToken len=%d, want len=%d", len(got), len(real))
	}
	if got := (Session{ServerMsg: `{"security_msg":"old_pass"}`}).UpgradeToken(); got != "" {
		t.Fatal("absent token2 must yield empty")
	}
}

func TestRecordMiddle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pairs")
	n, err := RecordMiddle(path, "blob", "111:22222:333")
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("middle len = %d, want 5", n)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(raw))
	md5hex, mid, ok := strings.Cut(line, ",")
	if !ok || len(md5hex) != 32 || mid != "22222" {
		t.Fatalf("pairs line shape = %q", line)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("pairs file mode = %v, err = %v", fi.Mode(), err)
	}
	// Malformed token2 records nothing and fails nothing.
	if n, err := RecordMiddle(path, "blob", "no-colons"); err != nil || n != 0 {
		t.Fatalf("malformed = (%d, %v), want (0, nil)", n, err)
	}
}
