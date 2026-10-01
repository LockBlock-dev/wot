package tproxy

// Offline default: zero config means the documented 5-minute idle
// reap; explicit values pass through.
import (
	"testing"
	"time"
)

func TestIdleTimeoutDefault(t *testing.T) {
	var f Forwarder
	if got := f.idleTimeout(); got != 5*time.Minute {
		t.Fatalf("idleTimeout = %v, want 5m", got)
	}
	f.IdleTimeout = 30 * time.Second
	if got := f.idleTimeout(); got != 30*time.Second {
		t.Fatalf("idleTimeout = %v, want 30s", got)
	}
}
