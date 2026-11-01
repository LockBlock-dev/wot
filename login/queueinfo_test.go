package login

import (
	"os"
	"testing"
)

// TestQueueInfoTemplateLoads pins the 502 answer: CMD_REQ_QUEUE_INFO is
// answered with the 1a/67 small {players, classes}, and the template is
// taken from the bulk capture when the tail capture never saw a 502.
func TestQueueInfoTemplateLoads(t *testing.T) {
	const dump = "../../captures/proxy-20261014-1752.hex"
	if _, err := os.Stat(dump); err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	s := &BaseAppServer{cfg: BaseAppConfig{
		FloodPath:    dump,
		FloodKeyPath: "/tmp/k1752.txt",
		FloodFlow:    "35493->",
		BulkFragSize: 1252,
	}}
	if _, err := ReadAnyKeyFile(s.cfg.FloodKeyPath); err != nil {
		t.Skipf("key unavailable: %v", err)
	}
	if err := s.loadQueueTemplate(); err != nil {
		t.Fatalf("loadQueueTemplate: %v", err)
	}
	if s.queueAns == nil {
		t.Fatal("no queue-info template")
	}
	if !hasSmall(s.queueAns, 0x1a, 0x67) {
		t.Fatalf("template is not a 1a/67 small: % x", s.queueAns[:12])
	}
	// The minted answer slices [4:len-8], so the body must be longer.
	if len(s.queueAns) <= 12 {
		t.Fatalf("template too short to mint from: %d B", len(s.queueAns))
	}
	t.Logf("queue-info template: %d B clear", len(s.queueAns))
}
