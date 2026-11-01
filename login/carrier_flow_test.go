package login

import "testing"

// TestCarrierFlowSelection pins the multi-flow guard: a capture that
// interleaves several sessions must be filtered to one flow, or the
// post-flood matcher pairs one session's terminator with another's
// ticks. An empty selector keeps the single-flow behaviour.
func TestCarrierFlowSelection(t *testing.T) {
	s := &BaseAppServer{}
	if !s.inFlow("127.0.0.1:35708->92.223.20.215:32874") {
		t.Error("empty selector rejected a record")
	}

	s.cfg.FloodFlow = "35708->"
	if !s.inFlow("127.0.0.1:35708->92.223.20.215:32874") {
		t.Error("selected flow rejected")
	}
	if s.inFlow("127.0.0.1:34587->92.223.20.215:32874") {
		t.Error("a different flow was accepted")
	}
	if s.inFlow("127.0.0.1:35708->92.223.20.215:32874") == false {
		t.Error("exact flow rejected")
	}
}
