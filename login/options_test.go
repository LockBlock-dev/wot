package login

import (
	"testing"
	"time"
)

func TestApplyOptions(t *testing.T) {
	base := Config{Host: "a", Session: "s", MTU: 1300, Threads: 0}
	got := ApplyOptions(base,
		WithHost("b"),
		WithSession("blob"),
		WithTemporary("0"),
		WithClientContext(`{"lang_id": "fr"}`),
		WithBlockKey("k"),
		WithThreads(3),
		WithSolveTimeout(9*time.Second),
		WithMTU(1200),
		WithVerbose(true),
		nil, // nil options are skipped
	)
	if got.Host != "b" || got.Session != "blob" || got.Temporary != "0" {
		t.Fatalf("identity overrides = %+v", got)
	}
	if got.ClientContext != `{"lang_id": "fr"}` || got.BlockKey != "k" {
		t.Fatalf("material overrides = %+v", got)
	}
	if got.Threads != 3 || got.SolveTimeout != 9*time.Second || got.MTU != 1200 || !got.Verbose {
		t.Fatalf("tuning overrides = %+v", got)
	}
	// Input never mutated: the caller keeps the pre-override value.
	if base.Host != "a" || base.Session != "s" || base.MTU != 1300 || base.Threads != 0 {
		t.Fatalf("base mutated = %+v", base)
	}
	// Order wins last (mirrors the CLI empty-key/raw-key sequence).
	got = ApplyOptions(base, WithBlockKey(""), WithBlockKey("raw16byteshere"))
	if got.BlockKey != "raw16byteshere" {
		t.Fatalf("last-wins BlockKey = %q", got.BlockKey)
	}
}
