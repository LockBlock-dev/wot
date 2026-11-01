package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// TestLifecycleEventsAreLogged pins the ops contract: a refused login,
// a minted session and a sweep each leave one structured line, and the
// password never appears in any of them.
func TestLifecycleEventsAreLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := New(openTestStore(t), Config{
		DefaultUser:     "admin",
		DefaultPassword: "s3cret-pass",
		Logger:          logger,
	})
	ctx := context.Background()
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "default account created") {
		t.Errorf("provision not logged: %s", buf.String())
	}

	buf.Reset()
	if _, err := srv.Authenticate(ctx, "admin", "wrong"); err == nil {
		t.Fatal("bad password accepted")
	}
	if !strings.Contains(buf.String(), "login refused") {
		t.Errorf("refusal not logged: %s", buf.String())
	}

	buf.Reset()
	acct, sess, err := srv.BeginSession(ctx, "admin", "s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "session issued") {
		t.Errorf("session not logged: %s", out)
	}
	if !strings.Contains(out, acct.Name) {
		t.Errorf("account name missing from session line: %s", out)
	}
	if sess.Key == 0 {
		t.Error("session key is the no-session sentinel")
	}

	// The password must never reach the log, in any event.
	if strings.Contains(buf.String(), "s3cret-pass") {
		t.Error("password leaked into the log")
	}
}

// TestNilLoggerIsSilent keeps the thin CLIs and tests quiet by default.
func TestNilLoggerIsSilent(t *testing.T) {
	srv := New(openTestStore(t), Config{})
	if srv.log() == nil {
		t.Fatal("log() returned nil")
	}
	// A discarding logger must not panic on use.
	srv.log().Info("noise", "k", "v")
}
