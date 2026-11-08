package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConfigFileFillsOnlyUnset pins the precedence rule: a flag given on
// the command line wins, the file fills the rest, and an absent key
// leaves the built-in default alone.
func TestConfigFileFillsOnlyUnset(t *testing.T) {
	// apply writes through the package-level flag targets, which main
	// normally allocates; give the test its own.
	flagAddr, flagPrivKey, flagS1, flagS2 = new(string), new(string), new(string), new(string)
	flagBaseApp = new(string)
	flagMaxNonce = new(int64)
	flagAnyVersion, flagVerbose = new(bool), new(bool)
	flagDigest, flagDB, flagUser, flagPass = new(string), new(string), new(string), new(string)

	*flagAddr = "127.0.0.1:20016" // the built-in default
	*flagS1 = "127.0.0.1:32850"
	*flagMaxNonce = 1000
	*flagVerbose = false

	path := filepath.Join(t.TempDir(), "wotserver.json")
	body := `{"addr":"0.0.0.0:20016","s1":"0.0.0.0:32900","maxnonce":5000,"verbose":true,"db":"/tmp/x.db"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// The command line set -addr and -s1; the file must not touch them.
	explicit := map[string]bool{"addr": true, "s1": true}
	cfg.apply(func(name string) bool { return explicit[name] })

	if *flagAddr != "127.0.0.1:20016" {
		t.Errorf("addr overridden by file: %q", *flagAddr)
	}
	if *flagS1 != "127.0.0.1:32850" {
		t.Errorf("s1 overridden by file: %q", *flagS1)
	}
	if *flagMaxNonce != 5000 {
		t.Errorf("maxnonce = %d, want 5000 from file", *flagMaxNonce)
	}
	if !*flagVerbose {
		t.Error("verbose not taken from file")
	}
	if *flagDB != "/tmp/x.db" {
		t.Errorf("db = %q, want /tmp/x.db from file", *flagDB)
	}
	if *flagS2 != "" {
		t.Errorf("s2 = %q, want untouched default", *flagS2)
	}
}

// TestConfigEmptyPathIsNoop keeps -config optional.
func TestConfigEmptyPathIsNoop(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if cfg.Addr != nil || cfg.DB != nil {
		t.Error("empty path produced a non-empty config")
	}
}

// TestConfigRejectsBadJSON surfaces a typo instead of silently running
// on defaults.
func TestConfigRejectsBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"addr":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}
