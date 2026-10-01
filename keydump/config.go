package keydump

import "time"

// Config drives one headless dump run. PID 0 means find by ExeName.
// Needle/Mask nil means the vendored DefaultPattern (EU 2.4.0.0).
// WaitFor polls for the game process (and its loaded image) instead of
// failing when it isn't there yet — 0 keeps the old fail-fast behavior.
type Config struct {
	PID     int
	ExeName string
	Needle  []byte
	Mask    []byte
	KeyFile string
	MaxHits int
	Timeout time.Duration
	WaitFor time.Duration
}

func (c *Config) withDefaults() error {
	if c.ExeName == "" {
		c.ExeName = "WorldOfTanks.exe"
	}
	if c.Needle == nil {
		n, m, err := ParsePattern(DefaultPattern)
		if err != nil {
			return err
		}
		c.Needle, c.Mask = n, m
	}
	if c.KeyFile == "" {
		c.KeyFile = "wotkeys.txt"
	}
	if c.MaxHits <= 0 {
		c.MaxHits = 20 // same cap as ce/wotkeydump.lua MAXHITS
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Minute
	}
	return nil
}
