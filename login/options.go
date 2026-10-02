package login

import "time"

// Option adjusts a Config. CLI flag overrides and tests compose them
// via ApplyOptions instead of mutating struct fields at call sites —
// the override vocabulary lives in the library, next to the defaults
// in LoadEnv. Options set verbatim; callers guard empties (a flag left
// unset contributes no Option).
type Option func(*Config)

// WithHost overrides LOGIN_HOST (e.g. another LoginApp cluster).
func WithHost(host string) Option {
	return func(c *Config) { c.Host = host }
}

// WithSession overrides SESSION (stored session blob text): reuse one
// value across runs to emulate an established machine instead of
// minting fresh per run.
func WithSession(blob string) Option {
	return func(c *Config) { c.Session = blob }
}

// WithTemporary overrides TEMPORARY ("0" = remembered, "1" = throwaway).
func WithTemporary(t string) Option {
	return func(c *Config) { c.Temporary = t }
}

// WithClientContext overrides CLIENT_CONTEXT JSON wholesale.
func WithClientContext(ctx string) Option {
	return func(c *Config) { c.ClientContext = ctx }
}

// WithBlockKey sets the Blowfish session key ("" = empty-key probe:
// server unencrypted-fallback path, also needs BLOCK_KEY_EMPTY=1
// semantics at LoadEnv).
func WithBlockKey(key string) Option {
	return func(c *Config) { c.BlockKey = key }
}

// WithThreads sets PoW workers (<=0 = auto).
func WithThreads(n int) Option {
	return func(c *Config) { c.Threads = n }
}

// WithSolveTimeout overrides the PoW budget.
func WithSolveTimeout(d time.Duration) Option {
	return func(c *Config) { c.SolveTimeout = d }
}

// WithMTU overrides the BaseApp MTU.
func WithMTU(mtu int) Option {
	return func(c *Config) { c.MTU = mtu }
}

// WithVerbose toggles stage diagnostics to stderr.
func WithVerbose(v bool) Option {
	return func(c *Config) { c.Verbose = v }
}

// ApplyOptions returns cfg with opts applied in order (cfg itself is
// never mutated — the caller keeps the pre-override value).
func ApplyOptions(cfg Config, opts ...Option) Config {
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}
