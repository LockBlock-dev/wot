package server

import "log/slog"

// log returns the configured logger, or a discarding one. Callers never
// have to nil-check: an unconfigured server is silent, which is what the
// tests and the thin CLIs want.
func (s *Server) log() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.New(slog.DiscardHandler)
}
