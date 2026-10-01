//go:build !linux && !windows

package keydump

import "errors"

// Run is unsupported on this OS: the breakpoint recipe needs ptrace/procfs
// (Linux/Wine) or the Win32 Debug API (Windows).
func Run(Config) error {
	return errors.New("keydump: unsupported OS (need linux or windows)")
}
