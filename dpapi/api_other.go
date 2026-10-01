//go:build !windows

package dpapi

// Unprotect is windows-only (Wine crypt32 in-prefix).
func Unprotect(hexBlob string) ([]byte, error) {
	return nil, ErrNeedWindows
}
