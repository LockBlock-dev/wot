package wgcs

// Token2 extraction from broker out-bufs (shapes only on screen).
import (
	"fmt"

	"github.com/LockBlock-dev/wot/login"
)

// FindToken2 scans buf for a token2-shaped run (3 colon-separated
// decimal segments, total 60-80 chars) in ASCII or UTF-16LE form
// (broker structs carry WCHAR inline: `1\0:\0…`). It returns the
// token string for keyfile storage only; callers print
// lengths/hashes, never the value.
func FindToken2(buf []byte) (string, bool) {
	if tok, ok := findRun(buf, false, 0); ok {
		return tok, true
	}
	// Wide pass at both parities (struct field may start odd).
	if tok, ok := findRun(buf, true, 0); ok {
		return tok, true
	}
	return findRun(buf, true, 1)
}

func findRun(buf []byte, wide bool, base int) (string, bool) {
	step := 1
	if wide {
		step = 2
	}
	start := -1
	flush := func(end int) (string, bool) {
		var cand []byte
		if wide {
			if (end-start)%2 != 0 {
				start = -1
				return "", false
			}
			for i := start; i < end; i += 2 {
				if buf[i+1] != 0 {
					start = -1
					return "", false
				}
				cand = append(cand, buf[i])
			}
		} else {
			cand = buf[start:end]
		}
		if len(cand) < 60 || len(cand) > 80 {
			start = -1
			return "", false
		}
		segs := 0
		digits := 0
		for i := 0; i < len(cand); i++ {
			c := cand[i]
			if c == ':' {
				segs++
				continue
			}
			if c < '0' || c > '9' {
				return "", false
			}
			digits++
		}
		if segs != 2 || digits < 50 {
			return "", false
		}
		start = -1
		return string(cand), true
	}
	isTok := func(c byte) bool { return (c >= '0' && c <= '9') || c == ':' }
	for i := base; i < len(buf); i += step {
		c := buf[i]
		if wide && (i+1 >= len(buf) || buf[i+1] != 0) {
			if start >= 0 {
				if tok, ok := flush(i); ok {
					return tok, true
				}
			}
			continue
		}
		if isTok(c) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if tok, ok := flush(i); ok {
				return tok, true
			}
		}
	}
	if start >= 0 {
		if tok, ok := flush(len(buf)); ok {
			return tok, true
		}
	}
	return "", false
}

// StoreToken2 writes a minted token2 to a 0600 keyfile (hex) for
// wotlogin TOKEN2 use; prints lengths/hashes only, never the value.
func StoreToken2(path, token string) error {
	if token == "" {
		return fmt.Errorf("wgcs: empty token2")
	}
	if err := login.WriteKeyFile(path, token); err != nil {
		return err
	}
	return nil
}

// TokenID hashes a token2 for logs (lengths/hashes only).
func TokenID(token string) string {
	return login.KeyID(token)
}
