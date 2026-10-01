package keydump

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AppendKey appends one timestamped hit to path in ce/wotkeydump.lua format
// ("STAMP ptr=%X len=%d key=%s" plus the 32 B strobj line), so wotproxy
// -keyfile and the CE flow share one reader. The key bytes themselves are
// file content only — callers must log lengths/hashes, never plaintext.
func AppendKey(path string, ptr uint64, key, strobj []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("keydump: open keyfile: %w", err)
	}
	defer f.Close()
	hexSpaced := func(b []byte) string {
		var sb strings.Builder
		for i, v := range b {
			if i > 0 {
				sb.WriteByte(' ')
			}
			fmt.Fprintf(&sb, "%02X", v)
		}
		return sb.String()
	}
	stamp := time.Now().Format("20060102_150405")
	if _, err := fmt.Fprintf(f, "%s ptr=%X len=%d key=%s\n", stamp, ptr, len(key), hexSpaced(key)); err != nil {
		return fmt.Errorf("keydump: write keyfile: %w", err)
	}
	if len(strobj) > 0 {
		if _, err := fmt.Fprintf(f, "  strobj=[%s]\n", hexSpaced(strobj)); err != nil {
			return fmt.Errorf("keydump: write keyfile: %w", err)
		}
	}
	// Under sudo the file lands root-owned and the (unprivileged) proxy
	// tail can't read it — hand it to the invoking user, mode untouched
	// (still 0600). allowlisted env only; never logs key bytes.
	if uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); uid != "" {
		if u, err1 := strconv.Atoi(uid); err1 == nil {
			g, _ := strconv.Atoi(gid)
			f.Chown(u, g) //nolint:errcheck // best effort; tail degrades loud
		}
	}
	return nil
}

// LatestKeys returns up to n most recent key= payloads, newest first.
// The 232B rewriter tries each in turn: the keyfile accumulates one key
// per login and the newest may lag the live session (scan passes trail
// the reply by ~0.1 s), so first-valid-wins beats newest-or-nothing
// (Sep 27: newest-only shipped a stale-key rewrite and killed the game).
func LatestKeys(path string, n int) ([][]byte, error) {
	if n <= 0 {
		n = 1
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("keydump: open keyfile: %w", err)
	}
	defer f.Close()
	var keys [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 65536)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, "key=")
		if i < 0 {
			continue
		}
		raw := strings.ReplaceAll(strings.TrimSpace(line[i+4:]), " ", "")
		if raw == "" {
			continue
		}
		b, err := hex.DecodeString(raw)
		if err != nil || len(b) == 0 {
			continue
		}
		keys = append(keys, b)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("keydump: read keyfile: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("keydump: no key= line in %s", path)
	}
	if len(keys) > n {
		keys = keys[len(keys)-n:]
	}
	for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
		keys[i], keys[j] = keys[j], keys[i]
	}
	return keys, nil
}

// LatestKey returns the most recent key= hex payload in path (spaces
// stripped). It mirrors what wotproxy -keyfile tails and what
// ce/hijack_trigger.lua feeds game.env BLOCK_KEY_HEX with.
func LatestKey(path string) ([]byte, error) {
	keys, err := LatestKeys(path, 1)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
}
