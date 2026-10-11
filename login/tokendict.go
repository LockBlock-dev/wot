package login

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/LockBlock-dev/wot/lobby"
)

// TokenDict is one XMPPCS/WGNI token dict from S>C traffic: the
// pickled {databaseID, token} pair the TokenRequester answers arrive
// in (`_onTokenReceived(requestID, tokenType, data)` unpickles it
// into TokenResponse; DBID match + 3000 s validity gate use).
// Values never hit logs SANS explicit opt-in (see -show-token).
type TokenDict struct {
	DBID  int64
	Token string
	// JWT reports whether the token parses as a dot-separated JWT;
	// WGNI/shop tokens are JWTs, XMPPCS tails are not.
	JWT bool
}

// TokenID returns lengths + sha (never the value) for safe logging.
func (t TokenDict) TokenID() string {
	sum := sha256.Sum256([]byte(t.Token))
	return fmt.Sprintf("len=%d sha=%.8x", len(t.Token), sum[:4])
}

// FindTokenDicts scans one decrypted S>C body for pickled
// {databaseID, token} dicts: every `databaseID` hit is traced back
// to the nearest enclosing dict start and decoded. It returns unique
// hits (first wins). Pure offline parsing, no network.
func FindTokenDicts(clear []byte) []TokenDict {
	var out []TokenDict
	seen := map[string]bool{}
	for i := 0; i+10 < len(clear); i++ {
		if string(clear[i:i+10]) != "databaseID" {
			continue
		}
		start := -1
		for j := i - 1; j >= 0 && j > i-300; j-- {
			if clear[j] == 0x7d {
				start = j
				break
			}
		}
		if start < 0 {
			continue
		}
		end := -1
		if k := bytes.Index(clear[i:], []byte{0x75, 0x2e}); k >= 0 {
			end = i + k + 2
		}
		cands := [][]byte{clear[start:]}
		if end > start {
			cands = append([][]byte{clear[start:end]}, cands...)
		}
		var hits []TokenDict
		for _, frag := range cands {
			stk, _, err := lobby.DecodePrefix(frag)
			if err != nil {
				continue
			}
			for _, e := range stk {
				d, ok := e.(*lobby.PDict)
				if !ok {
					continue
				}
				var dbid int64
				var token string
				var hasDB, hasTok bool
				for _, en := range d.Entries {
					switch en.Key {
					case "databaseID":
						if v, ok := en.Value.(int64); ok {
							dbid, hasDB = v, true
						}
					case "token":
						switch v := en.Value.(type) {
						case string:
							token, hasTok = v, true
						case int64:
							token, hasTok = fmt.Sprintf("%d", v), true
						}
					}
				}
				if hasDB && hasTok {
					hits = append(hits, TokenDict{
						DBID:  dbid,
						Token: token,
						JWT:   len(strings.Split(token, ".")) == 3,
					})
				}
			}
			if len(hits) > 0 {
				break
			}
		}
		for _, h := range hits {
			if !seen[h.Token] {
				seen[h.Token] = true
				out = append(out, h)
			}
		}
	}
	return out
}
