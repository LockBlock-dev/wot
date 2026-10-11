package login

import (
	"bufio"
	"crypto/md5" //nolint:gosec // game-mandated session hashing
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config carries everything Login needs. Secrets come from the .env file
// (see .env.example); nothing secret is logged.
type Config struct {
	Host          string // LoginApp DNS name, e.g. login.p2.worldoftanks.eu
	Port          int
	AuthMethod    string // basic | token | token2 (connection_mgr.py)
	Realm         string // auth_realm, e.g. EU
	Lang          string // client language id for pwd_token + clientContext
	Login         string // account login (basic) — also embedded in JSON
	Password      string // plaintext; transformed per locale by pwdToken
	Token         string // WGC fast token (token method)
	Token2        string // upgraded token (token2 method)
	Session       string // stored session blob text, md5-hexed into the username JSON
	Temporary     string // "1" = throwaway session (not rememberUser)
	Publication   string // WGC publication id: 0 = PC launcher, -1 = unknown
	PubkeyPath    string // loginapp RSA pubkey PEM file
	BlockKey      string // Blowfish session key we generate (encryptionKey)
	ClientContext string // 4th LogOnParams string: game sends JSON
	// {lang_id, publication} (connection_mgr.__setConnectionData)
	Encrypted     bool     // RSA-encrypt params (false = plaintext probe)
	Digest        [16]byte // entity-defs MD5 (server rejects mismatch, status 70)
	MTU           int
	FooterPad     int           // zero bytes before reqOff footer (experimental)
	Verbose       bool          // stage diagnostics to stderr
	Timeout       time.Duration // per round-trip
	SolveTimeout  time.Duration // PoW solver budget
	Threads       int           // PoW workers (<=0 = auto, 4 concurrent key attempts)
	LoginAttempts int           // login request resends (RetryingRequest)
	FirstReplyID  uint32        // starting Mercury ReplyID
	nonce         uint32
}

// Username builds the LogOnParams username JSON. Ground truth from the
// live client (CE.txt key order + game.log Sep-19 connection_mgr params:
// py2.7 dict hash order, NOT sorted): temporary="1" (throwaway session;
// remember_user is None in the live prefs — the old "0" default matched
// only the stale CE.txt era and is withdrawn):
// {"auth_realm": "EU", "login": ..., "session": md5, "temporary": "1",
//
//	"auth_method": "basic", "publication": "0"}.
//
// (py2.7 dict hash order, NOT sorted: CE.txt lines 7/15 print the live
// game's params dicts as token2/session/temporary/publication/
// auth_realm/login/auth_method (token2 set) and auth_realm/login/
// session/temporary/auth_method/publication (basic set). An earlier
// "sorted" reading of line 15 was wrong — sorted would put
// auth_method first. Unobserved key sets (token method) keep sorted
// fallback. EU 1.27.1 connection_mgr.__setConnectionData:176-199;
// login params assembled in gui/login/manager.initiateLogin:99-103;
// confirmed against the real 2.4.0.0 .pyc via uncompyle6 Sep 2026.)
func (c Config) Username() string {
	params := map[string]string{
		"auth_method": c.AuthMethod,
		"auth_realm":  c.Realm,
		"session":     md5hex(cpsaltSession(c.Session)),
		"login":       c.Login,
		"temporary":   c.Temporary,
		"publication": c.Publication,
	}
	if c.Token != "" {
		params["token"] = c.Token
	}
	if c.Token2 != "" {
		params["token2"] = c.Token2
	}
	return encodeUsername(params, usernameOrder(params))
}

// usernameOrder reproduces the live client's key order per key set
// (CE.txt ground truth); unknown sets fall back to sorted.
func usernameOrder(params map[string]string) []string {
	_, hasToken := params["token"]
	_, hasToken2 := params["token2"]
	switch {
	case !hasToken && !hasToken2:
		// Basic set, CE.txt line 15.
		return []string{"auth_realm", "login", "session", "temporary", "auth_method", "publication"}
	case !hasToken && hasToken2:
		// Token2 set, CE.txt line 7.
		return []string{"token2", "session", "temporary", "publication", "auth_realm", "login", "auth_method"}
	default:
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return keys
	}
}

func encodeUsername(params map[string]string, order []string) string {
	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	for _, k := range order {
		v, ok := params[k]
		if !ok {
			continue
		}
		if !first {
			sb.WriteString(", ")
		}
		first = false
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(v)
		sb.Write(kb)
		sb.WriteString(": ")
		sb.Write(vb)
	}
	sb.WriteByte('}')
	return sb.String()
}

// Peer resolves the LoginApp UDP address (DNS allowed).
func (c Config) Peer() (*net.UDPAddr, error) {
	return net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.Host, c.Port))
}

// Nonce returns the LogOnParams nonce (one per process, like std::rand init).
func (c *Config) Nonce() uint32 { return c.nonce }

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // game-mandated hashing
	return hex.EncodeToString(sum[:])
}

// cpsaltSession mirrors BigWorld.wg_cpsalt (IDA sub_140EFB2A0): it only
// ensures the stored session BLOB exists (empty store mints a GUID via
// CoCreateGuid, DPAPI-protects it, persists it — stable per machine).
// The wire `session` is md5hex of the BLOB TEXT itself, not of the
// decrypted GUID (proven Sep 2026: md5(blob ASCII) == the genuine wire
// hash in captures/CE.txt; every GUID variant misses). So a non-empty
// SESSION passes through UNCHANGED and must be the blob text (base64
// DPAPI); empty mints a v4 GUID per run as a best-effort fallback
// (genuine would protect-then-md5 — unreproducible offline).
// The game NEVER sends md5("") (d41d8cd98f00b204e9800998ecf8427e).
func cpsaltSession(stored string) string {
	if stored != "" {
		return stored
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return stored
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// LoadEnv reads KEY=VALUE lines (strips `export `, quotes, # comments)
// and maps the documented keys onto Config with sane defaults.
func LoadEnv(path string) (Config, error) {
	c := Config{
		Port:         DefaultPort,
		AuthMethod:   "basic",
		Realm:        "EU",
		Lang:         "en",
		Temporary:    "1",
		Publication:  "0", // WGC_PC launcher install (standalone = -1)
		PubkeyPath:   "../../World_of_Tanks_EU/2.4.0.0/res/loginapp_wot.pubkey",
		Encrypted:    true,
		MTU:          1300,
		Timeout:      5 * time.Second,
		SolveTimeout: 120 * time.Second,
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return c, err
	}
	// Genuine ReplyIDs are small (< 2^17 in every capture: logins count
	// 80356→80357, pings 48569…; stage-1 continues the login sequence
	// (+1: 80358/82103/50983), only stage-2 mints fresh
	// (95197/53365/105623)) — never full-range u32. Bound ours the
	// same way; a manager-side rid handler sized for the genuine range
	// is the cheapest explanation left for silence with otherwise
	// perfect bytes.
	c.FirstReplyID = binary.LittleEndian.Uint32(b[:]) & 0x1FFFF
	if c.FirstReplyID == 0 {
		c.FirstReplyID = 1 // genuine ReplyIDs are never zero
	}
	if _, err := rand.Read(b[:]); err != nil {
		return c, err
	}
	c.nonce = binary.LittleEndian.Uint32(b[:])

	f, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("wotlogin: open .env: %w", err)
	}
	defer f.Close()
	vals := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		vals[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		return c, fmt.Errorf("wotlogin: read .env: %w", err)
	}
	str := func(k, def string) string {
		if v, ok := vals[k]; ok && v != "" {
			return v
		}
		return def
	}
	num := func(k string, def int) int {
		if v, ok := vals[k]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
		return def
	}
	dur := func(k string, def time.Duration) time.Duration {
		if v, ok := vals[k]; ok {
			if d, err := time.ParseDuration(v); err == nil {
				return d
			}
		}
		return def
	}
	c.Host = str("LOGIN_HOST", "")
	c.Port = num("LOGIN_PORT", c.Port)
	c.AuthMethod = str("AUTH_METHOD", c.AuthMethod)
	c.Realm = str("AUTH_REALM", c.Realm)
	c.Lang = str("LANG", c.Lang)
	c.Login = str("LOGIN", "")
	c.Password = str("PASSWORD", "")
	c.Token = str("TOKEN", "")
	c.Token2 = str("TOKEN2", "")
	c.Session = str("SESSION", "")
	c.Temporary = str("TEMPORARY", c.Temporary)
	c.Publication = str("PUBLICATION", c.Publication)
	c.PubkeyPath = str("PUBKEY_PATH", c.PubkeyPath)
	c.BlockKey = str("BLOCK_KEY", "")
	// BLOCK_KEY_HEX: raw key bytes as hex — the CE memory dumps are hex
	// and the game's RAND_bytes key is full-range binary (NUL bytes),
	// unrepresentable as the text BLOCK_KEY. Overrides BLOCK_KEY when
	// set (Blowfish accepts 4-56 B, protocol doc §5).
	if bh, ok := vals["BLOCK_KEY_HEX"]; ok && strings.TrimSpace(bh) != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(bh))
		if err != nil || len(raw) < 4 || len(raw) > 56 {
			return c, fmt.Errorf("wotlogin: BLOCK_KEY_HEX must be 4-56 B of hex")
		}
		c.BlockKey = string(raw)
	}
	// clientContext mirrors the game default (connection_mgr
	// __setConnectionData: json {lang_id, publication}); explicit
	// CLIENT_CONTEXT still overrides it wholesale.
	c.ClientContext = str("CLIENT_CONTEXT", defaultClientContext(c.Lang, c.Publication))
	c.Encrypted = str("ENCRYPTED", "1") == "1"
	if dh, ok := vals["DIGEST_HEX"]; ok && dh != "" {
		raw, err := hex.DecodeString(strings.TrimSpace(dh))
		if err != nil || len(raw) != 16 {
			return c, fmt.Errorf("wotlogin: DIGEST_HEX must be 32 hex chars")
		}
		copy(c.Digest[:], raw)
	}
	c.MTU = num("MTU", c.MTU)
	c.FooterPad = num("FOOTER_PAD", 0)
	c.Verbose = vals["VERBOSE"] == "1"
	c.Timeout = dur("TIMEOUT", c.Timeout)
	c.SolveTimeout = dur("SOLVE_TIMEOUT", c.SolveTimeout)
	c.Threads = num("THREADS", 0)
	// Exe LoginRequestProtocol ctor (sub_140E68910) defaults to 10
	// attempts (+16=10; per-type overrides from the config table are
	// unresolved, so the default cap applies to all transports here).
	c.LoginAttempts = num("LOGIN_ATTEMPTS", 10)
	if c.Host == "" {
		return c, fmt.Errorf("wotlogin: LOGIN_HOST missing in %s", path)
	}
	if c.BlockKey == "" && vals["BLOCK_KEY_EMPTY"] != "1" {
		// Fresh Blowfish key per run, like EncryptionFilter(keySize).
		// Alphanumeric only (no NUL bytes): the key crosses a C++
		// boundary on both ends (packed string, RSA block, BF_set_key),
		// and any layer sizing it via strlen instead of its explicit
		// length would silently truncate a key containing 0x00,
		// desynchronizing our decrypt from the server's encrypt.
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		kb := make([]byte, 16)
		if _, err := rand.Read(kb); err != nil {
			return c, err
		}
		for i := range kb {
			kb[i] = alphabet[int(kb[i])%len(alphabet)]
		}
		c.BlockKey = string(kb)
	}
	// BLOCK_KEY_EMPTY=1: send an empty encryptionKey (the fork's
	// LogOnParams streams whatever string it gets). Server side,
	// Proxy::attachToClient falls back to an unencrypted connection
	// when the key is empty — IF the login path accepts it, the 232B
	// record and the baseapp channel go plaintext (proxy-visible).
	// Diagnostic only; the game never does this.
	return c, nil
}

// defaultClientContext renders the game's clientContext JSON
// ({lang_id, publication}) with json.dumps default separators.
func defaultClientContext(lang, publication string) string {
	return fmt.Sprintf(`{"lang_id": %q, "publication": %q}`, lang, publication)
}

// unquote strips one layer of matching single/double quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
