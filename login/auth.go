package login

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AuthProvider supplies the LogOnParams identity half: the username
// JSON and the password material. Config remains the data holder (env
// parsing, sockets, timeouts); the provider is the per-method behavior
// (basic | token | token2, see connection_mgr.py). Wire output is
// byte-identical to Config.Username + pwdToken: providers build the
// same param maps and run them through usernameOrder/encodeUsername,
// pinned by TestProviderUsernameMatchesConfig.
type AuthProvider interface {
	// Method is the auth_method wire value ("basic", "token", "token2").
	Method() string
	// Username renders the LogOnParams username JSON (key order per
	// key set, CE.txt ground truth — see Config.Username).
	Username() string
	// Password returns the LogOnParams password field for lang
	// (pwdToken transform: identity except CN/VN md5).
	Password(lang string) string
}

// BasicAuth is password login (no token keys on the wire).
type BasicAuth struct {
	Login       string
	Session     string // stored session blob text (md5-hexed into username)
	Temporary   string
	Publication string
	Realm       string
	PasswordVal string
	// MethodVal is the auth_method wire value, carried verbatim from
	// Config (like Config.Username before it). Type selection keys off
	// token presence (shape + key order); the method string itself is
	// never normalized — normalizing an inconsistent config would be a
	// wire change without live proof.
	MethodVal string
}

// TokenAuth carries the WGC fast token alongside basic fields.
type TokenAuth struct {
	BasicAuth
	Token string
}

// Token2Auth carries the upgraded token (password field emptied).
type Token2Auth struct {
	BasicAuth
	Token2 string
}

func (a BasicAuth) Method() string  { return a.MethodVal }
func (a TokenAuth) Method() string  { return a.MethodVal }
func (a Token2Auth) Method() string { return a.MethodVal }

func (a BasicAuth) Password(lang string) string { return pwdToken(lang, a.PasswordVal) }
func (a TokenAuth) Password(lang string) string { return pwdToken(lang, a.PasswordVal) }

// Token2 logins send an empty password (from-zero token2 login:
// 325B params, empty password — see the Oct-01 live passage).
func (a Token2Auth) Password(string) string { return "" }

// Username builds the basic key set (CE.txt line 15 order).
func (a BasicAuth) Username() string {
	params := map[string]string{
		"auth_method": a.Method(),
		"auth_realm":  a.Realm,
		"session":     md5hex(cpsaltSession(a.Session)),
		"login":       a.Login,
		"temporary":   a.Temporary,
		"publication": a.Publication,
	}
	return encodeUsername(params, usernameOrder(params))
}

// Username builds the token key set (sorted fallback, unobserved live).
func (a TokenAuth) Username() string {
	params := map[string]string{
		"auth_method": a.Method(),
		"auth_realm":  a.Realm,
		"session":     md5hex(cpsaltSession(a.Session)),
		"login":       a.Login,
		"temporary":   a.Temporary,
		"publication": a.Publication,
		"token":       a.Token,
	}
	return encodeUsername(params, usernameOrder(params))
}

// Username builds the token2 key set (CE.txt line 7 order).
func (a Token2Auth) Username() string {
	params := map[string]string{
		"auth_method": a.Method(),
		"auth_realm":  a.Realm,
		"session":     md5hex(cpsaltSession(a.Session)),
		"login":       a.Login,
		"temporary":   a.Temporary,
		"publication": a.Publication,
		"token2":      a.Token2,
	}
	return encodeUsername(params, usernameOrder(params))
}

// BrokerAuth replays a broker-minted loginData dict VERBATIM (the WGC
// token2 flavor): the game passes WGC.loginData() straight into
// connection_mgr.initiateConnection, which only md5s `session` and
// empties the password when token2 is present — every other key rides
// untouched (shipped 2.4.0.1 Manager.pyc _WgcModeManager.relogin +
// connection_mgr.pyc __setConnectionData, uncompyle6). Order is the
// LIVE dict iteration order (py2.7 hash order on the wire via
// json.dumps) captured by mods/wgc-token-mod — NOT sorted, NOT the
// CE.txt 7-key order (that is the remember-me/switchToToken2 flavor,
// Token2Auth above). Values keep their JSON types: numbers stay
// unquoted on the wire exactly like the game's json.dumps; only
// `session` (raw blob text) is transformed (md5hex, same helper as
// the basic path). String rendering matches Python json for ASCII
// (all broker dict values observed so far are digits/spaces/short
// tags; non-ASCII would need ensure_ascii \uXXXX form — unobserved).
type BrokerAuth struct {
	// Order is the live loginData iteration order (wire order).
	Order []string
	// Values is the loginData dict (session = RAW blob text, pre-md5).
	Values map[string]json.RawMessage
	// MethodVal is the auth_method wire value (from the dict).
	MethodVal string
}

func (a BrokerAuth) Method() string { return a.MethodVal }

// Password is empty: token2 present means no password material
// (connection_mgr.pyc __setConnectionData).
func (a BrokerAuth) Password(string) string { return "" }

// Username renders the verbatim params: session md5'd, every other
// value byte-identical to the broker dump, spaced separators like the
// game's json.dumps (", " and ": ").
func (a BrokerAuth) Username() string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range a.Order {
		raw, ok := a.Values[k]
		if !ok {
			continue
		}
		if i > 0 {
			sb.WriteString(", ")
		}
		// json.Marshal of a string is infallible.
		kb, _ := json.Marshal(k)
		sb.Write(kb)
		sb.WriteString(": ")
		if k == "session" {
			var blob string
			if err := json.Unmarshal(raw, &blob); err == nil {
				// json.Marshal of a string is infallible.
				mb, _ := json.Marshal(md5hex(cpsaltSession(blob)))
				sb.Write(mb)
				continue
			}
		}
		sb.Write(raw)
	}
	sb.WriteByte('}')
	return sb.String()
}

// ParseBrokerParams parses the operator-pasted broker dump
// (mods/wgc-token-mod JSON blocks):
// {"order":[...], "params":{...}}. It fails loud on shape problems
// (order/params mismatch, missing or empty token2, non-string
// session) — a fresh tail must never be spent on a malformed shape.
func ParseBrokerParams(raw []byte) (BrokerAuth, error) {
	var dump struct {
		Order  []string                   `json:"order"`
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: %w", err)
	}
	if len(dump.Order) == 0 || len(dump.Params) == 0 {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: empty order/params")
	}
	if len(dump.Order) != len(dump.Params) {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: order has %d keys, params has %d",
			len(dump.Order), len(dump.Params))
	}
	seen := map[string]struct{}{}
	for _, k := range dump.Order {
		if _, dup := seen[k]; dup {
			return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: duplicate key %q", k)
		}
		seen[k] = struct{}{}
		v, ok := dump.Params[k]
		if !ok {
			return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: order key %q absent from params", k)
		}
		if len(v) == 0 {
			return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: empty value for %q", k)
		}
	}
	tokRaw, ok := dump.Params["token2"]
	if !ok {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: no token2 (not a token2 login)")
	}
	var tok string
	if err := json.Unmarshal(tokRaw, &tok); err != nil || tok == "" {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: token2 absent or empty")
	}
	sessRaw, ok := dump.Params["session"]
	if !ok {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: no session")
	}
	var blob string
	if err := json.Unmarshal(sessRaw, &blob); err != nil {
		return BrokerAuth{}, fmt.Errorf("wotlogin: broker params: session not a string")
	}
	method := "token2"
	if mRaw, ok := dump.Params["auth_method"]; ok {
		var m string
		if err := json.Unmarshal(mRaw, &m); err == nil && m != "" {
			method = m
		}
	}
	return BrokerAuth{Order: dump.Order, Values: dump.Params, MethodVal: method}, nil
}

// ProviderForConfig selects the provider for cfg: token2 wins over
// token (LoginApp binds session→token2-middle; the from-zero token2
// leg carries token2 only), token over basic.
func ProviderForConfig(cfg Config) AuthProvider {
	base := BasicAuth{
		Login:       cfg.Login,
		Session:     cfg.Session,
		Temporary:   cfg.Temporary,
		Publication: cfg.Publication,
		Realm:       cfg.Realm,
		PasswordVal: cfg.Password,
		MethodVal:   cfg.AuthMethod,
	}
	switch {
	case cfg.Token2 != "":
		return Token2Auth{BasicAuth: base, Token2: cfg.Token2}
	case cfg.Token != "":
		return TokenAuth{BasicAuth: base, Token: cfg.Token}
	default:
		return BasicAuth(base)
	}
}

// ExtractUpgradeToken pulls token2 out of a login reply ServerMsg
// without logging it (SSO material). Returns "" when there is nothing
// to upgrade to: key absent, null, "", or unparseable. Shape logging
// (lengths only) stays at the call site, never here.
func ExtractUpgradeToken(msg string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(msg), &m); err != nil {
		return ""
	}
	raw, ok := m["token2"]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// ReloginConfig derives the from-zero token2 config from a basic one:
// auth_method=token2, token2 set, password emptied. The caller reloads
// env defaults first (like the game path never re-logging: this is
// diagnostic only, NOT game behavior).
func ReloginConfig(base Config, token2 string) Config {
	base.AuthMethod = "token2"
	base.Token2 = token2
	base.Password = ""
	return base
}
