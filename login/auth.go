package login

import "encoding/json"

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
