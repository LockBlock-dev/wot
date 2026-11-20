package login

import "testing"

// TestTokenLoginMapsToAnAccount is the Steam case: the client sends a
// token and leaves `login` empty, so there is no name to look up.
func TestTokenLoginMapsToAnAccount(t *testing.T) {
	// A representative document of the shape a Steam build sends
	// (values anonymized).
	token2 := `{"session": "0123456789abcdef0123456789abcdef", "token2": "123456789:1234567890123456789:123456789012345678901234567890123456789", "gameid": "wot", "publication": "2", "allowed_peripheries": "201 202", "auth_realm": "eu", "login": "", "auth_method": "token2", "account_complete": "1"}`
	if got := tokenLoginName(token2, "admin"); got != "admin" {
		t.Errorf("token2 login mapped to %q, want admin", got)
	}

	token := `{"gameid": "wot", "token": "12345678", "session": "0123456789abcdef0123456789abcdef", "publication": "2", "allowed_peripheries": "201 202", "auth_realm": "eu", "account_complete": "1", "login": "", "requested_for": "wot", "account_id": "123456789", "auth_method": "token"}`
	if got := tokenLoginName(token, "admin"); got != "admin" {
		t.Errorf("token login mapped to %q, want admin", got)
	}
}

// TestBasicLoginIsNotMapped keeps a typed username authoritative: a real
// login must never be redirected to the token account.
func TestBasicLoginIsNotMapped(t *testing.T) {
	basic := `{"login": "playerone", "session": "abc", "auth_method": "basic", "auth_realm": "eu"}`
	if got := tokenLoginName(basic, "admin"); got != "" {
		t.Errorf("basic login mapped to %q, want no mapping", got)
	}
	// A document with a login and a token still uses the login.
	both := `{"login": "playerone", "token2": "x", "auth_method": "token2"}`
	if got := tokenLoginName(both, "admin"); got != "" {
		t.Errorf("named token login mapped to %q, want no mapping", got)
	}
}

// TestTokenLoginWithoutFallbackIsUnmapped keeps the mapping opt-in.
func TestTokenLoginWithoutFallbackIsUnmapped(t *testing.T) {
	token2 := `{"login": "", "token2": "x"}`
	if got := tokenLoginName(token2, ""); got != "" {
		t.Errorf("mapped to %q with no fallback configured", got)
	}
}

// TestTokenLoginIgnoresNonJSON keeps a plain username working.
func TestTokenLoginIgnoresNonJSON(t *testing.T) {
	if got := tokenLoginName("playerone", "admin"); got != "" {
		t.Errorf("plain name mapped to %q", got)
	}
	// A JSON document with neither a login nor a token is not a token
	// login either.
	if got := tokenLoginName(`{"auth_realm": "eu"}`, "admin"); got != "" {
		t.Errorf("empty document mapped to %q", got)
	}
}
