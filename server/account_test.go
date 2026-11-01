package server

import "testing"

// TestLoginNameValid pins the client's login-name pattern. The login form
// validates against it before sending anything, so a name that fails it
// can never be typed in — the player sees "invalid login" and no datagram
// leaves the machine. The cases are the shipped EU regex
// (external_strings_utils.LOGIN_NAME_RE, 2.4.1.1) applied by hand.
func TestLoginNameValid(t *testing.T) {
	valid := []string{
		"admin@wot.test",
		"player.one@wot.test",
		"a@b.co",
		"first-last@sub.domain.co",
		"under_score@wot.lan",
		"admin@wot.test.com", // the TLD is the last label only
		"ADMIN@WOT.TEST",     // normalized to lowercase first
		"  admin@wot.test  ",
	}
	for _, name := range valid {
		if !LoginNameValid(name) {
			t.Errorf("LoginNameValid(%q) = false, want true", name)
		}
	}
	invalid := []string{
		"admin",           // no @: the old default, untypable in the form
		"admin@wot",       // no TLD
		"admin@wot.local", // TLD longer than 4
		"admin@wot.t",     // TLD shorter than 2
		"@wot.test",       // empty local part
		"admin@",          // empty domain
		"ad min@wot.test", // space
		"admin@wot..test", // empty label
	}
	for _, name := range invalid {
		if LoginNameValid(name) {
			t.Errorf("LoginNameValid(%q) = true, want false", name)
		}
	}
}
