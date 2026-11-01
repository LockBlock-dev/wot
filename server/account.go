package server

import (
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Account is one player identity. Name is the login name the client
// sends in LogOnParams.Username; the wire carries it in the clear once
// the RSA layer is peeled, so it is the natural primary key.
type Account struct {
	ID       int64
	Name     string
	PassHash string
	Created  time.Time
	Roles    []string
}

// NormalizeName canonicalises a login name for lookup. The client sends
// whatever the player typed and the real server is case-insensitive, so
// every lookup and every insert goes through this.
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// loginNameRE is the client's own login-name pattern, copied from the
// shipped EU scripts (external_strings_utils.LOGIN_NAME_RE, 2.4.1.1):
//
//	^[a-z0-9_-]+(\.[a-z0-9_-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*\.([a-z]{2,4})$
//
// The login form validates against it before anything is sent, so a name
// that fails it can never be typed in the client — the player sees
// "invalid login" and no datagram leaves the machine.
var loginNameRE = regexp.MustCompile(
	`^[a-z0-9_-]+(\.[a-z0-9_-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,4}$`)

// LoginNameValid reports whether name is a login the client's form
// accepts. Names are compared normalized, like every other lookup.
func LoginNameValid(name string) bool {
	return loginNameRE.MatchString(NormalizeName(name))
}

// HashPassword returns a bcrypt hash suitable for Account.PassHash.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword reports whether pw matches the stored hash. A malformed
// or empty hash never matches.
func (a *Account) CheckPassword(pw string) bool {
	if a == nil || a.PassHash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(a.PassHash), []byte(pw)) == nil
}

// HasRole reports whether the account carries the given role.
func (a *Account) HasRole(role string) bool {
	for _, r := range a.Roles {
		if r == role {
			return true
		}
	}
	return false
}
