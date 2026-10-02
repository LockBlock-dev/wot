package login

import "testing"

// Providers must render byte-identical username JSON to the Config
// path they replace (ground truth: CE.txt key orders).
func TestProviderUsernameMatchesConfig(t *testing.T) {
	basic := Config{
		Login: "gapuser", Password: "fakepw", Session: "blob", Temporary: "1",
		Publication: "0", Realm: "EU", AuthMethod: "basic",
	}
	if got, want := ProviderForConfig(basic).Username(), basic.Username(); got != want {
		t.Fatalf("basic username mismatch:\n got %q\nwant %q", got, want)
	}
	t2 := basic
	t2.AuthMethod = "token2"
	t2.Token2 = "123456789:123456789012345678:123456789012345678901234567890123456789"
	if got, want := ProviderForConfig(t2).Username(), t2.Username(); got != want {
		t.Fatalf("token2 username mismatch:\n got %q\nwant %q", got, want)
	}
	tok := basic
	tok.AuthMethod = "token"
	tok.Token = "fasttok"
	if got, want := ProviderForConfig(tok).Username(), tok.Username(); got != want {
		t.Fatalf("token username mismatch:\n got %q\nwant %q", got, want)
	}
	// Type selection keys off token presence (shape + key order);
	// the auth_method string rides verbatim from cfg.
	both := tok
	both.Token2 = "x"
	if _, ok := ProviderForConfig(both).(Token2Auth); !ok {
		t.Fatal("token+token2 config must select Token2Auth")
	}
	// Passwords: identity except CN/VN; token2 leg sends empty.
	pw := ProviderForConfig(basic).Password("en")
	if pw != "fakepw" {
		t.Fatalf("basic password = %q, want fakepw", pw)
	}
	if got := ProviderForConfig(basic).Password("cn"); got == "" {
		t.Fatal("cn password must be md5, not empty")
	}
	t2p := ProviderForConfig(t2)
	if got := t2p.Password("en"); got != "" {
		t.Fatalf("token2 password = %q, want empty", got)
	}
}

func TestExtractUpgradeToken(t *testing.T) {
	const real = "123456789:123456789012345678:123456789012345678901234567890123456789"
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"absent", `{"security_msg":"old_pass"}`, ""},
		{"null", `{"token2":null}`, ""},
		{"empty", `{"token2":""}`, ""},
		{"real", `{"token2":"` + real + `"}`, real},
		{"garbage", `not json`, ""},
	}
	for _, c := range cases {
		if got := ExtractUpgradeToken(c.msg); got != c.want {
			t.Fatalf("%s: got len=%d want len=%d", c.name, len(got), len(c.want))
		}
	}
}

func TestReloginConfig(t *testing.T) {
	base := Config{AuthMethod: "basic", Password: "pw", Login: "u", Token2: ""}
	got := ReloginConfig(base, "tok2val")
	if got.AuthMethod != "token2" || got.Token2 != "tok2val" || got.Password != "" {
		t.Fatalf("relogin config = %+v", got)
	}
	if got.Login != "u" {
		t.Fatal("relogin must preserve login")
	}
}
