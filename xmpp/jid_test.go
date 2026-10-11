package xmpp

import (
	"testing"
)

func TestParseJID(t *testing.T) {
	j, err := ParseJID("123456789@xmpp.wargaming.net/WoT-abc")
	if err != nil {
		t.Fatal(err)
	}
	if j.Node != "123456789" || j.Domain != "xmpp.wargaming.net" || j.Resource != "WoT-abc" {
		t.Fatalf("got %+v", j)
	}
	if j.String() != "123456789@xmpp.wargaming.net/WoT-abc" {
		t.Fatalf("round-trip %q", j.String())
	}
	if j.Bare() != "123456789@xmpp.wargaming.net" {
		t.Fatalf("bare %q", j.Bare())
	}
	b, err := ParseJID("123456789@xmpp.wargaming.net")
	if err != nil || b.Resource != "" || b.String() != "123456789@xmpp.wargaming.net" {
		t.Fatalf("bare parse %+v %v", b, err)
	}
	for _, bad := range []string{"", "nodomain", "@domain/x", "node@/x", "node@"} {
		if _, err := ParseJID(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
