package xmpp

import (
	"encoding/hex"
	"testing"
)

// genuine124B is the S>C 124B endpoint-list body from the Sep-29
// lobby #2 flow (44395), channel-decrypted offline with the login-leg
// key MITM-recovered from the same capture (see docs/
// NETWORK_PROTOCOL.md §16). Flags (0478) and footers (seq 177,
// cumul 1) stripped; 101 B body verbatim.
const genuine124B = "6872b821000065855272b92100007555" +
	"15786d70705f626f73685f636f6e6e65" +
	"6374696f6e7372ba2100005d72bb2100" +
	"00551a776f74657533342e786d70702e" +
	"77617267616d696e672e6e65744b5086" +
	"72bc2100006152e141d7f0b000010000" +
	"00b1000000"

func TestParseEndpointListGenuine(t *testing.T) {
	body, err := hex.DecodeString(genuine124B)
	if err != nil || len(body) != 101 {
		t.Fatalf("vector: %v %d", err, len(body))
	}
	el, err := ParseEndpointList(body)
	if err != nil {
		t.Fatal(err)
	}
	if el.KeyName != "xmpp_bosh_connections" {
		t.Fatalf("key=%q", el.KeyName)
	}
	if len(el.Hosts) != 1 || el.Hosts[0].Host != "woteu34.xmpp.wargaming.net" {
		t.Fatalf("hosts=%v", el.Hosts)
	}
	if el.Hosts[0].Port != DefaultBOSHPort {
		t.Fatalf("port=%d (default, not wire)", el.Hosts[0].Port)
	}
	if len(el.Sections) != 5 {
		t.Fatalf("sections=%d, want b8..bc", len(el.Sections))
	}
	for i, want := range []byte{0xb8, 0xb9, 0xba, 0xbb, 0xbc} {
		if el.Sections[i].Sub != want {
			t.Fatalf("section %d sub=%x", i, el.Sections[i].Sub)
		}
	}
	bc := el.Sections[4]
	if len(bc.Payload) != 16 {
		t.Fatalf("bc=%dB, want 16", len(bc.Payload))
	}
	words, err := SectionU32s(bc)
	if err != nil || len(words) != 4 || words[2] != 1 {
		t.Fatalf("bc words=%x %v", words, err)
	}
}

func TestParseEndpointListRejects(t *testing.T) {
	body, _ := hex.DecodeString(genuine124B)
	for name, mut := range map[string]func([]byte){
		"bad-id":      func(b []byte) { b[0] = 0x35 },
		"bad-tag":     func(b []byte) { b[1] = 0x1a },
		"truncated":   func(b []byte) { copy(b, b[:40]) },
		"no-hostname": func(b []byte) { b[77], b[78] = 0x00, 0x00 },
	} {
		b := append([]byte(nil), body...)
		if name == "truncated" {
			b = b[:40]
		} else {
			mut(b)
		}
		if _, err := ParseEndpointList(b); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := ParseEndpointList(nil); err == nil {
		t.Fatal("empty accepted")
	}
}
