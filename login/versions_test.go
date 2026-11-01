package login

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestKnownVersionsPairProtoWithDigest pins the registry: both shipped
// builds announce the same protocol bytes (the 2.4.1.0 capture carries
// `05 00 01 11` too), so the digest is what tells them apart.
func TestKnownVersionsPairProtoWithDigest(t *testing.T) {
	vs := KnownVersions()
	if len(vs) != 2 {
		t.Fatalf("KnownVersions = %d entries, want 2", len(vs))
	}
	want := [4]byte{verSub, verPatch, verMinor, verMajor}
	for _, v := range vs {
		if v.Proto != want {
			t.Errorf("%s proto = %v, want %v", v.Name, v.Proto, want)
		}
	}
	if vs[0].Digest == vs[1].Digest {
		t.Fatal("the two builds share a digest; the gate could not tell them apart")
	}
	// The digests are the pinned truths, not copies of each other.
	for i, hx := range []string{entdef.Truth240, entdef.Truth241} {
		b, err := hex.DecodeString(hx)
		if err != nil {
			t.Fatal(err)
		}
		var d [16]byte
		copy(d[:], b)
		if vs[i].Digest != d {
			t.Errorf("%s digest = %x, want %s", vs[i].Name, vs[i].Digest, hx)
		}
	}
}

// TestIdentify covers the pairing rule: a build's protocol bytes with
// another build's digest is not a match.
func TestIdentify(t *testing.T) {
	vs := KnownVersions()
	proto := vs[0].Proto

	if v, ok := Identify(vs, proto, vs[0].Digest); !ok || v.Name != "2.4.0" {
		t.Errorf("2.4.0 not identified: %v %v", v, ok)
	}
	if v, ok := Identify(vs, proto, vs[1].Digest); !ok || v.Name != "2.4.1" {
		t.Errorf("2.4.1 not identified: %v %v", v, ok)
	}
	// A foreign digest is refused even though the protocol matches.
	if _, ok := Identify(vs, proto, [16]byte{0xde, 0xad}); ok {
		t.Error("foreign digest accepted")
	}
	// A foreign protocol is refused even with a known digest.
	if _, ok := Identify(vs, [4]byte{9, 9, 9, 9}, vs[0].Digest); ok {
		t.Error("foreign protocol accepted")
	}
}

// TestAcceptsProto is the version gate: it looks at the protocol bytes
// alone, because the live server answers status 65 before it ever sees
// the digest.
func TestAcceptsProto(t *testing.T) {
	vs := KnownVersions()
	if !AcceptsProto(vs, vs[0].Proto) {
		t.Error("known protocol refused")
	}
	if AcceptsProto(vs, [4]byte{3, 0, 1, 17}) {
		t.Error("2022 protocol (17.1.0.3) accepted; only 17.1.0.5 is served")
	}
	if AcceptsProto(nil, vs[0].Proto) {
		t.Error("empty table accepted a protocol")
	}
}

// TestServerAcceptsBothBuilds is the end-to-end point of the phase: a
// 2.4.1 client logs in against the same server as a 2.4.0 one, and a
// build whose digest is unknown is refused with the digest status.
func TestServerAcceptsBothBuilds(t *testing.T) {
	vs := KnownVersions()
	for _, v := range vs {
		srv, err := NewLoginAppServer(ServerConfig{
			MaxNonce: serverTestMaxNonce,
			Versions: vs,
		}, testRSAKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if !srv.acceptDigest(v.Proto, v.Digest) {
			t.Errorf("%s digest refused", v.Name)
		}
	}
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce: serverTestMaxNonce,
		Versions: vs,
	}, testRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if srv.acceptDigest(vs[0].Proto, [16]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Error("unknown digest accepted")
	}
	// The probe escape still works.
	srv.cfg.AcceptAnyDigest = true
	if !srv.acceptDigest([4]byte{1, 2, 3, 4}, [16]byte{0xde}) {
		t.Error("AcceptAnyDigest did not disable the gate")
	}
}

// TestLoggedOnCarriesVersion checks the identified build reaches the
// BaseApp handoff, so an admission can say which client it is serving.
func TestLoggedOnCarriesVersion(t *testing.T) {
	var got LoggedOnSession
	srv, err := NewLoginAppServer(ServerConfig{
		MaxNonce:   serverTestMaxNonce,
		Versions:   testVersions(),
		OnLoggedOn: func(s LoggedOnSession) { got = s },
	}, testRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	listen := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20016}

	pkt, err := srv.handlePacket(loginOneDatagram(t, 71, true), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#1: %v", err)
	}
	ch := challengeOf(t, pkt, 71)
	pkt, err = srv.handlePacket(loginTwoDatagram(t, 72, ch, testDigestA, nil), from, listen)
	if err != nil {
		t.Fatalf("handlePacket#2: %v", err)
	}
	if _, status, _, err := parseReply(pkt); err != nil || status != statusLoggedOn {
		t.Fatalf("status=%d err=%v, want LOGGED_ON", status, err)
	}
	if got.Version != "test" {
		t.Errorf("LoggedOnSession.Version = %q, want %q", got.Version, "test")
	}
	if got.SessionKey == 0 {
		t.Error("no session key on the handoff")
	}
}
