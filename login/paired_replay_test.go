package login

// Paired-capture replay: pins our stage-1/stage-2 builders byte-for-byte
// (past the random prefix) against the genuine EU2 login of Sep 17 2026
// (mitmproxy save ../../captures/flows3, CE Blowfish key ../../captures/key3.txt).
//
// Vectors live OUTSIDE the repo: generate them with
// ../captures/extract_flows3.py (reads ../../captures/flows3, writes
// /tmp/opencode/vectors/*.hex + ../captures/flows3-s2.txt).
// Re-run it any time /tmp is wiped. The test skips when vectors are
// absent.
// Raw-level equality is asserted (genuine pads with uninitialized bytes;
// pad content is unchecked by decrypt and cosmetically differs).
//
// Findings pinned here: 22B handshake layout, [FF][len=8][rid][newkey]
// rotation in the first 36B, ack0/auth1/pure-ack/auth2 shapes, cumul =
// acked server seq + 1, [13][XX][44][ip BE][port BE] redirect (XX varies:
// 0x3f flows3, 0xbc logins.pcapng — only the 0x44 core is matched), stage-2
// double authenticate. See ../docs/NETWORK_PROTOCOL.md.

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

func mustHexP(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPairedReplay(t *testing.T) {
	if _, err := os.Stat("/tmp/opencode/vectors/s1_c28_1.hex"); err != nil {
		t.Skip("no /tmp/opencode/vectors (run vectors.py on captures/flows3)")
	}
	K := string(mustHexP(t, "bf5473286748148dfacf38be5a298ab6"))
	const authKey = uint32(0x696aae88) // rotation newkey: auths + stage-2 22B
	const key2 = uint32(0x78128370)    // stage-2 rotation (70 83 12 78 LE)
	vec := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile("/tmp/opencode/vectors/" + name + ".hex")
		if err != nil {
			t.Fatal(err)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	checkPkt := func(name string, gotPkt, wantPkt []byte, wantRaw string) {
		t.Helper()
		g, w := hex.EncodeToString(gotPkt[4:]), hex.EncodeToString(wantPkt[4:])
		if g == w {
			return
		}
		// Ciphertext differs: pad bytes (unchecked by decrypt) are
		// cosmetic; raw must match.
		raw, err := decryptBlowfish(K, wantPkt[4:])
		if err != nil {
			t.Errorf("%s decrypt-err=%v", name, err)
			return
		}
		if hex.EncodeToString(raw) != wantRaw {
			t.Errorf("%s RAW mismatch: want-raw=%x", name, raw)
		}
	}
	// auth1 (flows3 vector): reliable authenticate + 0b, seq 0, cumul 1.
	// Decrypt-proven genuine shape on two successful lobby sessions
	// (flows3 here, proxy-20261001 below) — the live script mirrors it.
	p, err := buildChannelPacket(K, flagsRel, authApp(authKey), nil, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	checkPkt("auth1", p, vec("s1_c28_1"), "58040288ae6a690b0000000001000000")
	// Cross-session proof (proxy-20261001, Oct-01 lobby, key recovered
	// offline via the MITM privkey): the game's stage-1 auth1 there
	// decrypts to RELIABLE [02][key]+0b too — raw
	// "580402c46532e40b0000000001000000" (key 0xe43265c4 LE, the
	// rotation from that session's 36B). Two successful sessions, one
	// shape; the old unreliable-no-0b reading (size-only 28+28) is
	// withdrawn.
	octKey := uint32(0xe43265c4)
	octAuth1, err := buildChannelPacket(K, flagsRel, authApp(octKey), nil, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	octRaw, err := decryptBlowfish(K, octAuth1[4:])
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(octRaw) != "580402c46532e40b0000000001000000" {
		t.Errorf("oct-01-shaped auth1 raw = %x", octRaw)
	}
	// pure acks seq/cumul 2,2 3,3 4,4.
	for i, name := range []string{"s1_c28_2", "s1_c28_3", "s1_c28_4"} {
		q, err := buildChannelPacket(K, flagsUnrel, nil, midZero, uint32(i+2), uint32(i+2))
		if err != nil {
			t.Fatal(err)
		}
		checkPkt(fmt.Sprintf("pureack%d", i+2), q, vec(name),
			fmt.Sprintf("481400000000%02d000000%02d000000", i+2, i+2))
	}
	// auth2: unreliable authenticate, zeros, seq 5 cumul 5.
	q, err := buildChannelPacket(K, flagsUnrel, buildAuthenticate(authKey), midZero, 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	checkPkt("auth2", q, vec("s1_c28_5"), "48140288ae6a69000000000500000005000000")
	// ack0: bare aux word + footers, no app message (decrypt-proven 14B).
	enc0, err := encryptBlowfish(K, ack0Clear)
	if err != nil {
		t.Fatal(err)
	}
	checkPkt("ack0", append([]byte{0, 0, 0, 0}, enc0...), vec("s1_c28_0"), "4814ffffff0f0100000001000000")
	// stage-2 22B rebuild with genuine prefix (carries rotation key).
	gen22b := vec("s2_22")
	reb := append([]byte{}, gen22b[:4]...)
	reb = append(reb, 0x01, 0x00)
	reb = append(reb, buildBaseAppLoginMsg(42912, authKey, 1, 1300)...)
	reb = append(reb, requestFooter(2)...)
	if hex.EncodeToString(reb) != hex.EncodeToString(gen22b) {
		t.Errorf("stage2-22B mismatch:\n got %x\nwant %x", reb, gen22b)
	}
	// stage-2 double authenticate.
	r, err := buildChannelPacket(K, flagsUnrel, buildAuthenticate(key2), midRotAck, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	checkPkt("s2first", r, vec("s2_c28_a"), "")
	r, err = buildChannelPacket(K, flagsRel, authApp(key2), nil, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	checkPkt("s2auth", r, vec("s2_c28_b"), "")
	// Redirect + rotations parse back.
	c36b, err := decryptBlowfish(K, vec("s1_srv_4_36B")[4:])
	if err != nil {
		t.Fatal(err)
	}
	tgt, ok := parseRedirect(c36b)
	if !ok || tgt.String() != "92.223.20.212:32844" {
		t.Errorf("redirect parse: %v %v", tgt, ok)
	}
	if k, ok := stageKeyOf(vec("s1_srv_0_36B"), 44654, K); !ok || k != authKey {
		t.Errorf("rotation1: %08x %v", k, ok)
	}
	if k, ok := stageKeyOf(vec("s2_36a"), 42912, K); !ok || k != key2 {
		t.Errorf("rotation2: %08x %v", k, ok)
	}
}
