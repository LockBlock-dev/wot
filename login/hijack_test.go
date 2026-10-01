package login

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/blowfish"
)

// encryptLoginTest is the inverse of decryptLogin (login reply path, NO
// magic trailer): c[i] = E(plain[i] ⊕ plain[i-1]).
func encryptLoginTest(t *testing.T, key string, src []byte) []byte {
	t.Helper()
	c, err := blowfish.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, len(src))
	var prev []byte
	for i := 0; i < len(src); i += bfBlockSize {
		blk := append([]byte{}, src[i:i+bfBlockSize]...)
		if prev != nil {
			for j := 0; j < bfBlockSize; j++ {
				blk[j] ^= prev[j]
			}
		}
		c.Encrypt(dst[i:i+bfBlockSize], blk)
		prev = src[i : i+bfBlockSize : i+bfBlockSize]
	}
	return dst
}

// buildLoggedOnReply builds a synthetic 232B-class LoginApp reply:
// [prefix4][flags 00 00][FF][len][rid][status=1][encrypted record], the
// framing parseReply + decryptSession consume (record: ip4 + port BE +
// salt + key LE, padded to the Blowfish block size).
func buildLoggedOnReply(t *testing.T, key string, ip [4]byte, port uint16, sessionKey, rid uint32) []byte {
	t.Helper()
	rec := make([]byte, 16) // 12 B record + 4 B zero pad (block multiple)
	copy(rec, ip[:])
	binary.BigEndian.PutUint16(rec[4:6], port)
	binary.LittleEndian.PutUint32(rec[8:12], sessionKey)
	body := encryptLoginTest(t, key, rec)
	pkt := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, msgReply}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(5+len(body)))
	pkt = append(pkt, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], rid)
	pkt = append(pkt, tmp[:]...)
	pkt = append(pkt, 0x01) // status LOGGED_ON
	return append(pkt, body...)
}

// dumpLine renders one wotproxy -dump line (cmd/wotproxy dumpLine format:
// "%s %s %-21s %4d %s").
func dumpLine(dir string, pkt []byte) string {
	return fmt.Sprintf("%s %s %-21s %4d %s\n",
		"12:00:00.001", dir, "127.0.0.1:51260", len(pkt), hex.EncodeToString(pkt))
}

// pingPair returns the genuine 16 B ping pair from captures/wotproxy.hex
// (framing noise the parser must skip without matching).
func pingPair(t *testing.T) (c2s, s2c []byte) {
	t.Helper()
	var err error
	if c2s, err = hex.DecodeString("b43aa2db010002b9bd00000000000200"); err != nil {
		t.Fatal(err)
	}
	if s2c, err = hex.DecodeString("9fc01a810000ff05000000b9bd000000"); err != nil {
		t.Fatal(err)
	}
	return c2s, s2c
}

// loginPairLines renders a minimal synthetic login#1 (534 B, rid at
// [9:13]) + login#2 (728 B, login-retry rid at [203:207]) pair: only the
// framing bytes loginRIDs reads are meaningful, the rest is zero.
func loginPairLines(r1 uint32) string {
	p1 := make([]byte, 534)
	p1[4], p1[5], p1[6] = 0x01, 0x00, msgLogin
	binary.LittleEndian.PutUint32(p1[9:13], r1)
	p2 := make([]byte, 728)
	p2[200] = msgLogin
	binary.LittleEndian.PutUint32(p2[203:207], r1+1)
	return dumpLine("C>S", p1) + dumpLine("C>S", p2)
}

func TestSessionFromDumpRoundTrip(t *testing.T) {
	key := "0123456789abcdef"
	reply := buildLoggedOnReply(t, key, [4]byte{92, 223, 20, 215}, 32838, 0x1327c898, 80357)
	var dump bytes.Buffer
	pingC2S, pingS2C := pingPair(t)
	dump.WriteString(dumpLine("C>S", pingC2S))
	dump.WriteString(dumpLine("S>C", pingS2C))
	dump.WriteString(loginPairLines(80356))
	dump.WriteString(dumpLine("S>C", reply))

	dg, err := ParseWotproxyDump(&dump)
	if err != nil {
		t.Fatalf("ParseWotproxyDump: %v", err)
	}
	if len(dg) != 5 {
		t.Fatalf("parsed %d datagrams, want 5", len(dg))
	}
	s, stageRID, err := SessionFromDump(dg, key)
	if err != nil {
		t.Fatalf("SessionFromDump: %v", err)
	}
	if s.ServerAddr.String() != "92.223.20.215" || s.ServerPort != 32838 || s.SessionKey != 0x1327c898 {
		t.Fatalf("session = %s:%d key=%08x", s.ServerAddr, s.ServerPort, s.SessionKey)
	}
	if stageRID != 80358 {
		t.Fatalf("stageRID = %d, want login#2+1 = 80358", stageRID)
	}
}

func TestLoginRIDsRejectsOrphans(t *testing.T) {
	var dump bytes.Buffer
	dump.WriteString(loginPairLines(100))
	dump.WriteString(dumpLine("C>S", make([]byte, 728))) // orphan retry, zero rid
	dg, err := ParseWotproxyDump(&dump)
	if err != nil {
		t.Fatalf("ParseWotproxyDump: %v", err)
	}
	if _, err := loginRIDs(dg, len(dg)); err == nil {
		t.Fatal("orphan 728 pairing must fail, not mint a wrong rid")
	}
}

func TestSessionFromDumpLastWins(t *testing.T) {
	key := "0123456789abcdef"
	first := buildLoggedOnReply(t, key, [4]byte{92, 223, 20, 213}, 32892, 0xaaaa1111, 100)
	last := buildLoggedOnReply(t, key, [4]byte{92, 223, 20, 215}, 32838, 0xbbbb2222, 101)
	var dump bytes.Buffer
	dump.WriteString(loginPairLines(98))
	dump.WriteString(dumpLine("S>C", first))
	dump.WriteString(loginPairLines(500))
	dump.WriteString(dumpLine("S>C", last))
	dg, err := ParseWotproxyDump(&dump)
	if err != nil {
		t.Fatalf("ParseWotproxyDump: %v", err)
	}
	s, stageRID, err := SessionFromDump(dg, key)
	if err != nil {
		t.Fatalf("SessionFromDump: %v", err)
	}
	if s.ServerAddr.String() != "92.223.20.215" || s.ServerPort != 32838 || s.SessionKey != 0xbbbb2222 {
		t.Fatalf("last login did not win: %s:%d key=%08x", s.ServerAddr, s.ServerPort, s.SessionKey)
	}
	if stageRID != 502 {
		t.Fatalf("stageRID = %d, want last login#2+1 = 502", stageRID)
	}
}

func TestSessionFromDumpWrongKey(t *testing.T) {
	key := "0123456789abcdef"
	reply := buildLoggedOnReply(t, key, [4]byte{92, 223, 20, 215}, 32838, 0x1327c898, 80357)
	dg := []DumpDatagram{{Dir: "S>C", Addr: "x", Data: reply}}
	if _, _, err := SessionFromDump(dg, "ffffffffffffffff"); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

// TestLoginRIDsHijackDump pins stage-rid derivation against the real
// Sep 19 2026 hijack capture (game login 91399/91400, stage-1 91401 on
// the wire): the probe must open with login#2rid+1, not a fresh rid.
func TestLoginRIDsHijackDump(t *testing.T) {
	for _, tc := range []struct {
		path string
		want uint32
	}{
		{"../../captures/dump_p2.txt", 91401},
	} {
		f, err := os.Open(tc.path)
		if err != nil {
			t.Skipf("capture unavailable: %v", err)
		}
		dg, err := ParseWotproxyDump(f)
		f.Close()
		if err != nil {
			t.Fatalf("ParseWotproxyDump: %v", err)
		}
		got, err := loginRIDs(dg, len(dg))
		if err != nil {
			t.Fatalf("loginRIDs: %v", err)
		}
		if got != tc.want {
			t.Fatalf("stageRID = %d, want %d", got, tc.want)
		}
	}
}

// TestLoginSourcePortGameDump pins port-steal derivation against the
// Sep 20 2026 game dump: the game's login socket source port was 58107
// (wotproxy logs ReadFromUDP's caddr for C>S lines), so the hijack
// stage-1 socket must bind :58107 once the game is dead.
func TestLoginSourcePortGameDump(t *testing.T) {
	f, err := os.Open("../../captures/dump_game_20260920.txt")
	if err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	dg, err := ParseWotproxyDump(f)
	f.Close()
	if err != nil {
		t.Fatalf("ParseWotproxyDump: %v", err)
	}
	got, err := LoginSourcePort(dg)
	if err != nil {
		t.Fatalf("LoginSourcePort: %v", err)
	}
	if got != 58107 {
		t.Fatalf("source port = %d, want 58107", got)
	}
}

// TestSessionFromDumpRealCapture pins the parser against the frozen
// captures/wotproxy.hex game session (10 ping pairs, invalid + valid
// logins, 28 datagrams, one 232 B LOGGED_ON reply). No CE key exists for
// that login, so extraction must cleanly refuse a wrong key.
func TestSessionFromDumpRealCapture(t *testing.T) {
	f, err := os.Open("../../captures/wotproxy.hex")
	if err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	defer f.Close()
	dg, err := ParseWotproxyDump(f)
	if err != nil {
		t.Fatalf("ParseWotproxyDump: %v", err)
	}
	if len(dg) != 28 {
		t.Fatalf("parsed %d datagrams, want 28", len(dg))
	}
	var found232 bool
	for _, d := range dg {
		if d.Dir == "S>C" && len(d.Data) == 232 {
			found232 = true
		}
	}
	if !found232 {
		t.Fatal("no 232 B S>C reply in capture")
	}
	if _, _, err := SessionFromDump(dg, "0123456789abcdef"); err == nil {
		t.Fatal("capture's login must not decrypt under an unrelated key")
	}
}
