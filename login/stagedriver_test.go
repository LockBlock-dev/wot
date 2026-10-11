package login

// Offline coverage for the stage drivers (baseapp.go): the scripted
// Transport + real Blowfish round-trip pin each step's wire shape
// without any network.
import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

const stageTestKey = "0123456789abcdef"

// stagePacket wraps cleartext as a stage datagram: [prefix4] +
// Blowfish(channel key).
func stagePacket(t *testing.T, clear []byte) []byte {
	t.Helper()
	enc, err := encryptBlowfish(stageTestKey, clear)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0x01, 0x02, 0x03, 0x04}, enc...)
}

// stageApp decrypts a sent channel packet past the 4B prefix.
func stageApp(t *testing.T, pkt []byte) []byte {
	t.Helper()
	clear, err := decryptBlowfish(stageTestKey, pkt[4:])
	if err != nil {
		t.Fatal(err)
	}
	return clear
}

func TestStageOneOpeningSendsAck0Auth1(t *testing.T) {
	fake := &scriptTransport{}
	d := &stageOneDriver{
		ctx: context.Background(), sendConn: fake, readConn: fake,
		peer:     &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 32816},
		newKey:   0xAABBCCDD,
		blockKey: stageTestKey,
		unrel:    2, relSent: 1,
		buf: make([]byte, 2048), end: time.Now().Add(time.Second),
	}
	if err := d.sendOpening(); err != nil {
		t.Fatal(err)
	}
	if len(fake.writes) != 2 {
		t.Fatalf("writes=%d, want ack0+auth1", len(fake.writes))
	}
	if len(fake.writes[0]) != 28 {
		t.Fatalf("ack0=%dB, want 28 (14B + magic/wastage trailer + prefix)", len(fake.writes[0]))
	}
	auth1 := stageApp(t, fake.writes[1])
	if len(auth1) < 8 || auth1[2] != 0x02 || auth1[7] != msgEnableEntities {
		t.Fatalf("auth1 app lacks [02][key][0b]: %x", auth1)
	}
	if d.got[0] != "→ack0" || d.got[1] != "→auth1" {
		t.Fatalf("got=%q", d.got)
	}
}

func TestStageOneAnswerFollowsRedirect(t *testing.T) {
	// flags(2) + [44][ip BE][port BE][00 00 01]: the redirect core.
	clear := []byte{0x48, 0x14, 0x44,
		203, 0, 113, 9, 0x80, 0x30, 0x00, 0x00, 0x01}
	fake := &scriptTransport{}
	d := &stageOneDriver{
		ctx: context.Background(), sendConn: fake, readConn: fake,
		peer:     &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 32816},
		newKey:   0xAABBCCDD,
		blockKey: stageTestKey,
		unrel:    2, relSent: 1,
		buf: make([]byte, 2048), end: time.Now().Add(time.Second),
	}
	target, err := d.answer(stagePacket(t, clear))
	if err != nil {
		t.Fatal(err)
	}
	if target == nil || target.String() != "203.0.113.9:32816" {
		t.Fatalf("target=%v", target)
	}
	if len(fake.writes) != 1 {
		t.Fatalf("writes=%d, want auth2 only", len(fake.writes))
	}
	auth2 := stageApp(t, fake.writes[0])
	if len(auth2) < 7 || auth2[2] != 0x02 ||
		binary.LittleEndian.Uint32(auth2[3:7]) != 0xAABBCCDD {
		t.Fatalf("auth2 app lacks [02][key]: %x", auth2)
	}
}

func TestStageOneAnswerSkipsUndecryptable(t *testing.T) {
	fake := &scriptTransport{}
	d := &stageOneDriver{
		ctx: context.Background(), sendConn: fake, readConn: fake,
		peer:     &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 32816},
		blockKey: stageTestKey,
		buf:      make([]byte, 2048), end: time.Now().Add(time.Second),
	}
	target, err := d.answer([]byte{0x01, 0x02, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef})
	if err != nil || target != nil {
		t.Fatalf("target=%v err=%v", target, err)
	}
	if len(fake.writes) != 0 || len(d.got) != 1 || !strings.Contains(d.got[0], "undecryptable") {
		t.Fatalf("writes=%d got=%q", len(fake.writes), d.got)
	}
}

func TestStageTwoCheckExit(t *testing.T) {
	d := &stageTwoDriver{got: []string{"1B"}, end: time.Now().Add(-time.Second)}
	done, err := d.checkExit()
	if !done || err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("done=%v err=%v", done, err)
	}
	d = &stageTwoDriver{
		census:      map[int]int{},
		floodSeen:   true,
		floodSeenAt: time.Now().Add(-46 * time.Second),
		end:         time.Now().Add(time.Minute),
	}
	done, err = d.checkExit()
	if !done || err != nil {
		t.Fatalf("done=%v err=%v", done, err)
	}
}

func TestStageTwoObserveCensus(t *testing.T) {
	d := &stageTwoDriver{
		census:       map[int]int{},
		floodSeen:    true,
		lastPollSent: time.Now(),
	}
	d.observeCensus(36)
	d.observeCensus(1252)
	if d.pollAnswers != 1 || d.census[36] != 1 || d.census[1252] != 1 {
		t.Fatalf("census=%v answers=%d", d.census, d.pollAnswers)
	}
}

func TestStageTwoDoubleAuth(t *testing.T) {
	const rid2 = 4242
	const key2 = 0x12345678
	var tmp [4]byte
	clear := []byte{0x58, 0x04, msgReply}
	binary.LittleEndian.PutUint32(tmp[:], 8)
	clear = append(clear, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], rid2)
	clear = append(clear, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], key2)
	clear = append(clear, tmp[:]...)
	fake := &scriptTransport{}
	d := &stageTwoDriver{
		ctx: context.Background(), conn: fake,
		target:   &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 32816},
		blockKey: stageTestKey,
		rid2:     rid2,
		census:   map[int]int{},
	}
	acted, err := d.maybeDoubleAuth(stagePacket(t, clear))
	if err != nil || !acted {
		t.Fatalf("acted=%v err=%v", acted, err)
	}
	if !d.rotated || d.stageKey != key2 || d.relSent != 1 {
		t.Fatalf("rotated=%v key=%x relSent=%d", d.rotated, d.stageKey, d.relSent)
	}
	if len(fake.writes) != 2 {
		t.Fatalf("writes=%d, want unreliable+reliable auth", len(fake.writes))
	}
	auth := stageApp(t, fake.writes[1])
	if len(auth) < 8 || auth[2] != 0x02 ||
		binary.LittleEndian.Uint32(auth[3:7]) != key2 || auth[7] != msgEnableEntities {
		t.Fatalf("reliable auth lacks [02][key][0b]: %x", auth)
	}
}
