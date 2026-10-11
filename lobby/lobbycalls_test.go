package lobby

// Offline lobby base-call builders: synthetic args only (no captures;
// framing bytes + lengths are the protocol, values stay out of tree).
import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDoCmdInt3Poll(t *testing.T) {
	// Game vector shape: the 5s poll is (202, 501, 0, 0, 0), 31B app.
	app := DoCmdInt3(202, 501, 0, 0, 0)
	if len(app) != 31 {
		t.Fatalf("len=%d", len(app))
	}
	wantHead := []byte{0x95, 0x1c, 0x00, 0xca, 0x00, 0xf5, 0x01}
	if !bytes.Equal(app[:7], wantHead) {
		t.Fatalf("head=%x", app[:7])
	}
	if !bytes.Equal(app[7:], make([]byte, 24)) {
		t.Fatalf("tail not zero: %x", app[7:])
	}
	// Full 60B UDP shape: flags(0458) + prime(5) + app(31) + seq/cumul(8).
	if 2+5+len(app)+8 != 46 {
		t.Fatalf("clear len math")
	}
}

func TestDoCmdInt2Shape(t *testing.T) {
	app := DoCmdInt2(225, 121, 7, 9)
	if len(app) != 23 {
		t.Fatalf("len=%d", len(app))
	}
	if !bytes.Equal(app[:7], []byte{0x93, 0x14, 0x00, 0xe1, 0x00, 0x79, 0x00}) {
		t.Fatalf("head=%x", app[:7])
	}
}

func TestDoCmdInt4Shape(t *testing.T) {
	app := DoCmdInt4(202, 501, 1, 2, 3, 4)
	if len(app) != 39 {
		t.Fatalf("len=%d", len(app))
	}
	// Codebook A1 (rank15 → 0x97) + 36B length; game-unpinned.
	if !bytes.Equal(app[:7], []byte{0x97, 0x24, 0x00, 0xca, 0x00, 0xf5, 0x01}) {
		t.Fatalf("head=%x", app[:7])
	}
}

func TestDoCmdStrShape(t *testing.T) {
	app := DoCmdStr(221, 100, []byte{1, 2, 3})
	// 1 + 2 + 2+2 + 1+3 = 11 (packed-int string length).
	if len(app) != 11 {
		t.Fatalf("len=%d", len(app))
	}
	if !bytes.Equal(app, []byte{0x9b, 0x08, 0x00, 0xdd, 0x00, 0x64, 0x00, 0x03, 0x01, 0x02, 0x03}) {
		t.Fatalf("app=%x", app)
	}
}

func TestRequestTokenShape(t *testing.T) {
	app := BuildRequestToken(7, 2)
	if len(app) != 6 {
		t.Fatalf("len=%d", len(app))
	}
	if !bytes.Equal(app, []byte{0x8a, 0x03, 0x00, 0x07, 0x00, 0x02}) {
		t.Fatalf("app=%x", app)
	}
}

func TestLobbyBundleConcat(t *testing.T) {
	a := DoCmdInt3(202, 501, 0, 0, 0)
	b := BuildRequestToken(1, 1)
	bun := BuildLobbyBundle(0x01020304, a, b)
	if len(bun) != 5+31+6 {
		t.Fatalf("len=%d", len(bun))
	}
	if !bytes.Equal(bun[:5], []byte{0x02, 0x04, 0x03, 0x02, 0x01}) {
		t.Fatalf("prime=%x", bun[:5])
	}
	if !bytes.Equal(bun[5:10], []byte{0x95, 0x1c, 0x00, 0xca, 0x00}) {
		t.Fatalf("call0=%x", bun[5:10])
	}
}

func TestTail9825Vectors(t *testing.T) {
	// Generic framer still reproduces both genuine tails verbatim
	// (flows3 148B + 84B, structure only).
	tail148, _ := hex.DecodeString("98190001000000000000001600000000000000000000000000000000")
	tail84, _ := hex.DecodeString("98190002000000000000000000000000020000000000000000000000")
	for i, tv := range [][]byte{tail148, tail84} {
		if len(tv) != 28 {
			t.Fatalf("vec%d len=%d", i, len(tv))
		}
		got := BuildTail9825(tv[3:])
		if !bytes.Equal(got, tv) {
			t.Fatalf("vec%d mismatch %x", i, got)
		}
	}
}

func TestChatCommandFromClientVectors(t *testing.T) {
	// The sync-bundle tails are Chat.chatCommandFromClient
	// (rank16 → A1 0x98): byte-exact reproductions of both genuine
	// vectors (flows3 148B + 84B, structure only).
	tail148, _ := hex.DecodeString("98190001000000000000001600000000000000000000000000000000")
	tail84, _ := hex.DecodeString("98190002000000000000000000000000020000000000000000000000")
	if got := BuildChatCommandFromClient(1, 22, 0, 0, 0, nil, nil); !bytes.Equal(got, tail148) {
		t.Fatalf("vec148 mismatch %x", got)
	}
	if got := BuildChatCommandFromClient(2, 0, 0, 2, 0, nil, nil); !bytes.Equal(got, tail84) {
		t.Fatalf("vec84 mismatch %x", got)
	}
}

func TestDoCmdIntArrEnqueue(t *testing.T) {
	// Byte-exact genuine vector: lobby #2 52B battle-queue join
	// (enqueueRandom: RANDOMS=1, vehInvID, gameplays, arena, flags).
	vec, _ := hex.DecodeString("9e1900ca00bc02050100000053010000430000000000000002000000")
	got := DoCmdIntArr(202, 700, []int32{1, 339, 67, 0, 2})
	if !bytes.Equal(got, vec) {
		t.Fatalf("got %x want %x", got, vec)
	}
}

func TestDoCmdIntArrLongCount(t *testing.T) {
	// Packed-int extended form: 255 elements → FF + 3 LE bytes.
	vals := make([]int32, 255)
	app := DoCmdIntArr(202, 700, vals)
	// 1 + 2 + (2+2+4+255*4) = 1031.
	if len(app) != 1031 {
		t.Fatalf("len=%d", len(app))
	}
	if !bytes.Equal(app[3:11], []byte{0xca, 0x00, 0xbc, 0x02, 0xff, 0xff, 0x00, 0x00}) {
		t.Fatalf("head=%x", app[3:11])
	}
	wantLen := 2 + 2 + 4 + 255*4
	if int(binary.LittleEndian.Uint16(app[1:3])) != wantLen {
		t.Fatalf("lenword=%d want %d", binary.LittleEndian.Uint16(app[1:3]), wantLen)
	}
}

func TestRequestSequences(t *testing.T) {
	// Base sequence: repository starts at 220, first allocation 221,
	// wraps 30000 -> 220 (Account.__getRequestID + UNRESERVED range).
	b := NewBaseRequestIDs()
	for want := uint16(221); want <= 223; want++ {
		if got := b.NextBaseID(); got != want {
			t.Fatalf("base id = %d, want %d", got, want)
		}
	}
	b.cur = 29999
	if got := b.NextBaseID(); got != 220 {
		t.Fatalf("base wrap = %d, want 220", got)
	}
	if got := b.NextBaseID(); got != 221 {
		t.Fatalf("base rewrap = %d, want 221", got)
	}
	// Token sequence: shared class-level generator from 0, first
	// allocation 1 (TokenRequester), wrap 32767 -> 0.
	tk := NewTokenRequestIDs()
	if got := tk.NextTokenID(); got != 1 {
		t.Fatalf("token id = %d, want 1", got)
	}
	tk.cur = 32766
	if got := tk.NextTokenID(); got != 0 {
		t.Fatalf("token wrap = %d, want 0", got)
	}
	if got := tk.NextTokenID(); got != 1 {
		t.Fatalf("token rewrap = %d, want 1", got)
	}
	// Chat sequence: per-ClientChat generator, same 0/32767 rule.
	ch := NewChatRequestIDs()
	if got := ch.NextChatID(); got != 1 {
		t.Fatalf("chat id = %d, want 1", got)
	}
	if got := ch.NextChatID(); got != 2 {
		t.Fatalf("chat id = %d, want 2", got)
	}
}

func TestOpenerIDOrder(t *testing.T) {
	// The genuine opener IDs are allocator outputs, not constants:
	// replaying the fixed call order through fresh sequences must
	// yield exactly the wire IDs (Oct-01: base 221-226, token 1-2,
	// chat 1-2), with the fire-and-forget poll pinned at 202.
	baseIDs := NewBaseRequestIDs()
	tokenIDs := NewTokenRequestIDs()
	chatIDs := NewChatRequestIDs()
	var base, token, chat []uint64
	base = append(base, uint64(baseIDs.NextBaseID()), uint64(baseIDs.NextBaseID()), uint64(baseIDs.NextBaseID()))
	token = append(token, uint64(tokenIDs.NextTokenID()))
	base = append(base, uint64(baseIDs.NextBaseID()))
	token = append(token, uint64(tokenIDs.NextTokenID()))
	base = append(base, uint64(baseIDs.NextBaseID()), uint64(baseIDs.NextBaseID()))
	chat = append(chat, uint64(chatIDs.NextChatID()), uint64(chatIDs.NextChatID()))
	wantBase := []uint64{221, 222, 223, 224, 225, 226}
	for i, w := range wantBase {
		if base[i] != w {
			t.Fatalf("base[%d] = %d, want %d", i, base[i], w)
		}
	}
	if token[0] != 1 || token[1] != 2 {
		t.Fatalf("token ids = %v, want [1 2]", token)
	}
	if chat[0] != 1 || chat[1] != 2 {
		t.Fatalf("chat ids = %v, want [1 2]", chat)
	}
	if RequestIDNoResponse != 202 {
		t.Fatalf("no-response id = %d, want 202", RequestIDNoResponse)
	}
}
