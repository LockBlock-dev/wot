package login

// Offline stage-2 flood framing: synthetic fixtures only (no captures).
import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"github.com/LockBlock-dev/wot/lobby"
	"testing"
)

const floodTestKey = "0123456789abcdef"

func TestKeyFileRoundTrip(t *testing.T) {
	p := t.TempDir() + "/k.hex"
	if err := WriteKeyFile(p, floodTestKey); err != nil {
		t.Fatal(err)
	}
	back, err := ReadKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if back != floodTestKey {
		t.Fatal("key mismatch")
	}
	if KeyID(back) == "" || KeyID(back) == floodTestKey {
		t.Fatal("bad key id")
	}
}

func TestCensusSmalls(t *testing.T) {
	doc := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	body := append([]byte{0x1a, 0x5f, byte(len(doc))}, doc...)
	dd := []DumpDatagram{
		{Dir: "S>C", Addr: "f->t", Data: encSmall(t, 0x78, body, 1, 0)},
		{Dir: "S>C", Addr: "f->t", Data: encSmall(t, 0x78, []byte{0x13, 0x00}, 2, 0)},
	}
	rows, st, err := CensusSmalls(dd, "f->t", 1252, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frags != 2 || len(rows) != 2 {
		t.Fatalf("rows=%+v st=%+v", rows, st)
	}
	if rows[0].ID != 0x13 || rows[0].Count != 1 {
		t.Fatalf("row0=%+v", rows[0])
	}
	if rows[1].ID != 0x1a || rows[1].Type != 0x5f || rows[1].Decoded != 1 || rows[1].Summary != "dict{a}" {
		t.Fatalf("row1=%+v", rows[1])
	}
}

func encSmall(t *testing.T, flags uint16, app []byte, seq, cumul uint32) []byte {
	t.Helper()
	// Trailer length and order follow ChannelTrailerLen:
	// [fragment 8B][aux 4B][seq 4B][cumul 4B].
	full := make([]byte, 2)
	binary.LittleEndian.PutUint16(full, flags)
	full = append(full, app...)
	var s, c [4]byte
	binary.LittleEndian.PutUint32(s[:], seq)
	binary.LittleEndian.PutUint32(c[:], cumul)
	if flags&chFlagFragment != 0 {
		full = append(full, s[:]...) // request id
		full = append(full, c[:]...) // reply id
	}
	if flags&chFlagAux != 0 {
		full = append(full, s[:]...)
	}
	if flags&chFlagSequence != 0 {
		full = append(full, s[:]...)
	}
	if flags&chFlagCumulAck != 0 {
		full = append(full, c[:]...)
	}
	enc, err := encryptBlowfish(floodTestKey, full)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{9, 9, 9, 9}, enc...)
}

func TestReassembleBulk(t *testing.T) {
	chunks := [][]byte{[]byte("frag-AAA"), []byte("frag-BBB"), []byte("frag-CCC")}
	var dd []DumpDatagram
	for i, ch := range chunks {
		full := make([]byte, 2)
		binary.LittleEndian.PutUint16(full, 0x0078)
		full = append(full, ch...)
		var s, c, m [4]byte
		binary.LittleEndian.PutUint32(s[:], uint32(100+i))
		binary.LittleEndian.PutUint32(c[:], uint32(i))
		binary.LittleEndian.PutUint32(m[:], uint32(100+i))
		full = append(full, m[:]...)
		full = append(full, s[:]...)
		full = append(full, c[:]...)
		enc, err := encryptBlowfish(floodTestKey, full)
		if err != nil {
			t.Fatal(err)
		}
		pkt := append([]byte{9, 9, 9, 9}, enc...)
		dd = append(dd, DumpDatagram{Dir: "S>C", Addr: "x->y", Data: pkt})
	}
	// Decoy: different size must not join.
	dd = append(dd, DumpDatagram{Dir: "S>C", Addr: "x->y", Data: make([]byte, 28)})
	app, st, err := ReassembleBulk(dd, "x->y", len(dd[0].Data), floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(app) != "frag-AAA"+"frag-BBB"+"frag-CCC" {
		t.Fatalf("bad reassembly %q", app)
	}
	if st.Frags != 3 {
		t.Fatalf("frags=%d", st.Frags)
	}
	if _, _, err := ReassembleBulk(dd, "zzz", len(dd[0].Data), floodTestKey); err == nil {
		t.Fatal("empty flow must fail")
	}
}

func TestBulkStream(t *testing.T) {
	if got := BulkStream([]byte{0xFF, 0x18, 0x46, 0x03, 0x80, 0x02}); string(got) != "\x80\x02" {
		t.Fatalf("strip: %x", got)
	}
	raw := []byte{0x80, 0x02, 0x7d}
	if got := BulkStream(raw); string(got) != string(raw) {
		t.Fatal("passthrough changed bytes")
	}
	if got := BulkStream(nil); len(got) != 0 {
		t.Fatal("nil changed")
	}
}

func TestClassifySmalls(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write([]byte("hello-pickle")); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	app := []byte{0x13, 0x7e}
	app = append(app, 0x1a, 0x76, 0x03, 'a', 'b', 'c')
	app = append(app, 0xFF, 0x08, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD)
	app = append(app, 0x45, 0x02, 0xE2, 0x05)
	zb := zbuf.Bytes()
	var zl, zd [4]byte
	binary.LittleEndian.PutUint16(zl[:2], uint16(4+len(zb)))
	binary.LittleEndian.PutUint32(zd[:], uint32(len("hello-pickle")))
	app = append(app, 0x46, zl[0], zl[1])
	app = append(app, zd[:]...)
	app = append(app, zb...)
	pkt := encSmall(t, 0x0458, app, 7, 3)
	msgs, rest, err := ClassifySmalls(pkt, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("rest=%x", rest)
	}
	if len(msgs) != 5 {
		t.Fatalf("msgs=%d", len(msgs))
	}
	if msgs[0].ID != 0x13 || msgs[1].ID != 0x1a || msgs[1].Type != 0x76 || string(msgs[1].Body) != "abc" {
		t.Fatalf("bad 13/1a: %+v", msgs[:2])
	}
	if msgs[2].ID != 0xFF || msgs[2].Length != 8 {
		t.Fatalf("bad ff: %+v", msgs[2])
	}
	if msgs[3].ID != 0x45 || msgs[3].Length != 2 {
		t.Fatalf("bad 45: %+v", msgs[3])
	}
	if msgs[4].ID != 0x46 || string(msgs[4].Body) != "hello-pickle" {
		t.Fatalf("bad 46: %+v", msgs[4])
	}
	// 16B-trailer variant (0x0478 = ON|REL|SEQ|REQ|CUMUL) + unknown-ID rest.
	pkt2 := encSmall(t, 0x0478, []byte{0x13, 0x01, 0xBB, 0x02}, 9, 4)
	msgs, rest, err = ClassifySmalls(pkt2, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].ID != 0x13 {
		t.Fatalf("msgs=%+v rest=%x", msgs, rest)
	}
	if len(rest) != 2 || rest[0] != 0xBB {
		t.Fatalf("rest=%x", rest)
	}
	// Wrong key fails.
	if _, _, err := ClassifySmalls(pkt, "fedcba9876543210"); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestClassifySmalls5b(t *testing.T) {
	// 1a/0x5b server-stats reply: fixed [type8][u32][u32], no length
	// (Oct-01 genuine poll answer: tick + 1a/5b + two counters).
	app := []byte{0x13, 0x7e}
	app = append(app, 0x1a, 0x5b, 0x30, 0xd4, 0x00, 0x00, 0x63, 0xe3, 0x01, 0x00)
	pkt := encSmall(t, 0x0458, app, 7, 3)
	msgs, rest, err := ClassifySmalls(pkt, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("rest=%x", rest)
	}
	if len(msgs) != 2 {
		t.Fatalf("msgs=%d", len(msgs))
	}
	m := msgs[1]
	if m.ID != 0x1a || m.Type != 0x5b || m.Length != 8 {
		t.Fatalf("bad 5b: %+v", m)
	}
	if binary.LittleEndian.Uint32(m.Body[0:4]) != 54320 || binary.LittleEndian.Uint32(m.Body[4:8]) != 123747 {
		t.Fatalf("bad counters: %x", m.Body)
	}
	// Truncated 5b errors instead of mis-splitting.
	pkt2 := encSmall(t, 0x0458, []byte{0x1a, 0x5b, 0x30, 0xd4}, 7, 3)
	if _, _, err := ClassifySmalls(pkt2, floodTestKey); err == nil {
		t.Fatal("truncated 5b must fail")
	}
}

func TestHarvestChunksIsolates(t *testing.T) {
	doc := []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")
	random := []byte{0x13, 0x53, 0x46, 0xeb, 0xb7, 0xf3, 0x68, 0xfa, 0x19, 0x47, 0xb2, 0x6e, 0xd9, 0xe8, 0xdc, 0xd3}
	frags := []lobby.Frag{{Seq: 1, NN: 1, Payload: doc}, {Seq: 2, NN: 2, Payload: random}}
	got := HarvestChunks(frags)
	if len(got) != 2 {
		t.Fatalf("chunks=%d", len(got))
	}
	if got[0].Distinct != 1 || got[0].Top != "a" || got[0].Prefix != len(doc) {
		t.Fatalf("chunk1=%+v", got[0])
	}
	if got[1].Distinct != 0 || got[1].Prefix != 1 {
		t.Fatalf("chunk2=%+v", got[1])
	}
}

func TestParseEntityBurst(t *testing.T) {
	mk := func(c uint16) []byte {
		b := make([]byte, 88)
		for i := range b {
			b[i] = byte(i*7 + int(c))
		}
		binary.LittleEndian.PutUint16(b[84:86], c)
		b[86], b[87] = 0, 0
		return b
	}
	bodies := [][]byte{mk(249), mk(258), mk(267)}
	cs, err := ParseEntityBurst(bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 3 || cs[0] != 249 || cs[2] != 267 {
		t.Fatalf("counters=%v", cs)
	}
	// Short body rejected.
	if _, err := ParseEntityBurst([][]byte{make([]byte, 87)}); err == nil {
		t.Fatal("short body must fail")
	}
	// Nonzero tail rejected.
	bad := mk(276)
	bad[86] = 1
	if _, err := ParseEntityBurst([][]byte{mk(249), bad}); err == nil {
		t.Fatal("nonzero tail must fail")
	}
	// Off-step counter rejected.
	if _, err := ParseEntityBurst([][]byte{mk(249), mk(260)}); err == nil {
		t.Fatal("off-step must fail")
	}
}

// encFragment builds one datagram of a fragment chain: flags 0x0078
// (ON|RELIABLE|SEQ|FRAG) with the 12-byte trailer [first u32][last u32]
// [seq u32] and the given payload.
func encFragment(t *testing.T, first, last, seq uint32, pay []byte) []byte {
	t.Helper()
	full := make([]byte, 2)
	binary.LittleEndian.PutUint16(full, 0x0078)
	full = append(full, pay...)
	var b [4]byte
	for _, v := range []uint32{first, last, seq} {
		binary.LittleEndian.PutUint32(b[:], v)
		full = append(full, b[:]...)
	}
	enc, err := encryptBlowfish(floodTestKey, full)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return append([]byte{9, 9, 9, 9}, enc...)
}

// TestReassembleFragsOrdersBySeq is the regression for the reassembly
// bug: fragments must be concatenated in chain order (seq - first), not
// arrival order. Arrival order scrambles the payload whenever the
// network reorders, which is what corrupted every lobby bundle.
func TestReassembleFragsOrdersBySeq(t *testing.T) {
	// Three fragments of one chain, delivered 3rd, 1st, 2nd.
	dd := []DumpDatagram{
		{Dir: "S>C", Addr: "f->t", Data: encFragment(t, 10, 12, 12, []byte("CCC"))},
		{Dir: "S>C", Addr: "f->t", Data: encFragment(t, 10, 12, 10, []byte("AAA"))},
		{Dir: "S>C", Addr: "f->t", Data: encFragment(t, 10, 12, 11, []byte("BBB"))},
	}
	frags, _, _, err := ReassembleFrags(dd, "f->t", len(dd[0].Data), floodTestKey)
	if err != nil {
		t.Fatalf("ReassembleFrags: %v", err)
	}
	if len(frags) != 1 {
		t.Fatalf("got %d chains, want 1", len(frags))
	}
	// Concatenation must follow seq order. Arrival order would give
	// "CCCAAABBB"; the synthetic head carries no marker, so nothing is
	// stripped.
	if got := string(frags[0].Payload); got != "AAABBBCCC" {
		t.Fatalf("payload = %q, want %q (arrival order would give %q)", got, "AAABBBCCC", "CCCAAABBB")
	}
}
