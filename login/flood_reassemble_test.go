package login

// Bulk reassembly vectors (login side): chunk headers, gap fill and
// frag grouping. Pure-pickle decoding lives in the lobby package.
import (
	"bytes"
	"encoding/binary"
	"testing"
)

func mkFrag(t *testing.T, seq uint32, payload []byte) DumpDatagram {
	t.Helper()
	full := make([]byte, 2)
	binary.LittleEndian.PutUint16(full, 0x0078)
	full = append(full, payload...)
	var s, c [4]byte
	binary.LittleEndian.PutUint32(s[:], seq)
	binary.LittleEndian.PutUint32(c[:], 0)
	full = append(full, s[:]...)
	full = append(full, s[:]...)
	full = append(full, c[:]...)
	enc, err := encryptBlowfish(floodTestKey, full)
	if err != nil {
		t.Fatal(err)
	}
	return DumpDatagram{Dir: "S>C", Addr: "f->t", Data: append([]byte{1, 2, 3, 4}, enc...)}
}

func TestReassembleBaseVote(t *testing.T) {
	// Sep-17 style: odd-shape base 0x51 voted from dd00 heads.
	mk := func(seq uint32, head []byte, bodyLen int) DumpDatagram {
		p := append(append([]byte(nil), head...), bytes.Repeat([]byte{0x41}, bodyLen)...)
		return mkFrag(t, seq, p)
	}
	d0 := mk(1, []byte{0xFF, 0x18, 0x46, 0x03}, 104)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mk(2, []byte{0x13, 0x53, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x02}, 100),
		mk(3, []byte{0x13, 0x55, 0x1A, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, 100),
		mk(4, []byte{0x13, 0x56, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x05}, 100),
	}
	frags, _, _, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 4 {
		t.Fatalf("frags=%d", len(frags))
	}
	for i, want := range []int{1, 2, 4, 5} {
		if frags[i].NN != want {
			t.Fatalf("frag%d NN=%d want %d", i, frags[i].NN, want)
		}
	}
}

func TestReassembleGapFill(t *testing.T) {
	mk := func(seq uint32, head []byte, bodyLen int) DumpDatagram {
		p := append(append([]byte(nil), head...), bytes.Repeat([]byte{0x41}, bodyLen)...)
		return mkFrag(t, seq, p)
	}
	d0 := mk(1, []byte{0xFF, 0x18, 0x46, 0x03}, 104)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mk(9, []byte{0x13, 0x7B, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x03}, 100),
		mk(3, []byte{0xFE, 0x7B, 0x71, 0xC5, 0xAB, 0x0C, 0x86, 0xF1}, 100),
	}
	frags, _, _, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(frags) != 3 {
		t.Fatalf("frags=%d", len(frags))
	}
	if frags[0].NN != 1 || frags[1].NN != 3 {
		t.Fatalf("nns=%d,%d", frags[0].NN, frags[1].NN)
	}
	if frags[2].NN != 2 {
		t.Fatalf("gap-filled NN=%d, want 2", frags[2].NN)
	}
	if len(frags[2].Payload) != 100 {
		t.Fatalf("unknown head not stripped 8: len=%d", len(frags[2].Payload))
	}
}

func TestReassembleFrags(t *testing.T) {
	// Chunk model: same-seq datagrams are one chunk's burst (head +
	// continuations), concatenated — not dropped as retransmits.
	p0 := append([]byte{0xFF, 0x18, 0x46, 0x03}, bytes.Repeat([]byte{0x41}, 100)...)
	p0cont := bytes.Repeat([]byte{0x43}, 104) // same wire size as p0
	p1 := append([]byte{0x13, 0x50, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x07}, bytes.Repeat([]byte{0x42}, 100)...)
	d0 := mkFrag(t, 7, p0)
	sz := len(d0.Data)
	dd := []DumpDatagram{
		d0,
		mkFrag(t, 7, p0cont), // same seq: continuation, appended raw
		mkFrag(t, 9, p1),
		mkFrag(t, 3, p1),
	}
	frags, offsets, st, err := ReassembleFrags(dd, "f->t", sz, floodTestKey)
	if err != nil {
		t.Fatal(err)
	}
	if st.Frags != 4 || len(frags) != 3 {
		t.Fatalf("frags=%d st=%+v", len(frags), st)
	}
	if len(frags[0].Payload) != 204 || frags[0].Payload[0] != 0x41 || frags[0].Payload[100] != 0x43 {
		t.Fatalf("frag0 not concatenated: len=%d", len(frags[0].Payload))
	}
	if frags[0].NN != 1 {
		t.Fatalf("frag0 NN=%d", frags[0].NN)
	}
	if len(frags[1].Payload) != 100 || frags[1].Payload[0] != 0x42 {
		t.Fatalf("frag1 head not stripped: %x", frags[1].Payload[:4])
	}
	if frags[1].NN != 7 {
		t.Fatalf("frag1 NN=%d", frags[1].NN)
	}
	if len(offsets) != 3 || offsets[0] != 0 || offsets[1] != 204 || offsets[2] != 304 {
		t.Fatalf("offsets=%v", offsets)
	}
}
