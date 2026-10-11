package login

import (
	"encoding/binary"
	"testing"
)

// Synthetic token-dict pickles in the genuine framing:
// EMPTY_DICT + MARK + (SHORT_BINUNICODE key, BININT/J value)* +
// SETITEMS, embedded in noise. Values are synthetic.
func tokDict(intTok bool) []byte {
	out := []byte{0x7d, 0x71, 0x01, 0x28} // } q1 (
	out = append(out, 0x55, 0x0a)
	out = append(out, "databaseID"...)
	out = append(out, 0x71, 0x02) // q2
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 123456789)
	out = append(out, 0x4a)
	out = append(out, tmp[:]...) // J BININT
	out = append(out, 0x55, 0x05)
	out = append(out, "token"...)
	out = append(out, 0x71, 0x03) // q3
	if intTok {
		binary.LittleEndian.PutUint32(tmp[:], 12345678)
		out = append(out, 0x4a)
		out = append(out, tmp[:]...)
	} else {
		out = append(out, 0x55, 0x05, 'a', '.', 'b', '.', 'c') // dotted => JWT flag
	}
	out = append(out, 0x75, 0x2e) // u .
	return out
}

func TestFindTokenDicts(t *testing.T) {
	blob := append([]byte{0x13, 0x05, 0xde, 0xad}, tokDict(true)...)
	blob = append(blob, 0x99, 0x88)
	blob = append(blob, tokDict(false)...)
	hits := FindTokenDicts(blob)
	if len(hits) != 2 {
		t.Fatalf("hits=%d", len(hits))
	}
	if hits[0].DBID != 123456789 || hits[0].Token != "12345678" || hits[0].JWT {
		t.Fatalf("int hit %+v", hits[0])
	}
	if hits[1].Token != "a.b.c" || !hits[1].JWT {
		t.Fatalf("str hit %+v", hits[1])
	}
	if id := hits[0].TokenID(); len(id) < 8 {
		t.Fatalf("token id %q", id)
	}
	if len(FindTokenDicts([]byte("no databaseID here"))) != 0 {
		t.Fatal("false positive")
	}
	// truncated dict: no hit, no panic
	if len(FindTokenDicts(tokDict(true)[:10])) != 0 {
		t.Fatal("truncated hit")
	}
}
