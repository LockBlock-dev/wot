package login

import (
	"bytes"
	"testing"

	"github.com/LockBlock-dev/wot/lobby"
)

// TestErrorSmallMatchesLiteral pins the 1a/5e error answer to the bytes
// the hand-built literal produced, so moving it onto lobby.Small did not
// change the wire.
func TestErrorSmallMatchesLiteral(t *testing.T) {
	for _, status := range []byte{0x00, 0x01} {
		for _, req := range []uint16{0, 225, 234, 0xFFFF} {
			small, err := lobby.Small{Family: 0x1a, Type: 0x5e, Body: []byte{
				byte(req), byte(req >> 8), status, 0x00, 0x00,
			}}.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			want := []byte{0x1a, 0x5e, 0x05, byte(req), byte(req >> 8), status, 0x00, 0x00}
			if !bytes.Equal(small, want) {
				t.Fatalf("req %d status %d: % x, want % x", req, status, small, want)
			}
			app := answerApp(small)
			wantApp := append([]byte{0x13, 0x00}, want...)
			if !bytes.Equal(app, wantApp) {
				t.Fatalf("answer app = % x, want % x", app, wantApp)
			}
		}
	}
}
