package login

import (
	"bytes"
	"testing"
)

const testBlockKey = "0123456789abcdef"

// TestFrameSizeMatchesCapture pins the datagram size: a 1223 B payload
// must produce the 1252 B frames every genuine flood uses.
func TestFrameSizeMatchesCapture(t *testing.T) {
	if got := FrameSize(DefaultBulkPayload); got != 1252 {
		t.Fatalf("FrameSize(%d) = %d, want 1252", DefaultBulkPayload, got)
	}
}

// TestBuildFramesRoundTrip is the builder's contract: frames built from a
// stream reassemble to that stream.
func TestBuildFramesRoundTrip(t *testing.T) {
	stream := make([]byte, 5000)
	for i := range stream {
		stream[i] = byte(i * 7)
	}
	frames, err := BuildFrames(testBlockKey, stream, DefaultBulkPayload, 1)
	if err != nil {
		t.Fatalf("BuildFrames: %v", err)
	}
	if len(frames) != 5 { // 4 full + 1 short
		t.Fatalf("%d frames, want 5", len(frames))
	}
	for i, f := range frames {
		want := 1252
		if i == len(frames)-1 {
			want = FrameSize(len(stream) - 4*DefaultBulkPayload)
		}
		if len(f) != want {
			t.Errorf("frame %d is %d B, want %d", i, len(f), want)
		}
	}
	got, err := ReadFrames(testBlockKey, frames)
	if err != nil {
		t.Fatalf("ReadFrames: %v", err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("round-trip differs: %d in, %d out", len(stream), len(got))
	}
}

// TestBuildFramesCarriesRange pins the trailer: every frame of a chain
// carries the same (first, last) range, which is what lets the client
// reassemble by position.
func TestBuildFramesCarriesRange(t *testing.T) {
	stream := make([]byte, 3*DefaultBulkPayload)
	frames, err := BuildFrames(testBlockKey, stream, DefaultBulkPayload, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("%d frames, want 3", len(frames))
	}
	for i, f := range frames {
		clear, err := decryptBlowfish(testBlockKey, f[4:])
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		n := len(clear)
		flags := uint16(clear[0]) | uint16(clear[1])<<8
		if flags != bulkFlags {
			t.Errorf("frame %d flags = %#04x, want %#04x", i, flags, bulkFlags)
		}
		first := uint32(clear[n-12]) | uint32(clear[n-11])<<8 | uint32(clear[n-10])<<16 | uint32(clear[n-9])<<24
		last := uint32(clear[n-8]) | uint32(clear[n-7])<<8 | uint32(clear[n-6])<<16 | uint32(clear[n-5])<<24
		seq := uint32(clear[n-4]) | uint32(clear[n-3])<<8 | uint32(clear[n-2])<<16 | uint32(clear[n-1])<<24
		if first != 100 || last != 102 {
			t.Errorf("frame %d range = %d..%d, want 100..102", i, first, last)
		}
		if seq != uint32(100+i) {
			t.Errorf("frame %d seq = %d, want %d", i, seq, 100+i)
		}
	}
}

// TestReadFramesIgnoresArrivalOrder is why the range exists: a chain
// delivered out of order must still reassemble.
func TestReadFramesIgnoresArrivalOrder(t *testing.T) {
	stream := make([]byte, 4*DefaultBulkPayload)
	for i := range stream {
		stream[i] = byte(i)
	}
	frames, err := BuildFrames(testBlockKey, stream, DefaultBulkPayload, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse the arrival order.
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	got, err := ReadFrames(testBlockKey, frames)
	if err != nil {
		t.Fatalf("ReadFrames: %v", err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatal("out-of-order chain did not reassemble")
	}
}

// TestBuildFramesRejectsEmpty keeps a zero-length bundle from producing a
// chain the client would wait on forever.
func TestBuildFramesRejectsEmpty(t *testing.T) {
	if _, err := BuildFrames(testBlockKey, nil, DefaultBulkPayload, 1); err == nil {
		t.Fatal("empty stream accepted")
	}
}
