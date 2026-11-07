package login

import (
	"bytes"
	"encoding/binary"
	"os"
	"sort"
	"testing"
)

// TestFloodBundleMatchesCapture is the oracle for the authored bundle:
// the genuine 2.4.1 flood's createBasePlayer element must come out
// byte-identical from FloodBundle.Encode, given the capture's own
// settings pickle. The capture is a TEST fixture only — the server never
// reads it.
func TestFloodBundleMatchesCapture(t *testing.T) {
	dumpPath, keyPath := "../../captures/live-flood.hex", "../../captures/key-live.txt"
	if _, err := os.Stat(dumpPath); err != nil {
		t.Skipf("no capture (%v)", err)
	}
	key, err := ReadAnyKeyFile(keyPath)
	if err != nil {
		t.Skipf("no key (%v)", err)
	}
	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dump, err := ParseWotproxyDump(f)
	if err != nil {
		t.Fatal(err)
	}
	// Reassemble the biggest fragment chain: the flood bundle.
	type fr struct {
		pay []byte
		rel uint32
	}
	chains := map[uint32][]fr{}
	for _, d := range dump {
		if d.Dir != "S>C" || len(d.Data) < 20 {
			continue
		}
		clear, err := DecryptChannelFrame(key, d.Data)
		if err != nil || len(clear) < 14 {
			continue
		}
		flags := binary.LittleEndian.Uint16(clear[0:2])
		if flags&chFlagFragment == 0 {
			continue
		}
		tr := ChannelTrailerLen(flags)
		if len(clear) < 2+tr {
			continue
		}
		first, _, seq, ok := fragRange(clear)
		if !ok {
			continue
		}
		chains[first] = append(chains[first], fr{pay: clear[2 : len(clear)-tr], rel: seq - first})
	}
	var best uint32
	for id, c := range chains {
		if len(c) > len(chains[best]) {
			best = id
		}
	}
	c := chains[best]
	sort.Slice(c, func(a, b int) bool { return c[a].rel < c[b].rel })
	var stream []byte
	for _, x := range c {
		stream = append(stream, x.pay...)
	}

	// Pull the capture's own values out of the stream so the comparison
	// is about the ENCODING, not about our content choices.
	//   [02][freq][unk u16][gameTime u32][13][tag][05][FF FF][u32 len]
	//   [entity u32][type u16][blob 0][ver][name][incarnation u64][py][comp]
	if len(stream) < 24 || stream[0] != 0x02 || stream[8] != 0x13 || stream[10] != 0x05 {
		t.Fatalf("unexpected bundle head % x", stream[:24])
	}
	freq := stream[1]
	gameTime := binary.LittleEndian.Uint32(stream[4:8])
	tag := stream[9]
	// The element's oversize form moved the payload's first four bytes
	// (the entity id) to the end of the element, so the body starts with
	// the type id and the entity id is the element's last four bytes.
	elemLen := int(binary.LittleEndian.Uint32(stream[13:17]))
	elemEnd := 17 + elemLen // one past the element's last byte
	entityID := binary.LittleEndian.Uint32(stream[elemEnd-4 : elemEnd])
	typeID := binary.LittleEndian.Uint16(stream[17:19])
	off := 20 // 17 + 2 (type) + 1 (blob)
	readPacked := func() []byte {
		if stream[off] == 0xFF {
			n := int(stream[off+1]) | int(stream[off+2])<<8 | int(stream[off+3])<<16
			v := stream[off+4 : off+4+n]
			off += 4 + n
			return v
		}
		n := int(stream[off])
		v := stream[off+1 : off+1+n]
		off += 1 + n
		return v
	}
	version := readPacked()
	name := readPacked()
	incarnation := binary.LittleEndian.Uint64(stream[off : off+8])
	off += 8
	settings := readPacked()
	components := stream[off]

	got, err := FloodBundle{
		EntityID:    entityID,
		TypeID:      typeID,
		Version:     string(version),
		Name:        string(name),
		Incarnation: incarnation,
		Settings:    settings,
		Components:  components,
		Frequency:   freq,
		GameTime:    gameTime,
		TickTag:     tag,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, stream) {
		// Report the first divergence, not 246 KB of hex.
		i := 0
		for i < len(got) && i < len(stream) && got[i] == stream[i] {
			i++
		}
		lo := i - 8
		if lo < 0 {
			lo = 0
		}
		hi := i + 16
		if hi > len(stream) {
			hi = len(stream)
		}
		t.Fatalf("authored bundle is %d B, capture %d B; first difference at %d:\n got % x\nwant % x",
			len(got), len(stream), i, got[lo:min(hi, len(got))], stream[lo:hi])
	}
	t.Logf("authored bundle matches the capture: %d B, entity %d, %d B settings, %d components",
		len(got), entityID, len(settings), components)
}
