// Command wotcapwalk walks a wotproxy capture's bulk stream element by element.
//
// The element sizes come from the reference's client element table
// (reference/wg-toolkit/src/app/client/element.rs, `id` module): FIXED n for the
// fixed-size elements, VAR 2 for the variable ones, and for an entity method
// `[elem][entity-or-alias][len u16][args]`, which is how the captured server
// frames them.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/LockBlock-dev/wot/login"
)

// fixed sizes from the reference's client element table (wg-toolkit
// wg-toolkit/src/app/client/element.rs, id module).
var fixed = map[byte]int{
	0x00: 4, 0x01: 4, 0x02: 7, 0x03: 4, 0x04: 1,
	0x0D: 0, 0x0E: 0, 0x0F: 4,
	0x10: 5, 0x11: 9,
	0x13: 1, 0x14: 2, 0x15: 1, 0x16: 12, 0x17: 8, 0x18: 1, 0x19: 4, 0x1A: 0, 0x1B: 38,
	0x1C: 29, 0x1D: 26, 0x1E: 25,
	0x24: 0, 0x25: 0,
	0x29: 15, 0x2A: 13, 0x2B: 12, 0x2C: 11, 0x2D: 12, 0x2E: 10, 0x2F: 9, 0x30: 8,
	0x31: 9, 0x32: 7, 0x33: 6, 0x34: 5,
	0x35: 12, 0x36: 10, 0x37: 9, 0x38: 8, 0x39: 9, 0x3A: 7, 0x3B: 6, 0x3C: 5,
	0x3D: 9, 0x3E: 7, 0x3F: 6, 0x40: 5,
}

var variable = map[byte]bool{
	0x05: true, 0x06: true, 0x07: true, 0x08: true, 0x09: true, 0x0A: true,
	0x0B: true, 0x0C: true, 0x12: true,
	0x1F: true, 0x20: true, 0x21: true, 0x22: true, 0x23: true, 0x26: true, 0x27: true, 0x28: true,
	0x49: true, 0x4A: true, 0x4B: true,
}

func main() {
	f, _ := os.Open(os.Args[1])
	defer f.Close()
	dd, _ := login.ParseWotproxyDump(f)
	key, _ := login.ReadKeyFile(os.Args[3])
	var stream []byte
	for _, d := range dd {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, os.Args[2]) || len(d.Data) != 1252 {
			continue
		}
		clear, err := login.DecryptChannel(key, d.Data)
		if err != nil {
			continue
		}
		trl := login.ChannelTrailerLen(binary.LittleEndian.Uint16(clear[0:2]))
		stream = append(stream, clear[2:len(clear)-trl]...)
	}
	fmt.Printf("stream=%d\n", len(stream))
	i := 0
	for n := 0; n < 40 && i < len(stream); n++ {
		e := stream[i]
		if sz, ok := fixed[e]; ok {
			fmt.Printf("%3d @%5d elem=%02x FIXED %d\n", n, i, e, sz)
			i += 1 + sz
			continue
		}
		if variable[e] {
			if i+3 > len(stream) {
				break
			}
			l := int(stream[i+1]) | int(stream[i+2])<<8
			fmt.Printf("%3d @%5d elem=%02x VAR %d % x\n", n, i, e, l, stream[i+3:i+3+min(12, l)])
			i += 3 + l
			continue
		}
		if e >= 0x4E && e <= 0xA6 {
			// [elem][entity-or-alias][len u16][args]
			if i+4 > len(stream) {
				break
			}
			l := int(stream[i+2]) | int(stream[i+3])<<8
			fmt.Printf("%3d @%5d elem=%02x METHOD ent=%02x len=%5d % x\n", n, i, e, stream[i+1], l, stream[i+4:i+4+min(12, l)])
			i += 4 + l
			continue
		}
		if e >= 0xA7 && e <= 0xFE {
			fmt.Printf("%3d @%5d elem=%02x ENTITY_PROPERTY rest=% x\n", n, i, e, stream[i:i+min(16, len(stream)-i)])
			return
		}
		fmt.Printf("%3d @%5d elem=%02x UNKNOWN rest=% x\n", n, i, e, stream[i:i+min(16, len(stream)-i)])
		return
	}
}

func min(a, b int) int { if a < b { return a }; return b }
