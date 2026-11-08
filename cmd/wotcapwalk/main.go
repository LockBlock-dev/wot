// Command wotcapwalk walks a wotproxy capture's bulk stream element by element.
//
// The element sizes come from the client's own server-to-client table
// (`login/clientElements`), so an id this build does not know is reported
// rather than guessed at. Entity methods are `[elem][entity-or-alias][len u16]
// [args]`; entity properties carry no entity byte — the entity is whatever the
// preceding selectEntity/selectPlayerEntity selected, and the length is the
// property's declared one.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/LockBlock-dev/wot/login"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "usage: wotcapwalk DUMP ADDR-SUBSTR KEYFILE [MAX]\n")
		os.Exit(2)
	}
	max := 400
	if len(os.Args) > 4 {
		fmt.Sscanf(os.Args[4], "%d", &max)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	dd, err := login.ParseWotproxyDump(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	key, err := login.ReadKeyFile(os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Concatenate in arrival order. A capture also contains the
	// retransmissions, so a walk past a resent frame is unreliable — the
	// stream needs per-channel reassembly (the client rebinds its socket on
	// battle entry, so one flow substring can span two channels) and that is
	// not what this tool does. It is still enough to read the head of a
	// stream and to census it.
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
		if len(clear) < 2+trl {
			continue
		}
		stream = append(stream, clear[2:len(clear)-trl]...)
	}
	fmt.Printf("stream=%d\n", len(stream))
	counts := map[uint8]int{}
	i := 0
	for n := 0; n < max && i < len(stream); n++ {
		e := stream[i]
		if fixed, ok := login.ClientElementLength(e); ok {
			if fixed >= 0 {
				fmt.Printf("%4d @%6d elem=%02x %-28s FIXED %d\n", n, i, e, login.ClientElementName(e), fixed)
				counts[e]++
				i += 1 + fixed
				continue
			}
			if i+3 > len(stream) {
				break
			}
			l := int(stream[i+1]) | int(stream[i+2])<<8
			fmt.Printf("%4d @%6d elem=%02x %-28s VAR %d % x\n", n, i, e, login.ClientElementName(e), l, stream[i+3:i+3+min(12, l)])
			counts[e]++
			i += 3 + l
			continue
		}
		if e >= 0x4E && e <= 0xA6 {
			if i+4 > len(stream) {
				break
			}
			l := int(stream[i+2]) | int(stream[i+3])<<8
			fmt.Printf("%4d @%6d elem=%02x METHOD ent=%02x len=%5d % x\n", n, i, e, stream[i+1], l, stream[i+4:i+4+min(12, l)])
			counts[e]++
			i += 4 + l
			continue
		}
		if e >= 0xA7 && e <= 0xFE {
			if i+3 > len(stream) {
				break
			}
			l := int(stream[i+1]) | int(stream[i+2])<<8
			fmt.Printf("%4d @%6d elem=%02x PROPERTY len=%5d % x\n", n, i, e, l, stream[i+3:i+3+min(12, l)])
			counts[e]++
			i += 3 + l
			continue
		}
		fmt.Printf("%4d @%6d elem=%02x UNKNOWN rest=% x\n", n, i, e, stream[i:i+min(16, len(stream)-i)])
		break
	}
	for id := 0; id < 256; id++ {
		if c := counts[uint8(id)]; c > 0 {
			name := login.ClientElementName(uint8(id))
			if name == "" {
				name = "?"
			}
			fmt.Printf("  %#02x %-28s x%d\n", id, name, c)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
