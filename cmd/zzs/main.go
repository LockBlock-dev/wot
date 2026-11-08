package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/LockBlock-dev/wot/login"
)

func main() {
	f, _ := os.Open(os.Args[1])
	dd, _ := login.ParseWotproxyDump(f)
	key, _ := login.ReadKeyFile(os.Args[3])
	type rec struct {
		seq   uint32
		flags uint16
		head  string
		n     int
	}
	seen := map[uint32]rec{}
	var order []uint32
	for _, d := range dd {
		if d.Dir != "S>C" || !strings.Contains(d.Addr, os.Args[2]) {
			continue
		}
		clear, err := login.DecryptChannel(key, d.Data)
		if err != nil || len(clear) < 2 {
			continue
		}
		flags := binary.LittleEndian.Uint16(clear[0:2])
		tr := login.ChannelTrailerLen(flags)
		if len(clear) < 2+tr {
			continue
		}
		app := clear[2 : len(clear)-tr]
		seq := binary.LittleEndian.Uint32(clear[len(clear)-8:])
		if _, ok := seen[seq]; ok {
			continue
		}
		h := ""
		if flags == 0x0078 {
			h = fmt.Sprintf("[%d..%d]", binary.LittleEndian.Uint32(clear[len(clear)-12:]), binary.LittleEndian.Uint32(clear[len(clear)-8:]))
		} else {
			for i := 0; i < len(app) && i < 6; i++ {
				h += fmt.Sprintf("%02x ", app[i])
			}
		}
		seen[seq] = rec{seq, flags, h, len(app)}
		order = append(order, seq)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, s := range order {
		if s < 8 || s > 26 {
			continue
		}
		r := seen[s]
		fmt.Printf("seq %-4d flags=%#04x %-5dB %s\n", r.seq, r.flags, r.n, r.head)
	}
}
