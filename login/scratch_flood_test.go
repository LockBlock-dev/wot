// SCRATCH (delete after EU5-hangar iteration): decode a flood.hex capture.
package login

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestScratchDecodeFlood(t *testing.T) {
	keyB, err := os.ReadFile("/tmp/opencode/stage2.key")
	if err != nil {
		t.Skip("no live stage2.key (needs a wotlogin harness run)")
	}
	keyRaw := strings.TrimSpace(string(keyB))
	key := keyRaw
	if len(keyRaw) == 32 {
		if hx, err := hex.DecodeString(keyRaw); err == nil {
			key = string(hx)
		}
	}
	f, err := os.Open("/tmp/opencode/flood.hex")
	if err != nil {
		t.Skip("no live flood.hex (needs a wotlogin harness run)")
	}
	defer f.Close()
	out, err := os.Create("/tmp/opencode/flood.clear")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	var nDec, nFail int
	var firstC2S []string
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, " ", 4)
		if len(parts) != 4 {
			continue
		}
		ts, dir, lnS, hx := parts[0], parts[1], parts[2], parts[3]
		ln, _ := strconv.Atoi(lnS)
		raw, err := hex.DecodeString(hx)
		if err != nil {
			continue
		}
		if dir == "S>C" {
			if len(raw) < 4 {
				continue
			}
			clear, err := decryptBlowfish(key, raw[4:])
			if err != nil {
				nFail++
				continue
			}
			nDec++
			sq, cu, _ := channelSeqs(clear)
			fmt.Fprintf(out, "%s S>C %d seq=%d cumul=%d %x\n", ts, ln, sq, cu, clear)
		} else {
			if len(raw) < 4 {
				continue
			}
			clear, err := decryptBlowfish(key, raw[4:])
			if err != nil {
				nFail++
				continue
			}
			nDec++
			fmt.Fprintf(out, "%s C>S %d %x\n", ts, ln, clear)
		}
	}
	for _, l := range firstC2S {
		fmt.Fprintln(out, l)
	}
	t.Logf("decoded=%d fail=%d", nDec, nFail)
}
