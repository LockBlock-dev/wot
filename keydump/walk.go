// Walk capture: records the login entity-defs digest walk live from the
// game (entry names in visit order + pass/fail per entry). The 2.4.1.0
// offline recompute is byte-correct (IDA-verified visitors) but the walk
// SET is runtime-decided (Python-side registration, unknowable from
// defs), so this reads the ground truth out of the running process
// instead of brute-forcing it.
//
// Breakpoint: the digest entry filter (2.4.1.0 sub_142CAA130, file
// offset 0x2CA9530: `sub rsp,28h; cmp byte [rdx+87h],0; jz; call
// 0x142CAA150; mov al,1`). It fires once per walked entry with the
// entry descriptor in RDX: pass byte at +135 (+0x87), name as an MSVC
// std::string at +8 (SSO-inline or heap, same 32 B layout as mem.go).
// The single-hit pattern below covers the prologue with ?? over the
// call rel32 (drifts per build); findHit's count==1 rule still guards.
package keydump

import (
	"encoding/binary"
	"fmt"
	"time"
)

// WalkDefaultPattern matches the digest entry filter on EU 2.4.1.0
// win64/WorldOfTanks.exe (82 MB; IDA sub_142CAA130). Verified single-hit
// against the image.
var WalkDefaultPattern = "48 83 EC 28 80 BA 87 00 00 00 00 74 0C E8 ?? ?? ?? ?? B0 01 48 83 C4 28 C3"

// Offsets inside the digest entry descriptor (IDA 2.4.1.0 sub_142CAA130/
// sub_142CAA150; version-invariant per the 2.4.0/2.4.1 walker diff).
const (
	// WalkPassOff is the +135 filter byte: 0 = entry skipped (name not
	// hashed), nonzero = visited.
	WalkPassOff = 135
	// WalkNameOff is the entry-name std::string object.
	WalkNameOff = 8
	// MaxWalkNameLen rejects garbage pointers (longest real entry name
	// is ~40 chars; bound is structural, not content).
	MaxWalkNameLen = 128
)

// WalkEntry is one visited digest-map entry in walk order.
type WalkEntry struct {
	Index int
	Name  string
	Pass  bool
}

// WalkConfig drives Walk (Linux/Wine only; see walk_linux.go).
type WalkConfig struct {
	PID        int
	ExeName    string
	Needle     []byte
	Mask       []byte
	OutPath    string
	MaxEntries int           // stop after this many walk hits (0 = 800)
	Timeout    time.Duration // overall deadline (0 = 15m)
	WaitFor    time.Duration // poll for the game instead of failing (0 = none)
	QuietAfter time.Duration // end the walk after this long without a hit once started (0 = 20s)
	Force      bool          // try ptrace even on sandboxed targets (kernel decides)
}

func (c *WalkConfig) withWalkDefaults() error {
	if c.ExeName == "" {
		c.ExeName = "WorldOfTanks.exe"
	}
	if c.Needle == nil {
		n, m, err := ParsePattern(WalkDefaultPattern)
		if err != nil {
			return err
		}
		c.Needle, c.Mask = n, m
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = 800
	}
	if c.Timeout <= 0 {
		c.Timeout = 15 * time.Minute
	}
	if c.QuietAfter <= 0 {
		c.QuietAfter = 20 * time.Second
	}
	if c.OutPath == "" {
		c.OutPath = "walkdump.txt"
	}
	return nil
}

// readStdString reads an MSVC x64 std::string object at addr (32 B:
// [ptr][len@16][cap@24], SSO-inline when cap <= 15).
func readStdString(mr MemReader, addr uint64) (string, error) {
	obj, err := mr.Read(addr, 32)
	if err != nil {
		return "", fmt.Errorf("walkdump: read string object: %w", err)
	}
	n := binary.LittleEndian.Uint64(obj[16:24])
	if n > MaxWalkNameLen {
		return "", fmt.Errorf("walkdump: odd name length %d", n)
	}
	cap := binary.LittleEndian.Uint64(obj[24:32])
	if cap > 15 {
		ptr := binary.LittleEndian.Uint64(obj[:8])
		raw, err := mr.Read(ptr, int(n))
		if err != nil {
			return "", fmt.Errorf("walkdump: read name bytes: %w", err)
		}
		return string(raw), nil
	}
	return string(obj[:n]), nil
}
