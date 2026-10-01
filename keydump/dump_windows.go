//go:build windows

package keydump

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows backend: same breakpoint recipe as dump_linux.go, via the Win32
// Debug API instead of ptrace. Only kernel32 entry points are used and all
// are resolved lazily, so the build needs no CGO. This file is
// compile-checked on Linux (GOOS=windows go build); live runs happen on
// the game host.

var (
	k32                     = windows.NewLazySystemDLL("kernel32.dll")
	pProcess32First         = k32.NewProc("Process32First")
	pProcess32Next          = k32.NewProc("Process32Next")
	pModule32First          = k32.NewProc("Module32First")
	pModule32Next           = k32.NewProc("Module32Next")
	pReadProcessMemory      = k32.NewProc("ReadProcessMemory")
	pWriteProcessMemory     = k32.NewProc("WriteProcessMemory")
	pFlushInstructionCache  = k32.NewProc("FlushInstructionCache")
	pDebugActiveProcess     = k32.NewProc("DebugActiveProcess")
	pDebugActiveProcessStop = k32.NewProc("DebugActiveProcessStop")
	pWaitForDebugEvent      = k32.NewProc("WaitForDebugEvent")
	pContinueDebugEvent     = k32.NewProc("ContinueDebugEvent")
	pOpenThread             = k32.NewProc("OpenThread")
	pGetThreadContext       = k32.NewProc("GetThreadContext")
	pSetThreadContext       = k32.NewProc("SetThreadContext")
)

const (
	dbgException   = 1
	dbgExitProcess = 5
	excBreakpoint  = 0x80000003
	dbgContinue    = 0x00010002
	ctxFull        = 0x10000B // CONTEXT_FULL: control|integer|fp
	ctxFlagsOff    = 0x30
	ctxRcxOff      = 0x80
	ctxRipOff      = 0xF8
	ctxSize        = 0x4D0
)

type processEntry struct {
	size         uint32
	usage        uint32
	pid          uint32
	heapID       uintptr
	moduleID     uint32
	threads      uint32
	parentPID    uint32
	priClassBase int32
	flags        uint32
	exeFile      [260]byte
}

type moduleEntry struct {
	size      uint32
	moduleID  uint32
	processID uint32
	glblUsage uint32
	procUsage uint32
	baseAddr  *byte
	baseSize  uint32
	hModule   windows.Handle
	module    [256]byte
	exePath   [260]byte
}

type debugEvent struct {
	code uint32
	pid  uint32
	tid  uint32
	data [176]byte
}

func cstr(b []byte) string {
	for i, v := range b {
		if v == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Run attaches to the game, dumps up to MaxHits keys, then detaches.
func Run(cfg Config) error {
	if err := cfg.withDefaults(); err != nil {
		return err
	}
	pid := cfg.PID
	if pid == 0 {
		deadline := time.Now().Add(cfg.WaitFor)
		for {
			p, err := findExe(cfg.ExeName)
			if err == nil {
				pid = p
				break
			}
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Second)
		}
	}
	d := &debugger{pid: uint32(pid), cfg: cfg}
	return d.run()
}

func findExe(exe string) (int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("keydump: snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	var pe processEntry
	pe.size = uint32(unsafe.Sizeof(pe))
	r1, _, _ := pProcess32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&pe)))
	if r1 == 0 {
		return 0, fmt.Errorf("keydump: Process32First failed")
	}
	var found []int
	for {
		if strings.EqualFold(cstr(pe.exeFile[:]), exe) {
			found = append(found, int(pe.pid))
		}
		r1, _, _ = pProcess32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&pe)))
		if r1 == 0 {
			break
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("keydump: no %s process (start the game to the login screen first)", exe)
	case 1:
		return found[0], nil
	default:
		return 0, fmt.Errorf("keydump: %d %s processes %v, pass -pid", len(found), exe, found)
	}
}

type debugger struct {
	pid   uint32
	cfg   Config
	hProc windows.Handle
	hitVA uint64
	orig  byte
	plant bool
	hits  int
}

type winReader struct{ d *debugger }

func (w winReader) Read(addr uint64, n int) ([]byte, error) {
	return w.d.readMem(addr, n)
}

func (d *debugger) readMem(addr uint64, n int) ([]byte, error) {
	buf := make([]byte, n)
	var done uintptr
	r1, _, e := pReadProcessMemory.Call(uintptr(d.hProc), uintptr(addr), uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&done)))
	if r1 == 0 {
		return nil, fmt.Errorf("keydump: ReadProcessMemory: %v", e)
	}
	return buf[:int(done)], nil
}

func (d *debugger) writeMem(addr uint64, b []byte) error {
	var done uintptr
	r1, _, e := pWriteProcessMemory.Call(uintptr(d.hProc), uintptr(addr), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&done)))
	if r1 == 0 {
		return fmt.Errorf("keydump: WriteProcessMemory: %v", e)
	}
	pFlushInstructionCache.Call(uintptr(d.hProc), uintptr(addr), uintptr(len(b)))
	return nil
}

func (d *debugger) moduleBase() (uint64, uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, d.pid)
	if err != nil {
		return 0, 0, fmt.Errorf("keydump: module snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	var me moduleEntry
	me.size = uint32(unsafe.Sizeof(me))
	r1, _, _ := pModule32First.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	if r1 == 0 {
		return 0, 0, fmt.Errorf("keydump: Module32First failed")
	}
	for {
		if strings.EqualFold(cstr(me.module[:]), d.cfg.ExeName) {
			return uint64(uintptr(unsafe.Pointer(me.baseAddr))), me.baseSize, nil
		}
		r1, _, _ = pModule32Next.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
		if r1 == 0 {
			break
		}
	}
	return 0, 0, fmt.Errorf("keydump: %s module not found in %d", d.cfg.ExeName, d.pid)
}

func (d *debugger) run() error {
	h, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_QUERY_INFORMATION, false, d.pid)
	if err != nil {
		return fmt.Errorf("keydump: OpenProcess: %w", err)
	}
	d.hProc = h
	defer windows.CloseHandle(d.hProc)
	// The module may not be loaded yet when -wait caught a fresh process.
	deadline := time.Now().Add(d.cfg.WaitFor)
	for {
		base, size, err := d.moduleBase()
		if err == nil {
			return d.runAt(base, size)
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(2 * time.Second)
	}
}

func (d *debugger) runAt(base uint64, size uint32) error {
	// Bulk-read the image for the pattern scan (chunked; one 80 MB
	// ReadProcessMemory usually works but chunking is safer).
	img := make([]byte, 0, size)
	for off := uint64(0); off < uint64(size); {
		n := uint64(1 << 20)
		if off+n > uint64(size) {
			n = uint64(size) - off
		}
		chunk, err := d.readMem(base+off, int(n))
		if err != nil {
			return fmt.Errorf("keydump: read image: %w", err)
		}
		img = append(img, chunk...)
		off += uint64(len(chunk))
		if len(chunk) == 0 {
			break
		}
	}
	var hits []uint64
	for _, o := range Scan(img, d.cfg.Needle, d.cfg.Mask) {
		hits = append(hits, base+uint64(o))
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("keydump: pattern not found in %s image (wrong game version? re-derive via IDA sub_140E6E210)", d.cfg.ExeName)
	case 1:
		d.hitVA = hits[0]
	default:
		return fmt.Errorf("keydump: pattern hits %d addresses %x (refine the pattern, refusing to guess)", len(hits), hits)
	}
	orig, err := d.readMem(d.hitVA, 1)
	if err != nil {
		return fmt.Errorf("keydump: read target byte: %w", err)
	}
	d.orig = orig[0]
	if err := d.writeMem(d.hitVA, []byte{0xCC}); err != nil {
		return fmt.Errorf("keydump: plant breakpoint: %w", err)
	}
	d.plant = true
	defer func() {
		if d.plant {
			d.writeMem(d.hitVA, []byte{d.orig}) //nolint:errcheck // best effort
		}
		pDebugActiveProcessStop.Call(uintptr(d.pid)) //nolint:errcheck // best effort
	}()
	r1, _, e := pDebugActiveProcess.Call(uintptr(d.pid))
	if r1 == 0 {
		return fmt.Errorf("keydump: DebugActiveProcess (VEH/already-debugged? close CE first): %v", e)
	}
	deadline := time.Now().Add(d.cfg.Timeout)
	var ev debugEvent
	for d.hits < d.cfg.MaxHits {
		if time.Now().After(deadline) {
			return fmt.Errorf("keydump: timeout after %d hits (click Login in the game; breakpoint is at login-build time)", d.hits)
		}
		r1, _, _ = pWaitForDebugEvent.Call(uintptr(unsafe.Pointer(&ev)), 1000)
		if r1 == 0 {
			continue // timeout: re-check deadline/hits
		}
		if ev.code == dbgExitProcess {
			pContinueDebugEvent.Call(uintptr(ev.pid), uintptr(ev.tid), dbgContinue) //nolint:errcheck // best effort
			return fmt.Errorf("keydump: game exited after %d hits", d.hits)
		}
		if ev.code != dbgException {
			pContinueDebugEvent.Call(uintptr(ev.pid), uintptr(ev.tid), dbgContinue) //nolint:errcheck // best effort
			continue
		}
		code := *(*uint32)(unsafe.Pointer(&ev.data[0]))
		addr := *(*uint64)(unsafe.Pointer(&ev.data[16]))
		if code != excBreakpoint || addr != d.hitVA {
			pContinueDebugEvent.Call(uintptr(ev.pid), uintptr(ev.tid), dbgContinue) //nolint:errcheck // best effort
			continue
		}
		d.onHit(ev.tid)
		pContinueDebugEvent.Call(uintptr(ev.pid), uintptr(ev.tid), dbgContinue) //nolint:errcheck // best effort
	}
	return nil
}

// onHit reads RCX+[0x58]/[0x68] at the breakpoint, logs the key, and rewinds
// past the int3 so the builder runs normally — the pause is milliseconds,
// like CE's co_run resume, and never burns the 30 s pending window.
func (d *debugger) onHit(tid uint32) {
	hThread, _, _ := pOpenThread.Call(windows.THREAD_GET_CONTEXT|windows.THREAD_SET_CONTEXT, 0, uintptr(tid))
	if hThread == 0 {
		return
	}
	defer windows.CloseHandle(windows.Handle(hThread))
	var ctx [ctxSize]byte
	*(*uint32)(unsafe.Pointer(&ctx[ctxFlagsOff])) = ctxFull
	r1, _, _ := pGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0])))
	if r1 == 0 {
		return
	}
	rcx := *(*uint64)(unsafe.Pointer(&ctx[ctxRcxOff]))
	key, ptr, strobj, err := ReadKey(winReader{d}, rcx)
	if err == nil {
		_ = AppendKey(d.cfg.KeyFile, ptr, key, strobj)
	}
	_ = d.writeMem(d.hitVA, []byte{d.orig})
	rip := (*uint64)(unsafe.Pointer(&ctx[ctxRipOff]))
	*rip--
	pSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx[0]))) //nolint:errcheck // best effort
	if err == nil {
		d.hits++
	} else {
		_ = d.writeMem(d.hitVA, []byte{0xCC}) // stale hit: re-arm
	}
}
