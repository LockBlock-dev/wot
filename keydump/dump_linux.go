//go:build linux

package keydump

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Linux backend: the game is a Windows EXE running under Wine/Proton, which
// is a regular Linux process, so the breakpoint recipe works with ptrace +
// procfs and no Wine cooperation is needed:
//
//  1. find the PID by comm/cmdline match (Wine truncates comm to 15 chars,
//     so "WorldOfTanks.exe" appears as "WorldOfTanks.e" — match both),
//  2. read r-x code mappings of WorldOfTanks.exe from /proc/pid/maps and
//     scan them via /proc/pid/mem (fast bulk pread, no ptrace word loop),
//  3. PTRACE_ATTACH every thread, plant 0xCC at the single pattern hit,
//  4. on SIGTRAP with RIP-1 == hit, read RCX+[0x58]/[0x68] via
//     process_vm_readv, append the keyfile line, restore the byte,
//     rewind RIP and continue.
//
// If PTRACE_ATTACH fails with EPERM the kernel Yama scope is likely
// blocking non-descendant tracing; the error says so loudly. A hardware
// breakpoint (DR0/DR7, no .text patching) is the fallback if Wine ever
// swallows int3 traps — not implemented until a live run proves it needed.

// Run attaches to the game, dumps up to MaxHits keys, then detaches.
func Run(cfg Config) error {
	if err := cfg.withDefaults(); err != nil {
		return err
	}
	pid := cfg.PID
	if pid == 0 {
		// WaitFor lets the helper start before the game: poll for the
		// process (Wine takes a while past process creation before the
		// EXE image is mapped — the scan retry below covers that).
		deadline := time.Now().Add(cfg.WaitFor)
		for {
			p, err := findExe(cfg.ExeName)
			if err == nil {
				pid = p
				break
			}
			fmt.Fprintf(os.Stderr, "keydump: find: %v (retrying)\n", err)
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Second)
		}
	}
	t := &tracer{pid: pid, cfg: cfg}
	fmt.Printf("keydump: attached to %d (%s), scanning image\n", pid, cfg.ExeName)
	// Ctrl+C must give the game back: the tracer stops every thread,
	// and a bare SIGINT would leave them (and our int3) in place.
	// The watcher detaches, restores the target byte and CONTs all
	// threads before exiting (Sep 27: game frozen with a silent tool).
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, unix.SIGTERM)
	go func() {
		<-sigc
		fmt.Fprintln(os.Stderr, "keydump: interrupted, releasing the game")
		t.abort()
		os.Exit(130)
	}()
	defer signal.Stop(sigc)
	return t.run()
}

// abort releases the game from a signal watcher: restores the breakpoint
// byte, detaches every thread and CONTs them (covers threads stopped
// outside ptrace, e.g. mid-attach). Best effort throughout; never blocks.
func (t *tracer) abort() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.plant {
		t.writeAtLocked(t.hitVA, []byte{t.orig})
		t.plant = false
	}
	for _, tid := range t.tids {
		unix.PtraceDetach(tid)       //nolint:errcheck // best effort
		unix.Kill(tid, unix.SIGCONT) //nolint:errcheck // unsticks plain stops
	}
	t.tids = nil
	if t.mem != nil {
		t.mem.Close() //nolint:errcheck // best effort
		t.mem = nil
	}
}

type memRegion struct {
	start, end uint64
}

type tracer struct {
	mu    sync.Mutex
	pid   int
	cfg   Config
	tids  []int
	mem   *os.File // /proc/pid/mem, O_RDWR
	hitVA uint64
	orig  byte
	plant bool
	hits  int
}

func procState(pid int) byte {
	// /proc/pid/stat: pid (comm) state ... — comm may contain spaces and
	// parens, so the state is the first field after the LAST ')'.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return '?'
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return '?'
	}
	return s[i+2]
}

// argvMatches reports whether argv[0] IS the exe (basename, both path
// separators, case-insensitive) as opposed to merely mentioning it.
func argvMatches(argv0, exe string) bool {
	if argv0 == "" {
		return false
	}
	base := argv0
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	return strings.EqualFold(base, exe)
}

func findExe(exe string) (int, error) {
	short := exe
	if len(short) > 15 {
		short = short[:15] // TASK_COMM_LEN cap, see above
	}
	wantPrefix := strings.TrimSuffix(exe, ".exe")
	var found []int
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		pid, _ := strconv.Atoi(filepath.Base(p))
		if pid == 0 {
			continue
		}
		if procState(pid) == 'Z' {
			continue // zombie (e.g. a dead WorldOfTanks.ex reaped by
			// nobody): unmatchable, unkillable, must be skipped or
			// -wait spins on "multiple processes" forever (Sep 27).
		}
		if b, err := os.ReadFile(filepath.Join(p, "comm")); err == nil {
			if c := strings.TrimSpace(string(b)); c == exe || c == short || strings.HasPrefix(c, wantPrefix) {
				found = append(found, pid)
				continue
			}
		}
		if b, err := os.ReadFile(filepath.Join(p, "cmdline")); err == nil {
			// argv[0] basename match only: a substring match catches
			// unrelated tools whose ARGUMENTS name the exe (Sep 27: our
			// own IDA MCP worker, `ida-nexus worker .../WorldOfTanks.exe.i64`,
			// poisoned the scan into a silent "multiple processes" retry).
			// Wine shows the Windows path (S:\...\WorldOfTanks.exe), so
			// split on both separators and compare case-insensitively.
			argv := strings.Split(string(b), "\x00")
			if len(argv) > 0 && argvMatches(argv[0], exe) {
				found = append(found, pid)
			}
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("keydump: no %s process (attach the game at the login screen first)", exe)
	case 1:
		return found[0], nil
	default:
		return 0, fmt.Errorf("keydump: %d %s processes %v, pass -pid", len(found), exe, found)
	}
}

// sandboxedTarget reports Steam-style sandboxing: NoNewPrivs plus a
// single-entry UID map (pressure-vessel/bwrap). parseSandboxed is split
// out for offline tests.
func sandboxedTarget(pid int) bool {
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	um, err := os.ReadFile(fmt.Sprintf("/proc/%d/uid_map", pid))
	if err != nil {
		return false
	}
	return parseSandboxed(st, um)
}

func parseSandboxed(status, uidmap []byte) bool {
	nnp := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") && strings.Contains(line, "1") {
			nnp = true
		}
	}
	// A plain host process also has a single-line map — the full range
	// (0 0 4294967295). Confinement is a single PARTIAL line
	// (pressure-vessel: "1000 1000 1").
	confined := false
	for _, line := range strings.Split(strings.TrimSpace(string(uidmap)), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[2] == "4294967295" {
			return false
		}
		confined = true
	}
	return nnp && confined
}

func listTasks(pid int) ([]int, error) {
	ents, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/[0-9]*", pid))
	if err != nil {
		return nil, err
	}
	var tids []int
	for _, e := range ents {
		tid, _ := strconv.Atoi(filepath.Base(e))
		tids = append(tids, tid)
	}
	if len(tids) == 0 {
		return nil, fmt.Errorf("keydump: no threads in %d", pid)
	}
	return tids, nil
}

// codeRegions returns r-x mappings belonging to the game EXE. Wine mmap's
// the PE file, so the host path usually shows; if no named mapping matches,
// every r-x region is scanned and the single-hit rule still guards.
func codeRegions(pid int, exe string) ([]memRegion, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("keydump: open maps: %w", err)
	}
	defer f.Close()
	var named, all []memRegion
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || len(fields[0]) < 3 {
			continue
		}
		perms := fields[1]
		if len(perms) < 3 || perms[0] != 'r' || perms[2] != 'x' {
			continue
		}
		span := strings.SplitN(fields[0], "-", 2)
		start, err1 := strconv.ParseUint(span[0], 16, 64)
		end, err2 := strconv.ParseUint(span[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		r := memRegion{start, end}
		all = append(all, r)
		if len(fields) >= 6 && strings.Contains(fields[5], exe) {
			named = append(named, r)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("keydump: read maps: %w", err)
	}
	if len(named) > 0 {
		return named, nil
	}
	return all, nil
}

func (t *tracer) attach() error {
	if sandboxedTarget(t.pid) {
		// Steam pressure-vessel runs the game NoNewPrivs in a
		// single-UID user namespace. ptrace there is a trap: ATTACH
		// stops every thread (SIGSTOP lands) but tracership never
		// sticks (TracerPid stays 0), so CONT/DETACH/GETREGS ESRCH on
		// all of them — as ANY uid including root (Sep 27: 74/74,
		// game frozen until manual CONT). Refuse BEFORE touching the
		// process. Keys on sandboxed targets need the in-process mod
		// (VEH breakpoint via ctypes, no ptrace), not this tool.
		return fmt.Errorf("keydump: target %d is sandboxed (userns+NoNewPrivs): ptrace cannot control it — use the in-process keydump mod instead", t.pid)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	tids, err := listTasks(t.pid)
	if err != nil {
		return err
	}
	for _, tid := range tids {
		if err := unix.PtraceAttach(tid); err != nil {
			if err == unix.ESRCH {
				continue // Wine thread churn: exited between list
				// and attach; dropping it beats failing the run
				// (Sep 27: exact-count Wait4 hung forever here,
				// game frozen, tool silent).
			}
			t.detachLocked()
			if err == unix.EPERM {
				return fmt.Errorf("keydump: ptrace EPERM (kernel.yama.ptrace_scope blocks non-descendant tracing: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope, or start the game from this shell): %w", err)
			}
			return fmt.Errorf("keydump: attach %d: %w", tid, err)
		}
		t.tids = append(t.tids, tid)
	}
	if len(t.tids) == 0 {
		return fmt.Errorf("keydump: no threads attached in %d", t.pid)
	}
	// Reap each thread's SIGSTOP with a deadline: blocking Wait4(-1)
	// hangs if any event goes elsewhere (exits, grandchildren), so
	// poll and require only the tids we actually attached.
	pending := map[int]bool{}
	for _, tid := range t.tids {
		pending[tid] = true
	}
	stopWait := time.Now().Add(10 * time.Second)
	for len(pending) > 0 {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(-1, &ws, unix.WALL|unix.WNOHANG, nil)
		if err != nil {
			t.detachLocked()
			return fmt.Errorf("keydump: wait stop: %w", err)
		}
		if wpid <= 0 {
			if time.Now().After(stopWait) {
				t.detachLocked()
				return fmt.Errorf("keydump: %d/%d threads never stopped", len(pending), len(t.tids))
			}
			t.mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			t.mu.Lock()
			continue
		}
		delete(pending, wpid)
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", t.pid), os.O_RDWR, 0)
	if err != nil {
		t.detachLocked()
		return fmt.Errorf("keydump: open mem: %w", err)
	}
	t.mem = f
	return nil
}

func (t *tracer) detach() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.detachLocked()
}

// detachLocked is the lock-held core (attach/abort already own mu;
// sync.Mutex is not reentrant).
func (t *tracer) detachLocked() {
	for _, tid := range t.tids {
		unix.PtraceDetach(tid) //nolint:errcheck // best effort; process may be gone
	}
	// CONT regardless: stops outlive a failed tracership (the sandbox
	// saga: SIGSTOPs landed, TracerPid stayed 0, only CONT resumed).
	// Harmless when already running.
	for _, tid := range t.tids {
		unix.Kill(tid, unix.SIGCONT) //nolint:errcheck // best effort
	}
	t.tids = nil
	if t.mem != nil {
		t.mem.Close() //nolint:errcheck // best effort
		t.mem = nil
	}
}

func (t *tracer) readAt(va uint64, n int) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mem == nil {
		return nil, fmt.Errorf("keydump: mem closed")
	}
	buf := make([]byte, n)
	// /proc/pid/mem pread works on attached processes and reads full
	// pages even where process_vm_readv would short-read.
	if _, err := t.mem.ReadAt(buf, int64(va)); err != nil {
		return nil, err
	}
	return buf, nil
}

func (t *tracer) writeAt(va uint64, b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.mem == nil {
		return fmt.Errorf("keydump: mem closed")
	}
	if _, err := t.mem.WriteAt(b, int64(va)); err != nil {
		return err
	}
	return nil
}

// writeAtLocked is abort's lock-held variant (abort already owns mu;
// WriteAt on /proc/pid/mem is synchronous, never blocks on the game).
func (t *tracer) writeAtLocked(va uint64, b []byte) {
	if t.mem != nil {
		t.mem.WriteAt(b, int64(va)) //nolint:errcheck // best effort
	}
}

// snapshotTids copies the attached thread list for loops that must not
// hold mu across blocking syscalls (abort can detach concurrently).
func (t *tracer) snapshotTids() []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]int(nil), t.tids...)
}

func (t *tracer) findHit() error {
	regions, err := codeRegions(t.pid, t.cfg.ExeName)
	if err != nil {
		return err
	}
	var hits []uint64
	var total uint64
	for _, r := range regions {
		size := r.end - r.start
		if size == 0 || size > 512<<20 {
			continue // guard pages / absurd mappings move under Wine
		}
		total += size
		buf, err := t.readAt(r.start, int(size))
		if err != nil {
			continue // unmapped guard pages move under Wine; skip
		}
		for _, off := range Scan(buf, t.cfg.Needle, t.cfg.Mask) {
			hits = append(hits, r.start+uint64(off))
		}
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("keydump: pattern not found in %d code regions (%.1f MB scanned; wrong game version? re-derive via IDA sub_140E6E210)", len(regions), float64(total)/1048576)
	case 1:
		t.hitVA = hits[0]
		fmt.Printf("keydump: pattern hit at %x, arming breakpoint\n", t.hitVA)
		return nil
	default:
		return fmt.Errorf("keydump: pattern hits %d addresses %x (refine the pattern, refusing to guess)", len(hits), hits)
	}
}

type vmReader struct{ t *tracer }

func (v vmReader) Read(addr uint64, n int) ([]byte, error) { return v.t.readAt(addr, n) }

func (t *tracer) run() error {
	deadline := time.Now().Add(t.cfg.WaitFor)
	for {
		if err := t.attach(); err != nil {
			fmt.Fprintf(os.Stderr, "keydump: attach: %v (retrying)\n", err)
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Second)
			continue
		}
		if err := t.findHit(); err != nil {
			fmt.Fprintf(os.Stderr, "keydump: scan: %v (retrying)\n", err)
			t.detach()
			if time.Now().After(deadline) {
				return err
			}
			time.Sleep(2 * time.Second) // image still loading under Wine
			continue
		}
		break
	}
	defer t.detach()
	orig, err := t.readAt(t.hitVA, 1)
	if err != nil {
		return fmt.Errorf("keydump: read target byte: %w", err)
	}
	t.orig = orig[0]
	if err := t.writeAt(t.hitVA, []byte{0xCC}); err != nil {
		return fmt.Errorf("keydump: plant breakpoint: %w", err)
	}
	t.plant = true
	defer func() {
		if t.plant {
			t.writeAt(t.hitVA, []byte{t.orig}) //nolint:errcheck // best effort
		}
	}()
	for _, tid := range t.snapshotTids() {
		if err := unix.PtraceCont(tid, 0); err != nil {
			if err == unix.ESRCH {
				fmt.Fprintf(os.Stderr, "keydump: cont %d exited mid-run, skipping\n", tid)
				continue
			}
			return fmt.Errorf("keydump: cont %d: %w", tid, err)
		}
	}
	hitDeadline := time.Now().Add(t.cfg.Timeout)
	for t.hits < t.cfg.MaxHits {
		if time.Now().After(hitDeadline) {
			return fmt.Errorf("keydump: timeout after %d hits (click Login in the game; breakpoint is at login-build time)", t.hits)
		}
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(-1, &ws, unix.WALL|unix.WNOHANG, nil)
		if err != nil {
			return fmt.Errorf("keydump: wait: %w", err)
		}
		if wpid <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if ws.Exited() || ws.Signaled() {
			return fmt.Errorf("keydump: thread %d gone (%v) after %d hits", wpid, ws, t.hits)
		}
		if !ws.Stopped() || ws.StopSignal() != unix.SIGTRAP {
			sig := 0
			if ws.Stopped() {
				sig = int(ws.StopSignal())
			}
			unix.PtraceCont(wpid, sig) //nolint:errcheck // forward foreign stops
			continue
		}
		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(wpid, &regs); err != nil {
			unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
			continue
		}
		if regs.Rip-1 != t.hitVA {
			// Not ours (Wine internal trap): forward.
			unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
			continue
		}
		key, ptr, strobj, err := ReadKey(vmReader{t}, regs.Rcx)
		if err == nil {
			if err = AppendKey(t.cfg.KeyFile, ptr, key, strobj); err == nil {
				fmt.Printf("keydump: hit #%d key len=%d sha1=%x -> %s\n", t.hits+1, len(key), sha1.Sum(key), t.cfg.KeyFile)
			}
		}
		// builder runs normally; the pause is milliseconds, like CE's
		// co_run resume, and never burns the 30 s pending window.
		_ = t.writeAt(t.hitVA, []byte{t.orig})
		regs.Rip--
		_ = unix.PtraceSetRegs(wpid, &regs)
		if err != nil {
			// Odd-length hit (stale heap): note via strobj-less line is
			// skipped — keep the game alive, keep listening.
			_ = t.writeAt(t.hitVA, []byte{0xCC})
			unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
			continue
		}
		t.hits++
		if t.hits >= t.cfg.MaxHits {
			unix.PtraceCont(wpid, 0) //nolint:errcheck // let the login finish
			return nil
		}
		_ = t.writeAt(t.hitVA, []byte{0xCC})
		unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
	}
	return nil
}
