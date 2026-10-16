//go:build linux

package keydump

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Walk attaches to the game, arms the digest entry-filter breakpoint and
// records every walked entry (name + pass/fail) until the walk ends
// (MaxEntries hits or QuietAfter of silence once started) or Timeout.
// It returns whatever was captured even on timeout/threads-gone (partial
// prefix is still diagnostic); callers must still treat error returns as
// incomplete.
//
// Reliability contract (no game crash): the int3 byte is restored on
// every exit path (normal, timeout, SIGINT/SIGTERM, error); every
// attached thread is detached and CONTed (detachLocked CONTs even
// threads whose tracership never stuck); foreign traps/signals are
// forwarded; new threads are followed via PTRACE_O_TRACECLONE because
// an untraced thread hitting our int3 would die on SIGTRAP. Refuses
// sandboxed targets and multi-match PIDs before touching anything.
func Walk(cfg WalkConfig) ([]WalkEntry, error) {
	if err := cfg.withWalkDefaults(); err != nil {
		return nil, err
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
			fmt.Fprintf(os.Stderr, "walkdump: find: %v (retrying)\n", err)
			if cfg.WaitFor <= 0 || time.Now().After(deadline) {
				return nil, err
			}
			// Fast poll: the digest walk fires seconds after spawn and
			// a 2s period can lose the race outright.
			time.Sleep(200 * time.Millisecond)
		}
	}
	kc := Config{
		PID: pid, ExeName: cfg.ExeName,
		Needle: cfg.Needle, Mask: cfg.Mask,
		Timeout: cfg.Timeout, WaitFor: cfg.WaitFor,
		Force: cfg.Force,
	}
	t := &tracer{pid: pid, cfg: kc}
	fmt.Printf("walkdump: found %d (%s), attaching\n", pid, cfg.ExeName)
	if cfg.Force {
		fmt.Fprintln(os.Stderr, "walkdump: -force: attempting ptrace on a sandboxed target anyway")
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, unix.SIGTERM)
	go func() {
		<-sigc
		fmt.Fprintln(os.Stderr, "walkdump: interrupted, releasing the game")
		t.abort()
		os.Exit(130)
	}()
	defer signal.Stop(sigc)
	return t.walkRun(&cfg)
}

func (t *tracer) addTid(tid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.tids {
		if e == tid {
			return
		}
	}
	t.tids = append(t.tids, tid)
}

func (t *tracer) removeTid(tid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, e := range t.tids {
		if e == tid {
			t.tids = append(t.tids[:i], t.tids[i+1:]...)
			return
		}
	}
}

// followOptions makes the tracer follow everything a Wine spawn can do:
// threads (CLONE), processes (FORK/VFORK) and image replacement (EXEC).
// ESRCH (exited mid-call) only prunes; anything else is reported.
const followOptions = unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEFORK |
	unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACEEXEC

// setFollow applies followOptions to every attached thread, dropping
// dead ones. Returns the survivor count.
func (t *tracer) setFollow() int {
	kept := 0
	for _, tid := range t.snapshotTids() {
		if err := unix.PtraceSetOptions(tid, followOptions); err != nil {
			if err == unix.ESRCH {
				t.removeTid(tid)
				continue
			}
			fmt.Fprintf(os.Stderr, "walkdump: setoptions %d: %v\n", tid, err)
			continue
		}
		kept++
	}
	return kept
}

// refreshTids re-syncs the thread list with the kernel (post-exec the
// old list is garbage): drops everything gone, attaches nothing new
// (clone/fork events already added them), re-arms follow options.
func (t *tracer) refreshTids() {
	t.mu.Lock()
	t.tids = nil
	t.mu.Unlock()
	if tids, err := listTasks(t.pid); err == nil {
		for _, tid := range tids {
			// Post-exec threads of a traced process stay traced; only
			// re-arm options (best effort, pruned inside setFollow).
			t.addTid(tid)
		}
	}
	t.setFollow()
}

// followOne arms followOptions on one thread (newborns from fork/vfork/
// clone events); ESRCH (already gone) is silently fine.
func (t *tracer) followOne(tid int) {
	opts := followOptions
	if t.plant {
		// Post-arm only thread births matter (a newborn hitting the
		// int3 untraced would die on SIGTRAP); fork/vfork/exec events
		// only cost stops, and exec remaps are caught by the heartbeat
		// verifier + re-arm instead.
		opts = unix.PTRACE_O_TRACECLONE
	}
	if err := unix.PtraceSetOptions(tid, opts); err != nil {
		if err == unix.ESRCH {
			t.removeTid(tid)
		}
		return
	}
}

// rearm (re)plants the breakpoint, re-scanning first: after an exec
// (or any Wine remap) hitVA may point at fresh pages holding the
// original byte. Returns false when the image isn't mapped (yet).
func (t *tracer) rearm() bool {
	if err := t.findHitQuiet(); err != nil {
		return false
	}
	orig, err := t.readAt(t.hitVA, 1)
	if err != nil {
		return false
	}
	t.orig = orig[0]
	if err := t.writeAt(t.hitVA, []byte{0xCC}); err != nil {
		return false
	}
	t.plant = true
	return true
}

// non-hit case: fork/vfork/clone following, exec refresh, exits,
// foreign traps/signals. Returns (handled-something, fatal-error).
// Hits are NOT handled here (caller owns the breakpoint); when armed,
// a SIGTRAP with cause 0 is reported via hitTid.
func (t *tracer) pump(armed bool) (hitTid int, pumped bool, fatal error) {
	var ws unix.WaitStatus
	wpid, err := unix.Wait4(-1, &ws, unix.WALL|unix.WNOHANG, nil)
	if err != nil {
		return 0, false, fmt.Errorf("walkdump: wait: %w", err)
	}
	if wpid <= 0 {
		return 0, false, nil
	}
	if ws.Exited() || ws.Signaled() {
		t.removeTid(wpid)
		return 0, true, nil
	}
	if !ws.Stopped() {
		return 0, true, nil
	}
	sig := ws.StopSignal()
	if sig == unix.SIGTRAP {
		switch ws.TrapCause() {
		case unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK, unix.PTRACE_EVENT_CLONE:
			if msg, merr := unix.PtraceGetEventMsg(wpid); merr == nil {
				t.addTid(int(msg))
				t.followOne(int(msg))
				unix.PtraceCont(int(msg), 0) //nolint:errcheck // newborn, stopped
			}
			unix.PtraceCont(wpid, 0) //nolint:errcheck // reporter resumes
			return 0, true, nil
		case unix.PTRACE_EVENT_EXEC:
			t.refreshTids()
			if t.plant {
				// Exec re-mapped the image: the old int3 is gone with
				// the old pages. Re-scan + re-plant at the new base.
				t.plant = false
				if t.rearm() {
					fmt.Fprintf(os.Stderr, "walkdump: re-armed at %x after exec\n", t.hitVA)
				} else {
					fmt.Fprintf(os.Stderr, "walkdump: re-arm after exec failed\n")
				}
			}
			unix.PtraceCont(wpid, 0) //nolint:errcheck
			return 0, true, nil
		}
		if armed {
			return wpid, true, nil
		}
		unix.PtraceCont(wpid, 0) //nolint:errcheck // pre-arm trap: Wine internal
		return 0, true, nil
	}
	// Never re-inject job-control stops (see below): CONT(SIGSTOP)
	// parks the thread again and piles stuck threads until frozen.
	if sig == unix.SIGSTOP || sig == unix.SIGTSTP || sig == unix.SIGTTIN || sig == unix.SIGTTOU {
		unix.PtraceCont(wpid, 0) //nolint:errcheck
	} else {
		unix.PtraceCont(wpid, int(sig)) //nolint:errcheck // forward foreign stops
	}
	return 0, true, nil
}

// pathname (any permissions): the game image check that gates arming
// under PROTON_WAIT_ATTACH (pre-exec there is nothing mapped yet).
func exeMapped(pid int, exe string) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		// Pathname is fields[5:] joined: game paths contain spaces
		// ("World of Tanks") and a naive fields[5] never matches.
		if strings.Contains(strings.Join(fields[5:], " "), exe) {
			return true
		}
	}
	return false
}

func (t *tracer) walkRun(cfg *WalkConfig) ([]WalkEntry, error) {
	t0 := time.Now()
	if err := t.attach(); err != nil {
		// Spawn-race: the found PID may be a transient preloader whose
		// threads are already gone (ESRCH) — re-find until Timeout.
		start := time.Now()
		for {
			if time.Now().After(start.Add(cfg.Timeout)) {
				return nil, err
			}
			time.Sleep(1 * time.Second)
			pid, ferr := findExe(t.cfg.ExeName)
			if ferr != nil {
				continue
			}
			t.pid = pid
			t.mu.Lock()
			t.tids = nil
			if t.mem != nil {
				t.mem.Close() //nolint:errcheck
				t.mem = nil
			}
			t.mu.Unlock()
			if err = t.attach(); err == nil {
				break
			}
		}
	}
	t.setFollow()
	// WAIT_IMAGE: Wine spawn is a fork/exec dance (preloader dies,
	// image appears later). Pump all events (following children,
	// refreshing on exec) until the game image is mapped; never detach
	// mid-flight. A steady-state attach (image already mapped) skips
	// the wait instantly.
	imageWait := time.Now().Add(3 * time.Minute)
	for !exeMapped(t.pid, t.cfg.ExeName) {
		if time.Now().After(imageWait) {
			t.detach()
			return nil, fmt.Errorf("walkdump: game image never mapped (is PROTON_WAIT_ATTACH holding it pre-exec?)")
		}
		if _, pumped, perr := t.pump(false); perr != nil {
			t.detach()
			return nil, perr
		} else if !pumped {
			if len(t.snapshotTids()) == 0 {
				// Preloader parent exited: follow by name to the child.
				if pid, ferr := findExe(t.cfg.ExeName); ferr == nil && pid != t.pid {
					t.pid = pid
					t.mu.Lock()
					t.tids = nil
					t.mu.Unlock()
					if aerr := t.attach(); aerr == nil {
						t.setFollow()
					}
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.setFollow()
	if err := t.findHit(); err != nil {
		t.detach()
		return nil, err
	}
	fmt.Printf("walkdump: filter at %x, arming (click Login in the game)\n", t.hitVA)
	orig, err := t.readAt(t.hitVA, 1)
	if err != nil {
		t.detach()
		return nil, fmt.Errorf("walkdump: read target byte: %w", err)
	}
	t.orig = orig[0]
	// No single-step resume: the filter prologue is `48 83 EC 28`
	// (sub rsp,0x28 — verified against the 2.4.1.0 image at pattern
	// time), so each hit is resumed by emulating those 4 bytes in
	// registers (RSP-=0x28, RIP=hitVA+4) with the int3 left planted.
	// A single-step resume round-trip under Wine costs ~1s/hit
	// (385 hits = a frozen-feeling load); emulation is ~100µs. Refuse anything else.
	pro, err := t.readAt(t.hitVA, 4)
	if err != nil || len(pro) != 4 || pro[0] != 0x48 || pro[1] != 0x83 || pro[2] != 0xEC || pro[3] != 0x28 {
		t.detach()
		return nil, fmt.Errorf("walkdump: filter prologue is not sub rsp,28h, refusing to emulate")
	}
	if err := t.writeAt(t.hitVA, []byte{0xCC}); err != nil {
		t.detach()
		return nil, fmt.Errorf("walkdump: plant breakpoint: %w", err)
	}
	t.plant = true
	// Downgrade existing threads to clone-only (see followOne): post-arm
	// fork/exec events only cost stops.
	for _, tid := range t.snapshotTids() {
		unix.PtraceSetOptions(tid, unix.PTRACE_O_TRACECLONE) //nolint:errcheck // best effort
	}
	// From here every return must restore + detach: single cleanup func.
	done := false
	cleanup := func() {
		if done {
			return
		}
		done = true
		if t.plant {
			t.writeAt(t.hitVA, []byte{t.orig}) //nolint:errcheck // best effort
			t.plant = false
		}
		t.detach()
	}
	defer cleanup()
	ncont := 0
	for _, tid := range t.snapshotTids() {
		if err := unix.PtraceCont(tid, 0); err != nil && err != unix.ESRCH {
			return nil, fmt.Errorf("walkdump: cont %d: %w", tid, err)
		}
		if err != nil {
			t.removeTid(tid)
			continue
		}
		ncont++
	}
	fmt.Printf("walkdump: released %d threads (attach+scan took %v)\n", ncont, time.Since(t0))
	var out []WalkEntry
	lastHit := time.Time{}
	lastBeat := time.Now()
	deadline := time.Now().Add(cfg.Timeout)
	vmr := vmReader{t}
	for {
		if time.Now().After(deadline) {
			return out, fmt.Errorf("walkdump: timeout after %d entries", len(out))
		}
		if len(out) > 0 && !lastHit.IsZero() && time.Since(lastHit) > cfg.QuietAfter {
			fmt.Printf("walkdump: walk ended (%d entries)\n", len(out))
			return out, nil
		}
		if len(t.snapshotTids()) == 0 {
			return out, fmt.Errorf("walkdump: no threads left after %d entries", len(out))
		}
		hitTid, pumped, fatal := t.pump(true)
		if fatal != nil {
			return out, fatal
		}
		if hitTid <= 0 {
			if !pumped {
				time.Sleep(5 * time.Millisecond)
			}
			if time.Since(lastBeat) > 15*time.Second {
				lastBeat = time.Now()
				// Sweep: CONT everything unconditionally. Any missed
				// resume (a CONT lost to exec-transition churn leaves a
				// thread parked forever — the freeze class) heals here;
				// CONT on a running tracee is a harmless ESRCH no-op.
				for _, tid := range t.snapshotTids() {
					unix.PtraceCont(tid, 0) //nolint:errcheck // best effort sweep
				}
				// Verify the plant survived (Wine remaps silently kill
				// it without an exec event we necessarily see).
				if t.plant {
					if cur, err := t.readAt(t.hitVA, 1); err != nil || cur[0] != 0xCC {
						t.plant = false
						if t.rearm() {
							fmt.Printf("walkdump: re-armed at %x\n", t.hitVA)
						}
					}
				}
				fmt.Printf("walkdump: waiting (hits=%d traced=%d)\n", len(out), len(t.snapshotTids()))
			}
			continue
		}
		wpid := hitTid
		var regs unix.PtraceRegs
		if err := unix.PtraceGetRegs(wpid, &regs); err != nil {
			unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
			continue
		}
		if regs.Rip-1 != t.hitVA {
			unix.PtraceCont(wpid, 0) //nolint:errcheck // Wine internal trap
			continue
		}
		// Ours: RDX is the entry descriptor (filter __fastcall ABI).
		entry := WalkEntry{Index: len(out), Pass: true}
		if pb, err := t.readAt(regs.Rdx+WalkPassOff, 1); err == nil {
			entry.Pass = pb[0] != 0
		} else {
			fmt.Fprintf(os.Stderr, "walkdump: entry #%d: pass read: %v\n", len(out), err)
		}
		if nm, err := readStdString(vmr, regs.Rdx+WalkNameOff); err == nil {
			entry.Name = nm
		} else {
			fmt.Fprintf(os.Stderr, "walkdump: entry #%d: name read: %v\n", len(out), err)
			entry.Name = "?"
		}
		// Resume by emulating the 4-byte prologue (sub rsp,0x28) the
		// int3 replaced: RSP-=0x28, RIP past it. The breakpoint stays
		// planted (every later call traps again, as wanted); no
		// restore/step/replant window for a sibling thread to slip
		// through unrecorded, and no single-step latency.
		regs.Rsp -= 0x28
		regs.Rip = t.hitVA + 4
		_ = unix.PtraceSetRegs(wpid, &regs)
		out = append(out, entry)
		lastHit = time.Now()
		fmt.Printf("walkdump: #%d pass=%v %s\n", entry.Index, entry.Pass, entry.Name)
		if len(out) >= cfg.MaxEntries {
			fmt.Printf("walkdump: max entries (%d)\n", len(out))
			unix.PtraceCont(wpid, 0) //nolint:errcheck // let loading finish
			return out, nil
		}
		unix.PtraceCont(wpid, 0) //nolint:errcheck // best effort
	}
}
