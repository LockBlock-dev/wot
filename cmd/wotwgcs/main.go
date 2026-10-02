// Command wotwgcs mints a broker token2 via wgcs_api.dll WITHOUT
// touching LoginApp (GOOS=windows helper, run inside the Proton
// prefix while Steam SSO is valid). Writes the token2 to a 0600
// keyfile for wotlogin TOKEN2 use; stdout carries HRESULTs and
// lengths/hashes only, never the value.
package main

import (
	"flag"
	"fmt"
	"os"
	"unsafe"

	"github.com/LockBlock-dev/wot/wgcs"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wotwgcs:", err)
	os.Exit(1)
}

// ptr passes a buffer address to the broker (in-process memory;
// buffers are scrubbed after use, never logged).
func ptr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func main() {
	dll := flag.String("dll", `S:\steamapps\common\World of Tanks\eu\win64\wgcs_api.dll`, "wgcs_api.dll path (prefix-relative S: path under proton)")
	out := flag.String("out", "", "keyfile for the minted token2 (0600, required unless -probe-only)")
	probeOnly := flag.Bool("probe-only", false, "HRESULT scan only (no token write)")
	step := flag.String("step", "all", "crash-bisect: load | create | prepare | logininfo | manual (private instance, game-faithful slot1+slot12+slot3+slot0) | all")
	flag.Parse()

	mark := func(s string) {
		fmt.Fprintf(os.Stderr, "[wotwgcs] step %s\n", s)
		os.Stderr.Sync()
	}
	_ = mark

	api, err := wgcs.Load(*dll)
	if err != nil {
		fatal(err)
	}
	mark("loaded")
	if *step == "load" {
		return
	}
	if err := api.CreateGlobalInstance(); err != nil {
		fatal(fmt.Errorf("create-instance: %w", err))
	}
	defer api.Free()
	mark("created")
	if *step == "create" {
		return
	}
	// Game-faithful Prepare (WGCControllerImpl::prepare,
	// sub_1424BE7D0): the instance's slot1 takes a 16B struct
	// {u64 0, u32 1}, NOT an integer — small ints fault the callee
	// (0 and 1 both crashed live: NULL-ish deref). The flat binding
	// takes the same single pointer arg.
	prep := make([]byte, 16)
	prep[8] = 1
	var prepPtr uintptr
	if len(prep) > 0 {
		prepPtr = ptr(prep)
	}
	if err := api.Prepare(prepPtr); err != nil {
		fmt.Fprintf(os.Stderr, "[wotwgcs] prepare(struct{0,1}) failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[wotwgcs] prepare(struct{0,1}) ok\n")
	}
	clear(prep)
	if *step == "manual" {
		runManual(api, mark)
		return
	}
	if *step == "remember" {
		runRemember(api, mark)
		return
	}
	buf := make([]byte, wgcs.LoginInfoSize)
	mark("prepare-done")
	if *step == "prepare" {
		return
	}
	err = api.GetLoginInfo(buf)
	fmt.Fprintf(os.Stderr, "[wotwgcs] GetLoginInfo hr=%v buf=%dB\n", err, len(buf))
	tok, ok := wgcs.FindToken2(buf)
	if err == nil && !ok {
		// Remember-me path (2 params: struct + WCHAR[1024] buffer).
		st := make([]byte, wgcs.RememberMeStruct)
		wb := make([]byte, wgcs.RememberMeBuf)
		r1, rerr := api.Raw("binding_WGCApiGetRememberMeToken", ptr(st), ptr(wb))
		fmt.Fprintf(os.Stderr, "[wotwgcs] GetRememberMeToken r1=%#x err=%v\n", r1, rerr)
		if tok2, ok2 := wgcs.FindToken2(st); ok2 {
			tok, ok = tok2, true
		} else if tok2, ok2 := wgcs.FindToken2(wb); ok2 {
			tok, ok = tok2, true
		}
		clear(st)
		clear(wb)
	}
	if err != nil && !ok {
		fatal(fmt.Errorf("no token2: %w", err))
	}
	for i := range buf {
		buf[i] = 0 // scrub the scratch (may hold token2)
	}
	if !ok {
		fatal(fmt.Errorf("no token2-shaped run in %dB (broker store empty or layout differs)", wgcs.LoginInfoProbe))
	}
	fmt.Fprintf(os.Stderr, "[wotwgcs] token2 len=%d id=%s\n", len(tok), wgcs.TokenID(tok))
	if *probeOnly {
		return
	}
	if *out == "" {
		fatal(fmt.Errorf("need -out keyfile (or -probe-only)"))
	}
	if err := wgcs.StoreToken2(*out, tok); err != nil {
		fatal(err)
	}
	fmt.Printf("token2: len=%d id=%s -> %s\n", len(tok), wgcs.TokenID(tok), *out)
}

// runRemember probes the broker-info surface that may not need a
// session: IsLaunchedFromWgc / GetPublication on the global, then
// GetRememberMeToken(struct, WCHAR[1024] buf) + shape-scan of both.
// HRESULTs/lengths only, buffers scrubbed.
func runRemember(api *wgcs.API, mark func(string)) {
	for _, name := range []string{"binding_WGCApiIsLaunchedFromWgc", "binding_WGCApiGetPublication"} {
		ob := make([]byte, 8)
		r1, rerr := api.Raw(name, ptr(ob))
		fmt.Fprintf(os.Stderr, "[wotwgcs] %s r1=%#x out-dword=%x err=%v\n", name, r1, ob[:4], rerr)
		clear(ob)
	}
	st := make([]byte, wgcs.RememberMeStruct)
	wb := make([]byte, wgcs.RememberMeBuf)
	r1, rerr := api.Raw("binding_WGCApiGetRememberMeToken", ptr(st), ptr(wb))
	fmt.Fprintf(os.Stderr, "[wotwgcs] GetRememberMeToken r1=%#x err=%v\n", r1, rerr)
	if rerr == nil {
		if tok, ok := wgcs.FindToken2(st); ok {
			fmt.Fprintf(os.Stderr, "[wotwgcs] remember struct token2 len=%d id=%s\n", len(tok), wgcs.TokenID(tok))
		}
		if tok, ok := wgcs.FindToken2(wb); ok {
			fmt.Fprintf(os.Stderr, "[wotwgcs] remember buf token2 len=%d id=%s\n", len(tok), wgcs.TokenID(tok))
		}
	}
	clear(st)
	clear(wb)
	mark("remember-done")
}

// runManual drives a private instance end-to-end like the game
// (sub_1424BE7D0): Ex-construct, slot1(struct{0,1}), slot12(zeroed
// struct — the worker only stamps [0]=2), slot3 session, slot0 login
// info. The flat bindings expose no slot12, so the global path stalls
// at 0x80EE1003 (session missing). HRESULTs/lengths only.
func runManual(api *wgcs.API, mark func(string)) {
	ppv, err := api.CreateInstanceEx()
	if err != nil {
		fatal(fmt.Errorf("ex-construct: %w", err))
	}
	mark("manual-ex")
	s1 := make([]byte, 16)
	s1[8] = 1
	r1, err := api.CallSlot(ppv, 1, ptr(s1))
	clear(s1)
	fmt.Fprintf(os.Stderr, "[wotwgcs] manual slot1 r1=%#x err=%v\n", r1, err)
	if err != nil {
		fatal(fmt.Errorf("manual slot1: %w", err))
	}
	if herr := wgcs.HR(r1); herr != nil {
		fatal(fmt.Errorf("manual slot1: %w", herr))
	}
	mark("manual-slot1")
	s2 := make([]byte, 16)
	r1, err = api.CallSlot(ppv, 12, ptr(s2))
	fmt.Fprintf(os.Stderr, "[wotwgcs] manual slot12 r1=%#x s2head=%x err=%v\n", r1, s2[:8], err)
	clear(s2)
	if err != nil {
		fatal(fmt.Errorf("manual slot12: %w", err))
	}
	if herr := wgcs.HR(r1); herr != nil {
		fatal(fmt.Errorf("manual slot12: %w", herr))
	}
	mark("manual-slot12")
	var sessBuf [8]byte
	sessPtr := ptr(sessBuf[:])
	r1, err = api.CallSlot(ppv, 3, sessPtr)
	var sess uintptr
	for i := 0; i < 8; i++ {
		sess |= uintptr(sessBuf[i]) << (8 * i)
	}
	fmt.Fprintf(os.Stderr, "[wotwgcs] manual slot3 r1=%#x sess-present=%v err=%v\n", r1, sess != 0, err)
	if err != nil {
		fatal(fmt.Errorf("manual slot3: %w", err))
	}
	if herr := wgcs.HR(r1); herr != nil {
		fatal(fmt.Errorf("manual slot3: %w", herr))
	}
	if sess == 0 {
		fatal(fmt.Errorf("manual slot3: null session"))
	}
	mark("manual-slot3")
	buf := make([]byte, wgcs.LoginInfoSize)
	r1, err = api.CallSlot(sess, 0, ptr(buf))
	fmt.Fprintf(os.Stderr, "[wotwgcs] manual session-slot0 r1=%#x err=%v\n", r1, err)
	if err != nil {
		fatal(fmt.Errorf("manual session slot0: %w", err))
	}
	if herr := wgcs.HR(r1); herr != nil {
		for i := range buf {
			buf[i] = 0
		}
		fatal(fmt.Errorf("manual session slot0: %w", herr))
	}
	mark("manual-slot0")
	tok, ok := wgcs.FindToken2(buf)
	for i := range buf {
		buf[i] = 0
	}
	if !ok {
		fatal(fmt.Errorf("manual: no token2-shaped run in %dB", wgcs.LoginInfoSize))
	}
	fmt.Fprintf(os.Stderr, "[wotwgcs] manual token2 len=%d id=%s\n", len(tok), wgcs.TokenID(tok))
}
