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
	flag.Parse()

	api, err := wgcs.Load(*dll)
	if err != nil {
		fatal(err)
	}
	if err := api.CreateGlobalInstance(); err != nil {
		fatal(fmt.Errorf("create-instance: %w", err))
	}
	defer api.Free()
	for _, arg := range []uintptr{0, 1} {
		if err := api.Prepare(arg); err == nil {
			fmt.Fprintf(os.Stderr, "[wotwgcs] prepare(%d) ok\n", arg)
			break
		} else if arg == 1 {
			fmt.Fprintf(os.Stderr, "[wotwgcs] prepare failed: %v\n", err)
		}
	}
	buf := make([]byte, wgcs.LoginInfoSize)
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
