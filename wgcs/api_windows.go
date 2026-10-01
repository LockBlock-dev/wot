//go:build windows

package wgcs

import (
	"fmt"
	"syscall"
	"unsafe"
)

// API wraps the flat binding_* exports of wgcs_api.dll (Steam
// variant, same surface as wgc_api.dll). All calls are Win64
// (RCX,RDX,R8,R9); HRESULT in EAX (negative = failure).
type API struct {
	dll   *syscall.LazyDLL
	procs map[string]*syscall.LazyProc
}

// Names of the exports used (ordinals from objdump -p; slot order
// from the binding_* trampolines): CreateGlobalInstance, Prepare,
// GetLoginInfo(accessor slot3+18 method0, 1 param),
// GetRememberMeToken(18,28 — 2 params), FreeGlobalInstance(slot0).
var procNames = []string{
	"binding_WGCApiCreateGlobalInstance",
	"binding_WGCApiPrepare",
	"binding_WGCApiGetLoginInfo",
	"binding_WGCApiGetRememberMeToken",
	"binding_WGCApiStoreRememberMeToken",
	"binding_WGCApiIsLaunchedFromWgc",
	"binding_WGCApiGetPublication",
	"binding_WGCApiFreeGlobalInstance",
}

// Load maps the DLL (absolute prefix path) and resolves the procs.
func Load(dllPath string) (*API, error) {
	dll := syscall.NewLazyDLL(dllPath)
	a := &API{dll: dll, procs: map[string]*syscall.LazyProc{}}
	for _, n := range procNames {
		p := dll.NewProc(n)
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("wgcs: %s: %w", n, err)
		}
		a.procs[n] = p
	}
	return a, nil
}

func hr(r1 uintptr) error {
	if int32(r1) < 0 {
		return fmt.Errorf("wgcs: HRESULT 0x%08x", uint32(r1))
	}
	return nil
}

// CreateGlobalInstance calls binding_WGCApiCreateGlobalInstance(iid).
func (a *API) CreateGlobalInstance() error {
	r1, _, _ := a.procs["binding_WGCApiCreateGlobalInstance"].Call(uintptr(InstanceIID))
	return hr(r1)
}

// Prepare calls binding_WGCApiPrepare(arg) — game passes 1 arg;
// probed live, starting with 0.
func (a *API) Prepare(arg uintptr) error {
	r1, _, _ := a.procs["binding_WGCApiPrepare"].Call(arg)
	return hr(r1)
}

// Raw calls any resolved export with raw args (live layout probing;
// returns the raw register, never interprets buffers).
func (a *API) Raw(name string, args ...uintptr) (uintptr, error) {
	p, ok := a.procs[name]
	if !ok {
		return 0, fmt.Errorf("wgcs: unknown proc %s", name)
	}
	r1, _, _ := p.Call(args...)
	return r1, nil
}

// GetLoginInfo calls binding_WGCApiGetLoginInfo(out) with a caller
// buffer sized LoginInfoSize (layout in wgcs.go); returns the
// HRESULT. Buffers are never logged (may hold token2).
func (a *API) GetLoginInfo(out []byte) error {
	var p uintptr
	if len(out) > 0 {
		p = uintptr(unsafe.Pointer(&out[0]))
	}
	r1, _, _ := a.procs["binding_WGCApiGetLoginInfo"].Call(p)
	return hr(r1)
}

// Free calls binding_WGCApiFreeGlobalInstance() (vtable slot0).
func (a *API) Free() error {
	r1, _, _ := a.procs["binding_WGCApiFreeGlobalInstance"].Call()
	return hr(r1)
}
