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
// WGCApiCreateInstanceEx is the raw constructor behind the global
// (binding create calls Ex(iid, &ver, &ppv), then stores the global):
// calling Ex directly yields an instance pointer for manual vtable
// calls — the only route to WGCApi slot12 (+0x60), the game's second
// prepare step, which no flat binding wraps.
var procNames = []string{
	"binding_WGCApiCreateGlobalInstance",
	"binding_WGCApiPrepare",
	"binding_WGCApiGetLoginInfo",
	"binding_WGCApiGetRememberMeToken",
	"binding_WGCApiStoreRememberMeToken",
	"binding_WGCApiGenerateAuthToken",
	"binding_WGCApiIsLaunchedFromWgc",
	"binding_WGCApiGetPublication",
	"binding_WGCApiFreeGlobalInstance",
	"WGCApiCreateInstanceEx",
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

// CreateInstanceEx calls WGCApiCreateInstanceEx(iid, ver, ppv)
// directly (same args the global binding passes: ver/u32 + ppv slots
// zeroed) and returns the instance pointer for manual vtable calls.
// HRESULT in EAX like all Win64 calls here.
func (a *API) CreateInstanceEx() (uintptr, error) {
	p, ok := a.procs["WGCApiCreateInstanceEx"]
	if !ok {
		return 0, fmt.Errorf("wgcs: unknown proc WGCApiCreateInstanceEx")
	}
	var ver uint32
	var ppv uintptr
	r1, _, _ := p.Call(uintptr(InstanceIID),
		uintptr(unsafe.Pointer(&ver)), uintptr(unsafe.Pointer(&ppv)))
	if err := hr(r1); err != nil {
		return 0, err
	}
	if ppv == 0 {
		return 0, fmt.Errorf("wgcs: CreateInstanceEx null instance")
	}
	return ppv, nil
}

// slotAddr reads WGCApi vtable slot n from a live instance pointer
// (vftable `??_7WGCApi@WGC@@6B@`: slot1 prepare +8, slot12 +0x60,
// slot3 session +0x18 — game sub_1424BE7D0 + dll trampolines).
// NOTE: the uintptr→pointer reads below trip GOOS=windows vet's
// unsafeptr heuristic (true positive accepted: in-process vtable
// walk, the only route to slots without flat bindings; native
// `go vet ./...` stays clean, windows cross-vet flags these two
// lines by design).
func slotAddr(ppv uintptr, slot int) (uintptr, error) {
	if ppv == 0 {
		return 0, fmt.Errorf("wgcs: null instance")
	}
	vt := *(*uintptr)(unsafe.Pointer(ppv))
	if vt == 0 {
		return 0, fmt.Errorf("wgcs: null vtable")
	}
	fn := *(*uintptr)(unsafe.Pointer(vt + uintptr(slot*8)))
	if fn == 0 {
		return 0, fmt.Errorf("wgcs: null slot %d", slot)
	}
	return fn, nil
}

// CallSlot invokes WGCApi vtable slot n as (this, arg) — the shape of
// slot1/slot12 prepare and slot3 session. Returns the raw HRESULT
// register (negative = failure); buffers are never logged.
func (a *API) CallSlot(ppv uintptr, slot int, arg uintptr) (uintptr, error) {
	fn, err := slotAddr(ppv, slot)
	if err != nil {
		return 0, err
	}
	r1, _, _ := syscall.Syscall(fn, 2, ppv, arg, 0)
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
