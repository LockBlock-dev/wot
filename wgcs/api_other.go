//go:build !windows

package wgcs

import "fmt"

// API is a stub outside Windows (probing runs via proton).
type API struct{}

// Load always fails outside Windows; cross-compile the helper with
// GOOS=windows and run it inside the prefix via proton.
func Load(dllPath string) (*API, error) {
	return nil, fmt.Errorf("%w (dll %s)", ErrNeedWindows, dllPath)
}

func (a *API) CreateGlobalInstance() error { return ErrNeedWindows }
func (a *API) Prepare(arg uintptr) error   { return ErrNeedWindows }
func (a *API) CreateInstanceEx() (uintptr, error) {
	return 0, ErrNeedWindows
}
func (a *API) CallSlot(ppv uintptr, slot int, arg uintptr) (uintptr, error) {
	return 0, ErrNeedWindows
}
func (a *API) Raw(name string, args ...uintptr) (uintptr, error) {
	return 0, ErrNeedWindows
}
func (a *API) GetLoginInfo(out []byte) error { return ErrNeedWindows }
func (a *API) Free() error                   { return ErrNeedWindows }
