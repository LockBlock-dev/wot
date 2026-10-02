// Package wgcs talks to the WGC-for-Steam broker (wgcs_api.dll) to
// obtain a broker-minted token2 WITHOUT touching LoginApp ourselves.
//
// Wire why: the Steam game logs in with auth_method=token2 via
// WGC.loginData(), which the in-process WGC module builds from the
// broker (wgc.exe, GameCenter for Steam in the Proton prefix) over the
// WgIpcPipe IPC (LoadSpaToken2 at login, SaveSpaToken2 after
// LOGGED_ON — see the wgc_* broker logs). The DLL exposes flat
// binding_* exports (no vtable needed); interface slots and the
// instance IID below come from static RE of wgcs_api.dll
// (PE32+, ImageBase 0x180000000): WGCApiCreateInstance validates
// RCX == 0x1600020001247C (else 0x80EE0001) and writes *ppv.
package wgcs

import (
	"errors"
	"fmt"
)

// InstanceIID is the interface id the game passes as RCX to
// WGCApiCreateInstance / binding_WGCApiCreateGlobalInstance
// (game VA 0x1424BE281: movabs rcx, 0x1600020001247C).
const InstanceIID = 0x1600020001247C

// ErrNeedWindows reports that the broker API only exists inside the
// Proton/Wine prefix (GOOS=windows helper run via proton).
var ErrNeedWindows = errors.New("wgcs: broker API requires the windows helper (GOOS=windows via proton)")

// HR interprets a raw HRESULT register (negative = failure).
// Negative values are broker errors (e.g. 0x80EE1003 = session
// missing, 0x80EE1007 = null arg, 0x80EE2006 = no instance).
func HR(r uintptr) error {
	if int32(r) < 0 {
		return fmt.Errorf("wgcs: HRESULT 0x%08x", uint32(r))
	}
	return nil
}

// LoginInfoProbe is the scratch size for GetLoginInfo out-param
// probing (layout unknown statically; iterated live).
const LoginInfoProbe = 65536

// GetLoginInfo OUT layout (IDA sub_180050190, wgcs_api.dll):
// +0 WCHAR[64], +128 WCHAR[256] (token-sized), +640 WCHAR[64],
// +768 UINT64 (wcstoui64 decimal = spa/account id), +776 DWORD.
// Minimum 780 bytes; callers pass 1024 zeroed. All strings inline
// WCHAR (FindToken2 reads UTF-16LE runs, no pointer chasing).
const LoginInfoSize = 1024

// GetRememberMeToken params (IDA sub_18004F220/53xxx): p1 is a
// >=264B struct (+0 inline token wstring area, +256 UINT64 id),
// p2 is a WCHAR[1024] token buffer (responses longer than 1024
// words fail). Callers pass zeroed buffers and shape-scan both.
const RememberMeStruct = 512
const RememberMeBuf = 4096 // 1024 WCHARs
