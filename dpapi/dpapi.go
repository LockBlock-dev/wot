// Package dpapi unwraps Wine/Proton DPAPI blobs (CryptUnprotectData)
// offline-style: no network, no broker, no game. The WGC store blobs
// (user_info.xml) are Wine-DPAPI + hex (provider tag "WinCrypt"),
// sealed via game_center.dll's sub_180800450 path. Unwrapping uses
// Wine's own crypt32 in-prefix, so key storage never matters.
package dpapi

import "errors"

// ErrNeedWindows reports that DPAPI only exists inside Wine/Proton
// (GOOS=windows helper run via proton on the game prefix).
var ErrNeedWindows = errors.New("dpapi: CryptUnprotectData requires the windows helper (GOOS=windows via proton)")

// MaxBlob caps an unwrapped blob (SSO sessions are a few KB).
const MaxBlob = 65536
