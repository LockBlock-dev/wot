//go:build windows

package dpapi

import (
	"fmt"
	"syscall"
	"unsafe"
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// Unprotect hex-decodes a DPAPI blob and calls CryptUnprotectData
// (user scope, no description). Returns plaintext bytes for 0600
// storage by the caller; never logs them.
func Unprotect(hexBlob string) ([]byte, error) {
	raw := make([]byte, len(hexBlob)/2)
	n := 0
	for i := 0; i+1 < len(hexBlob); i += 2 {
		hi := unhex(hexBlob[i])
		lo := unhex(hexBlob[i+1])
		if hi > 15 || lo > 15 {
			return nil, fmt.Errorf("dpapi: bad hex at %d", i)
		}
		raw[n] = hi<<4 | lo
		n++
	}
	raw = raw[:n]
	crypt32 := syscall.NewLazyDLL("crypt32.dll")
	unprotect := crypt32.NewProc("CryptUnprotectData")
	if err := unprotect.Find(); err != nil {
		return nil, err
	}
	var in, out dataBlob
	if len(raw) > 0 {
		in.cbData = uint32(len(raw))
		in.pbData = &raw[0]
	}
	r1, _, _ := unprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)))
	if r1 == 0 {
		return nil, fmt.Errorf("dpapi: CryptUnprotectData failed")
	}
	if out.cbData == 0 || out.cbData > MaxBlob || out.pbData == nil {
		return nil, fmt.Errorf("dpapi: bad out len %d", out.cbData)
	}
	plain := make([]byte, out.cbData)
	copy(plain, (*[1 << 26]byte)(unsafe.Pointer(out.pbData))[:out.cbData])
	freeLocal(out.pbData)
	for i := range raw {
		raw[i] = 0
	}
	return plain, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

func freeLocal(p *byte) {
	kernel := syscall.NewLazyDLL("kernel32.dll")
	free := kernel.NewProc("LocalFree")
	_ = free.Find()
	free.Call(uintptr(unsafe.Pointer(p)))
}
