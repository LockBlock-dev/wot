package keydump

import (
	"encoding/binary"
	"fmt"
)

// MSVC x64 std::string object layout (32 B): [ptr u64][len u64][cap u64-or-inline].
// LogOnParams::addToStreamInternal (IDA sub_140E6E210) streams four strings
// at this+0x18/+0x38/+0x58/+0x78 = username/password/encryptionKey/
// clientContext — verified in disasm (lea rdx,[rbp+18h]/[rbp+38h] feeding
// sub_140E65FC0) and ce/CE_KEY_HUNT.md §2. So with RCX = LogOnParams* on
// breakpoint entry, the key object starts at RCX+KeyFieldOff and its length
// lives at RCX+KeyLenOff.
const (
	KeyFieldOff = 0x58
	KeyLenOff   = 0x68
	// MaxKeyLen mirrors ce/wotkeydump.lua (1..64): genuine keys are 16 B,
	// the bound only rejects garbage pointers.
	MaxKeyLen = 64
)

// MemReader abstracts one remote read; OS backends implement it over
// ReadProcessMemory (Windows) or process_vm_readv (Linux/Wine).
type MemReader interface {
	Read(addr uint64, n int) ([]byte, error)
}

// ReadKey extracts the encryptionKey bytes for the LogOnParams object at
// objAddr. It returns the key, the heap pointer logged as ptr= (or
// objAddr+KeyFieldOff for SSO-inline keys, mirroring ce/wotkeydump.lua),
// and the raw 32 B string object (strobj). Keys longer than MaxKeyLen are
// rejected as garbage.
func ReadKey(mr MemReader, objAddr uint64) (key []byte, ptr uint64, strobj []byte, err error) {
	strobj, err = mr.Read(objAddr+KeyFieldOff, 32)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("keydump: read string object: %w", err)
	}
	n := int(binary.LittleEndian.Uint64(strobj[16:24])) // [RCX+0x68]
	if n < 1 || n > MaxKeyLen {
		return nil, 0, strobj, fmt.Errorf("keydump: odd key length %d", n)
	}
	if n < 16 {
		// Short-string optimization: chars live inline at +0x58.
		return append([]byte(nil), strobj[:n]...), objAddr + KeyFieldOff, strobj, nil
	}
	ptr = binary.LittleEndian.Uint64(strobj[:8]) // [RCX+0x58]
	key, err = mr.Read(ptr, n)
	if err != nil {
		return nil, 0, strobj, fmt.Errorf("keydump: read key bytes: %w", err)
	}
	return key, ptr, strobj, nil
}
