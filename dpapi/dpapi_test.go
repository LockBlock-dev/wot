// Offline dpapi tests (no Windows, no blobs).
package dpapi

import "testing"

func TestStubOutsideWindows(t *testing.T) {
	if _, err := Unprotect("0100"); err == nil {
		t.Fatal("non-windows Unprotect must fail")
	}
	if MaxBlob != 65536 {
		t.Fatalf("MaxBlob=%d", MaxBlob)
	}
}
