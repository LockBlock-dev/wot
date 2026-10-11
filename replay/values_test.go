package replay

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecodeUnits pins the wire rules on hand-picked samples:
// u8-len strings, ff-extended Python, u8-count arrays, optional dicts.
func TestDecodeUnits(t *testing.T) {
	// updateSpawnList string: [0x19][25B].
	v, n, err := Decode("String", mustHex(t, "1930355f706c616e6573437261736830315f7363656e6172696f"))
	if err != nil {
		t.Fatal(err)
	}
	if v.(string) != "05_planesCrash01_scenario" || n != 26 {
		t.Fatalf("string=%q n=%d", v, n)
	}
	// showShotResults single element: [01][u32 u32 u8].
	v, n, err = Decode("Array[0]{FixedDict{vehicleID:UINT32,hitFlags:UINT32,gunInstallationIndex:UINT8}}",
		mustHex(t, "01d32c48008001100000"))
	if err != nil {
		t.Fatal(err)
	}
	el := v.([]any)[0].(map[string]any)
	if el["vehicleID"].(uint64) != 4730067 || el["gunInstallationIndex"].(uint64) != 0 || n != 10 {
		t.Fatalf("shotres=%v n=%d", el, n)
	}
	// Python zlib payload.
	v, n, err = Decode("Python", mustHex(t, "12789c6b608a2d6474678082443d00170a0228"))
	if err != nil {
		t.Fatal(err)
	}
	pb := v.(PythonBlob)
	if len(pb.Raw) != 18 || len(pb.Plain) != 16 || n != 19 {
		t.Fatalf("python raw=%d plain=%d n=%d", len(pb.Raw), len(pb.Plain), n)
	}
	// Optional dict absent.
	v, n, err = Decode("FixedDict{?damage:UINT32,count:UINT16}", mustHex(t, "00"))
	if err != nil {
		t.Fatal(err)
	}
	if v != nil || n != 1 {
		t.Fatalf("absent=%v n=%d", v, n)
	}
	// Optional dict present.
	v, n, err = Decode("FixedDict{?damage:UINT32,count:UINT16}", mustHex(t, "01e80300000500"))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["damage"].(uint64) != 1000 || m["count"].(uint64) != 5 || n != 7 {
		t.Fatalf("present=%v n=%d", m, n)
	}
}

func TestMatchBrace(t *testing.T) {
	body, rest, ok := matchBrace("a:{b},c},tail")
	if !ok || body != "a:{b},c" || rest != ",tail" {
		t.Fatalf("body=%q rest=%q ok=%v", body, rest, ok)
	}
	for _, s := range []string{"", "a:{b},c", "noparen"} {
		if _, _, ok := matchBrace(s); ok {
			t.Fatalf("unterminated %q accepted", s)
		}
	}
}
