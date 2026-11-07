package login

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestDefsAgreeWithPostDoCmd is the cross-check that lets the defs-driven
// codec replace the hand-written reader: on every doCmdInt2/doCmdInt3
// call in a real capture, both must extract the same request id and
// command id.
func TestDefsAgreeWithPostDoCmd(t *testing.T) {
	const (
		dump = "../../captures/proxy-20261014-1752.hex"
		flow = "35493->"
		key  = "/tmp/k1752.txt"
		defs = "../../scripts-2.4.1/entity_defs"
	)
	if _, err := os.Stat(dump); err != nil {
		t.Skipf("capture unavailable: %v", err)
	}
	if _, err := os.Stat(defs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	blockKey, err := ReadAnyKeyFile(key)
	if err != nil {
		t.Skipf("key unavailable: %v", err)
	}

	l := &entdef.Loader{Dir: defs}
	d, err := entdef.NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	acct := d.Entity("Account")
	if acct == nil {
		t.Fatal("no Account")
	}

	f, err := os.Open(dump)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := ParseWotproxyDump(f)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, rec := range records {
		if rec.Dir != "C>S" || !strings.Contains(rec.Addr, flow) {
			continue
		}
		clear, err := decryptBlowfish(blockKey, rec.Data[4:])
		if err != nil || len(clear) < 14 || clear[2] != 0x02 {
			continue
		}
		// The hand-written reader's view (no dispatch configured).
		plain := &BaseAppServer{}
		call, ok := plain.postDoCmd(clear, 0)
		if !ok {
			// postDoCmd checks the session key; re-read the ids directly
			// so the comparison does not depend on it.
			switch [2]byte{clear[7], clear[8]} {
			case [2]byte{0x95, 0x1c}, [2]byte{0x93, 0x14}:
				call.Req = uint16(clear[10]) | uint16(clear[11])<<8
				call.Cmd = uint16(clear[12]) | uint16(clear[13])<<8
			default:
				continue
			}
		}
		req, cmd := call.Req, call.Cmd
		// The defs' view: base id 13 is doCmdInt3, 11 is doCmdInt2.
		id := 13
		if clear[7] == 0x93 {
			id = 11
		}
		m := acct.MethodByID(2, id) // compBase
		if m == nil {
			t.Fatalf("no base method at id %d", id)
		}
		args, err := m.ReadArgs(bytes.NewReader(clear[10:]))
		if err != nil {
			t.Fatalf("%s: ReadArgs: %v", m.Name, err)
		}
		if len(args) < 2 {
			t.Fatalf("%s has %d args", m.Name, len(args))
		}
		if int64(req) != args[0].Int {
			t.Errorf("%s: requestID defs=%d reader=%d", m.Name, args[0].Int, req)
		}
		if int64(cmd) != args[1].Int {
			t.Errorf("%s: cmd defs=%d reader=%d", m.Name, args[1].Int, cmd)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no doCmd calls in the capture")
	}
	t.Logf("cross-checked %d calls against the defs", checked)
}
