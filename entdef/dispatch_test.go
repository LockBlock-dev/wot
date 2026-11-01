package entdef

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAccountExposedIDs pins the exposed-id table against the live client.
//
// Two numbers here are load-bearing and were both wrong before the dedup:
// Account owns 41 client methods (slots 0..40), and its base slot 13 is
// doCmdInt3 (28 B). Counting the inherited `requestToken` twice pushed
// doCmdInt3 to 14, so the client's id 13 landed on
// accountDebugger_registerDebugTaskResult (20 B) and every call left 8
// bytes unread.
func TestAccountExposedIDs(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	d, err := NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	e := d.Entity("Account")
	if e == nil {
		t.Fatal("no Account")
	}
	if got := len(e.ClientMethods); got != 41 {
		t.Errorf("Account has %d client methods, want 41", got)
	}
	m := e.MethodByID(compBase, 13)
	if m == nil {
		t.Fatal("no base method at id 13")
	}
	if m.Name != "doCmdInt3" {
		t.Errorf("base[13] = %q, want doCmdInt3", m.Name)
	}
	if !m.Length.Fixed || m.Length.Size != 28 {
		t.Errorf("doCmdInt3 length = %s, want fixed(28)", m.Length)
	}
	if len(m.Args) != 5 {
		t.Errorf("doCmdInt3 has %d args, want 5", len(m.Args))
	}
	// The table is ordered: fixed lengths ascending, then variable.
	prev := ElementLength{Fixed: true, Size: -1}
	for i := range e.BaseMethods {
		cur := e.BaseMethods[i].Length
		kc, sc := cur.sortKey()
		kp, sp := prev.sortKey()
		if kc < kp || (kc == kp && sc < sp) {
			t.Fatalf("base[%d] %s (%s) sorts before base[%d] (%s)", i, e.BaseMethods[i].Name, cur, i-1, prev)
		}
		prev = cur
	}
}

// TestDecodeRealDoCmdInt3 decodes two genuine calls from the 1752 capture
// with the defs, and checks the values the hand-written reader already
// extracts: request id and command id.
func TestDecodeRealDoCmdInt3(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	d, err := NewDispatch(l, []string{"Account"})
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	m := d.Entity("Account").MethodByID(compBase, 13)
	if m == nil || m.Name != "doCmdInt3" {
		t.Fatal("no doCmdInt3 at base id 13")
	}

	cases := []struct {
		name string
		hex  string
		req  int64
		cmd  int64
	}{
		// A CMD_SYNC_DATA (100) call.
		{"sync", "e60064005000000000000000646fb844000000000000000000000000", 230, 100},
		// A CMD_REQ_SERVER_STATS (501) call.
		{"poll", "ca00f501000000000000000000000000000000000000000000000000", 202, 501},
	}
	c := NewCodec()
	for _, tc := range cases {
		raw, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatal(err)
		}
		args, err := m.ReadArgs(bytes.NewReader(raw), c)
		if err != nil {
			t.Fatalf("%s: ReadArgs: %v", tc.name, err)
		}
		if len(args) != 5 {
			t.Fatalf("%s: %d args, want 5", tc.name, len(args))
		}
		if args[0].Int != tc.req {
			t.Errorf("%s: requestID = %d, want %d", tc.name, args[0].Int, tc.req)
		}
		if args[1].Int != tc.cmd {
			t.Errorf("%s: cmd = %d, want %d", tc.name, args[1].Int, tc.cmd)
		}
		// Re-encoding must reproduce the capture's bytes exactly.
		var out bytes.Buffer
		if err := m.WriteArgs(&out, c, args); err != nil {
			t.Fatalf("%s: WriteArgs: %v", tc.name, err)
		}
		if !bytes.Equal(out.Bytes(), raw) {
			t.Errorf("%s: re-encode = % x, want % x", tc.name, out.Bytes(), raw)
		}
	}
}

// TestDispatchCoversEveryEntity keeps the loader and the dispatch tables
// from drifting apart.
func TestDispatchCoversEveryEntity(t *testing.T) {
	l := &Loader{Dir: testDefsDir}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatalf("LoadEntities: %v", err)
	}
	d, err := NewDispatch(l, names)
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	if got := len(d.Entities()); got != len(names) {
		t.Fatalf("%d entities in the dispatch, %d loaded", got, len(names))
	}
	for _, name := range names {
		e := d.Entity(name)
		if e == nil {
			t.Errorf("%s missing from the dispatch", name)
			continue
		}
		// Every table must be ordered, or the ids are wrong.
		for _, tbl := range [][]MethodDef{e.ClientMethods, e.BaseMethods, e.CellMethods} {
			for i := 1; i < len(tbl); i++ {
				kc, sc := tbl[i].Length.sortKey()
				kp, sp := tbl[i-1].Length.sortKey()
				if kc < kp || (kc == kp && sc < sp) {
					t.Errorf("%s: %s (%s) sorts before %s (%s)",
						name, tbl[i].Name, tbl[i].Length, tbl[i-1].Name, tbl[i-1].Length)
					break
				}
			}
		}
	}
}
