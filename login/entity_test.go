package login

import (
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

const entityTestDefs = "../../scripts-2.4.1/entity_defs"

func entityTestDispatch(t *testing.T) *entdef.Dispatch {
	t.Helper()
	if _, err := os.Stat(entityTestDefs); err != nil {
		t.Skipf("defs unavailable: %v", err)
	}
	l := &entdef.Loader{Dir: entityTestDefs}
	names, err := l.LoadEntities()
	if err != nil {
		t.Fatalf("LoadEntities: %v", err)
	}
	d, err := entdef.NewDispatch(l, names)
	if err != nil {
		t.Fatalf("NewDispatch: %v", err)
	}
	return d
}

// TestCreateBasePlayerRoundTrip is the entity layer's contract: an entity
// built from the defs encodes to a CreateBasePlayer element that decodes
// back to the same values.
func TestCreateBasePlayerRoundTrip(t *testing.T) {
	d := entityTestDispatch(t)
	acct := d.Entity("Account")
	if acct == nil {
		t.Fatal("no Account")
	}

	e := NewEntity(7, acct).
		SetUint("incarnationID", 0x1122334455667788).
		SetString("name", "playerone").
		Set("initialServerSettings", entdef.Value{Kind: entdef.VString, Str: ""})
	// The version property is named after the build the defs belong to.
	for _, name := range []string{"requiredVersion_2410", "requiredVersion_2400"} {
		if acct.PropertyByName(name) != nil {
			e.SetString(name, "2.4.1.0")
			break
		}
	}

	elem, err := EncodeCreateBasePlayer(e)
	if err != nil {
		t.Fatalf("EncodeCreateBasePlayer: %v", err)
	}
	if elem[0] != elCreateBasePlayer {
		t.Fatalf("element id = %#02x, want %#02x", elem[0], elCreateBasePlayer)
	}

	back, err := DecodeCreateBasePlayer(elem, d)
	if err != nil {
		t.Fatalf("DecodeCreateBasePlayer: %v", err)
	}
	if back.ID != 7 {
		t.Errorf("id = %d, want 7", back.ID)
	}
	if back.Type.Name != "Account" {
		t.Errorf("type = %q, want Account", back.Type.Name)
	}
	if v := back.Props["incarnationID"]; v.Uint != 0x1122334455667788 {
		t.Errorf("incarnationID = %#x", v.Uint)
	}
	if v := back.Props["name"]; v.Str != "playerone" {
		t.Errorf("name = %q", v.Str)
	}
	verName := "requiredVersion_2410"
	if acct.PropertyByName(verName) == nil {
		verName = "requiredVersion_2400"
	}
	if v := back.Props[verName]; v.Str != "2.4.1.0" {
		t.Errorf("%s = %q", verName, v.Str)
	}
	t.Logf("CreateBasePlayer: %d B for %s (%d base props)", len(elem), acct.Name, len(acct.BaseProps))
}

// TestCreateBasePlayerNeedsEveryProp keeps a half-filled entity from
// encoding a short payload the client would misread.
func TestCreateBasePlayerNeedsEveryProp(t *testing.T) {
	d := entityTestDispatch(t)
	e := NewEntity(1, d.Entity("Account")).SetString("name", "x")
	if _, err := EncodeCreateBasePlayer(e); err == nil {
		t.Fatal("an entity missing base properties encoded")
	}
}

// TestClientMethodCallFromDefs pins the element id and the argument
// encoding: a client method call is ENTITY_METHOD_BASE + exposed id.
func TestClientMethodCallFromDefs(t *testing.T) {
	d := entityTestDispatch(t)
	acct := d.Entity("Account")
	e := NewEntity(1, acct)

	// onEnqueued is client slot 3 and takes one UINT8.
	m := acct.MethodByID(entdef.CompClient, 3)
	if m == nil || m.Name != "onEnqueued" {
		t.Fatalf("client[3] = %v, want onEnqueued", m)
	}
	elem, err := EncodeClientMethodCall(e, "onEnqueued", []entdef.Value{
		{Kind: entdef.VUint, Uint: 1},
	})
	if err != nil {
		t.Fatalf("EncodeClientMethodCall: %v", err)
	}
	if want := byte(entityMethodBase + 3); elem[0] != want {
		t.Errorf("element id = %#02x, want %#02x", elem[0], want)
	}
	// Fixed-size method: no length field, the payload follows the id.
	if len(elem) != 2 {
		t.Fatalf("element = %d B, want 2 (id + 1-byte payload)", len(elem))
	}
	if elem[1] != 1 {
		t.Errorf("arg = %d, want 1", elem[1])
	}

	// A no-argument method encodes an empty payload.
	elem, err = EncodeClientMethodCall(e, "onArenaCreated", nil)
	if err != nil {
		t.Fatalf("onArenaCreated: %v", err)
	}
	if want := byte(entityMethodBase + 0); elem[0] != want {
		t.Errorf("element id = %#02x, want %#02x", elem[0], want)
	}
	if len(elem) != 1 {
		t.Errorf("element = %d B, want 1 (id only)", len(elem))
	}

	// An unknown method is an error, not a silent no-op.
	if _, err := EncodeClientMethodCall(e, "noSuchMethod", nil); err == nil {
		t.Error("unknown method accepted")
	}
	// Wrong argument count is an error too.
	if _, err := EncodeClientMethodCall(e, "onEnqueued", nil); err == nil {
		t.Error("missing argument accepted")
	}
}

// TestPropertyUpdateFromDefs pins the property element id and value.
func TestPropertyUpdateFromDefs(t *testing.T) {
	d := entityTestDispatch(t)
	acct := d.Entity("Account")
	e := NewEntity(1, acct).SetString("name", "tank")

	idx := -1
	for i, p := range acct.Properties {
		if p.Name == "name" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("Account has no name property")
	}
	elem, err := EncodePropertyUpdate(e, "name")
	if err != nil {
		t.Fatalf("EncodePropertyUpdate: %v", err)
	}
	if want := byte(entityPropertyBase + idx); elem[0] != want {
		t.Errorf("element id = %#02x, want %#02x", elem[0], want)
	}
	// A 1-byte length header, then the string.
	if elem[3] != 4 || string(elem[4:]) != "tank" {
		t.Errorf("payload = % x", elem[3:])
	}
	if _, err := EncodePropertyUpdate(e, "noSuchProp"); err == nil {
		t.Error("unknown property accepted")
	}
}

// TestEntityRegistry covers id allocation and teardown.
func TestEntityRegistry(t *testing.T) {
	d := entityTestDispatch(t)
	acct, avatar := d.Entity("Account"), d.Entity("Avatar")
	r := NewEntityRegistry()

	a := r.Create(acct)
	b := r.Create(avatar)
	c := r.Create(acct)
	if a.ID == 0 || b.ID == 0 || c.ID == 0 {
		t.Fatal("id 0 is the no-entity sentinel")
	}
	if a.ID == b.ID || b.ID == c.ID || a.ID == c.ID {
		t.Fatalf("ids collide: %d %d %d", a.ID, b.ID, c.ID)
	}
	if r.Len() != 3 {
		t.Fatalf("Len = %d, want 3", r.Len())
	}
	if got := r.OfType("Account"); len(got) != 2 {
		t.Errorf("OfType(Account) = %d, want 2", len(got))
	}
	if r.Get(b.ID) != b {
		t.Error("Get did not return the entity")
	}
	r.Destroy(b.ID)
	if r.Len() != 2 || r.Get(b.ID) != nil {
		t.Error("Destroy did not remove the entity")
	}
	if got := r.OfType("Avatar"); len(got) != 0 {
		t.Errorf("OfType(Avatar) = %d after destroy, want 0", len(got))
	}
	// A destroyed id is not reused, so a stale reference cannot alias a
	// new entity.
	next := r.Create(avatar)
	if next.ID == b.ID {
		t.Error("a destroyed id was reused")
	}
}

// TestTickSyncElement pins the one-byte message head the post-flood chain
// uses.
func TestTickSyncElement(t *testing.T) {
	got := EncodeTickSync(0x7a)
	if len(got) != 2 || got[0] != elTickSync || got[1] != 0x7a {
		t.Fatalf("EncodeTickSync = % x", got)
	}
}

// TestClientMethodElementWidth pins the element-length width to the
// method's VariableLengthHeaderSize. `update` declares 1, so its element is
// `[id][u8 len][u8 strLen][pickle]`; writing a u16 there shifts every field
// by one and the client dies on
// `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.
func TestClientMethodElementWidth(t *testing.T) {
	d := entityTestDispatch(t)
	acct := d.Entity("Account")
	if acct == nil {
		t.Fatal("no Account entity")
	}
	doc := []byte{0x80, 0x02, 0x7d, 0x2e} // an empty-ish pickle
	el, err := EncodeClientMethodCall(NewEntity(0, acct), "update",
		[]entdef.Value{{Kind: entdef.VString, Str: string(doc)}})
	if err != nil {
		t.Fatalf("EncodeClientMethodCall: %v", err)
	}
	if len(el) < 3 {
		t.Fatalf("element is %d B", len(el))
	}
	wantID := -1
	for i := range acct.ClientMethods {
		if acct.ClientMethods[i].Name == "update" {
			wantID = i
			break
		}
	}
	if wantID < 0 {
		t.Fatal("no update in the Account client methods")
	}
	if el[0] != byte(entityMethodBase+wantID) {
		t.Fatalf("element id %#02x, want %#02x (update)", el[0], byte(entityMethodBase+wantID))
	}
	// One-byte length: 1 (string header) + len(doc).
	if got, want := int(el[1]), 1+len(doc); got != want {
		t.Fatalf("element length %d, want %d (a u8 header, not a u16)", got, want)
	}
	if got, want := int(el[2]), len(doc); got != want {
		t.Fatalf("string length %d, want %d", got, want)
	}
	if len(el) != 3+len(doc) {
		t.Fatalf("element is %d B, want %d", len(el), 3+len(doc))
	}
}
