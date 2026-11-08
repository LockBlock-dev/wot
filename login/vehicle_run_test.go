package login

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestVehiclePropertyRunRoundTrips encodes the Vehicle's property run and
// decodes it back with the same codec, so a broken value encoding shows up
// here instead of as an empty publicInfo in the client.
func TestVehiclePropertyRunRoundTrips(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	typ := d.Entity("Vehicle")
	if typ == nil {
		t.Skip("no Vehicle")
	}
	h := &ArenaHandoff{
		ArenaID: 1, SpaceID: 1, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte{1, 0, 0, 0, 240, 7, 203, 0, 5, 0, 0, 0, 246, 7, 0}},
		VehicleID: 0x2222,
	}
	st := &clientState{accountID: 2, name: "admin", entityID: 0x1234}
	e, err := s.arenaVehicleApp(st, h)
	if err != nil {
		t.Fatal(err)
	}
	run, err := EntityPropertyRun(e)
	if err != nil {
		t.Fatal(err)
	}
	if int(run[0]) != len(typ.Properties) {
		t.Fatalf("count = %d, want %d", run[0], len(typ.Properties))
	}
	r := bytes.NewReader(run[1:])
	c := entdef.NewCodec()
	got := map[string]entdef.Value{}
	for i := range typ.Properties {
		// The run's property index is a u16 (the client reads it that way).
		var id [2]byte
		if _, err := r.Read(id[:]); err != nil {
			t.Fatalf("property %d: %v", i, err)
		}
		if got := int(binary.LittleEndian.Uint16(id[:])); got != i {
			t.Fatalf("exposed id = %d, want %d", got, i)
		}
		v, err := c.Read(r, typ.Properties[i].Type)
		if err != nil {
			t.Fatalf("property %q: %v", typ.Properties[i].Name, err)
		}
		got[typ.Properties[i].Name] = v
	}
	if r.Len() != 0 {
		t.Fatalf("%d bytes left after the run", r.Len())
	}
	pi := got["publicInfo"]
	var cd string
	for _, f := range pi.Dict {
		if f.Name == "compDescr" {
			cd = f.Value.Str
		}
	}
	if cd != string(h.Player.VehicleCompDescr) {
		t.Fatalf("publicInfo.compDescr = %q, want %q", cd, h.Player.VehicleCompDescr)
	}
}

// TestServerDefsMatchTheClientBuild pins the defs tree the server authors
// entity data from to the build the client runs.
//
// The property tables are what the client decodes entity data against, and
// a type that changed between builds shifts every field after it without
// any error on the wire. `PUBLIC_VEHICLE_INFO.index` is UINT8 in 2.4.0.0
// and UINT16 in 2.4.1, so a 2.4.1 client fed 2.4.0 defs reads a shifted
// `publicInfo` and leaves `compDescr` empty — which is what
// "compact descriptor to XML mismatch? (”,)" in `Vehicle.onEnterWorld`
// was, and why the tank never appeared.
func TestServerDefsMatchTheClientBuild(t *testing.T) {
	const dir = "../../scripts-2.4.1/entity_defs"
	raw, err := os.ReadFile(dir + "/alias.xml")
	if err != nil {
		t.Skipf("client defs unavailable: %v", err)
	}
	// The packed alias.xml is a name table plus binary sections; the field
	// name and its type tag are adjacent in the string table, so a plain
	// search for the pair is enough to tell the two builds apart.
	i := bytes.Index(raw, []byte("PUBLIC_VEHICLE_INFO"))
	if i < 0 {
		t.Fatal("no PUBLIC_VEHICLE_INFO in the client's alias.xml")
	}
	if !bytes.Contains(raw[i:], []byte("index")) {
		t.Fatal("no index field in PUBLIC_VEHICLE_INFO")
	}
	// The server's own default must point at this tree.
	if _, err := os.Stat(dir + "/Vehicle.def"); err != nil {
		t.Fatalf("client Vehicle.def missing: %v", err)
	}
}

// TestAvatarCellPropsRoundTrip checks the Avatar's cell property block, which
// is what `createCellPlayer` carries after its 39-byte header. A single
// mis-sized value there makes the client drop the element silently — no
// space, no `onEnterWorld`, and the battle app renders nothing.
func TestAvatarCellPropsRoundTrip(t *testing.T) {
	s := tokenTestServer(t, nil)
	d := s.cfg.Dispatch
	typ := d.Entity("Avatar")
	if typ == nil {
		t.Skip("no Avatar")
	}
	h := &ArenaHandoff{
		ArenaID: 1, SpaceID: 1, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1},
		VehicleID: 0x2222,
	}
	st := &clientState{accountID: 2, name: "admin", entityID: 0x1234}
	e, _, err := s.arenaAvatarApp(st, h)
	if err != nil {
		t.Fatal(err)
	}
	data, err := e.encodeProps(typ.CellProps, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(data)
	c := entdef.NewCodec()
	got := map[string]entdef.Value{}
	for i := range typ.CellProps {
		v, err := c.Read(r, typ.CellProps[i].Type)
		if err != nil {
			t.Fatalf("cell property %q: %v", typ.CellProps[i].Name, err)
		}
		got[typ.CellProps[i].Name] = v
	}
	if r.Len() != 0 {
		t.Fatalf("%d bytes left after the cell block", r.Len())
	}
	if got["team"].Uint != 1 {
		t.Fatalf("team = %d, want 1", got["team"].Uint)
	}
	if got["playerVehicleID"].Int != 0x2222 {
		t.Fatalf("playerVehicleID = %d, want %d", got["playerVehicleID"].Int, 0x2222)
	}
}

// `avatarID` is ALL_CLIENTS with no DetailLevel, so it rides the creation run —
// the `updateEntity` that follows only carries the MY_VEHICLE properties, and
// it was never sent at all: the client read 0. It is the Avatar's ENTITY id,
// not the account id, because the client compares it with
// `BigWorld.player().id`.
func TestVehicleCreationCarriesAvatarID(t *testing.T) {
	s := tokenTestServer(t, nil)
	if s.cfg.Dispatch.Entity("Vehicle") == nil {
		t.Skip("no Vehicle")
	}
	h := &ArenaHandoff{
		ArenaID: 1, SpaceID: 1, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte{1, 0, 0, 0, 240, 7, 203, 0, 5, 0, 0, 0, 246, 7, 0}},
		VehicleID: 0x2222,
	}
	st := &clientState{accountID: 2, name: "admin", entityID: 0x1234}
	e, err := s.arenaVehicleApp(st, h)
	if err != nil {
		t.Fatal(err)
	}
	run, err := EntityPropertyRunNames(e, "publicInfo", "health", "isCrewActive", "avatarID")
	if err != nil {
		t.Fatalf("avatarID is not in the creation run: %v", err)
	}
	if len(run) == 0 {
		t.Fatal("empty creation run")
	}
	if got := e.Props["avatarID"].Int; got != int64(st.entityID) {
		t.Fatalf("avatarID = %d, want the Avatar's entity id %d", got, st.entityID)
	}
}

// `Vehicle.dogTag` has to carry a BACKGROUND and an ENGRAVING component.
//
// `DogTagsController.__addDogTagMarker` runs on `Avatar.onVehicleEnterWorld`,
// which `Avatar.setClientReady` calls for every vehicle, and it does
// `PlayerDogTag.fromDict(vehicle.dogTag['dogTag']).getComponentByType(BACKGROUND)
// .componentDefinition`. With no components that is `None` and the
// `AttributeError` unwinds through `__startVehicleVisual`, so `setClientReady`
// never finishes: no `isOnArena`, no `onPeriodChange`, no battle.
func TestVehicleDogTagHasBackgroundAndEngraving(t *testing.T) {
	s := tokenTestServer(t, nil)
	if s.cfg.Dispatch.Entity("Vehicle") == nil {
		t.Skip("no Vehicle")
	}
	typ := entdef.Alias("BATTLE_DOG_TAG")
	if typ == nil {
		t.Skip("no BATTLE_DOG_TAG")
	}
	h := &ArenaHandoff{
		ArenaID: 1, SpaceID: 1, ArenaTypeID: 1, Map: "spaces/01_karelia",
		Player:    ArenaPlayerDoc{AccountID: 2, Name: "admin", Team: 1, VehicleCompDescr: []byte{1, 0, 0, 0, 240, 7, 203, 0, 5, 0, 0, 0, 246, 7, 0}},
		VehicleID: 0x2222,
	}
	st := &clientState{accountID: 2, name: "admin", entityID: 0x1234}
	e, err := s.arenaVehicleApp(st, h)
	if err != nil {
		t.Fatal(err)
	}
	dt, ok := e.Props["dogTag"]
	if !ok {
		t.Fatal("no dogTag on the Vehicle")
	}
	tag, ok := dt.Get("dogTag")
	if !ok {
		t.Fatal("dogTag has no dogTag field")
	}
	comps, ok := tag.Get("components")
	if !ok || comps.Kind != entdef.VSeq {
		t.Fatal("dogTag.dogTag has no components")
	}
	// The client keys them by view type, so both have to be there and they
	// have to be different components.
	ids := map[int64]bool{}
	for _, c := range comps.Seq {
		id, _ := c.Get("id")
		ids[id.Int] = true
	}
	if !ids[300] || !ids[66] {
		t.Fatalf("components %v, want 300 (engraving) and 66 (background)", ids)
	}
	// And it has to encode: the run is what the client reads.
	if _, err := EntityPropertyRunNames(e, "dogTag"); err != nil {
		t.Fatalf("dogTag does not encode: %v", err)
	}
}
