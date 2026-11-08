package login

import (
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestInterestEntersAndLeaves pins the area of interest: an entity is entered
// when it comes into range, left when it goes out, and an `always` one is held
// whatever its distance.
func TestInterestEntersAndLeaves(t *testing.T) {
	in := newInterest([3]float32{})
	in.add(1, [3]float32{0, 0, 0}, true)    // the player's own vehicle
	in.add(2, [3]float32{0, 0, 100}, false) // near
	in.add(3, [3]float32{0, 0, 900}, false) // far
	// The always one is entered by the battle entry itself, so the interest
	// starts knowing it; only the near tank is new.
	enter, leave := in.diff()
	if len(enter) != 1 || enter[0] != 2 || len(leave) != 0 {
		t.Fatalf("enter %v leave %v, want the near one", enter, leave)
	}
	if !in.known[1] || !in.known[2] || in.known[3] {
		t.Fatalf("known = %v, want 1 and 2", in.known)
	}
	// Driving toward the far one brings it in.
	in.move([3]float32{0, 0, 500})
	enter, leave = in.diff()
	if len(enter) != 1 || enter[0] != 3 || len(leave) != 0 {
		t.Fatalf("enter %v leave %v, want 3 in", enter, leave)
	}
	// Driving away from the near one drops it.
	in.move([3]float32{0, 0, 900})
	enter, leave = in.diff()
	if len(enter) != 0 || len(leave) != 1 || leave[0] != 2 {
		t.Fatalf("enter %v leave %v, want 2 out", enter, leave)
	}
	// The always one never leaves.
	if !in.known[1] {
		t.Fatal("the player's own vehicle left the interest")
	}
}

// TestAudienceFromTheDefs pins the audience the defs' flags give: a vehicle's
// `isMyVehicle` is the owner's, `publicInfo` is everyone's.
func TestAudienceFromTheDefs(t *testing.T) {
	d := testDispatch(t)
	veh := d.Entity("Vehicle")
	if veh == nil {
		t.Fatal("defs have no Vehicle")
	}
	byName := map[string]entdef.Audience{}
	for _, p := range veh.Properties {
		byName[p.Name] = p.Audience
	}
	if got := byName["publicInfo"]; got != entdef.AudienceAll {
		t.Errorf("publicInfo audience = %v, want all", got)
	}
	// `isMyVehicle` is ALL_CLIENTS with a MY_VEHICLE detail level, which is a
	// separate mechanism; `arenaUniqueID` is the owner's alone.
	if got := byName["isMyVehicle"]; got != entdef.AudienceAll {
		t.Errorf("isMyVehicle audience = %v, want all (its MY_VEHICLE detail level is what narrows it)", got)
	}
	if got := byName["arenaUniqueID"]; got != entdef.AudienceOwn {
		t.Errorf("arenaUniqueID audience = %v, want own", got)
	}
	// A run for a client that does not own the tank leaves it out, and the
	// count shrinks with it.
	e := NewEntity(100004, veh)
	for _, p := range veh.Properties {
		e.Set(p.Name, entdef.ZeroValue(p.Type))
	}
	e.SetUint("isMyVehicle", 1)
	own, err := EntityPropertyRunFor(e, true, "publicInfo", "arenaUniqueID")
	if err != nil {
		t.Fatal(err)
	}
	other, err := EntityPropertyRunFor(e, false, "publicInfo", "arenaUniqueID")
	if err != nil {
		t.Fatal(err)
	}
	if own[0] != 2 {
		t.Fatalf("the owner's run carries %d properties, want 2", own[0])
	}
	if other[0] != 1 {
		t.Fatalf("another client's run carries %d properties, want 1 (no arenaUniqueID)", other[0])
	}
}
