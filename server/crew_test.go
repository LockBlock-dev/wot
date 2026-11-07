package server

import (
	"context"
	"testing"
)

// crewFixture provisions one account with a two-vehicle garage and returns
// the crew surface plus the account id.
func crewFixture(t *testing.T) (*Crew, *SQLiteStore, int64) {
	t.Helper()
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	setState(t, store, acct.ID, func(st *PlayerState) {
		st.Garage = []GarageVehicle{
			{CompactDescr: []byte{1, 1, 2}},
			{CompactDescr: []byte{1, 2, 3}},
		}
	})
	return NewCrew(store), store, acct.ID
}

// TestEquipCrewAssignsSlot checks the plain case: an empty slot takes the
// tankman and the tankman's vehicle follows.
func TestEquipCrewAssignsSlot(t *testing.T) {
	crew, store, id := crewFixture(t)
	res := crew.EquipCrew(id, 1, 1, 42)
	if !res.Ok() {
		t.Fatalf("EquipCrew: %d %s", res.Code, res.Message)
	}
	if got := res.Vehicles[1]; len(got) != 2 || got[0] != 0 || got[1] != 42 {
		t.Fatalf("vehicles[1] = %v, want [0 42]", got)
	}
	if got := res.Tankmen[42]; got != 1 {
		t.Fatalf("tankmen[42] = %d, want 1", got)
	}
	st, err := store.LoadState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Garage[0].Crew; len(got) != 2 || got[1] != 42 {
		t.Fatalf("stored crew = %v, want slot 1 = 42", got)
	}
}

// TestEquipCrewMovesBetweenVehicles checks that a tankman can only sit in
// one slot: assigning it to a second vehicle clears the first.
func TestEquipCrewMovesBetweenVehicles(t *testing.T) {
	crew, store, id := crewFixture(t)
	if res := crew.EquipCrew(id, 1, 0, 42); !res.Ok() {
		t.Fatalf("first EquipCrew: %d %s", res.Code, res.Message)
	}
	res := crew.EquipCrew(id, 2, 2, 42)
	if !res.Ok() {
		t.Fatalf("second EquipCrew: %d %s", res.Code, res.Message)
	}
	if got := res.Vehicles[1]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("vehicles[1] = %v, want the slot cleared", got)
	}
	if got := res.Vehicles[2]; len(got) != 3 || got[2] != 42 {
		t.Fatalf("vehicles[2] = %v, want slot 2 = 42", got)
	}
	if got := res.Tankmen[42]; got != 2 {
		t.Fatalf("tankmen[42] = %d, want 2", got)
	}
	st, err := store.LoadState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Garage[0].Crew; len(got) != 1 || got[0] != 0 {
		t.Fatalf("stored vehicle 1 crew = %v, want empty", got)
	}
}

// TestEquipCrewDisplacesOccupant checks that the tankman already in the
// slot goes back to the barracks.
func TestEquipCrewDisplacesOccupant(t *testing.T) {
	crew, _, id := crewFixture(t)
	if res := crew.EquipCrew(id, 1, 0, 42); !res.Ok() {
		t.Fatalf("first EquipCrew: %d %s", res.Code, res.Message)
	}
	res := crew.EquipCrew(id, 1, 0, 43)
	if !res.Ok() {
		t.Fatalf("second EquipCrew: %d %s", res.Code, res.Message)
	}
	if got := res.Vehicles[1][0]; got != 43 {
		t.Fatalf("slot 0 = %d, want 43", got)
	}
	if got, ok := res.Tankmen[42]; !ok || got != -1 {
		t.Fatalf("tankmen[42] = %d (present %v), want -1", got, ok)
	}
}

// TestEquipCrewClearsSlot checks the drag-to-barracks path: tmanInvID -1
// empties the slot.
func TestEquipCrewClearsSlot(t *testing.T) {
	crew, _, id := crewFixture(t)
	if res := crew.EquipCrew(id, 1, 0, 42); !res.Ok() {
		t.Fatalf("first EquipCrew: %d %s", res.Code, res.Message)
	}
	res := crew.EquipCrew(id, 1, 0, -1)
	if !res.Ok() {
		t.Fatalf("clear: %d %s", res.Code, res.Message)
	}
	if got := res.Vehicles[1][0]; got != 0 {
		t.Fatalf("slot 0 = %d, want 0", got)
	}
	if got := res.Tankmen[42]; got != -1 {
		t.Fatalf("tankmen[42] = %d, want -1", got)
	}
}

// TestEquipCrewRejectsUnknownVehicle checks the refusal path.
func TestEquipCrewRejectsUnknownVehicle(t *testing.T) {
	crew, _, id := crewFixture(t)
	res := crew.EquipCrew(id, 99, 0, 42)
	if res.Ok() {
		t.Fatal("EquipCrew accepted an unknown vehicle")
	}
	if res.Code != -1 {
		t.Fatalf("code = %d, want -1", res.Code)
	}
}

// TestSeedGarageKeepsCrew pins the restart contract: re-seeding the garage
// must not empty the tanks, and the crew must follow its vehicle even when
// the list is reordered.
func TestSeedGarageKeepsCrew(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	first := []GarageVehicle{
		{CompactDescr: []byte{1, 1, 2}},
		{CompactDescr: []byte{1, 2, 3}},
	}
	if _, err := srv.SeedGarage(ctx, acct.ID, first); err != nil {
		t.Fatal(err)
	}
	if res := NewCrew(store).EquipCrew(acct.ID, 2, 0, 42); !res.Ok() {
		t.Fatalf("EquipCrew: %d %s", res.Code, res.Message)
	}
	// Re-seed with the vehicles in the other order.
	second := []GarageVehicle{
		{CompactDescr: []byte{1, 2, 3}},
		{CompactDescr: []byte{1, 1, 2}},
	}
	st, err := srv.SeedGarage(ctx, acct.ID, second)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Garage[0].Crew; len(got) != 1 || got[0] != 42 {
		t.Fatalf("vehicle 2 crew = %v, want slot 0 = 42", got)
	}
	if got := st.Garage[1].Crew; len(got) != 0 {
		t.Fatalf("vehicle 1 crew = %v, want empty", got)
	}
}

// TestEquipCrewPadsToSlotCount pins the length rule on the stored list: the
// client rejects any crew list that is not exactly the vehicle's slot
// count, so an assignment must leave a full-length list behind.
func TestEquipCrewPadsToSlotCount(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	setState(t, store, acct.ID, func(st *PlayerState) {
		st.Garage = []GarageVehicle{{CompactDescr: []byte{1, 1, 2}, CrewSize: 4}}
	})
	res := NewCrew(store).EquipCrew(acct.ID, 1, 1, 42)
	if !res.Ok() {
		t.Fatalf("EquipCrew: %d %s", res.Code, res.Message)
	}
	if got := res.Vehicles[1]; len(got) != 4 || got[1] != 42 {
		t.Fatalf("vehicles[1] = %v, want 4 slots with 42 at index 1", got)
	}
	st, err := store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Garage[0].Crew; len(got) != 4 {
		t.Fatalf("stored crew = %v, want 4 slots", got)
	}
}

// TestSetLayoutsStoresBothHalves pins the layout store: a nil half is left
// alone, which is what the client means when it sends a zero count.
func TestSetLayoutsStoresBothHalves(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	setState(t, store, acct.ID, func(st *PlayerState) {
		st.Garage = []GarageVehicle{{CompactDescr: []byte{1, 1, 2}, CrewSize: 4}}
	})
	lay := NewLayouts(store)
	res := lay.SetLayouts(acct.ID, 1, []int64{100, 30, 200, 15}, nil)
	if !res.Ok() {
		t.Fatalf("SetLayouts: %d %s", res.Code, res.Message)
	}
	if len(res.Shells) != 4 || res.Shells[0] != 100 {
		t.Fatalf("shells = %v", res.Shells)
	}
	if res.Eqs != nil {
		t.Fatalf("eqs = %v, want nil", res.Eqs)
	}
	// The consumables half, leaving the shells alone.
	res = lay.SetLayouts(acct.ID, 1, nil, []int64{7, 8})
	if !res.Ok() {
		t.Fatalf("SetLayouts: %d %s", res.Code, res.Message)
	}
	if len(res.Shells) != 4 || len(res.Eqs) != 2 {
		t.Fatalf("shells = %v, eqs = %v", res.Shells, res.Eqs)
	}
	st, err := store.LoadState(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Garage[0].Shells) != 4 || len(st.Garage[0].Eqs) != 2 {
		t.Fatalf("stored shells = %v, eqs = %v", st.Garage[0].Shells, st.Garage[0].Eqs)
	}
}
