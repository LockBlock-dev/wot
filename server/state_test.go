package server

import (
	"context"
	"testing"
)

// TestSeedGarageReplacesAndRaisesSlots pins the seeding contract: the
// garage is REPLACED (a seed is a known, reproducible garage, not a merge)
// and the slot count is raised to fit, because the client's own capacity
// check is `getFreeSlots(stats.vehicleSlots)` — a garage larger than the
// slot count reads as full.
func TestSeedGarageReplacesAndRaisesSlots(t *testing.T) {
	ctx := context.Background()
	store, err := OpenSQLite(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	srv := New(store, Config{DefaultUser: "admin@wot.test", DefaultPassword: "admin"})
	if err := srv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	acct, err := store.AccountByName(ctx, NormalizeName("admin@wot.test"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := srv.State(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if before.Slots != DefaultSlots {
		t.Fatalf("fresh account has %d slots, want %d", before.Slots, DefaultSlots)
	}

	vehicles := make([]GarageVehicle, 0, 1200)
	for i := 0; i < 1200; i++ {
		vehicles = append(vehicles, GarageVehicle{CompactDescr: []byte{0x01, byte(i)}})
	}
	st, err := srv.SeedGarage(ctx, acct.ID, vehicles)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Garage) != len(vehicles) {
		t.Fatalf("garage has %d vehicles, want %d", len(st.Garage), len(vehicles))
	}
	if want := int64(len(vehicles)) + GarageSlotMargin; st.Slots != want {
		t.Fatalf("slots %d, want %d", st.Slots, want)
	}

	// A second, smaller seed replaces rather than merges.
	st, err = srv.SeedGarage(ctx, acct.ID, vehicles[:3])
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Garage) != 3 {
		t.Fatalf("garage has %d vehicles after a smaller seed, want 3", len(st.Garage))
	}
	if st.Slots < 3 {
		t.Fatalf("slots %d, want at least 3", st.Slots)
	}
}
