package login

import (
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// TestVehicleHealthInfoElement pins the OwnVehicle `vehicleHealthInfo` update:
// the player's own health, as the HUD reads it, is a component property
// separate from `Vehicle.health`.
func TestVehicleHealthInfoElement(t *testing.T) {
	enterTestServer(t) // loads the defs and their aliases
	if entdef.Alias("VEHICLE_HEALTH_INFO") == nil {
		t.Skip("no VEHICLE_HEALTH_INFO alias")
	}
	comp := nrlComponent{TypeID: OwnVehicleNrlID, Node: 10, FirstChild: 11, Props: len(ownVehicleProps)}
	el, err := vehicleHealthInfoElement(comp, 100003, 1248, true)
	if err != nil {
		t.Fatalf("vehicleHealthInfoElement: %v", err)
	}
	if len(el) == 0 {
		t.Fatal("empty element")
	}
	// The value carries the vehicle id and the health.
	v := vehicleHealthInfoValue(100003, 1248, true)
	if f, ok := v.Get("id"); !ok || f.Int != 100003 {
		t.Fatalf("id = %+v, want 100003", f)
	}
	if f, ok := v.Get("health"); !ok || f.Int != 1248 {
		t.Fatalf("health = %+v, want 1248", f)
	}
	if f, ok := v.Get("isCrewActive"); !ok || f.Uint != 1 {
		t.Fatalf("isCrewActive = %+v, want true", f)
	}
}
