package login

import (
	"bytes"
	"fmt"

	"github.com/LockBlock-dev/wot/entdef"
)

// The OwnVehicle component's `vehicleHealthInfo`.
//
// The player's own health reaches the client twice: as the `Vehicle.health`
// property, which every client sees, and as this component property, which is
// what the player's own HUD reads (the reference's `set_vehicleHealthInfo`).
// The two are separate wire paths and the official server sends both.
//
// `VEHICLE_HEALTH_INFO` is `{id, health, deathReasonID, isCrewActive,
// isRespawnActive, deathReasonExtID}` (`alias.xml`).
func vehicleHealthInfoValue(vehicleID uint32, health int, crewActive bool) entdef.Value {
	return entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		// OBJECT_ID is INT32 in the defs, so the id rides signed.
		{Name: "id", Value: entdef.Value{Kind: entdef.VInt, Int: int64(vehicleID)}},
		{Name: "health", Value: entdef.Value{Kind: entdef.VInt, Int: int64(health)}},
		{Name: "deathReasonID", Value: entdef.Value{Kind: entdef.VInt, Int: -1}},
		// Both are UINT8 in the defs, 0 or 1.
		{Name: "isCrewActive", Value: entdef.Value{Kind: entdef.VUint, Uint: boolUint(crewActive)}},
		{Name: "isRespawnActive", Value: entdef.Value{Kind: entdef.VUint}},
		{Name: "deathReasonExtID", Value: entdef.Value{Kind: entdef.VInt, Int: -1}},
	}}
}

// boolUint is 1 for true, 0 for false.
func boolUint(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

// vehicleHealthInfoElement builds the NRL property update that sets the
// OwnVehicle component's `vehicleHealthInfo`.
func vehicleHealthInfoElement(comp nrlComponent, vehicleID uint32, health int, crewActive bool) ([]byte, error) {
	dt := entdef.Alias("VEHICLE_HEALTH_INFO")
	if dt == nil {
		return nil, fmt.Errorf("no VEHICLE_HEALTH_INFO alias")
	}
	idx := ownVehiclePropIndex("vehicleHealthInfo")
	if idx < 0 {
		return nil, fmt.Errorf("OwnVehicle has no vehicleHealthInfo property")
	}
	var buf bytes.Buffer
	if err := entdef.NewCodec().Write(&buf, dt, vehicleHealthInfoValue(vehicleID, health, crewActive)); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	return EncodeNrlPropertyUpdate(comp, idx, buf.Bytes())
}
