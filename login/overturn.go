package login

import (
	"net"

	"github.com/LockBlock-dev/wot/entdef"
)

// Overturning: a hull that ends up on its side or its roof is out of the
// battle, its crew trapped.
//
// The client reads it from two things, not from the health alone: its
// `VehicleDamageState.getState(health, isCrewActive, isUnderWater)` returns
// `crewDeath` for a positive health with an inactive crew, and `submersionDeath`
// for the same under water. So an overturned tank keeps its hit points and its
// crew goes inactive, with `ATTACK_REASON.OVERTURN` as the death's reason.
//
// Drowning is the same shape with the water flag, but this server has no water
// level: the terrain carries heights only, so a tank cannot be told it is under
// water. That needs the space's water plane.

// battleLogReasonOverturn is `ATTACK_REASON_INDICES[ATTACK_REASON.OVERTURN]`:
// the eighth entry of the client's `ATTACK_REASONS` (shot, fire, ramming,
// world collision, death zone, drowning, gas attack, overturn, …).
const battleLogReasonOverturn = 7

// overturnAngle is how far from level a hull must be to count as overturned,
// in radians: 60 degrees, past any slope it can drive on.
const overturnAngle = 1.047

// checkOverturn overturns the player's tank when it ends up on its side or its
// roof: the crew goes inactive and the client is told, once.
func (s *BaseAppServer) checkOverturn(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64) {
	s.mu.Lock()
	if st.overturned || st.hull.Airborne {
		s.mu.Unlock()
		return
	}
	if abs32(st.hull.Direction[0]) < overturnAngle && abs32(st.hull.Direction[1]) < overturnAngle {
		s.mu.Unlock()
		return
	}
	st.overturned = true
	vehicle := st.vehicle
	avatar := st.avatar
	infoIndex := st.infoPlayer
	s.mu.Unlock()
	if vehicle == nil || avatar == nil {
		return
	}
	s.logf("arena %d: the hull overturned (roll %.2f, pitch %.2f)", arenaID, st.hull.Direction[0], st.hull.Direction[1])
	oldHealth := 0
	s.mu.Lock()
	if hv, ok := vehicle.Props["health"]; ok {
		oldHealth = int(hv.Int)
	}
	s.mu.Unlock()
	var app []byte
	if el, err := EncodeSelectEntity(vehicle.ID); err == nil {
		app = append(app, el...)
	}
	// The crew is what the client reads as the death: `isCrewActive` false
	// with a positive health is `crewDeath`.
	vehicle.SetUint("isCrewActive", 0)
	if el, err := EncodePropertyUpdate(vehicle, "isCrewActive"); err == nil {
		app = append(app, el...)
	}
	if el, err := onHealthChangedElement(vehicle, oldHealth, oldHealth, 0); err == nil {
		app = append(app, el...)
	}
	// The death's reason, which the kill feed and the post-battle read.
	if el, err := EncodeClientMethodCall(vehicle, "onDeath", []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(battleLogReasonOverturn)},
	}); err == nil {
		app = append(app, el...)
	}
	app = append(app, EncodeSelectPlayerEntity()...)
	if el := s.killVehiclesInfo(st, infoIndex, 0); len(el) > 0 {
		app = append(app, el...)
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("arena %d: overturn: %v", arenaID, err)
	}
}
