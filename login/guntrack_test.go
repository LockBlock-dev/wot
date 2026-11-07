package login

import (
	"math"
	"testing"

	"github.com/LockBlock-dev/wot/entdef"
)

// gunTrackState is a session with the player's tank in it, which is all
// `answerGunTrack` reads.
func gunTrackState() *clientState {
	return &clientState{
		entityID: 42,
		vehicle:  &Entity{ID: 100003, Props: map[string]entdef.Value{}},
		gunSpec:  gunSpec{Turret: 0.4363, Gun: 0.4581, YawMin: -0.5236, YawMax: 0.5236},
	}
}

// The client reports the angles it settled on through an Avatar cell method, so
// the call carries the Avatar's entity id and not the vehicle's. Rejecting it
// left the server aiming at a world point the client had stopped updating, and
// the turret swung away from the settled angle as soon as the hull turned.
//
// The angles it reports are ignored: the reference's `hold_gun` holds the
// SERVER's own (`turret.hold(turret.yaw, turret.pitch)`), because the two step
// at the same rate from the same aim and are already together — adopting the
// client's number would import whatever drift it has accumulated.
func TestStopTrackingWithGunHoldsTheServersAngles(t *testing.T) {
	st := gunTrackState()
	st.aimSet = true
	st.aimWorld = [3]float32{100, 0, 0}
	st.gunYaw, st.gunTarget = -0.2, 0.3

	call := postCall{
		Method:   &entdef.MethodDef{Name: "vehicle_stopTrackingWithGun"},
		Args:     []entdef.Value{{Kind: entdef.VFloat, Float: 0.4}, {Kind: entdef.VFloat, Float: 0.05}},
		EntityID: st.entityID,
	}
	if err := (&BaseAppServer{}).answerGunTrack(nil, nil, st, call); err != nil {
		t.Fatalf("answerGunTrack: %v", err)
	}
	if math.Abs(st.gunYaw+0.2) > 1e-9 {
		t.Fatalf("yaw %v, want the server's own -0.2", st.gunYaw)
	}
	if math.Abs(st.gunTarget+0.2) > 1e-9 {
		t.Fatalf("target %v, want -0.2", st.gunTarget)
	}
	if st.aimSet {
		t.Fatal("aimSet still true: the tick would re-derive a bearing from the stale world point")
	}
}

// A track point is a Vehicle cell method and carries the vehicle's id; it
// switches the tick back to re-deriving the bearing from the world point.
func TestTrackRelativePointSetsAim(t *testing.T) {
	st := gunTrackState()
	st.hull.Direction = [3]float32{0, 0, 0}
	st.hull.Position = [3]float32{10, 0, 10}

	call := postCall{
		Method: &entdef.MethodDef{Name: "trackRelativePointWithGun"},
		Args: []entdef.Value{{Kind: entdef.VSeq, Seq: []entdef.Value{
			{Kind: entdef.VFloat, Float: 0}, {Kind: entdef.VFloat, Float: 0}, {Kind: entdef.VFloat, Float: 20},
		}}},
		EntityID: st.vehicle.ID,
	}
	if err := (&BaseAppServer{}).answerGunTrack(nil, nil, st, call); err != nil {
		t.Fatalf("answerGunTrack: %v", err)
	}
	if !st.aimSet {
		t.Fatal("aimSet false after a track point")
	}
	if want := ([3]float32{10, 0, 30}); st.aimWorld != want {
		t.Fatalf("aimWorld %v, want %v", st.aimWorld, want)
	}
}

// A call addressed to some other entity is not the player's to answer.
func TestGunTrackIgnoresOtherEntities(t *testing.T) {
	st := gunTrackState()
	call := postCall{
		Method:   &entdef.MethodDef{Name: "vehicle_stopTrackingWithGun"},
		Args:     []entdef.Value{{Kind: entdef.VFloat, Float: 0.4}},
		EntityID: 999,
	}
	if err := (&BaseAppServer{}).answerGunTrack(nil, nil, st, call); err != nil {
		t.Fatalf("answerGunTrack: %v", err)
	}
	if st.gunYaw != 0 {
		t.Fatalf("yaw %v, want 0", st.gunYaw)
	}
}
