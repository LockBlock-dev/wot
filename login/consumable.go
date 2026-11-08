package login

import (
	"math"
	"net"

	"github.com/LockBlock-dev/wot/entdef"
)

// Consumables: the client's `Avatar.cell.activateEquipment(equipmentID, index)`
// and, for the ones aimed at a point, `setEquipmentApplicationPoint(id, point,
// dir)`.
//
// What a consumable does is the server's: the client only sends the id and,
// for the aimed ones (artillery, smoke), where it wants it. This server models
// the aimed ones — an artillery strike damages every synthetic tank in its
// blast, through the same explosion model an HE shell uses — and acknowledges
// the rest, whose effects (repairing a module, putting out a fire, healing a
// crew) need the player's own damage model, which this server does not have
// yet: nothing can damage the player's tank, so there is nothing to repair.
//
// The equipment's own radius and damage come from its item def when the defs
// carry them; the fallbacks are a 105 mm shell's blast and damage.

const (
	// equipmentBlastRadius is the fallback blast radius of an aimed consumable,
	// in metres.
	equipmentBlastRadius float32 = 6
	// equipmentDamage is the fallback damage at the centre of the blast.
	equipmentDamage float32 = 400
)

// answerActivateEquipment handles `activateEquipment`: it remembers the id so
// the application point that follows can use it, and acknowledges the use.
func (s *BaseAppServer) answerActivateEquipment(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if len(call.Args) == 0 || call.Args[0].Kind != entdef.VUint {
		return nil
	}
	id := uint16(call.Args[0].Uint)
	s.mu.Lock()
	st.equipmentID = id
	s.mu.Unlock()
	s.logf("arena: activateEquipment %d", id)
	return nil
}

// answerEquipmentPoint handles `setEquipmentApplicationPoint`: an aimed
// consumable lands at the point the client picked. An artillery strike damages
// every synthetic tank in its blast.
func (s *BaseAppServer) answerEquipmentPoint(conn Transport, from *net.UDPAddr, st *clientState, call postCall) error {
	if len(call.Args) < 2 || call.Args[1].Kind != entdef.VSeq || len(call.Args[1].Seq) < 3 {
		return nil
	}
	point := [3]float32{}
	for i := 0; i < 3; i++ {
		point[i] = float32(call.Args[1].Seq[i].Float)
	}
	s.mu.Lock()
	id := st.equipmentID
	avatar := st.avatar
	targets := append([]*botTarget(nil), st.targets...)
	vehicle := st.vehicle
	s.mu.Unlock()
	if avatar == nil || vehicle == nil {
		return nil
	}
	// The client's own "the equipment went off" call, for the effect.
	var app []byte
	app = append(app, EncodeSelectPlayerEntity()...)
	if el, err := EncodeClientMethodCall(avatar, "onCombatEquipmentShotLaunched", []entdef.Value{
		{Kind: entdef.VUint, Uint: uint64(id)},
		vec3Value(point),
	}); err == nil {
		app = append(app, el...)
	}
	if len(app) > 0 {
		st.sendMu.Lock()
		seq, cumul := s.nextSeq(st)
		err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
		st.sendMu.Unlock()
		if err != nil {
			s.logf("arena: equipment launch: %v", err)
		}
	}
	// The blast: the same explosion model an HE shell uses, at the point.
	sh := shellSpec{
		Kind: "HIGH_EXPLOSIVE", KindIndex: 1,
		Damage: float64(equipmentDamage), DamageNear: float64(equipmentDamage), DamageFar: float64(equipmentDamage),
		ExplosionRadius: float64(equipmentBlastRadius), Caliber: 105,
	}
	for i, t := range targets {
		if t == nil || t.dead.Load() {
			continue
		}
		damage, hit, ok := explosionAt(sh, point, t.collision, t.pos, t.yaw)
		if !ok || damage <= 0 {
			continue
		}
		dir := [3]float32{hit.Point[0] - point[0], hit.Point[1] - point[1], hit.Point[2] - point[2]}
		if l := dist3(hit.Point, point); l > 1e-6 {
			dir = [3]float32{dir[0] / l, dir[1] / l, dir[2] / l}
		}
		res := shotResult{
			Hit: true, Target: i, Point: hit.Point, Normal: dir,
			Distance: dist3(point, hit.Point), Part: hit.Part, Bounds: hit.Bounds,
			Local: hit.LocalPoint, LocalDir: dir, LocalNormal: dir,
			Face:    faceOf(hit.LocalNormal),
			Pierced: false,
			Damage:  int(math.Round(float64(damage))),
			Effect:  hitEffectNotPierced,
			Flags:   hitFlagDirect | hitFlagExploded,
		}
		s.logf("arena: equipment %d blast %.1f m from bot %d: %d damage", id, res.Distance, t.id, res.Damage)
		s.applyDamage(conn, from, st, 0, sh, 0, vehicle.ID, vehicle, avatar, nrlGunMarker{}, t, res)
	}
	return nil
}
