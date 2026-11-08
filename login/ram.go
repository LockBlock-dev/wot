package login

import (
	"math"
	"net"

	"github.com/LockBlock-dev/wot/entdef"
)

// battleLogReasonRam is `ATTACK_REASON_INDICES[ATTACK_REASON.RAM]`: the third
// entry of the client's `ATTACK_REASONS` (shot, fire, ramming, …).
const battleLogReasonRam = 2

// Ramming: two tanks that drive into each other take damage from the
// collision, the lighter one more, and the client is shown the impact.
//
// The game's own formula is not in the shipped Python — the client only plays
// the effect (`Avatar.onCollisionWithVehicle(point, energy)`, and its
// `Vehicle.__getImpulse` normalizes the speed by the tank's top speed for the
// dust and the sound). The damage is the server's, so what is modelled here is
// the physics: the closing speed squared, times the share the other tank's mass
// gives it (`m_other/(m_self+m_other)`), so a heavy tank ramming a light one
// hurts it more than the reverse. `ramFactor` scales that into hit points so
// that two 40-tonne tanks meeting at 30 km/h hurt each other for a couple of
// hundred, which is the order the game shows.

const (
	// ramFactor turns the collision's energy into hit points.
	ramFactor float32 = 6
	// ramMinSpeed is the closing speed below which a contact is a nudge, not a
	// ram, in m/s.
	ramMinSpeed float32 = 1.5
	// ramCooldown is how long one pair of tanks cannot ram each other again,
	// in seconds: the client's own `handleVehicleCollidedVehicle` ignores a
	// repeat within 0.2 s.
	ramCooldown = 0.2
	// ramDefaultMass is the mass a synthetic tank is assumed to have when its
	// defs are not loaded, in kilograms.
	ramDefaultMass float32 = 40000
)

// ramDamage is what a collision at `closing` m/s does to a tank of `mass`
// meeting one of `otherMass`.
func ramDamage(closing, mass, otherMass float32) int {
	if closing < ramMinSpeed || mass <= 0 || otherMass <= 0 {
		return 0
	}
	// The share each side takes is the other's mass against the pair's.
	share := otherMass / (mass + otherMass)
	return int(math.Round(float64(closing * closing * share * ramFactor)))
}

// ramTick checks the player's hull against the synthetic tanks and rams what it
// meets: the victim takes its damage, its health goes out, and the client is
// shown the impact.
func (s *BaseAppServer) ramTick(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, dt float32) {
	s.mu.Lock()
	if st.hull.Airborne || len(st.targets) == 0 || st.avatar == nil || st.vehicle == nil {
		s.mu.Unlock()
		return
	}
	hull := st.hull
	targets := append([]*botTarget(nil), st.targets...)
	avatar := st.avatar
	vehicle := st.vehicle
	attacker := vehicle.ID
	mass := hull.Limits.Weight
	if mass <= 0 {
		mass = ramDefaultMass
	}
	now := st.arenaTime
	st.arenaTime += float64(dt)
	s.mu.Unlock()

	// The player's hull as a circle on the ground plane.
	playerHalf := float32(math.Hypot(
		float64(hullCollisionBounds[1][0]-hullCollisionBounds[0][0])/2,
		float64(hullCollisionBounds[1][2]-hullCollisionBounds[0][2])/2))
	for i, t := range targets {
		if t == nil || t.dead.Load() || t.collision == nil {
			continue
		}
		// The victim's hull as a circle too, from its own collision bounds.
		var botHalf float32
		for _, part := range t.collision.Parts {
			if part.Part != 1 {
				continue
			}
			botHalf = float32(math.Hypot(
				float64(part.Bounds[1][0]-part.Bounds[0][0])/2,
				float64(part.Bounds[1][2]-part.Bounds[0][2])/2))
			break
		}
		if botHalf <= 0 {
			botHalf = 3
		}
		dx := t.pos[0] - hull.Position[0]
		dz := t.pos[2] - hull.Position[2]
		dist := float32(math.Hypot(float64(dx), float64(dz)))
		if dist > playerHalf+botHalf || dist < 1e-3 {
			continue
		}
		// The closing speed along the line between them: the player's own
		// velocity toward the victim, and the victim's toward the player (a
		// synthetic tank stands still, so that is zero).
		nx, nz := dx/dist, dz/dist
		closing := hull.Velocity[0]*nx + hull.Velocity[1]*nz
		if closing < ramMinSpeed {
			continue
		}
		// One ram per pair per cooldown.
		key := t.id
		if last, ok := st.ramAt[key]; ok && now-last < ramCooldown {
			continue
		}
		damage := ramDamage(closing, mass, ramDefaultMass)
		if damage <= 0 {
			continue
		}
		st.ramAt[key] = now
		// The contact point: on the line between the two hulls.
		contact := [3]float32{
			hull.Position[0] + nx*(dist-botHalf),
			hull.Position[1] + 1.0,
			hull.Position[2] + nz*(dist-botHalf),
		}
		s.logf("arena %d: ram: bot %d at %.1f m/s closing, %d damage", arenaID, t.id, closing, damage)
		s.applyRam(conn, from, st, arenaID, avatar, attacker, t, i, contact, closing, float32(damage))
	}
}

// applyRam applies a ram's damage to the victim and tells the client: the
// impact, the victim's health, the shooter's hit marker and the damage log.
func (s *BaseAppServer) applyRam(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, avatar *Entity, attacker uint32, t *botTarget, index int, contact [3]float32, closing, damage float32) {
	s.mu.Lock()
	oldHealth := t.health
	maxHealth := t.maxHealth
	s.mu.Unlock()
	if oldHealth <= 0 {
		return
	}
	if maxHealth <= 0 {
		maxHealth = 1000
	}
	dmg := int(damage)
	newHealth := oldHealth - dmg
	if newHealth < 0 {
		newHealth = 0
	}
	if newHealth > 0 && s.allCrewDead(t) {
		newHealth = 0
	}
	var victimApp, avatarApp []byte
	if el, err := EncodeSelectEntity(t.id); err == nil {
		victimApp = append(victimApp, el...)
	}
	t.entity.SetInt("health", int64(newHealth))
	victimApp = append(victimApp, EncodeBareU16(elVehicleHealth, uint16(newHealth))...)
	if el, err := onHealthChangedElement(t.entity, newHealth, oldHealth, attacker); err == nil {
		victimApp = append(victimApp, el...)
	}
	if newHealth == 0 && dmg > 0 {
		if el := s.killVehiclesInfo(st, t.infoIndex, attacker); len(el) > 0 {
			victimApp = append(victimApp, el...)
		}
	}
	// The shooter's own view: the impact on the hull, the hit marker and the
	// damage log, with the ram as the reason.
	avatarApp = append(avatarApp, EncodeSelectPlayerEntity()...)
	if el, err := onCollisionWithVehicleElement(avatar, contact, closing); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	flags := hitFlagDirect
	if newHealth == 0 && dmg > 0 {
		flags |= hitFlagVehicleKilled
	}
	if el, err := showShotResultsElement(avatar, t.id, flags); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	events := []battleEvent{{
		eventType: battleEventDamage, targetID: t.id,
		details: packDamage(uint64(dmg), uint64(battleLogReasonRam), 0, -1),
		count:   uint16(dmg),
	}}
	if newHealth == 0 && dmg > 0 {
		events = append(events, battleEvent{
			eventType: battleEventKill, targetID: t.id,
			details: packDamage(uint64(dmg), uint64(battleLogReasonRam), 0, -1),
			count:   1,
		})
	}
	if el, err := onBattleEventsElement(avatar, events); err == nil {
		avatarApp = append(avatarApp, el...)
	}
	s.mu.Lock()
	t.health = newHealth
	st.damageDealt += uint32(dmg)
	damageDealt := st.damageDealt
	comp := st.ownVehicle
	s.mu.Unlock()
	if el, err := battleEventsSummaryElement(comp, damageDealt); err == nil {
		avatarApp = append(avatarApp, el...)
	}

	st.sendMu.Lock()
	for _, app := range [][]byte{victimApp, avatarApp} {
		if len(app) == 0 {
			continue
		}
		seq, cumul := s.nextSeq(st)
		if err := s.sendReliableLocked(conn, from, st, app, seq, cumul); err != nil {
			s.logf("arena %d: ram: send failed: %v", arenaID, err)
			break
		}
	}
	st.sendMu.Unlock()
}

// onCollisionWithVehicleElement is `Avatar.onCollisionWithVehicle`: the point
// the two hulls met at and the speed they met at, which the client turns into
// the impact effect and the camera shake.
func onCollisionWithVehicleElement(avatar *Entity, point [3]float32, speed float32) ([]byte, error) {
	args := []entdef.Value{
		vec3Value(point),
		{Kind: entdef.VFloat, Float: float64(speed)},
	}
	return EncodeClientMethodCall(avatar, "onCollisionWithVehicle", args)
}
