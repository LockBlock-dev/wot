package login

import (
	"fmt"
	"net"
	"time"

	"github.com/LockBlock-dev/wot/entdef"
)

// Fires, for the synthetic opponent.
//
// A fire is not a property: it is a dynamic component. The client's `Fire`
// (`scripts/client/Fire.py`) is a `BigWorld.DynamicScriptComponent` whose
// `fireInfo` property carries who set it alight and with what, and whose
// creation is what starts the flame effect — `isOnFire()` is literally
// `'fire' in self.dynamicComponents`. So the server attaches the `Fire`
// component to the burning vehicle's NRL node and unlinks it to put the fire
// out.
//
// The component's type id is 64 (`docs/ENTITY_TYPE_IDS.md`) and its one
// property is `fireInfo`, a `FIRE_INFO`:
// `{deviceExtraIndex, notificationIndex, attackerID, equipmentID, startTime}`.
// `notificationIndex` indexes `FIRE_NOTIFICATION_CODES`
// (`DEVICE_STARTED_FIRE_AT_SHOT` is 0).
const (
	// FireNrlID is the client's `Fire` dynamic component.
	FireNrlID uint16 = 64
	// fireNotificationShot is `FIRE_NOTIFICATION_CODES` index 0,
	// `DEVICE_STARTED_FIRE_AT_SHOT`.
	fireNotificationShot uint8 = 0
	// fireDuration is how long a fire burns before it goes out on its own.
	fireDuration = 10 * time.Second
	// fireBurnShare is the share of the tank's max health a fire takes per
	// second. The game's own rate is a server-side `healthBurnPerSec` the item
	// defs do not ship; 1% a second is the game's order of magnitude.
	fireBurnShare = 0.01
)

// fireStart is what a module hit asks for when it sets the tank alight.
type fireStart struct {
	// Extra is the module that started it (the engine or fuel tank).
	Extra int
	// Attacker is the entity that fired the shot.
	Attacker uint32
}

// fireInfoValue is the `FIRE_INFO` the `Fire` component carries.
func fireInfoValue(extraIndex int, attacker uint32, start time.Time) entdef.Value {
	return entdef.Value{Kind: entdef.VDict, Dict: []entdef.DictField{
		{Name: "deviceExtraIndex", Value: entdef.Value{Kind: entdef.VInt, Int: int64(extraIndex)}},
		{Name: "notificationIndex", Value: entdef.Value{Kind: entdef.VUint, Uint: uint64(fireNotificationShot)}},
		{Name: "attackerID", Value: entdef.Value{Kind: entdef.VInt, Int: int64(attacker)}},
		{Name: "equipmentID", Value: entdef.Value{Kind: entdef.VUint}},
		{Name: "startTime", Value: entdef.Value{Kind: entdef.VFloat, Float: float64(start.Unix())}},
	}}
}

// startFireElement attaches the `Fire` component to the dummy and returns the
// element plus the component's node, which is what puts it out.
func (s *BaseAppServer) startFireElement(st *clientState, dummyID uint32, extraIndex int, attacker uint32) ([]byte, uint16, error) {
	s.mu.Lock()
	alloc := st.nrlAlloc
	s.mu.Unlock()
	if alloc == nil {
		return nil, 0, fmt.Errorf("no NRL allocator")
	}
	s.mu.Lock()
	app, comp, err := EncodeNrlAttachComponentAt(alloc, dummyID, FireNrlID,
		[]nrlProp{{Name: "fireInfo", Type: "FIRE_INFO"}}, 0,
		map[string]entdef.Value{"fireInfo": fireInfoValue(extraIndex, attacker, time.Now())})
	s.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	return app, comp.Node, nil
}

// burnFire runs the fire: every second it takes `fireBurnShare` of the tank's
// max health and tells the client with `onHealthChanged` under the FIRE attack
// reason, then puts the fire out (unlinks the component).
//
// It stops when the battle does, like the reload's completion timer.
func (s *BaseAppServer) burnFire(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, dummy *Entity, dummyID uint32, attacker uint32, fireNode uint16) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	deadline := time.Now().Add(fireDuration)
	for now := range tick.C {
		s.mu.Lock()
		live := st.arena != nil && st.arena.ArenaID == arenaID
		health := st.dummyHealth
		maxHealth := st.dummyMaxHealth
		s.mu.Unlock()
		if !live {
			return
		}
		burn := int(float32(maxHealth) * fireBurnShare)
		if burn < 1 {
			burn = 1
		}
		newHealth := health - burn
		if newHealth < 0 {
			newHealth = 0
		}
		s.mu.Lock()
		st.dummyHealth = newHealth
		s.mu.Unlock()
		dummy.SetInt("health", int64(newHealth))
		var app []byte
		app = append(app, EncodeBareU16(elVehicleHealth, uint16(newHealth))...)
		if el, err := onHealthChangedReasonElement(dummy, newHealth, health, attacker, attackReasonFire); err == nil {
			app = append(app, el...)
		}
		if newHealth == 0 {
			if el := s.killVehiclesInfo(st, dummyID, attacker); len(el) > 0 {
				app = append(app, el...)
			}
		}
		st.sendMu.Lock()
		seq, cumul := s.nextSeq(st)
		err := s.sendReliableLocked(conn, from, st, app, seq, cumul)
		st.sendMu.Unlock()
		if err != nil {
			s.logf("arena %d: fire burn send: %v", arenaID, err)
			return
		}
		s.logf("arena %d: fire burns %d (health %d -> %d)", arenaID, burn, health, newHealth)
		if newHealth == 0 || now.After(deadline) {
			s.stopFire(conn, from, st, arenaID, fireNode)
			return
		}
	}
}

// stopFire puts the fire out: the `Fire` component is unlinked, which is what
// the client's `Fire.onDestroy` sees.
func (s *BaseAppServer) stopFire(conn Transport, from *net.UDPAddr, st *clientState, arenaID uint64, fireNode uint16) {
	el, err := EncodeNrlUnlinkTree(fireNode)
	if err != nil {
		return
	}
	st.sendMu.Lock()
	seq, cumul := s.nextSeq(st)
	err = s.sendReliableLocked(conn, from, st, el, seq, cumul)
	st.sendMu.Unlock()
	if err != nil {
		s.logf("arena %d: fire stop send: %v", arenaID, err)
		return
	}
	s.logf("arena %d: fire out", arenaID)
}

// attackReasonFire is `ATTACK_REASON_INDICES[ATTACK_REASON.FIRE]`: the second
// entry of `ATTACK_REASONS`, after SHOT.
const attackReasonFire uint8 = 1

// onHealthChangedReasonElement is `Vehicle.onHealthChanged` under an arbitrary
// attack reason (the shot's is 0, a fire's 1).
func onHealthChangedReasonElement(vehicle *Entity, newHealth, oldHealth int, attacker uint32, reason uint8) ([]byte, error) {
	args := []entdef.Value{
		{Kind: entdef.VInt, Int: int64(newHealth)},
		{Kind: entdef.VInt, Int: int64(oldHealth)},
		{Kind: entdef.VInt, Int: int64(attacker)},
		{Kind: entdef.VUint, Uint: uint64(reason)},
		{Kind: entdef.VInt, Int: -1},
	}
	return EncodeClientMethodCall(vehicle, "onHealthChanged", args)
}
