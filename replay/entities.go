package replay

// Entity-type table for battle-stream dispatch.
//
// EntityTypeID is 1-based over ClientServerEntities order in
// res/scripts/entities.xml (2.4.0.0): type 6 = Vehicle, 7 =
// AreaDestructibles, 18 = EmptyEntity, 40 = NetworkEntity.
// Method signatures live in methods_gen.go (generated from the
// shipped .defs): fixed-block wires index the size-sorted-stable
// client list (interface methods first, then own), variable-size
// wires use per-version maps. See REPLAY.md §6 for the proof.

// EntityTypes is the 1-based ClientServerEntities order.
var EntityTypes = []string{
	"Account", "Avatar", "ArenaInfo", "ClientSelectableObject",
	"HangarVehicle", "Vehicle", "AreaDestructibles", "OfflineEntity",
	"Flock", "FlockExotic", "Login", "DetachedTurret",
	"DebugDrawEntity", "ClientSelectableCameraObject",
	"ClientSelectableCameraVehicle", "ClientSelectableWebLinksOpener",
	"ClientSelectableEasterEgg", "EmptyEntity", "LimitedVisibilityEntity",
	"HeroTank", "PlatoonTank", "PlatoonLighting", "SectorBase",
	"Sector", "DestructibleEntity", "StepRepairPoint", "ProtectionZone",
	"TeamInfo", "AvatarInfo", "ArenaObserverInfo", "AreaOfEffect",
	"AttackBomber", "AttackArtilleryFort", "PersonalDeathZone",
	"ClientSelectableRankedObject", "SimulatedVehicle",
	"ClientSelectableHangarsSwitcher", "StaticDeathZone", "BasicMine",
	"NetworkEntity",
}

// EntityTypeName maps a 1-based type ID to its name, "" if unknown.
func EntityTypeName(id uint16) string {
	if id == 0 || int(id) > len(EntityTypes) {
		return ""
	}
	return EntityTypes[id-1]
}
