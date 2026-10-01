// Code generated from 2.4.0.0 entity_defs; DO NOT EDIT.
// Per-entity client-server properties in FullIndex (wire) order.

package replay

// AvatarProps has 28 client-server properties.
var avatarProps = []PropSig{
	{Name: "isObserverFPV", Type: "UINT8"},                                                                  // [0] flags=0x104
	{Name: "numOfObservers", Type: "UINT8"},                                                                 // [1] flags=0x104
	{Name: "arenaBonusType", Type: "UINT8"},                                                                 // [2] flags=0x10c
	{Name: "arenaGuiType", Type: "UINT8"},                                                                   // [3] flags=0x10c
	{Name: "weatherPresetID", Type: "UINT8"},                                                                // [4] flags=0x10c
	{Name: "tkillIsSuspected", Type: "UINT8"},                                                               // [5] flags=0xc
	{Name: "team", Type: "UINT8"},                                                                           // [6] flags=0x104
	{Name: "isObserverBothTeams", Type: "UINT8"},                                                            // [7] flags=0x104
	{Name: "observableTeamID", Type: "UINT8"},                                                               // [8] flags=0x4
	{Name: "isGunLocked", Type: "UINT8"},                                                                    // [9] flags=0x104
	{Name: "ownVehicleGear", Type: "UINT8"},                                                                 // [10] flags=0x104
	{Name: "customizationDisplayType", Type: "UINT8"},                                                       // [11] flags=0x4
	{Name: "shouldSendKillcamSimulationData", Type: "UINT8"},                                                // [12] flags=0x4
	{Name: "denunciationsLeft", Type: "INT16"},                                                              // [13] flags=0xc
	{Name: "ownVehicleHullAimingPitchPacked", Type: "UINT16"},                                               // [14] flags=0x104
	{Name: "battleChatRestriction", Type: "FixedDict{isBattleChatDisabled:UINT8,restrictionReasonID:INT8}"}, // [15] flags=0x10c
	{Name: "arenaTypeID", Type: "INT32"},                                                                    // [16] flags=0x10c
	{Name: "playerVehicleID", Type: "INT32"},                                                                // [17] flags=0x104
	{Name: "arenaUniqueID", Type: "UINT64"},                                                                 // [18] flags=0x10c
	{Name: "ownVehicleAuxPhysicsData", Type: "UINT64"},                                                      // [19] flags=0x104
	{Name: "playLimits", Type: "FixedDict{curfew:INT32,weeklyPlayLimit:INT32,dailyPlayLimit:INT32,sessionLimit:INT32}"}, // [20] flags=0x10c
	{Name: "remoteCamera", Type: "FixedDict{time:FLOAT64,shotPoint:VECTOR3,zoom:UINT8,mode:UINT8}"},                     // [21] flags=0x104
	{Name: "name", Type: "String"},           // [22] flags=0x10c
	{Name: "sessionID", Type: "String"},      // [23] flags=0xc
	{Name: "arenaExtraData", Type: "Python"}, // [24] flags=0x10c
	{Name: "clientCtx", Type: "String"},      // [25] flags=0x10c
	{Name: "ammoViews", Type: "FixedDict{vehTypeCompDescrs:Array[0]{INT32},compDescrs:Array[0]{Array[0]{INT32}}}"},                                                                                                                                             // [26] flags=0x7
	{Name: "goodiesSnapshot", Type: "Array[0]{FixedDict{?goodieID:UINT32,lifetime:UINT16,useby:UINT64,resource:FixedDict{?type:UINT8,value:UINT16,isPercentage:UINT8},stateInfo:FixedDict{?state:UINT8,finishTime:FLOAT64,count:UINT16,expirations:Python}}}"}, // [27] flags=0x10c
}

// VehicleProps has 50 client-server properties.
var vehicleProps = []PropSig{
	{Name: "burnoutLevel", Type: "UINT8"},                                                           // [0] flags=0x7
	{Name: "isStrafing", Type: "UINT8"},                                                             // [1] flags=0x7
	{Name: "isHidden", Type: "UINT8"},                                                               // [2] flags=0x7
	{Name: "physicsMode", Type: "UINT8"},                                                            // [3] flags=0x107
	{Name: "siegeState", Type: "UINT8"},                                                             // [4] flags=0x7
	{Name: "isCrewActive", Type: "UINT8"},                                                           // [5] flags=0x7
	{Name: "customRoleSlotTypeId", Type: "UINT8"},                                                   // [6] flags=0x7
	{Name: "arenaBonusType", Type: "UINT8"},                                                         // [7] flags=0x104
	{Name: "isSpeedCapturing", Type: "UINT8"},                                                       // [8] flags=0x7
	{Name: "isBlockingCapture", Type: "UINT8"},                                                      // [9] flags=0x7
	{Name: "isMyVehicle", Type: "UINT8"},                                                            // [10] flags=0x7
	{Name: "enableExternalRespawn", Type: "UINT8"},                                                  // [11] flags=0x7
	{Name: "botDisplayStatus", Type: "UINT8"},                                                       // [12] flags=0x7
	{Name: "gunAnglesPacked", Type: "UINT16"},                                                       // [13] flags=0x107
	{Name: "health", Type: "INT16"},                                                                 // [14] flags=0x107
	{Name: "engineMode", Type: "Tuple[2]{UINT8}"},                                                   // [15] flags=0x107
	{Name: "avatarID", Type: "INT32"},                                                               // [16] flags=0x7
	{Name: "masterVehID", Type: "UINT32"},                                                           // [17] flags=0x7
	{Name: "arenaTypeID", Type: "INT32"},                                                            // [18] flags=0x104
	{Name: "debuff", Type: "INT32"},                                                                 // [19] flags=0x7
	{Name: "quickShellChangerFactor", Type: "FLOAT32"},                                              // [20] flags=0x7
	{Name: "onRespawnReloadTimeFactor", Type: "FLOAT32"},                                            // [21] flags=0x7
	{Name: "wheelsState", Type: "UINT64"},                                                           // [22] flags=0x7
	{Name: "stunInfo", Type: "FLOAT64"},                                                             // [23] flags=0x7
	{Name: "arenaUniqueID", Type: "UINT64"},                                                         // [24] flags=0x104
	{Name: "remoteCamera", Type: "FixedDict{time:FLOAT64,shotPoint:VECTOR3,zoom:UINT8,mode:UINT8}"}, // [25] flags=0x104
	{Name: "steeringAngles", Type: "Tuple[0]{UINT8}"},                                               // [26] flags=0x7
	{Name: "wheelsScroll", Type: "Tuple[0]{UINT8}"},                                                 // [27] flags=0x7
	{Name: "perkEffects", Type: "FixedDict{equipment:Array[0]{String}}"},                            // [28] flags=0x7
	{Name: "perks", Type: "Array[0]{FixedDict{?perkID:INT32,state:UINT8,coolDown:FLOAT32,lifeTime:FLOAT64}}"}, // [29] flags=0x7
	{Name: "perksRibbonNotify", Type: "Array[0]{FixedDict{?perkID:INT32,endTime:FLOAT64}}"},                   // [30] flags=0x7
	{Name: "postmortemViewPointName", Type: "String"},                                                         // [31] flags=0x7
	{Name: "publicInfo", Type: "FixedDict{name:String,compDescr:String,outfit:String,outfitLevel:UINT8,index:UINT8,team:UINT8,prebattleID:INT32,marksOnGun:UINT8,crewGroups:Array[0]{UINT16},commanderSkinID:UINT16,maxHealth:UINT16,respawnID:UINT32,stFrags:UINT32}"}, // [32] flags=0x7
	{Name: "damageStickers", Type: "Array[0]{FixedDict{networkID:UINT32,segment:UINT64,params:UINT32}}"},                      // [33] flags=0x7
	{Name: "publicStateModifiers", Type: "Array[0]{UINT8}"},                                                                   // [34] flags=0x7
	{Name: "crewCompactDescrs", Type: "Tuple[0]{String}"},                                                                     // [35] flags=0x7
	{Name: "enhancements", Type: "Python"},                                                                                    // [36] flags=0x7
	{Name: "setups", Type: "Python"},                                                                                          // [37] flags=0x7
	{Name: "setupsIndexes", Type: "Python"},                                                                                   // [38] flags=0x7
	{Name: "vehPerks", Type: "Python"},                                                                                        // [39] flags=0x7
	{Name: "vehPostProgression", Type: "Array[0]{INT32}"},                                                                     // [40] flags=0x7
	{Name: "disabledSwitches", Type: "Array[0]{INT32}"},                                                                       // [41] flags=0x7
	{Name: "inspiringEffect", Type: "FixedDict{?radius:FLOAT32,startTime:FLOAT64,endTime:FLOAT64,inactivationDelay:FLOAT32}"}, // [42] flags=0x7
	{Name: "healingEffect", Type: "FixedDict{?radius:FLOAT32,startTime:FLOAT64,endTime:FLOAT64,inactivationDelay:FLOAT32}"},   // [43] flags=0x7
	{Name: "dotEffect", Type: "FixedDict{?endTime:FLOAT64,period:FLOAT32,groupId:UINT8,attackReasonID:UINT8}"},                // [44] flags=0x7
	{Name: "inspired", Type: "FixedDict{?primary:UINT8,startTime:FLOAT64,endTime:FLOAT64,inactivationStartTime:FLOAT64,inactivationEndTime:FLOAT64,inactivationSource:UINT8,equipmentID:UINT16}"},                                                      // [45] flags=0x7
	{Name: "healing", Type: "FixedDict{?senderKey:String,startTime:FLOAT64,endTime:FLOAT64,inactivationStartTime:FLOAT64,inactivationEndTime:FLOAT64}"},                                                                                                // [46] flags=0x7
	{Name: "healOverTime", Type: "FixedDict{?senderKey:String,startTime:FLOAT64,endTime:FLOAT64,inactivationStartTime:FLOAT64,inactivationEndTime:FLOAT64,isInfluenceZone:UINT8}"},                                                                     // [47] flags=0x7
	{Name: "dogTag", Type: "FixedDict{dogTag:FixedDict{components:Array[0]{FixedDict{id:INT32,progress:FLOAT32,grade:INT8}}},defaultDogTag:FixedDict{components:Array[0]{FixedDict{id:INT32,progress:FLOAT32,grade:INT8}}},showDogTagToKiller:UINT8}"}, // [48] flags=0x7
	{Name: "ownVehiclePosition", Type: "FixedDict{?position:VECTOR3,direction:VECTOR3,speed:FLOAT32,rotationSpeed:FLOAT32}"},                                                                                                                           // [49] flags=0x7
}
