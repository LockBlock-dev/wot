# Gun-chain probe — run inside the live client, in battle.
#
#   cd pyconsole-client && uv run pyconsole -f ../wot/tools/gun_probe.py
#
# It answers, in one shot, every question the gun depends on:
#
#   * is the client actually in the arena (`isOnArena`), and did
#     `Avatar.setClientReady` get all the way through (`__initProgress`)?
#   * does `VehicleGunRotator` exist, has `update()` ever run
#     (`__speedsInitialized`), and has `start()` taken (`__isStarted`)?
#   * did the `OwnVehicle` component attach, and what `targetingInfo` did it
#     carry? Its setter is what calls `Avatar.updateTargetingInfo`, which is the
#     only thing that sets `__speedsInitialized`.
#   * does the vehicle have a descriptor with real turret/gun limits? Without
#     them `getShotAngles` cannot produce an angle and the gun stays put.
#   * is `ClientArena.vehicles` populated (the minimap and the descriptor both
#     read it)?
#
# Everything is guarded: at the login screen it prints what it can and says so
# rather than raising.
#
# Why each of these matters is in docs/PRIVATE_SERVER.md, "The gun" and
# "Dynamic components"; the NRL type ids are in docs/ENTITY_TYPE_IDS.md.

import traceback

import BigWorld


def show(label, fn):
    try:
        print('%-34s %r' % (label, fn()))
    except Exception:
        print('%-34s <raised>' % label)
        traceback.print_exc()


def private(obj, name):
    return getattr(obj, '_%s%s' % (type(obj).__name__, name))


p = BigWorld.player()
print('player: %r' % (p,))
if p is None:
    print('not logged in — log in and enter a battle, then run this again')
else:
    print('--- avatar')
    show('isOnArena', lambda: p.isOnArena)
    show('__initProgress', lambda: private(p, '__initProgress'))
    show('playerVehicleID', lambda: p.playerVehicleID)
    show('observedVehicleID', lambda: p.observedVehicleID)
    show('arena.period', lambda: p.arena.period)
    show('arena.periodEndTime', lambda: p.arena.periodEndTime)
    show('vehicleTypeDescriptor', lambda: p.vehicleTypeDescriptor)

    print('--- gun rotator')
    g = getattr(p, 'gunRotator', None)
    print('gunRotator: %r' % (g,))
    if g is not None:
        for f in ('__isStarted', '__speedsInitialized', '__timerID', '__time',
                  '__turretYaw', '__gunPitch', '__maxTurretRotationSpeed',
                  '__maxGunRotationSpeed', '__turretRotationSpeed',
                  '__clientMode', '__isLocked', '__dispersionAngles',
                  '__markerInfo', '__gunPosition', '__gunIndex'):
            show(f, lambda f=f: private(g, f))
        show('turretMatrix', lambda: g.turretMatrix)
        show('gunMatrix', lambda: g.gunMatrix)

    print('--- vehicle')
    v = BigWorld.entity(p.playerVehicleID) if p.playerVehicleID else None
    print('vehicle: %r' % (v,))
    if v is not None:
        show('inWorld', lambda: v.inWorld)
        show('isStarted', lambda: v.isStarted)
        show('isPlayerVehicle', lambda: v.isPlayerVehicle)
        show('position', lambda: v.position)
        show('typeDescriptor', lambda: v.typeDescriptor)
        show('publicInfo', lambda: v.publicInfo)
        show('dogTag', lambda: v.dogTag)
        td = getattr(v, 'typeDescriptor', None)
        if td is not None:
            show('turret.name', lambda: td.turret.name)
            show('gun.name', lambda: td.gun.name)
            show('turret.rotationSpeed', lambda: td.turret.rotationSpeed)
            show('gun.rotationSpeed', lambda: td.gun.rotationSpeed)
            show('hull.turretPitches', lambda: td.hull.turretPitches)
            show('turret.gunJointPitch', lambda: td.turret.gunJointPitch)
            show('turret.yawLimits', lambda: td.turret.yawLimits)
            show('gun.pitchLimits', lambda: td.gun.pitchLimits)
            show('gun.shotDispersionFactors',
                 lambda: td.gun.shotDispersionFactors)
            show('isDualgunVehicle', lambda: td.isDualgunVehicle)
        # The component whose targetingInfo setter drives the rotator.
        own = getattr(v, 'ownVehicle', None)
        print('ownVehicle component: %r' % (own,))
        if own is not None:
            show('ownVehicle.targetingInfo',
                 lambda: own.targetingInfo)
            show('ownVehicle.vehicleHealthInfo',
                 lambda: own.vehicleHealthInfo)
            show('ownVehicle.vehicleAmmoList',
                 lambda: own.vehicleAmmoList)
            show('ownVehicle._avatar', lambda: own._avatar())

    print('--- arena')
    show('arena.vehicles keys', lambda: sorted(p.arena.vehicles.keys()))
    show('arena.vehicles[player]',
         lambda: p.arena.vehicles.get(p.playerVehicleID))
    show('ClientArena.__positions',
         lambda: private(p.arena, '__positions'))
    show('arena.period', lambda: p.arena.period)

    print('--- server settings')
    ss = p.lobbyContext.getServerSettings()
    show('isDogTagEnabled', lambda: ss.isDogTagEnabled())
    show('isDogTagInBattleEnabled', lambda: ss.isDogTagInBattleEnabled())
    show('isDogTagsBattleMarkerEnabled',
         lambda: ss.isDogTagsBattleMarkerEnabled())

    print('--- input handler')
    ih = getattr(p, 'inputHandler', None)
    print('inputHandler: %r' % (ih,))
    if ih is not None:
        show('getDesiredShotPoint', lambda: ih.getDesiredShotPoint(False))
        show('getAimingMode', lambda: ih.getAimingMode(0))
