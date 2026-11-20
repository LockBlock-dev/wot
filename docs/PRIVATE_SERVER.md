# Private server — architecture and status

Scope: everything up to and including the lobby. **Matchmaking, queue,
battle and post-battle are explicitly out of scope** for now — they are
the most complex part and are not modelled here.

## Client build: 2.4.1.1

**The build in use is World of Tanks EU 2.4.1.1 (#993)** — the Steam install
under `~/.local/share/Steam/steamapps/common/World of Tanks/eu`. Every def
tree the server loads must be that build's:

| what | where it comes from |
|---|---|
| entity defs (`Vehicle.def`, `Account.def`, …) | `../scripts-2.4.1/entity_defs`, extracted from the live `res/packages/scripts.pkg` (2.4.1.0, and `Vehicle.def` is byte-identical in 2.4.1.1) |
| component/alias/space defs, mode entities | `../wotdefs-2.4.1/` |
| item defs (vehicles, guns, shells, damage stickers, arena defs) | the live `res/packages/scripts.pkg` → `scripts/item_defs/…`, read in place by `login`/`lobby` |
| client Python sources (settings generator, client behaviour) | the same `scripts.pkg`, extracted |
| client binary (IDA) | `World_of_Tanks_EU/2.4.1.0/win64/WorldOfTanks.exe` (same build as the live exe) |

The `World_of_Tanks_EU/2.4.0.0` tree is **historical**: it is the 2.4.0
capture/analysis tree, kept for the archived captures and the closed 2.4.0
digest oracle. Do not generate anything the server ships from it — a table
built from the wrong tree is silently accepted by the server and rejected by
the client, which is how a 2.4.0-generated garage produced 1238 vehicles with
descriptors that did not match and the client's inventory validator dropped
the account back to login (`compact descriptor to XML mismatch`).

## Layers

```
cmd/wotserver        CLI: flags, wiring, lifecycle
  server/            application layer — accounts, sessions, player state
    login/           wire layer — LoginApp + BaseApp halves
    lobby/           protocol codecs — pickles, commands, battle records
```

`login/` decides what the bytes are. `server/` decides what they mean.
Nothing above `server/sqlite.go` knows SQL exists.

## The stage-2 bundle is authored, not replayed

Nothing in the server reads a capture any more. The flood bundle is built
from the entity defs and the server's own settings document:

| layer | what it does |
|---|---|
| `login.FloodBundle` | the ClientInterface stream: `updateFrequencyNotification`, `tickSync`, then the `createBasePlayer` element carrying the Account entity |
| `entdef.Entity.WireProps` | the property order the wire uses (interfaces first, then declaration) — **not** the digest's FullIndex sort |
| `login.elementOversize` | the engine's special length form (`FF FF` + u32 + the four displaced bytes at the end) for a payload past 64 KB |
| `login.BuildFrames` | the fragment chain (or one plain frame when the bundle fits a datagram — the client refuses a one-fragment chain) |
| `server.SettingsFromJSON` | the `initialServerSettings` pickle, from `wotserver.settings.json` |

`TestFloodBundleMatchesCapture` pins the encoder against the genuine
2.4.1 flood: given the capture's own settings pickle it reproduces the
246 531 B stream byte for byte. The capture is a test fixture only.

The post-flood smalls are authored too (`login/lobby_content.go`): the
session dict (1a/76), the revisions answer (1a/5f), the server-stats
answer (1a/5b), the command error (1a/5e) and the queue census (1a/67).

### The stage-2 sequence

The whole stage-2 stream is one contiguous reliable seq space — the
client's channel delivers IN ORDER, so a gap stalls everything after it
(the frames sit in the receive window, are never ACKed, and the server
resends until the peer times out):

| seq | frame |
|---|---|
| 0 | rotation-2 (`[FF][len=8][rid][newkey]`) |
| 1..N | the flood chain (fragment frames, or one plain frame when the bundle fits a datagram — the client refuses a one-fragment chain: `Packet::stripFragInfo: Illegal fragment count (1)`) |
| N+1 | `[13][40]` + `selectPlayerEntity` + `showGUI` (the session dict is showGUI's argument) |
| N+2 | `selectPlayerEntity` + `onUnitBrowserResultsUpdate` (the account's free XP) |
| N+3… | the tick stream (`[13][tag]`, tag ramping from 0x7a) |

**`0x1A` is `selectPlayerEntity`, not a "login-app small".** The exe's
message-name table settles it: `tickSync` is 19 = `0x13` and
`selectPlayerEntity` is 26 = `0x1A`, so every `1a XX …` in a genuine
capture is `selectPlayerEntity` (FIXED 0) followed by a **client method
call** — `XX` = `entityMethodBase (0x4E) + method id`. `0x76` is showGUI
(id 40) and `0x69` is `onUnitBrowserResultsUpdate` (id 27).

A client method call's framing is
`[elemID][elementLen][stringLen][string]`, where the method's
`VariableLengthHeaderSize` is the width of the **element** length and the
string's own header is always **one** byte. The genuine elements are
`1a 76 9c 00 9b <155B>` (0x9c = 156 = 1 + 155, 0x9b = 155) and
`1a 69 44 43 <67B>` (0x44 = 68 = 1 + 67, 0x43 = 67). Writing a fixed
"status" byte where the string length belongs makes the client read past
the element — `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_` in
`MemoryIStream::retrieve`.

`showGUI` is the one that matters: without it the client sits in the
loading screen with the lobby app up and never creates the hangar app.
It rides the same frame as `selectPlayerEntity`, once — the genuine
server does not send it twice. Its `STRING` argument is a **pickle**, not text — `Account.showGUI` does
`ctx = pickle.loads(ctx)` and then reads `databaseID` (required),
`serverUTC`, `inQueue`, `prebattleID` and `isLongDisconnectedFromCenter`
out of the dict. The live game.log shows the argument is the *same seven
keys as the 1a/76 session dict* (account id redacted):

```
[Account] showGUI {'serverUTC': 1792239378.848033, 'databaseID': 123456789,
 'aogasStartedAt': 1792236144.737068, 'sessionStartedAt': 1792236144,
 'isAogasEnabled': True, 'collectUiStats': True, 'logUXEvents': False}
```

so both are minted from one builder (`sessionDictDoc`).

### The sync answer

`CMD_SYNC_DATA` (100) is answered with the 1a/5f small, whose body is
`[request id u32][status 0][pickle length][pickle]`. The pickle has two
forms, and the client picks by the presence of `prevRev`
(`AccountSyncData.isFullSyncDiff` is `diff.get('prevRev') is None`):

| client state | answer |
|---|---|
| revision 0 (no account cache) | **full sync**: `{rev, stats: {credits, gold, crystal, eventCoin, bpcoin, equipCoin, freeXP}, inventory: {1: {compDescr: {invID: compDescr}, postProgression: {}}}}`, no `prevRev` |
| revision > 0 | **diff**: `{rev, prevRev}`, nothing changed |

The `stats` keys are `Currency.ALL` + `freeXP` (`gui/shared/money.py`,
`account_helpers/Stats.py`). The garage rides the same diff under
`inventory`, keyed by item type index (`items.ITEM_TYPE_NAMES`: 1 =
vehicle, 8 = optionalDevice, …), each entry `{invID: {compDescr, …}}`.

**Item type 1 must be present even when the garage is empty.**
`InventoryRequester._response` does
`invData[GUI_ITEM_TYPE.VEHICLE]['compDescr']` unconditionally, so a full
sync without it raises `KeyError(1)` and the hangar's items-cache sync
aborts — the loading screen never advances past `SHOW GUI`. `compDescr`
is keyed by instance id (int) and its values are py2 `str` (bytes), not
text.

### The settings document

`initialServerSettings` is the lobby's server config. The client reads it
in `helpers/server_settings.py`:

* most keys are optional — `set()` guards each with `if key in settings`,
  so a missing key keeps the client's default;
* the keys read through the schema manager (`getConfigModel`) are **not**
  optional: a missing key raises and the app_loader's predicate chain
  aborts before the hangar app is created;
* a few keys are read directly (`settings['key']`) and raise KeyError;
* the namedtuple-backed configs go through `makeTupleByDict`, which calls
  `cls(**data)` — an empty object raises unless the namedtuple carries
  `__new__.__defaults__` or a `__new__(cls, **kwargs)` (or all-defaulted
  `__new__` signature);
* `winback_config` is handed to `_logger.info(msg, value)`, and
  `logging.LogRecord.__init__` unwraps a single **non-empty** mapping
  argument (`args = args[0]`). A non-empty dict formats fine (the message
  has no `%(key)s`, and a mapping argument is left alone); an **empty**
  dict is falsy, stays wrapped in a tuple, and `'winback_config' % ({},)`
  raises `TypeError: not all arguments converted during string
  formatting`. So that key must never be emitted as `{}`.

The failure is fatal for the whole document:
  `set()` raises, `ServerSettings.__init__` never returns, the client
  keeps **no** settings at all, and because `set()` also ends with
  `self.__schemaManager.set(...)` the schema models stay empty — which is
  what turns into the *second* symptom, `SoftException('Schema
  story_mode_settings was not registered')` from the app_loader's
  predicate chain. One bad key produces both errors.

`tools/gen_server_settings.py` extracts exactly what is required from the
shipped bytecode and writes `wotserver.settings.json`:

* every `gameParamsKey` schema with its `required=True` fields — from
  `res/scripts` **and every** `res/packages/*.pkg` (the halloween package
  carries four `usedInReplay=True` schemas and BattleReplay does
  `serverSettings[key]` for each, so a missing one is a KeyError on every
  account-become-player; its keys are spelled through a constants module
  that lives in a *different* package, so the constants are harvested
  across all packages first). A field class spelled without the `fields.`
  prefix (`'enabled': (Boolean(required=True))`, as
  `hints_common/prebattle/schemas.py` does) counts too — missing it left
  `prebattle_hints_config` empty and the schema manager raised
  `ValidationError: Required attribute: enabled missing`. A field with no
  `default=` is required in practice even without `required=True`
  (`umgMissions`/`umgEvents` declare `weights` that way), so every
  declared scalar/list field is emitted; an OPTIONAL `Nested` field whose
  sub-schema cannot be expanded is left out rather than sent as `{}`
  (fort_rush's `battle`/`squadRestrictions`), and a required one is
  expanded through `Schema[...](fields={...})` — including the positional
  `fields.Nested(X, ...)` form, and a field spelled
  `'win': (_helperFunction())` is resolved through the helper's
  `return fields.X(...)`. The value must also match the field's
  TYPE: `Dict._convert` does `viewitems(incoming)` (an int there is an
  AttributeError) and `ListFromString` splits a STRING (a list there is a
  TypeError), so dict-ish fields get `{}`, list-ish `[]`, `ListFromString`
  `""`, and a `default=_CONSTANT` is resolved from the module. Two
  wire forms are not what the declared default suggests: `ListFromString`
  takes a STRING (`default=list` is the post-deserialize default, so a
  list is "Unsupported string type") and `DateTime` takes an ISO-8601
  string (`utils.fromIso`; an int is "Cannot be formatted as a
  datetime");
* the keys the mode packages append to `constants.INBATTLE_CONFIGS` at
  import time (`comp7_common/__init__` extends it with
  `COMP7_INBATTLE_CONFIGS`, `comp7_light` with `COMP7_LIGHT_INBATTLE_CONFIGS`,
  `fun_random` appends `FUN_GAME_PARAMS_KEY`). BattleReplay iterates
  `getUsedInReplaysConfigKeys()` = the `usedInReplay` schema set **plus**
  that list, so the five literals in `constants.py` are not the whole
  story;
* for every key `set()` builds with `makeTupleByDict`, the class's own
  `defaults()` values when `cls(**{})` would raise, and `{}` when it
  would not — so the document never carries a config the client cannot
  construct;
* the keys read directly (`vehicle_post_progression_config` via
  `post_progression_common.SERVER_SETTINGS_KEY`, `file_server`, …).

Regenerate it when the client build changes:

```sh
# The scripts tree must be the build the client runs (2.4.1.1): extract
# scripts/ from the live res/packages/scripts.pkg first.
tools/gen_server_settings.py \
  --scripts /tmp/scripts-2.4.1.1/scripts \
  --packages ~/.local/share/Steam/steamapps/common/"World of Tanks"/eu/res/packages \
  --out wotserver.settings.json
```

## What works today

- **LoginApp** — full handshake (PoW, digest gate, `LOGGED_ON`), now with
  **real credential checking** against the account store. A refusal
  rides status 68 with the live server's short wording
  (`Invalid password.`).
- **Accounts** — bcrypt hashes (`x/crypto`), case-insensitive names,
  roles column.
- **Sessions** — random non-zero u32 keys, TTL, in-memory only (a
  restart invalidates them, which is what the client expects).
- **Player state** — credits/gold/free XP, garage, research; stored as a
  JSON document so the model can grow without migrations.
- **Provisioning** — one default account (`-user`/`-pass`, default
  `admin@wot.test` / `admin`) created on startup when absent. Idempotent:
  a restart never resets progress.
- **Login names are emails.** The client's login form validates the name
  against its own pattern before sending anything
  (`external_strings_utils.LOGIN_NAME_RE`, 2.4.1.1):
  `^[a-z0-9_-]+(\.[a-z0-9_-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,4}$`.
  A bare `admin` is refused client-side — "invalid login", no datagram
  leaves the machine. `server.LoginNameValid` mirrors the pattern, and
  `Provision` / `wotaccounts add` warn when a name cannot be typed in.
- **Token logins** — a Steam build authenticates with a token2 and sends
  `login: ""`, so there is no name to look up. `-token-account` (default:
  the default account) lands those logins on a named account, and
  `ServerConfig.TokenLogin` resolves it **without a password check** —
  the token is the credential, and the document carries no password at
  all. A document with a real `login` is never redirected, so a typed
  username stays authoritative. Verified end to end with
  `wotlogin -token2 TOKEN -baseapp`: `LOGGED_ON` → stage-2 → flood →
  lobby syncs. `mods/login-credentials-mod` restores the credential
  fields for the custom server when several accounts are needed from one
  client.
- **Remember me** rides the same token2. The LOGGED_ON mints one and
  `ServerConfig.OnTokenIssued` hands it to the account store
  (`SetRememberToken`); the next login presents it in the identity
  document's `token2` field, and `TokenLogin` resolves that stored token
  back to its account without a password. The new LOGGED_ON overwrites
  it — single-use-forward, so an old value stops matching. A first login
  with no stored token falls back to `-token-account`.
- **BaseApp stage-1/2** — the staged dance, the authored flood bundle,
  the authored post-flood chain.
- **Social** — friends, ignores, notes, blocking, private messages, the
  clan channel, clan membership, squads and invitations. See the next
  section.
- **In battle** — the tank drives (hull simulated server-side, position by
  alias, tracks and tacho from the aux word), the turret and gun follow the
  aim, the gun fires and reloads, the saved ammunition layout is the one
  shown, wheeled vehicles' wheels turn, siege mode toggles both ways, the
  handbrake stops the tank, and the engine, gun and track sounds play. What
  is still missing is listed under "Collisions (PARKED)" and "The speedometer".

## Social

The social half of the client is **XMPP**, not the game channel. In 2.4
`messenger/proto/__init__.pyc` `ServerSettings.useToShowContacts` returns
true for `PROTO_TYPE.XMPP` exactly when `xmpp_enabled` is set in the
server-settings document; the legacy BW fallback calls
`BigWorld.player().addFriend(...)` / `requestUsersRoster()`, methods that
do not exist in the 2.4 entity defs, so with XMPP off the contacts UI can
never populate. The client's transport is `BigWorld.XmppClient`, a gloox
wrapper, so the wire is plain XMPP.

`xmppserver` is that service (the offline builders stay in `xmpp`,
which performs no I/O):

| Piece | What it answers |
| --- | --- |
| stream + SASL PLAIN | the credential is the XMPPCS token the BaseApp mints (`requestToken` → `onTokenReceived`), a per-run HMAC of the client databaseID |
| `jabber:iq:roster` | get, set and the push that makes `onNewRosterItem` fire |
| `urn:xmpp:blocking` | the ignore list (`blocklist`, `block`, `unblock`) |
| `http://wargaming.net/xmpp#storage` | contact notes, paged with a result-set count |
| `http://wargaming.net/xmpp#spa-resolver` | nickname lookup by databaseID |
| presence | relayed with a server-authored `wgexts` block (`nickname`, `userid`, `clanid`, `clantag`) — the client's own presence carries only `wgexts-client` |
| XEP-0045 MUC | the clan channel (`clan_<clanDBID>@clans.<domain>`) and user rooms |
| disco#info / #items | the service identity and the MUC hosts |

Roster, block list and notes persist in the `social` table, keyed by the
client databaseID (the JID node).

**Clans.** The game protocol carries the membership, not the clan
service: `account.clanDBID` and `stats.clanInfo` — the client's own
5-tuple `ClanInfo(clanName, clanAbbrev, chatChannelDBID, memberFlags,
enteringTime)` from `gui/clans/clan_cache.pyc` — plus
`Account.onClanInfoReceived` for the motto and description, and the clan
MUC channel. `-clan-tag` (default `ADMIN`) seeds the default account into
a clan on startup, the same way `-garage-all` seeds the garage. The clan
profile *window* is served by the WG web API (`webCtrl.sendRequest`), so
it stays empty; see `TODO.md` #8.

**Squads.** The client's unit manager is a thin RPC layer:
`accountUnitClient_create/join/doCmd/sendInvites/setRosterSlots` in,
`Account.onUnitUpdate(unitMgrID, packedUnit, packedOps)` out. Both blobs
are the client's own binary format (`common/UnitBase.pyc` `pack` and
`common/ops_pack.pyc`), reproduced field for field in `lobby/unit.go`:
`_IDS '<IBB'`, the roster, `_HEADER '<HHHHHHHHBiiiiii'`,
`_PLAYER_VEHICLES_LIST '<qH'`, `_SLOT_PLAYERS '<Bq'`,
`_PLAYER_DATA '<qiIHBHHHq?'`, pascal strings, the two-byte empty badge
block and a pascal-framed pickled empty dict. `server.UnitManager` holds
the state (one squad per account, three roster slots, ready mask,
comment, vehicles) and implements `login.UnitBackend`, so the wire layer
never sees the model.

**Invitations.** `CMD_INVITATION_SEND` (10012) records the invitation and
pushes `Account.processInvitations` to each target with the dict keys
`gui/prb_control/invites.pyc` reads (`id`, `type`, `status`, `sentAt`,
`expiresAt`, `senderDBID`, `receiverDBID`, `senderVehID`,
`receiverVehID`, `info{comment, unitMgrID, peripheryID}`); accept (10010)
and decline (10011) answer with the ordinary command response.

## Arena and reconnect

A battle is a record plus a five-message entry sequence. The record is
`server.Arena`: an id, a space id, an arena type, the map path, the roster
and a state. The sequence is what puts a client in it, and every step is
required — skipping any leaves the client on the battle-loading screen
forever:

| Step | Wire | Why |
| --- | --- | --- |
| `Account.onArenaCreated()` | client method 0 | sets `isPlayerEntityChanging`, which is what makes the app loader switch to the battle-loading space |
| `resetEntities(false)` | element `0x04`, one bool | clears the client's entities and makes it send `enableEntities` again; the engine asserts the player entity is NULL before creating a new one |
| `CreateBasePlayer` (Avatar) | element `0x05` | the player entity, now an Avatar |
| `spaceData` | element `0x07` | maps the geometry into the space: key 1, a 4×4 identity matrix, then `spaces/<map>` |
| `CreateCellPlayer` | element `0x06` | the cell half; this is what ends the loading screen — the engine loads the space and calls `Avatar.onEnterWorld` |

**`CreateCellPlayer` carries the Avatar's cell-to-client properties with no
count prefix.** The client reads them with
`EntityDescription::readStreamToDict(FROM_CELL_TO_CLIENT_DATA)`, which walks
the entity description and takes every property in that domain, in order —
so the server must write exactly those, and `entdef` now exposes them as
`EntityDispatch.CellProps` (14 for the Avatar: `remoteCamera`,
`isObserverFPV`, `numOfObservers`, `team`, `playerVehicleID`, …). The same
applies to `CreateBasePlayer` and `BaseProps`. `entdef.ZeroValue` fills the
ones this server does not model, which is what the client itself would use
for a property the server never set.

**Reconnect is the same sequence.** `server.Arenas` holds a dropped player's
slot for `ReconnectWindow` (two minutes — the client's own reconnect backoff
tops out at 20 s between attempts), and a returning client gets the same
arena id and space id back. The trigger is the same `enableEntities` the
lobby entry uses: if the account is in a live arena, the server sends the
entry sequence instead of the lobby one.

Rejoin is **off by default** (`-arena-rejoin` turns it on). A held slot
otherwise drags every login straight back into the battle the client dropped
out of, which is not what a hangar start means and which also lands the
reset in the middle of the lobby sync.

**Nothing may be answered between the reset and the new entity.** Once
`resetEntities` has gone out the client holds no entity at all, so an
Account-level answer — `onCmdResponseExt` (0x5f), the Account `update`
(0x69) — makes it size an entity method for a null entity and assert:
`MF_ASSERT_DEV FAILED: pEntity` in `BWEntities::getEntityMethodStreamSize`
(`bw_entities.cpp:1103`). `clientState.resetSent` marks that window and
`answerPostCall` drops account calls inside it; the client re-asks for the
whole state once it is a player again. The resend queue is cleared for the
same reason (`resend.forget` in `enterArena`). On the leave path the queue
is dropped only AFTER `st.arena` is cleared: a tick tracked between the
forget and the clear is resent for the whole give-up window, and the
client — back in its login state — drops those resends as "unexpected
packet on external interface" and disconnects. The LEAVE reset rides the
RELIABLE stream, like the arena-entry one: an unreliable reset shares the
unreliable counter with the arena ticks and is discarded as out of order
(`Dropping out-of-order unreliable packet seq=…`), so the client never
sends `enableEntities` and the lobby sync then lands with no entity. The
queue is cleared again by `enterAccount` when the re-entered login reply
goes out, so the reset is not retransmitted past that point.

**Do not send `switchBaseApp` on the battle entry.** The genuine server
sends element `0x44` before the Avatar because its battle runs on a
DIFFERENT BaseApp, and the client rebinds and re-handshakes there. This
server serves the lobby and the battle on one stage-2 endpoint, so a `0x44`
pointing at that endpoint makes the client tear its connection down and
re-handshake against itself: measured, `switchBaseApp(0)` to a garbage
address, 60 failed attempts, `Failed to switch BaseApps`, DISCONNECTED. The
entry works without it (the client rebinds its socket when it builds the
battle app and the server follows the new source address).

**A battle is formed by the matchmaker, not at login.** The client starts in
the hangar as usual; queueing is what hands it off. `Matchmaking.OnMatch`
creates the arena and calls `BaseAppServer.EnterArena` for each player, which
is the same entry sequence a rejoin uses.

`BATTLE_TEAM_SIZE=0 ./start-server.sh` makes ONE queued player enough to
form a battle, which is how the arena and the reconnect are exercised with a
single client — the default is 15 per side, so a real battle needs 30. The
battle has no physics, no other tanks and no map logic.

### The ammo layout is keyed by compact descriptors, not component ids

`vehicle_equipment.__parseLayout` builds

```python
shellsLayoutKey = (vehDescr.turret.compactDescr, vehDescr.gun.compactDescr)
if shellsLayoutKey in shellsInvLayout:
    shellsLayout = shellsInvLayout[shellsLayoutKey][layoutIdx]
else:
    shellsLayout = self.__getDefaultShellsLayout(vehDescr)
```

so `inventory[1].shellsLayout[vehInvID]` is keyed by the **compact
descriptors**, and the value is a list of layouts, one per setup index.

Two separate bugs, both of which had to be fixed before the layout showed up.

**The component order.** The descriptor's block is
`chassis, engine, fuelTank, radio, turret, gun` — turret and gun are the **last**
two u16s, not the second and third. Measured on a Panhard EBR 105: its inventory
descriptor is `41 4A 9D 00 65 00 CD 00 22 00 82 00 63 00 00`, and the client's
own `descriptor.chassis/turret/gun.compactDescr` are 40258 / 33347 / 25412,
which decode to ids 157 / 130 / 99 — bytes `[2..3]`, `[10..11]`, `[12..13]`.
Reading `CompOff+2`/`CompOff+4` gave ids 101 and 205, so the key was
`(25923, 52548)` against the client's `(33347, 25412)`.

**The key is compact descriptors, not ids.** `makeIntCompactDescrByID` is
`(id << 8) + itemType + (nation << 4)`, `vehicleTurret` 3, `vehicleGun` 4, and
the nation from the vehicle's own descriptor, `(vehicleCD >> 4) & 15`. A turret
CD overflows a u16, so `LayoutResult.Turret`/`Gun` are `int32`.

With either wrong, every lookup missed, the client fell back to
`__getDefaultShellsLayout`, and an applied layout never appeared — the server
logged `CMD_SET_AND_FILL_LAYOUTS → ok` and stored it, but the client never read
it back. `TestVehicleGunKey` now pins the EBR's real key.

### Empty configs throw on lobby init

Several lobby controllers read a sub-key of a settings config and use it without
a guard, so an **empty** config is not neutral — it is a `None` or a wrong-shaped
default that throws once per lobby init. Measured on 2026-11-07, five of them:

| controller | error | cause |
|---|---|---|
| `BoostersController.updateGameModeStatus` | `'frozenset' object has no attribute '__getitem__'` | `personal_reserves_config.supportedQueueTypes` — the client's own default is a bare `frozenset()`, but the code does `supportedQueueTypes[category.name]` for each `BoosterCategory` (`personal`, `clan`, `event`), so it must be a dict keyed by those names |
| `epic_meta_game_ctrl.__setData` | `'tuple' object has no attribute 'get'` | `epic_config` is `{"epicMetaGame": {}}`; the controller reads further keys |
| `battle_royale_controller.onLobbyInited` | `KeyError('isWidgetEnabled')` | `battle_royale_config` is `{}` |
| `ingame_tournament_controller.getCurrentShowmatch` | `'dict' object has no attribute 'isEnabled'` | `ingame_tournament_config` / `tournament_config` are `{}`; the code expects config objects, not dicts |
| `scheduled_notifications.startNotification` | `'NoneType' object has no attribute 'enabled'` | same, via the battle-royale config |

All five are now filled in, and `TestSettingsDocumentLoads` requires the keys so
they cannot silently go missing again:

- `personal_reserves_config.supportedQueueTypes` — a dict keyed by the
  `BoosterCategory` **names** (`PERSONAL`, `CLAN`, `EVENT`; `.name`, not
  `.value`), each an empty list.
- `battle_royale_config.tournamentsWidget.isWidgetEnabled` — `BattleRoyaleConfig`
  defaults `tournamentsWidget` to `{}` and the controller subscripts it.
- `epic_config.epicMetaGame.metaLevel` — `_EpicMetaGameConfig`'s default for
  `metaLevel` is the **tuple** `(0, False)`, the only tuple default in the whole
  settings module, and `__setData` calls `.get()` on it. It has to be a dict.
- `ingame_tournament_config` — `_IngameTournamentConfig._preprocessData` only
  converts a tournament type to a namedtuple when its key is **present**;
  otherwise it stores `_IngameTournamentConfigByTournamentType.defaults()`, a
  plain dict, and `getCurrentShowmatch` then does `config.isEnabled` on it. Both
  types (`wci`, `ols`) must be present.
- `achievements20_config` — see above; that one loops rather than firing once.

The general rule: **an empty config is not neutral.** The client's config classes
apply their own defaults, and several of those defaults are the wrong shape for
the code that reads them (`{}` subscripted, a tuple `.get()`, a `frozenset`
indexed). A config the server does not model still has to be spelled out with
the shape the reader expects.

### `achievements20_config` is required, or the hangar locks up

`Achievements20GeneralConfig.getRequiredCountOfBattles` is
`self._config.get('requiredCountOfBattles')` — **no default** — and
`notifications_utils._NotificationNewSummaryPage.req` subtracts it from an int
on every lobby tick:

```python
battlesLeftCountBeforeFeature = requiredCountOfBattles - self._achievementsCtrl.getInitialBattleCount()
```

With the key absent it returns `None` and the client throws
`TypeError: unsupported operand type(s) for -: 'NoneType' and 'int'` about three
times a second, which locks the hangar up — measured, applying an ammo loadout
left the client unable to exit. The settings document now carries
`achievements20_config` with `requiredCountOfBattles` 0 and the feature flags
off, and `TestSettingsDocumentLoads` lists it among the keys that must be
present.

### Leaving a battle: the login reply is ONE packet

`leaveArena` (and `leaveArenaByAccount`, the one the 2.4 client actually
sends) sends `resetEntities(false)`, and the `enableEntities` that
provokes re-creates the Account through `enterAccount(..., withCreate=true)`.
That path sends `CreateBasePlayer` and the `1a/76` session dict
(`selectPlayerEntity` + `Account.showGUI`).

Both need the `0x13` head (`EncodeTickSync(0)` on `CreateBasePlayer`,
`EncodeTickSync(0x40)` on the `1a/76` pair, matching `serveBulk`'s own tag for
that small), but the heads alone are not enough: they must ride **one reliable
packet**. The client's `LoginReplyFilter` (`sub_142D32190`) passes only the
packet whose byte at offset 146 is `0xFF` — the login-reply flag — and drops
every other packet as

```
LoginReplyFilter::recv( 127.0.0.1:32851 ): Dropping unexpected packet on external interface (noise/malicious)
```

The `CreateBasePlayer` packet has that flag (measured live: the client creates
the Account), a separate `1a/76` packet does not, so the client then dropped
the `showGUI`, logged `REASON_GENERAL_NETWORK` six times and went to
`HANGAR LOADING STATE: DISCONNECTED`. `enterAccount` now concatenates both into
one packet (`0x13 0x00 <CreateBasePlayer> 0x13 0x40 <1a/76>`), and
`TestEnterAccountSendsTheSequence` pins the single packet.

The filter also stays armed until the client itself speaks again, and it reads
the flag at a fixed offset: a 28 B tick has no byte 146 at all, so the 10 Hz
login-phase ticker was dropped as "unexpected packet on external interface"
right after the re-entry and the client disconnected anyway. `clientState
.postHold` stops those ticks from the moment a login reply goes out until the
client's next datagram (`noteReliable` clears it);
`TestLoginReplyHoldsTheTicksUntilTheClientSpeaks` pins both halves.

### The shell hole's segment is written EXIT→ENTRY

`Vehicle.damageStickers` is an ALL_CLIENTS ARRAY of `VEHICLE_HIT_POINT`
(`networkID`, `segment`, `params`). The client decodes it in
`helpers_common.decodeSegment` and hands the two points to
`WGStickerModel.addDamageSticker`, which anchors the decal at the segment's
**END**. `showDamageFromShot`'s hit point is read from its **START** (the
client's `parseHitPoints` collides from `segStart`), so the two elements need
opposite segment orders: the impact effect takes the shell's own path
(entry→exit), the persistent hole takes the reverse (exit→entry). With both
written entry→exit the hole is projected through the tank onto the FAR side —
measured by the player: "if I shoot on the north side, the hole appears on the
south side". The sticker id is the `armorPierced`/`armorResisted` name's index
in `common/damage_stickers.xml` (`main_hole` = 7), which is exactly what the
live client's `vehicles.g_cache.damageStickers['ids']` reports.

The hole can sit a few centimetres off the aim point: the server's hit point is
on the part's **bounding box**, and the segment is quantized over that box, so
the client projects the decal from a point on the box rather than on the mesh.

### The arena's vehicle list (`arena.vehicles`)

The loading screen's two teams come from `ClientArena.vehicles`, which is filled by
exactly one caller: `AvatarVehiclesInfoBase.__init__` →
`arena.updateVehiclesList(self.vehiclesInfo)`. That component is **not on the Avatar**.
It is a dynamic component on a separate `AvatarInfo` entity, and the client only takes
it when `self.avatar.id == self.entity.avatarID`.

- `AvatarInfo` — entity, cell property `avatarID: OBJECT_ID`.
- `AvatarVehiclesInfo` — component, `ofEntity AvatarInfo`, one property
  `vehiclesInfo: ARRAY<VEHICLES_INFO>` (ALL_CLIENTS, AllowUnsafeData).
  `VEHICLES_INFO` is a `FIXED_DICT` in `entity_defs/alias.xml`; its field order is the
  wire order.
- Components ride **NRL**, not the entity stream: element `0x21` `NRL_CREATE_NODE`
  (VAR 2). Two messages — one creating the entity node
  (`[node_id BE][parent 0 BE][01][entity_id u32 LE]`), one attaching the component
  (`[node_id BE][parent BE][02][component_type_id u16 LE][name varstr][children][data]`).
  The element id implies message type 0 for the first message, so its type byte is
  omitted. `NrlIdList` is a run-length id list relative to the owning node's id.
- The component's NRL type id is `entities.len() + index in <DynamicComponents>`
  of `scripts/components.xml`. For 2.4.1 that is `50 + 76 = 126`. The base was
  pinned empirically: 127 attached `ForcedReloadComponent`, the entry right after
  `AvatarVehiclesInfo` in that list, and the client's own `entity.components`
  named it.

The player's own tank also gets its `OwnVehicle` component (NRL id 50, the first
entry in `<DynamicComponents>`), attached to the Vehicle entity: the client only turns
its turret once it knows how fast it can, and it reads the ammunition, the loaded
shells, the reload and the health from there. `EncodeNrlAttachComponent` builds it
generically from a property table — 23 properties, no client methods, so 24 children,
each encoded at its alias type's zero value.

The battle then has to be started: `Avatar.setClientReady` only sets `isOnArena` when
`arena.period == ARENA_PERIOD.BATTLE`. The period arrives as
`Avatar.updateArena(ARENA_UPDATE.PERIOD, argStr)`, where `argStr` is a zlib-compressed
pickle of `(period, periodEndTime, periodLength, periodAdditionalInfo)`; the client
unpacks it in `ClientArena.__onPeriodInfoUpdate` and fires `onPeriodChange`.

Both are implemented: `login/nrl.go` (the NRL framing), `arenaInfoApp` (the entity and
its component) and `arenaPeriodUpdate` (the period change), all sent from
`enterArenaSpace`. A solo battle gets a synthetic opponent in the other team
(`ArenaHandoff.Dummy`, a TOG II) so both columns have a tank.

Two ordering rules the client enforces, both learned the hard way:

- **An entity method applies to whatever `selectEntity` last selected.** The period
  change is an Avatar method, so `selectEntity(avatar)` has to go out first. Without
  it the client resolves the element id against the Vehicle that was selected for its
  own `updateEntity`, finds it out of range, and drops the whole bundle as
  `REASON_CORRUPTED_PACKET`.
- **`createEntityDetailed` carries the client-server property run**, filtered to the
  properties with no detail level (the reference's `visible_properties(.., inner=false)`).
  A Vehicle's `publicInfo` is one of them, so it belongs in that run — not in the base
  subset, which is empty for a Vehicle.
- **NRL node ids are unique per space.** One allocator per arena entry, shared by every
  entity node, component node and component child. A second allocator starting at 2
  hands out ids the AvatarInfo entity already took, the client grafts the vehicle's
  component onto the info entity's node, and `arena.vehicles` comes back empty.

- **The property table splits by `<DetailLevel>`.** A property with none is outer state
  and rides the creation message; one with a level (`MY_VEHICLE`, …) rides the update
  that follows. `Vehicle.def` has 68 properties, 10 of them `MY_VEHICLE`. Sending the
  whole table in `createEntityDetailed` makes the client read past what it expects and
  leave the rest of the stream unread (`MemoryIStream: There are still N bytes left`),
  which is how a Vehicle ended up with an empty `publicInfo` and no type descriptor.
  `EntityPropertyRunLevel(e, inner)` and `EncodeUpdateEntityLevel(e, inner)` do the
  split; `entdef.PropertyDef.DetailLevel` carries the level from the defs.

### The server-list ping dot is red, and it is not the ping

The dot next to a server in the login list is **not** driven by the ping value. It
comes from `ServersDataProvider.__getUpdatedPingStatus` (`gui/Scaleform/daapi/view/
servers_data_provider.pyc`):

```python
def __getUpdatedPingStatus(self, pingStatus, item):
    csisStatus = item['csisStatus']
    if pingStatus == PING_STATUSES.REQUESTED:
        return _INDICATOR_STATUSES.WAITING
    if csisStatus in (HOST_AVAILABILITY.RECOMMENDED, HOST_AVAILABILITY.UNKNOWN):
        return self.__checkPingForValidStatus(pingStatus)   # the ping decides
    if csisStatus in (HOST_AVAILABILITY.NOT_AVAILABLE, HOST_AVAILABILITY.NOT_RECOMMENDED):
        return _INDICATOR_STATUSES.IGNORED                  # red, ping ignored
```

`csisStatus` is filled by the **CSIS** server-status query — Wargaming's own service.
A private server is not in it, so the status comes back `NOT_AVAILABLE` (-1) and the
function returns `IGNORED` (-2): a red dot **regardless of the ping**. That is why a
real 1 ms reading sits next to a red indicator.

Confirmed on a live client: `g_preDefinedHosts.getPingResult()` reports
`'127.0.0.1:20016': PingData(value=0, status=3)` — `status=3` is `PING_STATUSES.LOW`,
the green state — and `wotping` against the same server returns `status=LOW`. Both
sides are correct; the dot is red because of CSIS, not because of anything on the
wire.

`enabled = item.get('enabled', csisStatus != HOST_AVAILABILITY.NOT_AVAILABLE)` is the
same cause: the entry would normally be greyed out too.

**There is nothing to fix server-side.** Changing it would mean answering the client's
CSIS query for our host, which is a client/mod concern, not a protocol one.

### Reading the wire back as the client reads it

`WOT_WIRE_CHECK=1 ./start-server.sh` re-reads every outgoing app with the
client's own bundle reader (`login/wirecheck.go`, `CheckClientApp`) and logs
`WIRE CHECK FAILED` for any packet the client would drop. The reader has no
resynchronisation: a bundle is a sequence of `[id][payload]` (fixed-size
message) or `[id][len of the declared width][payload]` (variable), and a
stray byte is read as the next id — `00` is `authenticate`, which wants a
4-byte key, so the whole bundle dies with `Not enough data on stream ...
needed 4` / `Got corrupted message header` / `REASON_CORRUPTED_PACKET`.

That is why a **fixed-size client method carries no length field**: the
client knows the size from the defs. Writing one anyway (the old
`EncodeClientMethodCall`) left `00 00` on the stream after every
`onArenaCreated` / `onEnqueued` / `resetEntities`, and the arena-entry
bundle was discarded before the space could load.

The same reader runs in the tests: `enableWireCheck` is installed by
`tokenTestServer`, so every login test that emits a packet also proves the
client can consume it, and `TestArenaHandoffIsConsumedExactly` walks the
whole queue → arena chain message by message.

### The matchmaker → battle entry, end to end

The entry is a state machine, and every step below was pinned against the
genuine client (`captures/game_20260920.log`, a real battle) or the client
binary. Getting any one of them wrong costs the whole battle.

1. **Queue.** `doCmdIntArr` `CMD_ENQUEUE_IN_BATTLE_QUEUE` → `Account.onEnqueued`
   (fixed-size: `[id][queueType]`, no length field). `onDequeued` likewise.
2. **Match.** `BATTLE_TEAM_SIZE` players per side; `Arenas.Create` picks the
   map and arena type. `arenaTypeID` must be non-zero or
   `Avatar.onBecomePlayer` calls `game.abort()`.
3. **Handoff.** `onArenaCreated` (Account client method, element `0x4E`) then
   `resetEntities(false)` (`0x04`, one bool). The resend queue is cleared
   first: everything queued before the reset refers to entities the client is
   about to drop, and replaying one makes it size an entity method for a
   missing entity — `MF_ASSERT_DEV FAILED: pEntity` in
   `BWEntities::getEntityMethodStreamSize` (`bw_entities.cpp:1103`).
4. **Avatar.** `createBasePlayer` (`0x05`) with the dynamic-component count
   (`2` for the Avatar; the client refuses any other value).
5. **Socket rebind.** The client calls
   `NetworkInterface::recreateListeningSocket` when the battle app is created.
   The rest of the entry is held back for `arenaNextDelay` (200 ms) and then
   sent on the client's next datagram *or* by the tick sweep, whichever comes
   first — the genuine server sends `createCellPlayer` ~215 ms after
   `createBasePlayer`. The server follows the new source address and keys the
   resend queue by it, or every answer goes to a closed port.
6. **Space.** `spaceProperty` (`0x08`) maps the geometry, then
   `createCellPlayer` (`0x06`): `[u8][spaceID u32][u16][vehicleID u32]
   [pos 3×f32][xzScale f32][dir 3×f32][cell props][static components u8]`.
   The `vehicleID` field is what registers the space→vehicle mapping the
   client's `createEntity` reads back.
7. **Vehicle.** `createEntityDetailed` (`0x0C`) with the property run,
   `enterAoI` (`0x10`, fixed 5), `selectEntity` (`0x19`, fixed 4), then
   `updateEntity` (`0x4B`, a bare run — it applies to the selected entity).
   `publicInfo.compDescr` is what `Vehicle.getDescr` builds the tank from.
8. **In battle.** `Avatar.onEnterWorld`, `set_playerVehicleID`, and
   `ClientArena.updateVehiclesList` all follow from the cell data; the arena's
   vehicle list is the entities in the AoI, so a one-player battle needs only
   the player's own Vehicle.

**Known gap: `switchBaseApp`.** The genuine server does not run the battle on
the lobby's BaseApp. `captures/game_20260920.log` shows, one second before the
Avatar:

```
22:05:24.344  ServerConnection::switchBaseApp(3294439): Client ...:61621
              switching from udp:92.223.20.213:32825...
22:05:24.345  NetworkInterface::recreateListeningSocket: address ...:62511
22:05:24.378  Account.onBecomeNonPlayer()
```

`switchBaseApp` is element `0x44`, FIXED 9 — the same element the stage-1
redirect uses: `[0x44][ip4 BE][port BE][00 00][resetEntities]`. The client
rebinds its socket and re-handshakes against the new BaseApp, and the battle
runs there. This server keeps one stage-2 endpoint and does not send it; the
client rebinds anyway when it builds the battle app, and the server follows
the new source address. Implementing the switch properly needs a second
BaseApp endpoint plus a re-handshake, so it is recorded here rather than
half-done.

Two traps worth naming. `arena_dp` logging *"Player's team not found"* and
*"Player's vehicle ID not found"* is **normal** — the genuine client logs the
same, because `team` and `playerVehicleID` are cell properties and have not
arrived yet. And the defs tree must be the build the client runs: see the
`PUBLIC_VEHICLE_INFO.index` note above.

### What the battle still needs, as a verified checklist

The in-battle entity surface below was cross-checked field by field against
the 2.4.1.1 defs (`scripts.pkg`), so the names, order and types are the
client's, not a guess. It is the whole of what a battle adds to the lobby:

| Where | Members |
| --- | --- |
| `Avatar` cell | `vehicle_shoot()`, `vehicle_moveWith(flags u8)`, `vehicle_stopTrackingWithGun(yaw f32, pitch f32)`; properties `ownVehicleAuxPhysicsData u64`, `ownVehicleGear u8` |
| `Avatar` client | `showTracer(13 args)`, `stopTracer(shotID, end)`, `explodeProjectile(10 args)`, `showShotResults(ARRAY of CLIENT_SHOT_RESULT_DATA)` |
| `Avatar` base | `setClientReady()`, `leaveArena()`, `leaveArenaByAccount()` |
| `Vehicle` cell | `trackRelativePointWithGun(VECTOR3)`, `stopTrackingWithGun(yaw, pitch)`; properties `health`, `damageStickers`, `gunAnglesPacked`, `engineMode`, `avatarID`, `vehPostProgression`, `publicInfo`, `isStrafing`, `isCrewActive`, `publicStateModifiers`, `dogTag`, `isMyVehicle`, `quickShellChangerFactor`, `onRespawnReloadTimeFactor`, `perkEffects`, `perks`, `perksRibbonNotify`, `crewCompactDescrs`, `enhancements`, `setups`, `setupsIndexes`, `vehPerks`, `disabledSwitches`, `ownVehiclePosition` |
| `Vehicle` client | `showShooting(burst u8, gunIndex i8, shellKind u8)`, `showDamageFromShot(9 args)`, `onHealthChanged(new i16, old i16, attacker, reason u8, extReason i8)` |
| `AvatarInfo` entity | cell property `avatarID` |
| `AvatarVehiclesInfo` component | cell property `vehiclesInfo` (ARRAY of `VEHICLES_INFO`, 39 fields) |
| `OwnVehicle` component | cell properties `syncVehicleAttrs`, `targetingInfo`, `vehicleAmmoList`, `vehicleSettings`, `vehicleGunReloadTime`, `vehicleHealthInfo`, `siegeStateStatus` |
| `GunMarkerComponent` | cell property `gunMarker` |
| `Fire` | cell property `fireInfo` |

`perkEffects`, `perks` and `perksRibbonNotify` come from the `Perks_Vehicle`
interface, not `Vehicle.def`, and carry `DetailLevel MY_VEHICLE` — they are
sent only to the vehicle's own client, which `entdef`'s cell-to-client mask
does not model yet.

**One def-version trap.** `PUBLIC_VEHICLE_INFO.index` is `UINT8` in the
2.4.0.0 defs and `UINT16` in 2.4.1.1, so a vehicle's `publicInfo` encoded
against the 2.4.0 tree is one byte short for this client. The Account
base-method list also differs (33 entries in 2.4.0.0, 32 in 2.4.1.1:
`destroySelfForPeriphery` is gone and `processWalletResponse` became
`processWGMoneyMQMessage`), which shifts every element id past index 11.
The server therefore loads `../scripts-2.4.1/entity_defs`, never the 2.4.0
tree; the digest gate is a pinned table, so it does not depend on which tree
is loaded.

### The gun: `updateTargetingInfo` is not the path

`VehicleGunRotator` is what turns the turret, and it refuses to run until two
things are true: `Avatar.isOnArena`, and its own `__speedsInitialized`. The
second is set in exactly one place, `VehicleGunRotator.update()`, and the only
caller of that is `Avatar.updateTargetingInfo`.

That method looks like the obvious thing to send, and it is a trap:

- `Avatar.def` declares it as **nine FLOAT32, no entity id** (36 B), and the
  client's own method table carries that size — `0x72` is the element, and
  sending 44 bytes leaves eight to be read as the next element id, so the
  client drops the packet as `REASON_CORRUPTED_PACKET`.
- The client's Python is `updateTargetingInfo(self, entityId, turretYaw, ...)`
  — eleven arguments. Nine floats raise `TypeError`, so the 36-byte form
  cannot reach it either. The def is stale; the method is dead.

The live path is the `OwnVehicle` component's `targetingInfo` property.
`OwnVehicleBase.__getattr__` synthesises `set_<prop>` → `update_<prop>`, and
`update_targetingInfo(data)` calls
`avatar.updateTargetingInfo(self.entity.id, ...)` with the id filled in. So
setting the property is what starts the rotator, and `__attachToVehicle()`
re-applies it once the vehicle is in the world and started — which is why the
component has to be attached *after* `AvatarVehiclesInfo`, or the descriptor
`getOwnVehicleShotDispersionAngle` needs is not there yet.

`isOnArena` is the other half, and it is set by `Avatar.setClientReady` — see
the dog-tag note below, because a throw in there silently costs both.

Two more things pin the turret, both of them zero values that are not "off":

- **`fixAngles` must be `None`, not its zero value.** `OwnVehicleBase.
  update_fixAngles` does `if self.fixAngles: gunRotator.fixShotPosition(...)`
  else `unFixShotPosition()`. The zero value of `GUN_ROTOR_FIX_ANGLES` is a
  dict of two zero floats, which is *truthy*, so the turret gets pinned to
  (0, 0) and `__rotate` never turns it. The alias is `AllowNone`; `None`
  encodes as a single `0x00`.
- **The rotation speeds are the vehicle's own, not a constant.** They live in
  the item defs inside `scripts.pkg`: the turret's `rotationSpeed` under
  `turrets0/<Turret>`, the gun's in `components/guns.xml`. `login/vehiclespec.go`
  resolves them from the compact descriptor (a TOG II*'s turret is 25 deg/s,
  its gun 26.25 deg/s — both matching what the client's own
  `vehicleTypeDescriptor` reports). A constant like 30 rad/s is 1719 deg/s,
  which is why the turret used to snap.
- **The gun is driven by the NRL marker, not by `gunAnglesPacked`.** The
  captured server sends `gunAnglesPacked` as a bare `0xb4` element; the aiming
  rides element `0x28` (see "The gun marker: NRL element `0x28`" above), which
  `Avatar.updateGunMarker` hands to `VehicleGunRotator.setShotPosition`. The
  server still steps its own yaw toward the client's aim at the turret's rate
  (`trackTurret`) so the marker it reports is the angle the client is settling
  on rather than a whole swing ahead. The rate is the game's own: the client's
  `SERVER_TICK_LENGTH` is `0.1` (`common/constants.pyc`) and the reference
  implementation ticks at 100 ms, so 10 Hz is right — but the step has to be
  the *measured* elapsed time, not a nominal 0.1, or the server drifts against
  the client's `BigWorld.time()` delta. The client's cell call
  `Vehicle.trackRelativePointWithGun` carries the aim point in the hull frame,
  and a client -> server cell method carries the entity id ahead of its
  arguments: `[elemID][len u16][entityID u32][args]`. Two consequences worth
  knowing: an element the server does not model must be **skipped, not
  fatal** — the client sends `Vehicle.setRemoteCamera` (0x1a) right after the
  track call, and aborting the walk there dropped everything behind it in the
  same bundle, `leaveArena` included, which is why the leave button stopped
  answering; and the `selectEntity(vehicle)` / update / `selectEntity(avatar)`
  sequence must be **atomic per session** (`clientState.sendMu`), or the update
  lands on the Avatar and the client asserts `result && pValue` in
  `entity_description.cpp`.
- **`vehicle_stopTrackingWithGun` is an Avatar cell method, not a Vehicle
  one.** `VehicleGunRotator.stopTrackingOnServer` calls
  `self._avatar.cell.vehicle_stopTrackingWithGun(yaw, pitch)`, so the entity id
  ahead of its arguments is the *Avatar's*. A handler that only accepts the
  vehicle's id drops it, and the server then keeps re-deriving the bearing from
  the last world point the client sent — which the client has stopped updating.
  As soon as the hull turns, the server's yaw swings away from the angle the
  client settled on, the client snaps back to it, and the turret jitters
  between two angles. The reported angles are the client's own, already stepped
  at the turret's rate and already clamped to its arc, so they are adopted
  verbatim (no clamp — a narrower arc here is itself a snap) and `aimSet` is
  cleared so the tick stops re-deriving from the stale point.
- **The pitch rides the marker, not `gunAnglesPacked`.** The marker's
  `shot_velocity` carries the barrel's full direction, elevation included, so
  the elevation is modelled there. `gunAnglesPacked` is never sent, and the
  client's copy stays at the def's default.
- **`ownVehicleAuxPhysicsData` zero is not level.** It is the packed hull
  attitude the client feeds to `WoT.computeStabilisedVehicleMatrixU64`, and
  `WoT.unpackAuxVehiclePhysicsData(0)` gives `(-pi, -pi/2, -pi, -15, -15, 0)`
  — a 90-degree tilt about X. `getShotAngles` then aims in that rotated frame,
  so the turret only ever reaches its limits instead of tracking. The level
  value is `WoT.packAuxVehiclePhysicsData(0, 0, 0, 0, 0, 0)` =
  `0x55558004004000`, sent as an `updateEntity` on the Avatar before the
  vehicle starts (`__startVehicleVisual` reads it once).
- **`ARENA_PERIOD.BATTLE` is 3, not 2.** From the client's own
  `common/constants.pyc`: `IDLE 0, WAITING 1, PREBATTLE 2, BATTLE 3,
  AFTERBATTLE 4`. Announcing 2 leaves the client in PREBATTLE — in the battle,
  loaded, minimap right, and `isOnArena` False, so `start()` never runs and
  `Avatar.moveVehicle` returns before it ever sends `vehicle_moveWith`: the
  tank does not drive at all, and nothing on the wire says why. The period is
  driven by the CLIENT, not by a timer: the entry sends WAITING (1), and the
  sequence waits for the client's `Avatar.setClientReady` base call before it
  sends PREBATTLE (2) and then BATTLE (3) three seconds later.
  `setClientReady` registers its `onPeriodChange` handler only AFTER its
  `period == BATTLE` check, so a BATTLE that lands earlier is dropped and the
  client sits in the battle with `isOnArena` false — the old "loaded but
  frozen for 30 s" bug, which the timer-based entry only worked around by
  also announcing BATTLE at the entry (and then flipping back to PREBATTLE
  when the delayed update arrived, which is what made the prebattle countdown
  appear after the battle had already started). The ready call is released
  through `st.readyCh` (`markClientReady`, idempotent and re-armed per battle
  by `enterArena`); a 12 s timeout starts the battle anyway for a rejoin that
  never calls it. **`setClientReady` is Avatar base slot 1 and Account slot 1
  is `onStreamComplete` (3 B)**, so the base decoder must fall through to the
  Avatar on a length mismatch — refusing on the Account mismatch dropped the
  ready signal entirely (`decodeBaseCall`/`postDoCmd`).
- **The BATTLE announcement has to mint its sequence number under
  `st.sendMu`.** It used to read `st.postSeq` and hand it to `sendReliable`,
  which takes the lock afterwards — the 100 ms ticker minted and sent in
  between, so the announcement went out with a number the client had already
  seen and was dropped as a duplicate. The period stayed at PREBATTLE and the
  client stayed out of the arena. `nextSeq` + `sendReliableLocked` under one
  hold of `sendMu` is the only correct shape.

#### The damage UI and the kill are feedback calls, not health updates

The victim's `Vehicle.onHealthChanged` moves the health bar and nothing else.
What the player sees is two more paths:

- `Avatar.onBattleEvents(ARRAY<BATTLE_EVENT>)` — the per-event damage log
  (`{eventType, targetID, details, count}`, `details` =
  `BattleFeedbackCommon.packDamage(damage, attackReasonID, …)`; event types
  DAMAGE 7 and KILL 8). This is what the bottom-left log and the personal
  efficiency log read.
- `OwnVehicle.battleEventsSummary` — the running totals
  (`damage`/`trackAssist`/`radioAssist`/`tankings`/`stunAssist`) that the
  personal efficiency panel's damage counter reads
  (`BattleSummaryFeedbackEvent.fromDict`).

A kill is a NESTED `AvatarVehiclesInfo.vehiclesInfo` update, never a re-sent
list: the component has no `set_vehiclesInfo` handler, so a whole-value update
sets the attribute and calls nothing and the tab keeps the victim alive. Its
`setNested_vehiclesInfo` buffers one field's diff and the `__generation` bump
flushes it into `ClientArena` (`setVehInfo_isAlive` → `updateVehicleIsAlive` →
`onVehicleKilled`). The record is NRL kind 2,
`[node u16 BE][2][len packed-u24][compressed path][value]`, with the path
`[1][prop][1][elem][0][field]` MSB-first and each index `bitsRequired(count)`
bits wide. The diff buffer is keyed by field NAME, so each vehicle needs its
own `__generation` flush. The kind is the client's dispatch: 0 whole value, 1
SLICE (`setSlice_vehiclesInfo` — a field path there raises `TypeError: 'int'
object is not iterable`), 2 nested (`setNested_vehiclesInfo`).

### Standalone property elements are framed by the property's own length

`EntityDispatch.Properties[i].Length` is the client's element length for that
property, and it is what a property element OUTSIDE an `updateEntity` run must
use: a fixed-size value (`health`, INT16) is `[id][value]` with no length
field, and a variable one (`damageStickers`, an ARRAY alias) is
`[id][u8 len][value]` — ARRAY/STRING aliases have `VariableLengthHeaderSize`
1, not 2. `EncodePropertyUpdate` wrote a u16 header for everything, which
shifted every element after it by one byte. The client first dropped the
bundle as `REASON_CORRUPTED_PACKET` (it read `b5 <health> 52` as the channel
key: `ServerConnection::authenticate: Unexpected key!`) and on the next
pierced hit asserted `pCurr_ + nBytes <= pEnd_` and crashed the game. Only a
PIERCED hit sends the shell-hole property, which is why bounces and HE
splashes were fine.

The offline wire check (`CheckClientApp`) now reads a standalone property by
its declared length and backtracks over the entity a bundle is addressing
(`selectEntity(vehicle)` → a Vehicle method → `selectPlayerEntity` → an Avatar
method is one shot packet), and `sendReliableLocked` runs it, so the battle's
own traffic is checked too.

## Driving: every tick bundle opens with `TickSync`

The tick bundle must start with `TickSync` (element `0x13`, one byte), exactly
as the reference's `write_tick` does — it is the first element of every tick,
before the leaving/entering/created/positions/events sequence.

Without it the client's witness has no idea a tick has arrived, and it applies
the position updates in **bursts**: the tank sat still for two or three seconds
and then jumped twenty metres, which reads as "the tank does not drive" even
though the server had it moving at full speed the whole time. With `TickSync`
in front, the same position stream is applied every tick and the tank drives
smoothly — measured at 10 m/s forward and 33 deg/s rotating, sampled every
500 ms with no jumps.

The tick goes out at **100 ms**, the client's own `SERVER_TICK_LENGTH` and the
reference's `TICK`, and `UPDATE_FREQUENCY_NOTIFICATION` announces 10 Hz to match.
(60 Hz was tried as a workaround for the missing interpolation; it does not
substitute for it, and it makes the announced frequency a lie.) The client does not interpolate here: its
`WGVehicleFilter` stays in lag mode (`isLaggingNow` true, `movementSignals` 0),
so `filter.bodyMatrix` is *exactly* the entity position — measured, the
difference is 0.000 at every sample — and the tank is drawn at whatever the last
update said. There is nothing between synchronisations, so the tick period is
the tank's frame rate — and the **channel** decides whether the ticks arrive on
time: on the reliable stream a late tick head-of-line-blocks the ones behind it
(measured 5.58 Hz effective, gaps of 100/150/200/300 ms), on the unreliable one
the same 100 ms lands at 9.86 Hz with 104 ms p50 and 106 ms max. See
"Conclusion: the client draws the last position it was told" below.

**Two `TickSync` counters, and that is deliberate.** The hangar's post-flood
stream writes `postTag` (from `0x7a`) and the arena tick writes its own. Merging
them into one sequence does make `WGVehicleFilter.isLaggingNow` read **false** —
measured — but the client then applies exactly one position update and stops:
the tank jumps once and freezes while the server keeps driving it. Stopping the
hangar stream and letting the arena own the counter does the same. Both were
tried and reverted; the two streams have to keep running as they are.

Three things that are *not* the answer, all tried and reverted:

- **Position updates on the unreliable channel.** The client ignores them
  outright: the hull kept stepping on the server (`engineMode` reached
  cruising) and the reliable property updates arrived, but the tank never left
  its spawn point. Whatever the witness does with an unreliable bundle, it
  does not apply position updates from one.
- **Stopping the hangar's post-flood tick stream once the arena starts.** The
  arena tick then carries the only `TickSync`, and the client stops applying
  position updates altogether — the tank moves once and freezes while
  `engineMode` keeps updating. Both streams have to keep running.
- **`gunAnglesPacked` on the reliable channel.** It is sent, but on the
  unreliable tick, as a bare `0xb4` element after the `0x1d` that selects the
  Vehicle alias — the same place the capture puts it. Putting it on the reliable
  stream is what used to clog that channel; the element itself is required,
  because the client's own physics is inert and it cannot derive the turret yaw
  (see "The turret and gun angles").

### The aim point is a WORLD-axis offset, not a hull-frame one

`VehicleGunRotator.__trackPointOnServer` sends
`shotPoint - stabilisedVehPos` — an offset from the hull's **position**, in
**world axes**. It is not in the hull's frame, so it must be added to the hull
position as it stands. Rotating it by the hull yaw puts the aim point a whole
hull-yaw's worth off, and because that error changes as the tank turns, the
turret desyncs the moment it drives: the client's own `getShotAngles` and the
server's bearing disagree by the hull yaw, the client's rotator runs ahead, and
`__syncWithServerTurretYaw` snaps it back every time the deviation passes
`0.1396 + 0.4 * speed` — a sawtooth, and an unaimable gun.

Measured on a hull at yaw 2.938 with the aim 14.8 m along +Z: the client's
`getShotAngles` says **-2.947 rad**, the rotated form gave **0.000**. With the
offset added unrotated the two agree to 0.002 rad and stay there while the tank
drives and turns.

The turret step is also the **shortest way round**
(`stepTurret`, `wrap_angle(target - cur).clamp(-step, step)`): across the ±π
seam the plain difference is nearly a full turn, so an unwrapped step swings the
turret the long way while the client takes the short one and snaps back.

### The turret and gun angles

`gun_rotation_shared.encodeGunAngles(yaw, pitch, pitchLimits)` is a 10-bit yaw
over `[-pi, pi)` in the high bits and the pitch's 6 bits below it, the pitch
packed over the gun's own `pitchLimits` (`encodeRestrictedValueToUint`). It is
**not sent** — the captured server sends no property updates — but the two
angles it would carry are still simulated, because the NRL marker's
`shot_velocity` is built from them:

- The **yaw** steps toward the aim's bearing at the turret's rate, the shortest
  way round (`stepTurret`).
- The **pitch** steps toward the aim's elevation at the gun's rate, clamped to
  the gun's absolute range. It is measured from the **gun's pivot**, not the
  hull's origin: `turretPositions/turret` plus the turret's own `gunPosition`,
  which for the Headshaker is 0.408 + 0.526 = 0.934 m. Measuring from the hull
  reads a level aim as several degrees of depression.

The limits come from the defs' `<guns>/<gun>/pitchLimits`, whose `minPitch` and
`maxPitch` are flat (yaw, pitch) pair lists **in degrees**; the lowest of the
mins and the highest of the maxes, in radians, is exactly what the client's
`typeDescriptor.gun.pitchLimits['absolute']` reports (`(-0.349, +0.105)` for
this tank). The sign convention is the client's: negative is up
(`getShotAngles` gives -1.10 for a point 40 m above and +1.14 for one 40 m
below).

`ownVehicleAuxPhysicsData` already matches the reference bit for bit — yaw 15
bits, pitch 12 over ±π/2, roll 13, the two track speeds 8 each over -15..30 m/s,
and the engine's relative RPM 8 over 0..1.2, from the lowest bit up.

### A PYTHON property over 255 bytes needs the unsafe length

`Account.initialServerSettings` is `PYTHON` with `AllowUnsafeData: true`, and the
engine writes those with `[0xFF][u24 length][data]` once they outgrow the
variable-length header — `appendPacked` in `flood_build.go` is the same rule, and
it is what the client's `PythonStreamElement` reads. The codec wrote a plain
1-byte header, so `createBasePlayerApp` failed with

```
CreateBasePlayer: entity … (Account): property "initialServerSettings":
entdef: length 802 does not fit a 1-byte header
```

and a **re-login** — the only path that builds `CreateBasePlayer` itself, since
`serveBulk` sends the whole lobby bundle instead — left the client stuck at the
login screen with no entities. `entdef`'s `writeString` now takes the type and
uses the unsafe form for `Python` blobs of 0xFF bytes or more.

### `Vehicle.physicsMode` is sent

`physicsMode` is `ALL_CLIENTS` `UINT8` and this server never sent it, so it sat
at its zero value. It is the one per-vehicle field that could plausibly say who
owns the simulation, so it now goes out as `1` in the creation run. Measured
effect: none — `numTrackContacts` stays 0 and `bodyMatrix` stays exactly the
entity position. The client has no Python reader for it (`Vehicle.pyc` has no
`physicsMode`, and the binary has no such string), so it is probably telemetry.

### `UPDATE_FREQUENCY_NOTIFICATION` is sent

Element `0x02`, FIXED 7 — `frequency: u8`, `unknown: u16`, `game_time: u32`.
Its doc comment in the reference is "the server informs us how frequently it is
going to send updates to the client, and also gives the server game time": the
one element in the protocol whose whole purpose is the tick rate, which is the
number a client interpolates between ticks with. The real server sends it; this
one did not. It goes out once at arena entry, before the first tick, with the
actual rate (`time.Second/arenaTickPeriod`, 62 Hz at a 16 ms tick).

**`game_time` is the raw 10 Hz tick counter, not seconds.** The capture pins the
two units against each other: at 14:17:25.943 the element carries
`game_time = 1126351` while the period tuples are in seconds
(`(2, 112646.6, 3, [10.0, 10.0])`), and the tick at that instant is ~1126346. So
`BigWorld.serverTime()` is `game_time / 10 + elapsed` — seconds, the same base
`periodEndTime` uses. Sending seconds here makes `serverTime()` ten times too
small, and `Avatar.__onArenaPeriodChange`'s
`battleTime = serverTime - (periodEndTime - periodLength)` then carries a
constant **-128 s** offset: the battle timer opens at 2:08 instead of 0:00 and
the prebattle countdown is wrong by the same amount. `arenaGameTime` and
`arenaPeriodEnd` in `login/arena.go` are the two halves of that rule, and
`TestArenaGameTimeIsTheRawTick` pins them against each other.

Measured effect: `WGVehicleFilter.isLaggingNow` reads **false** with it, where it
had been true in every sample before. The filter still does not integrate
(`bodyMatrix` is still exactly the entity position, `numTrackContacts` still 0),
so it is necessary but not sufficient.

### Why the client's filter does not simulate (closed: it never will)

`WGVehicleFilter` computes `speedInfo` from the position deltas — that is why the
km/h digits work — but it never integrates its own physics, so
`filter.bodyMatrix` is *exactly* the entity position at every sample and there is
nothing between synchronisations. This is now **measured, not inferred**: a
Frida probe (`tools/frida-inject/filter_probe.js`) logs the entity position and
`bodyMatrix`'s translation in the same call of the filter's per-frame update
(`sub_142F022A0`, vtable slot 3 of `0x143C071E0`) and they agree to the last
digit, driving or parked:

```
UPD pos=336.830,-5.054,686.497 body=336.830,-5.054,686.497
UPD pos=336.919,-4.818,686.119 body=336.919,-4.818,686.119
```

**The filter is ticked every frame.** `sub_142CE2CE0` (the entity's
"update filter" pass, called from the space's per-frame loop `sub_142CEA7B0`)
dispatches `vt[3]` on `*(entity+136)`, and the probe counts it at the frame
rate. So the earlier "the engine never calls it" reading was wrong.

**The one extrapolation in the filter is lag compensation, not smoothing.**
`sub_142EFF3D0` is called from `sub_142F022A0` and rewrites the position in
place, but:

- its blend factor is `v50 = (distance_to_server - 30.0) * 0.0333`, and the
  applied weight stays 0 while that is negative — i.e. it only engages once the
  client is more than **30 m** behind the server position;
- it is gated on `byte_144664CF5` (`enableClientFilters`, true) **and**
  `*(filter+0x5AD)`, which is the Python property `allowStrafeCompensation`
  (`sub_142F06200`/`sub_142F06240`). `Vehicle.startVisual` sets it to
  `not self.isPlayerVehicle`, so it is **false for the player's own tank on
  official too**. Setting it true live (verified: the probe's `en=` flips 0→1)
  changes nothing, because of the 30 m threshold above;
- the surrounding blend weight `*(filter+0x6A8)` is only 1.0 while
  `isStrafing` (`*(filter+0x86B)`) is false, and decays by `2*dt` otherwise.

`filter.input()` (`sub_142F01650`, slot 2) only *stores* the position: its tail
`sub_142EFC040` compares the incoming position with the stored one and calls the
filter's reset (`vt[1]`) when the jump exceeds `*(filter+0x318)` and
`allowCustomResets` is set. There is no smoothing anywhere on that path.

**The player's filter takes a different slot than remote vehicles.**
`sub_142EFB9B0` (slot 11) dispatches on `*(filter+0x2E8)`:

| `filter+0x2E8` | slot | function | what it does |
| --- | --- | --- | --- |
| non-zero (remote) | `vt[8]` | `sub_142F00100` | the input-driven lag extrapolator: reads `+0x5AC` (has-input), `+0x5A8` (movement), `+0x5A4` (rotation) and simulates the hull forward |
| zero (player) | `vt[7]` | `sub_142EFB170` | velocity from the position delta only |

Measured: `sub_142F00100` is called for the dummy and **never** for the player's
vehicle. So the client deliberately does not run the input extrapolator on the
player's own tank — it expects the server's positions to be good enough.

`notifyInputKeysDown` does reach the filter — `sub_142F01B80` writes `+0x5A4`
(rotation), `+0x5A8` (movement) and `+0x5AC` (has-input) — so the input is
recorded; it is simply not used on the player's path.

**`UPDATE_FREQUENCY_NOTIFICATION` is not the lever either.** Its handler
(`sub_142CFF130`) stores the frequency at `+0x231`, derives the expected update
interval `1/(freq * *(conn+0x229))` at `+0x221`, and `sub_142CFCAD0` uses that
interval only as a *stall timeout* (`now - lastUpdate > interval` → poke). It
does not set a simulation step. The reference sends no such element at all.

**Conclusion: the client draws the last position it was told, so the tick period
is the frame rate of the tank's motion — and what decides whether the ticks
arrive on time is whether the reliable channel is EMPTY.** The captured server
sends one datagram per tick, on the **reliable** stream: 7582 of its 7702
`0x13`-led datagrams are `fl=0x0458` (ON|RELIABLE|SEQ|CUMUL) and only 109 are
the unreliable `fl=0x1448`. Its shape is `0x13` TickSync, `0x16`
RelativePosition metre-rounded, `0x1e` PlayerDetailed at zero from it, `0x1d`
AliasDetailed with the vehicle's absolute floats, ~20× `0x35` packed alias
updates for the other tanks, and finally `0x28` the NRL gun marker. Measured
over battle 1 of `captures/proxy-20261031-1358.hex`: exactly 10 S>C
datagrams/s, `0x1d` gaps p50 100 ms / p90 200 ms / max 300 ms.

It sends **no `0x19`-led and no `0x4b`-led datagrams** over those 250 s — but
that is not the same as sending no property updates, which is what this doc
used to claim. It sends them as **bare elements**: `entityPropertyBase + index`
followed immediately by the value, with no length and no `updateEntity`
wrapper. That is why they looked absent. The three it sends every tick are

| element | entity | property | size |
|---|---|---|---|
| `0xba` | Avatar | `ownVehicleAuxPhysicsData` | 8 |
| `0xb4` | Vehicle | `gunAnglesPacked` | 2 |
| `0xb6` | Vehicle | `engineMode` | 2 |

and the **order is load-bearing**, because a bare element carries no entity id
— it applies to whatever the last selection element named. The captured
server's own order, from the 440 B datagram at 14:18:44.647, is

```
13 e3                          TickSync
1a                             SelectPlayerEntity
ba <8 B aux>                   the Avatar's aux word
16 <ref>                       RelativePosition, metre-rounded
1e 00 <0> <0>                  PlayerDetailed, on the reference
1d 00 fd <pos> <dir>           AliasDetailed, alias 253 = the own vehicle
b4 <2 B>                       gunAnglesPacked, on alias 253
35 00 fc <packed> <ypr> <unk>  AliasFullPosYawPitchRoll, alias 252
b6 <2 B>  b4 <2 B>             engineMode + gunAnglesPacked, on alias 252
35 …                           the next tank, and so on
28 <…>                         the NRL gun marker, last
```

So the aux word must follow `0x1a` and precede `0x1d`, and the Vehicle's two
must follow `0x1d`. Sending the aux after `0x1d` leaves the player selected and
the Vehicle's `0xb4`/`0xb6` then land on the Avatar, where those ids mean
`denunciationsLeft` and `battleChatRestriction`.

The aux word is **unconditional** — it goes out every tick once the battle has
started, parked or moving. It used to sit behind a `WOT_AUX` env gate that
defaulted to off, which produced a tank that drove with dead tracks, a frozen
tacho and no engine sound; the only real condition is `battleStarted`, because
sending it during the loading screen leaves the client stuck there with
`isOnArena` false (measured).

Walking the whole capture with that selection state machine settles it — every
bare element lands on exactly one entity, never both:

| element | Avatar | Vehicle |
|---|---|---|
| `0xa8` | — | 2122 |
| `0xb3` | 1 | — |
| `0xb4` | — | 16477 |
| `0xb5` | — | 16 |
| `0xb6` | — | 2793 |
| `0xba` | 5052 | — |

`Vehicle.engineMode` is `Tuple[2]{UINT8}`, not a UINT16: byte 0 is the mode,
byte 1 the movement flags. The capture's values are `0x0001` (mode 1 idle, no
flags), `0x0102` (mode 2 cruise, forward) and `0x0103` (mode 3 accelerating,
forward), plus `0x0000` before the engine starts.
`VehicleAppearance.changeEngineMode` feeds `mode[0]` to
`DetailedEngineState.mode`.

### The engine sound (CLOSED Nov-07 — it works)

**The engine sound works as of 2026-11-07**, confirmed live in battle: the engine
audition plays and follows the RPM. Two things changed between the silent
measurement below and now, and both were server bugs:

- the `OwnVehicle.siegeStateStatus` NRL write was removed. It was corrupting the
  component — the same write that destroyed every module on the tank when siege
  mode was switched off — so the audition's state was garbage. It is back now,
  correctly framed (see "Siege mode (the X key)").
- `Vehicle.wheelsScroll` was mis-framed and the client discarded the whole tick
  bundle on `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`, so no aux word
  arrived at all. See `NETWORK_PROTOCOL.md` §20.2.

The 2026-11-06 measurement below is kept as history: it was taken while the
component was being corrupted, so its conclusion ("the break is inside
`VehicleAudition`'s start path") does not hold.

Measured live with pyconsole on 2026-11-06, in battle, tank rolling. **Every
value the server feeds is arriving and correct**:

| probe | value |
|---|---|
| `detailedEngineState.rpm` | 1294.3 |
| `detailedEngineState.relativeRPM` | 0.362 |
| `detailedEngineState.rpmPhysicRel` / `rpmPhysicAbs` | 0.362 / 1294.3 |
| `detailedEngineState.physicLoad` | 0.923 |
| `detailedEngineState.mode` | 3 (accelerating) |
| `detailedEngineState.gearNum` | 0 |
| `filter.averageSpeed` | 7.62 m/s |
| `Avatar.ownVehicleAuxPhysicsData` | `0x698787809bc61e34` |

The chain, from `common_tank_appearance._initDrivetrain` and the binary:

- `detailedEngineState.vehicleSpeedLink = CGF.createFloatLink(filter, 'averageSpeed')`
- `detailedEngineState.physicRPMLink = lambda: WoT.unpackAuxVehiclePhysicsData(player().ownVehicleAuxPhysicsData)[5]`
  — the aux word's rpm field, which is why the tacho tracks.
- `detailedEngineState.physicGearLink = lambda: player().ownVehicleGear`
- `VehicleAudition` (`sub_140941A10`) sets `RTPC_ext_engine_state` and
  `RTPC_ext_rpm`; those two drive the engine loop.

**The event that should rev never plays.** `eng_Ford_GAA_pc` (from
`typeDescriptor.engine.sounds.getEvents()`) reports `isPlaying` **False** on all
four of the vehicle's sound objects (`getSoundObject(0..3)`, all with
`name = u''`), and alternating `play()`/`stop()` on it for 12 s produced no
audible change — the idle played straight through. Swinging `RTPC_ext_rpm`
0.0↔1.0 for 27 s, both per-sound-object and via `WW_setRTCPGlobal`, also
produced no change, as did `RTPC_ext_physic_rpm_rel`/`_abs` and
`RTPC_ext_engine_load`. So the idle that is audible is a **different** sound
source, and the engine event is silent.

`detailedEngineState.onEngineStart` is a `Svarog::Event`: assigning to it works,
reading it throws `TypeError: Unable to convert function return value to a
Python type`. `_initDrivetrain` assigns `_onEngineStart` to it, and calling
`_onEngineStart()` by hand does reach `engineAudition.onEngineStart()` — but the
event still does not start. The break is inside `VehicleAudition`'s start path.

The "next step" this section used to end on — muting `frictionAudition`,
`suspensionSound` and `trackScrollController` one at a time — is moot: the sound
came back once the component stopped being corrupted, with no change to the
audition itself.

The reliable stream works for it because nothing else is on it. Ours used to
carry a property bundle (`engineMode`, `ownVehicleAuxPhysicsData`,
`ownVehicleGear`, `gunAnglesPacked`) every tick, and the positions queued behind
it. Measured on the same tank with a pyconsole sampler on `vehicle.position`:

| | positions behind the property bundle | positions with the bundle gone |
|---|---|---|
| changes while driving | 3.10 Hz | **9.86 Hz** |
| gap p50 / p90 / max | 200 / 300 / 2700 ms | **104 / 104 / 106 ms** |

A late tick head-of-line-blocks every tick behind it, so the same 100 ms period
arrived as 100/150/200/300 ms gaps with the tank frozen in between. The fix is
not the channel but the queue: the property bundle is gone (the captured server
sends none), so the reliable channel carries only the tick and lands at 9.86 Hz.
The unreliable form is kept as a fallback for a deep backlog
(`arenaTickReliableBacklog`), and it needs its own sequence counter
(`clientState.unrelSeq`, from 1) plus the aux word (`auxFor(reliableSends)`);
reusing the reliable seq makes it jump by however many reliable sends happened
in between, and the client discards a packet whose sequence does not advance.

### Collisions (PARKED — needs the map's collision geometry)

Driving into rocks, buildings and trees does nothing, and it cannot be fixed
client-side. `WGVehicleFilter` never integrates its own physics — `bodyMatrix`
is *exactly* the entity position at every sample (measured with the Frida probe,
see "Why the client's filter does not simulate") — so the tank's position **is**
the server's hull and the client has nothing to collide against. The server has
to refuse the move.

That means the server needs the map's static collision geometry, which lives in
the `spaces/<map>/XXXXZZZZo.cdata_processed` chunks alongside the heightmaps
`mapdata.go` already reads. It is a different format from `terrain2/heights` and
has not been decoded.

Two cheap slices that do NOT need it, if this is ever picked up as a quick win:

- **Map borders.** The playable area is a box (Karelia: `(-500,-500)..(500,500)`,
  see `SpawnX`/`SpawnZ` in `login/arena.go`). `hull.step` already refuses a move
  that leaves the map via `settle` returning false, but only once the terrain
  lookup fails — an explicit box test is cheaper and exact.
- **Slope refusal.** `settle` already samples the terrain under the hull's four
  corners and derives pitch and roll from them, so the slope is in hand; refusing
  a step whose slope exceeds the tank's climb angle is a few lines. That buys
  "cannot climb cliffs", not rocks.

Trees are destructible and client-side; they do not block a tank in the first
place, so they are not part of this.

### The gun marker: NRL element `0x28`

The captured server sends `gunAnglesPacked` as a bare `0xb4` element (see the
tick shape above), and the *aiming* half of the gun — the shot position, the
shot velocity and the dispersion angle the crosshair is drawn from — rides
element `0x28`, `NRL_UNRELIABLE_MSG_TO_CLIENT` (VAR 2), which closes every tick
datagram. Its body is

```
06 00 01                      message type 6 on node 1, the NRL root
id_a u32   id_b u32           per-arena, constant within a battle
tick u32   prev_tick u32      10 Hz counter; prev_tick = tick-1
kind u8                       0x30 gun marker, 0x11 "unchanged"
d6 c3 c4 00 00 01             class tag, constant
flags u8                      0x20 = prev_tick holds data; 0 on the first
00                            constant
payload_len u8
payload
```

`0x13` TickSync's byte is the **low byte of the same counter** — at 14:17:38.143
the marker's tick is 1126474 and the datagram's `0x13` byte is 74, and
`1126474 & 0xFF` is 74. The first marker of a battle carries `flags` 0 and
`prev_tick` 0; every later one `0x20` and `tick-1`.

The `kind 0x30` payload is 39 B: a constant 9-byte prefix
(`20 00 20 02 00 83 82 01 01`), `shot_position` (3×f32), `shot_velocity`
(3×f32), `dispersion_angle` (f32), and a constant 2-byte suffix (`01 20`). It is
what the client's `Avatar.updateGunMarker(vehicleID, shotPos, shotVec,
dispersionAngle)` receives and `VehicleGunRotator.setShotPosition` draws the
crosshair from. Over one battle: 7183 ticks carry it, 408 carry the 8-byte
`kind 0x11` form (payload `20 00 00 02 01 73 20 00`, constant) in runs up to
101 ticks — the pre-battle countdown.

- `shot_position` is the gun's pivot: within 2.5 m of the vehicle, about 2 m up.
- `shot_velocity` is the barrel's direction times the shell's muzzle velocity,
  so its length is the shell speed — constant at 792.00 m/s for a whole battle,
  switching only with the shell.
- `dispersion_angle` is the gun's `shotDispersionAngle` times the client's own
  dispersion factor: 0.00365 at rest, 0.01185 while driving, back to 0.00367
  once stopped. The factor is
  `sqrt(1 + (speed*movement)^2 + (yawRate*rotation)^2 + (turretRate*turretRotation)^2)`,
  snapped up to immediately and decayed back over the gun's `aimingTime`
  (`Avatar.getOwnVehicleShotDispersionAngle`). The three factors come from the
  defs: chassis `shotDispersionFactors/vehicleMovement` (km/h → m/s) and
  `/vehicleRotation` (degrees → radians), gun
  `shotDispersionFactors/turretRotation` (degrees → radians), and the gun's
  `shotDispersionRadius` → `atan(r/100)`.

`id_a`/`id_b` are constant within a battle and **differ between battles** (five
flows of the capture, five different pairs), so they are per-arena. What the
server derives them from is not known — they appear nowhere else in the stream,
so they cannot be matched against the space id, the entity id or the arena id.
`arenaNrlIds` mints them from the arena id, which reproduces the only property
the capture establishes.

The reliable resend queue is keyed by **session**, not by address: the client
rebinds its socket on battle entry and a re-login abandons the old session
outright, and an address-keyed queue outlived both — a live run logged 15,344
resends, 13,429 of them 28 B lobby poll answers, all to the previous session's
port, and the position updates queued behind them. `Admit` retires the previous
session for the same account, `sweepStage1` retires stage-2 sessions silent for
`SessionIdleTTL` (60 s), and `readdr` moves a session's pending packets to its
new address on a rebind.

**Why the client's own physics never engages** (still true, and it is client
data, not the wire): `numLeftTrackContacts`/`numRightTrackContacts` are **0**,
`placingOnGround` false, `suspCompressionRate` 0 — for **both** vehicles, the
dummy included. `initVehiclePhysicsClient` builds the 40 damper springs (the
probe counts 40 `addDamperSpring` calls, 20 per side) but never calls
`configurePhysics`: only `initVehiclePhysicsServer`, `initVehiclePhysicsForced`
and `initVehiclePhysicsEditor` do, and
`BW::PyWGVehicleFilter::setVehiclePhysics` (`sub_142F075D0`) just forwards to the
filter's `setPhysics` (`sub_142F058C0`, storing at `filter+0x5E0`).
`WGVehiclePhysics::configure` is what sets up the ground materials ("failed to
setup ground materials"), so an unconfigured physics has none and its springs
find nothing.

Calling it by hand does not work either, and the reason is client data:

- `configurePhysics` starts with
  `typeDescr.type.xphysics['detailed'].get('vehiclePhysicsType', …)`, and
  `typeDesc.type.xphysics` has only `['engines', 'chassis']` — **no `detailed`**.
- Injecting `xphysics['detailed'] = xphysics` gets past that and then fails on
  `'axleCount'`: `xphysics['chassis']['Chassis_GB151_Headshaker']` has only
  `['grounds']`, while the vehicle XML carries `<axleCount>5</axleCount>` right
  next to it.

So the client's own `xphysics` is missing two fields the physics configuration
needs, and the vehicle physics is never configured. That is client data, not the
wire — no server message can supply it.

### Wheeled vehicles: `Vehicle.wheelsScroll` is what turns the wheels

A wheeled vehicle's wheels are not driven by the aux word's track scrolls. They
are driven by **`Vehicle.wheelsScroll`** — property 27, bare element `0xc2`,
`Tuple[0]{UINT8}`, one packed byte per wheel:

```python
def set_wheelsScroll(self, prev=None):
    for packedValue, scrollFilter in zip(self.wheelsScroll, self.__wheelsScrollFilter):
        scrollFilter.input(BigWorld.time(), WoT.unpackWheelScroll(packedValue))
```

`WoT.unpackWheelScroll` (`sub_142437050`) is

```
value = (int8)byte * 0.19607845 - 24.90196
```

i.e. a signed byte over `[-50, 0]` rad/s at `50/255` per step, negative for
forward travel. `packWheelScroll` in `login/drive.go` is the inverse.

The filters come from `createWheelFilters(typeDescriptor)`
(`client_common/shared_utils/vehicle_utils.py`), which builds
`getNonTrackWheelsCount()` scroll filters and `getSteerableWheelsCount()`
steering filters. `Vehicle.set_wheelsScroll` zips `wheelsScroll` against the
**scroll** list only, so the tuple length is `getNonTrackWheelsCount()` — the
number of `wheel` entries carrying `<nonTrack>true</nonTrack>`, NOT every wheel.
The EBR 105 declares 16 wheels and only 8 are non-track; a 16-byte tuple is
silently truncated and a short one leaves the tail un-driven.

Without this element no wheel on a wheeled vehicle turns at all, which is what
"the wheels don't spin" was.

**The element id is `ENTITY_PROPERTY_BASE + FullIndex`, and the base is `0xA7`
for every entity** — the reference toolkit's
`ElementIdRange::new(0xA7, 0xFE)`. `FullIndex` is the client's
`allocateClientServerFullIndexes` order (fixed sizes first and ascending, then
the variable ones in declaration order), which is `entdef.Entity.CSPropsOrdered`.
`wheelsScroll` is FullIndex 27, so the element is **`0xc2`**.

Four ids in the capture pin the base independently, and each matches the def's
own table:

| element | FullIndex | property | width |
|---|---|---|---|
| `0xa8` | 1 | `isStrafing` | 1 |
| `0xb3` | 12 | `botDisplayStatus` | 1 |
| `0xb4` | 13 | `gunAnglesPacked` | 2 |
| `0xb6` | 15 | `engineMode` | 2 |

Walking every `S>C` tick in `captures/proxy-20261031-1358.hex` with that table
parses 1184 packets cleanly and finds exactly those four property ids, so the
base is not a guess.

The header is **one byte**: the property's `VariableLengthHeaderSize` is 1, which
is `ElementLength::Variable8`. And because `Tuple[0]` has no fixed element count,
the payload starts with that count — `Codec::write` does
`write_packed_u24(list.len())` then the elements, and `read` takes the count the
same way. So the element is

```
c2 <len8> <count> <count bytes>          len8 = 1 + count
```

Omitting the count is what killed the client: `c2 08 <8 bytes>` made it read the
first wheel byte `0x80` as a count of 128 out of an 8-byte element and die on
`MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`. The earlier `0xc3` attempts
failed the same way for the same reason, on top of the wrong id.

### Siege mode (the X key)

The client's X key is `SiegeModeControl.__switchSiegeMode`, which sends

```python
player.cell.vehicle_changeSetting(VEHICLE_SETTING.SIEGE_MODE_ENABLED, enableSiegeMode)
```

— `Avatar.vehicle_changeSetting`, **cell index 12**, a `UINT8` code and an
`INT32` value, fixed 5 bytes. `SIEGE_MODE_ENABLED` is 3.

Two things have to go back, and both are needed:

- **`Vehicle.siegeState`** (property 4, bare element `0xab` — `0xa7 + 4`).
  `Avatar.__isOwnVehicleSwitchingSiegeMode` reads it to block shooting while the
  switch is in flight, and `Vehicle.set_siegeState` feeds the prebattle setups
  panel.
- **`OwnVehicle.siegeStateStatus`** — `FixedDict{?status:UINT8, endTime:FLOAT32,
  timeLeft:FLOAT32}`, index 10 of `ownVehicleProps`. Its setter is
  `OwnVehicleBase.update_siegeStateStatus` → `Avatar.updateSiegeStateStatus` →
  `Vehicle.onSiegeStateUpdated`, which is what actually changes the model, the
  gun's pitch limits and the sound. `Avatar.updateSiegeStateStatus` is NOT a def
  method — it is reached only through this property.

  **It is not optional.** Measured live with only `Vehicle.siegeState` sent:
  `Vehicle.siegeState` read 2 while `SiegeModeControl.__currentState` was still
  0, because `notifySiegeModeChanged` is called only from
  `Vehicle.onSiegeStateUpdated`. The consequences are that the HUD never shows
  siege, `typeDescriptor.onSiegeStateChanged` never runs so the composite
  descriptor never switches to `VEHICLE_MODE.SIEGE`, and
  `__switchSiegeMode`'s `enableSiegeMode = __currentState not in (SWITCHING_ON,
  ENABLED)` is always True — pressing X can only ever ask to ENABLE, so the
  state never toggles back off.

**On the wheeled French tanks siege mode is the FAST mode**, so the hull's
envelope has to swap with it. The EBR 105's base def is 70/50 km/h and its
`F108_Panhard_EBR_105_siege_mode` sibling is **91/65** — the sibling is a
separate vehicle def, not a section, so the limits are read from
`<vehicle>_siege_mode.xml` and `st.hull.Limits` is swapped on the switch.
Without that the tank is capped at the travel limit whatever the client shows.

`VEHICLE_SIEGE_STATE` is `DISABLED 0, SWITCHING_ON 1, ENABLED 2, SWITCHING_OFF 3,
PILLBOX_ENABLED 4`. The switch times are the vehicle's own
`siege_mode/switchOnTime` and `switchOffTime`; they are **0** on the wheeled
French tanks, so the end state is sent directly — a SWITCHING state with
`timeLeft` 0 would leave `__isOwnVehicleSwitchingSiegeMode` true and the gun
blocked. Non-zero times send SWITCHING first and the settled state after.

### Shooting: the gun fires, nothing is hit

Scope is deliberately "the gun fires and reloads, nothing is hit" — with
`-battle-team-size 0` there is no target, so penetration, damage and the armour
model are all deferred.

**The client fires its own visual.** `Avatar.shoot` sends
`cell.vehicle_shoot()` and then starts a 0.12-0.2 s timer
(`__startWaitingForShot`, clamped from `LatencyInfo().value[3] * 0.5`). If the
server has not answered by then, `__showTimedOutShooting` calls
`vehicle.showShooting(...)` and the tracer, muzzle flash and recoil all play
anyway. So the server is not what makes the shot visible — it is what makes the
*second* shot possible.

**`Avatar.vehicle_shoot` is cell index 0 with zero arguments** (fixed size 0), so
there is nothing to decode. `answerShoot` only starts the reload.

**The blocker was the ammunition, not the shot.** `AmmoController.canShoot`
returns `(False, CANT_SHOOT_ERROR.WAITING)` while `__currShellCD` is None, and
`__currShellCD` is only ever set from `Avatar.__updateVehicleSetting` on
`VEHICLE_SETTING.CURRENT_SHELLS` — which first requires
`ammoCtrl.shellInAmmo(value)`, i.e. the shell must already be in
`vehicleAmmoList`. Both were being sent as their zero values (empty arrays), so
the client refused every shot before it ever reached `cell.vehicle_shoot`:
nothing was sent and nothing fired.

The shell's compact descriptor is
`items.makeIntCompactDescrByID('shell', nation, id)` =
`(id << 8) + 10 + (nation << 4)`, where 10 is `shell` in `ITEM_TYPE_NAMES`, the
nation is its index in `nations.NAMES` (`ussr, germany, usa, china, france, uk,
japan, czech, sweden, poland, italy`), and `id` is the shell's own `id` child in
`<nation>/components/shells.xml`. Verified against the live client: a UK
5.5-inch AP Mk II is id 332, nation 5, and the client's own
`typeDescriptor.shot.shell.compactDescr` reads **85082**.

The reload rides `OwnVehicle.vehicleGunReloadTime`
(`FixedDict{?endTime:FLOAT32, baseTime:FLOAT32, timeLeft:FLOAT32,
clipTime:FLOAT32}`), an NRL dynamic-component property, so it goes out as a node
update (`EncodeNrlPropertyUpdate`, index 2 of `ownVehicleProps`) rather than a
bare element. `OwnVehicleBase.__getTimeLeftBaseTime` reads `timeLeft` directly
once the vehicle is attached, and `baseTime` is the reload's length, so both
carry the gun's own `reloadTime`; `endTime` is in the seconds
`BigWorld.serverTime()` is in.

**The reload has to be closed by the server, not just started.**
`ReloadingTimeState.setTimes` stores `_actualTime` verbatim and nothing counts
it down — `isReloadingFinished()` is `self._actualTime == 0` and
`AmmoController.isGunReloading` is its negation. One update with
`timeLeft = reload` therefore leaves the gun "reloading" forever: measured, one
shot fired and every later shot was refused with `CANT_SHOOT_ERROR.RELOADING`.
`answerShoot` spawns `finishReload`, which sleeps the reload and sends a second
update with `timeLeft` 0 (and `baseTime` still the reload), which also clears
`_waitReloadingStartResponse` through `stopPredicateReloading`.

### The speedometer

`Vehicle.getSpeed()` is `__speedInfo.value[0]`, and `__speedInfo` follows
`filter.speedInfo`, so the number is the client's `WGVehicleFilter`. It tracks
the hull: measured 0 → 0.3 → 1.7 → 4.8 → 9.8 → 11.5 m/s over a 3 s pull-away.

The **km/h digits** next to the cruise-mode indicator in the damage panel are
`VEHICLE_VIEW_STATE.SPEED`, which `damage_panel` maps to `as_updateSpeedS`. It
is polled by `_VehicleUpdater` every `VEHICLE_UPDATE_INTERVAL` (30 ms) from
`Avatar.getOwnVehicleSpeeds()` → `vehicle.speedInfo.value[0] * 3.6`.

That updater was never started, which is why the digits sat at 0 for the whole
battle. `_VehicleUpdater.start()` is the last thing `_setup` does, and `_setup`
runs `onVehicleControlling` first — where `timers_panel.__onVehicleControlling`
replays the cached `VEHICLE_VIEW_STATE.SMOKE` through `__updateSmokeTimer`:

```python
equipment = vehicles.g_cache.equipments()[smokeInfo['equipmentID']]
duration = equipment.expireDelay if smokeInfo['expiring'] else equipment.totalDuration
```

The cached value was `OwnVehicle.smokeInfo`'s **zero value** — a dict with
`equipmentID: 0` — and `equipments()[0]` is an `Extinguisher`, which has no
`totalDuration`. The `AttributeError` unwound through the event and aborted
`_setup` before `updater.start()`. `SMOKE_INFO` is `AllowNone`, so the server
sends `None` and `__updateSmokeTimer` takes its `_hideTimer` branch. With that,
`updateTI` is live and the digits track the hull: measured `None → 2 → 5 → 8 →
11 → 14 → 17 → 19 → 23 → 25 → 28 → 31 → 34` km/h over a 3 s pull-away.

(The separate `SpeedometerWheeledTech` gauge is a different thing, gated on
`vehicle.hasSpeedometer` — false for every tracked vehicle.)

The filter also stays in **lag mode** (`isLaggingNow` true, `movementSignals`
0): the engine never calls `filter.input()` for this vehicle, so the filter
measures the position deltas to produce `speedInfo` but does not drive the
visual — `filter.bodyMatrix` is exactly the entity position at every sample.
`notifyInputKeysDown` does reach the physics (it writes `+5A4/+5A8/+5AC`), so
the input is recorded; it is the position feed that is missing.

### What the vehicle's creation run has to carry

`Vehicle.avatarID` is `ALL_CLIENTS` with **no** `DetailLevel`, so it belongs to
the outer property run — the one the creation element carries. It was never
sent at all: the creation run held only `publicInfo`, `health` and
`isCrewActive`, and the `updateEntity` that follows carries only the
`MY_VEHICLE` (inner) properties, so the client read 0. Its value is the
**Avatar's entity id**, not the account id — the client compares it with
`BigWorld.player().id` (`BattleReplay`'s `hasEnteredAoI`), and the reference
sets it from `avatar.id()`.

`ownVehicleAuxPhysicsData` goes out **every tick**, as the reference's `step`
does, not only when it changes. It carries the hull's roll, pitch and yaw and
the tracks' speeds, and the client builds the stabilised vehicle matrix the gun
aims from out of it — a value held back because it "did not change" is a stale
aim frame.

Still not modelled, and why:

- **`GunMarkerComponent`.** The reference attaches one to the vehicle and
  updates `gunMarker` every tick. It only feeds `Avatar.updateGunMarker`, which
  is the *server aim* marker shown when the player turns on `useServerAim` — not
  the reticle, which the client computes itself.
- **`gunAnglesPacked` is sent** (bare `0xb4`, unreliable tick). The reference
  packs the real pitch into it every tick; this server does the same, because
  the client's physics is inert and it cannot derive the turret yaw on its own.
  The elevation also reaches the client through the NRL marker's
  `shot_velocity`, which carries the barrel's full direction.
- **`isStrafing`, `damageStickers`, `publicStateModifiers`, `vehPostProgression`.**
  The reference sets them explicitly; their zero values are the same values
  (`false`, empty list), so leaving them out changes nothing.

### Driving: the hull is simulated, and the position goes by alias

The client sends `Avatar.vehicle_moveWith(flags u8)` — cell method 2, element
`0x12` — whenever the driver changes gear or direction, and drives its own hull
locally. The server has to simulate the same hull and stream the result, or the
tank never leaves the spawn: `login/drive.go` steps it at the vehicle's own
limits (from the item defs: `speedLimits/forward`, `speedLimits/backward`, the
chassis's `rotationSpeed`), rests it on the terrain, and derives the engine mode
and gear the client's track scroll and engine sound follow. The hull keeps its
velocity in world space and the tracks' lateral grip pulls it toward the
heading, so a turn carries a slip angle and the handbrake can break the hull
loose.

The flag byte is `MOVEMENT_FLAGS` (`client/avatar.py`): forward 1, backward 2,
rotate left 4, rotate right 8, cruise 50 16, cruise 25 32, and **`BLOCK_TRACKS`
64 — the handbrake**, which the client's space bar (`CMD_BLOCK_TRACKS`) folds
into the same byte. It locks the tracks: the hull brakes and a stationary hull
cannot pivot, but a moving hull keeps its momentum — the lateral grip drops, so
the steering turns the hull under the velocity vector and the tank slides (the
drift). A server that stops reading at bit 5 drives straight through it.

The vertical axis is simulated too, and the hull is a body resting on the
ground rather than glued to it. `settle` follows the terrain while the drop is
within what the ground's own gradient along the travel predicts — sampled
BEHIND the hull, because sampled ahead it already sees the cliff face and
calls it followable — plus the suspension's travel (0.3 m), and no steeper
than 45° (the heightmap turns a cliff into a steep ramp over one cell). Past
either, the hull goes airborne: gravity owns its height and it lands on the
ground below. Airborne the hull keeps its horizontal velocity and cannot
steer. A rule that only compared the drop to the horizontal step against a
fixed 45° followed every ledge a tank could drive over, so the tank could
never jump.

Two wire details cost a round each:

- **The position of anything but the player's own entity is addressed by AoI
  alias**, so the Vehicle needs a real one — `enterAoI` with alias 0 leaves it
  unaddressable and the client never learns where the tank is. `VehicleAlias` is
  1.
- **`AvatarUpdateAliasDetailed` (0x1D) carries the position outright**, not
  relative to the `RelativePosition` (0x16) reference. Sending zero from the
  reference put the tank at the world origin, which on Karelia is under the
  terrain. The player's own entity is the Avatar, which rides the vehicle, so
  its position is derived and `AvatarUpdatePlayerDetailed` (0x1E) is not what
  moves the tank.

`ownVehicleAuxPhysicsData` carries the hull attitude, both track speeds and the
engine RPM, packed as `WoT.packAuxVehiclePhysicsData` does — a level, still tank
is `0x55558004004000` with the RPM field at idle, which is what
`TestHullAuxPhysicsDataIsLevelAtRest` pins.

### Shooting the dummy: the shell is traced and the damage streamed

`Avatar.vehicle_shoot()` is a cell call with no arguments: the server owns the
gun marker, so it resolves the shot from the marker it already streams. The
shell comes from the vehicle's own item defs — the default `shots` entry gives
speed, penetration and ballistics, the shell's def gives damage, kind, caliber
and the `shot_effects.xml` hit effect — and `login/damage.go` traces it against
the synthetic opponent's hull box.

The trace follows the client's own rule, not a random roll: the effective
armour is the face's nominal value over the cosine of the impact angle, the
penetration is the shell's 100 m value ±25%, and a piercing hit does the
shell's damage ±25%. The TOG II's defs give 76.2 mm front and sides, 50.8 rear
and 25.4 roof. An HE shell that does not pierce explodes on the armour for half
its damage less 1.3 mm per millimetre of armour.

The result goes out as the client's own methods, selected the way the engine
expects (`selectEntity(dummy)` first, then `selectPlayerEntity` for the
Avatar's):

- `Vehicle.showDamageFromShot` — the hit point (`VEHICLE_HIT_POINT`: the hull
  part and hit effect in the low bytes, the enter/exit points quantized over
  the hull box) and the damage;
- `Vehicle.showShooting(burst, gunInstallationIndex, shellKind)` — the muzzle
  flash and smoke, on the own vehicle (a Vehicle method, so
  `selectEntity(vehicle)` precedes it; the tracer that follows re-selects the
  player). The reference server sends it right after the tracer;
- `Vehicle.damageStickers` — the persistent shell hole. It is an
  `ALL_CLIENTS` property (`ARRAY of VEHICLE_HIT_POINT`), so it rides a
  property update, not a method call: one hit point per pierced hit, its
  segment context the sticker id (`shot_effects.xml`'s
  `targetStickers/armorPierced` name resolved to its index in
  `damage_stickers.xml`), its params the pierced hit effect.
  `showDamageFromShot` alone only plays the impact effect. The shell's
  `<effects>` node is a packed BLOB in the shipped defs, so it must be read
  with `Section.StrVal`, not `AsString` (which returns "" and silently
  disables the sticker). The segment's fractions are quantized over the hit
  PART's own collision bounds in that part's frame — the client's
  `getBoundingBox(part)` is the part's `HKBodyFlagsData`
  `minBounds_`/`maxBounds_` (TOG II hull
  `(-1.5622,-0.8706,-5.2344)..(1.5622,0.7324,4.2737)` at
  `<hullPosition>0 1.3553 0`; turret
  `(-1.025,-0.2735,-1.4434)..(1.025,0.9986,1.0816)` at
  `<turretPositions><turret>0 0.704143 1.81585`, which is relative to the
  HULL, so the turret sits at 2.059 m and rises to 3.058 m). A centred guess
  put every hole a few tenths of a metre off the aim point. The dummy is
  traced against all three parts and the segment carries the one that was hit
  (index 1 hull, 2 turret, 3 gun): with only the hull, a shell aimed at the
  turret passed over the hull's 2.088 m top and did nothing at all. The gun
  (`Gun_01.havok`, 25.4 mm) is a DEVICE: a penetrating hit damages the gun
  module and does no hull damage (`ARMOR_PIERced_DEVICE_DAMAGED`, 6, which
  the client shows as a critical hit);
- `Vehicle.onExtraHitted(extraIndex, hitPoint)` — the module or crewman a
  penetrating hit damaged, and where. The index is the client's
  `typeDescr.extras` order (the common `vehicle.xml` `<extras>` list; the
  TOG II's engine 62, ammo bay 63, fuel tank 64, radio 65, tracks 66/67, gun
  68, turret rotator 69, optics 70, crew 71-78). A wrecked track also gets
  `Vehicle.startOrUpdateExtraFromOutside("leftTrack0Health", <pickled None>)`,
  whose `TrackHealth._start` calls `addCrashedTrack` — the broken-track
  visual. The module HP are the item defs' own; a hit takes half the shell's
  damage, and a tank whose whole crew is dead is dead.
- A **fire** is a dynamic component, not a property: `Fire` (NRL type 64)
  attached to the burning vehicle's node with `fireInfo` =
  `{deviceExtraIndex, notificationIndex, attackerID, equipmentID, startTime}`
  (`FIRE_INFO`). Attaching it starts the flame (`isOnFire()` is `'fire' in
  self.dynamicComponents`); its burn is the server's — 1% of max health a
  second as `onHealthChanged` under `ATTACK_REASON.FIRE` — and unlinking the
  component (`0x22`) puts it out.
- `Vehicle.health` — a bare property element `[0xB5][i16]`, then
  `Vehicle.onHealthChanged(new, old, attacker, SHOT, -1)`. It must NOT use
  `EncodePropertyUpdate`: that writes `[id][u16 len][value]`, the
  `updateEntity` run's form, and standalone the client reads the length as
  the health and the value's low byte as the next element id (health 926 =
  `0x039E` → element `0x9E` = exposed method 80, out of range on the
  11-method Vehicle, then `REASON_CORRUPTED_PACKET` and a crash);
- `Avatar.showShotResults` — the shooter's hit marker, with
  `VEHICLE_HIT_FLAGS` (`0x100110` pierced, `0x100020` resisted, `|1` killed);
- `Avatar.showTracer` / `Avatar.stopTracer` — the shell itself.

The shot also consumes a shell: `OwnVehicle.vehicleAmmoList` is re-sent with
the fired shell's `quantity` decremented (the list is the garage's saved
layout, kept per session), or the client's ammo panel keeps the count it got
at arena entry. The loaded shell is the first one of that layout with ammo
left (the reference's `Gun::new` / `first_left`), and `NEXT_SHELLS` is the
SAME shell at entry: the reference constructs its gun with `next_shell:
loaded`, and only `select_next` moves it when the player picks a shell once.
Sending the first OTHER shell pre-highlights it in the ammo panel, so the
player enters one press into the cycle and the two presses that should reach
the third shell only reach the second. `vehicle_changeSetting` codes 0
(`CURRENT_SHELLS`) and 1 (`NEXT_SHELLS`) move the session's loaded/next shell
and re-send `vehicleSettings`, so the decrement follows the shell the client
shows as loaded. A `CURRENT_SHELLS` change also restarts the gun's FULL reload
(`vehicleGunReloadTime`): the client's `changeCurrentShell` sets its own
reload state and waits for the server's update, so without it the gun stays
"reloading" forever. A `reloadGen` counter keeps the previous reload's
completion timer from closing the new one.

The exposed ids are the defs' indexes (`showDamageFromShot` 10,
`onHealthChanged` 4, `showShotResults` 54, `showTracer` 37), and the engine's
`EntityMethodDescriptions::exposedMethod` (`sub_142CB5E10`) range-checks them
against the entity's own table. A kill also updates the arena's
`AvatarVehiclesInfo.vehicles`: the victim's `isAlive` goes false with a
`deathInfo` (the killer and the SHOT reason), and the shooter's
`stFrags`/`frags` count the kill. The whole list is re-sent as an NRL property
update, which is what greys the row in the team panel, shows the kill message
and puts the 1 in the kill column.

### Dynamic components: type id, children, property order

Three rules, each of which cost a client crash to learn. The full id table is
in `ENTITY_TYPE_IDS.md`.

1. **The type id is an index into the client's `EntityType` table**, entities
   first (0..52) then the dynamic components in `scripts/components.xml`
   order: `OwnVehicle` 53, `InAoEZone` 54, `AvatarVehiclesInfo` 126. An id that
   names an *entity* is survivable — the client logs
   `PyEntity::createDynamicComponent: <Name> failed to load` and carries on,
   which is how `OwnVehicle` at 50 (`HWDeathZone`) was caught.
2. **The child list is properties, then client methods, then a trailing
   child.** `OwnVehicle` declares 23 + 11 + 1 = 35. The client maps a child's
   position onto its own tables, so a list that stops after the properties
   makes it read the trailing child as client method 0. A method child carries
   its exposed id as a packed u24 (one byte below 255, else `0xFF` + three
   bytes); the trailing child carries nothing.
3. **Properties are read in size-sorted order, not declaration order** —
   fixed sizes first and ascending, then the variable ones in declaration
   order (`allocateClientServerFullIndexes`). `syncVehicleAttrs` is the only
   fixed-size `OwnVehicle` property (10 B), so it leads; everything else is
   `AllowNone` and therefore variable. Declaration order shifts every value by
   the size difference and the client dies on
   `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`.

### A throw in `Avatar.setClientReady` costs the whole battle

`setClientReady` sets `isOnArena`, registers `onPeriodChange`, calls
`arena.invalidateVehiclesPosition()` and fires `g_playerEvents.onAvatarReady`
— all *after* a loop over every vehicle that calls `__startVehicleVisual`.
One exception in that loop aborts the rest, and the client stays loaded but
out of the arena: no gun, minimap at 0,0, no period handler.

The one that bit us was `dog_tags_ctrl.__addDogTagMarker`, which reads
`vehicle.dogTag['dogTag']` and expects a BACKGROUND **and** an ENGRAVING
component. `Vehicle.dogTag` is an `ALL_CLIENTS` property, and its default has
no components, so `getComponentByType(...)` returns `None` and
`.componentDefinition` raises. The client logs it as
`Attribute "setClientReady" not found, exception 'NoneType' object has no
attribute 'componentDefinition'` — easy to miss, and it looks like a GUI
problem rather than the reason the battle is inert.

The fix is to send a real tag, as the reference's `DEFAULT_DOG_TAG` does:
components `(300, grade 9)` and `(66, grade 0)`, which the client's own
`componentConfigAdapter` resolves to ENGRAVING and BACKGROUND. It rides the
Vehicle's creation run (`dogTag` is `ALL_CLIENTS` with no `DetailLevel`), and
**every** vehicle needs it — the dummy enemy included, or the same throw comes
back from its `onVehicleEnterWorld`. With it in place `dog_tags_config.enabled`
can stay `true` and `setClientReady` runs to the end: `isOnArena` true, the
period handler registered (the `onPeriodChange` handler count goes 8 → 9), and
the battle live.

## Matchmaker

The queue is real state, not a stub. Three commands drive it
(`Account.pyc` `enqueueRandom` / `dequeueRandom` / `requestQueueInfo`):

| Command | Wire | Answer |
| --- | --- | --- |
| `CMD_ENQUEUE_IN_BATTLE_QUEUE` (700) | `doCmdIntArr([queueType, vehInvID, gameplaysMask, arenaTypeID, randomFlags])` | `onEnqueued(queueType)` or `onEnqueueFailure(queueType, code, msg)` |
| `CMD_DEQUEUE_FROM_BATTLE_QUEUE` (701) | `doCmdInt(queueType)` | `onDequeued(queueType)` |
| `CMD_REQ_QUEUE_INFO` (502) | `doCmdInt3(queueType, 0, 0)` | the `1a/67` census `{players, classes}` |

**The census is per queue type.** The client polls it every 5 s for the
queue it is in (`battle_queue.pyc` `QueueProvider.requestQueueInfo`), so a
random-battle poll must not count a ranked entry. `classes` is indexed by
the client's own `constants.VEHICLE_CLASSES` — lightTank, mediumTank,
heavyTank, SPG, AT-SPG — and an entry whose vehicle could not be resolved
counts in `players` but lands in no bucket, which is why the two can
differ.

**The vehicle is resolved server-side.** The enqueue carries only the
inventory id; the class and tier live in the compact descriptor, so the
handler looks it up in the session's garage. That lookup is what makes the
census truthful, and it is why `lobby.ParseIntDescr` had to be fixed: a
vehicle whose type id is above 255 carries
`EXTENDED_VEHICLE_TYPE_ID_FLAG` in its low nibble, and
`getTypeOfCompactDescr` subtracts it back off for the simple item types.
Without that, 111 of the 1256 ownable vehicles read as item type 3 (turret)
instead of 1 (vehicle).

**A squad queues as one group.** The leader's enqueue puts every member in
atomically (`Queue.EnqueueGroup`), and only the leader may do it — a member
gets `JOIN_FAILURE.QUEUE_FORBIDDEN`. A squad member's vehicle is not on the
wire, so it is resolved from that account's own garage.

**The matchmaker** (`server/matchmaker.go`) is the pure formation rule:
oldest entry anchors the battle and fixes a ±2 tier band, a squad goes to
one team, and the two sides fill alternately. It is tested on its own and
runs on every enqueue, but a formed battle is only **logged** — the handoff
(`Account.onArenaCreated`) makes the client wait for a `CreateCellPlayer`
that a lobby-only server cannot send, so sending it would hang the client
on the loading screen. That is `TODO.md` #1.

## Economy

Every purchase the client can trigger over the game protocol is applied
against per-account state, and the new balances come back through
`Account.update(diff)` — the client never reads a balance out of a command
answer (`Stats` callbacks take `resultID` only).

| Command | Wire | What it does |
| --- | --- | --- |
| `CMD_EXCHANGE` (202) | `doCmdInt4(shopRev, gold, credits, 0)` | gold → credits at the server's rate |
| `CMD_FREE_XP_CONV` (203) | `doCmdIntArr([shopRev, xp, gold, …vehCDs])` | gold → free XP |
| `CMD_PREMIUM` (204) | `doCmdInt3(shopRev, days, arenaUniqueID)` | gold → premium days |
| `CMD_BUY_SLOT` (205) | `doCmdInt3(shopRev, 0, 0)` | credits → one garage slot |
| `CMD_BUY_BERTHS` (206) | `doCmdInt3(shopRev, packs, 0)` | gold → barracks berths |
| `CMD_SET_RESERVES_PIGGY_BANK_DEV` (10084) | `doCmdInt2(credits, gold)` | set the two reserves |
| `CMD_SMASH_PIGGY_BANK_DEV` (10088) | `doCmdInt(6)` | pay the reserves out |

The rates are the server's, not the client's: `Stats.exchange(gold,
credits)` sends both numbers, and trusting the credits would let a client
name its own price. `server.Economy` implements `login.EconomyBackend`, so
the wire layer never touches the store.

**The shop document carries the price tables.** `Stats.exchange` /
`convertToFreeXP` / `upgradeToPremium` read them through the RAW `Shop`
object, not through the requester that holds the client's defaults — so an
absent key is `None` and the flow aborts with "Result of the getPremiumCost
request is None" before it sends anything. `ShopDoc` therefore emits
`premiumCost` (`{days: gold}`), `slotsPrices` (`(base, [[currency,
amount]])`), `berthsPrices` (`(base, packSize, [gold])`),
`freeXPConversion` (`(xp, gold)`), `sellPriceModif` and `clanCreationCost`
alongside the exchange rates.

**Premium is per-account state**, not a constant: `PlayerState.PremiumExpiry`
rides `account.premiumExpiryTime` and the `premium` block, and a purchase
extends it from `max(now, current)` clamped to `server.MaxPremiumExpiry`
(32535216000, 3001-01-01) — the client's date formatter rejects anything
past that. A fresh account starts at the ceiling, so a purchase there
still costs gold but cannot move the clock.

**The piggy bank** is two reserves (`piggyBank.credits`, `.gold`) plus the
two smash timestamps, carried in the full sync and in every economy push.
The live server smashes the bank from a service-channel push; a private
server has no such push, so the dev command pair is the honest path to the
same state.

**Not on the game protocol:** the premium purchase BUTTON is web-only
(`PremiumAccountBuyer` is constructed only in
`web/web_client_api/shop/trade.pyc`), and the goodie catalog that defines
discounts and personal offers is fetched over HTTP from
`productsCatalog.url`. See `TODO.md` #11.

## Crew

Assigning a tankman to a tank slot is `CMD_EQUIP_TMAN` (105), sent by
`account_helpers/Inventory.pyc equipTankman` as
`doCmdIntArr([vehInvID, slot, tmanInvID, groupID, groupSize])`; `tmanInvID
= -1` empties the slot (the drag-to-barracks path). The answer is the
ordinary command response, and the new assignment reaches the client
through `Account.update(diff)` — the client never reads state out of a
command answer.

**The assignment lives in one place: the vehicle's crew list.** The client
builds a vehicle's crew from `inventory[1].crew[vehInvID]`
(`InventoryRequester.__makeVehicle` → `value('crew', [])`) and a tankman's
vehicle from `inventory[8].vehicle[tmanInvID]` (`__makeTankman` →
`value('vehicle', VEHICLE_NO_INV_ID)`). The tankman's own compact
descriptor only carries the vehicle TYPE it is trained for, never the
instance, so there is no second copy to keep in step — the server derives
the tankman→vehicle map from the crew lists when it builds the sync.

`server.Crew` implements `login.CrewBackend` and stores the list in
`PlayerState.Garage[i].Crew` (one tankman instance id per slot, 0 for an
empty slot). One assignment can touch three things, and the push carries
all of them:

- the target vehicle's list, with the tankman in `slot`;
- the vehicle that held the tankman before, with that slot cleared (a
  tankman can only sit in one tank);
- the tankman that was in the slot, back to the barracks (`-1`).

`SeedGarage` carries the crew across a re-seed by compact descriptor, so a
server restart does not empty every tank.

## Storage

`server.Store` is the persistence boundary — a domain-level interface
(accounts, state), not a SQL one. `SQLiteStore` is the only
implementation today; swapping in PostgreSQL means writing another
`Store`, nothing else.

Driver: `modernc.org/sqlite` (pure Go, no cgo), so the tree still
cross-compiles.

```sql
accounts(id, name UNIQUE, pass_hash, roles, created_at)
player_state(account_id PK → accounts, data JSON, updated_at)
social(dbid PK, data JSON, updated_at)   -- XMPP roster, block list, notes
```

## The bundle is a sequence of documents

The stage-2 flood is **not one pickle**. It is a sequence of proto-2
documents, and the second one is the account's state. The decoder used to
swallow the second document's `PROTO` opcode (it read it as a no-op and
carried on), so the account data was invisible and the bundle looked like
pure config.

`proxy-20261014-1752` flow `35493->` is the capture that shows it:

| | |
|---|---|
| stream | 249 464 B, 204 frames |
| document 0 | 374 objects — static lobby config (shop, matchmaker, missions, `cust_progress_*`) |
| document 1 | 42 objects — **the account** |
| tail | 3 651 B, not pickle (channel-framed packets) |

Document 1 holds `stats` (`credits`, `freeXP`, `dossier`, `vehTypeXP`,
`dummySessionStats`), `piggyBank.credits`, `account.globalRating`,
`inventory`, `dogTags`, `quests`, `tokens`, `battlePass`, `wtr`,
`sessionStats`, `prevRev` and `rev`. The captured player's values:
`stats.credits` = 12 715 044, `stats.freeXP` = 2 003,
`piggyBank.credits` = 34 875.

Two consequences:

- **The account's economy is in the bundle, not the smalls.** The smalls
  carry `freeXP` (`1a/69`) and the account id (`1a/76` `databaseID`);
  credits only exist here.
- **The document's outer dict is never closed.** The flood is cut short
  before its `SETITEMS`, so the pairs are siblings on the stack rather
  than entries of one dict. `BundleDoc.pair` resolves them by "the node
  after the string node".

### What is served

The economy reaches the client in the **full-sync answer** (see "The sync
answer" above): `stats.credits`, `stats.gold` and `stats.freeXP` come from
the account's `PlayerState`, and the 1a/69 stats small carries `freeXP`
again for the client's own stats cache.

`server.ApplyState` / `server.BulkPatcher` are the *bundle-patching* path
from the capture-replay era: they rewrite `stats.credits`/`stats.freeXP`
inside a captured bundle in place (length-preserving, so a value that
would need a wider pickle opcode is refused rather than resizing the
stream). The server no longer uses them — the bundle is authored, not
patched — but they stay as the tested mutation pipeline for
`cmd/wotbundle` and for anyone driving a captured bundle.

The 2.4.0 capture's account document (document 1 of the flood) is the
shape reference for the garage:

| key | content |
|---|---|
| `stats` | `credits`, `freeXP`, `dossier` (blob), `vehTypeXP`, `dummySessionStats` |
| `piggyBank` | `credits` |
| `account` | `globalRating` (float) |
| `inventory` | the garage: `{itemTypeIdx: {invID: {compDescr, …}}}` |
| `sessionStats`, `wtr`, `battlePass`, `dogTags`, `quests`, `tokens`, `eventsData`, `cache`, `prevRev`, `rev` | per-session and progression state |

The 2.4.1 flow carries no account document at all (one document, the
config), so on that build the same state rides the sync answer instead.

### Authoring a bundle

The bundle can be built rather than replayed, in three layers:

| layer | API | what it does |
|---|---|---|
| `lobby` | `NewDict`/`NewList`/`NewTuple`/`NewInt`/`NewString`/`NewUnicode`/`NewBool`/`NewNone`, `Set`/`Append`/`Get`, `EncodeDocument` | builds pickle nodes and serialises a document |
| `server` | `NewBundle().Document(...).Encode()`, `FromCapture` | composes documents into a bundle stream |
| `login` | `BuildFrames`, `ReadFrames`, `FrameSize` | splits a stream into the flood's fragment chain and back |

A node built in code has no `Raw` and no `Recipe`, so the encoder writes
it canonically — `emitPairs`/`emitItems` fall back to one
`SETITEMS`/`APPENDS` over the items, which is what cPickle produces for a
literal. That is the difference between patching a capture and authoring
one.

`BuildFrames` uses the flags word the flood's fragments carry (`0x0078` =
ON|RELIABLE|SEQ|FRAG), whose 12 B trailer is `(first, last, seq)` — read
off the capture, and the reason a chain reassembles by position rather
than arrival order. A 1223 B payload produces the 1252 B datagrams every
genuine flood uses.

`wotbundle` drives both directions over one JSON form:

```sh
# capture -> JSON (inspect what the client actually receives)
wotbundle -from ../captures/proxy-20261014-1752.hex -flow 35493-> -doc 1

# JSON -> bundle, and optionally the frames
wotbundle -json spec.json -out bundle.bin -raw -frames <hexkey>
```

`-json` decodes its own output before writing it, so a spec that cannot
round-trip fails loudly.

### Carrier sources are split

No single capture carries both halves of what the server needs:

| need | capture | why |
|---|---|---|
| bulk bundle | `proxy-20261014-1752` flow `35493->` | the only one with both documents, 245 813 of 249 464 B decodable |
| post-flood chain + smalls | `flows3-s2.txt` | the only one with the 332 B terminator, rev answer, poll answer and seed tick |

So `-flood`/`-floodkey`/`-floodflow` and `-post`/`-postkey`/`-postflow`
are separate. The flow selector is only inherited when the post source is
the flood source, because flow names belong to a dump.

`login.VerifyBulk` gates the carrier at load: the bundle is decoded and
re-encoded, and a carrier that does not reproduce itself is refused
instead of served as garbage the client would silently ACK.

### Defs-driven encoding

The defs knew the shape of every property and method but could not encode
or decode a value. `entdef` now has both halves:

| piece | what it does |
|---|---|
| `entdef.Value` + `Codec.Read`/`Write` | a value of any modelled type: INT/UINT 8..64, FLOAT32/64, STRING/BLOB/PYTHON/UNICODE, VECTOR2/3/4, MAILBOX, fixed and variable ARRAY/TUPLE, FIXED_DICT (field order plus the `allowNone` flag byte) |
| `entdef.Dispatch` / `EntityDispatch` | per entity: the client/base/cell method tables indexed by exposed id, and the client-server property table in wire order |
| `MethodDef.ReadArgs`/`WriteArgs` | a call's arguments, in declared order |

The exposed-id order is BigWorld's: exposed methods only, **deduplicated
by name**, sorted by element length (fixed ascending, then variable by
header width). The dedup is load-bearing. `Account` declares
`requestToken` itself and also inherits it from
`AccountAuthTokenProvider`; counting it twice pushed `doCmdInt3` from
slot 13 to 14, so the client's id 13 landed on
`accountDebugger_registerDebugTaskResult` (20 B) and every call left 8
bytes unread. With the dedup `Account` has 41 client methods and
`base[13]` is `doCmdInt3` fixed(28) — both matching the live client.

`TestDecodeRealDoCmdInt3` decodes two genuine calls from the 1752 capture
with the defs and re-encodes them byte-identically;
`TestDefsAgreeWithPostDoCmd` cross-checks all 17 `doCmdInt2`/`doCmdInt3`
calls in that capture against the hand-written reader and finds the same
request and command ids.

`wotdefs` prints the tables:

```sh
wotdefs -defs ../scripts-2.4.1/entity_defs
wotdefs -defs ... -entity Account     # full tables for one entity
wotdefs -defs ... -json               # the whole model
```

### The entity layer

`login/entity.go` builds entities from the defs instead of from byte
layouts:

| piece | wire |
|---|---|
| `EncodeCreateBasePlayer` | `[0x05][len][entity id u32][type id u16][empty blob][base props][component count]` |
| `EncodeClientMethodCall` | `[0x4E + exposed id][len][args]` |
| `EncodePropertyUpdate` | `[0xA7 + property index][len][value]` |
| `EncodeTickSync` | `[0x13][tag]` |

The two ranges are what make this work without a table per method: a
client method call is `ENTITY_METHOD_BASE + id` and a property update is
`ENTITY_PROPERTY_BASE + index`, so the defs' ordering *is* the wire
addressing. `EntityRegistry` allocates ids and never reuses a destroyed
one, so a stale reference cannot alias a new entity.

`CreateBasePlayer` carries only the **base-hosted** client-visible
properties (`DATA_BASE`), which is why `EntityDispatch.BaseProps` exists
next to `Properties`: `Avatar` has 14 base of its 28 client properties,
and sending all 28 would run past the element.

`DecodeCreateBasePlayer` is the inverse, so a built element is checked
against the defs that produced it.

### Smalls

`lobby.Small` describes each small family's framing once, and both the
reader and the writer use it:

| family | framing |
|---|---|
| `0x1a` | `[1a][type][len8][body]` |
| `0x1a/5b` | `[1a][5b][u32][u32]` — **no length byte**: the `len8` slot carries the low counter byte |
| `0x13` | `[13][tag]`, fixed 1 |
| `0x45` | `[45][len u16][id u16][packed-u24 descLen][desc]` — `RESOURCE_HEADER` |
| `0x46` | `[46][len u16][id u16][seq u8][last u8][data]` — `RESOURCE_FRAGMENT` |
| `0xff` | `[ff][len u32][rid u32][body]` |

`ClassifySmalls` walks with `ParseSmall` instead of its own switch, so the
two cannot drift. An unmapped family is `ErrUnknownSmall`, distinct from
truncation, so a walker still hands the remaining bytes back rather than
calling it corruption.

Two bugs fell out of the consolidation:

- `hasSmall` was a byte scan for `1a/xx` anywhere in the frame, so a tag
  pair inside a payload matched. It now parses the app and walks the
  smalls.
- The answer bodies were sliced `[4:len-8]`, which assumes an 8-byte
  trailer. A `0x0478` frame has 16, so the slice left 8 trailer bytes on
  the answer. `carrierSmall` follows `ChannelTrailerLen` instead.

The `1a/5e` error answers are built from `Small` rather than a literal,
and a test pins them to the old bytes exactly.

### Element length: 0xFF is an escape, not a maximum

Every element is `[id][length][body]`, and the length field's width is the
method's `VariableLengthHeaderSize` (1 byte for `onCmdResponseExt`, 2 for
`showGUI` and the resource elements). A body that does not fit the field is
**not** written as a plain all-ones field — all-ones IS the escape. The
client's own writer (`InterfaceElement::compressLength`) fills the field
with ones, replaces the body's **first four bytes** with the full u32
length, and moves those four displaced bytes to the **end** of the element:

```
[id][FF…][u32 len LE][body[4:]][body[:4]]
```

The reader reverses it. Writing `[id][FF][body]` for a 255-byte body makes
the client read the next four bytes as the length, over-read the bundle and
die on

```
MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_
```

That is what happened once the account full sync grew past 254 bytes (the
`potapovQuests` and `dogTags` sections pushed it to 255): the client crashed
7 ms after `SHOW GUI` and the hangar showed `-` for every resource, because
the sync carrying them never parsed. `appendElement` implements the escape
for any width.

A STRING argument's own length (the `ext` of `onCmdResponseExt`, the
`description` of a `RESOURCE_HEADER`) is a packed-u24 blob length instead:
one byte below 255, else `0xFF` and a little-endian u24.

### The account sync rides the resource stream

`CMD_SYNC_DATA` is answered with `RES_STREAM` plus the full state as a
resource, not with an inline `1a/5f` element. The reason is size: a garage
holding every ownable vehicle is ~9 KB of pickle, and the bundle payload is
1223 bytes. The resource mechanism is exactly what the genuine server uses
for the account cache (367 KB in the reference capture).

The follow-up matters. `AccountSyncData.__onSyncComplete` ends with
`self._synchronize()`, which asks again with the revision the stream just
delivered — so the server answers that one with a cheap revision ack
(`{prevRev: rev, rev: rev}`) instead of resending the state. That is why
every full sync carries a **non-zero** revision (`fullSyncRev`): a zero
would make the follow-up look like a first sync and pull the document a
second time.

### Crew skins and the barracks

Two inventory sections carry the crew side, and both have a keying trap.

**Crew skins (`inventory[13]`)** — `13` is `ITEM_TYPE_INDICES['crewSkin']`.
The section is `{1: {skinID: count}, 2: {}}`:

- `1` is `SkinInvData.ITEMS` and is keyed by the **bare skin id**, not the
  intCD. `CrewSkin.__init__` does
  `proxy.inventory.getItems(GUI_ITEM_TYPE.CREW_SKINS, self.__id)` where
  `self.__id` is the third field of `parseIntCompactDescr(intCD)`, and
  `InventoryRequester.__getCrewSkinsData` returns
  `crewSkinsInvData[ITEMS].get(idx, 0)`. Keying by intCD leaves every skin
  unowned (`getFreeCount() == 0`), which disables every card in the tankman
  personal-data skin picker.
- `2` is `SkinInvData.OUTFITS` and **must exist even when empty**:
  `Tankman._equippedSkinID` indexes `skinsPdata[SkinInvData.OUTFITS]`
  directly, so a missing key raises `KeyError(2)` while building any
  tankman.

The shop price table is the other way round — `items.itemPrices` is keyed by
the skin's intCD (`makeIntCompactDescrByID('crewSkin', CREW_SKIN, skinID)`).

**Barracks (`inventory[8]`)** — `8` is `ITEM_TYPE_INDICES['tankman']`, and
the section is `{compDescr: {invID: descriptor}}`, the same shape as the
garage. `lobby.TankmanCompDescr` writes the descriptor exactly as
`tankmen.generateCompactDescr` does for a skill-less crew member:

```
[header = tankman(8) | nation << 4]
[flags]                 TankmanFlags.pack(): 128 extended type, 64 premium,
                        32 female, 16 free skills, 8 bonus skills
[vehicleTypeID]         1 byte, or 2 big-endian when > 255
[roleID][xp hi][xp lo]  roleID = (SKILL_INDICES[role] << 1) | (xp >> 16 & 1)
[numSkills = 0][lastSkillLevel = 0]
[firstNameID >H][lastNameID >H][iconID >H][freeXP >I]
[dossierCompactDescr]   empty
```

`TankmanDescr.__initFromCompactDescr` validates every id against the
nation's `tankmen/<nation>.xml` config and the vehicle type against
`vehicles.g_list.getList(nation)`, so the name ids must come from
`lobby.AllTankmanGroups` (generated) and the type id from a vehicle the
garage already owns.

`stats.berths` is the barracks capacity, the crew-side twin of
`stats.slots`: the client shows free beds as `berths - tankmen`, so it must
exceed the barracks size.

**Consumables (`inventory[11]`)** — `11` is `ITEM_TYPE_INDICES['equipment']`.
Unlike the garage and the barracks this section is a **flat**
`{intCD: count}` map: `InventoryRequester.__getItemsData` returns
`cache[intCD]` for every simple item type, and `FittingItem.__init__` reads
it as `inventory.getItems(itemTypeID, intCD)`.

The intCD is `makeIntCompactDescrByID('equipment', NONE_INDEX, id)` =
`(id << 8) + 251`. The nation nibble is **15**, not 0: `artefacts.Equipment.id`
is the pair `(nations.NONE_INDEX, id)` and `compactDescr` is built from it, so
the live client's own equipment intCDs are `(id << 8) + 251` (handExtinguishers
is 251, autoExtinguishers 507). Keying with nation 0 puts every consumable at
an intCD the client never asks for — the depot lists nothing and the loadout
screen offers nothing to mount. The ids come
from `item_defs/vehicles/common/equipments.xml`, filtered to `type` absent or
`regular` (battle boosters and battle abilities share the file but are a
different item type), to entries without the `notForSale` tag (the built-in and
example consumables) and to entries without `notInShop` (the avatar-driven
battle abilities — `artillery_cw_tier6`, `bomber_fallout`, … — which have no
depot icon and render as a broken texture). `lobby.AllEquipment` is that list.

`notInShop` is a SECTION carrying the text `True`, not a value element, so
`Section.AsString` (which only handles value sections) returns `""` for it;
`Section.StrVal` is what reads it.

The count is a plain pickled int, so there is no wire width to respect;
`lobby.MaxItemCount` is simply "more than any battle can spend".

Consumables also need a **shop price**: `ItemsRequester.getItems` walks the
shop's price table with `onlyWithPrices=True` by default, so an equipment
intCD with no price is filtered out of the storage screen even when the
inventory owns it — the same trap as the empty carousel.

**The Depot needs `shop.isStorageEnabled`.** `StorageView._populate` sets
`showDummyScreen = not lobbyContext.getServerSettings().isStorageEnabled()`,
and `ServerSettings.isStorageEnabled` is `_BwShop.isStorageEnabled` — a field
of the `shop` block of the server-settings document, built by
`makeTupleByDict(_BwShop, serverSettings['shop'])` with a namedtuple default of
`False`. An empty `shop` block therefore renders the Depot's dummy screen: the
window opens, the route changes, and nothing is listed. The settings document
carries `"shop": {"hostUrl": "", "isStorageEnabled": true}`.

**Optional devices (`inventory[9]`)** — `9` is
`ITEM_TYPE_INDICES['optionalDevice']`, and the intCD is
`(id << 8) + 9 + NONE_INDEX << 4` = `(id << 8) + 249` (the live client's
`g_cache.optionalDevices()[43].compactDescr` is 11257). The section is a flat
`{intCD: count}` map like consumables. `lobby.AllOptionalDevices` is the
generated table from `vehicles/common/optional_devices.xml` — all 89 entries,
covering the standard, deluxe (`deluxe` tag, priced in crystal) and
modernized (`modernized_1/2/3` tags) tiers plus the bounty ones.

The shop document must also carry the exchange rates. `Shop.getSellPrice`
reads `self.__cache['crystalExchangeRate']` **directly** — not through the
requester's defaults — whenever a buy price has a `crystal` entry, so a
document without it raises `KeyError('crystalExchangeRate')` while building
any crystal-priced item (every deluxe optional device). That raise happens
inside `FittingItem.__init__`, which aborts `crew_presenter.__calcOptDeviceBonuses`
and with it the hangar's crew and loadout presenters — the shells, equipment,
consumables and crew boxes under the tank all disappear. `ShopDoc` carries
`exchangeRate` 400, `exchangeRateForShellsAndEqs` 400 and
`crystalExchangeRate` 200 (the client's own `DefaultShopRequester` values),
plus `sellPriceFactor` (a scalar; `Shop.__onSyncDataReceived` copies it into
`sellPriceModif`) and `items.itemPrices`.

The price dict is per-currency, not a `(credits, gold)` pair:
`ItemsPrices.__setitem__` accepts a dict as-is, so a crystal-priced device is
`{'crystal': 5000}`. `lobby.priceOf` omits zero entries for the same reason
`__setitem__` does — a zero would make `getCurrency()` pick a currency the
item is not sold in.

**Customization (`inventory[12]`)** — `12` is
`ITEM_TYPE_INDICES['customizationItem']`. The intCD is
`(id << 8) + 12 + (cType << 4)`, where the nibble is the `CustomizationType`,
not a nation: 1 paint, 2 camouflage, 3 decal, 4 style (the 3D styles), 5
modification, 7 projection decal, 8 insignia, 9 personal number, 10 font, 11
sequence, 12 attachment, 13 stat tracker. Verified live:
`g_cache.customization20().styles[1].compactDescr` is 332.

The section is **three levels deep**, unlike every other item type:

```
{ITEMS: {cType: {id: {UNBOUND_VEH_KEY: count}}}}
```

`InventoryRequester.__getCustomizationsData` walks `cache[ITEMS][cType][id]`
and `Customization.__init__` then iterates the result as
`{vehicleIntCD: count}`, popping `UNBOUND_VEH_KEY` (0) into `inventoryCount`.
A flat `{intCD: count}` section — the shape consumables use — reads as `{}`
here and every item shows as unowned. Seeding everything unbound is what makes
the whole stock usable on any tank.

`lobby.AllCustomizationIDs` is generated from the client's own
`vehicles.g_cache.customization20()` cache rather than the item_defs XML: the
XML is split across sixteen directories with per-nation and per-region
variants, and the cache is what the client resolves ids against.

**The customize button is gated on this table.** The hangar's
`CustomizationEntrySubPresenter._getState` returns `DISABLED` unless
`items.getItems(STYLE, ~HAS_TAGS([IS_3D]) | FOR_VEHICLE(veh), limit=1)` finds
something — and `getItems` walks the shop's price table with
`onlyWithPrices=True`. With no customization prices the button is greyed out
on every tank, which is exactly what an empty price table looks like.

**Shells (`inventory[10]`)** — `10` is `ITEM_TYPE_INDICES['shell']`, and the
intCD is `(id << 8) + 10 + nation << 4` (shells are per-nation, unlike
consumables). The inventory section is a flat `{intCD: count}` map like
consumables, but the sharper requirement is the **price**: the hangar's
`shells_presenter.__fillShellItemPriceModel` reads
`shell.buyPrices.itemPrice.price` for every shell of the mounted gun and calls
`setValue(value)` on the price model. With no price the value is `None`,
`setReal()` raises `TypeError`, and `loadout_presenter_base._onLoading` aborts
before the loadout view finishes — the whole panel stays empty. `lobby.AllShells`
is the generated table (nation, id, credit price) from
`vehicles/<nation>/components/shells.xml`, whose shells are top-level blocks
carrying their own `<id>` and `<price>` (no `<ids>` index, unlike the other
component tables).

### Achievements and the account dossier

The profile and the achievements screen read the **account dossier**, and for
the player's own account it is a **stat**, not a command answer:
`StatsRequester.accountDossier` is `getCacheValue('dossier', '')` and
`ItemsRequester.__getAccountDossierDescr` feeds it to
`dossiers2.getAccountDossierDescr`. So the blob rides `stats.dossier` in the
account sync. The client never sends `CMD_REQ_PLAYER_INFO` (503) for its own
account — that path is for *other* players' profiles, and the server answers
it too, but it is not what fills the local dossier.

With `stats.dossier` absent the dossier is empty and every achievement, medal,
badge and battle stat renders as zero.

The dossier is a packed binary: a `u16` version, then one `u16` size per block
in the client's `accountDossierLayout` order, then the blocks back to back.
`DossierDescr.__init__` unpacks the header and slices each block out of
`compDescr[offset:offset+size]`, so a size that does not add up shifts every
later block.

`lobby.AccountDossier` is that blob, and it is **not hand-authored**: the
client's own `dossiers2` builders produce it, which is the only way to get
something the same build accepts. `dossiers2.custom.records.RECORDS` is the
whole layout as `(block, record, type, format, maxValue)` per record, so
"unlock everything" is exactly "set every record to its maxValue". The two set
blocks (`singleAchievements`, `uniqueAchievements`) are bitmasks keyed by
achievement *name*, and `dossiers2.ui.achievements.ACHIEVEMENTS` is the name
table. The regeneration snippet is in the file header.

The achievement blocks, `total` and `playerBadges` are filled; the rest stay
at size 0.

**`playerBadges` is the badge unlock list.** `Badge.__init__` does
`receivedBadges = proxy.getAccountDossier().getDossierDescr()[BADGES_BLOCK]`,
then `isAchieved = self.badgeID in receivedBadges` with the value as
`achievedAt`. The badge *catalog* is client-side
(`gui.doc_loaders.badges_loader.getAvailableBadges()` reads `badges.xml`, 229
badges after the realm filter), so filling this block is what turns every one
of them from "not earned" to earned — `rng`, `beta_tester`,
`10YC_POINTS`, the personal-mission badges, all of it.

That makes the blob 2677 B, past the channel MTU, so the answer rides a
fragment chain: `BaseAppServer.mintPostLarge` allocates the whole seq range up
front and emits `BuildFrames`' chain (`bulkFlags` = ON|REL|SEQ|FRAG with the
(first, last, seq) trailer) — the same shape the flood uses. The chain's
sequence number is one byte, so 256 fragments of 1223 B is the ceiling.

### Garage seeding (`-garage-all`)

`lobby.AllOwnableVehicles` (generated by `cmd/wotgarage` from the client's
own `item_defs/vehicles/<nation>/list.xml`) is every vehicle the client
declares as ownable — premium, collector, reward, event and variant
vehicles included. The only exclusion is the `maps_training` tag: those are
the training-mode bots and dummies, real vehicle types but not ownable (the
client shows them as `#maps_training:` entries, not garage tanks).

`wotserver -garage-all` (or `GARAGE_ALL=1 ./start-server.sh`) replaces the
default account's garage with that list and raises `stats.slots` to
`len(garage) + 100`, because the client's own capacity check is
`itemsCache.items.inventory.getFreeSlots(stats.vehicleSlots)` — a garage
larger than the slot count reads as full.

The inventory entry for a vehicle is its **type** compact descriptor, not
the full module descriptor. The client's `items/vehicles.pyc
parseVehicleCompactDescr` reads nation and typeID out of it:

```
header, vehicleTypeID = struct.unpack('2B', compactDescr[:2])
if header & EXTENDED_VEHICLE_TYPE_ID_FLAG:      # 2
    vehicleTypeID += unpackByte(compactDescr[2]) << 8
return (header >> 4 & 15, vehicleTypeID)
```

so the bytes are `[1 | nation << 4 (+2 if typeID > 255)][typeID lo][typeID
hi]` — two or three bytes, no modules. `InventoryRequester` turns it back
into a type id and `InventoryVehiclesValidator` builds a `VehicleDescr`
from it, which fills in the stock modules itself.

### Resource streams (`RES_STREAM`)

A command answered with `RES_STREAM` (1) is not followed by a bare data
element: the payload rides the client's **resource transfer** mechanism,
which is two elements and a header that is not optional.

```
[45][len u16][id u16][packed-u24 descLen][desc]      RESOURCE_HEADER
[46][len u16][id u16][seq u8][last u8][data]         RESOURCE_FRAGMENT
```

`id` is the request id the client asked with — the same number end to end,
because `Account._subscribeForStream(requestID, …)` keys the callback by
it. `desc` is a pickled `(len(data), crc32(data))` over the **compressed**
bytes, CRC signed the way Python 2's `zlib.crc32` returns it; the client
unpickles it and builds the `(isCorrupted, origPacketLen, packetLen,
origCrc32, crc32)` tuple `Account.onStreamComplete` unpacks, checking the
data against the CRC. `packed-u24` is one byte below 255, else `0xFF` and
a little-endian u24. `data` is the zlib-compressed pickle the
`SyncController` decompresses.

**The header is what registers the stream.** The client keeps a table of
in-flight resources keyed by id and drops a fragment whose id has no
header — no error, no log, nothing. Sending the fragment alone is why the
hangar sat on "Synchronisation du fichier personnel": the dossier answer
(`RES_STREAM` for request 223) was followed by a bare `0x46`, so
`Account.onStreamComplete` was never called, `DossierCache.__isSynchronizing`
stayed true, and `DossierRequester` parked forever with no traffic and no
error on either side. Confirmed live: calling `onStreamComplete(223,
(0,0,0,0,0), data)` by hand flipped `__isSynchronizing` to false and the
client advanced to `QUESTS SYNC` immediately.

### Reliable delivery

The channel is reliable in the protocol's sense — every packet sent with
the RELIABLE flag carries a sequence number, and the client acknowledges
everything below its cumulative watermark — but UDP does not retransmit,
so the sender has to. `login.resendQueue` tracks `(peer, seq, bytes)` for
every reliable send, drops them below the client's watermark, and hands
back the ones past a **400 ms** timeout for the sweep to repeat, giving up
after **20 s** so a dead peer cannot leak packets for the life of the
process. Both numbers are the reference implementation's.

The client's cumulative ack is read from **any** frame that carries
`HAS_CUMULATIVE_ACK`, not only from RELIABLE ones: its ack-only datagrams
are unreliable (no RELIABLE bit) and are the only place it says what it
has received. Gating the ack on RELIABLE left every answer queued
forever, and the sweep then resent the whole stage-2 stream — ticks
included — until the give-up deadline, hundreds of duplicates a second at
a client that was already stalled. The queue is also capped per peer
(`resendMaxPending`) so a peer that stops acking cannot turn the sweep
into a broadcast.

Wired into the rotation reply, the pre-flood info and stats smalls, the
minted post-flood answers and the ticks. Without it the server minted each
answer once: on a lossy link the client waits for a packet that never
comes and the lobby stalls with no error on either side.

### Built smalls

| small | state |
|---|---|
| `1a/5e` error | built (`lobby.Small`) |
| `1a/69` stats | **built** (`BuildStatsSmall`) — `{stats:{freeXP}, prevRev, cache, rev}` |
| `1a/5f`, `1a/5b`, `1a/67`, `1a/76` | replayed from the carrier |

`1a/69` used to be a carrier template with the freeXP bytes rewritten in
place, which tied the answer to one capture's pickle layout.
`BuildStatsSmall` renders it from the builder and `ParseStatsSmall` is its
inverse — the same function reads the carrier's revisions once at load.
Those revisions stay the carrier's: they are the client's cache counters,
not ours to invent.

The rest stay replayed because their *values* are unknown, not their
shape: what `1a/5f` revisions should say, what the `1a/5b` counters mean.
`1a/76`'s framing is also unsettled — its length field looks like a u16
where every other `0x1a` small uses a u8.

### The player entity

`CreateBasePlayer` (element `0x05`) is how the client gets its `Account`
entity — the thing `onEnqueued`, `onDequeued` and `receiveServerStats` are
addressed to. Without it those calls are well-formed but have no target.

The sequence is the reference's, which has a capture behind it:

1. the client sends `enableEntities` (`0x0B`) — *that* is the trigger, not
   a point in the flood;
2. `CreateBasePlayer` — the `Account` entity, with the capture's dynamic
   component count (19; no component data follows it);
3. `SelectPlayerEntity` (`0x1A`, FIXED 0);
4. `showGUI` — the `Account` client method (slot 40) that actually makes
   the hangar appear.

A repeated `enableEntities` is not a second entity.

`showGUI`'s argument is a `STRING` with `VariableLengthHeaderSize 2`, so
its length header is **two** bytes. `MethodDef.Codec()` derives the width
from the method's own `Length`, and `ReadArgs`/`WriteArgs` use it — passing
the default 1-byte codec wrote the length one byte short. The argument is
the pickled session dict (see "The stage-2 sequence" above).

`-createbaseplayer` (default on) turns the whole sequence off, and it needs
`-defs`: without them the element cannot be built, and the server says so
rather than sending a half-built one.

### Matchmaking queue

No capture contains an enqueue (700) or dequeue (701) — only the
queue-info poll (502) — so the request and answer shapes come from the
defs, not from traffic:

```
doCmdIntArr(INT16 reqID, INT16 cmd, ARRAY<INT32>)
  args = [queueType, vehInvID, gameplaysMask, arenaTypeID, randomFlags]
Account.onEnqueued(UINT8) / onDequeued(UINT8) / onKickedFromQueue(UINT8)
```

`server.Queue` is the registry: one slot per account (a second enqueue is
a no-op, not a second slot), arrival order, and a census in the `1a/67`
shape. The captured census is `{players: 924, classes: [186 226 209 98
205]}`, whose classes sum to players — so the breakdown is per **vehicle
class**, not per queue type. `ClassOf` reads the class nibble straight
from the compact descriptor header, so no component table is needed.

`login.QueueHooks` keeps the layering: the wire layer parses the client's
call and hands it over; the application layer owns the queue. 502 now
answers from the live queue instead of replaying the carrier, and 700/701
answer with the defs-built client method call.

**In-battle is out of scope.** Forming a battle needs a cell app and a
space — `CreateCellPlayer`, `EnterAoI`, entity replication, positions —
and no capture covers a battle session from the server side.

### Command surface

Five post-flood commands are answered:

| cmd | name | answer |
|---|---|---|
| 100 | `CMD_SYNC_DATA` | `[13][7b]` rev answer (once per session) |
| 121 | `CMD_SET_ACTIVE_VEH_SEASON` | `1a/5e` error, status 0 |
| 501 | `CMD_REQ_SERVER_STATS` | `1a/5b` counters |
| 502 | `CMD_REQ_QUEUE_INFO` | `1a/67` `{players, classes}` census |
| 1500 | `CMD_REQ_BATTLE_RESULTS` | `1a/5e` error, status 1 |

The client also sends 300 (`CMD_SYNC_SHOP`), 600 (`CMD_SYNC_DOSSIERS`),
700 (`CMD_ENQUEUE_IN_BATTLE_QUEUE`), 1501 (`CMD_BATTLE_RESULTS_RECEIVED`)
and 10096 (`CMD_SET_BATTLE_PASS_CHAPTER`). The **real server does not
answer 300, 600, 700 or 1501 either** — silence is the faithful
behaviour there, not a gap. 10096 gets a `1a/5c` answer we do not model
yet.

### Also missing

Social (chat/friends/clans — `xmpp/` is an offline codec with no network;
no capture contains an S>C chat action to model on), and battle
(`lobby/feed.go`/`live.go` are offline analysis for `wotbattlefeed`, not
wired to the server).

## Running

For the in-battle testing loop, use the detached script — it builds, stops any
running instance, starts on the battle arguments and waits for the port:

```sh
cd wot
./restart-server.sh              # build + (re)start, log at /tmp/wotserver.log
BUILD=0 ./restart-server.sh      # restart the existing binary
./restart-server.sh --stop
```

It differs from `./start-server.sh` (foreground `go run`, matchmaker at its
default team size) in two ways that the battle work needs: `-garage-all`, and
`-battle-team-size 0` (one queued player forms a battle).

By hand:

```sh
cd wot
go run ./cmd/wotserver \
  -privkey ../mitm/loginapp_mitm.privkey \
  -db wotserver.db \
  -user admin -pass admin
```

The client must be pointed at it (`mods/custom-server-mod`). The
password never appears in logs; only lengths and the account name do.

## Reading the live client

The client's own tables are the only authority for the NRL type ids, the
component child layout and the gun's runtime state, and none of it is in the
packages or the binary — it is built at load time. Three tools read it:

| Tool | What it gives | How |
| --- | --- | --- |
| `tools/gun_probe.py` | the whole gun chain: `isOnArena`, `__initProgress`, every `VehicleGunRotator` private field, the vehicle descriptor's turret/gun limits, the `ownVehicle` component and its `targetingInfo`, `ClientArena.vehicles` and `__positions`, the dog-tag settings | `cd pyconsole-client && uv run pyconsole -f ../wot/tools/gun_probe.py` |
| `tools/dump_entitytypes.py` | the `EntityType` table: id → name, all 385 entries | `sudo python3 tools/dump_entitytypes.py [pid]` (ptrace), or the same walk through `pyconsole`, which needs no privileges |
| `tools/ida_entitytype_layout.py` | re-derives what the dumper hardcodes — the vector address from `BW::EntityType::find`, the name/capacity offsets from `PyEntity::createDynamicComponent` | paste into IDA, or `idat -A -S"tools/ida_entitytype_layout.py"` |

The memory walk, for a new build: the vector's begin/end are at
`0x144B5E160`/`0x144B5E168`; each element points at a record whose first field
is the `EntityType *`; the name is a `std::string` at `+8` with its SSO
capacity at `+32`. `BW::EntityType::find` (`sub_14039A7F0`) is a plain index
into that vector, which is why the id is an index and not a hash.

Reading `/proc/<pid>/mem` from inside the client works without privileges
because it is self-access — but `os.getpid()` there returns the *Windows* pid,
so the Linux pid has to be passed in. `ctypes` is not available in the client's
Python 2.7 (`No module named _ctypes`); `open('/proc/<pid>/mem','rb')` plus
`seek`/`read` and `struct` is enough.

### When the client crashes, Steam gets stuck on "running"

A client crash leaves its `wineserver` orphaned on the prefix
(`compatdata/1407200`). The next launch starts a *second* wineserver on the
same prefix, which cannot take over, so `proton waitforexitandrun` blocks
before it ever spawns `cmd.exe` — no game process, no error dialog, and Steam
keeps showing the game as running. Steam's own log names the culprit:

```
wine: a wine server seems to be running, but I cannot connect to it.
   You probably need to kill that process (it might be pid 367316).
```

Recovery, in this order:

```sh
# 1. the orphaned wineserver — the pid Steam names
kill -9 <wineserver pid>
# 2. the wedged launch tree, if it is still there
pkill -9 -f "proton waitforexitandrun"
pkill -9 -f "wine/x86_64-unix/wine"
pkill -9 -f "Proton - Experimental/files/lib/wine/../../bin/wineserver"
```

Steam notices on its own and logs `Game Recording - game stopped`, which
clears the "running" state; no Steam restart is needed. To check the prefix is
really clean, look for any process whose `WINEPREFIX` is
`compatdata/1407200/pfx` — there should be none.

## Phase 6: operations

- **Config file.** `wotserver -config FILE` reads a JSON object whose
  keys mirror the flags (`cmd/wotserver/wotserver.example.json`).
  Precedence is flag > file > built-in default, so the file is a base
  profile and the command line stays an override. Malformed JSON is an
  error, never a silent run on defaults.
- **Structured logs.** `server.Config.Logger` (`*slog.Logger`) receives
  provisioning, auth outcomes, session minting and sweeps as records.
  `wotserver` wires a text handler to stderr, Debug under `-verbose`.
  A refused login logs the account name and the reason, never the
  password; a minted session logs its key (a wire value) so a BaseApp
  event can be tied back to the login that made it.
- **Reconnect takeover.** An account holds at most one live session.
  `SessionManager.Issue` replaces the account's previous session and
  returns it, so a client that re-logs in after a drop does not leave
  the old key alive until the TTL — a reconnect loop used to grow the
  map without bound. A `byAccount` index keeps `Drop`/`Sweep`
  consistent, and dropping a stale key never unregisters the session
  that replaced it.
- **Account management.** `cmd/wotaccounts` is the operator CLI:
  `list`, `add NAME [-pass P] [-role R]`, `passwd NAME`, `state NAME`,
  `set NAME [-credits N] [-gold N] [-freexp N]`. `wotserver` can only
  bootstrap one default account, so this is how a roster is created.
  Omitting `-pass` reads a line from stdin, keeping the password out of
  the process list; passwords are never printed.
- **Shutdown.** SIGINT/SIGTERM cancel the context, both listeners stop
  and the store closes. Sessions are in-memory by design, so a restart
  invalidates them and the client re-logs in.

## Phase 7: versions

- **Paired version registry.** `login.ClientVersion` pairs the protocol
  bytes a build announces with the entity-defs digest it presents, and
  `ServerConfig.Versions` replaces the old flat `Version` + `Digests`
  pair. The gate checks the pair: protocol bytes alone decide status 65,
  the `(proto, digest)` pair decides status 70. A client announcing one
  build's protocol while presenting another's digest is now refused
  instead of slipping through a flat allowlist.
- **Both shipped builds are ACCEPTED at login, 2.4.1 is the one served.**
  2.4.0 and 2.4.1 announce the same protocol bytes — the 2.4.1.0 capture
  carries `05 00 01 11` too — so the digest is the only thing that tells
  them apart, and `KnownVersions()` is the two pinned truths from
  `entdef`. The defs tree is 2.4.1, though, so a 2.4.0 client would be
  served 2.4.1-shaped properties (`PUBLIC_VEHICLE_INFO.index` alone is a
  byte wider); 2.4.1.1 is the supported build.
- **The build rides to the BaseApp.** `LoggedOnSession.Version` names
  the matched build and the admission line reports it, so an operator
  can tell a 2.4.0 client from a 2.4.1 one in the log.
- **The 2.4.1 bundle decodes.** `TestBundleRoundTrip241` reassembles the
  2.4.1.0 stage-2 flood (`proxy-20261031-1358`, flow `35708->`, key
  recovered from the capture's own login) and round-trips it
  byte-identically: 269 040 B, 373 objects. Getting there needed one
  codec fix — the flood's first chunk carries a document that never
  STOPs and the next chunk starts with a channel-framed packet, so
  `DecodeFaithfulStream` now ends the document at the first non-pickle
  byte and the encoder only emits STOP when the input had one. The
  2.4.0 capture happened to parse through that boundary; the 2.4.1.0 one
  starts with `0x00` and failed outright.
- **Multi-flow carrier selection.** `-floodflow` filters the carrier
  loaders to one flow. A capture that interleaves sessions otherwise
  pairs one flow's terminator with another flow's ticks.

### What the 2.4.1 tail still needs

The 2.4.0 post-flood matcher is pinned to exact wire sizes (332 B
terminator, 28 B tick, 60 B rev reply, 36 B poll answer). The 2.4.1.0
flow has **no 332 B frame at all**, so `loadPost` finds nothing. A
decrypt census of that flow's non-bulk S>C frames shows the same smalls
at different sizes:

| 2.4.1 wire | clear | head | what |
|---|---|---|---|
| 188 B | 175 B | `58 04 13 c3 1a 76 9c 00 9b 80 02 7d 71 01 28 55 09 "serverU…"` | `1a/76` session dict (2.4.0: 396 B) |
| 100 B | 84 B | `58 04 13 5b 1a 69 45 44 80 02 7d 71 01 28 55 05 "stats"…` | `1a/69` stats small (2.4.0: 92 B) |
| 36 B | 22 B | `58 04 13 03 1a 5b d8 7a 00 00 a9 4e 01 00 1e 01 00 00 04 00 00 00` | `1a/5b` poll answer (same shape) |
| 60 B | 45 B | `58 04 13 5d 1a 79 1e 0d "185.12.240.61," 80 bc` | `1a/79` lobby offer |

So the smalls survive the version bump; the **terminator and the
post-flood tick chain do not**. Identifying which 2.4.1 frame ends the
burst (candidates: the 556 B, 908 B, 1076 B and 1092 B frames) and where
the rev-sync answer moved is the remaining work, and it needs the same
decrypt-and-diff treatment the 2.4.0 tail got. It no longer blocks the
server: the flood bundle is authored from the defs (`login.FloodBundle`),
so no capture is read at runtime and `-floodflow` only matters for the
offline analyzer. The section above is the record of how the 2.4.1 wire
was read, not a description of what the server sends.

## Phase status (Oct-31)

| phase | state |
|---|---|
| 0 foundations | **done** — `server.Store` + SQLite, accounts, sessions, state |
| 1 real login | **done** — credential gate, status 68, account id on the wire |
| 2 player state | **done** — credits/gold/freeXP/garage/research, provisioning |
| 3 bundle | **done** — byte-identical round-trip |
| 4 commands | **complete for observed traffic** — see below |
| 5 social | **groundwork only** — see below |
| 6 ops | **done** — config file, structured logs, reconnect takeover, account CLI |
| 7 versions | **done for login + bundle** — 2.4.1 tail needs wire analysis |

### Phase 3 detail

- `server.DecodeBundle` → `Find`/`SetInt`/`SetString` → `Encode` works on a
  real capture (375 objects, 245 370 decoded bytes).
- **Mutation is proven**: `TestBundleMutationCapture` patches `crewLvl`
  100 → 101 and re-decodes to the new value.
- **Byte-identical round-trip: CLOSED.** 250 687 in, 250 687 out, and a
  mutation keeps the length while changing only the patched value.
  Four bugs were fixed on the way: MARK sentinels leaking into the value
  stack; container recipes not recording per-step item counts; a MARK
  not being bound to the container it fills; and a malformed capture
  region (offset 223 788: a SHORT_BINSTRING declaring 21 bytes whose
  payload contains `xmpp_bosh_conne\0\x80\x02}q\x01`, a NUL plus the
  next document's start) where the decoder now degrades instead of
  failing — items stay on the stack and the encoder replays the MARK and
  the container opcode.

### Phase 4: what the capture actually requires

The client sends `CMD_SYNC_DATA` (100), `CMD_SYNC_SHOP` (300),
`CMD_SYNC_DOSSIERS` (600), `CMD_REQ_SERVER_STATS` (501),
`CMD_SET_ACTIVE_VEH_SEASON` (121) and `CMD_ENQUEUE_IN_BATTLE_QUEUE`
(700). The server's S>C answers in the same session are only:

| small | answers |
|---|---|
| `1a/5f` | `CMD_SYNC_DATA` (rev pair) |
| `1a/5b` | `CMD_REQ_SERVER_STATS` |
| `1a/5e` | `CMD_SET_ACTIVE_VEH_SEASON` (no-vehicle error) |

**300 and 600 get no answer at all** — the genuine server is silent on
them too. So the three handlers the server already has are the whole
observed surface; implementing 300/600 would be inventing traffic the
real server never sends. Phase 4 is complete for what the client
actually exercises.

### Phase 5: chat is not exercised by any capture

`ParseChatCommandFromClient` decodes `Chat.chatCommandFromClient`
(A1 tag 0x98) and `chatCommandNames` is the full 48-entry
`CHAT_COMMANDS` table from the shipped `chat_shared.pyc`, so the server
names chat traffic in its log.

But **no capture contains a single chat command**: scanning all 21 proxy
dumps for tag 0x98 in the C>S direction yields zero. The client has the
feature (`ClientChat.pyc`), it just was not used in any captured
session. There is also no server→client chat action in any capture to
model an answer on, and the client only has a direct handler for
`receiveInvite` — every other action goes to registered processors.

So the server parses and names chat but stays silent. Inventing an
action dict would be guessing at a shape nothing on the wire shows.
Friends/clans/invites are in the same position: no captured traffic.

### Per-account data

The bulk is static config. Account state rides the smalls:

- **`1a/69`** — `{stats:{freeXP:N},prevRev,cache,rev}`. `freeXP` is served
  per account (`statsFrame` + `patchPickleInt`), the first genuinely
  per-account field on the wire.
- `1a/67` is `{players:<int>,classes:<tuple>}` — a count, not a roster.
- The other smalls (`1a/5b`, `5e`, `74`, `75`, `76`, `79`, `88`) do not
  decode with the `[len-1][pickle]` framing; each needs its own shape.

## Next steps

The ordering is driven by the measurement above: the encoder is only
worth building for the part we can actually decode, and the part we
cannot decode is what blocks per-account content.

1. **Understand chunks 2–40** — the real blocker. They carry no pickle
   structure at offset 0, so either they are a second layer
   (compressed/encrypted) or they are framed differently. Until this is
   answered, the garage cannot be made per-account.
2. Tagged string type in the decoder (`str` vs `unicode`).
3. Protocol-2 encoder with memo, verified by byte-identical round-trip
   on chunk 1's 14 673 B prefix.
4. Bundle pipeline: decode prefix → apply account state → encode →
   append the opaque remainder verbatim.
5. Command handlers, starting with the read-only sync family.
