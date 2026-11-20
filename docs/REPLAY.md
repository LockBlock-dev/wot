# World of Tanks EU — Replays (`.wotreplay`)

Scope: **replay files only** — container, crypto, playback model, and the
`replay/` reader. Network login/live traffic stays in
`NETWORK_PROTOCOL.md`. All offsets verified Sep 2026 on
`../replays/20260915_1911_uk-GB41_Challenger_05_prohorovka.wotreplay`
(2.4.0.0, EU2 Prokhorovka, 1,470,675 B).

## 1. Container layout

```
[12 B file header][JSON battle setup][encrypted battle stream]
```

- Header (verified on 2.0.0.0 / 2.3.1.0 / 2.4.0.0 files):
  `[magic u32 LE = 0x11343212][u32 JSON-block count][u32 LE setup-JSON
  length]`. The count is **2** on old files (setup + results JSONs as
  plaintext) and **1** on new files (setup only); the length is exact
  in all three samples (77267 / 76853 / 78095). Example
  (Prokhorovka 2.4.0.0):
  `12 32 34 11 | 01 00 00 00 | 0f 31 01 00`.
- Old files (count 2, e.g. 2.0.0.0): setup JSON + results JSON
  (`arenaUniqueID`, `personal`, `players`, `vehicles`) plus
  per-vehicle stat JSONs (`tkills`/`frags`), all plaintext; an 8-byte
  stream preamble of the same shape as new files follows. Surprise
  find (Sep 2026, via `wotverify` coverage): the 2.0 stream takes the
  SAME key+scheme (104907 chained packets, tail MD5 over
  setup+results) — the earlier "different key" hunt tested the wrong
  schemes, never the real one. What 2.0 needs is its own
  method/property TABLES (mid-30 call already overruns the 2.4
  signature — open, no 2.0 `.def`s on hand).
- New files (count 1): setup JSON only; results live inside the
  encrypted stream or external `.dat` files.

- Header (example): `12 34 11 01 01 00 00 00 0f 31 01 00`. First bytes
  look like a format version; not fully decoded — the reader treats
  the first 12 bytes as opaque.
- JSON setup: starts at offset 12, runs to the first balanced-close
  brace (brace matching through string escapes). Example: 78,095 B
  of battle setup — `playerVehicle`, `playerName`/`playerID`,
  `mapDisplayName`, `clientVersionFromExe`, `serverName`, `vehicles`
  roster (30 entries, with `fakeName`s), arena options. This is what
  the client needs to boot the scene (map + initial snapshot).
- Encrypted blob: everything after the JSON. The 12 bytes there are
  NOT a plaintext frame header (parsing them as
  `[time][size][type]` gives coincidences only) — the blob decrypts
  as one unit (see §2).

## 2. Stream crypto

- **Key** (16 B, community-published, Phalynx/WoT-Replay-To-JSON
  lineage crediting benvanstaveren/marklr):
  `DE 72 BE A0 DE 04 BE B1 DE FE BE EF DE AD BE EF`.
  Verified here: decrypts a genuine 2.4.0.0 replay to a valid zlib
  stream (`wotreplay` test pins map/player names, 5,319,705 stream
  bytes, head bytes). The key was NOT found verbatim in
  `win64/WorldOfTanks.exe` — not contiguous, not in halves, not
  single-byte-XORed, not nibble-swapped, not md5-of-any-obvious-string
  — and not in the scripts `.pyc` either. Oct-11 IDA narrows it hard:
  the replay file reader (`sub_14057BEE0`: both magics `0x11343212`/
  `0x12343210`, JSON-block shape, 50 MB cap) decrypts the stream via
  `sub_142AD6190` with a cipher from `SymmetricBlockCipher::create`
  (`sub_142AD6E60` → ctor `0x142AD6C30` → stock schedule
  `sub_142C08A10`) keyed by the static at `0x1442DA5A8` — which is
  `DEADBEEF`×4 plus a mask table and a `BWTB` tag region (angle
  constants π, π/2, π/4, 3π/4 follow). The working key shares
  10/16 bytes with that static (all even bytes + last two odds) but 6
  odd bytes differ — and stock-Blowfish(`DEADBEEF`×4) provably
  does NOT decrypt real streams (tested: zlib invalid header) while
  the published key does. So the static is a placeholder/decoy or a
  seed: the runtime key is filled at runtime or a second decrypt path
  exists (reader callers: `sub_14057FFC0` \u2190 `sub_14056FBB0`/
  `sub_14057A4F0`; writer side `WGReplayFileCompressor`). Key bytes
  re-verified absent image-wide Oct-11 (full16/halves/immediates).
  Open: runtime-fill site or second path.
- **Scheme**: skip the first 8 blob bytes, Blowfish-ECB decrypt per
  8-byte block, XOR each block with the previous *plaintext* block
  (same ECB+XOR-chain shape as the LoginApp session decrypt), then a
  single zlib inflate over the whole buffer. First two decrypted bytes
  are `78 da` (zlib).
- Decompressed content (5.3 MB for a full battle): Mercury-style
  framing — u32-prefixed records, version strings (`7 B +
  "2.4.0.0"`), entity IDs, arena GUID, UI strings (`ExampleUser`,
  `BattleLevel`, `RandomEventAllowed`, ...). Packet-level dispatch
  (entity/method IDs against `.def`s) is NOT implemented yet;
  `Replay.Stream` is exposed raw for that work.
- `res/replay-sign.pubkey` (EC P-256, shipped with the client) is the
  replay *signature* verification key (cf. OSE
  `BWReplayConnection::verificationKey_`): replays are signed so
  results can't be forged/edited undetectably. Read-only renderers
  don't care; editors do.

## 3. Playback model

Playback is **deterministic re-simulation, not video**: the client
boots map + snapshot from the JSON, starts its own clock, and feeds
the recorded frames through the same entity/codec path as live server
traffic. During battle the client records both directions (player
inputs + server updates), so replaying the stream reproduces
positions, shots, damage, chat — fully offline, no network.

Consequences:

- **Version-locked**: needs the same entity defs and behavior — old
  replays break on new clients (same defs the login digest covers).
- **Seeking is fast-forward**: jumping to 10:00 simulates 0:00→10:00
  as fast as possible; long seeks churn.
- **Pause/speed/free-cam/HUD** are presentation layered over the sim.
- Recording is the mirror: the client tees the same traffic to disk
  during battle and writes the JSON header around it.

## 4. Playback control (`BattleReplay.py`, decompiled client)

- Speeds `0, 1/16 … 16` (`setPlaybackSpeedIdx`); in-game effects off
  at ≥8x, sound muted at 0 — high speed is still realtime-bound sim.
- Clock: `replayCtrl.getTimeMark()` with magic IDs `2^31`
  (`CLIENT_READY`), `+1` (`REPLAY_FINISHED`), `+2`
  (`CURRENT_TIME`); start/end clamping in `play()`.
- Seek = `beginTimeWarp(t)` (C++ side): rewind (`t < now`) resets
  decals/particles/ground effects, saves camera, posts
  `REPLAY_REWIND`; forward = fast simulation. Keys: rewind,
  ±step, jump-to-start/end.
- `.wotreplaylist` files: playlists (plays each, quits after last).
- `SafeUnpickler` patches `pickle.loads` during playback — replay
  pickles are untrusted input, sandboxed.
- Recording: `./replays`, auto filename
  `AUTO_RECORD_TEMP_FILENAME + [i] + .wotreplay` (100 tries);
  capture itself is C++ (`replayCtrl.startRecording`).

## 5. Decompressed stream layout (Prokhorovka, 5.3 MB)

- Record 0: `[tag u32 = 0x0b][len u32 = 24]` + `u32 0` + `u32 7 +
  "2.4.0.0"` + `u32 15` + `u32 45` (client-version record).
- ~4 KB ASCII setup: comma-separated int lists, arena GUID,
  `ExampleUser`, `BattleLevel`, `RandomEventAllowed`, ... then binary.
- Binary packets: repeating Mercury-style message headers
  (`3a 7e fa 3a` / `3a 7e 7a 3a` families) with f32 position triples
  (map coords ~±90–900) and tick separators
  (`01 2d 00 00 00 0a 00 00 00 …`). Entity updates, parseable
  against `.def`s — the packet-dispatch work below starts here.

## 6. Battle-stream packets (Prokhorovka, 115,464 records)

Framing: `[u32 size][u32 type][f32 time][payload size bytes]`, chained
end to end (time 0.0–647.9 s). Type census matches the BigWorld
family (cf. Monstrofil mapping): `0x0` BasePlayerCreate ×1, `0x1`
CellPlayerCreate ×1, `0x2` EntityControl ×1, `0x5` EntityCreate
×239, `0x7` EntityProperty ×23984, `0x8` EntityMethod ×549, `0xa`
Position ×53918, `0xf` Map ×1, `0x24` NestedProperty ×374, `0x2b`
PlayerPosition ×7, plus 18 rarer types. Notably one packet carries
the entity-defs digest `5DF886F75E73B33CFF9D87FB9C69389C` —
identical to the login ground truth, tying the two worlds together.

Method IDs (cracked Sep 2026, supersedes the heuristic names below):
wire mid = 0-based index into the entity's interface-then-own CLIENT
methods sorted by ArgsStreamSize ascending, variable-size last,
stable — mirroring the property FullIndex allocation, but with the
interface block first (proven by Avatar wire 23 = enemySPGHit, whose
12 B content is an SPG strike position, and wire 7 =
onAutoAimVehicleLost — a sector method would make no sense in a
random battle). Proven by exact size+parse matches on two versions
(2.3.1 Mines + 2.4.0 Prohorovka): Vehicle `1=showShooting,
4=onHealthChanged, 5=onExtraHitted, 7=showDamageFromExplosion,
8=onStaticCollision, 10=showDamageFromShot`; Avatar `7, 23,
27=onSwitchViewpoint, 28=stopTracer, 29=onCollisionWithVehicle (Mines
only), 30=onFrictionWithVehicle (Mines only), 33=enemySPGShotSound,
37=showTracer`. The avatar (entity 4730140, both 0x0+0x1) never calls
mid 10 — that wire is Vehicle-only.

Variable-size method wires are versioned and identified by unique
exact-consumption fit, NOT by position (their block order is OPEN).
Cross-version drift (Prohorovka 2.4.0 / Mines 2.3.1 / Glacier 2.1.1,
third player): showShotResults@54 and onChatAction@38 are stable
everywhere; explodeProjectile 67/56/56, updateArena 58/59/59,
processInvitations 62/63/64 (drifts +1 per older version);
2.4.0-only wires seen: 65=updateSpawnList; 2.1.1-only wires seen:
40 (5 B id+empty-string, triple-ambiguous), 42 (bare-Python
end-battle notification, no 2.4.0 counterpart), 60 (periodic
`(Array{U16}, Array{U16})` sync, 394 calls, no 2.4.0 counterpart),
68=setUpdatedGoodiesSnapshot. Fixed-block wires do NOT move:
2.1.1 decodes 876/876 fixed calls exactly with the same table.
Ambiguous-by-framing picks are content-backed: 58 could be
showDevelopmentInfo (same `(u8,string)` shape; epic-config content
says updateArena), 62/63/64 fit all single-blob methods (invitation
pickle / scenario name decide).

Value wire rules (exact-consumption on all 549+ calls): ints/floats
LE fixed; String/Blob/UnicodeString/Python = `[u8 len | 0xFF u24LE
len][bytes]` (the u24 reading proven by ff 9301 00 = 403-style
headers); Python payload raw or zlib pickle (by magic);
`Array[0] = [u8 count | 0xFF u24][elements]`; FixedDict `?` =
`[u8 present][fields]`; MAILBOX 12 B raw; VECTORn = n f32.

Recording notes: damage attackers are vehicle entity IDs, but a few
(never-in-AOI vehicles) have no EntityCreate in the stream — damage
is reported arena-wide while creates/positions are AOI-scoped.
Duplicate EntityCreates exist (same ID re-created, type stable) —
entity tables must last-write-win.

Properties (`0x7`, 24–40k/battle): `[eid u32][FullIndex u32][len u32]
[value]`, indexes into the client-server property table
(size-sorted-stable FullIndex, same allocation as methods). All
94661 updates decode exactly on three fixtures (Avatar 28 +
Vehicle 50 properties generated). Size-0 tuples are count-prefixed
(steeringAngles `[02 82 82]` = two U8s centered at 128).

Nested (`0x24`, ~400/battle): `[eid][isSlice u8][len u32][000000]
[op u8][flags? u8][payload]` — isSlice 1 (2.4.0) vs 0 (2.1.1 mostly),
same shapes under both (a bare flag, not a count: a=00 samples carry
full payloads). Live mechanism (IDA): `BWEntities::
handleNestedEntityProperty` dispatches on isSlice to entity
vtable+24; the applier reads `[count][index]`, subtracts a per-type
base (`EntityDescription+0xF8`, else a component walk at +0x2F0),
bounds-checks against a u32 remap table, resolves the description
via `clientServerProperty`, and applies per data description in a
loop; `nested` + `slice` are separate Mercury messages sharing the
handler. The op is NOT `.def` numbering — affine, declaration,
FullIndex, name-hash, rotation, front/back moves, and ~20 sort keys
all fail. Shape-proven channels: Vehicle damageStickers (16 B
`{networkID,segment,params}` dict + hit-kind flags), engineMode
(1–2 B tuple elements), Area destroyed-family Tuple[3] (which of
modules/fragiles/columns is open) / fallenTrees Tuple[5]; paired
ba/bc timers and c0 structural. Missing piece: the runtime base
values (need EntityDescription init reverse or a live client).

Open records (once per battle): version `0x18`, arena config `0x2d`
(`"17, 1, 0, 5"`), sub-version `0x30` (`[u32 2][u16]` 0x6468 /
0x6473), digest `0x3d`, Base `0x0` (`[eid][type 2][len][0][name]
[vehicle-eid-as-string][18 B header + arena pickle + roster]`),
CellPlayerCreate `0x1` (107 B: spawn V3 + yaw + vehicle eid),
control `0x2` (`[eid][0]`), map `0xf` (name + identity matrix +
`01`). EntityCreate `0x5`: 42 B prefix
(`[eid][type][0][space][0][pos][dir]`) + per-type state raw.

Rarer families: `[eid]` (0x4/0x22), counters (0x16, 0x28 Proh-only
values 1,2 co-firing with PlayerPosition toggles), 1 B flags
(0x12/0x2e), empty ticks (0x35/0x36), debug strings (0x1b),
chat+flag (0x23, 01 = own messages), named traces (0x31),
space records (0xd), snapshots (0x6, eid+blob), `[u32 n][n bytes]`
compounds (0x32/0x37/0x39 — 0x39 proven universal), per-tick
triplets (`0x39` + `0x1a` 60 B + `0x1f` at identical ~10 Hz stamps;
0x1a = `[V3][36 B][F32][-1×3]`, map-wide; 0x1f mostly paired
toggle-values; 0x1c/0x1d counters, 0x26 40 B — values opaque).

Base roster (`0x0` Rest split): arena-dict pickle, then
`\x80\x02}q\x01.`-separated 33 B quest-log entries (17/19/20 per
battle; IDs match the onChatAction quest family), one 80 B special
(2.4.0 only), trailer `02`.

0x37 short-subs (a pure subset; most bodies mix long-forms):
`[TAG][X][02][kind][id][s][f]` (7 B) + `000000` trailers, kind 3 =
one-shot init (f 01) vs kind 6 = sequenced updates (f growing).
30 even IDs c0–fa in EVERY battle (fixed slots, not entities);
(TAG,X) constant per battle (0a21/0666/0c3d — origin open, not
arenaUID low bytes). Slot timing (staggered firsts/lasts) matches
neither deaths nor roster/team order — falsified; AoI-gating
candidate with a position-correlation recipe (slot↔vehicle via
0xa tracks).

Earlier heuristic attributions (Monstrofil-era guessing, now
superseded — kept for the record): `enemySPGHit[37]`,
`onRankUpdate[67]`, `onRepairPointAction[28]`,
`updateTargetVehicleID[10]`, Vehicle `onExtraHitted[1]`,
`updateLaserSight[4]`, `showRammingEffect[10]`. Truth: 37=showTracer,
67=explodeProjectile, Vehicle 1=showShooting, 4=onHealthChanged,
5=onExtraHitted; updateTargetVehicleID/onRepairPointAction/
onRankUpdate never fire in these battles.

- Position (`0xa`, 45 B): `[entityID u32][reserved u32 = 0]
  [X,Y,Z f32][Aux 3×f32][Yaw,Pitch,Roll f32][flags u8]` — pinned on a
  driving sample (entity 4730080, t≈31 s, +Z). Aux is a per-entity
  near-constant trim (±0.06 max, one vehicle tracked over 400
  samples barely moves) and ZERO for the locally-controlled avatar +
  own vehicle — server-correction candidate (not turret: turrets
  traverse ±π).
- EntityMethod (`0x8`): `[entityID u32][methodID u32][argsLen u32]
  [args]` (argsLen covers the tail exactly, all 549 calls).
- Entity table: EntityCreate (`0x5`) gives `[entityID u32][typeID u16
  1-based]`… (last-write-win; avatar 4730140 seeded from
  Base/CellPlayerCreate). Every method call decodes exactly via
  `DecodeAll` (versioned wire tables, both fixtures green).

Decoded so far (Prokhorovka, all time 0.00 unless noted):

| idx | type | size | layout |
|---|---|---|---|
| 0 | `0x18` version | 11 | `[u32 len=7]["2.4.0.0"]` |
| 1 | `0x2d` ? | 15 | `[u32 len=11]["17, 1, 0, 5"]` (arena config numbers?) |
| 2 | `0x30` ? | 6 | `[u32 2][u16 0x6468]` |
| 3 | `0x3d` digest | 36 | `[u32 len=32][32 ASCII hex]` = entity-defs digest |
| 5 | `0x0` BasePlayerCreate | 1291 | `[eid][type 2][len][0][name][vehicle-eid-as-string][18 B][arena pickle][33 B quest entries][80 B special?][02]` (see below) |
| 8 | `0x8` EntityMethod | 1261 | `[entityID u32][methodID u32 = 58 = updateArena][u8][string-pickle (`epic_config`, `epicMetaGame`, …)]` |
| 12 | `0x1` CellPlayerCreate | 107 | `[eid][spaceID][0000][vehicleEID][spawn V3][yaw][8 B 0][zeros][vehicleEID][0][A][CONST][0][2][2][zeros]` (A/CONST ~1e9 open) |
| 14 | `0x2` EntityControl | 5 | `[entityID u32][u8 control flag]` |
| 19 | `0xf` Map | 94 | `[spaceID = 2122][arenaID = 86][u8 20]["spaces/05_prohorovka"][identity matrix 16×f32][u8 01]` |
| 20 | `0xa` Position | 45 | `[entityID][0][X,Y,Z][Aux 3×f32][yaw,pitch,roll][flags]` (see above) |
| 1486 | `0x2b` PlayerPosition | 1 | `[u8 00/01]` — pairs at t=0/t=30, sparse toggles; 00 hits own death twice but also fires mid-battle with a same-tick 0x28 counter (values 1,2, Proh-only): reload/stun/death/spectate/killcam all fail somewhere — open |

Entity/table findings (same battle):

- EntityCreate (`0x5`): `[entityID u32][typeID u16][vehicleID u32]
  [spaceID u32][pos Vector3][dir Vector3][u32 ?][state…]`
  (Monstrofil 1.8 shape holds in 2.4).
- **typeIDs are 1-based over `entities.xml` order** (type 6 =
  Vehicle, 7 = AreaDestructibles ×130, 40 = NetworkEntity). Player
  avatar (entity 4730140, created via Base/CellPlayerCreate, no `0x5`)
  takes the high-wire calls (max 67 = explodeProjectile) — consistent
  with Avatar's 70 client methods; Vehicle targets stay within 0–10
  (11 methods).
- Named traffic (proven, Prohorovka census): Avatar `showTracer[37]`
  ×128, `explodeProjectile[67]` ×105, `stopTracer[28]` ×42,
  `enemySPGHit[23]` ×13, `showShotResults[54]` ×7, `updateArena[58]`
  ×9, `onChatAction[38]` ×4 (quest pickles), `enemySPGShotSound[33]`
  ×6; Vehicle `showShooting[1]` ×81, `onHealthChanged[4]` ×49,
  `showDamageFromShot[10]` ×47 (the damage event),
  `showDamageFromExplosion[7]` ×9, `onExtraHitted[5]` ×12,
  `onStaticCollision[8]` ×33.
- 24 entities receive Position packets (22 Vehicles + avatar +
  one `EmptyEntity`, typeID 18 — odd one out, open).
- Duplicate EntityCreates exist (same ID re-created, type stable) —
  entity tables must last-write-win.

## 7. Tooling (`replay/`)

- `replay.go`: `Open`/`Parse`, `decrypt`, inflate, `MetaField`,
  `ClientVersion`, `BlocksRaw` (all JSON blocks verbatim).
  Stdlib + `golang.org/x/crypto` only.
- `packets.go` + `dispatch.go`: framing, positions, methods, entity
  table, `DecodeAll`/`DecodeAllLenient`.
- `values.go`: descriptor-driven value decoder (`[u8 | FF u24LE]`
  lengths; size-0 tuples count-prefixed).
- `methods_gen.go` (generated), `methods.go` (versioned var maps,
  fit classifier), `events.go` (damage/health/shots + derived kills:
  health→0 with latest attacker in 10 s), `timeline.go` (`Extract`
  → JSON-ready `BattleTimeline`).
- `properties.go` + `properties_gen.go` (generated FullIndex table):
  EntityProperty `[eid][idx u32][len u32][value]`, 94661 updates
  exact on three fixtures.
- `nested.go`: NestedProperty `[eid][level][len][000000][op][payload]`
  (damageStickers/engineMode/area-tuples typed; paired-timer and
  c0 channels structural); PlayerPosition 1 B boolean.
- `creates.go`: version/arena-config/sub-version/digest records,
  CellPlayerCreate spawn struct, identity-matrix Map, Base strings +
  raw pickle, EntityCreate 42 B prefix + raw state.
- `misc.go`: eid/counter/flag/string/chat/named/space/snap records,
  `[u32 n][n bytes]` compound envelopes (0x32/0x37), per-tick
  families pinned (0x1a==0x1f counts, 0x39 41/72 B, empty 0x35/0x36).
- `replay_test.go`: offline pins (Prokhorovka + Mines + Glacier +
  2.0 decrypt).
- `cmd/wotreplay`: summary + `-meta` (setup fields) + `-dump PREFIX`
  (writes `.stream.bin`). `cmd/wotevents`: battle timeline JSON
  (damage, kills, explosions, tracers, explodes, shot results).
  See `AGENTS.md`.
- Fixtures: `../replays/` (repo root).

## 8. Verification (`wotverify`, tail MD5, EC pubkey)

- The stream's last packet (`0xFFFFFFFF`, 16 B) is
  **md5 over ALL JSON blocks concatenated** (setup-only on 1-block
  2.3/2.4 files, setup+results on 2-block 2.0/2.1 files — proven on
  all four fixtures); `wotverify` checks container, decrypt, full
  packet chain, this MD5, optionally the in-stream entity digest
  (`-digest`), and method/property table coverage where tables are
  proven (open var wires reported, not failed). This catches
  corruption and naive forgery, NOT a recomputed checksum — label it
  honestly (exit 0 prints `GENUINE (structural)`).
- `res/replay-sign.pubkey` (EC P-256) feeds the client's checksum
  schema (`ReplayController::init` fails without it). Verify chain
  (IDA): `sub_140E6A110` gates chunks (≥0x23 B, sigLen+39);
  `sub_142CA3420` runs the scheme verify (`+40` vtable) with
  "Insufficient data / Stream error" diagnostics;
  `sub_142AE6CF0` reports "Signature mismatch" via `sub_142C0B030`
  (digest-compare + key verify). Chunk layout `[u32 len][data]
  [u16-len sig]`. But 2.4 files carry NO such signature blocks —
  continuous decrypt+zlib+115k packets chain cleanly, zlib consumes
  all but 1 pad byte. So there is nothing to EC-verify in current
  files; the pubkey machinery targets a signed layout (older?
  downloaded?) not present here.

## 9. Open work

- Variable-size method-block ORDER (fixed block proven across
  2.1.1–2.4.0; var wires identified per-version by fit — the rule
  assigning them is unknown: ~20 analytic sort keys exhausted
  (doc/iface/nargs/prefix/arg-kind/name/hash/rotation), method-table
  build not found in IDA; constraints table in §6).
- 2.1.1-only var wires 40/42/60 (5 B id+string; bare-Python
  notification; periodic `(U16,U16)`-array sync) — no 2.4.0
  counterparts; need 2.1.1 `.def`s or more battles.
- 2.0 method/property tables (stream decrypts with the same key;
  mid-30 already overruns 2.4 signatures — need 2.0 `.def`s).
- Nested op-byte bases (mechanism mapped: count/index read,
  per-type base subtract, remap table, description-apply loop; need
  EntityDescription+0xF8 writer reverse or live client) and nested
  flags semantics.
- PlayerPosition flag + 0x28 counter semantics (falsified:
  reload, stun, death, spectate, killcam; co-firing avatar combat
  traffic logged).
- Position Aux exact semantics (per-entity trim, zero local —
  server-correction candidate) and 0x1 A/CONST fields.
- 0x37 long-form sub-records (08/84/00-led, eids+floats) and
  short-sub slot semantics (position-correlation recipe in §6).
- Per-tick families' values (0x1a 60 B, 0x1f, 0x1c/0x1d, 0x26,
  0x39), compound bodies (0x32/0x37 sub-records) — envelopes pinned,
  contents opaque (tick-model work, playback-adjacent).
- Kill/results extraction (`onBattleEvents`, `battleEventsSummary`
  never fire in these battles — need a battle that produces them, or
  the results path).
- Replay stream key: live key `DE72…` proven on fresh Sep-19
  recordings (so no rotation).   Writer mechanism CLOSED Sep 20
  (CE write-BP trace pasted in session, byte-verified in
  IDA on 2.4.0.0): the on-disk DEADBEEF×4 slot at `0x1442DA5A8`
  (writable `.data`)   is patched at startup by scattered `mov byte`
  immediates, one per subsystem ctor — odd bytes only (evens match
  static): `[slot+1]=0x72` in sound-engine ctor `sub_140570460`
  (`0x1405707E2`, which then starts the audio thread via
  `sub_1405845A0` and publishes to `qword_144847A20`),
  `[slot+3]=0xA0` + `[slot+9]=0xFE` in `sub_140352CB0`
  (`0x14035327C/83`), `[slot+5]=0x04` in `sub_142522AB0`
  (`0x142522E97`), `[slot+7]=0xB1` in `sub_1403854C0`
  (`0x140385555`). Engine parts (all IDA-verified): +3/+9 =
  `BW::game_loading::GameLoading` ctor, called straight from
  `WinMain` (`sub_1402E8D50`); +5 = `BW::ScaleformBW::Manager`
  ctor (Scaleform UI, `"Scaleform manager initializing…"` in
  `BW::WULF::UbUiRendererImpl::ctor` `sub_1404CD050`); +7 =
  `CameraApp` ctor (`"CameraApp"`, vtable `off_1435DD248`),
  reached via client-app init `sub_14035F630` from the same
  WinMain/GameLoading routine. So 4 of 5 bytes land at process
  startup; only +1 waits for the login screen's sound load (below). There is no key schedule — that is why every
  static derivation failed. Readers: replay file-open
  `sub_14057BEE0` (`lea rdx,[slot]` at `0x14057C1DA`) and
  `sub_14057C410` pass the slot as the Blowfish key.   Callers of
  the sound ctor trace back through Python (`call rax` at
  `0x1402EF372` ← `PyCFunction_Call` ← …), i.e. script-triggered
  init. Python trigger pinned (real 2.4.0 `.pyc`): `game.py::init`
  arms `SoundGroups.startListeningGUISpaceChanges`; on LOGIN-space
  entry `SoundGroups.__onGUISpaceEntered` calls
  `WWISE.WG_loadLogin` (C `sub_1424B2E70` → `sub_1426BB300` → AK
  engine → ctor). So byte+1 lands at login-screen load, before any
  battle/replay exists. `../ce/keyslot.lua` still useful to confirm the slot state
  per game stage.

## 10. Client command line (2.4.0.0, IDA-verified)

Parser `sub_140355DB0` (size `0x1d63`); arg-name string block at
`0x1435D7A48…`. No `--unattended` exists in the game binary — that
flag belongs to BigWorld's test runner (`runTests.py` invokes the exe
with `-unattended --script …`) and is not parsed here. Crash-reporter
(`--cat-*`) and embedded-browser (`--disable-gpu …`,
`--ppapi-flash-path …`) args are separate subsystems, listed for
completeness only.

- Replay/video/benchmark: `--replay-from <float>`
  (`dword_144847A28`), `--replay-to <float>`
  (`dword_1442DA500`), `--replay-times <n|"infinite">`
  (`dword_1442DA504`, infinite → -1), `--autoScreenshotTime <int>`
  (must be >0, `dword_1442DA50C`),
  `--replayScreenshotDirectory <path>`
  (`qword_1442DA578`), `--enableScreenshotsInReplay`
  (`byte_144847A1A`), `--forceAlwaysActive`
  (`byte_14483CAB4`), `--benchmarkMode`
  (`dword_14483CAD0`); replay file path itself
  (`g2DA558`, flag `byte_144847A18`, set by parseCommandLine).
  (Types/globals per IDA by operator; string-table confirmed Sep 20.)
- General: `--stealFocus`, `--nomulticore`, `--autodetectOnly`,
  `--resolutionOverload`, `--genAvailModes`, `--res`, `--options`,
  `--config`, `--cat-config`, `--script-arg`, `--logFilePrefix`,
  `--presetOverload`, `--preferences`, `--hangarMask`.
- Of login interest: `--preferences` (redirects the prefs file that
  holds the session blob), `--script` / `--script-arg` (startup
  Python automation surface; `--script-arg "lastStartCrashed -rg"`
  is the restart-after-crash convention).
- Nothing here touches the LoginApp/BaseApp handshake.
