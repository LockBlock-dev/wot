# AGENTS.md — wot (Go module `github.com/LockBlock-dev/wot`)

Single Go project for World of Tanks EU internals: LoginApp + BaseApp
client (`login`), LoginApp ping (`ping`), `.wotreplay` reader
(`replay`), entity-def reader + login digest (`entdef`), live key
dumper (`keydump`), transparent forwarder (`tproxy`), private server
half — LoginApp + BaseApp stage-1/2 (`login/loginapp.go`,
`login/baseappsrv.go`, `cmd/wotserver`). All CLIs
live under `cmd/`. Run from here: `go run ./cmd/wotlogin -env
live.env -baseapp`. Protocol truth lives in `../docs/NETWORK_PROTOCOL.md`
(login + server-side stage shapes §18) and `../docs/REPLAY.md`
(replays); update them on wire changes.

## Layout

- `server/` — private-server application layer (accounts, sessions,
  player state). `store.go` is the persistence boundary (a domain-level
  `Store` interface, not SQL); `sqlite.go` is the only implementation
  (`modernc.org/sqlite`, pure Go, no cgo); `account.go` (bcrypt via
  `x/crypto`, case-insensitive names), `session.go` (random non-zero u32
  keys, TTL, in-memory only), `state.go` (credits/gold/free XP, garage,
  research — stored as a JSON document so the model grows without
  migrations), `server.go` (`Provision` one default account
  idempotently, `Authenticate`, `BeginSession`), `unit.go` (squads:
  `UnitManager` implements `login.UnitBackend` — one squad per account,
  three roster slots, ready mask, comment, vehicles, invitations;
  in-memory because a squad is a live session object), `social.go`
  (implements `xmppserver.SocialStore` over the `social` table),
  `economy.go` (the purchase surface: `Economy` implements
  `login.EconomyBackend` — exchange, free XP, premium, slots, berths,
  piggy bank; the rates are the server's, and premium expiry is
  per-account state clamped to `MaxPremiumExpiry`), `crew.go` (the crew
  assignment: `Crew` implements `login.CrewBackend` for
  `CMD_EQUIP_TMAN`, storing one tankman instance id per slot in
  `GarageVehicle.Crew` — the client derives a tankman's vehicle from the
  vehicles' lists, so that is the only copy), `queue.go` (the
  matchmaking queue: per QUEUE TYPE, platoon-grouped via
  `EnqueueGroup`, with a census indexed by the client's own
  `VEHICLE_CLASSES`), `matchmaker.go` (the pure formation rule: oldest
  entry anchors a ±2 tier band, a squad goes to one team, sides fill
  alternately — a formed battle is LOGGED, not handed off, because
  `onArenaCreated` needs a cell app), `matchmaking.go` (the service
  behind `login.QueueHooks`: validation, JOIN_FAILURE codes, squad
  grouping), `arena.go` (the battle record: id, space, arena type, map,
  roster, state, and the reconnect window that holds a dropped player's
  slot). Wired into
  `cmd/wotserver` via `login.ServerConfig.VerifyCredentials`; a refusal
  rides status 68 with the live short wording. Scope and open problems:
  `../docs/PRIVATE_SERVER.md`.
- `login/` — framing builders/parsers + `Client.Login()` flow (pure where  possible; `SolveFunc` injected for tests; `Transport` interface over
  UDP so the handshake is script-testable offline): `client.go`
  (`Client`: config/auth-provider/solver/socket/peer/reply-ID sequence),
  `auth.go` (`AuthProvider`: basic/token/token2 identity + username
  JSON + `ExtractUpgradeToken` + `ReloginConfig`),
  `session.go` (`BaseAppSession` machine owning stage-1/stage-2 +
  `Session.UpgradeToken` + `RecordMiddle` pairs file),
  `options.go` (`Option`/`ApplyOptions` CLI overrides),
  `transport.go` (`Transport`, satisfied by `*net.UDPConn`),
  `login.go` (legacy `Login()` wrapper + builders), `logonparams.go`
  (packed strings, pwd_token, RSA chunking: partSize 213, 256 B blocks
  out), `crypto.go` (Blowfish-ECB+XOR-chain decrypt + verified encrypt,
  `decryptSession`), `rewrite.go` (`RewriteLoginReply`: length-preserving
  232B endpoint swap + `encryptLogin` mirror for the BaseApp MITM), `baseapp.go` (`buildBaseAppLoginMsg`,
  `buildChannelAck`, `buildAuthenticate`, `checkBaseAppReply`,
  stage-1/stage-2 script), `hijack.go` (wotproxy dump parser +
  `SessionFromDump` + `LoginSourcePort`), `config.go` (stdlib `.env`
  parser + `Config`; sorted+spaced username JSON; `cpsaltSession`),
  `flood.go` (bulk chunk reassembly by channel-seq + NN headers,
  smalls taxonomy + census, keyfile/recover helpers),
  `tokendict.go` (`FindTokenDicts`: pickled `{databaseID, token}`
  hunt in decrypted S>C, TokenResponse-shaped).
- `lobby/` — offline application layer, stdlib-only (no transport):
  `vehicle_data.go` + `vehicle_data_gen.go` (COMMITTED codegen output:
  1251 vehicles, components, per-turret guns, shells — built by
  `cmd/wotgendata` from 2.4.0.0 item_defs (1252 list rows minus the
  Observer pseudo-row); `GeneratedTable`/`GunSpec`
  replace XML at runtime),
  `garage.go` `OwnableVehicle` carries `Class`/`Level` from the list
  entry's `<tags>`/`<level>`, which is what the matchmaker's census
  buckets by; `ParseIntDescr` subtracts
  `EXTENDED_VEHICLE_TYPE_ID_FLAG` back off the low nibble for the simple
  item types (111 of the 1256 vehicles have a type id above 255 and
  would otherwise read as turrets),
  `unit.go` (squad wire codec: the client's own binary format from
  `common/UnitBase.pyc` `pack` + `common/ops_pack.pyc` — `_IDS '<IBB'`,
  the roster, `_HEADER '<HHHHHHHHBiiiiii'`, `_PLAYER_DATA '<qiIHBHHHq?'`,
  pascal strings, the empty badge block and a pascal-framed pickled
  empty dict; `PackUnit`/`Op*` builders plus the UNIT_* constant
  tables),
  `pickle.go` (hand-rolled proto 0-2 decoder, triple-verified vs
  CPython execution + independent emulator on 3 captures; LONG1/4
  sign fix Sep 28; `DecodeAt`/`DecodePrefix`/`Inventory` resync +
  `Frag`), `pickle_faithful.go` (second codec: decode to a node tree
  that remembers HOW each value was encoded — exact opcode per scalar,
  str vs unicode, container build recipes, memo index + BINPUT/
  LONG_BINPUT choice — so `EncodeFaithful` reproduces the input
  byte-for-byte; `SetInt`/`SetString` mark a node dirty for canonical
  re-encoding. This is the private server's bundle mutator and its
  round-trip oracle; `pickle.go` stays the salvage/census decoder),
  `lobby_state.go` (prefix salvage → plain maps/slices),
  `lobbycalls.go` (C>S base-call builders: doCmdInt2/3/4/Str,
  requestToken, primeBundle prefix, chat tails), `battle.go` (avatar
  position parser), `battlechat.go` (battle chat both directions:
  C>S submit `0x9d`/eventType 22, S>C relay `0x75`/23, shared 24B
  header + `[u8 len][text][u16 0]`, float64 UTC send time — see
  `../docs/NETWORK_PROTOCOL.md` §19.10). Split out of `login/` Oct
  2026; all callers
  import `lobby` directly (compat aliases removed).
  Tests: `login_test.go` (offline codec vectors), `hijack_test.go`,
  `paired_replay_test.go` (byte-identical replay of the paired genuine
  stage-1/stage-2 capture, `../captures/flows3` + `../captures/key3.txt`;
  fixtures rebuilt from those two files by
  `../captures/extract_flows3.py` — vectors to `/tmp/opencode/vectors`,
  stage-2 flow to `../captures/flows3-s2.txt`; re-run after any /tmp
  wipe),
  `scratch_flood_test.go`. Offline only.
- `xmppserver/` — the LIVE XMPP chat service (this one owns sockets;
  `xmpp/` below stays offline). It is what makes the contacts list work
  at all: in 2.4 `messenger/proto/__init__.pyc`
  `ServerSettings.useToShowContacts` picks XMPP exactly when
  `xmpp_enabled` is set in the server-settings document, and the legacy
  BW fallback calls `addFriend`/`requestUsersRoster`, methods that do not
  exist in the 2.4 defs. `node.go` (generic XML tree + stream reader:
  the stream root is never closed, so the caller reads the root
  StartElement itself), `server.go` (listener, session registry, rooms,
  `TokenFor` = per-run HMAC of the client DBID), `session.go` (stream
  negotiation, SASL PLAIN, bind, presence relay with a server-authored
  `wgexts` identity block — the client's own presence carries only
  `wgexts-client`), `roster.go` (jabber:iq:roster get/set/push,
  urn:xmpp:blocking, `#storage` notes, `#spa-resolver` nicknames,
  disco), `muc.go` (XEP-0045 rooms: clan channel + user rooms),
  `social.go` (`Social` model + `SocialStore`; `server.SQLiteStore`
  implements it over the `social` table). Tests drive a real TCP
  handshake.
- `xmpp/` — offline XMPP chat layer, stdlib-only (NO network: no
  TCP/UDP/HTTP clients — builders/parsers only): `jid.go` (DBID@
  domain/resource), `settings.go` (`ServerSettings` + TCP-first
  2-sample `Iterator`, mirrors `XmppServerSettings.pyc`),
  `endpoints.go` (124B endpoint-list parser, pinned on the Sep-29
  lobby #2 genuine vector: key name + KP-terminated bosh host;
  ports default, not wire), `stanza.go` (message/IQ/presence
  build+parse, stream open, features mechanisms, WG extensions
  passthrough), `bosh.go` (XEP-0124 framing, `/bosh/` path).
  Tests offline (genuine endpoint vector + genuine roster-IQ and
  live-features vectors, rest synthetic). BaseApp chat tails stay
  in `lobby`. Live Oct-12 (`cmd/wotxmpp`, read-only): TCP 5222 open,
  stream domain `c2s.xmpp-wot-eu.wargaming.net` (others get
  host-unknown), PLAIN-only no STARTTLS, identity = DBID, password
  auth dead (LOGIN 500 / DBID rejected); FULL LOGIN launcherless via
  `-token` (XMPPCS token = 8-digit INT from the int token-dict ~1 s
  after requestToken — NOT the JWT, which is WGNI/shop; SASL PLAIN
  DBID+token, bind + presence + roster all green, no WGC/Steam);
  BOSH :5280 RSTs creates, :443 refused.
- `ping/` — LoginApp ping library (`ping.go`: framing consts,
  `encodeRequestWithPrefix`, `decodeReply` for 16 B current and 18 B
  2022 replies, `Client`, `Classify`, `NewReplyID`) + `ping_test.go`.
  Offline only.
- `replay/` — `.wotreplay` reader: `replay.go` (`Open`/`Parse`,
  decrypt, inflate, `MetaField`, `ClientVersion`), `packets.go`,
  `dispatch.go`, `entities.go`, `values.go`, `methods.go` +
  `methods_gen.go` (GENERATED from 2.4.0.0 entity_defs via `entdef`
  DescribeDeep + iface-first stable size-sort; var lists doc order —
  see `../docs/REPLAY.md` §6 before regenerating; Bundle codec mapped Oct-11
  (see `../docs/NETWORK_PROTOCOL.md` §4: length formats, startMessage/
  startRequest(extra=6)/startReply/doFinalise — the Go builders mirror
  this exactly), `properties.go` +
  `properties_gen.go` (generated FullIndex table via entdef
  `CSPropsOrdered`), `nested.go`, `creates.go`, `misc.go`, `events.go`,
  `timeline.go`. Tests pin Prohorovka (2.4.0) + Mines (2.3.1) +
  Glacier (2.1.1) + 2.0 decrypt. Offline only.
- `entdef/` — entity-def reader (packed-section `.def` parser) + login
  digest computation over `../World_of_Tanks_EU/res/scripts`
  (entities/interfaces/alias) plus external game-data trees kept as
  uncommitted siblings of this repo (`../wotdefs-2.4.0/`: space defs,
  339 component defs, 10 mode entities, 17 extension manifests;
  `../wotdefs-2.4.1/` + `../scripts-2.4.1/`: 2.4.1.0 defs extracted
  from live `res/packages/scripts.pkg` + 19 mode pkgs; 403-entry walk,
  18 fails via `Skip241`): `components.go`, `digest.go`
  (`ComputeDigestFull`, 318-entry map walk for 2.4.0; `DigestVersion`
  version-aware wrapper + `Truth240`/`Truth241` + `ResetAliases`
  for multi-version use), `defs.go`, `packed.go`, `types.go`.
  Game defs are never vendored under `testdata/` (git-ignored).
- `internal/cuckoo/` — vendored `ZiRo-/cuckgo` (MIT, see
  `LICENSE-THIRD-PARTY`): `cuckoo.go` verbatim, `miner.go` = upstream
  search adapted with early exit + our `SolveChallenge` driver.
- `testdata/` is git-ignored: digest fixtures live outside this repo
  (see `entdef/`). Do not vendor game defs here.
- `cmd/wotlogin/main.go` — thin CLI (`-env`, `-baseapp`, `-host`,
  plus `-relogin` / `-session-guid` / `-temporary` / `-client-context`
  overrides and `-solve` / `-probe-port` / `-empty-key` / `-raw-key` /
  `-bare-auth` probes and `-hijack DUMP`; `wotlogin -h` is
  authoritative). BaseApp rides the first (basic) session by default;
  `-relogin` opts into the from-zero token2 diagnostic. One
  unconnected socket for login; never `connect()`. Prints `servermsg
  keys=` plus user-visible fields only, never secrets.
- `cmd/wotping/main.go` — thin CLI (flags, per-host loop, summary).
- `cmd/wotproxy/main.go` — transparent UDP log-and-forward proxy
  (stdlib only). Explicit LoginApp mode via `../mods/custom-server-mod`;
  `-dump file` appends raw hex. RSA MITM live Sep 27 (`mitm.go` +
  `login/rsamitm.go`): CUSTOM host uses our `loginapp_mitm.pubkey`,
  `-mitm-privkey/-mitm-pubkey` decrypt/re-encrypt in flight and feed
  the 232B rewrite the exact-session key (fail-open; `-keyfile`
  fallback). Key pair backed up at `../mitm/` (privkey 0600).
  `-keyfile` tails a wotkeydump/CE wotkeys.txt (lengths/hashes only).
  `-transparent addr` (Linux): DNAT mode for LoginApp + BaseApp with
  per-flow original-dst routing (pre-install rules per `tproxy/doc.go`,
  game runs stock, no mod); BaseApp flows log sizes only. PARKED Sep 27:
  OUTPUT-chain NAT never reports pre-NAT dst via cmsg on this host.
- `cmd/wotproxy -baseapp-listen` — BaseApp MITM without firewall: with
  `-keyfile`, rewrites the S>C 232B LOGGED_ON endpoint to a local
  `tproxy` relay (`login.RewriteLoginReply`, length-preserving,
  fail-open without a key). Captures stage-1; the relay's `RewriteSC`
  hook rewrites the stage-2 `[44]` redirect the same way
  (`login.RewriteRedirect`, retargets the relay, chains welcome).
- `cmd/wotproxy -battle-feed` — live battle feed (Oct-12, opt-in):
  `-battle-own/-side/-watch/-margin` tune `lobby.LiveFeed`, fed with
  decrypted BaseApp apps on the relay path (explicit + transparent);
  SHOT/HIT/KILL/READY/LINK/SPOT rows on stdout, names/counts only.
- `login/loginapp.go` — LoginApp SERVER half (same package: framing/
  statuses/packed strings stay single-sourced with the client halves).
  UDP serve loop (1 s deadline, ctx-cancelled) + per-client pending-PoW
  map; C>S walk mirrors udp_bundle_processor.cpp (request-chain
  offsets, next-request links honored by FIXED members too, varlen
  login/CR/MTU, login len covers DATA only); order version→
  unencrypted-64 →RSA-OAEP chunk decrypt→PoW→digest→LOGGED_ON.
  PoW: prefixes are ours (16-hex+':'), verify = HasPrefix + cuckoo Verify
  over exactly 42 nonces; ANY rejection (bad table/foreign prefix/bad
  nonces/restart) reissues a FRESH status-66 challenge — a documented
  server choice (live reject wording unobserved); the real client
  hierarchy ends at any second reply, so reissues surface cleanly.
  Digest gate: strict allowlist defaults to entdef.Truth240/Truth241
  (status 70 `Defs digest mismatch`, zero digest refuses like live);
  AcceptAnyDigest opts out. LOGGED_ON: 12 B record (mirror listener or
  explicit Advertise, IPv4-only, salt 0) + packed servermsg
  encrypted with the CLIENT's key via encryptLogin (no magic); minted
  per login: session_key u32, session_id 32-char with the genuine
  constant stretches (`06G`@[0:3], `000000`@[10:16], `41VPHF`@[16:22];
  census = 3 samples: captures/game_20260920.log:413,:4871 +
  login3-game.log — suspected time field at [0:10] not reproduced),
  token2 69 digits `9:19:39` with segments never zero-led,
  pseudoAccountID = FNV-1a
  (name) floor-biased to 9 digits, servermsg JSON field order
  isDemoAccount,name,security_msg,session_id,token2 compact unescaped
  (199 B with the ExampleUser census cite captures/game_20260920.log:413
  — values SYNTHESIZED, shape faithful); no account DB: any identity.
  Tests offline (`loginapp_test.go`): challenge 55-B echo + fresh-mint
  replacement, unencrypted 64 / version 65 / digest 70 texts, ping 16 B
  echo incl. a chained ping+login datagram, probe silence, bad-solution
  reissues (no index panic on short tables), malformed-datagram table,
  mint-shape units vs the genuine 199-B vector, full loopback handshake
  over real Client + SolveChallenge (Short-skipped).
- `login/rewrite.go` — `RewriteLoginReply` + `encryptLogin` (login-path
  Blowfish mirror, no magic trailer).
- `login/flood_build.go` — the stage-2 bundle AUTHORED from the defs
  (Nov-1): `FloodBundle` writes `updateFrequencyNotification` +
  `tickSync` + the `createBasePlayer` element (entity id, type id, the
  Account entity's wire-order properties, component count) with the
  engine's oversize length form when the payload passes 64 KB
  (`elementOversize`); `FloodFrames` splits it into the chain. No capture
  is read: `TestFloodBundleMatchesCapture` proves the encoder reproduces
  the genuine 246 531 B 2.4.1 stream byte for byte from the same settings
  pickle. `login/lobby_content.go` authors the post-flood elements.
  NOTE: `0x1A` is `selectPlayerEntity` (the exe's message-name table:
  tickSync 19 = 0x13, selectPlayerEntity 26 = 0x1A), so a `1a XX …`
  element is selectPlayerEntity followed by a CLIENT METHOD CALL (`XX` =
  entityMethodBase 0x4E + id; 0x76 = showGUI, 0x69 =
  onUnitBrowserResultsUpdate, 0x5b = receiveServerStats). Framing is
  `[elemID][elementLen][stringLen][string]`, the method's
  VariableLengthHeaderSize being the ELEMENT length width and the string
  header always ONE byte — a fixed byte where the string length belongs
  is a MemoryIStream over-read (`pCurr_ + nBytes <= pEnd_`).
  `entdef.Entity.WireProps` is the wire property order (interfaces first,
  then declaration) — distinct from the digest's FullIndex sort.
- `server/settings.go` — `SettingsFromJSON`: the lobby's
  `initialServerSettings` document from JSON to pickle. The committed
  `wot/wotserver.settings.json` is generated by
  `../tools/gen_server_settings.py` from the client's own bytecode: every
  `gameParamsKey` schema with its `required=True` fields (plus the mode
  packages', e.g. `story_mode.pkg`), and — for every key `set()` builds
  with `makeTupleByDict` — either `{}` (when the class accepts an empty
  dict: kwargs `__new__`, `__new__.__defaults__`, all-defaulted
  signature, or a `settingsBlock` subclass) or the class's own
  `defaults()` values — except `winback_config`, which `set()` hands to
  `_logger.info(msg, value)`: `LogRecord.__init__` unwraps a single
  NON-EMPTY mapping arg, so a non-empty dict formats fine but `{}` stays
  wrapped in a tuple and `'winback_config' % ({},)` raises. Every
  `res/packages/*.pkg` is scanned too (the halloween package's four
  `usedInReplay=True` schemas are read directly by BattleReplay, and its
  keys come from a constants module in a different package), plus the
  keys the mode packages append to `constants.INBATTLE_CONFIGS` at import
  time (comp7/comp7_light/fun_random) — BattleReplay iterates that list
  too. One key the client cannot construct is fatal for
  the WHOLE document: `ServerSettings.set()` raises, `__init__` never
  returns, the client keeps no settings, and because `set()` also ends
  with `schemaManager.set(...)` the schema models stay empty — which
  surfaces as the unrelated-looking `SoftException('Schema
  story_mode_settings was not registered')` from the app_loader's
  predicate chain. `vehicle_post_progression_config` is read directly
  (BattleReplay) and must be present.
- `login/baseappsrv.go` — BaseApp SERVER half (Oct-17; transport-frame
  parity with `baseapp.go`'s client script so a LOGGED_ON client walks
  stage-1 → rotation → tick → `[44]` → stage-2 → double-auth → flood
  against US, decrypt-verified). Shapes byte-exact vs the flows3
  decrypts (`baseappsrv_test.go`: rotation 36B `5804|FF 08 000000|
  rid|newkey|seq0|cumul0`, tick 28B `13 3e|seq2|cumul1`, redirect 36B
  `13 3f|44|ip BE|port BE|000001|seq4|cumul1` — the other stage-1
  smalls + the 76B stage-2 descriptor are v1-cut, capture-ackable).
  Channel crypto = the LOGGED_ON key for BOTH stages (rotation rides
  as app content — decrypt-proven flows3). Stage-1 keyed by login
  sessionKey (pending record ≈60 s TTL; rotation re-send reuses the
  minted key with the CURRENT rid), stage-2 non-handshake datagrams
  keyed by SOURCE ADDR (28B double-auth carries no parseable key
  header); flood = flows3-s2 440×1252B carrier decrypted once at load,
  re-keyed per frame at serve (fresh prefix + ECB+XOR chain), contents
  stale reference (per-session bulk heads future work). Tests: shape
  units + unknown-key silence + full loopback dance incl. a
  decrypt-verified 1252B frame (skips when captures absent).
  MILESTONE v2 — post-flood chain (Oct-17): `loadPost` pulls the tail's
  332B terminator, `[13][7b]` rev answer, 1a/5b stats answer and the
  12B seed tick (tag 7a / seq 503 / cumul 3) out of the SAME carrier;
  `serveBulk` ends with the terminator, `sweepStage2` mints one tick
  per `PostTickPeriod` (100 ms, measured `1562.609→.810→.911`), and
  `servePostFlood` classifies bundles via `postDoCmd` on the cmd field
  (100 → rev answer once/session, 501 → stats answer per poll, else
  v1-cut silent). Green at both levels: loopback
  `TestBaseAppStageLoopback` (full chain, byte-exact seed tick + rev
  answer) and a real CLI-binary walk (6/6 polls answered, census
  `28:225 36:7 60:1 332:1`). Two live-caught bugs, both
  regression-pinned (`TestBaseAppPostDoCmd`): the sync and the poll
  SHARE the leading `0x95` A1 tag — only cmd 100 vs 501 separates
  them; and the "sync answered" latch must be set on a cmd-100 arrival,
  never on the first post-flood datagram (the client's per-tick acks
  arrive first and would swallow the sync).
  MILESTONE v2.1 — per-session smalls (Oct-17): `loadPre` (same
  carrier) keeps three more flows3-s2 templates and `handleStage2`
  serves them per session —
  info (36B wire, app verbatim + footers seq1/cumul0, byte-exact),
  descriptor (76B, `descriptorFrame` substitutes the session name into
  the packed `[nlen 0b][ExampleUser]` slot at clear[25], 255-truncated
  like the 1B field; companion footers seq2/cumul1 ride verbatim),
  and the 1a/76 session-dict small (`1a 76 9c 00` + 156B = status 9b +
  155B proto-2 pickle; sent at serveBulk START as `[13][40]` + tpl +
  footers seq2/cumul-live). The dict's personal riders are V1-cut:
  `1a 73` (clan block, personal text) + `1a 79` (redirect offer with
  the capture's IP/port) never re-enter our wire.
  `dictApp`/`patchDict` re-patch four pickle fields per send —
  serverUTC (BINFLOAT, mint time), aogasStartedAt (= utc − 1.951 ms,
  the capture's playtime-watcher delta), sessionStartedAt (admission),
  databaseID (`pseudoAccountID(name)`) — the three booleans replay
  the capture's values; the patcher locates values by
  `key + BINPUT(0x71) + opcode` (`patchPickleValue`, fails loud on
  drift; loadPre dry-runs it on a COPY so the stored template keeps
  the capture's stale reference values).
  Post-flood answers are per-session MINTED on the shared walk
  (`allocPost`/`mintPost`: one WALK SLOT per S>C frame — tag
  7a+n mod 256, seq 503+n, cumul = live watermark; the genuine tail
  walks 7b/504 rev → 7e/506 offer-cut → a4/545 poll → dd/602 1a5e):
  rev answer once/session, 1a/5b poll stats per poll (body = the
  capture's FIRST answer — counters drift, stale note), and NEW cmd
  121 season-select → minted `[1a 5e 05][req u16 LE echo][000]` (we
  hold no garage; the genuine failure small is the honest answer).
  `noteReliable` advances the watermark from the client's reliable
  sends (byte-0 bit 0x10; seq at clear[len-8:len-4] + 1) so minted
  cumuls ramp like the capture (4 rev / 5 poll / 7 season); the seed
  floor `max(live, 3)` keeps the rev byte-exact. Deltas in §18.7:
  dict at burst-START (seq 2) vs the capture's mid-burst seq 176;
  descriptor's in-clear footers stay capture-stale. Tests green:
  `TestBaseAppPostFloodCarrier` (templates byte-exact incl.
  name-splice + 255-truncation units), `TestBaseAppPostDoCmd` (req
  surfacing: sync 224/100, poll 202/501, season 225/121),
  `TestBaseAppStageLoopback` (full walk: info byte-exact, spliced
  descriptor, dict decoded with per-session values via
  `lobby.DecodePrefix`, seed tick + rev byte-exact, minted poll + 1a5e
  at cumuls 5/7).
- `cmd/wotserver/main.go` — thin both-halves CLI (`-addr` default
  `127.0.0.1:20016`, `-privkey` default `mitm/loginapp_mitm.privkey`
  = the pair the game encrypts to under mods/custom-server-mod;
  BaseApp default-ON: `-s1 127.0.0.1:32850` = the LOGGED_ON record
  endpoint (LOGGED_ON mint admits via `cfg.OnLoggedOn`),
  `-s2 127.0.0.1:32851` = the `[44]` redirect target (bind inside the
  32810-32999 manager window or construction fails loud),
  `-flood` + `-floodkey` default the flows3 stage-2 carrier + its CE
  key (`../captures/…`, relative from `wot/`; empty `-flood` = no
  carrier, stage-2 answers the dance then errors on the flood loud);
  `-baseapp host:port` overrides the record endpoint (external
  advertise), `-maxnonce`, `-any-version`, `-digest any` gate bypass,
  `-verbose`; `-xmpp 127.0.0.1:5222` runs the chat service (must match
  `xmpp_connections` in the settings document; `""` = no chat),
  `-clan-tag`/`-clan-name` seed the default account into a clan
  (`""` = clanless), `-battle-team-size N` is how many players per side
  the matchmaker needs (default 15; 0 = one queued player forms a battle,
  which is how the arena entry and the reconnect are exercised with one
  client — the client still starts in the hangar); signal-ctx graceful
  stop, LoginApp+BaseApp+XMPP concurrent.
  Milestone v1 green Oct-17: our client's full decrypt-verified
  1252B flood over loopback (`TestBaseAppStageLoopback`), then the
  real CLI-binary walk (`go build wotlogin+wotserver`, scratch .env
  pointing at loopback, `-digest any`): basic login → LOGGED_ON
  (OnLoggedOn admits) → 22B rid rid+1 → rotation/tick/redirect all
  byte-exact → redirect followed (fresh socket) → rotation-2 →
  double-auth → FLOOD 1252B decrypt-verified → `LOBBY flood reached`;
  server census 440 frames emitted. Note: the smoke needs
  `-digest any` (client .env DIGEST_HEX empty = zero digest) and the
  MITM pubkey pair (PUBKEY_PATH=../mitm/loginapp_mitm.pubkey). Smoke-tested live: `wotping` 3/3 echo vs the running
  server binary.
  Oct-17 IDA packer pass (2.4.0.0 image) feeds the v2 mint plan: the
  client has NO pack side (`packVolatilePositionDirection: Unpacker was
  requested to pack` = log-only stubs `0x140E36520/0x140E52520`) —
  CellApp packing is server-only; the fork's mandatory packer name is
  the 10-byte constant `"bw.default"` (`0x143606830`, memcmp 0xA inside
  `ServerConnection::createEntity 0x140E4E870` / `-Detailed
  0x140E4ED50` / `-changeVolatilePackerType 0x140E4DBF0`, mismatch →
  disconnect); `createEntity` wire parse closed
  (`[entityID u32][u16][blobLen u8 | 0xFF→24-bit LE][creation
  blob][1B per-entity map slot][packerName len-scheme][dir u32
  dirType0]`). The flows3 116B "entity burst" is REFRAMED: it rides
  exactly one per flood tick (28 tick windows, `[13][5e..79]` tag ramp,
  counter +9/tick, app opaque after 8×11-volatile + raw-deflate +
  wrappers falsifications) — a flood-phase companion, not a
  creation/defs document; doc details in NETWORK_PROTOCOL.md §14/§18.5
  (incl. the post-flood tail: 332B terminator → `[13][7a]` short tick →
  client 84B `[02][key2][1c00]` re-auth → `[13][7b]` 60B reply).
- `tproxy/` — transparent forwarder: `forward.go` (flow table keyed by
  client+origDst, 4 MiB rcvbuf, idle reaper), `origdst_linux.go`
  (`SO_ORIGINAL_DST` via `x/sys/unix`), OS stub elsewhere.
- `cmd/wotkeydump/main.go` — headless LogOnParams encryptionKey dumper
  (CE-free `ce/wotkeydump.lua` replacement): pattern-scans the game image
  for `sub_140E6E210`, breaks on entry, appends `wotkeys.txt` lines for
  `wotproxy -keyfile` / `wotlogin -hijack`. Backends: Linux ptrace+procfs
  (Windows EXE under Wine/Proton), Win32 Debug API on Windows.
- `cmd/wotwgcs/main.go` — broker-mint CLI (GOOS=windows helper,
  run in-prefix via proton while Steam SSO valid): flat
  `binding_WGCApi*` calls (CreateGlobalInstance IID
  `0x1600020001247C`, Prepare, GetLoginInfo), token2 to a 0600
  keyfile, HRESULTs/lengths/hashes only. No LoginApp traffic.
- `wgcs/` — broker client library (`wgcs.go` IID/probe sizes,
  `api_windows.go` LazyDLL, `api_other.go` stub, `token.go`
  shape-scan + keyfile store). Stdlib only (`syscall`), tests
  offline; `GOOS=windows go vet` clean. IDA-recovered layouts
  (wgcs_api.dll, see `../docs/WGC.md`): pipe exactly
  `\\.\pipe\WGCS_IPC`; `GetLoginInfo` OUT = +0 WCHAR[64], +128
  WCHAR[256], +640 WCHAR[64], +768 UINT64 spaId, +776 DWORD
  (sub_180050190; all strings inline WCHAR, no pointer chasing);
  `GetRememberMeToken` = struct(+0 token area, +256 UINT64) +
  WCHAR[1024] buffer; `StoreRememberMeToken` = WCHAR[128] key +
  WCHAR[1024] token; LoginSession vtable @0x18015A588
  (slot0/4/5/8 = logininfo/store/get/generate workers).
  `wgc.exe` is a thin shell; the core is unpacked
  `dlls/game_center.dll` (see `../docs/WGC.md` §7: AES-ECB seal for SSO
  material, Wine-DPAPI-hex seal for the user_info store).
- `cmd/wotdpapi/main.go` — Wine-DPAPI unwrap CLI (GOOS=windows,
  proton-run, prefix-local only): hex blob in, 0600 plaintext out,
  lengths only. No network/broker/game.
- `cmd/wotxmpp/main.go` — live XMPP endpoint client (TCP stream +
  features by default, no auth; `-bosh` framing; `-auth` SASL PLAIN
  with live.env; `-token` XMPCCS/JWT token auth): read-only after
  login (presence + roster IQ, names only). Thin CLI, protocol in
  `xmpp/`.
- `dpapi/` — unwrap library (stdlib `syscall` LazyDLL crypt32,
  windows helper + stub, offline tests; `GOOS=windows go vet`
  clean).
- `keydump/` — shared core: `pattern.go` (masked scan), `mem.go`
  (MSVC string at `[RCX+0x58]/[RCX+0x68]`), `keyfile.go`
  (wotkeys.txt append/read), `pattern_default.go` (2.4.0.0 prologue),
  `dump_linux.go` / `dump_windows.go` OS backends (ptrace+procfs on
  Wine; ESRCH-tolerant attach, zombie PIDs skipped, Ctrl+C detaches +
  restores + CONTs the game). Sandboxed targets (Steam pressure-vessel
  userns + NoNewPrivs) are refused pre-attach at any uid — ptrace stops
  threads there without tracership (TracerPid stays 0, Sep 27: 74/74),
  so only CONT resumes; keys there need the in-process mod.
  `walk.go`/`walk_linux.go` (Oct-15): same backend records the digest
  walk (entry-filter breakpoint 2.4.1.0 `0x142CAA130`, RDX desc,
  pass=[+135], MSVC name@[+8]; TRACECLONE + single-step + quiet-end;
  dead on sandboxed targets — confirmed live Oct-15).
- `cmd/wotwalkdump/main.go` — walk recorder CLI (dump + optional
  `entdef` recompute/`-want` compare).
- `cmd/wotflood/main.go` — offline lobby analyzer (structure only):
  `-stream` bundle inventory + prefix salvage, `-dump -flow` chunk
  table + inventory, `-recover-key` (MITM key to keyfile, lengths
  only), `-smalls` census, `-tokens` (token-dict hunt in S>C,
  lengths/hashes only unless `-show-token`). Thin CLI, protocol in `login/`.
- `cmd/wotunpack/main.go` — packed binaries (`.def`/`.xml`, magic
  `0x62a14e45`) to readable XML on stdout.
- `cmd/wotdigest/main.go` — offline login digest per client version
  (`-version 2.4.0|2.4.1`, `-wotdefs`/`-entitydefs` overrides;
  game defs are external uncommitted siblings; prints
  computed/truth + MATCH/MISMATCH, exit 1 on mismatch).
- `cmd/wotreplay/main.go` — thin CLI (`file.wotreplay`, `-meta`,
  `-dump PREFIX` for `.stream.bin`).
- `cmd/wotverify/main.go` — genuineness CLI (structural only, see
  `../docs/REPLAY.md` §verify); exit 0/1.
- `cmd/wotevents/main.go` — thin CLI (`file.wotreplay`, `-pretty`):
  prints the battle timeline JSON.
- `cmd/wotgendata/main.go` — codegen CLI (`-item-defs DIR -out
  lobby/vehicle_data_gen.go`): static vehicle/gun/shell tables from
  unpacked item_defs; rerun + `gofmt -w` after client updates.
- `cmd/wotgarage/main.go` — codegen CLI (`-item-defs DIR -out
  lobby/garage_gen.go`): every OWN-able vehicle from the client's
  `item_defs/vehicles/<nation>/list.xml` (premium, collector, reward,
  event, variant — only the `maps_training` bots are dropped).
  `wotserver -garage-all` (or `GARAGE_ALL=1 ./start-server.sh`, or
  `./restart-server.sh`, which always passes it) seeds
  the default account's garage from it and raises `stats.slots` to
  `len(garage)+100`, because the client's capacity check is
  `getFreeSlots(stats.vehicleSlots)`. The inventory entry is the
  vehicle TYPE compact descriptor (`[1|nation<<4(+2 if typeID>255)]
  [typeID lo][typeID hi]`), not the module descriptor — the client's
  `parseVehicleCompactDescr` reads nation+typeID and builds the stock
  modules itself. It also emits `lobby.AllCrewSkinIDs` (from
  `crewSkins/crewSkins.xml`), `lobby.AllDogTagComponentIDs` (from
  `dog_tags/dog_tags.xml`), `lobby.AllTankmanGroups` (the name pools
  from `tankmen/<nation>.xml`, whose `_<id>` element names are the ids a
  tankman compact descriptor stores) and `lobby.AllEquipment` (the
  regular consumables from `vehicles/common/equipments.xml`, minus the
  `notForSale` built-ins).
- `cmd/wotbattlefeed/main.go` — offline battle-feed CLI over a
  wotproxy dump (`-dump FILE -flow SUB -keyfile F | -recover-key …`,
  `-own NAME` sets ALLY side, `-side all|ally|enemy` + `-watch SUB`
  filter SHOT rows): creation bulk → `lobby.NewObserver` (roster/
  teams/vehicles/mounts via the generated table, no XML), then
  time-ordered SHOT (+READY merge) / HIT / INCOMING (`-margin` over
  shell blast, displaced-track pad) / KILL / markers / CHAT (both
  directions, `lobby/battlechat.go`) / presence sections.
  Engine in `lobby/feed.go` (running buff calibration, drum/twin/
  dual/AR mag sim, caliber-unique tracerless marks, muzzle-history
  victims: two-sided offline `ObserveExplodeFull`, past-only live
  `ObserveExplode`), synthetic tests
  in `lobby/feed_test.go`. Streaming twin in `lobby/live.go`
  (`LiveFeed`: bulk buffering + per-packet scans + own track +
  presence, mutex-guarded; re-arms across battles — a ≥1000B S>C app
  while an observer is live is the next battle's bulk head, the old
  observer retires with its dedup maps (death counters/shot IDs
  restart per battle), lobby floods between battles close as rejected
  bulks; synthetic tests in `lobby/live_test.go`).
  Validated on Sep-29 Sweden: 132/132
  shots, 30/30 roster+guns, 31 hits (13 victims: 8 HIGH), 24/24 kills,
  0 incoming
  (correct), 4 LINK + 11 SPOT markers, 5458/19 presence — deltas vs
  the /tmp reference driver
  are live-honest only (running past-evidence calibration, no
  future-evidence backfill). The streaming path replays count-identical
  (132/31/24/98/4/11, 5458/19) via `/tmp/opencode/liveverify.go`.

## Standards (enforced, not optional)

- `gofmt -l .` empty, `go vet ./...` clean, `go test ./...` green.
- Dependencies: stdlib + `golang.org/x/crypto` (blowfish) +
  `golang.org/x/sys` (ptrace/transparent-socket syscalls, approved Sep
  27 for `keydump`/`tproxy` only). New external deps are fine when
  they carry their weight (e.g. a parsing library instead of a
  hand-rolled one), not for what a few lines of stdlib cover — say
  so in one line when adding one. Never reimplement shipped primitives (RSA,
  Blowfish block, SipHash/Cuckoo graph) — adapt library code instead.
- Secrets only via `.env` (see `.env.example`); `.env` and `live.env`
  are git-ignored. Never log username/password/token/session/
  ciphertext plaintext (lengths and hashes only). Never log replay
  contents beyond sizes/names (rosters are personal data).
- Keep `main.go` dumb; protocol in the library, unit-tested.
- Tests stay offline: no live packets in `go test` except the solver
  smoke test (gated by `testing.Short()` skip).
- Comments explain *wire why*, not *what*: byte offsets, endianness,
  and the IDA/pcap source for magic numbers (e.g. `sub_140397AE0`).
  Reply prefixes vary per packet — never assert a constant. Cite wire
  offsets/endianness and their source (pcap bytes, IDA address,
  engine file). Open guesses stay labeled as such in code AND md.
- Ping error style: sentinel errors (`ErrShort`, `ErrMalformed`,
  `ErrMismatch`) wrapped with `%w`; `PingOnce` keeps reading on all
  three (stray traffic), failing only on timeout/send errors.
- Don't commit built binaries; smoke-test via `go build -o
  /tmp/wotlogin ./cmd/wotlogin`.

## Login goal (current)

Consolidate the lobby. `Login()` returns genuine `LOGGED_ON` sessions
and `BaseAppLogin` reaches the decrypt-verified lobby flood from OUR
client as a matter of course now (Oct-03: EU2 single-shot `LOGGED_ON`
→ rotation → redirect → rotation-2 → double-auth → 1252B flood,
exit 0 — the "park" since Sep-20 was TWO stacked client bugs, not a
server gate: wrong stage-1 auth1 shape [unreliable-no-0b, corrected
to decrypt-proven reliable+0b Oct-03] plus a missing stage-2 victory
return [flood arrived, code looped till timeout — fixed Oct-03]).
Remaining: lobby application parsing is offline-only so far
(`wotflood` inventory/salvage/census + `lobbycalls.go` C>S builders
from game vectors; live client returns at the flood — speaking the
syncs back is next). Zero-byte silence at the 22B still occurs
intermittently (hits the game too — server-side flake, distinct from
the systematic park, which is closed). Falsified Sep 19, same machine/hour:
game reaches EU2 lobby; VPN exit rotation and off-VPN change nothing;
SESSION re-dump identical; `old_pass` shared with the game;
ping-first sweep (5×16 B LOW to `.215`) changes nothing.

## Login — what works (proven live, do not re-investigate)

- LoginApp handshake: framing, RSA-OAEP `LogOnParams`, Cuckoo PoW,
  challenge retry → `LOGGED_ON` + `decryptSession`. Username JSON is
  keys-SORTED + spaced (ground truth `../captures/CE.txt`),
  `temporary="0"` like the genuine client, clientContext
  `{"lang_id", "publication"}`; login#1 534 B / login#2 728 B.
- Session decrypt: `decryptLogin` (ECB + plaintext chain, NO magic).
  Record layout (`sub_140E6D3C0`/`sub_142AD3580`): ip u32 + port u16 BE
  + salt u16 + key u32 LE, then packed-string message.
- Digest strictly verified (zero → status 70). Live runs carry the
  recomputed digest (`entdef`, green since 2026-09-20).
- BaseApp: 22 B handshake bytes identical to genuine (pinned). Entry
  is TWO-stage with key ROTATION (`reply{rid,newkey}`; fork takes it,
  fails zero/unchanged). Stage-1 runs on the login socket; stage-2
  uses a fresh socket to the redirect target (`[44][ip][port]` + trailer).
  Builders pinned by `TestPairedReplay` (`../captures/flows3` +
  `../captures/key3.txt`). Channel footers are `[seq][cumul]` u32
  (`FLAG_HAS_CUMULATIVE_ACK 0x0400`); post-reply app step is
  `BaseApp.authenticate{newkey}` (`[02][key]`, FIXED-4;
  baseAppLogin=0/pingDatacenter=1/authenticate=2).
- Wire `session` is md5hex of the stored session BLOB TEXT (not the
  decrypted GUID). `SESSION=` / `-session-guid` take the BLOB text
  pass-through. The game never re-logs; `-stay` rides the basic
  session like the game.
- Error replies are plaintext packed strings: 68 bad creds, 64
  unencrypted-refused (no plaintext negotiation exists), 70 digest.
- Prefix byte 0 is cosmetic (base + parity) — never chase it.
- `hijack.go`: `SessionFromDump` derives the stage rid from the dump
  (`TestLoginRIDsHijackDump` pins it); structural validation: packed
  servermsg + zero block-pad + manager port window 32810-32999.
  `LoginSourcePort` = game's login source port from the last 534 B
  C>S line (pinned 58107 on the Sep 20 dump). `-hijack` binds stage-1
  to that port (override `-hijack-port`); game must be KILLED (bind
  fails loud if frozen).
- `../mods/` — `digest-dumper-mod` (ground-truth `BigWorld.digest`),
  `custom-server-mod` (`CUSTOM (wotproxy)` host), `session-guid-mod`
  (stored session blob + `wg_ucpdata` decryption),
  `wgc-token-mod` (live `WGC.loginData` capture for `-broker-params`,
  py2.7-compiled + installed), `garage-mod` (owned-vehicle
  inventory dump from the items cache for the tank list + 84b Int2
  vehInvID, py2.7-compiled + installed 2.4.0.2).
- Garage list via LOCAL dossier_cache (no wire needed): the
  per-account `.dat` is one cPickle doc `(version24, {322 IntCD
  blocks})` decodable with the existing hand-rolled decoder;
  dossier keys are `[2, IntCD]`, `IntCD=(id<<8)+type+(nation<<4)`
  (`items/__init__.pyc`), id==0 = nation aggregates, the rest
  resolve through `lobby/vehicle tables` → 294 tanks Oct-03
  (dossier accumulates history incl. sold tanks; 32 special/removed
  ids fail loud against 2.4.0.2 defs). LIVE garage via `garage-mod`
  (in-hangar items cache, Oct-03): 113 currently-owned tanks with
  live invIDs (`/tmp/opencode/garage.txt`: nation/name + #invID
  each). NOTE: dossier keys are vehTYPE IntCDs, live invIDs are instance IDs — the 225 Int2 call
  takes the latter, so 324 needs the mod's invIDs, not dossier
  keys. 4/117 live descrs reference vehicles absent from shipped
  defs (kept as raw bytes).
- `../captures/` — genuine traffic, indexed in `../captures/README.md`.

## Login — former blockades (all closed)

1. CLOSED Oct-03 — p2/EU2 silence at the 22B. The "park" was TWO
   stacked client bugs, not a server gate: a wrong stage-1 auth1 shape
   (unreliable-no-0b, corrected to the decrypt-proven reliable+0b) and
   a missing stage-2 victory return (the flood arrived, the code
   looped until timeout). EU2 now logs in single-shot: `LOGGED_ON` →
   rotation → redirect → rotation-2 → double-auth → 1252B flood,
   exit 0. The falsification record below is kept as history; its
   "server-side gate" verdicts are superseded.
   Falsified as gates, live: token2 machine family
   (`token2-family-match=true`), `lang_id` fr, reported PoW duration,
   VPN exit/path (rotation + off-VPN), SESSION staleness (re-dump
   identical), credential freshness (same `old_pass` as the game),
   login-reply content (`flows3` S232 + `key3.txt` decrypt: same keys,
   same values shape), login params from the REAL .pyc (uncompyle6:
   launcherless path sends our exact keys; `-Decompiled` tree is not
   the shipped build — cite the .pyc), stage-1 socket identity (game does login-socket
   and fresh-socket across runs), manager knock, ping-first sweep,
   first-packet delay (`-baseapp-delay 10s` still silent: push absent,
   not slow), delay sweep (0.3–6 s, all silent — no timing window),
    username key order (genuine hash order now, silent still),
    temporary (live game.log Sep-19: `temporary='1'`, remember_user=None;
    CE.txt's "0" is stale — default flipped to "1", silent still),
    self-throttle (game fine right after our hammers). (p5
    unblocked by the ack0 cumul fix; lobby reached 2×.)
    H1 instance-lottery FALSIFIED Sep 20: `login.p2` = 3 IPs
    (.212/.213/.215), we take DNS-first (.212), the game used .215 —
    swept all three literals with fresh logins + 60 s stage-1 each:
    3/3 LOGGED_ON first-class, 3/3 silent (75 attempts each, .215 run
    assigned `.215:32925`). Same instance as the game, opposite fate:
    the discriminator is per-session content, not the LoginApp.
    H3 232B-content FALSIFIED Sep 20 (throwaway in-package decrypt,
    deleted after): genuine `flows3` S232 (`key3.txt`) vs our live
    `.215` 232B — identical key sets, `old_pass`, same-family token2
    (69 chars both), 32-char session_id same shape, login#1/#2
    534/728 B same heads, PoW 42 nonces both. Reply content is
    indistinguishable. Token2 `-relogin` now SUCCEEDS (session-blob    pass-through fixed the family) → `RELOGGED .215:32819` — stage-1
    on the token2 session silent too (75 attempts): auth path is not
    the gate either. Off-VPN RE-falsified post-hammer Sep 20 (ISP
    exit, fresh IP, 32 attempts, silent): not a source-IP block.
    Gap inventory (`flows4`, Sep 18 game): in [232B, +3 ms] the game
    sends NOTHING but the stage-1 22B (no precursor/ack/side-channel).
    Key-equality verified on the paired capture (`flows3`+`key3.txt`):
    genuine 22B carries `0x69668ba0` = its 232B sessionKey — the game
    sends exactly what its 232B says, like we do. Net: our observable
    behavior is fully equivalent; the record for our key is absent
    (push never happens for our sessions) or instantly unusable.
    IDA hunt Sep 20 (session `befbfbd0`, still open): login path fully
    verified — caller passes flags=1 explicitly (`mov r8b,1` @
    `0x140E6C6E4`, stored-flags=1 unused), version `{5,0,1,17}`,
    layout flags+4 strings+digest+nonce, challenge-response
    ID=3/f32-duration/key/42-nonces, port default 20013, DF via
    setsockopt(IP,14); `flow12` proves the game sends NOTHING to
    LoginApp after its 232B. No client-side divergence left.
    L3/L4 mimicry FALSIFIED Sep 20: full-packet diff showed ours
    TTL=64/DF=1 vs game TTL=128/DF=0 — resent stage-1 with TTL 128 +
    DF 0 on an IPv4 socket (throwaway `winShape`, reverted): still
    silent. 232B trailing bytes: none (199B JSON + 4 zero pad).
    p5 VALIDATES keys (random-key 22B ×3 silent on a live p5 endpoint):
    our session keys are globally well-formed; EU2's miss is local.
    Parser probe Sep 20 (fresh login, valid + 10 malformed 22Bs, one
    packet each): zero bytes to everything. Seven distinct manager
    ports silent in one day (.215 ×5, .212 ×2 — game-proven family):
    app-level drop, not dead ports.
    Concurrency/linger DEAD (dual-boot + operator: game never open
    during wotlogin runs). Elimination state: day-one silence (Sep 17,
    zero history) kills all self-inflicted theories (throttle, block,
    flag-by-our-actions); kind-identity (bytes/params/timing/headers,
    audited live) kills all content theories; negative-caching cannot
    explain first-attempt silence (fresh keys per login) and every
    stable key is shared with the working game. Remainder: environment
    (stack micro-headers tested TTL/DF; IPID sequencing untestable
    without caps) and LoginApp-push internals (unobservable).
    Token chapter CLOSED Sep 20 (live launcher login captured+decrypted:
    `.215:32845`, token2 middle `5220…` (WGC family) vs basic `4957…`;
    the live WGC tail re-presented 10 min later → `Invalid token2` on
    BOTH .215 and .212: tails are single-use/short-lived, and validity
    is irrelevant to the push — our fresh-valid-token session was
    silent too).
    Oct-01 `-relogin -baseapp` live (p2, our client): basic (534/728,
    PoW 42 nonces, ~85 ms) → LOGGED_ON `.215:32821` → reply token2
    middle `123456789:495…` (basic family, family-match=false) →
    from-zero token2 login (325B params, empty password) → RELOGGED
    same manager, new key — BOTH legs first-class. Stage-1 on the
    token2 session: rotation-ok, 250+ ticks, cumul=0, no redirect →
    PARK. Auth path is not the gate (token2 session parks identically);
    the park was the client-side auth1/victory-return pair (CLOSED
    Oct-03, item 1). security_msg="old_pass",
    isDemoAccount=false.
    Same passage via `-host login.p5.worldoftanks.eu`: basic + token2
    relogin both first-class → RELOGGED `.215:32817` (p5 login still
    lands on EU2 metal) → stage-1 rotation-ok then park (250+ ticks,
    cumul=0, no redirect). p5 is not an escape either right now.
    Sep-29 sampler (3 login-only runs, fixed SESSION, temporary
    0/1/0 → identical middle): temporary ruled out, middle is
    session-only; naive f(sessionmd5) forms (u64 halves mod
    10^19/10^18) miss on the single pair — exact function needs
    fresh-SESSION pair variety.
    Broker path MAPPED Sep 28 (Steam): the game carries no WGC login —
    `wgcs_api.dll` (flat `binding_*` exports, IID `0x1600020001247C`)
    talks over `\\.\pipe\WgIpcPipe` IPC to wgc.exe (GameCenter for
    Steam, in-prefix `ProgramData/…`, starts with the game session):
    `LoadSpaToken2` at login, `SaveSpaToken2(spaId)` after LOGGED_ON
    (wgc_* broker logs prove both, timestamps match the game's
    `Token2 Login Prepared`). Game-side API surface RE'd
    (18 WGC methods, vtable slots, COM IID — see `wgcs/wgcs.go`);
    `wotwgcs` (GOOS=windows, proton-run) mints broker token2 with zero
    LoginApp traffic from us. Out-of-process minting CLOSED Oct-02
    (per-process sessions: 0x80EE1003 with the game in hangar).
    Verbatim-replay path FIRED Oct-02 (CLOSED): live 9-key broker
    loginData via `mods/wgc-token-mod` → `wotlogin -broker-params
    -baseapp` → `LOGGED_ON` (fresh tail accepted) → stage-1 parked
    byte-identically to basic. Auth path is not the gate (see
    `../docs/WGC.md` §8); the park was client-side (CLOSED Oct-03).
    Remember-me mechanism MAPPED Sep 20 (2.4.0.1 Manager.pyc):
    tail persisted to prefs['token2'] IFF remember-me checked
    (password never stored, only its length); next login presents the
    tail (token2-login, password field bogus); each link consumes the
    previous     (single-use-forward). OPEN TEST: chained (non-bootstrap)
    tail → our stage-1 (needs operator: check remember-me, log in,
    quit cleanly WITHOUT re-login, hand over prefs['token2'] fast;
    costs one password retype after (our use consumes the head).
    Exact-5-key relogin CLOSED Sep 20 (`{login,token2,session,temporary,
    auth_method}`, no publication/auth_realm per initiateRelogin):
    RELOGGED accepted, stage-1 silent — form doesn't matter either.
    Sep-20 CLIENT CORRECTNESS PROOF (p5, live): basic → rotation → infos → redirect → stage-2 double-auth → decrypt-verified 1252B lobby flood, all from our builders (turn-taking proves each step accepted). Same binary stays silent on EU2: the wall is purely server-side record-absence, not our script. p5-limbo earlier was transient server flake (hits the game too).
    Sep-20 MECHANISM PROOF (intervention, not correlation): forcing our
    wire session to today's value (`3ce6…`) flipped our token2 middle
    `495…`→`694…` (the game's current family) — LoginApp binds
    session→token2-middle deterministically and fully recognized our
    session, yet stage-1 stayed silent. Recognition ≠ push; the gate
    is downstream of session recognition. TCP connects on a manager
    ephemeral port (host alive; with UDP delivery proven, the silence
    is app-level).
   LoginApp path proven first-class Sep 19: `wotlogin` LOGGED_ON
   registers account-side (website-visible; probe 12:21:32 listed).
   Back-to-back byte proof
   (`captures/ours-p2-20260919.pcapng`): our stage-1 22B
   field-identical to the game's — the silence was never bytes. The
   push-routing probe now EXISTS: `-hijack DUMP`
   (Sep 19) runs stage-1 with the GAME's live session (wotproxy dump +
   `BLOCK_KEY_HEX` CE key; 14.4 sources re-read: pending record is
   created synchronously with key minting and stock login never checks
   srcAddr, so reply = our records are what's broken, silence = a
    WoT-side endpoint gate; 30 s window from the game's LOGGED_ON,
    CE-pause the game pre-22B). Sep 19 outcome: probe 25× silent with
    the game's live key, game resumed at T+20 s → hangar — BUT the
    probe sent rid `0x96ac…` instead of `login#2rid+1` (91401): void
   test. Fixed (`SessionFromDump` derives the stage rid from the
   dump, `TestLoginRIDsHijackDump` pins it). REDO DONE Sep 20
   (`../captures/dump_game_20260920.txt` + `../ce/wotkeys_20260920.txt`
   → `../captures/hijack_live_20260920.log`): offline re-derivation
   from the same dump gives baseapp `92.223.20.212:32847` + sessionKey
   match (CE key `7A546C3F7EDE2232F1EC7720F63845AB`) + stageRID 33713 = login#2+1 (VALID), and stage-1 stayed
   silent all 25 attempts anyway.    PORT-STEAL redo same day (game
   KILLED, `-hijack-port` auto-steal `:50935`, stageRID 76138):
   113× silent over 90 s (`../captures/hijack_portsteal_20260920.log`)
   — BUT started ~83 s after the 232B, past the ~30 s pending
   expiry: VOID on timing. KILL-MODE redo (`../ce/hijack_trigger.lua`
   MODE="kill": auto-kill+fire same second as the 232B, bind
   `:56370`, stageRID 22155, `../captures/hijack_kill_20260920.log`):
   25× silent over 20 s, all in-window. VERDICT AT THE TIME: a
   server-side session gate. SUPERSEDED Oct-03 — the park was two
   client bugs (item 1), and the probe's silence was our own auth1
   shape. Launcher ruled out — the game runs launcherless here.
2. Offline digest CLOSED Sep 20 (`TestComputeDigestMatchesClient` green).
   Full client map recomputed byte-identically (`5df886f7…`): spaces +
   40 entities + static-component merge + 10 mode entities + 281
   dynamics (`ComputeDigestFull`, defs in external `../wotdefs-2.4.0/`).
   Proven visit-for-visit by `ce/walkprobe.lua` (1242 visits),
   `ce/walkprobe2.lua` (flags/volatile), `ce/r8probe.lua` (2625 type
   tags in order), `ce/walkprobe3.lua` (entry names),
   `ce/walkfinal.lua` (entry pass/fail + gate85/varlen/descs); runs
   archived in `ce/`. Live logins carry the recomputed digest.
   2.4.1.0 truth `c0cc08a2…` (digest-dumper, probe-verified 68 Oct-15;
   `live.env` updated). Offline recompute OPEN: 2.4.1.0 defs extracted
   from `res/packages/scripts.pkg` (stock ZIP; +11 mode pkgs; white_tiger/
   fall_tanks gone from disk) walk to 310 entries (−28 WT/FT +6 new:
   respawn framework ×4, SpecBoost, StateMachineNetworkSync; all 14
   fail-list entries present; 299 shared entries byte-identical, 5 drift:
   Avatar/Account/StaticDeathZoneVisual/VehicleRespawnComponent/
   SMVehicleRespawnComponent) but hash to `941eba52…` (status 70).
   Ruled out: fail-set singles (all ±1), missing pkgs (absent from
   disk too), spaces/interfaces/order (same code paths), manifest
   enablement. Next: walkfinal re-run on 2.4.1.0 (runtime fail-set) or a
   new silent-drop construct in the 5 drifted entries.
   Update Oct-15 (still OPEN): IDA proved the digest algorithm
   version-invariant (FIXED_DICT visitor pseudo-diff + meth/prop/varlen/
   entry-filter diffs, all identical incl. the conditional
   moduleName/instanceName gate) — `implementedBy` (`true_dict.instance`
   on RespawnFrameworkVehicleComponent/FortRushScoreComponent) is now
   hashed raw/raw in `entdef` (no-op on 2.4.0). Membership brute-forced
   to exhaustion (singles, all pairs, triples, 4.6M quads, 8.9M quints,
   fail inclusions, group wipes, orders, prefixes/suffixes/ranges).
   Fail rule discovered (live `sys.modules` + full `.pyc` census):
   component walked ⟺ client `.pyc` exists (14/14 fails lack one; proven
   on 2.4.0 scripts scope: exactly ExtendedSPG/
   EnemyShotPredictorController/ArenaVehiclesInfo lack it) → 4 new
   2.4.1.0 fails (HWArenaDrop/VehicleRemoval/PhaseProgression/
   SpawnInfo, all `ofEntity Arena` orphans) giving `cb361e6a…`
   (probe-verified 70, well-formed). Remainder unknown. Tools:
   `cmd/wotwalkdump` (ptrace walk recorder — dead on sandboxed Steam
   targets, use the mod route) + `mods/walkset-dumper-mod`
   (`sys.modules`/`dir(BigWorld)`/`PyEntities` dumper, py2.7).
   Import-probe (live, 403 names test-imported): ok=385 fail=18, exactly
   the 14 + 4 HW — walk SET closed. Membership×order cross (pairs under
   all 24 group orders, 1.8M) also miss. Brute force over.
   Live walkdump NEVER FIRES (multiple full launch→hangar sessions,
   armed from spawn): 0x142CAA130 uncalled yet BigWorld.digest present
   ⇒ the game gets its digest without walking (def-cache? launcher?).
   Def-category census: only entity/component/space/alias dirs hashed;
   arena_defs are .xml, user_data_object_defs skipped in both versions.
   Update Oct-15 (external, version-agnostic, still OPEN): 2.4.1 defs
   kept as uncommitted siblings `../wotdefs-2.4.1/` (components/extensions/
   mode_entities/space_defs, 19 mode pkgs incl. halloween-part1+2 and
   fort_rush) + `../scripts-2.4.1/` (entities.xml + entity_defs,
   from live scripts.pkg); `TestComputeDigest241Offline` green at the
   truth `c0cc08a2…` (offline, deterministic — CLOSED Oct-31, see below).
   Shared-entry audit on the external trees: 304 shared, 297
   identical, 7 diff (Avatar handleScriptEvent 5→4 STRING, Account
   requiredVersion_2400→2410, StaticDeathZoneVisual +isCircular/
   customBorder, VehicleRespawn +isDisabledEffect, SMVehicleRespawn
   +isDisabledEffect via parent, Vehicle/SimulatedVehicle via alias
   publicInfo.index UINT8→UINT16; ConcentrationMode type rename is
   alias-neutral). IDA 2.4.1 proof (live DBs): FIXED_DICT visitor
   `0x142CC25F0` byte-identical to 2.4.0 `0x142AB3A30` (82 insns,
   same +0x60 raw-string slot for moduleName/instanceName with labels
   ignored; `qword_143B10958` = "moduleName"), entry filter
   `0x142CAA130` checks `[RDX+0x87]` like 2.4.0 — algorithm
   version-invariant, impl raw/raw correct. Re-proved on external
   403: singles both directions miss, HW/fort/respawn block moves
   miss, impl 21 single + 441 mixed + 84 per-site-gate miss, pairs
   (73,920 extra-skip + 153 include) miss, swap-pairs + 2in-1out miss,
   single moves (147,840) + swaps + true-pkg-block/superblock moves +
   section permutations + pkg wipes 1–3 miss, new-triples (156,849) +
   new-quads (3.76M) miss, fail include-triples→sextuples miss,
   joint singles/pairs/triples × 22 impl encodings miss, component
   parent same-domain method order variants miss, duplicate aliases
   byte-identical, user-data defs structurally excluded (no Flags).
   Defs verified byte-identical to live #974 pkgs (549 files +
   manifests). Sextuples over 99 new entries (1.1B) MISS (Oct-16,
   7573 s). Content-subtlety hunt Oct-16 (all miss): full hashed-field
   audit (exactly 7 byte-diff shared entries, all explained; every
   241 type/flag/varlen/allowNone/impl construct has byte-identical
   240 precedent), DatabaseLength ×6 neutral (Login bytes identical),
   bare <Volatile/> ×6 childless neutral, alias drift = 3×
   UINT8→UINT16 + 1 neutral rename + 1 unreferenced removal, no
   cross-pkg name collisions, no static-static dups, zero overrides
   in new parent chains, visit drop-1 (1141) + drop-2 (650k) + bounded
   add-1 (696) + dup-entry + name-only fails + 208 trailers/prepends
   miss, joints skip1×drop1 + include1×drop1 + visits×22impl miss,
   dynamics alpha/antialpha miss, fail include singles→quads miss
   (18/153/816/3060), per-site impl 441 mixed now genuinely verified
   (was only global-22 + gate-42 in-tree) + mixed×skip-singles
   (169,785) miss, extra-skip triples over all walked (9.4M) miss,
   2in-2out swaps (11.3M) miss. Drop-three visits (239M): DIED
   overnight Oct-16 (started 01:02, process gone by 12:18, log shows
   only the startup line — no MATCH, no completion; untested).
   Stood down + zz scratch deleted Oct-16 per protocol (suite green).
   Decisive next: live 2.4.1 walk via ce/walkfinal_241.lua
   (operator; probe static-verified Oct-16 in IDA on 2.4.1.0 — RVAs
   land on the right visitor slots, all field offsets re-confirmed,
   SizeOfImage gate = PE value; script now ALSO arms the r8 type-tag
   helper, pattern-verified unique at sub_1403DAE20 — one run yields
   walk + tag streams). IDA Oct-16: top driver sub_142CAA020, map
   thunk sub_142CA9E80, entity walk sub_142CA1E90 are byte-equivalent
   to 2.4.0 (unwind metadata only; write order identical) and the
   member prelude sub_142ABC050 (2.4.0) == sub_142CCAC10 (2.4.1) is
   instruction-identical too — gate [desc+0x55], streamSize()<0, then
   `mov r8d,[desc+0x58]; cmp 1; jz` and writer slot +0x40 gets the
   "varLenHeaderSize" label + r8d=varLen (IDA's decompile elides that
   third arg) — the algorithm is provably version-invariant, so the
   delta is in data
   the visitor sees. Comparator ready: paste the capture as
   ce/walkfinal_241_RUN.txt, run `go test ./entdef -run Walk241 -v`:
   diff241 checks entries/order/pass/visits (idx/flags/vol) AND the
   conditional varLen-u32 hash inputs (prop gate85+flags, meth
   gate85/varlen vs the model's memberMD5 condition),
   TestWalk241DigestFromObserved recomputes the digest with the
   OBSERVED pass-set (closes the gap if membership was the delta),
   TestWalk241TagsFromObserved aligns the r8 tags vs putTag emission
   (TypeTagRecorder hook; the tag path is pinned exact by
   TestR8TagsMatchOracle240 — 2625/2625 vs the archived 2.4.0 r8 run;
   a model census shows 2.4.1 emits 2724 tags over the same 10 class
   names, no new datatype class, so the live tag diff is a
   count/order test, not a class-coverage one).
   Ceiling of the probes: type-tree numbers
   (allowNone/dbLen/int sizes) stay offline-only — but those are
   byte-identical-to-240 constructs per the audit above.
   Follow-ups miss: include-quints/sextuples among 18 fails, true-pkg
   block moves, superblock pairs/triples, section permutations (120),
   alpha sorts, global transforms, rotations, filesystem readdir/mtime
   pkg orders, per-pkg alpha/reverse, entity/mode-entity alpha,
   halloween part1/part2 groupings, per-site impl gating, FullIndex
   zero dup/gap both versions, bool-tag cases all lowercase.

   Update Oct-16 (static closure round): model inputs verified
   byte-identical against the LIVE Steam install
   (~/.local/share/Steam/steamapps/common/World of Tanks/eu,
   2.4.1.0): scripts.pkg (11600 entries, all under scripts/) +
   all 19 feature pkgs — every extension.xml SAME (19 total across
   all 229 pkgs; halloween/extension.xml lives in part1, part2 is
   defs-only; last_stand_hd art-only), entities.xml/components.xml
   SAME, all 131 scripts component_defs SAME, all per-feature
   component defs SAME, all 12 mode-entity defs SAME, interfaces/
   + alias.xml SAME, live spaces.xml = <GeneralSpaceData/>.
   Orchestrator (2.4.1 sub_142CA72A0, full dump) decoded: spaces →
   CSE-40 via ECS(true) [always pass] → per-pkg entities via
   ECS(true) [always pass] → SOE via ECS(false) [noop: entities.xml
   has no SOE section] → old-style sub_142CA8630 [SKIPPED when
   ClientServerEntities present] → scripts dynamics via
   HasScriptOrTag(empty→"scripts/client") → per-pkg dynamics via
   HasScriptOrTag(node string); spaces decider canBeOnClient is a
   `return 1` stub; per-side loader a5=0/1 selects
   CSE+ECS(true)/SOE+ECS(false). Consequence: entities are NEVER
   .pyc-gated — Login (no scripts/client/Login.pyc in EITHER
   version, only client_common/Login.pyc) still passes, in both.
   Merged live top-level client modules (scripts.pkg 239 +
   per-feature dirs = 523 names) cover all 385 model-pass names
   except Login (explained); game.log Oct-15 ProbeWalk replays
   385/18 stable over 7 runs; res_mods/ clean (gui mods only).
   Model proven deterministic cross-version (zz_perentry: 290
   shared ENTRY identical, exactly the 7 audited diffs differ) and
   parse-complete (zz_struct × def cross-check: 403 entries, 22
   flags all nesting artifacts — <Exposed/>, nested <Default/>,
   <ReturnValues>). Exhaustive construct census: no new tag/attr/
   attr-value in 241 (only 3 harmless leaf values: eu_2.4.1,
   <default>TRUE</default> (defaults ignored both sides),
   <index>INT32</index> (method arg name)); named method args have
   34-method 240 precedent; <Parent> has 240 precedent
   (FallTanks/SM→VehicleRespawn); FIXED_DICT+AllowNone 94 in both;
   SMVehicleRespawn drift is knock-on via parent. ImplEncoding
   global sweep 0-20,99 + cleared all miss (cb361e6a best);
   consistent with prior mixed-441 miss. implementedBy fully decoded
   (Oct-16, live .i64): FixedDictMetaDataType::getType reads the
   element, splits at last '.', calls setCustomClassImplementor
   (sub_142CC6550) which imports the module + getattr (true_dict
   .instance — attr EXISTS, resolves) for per-object serialization
   callbacks (createObjFromDict/isSameType/addToStream/
   createFromStream at +192); digest hasher (sub_142CC25F0) hashes
   the RAW stored halves in every branch (module-missing resets
   +184→hash; attr-missing skips — both byte-forms swept). NOT the
   delta. Build identity closed: live truth-producing exe sha1
   be3263143bb37dd96aafa7db9d6a2c9bafc5a853 == repo 2.4.1.0 exe
   (82,163,376 B both) — analysis binary == truth binary. Static now
   exhausted at every stage (inputs/membership/order/hash/parse/
   determinism/implt); IDA workers re-verified driver identical
   (repo .i64 saved). Drop-three grind DIED overnight
   Oct-16 (no result; see above) — stood down, zz scratch deleted,
   suite re-verified green.
   **CLOSED Oct-31** — the live walk was captured on Linux/Proton via
   Frida (`tools/frida-inject/`, replacing the Windows CE route) and
   the delta was a *parser* bug, not a data one: `parseModeDefShared`
   followed a mode def's `<Parent>` only one level, so
   `HWPersonalDeathZone` → `PersonalDeathZone` → `AreaOfEffect` stopped
   at the middle link and contributed 0 visits instead of 6 (5 props +
   `playEffect`). Walking the chain to the root gives 403 entries /
   1315 visits, an exact visit-for-visit match, and
   `TestComputeDigest241Offline` now yields the truth `c0cc08a2…`.
   Remaining open item: `TestWalk241TagsFromObserved` diverges at tag
   #2048 (was #1337) — the model omits the `Uint` tag for
   `STANCE_DANCE_STATE.state` (UINT8) inside
   `StanceDanceController.abilityState`; digest-neutral.

## Battle — the gun and dynamic components (proven live, do not re-derive)

Detail in `../docs/PRIVATE_SERVER.md` ("The gun", "Dynamic components",
"A throw in `Avatar.setClientReady`"); the id table is
`../docs/ENTITY_TYPE_IDS.md`.

- **The gun is driven by the `OwnVehicle` component, not by the
  `Avatar.updateTargetingInfo` element.** `VehicleGunRotator` needs
  `isOnArena` AND `__speedsInitialized`; the latter is set only in
  `update()`, whose only caller is `Avatar.updateTargetingInfo`. That
  method's def says nine FLOAT32 (36 B) and the client's table agrees,
  but its Python takes the entity id plus ten floats — so 36 B raises
  `TypeError` and 44 B corrupts the packet. The live path is
  `OwnVehicle.targetingInfo`, whose setter
  (`OwnVehicleBase.update_targetingInfo`) supplies the id itself.
- **NRL component type id = index in the client's `EntityType` table**
  (entities 0..52, then `scripts/components.xml` order): `OwnVehicle`
  53, `InAoEZone` 54, `AvatarVehiclesInfo` 126. 50 is `HWDeathZone`.
- **Child list = properties, then client methods, then a trailing
  child** (`OwnVehicle`: 23 + 11 + 1 = 35). Method children carry their
  exposed id as a packed u24.
- **Properties are read size-sorted, not in declaration order** (fixed
  ascending, then variable in declaration order). `syncVehicleAttrs` is
  `OwnVehicle`'s only fixed-size property, so it leads.
- **`ARENA_PERIOD.BATTLE` is 3, not 2** (`IDLE 0, WAITING 1, PREBATTLE 2,
  BATTLE 3, AFTERBATTLE 4`). Announcing 2 leaves the client in PREBATTLE
  with `isOnArena` False, and `Avatar.moveVehicle` then returns before it
  sends `vehicle_moveWith` — the tank does not drive and nothing on the wire
  says why. `ClientArena` fires `onPeriodChange` on a *change*, so the server
  sends PREBATTLE at entry and BATTLE after the delay, repeated
  (`arenaPeriodDelays`) because a BATTLE that lands before
  `Avatar.setClientReady` is dropped. **The announcement must mint its seq
  under `st.sendMu`** (`nextSeq` + `sendReliableLocked`): reading `postSeq`
  and letting `sendReliable` take the lock afterwards races the 100 ms ticker
  and the client drops the packet as a duplicate.
- **Turret rotation speeds come from the item defs** (`login/vehiclespec.go`:
  turret `rotationSpeed` under `turrets0/<Turret>`, gun in
  `components/guns.xml`), and the server steps its own yaw at the turret's rate
  (`trackTurret`) so the gun marker it reports is the angle the client is
  settling on. **`vehicle_stopTrackingWithGun` is an Avatar cell method** — its
  entity id is the Avatar's, and dropping it left the server re-deriving the
  bearing from a world point the client had stopped updating, so the turret
  swung away from the settled angle as soon as the hull turned and the client
  snapped back: the jitter. The reported angles are adopted verbatim and
  `aimSet` cleared.
- **The gun's AIMING rides the NRL marker (`0x28`); `gunAnglesPacked` is a
  bare `0xb4` element.** The captured server sends no `0x19`-led and no
  `0x4b`-led datagrams, but it does send property updates — as **bare
  elements**, `entityPropertyBase + index` + value with no length and no
  wrapper: `0xba` the Avatar's `ownVehicleAuxPhysicsData` (8 B), `0xb4` the
  Vehicle's `gunAnglesPacked` (2 B), `0xb6` its `engineMode` (2 B). Every tick
  datagram ends in `0x28` `NRL_UNRELIABLE_MSG_TO_CLIENT` carrying
  `shot_position`,
  `shot_velocity` (barrel direction × shell muzzle velocity) and
  `dispersion_angle`, which `Avatar.updateGunMarker` hands to
  `VehicleGunRotator.setShotPosition`. `login/nrl.go` has the framing and the
  constants; `docs/PRIVATE_SERVER.md` "The gun marker: NRL element `0x28`" has
  the field-by-field decode. `0x13` TickSync's byte is the LOW BYTE of the same
  10 Hz counter the marker carries in full. The dispersion is the client's own
  model (`Avatar.getOwnVehicleShotDispersionAngle`), read from the defs'
  `shotDispersionRadius`/`aimingTime`/`shotDispersionFactors`.
- **`Avatar.ownVehicleAuxPhysicsData` zero is not level** — it unpacks to
  `(-pi, -pi/2, -pi)`, tilting the stabilised matrix 90 degrees about X so
  the turret only ever hits its limits. Send
  `WoT.packAuxVehiclePhysicsData(0,0,0,0,0,0)` = `0x55558004004000` as an
  `updateEntity` on the Avatar before the vehicle starts.
- **`OwnVehicle.fixAngles` must be `None`**, not its zero value: the zero
  is a dict of two zero floats, which is truthy, so
  `update_fixAngles` calls `fixShotPosition(0, 0)` and pins the turret.
- **Driving**: the client sends `Avatar.vehicle_moveWith(flags)` (cell 2,
  element `0x12`); the server simulates the hull (`login/drive.go`) and
  streams it. The Vehicle needs a real AoI alias (`VehicleAlias` 1) and
  `AvatarUpdateAliasDetailed` (0x1D) carries the position **outright**, not
  relative to the `RelativePosition` reference.
- **Every tick bundle opens with `TickSync`** (element `0x13`, one byte),
  as the reference's `write_tick` does. Without it the client's witness does
  not know a tick has arrived and applies the position updates in bursts —
  the tank sat still for seconds and then jumped twenty metres, which reads
  as "it does not drive" while the server had it at full speed. With it the
  same stream drives smoothly (10 m/s forward, 33 deg/s rotating, sampled
  every 500 ms with no jumps).
- **The tick rides the RELIABLE stream, and the reliable channel must stay
  EMPTY.** The captured server sends one datagram per tick, `fl=0x0458`
  (ON|RELIABLE|SEQ|CUMUL) in 7582 of 7702 cases and `fl=0x1448` in 109. Its
  shape is `0x13` TickSync, `0x16` RelativePosition metre-rounded, `0x1e`
  PlayerDetailed at zero from it, `0x1d` AliasDetailed with the vehicle's
  absolute floats, ~20× `0x35` packed alias updates for the other tanks, then
  `0x28` the gun marker. Its property updates are bare elements, not a bundle:
  `1a` SelectPlayerEntity + `ba` aux, then `16`/`1e`/`1d`, then `b4`/`b6` on
  the alias `0x1d` just selected. **The order is load-bearing** — a bare
  element applies to whatever the last selection element named, so the aux
  must precede `0x1d` and the Vehicle's two must follow it. Walking the whole
  capture with that state machine: `0xba` lands on the Avatar 5052× and never
  on the Vehicle, `0xb4`/`0xb6`/`0xa8` on the Vehicle 16477/2793/2122× and
  never on the Avatar. `Vehicle.engineMode` is `Tuple[2]{UINT8}` (byte 0 mode
  1/2/3, byte 1 the movement flags; capture values `0x0001`, `0x0102`,
  `0x0103`), and `VehicleAppearance.changeEngineMode` feeds `mode[0]` to
  `DetailedEngineState.mode`. That only works because nothing else is on the
  reliable channel. Ours used to add a property bundle (`engineMode`,
  `ownVehicleAuxPhysicsData`, `ownVehicleGear`, `gunAnglesPacked`) every tick
  and the positions queued behind it: measured on the same tank, **3.10 Hz with
  200/300/2700 ms gaps** against **9.86 Hz with 104 ms p50 and 106 ms max** once
  the bundle was gone. The bundle is gone; the unreliable form survives only as
  a deep-backlog fallback (`arenaTickReliableBacklog`), and it needs its OWN
  sequence counter (`clientState.unrelSeq`, from 1) plus the aux word
  (`auxFor(reliableSends)`); reusing the reliable seq makes it jump by however
  many reliable sends happened in between and the client discards the packet.
- **The engine sound works (CLOSED Nov-07).** It was silent while the
  `OwnVehicle.siegeStateStatus` NRL write was corrupting the component — the
  same write that destroyed every module when siege mode was switched off — and
  while `Vehicle.wheelsScroll` was mis-framed and the client discarded the whole
  tick bundle on `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`, so no aux word
  arrived at all. Both are fixed and the audition plays and follows the RPM. The
  2026-11-06 probe table that concluded "the break is inside `VehicleAudition`'s
  start path" was taken while the component was corrupted, so it does not hold;
  it is kept as history in `docs/PRIVATE_SERVER.md` "The engine sound".
- **`achievements20_config` must be in the settings document.** Its
  `getRequiredCountOfBattles` is `self._config.get('requiredCountOfBattles')`
  with **no default**, and `notifications_utils._NotificationNewSummaryPage.req`
  subtracts it from an int every lobby tick — absent, the client throws
  `TypeError: unsupported operand type(s) for -: 'NoneType' and 'int'` ~3×/s and
  the hangar locks up (measured: applying an ammo loadout left the client unable
  to exit). `TestSettingsDocumentLoads` now requires the key.
- **Leaving a battle used to kick you to the login screen.** `leaveArena` →
  `resetEntities` → `enableEntities` → `enterAccount(withCreate=true)` sends
  `CreateBasePlayer` then the `1a/76` session dict, and the dict was going out
  **bare**. Every other stage-2 datagram carries a `0x13` head (`answerApp`
  prepends `EncodeTickSync(0)`, `serveBulk` uses `EncodeTickSync(0x40)` for the
  same small on a fresh login). Without it the client ACKs `CreateBasePlayer`
  and never ACKs the dict, the server resends that seq forever, and the client
  logs `REASON_GENERAL_NETWORK` ×6 then `HANGAR LOADING STATE: DISCONNECTED`.
  Fixed by prepending the head; `TestEnterAccountSendsTheSequence` pins it.
- **Siege mode (X) works.** The client sends
  `Avatar.vehicle_changeSetting(VEHICLE_SETTING.SIEGE_MODE_ENABLED=3, enable)` —
  cell index 12, `UINT8` code + `INT32` value, fixed 5 bytes. The reply is
  `Vehicle.siegeState` (property 4, bare `0xab`), which
  `Avatar.__isOwnVehicleSwitchingSiegeMode` reads to block shooting mid-switch
  and `Vehicle.set_siegeState` feeds to the prebattle panel. Switch times come
  from the vehicle's `siege_mode/switchOnTime`/`switchOffTime`; they are 0 on
  the wheeled French tanks, so the end state goes out directly (a SWITCHING
  state with `timeLeft` 0 would leave the gun blocked).
  `OwnVehicle.siegeStateStatus` (index 10) is **required**, not optional: it is
  the only route to `Avatar.updateSiegeStateStatus`, which is not a def method.
  Measured live with only `Vehicle.siegeState` sent, `Vehicle.siegeState` read 2
  while `SiegeModeControl.__currentState` was still 0 — so the HUD never showed
  siege, the composite descriptor never switched to `VEHICLE_MODE.SIEGE`, and
  pressing X could only ever ask to ENABLE. It rides the NRL node update like
  the reload. See `docs/PRIVATE_SERVER.md` "Siege mode (the X key)".
- **The handbrake is `MOVEMENT_FLAGS.BLOCK_TRACKS` (64)** in the same
  `cell.vehicle_moveWith` flag byte as forward/back/turn — the client's space
  bar is `CMD_BLOCK_TRACKS`, which `Avatar.moveVehicle` folds in. `hull.step`
  keeps the hull's velocity in world space and drops the tracks' lateral grip
  while the bit is set, so the steering turns the hull under the velocity
  vector and the tank slides (the drift); it still brakes, and a stationary
  hull cannot pivot. Ignoring the bit leaves the tank driving straight through
  the handbrake.
- **Shooting the dummy is server-side.** `Avatar.vehicle_shoot()` has no
  arguments; `login/damage.go` resolves the shell from the gun marker against
  the dummy's hull box (TOG II: 76.2/50.8/25.4 mm), rolls penetration ±25% and
  damage ±25%, and streams `Vehicle.showDamageFromShot`/`health`/
  `onHealthChanged` plus `Avatar.showShotResults`/`showTracer`/`stopTracer`.
  The exposed ids are the defs' indexes; `selectEntity(dummy)` must precede the
  Vehicle calls and `selectPlayerEntity` the Avatar's.
- **`ENTITY_PROPERTY_BASE` is `0xA7` for every entity**, so a bare property
  element is `0xa7 + FullIndex` where `FullIndex` is
  `entdef.Entity.CSPropsOrdered` (fixed sizes first and ascending, then the
  variable ones in declaration order). Four ids in
  `captures/proxy-20261031-1358.hex` pin it: `0xa8` `isStrafing` (1 B), `0xb3`
  `botDisplayStatus` (1 B), `0xb4` `gunAnglesPacked` (2 B), `0xb6`
  `engineMode` (2 B). Walking every `S>C` tick with that table parses 1184
  packets cleanly. A variable-length property's header is
  `VariableLengthHeaderSize` bytes — 1 for `Tuple[0]`/`ARRAY` aliases
  (`ElementLength::Variable8`) — and a `Tuple[0]`/`ARRAY` payload starts with
  its element count (`write_packed_u24`), so the element is
  `id <len8> <count> <count bytes>` with `len8` covering the count. Omitting the
  count makes the client read the first element as the count and die on
  `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_` — measured.
- **Wheeled vehicles: `Vehicle.wheelsScroll` (`0xc2`) turns the wheels.** One
  packed byte per **non-track** wheel — `getNonTrackWheelsCount()`, not every
  `wheel` entry (the EBR 105 declares 16 and only 8 are non-track), because
  `Vehicle.set_wheelsScroll` zips the tuple against `createWheelFilters`'
  scroll-filter list. `WoT.unpackWheelScroll` is
  `(int8)byte * 0.19607845 - 24.90196`; `packWheelScroll` in `login/drive.go`
  is the inverse. `TestWheelScrollTupleMatchesTheClient` pins the id, the
  header width and the 8-wheel count.
- **Shooting works: the gun fires and reloads, nothing is hit.** The client
  fires its own visual (`Avatar.__showTimedOutShooting` after a 0.12-0.2 s
  timer), so the server only owes it the reload. `Avatar.vehicle_shoot` is cell
  index 0 with **zero arguments** — nothing to decode. The blocker was the
  ammunition: `AmmoController.canShoot` returns `(False, WAITING)` while
  `__currShellCD` is None, and that is only set from
  `VEHICLE_SETTING.CURRENT_SHELLS`, which first needs the shell in
  `vehicleAmmoList`. Both were empty arrays, so the client refused every shot
  before reaching `cell.vehicle_shoot`. `vehicleAmmoList` now carries the
  **saved layout** — one `VEHICLE_AMMO` entry per `cd,count` pair from
  `player_state.garage[].shells`, `index` = its position — because the client
  shows exactly this list: sending only the gun's default shell made a
  16/10/10 loadout read as 30 of the default. `CURRENT_SHELLS` is the gun's
  default shell, which is the layout's first entry, so `shellInAmmo` finds it.
  Shell CD is
  `(id << 8) + 10 + (nation << 4)` — `items.makeIntCompactDescrByID('shell',
  …)`, nation index from `nations.NAMES`, `id` from
  `<nation>/components/shells.xml`; pinned against the live client's 85082.
  The reload is `OwnVehicle.vehicleGunReloadTime` as an NRL node update
  (`EncodeNrlPropertyUpdate`, index 2), and it must be **closed** as well as
  started: `ReloadingTimeState.setTimes` stores `_actualTime` verbatim and
  nothing counts it down (`isReloadingFinished()` is `_actualTime == 0`), so a
  single `timeLeft = reload` update leaves the gun reloading forever.
  `finishReload` sends the zeroed update after the reload elapses. See
  `docs/PRIVATE_SERVER.md` "Shooting: the gun fires, nothing is hit".
- **Collisions are PARKED, and they cannot be fixed client-side.** The tank's
  position *is* the server's hull — `WGVehicleFilter` never integrates its own
  physics, `bodyMatrix` is exactly the entity position — so the client has
  nothing to collide against and the server has to refuse the move. That needs
  the map's static collision geometry from the `spaces/<map>/*.cdata_processed`
  chunks, a format distinct from the `terrain2/heights` `mapdata.go` already
  reads and not yet decoded. Two cheap slices that skip it: an explicit
  playable-area box test in `hull.step` (Karelia `(-500,-500)..(500,500)`), and
  refusing a step whose slope exceeds the tank's climb angle — `settle` already
  derives pitch and roll from the four corner samples. See
  `docs/PRIVATE_SERVER.md` "Collisions (PARKED)".
- **The reliable resend queue is keyed by SESSION, not by address.** The client
  rebinds its socket on battle entry and a re-login abandons the old session
  outright; an address-keyed queue outlived both and its packets were
  retransmitted to a dead port until the attempt cap — a live run logged
  **15,344 resends, 13,429 of them 28 B lobby poll answers, all to the previous
  session's port**, and the position updates queued behind them. `Admit` now
  retires the previous session for the same account, `sweepStage1` retires
  stage-2 sessions silent for `SessionIdleTTL` (60 s), and `readdr` moves a
  session's pending packets to its new address on a rebind.
- **Two `TickSync` counters, deliberately.** The hangar's post-flood stream
  (`postTag`, from `0x7a`) and the arena tick each write their own. Merging them
  makes `isLaggingNow` read false but the client then applies one position
  update and freezes; stopping the hangar stream does the same. Both reverted.
- **The arena tick runs at 100 ms, and the channel is the lever.** The client
  does not interpolate the player's vehicle: `filter.bodyMatrix` is exactly the
  entity position at every sample (measured with a Frida probe on the filter's
  per-frame update `sub_142F022A0` — the two agree to the last digit, driving or
  parked), so the tank is drawn at whatever the last update said. Measured again
  live with a pyconsole sampler on `vehicle.position`: 69 changes in 12.4 s of
  driving, each a discrete jump, the position bit-identical in between. The
  filter's only extrapolation (`sub_142EFF3D0`) is lag compensation — its blend
  factor is `(distance_to_server - 30) * 0.0333`, so it stays 0 until the client
  is 30 m behind, and it is gated by `filter.allowStrafeCompensation`, which
  `Vehicle.startVisual` sets to `not isPlayerVehicle` (off for the player on
  official too). `UPDATE_FREQUENCY_NOTIFICATION` only sets a stall timeout, not
  a simulation step. The hangar's post-flood tick stream must keep running
  alongside the arena tick — stopping it makes the client drop position updates
  entirely. Full evidence: `../docs/PRIVATE_SERVER.md` "Why the client's filter
  does not simulate".
- **The aim point is a WORLD-axis offset, not a hull-frame one.**
  `VehicleGunRotator.__trackPointOnServer` sends `shotPoint - stabilisedVehPos`,
  so `aimWorldPoint` adds it unrotated. Rotating it by the hull yaw makes the
  server's bearing disagree with the client's `getShotAngles` by the hull yaw,
  and the turret desyncs the moment the tank turns. The turret step is the
  shortest way round (`stepTurret`, wrapped difference).
- **The turret and gun angles are simulated even though `gunAnglesPacked` is
  never sent**: the NRL marker's `shot_velocity` is built from them. The pitch
  is measured from the gun's pivot — `turretPositions/turret` plus the turret's
  `gunPosition` — not the hull's origin. Negative pitch is up.
- **The km/h digits are `VEHICLE_VIEW_STATE.SPEED`**, polled by
  `_VehicleUpdater` from `Avatar.getOwnVehicleSpeeds()` →
  `vehicle.speedInfo.value[0] * 3.6`. That updater only starts at the end of
  `_setup`, and `_setup` runs `onVehicleControlling` first — where
  `timers_panel.__updateSmokeTimer` reads
  `vehicles.g_cache.equipments()[smokeInfo['equipmentID']].totalDuration`. The
  zero `smokeInfo` has `equipmentID: 0`, which is an `Extinguisher` with no
  `totalDuration`, so the throw aborted `_setup` and the digits stayed at 0.
  **`smokeInfo` must be `None`** (`SMOKE_INFO` is `AllowNone`).
- **A `PYTHON` property over 255 bytes needs the unsafe length**
  (`[0xFF][u24 len][data]`), not a 1-byte header. `initialServerSettings` is 802
  B, so `createBasePlayerApp` — the re-login path — failed and left the client
  at the login screen. `entdef.writeString` now takes the type and switches on
  `Python`.
- **`Vehicle.physicsMode` (ALL_CLIENTS UINT8) is sent as 1.** It was never
  sent before. No measured effect — the client has no Python reader for it.
- **`UPDATE_FREQUENCY_NOTIFICATION` (0x02, FIXED 7) is sent once at arena
  entry** with the real tick rate. It is the element that tells the client how
  often updates arrive, and with it `isLaggingNow` reads false where it had been
  true. The filter still does not integrate.
- **The client's filter does not integrate, and `filter.input()` is not the
  gate.** Feeding it every 50 ms clears `isLaggingNow` but `bodyMatrix` still
  equals the entity position and `movementSignals` stays 0. `movementSignals` is
  a Python-only property (its getter/setter are referenced only by the type
  registration), so 0 is expected. `velocityErrorCompensation` 0.5,
  `enableClientFilters` true, `ignoreInputs` false — all normal. A Frida probe
  (`tools/frida-inject/filter_probe.js`) proved the engine *does* tick and feed
  it; the blocker is **ground contact**: `numTrackContacts` is 0 for every
  vehicle. `initVehiclePhysicsClient` builds the 40 damper springs but never
  calls `configurePhysics`, which is what sets up the ground materials — and
  calling it by hand fails because the client's `typeDesc.type.xphysics` has no
  `detailed` key and its chassis entry has no `axleCount`, both of which the
  vehicle XML carries. Client data, not the wire. See `docs/PRIVATE_SERVER.md`
  "Why the client's filter does not simulate (open)".
- **`Vehicle.avatarID` is `ALL_CLIENTS` with no `DetailLevel`**, so it rides
  the creation run — the `updateEntity` that follows carries only the
  `MY_VEHICLE` ones. It was never sent, and its value is the **Avatar's entity
  id**, not the account id (the client compares it with
  `BigWorld.player().id`). `ownVehicleAuxPhysicsData` goes out every tick, not
  on change: the client builds the stabilised matrix the gun aims from out of
  it.
- **`Vehicle.dogTag` must carry a BACKGROUND and an ENGRAVING component**
  (`(300, 9)` and `(66, 0)`, the reference's `DEFAULT_DOG_TAG`), on **every**
  vehicle including the dummy enemy. `DogTagsController.__addDogTagMarker` runs
  from `Avatar.onVehicleEnterWorld` inside `setClientReady` and does
  `getComponentByType(BACKGROUND).componentDefinition`; with no components that
  is `None` and the `AttributeError` aborts `setClientReady` — no `isOnArena`,
  no period handler, an inert battle. With the tag sent, dog tags stay enabled
  in the settings and `setClientReady` completes.
- **A throw inside `Avatar.setClientReady` costs the whole battle** —
  it sets `isOnArena`, registers `onPeriodChange` and calls
  `invalidateVehiclesPosition()` after a per-vehicle loop. The one that
  bit us was `dog_tags_ctrl` reading `vehicle.dogTag`; the server
  disables dog tags (`dog_tags_config.enabled = false`).
- Tools: `tools/gun_probe.py` (whole gun chain, via `pyconsole`),
  `tools/dump_entitytypes.py` (id table), `tools/ida_entitytype_layout.py`
  (re-derives the dumper's addresses from a new build).

## Replay — key provenance

The 16 B stream key (`DE 72 BE A0 … AD BE EF`) is
community-published and verified here (test decrypts to a valid zlib
stream). It is NOT in the exe verbatim (Oct-11: full16/halves/
immediates all absent image-wide) — but the reader was found
(`sub_14057BEE0` → stock-Blowfish cipher from the static at
`0x1442DA5A8` = `DEADBEEF`×4 + mask/`BWTB` region), and that
static provably does NOT decrypt real streams (10/16 bytes shared
with the working key; tested deadbeef-fails/de72-passes). So the
static is placeholder/seed and the runtime key fills at runtime, or
a second decrypt path exists — open with two leads (reader
callers, writer side). Cite this file, not the provenance.

## Replay — TODO: live EU5 lobby application (hangar)

Transport is done (`login` reaches a sustained, acked 1252B flood on
p5; EU2 was silent for the same client-side reason, see above). What is
missing is the *application*: parse the flood into lobby state and
speak back. Established Sep 20:

- Capture harness: opt-in recorder in `login/baseapp.go`
  stageTwo (`WOT_FLOOD_DUMP=1`) dumps S>C to
  `/tmp/opencode/flood.hex` (`<ts> <dir> <len> <hex>`); per-run block
  key alongside (`stage2.key`, RAW bytes, ephemeral session — dead in
  minutes). Plus: C>S logging when recording, 60 s window, 5 s
  `clientToServerHeartbeat` (`[0e]`, wire ID 14 = table index-1,
  FIXED-0 per sub_140240640), 4 MB rcvbuf (burst loss is real:
  175 frags vs ~150), redirect follow-first-then-stay, stage2.key raw write.
  30-60 s windows verified sustained.
- S>C smalls FULLY decode (all cPickle proto 2): 0x13 tick;
  0x1a `[1a][type8][len8]` with type76 = session dict (recovered via
  `DecodePrefix`: the 156B body is STOP-truncated but the closed dict
  survives — `serverUTC`, `databaseID`, `aogas…`, `collectUiStats`;
  Sep 27), type79 = REDIRECT struct (NOT pickle: `0d` + IP string +
  port, e.g. `185.122.240.57`), type5f = `{prevRev,rev}`, type60 =
  `{databaseID,token}`, type5c =
  queue blob (binary + nested pickle `importantSeq`/`user_id`/
  `active`/`type`/`data{premType…}`); `1a67 classes|players` arena
 roster (auto-decoded Sep-29 lobby #2); 0x45 = `(entity, value)` tuples
  (`(226,N)` once, `(14,N)` every 5 s); 0x46 = zlib pickles
  (`{}` every 5 s, `{0: deque([serverEvent{originator,action…}])}`
  once — deque already allowlisted in the hand-rolled decoder,
  ack-and-park for v1).
 - Token2 LoginApp login shape (790/984B single+dual message, NOT basic
   534/728): 12-key JSON (account_complete[1], account_id[9],
   allowed_peripheries[7], auth_method[6], auth_realm[2], gameId[3],
   login[0], publication[1], requested_for[3], session[32], token[8],
   token2[69]; password empty) — our 7-key `-relogin` is a fidelity
   gap (missing 6 keys incl. the 8-char token).
 - Post-match pair (Sep-29 lobby #3): 180B = FIVE calls (225/100
   SyncData, 226/300 Shop, 227/600 DossierCache, (98,25) chat tail,
   228/600 dossier re-sync same args — producers
   AccountSyncData/Shop/DossierCache `__sendSyncRequest`, fan-out
   root Account.onBecomePlayer; double-228 trigger ranked:
   server-pushed resyncDossiers (checkable: S>C resyncDossiers call
   precedes), auto-retry, second cycle — answers the 180B in 77 ms)
   + 924B blob (900B: NARROWED — battle-results/SyncController/chat
   paths ruled out by .pyc recipe mismatch; ranked: (A) unknown-ID
   opaque small (leads), (B) engine-packed ClientMethod ARRAY push;
   decisive next step: byte0 of the 900B app = wire ID + ASCII runs
   ≥8 vs requestPlayerInfo's 13 ext keys); 108B = shorter
   XMPP connection-dict variant in the flood-tail slot (consumer
   XmppServerSettings; `woteu34…` is the bosh host element, path
   `/bosh/` hardcoded client-side); 180B tail is variant A (01) as
   the session's FIRST sync bundle — byte0 = bundle ordinal now
   3-for-3 (148→01, 84→02, 180→01).
- Oct-01 genuine session (`captures/proxy-20261001.hex`, 4335 datagrams,
  20:08:00–20:10:44, p2 upstream → EU2 lobby on `.215:32868`, clean quit):
  login (534→55→728→232) → stage-1 `.212:32819` (22→36 rotation→28s→52+44,
  redirect followed) → full lobby (489×1252 flood, 30×116 bursts
  ctr 258→519, 31×60B polls q5s). p2 reaches lobby fine this time —
  the park is intermittent, server-side.
  C>S script: 148 (3×0x95 Int3 (221,100),(222,300),(223,600) + chat
  tail (1,22,0,0,0) — same shape as Sep-27), 36 token(1,1),
  84a (Int3(224,100) + tail (2,0,0,2,0)), 68 (poll + token(2,5)),
  84b (Int2(225,121) + Int3(226,600), NO tail), 29×60B (202,501)
  byte-identical + 2 stats calls ((227,1500)=CMD_REQ_BATTLE_RESULTS,
  (202,1501)=CMD_BATTLE_RESULTS_RECEIVED, same extra args), 6×52B
  Int2 (228–233,121) season-selects while browsing vehicles, final
  36B disconnect `[0d][00][u32=42]` with 43 app-sends → sends-minus-self
  CONFIRMED (n=3). NO 180/924 (stats UI doesn't trigger the post-match
  pair), NO 0x9e (no queue), NO 0x46 in 163 s (session-dependent,
  like 804), NO Int4 (still unobserved; Str observed Oct-05, next
  bullet).
  S>C: 860 (0x45 req 221), 852 (req 227, ~108 ms after the 1500 call),
  324 (req 226, ~110 ms after 84b); every 60B poll → 36B tick +
  NEW 1a/0x5b fixed [type8][u32][u32] (NO length — len8 position is
  the low counter byte; 30/30 answers; counters drift 54320→54400
  and 123747→123676 = the server-stats reply; walker + test updated).
  NEW 1a/0x69 (87B dict{cache,prevRev,rev,stats}); 1a79 ×4 redirect
  offers (185.122.240.54:32810 valid + three unconstrued dotted
  digit-strings with invalid first octets, ports 32810/32816;
  byte0 ≈ strlen, 0d also on the 14-char one; client followed none,
  stayed on .215); 284B 0x0e-led vehicle-dossier pickle fragment
  (playerVehicles/marksOnGun/vehTypeCompDescr/ranks/boosters keys,
  memo idx 84 → continues an earlier doc; unknown-led family proven
  to carry pickles: concat harvest = 1 full doc
  {inventory/repair/shells/prevRev/cache/rev/stats/credits}).
  EU1 switch left ZERO UDP trace (same .215 connection throughout) —
  periphery switch is server-side-only. Chat tails byte-identical to
  Sep-27; codebook re-validated (0x95/0x93/0x8a/0x98 all genuine
  again).
- Oct-05 shop-claim session (`captures/proxy-20261005-battle.hex`,
  6667 datagrams, ~5 min, clean quit, no battle fought): basic login
  → stage-1 `.212:32816` → stage-2 `.213:32881` (476×1252 flood,
  42 chunks, nn=1 same offer bundle family). Opener WITHOUT 84b
  (sync1/token/sync2a/poll68 then polls only — dossier sync is
  session-conditional, not mandatory). The one shop action is
  doCmdStr(225, CMD_RECEIVE_OFFER_GIFT_MULTIPLE=10095) carrying a
  JSON map payload (A1 0x9b, FIRST live sighting — codebook tag
  confirmed, `lobbycalls.go` updated): answered in 75 ms by 332B
  (tick + 1a/69 shop dict + 1a/5f), then a 14-frag re-sync bulk +
  444B tail and premium/cache syncs (364/644B). Base IDs continue
  the allocator (…,224 then 225 for the claim; polls stay 202);
  token IDs run (3,1),(4,5) — shared TokenRequester generator with
  two prior in-session allocations, so opener token IDs are
  order-derived, not fixed (comment updated).
- Item 6 UNDERWAY (battle S>C, Sep-29 match `proxy-20260929B.hex`
  45507→.67 flow, 11,421 datagrams; key = token2 790/984 MITM leg,
  both decrypt — RecoverLoginKey now covers 534/790/984):
  C>S SUB census identical to Sep-29 notes, avatar parser holds.
  S>C heartbeat = ALTERNATING 14/15-record snapshots (276B/292B
  datagrams, strict alternation): 13B records `[35 00][11B payload]`
  with 3500 marks at 68+13k in every snapshot; entities rotate
  in/out per dead-reckoning (slots NOT fixed, records persist ~3
  snapshots then swap, last byte fa/fb flags-ish). Payload carries
  cm-scale i16 coords — avatar-z validated (250.49≈250.8,
  -77.19≈-77.4, -64.1≈-64.2; x often overflows i16 → partial-update
  semantics when |coord|>327m). Head 65B holds a LE-f32 reference
  position (385.0, 25.0, …). Reference PackedXZ/PackedXYZ impls
  validated by round-trip, but alias+packed+absolute model
  unconverged (25–110 m residuals, scale scatters) — WoT fork
  differs from 14.4.1 reference packing (or per-record base needed).
  1a/0x88 = `[1a][88][X][03][Z][zlib]` with tiny creation-state
  pickles at battle start ((1,42392.8,60,(1,1)) … ids 1–4 sequential,
  clock-like ~42–43 s, fully decoded) + an opaque 73B variant; 1a/0x93
  (len 0x52), ASCII/pickle text docs, NO 116-bursts, NO 0x46 in
  battle. OPEN: exact 11B field map, ID semantics, head layout,
  dir fields.
  Update (field-map push, mixed): 276B/292B snapshots STRICTLY
  ALTERNATE (14 vs 15 records — two interleaved update sets ≈ halves
  of ~30 entities); 3500-period-13 holds for them, other sizes are
  mixed content. Records ROTATE across snapshots (slots not fixed;
  persist ~3 then swap). cm-i16 avatar correlation RETRACTED: joint
  (x,z) test over 7193 records ≈ chance — earlier single-field hits
  were coincidences; NO converged position model (reference
  PackedXZ/XYZ validated by round-trip but unconverged vs avatar at
  any phase/scale; LE-f32 triple scan drowns in zero-padding).
  Head base drifts per snapshot group ((387,25) vs (276,21) — NOT the
  player; likely another entity inline, not a base). Battle-start
  creation docs found: 532B battle-info (1a/0x93 len 0x52, BlockB
  names, numbers, "battle") + 1148B structured table (u16s + space
  name "bwr.default") — the roster ground truth, unparsed. 1a/0x88
  tiny-zlib values fully decoded (slots 1–4, clock-like ~42–43 s).
  1a/0x93 CLOSED Oct-02: battle-start arena-params doc — head
  (player-name + account DB ID + ints + `ff aa 01 00`) + proto-2
  pickle (10 keys: arenaKind/arenaTypeID/battleLevel/
  battleModifiersDescr=nil/bonusCapsOverrides/botsDifficulty/
  gameParamsRev/isRandomEventsAllowed/postmortemSettings{config,
  gamemode}/reservesModifier), fully decoded with the existing
  decoder (426B consumed); only the first 532B table carries it
  (others = vehicle-descriptor doc + binary blobs); consumer
  AvatarPostmortemComponent (shipped .pyc carries the keys).
  STILL OPEN: 11B field map, ID semantics, head layout, dir fields —
  needs engine volatile-write-for-client specifics or a fresh angle,
  not more blind correlation.
  Volatile scan CLOSED Oct-02 (model + live walk agree): exactly ONE
  volatile prop exists in the whole 332-entry client map
  (GunMarkerComponent.gunMarker, var-size FIXED_DICT — cannot be in
  fixed 11B records); zero `<Volatile>` in live entity_defs. The 11B
  payloads are engine-builtin volatile data (position/yaw/pitch/roll),
  layout in the exe only → IDA task.
  11B FIELD MAP CLOSED Oct-02 (IDA + wire-fit, see
  `../docs/NETWORK_PROTOCOL.md` §14): `[ID u8][posType0 6B][dirType0 4B]`;
  unpacker `0x140E37200` (+mirror `0x140E55350`), BitReader
  MSB-first, custom 1+4+N floats (bias −2.0, per-entity scale),
  direction (roll10, pitch11-half, yaw11) with absolute 2π scales;
  yaw tracking med-step 0.10 rad; 14 entities/snapshot + visitors.
  Static follow-up Oct-02 (classes, sentinels, sources — see §14):
  `CellAppDefaultEntityVolatilePacker`/`ClientDefaultVolatileUnpacker`,
  posType{0,1,2}/dirType{0,1,2,3}, invalid = -13000/FLT_MAX, bias
  exactly -2.0, scale = runtime `[entity+0x130]+0x77C` (not a
  constant — scatter explained), ID = BW entity ID (lookup miss →
  `No such entity`), per-axis mantissas 12/12/9b. Base-add CLOSED:
  conditional on the `[entity+0x40]`-slot call returning NULL (base
  triple `[entity+0x130]+{0x13A8,0x13AC,0x13B0}`, else used as-is).
  Direction REFINED to signed reads with exact scales (roll11
  2π/2048, pitch11 π/2046 exact — measured `0.0015354804`, NOT
  π/2048, yaw10 2π/1024; 8b 2π/256).
  Slot order CLOSED Oct-11 (IDA output mapping, see §14): position
  wire (x, z, y) → out (x, y, z), y third and ABSOLUTE (no scale);
  posType1 = x,z-only with y-slot marker (`-13000.0`, tracker is
  posType-aware); direction wire (roll, pitch, yaw) → out (yaw,
  pitch, roll); dirType1 = roll8+pitch8 (yaw `FLT_MAX`), dirType2
  = roll8 only. Size fn `0x140E36580` confirms pos{6,3,0} +
  dir{4,2,1,0} (+1B ID). Remaining static: creation parse (absolute
  vs base-relative caller context).
- Item 4 CLOSED (unknown-led harvest, 3 sessions: Oct-01 54338,
  Sep-29 44395, flows3-s2): 1-byte resync inside rests recovers full
  trains where the strict walker stopped at the first unknown ID —
  but every extra must be INDIVIDUALLY validated (false alignment is
  rampant: resync-only 0x46 ×5/×2/×4 all failed declen+zlib,
  resync-only 0x45s are misaligned blobs, extra 0x13s suspect).
  VERIFIED real: 1a/69 second size (172B dict{cache,inventory,
  prevRev,rev,stats} beside the 87B one), 1a/51 (opaque 43B,
  framing-real at datagram start), 1a/58 (EMPTY signal, 284B tail),
  1a/73 (clan-hail text with 02 separators, flows3), 1a/4d (tiny,
  counter-like), 0x45 third byte 0x0b/0x0c/0x0e (status candidate —
  req 223 got 0x0b). 0x46: ZERO validated in all 3 sessions →
  session-dependent (Sep-27 only). Unknown-led family carries pickles:
  full shop/inventory sync dict via concat, 284B vehicle-dossier
  fragment (memo idx 84 with NO head in-capture → headless
  continuation, head lost or in-bulk; client tolerates). 1220B trains
  in 44395 (vs 1244B elsewhere — frag size varies). 5c pair is custom
  binary (DecodePrefix dies at byte 1, both sizes). PARKED singles
  (98/5d/ab/4f/a2: stop-byte recurrence in Oct-01 (5d×4/a2×2/ab×1/
  4f×1, 98 absent) but content still unvalidated (5d 4/4
  DecodeAt-fail) — session-specific shapes, no validated content;
  verdict stands).
- REDIRECT-FOLLOWING (Sep 21, live-verified): without it the server
  parks us on the login-assigned instance (infos, no entities,
  redirect repeated ~10 s). Following works: p5/AWS → EU2-metal
  chain (e.g. `185.122.240.54→.42→92.223.20.72`, all `:32956`),
  ends at a flood-serving host. Resend fresh 22B (same session),
  reset channel counters. Still no `createBasePlayer` after follow.
- Genuine oracle `captures/flows` flow 39 (EU5 stage-2, 20.8 s,
  mitmproxy dirs: is_server=true = GAME→server): game sends 686×28B
  acks + 22B + 9 app calls (148, 36, 60, 52, 68, 60, 52, 60, 36 —
  NOT heartbeat-sized); server answers 36B acks + 860/1244/100/
  780/244B + 31×116B + 473×1252B flood. Sequence: 148B@1.74 s →
  860+1244B; 36B↔36B pairs; 60B→100/36B; 52B→780B?; 68B→244B+36B.
  Parse with the tnetstring reader (flow applets in git history).
- Heartbeat result: 11× `[0e]` over 60 s, accepted (no kick) but no
  observable effect — keepalive only, not the gate.
- Bulk bundle CORRECTED Sep 27 (two genuine captures, `ReassembleFrags`
  + NN audit): the 1252B flood is ~511 datagrams in ARRIVAL order =
  one ~625KB shared-memo proto-2 pickle (single doc, NOT per-frag
  docs). 48 NN chunk headers ride along (`frag0: ff XX YY 03`;
  standard `13 NN+78 .. .. .. dd 00 NN`; alternate `13 NN+78 1a ..
  .. .. .. ..`, same pay[1] encoding) at chunk starts, NN 1..48
  exact, zero dups; chunk sizes vary wildly (chunk 1 ≈ 175 dgs).
  Sep-28 update (flows3, Sep 17, third capture): odd-header base is
  per-bundle, VOTED from dd00s (0x78 Sep 27, 0x51 Sep 17); a 4th
  header shape (`fe…`) takes NN by gap-elimination; 40 chunks,
  same model holds. Content verdict (entropy + per-chunk
  inventory): chunk 1 = the shared-memo pickle (H≈6.0, harvestable
  to noise sites); chunks 2+ = near-random (H≈7.9, no pickle/zlib/
  deflate/standalone-doc/file-magic under any strip or memo),
  chunk 13 head carries one standalone session dict; whole flood is
  one ~6 s burst (no demand pattern vs C>S). Chunks 2+ are
  second-layer-or-pad — indistinguishable offline, acked-only is
  parity-sufficient (Oct-02 flows3 re-proof, 4th session: 40 frags
  reassembled clean; chunk payloads reject all 6 rotation/login-key
  forms + zlib; no static lever left — needs a live known-content
  session or engine second-layer source). Chunks are NOT independent (memo refs span chunks — chunk 2+
  fails standalone at byte 1). Content = shop/offer defs (per-offer
  subdicts keyed `offer:<page>:<kind>:paid:<N>`, sequential memo).
  Per-capture NOISE: a few single/few-byte edits per 625KB at
  DIFFERENT sites per run (fresh: ~134546/161432/167573/214053;
  afternoon: 145549) — not server-deterministic (dedup shows zero
  dup datagrams; NN audit perfect), game unaffected (hangar both
  runs; likely VPN/userspace or server splice, game decodes lazily).
  Consequence: strict full-stream decode is brittle by nature —
  the analyzer must resync (`DecodeBundle` at chunk starts +
  `DecodePrefix` partial stacks; closed subdicts survive).
- Lobby speaks `doCmdInt*` via `ClientCommandsPort` interface
  (`CMD_SYNC_DATA=100`, `CMD_REQ_QUEUE_INFO=502`,
  `CMD_REQ_SERVER_STATS=501`, `REQUEST_ID_NO_RESPONSE`; sync via
  `SyncController` = zlib+cPickle `RES_STREAM`, matches 0x46).
  `Account.onBecomePlayer` fans out to ~35 subsystems.
- Next, in order: (1) WAIT OUT the stage-1 park (see below), then
  (2) redirect-policy retest (stay after hop #1 — now the default:
  follow-first-then-stay in stageTwo), (3) doCmd probe (LIVE default:
  codebook-correct A1 0x95 `doCmdInt3(202, 501, 0, 0, 0)`,
  unreliable 60B, one per 2 s after decrypt-verified flood+3 s — watch
  for any 36B+ response); (4) entity attach (see createBasePlayer note below);
  (5) subsystem syncs (long-term). Long-haul grind BUILT Oct-03
  (`wotlogin -longhaul`, fresh login per iteration + 120 s stage-1
  window + game-like 0.5 s resends/7 s pacing, tally counts-only):
  the game's persistence, which single-shot runs never mirror.
- Entity attach (static, Sep-29): S>C `ClientInterface::createBasePlayer`
  (exe wire table IDs 0–39: 4 createBasePlayer, 10 createEntity,
  19 tickSyncPeriodic = our 0x13 tick; 0x45/0x46 exceed the table so
  they are payload-internal, not message IDs) is emitted by the
  server proxy ONLY after the first C>S `[0b]` enableEntities per
  proxy (engine proxy.cpp) — buffered traffic waits behind it, so it
  arrives as a small reliable datagram, never in the bulk. Our
  redirect-follow already sends post-hop double-auth WITH `[0b]`
  (baseapp.go stageTwo), so a missing `[0b]` is FALSIFIED as our gap.
  Carrier narrowed: one of the unknown-ID-led smalls (walker stops
  at unknown IDs with rest preserved); 116B bursts DEMOTED (26–36
  datagrams/session, per-session unique — not a single creation
  message). Small→consumer map: 0x45 → onCmdResponse (reqID-embedded,
  answers polls), 0x46 → onStreamComplete/SyncController, 0x1a/76 →
  showGUI candidate, 5f → AccountSyncData revisions (proven in
  AccountSyncData.pyc), 5c → receiveQueueInfo candidate. Anomaly on
  record: `tokens.onAccountBecomeNonPlayer()` inside
  `onBecomePlayer` (Account.pyc).
  **RESOLVED (Nov-3, live):** 0x45/0x46 are the client's own element
  table entries `RESOURCE_HEADER` / `RESOURCE_FRAGMENT` (both
  Variable16), not payload-internal — the exe's element table puts
  `ENTITY_METHOD` at 0x4E..0xA6 and `ENTITY_PROPERTY` at 0xA7..0xFE,
  so 0x45/0x46 sit just below the method range. A `RES_STREAM` answer
  is `[45][len][id][packed-u24 descLen][pickled (len, crc32)]` then
  `[46][len][id][seq][last][zlib]`; the client DROPS a fragment whose
  id has no header, silently. Sending the fragment alone is what
  stalled the hangar on "Synchronisation du fichier personnel" —
  `Account.onStreamComplete` never fired, so
  `DossierCache.__isSynchronizing` stayed true and `DossierRequester`
  parked with no traffic and no error. See `docs/PRIVATE_SERVER.md`
  §"Resource streams".
- Lobby parsing is UNDERWAY (not blocked): `SalvageChunk`/`PlainValue`
  (`login/lobby_state.go`, tested) convert chunk-1 prefix salvage
  into plain maps/slices/scalars — verified on the live hangar dump
  (Sep-29 proxy session: 404 closed items = 103 maps + 55 lists +
  scalars; schema count/id/expires/tokens/customizations/
  vehTypeCompDescr/credits/seasonPoints… = shop/goodie/inventory
  state). Typed assembly UNDERWAY (`lobby/assembly.go`: presence-
  boolean accessors + `Offer` (both key shapes, `expires:{at}`,
  8/8 Oct-01) + `Quest` (dq/wq legs, 3/3 Oct-01) + `PiggyBank` +
  `ModeConfig` (epic/last_stand/squad) + `SlotCharges` (8+16 nations
  over 2 sessions) — synthetic green, live-validated counts;
  dossier objects (playerVehicles/marksOnGun) stay key-only (headless
  fragment, no value schema on hand). Shape census (Sep-29 dump, names only): 79 top-level
  shapes (17× empty, 6× {enabled}, season/battle-pass, arena-config,
  missions|onboarding…) + 217 nested shapes in depth (28×
  enabled|milestones|vehicles, 20× count|expires and level|quest,
  17× equipment cost|equipmentID|overrides, ranked id|name|tags…;
  16 offer:-keyed subdicts this session). Turn-taking mapped (148→852 in 152 ms; token→smalls
  train + paced 116s; flood unprompted +0.090–5.413). Remaining:
  116 content (opaque under pickle/zlib/raw+chained Blowfish with
  both keys, varint, floats, single-byte-XOR cribs
  (pickle/zlib magic hits at chance rate, token strings zero) —
  incl. a recovered stage-1 rotation key as second layer; first
  bytes 22/26 ≥35, not method indices), chunks 2+ (indistinguishable offline),
  subsystem assembly UNDERWAY (`lobby/assembly.go`: typed accessors
  with presence booleans + `Offer` parse — key shapes
  `offer:<page>:<kind>` and `offer:<page>:<kind>:paid:<N>:<M>`,
  `{count, expires:{at}[, limit]}`, synthetic green, 8/8 offers from
  Oct-01 salvage; speak-back still needs a stage-2 window).
- Battle (CellApp arena) parsing is UNDERWAY (Sep-29 proxy match,
  11,421 datagrams, own channel key from the 790/984 token2-login
  C>S packer note (Oct-11 IDA): no client bit-packer exists — image holds
  only unpackers + pack-stubs (CellApp packer is server-side). Own-position
  goes out as LE floats via BaseAppExt `avatarUpdateImplicit/Explicit`
  (table order confirms ranks; matches `ParseAvatarUpdate`); S>C owns
  `avatarUpdateVolatileProperties` (ClientInterface, not C>S as once
  assumed) alongside the packed 11B records.
  leg — NOT the lobby keys): C>S = `[02][key4][SUB…]` bundles at ~18 Hz
  (key4 = per-flow server-assigned 4B from the first 36B S>C reply, echoed
  as every bundle head; records always bare — the Oct-12 `0x93 family`
  was the Sep-29 key's low byte, corrected Oct-14),
  `ParseMoveWith` (`lobby/battle.go`, tested)
  decodes the 60B/34B moveWith shape (entity + F1 + speed 7.14 + xyz
  LE f32 at [20:32]; 2535/2538 live packets parse; 60/60 sane + 59/59
  smooth steps verified); SUB = Avatar own-cell index (0x1a=26 moveWith
  CLOSED; 0x07 = sequenced ack-like records (u8 seq, near-constant —
  NOT disclose, stride refuted) riding standalone + inside 18/12/06-led
  bundles; 0x18 ≠ plain stats; 0x1c/0x1d trackGun medium — Oct-12 census
  7214/7214 decrypt: 07 ×2994 var-len, 18 ×1405, 12 ×165+, 06 ×49+,
  1c ×21, 1d ×10, 10 ×9 (4 lead + 5 chained), 07/15 ×116 bare; zero 0x1b
  DESPITE 9 confirmed
  own shots (see below) — so the shoot SUB is NOT doc-order 0x1b
  (fork (a) confirmed) or firing is state-based; trigger still open,
  now well-posed with 9 true shot times (two post-shot 0x1c/0x1d
  proximities: s6 +0.06 s, s9 +0.04 s — aim aftermath, not trigger);
  every position-carrying call ends with the uniform 29B
  `[1a][1a00][entity][nonce][speed][xyz][tail]` trailer (standalone 0x1a
  = trailer only; `ParseTrailer`; nonce verdict: per-packet
  uniform-random freshness).
  Caliber finding Oct-12 late: tracer Range = shell caliber in mm
  (proven on own-vehicle ground truth: Prohorovka Challenger 17-pdr
  76.2 mm → Range 76.2 on all 11 own tracers; WolfPlayer T110E5 120 mm
  → Range 120 on all 42; battle-wide set 57/75/76/85/88/90/105/122/
  128/150/152/155, fixed per shooter like a0); template validated
  clean (0/533 lobby bodies). CORRECTION (same day): the recorder
  (ExampleUser, SU-152) IS entity 542282516 and fired 9× 152 mm in
  this battle — the old "fired zero" corollary rested on tracer↔own
  distances computed against the C>S position track, which is
  displaced/glitchy here (teleports + smooth-but-offset segments, see
  below), plus a hex arithmetic slip (0x20529314 = 542282516, the
  user's entity — not 542278420). Identity is triple-proven
  server-side: battle-start arena-params head pairs
  (ExampleUser, 542282516) — same shape as the user's Prohorovka
  replay (ExampleUser, 4730080 = own a0); C>S moveWith entity =
  542282516; 9 S>C tracers with a0 = 542282516, all Range 152.
  Framing CLOSED Oct-12 late (IDA static tables + byte-exact fits),
  CORRECTED Oct-14 (records always bare; `0x93` was the flow key's low
  byte): bundle = `[02][key4]([SUB][len16le][args] |
  [1a][len16le][26B])*` — SUB and len coexist (0x1a/34 =
  [1a][len 26][26B]); SUB = own-cell doc index statically except
  the trigger (wire 0x10 = vehicle_shoot behaviorally; doc-order 0x1b
  never sent over 7323 C>S despite 9 confirmed shots); long bundles chain implicitly-framed
  records (per-SUB sizes open). T2 stands (a0 shooter proof).
  TRIGGER CLOSED Oct-12 late (this battle is the firing capture;
  shape CORRECTED Oct-14, re-proven 8/8 on 2.4.1.0 b2):
  C>S shoot = bare SUB 0x10 record `[10][0400][00000000]`, lead
  or chained-inner — 9/9 own shots 60–140 ms pre-tracer, zero baseline.
  OWN SHOTS CLOSED Oct-12 late (9 confirmed, recorder=542282516):
  s1 20:46:59 (275,23,-2) → 846 m; s2 20:47:16 (275,23,-1) → 841 m
  + explode (−133,0,284); s3 20:47:57 (261,23,1) → 856 m;
  s4 20:48:16 (264,23,1) → 859 m; s5 20:48:49 (279,23,-39) → 450 m
  + explode (426,53,-238); s6 20:49:09 (278,23,-36) → 462 m;
  s7 20:49:46 (409,27,12) → 484 m; s8 20:50:23 (397,32,-85) → 408 m;
  s9 20:52:14 (277,23,-21) → 662 m (AMX-duel reply; enemy 542264099
  3× 57 mm @11.8/12.8/13.9 closing 62→20 m, silent after; own death
  20:52:17.9, postmortem names 542264105 — kill/direction decode open).
  Gaps 17–111 s, all ≥152 mm reload-plausible. Muzzles sit on 3 spots
  ≤130 m apart (A s1–s6 ±20 m, B s7–s8, back-near-A s9) — no chase;
  T20-window shots all from stationary spot A (user correction
  accepted; the chase reading rested on teleport artifacts).
  Ack rule (recorder-supplied,consistent with wire): spotted hits ack
  live (s2/s5 explodes = the 2–3 acknowledged), unspotted/ground hits
  withhold everything until battle results (7/9 silent; this capture
  holds no 1500-request/852 — results never pulled in-window).
  Trigger CLOSED Oct-12 late: C>S shoot = bare SUB 0x10 record
  `[10][0400][00000000]` (lead ×4, chained-inner ×5),
  one per shot 60–140 ms before its S>C tracer (9/9 both directions,
  zero baseline over 7323 C>S); builder + recognizer in
  `lobby/battle.go` (`BuildShootTrigger` takes the flow key4; genuine
  Sep-29 + Oct-14 vectors pinned in tests). Behaviorally
  vehicle_shoot() (sole cell call in decompiled Avatar.shoot; no other
  client caller; equipment path excluded); wire index ≠ doc order (0x1b
  never sent) and the 4 zero bytes vs 0-arg defs stay open statically.
  Shots hunt remainder: others' shots in S>C
  1a/ba tails (07-echo = confirmed ack by seq tracking; routine 71/74B
  call carries an unidentified V3 pair; ~20 rare long tails are event
  candidates); replay-anchored arg layouts (showTracer fixed-37 50B,
  showShooting 3B, explode, shotResults) documented in protocol §14;
  decisive next = firing capture with recorded shot times.
  Tracer CLOSED live Oct-12 late: replays are S>C-only (128 tracers +
  81 shootings + 105 explodes, zero inputs); live S>C carries 114
  tracers as [13 tick][1a 0x73][50B] ahead of the snapshot train —
  same 50B serialization as replay; trigger CLOSED (0x10 record,
  see above).
  Explode CLOSED too (35× 1a/0x91: len8=41, shotID-linked to tracers);
  showShooting/damage/results still open (NOT in 1a/ba tails —
  re-rejected Oct-12: flat length distribution under boundary
  validation, same misparse as before; NOT in 0x75 markers or 0b a8 02
  bundles either — needs CellApp S>C dispatch-table work or a live
  known-content session).
  Shot feed (Oct-12): `replay.ShotFeed` joins tracers × setup roster
  → `[mm:ss] [name] [tank] SHOT` (`wotevents -shots`; Prohorovka:
  128 rows, 11 own pinned); live pieces in `lobby`
  (`ScanBattleTracers` incl. denormal-ghost rejection,
  `ParseBattleRoster` entity→name + `ParseBattleVehicles`
  entity→(nation,typeID) + `ParseBattleTeams` entity→team +
  `ParseBattleMounts` entity→mounted (turret,gun) +
  `ScanBattleExplodes` (23/31 join tracers; 8 tracerless loss-class,
  2× 130mm → SU100Y; Oct-12 field-order fix: impact V3 FIRST at
  +16/+20/+24, replay-homologous End V3 second — the old reading took
  the near-origin triple; tracer end = trajectory endpoint, not
  impact) — Sweden:
  30 pairs, 132/132 shots attributed, ghost-free, all 30 tanks
  resolved via list.xml vehicle IntCDs, 15/15 teams, 26/26 exact
  single-gun reloads (inline mounted-only 12B descr, name-anchored),
  drum+dual live mag counts, Italian autoreloader chain model mapped
  (ammo_ctrl.pyc + WG article, needs wire validation),
  31-row HIT feed with muzzle-history victims (misses suppressed:
  explodes = non-fatal spotted hits — all 4 observed fatal blows carry
  no explode; two-sided offline 13/23 joined with HIGH/MED grading,
  past-only live core), 24-kill feed
  via ParseBattleDeaths (deathOrder victim/killer, counters 1–24;
  6-record `0b a8 02` death bundle closed: 03/1a-fixed/10 all 24/24;
  Oct-14: per-battle pair (0c23 b2 28/28 incl. own #8 at 05:12,
  0c99 b1 2/2, 0c92/08b6 next sessions) matched by nothing, anchors
  + counters + roster carry it; b1 own single trigger drew no tracer
  (unserved-shot anomaly, open: burst loss vs server drop)),
  per-shot shell kind (tracer flag byte 3: HEAT/HE/AP/APCR),
  shell blast fields + ballistics (MatchShell/FlightTime/IncomingShot;
  Sweden: 132 evaluated, 0 warnings — correct, nearest Hummel impact
  217 m), snapshot decoder (ScanSnapshots: 5458 records, 19 tokens;
  Oct-14: 324B mixed trains (same 13B packing, event smalls
  interleaved, run gate harvests 0.5/dg) covered by gate-free
  `ScanSnapshotTokens` (token at fixed +2; presence now folds tokens)
  — token→entity map OPEN with completed negative survey: global affine
  rejected at chance, own never in snapshots (structural), C>S track
  chaos, yaw≠movement; needs denser anchors or in-process scale),
  type-0x75 markers (`ScanBattleMarkers`: 5 ENEMY+ALLY links + 11 ally
  SPOT reports with positions, framing closed, semantics open),
  HP per-hit numbers BLOCKED (absent from all surveyed families —
  same wall as live showShooting);
  S>C battle snapshots (276/292B) decrypt with the SAME key (561/561).
  `1a ba` is a lobby-framing misparse — neither body- nor
  total-length fits, 12/4047; records show `35 00` separators +
  float tail, packed formats need engine tables); fragmented
  ff/45/46 shapes fail cleanly (16/3/3, need reassembly).
- STAGE-1 PARK (Sep 21 ~18:35–19:45, 12+ consecutive identical runs,
  plus Sep 27 ~22:43 p5 and ~22:55 p2, plus Sep 28 p5 live-fire, plus
  Oct-02 `.215:32836` re-proof (fresh GUID, 90 s budget):
  rotation-ok throughout, 250+ ticks, no redirect — opener unfired):
  server sends rotation (36B) + ticks only (cumul=0, no 52B reply, no
  0x44 redirect, auth1 never answered) then 25 s timeout. NOT the live
  game session (persists 40+ min after user logged off). SESSION/
  TEMPORARY matrix tested (fixed blob, fresh GUID, temp 0/1 — all log
  in fine, all park). No-auth1 tested (not poison). ROOT DIFFERENCE
  FOUND (captures/CE.txt genuine params):
  game logs in with `auth_method: token2` (WGC-issued token) +
  `temporary: 0`; we use `basic` (password). Launcher-token path
  needs WGC (Proton env). Park = likely account-level velocity
  throttle (slow decay) and/or basic-auth deprioritization — STAND
  DOWN live attempts for hours, not minutes.
  Oct-02 parked-tick detail (same run): each 28B server tick carries
  an incrementing app byte (walker `id` 0x00→0xfb across the run —
  new observable, meaning open: tick counter vs channel echo).
   Genuine stage-1 shape SETTLED Oct-03 (decrypt-proven, twice):
  auth1 is RELIABLE `[02][key]` WITH the 0x0b trailer (flags 5804,
  reliable seq 0) — flows3 Sep-17 AND proxy-20261001 Oct-01 (login
  key MITM-recovered offline, auth1 cleartext `580402…0b…`) agree,
  both sessions reached the lobby. The Oct-02 unreliable-no-0b
  "mirror" is WITHDRAWN: it rested on a size-only 28+28 reading
  (both shapes are 28B on the wire — only decrypt decides), and
  every run under it parked (Oct-02 solo + 4 Oct-02/03 runs + grind
  iter #1 with a 120 s window: 1201 ticks, no redirect). Live script
  sends ack0 + reliable auth1 (10 ms) + pure acks; the opener
  allocates request IDs in call order (base 221,222,223 + 224…,
  token 1,2, chat 1,2 — allocator-derived per decompiled .pyc,
  not constants) with both chat tails. Park signature throughout (all shapes): 36B seq1 +
  ticks (app byte 02→fb), cumul=0, no 52B/redirect. 2-session
  confound falsified Oct-02: game-quit solo retry (→ `.213:32842`)
  parks identically (36B + 246 ticks 02→f7, cumul=0).
- Genuine C>S script DECODED Sep 27 (decrypted with the login key,
  builders in `login/lobbycalls.go`): every C>S app bundle is
  `[02][newkey]` (primeBundle auth) + concatenated base calls
  `[A1][msgID u16 LE][args]`, channel `[seq][cumul]`. Opening:
  22B handshake, 148B = doCmdInt3(221,100,…)+doCmdInt3(222,300,…)
  +doCmdInt3(223,600,…) (SYNC_DATA + SYNC_SHOP + SYNC_DOSSIERS, with
  account-specific args — corrected Sep-29: THREE calls, not two)
  + (98,25) tail, 36B = requestToken(1,1) [08/8a tag],
  84B = doCmdInt3(224,100,…)+ (98,25) tail, 68B = doCmdInt3(202,501,0,0,0)
  + requestToken(2,5) in flows3 (the Sep-27 Int4 attribution is
  unverified offline — no decrypted Sep-27 dump survives; Int4
  UNOBSERVED in 3 wired sessions Sep-17/Sep-29 ×2, every 68B there
  is Int3+token — the Sep-27 read was likely an Int3+token
  misread; `DoCmdInt4` kept as untested framing),
  52B = doCmdInt2(225,121,…) (SET_ACTIVE_VEH_SEASON),
  4×60B q5s = doCmdInt3(202,501,0,0,0) = requestServerStats,
  36B = unknown (0d,00). 52B SHAPE VARIES BY SESSION (Sep-29 lobby #2:
  `doCmdIntArr(202, 700, [1=RANDOMS, 339=vehInvID, 67, 0, 2])` =
  enqueueRandom battle-queue join, A1 0x9e, count-u8 + INT32s,
  byte-exact in `TestDoCmdIntArrEnqueue` — the match followed;
  A1 selects doCmd variant: 0x95 Int3/Str, 0x93 Int2, 0x9e IntArr). Method map from decompiled Account.py +
  ClientCommandsPort.def. Cross-session diff (Sep 27 two runs):
  148/84/68/60/token apps BYTE-IDENTICAL (requestIDs 221-224 —
  allocator-derived from the identical call order, not constants;
  sync args, Int4 args — static per account, safe to replicate);
  only the 52B varies in ONE byte (2nd i64 low byte).
  Server answers 148B with 860B (0x45) + 1244B (concatenated
  smalls train: tick + 1a5e + …, NOT a bulk doc) and
  36B with paired smalls + 36×116B entity burst, then the flood;
  every 60B poll gets a 36B answer in ~100 ms (live success signal).
  Entity burst framing CLOSED (flows3, 28×116B, Sep-28; parser
  `ParseEntityBurst`/`CensusEntityBursts` + `wotflood -smalls` section,
  synthetic tests green): flags 0478 + 88B packed-entity-opaque bodies,
  tail `[counter u16 LE][0000]` with the counter stepping exactly +9
  per datagram in arrival order (249→492, 27/27 deltas). First bytes
  all distinct, bodies high-entropy — NO plaintext framing; login-key
  plaintext (magic-validated), not pickle/zlib/double-wrap/deflate.
  Content stays parked as packed-entity-opaque (acked-only is
  parity-sufficient for v1); the envelope is now machine-checked per
  run instead of eyeballed. Entity cross-over probed Sep-29:
  LEB128-varint cover fails on 27/28 bodies (1 chance pass) —
  not packed-int streams either; cross-session (Sep-17/29 ×3:
  28/26/27 bodies) finds ZERO identical bodies and ZERO positional
  first-byte matches — per-session unique content, tails start
  249/252/253 stepping +9 throughout. Engine side (Oct-02 IDA):
  `createEntity` wire registration located (thunks `0x140240740`,
  arginfo `0x1442DCC00` — entry = {handlerVtable, u32,
  lambdaVtable, u32}, Oct-11: handler = `InputMessageHandlerT`
  (source check + bound functor), lambda =
  `std::function<void(ServerConnection&,BinaryIStream&)>`; local
  create API `0x140F16030`; per-arg stream reads still open).
   Consumer side mapped Oct-11: `handleEntityPackedVolatileData`
   (`0x140E3D300`) preloads defaults, looks the entity up, invokes
   unpack slot +40 (`0x140E37200`), applies via `sub_140E3D070`;
   init array is 0x50-stride with class-level (not per-method)
   handler pairs; record-loop callers untraceable statically
   (virtual dispatch wall) but the callee family is complete Oct-11:
   packed/detailed/nonvolatile entries (`0x140E3D300/0x140E3CAF0/
   0x140E3D1F0` → `sub_140E3D070`, last arg = isVolatile) — the
   loop can only route 13B records into these three; creation takes
   the absolute unpack branch or the nonvolatile path. Apply step
   `sub_140E3D070` = `handleEntityMoveWithError` (skips spaceless
   moves). 0x35 = battle small-ID, NOT a method rank (Avatar 42
   client methods, Vehicle 11 — index 53 on neither; `[35 00]` is
   small framing, C++-consumed only). Large-function triage Oct-11: all four
   still undecompilable on a fresh worker; `EncryptionFilter::send`
   fully mapped from disasm (no-cipher drop, wastage math exact),
   `processFilteredPacket` dispatch order confirmed (1302 insns),
   property parser is `strtok`+Python-API driven (899 insns).
  counter-as-entity-ID tested same-session vs 0x45 tuples → 0/30
  overlap (0x45s are 3 poll-answer classes, not entity-indexed);
  body[0] vs wire-ID tested → 30 distinct in [32,247], excludes
  [0,40). Registration shape Oct-02 (bounded attempt):
  `sub_142AD7A30(iface, name, r8b=1, r9d=argc, arginfo)`; arginfo
  entries are Mercury dispatch machinery
  (`InputMessageHandlerT`, `ServerConnection&+BinaryIStream&`
  lambdas at `0x140E448E0+`), NOT per-arg readers — the arg stream
  layout needs dispatch-following RE from the lambda. Envelope-only
  verdict stands with new evidence
  (acked-only parity-sufficient for v1). 14.4 reference
  (`server_connection.cpp::createEntity`): `[EntityID u32][type]
  [pos][packedYPR][vehicleID][props]`, whole-message
  `CompressionIStream` (type byte 0–9) — our first bytes spread
  [32,247], ruling stock compression out for the WoT fork;
  head-vs-tail ID tested 0/30. +9 stride CLOSED Oct-11
  (cumulative: 28/28 flows3 burst datagrams show server seq AND
  tail counter both stepping +9/datagram with counter = seq − 8
  exactly — the counter is the server channel clock, not an
  entity-ID stride; +9/datagram is burst-mode seq consumption). Content exclusion (Oct-02): stock
  `CompressionIStream`/zlib ruled OUT (first bytes spread [32,247],
  no 78xx, zlib linked but never struck; only zlib strings in the
  image, no Oodle/LZ4/Snappy) — the fork packs these bodies
  differently (server-side packer, not in this image). The +9
  slope is now PROVEN server-seq consumption (see above), not a
  hypothesis.
  804B infos CLOSED Oct-02 (flows3-s2, fixed key): server_settings /
  feature-flags small (genuinely custom, NOT a bulk fragment: no
  chunk header, zero pickle docs ≥30B at any offset, 794B cleartext
  flags 0478): 23 identifier-shaped text runs (`TargetAreaEnabled`,
  `ab_feature_test`, `newbieHints*`, `isTankmanRestoreEnabled`,
  `xmpp_resource`, `xmpp_bosh_connections` + `woteu34` bosh host,
  `vehicle_post_progression_config`, `forbiddenVehicles`,
  `enabledFeatures`, `shells_consumables_switch`,
  `opt_dev_boosters_switch`…) + binary values, unknown-led framing.
  Session-dependent (Sep-17 only). That session's infos instead:
  84B account-info (flood-burst HEAD position in both
  S>C 84s; mixed framing suggests engine packing; lead:
  AccountVersion.def version-as-property), 124B XMPP endpoint list
  (consumer XmppServerSettings; `woteu34…` = bosh host element;
  `b8→bc` walk + `KP` marker likely C++ XmppClient framing, no .pyc
  parser),
  220B = tick + 1a76 session dict (156B STOP-truncated pickle,
  salvaged) + 1a79 redirect CLOSED Oct-02 (19 samples, 3 sessions:
  Sep-17 flows3 + Sep-29 + Oct-01): byte0 = IP-string length EXACT
  (11/12/13 all fit; the old 14-char misread withdrawn), port
  ALWAYS 32956, 13B trailer byte-constant
  (`687720000000000f0040771b00`, 19/19 across days) — magic, not
  routing info; the redirect pool is STABLE across Sep-17→Oct-01
  (83.229.15.109, 52.57.68.91, 63.182.9.216 recur) and Oct-14 adds
  in-window legs (stage-2s .212:32825/.213:32882/.215:32862+:32894,
  arenas .77:32815/.71:32811/.67:32810/.69:32815/.77:32811). Oct-14
  relay guard (same file: `parseRedirectAt` now skips targets outside
  32810-32999): battle blobs hold coincidental 44..000001 cores
  (34.160.176.0:4864/13312, 7.0.48.214:50116) that the relay followed
  into total blackholes, freezing then disconnecting two mid-battle
  sessions; fail-open now (game follows them direct, relay stays
  healthy). 1a76 session
  dict + 1a5c queue blob re-verified here.
  148B/84B end with a (98,25) carrier (28B: `[98][1900]` + 25B
  args; `BuildChatCommandFromClient` frames it, both vectors pinned
  byte-exact in `TestChatCommandFromClientVectors`). It is a 4th
  concatenated base call (A1 `0x98`), NOT engine framing — the old
  engine/channel-level attribution is retracted. Identity CLOSED
  Sep-29: Chat.chatCommandFromClient (codebook rank16 → 152;
  FALSIFIED on the way: updateVehicleDossiers (zero args),
  invitationAcceptOrDeclineInBattle (no callers), all 13 doCmd
  shapes, every Account component); no `self.base.*` caller in the
  sync subsystems (AccountSyncData/Shop/DossierCache emit bare
  doCmdInt3); no isolated S>C answer (84B draws only acks, 148B
  draws 860 + smalls-train).
  tails ride ONLY the two sync bundles (full-session scan: no
  other C>S carries `98 19 00`; byte0 01|02 = first|second sync
  bundle — 5-for-5 across sessions (lobby #2's 148/84 repeat 01/02
  byte-identical); subsystem-tag reading (dossier=01/shop=02) still
  unfalsified. Component hunt CLOSED (all 18 Account-attached
  component defs: no 25B base method; varlen fits fail;
  invitationAcceptOrDecline has no callers). Method codebook
  CLOSED Sep-29 (exe IDA, in-tree DB): BaseAppExt registration order
  (init array: 16 fixed 0..15, cellEntityMethod 16 portion 2 →
  cell [16,135], baseEntityMethod 136 portion 1 → base [136,254])
  gives wireID = 136 + exposedID; ranks are stable-size-sorted
  (fixed ascending, variable declaration order, interfaces-first
  with first-wins dedup — the own requestToken duplicate drops, the
  earlier base=135 read double-counted it). Verified 4-for-4:
  requestToken rank2→138, Int2 rank11→147, Int3 rank13→149,
  (98,25) rank16→152 = Chat.chatCommandFromClient, first
  variable-size base method (INT64,UINT8,INT32,INT64,INT16 + two
  packed-int strings; both tails parse exactly with empty strings:
  (1,22,0,0,0,"","") + (2,0,0,2,0,"","")). Micro-fit rerun with
  packed-int strings: only the rank-predicted method satisfies wire
  ID AND args (accountUnitClient_doCmd fits args alone at the wrong
  wire ID 0xA9). Command semantics CLOSED (shipped .pyc):
  (1,22,…) = requestLastSysMessages (service-channel backlog pull on
  LOBBY-scope switch), (2,0,0,2,0,…) = initAck for chat stream 2,
  decode OK (ClientChat.__baseChatCommand; ordinals in
  chat_shared.pyc). Builders in login/lobbycalls.go
  (BuildChatCommandFromClient, both vectors byte-exact in
  TestChatCommandFromClientVectors); Int4/Str A1 corrected to
  codebook tags (0x97/0x9b, game-unpinned). Opcode table (CHAT_COMMANDS
  ordinals, chat_shared.pyc): 0 initAck … 22 requestLastSysMessages …
  39 broadcast …; full table in the hunt report.
  SyncController.py audited: generic request/stream machinery, no
  literal base calls — owner not there either.
  Omitted from v1; last-36B CLOSED Sep-29 as `disconnectClient`:
  BaseAppExt table order in the exe strings (indices = wire IDs:
  …11 enableEntities, 12 restoreClientAck, 13 disconnectClient,
  14 heartbeat…) + end-of-session position (clean quit, acks-only
  after) + zero Python callers (C++ teardown path). Wire form
  `02[newkey] 0d 00 <u32 8|9>`: reason=0 plus a u32 that reads
  sends-minus-self in both sessions (9→8, 10→9; n=2, recorded not
  claimed). S>C 0x45 CLOSED (Sep 28,
  flows3 852B + Sep-27 860B vectors agree): `[00][221 u16
  LE][0x0e]` + STOP-less proto-2 `(int64,int64)` tuple, decodable
  with existing `DecodePrefix` (constant header across sessions).
  v1 omits Int4/Int2/wire00 (Int2 selects veh season — side
  effects; rest unknown).
  Bulk harvest CLOSED Sep-28 (per-chunk prefix salvage
  `HarvestChunks` + `wotflood -dump` table, flows3 40 chunks):
  nn=1 salvages 14673B/80 stack items/57 keys (top `oneof` 24) to its
  first noise site; nn=13 head carries the standalone session dict
  (`databaseID,token`, 42B); the other 38 chunks salvage to zero
  (prefix=1B, empty stack) — second-layer-or-pad confirmed per chunk,
  not per stream. Full-stream STOP-walk numbers are stale context,
  not signal.
  FIRED Oct-03 (first speak-back from our client, `-lobby` live):
  sync1 148B → token 36B → sync2 84B → 6 polls, 6/6 polls drew 36B
  answers ≤1 s; S>C census over 45 s: ticks + 116×92 entity burst +
  852 (sync answer) + 540/388 + 100/92/76/68/60/52/44/36 + offers
  (stayed put). Reliable-seq counter confirmed on the genuine Oct-01
  channel first (s2auth 0, sync1 1, token 2 ... — one counter, not
  the unreliable one). Speak-back is `-baseapp` DEFAULT since (no
  flag needed). FIRED Oct-03 v2 (opener +68B poll/token +84b):
  sync1/token/sync2a/poll68/sync2b/polls, exit 0; answers this
  session: 1244×2 (tick + 1a/5e pair + 237B 1a/5c queue blob with
  nested importantSeq/user_id/active/type/data pickle, then a
  session-dependent undecodable 0x46), 1108 (same 0x46 fate — ZERO
  validated anywhere, parity with genuine), 876 (req-226 0x45:
  our 84b Int3 works with zero-state args), 852 (req-221 0x45),
  676/868 opaque customs (no pickle, no text runs — parked like the
  116 bodies), 556 hints/flags pickle fragment (BattleHints/newbie/
  tutorial + xmpp/enabledFeatures vocabulary, 804B-infos family),
  188 session dict, polls mostly answered. Queue blob + 226-answer
  are new vs v1. Bulk shop-state from OUR OWN session decodes
  end-to-end (v2 recording: 1003×1252 over 16 s, NN 1..43, nn=1
  222KB salvage top=finishTime — same bundle family as genuine):
  typed assembly gives 2 offers (comp7 anniversary page), 3 mode
  configs, 8 slot charges — but 0 quests and no piggybank (genuine
  Oct-01 same-account had dq/wq legs: quest-sync trigger still
   open), plus the nn=8 session-dict head. v3 (genuine Oct-01
  Int2/Int3 values replayed: Int2(225,121,1746,2) +
  Int3(226,600,24,0x6abe9ee,0)): server answers "No such vehicle"
  (1a/5e text small) + no 324 — and a 3-run sweep programme
  (8 Int2 candidates/run: 1746 calibration + 339 + six browse
  refs, 3 s spacing, 324-attribution by 110 ms timing) drew zero
  324s across ~18 trials while every variant drew its 876-text +
  (once) an undecryptable 724 exactly +1.1 s later. Split-halves
  experiment (Int2-alone 52B + Int3-alone 60B): both silent — the
  pair is the stimulus. Select-then-ask (52B live-Challenger select
  + paired 84b): error persists — selection state is not the gate
  either. Baseline restored (zero-state paired 84b, no account
  guessing; genuine sync1/sync2a args kept for their explicit
  answers). Read: 225-Int2 selects ONE vehicle, so 324 is
  per-vehicle, not the garage; the missing family is the live
  arenaUID/battle-ref (Int3-b, 223-b, 1500-args), which only flows
  after real battles — next: record a play-a-battle proxy session
  and exhume fresh IDs. The garage list itself came from the LOCAL
  dossier_cache .dat instead (294 tanks) + live inventory mod
  (113 owned). Rot-key persistence (`stage2-rot.key`
  in dump mode) now arms offline second-layer probing of the
  724-class answers next time one lands. v3 also drew 1244×2 + 1068 (0x46 undecodable again),
  388 (session dict + 1a/5c premium queue blob), 588 hints/flags
  pickle (BINFLOAT-headed variant). Still open: 324 (live
  vehInvID), 223-answer, createBasePlayer carrier (unknown-led:
  868/676 + 116 opaque).
  116B entity tables (envelope closed, content opaque — needs engine
  pack tables or a live experiment, not more offline grinding: Oct-02
  flows3 re-proof (correct-key channel decrypt) — 88B bodies uniform
  4.8b entropy at EVERY position 0–83, concat 2464B H=7.85 no
  zlib/ASCII/magic, ECB-2nd-layer under 6 key forms H≈6.1 unstructured,
  all rotation/login-key chained forms fail; envelope-only verdict
  stands).
- EU2 wall CLOSED Oct-03 (see "Login — former blockades" item 1):
  the Sep-27 "moved" observation (p2 giving rotation+ticks like p5 but
  no redirect) was the same client-side auth1/victory-return pair, not
  a cross-cluster server gate.
- Archive captures as `captures/ours-p5-lobby-<date>.hex` + key file
  when a run is worth keeping.

## Potential todos (untouched game surface, Oct-02)

1. Event-mode entities in external `../wotdefs-2.4.0` (`white_tiger`,
   `fun_random`, `last_stand`, `comp7*`, `frontline`, `story_mode`,
   battle-royale `Loot`/`Mine`/`ThunderStrike`/`Placement`/
   `InfluenceZone`): data archaeology, zero live needs — DONE Oct-02:
   White Tiger = PvE boss raid (generator capture w/ miniboss block,
   boss health/shield/plasma/hyperion, respawns, teleporters,
   lightning, impact zones); Last Stand = wave survival (~30 buff
   components: nitro/invis/ignite/drain/stun/laser/souls, beams,
   phases, bot spawns); story = abilities (arty channel, recon,
   distraction, detection delay) + lootables; frontline = reserves/
   upgrades, stealth radar, regen kits, respawn; comp7 = ranked 7v7
   (role skills, vehicle ban voting + timers, prestige, inspire);
   BR entities = Loot (pickup ranges, PYTHON content, pickedUpBy),
   Mines (owner, deployTime, detonated), ThunderStrike (attacker,
   delay), Placement drops (team, yaw), InfluenceZone (DoT),
   Radio (`<Volatile><position/>` — bare engine builtin, confirming
   the task-1 model drop); Radar readiness + cone vision angles.
   FallTanks = evacuation state.
2. Client ballistics (`Avatar.pyc` `__projectileMover`, gravity/drag):
   static shell-flight model from shipped bytecode — DONE Oct-02:
   integrator is engine `BigWorld.PyBallisticsSimulator` (pure
   gravity `(0,-g,0)`, NO drag field anywhere; server-authoritative
   `collideWithSpaceBB`; client snaps to server snapshot beyond
   20 m); per-(gun,shell) `speed` 750–1000 m/s, `gravity` 9.81
   standard / 125–190 HE+howitzer plunging arcs / 0.8 meme (JP
   12cm Funshinhou) / 8.81 story-mode, `maxDistance` 720 (10000
   arty); visuals hidden-model + tracers, own-shot autoscale ≤180 m,
   arty via `PySalvo`, hide/explode/hold lifecycle.
3. Telemetry census (`aogas…`, `collectUiStats` senders): what the
   game phones home (`.pyc` + captures) — DONE Oct-02 (see
   `../docs/NETWORK_PROTOCOL.md` §15): in-band UX events (7 subsystems ×
   ~35 types incl. keyDown/Up, 70/batch, ≤70/session, engine
   `logUXEvents`, server-gated); aogas = playtime-control;
   HTTP bootstrap mapped (CSIS, WebCache, Vivox, dcont, RSS).
4. Vehicle compDescr (10304 battle doc + `vehTypeCompDescr` blobs):
   tank descriptor format; unlocks dossier/vehicle parsing — DONE
   Oct-02: full layout from shipped `items/vehicles.pyc`
   (`_split/_combine`, `makeCompactDescr`, `parseIntCompactDescr`)
   in `lobby/vehicle.go` (table-free sectioning + int-head reader,
   synthetic writer-mirror round-trip green): header
   (type lo4=1|nation hi4|+2 ext), typeID, components (8B + 4B/turret),
   flags (optdev mask|16 enh|32 emb|64 skip|128 camo), optdev u16s,
   enh 6B, emb 6B/inscr 7B, camo tail; nations ussr0..italy10;
   `vehTypeCompDescr` ≡ compactDescr (dossier `utils` parses via
   `parseIntCompactDescr`); ext IDs never live (per-nation <255,
   shipped compares lo4==1 verbatim); camo tail length-less (absorbs
   truncation by design). Wire proof: 69B blob in Sep-29 S>C smalls
   sections t=2 clean (carrier 1a/ba is framing-real in lobby —
   parser-accepted len8; the battle 1a-ba appearance stays misparse,
   different domain); 5× 89B tankman blobs (type 8) correctly
   rejected; trawl 38 candidates. Open: component-ID resolution
   against vehicle XML tables.
   Resolution DONE Oct-02 (`lobby/vehicle_table.go` + `vehicle_load.go`,
   synthetic green): `ComponentTable`/`StaticTable`/`ResolveCompactDescr`
   over unpacked item_defs (11 nations, 1252 vehicles, turret counts
   from `<turrets0>` definitions — bare `<turret>` tags are position
   vectors, `<turret>/<gun>` wrappers carry names as text); unknown
   IDs fail loud. Real-tree validation: all turret names resolve in
   nation ids tables. Wire cross-check anomaly (open): the single 69B
   blob sections t=2 but its table row says 1 turret — mode roster,
   battle-mode descr, or arithmetic coincidence; needs a second blob
   to decide.
5. Token anatomy (`token`/`token2`/`session` structures) — DONE
   Oct-02 (offline, shapes only, see `../docs/WGC.md` §6): token2 =
   `{9-digit accountID}:{18–19-digit middle}:{39-digit tail}` all
   numeric (9 samples, 4 families); middle uniform-random-looking,
   NOT a standard session-md5 transform (needs `-middle-out`
   blob pairs live); `token` = 8 digits; 12-key login census pinned.
6. Battle-results answers (852B `CMD_REQ_BATTLE_RESULTS` replies):
   straight pickle decode from captures on hand — DONE Oct-02 (see
   `../docs/NETWORK_PROTOCOL.md` §17): full cache mechanism from shipped
   `.pyc`, 0x45 `[len][req BE][res=RES_SUCCESS][extlen][ext pickle
   tuple]` on 4 live answers (varying byte proven to be ext length,
   not status), stream inside the 852's own train (63-list +
   arenaUID pickle + roster), 1500/1501 linkage + direct-base A1
   flavor; Meta checksum CLOSED Oct-11 (263845007 = REGULAR SELF,
   BP-integrated, reproduced by real py2.7 config execution) with
   the full 62-name map in `../docs/NETWORK_PROTOCOL.md` §17;
   consumer synthesis CLOSED Oct-14 (2.4.1.0 live run, 156 logger
   lines in game.log — hooks armed for onCmdResponse/onCmdResponseExt/
   _subscribeForStream; BattleResultsCache/SyncController hook paths
   need 2.4.1.0 module names): res=1 always subscribes (221/223/228/
   232/233/234), res=2 never (222), res=0 empty acks, res=-10 failures
   (226 'Not found'); battle-852s pair to onCmdResponse(req,1)+
   subscribe 2 ms after S>C (233 post-b2, 234 next session); C>S pulls
   decoded as Port-routed `doCmdInt3(req, 1500, arenaUID u64, 0, 0)`
   (req allocator-derived, NOT 227 — that was one session's req) with
   live arenaUIDs `0xf29ccf6a14590120`/`0x200195996acfa588`, then
   `doCmdInt3(202, 1501, arenaUID, 0, 0)` received-ack; 226 dual fate
   (Ext str[113] vs -10) and 230's 22 KB ext string observed live;
   open: tuple second-elem semantics, stream-chunk framing past the
   852, res=0-wire vs res=1-consumer mapping in the C++ dispatcher.
7. XMPP/bosh chat beyond the tails (gated on HTTP flows, maybe in
   `eu2-mitmproxy-flows`) — DONE Oct-02 (see `../docs/NETWORK_PROTOCOL.md`
   §16): TCP-first/BOSH-fallback, JID = DBID@domain/resource,
   XMPPCS token login, disconnects reported to server; 124B list
   proven bosh-only on lobby-#2 wire (per-flow key recovery);
   distinct layer from the (98,25) BaseApp tails. Oct-11: gloox-static
   stack confirmed (`WGXmppClient` type init mapped); settings contract
   decoded (`update()` dict + randomized 2-sample iterator); C++ key
   strings absent — dict comes from pickled smalls, b8→bc/KP walk
   stays with the binary infos framing. IDA naming pass Oct-11: 52
   verified functions renamed (`BW_*`, saved to
   `WorldOfTanks.exe.i64`) — unpacker/Bundle/crypto/replay/XMPP
   clusters now labeled.
8. FairPlay surface (observed-data-shapes only — dual-use adjacent) —
   DONE Oct-02: 6 def components (5 empty shells; Account
   `setupArena(config: PYTHON)` opaque cell-side; Avatar
   `showWarningMessage(STRING)` server→client push with no Python
   consumer = engine-side dialog); battle-results carry
   `fairplayViolations` (warnings/penalties/violations masks [+
   percent]) → BAN/PENALTY/WARNING ladder (+banDuration, AFK flag);
   catalog `scripts/item_defs/fairplay_violation_types.xml` (11
   violations × DESERTER/SUICIDE/AFK, masks 1<<xml-order, per-mode
   + NO_WARNING variants; BR excluded from arena bonuses);
   `ArenaFairplayKafkaLoggingComponent` is server-side only (zero
   kafka strings client-side or in exe). No detection internals
   touched.
