# World of Tanks EU — Connection / Login Networking Protocol

Scope: **connection only** — from launcher to lobby. Not in-game (avatarUpdate, cell), not matchmaking queues. Static analysis + live-client replay + IDA headless decompilation.

## 0. Which build

**The build the private server serves is EU 2.4.1.1 (#993)** — the live Steam
install under `~/.local/share/Steam/steamapps/common/World of Tanks/eu`. Its
defs (entity, component, alias, item) are the 2.4.1 ones: entity defs from
`../scripts-2.4.1/entity_defs` (extracted from the live `scripts.pkg`;
`Vehicle.def` is byte-identical in 2.4.1.0 and 2.4.1.1), everything else read
straight out of the live `res/packages/scripts.pkg`. See
`PRIVATE_SERVER.md` § "Client build: 2.4.1.1".

Every **2.4.0** reference below is the *capture* material this document was
written from (2.4.0.0 #944, Sep–Oct 2026 captures, the 2.4.0.0 binary in
`../World_of_Tanks_EU/2.4.0.0`). The wire shapes in §§3–19 are the same in
2.4.1 — the protocol bytes are identical (`05 00 01 11`) and the 2.4.1 flood
round-trips through the same codec — but the *defs* are not: a table generated
from the 2.4.0 tree is rejected by a 2.4.1 client (`PUBLIC_VEHICLE_INFO.index`
is one byte wider, and item-def compact descriptors differ).

## 1. Materials and method

* Client: `../World_of_Tanks_EU/` **v2.4.0.0 #944, EU, branch v2.4** (`version.xml`, `game_info.xml` `WOT.EU.PRODUCTION 2.4.0.5437`). Binary `win64/WorldOfTanks.exe` 76 MB, PE32+ x64.
* Decompiled snapshots: `../WoT Decompiled/WorldOfTanks-Decompiled/` = **RU 1.44.0.0 #2253**; `../WoT Decompiled/WorldOfTanks-Decompiled_EU/` = **EU 1.27.1.0 #601 (`1.27.1_EU`)**, neither is EU 2.4. EU 1.27.1 `connection_mgr.py` matches RU 1.44 wire logic (`BASIC`/`TOKEN`/`TOKEN2`, same `LOGIN_STATUS`); only diffs are `version_utils` → `account_shared.isValidClientVersion` and dev-gated logging. Useful for `connection_mgr.py` / `predefined_hosts.py` logic, misleading for wire version numbers.
* Engines: `../BigWorld/BigWorld-Engine-1.9.1` (2008 leak, WoT fork base), `../BigWorld/BigWorld-Engine-2.0.1` (classic reference used below), `../BigWorld/BigWorld-Engine-14.4.1` OSE (closest to modern WoT fork: same `programming/shared_libs/connection/*`, `network/*`, `CuckooCycleLoginChallenge`).
* Captures: `../captures/wot_EU1_connection.pcapng` 1526 pkts, `../captures/wot_server_ping.pcapng` 39 pkts, both Oct 2022; `../captures/login.pcapng` + `../captures/login2.pcapng`, genuine 2.4.0 typed-creds logins (Sep 2026, LoginApp + BaseApp entry). Dissected with `scapy`.
* Proxy ground truth: `../captures/wotproxy.log` + `../captures/wotproxy.hex` — game client via `wotproxy.exe` to `login.p2:20016` (Sep 2026): 10 ping pairs, one invalid-creds login (ends status 68) and one valid login (ends status 1). Pinned as Go test vectors (`TestParseChallengeReply24`, `TestParseErrorReply68`, `TestChallengeResponseMatchesGenuine`). Later proxy dumps: `../captures/dump.hex`, `../captures/dump2.hex` (ping sweeps).
* Full sessions: `../captures/eu2-mitmproxy-flows` — mitmproxy save, 27 flows (18 UDP, 8 HTTP decrypted, 1 TCP): EU2 login → two-stage BaseApp → 30 s lobby on `92.223.20.215`, ping/probe sweeps, CSIS/RSS/WGC-cache/Vivox/wgcdn HTTPS, XMPP chat. See §12. Later sessions: `../captures/flows` (55 flows: wrong-then-right login on `.213`, stage-1 on `.213:32826`, 218 s lobby on `.215:32910`, p5/EU5 login → stage-1 on `:32819` → 20 s lobby on `:32832`) and `../captures/flows2` (125 flows: several EU2 logins on `.215/.213/.212`, stage-1 on `:32918`, 33 s lobby on `:32914`).
* Client ground truth: `../captures/CE.txt` — the game's actual LogOnParams username JSON (typed basic login): keys SORTED with `json.dumps` default separators, `temporary="1"`, `session` = md5, `auth_realm` = EU present. This killed a wrong py2.7-hash-order simulation; `wotlogin` now emits sorted+spaced.
* IDA: headless sessions on `../World_of_Tanks_EU/win64/WorldOfTanks.exe` (base `0x140000000`; string-xref driven, only 1466/217389 funcs named; see §10).
* Live client: the `wot/` Go client replays the full handshake against EU production (Sep 2026): login#1/#2 framing, PoW solve, challenge retry, `LOGGED_ON`, Blowfish session decrypt — all confirmed. Ground-truth entity digest read from the running client via `../mods/digest-dumper-mod/` (in-game mod printing `BigWorld.digest`, Python 2.7, `res_mods/2.4.0.0/scripts/client/gui/mods/`). Current wall: the server ignores our BaseApp handshake (`[no-reply x4]`); basic sessions are lobby-dead, token2 login is the open path (see §7, §11).

## 2. Big picture

```
WGC launcher --(empty params, token via live WGC IPC, never cmdline/files)--> WoT client
  --UDP 20016--> LoginApp (185.12.240.75:20016 in pcap)
WGC IPC, reversed Sep 20 (IDA `WorldOfTanks.exe` = live sha1
`11e4ac11…`, so addresses are current): the game
`LoadLibraryW(wgc_api.dll)` (4 candidate paths;
`win64/wgc_api.dll` ships, 2.4 MB) →
`GetProcAddress(WGCApiCreateInstance/WGCApiGetResultDescription)` →
COM-style instance (`sub_1424BE140`); Python `WGC.loginData()` builds
the login dict from the instance cache (`sub_1424C11D0` ←
`sub_1424BE550`/`sub_1424C0960`). Transport is named pipe
`\\.\pipe\WgIpcPipe` to the running `wgc.exe` (client
`WaitNamedPipeA`/`PeekNamedPipe` imports; `wgc_api.dll` exports the
SpaToken API: `SaveSpaToken2`/`LoadSpaToken2`/`QuerySpaToken1`).
No token ever touches disk-plaintext/prefs/cmdline/registry — purely
live local IPC, SSO session in WGC. Standalone (no WGC process):
`Can not load API library` → basic path. Consequence: WGC tokens are
architecturally out of reach from Linux (needs Windows + live WGC SSO
per login); token2 tails also die on re-presentation
(`Invalid token2` both clusters).
    <--challenge cuckoo_cycle--> solve PoW
    <-- Blowfish(sessionKey, serverAddr BaseApp) --
  --UDP ephemeral--> BaseApp (185.12.240.66:32814 in pcap)
    --authenticate(sessionKey)--> lobby download (~75 KB burst)
  --UDP 20016--> Pinger (185.12.240.61, 92.223.x.x, 83.229.x.x)
```

Pcap proof:

* `192.168.1.43.61860 > 185.12.240.75.20016` 2 pkts, reverse 2 pkts = **only 4 LoginApp packets**.
* `192.168.1.43.61860 <-> 185.12.240.66.32814` 767+755 = **1522 BaseApp packets**.
* BaseApp sizes: `28:958, 1252:407, 76:36, 1244:22, 68:22, 52:21, 44:20`. Login sizes: `534,55,728,184` exactly.

Python entry (`../WoT Decompiled/WorldOfTanks-Decompiled/source/res/scripts/client/connection_mgr.py`):

`initiateConnection(params,password,serverName)` → `__setConnectionData` (`auth_method basic|token|token2`, wire `session` = md5hex of the stored session BLOB TEXT — the base64 DPAPI ASCII, NOT the decrypted GUID; proven Sep 2026 by a 10-variant sweep against `../captures/CE.txt`, `username=json.dumps(params)`, `password=pwd_token.generate(password)` or `''` if `token2`, `clientContext={lang_id,publication}`, `publicKeyPath=host.keyPath`) → `BigWorld.connect(url, connectionData, responseHandler)` → stages, `LOGGED_ON`, `LOGIN_REJECTED_RATE_LIMITED` retry. `predefined_hosts.py`: `BigWorld.Pinger.ping(peripheries)`, `BigWorld.serverDiscovery.servers`. Token2 notes (verified in 2.4.0 `connection_mgr.pyc` bytecode as well as 1.27.1 source): the client NEVER re-logs — `__swtichToToken2` only rewrites the *stored* username JSON (pop `token`, set `token2`/`auth_method`) for future connects; the current session proceeds straight to `onConnected`/BaseApp. And with a stored WGC `token2` preference even typed-creds logins go out as `auth_method=token2` (`gui/login/manager.py:91-105`); pure basic is the no-token fallback. Live result Sep 2026: our complete basic sessions (`LOGGED_ON`, valid decrypt) get BaseApp silence while the genuine client's basic sessions enter the lobby — our bug, downstream of login (see §7, §11).
* Auth is purely UDP: full working EU2/EU5 logins (mitmproxy, §12) show NO credential/token HTTP — just CSIS status, ping sweeps, then the 534 B login. Basic → lobby is PROVEN by those captures (attempt #1 with wrong creds failed `68 ... for basic authentication`, so no token2 was in play; attempt #2 seconds later in the same process must also have been basic — and it reached the lobby; verified against every token2-fallback scenario). Sizes are identical by construction (fixed 512 B RSA for any plaintext ≤ 428 B), so size can't tell auth methods apart — and the old "basic is lobby-dead" theory is withdrawn: our client's failure is downstream of `LOGGED_ON`.
* Clusters differ in talkativeness: p5/AWS managers answer with `reply{newkey}` + heartbeats but never switch us; p2/EU2 managers were silent at our 22B. That silence was OUR bug, not a cluster gate — CLOSED Oct-03 (§7): the park was a wrong stage-1 auth1 shape plus a missing stage-2 victory return, and EU2 now logs in single-shot. The GAME always reached the lobby on EU2 and EU5 alike.
* BaseApp entry is two-stage (EU2 flows 9–10): the 22 B handshake first goes to a negotiation port (`:32848`, 14 small encrypted msgs in 0.2 s), then a FRESH 22 B to the game port (`:32816`), where the lobby flood arrives (440× 1252 B over 30 s). The two handshakes carry DIFFERENT cleartext session keys (`ebef84e6` → `fb6289e6`) and ReplyIDs — so stage 1 issues a redirect + new credentials inside its encrypted exchange. The 2022 pcap's single `:32814` stream is the same shape collapsed (767+755 pkts).
* Server selection / AUTO (decompiled `predefined_hosts.py` + unpacked
  `scripts_config.xml`, Sep 27): five LoginApps EU1–EU5
  (`login.p1..p5.worldoftanks.eu:20016`, periphery IDs 201–205) plus
  `csisUrl http://csis.worldoftanks.eu/csis/woteu/`. AUTO is not
  lowest-ping: `autoLoginQuery` fires the 16 B ping sweep AND a CSIS
  HTTP query in parallel, prefers CSIS-RECOMMENDED peripheries, falls
  back to ping-only, keeps candidates within 1.2× of best ping, then
  picks RANDOMLY among survivors (cached for the session). Our
  `-host` flag is a manual override of exactly this vote.

## 3. UDP transport (IDA-confirmed)

All connection traffic is UDP (`sendto`/`recvfrom`/`WSASend`/`WSARecvFrom` imports; `PacketSender::basicSendSingleTry` `sub_142AFAB00` passes the packet buffer straight to `sendto` — **no prefix is added at send time**).

Wire per datagram (WoT fork):

```
0..3  prefix (4 B, random per packet — NOT a sequence; see below)
4..5  Mercury flags (2 B, LITTLE-endian; classic BigWorld was BE/NTOHS)
6..   Mercury bundle (messages) + footers
```

Proven by disassembly (all addresses for `WorldOfTanks.exe` 2.4.0, base `0x140000000`):
- Receiver `PacketReceiver::processFilteredPacket` (`sub_142AF86E0`, 0x16b4 B) reads flags as `movzx eax, word ptr [rbx+90h]` — struct+0x90.
- Sender `basicSendSingleTry` uses `buf = rbx+0x90` or `rbx+0x8C`, `len = [rbx+30h]+[rbx+34h] (+4)`, gated on byte `[rbx+88h]` (`neg al; sbb; and 4` idiom, mirrored on receive at `0x142af8b8e`). So `data_` starts at struct+0x8C, the 4 B prefix sits at `data_[0..3]`, and **flags live at `data_+4` (struct+0x90)**. `msgEndOffset`=[0x30], `footerSize`=[0x34], channel timestamp=[0x7C], indexed id/ver=[0x68]/[0x6C].
- Classic flag bits kept for 0–10 (`ON_CHANNEL` tested via `shr al,3`, `CREATE_CHANNEL` via `shr ax,9`, `INDEXED_CHANNEL` via `shr al,7`); **new bit 11 = `0x0800` channel-timestamp** (`shr ax,11` in `Packet::stripChannelTimestamp`, `sub_142AF3420`: needs `msgEnd>=6`, `msgEnd-=4`, reads U32 timestamp footer). Unknown-bits mask is now `0xFFFFE000` (was `KNOWN_FLAGS 0x07FF`), i.e. 13 known bits.
- The prefix is written during bundle prepare (before `basicSendSingleTry`, which only forwards the buffer) into the filter-spare region; on receive it is accounted by the same `[0x88]`-gated ±4. It stays **in cleartext even on Blowfish packets** (EU2 lobby flow: every post-handshake size ≡ 4 mod 8 in both directions — cipher covers flags+body+footers only; our `decryptBlowfish(data[4:])` offset confirmed).
- Prefix content (Sep 2026, ~200 pre-login datagrams + 1500 channel datagrams): on the encrypted channel all 4 bytes are uniform-random per packet. On pre-login LoginApp requests byte 0 = random base (low 7 bits, constant per socket/burst: `0x34`, `0x5d`, `0x65`, `0x7a`…) with the top bit = ReplyID parity (`63/63` for id-00/02; the id-01 probe uses the INVERSE, `150/150` — different code path). Server simple replies (ping) use base `0x1f` and echo the request's top bit; app-level replies vary (`0x1f`, `0x61`). No server enforces any of this (random prefixes accepted everywhere) — cosmetic, mechanism unknown.
- Channel footers (fork 14.4 source + live verification): `FLAG_HAS_CUMULATIVE_ACK = 0x0400`; wire order at packet end is `[seq u32][cumul u32]` (the receiver strips cumul first, i.e. cumul sits LAST — 14.4 `packet_receiver.cpp`: cumul strip ~763 runs before seq strip ~902; `SeqNum` = u32). Our channel flags `0x0458` = ON_CHANNEL|RELIABLE|SEQ|CUMUL. Server seqs increment per packet (observed 0→771 over a session); server cumul counts our received packets (0,1,2… per 22B/ACK — receipt counting, NOT processing proof!). Pure-ACK packet = flags + cumul + seq + magic/wastage = 20 B; with the 5B `authenticate` app message = 28 B exactly (genuine post-reply size).
- **Footer length is additive over the flag bits** (settles the old
  `12B if 0x20 else 8B` heuristic; `login.ChannelTrailerLen`). The fork
  re-assigns two classic bits: **`0x0010` = RELIABLE** (not
  HAS_SEQUENCE) and **`0x0040` = HAS_SEQUENCE** — forced by the two
  pinned stage-1 shapes (`0x0458` = ON|REL|SEQ|CUMUL, `0x1448` =
  ON|SEQ|CUMUL|AUX). Contributions: `0x0040`→4, `0x0400`→4,
  `0x1000`→4 (the unreliable aux word), `0x0020`→8 (request/reply
  pair). Verified against every flags word in the Oct-31 EU2 battle
  capture (2806 S>C + 216 C>S datagrams, by channel-seq monotonicity
  and an independent message walk):

  | flags | trailer | composition |
  |---|---|---|
  | `0x0458` | 8 | ON\|REL\|SEQ\|CUMUL |
  | `0x1448` | 12 | ON\|SEQ\|CUMUL\|AUX |
  | `0x0078` | 12 | ON\|REL\|SEQ\|REQ |
  | `0x0478` | 16 | ON\|REL\|SEQ\|REQ\|CUMUL |
  | `0x0058` | 4 | ON\|REL\|SEQ |
  | `0x045a` | 8 | ON\|REL\|SEQ\|CUMUL\|`0x02` |
  | `0x144c` | 12 | ON\|SEQ\|CUMUL\|AUX\|`0x04` |

  The old rule matched only `0x0458`/`0x0078`/`0x045a`: it
  under-counted `0x0478` by 4 B, over-counted `0x0058` by 4 B and
  under-counted `0x1448`/`0x144c` by 4 B. **Intra-trailer order is
  still only partly pinned**: the seq word is the LAST word on S>C
  datagrams (`0x0458`/`0x0078`/`0x0478` all share one monotone
  counter) but the SECOND-to-last on C>S `0x0458`, where the last word
  is the cumul. The `0x0020` pair reads `[1][203]` on the dominant
  S>C shapes (`203` = `REQUEST_ID_NON_CLIENT`), i.e. it sits before
  seq/cumul, matching BigWorld writing requests before the channel
  footers.
## 4. Mercury bundle / message (IDA-confirmed)

- Bundle codec, message level (Oct-11 IDA, same image — `Bundle@Mercury` vtable `0x143930A00`, `UDPBundle` vtable `0x14392B540`, all 12 slots identified): length-format lookup `sub_142AE7920` (desc byte[1]==0 → 1B header, ==1 → `*(u32)+1`, else assert `newMessage: unknown length format`, `udp_bundle.cpp:853`); `newMessage` (`0x142AD4660`, 74 insns) reserves header+extra at the cursor and records msgID (`+0xAC`) and expected end (`+0xB8`); `startMessage` (`0x142AD5190`) with extra=0; `startRequest` (`0x142AD5340`, 93 insns) with extra=**6** (ReplyID u32 + nextOff u16 — confirms the `login.go` reservation comment verbatim), message-kind enum (`3` = reliable), non-default-timeout log (default `0x4C4B40` = 5 s), outstanding-request tracking (0x20B records), `HAS_REQUESTS` bit set; `startReply` (`0x142AD52B0`) with a 24B const descriptor + 4B reply-ID reservation; `doFinalise` (`0x142AD4460`, 46 insns) asserts cursor accounting (`finalise: data not part of message found at end of bundle!`, `:394`) — every builder byte must belong to the message, which is why genuine sizes are exact; size walk (`0x142AD4FB0`). `endMessage` (`0x142AD4530`, 39 insns): backpatches the VARIABLE length via `sub_142AE7390` (reserve-then-fill — newMessage reserves, endMessage fills), accumulates `+0xA8`, resets cursor/descriptor, and on channel bundles does reliable-send bookkeeping (`sub_142AD40C0`). Remaining UDPBundle slots: dtor (`0x142AD3EB0`), reserve (`0x142AD4F20`, cursor = buf+144), append (`0x142AD3FC0`, chunked `memcpy` with the same space rule), size walk (`0x142AD4FB0`), init/reset (`0x142AD4180`, default descriptor via the same `0x142AE7160` record builder as interface registration), free-space query (`0x142AD45F0`, avail−35, −39 when filtered), list accessor (`0x142AD47B0`), length-format query (`0x142AD4630`). `DeferredBundle` vtable `0x14392CFD8` fully mapped (the RetryingRequest queue): dtor, two timer-query one-liners, three enqueue flavors (explicit descriptor `0x142ADCCF0`, full-args `0x142ADCF30`, const-descriptor `0x142ADCE10` — all queue 0x50B nodes with 5,000,000 µs default timeout, matching `startRequest`'s `0x4C4B40`), reset (`0x142ADCBB0`, news the 0x40 MemoryOStream), send-hook fixup (`0x142ADCC90`). `FragmentedBundle` located (duplicate-suppression + mangled-footer asserts) with methods open.


Interface registration thunks decompiled (`sub_142AD7A30(table, name, style, param)` = `InterfaceElement` ctor). Full `LoginInterface` table (`&unk_1442DDD40`):

| message | style | len bytes | global |
|---|---|---|---|
| `login` | 1 VARIABLE | 2 | `qword_144858110` (`sub_1402425E0`) |
| `ping` | 0 FIXED | 1 (fixed) | `qword_144858120` (`sub_140242660`) |
| `probe` | 0 FIXED | 0 (empty) | `qword_144858118` (`sub_1402426A0`) |
| `challengeResponse` | 1 VARIABLE | 2 | `qword_144858128` (`sub_140242570`) |
| `mtuProbe` | 1 VARIABLE | 2 | `qword_144858130` (`sub_140242620`) |

Wire IDs (proven by pcap ID bytes + header declaration order): **`login=0, probe=1, ping=2, challengeResponse=3, mtuProbe=4`**. The WGPinger therefore speaks the SAME `LoginInterface` (fixed-1 B `ping`), not a separate protocol — §8 rewritten accordingly. (`sub_1402425B0` pre-sizes the interface table to 256.)

* Normal: `[ID:1][len:2 LE][payload:len]` (variable) or `[ID:1][payload:fixed]` (fixed).
* Reply: `[0xFF:1][len:4 LE][ReplyID:4 LE][payload...]`.
* Request: payload starts `[ReplyID:4 LE][nextRequestOffset:2 LE][args...]` (`Bundle::startRequest` reserves 6 B; `firstRequestOffset` footer = packet-relative offset incl. 2 B flags: `02 00`=2 for single-request, `c4 00`=196 for the 2-message packet pointing at the login message).
* Receiver strip order (from `processFilteredPacket` call sequence): `validateChecksum` (`sub_142AF3680`) → piggybacks (`sub_142AF3070`) → **channel timestamp** (`sub_142AF3420`) → indexed/cumulative/acks/seq/reliable → requests+dispatch (`sub_142AF6E40` area).

Interface string tables, in registration order (Oct-11 IDA, `0x14368CAA8` region — wire IDs follow table order): `BaseAppExtInterface`: baseAppLogin=0, pingDatacenter=1, authenticate=2, avatarUpdateImplicit, avatarUpdateExplicit, ackPhysicsCorrection, requestEntityUpdate, nrlMsgToCell, avatarUpdateWardImplicit, avatarUpdateWardExplicit, ackWardPhysicsCorrection, enableEntities=11, restoreClientAck=12, disconnectClient=13, clientToServerHeartbeat=14, sendToCell=15 (matches the Sep-29 codebook ranks independently); `CellAppExtInterface`: cellAppLogin, runExposedMethod; `ClientInterface`: bandwidthNotification, updateFrequencyNotification, setGameTime, resetEntities, createBasePlayer=4, createCellPlayer, dummyPacket, spaceProperty, addSpaceGeometryMapping, removeSpaceGeometryMapping, createEntity=10, createEntityDetailed, cellAppSuspended, cellAppResumed, clientSuspensionDetectionEnabled, enterAoI, enterAoIOnVehicle, leaveAoI, tickSync, tickSyncPeriodic=19, relativePositionReference, relativePosition, setVehicle, selectAliasedEntity, selectEntity, selectPlayerEntity, forcedPosition, avatarUpdateNoAliasDetailed, avatarUpdateAliasDetailed, avatarUpdatePlayerDetailed, avatarUpdateVolatileProperties, changeVolatilePackerType, nrl*, then the avatarUpdate{NoAlias,Alias}{FullPos,OnGround,NoPos}{YawPitchRoll,...,NoDir} matrix (the S>C per-entity update family). (`Connection` inside the table is a non-method entry — excluded from ranking; 0/1/2 and 4/10/19 anchors all match.) Consequences: C>S own-position = avatarUpdateImplicit/Explicit (LE floats, cf. `ParseAvatarUpdate`); S>C owns avatarUpdateVolatileProperties (not C>S); `0x35` is below every table (ClientInterface ends ~50) — battle small-ID framing, not a method rank.

## 5. LoginApp handshake — packet walk

`LoginInterface` (14.4, also WoT): `login(ID 0)`, `probe(ID 1)`, `challengeResponse(ID 2 in 14.4, ID 3 on wire in 2022 pcap — WoT inserted one message)`.

### 5.1 C→S login #1 — 534 B

```
IP 192.168.1.43.61860 > 185.12.240.75.20016, UDP payload 534
b0 10 9f 51 | 01 00 | 00 05 02 | d8 67 01 00 00 00 03 00 01 11 01 a6... (511 B) | 1d 2b e1 8c e6 8b 02 00
prefix      | flags | ID=0 len=517 LE | ReplyID=92120 NextOff=0 version+cipher | footers (reqOff=2)
```

* `ReplyID d8 67 01 00 LE = 92120`, `nextRequestOffset 00 00` (single request, last), then `03 00 01 11` = `ClientServerProtocolVersion`. **IDA settles the field order**: `LoginAppLoginRequestProtocol::addRequestDataToStream` (`sub_140E6C650`) writes the four bytes one at a time as `5, 0, 1, 17`, matching 14.4 `writeToStream` order `sub,patch,minor,major`. So the current 2.4.0 binary speaks **protocol 17.1.0.5**; the 2022 pcap spoke **17.1.0.3**. Only the subpatch bumped.
* Next 1 B `01` = `LogOnParams::HAS_ALL`.
* Rest ~506 B = RSA-OAEP ciphertext (see §6). Two logins have same plaintext but different ciphertext (OAEP random) — pkt0 starts `a6 2c...`, retry starts `65 5e...`. **Anomaly (historical)**: `len 517` with a 506 B cipher is 6 short of 2×256 B RSA blocks. The fork's `LogOnParams::addToStreamInternal` is since decompiled (`sub_140E6E210`: flags + 4 strings + digest + nonce, single-RSA path via `sub_140E6E100`) and fits the current 512 B shape exactly — so the 2022 blob came from a different code path/key era. Left as is.
* Fresh Sep 2026 data point: the 278/472 B shape was OUR client's bug (missing LogOnParams fields, see §6) — the genuine 2.4.0 client sends **534/728 B** even for typed-creds   logins (`../captures/login.pcapng` idx 912/914, `../captures/login2.pcapng` idx 1016/1018: login#1 len 517 = 4+1+512, i.e. two whole RSA-2048 blocks). The extra cleartext vs our old build is the username JSON's `temporary`+`publication` keys and the two-key `clientContext` (§6). Standard RSA-2048 chunking holds on the current path; the 2022 506 B shape remains unexplained (different code path/key era).

Modern sender (`14.4/.../loginapp_login_request_protocol.cpp::sendRequest`): optional `challengeResponse` (unreliable) + `startRequest(login)` + `addRequestDataToStream: bundle << currentVersion << LogOnParams(RSA)`, `transport.sendBundle(..., offChannel=false)`. Plus `addMTUProbeToBundle` if small.

### 5.2 S→C challenge — 55 B

```
9f 3d 11 7b | 00 00 | ff 2c 00 00 00 | d8 67 01 00 42 0c cuckoo_cycle 11 fca223380bde7178: cc cc 08 00 00 00 00 00
prefix       | flags | reply len=44    | ReplyID=92120 status type prefix maxNonce
```

* `ReplyID` matches request. No footers (flags 0).
* `42` = 66 = `LOGIN_CHALLENGE_ISSUED` (enum: `NOT_SET 0, LOGGED_ON 1, ... PUBLIC_KEY 8, MALFORMED 64, BAD_VERSION 65, CHALLENGE_ISSUED 66` from `log_on_status.hpp`).
* `0c`=12 `"cuckoo_cycle"`, `11`=17 = 16-hex server prefix + `:` (e.g. `39e832d014cceb66:`, `c06312fa01294c54:`, `4e87d1c03cfb81e2:` — fresh per login), then `maxNonce` 8 B LE directly (`cccc080000000000` = 576716; the leading `cc` bytes ARE the number, not a separator). No easiness field on the wire — `SIZE=1<<20=1048576` is compiled in (`SIZESHIFT 20`), easiness is `maxNonce/SIZE` server-side (`CuckooCycleLoginChallenge::writeChallengeToStream: data << prefix_ << maxNonce_`).
* Solve-speed mystery CLOSED (Sep 2026, proxy + mitmproxy): the client genuinely solves in **38–214 ms** — the login#2 response carries a float `challengeCalculationDuration` (0.0380 s, 0.0941 s, 0.2136 s observed) matching the challenge→response gap. No pre-solve; the C++ solver is just fast. Our Go solver (rewritten: the old N-overlapping-scan race was pure overhead — the simple miner needs the whole edge set in one table, so extra threads only burned CPU; profile showed `recoverNonces` map+allocs+re-scan eating ~70%) now runs single scans (~50 ms, uint32 table, array recovery bounded to the just-inserted nonce) racing up to 4 keys with first-verified-wins + cancel: typical 45–65 ms, worst ~65 ms on random challenges — inside the genuine envelope. Server only checks the solution.

### 5.3 C→S login #2 + PoW — 728 B (two messages, one datagram)

```
86 40 47 25 | 01 00 | 03 bf 00 | 32 cb b3 3d 12 fca223380bde7178:0 <42 nonces> | 00 05 02 | d9 67 01 00 ... | e8 20 21 93 df 33 c4 00
             |       | ID=3 len=191   | duration+key+solution            | ID=0 len=517 | ReplyID=92121 ... | footers
```

* Msg0 `challengeResponse`: `32 cb b3 3d` = `float LE 0.0877s` = `challengeCalculationDuration`, `12`=18 `"fca223380bde7178:0"` (`prefix+iteration 0`, solved first try), then `168 B = 42*4 B nonces` (`PROOFSIZE 42`, `nonce_t uint32`). Matches `writeResponseToStream: data << key; for solution: data << nonce`.
  Nonces LE: `47 ce 00 00, 20 01 01 00, e4 96 01 00...` — ascending, `< easiness`, SipHash-2-4 Cuckoo cycle (`verify()` in `cuckoo_cycle_login_challenge_factory.cpp`). Genuine 2.4.0 vectors (pinned in `login/login_test.go:TestChallengeResponseMatchesGenuine`): keys `:4`/`:1`/`:0` (iteration = restarts needed), durations 0.0380/0.0941/0.2136 s, nonces strictly ascending with max 551673–556492 < maxNonce 576716. Our builder reproduces a genuine 194 B message byte-identically.
* Msg1 `login` retry: same as §5.1 but `ReplyID d9 67 01 00 = 92121` (+1), fresh RSA block.
* Footers 8 B, last 2 `c4 00 LE=196` = offset of second message header (`194+2`), first message at 2 — chained via `nextRequestOffset`.

### 5.4 S→C success — 184 B

```
61 f3 fd 93 | 00 00 | ff ad 00 00 00 | d9 67 01 00 01 96 be d5... (173 B)
                              reply len=173 | ReplyID=92121 status=01 + Blowfish blob
```

* `ReplyID` matches retry. `01` = `LOGGED_ON`. Per `onReply`: if `pBlockCipher` exists, `decryptStream` via `EncryptionFilter` (Blowfish, key = `encryptionKey` from `LogOnParams`), then `readReplyRecordFromStream: data >> replyRecord (serverAddr: ip/port/salt + sessionKey:uint32) >> serverMessage?`. `LoginReplyRecord { Address serverAddr; uint32 sessionKey; }`. Record layout confirmed by fork (`sub_142AD3580`: ip u32 + port u16 BE + salt u16 + key u32 LE) + message.
* Client then `sendBaseAppLogin()` to `replyRecord.serverAddr`.
* Live Sep 2026: success bodies are **232 B** (216 B body). Decrypt is SOLVED: the login path has NO magic/wastage check (that's channel-only, `sub_142AD6570`) — ECB + plaintext chaining straight to the record (`decryptLogin` in `login/crypto.go`). Sessions validate via JSON account name, `session_id`/`token2`, and host pings.
* Digest is **strictly verified**: zero digest + real creds → status 70 `Defs digest mismatch` (proven live). Live logins carry the recomputed digest (`entdef`, green since 2026-09-20); the mod ground truth confirmed it.
* Client-side handler is `LoginAppLoginRequestProtocol::onReply` (`0x140e6ced0`):
  status 66 → challenge path (`sub_140E6C860`), status ≠ 1 → reject log
  (`Attempt #%u: Server rejected our login`), status 1 → decrypt via
  `sub_142AD6320`→`sub_142AD6190` (else `Failed to decrypt`), then
  `readReplyRecordFromStream` (`sub_140E6D3C0`), which requires ≥ 12 B
  cleartext and then reads the packed-string server message (`Got
  message with success result from LoginApp`). Record layout confirmed:
  12 B (`ip4, port BE, salt, sessionKey LE`) + message.

Failure path (same handler): `status != LOGGED_ON → data >> serverMessage`, `LOGIN_BAD_PROTOCOL_VERSION`, `LOGIN_REJECTED_*`, `LOGIN_CUSTOM_DEFINED_ERROR 254`, etc. Non-1 bodies are PLAINTEXT packed strings (no Blowfish): status 68 = `Invalid login/password for basic authentication` (the `2f` first byte is the packed length 47, not a `/` prefix — pinned in `TestParseErrorReply68`) or the shorter `Invalid password.` (unknown account vs wrong password); status 64 = `Unencrypted connection is not allowed.` (empty Blowfish key is refused at login — no plaintext negotiation exists; `-empty-key` probe). Our live sessions' message keys: `[isDemoAccount name security_msg session_id token2]` (token2 empty for basic); `security_msg="old_pass"` (password-age nag, not a restriction — same account plays), `isDemoAccount=false`.

Session_id structure (the game's OWN C++ log line `LoginAppLoginRequestProtocol::readReplyRecordFromStream`, 3 samples: `game_20260920.log:413` `06GCxxxxxx00000041VPHFxxxxxxxxxx`, `:4871` `06GCxxxxxx00000041VPHFxxxxxxxxxx`, `login3-game.log` `06GBxxxxxx00000041VPHFxxxxxxxxxx`): 32 chars over digits+letters minus I/L/O/U; literal stretches `[0:3]="06G"`, `[10:16]="000000"`, `[16:22]="41VPHF"`, the rest session-variable (char 3 drifts `B`→`C1` across days — suspected time encoding, unconfirmed). Token2 in every fresh servermsg: `{accountID 9d}:{middle 19d}:{tail 39d}` = 69 chars, segments decimal (never zero-led) — the stored-preferences copy may lag shorter (`len=68`, 18-digit middle: a consumed/stale tail, §12 WGC notes). Private-server reconstruction (goes with the login server, `login/loginapp.go`): all minted ids/token2s land inside the observed structural space with values marked ours; client-accepted iff the shapes hold (client never validates values beyond JSON presence).

## 6. Crypto

* RSA-2048 OAEP (`loginapp_wot.pubkey` in `res/`):
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2G58NsNUP1h3qQMhi+nE...
-----END PUBLIC KEY-----
modulus d8:6e:7c... (2048 bit), e=65537
```
`PublicKeyCipher::encrypt` splits to `partSize=modulus-42-1=213 B`, each →256 B (`RSA_public_encrypt ... RSA_PKCS1_OAEP_PADDING`). `LogOnParams::addToStreamInternal` decompiled (`sub_140E6E210`): `flags:u8` (or stored flags if `PASS_THROUGH`), then **FOUR** strings via `sub_140E65FC0` at `+24/+56/+88/+120` = username/password/encryptionKey/**clientContext** (confirmed: `connection_mgr.__setConnectionData` builds `clientContext = json {lang_id, publication}`), then `[digest:16 at +156 if flags&1]`, then `nonce:u32 at +152`. Username JSON keys (EU 1.27.1 `gui/login/manager.initiateLogin:99-103` + `connection_mgr.__setConnectionData:176-199`): `{login, session(md5 of wg_cpsalt), temporary ("0"/"1"), auth_method, publication ("0" = WGC_PC, "-1" = unknown), auth_realm, token/token2?}`. Note: with a stored WGC `token2` preference even typed-creds logins go out as `auth_method=token2` (password emptied, `loginParams['token2']` attached, `manager.py:91-105`); pure basic is the no-token fallback. Modern username = WGC JSON (`auth_method, auth_realm, session(md5), token/token2, allowed_peripheries, publication, lang_id`), password empty for token2. Oct-14 2.4.1.0 live census (MITM-decrypted SSO logins, `MitmLoginParamsFromPacket`, keys/lengths only): token2 path sends 9 keys (`account_complete, allowed_peripheries, auth_method, auth_realm, gameId, login, publication, session, token2` — no `token`/`account_id`/`requested_for` vs the 12-key 2.4.0.x shape) in 534/728B messages (not 790/984); `temporary` ABSENT entirely; `publication=2` (Steam build); session 32-hex; password empty; key 16B; digest nonzero; clientContext `{lang_id, publication}` unchanged. A token-path retry 2 s later sends 11 keys (`token` + `account_id` + `requested_for`, no `token2`; `auth_method=token`) and is the attempt that gets LOGGED_ON — game.log explains it: `Logon failed: Token2 expires time` on the token2-shape attempt (stale remembered tail, single-use), fallback to token. Slimmer SSO + missing `temporary` read as version drift (Steam-publication path confound open).

* Blowfish (BaseApp + LoginApp success blob): `EncryptionFilter BLOCK_SIZE 8, ENCRYPTION_MAGIC 0xdeadbeef`, `encrypt: XOR chain (prev plaintext block) then BF_ecb_encrypt` (replay protection, v49), `send: len+=magic, wastage=((8-((len+1)%8))%8)+1, append magic+wastage, encrypt`. `recv` checks magic, `shrink(wastage+4)`. `encryptStream/decryptStream` for `LoginReplyRecord`. Key = random `LogOnParams.encryptionKey` (default 16 B), `pBlockCipher`. Fork re-verified Sep 2026: same chaining decoded from its own encrypt loop (`sub_142AD67F0`: `dst=E(src⊕srcPrev)`, first block raw), same framing in `recv` (`sub_142AD6570`), OpenSSL Blowfish, `SymmetricBlockCipher` is the only symmetric impl (key sizes 4–56 B). Send path fully mapped Oct-11 (disasm `0x142AD67F0`, 191 insns): no-cipher drops the packet (`EncryptionFilter::send: Dropping packet`, returns -3 — the client never emits plaintext, hence status 64 server-side); wastage math exact (`len+4+1` rounded up to mult-of-8, magic `0xDEADBEEF` at last-5, wastage byte last); mode byte `+89h` copied per packet; XOR chain 8B blocks + trailing bytes; block encrypt `sub_142AE7140`; input-length assert cites `encryptionfilter.cpp:295`.

* Entity-defs digest (the 16 B after the 4 strings when `flags&1`): MD5 over
  the full client description map, **strictly enforced** by the server
  (`LOGIN_REJECTED_BAD_DIGEST` = status 70; zero digest + real creds
  fails live). 2.4.1.0 truth `c0cc08a2f494f7087112009ce1d002db`
(digest-dumper + dummy-creds probe → 68, Oct-15); offline recompute
from external 2.4.1 defs (`../wotdefs-2.4.1/` +
`../scripts-2.4.1/`, 403-entry walk) reproduces it exactly
(`TestComputeDigest241Offline`; see `AGENTS.md`). The client computes it at startup (`EntityType::init` →
  `EntityDefConstants`) and publishes it to Python (`BigWorldClientScript::init`,
  `sub_140381660`, `PyObject_SetAttrString("digest")` at `0x1403822b3`).
  Reference vector, live EU 2.4.0 (read in-game 2026-09-17, re-dumped
  2026-09-20, identical): `BigWorld.digest =
  5df886f75e73b33cff9d87fb9c69389c`. With this value, dummy
  credentials fail with 68 (`Invalid password`) instead of 70 —
  digest accepted. The fork recomputes it byte-identically
  (`entdef/`, `TestComputeDigestMatchesClient` green
  since 2026-09-20; `ComputeDigestFull`). Visitor
  (`AbstractMD5Visitor` / `ClientServerTypesMD5Visitor`, vtable
  `0x143923290`; driver `sub_142A9B5B0`, per-entry walker
  `sub_142A93420`, filter `sub_142A9B6C0` (+135), name hash
  `sub_142A9B6E0`, MD5 state `BW::MD5Calculator` vtable
  `0x1439230B8`). Map order (walkprobe-confirmed visit-for-visit,
  1242/1242): spaces (`space_defs/GeneralSpaceData` + `SpaceRecording`
  iface) → 40 `entities.xml` entities → 10 mode-pkg entities
  (`Mine/Loot/Placement/InfluenceZone/BattleRoyaleRadio/ThunderStrike`,
  `ApplicationPoint`, `Comp7Lighting`, `ReplayAccount`, `SPGZone`) →
  113 scripts dynamics (`components.xml` order) → mode-pkg dynamics
  (pkg-alpha, extension order). StaticComponents merge methods into
  their ofEntity entry per-domain (continuing legacy, no dedup);
  their props never walk. DynamicComponents walk standalone.
  Per-domain method order is interfaces-merged-first with first-wins
  name dedup (Account own `requestToken` drops); component methods
  never dedup (Avatar def + story-mode `setDevelopmentFeature` both
  hash). FullIndex = stable stream-size sort (`finish()`); exposure
  mask `0xC` everywhere including client methods; method
  `<AllowUnsafeData>` sets `0x10`; `<Exposed/>` bare = `|0xC`,
  `OWN_CLIENT` = `|0x8`; space `<Exposed/>` = `0x204`; volatile only
  `GunMarkerComponent.gunMarker` (section form); varLen `u32(2)`
  hashed for the 8 VarLen-2 client methods (gate85=1 universally);
  14 def-empty dynamics fail +135 (walkfinal-observed denylist:
  `ExtendedSPG`, `EnemyShotPredictorController`, `ArenaVehiclesInfo`,
  `ArenaLootComponent`, `ArenaDeathZonesComponent`,
  `ArenaEntityPositionGridComponent`, `SpawnKeyPointController`,
  `FLReservesComponent`, `FLArenaMinefieldComponent`,
  `FLArenaBattleModifiersComponent`, `ArenaAchievementsComponent`,
  `LSArenaDropComponent`, `LSArenaVehicleRemovalComponent`,
  `LSArenaWatersComponent`); everything else (even content-less
  entries) hashes its name. NO labels anywhere (all label slots are
  stubs: `+24/+32` = `sub_1402F7290`); NO arg/element/field names
  (`+24` stub); NO `"type"` dispatch label; type tags NUL-terminated
  (`sub_1403E81E0` strlen+1); values raw (`+40/+64` = u32
  `sub_1403E8290`, `+48/+72` = u16 `sub_1403E8260` (unused by our
  defs), `+80/+88` = u8 `sub_1403E8230`, `+96` = raw string
  `sub_1403E8210`); per-property FullIndex u32 first
  (`sub_142A9B870`, filter `0x106`), per-method legacy index u32 last
  (`sub_142A9B810`); sequences (`Array`/`Tuple` + `sub_142ACD660`:
  size + dbLen-if->0 + elem); FixedDict allowNone u8, no
  `<implementedBy>` in 2.4.0. Probes: `../ce/walkprobe.lua` (visits),
  `../ce/walkprobe2.lua` (flags/volatile), `../ce/walkprobe3.lua` (entry
  names), `../ce/walkfinal.lua` (unified: entry pass/fail + visits +
  gate85/varlen/descs), `../ce/r8probe.lua` (type tags, 2625 hits
  matching the model tag-for-tag in order); runs archived in `../ce/`.
  Historical anomalies from the entities-only era, all explained by the
  full map: (1) the 13-tag block = component base methods;
  (2) `requestToken` skipped = iface/own first-wins dedup;
  (3) the `(String,Int32,String)` gap = story-mode
  `setDevelopmentFeature`; (4) the base-methods repeat = interface
  method tables shared across entities; (5) the tag-heavy tail =
  standalone dynamics.
  Type-name strings fully interned (1 R8 address per tag); caller
  addresses type every fire exactly (Uint8/16/32/64, Int8/16/32/64
  mapped conflict-free from 256 verified tags — matches IDA
  immediates independently). Enriched probe (`t=`+`ret=` per hit)
  archived as `../ce/r8probe_enriched.txt`. Avatar block (1015 tags
  from hit #283) aligns 425. Closed 2026-09-20: the full client map
  (spaces + entities + statics + mode entities + dynamics) recomputes
  `5df886f7…` byte-identically (`TestComputeDigestMatchesClient`
  green); r8probe/walkprobe/walkprobe2/walkprobe3/walkfinal runs
  archived in `../ce/` pin visits, tags, flags, and entry names.

Block-alignment proof (BaseApp, `len-4` to strip prefix): `1521/1522` have `(len-4)%8==0` (`28→24, 36→32, 52→48, 1252→1248`). Only first C→S BaseApp `22 B (22-4=18)` is non-aligned → plaintext handshake before filter enables.

## 7. BaseApp (lobby) — what the pcap shows

* `C→S 22 B: 1b 12 f3 bf | 01 00 | 00 da 67 01 00 00 00 cf d8 c1 f8 01 14 05 02 00` — only non-encrypted BaseApp packet → `BaseAppExtInterface::baseAppLogin`. Full split: `ID=00`, `ReplyID da 67 01 00 LE = 92122`, `nextOff 00 00`, args `cf d8 c1 f8 01 14 05` (7 B), footer `02 00` (=2). **IDA resolves the 7 B**: `BaseAppLoginRequestProtocol::sendRequest` (`sub_140E6B740`) streams `{sessionKey U32 from handler+416; numAttempts U8; mtu U16 from serverConn+609}` via `sub_140E481B0` — so `key=cf d8 c1 f8`, `numAttempts=01`, **`mtu=0x0514=1300`**. Proof it's MTU: the same `+609` field feeds the login MTU ceiling (`sub_140E6D7C0`) and the tail call `setPacketSizeLimit(mtu-28)` (`sub_142AD5B80`, 28 = `UDP_OVERHEAD`). (The WORD table at `0x143692908` = `1500/1492/1280/1006/576…` is for MTU *probing*, not the handshake.) After send, client calls `pChannel()->setEncryption(pBlockCipher())`, so the reply is Blowfish (see §6).
* Genuine 2.4.0 handshake (`../captures/login.pcapng` idx 936, `login2.pcapng` idx 1039) parses with the identical layout — stage-1 CONTINUES the login RID sequence (82103 = 82102+1, 50983 = 50982+1, 80358 = 80357+1 across all three genuine sessions), while stage-2 mints a fresh RID (53365 / 105623 / 95197); fresh local socket for stage-2 only (login 63861 → stage-1 on 63861 → stage-2 on 63862). EU2 (flows 9–10), `.213:32826` (flows flow 10) and `.215:32918` (flows2 flow 10) show the same two-stage form: stage 1 (22 B → 36 B → client 28Bs → 52 B and/or 44 B → 28Bs → final 36B, 0.2–0.35 s; LOGGED_ON→stage-1 gap is 3–4 ms), then stage 2 with a FRESH 22 B (new ReplyID, DIFFERENT session key) to the game port (`:32816`, `:32910`, `:32914`, `:32832`), where the lobby flood arrives (327–473× 1252 B). Turn-taking is strict: the server sends 52B/44B only after receiving client 28Bs; all client 28Bs are 28 B (= flags + footers + 8 B app — primeBundle behavior, see below).
* Stage-1 reply = session-key ROTATION: `[FF][len=8][rid][newkey]` (reply echoes OUR rid; the 4 B varies per session, constant within). Fork `BaseAppLoginRequestProtocol::onReply` reads exactly this as the new key — takes it unconditionally, FAILS on zero/unchanged (`Got zero/unchanged session key` strings present in WoT binary too). Our client takes it (`stageKeyOf`), never logs the value.
* Post-reply app step = `BaseApp.authenticate{newkey}` + `enableEntities`: `[02][key u32]` (FIXED-4 `authenticate`) + `[0b]` (empty FIXED-0 `enableEntities`, BaseAppExt ID 11 — full table dumped Sep 19 at `0x14368CAA8…`: 0 baseAppLogin, 1 pingDatacenter, 2 authenticate, 3/4 avatarUpdateImplicit/Explicit, 5 ackPhysicsCorrection, 6 requestEntityUpdate, 7 nrlMsgToCell, 8/9 WardImplicit/Explicit, 10 ackWardPhysicsCorrection, 11 enableEntities, 12 restoreClientAck, 13 disconnectClient, 14 clientToServerHeartbeat, 15 sendToCell, 16/17 cell/baseEntityMethod). The 0b is the entities-ready trigger, not framing: without it (`-bare-auth` Sep 19) the server sends rotation+heartbeats but never infos. Unreliable channel packets carry a 4B aux word before footers (WoT bit12 `0x1000` marks them: `48 14` = ON|SEQ|CUMUL|+0x1000 vs reliable `58 04` = ON|RELIABLE|SEQ|CUMUL per the OSE flag enum; exe UDPBundle finalise `sub_142AD4970`: `0x1000` bit + 4B reservation at `0x142AD4B1C` for packets with no reliable content on a channel, aux value written at `0x142AD4D81` as `(channel+0x158 - 1) & SEQ_MASK`, i.e. reliable-send counter minus one — all-bits fresh, 0 after reliable seq 0 leaves). ack0 = bare aux + footers, no app byte (`48 14 ffffff0f seq=1 cumul=1`, 14B decrypt-proven from flows3+key3; our old build carried a phantom `01` with a short cumul). Unreliable footer seq starts at 1 per channel; reliable stays 0; cumul = acked server seq + 1. Fork server verifies the key (`authenticate: Unexpected key!` string in WoT binary) and routes by channel (`proxies_.find(channel-addr)`; unknown key/channel → silent drop).
* Server-side stage-1 (14.4 `server/baseapp/login_handler.cpp` + `pending_logins.cpp` + `proxy.cpp`, re-read Sep 19 2026 — no WoT server binary): `PendingLogins::add` stores `loginKey = proxy->sessionKey()` (this is LoginApp `key#0`) then `regenerateSessionKey()` (`sessionKey_ = u32(timestamp()); while(==0)`) with 30 s expiry; unknown key in the manager's pending table → SILENT drop (`No pending login for loginKey %u`, `breakBundleLoop`); channel collision → silent; then `attachToClient(srcAddr,replyID)` creates the UDP channel, `setEncryption(SymmetricBlockCipher(encKey))`, and replies `bundle.startReply(rid); bundle << sessionKey_` (the ROTATED `#1`, first + alone on the channel) followed by `updateFrequencyNotification{hertz}` + `setGameTime{time}` via `clientBundlePrimer_` (hence `52B/44B/36B-redirect` only after our `28B auth`). This is the leading mechanism for p2/EU2 zero-byte drops of fresh-issued keys (push missing/expired Belfry — trigger unknown).
* Standing results at the time: p2/EU2 gave zero bytes on BOTH sockets (fresh + login watched); p5 answered with reply+heartbeats and ran a healthy channel under our ACK loop but never sent 52B despite sustained `authenticate` (msgIDs 01–0F, old/new key, interface-prefixed, garbage, burst/spaced — no oracle: even garbage doesn't disturb heartbeats). Both were our own client bugs, CLOSED Oct-03: the stage-1 auth1 shape was wrong (unreliable-no-0b instead of the decrypt-proven reliable+0b) and the stage-2 victory return was missing. EU5 switches the GAME, so p5-policy is dead.
* Transport note: use one unconnected socket per peer set (`net.ListenUDP` + `WriteToUDP`); a socket `connect()`ed to LoginApp drops other peers' datagrams in-kernel. High-port UDP egress verified working via STUN + live pings, so BaseApp silence is server-side, not network.
* Channel cipher covers everything past the 4 B plaintext prefix (all post-handshake sizes ≡ 4 mod 8 both directions; flags are INSIDE the encrypted region). Our `decryptBlowfish(blockKey, data[4:])` offset and key (own `encryptionKey`, learned by the server from the RSA'd LogOnParams) are therefore correct — verified, not assumed.
* `S→C 36 B: e3 b8 9e 47 | ... 32 B` — first encrypted reply (`32%8==0`).
* Then `28 B` ping-pong (`24%8==0`, 958×) = `UDPChannel` ACK/keepalive, `52 B`, `44 B`, etc.
* Burst `~60×1252 B + 1204 B + 404 B` server→client at `15:31:10.816` ≈75 KB = account/lobby download (`createBasePlayer`, `authenticate`, `switchBaseApp`, `ClientInterface::authenticateArgs`, `BaseAppExtInterface` in strings). All `(len-4)%8==0`, i.e. Blowfish.
* Stage-1/stage-2 script CRACKED (paired EU2 capture Sep 17 2026, `../captures/flows3` + CE key `../captures/key3.txt`, login 23:45:55, lobby 23:45:56 — key `BF54…` cross-validated: decrypts the 232B to the exact stage-1 endpoint `.213:32892`): stage-1 socket varies by run: `flows3` reuses the login socket (login `:63861` → stage-1 `:32841` all on `:63861`), `login3.pcapng` uses a fresh socket per stage (`62485` login → `62486` stage-1 → `62488` stage-2, each stage's first packet the 22B) — EU2 answers both ways, so socket identity is not a gate (our client mirrors the flows3 form). `login3` cadence: 22B → six 28Bs over ~145 ms → stage-2 22B at +147 ms (redirect arrived that fast). Timed script, all post-22B: 22B → +24 ms 36B `[FF][len=8][rid][newkey]` (rotation, server seq 0) → +2 ms client 28B ack0 `[4814][ffffff0f][seq=1][cumul=1]` (bare aux, no app) → +10 ms client 28B auth1 `[5804][02][newkey][0b=enableEntities][seq=0][cumul=1]` → +24 ms 52B account-info (seq 1, server-auth with a THIRD key ≠ ROT ≠ sessionKey, + account ID ASCII) → +1 ms 28B `[13][1B]` (server→client 0x13 FIXED-1; payload drifts ba→bb→bc across seqs, meaning open) → per-message client pure-acks `[4814][00000000][seq=N][cumul=M]` → 44B (`"default"` string, seq 3) → 36B redirect `[13][XX][44][ip4 BE][port BE][00 00 01]` (seq 4–5; XX=0x3f flows3, 0xbc logins.pcapng) → client re-auth `[4814][02][newkey][00000000]` with BOTH footer longs = redirect-seq+1 ((5,5) flows3, (6,6) logins.pcapng — not the unreliable counter, which would say 5 in the latter) → fresh-socket 22B to redirect target (fresh small rid, rotation key, att=1). Stage-2: 22B → 36B rotation-2 → 36B info → client double-auth (`[4814][02][key2][ff ff ff 0f][seq=1][cumul=1]` + `[5804][02][key2][0b][seq=0][cumul=1]`) → 76B → 1252B lobby flood. Cumul model (fork `UDPChannel::writeFooter` + fits every observed position): cumul sent = last-processed-peer-RELIABLE-seq + 1; own unreliable seq counts 1,2,3,4,5, own reliable seq stays 0 (fresh channel resets both). Flags decode per OSE enum + WoT bits 11/12 (`5804`=ON|RELIABLE|SEQ|CUMUL, `4814`=ON|SEQ|CUMUL|+0x1000). Our builders reproduce every client packet raw-identical (`TestPairedReplay`); genuine pads with uninitialized bytes (pad unchecked by decrypt — ours zero-pad, cosmetically different ciphertext only). Our client implements this script (`stageOneScript`/`stageTwo`, stage-1 from the login socket).
* Standing Sep 18 2026: p2 managers stay silent at our stage-1 22B (10+ ports, login-socket sends, same-host logins — all silent; the game answered on p2 the same evening); p5 answers (rotation + infos + heartbeats, transport healthy both ways, our auth cumul-acked) but never redirects (bare-auth and 50 ms-delay variants also limbo → not the 0b trailer, not a commit race). Session records equivalent (same servermsg keys AND user-visible values, incl. `security_msg="old_pass"`). Churn-tangle theory WITHDRAWN Sep 18 2026: the genuine client hammers harder than we do (5-periphery ping sweeps + 10-host probe bursts, orphan/failed/good logins seconds apart, relogin 7 s after a failure in `../captures/login3-game.log`) with no cooldown and still enters the lobby. The wall looked byte-level downstream of `LOGGED_ON`, not rate/state. DONE since: LogOnParams audited field-by-field (534/728 B, ver, RSA, username, PoW envelope), builders pinned to paired EU2 captures, socket/knock falsified (see §7/login3). RESOLVED Oct-03: the discriminator was never on the wire — a wrong stage-1 auth1 shape plus a missing stage-2 victory return, both client-side (see §11).

* CLOSED Sep 19 — version drift: the exe DID change once (Sep 18:
  running game = 78,777,520 B, SHA1 `11e4ac11…`; the `2.4.0.1` folder
  itself is res-only — GUI gen resources differ, `connection_mgr.pyc`
  + `Manager.pyc` byte-identical). But the handshake did NOT drift:
  `login3.pcapng` (new-build era, Sep 18 19:19+) shows the same 22B
  stage-1 shape our builders pin — game works on EU2 before and after
  with identical bytes. Our IDA offsets (`0x140E…`) may be stale vs
  the current file (explains the Sep 18 CE key-grab breakage: re-find
  by pattern, not fixed offset); wire conclusions unaffected.
* Hijack Sep 19 (game frozen post-LOGGED_ON, our probe with the
  game's LIVE key+endpoint, `login_p2.pcapng`): probe 25× silent,
  game resumed at T+20 s and answered in 38 ms → hangar. Post-mortem:
  the probe sent rid `0x96ac…+attempt` instead of the session's
  `login#2rid+1` (`91400→91401`) — wrong rid, void test (manager may
  well gate on rid continuity). Fixed: `SessionFromDump` now derives
  the stage rid from the dump's cleartext login rids (pinned by
  `TestLoginRIDsHijackDump` = 91401) and fails loud on orphan
  pairings. Redo Sep 20 2026 (game dump `../captures/dump_game_20260920.txt`
  + that login's CE key `<redacted CE key>`,
  `../captures/hijack_live_20260920.log`):
  `SessionFromDump` re-derived offline from the same dump → baseapp
  `92.223.20.212:32847`, sessionKey match, stageRID `33713` =
  game's login#2 rid + 1 (redo VALID, temp test then deleted) — and
  stage-1 stayed silent for all 25 attempts anyway. Per-session wall
  at maximum strength: the game's OWN live session + correct rid
  math, from our socket on the same machine, gets zero bytes.
  PORT-STEAL redo Sep 20 2026, same day (`../captures/dump_hijack_20260920.txt`
  + that login's CE key `<redacted CE key>` →
  `../captures/hijack_portsteal_20260920.log`): game KILLED after
  LOGGED_ON (not frozen), probe bound the game's own login source
  port `:50935` (auto-derived via `LoginSourcePort`, bind success =
  sole claimant), stageRID `76138` = login#2+1 re-verified offline —
  silent for all 113 attempts over 90 s. BUT: file mtimes prove the
  probe started ~83 s after the 232B (dump 11:39:58.9, log end
  11:42:51 − 90 s budget) — past the ~30 s pending-record expiry,
  so this run is VOID on timing (tested a corpse, not the wall).
  Lesson: the game fires stage-1 4 ms after its 232B
  (`login3.pcapng`: 232B …234.205 → 22B …234.209); manual
  kill+run takes 30-80 s and can never land inside the window.
  `hijack_trigger.lua` MODE="kill" now automates kill+fire (~2-3 s).
  The full-strength test (valid rid + in-window + port steal + sole
  claimant) has NOT run yet. No pre-packets are needed anywhere:
  the kill-flow dump shows the game logging in with zero ping sweep
  (4 datagrams: 534/55/728/232) — what matters is seconds AFTER,
  not packets BEFORE.
  KILL-MODE VERDICT Sep 20 2026, same day
  (`../captures/dump_kill_20260920.txt` + `../ce/wotkeys_20260920_1303.txt`
  → `../captures/hijack_kill_20260920.log`): 232B at 13:03:10.213,
  CE auto-kill+fire the same second (bind `:56370` ok), stageRID
  22155 = login#2+1 re-verified offline — 25 attempts over 20 s,
  all in-window, all silent. Same IP + same port + same bytes +
  correct rid + live session + sole claimant + in-window: at the time
  this read as pure server-side session state. SUPERSEDED Oct-03 —
  the park was two client bugs (§7), and the probe's silence was our
  own auth1 shape.
  p1 side-note:
  game-via-proxy logged into p1 fine while our direct p1 stays dark
  (transient or resolver difference — open).
* Sep 19 2026 `-bare-auth` on p5: DECISIVE oracle — the 0b byte is parsed. Bare `[02][key]` (no 0b) yields `36B seq1 [id=02 …]` then bare `28B` heartbeats only (no 52B/44B infos, no redirect, `no redirect` at 25 s); with-0b yields 52B/44B infos then heartbeats. So 0b is REQUIRED for infos but NOT sufficient for redirect. Redirect failure lies downstream — LoginApp plaintext diff vs genuine `62485` (username JSON, clientContext, key size, PoW iteration/duration) is now the top lead.
* `login3.pcapng` pre-login inventory (nothing-to-replicate proof):
  ping sweep (100×16 B, 5 hosts, per-host sockets) ends ...986, then
  ~119 s of total WG silence, then login#1 → 55-challenge → the game
  ABANDONS it (no 728!) → ~121 s silence → login → **34 B error
  reply** → 7 s → login → 232 LOGGED_ON → stage-1 22 B **4 ms**
  later. So: no packets go "beforehand" (pings are minutes old,
  nothing immediately precedes login), the genuine client itself
  eats abandoned challenges + error replies + minute-scale gaps on
  EU2 (flakiness is normal there, not our bug), and everything
  moves in milliseconds once LOGGED_ON. Fresh ephemeral source
  port per login (55186 → 62483 → 62485); stage-1 on another fresh
  port (62486) answered instantly — no port binding anywhere.
  TCP/DNS inventory (same capture): DNS resolves all five
  `login.p*` hosts at startup (server selection), `wgcg-eu` early,
  chat/voice hostnames only post-lobby; one pre-login HTTPS SYN
  (`92.38.146.146:443`, 13 ms before the failed attempt) with NO
  counterpart before the successful login 7 s later — not a
  precondition. Post-lobby HTTPS bursts (`92.223.23.146`,
  `92.223.84.84`), XMPP (`92.223.20.55:5222`), voice, web — all
  after the lobby. Nothing TCP or DNS gates login or stage-1.
  `flows3` (mitmproxy, parsed via tnetstring walk) confirms the same
  shape: pings ancient, then login saga (534→55→728→**31 B error**,
  66 s pause, 534→55→73 s gap→728→fresh 534→55→728→232), stage-1
  200 ms after LOGGED_ON, lobby flood right behind. Voice probing
  (`3281x`, 25/17 B pairs) and XMPP chat (TCP `92.223.20.55:5222`)
  both start AFTER the lobby (+304 s) — nothing precedes login or
  stage-1 anywhere. No pre-packets exist to replicate, TCP or UDP.
* `logins.pcapng` (user capture, 8 sessions incl. 4 validated CE keys): the genuine client, meeting stage-1 silence, resends its 22B with fresh rid AND att++ every ~0.5 s, unbounded (192 attempts seen vs a silent manager) — wotlogin now mirrors this (was: ≤10 tries, same rid, ≤3 s waits). Same capture shows p5-limbo and a stalled 6-msg stage-1 hitting the game too: silence is not our bug.
* LOBBY REACHED with our client (p5, 2× reproduced): rotation → stage-1 infos → redirect → stage-2 double-auth → decrypt-verified 1252B flood. Prime suspect for the unblock is the ack0 cumul fix (old build reported cumul=256 garbage in its first post-rotation packet; cumul=1 now) — plus login-continuation RID and game-shaped resends deployed in the same window. p2/EU2 was still silent at the 22B then — the same client-side pair, CLOSED Oct-03.

Do not confuse with in-game CellApp (`CellAppLoginRequestProtocol`, `avatarUpdate*`, `controlEntity`, `enterAoI` — out of scope).

## 8. Pinger (`../captures/wot_server_ping.pcapng`, 39 pkts)

`BigWorld.Pinger`, `WGPinger`, `PingerWorker` in binary + `predefined_hosts.py: BigWorld.Pinger.ping(peripheries)`, `setOnPingCallback`.

```
C→S 16 B: 0c c0 1f c5 | 01 00 | 02 a1 1b 01 00 00 00 00 02 00
S→C 18 B: 9f 4c 1b 99 | 00 00 | ff 05 00 00 00 a1 1b 01 00 00 00 00
```

Same 4+2 framing as LoginApp — and **IDA shows `ping` is a member of the same `LoginInterface`** (FIXED, 1 B: `sub_140242660`). Sender decompiled (`sub_140397AE0`): `startRequest(ping IE, timeout=*(+208))`, `seq = ++*(+212)`, stream 1 B seq, send; guarded by an outstanding-window check. So: `[02:1][ReplyID:4][nextOff:2][seq:1][reqOff:2]`. E.g. `02 | a1 1b 01 00 | 00 00 | 00 | 02 00`. Reply is `ff 05 00 00 00` + `ReplyID echo (u32)` + `seq echo`, then version-dependent tail. **Live-validated Sep 2026**: our Go client (`ping/`) pinged `login.p2.worldoftanks.eu` (92.223.20.215:20016) 4/4 at ~34 ms — request construction and reply matching confirmed end-to-end. Current servers send **16 B replies with no 2 B trailer** (echo = full u32 ReplyID + 1 B seq); the 2022 captures show 18 B with trailer, so it was dropped server-side between 17.1.0.3 and now. Reply prefixes VARY per packet (base `0x1f` + request's top bit, §3) — the earlier "fixed `9f 4c 1b 99` constant" reading (4 samples) is withdrawn; one exact cross-year repeat of that value (2022 + 2026 captures) is on record, unexplained. And `login.p1` (185.12.240.39, the actual login host) does NOT answer pings — only ping-designated peripheries do; all 2022 capture IPs are dark. Sep 2026 sweep with `ping/` over a community server list (RU1-9 `login.pX.tanki.su`, EU1-5 `login.pX.worldoftanks.eu`, USC/LATAM/ASIA, CN1-2, CT1-2, Lesta PT1): only 3/21 answer — `login.p2.worldoftanks.eu` (~34 ms), `login.p5.worldoftanks.eu` (Frankfurt, ~24.5 ms) and `wotasia1.login.wargaming.net` (Singapore, ~144 ms). RTT ordering matches geography, confirming genuine replies. All RU/CN/US/CT/PT endpoints and EU1/3/4 are 100% dark (first A record each, 2×2 s timeouts). The client (`PingReplyHandler`, `sub_1403973F0` ctor / `sub_140397700` reply / `sub_1403976B0` timeout→resend) **does not parse the trailer** — it just fires the next ping, so the displayed ping (`PingData` in `predefined_hosts.py`) is measured client-side (send→reply RTT). Trailer values per host start `0000,0000` then vary (`3ab6,a4a6,e784…`; BE = 15030,42150,59268 — no consistent ratio to the ~15 ms observed RTTs, ruling out µs-RTT; also not usersCount, not a timestamp at any standard tick). Encoding unresolved; prime suspects: server load metric or obfuscated RTT. Full correlation table (host × seq × metric × timestamps) was checked: metric is zero for the first two samples per host, then pseudo-random. Targets `*.20016`: `185.12.240.61, 92.223.24.243, 92.223.54.104, 83.229.15.206`. (`probe` ID 1 is EMPTY and never carries payload; `mtuProbe` ID 4 only appears when the login bundle needs MTU padding — our logins at 534/728 B were already big enough, hence the `addMTUProbeToBundle : already big enough` path.)

**`probe` with payload (id=01, Sep 2026, EU2 flows 11/14–17/19–22/26):** the same `LoginInterface.probe` (wire ID 1, §4 line 69) but sent to GAME ports (`:32811`–`:32816`) on ten hosts across regions (EU `185.12.240.42/.54`, `92.223.20.73/.76`, `92.223.54.109/.114`, `45.82.31.14`, `83.229.15.109`, AWS `52.57.68.91`, US `63.182.9.216`), 15-packet bursts in 0.3–3 s, then silence — region/server-selection measurement, not login:
```
C→S 25 B: 7a ee de 3c | 01 00 | 01 b1 c7 00 00 00 00 | bc 68 77 20 00 00 00 00 0e 00 | 02 00
S→C 17 B: 1f 54 1a a8 | 00 00 | ff 06 00 00 00 b1 c7 00 00 0e 00
```
Body = 8 B constant cookie `bc68772000000000` (identical across all bursts/hosts) + u16 countdown `0e→00`. Reply (`len=6`) echoes the FULL u32 ReplyID + 2 B countdown. IDA-resolved: id=01 here is **`pingDatacenter`**, a WoT-added `BaseAppExtInterface` method (interface string table at `0x14368CAA8…`: `baseAppLogin=0, pingDatacenter=1, authenticate=2, avatarUpdate…` — vanilla 14.4 lacks it). Prefix top-bit rule is INVERTED vs ping (`~rid&1`, 150/150 — different code path, cosmetic only).

## 9. Binary evidence (strings + IDA decompiles)

IDA session `5686b310` on `../World_of_Tanks_EU/win64/WorldOfTanks.exe` (217389 funcs, base `0x140000000`). Decompiled/confirmed (all `WorldOfTanks.exe` 2.4.0 addresses). This round added: ping sender `sub_140397AE0` (seq counter at `+212`, window guard, `startRequest(ping)`), `PingReplyHandler` ctor `sub_1403973F0` / reply `sub_140397700` / timeout-resend `sub_1403976B0` (reply content ignored — next ping fires immediately), `PingerWorker` ctor `sub_142C9B320`, `BaseAppLoginRequestProtocol::sendRequest` `sub_140E6B740`, `LogOnParams::addToStreamInternal` `sub_140E6E210` (+ wrapper `sub_140E6E100`), `WGPinger` Python expo `sub_140AA68E0`. Later headless sessions (same `.i64`, e.g. `47cd3dec`/`bd3b763e`) added: `BigWorldClientScript::init` (`sub_140381660`, digest `SetAttrString` at `0x1403822b3`), `EntityType::init` (`sub_140394440`), digest driver `sub_142A9B5B0` + entity walker `sub_142A93420`, `AbstractMD5Visitor::startMethods` (`sub_142A9B750`, domains 1=base/2=client/4=cell), property visitor `sub_142A894E0` (`dataDistributionFlags&0x5F` + `isVolatile` + `type`), method visitor `sub_142AA17D0` (`flags` + `args` + `returnValues` + legacy index), `Int`/`FixedDict` datatype visitors (`sub_142AC1270`/`sub_142AB3A30`), `LoginAppLoginRequestProtocol::onReply` (`0x140e6ced0`, vtable slot after `sendRequest`) + `readReplyRecordFromStream` (`sub_140E6D3C0`, ≥12 B + message), `EncryptionFilter::recv` (`sub_142AD6570`), decrypt `sub_142AD6190`, encrypt/send `sub_142AD67F0` (plaintext chaining confirmed), `ServerConnection` ctor/dtor (`sub_140E46FF0`/`sub_140E47B50`, cipher slot `+0x13D8`), `logOnBegin` (`sub_140E50D30`). Deep BaseApp round (session `eeeb023d`, Sep 18–19 2026, exe-only, no Go tools) added: `sendRequest` disasm (timeout `a4*1e6 us`, `startRequest` vtbl+`0x28` on `qword_144857DA0`, `sendBundle` vtbl+`0x10`, `createChannel` vtbl+`0x8`), args writer `sub_140E481B0` (`[u32 key][u16 att|mtu_lo][u8 mtu_hi]`, `reserve 7`), `LoginRequest::finish` (`sub_140E67AC0`, `Already finished: Attempt #%u`), `removeChildRequest` (`sub_140E60FE0`, `Request not present #%u`), `DeferredBundle` ctor (`sub_142ADC8F0`, msglist `0x50` + `MemoryOStream 0x40`/buf `0x40` cap 64), timer wheel (`sub_142AD0660`, `TimeQueue 0x60` heap by expiry, `LoginHandler::sendNextRequest` / `ServerConnectionHeartbeatChecker`), channel detach (`sub_140E4F7A0`) / reset (`sub_140E4F4C0`), `UDPChannel` ctor (`sub_142AD8220`, `0x248 B`), `Address::str` (`sub_142AD35E0`: type 1 `ntohl(+12)`+`ntohs(+10)` → BE proof), `LoginRequestProtocol` ctor (`sub_140E68910`: BaseApp profile `a2[11,9,10]`), `LoginHandler` ctor (`sub_140E5F1B0`), queue-walk (`sub_142AFBC50`/`sub_142AFBD00`). Oct-11 receive-path inventory (disasm, `processFilteredPacket` `0x142AF86E0`, 1302 insns, still undecompilable): dispatch order confirmed checksum (`0x142AF3680`) → piggyback (`0x142AF3070`) → timestamp strip (`0x142AF3420`) → INDEXED id/ver (`0x142AD2580/550`) → ON_CHANNEL (`0x142AD2530`) → dispatch (`0x142ADA9F0`) → indexed/channel handler family (`0x142ADA820`, `0x142ADB240`, `0x142ADA8B0`, `0x142ADA800`, `0x142ADB670`, `0x142ADAD70`, `0x142ADB5E0`, `0x142AD9FC0`, `0x142AF6E40`); per-packet counter `+1D8h`.

* `LoginAppLoginRequestProtocol::sendRequest` (`sub_140E6D7C0`): optional `challengeResponse` first (`float challengeCalculationDuration` + raw PoW blob via `startMessage`, unreliable), then `startRequest(login)` + `addRequestDataToStream`, MTU-probe padding (`qword_144858130` = `mtuProbe`, U16 length + zero pad) or the `addMTUProbeToBundle : already big enough` log. Ends with `transport.sendBundle(bundle, offChannel=false)`.
* `...::addRequestDataToStream` (`sub_140E6C650`): version bytes + `LogOnParams::addToStream(HAS_ALL, RSAEncoder)`; failure → `fail(PUBLIC_KEY_LOOKUP_FAILED, "Failed to encode log on parameters")`.
* `CuckooCycleLoginChallenge::readChallengeFromStream` (`sub_140E664C0`): `stream >> prefix_ (a1+16) >> maxNonce_ (a1+48, U64)`, error → `Failed to de-stream parameters`.
* `BigWorld.wg_cpsalt` chain: expo registration `sub_140EECD00` → impl `sub_140EE56F0` → arg parse `sub_140EF1880` → core `sub_140EFB2A0`: valid GUID passes through (`UuidFromStringA` ok → copy), empty/invalid → fresh `CoCreateGuid` → `UuidToStringA` (persisted to preferences by the caller). So the game NEVER sends `md5("")`.
* BaseApp interface strings (`0x14368CAA8…`, 256 B dump Sep 19 2026): `BaseAppExtInterface\0 baseAppLogin=0 pingDatacenter=1 authenticate=2 avatarUpdateImplicit avatarUpdateExplicit ackPhysicsCorrection requestEntityUpdate nrlMsgToCell avatarUpdateWardImplicit/Explicit ackWardP…` (declaration order = wire IDs). `ClientInterface` (`0x14368CD80…`): `… updateFrequencyNotification setGameTime resetEntities …` + `connection.cpp` + per-method metadata. Related server logs present in binary: `authenticate: Unexpected key! (%x, wanted %x)`, `BaseAppLoginRequestProtocol::onReply`, NAT/ICMP `onAttemptsExhausted` texts (also `CellApp` variants). Misc strings pinned Sep 19: `NoSuchPort 0x143691030`, `condemned 0x14392C3BB/0x1439310C6`, `addMTUProbeToBundle 0x143692F9E / already big enough 0x143692FC4`; probe table `0x143692908` live bytes `dc 05 d4 05 00 05 ee 03 40 02` = `1500,1492,1280,1006,576 LE`.
* Fork 14.4 (in `../BigWorld/`, same lineage) pins the mechanics WoT shares: `FLAG_HAS_CUMULATIVE_ACK 0x0400`, `SeqNum` u32, footer order (receiver strips cumul before seq ⇒ wire `[seq][cumul]`), `writeFooter`/`handleCumulativeAck`, `Bundle::startMessage`/`startRequest` framing (`[msgID][len?]` — NO interface byte; `compressLength` FIXED vs VARIABLE styles), struct messages FIXED (`MERCURY_STRUCT_MESSAGE` → `FIXED_LENGTH_MESSAGE`), `BaseAppLoginRequestProtocol::sendRequest` (key + `attemptNum`, off-channel, then create channel + set encryption) and `::onReply` (`data >> sessionKey`, fail zero/unchanged, `onBaseAppLoginSuccess`), `ServerConnection::primeBundle` (`authenticate{sessionKey_}` on EVERY post-login bundle), server `BaseApp::authenticate` (find proxy BY CHANNEL address, `CHEAT: Received wrong session key` → break), `LoginHandler::login` (unknown key → silent drop), `SymmetricBlockCipher::create` (default 128-bit = 16 B `RAND_bytes`), `Proxy::attachToClient` (empty key → unencrypted fallback, refused at login here).
* `Packet::stripChannelTimestamp` (`sub_142AF3420`, 36 insns full Sep 19): `ax=[+0x90]; shr ax,11; if(!set) return 1; ecx=[+0x30]; eax=ecx-2; if(eax<4) → Packet too short (%d)… return 0; [+0x34]+=4; eax=ecx-4; [+0x30]=eax; ecx=[rax+rbx+0x90]; [+0x7C]=ecx; return 1` — i.e. needs `msgEnd>=6`, pops trailing `U32` to `+0x7C`. `UDPChannel::writeFlags` (`sub_142ADB7A0`, disasm paged): `flags|=0x08; if([ch+0x134]){flags|=0x0800; footer+=4; pkt+0x7C=[ch+0x134];} if([ch+0x138]){flags|=0x0080; footer+=8; pkt+0x68=[ch+0x138]; pkt+0x6C=[ch+0x13C];} space-=0x23; if(<4) fragment path; flags|=0x0400; footer+=4; walk [ch+0x120] reliable list (delta&0xFFFFFFF, window 0x8000000)` (`updating expired timestamp: %u -> %u`), `PacketSender::basicSendSingleTry` (`sub_142AFAB00`, straight to `sendto`). `writeFlags` fully read Oct-11 (disasm `0x142ADB7A0`, 222 insns): flag-bit conditions explicit — `0x08` always, `0x0800`+`u32@+0x7C` iff `[ch+0x134]`, `0x0080`+8B@`+0x68` iff `[ch+0x138]`, `0x0400`+cumul always, `0x04`+count@`+0x48` timestamp-list iff `[ch+0x128]` and space, `0x210` piggyback iff indexed flags clear; reliable-list walk at `[ch+0x120]` (delta `&0xFFFFFFF`, window `0x8000000`, expiry update); fragment path below 4B space. `setPacketSizeLimit` (`0x142AD5B80`, 56 insns): type-gated flexible limit (`0x1C`/`0x28` + requested, clamped, stored `+0x114`). Channel struct mapped via ctor `0x142AD8220` (197 insns): `+0x120` reliable list, `+0x130/134/138/13C` footer conditionals, `+0x150` window, `+0x154` relSent (adj. `+0x158` aux counter — confirms the exe model), `+0x1B8` seq init `(relSent-1)&0xFFFFFFF`, `+0x1D8` packet counter, `+0x114` size limit., `PacketReceiver::processFilteredPacket` (`sub_142AF86E0`, paged to +320: `undersize → bad flags → CREATE-external → Invalid checksum (0x142AF3680) → Corrupted piggyback (0x142AF3070) → Failed timestamp → INDEXED id/ver [0x68]/[0x6C] via 0x142AD2580/550 (Could not get indexed channel for id %d) → ON_CHANNEL lookup 0x142AD2530 → dispatch 0x142ADA9F0` with `neg/sbb/and 4` prefix compensation), `UDPLoginRequestTransport::createChannel` (`sub_140E68E20`: `new UDPChannel 0x248 via 0x142AD8220`, `setInactivity(0)`).
* `BW::BaseAppLoginRequestProtocol::onReply` (`sub_140E6B460`): reads the new key as a stream U32 (no rid check client-side — Mercury matches rid→request first), then `LoginHandler::onBaseAppLoginSuccess` (`sub_140E5FF00`): zero key → fail `Got zero session key`, unchanged (== handler+416) → fail `Got unchanged session key`, else commit to handler+416 AND `ServerConnection+36` (the authenticate "wanted" key) + channel bind (`sub_140E4DDE0`). Null channel → fail `Did not get channel from request` (the reply must resolve a channel — endpoint/key binding lives here).
* `ServerConnection::switchBaseApp` (`sub_140E54400`): gated by byte flag +5144 (same flag gates the authenticate key-check; likely dead/offline guard). Args = 9 B `[u32 ip][u16 port BE][u16 0000][u8 01]` (offsets confirm our redirect parse; trailing u8 stored to ServerConnection+32). `Address::str sub_142AD35E0` proves BE: type 1 = `ntohl(+12)` + `ntohs(+10)` → `%d.%d.%d.%d:%d`; type 2 = 8×`ntohs` IPv6; else `None`. Then `LoginHandler::startWithBaseAddr` (`sub_140E617D0`) with numAttempts=1 + key=+36 → fresh stage-2 22B (att=1, rotation key — matches genuine bytes). `startWithBaseAddr` detail (Sep 19): guards `+472 completed`, `+516=a5, +48=a3, +416=key, +408=*(a2+12)=ip, +412=*(a2+10)=port (type 1/2), +414=*(a2+136)`, `setServerAppAddress sub_140E61440` (IPv6 synth `0x142AD7090/390`), `sendNextRequest sub_140E61140` (`++476`, `new Request 0x140E67820/0x140E68F70/0x140E69290`, RB `+480` insert, `transport.send 0x142AD0660` with `timeout_us` + `"LoginHandler::sendNextRequest"`; timer wheel `sub_142AD0660` = `TimeQueue 0x60` heap by expiry, also drives `ServerConnectionHeartbeatChecker 1000*ms`). `LoginRequest::finish sub_140E67AC0` (`Already finished #%u`, release proto `0x140E69210`, chan `+88` graceful `[vtbl+56]` vs flush `0x142AD5850` + unbind `0x142AD57C0`, transport `0x142AD2420` → queue-walk `0x142AFBC50`/`0x142AFBD00`, handler `[vtbl+64]`, map remove `sub_140E60FE0` else `Request not present #%u`). `LoginHandler` ctor `sub_140E5F1B0` (`+40 ServerConn, +48 type, +56/64/72 reqs, +88=-1, +96…232 retry table, +384 lock, +392/400 chan/proxy, +408 ip, +412 port, +414 ext, +416 key, +424 status, +432/+472 done, +476 attempts, +480 RB 0x101, +512 isBaseApp`); protocol ctor `sub_140E68910` (default `10/8.0f/1.0f`, BaseApp mode takes `a2[11,9,10]`); `setUpInterface` steals `ServerConn.networkInterface` for request#1 (stage-1 reuses login socket) else `new NetworkInterface` (stage-2 fresh); detach `sub_140E4F7A0` / reset `sub_140E4F4C0` clear `+176/+728/+36/+392`, entity map `+5064`.
* `ServerConnection::authenticate` (`sub_140E49250`): `if (!flag5144 && *key != key36) log "Unexpected key! (%x, wanted %x)"` — LOG ONLY, no disconnect/fail. Client sends regardless.
* Other strings: `LoginAppLoginRequestProtocol::onReply: Attempt #%u...`, `readReplyRecordFromStream...`, `BaseAppLoginRequestProtocol::onReply`, `ServerConnection::switchBaseApp`, `WGPinger`/`PingerWorker`/`WGPingerInstance`/`setOnPingCallback`, `loginapp.pubkey` (res file is `loginapp_wot.pubkey`).
* Build root proving 14.4 lineage: `D:\BuildAgent\work\wotd_ci_release\wc\programming\shared_libs\connection\baseapp_login_request_protocol.cpp`, `.../login_request_transport.cpp`, `.../network/udp_bundle.cpp`, `udp_channel.cpp`, `encryption_filter.cpp`, `websocket_stream_filter.cpp`.
* Digest framework (all `WorldOfTanks.exe` 2.4.0): property wrapper `sub_142A9B870` (filter `0x106`, FullIndex `i32` first — proven from disassembly), method slot `sub_142A9B810` (exposed `&0xC` check inside, legacy index via raw append), tuple visitor `sub_142ABCBC0` (label + per-element name + type dispatch, empty = nothing), member part `sub_142ABC050`, `Int` visitor `sub_142AC1270` (`"type"` + tag + size), `FixedDict` visitor `sub_142AB3A30` (`"type"` + tag + allowNone + `"fields"` + per-field name + nested dispatch), property parser `sub_142A8A1F0` (forces bit 8 from `ExposedForReplay` for client-server props only — no non-CS prop in our defs carries an explicit section), digest entry `sub_142A9B640` with `BW::MD5Calculator` (vtable `0x1439230B8`; string slots live on an unresolved derived state object). Property parser `sub_142A8A1F0` mapped Oct-11 (disasm, 899 insns, still undecompilable): `strtok`-based tokenizing + Python C-API (`BW_Py_DEC_REF`, `strdup`, datatype ctors `0x142A9CC80/142A9CDD0/142A9DBF0`) — order-sensitive dispatch, matching the visit-order digest model.

## 10. IDA notes

Headless worker sessions on `../World_of_Tanks_EU/win64/WorldOfTanks.exe` (base `0x140000000`). Only 1466/217389 functions have real names — work via string xrefs (all addresses §9). Decompilation fails on large functions (`processFilteredPacket`, `UDPChannel::writeFlags` + ctor `0x142AD8220`, `EncryptionFilter::send 0x142AD67F0`, `setPacketSizeLimit 0x142AD5B80`, property parser `sub_142A8A1F0`); use `disasm` pagination + fetched-output grep instead. `qword_144858xx` interface globals read as zero (live bytes `0x144857DA0` = 16×`00` Sep 19 — populated at client startup, not by analysis) — resolve IDs via registration thunks (`sub_142AD7A30` callers) + pcap ID bytes + `.rdata` string-table dumps instead. The string-xref index is sparse (many `xrefs_to` queries time out on this 76 MB image); prefer `find` (strings/immediates, fast index) + `get_bytes` for tables + scoped `search_text`, and RTTI-adjacent `.rdata` reads for vtables. Latest session `eeeb023d` (Sep 18–19 2026) holds all §9 deep-BaseApp decompiles/disassemblies. Oct-11 (fresh worker, same image): decompile failures reproduce on all four (`0x142AD67F0`, `0x142AF86E0`, `0x142ADB7A0`, `0x142A8A1F0`) — disasm inventories above are the durable record.

## 11. Open questions / next steps

* TOP: DONE Sep 17 2026 — game key + paired login in `../captures/flows3` + `../captures/key3.txt` unlocked the full stage-1/stage-2 script (§7). NEXT: why our sessions stall (p2 silence / p5 no-redirect) with equivalent records — churn-tangle withdrawn (genuine client re-logs in seconds with no cooldown, see §7); prime suspect is now a byte-level difference in our LoginApp plaintext or stage-1 script vs genuine `62485`. Sep 18 2026 adds a SECOND paired stage-1/2 vector (`../captures/login3.pcapng` + `../captures/flows4`, `62485` → `:32838` → `:32909`) but without the CE key, so no new byte-level diff yet.
* Offline digest CLOSED 2026-09-20 (`TestComputeDigestMatchesClient` green,
  `5df886f7…` recomputed byte-identically): full client map (spaces + 40
  entities + static merge + 10 mode entities + 281 dynamics), walkprobe /
  r8probe / walkprobe2 / walkprobe3 / walkfinal verified (1242 visits,
  2625 tags, flags, entry names+pass). Live logins now carry the
  recomputed digest.
* Ping reply trailing 2 B metric (encoding unresolved; client ignores it).
* One unexplained repeat: reply prefix `9f4c1b99` byte-identical in 2022 and 2026 captures (see §8).
* EU2 wall CLOSED Oct-03 2026 — the p2/EU2 zero-byte silence and the
  stage-1 "park" were TWO stacked client bugs, not a server gate: a
  wrong stage-1 auth1 shape (unreliable-no-0b, corrected to the
  decrypt-proven reliable+0b) and a missing stage-2 victory return (the
  flood arrived, the code looped until timeout). EU2 now logs in
  single-shot: `LOGGED_ON` → rotation → redirect → rotation-2 →
  double-auth → 1252B flood, exit 0. The Sep-19/20 falsification
  campaign is kept as history in `AGENTS.md` ("Login — former
  blockades"); its "server-side gate" verdicts are superseded. Ports'
  openness remains unknowable from here (ICMP filtered; `-probe-port`
  times out = open-or-filtered, never refused).

Concluded (not questions): the game never re-logs; login-reply decrypt has no magic check (channel path has magic+pad-then-wastage layout); BaseApp handshake bytes identical genuine-vs-ours (pinned); PoW solves live in 38–214 ms, ours typically 45–65 ms the same way (single scans + racing key attempts); the EU2 silence was never bytes (Sep 19 our client was assigned `92.223.20.215:32838`, the exact endpoint the genuine client flooded with a full lobby from `login3.pcapng` Sep 18, and got zero bytes) — it was our own stage-1 auth1 shape plus a missing stage-2 victory return, CLOSED Oct-03; builders are pinned to PAIRED EU2 captures (`flows3`: `.213:20016`→stage-1 `.213:32892`→lobby `.212:32844`); ping-first sweep changes nothing (Sep 19: 5×16 B LOW ~34 ms to `.215` then immediate login+baseapp → silent at `.215:32860`); genuine stage-1 socket varies by run (login-socket `flows3`, fresh `62486` `login3`), both answered; back-to-back byte proof Sep 19 (`../captures/ours-p2-20260919.pcapng` vs `login3.pcapng`): our stage-1 22B field-identical to the game's successful one (flags/ID/link/att/mtu all equal; only prefix/rid/key differ) — same wire form, same manager family, opposite fate; error replies are plaintext (68×2 messages, 64 unencrypted-refused, 70 digest); login success blobs field-identical genuine-vs-ours (`flows3` S232 + `key3.txt` decrypts to the stage-1 endpoint with the same keys, `old_pass`, token2 shape — discriminator is NOT in the login reply); `wotlogin` sessions register account-side (website-visible Sep 19: probe LOGGED_ON 12:21:32 listed); username JSON in genuine py2.7 hash order (CE.txt, was: sorted — same length, silent still); p1/p3/p4 LoginApps dark from here (only p2/p5 answer); channel cipher starts past the 4 B prefix; prefix byte 0 = base + parity; basic → lobby proven; key ROTATES at stage-1 (reply carries new key; client must take it, fails zero/unchanged); footers `[seq][cumul]`; post-reply app = `authenticate` primed every bundle (manager verifies, finds proxy by channel); clusters differ in talkativeness (p2 was silent at our 22B / p5 talkative-no-switch / EU2 full); EU5 switches the game (policy dead); plaintext negotiation refused (status 64); black-box app probing has no oracle (even garbage doesn't disturb heartbeats).

## 12. Auxiliary protocols (mitmproxy EU2 session, `../captures/eu2-mitmproxy-flows`)

No credential/token HTTP exists — auth is purely UDP (§2). Everything here is surrounding infrastructure:

* **CSIS** (`GET http://csis.worldoftanks.eu/csis/woteu/?periphery=201…206`, UA `Python-urllib/2.7`): cluster/periphery availability XML. Requested 201–206, answered 201–205 — the 206 is the CUSTOM mod host, proving the modded `scripts_config.xml` was active during the capture.
* **RSS** (`GET https://rss.worldoftanks.eu/fr`, UA `World of Tanks v.2.4.0.0 #944`, gzip, 495 B ×2): in-client news feed.
* **WGC web cache** (`GET https://wgcg-eu.wargaming.net/web_cache/v1/get_static_lists/`, 551 KB): static game data, no auth.
* **Vivox voice** (`POST http://www.woteuusp.vivox.com/api2/viv_get_prelogin.php`, `machine_id=…`, SDK 4.9): SIP realm/proxy/STUN config XML.
* **wgcdn configs** (`ce-eu.wgcdn.co/dcont/game_loading/config_eu.json` 13 KB, `service-record-customization.wgcdn.co/…` 3.6 KB, `wot-collections-cdn.wgcdn.co/eu/collections_content_config.json` 30 KB).
* **XMPP chat** (TCP `92.223.20.54:5222`, `c2s.xmpp-wot-eu.wargaming.net`, 27 stanzas over the whole 30 s session): SASL PLAIN (`<redacted>` = `\0` + the 9-digit account id + `\0` + an 8-digit chat token — both redacted, per-login derived), resource bind `wot`, roster with clan `<clan> (<clan id>)`, clan MUC join, `game-host: login.p2.worldoftanks.eu:20016` in presence (EU2 = login.p2). Clean `</stream:stream>` close at logout.
* Token2 (SSO) format, cracked from a decrypted genuine session: `{accountID}:{19-char stable}:{39-char rotating}` (e.g. stable middle constant across invalidated→current token2s, tail fresh per login). Every successful login (basic AND token2) carries one in the 232B message (`token2` ~69 chars). Our basic sessions also get one — but with a DIFFERENT stable middle, and ours is rejected (`Invalid token2`) on relogin. Confirmed Sep 2026: with `SESSION=<stored session blob text>` (preferences file, local only) our token2 middle flipped to the genuine family — the server binds token2 quality to the machine behind the session-md5. BaseApp silence persists regardless (`-stay` run on the basic session), so the wall is byte-level, not session-level.
* Later sessions add: p5/EU5 full login → stage-1 (`:32819`, 16 msgs) → lobby (`:32832`, 1383 msgs / 20.8 s) in `../captures/flows` (which also holds a wrong-then-right `.213` login, stage-1 on `.213:32826`, and a 218 s lobby on `.215:32910`); several EU2 logins (`.215/.213/.212`) + stage-1 on `:32918` (15 msgs, three 36Bs) + 33 s lobby on `:32914` in `../captures/flows2`; live ping sweep Sep 2026 (only p2/p5 answer); Sep 18 2026 paired EU2 session in `../captures/login3.pcapng` + `../captures/flows4` (37 flows: 16 http + 20 udp + 1 tcp): orphan login rid 16675, failed login rid 16677/16678 (34B status 68, PoW `:1` 0.094 s), good login `62485` rid 80356/80357 (232B status 1, PoW `:2` 0.131 s) → stage-1 `:32838` (12 msgs, 22B key `7daba9af` rid 80358) → lobby `:32909` (1591 msgs, 644× 1252B). No CE key for this login (wanted — must decrypt that 232B to `:32838`).
* Login↔periphery mapping: `login.pN` serves EU-N (confirmed p2/EU2, inferred rest). Infra split: p5 = AWS eu-central-1 Frankfurt (`18.157.140.120`, 25 ms); p1–p4 = EU bare-metal (`185.12.240.x`, `92.223.20.x`, `92.223.54.x`, `45.82.31.x`).

## 13. Live observer tooling (Sep 27 2026)

How genuine-client traffic is captured now (Steam/Proton host, game runs stock):

* **LoginApp**: `cmd/wotproxy` explicit mode + `../mods/custom-server-mod`
  (CUSTOM host `127.0.0.1:20016`, periphery 206), September-proven: full
  534→55→728→232 `LOGGED_ON` pinned live on EU2 (`92.223.20.215:20016`).
* **BaseApp stage-1**: `wotproxy -baseapp-listen 127.0.0.1:32901` rewrites
  the S>C 232B endpoint in flight (`login/rewrite.go`:
  `decryptLogin` → patch record `[0:6]` (ip u32 + port u16 BE) →
  `encryptLogin`; length-preserving, 216 B body untouched, fail-open
  without a key). The game then sends stage-1 to our `tproxy` relay by
  its own choice — no firewall, no mod change for BaseApp.
* **BaseApp stage-2** (live Sep 27): the relay's `RewriteSC` hook
  (`tproxy`, nil in transparent mode) decrypts S>C channel traffic
  with the MITM'd login key, rewrites the `[44][ip][port BE][00 00 01]`
  redirect core (`login.RewriteRedirect`, length-preserving) to the
  same relay, and retargets it (`Resolve` follows; existing flows keep
  their sockets, chains welcome, loop-guarded). Genuine EU2 stage-1
  captured + decrypt-verified (22B rid/key equality, 167/167 channel
  datagrams) the same night.
* **Keys**: RSA MITM (Sep 27, live): the CUSTOM host entry names our
  `loginapp_mitm.pubkey` (mod-shipped, EU1–5 keep the server key), so
  the game encrypts LogOnParams to us; `wotproxy -mitm-privkey
  -mitm-pubkey` decrypts (OAEP-SHA1, `login/rsamitm.go`), learns
  the per-login Blowfish key, re-encrypts the identical cleartext to
  the real server key and forwards (length-preserving, fail-open).
  The recovered key feeds the 232B rewrite directly (exact session);
  `-keyfile` stays the fallback. Heap-scan/VEH key recovery
  (`keydump`, `../mods/keydump-veh-mod`) is superseded, kept as
  backup.
* **Transparent proxy PARKED**: OUTPUT-chain NAT (DNAT and REDIRECT, to
* **Transparent proxy PARKED**: OUTPUT-chain NAT (DNAT and REDIRECT, to
  loopback and LAN targets) delivers to a local listener (nft counters +
  conntrack reply tuples prove the rewrite), but `IP_RECVORIGDSTADDR`
  reports the POST-NAT destination (listener itself) — three targets,
  same result. `SO_ORIGINAL_DST` getsockopt on UDP listeners answers
  `ENOPROTOOPT` (verified against libc `getsockopt`: only valid on
  connection-tracked sockets, i.e. TCP). The redsocks-style cmsg path is
  proven for PREROUTING only; same-host OUTPUT NAT is unusable here.
  `tproxy` stays for PREROUTING setups (per-flow orig-dst relay,
  self-dial guard, loud drops).
* **ptrace vs the Steam sandbox**: pressure-vessel runs the game
  `NoNewPrivs` in a single-UID userns; cross-namespace ptrace is denied
  by design (`ptrace(2)` 5b — confirmed via upstream bubblewrap#526, no
  AppArmor here). Observed at every uid incl. root and file-cap:
  `PTRACE_ATTACH` stops all threads yet `TracerPid` stays 0 and every
  control op `ESRCH`s (74/74); only `SIGCONT` resumes. `wotkeydump`
  refuses sandboxed targets pre-attach (any uid); a VEH `int3` detour
  crashed on resume five times (restored byte verified, registers
  untouched — trap-flag stepping under Wine never delivered) and was
  replaced by the read-only heap scanner.
* **Steam facts**: live exe is byte-identical to the analysis copy
  (78,777,520 B, SHA1 `11e4ac11…`), `res_mods/2.4.0.1`, game log shows
  token2 AUTO logins; EU1 (`185.12.240.39/.40`) dark from this exit,
  EU2/p2 live; game binds `192.168.1.82` explicitly.

## 14. Battle (CellApp) volatile updates — 11B field map CLOSED Oct-02

Sep-29 match (`../captures/proxy-20260929B.hex`, battle key via MITM
790/984 leg): S>C heartbeat = alternating 276/292B snapshots with
13B records `[35 00][11B payload]`, 6587 records over 361 clean
snapshots (14/15 records each). Oct-14 adds a 324B mixed-train class
(b2: 269 dgs, ~8 `35 00` marks each): SAME 13B packing (86% of marks
carry EB–FE tokens), but event smalls interleave between records, so
only 21% sit on a 13-stride and the run≥4 gate harvests 0.5/dg vs
5.7–5.9 on 276/292. Gate-free token harvest (`ScanSnapshotTokens`,
token at fixed +2 survives framing errors) covers them; presence now
folds tokens, not run-records. The payload layout is engine-builtin
volatile data — defs carry exactly ONE volatile prop in the whole
332-entry map (`GunMarkerComponent.gunMarker`, var-size dict, live
walk-confirmed), zero `<Volatile>` in live entity_defs — so the
format lives in the exe only. IDA ground truth below (2.4.0.0 image,
base `0x140000000`): `VolatileInfo::parse` (`0x142ABE830`, reads
`position/yaw/pitch/roll` floats + descending direction priorities),
`ClientDefaultVolatileUnpacker` vtable (`0x14368AD90`, slot 5 =
`unpackVolatilePositionDirection` `0x140E37200`; mirror `0x140E55350`
for the packer-entity variant), position readers `0x140E369D0`
(type 0) / `0x140E36E60` (type 1), `BW::BitReader` (`0x142CA1860`
ctor, `0x142CA1900` unsigned + `0x142CA19A0` signed MSB-first reads,
`0x142CA1880` exact-consumption dtor check).

Wire form per record: `[ID u8][position][direction]`, observed
population 6586/6587 = `[ID][posType0 6B][dirType0 4B]` (1+6+4 = 11
exact). Slot order CLOSED Oct-11 (IDA, same image — output mapping
in `0x140E369D0`/`0x140E37200`): position wire order is **(x, z, y)**,
output is **(x, y, z)**. Position 0 = 6B (X 1+4+12b ×scale, Z
1+4+12b ×scale, Y 1+4+9b ABSOLUTE — height gets fewer bits and no
scale); 1 = 3B x,z-only form (X 1+4+7b, Z 1+4+7b, both ×scale;
output slots read (y-marker, x, z) with the y slot = `-13000.0`
absolute, `baseY-13000.0` relative — the tracker is posType-aware;
slot assignment proven by base-add alignment (x+=base[1258],
y+=base[1259], z+=base[1260]));
2 = absent (`-13000.0` float ×3 written by the reader itself).
Direction output order is **(yaw, pitch, roll)** (wire reads run
roll,pitch,yaw): direction 0 = 4B SIGNED reads (roll 11b × 2π/2048,
pitch 11b × π/2046 exact — measured `0.0015354804`, NOT π/2048,
yaw 10b × 2π/1024); 1 = 2B (roll8, pitch8 × 2π/256; yaw slot
`FLT_MAX`); 2 = 1B (roll8 × 2π/256; yaw+pitch `FLT_MAX`); 3 =
absent (`FLT_MAX` ×3). (Only (0,0) seen live, so dirType1/2 slot
semantics are static-only.) Size fn `0x140E36580(posType,dirType)`
confirms the byte table: pos{6,3,0} + dir{4,2,1,0} (+1B ID).
Bit order MSB-first; position is a custom float (sign + 4b exponent
with forced `0b1000xxxx` high bits + N-b mantissa as f32 bits, then
`+ (-2.0)` (`dword_143602C68`, unconditional `addss`), then
× per-entity scale from entity state `[entity+0x130]+0x77C`);
base-add is CONDITIONAL: after decode the code calls
`[entity+0x40]`-slot and adds the base triple
(`[entity+0x130]+{0x13A8,0x13AC,0x13B0}`) only when that call
returns NULL (wire coords are base-relative). Per-axis quanta are
also emitted when asked (`0x140E369D0` tail: x/z `2^exp/4096` ×scale,
y `2^exp/512` absolute — same (x,y,z) slot order). ID byte is the BW
entity ID (`handleEntityPackedVolatileData` `0x140E3D300` looks it
up via `sub_140E3C1C0`, `No such entity %d` on miss). C>S side:
`avatarUpdateVolatileProperties`; per-entity packer switching via
`changeVolatilePackerType` exists. x/z convention CLOSED (above);
`createEntity` dispatch decoded next (below), per-arg stream reads
still open.

Validation on the wire: direction-last placement proven by
distribution (bytes [7:11] decode to roll≈0/pitch≈0/yaw-spread at
99% vs chance elsewhere); yaw slot-tracking med-step 0.098 rad
circular (p90 0.29); yaw-matched consecutive positions med-step
~30-45 prescale units (vs ±70000 spread); position third field
height-like (±35 prescale) vs map-spanning first two. ID dynamics:
14 entities every snapshot + span-limited visitors (early/mid/late
spans = spawn/despawn; one late joiner, one 0x00 singleton control
record); byte0 values 0xEB–0xFE minus 0xF8 (stable per entity —
the token namespace, exact ID width stays open; the F8 gap may be
self, unproven). STILL OPEN (runtime, not layout): per-entity
position scale value, base-add mode per record (`0x140E369D0` tail
adds `[entity+13A8h]` conditionally), creation-message parse
(116B bursts carry it — next).

Oct-02 static follow-up (same image): the unpacker family are
`CellAppDefaultEntityVolatilePacker` methods (pack side) /
`ClientDefaultVolatileUnpacker` (client) — proven by the
`...unpackVolatilePositionDirection: Invalid position type/direction
type` log strings referenced at `0x140E3725C`/`0x140E37335` (and the
`0x140E553xx` mirror). ID byte CLOSED as BW entity ID:
`handleEntityPackedVolatileData` (`0x140E3D300`) looks the entity up
via `sub_140E3C1C0` and logs `No such entity %d` with the ID byte on
miss, preloading the -13000/FLT_MAX defaults first. Base-add
CLOSED as unconditional `+ (-2.0)`: the reader issues
`addss xmm6` with `dword_143602C68` = `-2.0` exact before the scale
multiply. Scale source located (value stays runtime): each decoded
coordinate is `× [entity+0x130]+0x77C`, a per-entity float from
entity volatile state — NOT a constant, which explains the
wire-fit scatter (no static lever left; needs a live entity
object). Per-axis mantissas confirmed in code: coord1 12b, coord2
12b, coord3 9b (height gets fewer bits). Position type 1 head reads
3B (word+byte) then the same scaled path — an alternate compact
form. C>S side named: `avatarUpdateVolatileProperties`
(`0x1402402D9`); `changeVolatilePackerType` exists (`0x1402405D9`,
per-entity packer switching). REMAINING static-open: creation
parse (mechanism below; caller context open).

Oct-12 late live validation (same capture — `lobby.ScanSnapshots`,
committed): 13B `[35 00]` trains parse at exact 13B periodicity
(5458 records, 19 tokens EB–FE minus F8) with the decompiled bit
layout verbatim (MSB-first BitReader, 1+4+12b ×2 + 1+4+9b, bias
-2.0); direction wire order CORRECTED to yaw11/pitch11/roll10
(scales 2π/2048, π/2046 exact, 2π/1024 — the old roll-first reading
is withdrawn: it puts mean |roll| at 2.4 rad against flat physics,
while yaw-first validates at turn-rate stats, med nonzero-step
0.018 rad). Positions decode PRESCALE (runtime scale + base skipped
— the affine fit absorbs both). Token→entity mapping stays OPEN and
fought for: muzzle-anchored affine fits overfit camp clusters
(mirrored scales), the own C>S track is displaced (dense fit
useless), spawn anchors unmapped — presence is trackable per token,
names need a per-epoch joint assignment (next build).

`createEntity` dispatch (Oct-11 IDA, same image — arginfo decoded,
per-arg reads open): registration record is 24B
`{idx u8, u8, u32, name*, arginfo*}` (builder `0x142AE7160`,
vector-append `0x142AD7A30`; thunk `0x140240740` passes
`(iface, "createEntity", 1, 2, 0x1442DCC00)`, sibling
`createEntityDetailed` thunk `0x140240780`). The arginfo entry is
`{handlerVtable*, u32, lambdaVtable*, u32}`: handler =
`InputMessageHandlerT` (dtor `0x140E44F60`,
`handleMessage` `0x140E44D40`), lambda =
`std::function<void(ServerConnection&,BinaryIStream&)>`
(copy `0x140E44890`, move `0x140E448B0`, RTTI `0x140E448D0`,
delete `0x14035C040`). `handleMessage` validates the source
address (comparator `0x140E48250` vs entity-state-derived expected
struct, `+408`/`+416` sources) then invokes the bound functor
(vtable slot +16), else logs `ClientMessageHandler::handleMessage:
Dropping packet from unexpected source`. Local create API
`0x140F16030(spaceID, class, vehicleID, 12B vector, packed blob)`:
space lookup (`0x40000000` = client/replay split), class resolve,
pack via `0x140396800`, create via `0x140E3EFE0` (typeID from
class+130); player-on-vehicle warns unimplemented. OPEN: the
captured functor's `operator()` (the actual per-arg stream reads —
constructed at interface-init runtime; the init-array walker uses
indirect calls, no static xrefs) and the 84B burst-body field
split (fixed head vs props blob). Consumer side mapped Oct-11: `handleEntityPackedVolatileData` (`0x140E3D300`, 66 lines decompiled) preloads position `-13000.0`x3 + direction `FLT_MAX`x3, looks the entity up (`sub_140E3C1C0`, `No such entity %d` on miss), then invokes unpack slot +40 (vtable `0x14368AD90` slot 5 = `0x140E37200`) with (stream, entity, record fields, default bufs), then applies via `sub_140E3D070`. Init array is 0x50-stride: every method entry carries the same handler/lambda vftable pair (class-level dispatch, not per-method) with a self-pointer at +0x40 — per-method captures are runtime-built. OPEN route: callers of `0x140E3D300`/vtable users (no static xrefs — virtual dispatch wall; needs vtable-use scan or runtime trace). `avatarUpdateVolatileProperties` confirmed as the C>S volatile method name (interface string table). Apply step decompiled Oct-11: `sub_140E3D070` is `handleEntityMoveWithError` (applies the move, fires follow-ups, skips with `Received position update before space creation message (i.e. createCellPlayer)` when spaceless). 0x35 identity CLOSED Oct-11 as battle small-ID (NOT a method rank): Avatar carries 42 client methods (idx 0-41), Vehicle 11 — index 53 exists on neither, so the uniform `[35 00]` head on 6587 snapshot records is bundle-level small framing (cf. lobby 0x13/0x1a/0x45/0x46) with subtype 0x00, consumed purely by the C++ volatile path, never `.pyc` dispatch. Entry-point family complete Oct-11 (all three decompiled, all funnel into `sub_140E3D070` whose last arg reads as isVolatile): `handleEntityPackedVolatileData` (`0x140E3D300`, unpacks via slot+40 then applies, last=1), `handleEntityDetailedVolatileData` (`0x140E3CAF0`, pre-unpacked apply with a global scratch, last=1), `handleEntityNonVolatileMove` (`0x140E3D1F0`, absolute-position apply, last=0 — the creation/teleport-shaped path). The record loop calling them is still unlocated (no static xrefs — same virtual wall); its shape is now fully constrained (parse 13B record → route to one of three). Creation takes either the absolute unpack branch or the nonvolatile path — caller open.

C>S battle calls (Oct-12, wire + shipped defs + IDA static tables —
`../captures/proxy-20260929B.hex`
flow `45507→.67:32810`, 6.8 min, key = token2 790/984 MITM leg: 7214/7214
C>S + 561/561 S>C 276/292 snapshots decrypt with it). Framing CLOSED,
CORRECTED Oct-14 (the Oct-12 `0x93 family` model below was a
single-sample illusion — corrected, trigger finding itself unaffected):
bundle = `[02][key4]([SUB][len16le][args] | [1a][len16le][26B position])*`
with records always bare. `key4` is the 4B value the server assigns per
flow in the flow's first 36B S>C reply (`5804 ff08 000000 [rid?] 0100
[key4] 000...`, same slot in both versions), echoed by the client as
every C>S bundle head, acks included (Sep-29: `8b584a93`; Oct-14 b1/b2:
`831e5b63`/`16e4d857`; Oct-14 1752: `92062e02`). In Sep-29 the key
happened to end in 0x93, so the lead record read `[93][SUB]...` and 0x93
was misread as a per-record family tag — but chained-inner records were
bare all along (s1 `...93 07 0700... 10 0400 00000000...`), and 2.4.1.0
keys (`...57`, `...63`, `...02`) expose the bare form everywhere. SUB
and length coexist (the earlier SUB-is-length reading was wrong: 0x1a/34 =
[1a][len 26][26B], 0x07/44 = [07][len 7][7B] + [1a][len 26][29B], all modal
classes exact-consumption). SUB = Avatar own-cell doc index, statically
(IDAs three registration tables dumped in order: BaseApp 18 msgs,
CellApp 8, Client 80; doc order, interfaces excluded). Every C>S app is
`[02][key4][SUB][method args][1a][1a00][entity u32][trailer payload]
[tail 2B]`, SUB = own-cell index into
Avatar.def order (verified against `entdef`, iface 4 + own 38), and every
position-carrying call ends with the `[1a]` trailer (standalone 0x1a =
trailer only). Oct-12 late session (same capture): bundles CONCATENATE
records — the 10B 07-record (`07 07 00 06 00 01 XX …`) rides inside
0x18/63, 0x12/52 and 0x06/51-led bundles (lead-SUB census undercounts
chained records, which carry no 93: the tag seen on lead records is the
key's low byte, not framing); every position bundle carries exactly one 29B trailer
(`[1a][1a00][entity][nonce][speed][xyz][tail]`, 7179/7313; 134 bare
calls carry none: 116× 07/15 + rare tiny event-like SUBs
01/0b/12/13/14/84/ff + one 676B 0x14). Nested xyz tracks own motion
exactly like standalone (ranges + median steps match per class), so one
trailer parser serves all SUBs (`ParseTrailer`). The three loops rotate
(1a→07:1734, 07→1a:1695, ±18: ~1300; same→same rare): ~6.2 + ~7.4 +
~3.5 ≈ 17 Hz combined. SUB census: 0x1a/34 ×2535 (moveWith, CLOSED below),
0x07 ×2994 (15/44/52/…/383B), 0x18 ×1405 (53/63/61B), 0x12 ×165+
(13/42/52/60/61/59/71B), 0x06 ×49+ (51/59B), 0x1c ×21 (46/56/65B),
0x1d ×10 (49/59B), 0x10 ×9 (4 lead + 5 chained, the shoot trigger —
lead-only census saw 2–4 of them), 0x07/15 ×116 (bare 9B, no trailer,
~0.28 Hz). No 0x1b (vehicle_shoot, own[27]) in 6.8 min — zero shots fired.
SUB→method map REVISED: 0x1a=26 vehicle_moveWith(UINT8) CLOSED (only
periodic position sender in shipped Avatar.pyc:1923, 6.2 Hz, smooth-track
proven); 0x07 is ack/heartbeat-like, NOT discloseEntities — XX is a u8
packet sequence (256 values, +1 steps, ~12 wraps over 3019; the 383B is a
25-op backlog flush ~50s in) and content is near-constant (only XX + one
variant byte vary), refuting the 6B disclose stride (head diffs
8,12,15,19,27,35); 0x18 is NOT plain reportClientStats (no 5-in-[0,1]
summing to 1 at any offset over 935×53B, 6-float hunt also empty);
0x1c/0x1d trackGun stays medium (aim-event rates, VECTOR3-sized heads).
0x1a/34 field map CLOSED: `[02][key4][1a][1a00][entity u32 =
0x20529314, battle-constant][nonce u32][speed f32 = 7.15 cruise][x][y][z
f32 LE][tail 2B, 1900 modal]` — xyz smooth (median step 0.58 m from
(373.3, 24.5, 252.3)); column-stability over 2535 samples: [0:13]
constant within a flow. key4 is per-flow (server-assigned each battle:
`8b584a93` here, `831e5b63`/`16e4d857` Oct-14 b1/b2), so the head is
constant within a flow but NOT across flows — cross-flow head matching
is invalid. Nonce verdict: per-packet uniform-random (distinct=n, halves
uniform, lag-1 ≈ −0.17, r(turn-rate) ≈ −0.02) — freshness, since the head
is constant (second-capture confirmation open). Parsers in
`lobby/battle.go` (`ParseMoveWith`, `ParseTrailer`, synthetic
tests). NEXT: second battle capture (nonce distribution + XX wrap +
07 semantics); S>C record↔xyz correlation for the creation parse.

Shots (Oct-12 hunt, same capture — interim, needs a firing capture to
close). OWN shoot is rigorously ABSENT: SUB 0x1b (vehicle_shoot, Avatar
own-cell[27], 0 args per defs) appears 0/7313 C>S bundles — the player
never fired in 6.8 min. Its shape is predictable (`[93][1b]` + 29B trailer,
~35B app) but has no live sample. OTHERS' shots live in S>C, now mapped
as containers: non-snapshot S>C (3539 msgs) is almost all `13 tick +
1a/ba` trains = volatile `[35 00]` records + 07-echo + calls; the
07-echo is a confirmed ack (echo-XX tracks C>S record-XX lagged, with
retransmit dups). Routine tails (71B ×1501 + 74B ×584) end with one
unidentified fixed-head call carrying a V3 pair (V3a stays in a map
corridor x[251,409]/z[−85,264] — not own tank, deviation p50 = 144 m —
V3b roams ±599; framing `…00838201 01 [V3a][V3b] …0120`). Rare long tails
(≥95B, ~20 total) are the event candidates (one 104B: 32×`25` array +
double echo + 46B call with V3 pair). Zero-record S>C docs classified:
507B battle-results/config pickle, 790B engine+pickle mix, 1227B 1a/0x88
battle-info doc (epic_config/battleModifiers/allowVehicles), 1059/711B
opaque second-layer blobs. S>C does NOT use replay-style
[eid][mid-u32][len] framing (u32==37 hits are all ASCII `%`). Replay
ground truth for the arg layouts (`wotevents` already decodes them on
Prohorovka): showTracer = Avatar.client[17] (avatarFixed[37]:
I32×2,U8×4,F32,V3,V3,F32,F32,U8×2 = 50B, gravity-ish 6.28, maxDist 720/
10000), explodeProjectile (10 args + U32 tail), showShotResults
(Array[{U32,U32,U8}]), Vehicle.client[1] showShooting (U8,I8,U8 = 3B).
DECISIVE NEXT: a firing capture (operator fires N times at recorded
times) — 0x1b appears C>S and the S>C tracer/damage answers land at
known times, closing both directions at once.

Tracer CLOSED live (Oct-12 late session, replay-anchored). Replays are
S>C broadcast only (Prohorovka: 0 vehicle_shoot, 0 vehicle_moveWith —
no inputs recorded; but 128 showTracer + 81 showShooting + 105
explodeProjectile + 7 showShotResults + 47 showDamageFromShot + 9
showDamageFromExplosion + 42 stopTracer). Raw arg templates (BigWorld
native serialization, identical live): showShooting (Vehicle.client[1],
replay mid 1) = 3B `01 00 XX`; showTracer (Avatar.client[17], mid 37) =
50B `[I32][shotID I32 LE][U8×4 flags][Range F32 ∈ {57,75,76,85,88,90,
122,128,150,155}][start V3][end V3][A9 F32][A10 F32][00 00]` (verified
bytes: Range 150.0 = `00001643`, ShotID 28897910 = `76a2b801`, flags
`00380101`). Live S>C carries 114 of them as `[13 tick][1a 0x73][50B]`
followed by the snapshot train (tracer rides first, priority) —
shotIDs 27.2M (live ID space), flags `00100202`, same Range set and
in-map V3 pairs. S>C 1a-sub census: 0x73 ×128 (tracers), 0xba ×2524
(volatile trains), 0x88 ×13 / 0x93 ×9 (config/creation), rest noise —
so explode/damage/shooting ride inside 0xba tails, not own subs (open).
Shell-kind finding Oct-12 late (no separate record needed): tracer
flag byte 3 = shell kind — 0 HOLLOW_CHARGE (HEAT), 1 HIGH_EXPLOSIVE,
2 ARMOR_PIERCING, 4 ARMOR_PIERCING_CR — pinned by triple dissociation
(replay showShooting arg2 ∈ {1,2,4} ↔ tracer Flags[3]; Sweden T34_100
gun holds exactly AP+HEAT+HE and its 7 tracers read exactly {2,0,1};
SU-152 all-HEAT ×9, Hummel all-HE ×8, Chi-Go all-APCR ×6;
`lobby.ShellKindName`, feed shows `[tank|SHELL]`). Gun+kind resolves
to one shell (kind tables per gun are near-singletons) → pen/damage
via shells.xml is a table lookup away (build-time codegen follow-up,
same as the gun table).
Own 0x1b still 0/7313 C>S and absent from replays: predicted
`[93][1b]` + 29B trailer (~35B app) remains unsampled — yet the Sep-29
Sweden battle (recorder ExampleUser, `spaces/115_sweden`) holds 11
tracers starting within 15 m of own xyz, 2 certain self (muzzle
directly above own center, e.g. start (−126.3,2.2,280.2) vs own
(−126.3,0.9,279.7)): the server accepted ~6–11 self shots (ISU-reload
decontamination) with NO C>S shoot input under exhaustive search —
no [93][1b] in the complete 7313-bundle head census, no inner-0x1b
records (float bytes only), no distinctive pre-shot bundles (routine
07/1a only, enrichment flat), no field markers (F1 uniform, tails
split on certainties, 07-XX/VV sequential u16), no timing coupling
(nearest-0x1d never within 300; 0x1c gaps loose; 0x14 = channel-setup
+ bulk), no second channel (lobby flows end/start exactly at battle
bounds). Corroborating: harm_receiveAttackResults is defs-only (never
called by any client .pyc — missing harm dicts are EXPECTED, not
evidence), 0x1d CONFIRMED as trackRelativePointWithGun by
relative-scale V3 (`35fa0e3e…` ≈ 0.14). Standing fork: (a) wire table
≠ doc order for shoot (static route: Avatar cell-method registration
order via objdump, open); (b) state-based firing (server derives shots
from streamed aim/trigger state — fits the absence; tail1=03 runs are
the lead state candidate). Reload-greedy self shots for reference:
flowIdx 1811, 2212*, 4786, 6807, 10536, 11023 (*contaminated-cluster
member). Firing capture with noted times remains decisive.
Physics bound (nearest-0x1a ≤0.08 s ⇒ true self ≤ ~6 m + muzzle):
only ~4 strict (<8 m), rest allies — F1 MSB/b30/LSB all mixed on
pre-shot bundles (nonce confirmed, no fire bit there); joint
(tail0,tail1) collapses to {(19,00),(08,03)} pre-shot only.
Single-socket confirmed (all S>C battle → 45507), so inputs are in
the censused bundles. Every routine SUB/timing/field/edge test
fails: the trigger is either an F1-bit combination needing bigger
samples, a remapped SUB needing the exe table, or state-derived
server-side (no discrete input exists).
RESOLVED Oct-12 late (tracer args[0] = shooter entity, replay-proven
by two-camp firing pattern): 28 distinct shooters in two blocks
(542282512–515 ×35 shots + 542264088–111 ×79: losing team with 4
active guns vs winners with 24 — relevance-culled).
VERDICT Oct-12 late: SUPERSEDED — see RESOLVED below (recorder =
542282516, 9 shots). Kept for archaeology; its distance legs used a
displaced C>S track plus a hex slip, and its conclusion is wrong.
Original text: recorder never fired here (T2). Proof chain:
no a0 tracks own (best meddist 23–49 m; true self would sit ~5 m);
capture continuous (zero thin seconds in 407 s, no gaps to hide in);
single socket (inputs can't be elsewhere); harm defs-only (correctly
absent); near-own tracers = camp-mate TD + brawlers/pushers (even the
1.4 m muzzle-over-deck case); mid + AMX kills = allies' (fire/DOT
explains missing proximate tracers — e.g. @10993 hit → f1 burns out
@11152); own death = enemy 264099's duel + another enemy. The 5
"confirmed" shots leave zero wire trace because they never left the
client (reload-guard clicks / confabulated kills — the T20 chase and
AMX face-off happened, the firing didn't). Verified instead: camp +
AMX-duel near-own tracers exist (T20/Cromwell have none <18 m);
a0=shooter re-confirmed (per-a0 single-tank tracks + fixed Range per
shooter + replay two-camp pattern); explode framing (len8=41 empty
tail, shotID→tracer linkage e.g. 27742688). C>S shoot shape stays
PREDICTED ([93][1b]+trailer if doc-order) pending ANY firing battle;
a firing capture with noted times is still the gold-standard closer.
Per-shooter start tracks + meddist-to-own prove NO shooter is self
(best candidates 513: meddist 49 m, 264100: 23 m, 264099: 27 m —
all roam independently; true self would sit ~5 m): THE RECORDER
NEVER FIRED. Near-own tracers = brawling/pushing allies (even the
1.4 m muzzle-over-deck case), mid kills + AMX kill = allies', own
death = enemy 264099's duel. The paradox dissolves: no inputs because
no shots; harm/flags correctly absent. C>S shoot shape stays
PREDICTED ([93][1b]+trailer if doc-order) pending any firing battle. Narrative lock
(user: SU-152 camper, 3 early cross-map shots, behind-rotation vs
T20/Cromwell, T20 kill, alone at end, AMX kill, death): wire confirms
4/5 — camp-then-roam track (late camp (263,19,−49)), 5 early tracers
with 830–1050 m shell travel (cross-map ✓), f1-death@11152 → own-stop
@11172 0.7 s later (AMX kill then own death ✓), 0x1d all-late aim
cluster (endgame duels ✓); T20 unattributed among mid deaths
(f7/ec/fa). Physics bound on self-attribution (nearest-0x1a ≤0.08 s
⇒ true self dist ≤ ~6 m + 5 m muzzle): only ~4 certain (<8 m), rest
allies — consistent with ~6 ISU/SU-152 shots. 0x12-V = 9 even-spread
values (rage/gear/zone-ish, not events). Shoot input still unfound. Server-aim context
(user: aim is server-driven from mouse, click = trigger, S>C tracers
are broadcasts incl. self): exhaustive field differentials still show
no trigger — pre-shot 0x1a bundles collapse to joint states
{(19,00),(08,03)} only (vs 10 baseline states, p≈4e-6: players steadies
to fire) with tail0 now reading as moveWith FLAGS (0x19 =
FWD+RIGHT+CRUISE50, 0x08 = RIGHT, etc. — cruise/rotate combos match
driving; MOVEMENT_FLAGS from Avatar.pyc), but no fire bit: F1 uniform,
tail1=03 onset/edges/containment all fail (mixed on certainties),
07-XX/VV = pure u16 sequence, 28B = acks for reliable docs (22 ≈ doc
count), 0x14 = channel-setup + bulk. Standing fork: (a) trigger hides
in an untested field combination or shares routine SUBs invisibly
(needs exe table order via objdump, or firing capture); (b) recorder
never fired here — near-tracers = brawling/pushing allies (even the
1.4 m case fits nose-to-tail pushing), ISU kills = uncaptured battle;
vehicle ID for Sweden still open (roster shows stock parts only).
Bundle grammar breakthrough (Oct-12 late): records, 07-record and
trailer compose INDEPENDENTLY — proven by death: own position stops
@11172 (0.7 s after f1/AMX dies @11152) while 07-acks continue, and
@11174 carries a bare 0x13+07-record with NO trailer (observer mode).
The two 0x13s (@695 start-phase + @11174 death) read as player-state
transitions, not harm (14B args ≪ 100B+ harm dict) and not kills.
AMX window (@10500–11152) is routine 0x12/0x07 multi-record mix, no
anomalies — the 4 kill shots' inputs hide in plain routine sight.

Explode CLOSED live (Oct-12 late, CORRECTED same day — field order):
31× `1a 0x91` windows shaped `[1a 91][len8 = 41][00][shotID I32
LE][A1 f32][Range f32][Pos V3 = impact][End V3][A8 f32]`
(`1+4+8+12+12+4` = 41 exact). The old single-Pos reading took the
SECOND triple (always near-origin); wire truth is the FIRST: own-shot
ground truth s2 (-133,0,284) and s5 (426,53,-238) sits at +16/+20/+24,
and the replay homology is exact (replay explodeProjectile carries
Pos+End too: Glacier |pos-start|=17 m at close range while its End
triple reads (22,-1.8,-17) — same near-origin second triple as live).
The second triple's semantics stay open (labeled End). Caliber lives
at the A2 slot. Tracer END semantics corrected with it: Glacier
|pos-start|=17 m vs |tend-start|≈770 m — the tracer end is the
trajectory endpoint (despawn), NOT the impact (arty warnings
unaffected: plunging shells end at ground ≈ impact). 23/31 join live
tracers by shotID (`lobby.ScanBattleExplodes` + join: caliber rule +
in-map impact + 44B exact, counts unchanged by the fix); the other 8
are structurally perfect but tracerless — capture-loss class (their
shotIDs occur nowhere else on S>C; known lossy path), two of them
130mm = SU100Y-only caliber, attributing both to Mr__Nobody___
(marked) and closing the "silent killer" paradox half-way: he fired
acknowledged hits at 04:10 + 06:01. Tracer bodies carry the tracer
FIRST then the snapshot train (priority); explodes ride ~0.4–5 s
later (shell flight by range). Victim attribution CLOSED offline
(Oct-12 late, `lobby.Observer.victimOf`): explodes mark spotted hits
whose victim camped near the impact — nearest alive non-shooter
muzzle within ±120 s (offline two-sided) / past-only (live core),
HIGH (≤15 m & ≤30 s) / MED (≤30 m & ≤120 s) / `victim=?` else;
Sweden 13/23 joined (8 HIGH: s5→542264097 at 7 m/+16 s, kill-credit
confirmed; s2→ally T-50-2 friendly-fire flag via side split; Hummel→own
camper ×2). Suicide-gated by the 30 m cap; dead excluded via kill
feed. Still open live: showShooting (3B, no standalone sub at
replay-like rates — must hide in tails), showShotResults/damage (same).
HIT feed (Oct-12 late): the 22 joined + 2 caliber-attributed + 6
caliber-only `?` rows (misses suppressed — no explode means
unspotted/ground, silent by the ack rule), each joined row now
carrying `victim=<side> <name> [<tank>] <HIGH|MED>` or `victim=?`. Ack rule REFINED same day:
explodes mark NON-FATAL spotted hits — all 4 observed fatal blows
(own s6/s8/s9, AMX→swojak) carry no explode, and no explode links to
a kill; whether the server suppresses or replaces the impact record
on kills is open. Kill feed CLOSED via `deathOrder` (not damage
decodes): per-death bodies `[55 0a]deathOrder[71 02][4b ctr][73 2e]
[VV WW 02 10][XX 78 01][victim][killer]`, victim-first (a
survivor-second body never occurs), counters gapless — Sep-29 all 24
kills incl. own 3 (s6→097, s8→T20, s9→AMX, each ≤1s after its tracer)
and a self-kill by another player; ALLY wipe 15/15 = defeat. VV WW is a
per-battle pair, opaque (Oct-14: `0c 23` b2 28/28, `0c 99` b1 2/2,
`0c 92` + `08 b6` next-session battles, `0b a8` Sep-29 — uniform
within each battle, varying across battles on the same host/build; no
map/tier mapping found; the whole 6-record bundle carries the same
prefix). Oct-14 b2 re-proof: 28/28 kills attributed incl. own #8
(ExampleUser T20 → an enemy Super_Hellcat at 05:12, 8 own shots 0
kills, spectated to 14:50; enemy M12 closed with 4 late kills).
Death bundle
CLOSED (Oct-12 late): every death rides 6 chained `0b a8 02` records
`[03 TAG 04 00][1a TAG 6c 17 80 02 7d][01][deathOrder…][00 00 00 01
00 0][06 TAG 98 XX 00 00 00][04 TAG 84 01 00][06 TAG 98 XX 00 00 00]`
— 03b/1a-fixed/10 all exactly 24/24 (1a body CONSTANT across kills:
not damage, a fixed death descriptor; two tags per bundle, entity
semantics open). Battle-start carries the same family as
`03 XX 1c 01` + `06 XX 98 01 00 00 00` chains (~30, token-range tags).
Per-hit HP numbers are in NONE of the surveyed families (0x75 =
markers/text, 0b a8 02 = death/creation signaling, residue u32 scans
= unframed noise with self-pairs) — HP stays BLOCKED behind method
framing (same wall as live showShooting). Credits are
server-authoritative; MECHANISM is not on wire for 5 credits
(Gracek×2 with no proximate tracers — silent fire-DOT from unspotted
hits fits the ack rule; Danil's kill 15s before his only tracer;
_Jaxi_×2 with zero tracers ever — ram or lost packets, undetermined).

Marker family CLOSED structurally (Oct-12 late,
`lobby.ScanBattleMarkers`): S>C `[1a][0x75][len8]` records, chaining
verified (back-to-back `[1a 75]` + `[13 xx]` tick boundaries; the
`1a ba`-as-framing reading is re-rejected — flat length distribution
under boundary validation, same misparse as before). Battle shapes:
len 27 sub `0x2a` = link `[2a][000000][A u32][B u32][15×00]`
(Sweden: 5, all ENEMY+ALLY, duel/spot-adjacent — members shoot each
other ±11s or die ≤64s later); len 39 sub `0x1d` = report
`[1d][000000][counter u32][ent][12×00][00 0c][pos V3][00]`
(Sweden: 11, allies Danil_380×8 + _KissMyTralala_×3, shared global
counter with the links). Other 0x75 subtypes are map-script text
blobs (battle start). Semantics OPEN (spotting-link vs team target
ping; decisive test: operator ping + C>S correlation, or a second
battle capture). Feed prints LINK/SPOT rows (names/counts, never
coordinates).

Token→entity map: OPEN with completed negative survey (Oct-12 late).
Global affine (one scale+offset for all tokens) REJECTED: 132 muzzle
anchors vs all token tracks score 4.5–7.6% coverage ≈ chance.
Per-pair fits overfit (4–6 anchors vs bursty tracks: winners split
votes across entities at chance level). Structural causes proven:
S>C snapshots carry OTHERS only (own 9 anchors pair 0–2 token
samples total), slot duty cycle ~8–25% (bursty presence), own C>S
track is chaos (displacement 69–644 m shot-to-shot, 100 m+ teleports
every second — not a constant offset). Token yaw is NOT movement
direction (fast-quartile resultant scattered; likely
turret-relative like gunAnglesPacked, which the Prohorovka replay
confirms is hull-relative: tracer−gunYaw sd 1.2 rad). Y absolute
decodes map-plausible (heights 0–35 m), so the prescale unpack itself
is trusted. Route forward: per-epoch joint assignment needs denser
anchors than Sweden offers (a bush camper with 10+ shots), or the
runtime scale read in-process.

Shot feed (Oct-12 late): every shot attributable. Replay side
(`replay.ShotFeed`, `wotevents -shots`): tracers × setup roster →
`[mm:ss] [name] [tank-tag] SHOT` (Prohorovka: 128 rows, names+tanks
throughout, 11 own pinned). Live side (`lobby.ScanBattleTracers` +
`lobby.ParseBattleRoster`, Sweden): battle-start creation bulk
(di7..22 1223B-run) pairs 30 entities→usernames (binary-LE +
doubled-name + ascii-ID triple rule); 132/132 S>C tracers attributed
(denormal-ghost rejection drops 4 slide-ghosts sharing real shotIDs
plus 1 orphan-ID window). Live tank names CLOSED Oct-12 late via the
.pyc IntCD rules (`makeIntCompactDescrByID`): per-vehicle blocks
carry `[first-record][0f][IntCD u16le]`, with a 3-byte EXT form under
tag 0x10 for ids > 255 (Sep-29 germany/265 Chi-Go proves it), and a
same-shape 2-byte form under tag 0x11 (Oct-14 b1 own-Challenger:
flags 0x04 with one optdev slot fitted; `Vehicle(5,55)` +
6/6 Challenger components + flags walk land exactly):
30/30 entities → (nation,typeID) → list.xml tags, 26 gun-verified,
4 silent tier-plausible (KV-1s, FV304, M6, SU100Y); user's T20/AMX
memories confirmed as usa/A07_T20 + france/F69_AMX13_57.
Live teams CLOSED Oct-12 late: the u8 right after the doubled player
name is the team (1/2 = replay `team` values; `lobby.ParseBattleTeams`
requires 01/02 followed by 00 00): Sep-29 30/30, 15/15 split, own
team = 2 (ExampleUser); combat-corroborated (duelist 542264099 +
killer 542264105 both team 1). 132-shot feed splits 64 ALLY / 68
ENEMY. Note: killer 542264105 (SU100Y) fired zero tracers — killing
blow without a broadcast tracer (ram/fire/DOT or culled shot, open).
Live reloads CLOSED Oct-12 late, EXACT (no ranges): the server sends
the mounted modules INSIDE each creation block — the vehicle IntCD is
directly followed by the mounted compactDescr (`[chassis,engine,
fuelTank,radio,turret,gun LE u16]` 12B mounted-only + flags, then the
packed name; `lobby.ParseBattleMounts`, 30/30 name-anchored, 6/6
components resolve to the right vehicle every time, two independent
implementations agree). Mounted-only because the client owns the
unlock tree locally — battle wire carries what's fitted. (Turret-count
red herring killed: multi-turret types still send one 12B pair; the
full-type `8+4N` form is dossier-side.) All 26 shooters single-gun
resolved incl. the former ambiguities (VK3002M Turret_2/L70 4.2s,
Tiger Turret_2/KwK43 7.8s, T34_100 Turret_2/100mm 8.5s, SP I C Mecar
7.5s, T37 Turret_2/T91 3.8s, IS2 Turret_1/100JT 8.8s) and the
correction that gap-reading got wrong (Hummel Turret_2/sFH18 31.1s
top gun, not the 26.4 lean — min 25s gap implies a ~20% bonus stack).
Specials share the row grammar `SHOT -> next_in=<short>s <details>`
with per-type details `reload=<next>s fullreload=<full>s
[loaded/total]`: French drums (AMX 13 57: `next_in=1.0s reload=1.0s
fullreload=16s [5/8]` — endgame 3-shot burst in ~2s proves intra is
the tactical number; T-25: Turret_2 auto, `next_in=1.3s reload=1.3s
fullreload=10s [2/3]`, thresholds strict-nominal); Black Prince II
double-barrel (`next_in=1.0s reload=1s fullreload=6s [1/2] twin`, per-barrel 6s timers, ~1s active-index
switch lock — mechanic correction: the gun carries a `dualGun`
(volley) section, not alternating-`twinGun`; singles alternate the
active index, a charged double-shot exists server-side
(`DUALGUN_CHARGER_STATUS` PREPARING/APPLIED), volley penalty
candidate `reloadLockTime` 1 open, no volley observed — needs a volley
capture (penalty reads straight off the volley→next gap: 6s kills it,
~7s confirms); reference
true-twin: FV230 Canopener `Twin_120_mm_Gun_L1_MBC` (reload 10,
`twinGunReloadTime` 20, NO `dualGun` section — CORRECTION, user was
right: twin DOES fire both at once; Glacier rafal1o1 shows 4–5
same-tick doubles (distinct shotIDs, +0.00s) then next single +9.2s ≈
per-barrel 10s with bonuses: instant double-tap, no charge, no
measured penalty; alternating-only withdrawn. Same row shape, e.g.
`reload=1s fullreload=10s [1/2] twin`; doubles drain to [0/2] with
next ≈10s flat. Exact role of the 20 still open); Italian
autoreloaders (none in this battle): slots fire 1→N, fired slot i
reloads in `autoreload.reloadTime[i-1]` through ONE fifo chain (new
shells append; client single-timer `setClipReloadTime` API proves the
shape); from empty load order is N..1 so first shell = `tuple[-1]`
(WG Progetto article + `shellChangeFactor` divisor agree); full mag =
sum(tuple) (P44: 30s); intra = 60/rate (2.0s); base `reloadTime` 9.6
role open; UNVALIDATED on wire — decisive test is dump-2-rapidly
(chain +18s vs parallel +10s on P44); base `reloadTime` 9.6 role:
no consumer in `ammo_ctrl.pyc` for AR guns (only the non-AR
`shellChangeFactor` fallback + crew tables), so it never enters a
fired shell's timing — display doesn't need it, stat-side reference
at most;
Italian autoreloaders (none in this battle) read `autoreload/
reloadTime` per-shell sets + base (P44 Pantera: 8/10/12s auto, clip 3,
base 9.6s). All nominal (stock crew — real runs ~5–15% faster).

Own-shoot paradox (Oct-12 late, Sep-29 Sweden battle, recorder =
ExampleUser, `spaces/115_sweden`, 6.8 min, 6 entity deaths): 11
S>C tracers start within 15 m of own xyz (2 certain: muzzle directly
above own center, e.g. start (−126.3,2.2,280.2) vs own
(−126.3,0.9,279.7)) — server accepted 11 self shots — yet C>S holds
NO shoot input under exhaustive search: complete head census (7313
bundles all `[02 8b584a][93]`, no 0x1b); no inner-0x1b records (bytes
scattered in floats only); no distinctive pre-shot bundles (only
routine 07/1a in [F−15,F−1] ×11, enrichment flat); no field markers
(F1 uniform, tails 00/03 split on both certain shots, 07-XX/VV
sequential); no timing coupling (nearest-0x1d never within 300,
nearest-0x1c gaps 60–297 loose); no second channel (lobby flows end/
start exactly at battle bounds 20:45:42/20:52:29); replays carry no
inputs either. Corroborating absences: zero giant harm-dict C>S, zero
hitFlags S>C. Standing theories: (a) STATE-based firing (client
streams aim/trigger state in routine fields, server derives shots —
fits the absence perfectly; tail1=03 runs = 17 aim-like states is the
lead candidate, 5/11 pre-shot enriched but split on certainties);
(b) recorder didn't shoot here (near-tracers = brawling allies;
ISU kills = different battle). DECISIVE NEXT: recorder confirms
map/vehicle/shot-count for 45507, or a fresh firing capture with
noted shot times.

RESOLVED Oct-12 late (recorder-confirmed + wire proof — supersedes
the never-fired verdict and theory (b) above; the "11 near-own" and
"1.4 m muzzle" readings are withdrawn, they were distances against a
displaced C>S track): recorder = vehicle entity 542282516 (SU-152).
Triple proof: battle-start arena-params head pairs
(ExampleUser, 542282516) — same shape as the recorder's own
Prohorovka replay (ExampleUser, 4730080 = own tracer a0); C>S
moveWith entity field = 0x20529314 = 542282516 exact (an earlier note
misread it as 542278420 — arithmetic slip, corrected); 9 S>C tracers
with a0 = 542282516, all Range 152 (caliber proven on own-vehicle
ground truth: Challenger 17-pdr → 76.2 ×11, T110E5 120 mm → 120 ×42).
The 9 (recorder remembered 5): s1 20:46:59 → 846 m, s2 20:47:16 →
841 m (+explode), s3 20:47:57 → 856 m, s4 20:48:16 → 859 m,
s5 20:48:49 → 450 m (+explode), s6 20:49:09 → 462 m, s7 20:49:46 →
484 m, s8 20:50:23 → 408 m, s9 20:52:14 → 662 m; gaps 17–111 s
(reload-plausible); muzzles on 3 spots ≤130 m (no chase; T20-window
shots stationary). Ack rule (recorder-supplied, wire-consistent):
spotted hits ack live (2 explodes = the acknowledged 2–3), the rest
(unspotted/ground) stay silent until battle results — this capture
holds no 1500-request/852 (results never pulled), and its 924B blob
is a missions sync, not results. Endgame: 542264099 3× 57 mm
@20:52:11.8/12.8/13.9 → own s9 152 mm @20:52:14.8 → 099 silent →
own death 20:52:17.9 (postmortem + deathOrder naming 542264105;
kill direction/vehicles open). Consequence: 0x1b absent over 7323
C>S DESPITE 9 confirmed shots ⇒ shoot SUB ≠ doc order (fork (a)
confirmed) or state-based; trigger hunt re-posed on the 9 true times
(pre-shot windows = routine mix; post-shot 0x1c/0x1d at +0.06 s (s6),
+0.04 s (s9) read as aim aftermath). C>S position track itself is
suspect here (teleports + smooth-but-displaced segments — open wire
anomaly, attribution-independent since identity is server-side).

TRIGGER CLOSED Oct-12 late (same battle — this IS the firing
capture; shape CORRECTED Oct-14, see framing above): C>S shoot = bare
`[10][0400][00000000]` record (SUB 0x10, len 4, zero args — no 93 tag;
the `[93][10]...` reading on 4 of them was the key's low byte abutting
a lead-position record). Exactly 9 such records exist in 6.8 min (4 in
lead position, 5 chained-inner inside 07/18-led bundles); each sits
60–140 ms before one of the 9 own tracers
(s1 −0.09 inner, s2 −0.10 inner, s3 −0.10 outer, s4 −0.14 outer,
s5 −0.07 outer, s6 −0.10 outer, s7 −0.06 inner, s8 −0.11 inner,
s9 −0.06 inner) — 9/9 in both directions, zero baseline (no other
0x10 anywhere in 7323 C>S). The 4 arg bytes are zero on all 9.
Arg-shape cross-check: trigger bundles walk exactly (41 = 5 + 7 + 29,
51 = 5 + 10 + 7 + 29, 70 = 5 + 19 + 10 + 29, with 5B head = 02 + key4).
Behavioral identity = vehicle_shoot(): decompiled Avatar.shoot
(2.4.0.0 Avatar.pyc) runs reload/waiting/siege guards then calls
self.cell.vehicle_shoot() with no args and no accompanying cell
call; `vehicle_shoot` is referenced nowhere else client-side, while
the only other 0x10 candidate (setEquipmentApplicationPoint, callers
in CombatEquipmentManager/MapCaseMode, single-use consumables with
varying args) cannot emit 9 identical zero-arg records at exact
pre-shot latency. Wire-vs-defs deltas recorded open (not smoothed):
doc index own[27] vs wire 0x10; 4 zero bytes vs 0-arg signature
(possible Mercury 0-arg padding or hidden u32); 0x1b confirmed
never-sent. Emit spec (`lobby.BuildShootTrigger`, byte-identical to
captured s3 on wire fields): 41B standalone + live trailer over the
same unreliable channel (flags 0458); server answers with a tracer,
never an ack. s7/s8's extra 0x12/61 @−0.01 s and the post-shot
0x1c/0x1d proximities (+0.06 s s6, +0.04 s s9) read as aftermath,
not trigger.

Oct-17 packer pass (IDA, same 2.4.0.0 image — pack side hunt): the
client carries NO pack implementation. The `packVolatilePositionDirection`
string "…Unpacker was requested to pack" (rt `0x14368AF60`) resolves to
log-only stubs `0x140E36520`/`0x140E52520`; the
`CellAppDefaultEntityVolatilePacker` RTTI-time name is documentation of
the wire format, not client code. The fork's packer NAME gate is
`"bw.default"`: the 10-byte memcmp constant (`0x143606830` =
`62 77 2e 64 65 66 61 75 6c 74`) is checked by
`ServerConnection::createEntity` (`0x140E4E870`, "Disconnecting due to
non-default volatile packer type detected"),
`createEntityDetailed` (`0x140E4ED50`) and
`changeVolatilePackerType` (`0x140E4DBF0`); a wire packer-name that
fails the check (`handleEntityPackerChanged` `0x140E3D4B0`,
`Invalid packer type "%s"` → factory-vtable slot +136 with
`ClientDefaultVolatileUnpacker`/`ClientAlwaysDetailedVolatileUnpacker`
+ factory RTTI at `0x144652D70…0x1446540A0`) drops the client. Create
wire parse CLOSED (per-arg reads Oct-17): `[entityID u32][u16
(vehicle/type index)][blobLen u8, 0xFF sentinel → 24-bit LE][blob =
creation data][1B → per-entity map slot][packerName len u8 / 0xFF+24b +
name bytes][dir u32 dirType0]`.
The conditional base-add and aux quanta flows of `0x140E369D0` re-verified
byte-clean (17b/17b/14b x/z/y; bias −2.0 before ×scale; `0.00024414062`
= mantissa magnitude `1/4096`, `0.001953125` = `1/512`).

The lobby 116B "entity burst" is NOT the creation parse and NOT
packed-volatile (Oct-17 offline falsifications on flows3-s2, all 28
frames channel-decrypted magic-validated): clear = 102 B = `[flags
7804][80 B app][4 B per-frame random][counter u32 249 +9k][u32
= counter+8][u32 dup][u32 const 3]` (12 vs 16 B trailer boundary open,
same bytes); the 8×11 packed-volatile record model fails (all stride
positions random; per-column distinct ≈ 25.8/28 of 28 frames); raw
deflate (wbits −15…−9), gzip and zlib wrappers, bz2, lzma all fail;
consecutive-body XOR bit-load ≈ 0.5 ⇒ per-frame keying or per-frame
fresh data, not a continuing stream. Census shift: the 28 frames ride
EXACTLY one per flood tick in flows3 (28 tick windows, interleaved
between the per-tick 1252 B trains, tag ramp `[13][5e]…[13][79]` with
one 5f skip) — a flood-phase companion frame, not an entity-batch
document (AGENTS "118B entity burst" reading withdrawn). So the
creation-blob content mint question reverts to
`ServerConnection::createEntity`'s 88 B blob field + the still-unlocated
record loop, and the per-session-bulk-heads approach of the private
server.

## 15. Telemetry census (Oct-02, static + captured bootstrap flows)

What the client reports, and where bootstrap/config comes from. Shapes
and endpoints only; no player data reproduced.

In-band UX events (game server, not HTTP): `EventLogManager`
(`gui/Scaleform/framework/managers/event_logging.pyc`) batches
`[timestamp, subSystemType, eventTypeId, uiid, arg]` records
(LOG_LIMIT 70/batch, PACKAGE_LIMIT 70/session, 2.0 s cooldown
`CLIENT_LOG_UX_DATA_COOLDOWN`) and sends via the engine call
`BigWorld.player().logUXEvents(package)` (no entity-def surface —
engine-side RPC). Taxonomy (`genConsts/EVENT_LOG_CONSTANTS`):
7 subsystems (EVENT_LOG 0, TOOLTIP 2, VIEWSTACK 4, CONTEXT_MENU 8,
LOADER 16, HANDLE_INPUT 32, UI_COMMON 128) × ~35 event types
(clicks/hovers/drags, window open/close/minimize/resize, tooltips,
viewstack, context menus, view load/unload, keyDown/keyUp
256/257, data 4096). Gated server-side by session-dict flags
`logUXEvents` (default False) and `collectUiStats` (default True).
Sibling knob `CLIENT_LOG_XMPP_DATA_COOLDOWN` (10.0 s) is defined but
unreferenced in shipped code. `aogas*` session keys are
playtime-control (parental limits, daily/weekly playtime left —
`GameSessionController`), not analytics; session-stats requesters
are UI readers (battle count, credits, xp, damage…).

HTTP bootstrap (captured `eu2-mitmproxy-flows`, 8 flows): CSIS
cluster status (`csis.worldoftanks.eu/...`, center + peripheries
201–205 availability XML); WebCache static-lists manifest
(`wgcg-eu.wargaming.net`, 551 KB JSON: CDN hosts + files);
Vivox voice prelogin (`www.woteuusp.vivox.com`, `VCConfiguration`
XML with Watson speech config); dynamic content
(`ce-eu.wgcdn.co` loading sequences, service-record
backgrounds/ribbons, collections images); RSS feed
(`rss.worldoftanks.eu/fr`). Referenced but uncaptured here:
`collect.worldoftanks.eu` (telemetry collector), XMPP bosh hosts.
No `collect.*` sender in client `.pyc` or the exe strings —
collection likely flows through web views / WGC side.

## 16. XMPP chat (Oct-02, static + lobby-#2 wire proof)

Messenger XMPP is stock-protocol (gloox C++ + `messenger/proto/xmpp/`
drivers), server-configured. Connection (`connection.pyc`):
endpoint iterator TCP-first, BOSH fallback
(`client.connectBosh(jid, host, port, '/bosh/')` — path hardcoded),
JID = `{accountDBID}@{domain}/{resource}` (`XmppServerSettings`),
then an XMPPCS chat token from the game server (SPA) with a
databaseID match check before SASL login (live Oct-12: domain is
`c2s.xmpp-wot-eu.wargaming.net`, resource `wot`; PLAIN-only, no
STARTTLS; password path dead — LOGIN gets 500, DBID gets clean
rejection; BOSH :5280 RSTs creates, :443 refused; FULL LOGIN Oct-12
launcherless via `wotxmpp -token`: the XMPPCS token is the 8-digit
INT from the int token-dict (~1 s after `requestToken(1,1)`, NOT the
JWT — the JWT is WGNI/shop), SASL PLAIN `\0DBID\0<8-digit>`
authenticates, bind + presence + roster IQ succeed); reconnects use
random/mod backoff, token failures exp-backoff (3 tries);
disconnects are reported back to the game server
(`XMPP_EVENT_LOG.DISCONNECT` + host/port/reason/tries).
Message taxonomy (`gloox_constants.pyc`): CHAT/ERROR/GROUPCHAT/
HEADLINE/NORMAL/INVALID, roster ops, chat-states; extensions carry
chat-state, delay stamps, message UUIDs, per-JID history query
(`with` + `limit`).

Server-driven settings (`XmppServerSettings.update` keys:
`xmpp_connections`, `xmpp_alt_connections`,
`xmpp_bosh_connections`, `xmpp_host`, `xmpp_port`,
`xmpp_resource`, `xmpp_enabled`, `xmpp_muc_services` by
type/hostname/enabled): proven on lobby-#2 wire (Sep-29 B,
44395 flow, login key recovered per-flow via MITM privkey —
`RecoverLoginKey` last-wins returns the battle key there, filter by
login flow): the 124B list decrypts magic-valid to a bosh-only
dict (`xmpp_bosh_connections` = [`woteu34.xmpp.wargaming.net`],
`KP`-terminated host record, `b8→bc` framing walk). Oct-11: stack = gloox (static) + `WGXmppClient` wrappers (Python type init `0x140C85DE0`); `XmppServerSettings.update()` takes `{xmpp_connections, xmpp_alt_connections, xmpp_bosh_connections}` (host,port) lists with a TCP-first/BOSH-fallback iterator that 2-samples each list (`_makeSample` — connection choice is randomized); the `xmpp_*` key strings are ABSENT from the image, so the settings dict arrives via pickled smalls (offline-parseable) and the b8→bc/KP walk belongs to the binary infos framing (open). Same
session's 84B = account-info doc (build version + account name),
220B = tick + session dict (`serverUTC`, `databaseID`,
`aogasStartedAt`, `sessionStartedAt`, `iAogasEnabled`,
`collectUiStats`, `logUXEvents`, manager IP). This is a different
layer from the BaseApp `(98,25)` chat tails (§7) — those are
`Chat.chatCommandFromClient` sync calls, not XMPP stanzas.

## 17. Battle-results cache flow (Oct-02, wire + shipped `.pyc`)

Stats-UI "view results" = `BattleResultsCache.get(arenaUniqueID)`
(`client_common/.../BattleResultsCache.pyc`, shipped): cache check
(`<prefs>/battle_results/<arenaUID>.dat`, `BATTLE_RESULTS_VERSION`),
else `_doCmdInt3(CMD_REQ_BATTLE_RESULTS=1500, arenaUniqueID, 0, 0)`.
Proven on Oct-01 wire (game session, MITM-recovered lobby key):
`[00][227][1500][arenaUID:16d][0][0]` (dg 1407, direct-base A1
`0x00` flavor — cf. Port-routed `0x95`; `base.doCmdInt3` vs
`_doCmdInt3` in the `.pyc`) → 852B answer in ~108 ms: tick +
`1a/5e` + `0x45` `[00][227][0x0e]` + STOP-less 2-tuple
`(5472, <id>)`, then the zlib+pickle stream (732B here) INSIDE the
same datagram's smalls train past the walker's unknown-ID stop
(`0x2e`), then `[00][202][1501][arenaUID][0][0]` (dg 1422, same
arenaUID). Payload is a 63-list (`unpackClientBattleResults` form:
`[arenaUID, nil×4, 3, nil, roster[[dbID,vehID]×3], ...]` —
roster/ID classes only, no values reproduced); client saves it to
disk and acks. Same 0x45 shape on flows3 (req 221 SYNC_DATA →
`(332901, <id>)`). Live re-proof Oct-14 (2.4.1.0 game sessions, MITM
lobby keys + response-logger consumer shapes in game.log): the
Port-routed pull is `doCmdInt3(req, 1500, arenaUID u64, 0, 0)` (A1
`0x95`, `1c00`; CMD_REQ_BATTLE_RESULTS=1500 constant, req
allocator-derived — 233 post-b2, 234 next session — disentangling the
Oct-01 `[00][227][1500]` reading, where 227 was that session's req, not
the cmd) with live arenaUIDs `0xf29ccf6a14590120`
(17482075908060283168) and `0x200195996acfa588` (2306288970344932744)
— the battle-ref family, exhumed. Answer in ~100–200 ms is the same
852B 0x45 (`[len8][req BE][res=0][extlen][ext STOP-less tuple]`, req
echoed; ext first-elems 5492/5703 here, per-call like 5472) + stream
train with a 697B zlib + a decimal-string ID (`233032232428413613618`
/ `230622229964736618` — 18 digits, NOT the request arenaUID; second
ID family, open). Consumer synthesis CLOSED by pairing (S>C→Python in
2 ms): `onCmdResponse(req, 1)` + `_subscribeForStream(req, partial)`;
session census: res=1 always subscribes (221/223/228/232/233/234),
res=2 never does (222 direct answers), res=0 = empty acks
(225/227/229/231/235), res=-10 + errorStr = failures (226 'Not found',
matching game.log `Server fail response: code=-10`). Received-ack
follows: `doCmdInt3(202, 1501, arenaUID, 0, 0)` (fixed req 202, same
arenaUID — system calls reuse 202 like the 501 polls). 226 dual fate
live: `onCmdResponseExt(226, 0, '', str[113])` once (success with
payload) vs `(226, -10, 'Not found')` once — the missing per-vehicle
family fails live too. 230 draws a 22 KB ext string
(`onCmdResponseExt(230, 0, '', str[22016])`). Still open: tuple
second-elem semantics, stream-chunk framing past the 852, and the
res=0-wire vs res=1-consumer mapping inside the C++ 0x45 dispatcher. Wire truth Oct-11 (game session, MITM key + real py2.7 config
execution in docker): 0x45 = `[len8][req u16 BE][res u8][extlen u8]
[ext]` with res uniformly `RES_SUCCESS(0)` — the varying byte
(`0x0b/0x0c/0x0e`) is the ext LENGTH (11/12/14), not a status; ext
= STOP-less pickle 2-tuple, first elem per call
(battle-1500: 5472, sync-221: 353433/332901 across sessions,
dossier-226: 256; second elem big signed). Meta checksum CLOSED:
data[0] = 263845007 = REGULAR ACCOUNT_SELF Meta (battle-pass
integrated), reproduced EXACTLY by executing the shipped
`setBattleResultsConfig` under CPython 2.7 (docker + stubs) —
46 base-SELF + 7 base-ALL + 1 random + 8 battle-pass = 62 fields;
dict iteration is insertion-ordered here (no collisions); the
old-style-packer address worry dissolved (deterministic match).
Index→name map (positions 1–62, checksum at 0):
```
1 questTokensCount
2 questTokensConvertion
3 avatarDamageDealt
4 avatarKills
5 avatarDamaged
6 totalDamaged
7 fairplayViolations
8 badges
9 rankChange
10 avatarAmmo
11 avatarDamageEventList
12 accountDBID
13 team
14 clanDBID
15 fortClanDBIDs
16 winnerIfDraw
17 isPrematureLeave
18 watchedBattleToTheEnd
19 vseBattleResults
20 squadBonusInfo
21 progressiveReward
22 eligibleForCrystalRewards
23 activeRents
24 recruitsIDs
25 recruiterID
26 referralBonusVehicles
27 fareTeamXPPosition
28 questsProgress
29 PM2Progress
30 dogTags
31 eventCredits
32 eventXP
33 eventFreeXP
34 eventTMenXP
35 eventGold
36 eventCrystal
37 eventEventCoin
38 eventBpcoin
39 eventEquipCoin
40 credits
41 xp
42 freeXP
43 crystal
44 playerRank
45 goldBankGain
46 replayURL
47 originalBattlePassPoints
48 battlePassPointsReplay
49 battlePassPoints
50 eventBattlePassPointsList
51 eventBattlePassPoints
52 commendationsReceived
53 commendationsSent
54 avatarPlayerSatisfactionRating
55 bpChaptersInfo
56 bpTopPoints
57 bpTopExternalPoints
58 bpBonusPoints
59 bpNonChapterPointsDiff
60 hasBattlePass
61 battlePassComplete
62 availablePoints
```
Anchors: 12 accountDBID (= own DBID on wire), 26 recruitsIDs,
28 questsProgress (dq/wq legs), 30 dogTags, 40/41/42
credits/xp/freeXP (11580/198/11 here), 46 replayURL, 55 bpChapters,
8 badges tuple, 11 damage-event set. OPEN: tuple semantics
(best reading: stream handle for the in-train 732B — the 1501 ack
proves save+ack happened while res=0 \u2260 RES_STREAM, so the
engine likely synthesizes RES_STREAM on stream presence; C++ 0x45
dispatcher unlocated) and second-elem meaning.

## 18. Private server — stage-1/2 shapes (Oct-17, client-side `login/baseappsrv.go`)

The BaseApp server half answers the client script shape-for-shape so a
client LOGGED_ON by `cmd/wotserver` walks stage-1 → rotation → tick →
`[44]` redirect → stage-2 double-auth → flood **against us**. Frames
are the decrypt-proven genuine shapes (flows3 s1/s decrypts, Oct-17);
honesty layering: transport frames genuine, per-session smalls v1-cut,
bulk carrier = stale-content reference (see below).

### 18.1 Byte-exact S>C frame bodies (wire = 4 B channel prefix + Blowfish-ECB+XOR-chain under the LogOnParams key)

* rotation 36 B: `58 04 | FF 08 00 00 00 | rid u32 LE | newkey u32 LE | seq 0 | cumul 0`
  (genuine: rid 0xae6e, key 0x696aae88). Reply echoes the rid of the
  client's CURRENT 22B (key rotation re-signaling rule; client
  resends with a fresh rid each attempt).
* tick 28 B: `58 04 | 13 3e | seq 2 | cumul 1` — `[13][3e]` head is
  `tickSyncPeriodic` (wire id 19) + tag byte 0x3e (stage-1 era;
  parked servers walked it 0x02→0xfb — semantics open).
* redirect 36 B: `58 04 | 13 3f | 44 | ip u32 BE | port u16 BE |
  00 00 01 | seq 4 | cumul 1` (genuine core `5cdf14d4 804c` =
  92.223.20.212:32844). The `[13]` head is a piggy-backed tick; `cumul
  1` acks the client's reliable auth1 seq 0. Server-side: the target
  is our stage-2 listener, bound INSIDE 32810–32999 (the game follows
  any port; the window only keeps OUR client's `parseRedirectAt` guard
  happy — Oct-14 blackhole-guard evidence).
* v1-cut (captured but not minted per-session): 52B stage-1 infos
  (`02 0a 01 00 3e 8b 23 00` head + `[13][3e]` + the packed
  token-middle string), 44B (`1a`/`500d` `"default"`), 76B stage-2
  descriptor (flags `78 04` + packed `"eu_2.4.0_2"` + packed name —
  per-session version+name, release candidate), poll answers, 116B
  entity bursts.

### 18.2 Timestamp model

Rotation replies carry seq 0 cumul 0 (both stages — genuine); tick
seq 2 cumul 1; redirect seq 4 cumul 1. The `[13][XX]` tag byte steps
per window/epoch, NOT per packet.

### 18.3 Stage-2 bulk carrier

`[FF][len=8][rid][newkey]` rides as app content (rotation); the
Blowfish channel key NEVER changes (decrypt-proven flows3:
post-rotation datagrams still decrypt with the login key — §6).
Census (flows3-s2): 440 × 1252 B, flags `78 00`, clear 1237 B =
flags2 + aux u32 + body + 12 B trailer `[2][174][N]` (12 B trailer
⟺ flags bit5 0x20, else 8 B; `flood.go` rule). 40 Mercury packets,
seq constant across a packet's fragments (first chunk seq 174), cumul
= per-datagram fragment counter 3..173, stride between chunk-head
packets ≈ frag-count+1 (197…275 across the capture). Server-side v1
replays the capture frames VERBATIM: bodies decrypted once at load,
re-keyed at serve (fresh 4 B prefix + ECB+XOR-chain), captured
`[aux][seq][cumul]` untouched. Contents stay the capture's (stale
17-Sep shop/offer defs — per-session bulk heads: session dict,
databaseID — are future work).

### 18.4 Server-side session state (`login/baseappsrv.go`)

* Stage-1 listener = the LOGGED_ON record endpoint; 22B fixed
  handshake parse (`[prefix4][01 00][00][rid u32][00 00][sessionKey
  u32][attempts u8][mtu u16][footer u16=2]`, §7.1) acknowledges any
  rid; unknown session keys draw ZERO bytes (p5 validates keys —
  random-key 22B ×3 silent).
* Pending-record expiry ≈60 s (genuine precedent ≈30 s;
  hijack_portsteal +83 s was past expiry — void on timing).
* Stage-2 listener: 22B carries the stage-1 ROTATED key; rotation-2
  mints key2; the double-auth (`[02][key2]` unreliable + reliable
  twin, flags `48 14` / `58 04` — either halves proves key2 spent)
  triggers the flood burst. Stage-2 non-handshake datagrams resolve
  by SOURCE ADDRESS (28B auth datagrams carry no parseable key header;
  fresh sockets make addr the only stable join).
* LoginApp→BaseApp handoff: `ServerConfig.OnLoggedOn(SessionKey,
  BlockKey, Name)` fires when the LOGGED_ON reply is built.
* CLI: `wotserver -s1 127.0.0.1:32850 -s2 127.0.0.1:32851
  -flood ../captures/flows3-s2.txt -floodkey ../captures/key3.txt`
  (carrier files relative from the repository root; `-s1 ""` = LoginApp alone).

### 18.5 Flood-phase companions and the post-flood pipeline (Oct-17 census, flows3-s2)

The genuine flood phase is not 440 bare bulk datagrams: each ~100 ms
tick window carries `[13][XX]`-headed first chunks (tag ramp `5e→79`,
one 5f skip — the stage-1/2 `0x3e/0x3f/0x40` tags continue into the
flood window) AND one 116 B companion frame (`78 04`, clear 102 B =
`[flags][80 B app][4 B random][counter u32 249 +9k][counter+8][dup][3]`;
+9/tick = the 9 datagrams per tick window; app opaque — §14 Oct-17
entry excludes compressed/packed-volatile readings). v1 replay cuts
both. The genuine tail after the last bulk tick (`[13][79]`): a 332 B
terminator (`78 04`, clear 317 B, app head `69 45 0e 00 df 00 0b 80…`,
open), a 28 B `[13][7a][f7 01 00 00][03 00]` tick (12 B clear — the
post-flood tick form is SHORTER than the stage 16 B form), then the
client sends its 84 B `[58 04][02][key 78128370][1c 00 …]` (the stage-2
rotation key re-authed — the double-auth repeat), the server answers a
60 B `[13][7b]…` reply, and the tag ramp continues (`[13][7c]`). That
turn-taking chain is next-move material for the private server's
post-flood script; the per-tick companion frames and the 332 B
terminator stay v1-cut.

> Superseded by §18.6: that chain is now byte-resolved (the `[13][7a]`
> tick's open "shorter form" is `[13][tag][seq][cumul]`, counters
> understood) and served by `baseappsrv.go`. The per-tick 116 B
> companions stay v1-cut; the terminator is served.

#### 18.6 The post-flood chain, byte-resolved and SERVED (Oct-17)

Full-tail decrypt (every frame after the last bulk chunk, flows3-s2 +
key3) resolved the chain the v1 note above left open, and
`login/baseappsrv.go` now serves it (milestone v2; loopback
`TestBaseAppStageLoopback` + a real CLI-binary walk both green).

**The frames.** Term-by-term, with the counter fields:

| # | wire | dir | clear | shape |
|---|------|-----|-------|-------|
| 1 | 332 | S>C | 317 | terminator, `78 04` companion; app head `69 45 0e 00 df 00 0b 80 02 4b 13 4a …`, zlib `78 9c` island mid-body, tail `[f6 01 00 00][f6 01 00 00][03]` (seq/cumul/const-3 like the 116 B companion). Closes the bulk document. |
| 2 | 28 | S>C | 12 | plain tick `58 04 13 7a f7 01 00 00 03 00 00 00` = `[13][7a][seq 503][cumul 3]`. **The post-flood tick form is `[13][tag][seq][cumul]` = 10 B app — the tag ramp is continuous with the flood window.** |
| 3 | 84 | C>S | 74 | `58 04 02 70831278 95 1c 00 e0 00 64 00 58 …` = `[02][key2][95][len 1c][reqID 224][cmd 0x64 = 100 CMD_SYNC_DATA][88][0x699a133b][0]` + the `(98,19)` chat tail = the sync re-run. |
| 4 | 60 | S>C | 51 | `[13][7b]` + `1a 5f 24 e0 …` — a proto-2 pickle `{rev, prevRev}` (`72 65 76`/`70 72 65 76 52 65 76` are visible in the clear). The sync answer, ~40 ms after #3. |
| 5 | 28 | S>C | 12 | `[13][7c][seq 505][cumul 4]` — tick cadence continues, one per ~100 ms. |
| 6 | 36 | S>C | 22 | `[13][a4]` + `1a 5b 66 52 00 00 90 b5 00 00 …` = the 1a/5b counter small (the server-stats answer; counters drift 0x5266/0xb590 between polls). |
| 7 | 52 | C>S | 38 | `93 14 00 e1 00 79 00 …` = doCmdInt2(225, **121 = CMD_SET_ACTIVE_VEH_SEASON**). |
| 8 | 36 | S>C | 20 | `[13][dd]` + `1a 5e 05 e1 00 …` — the 1a/5e error small answering #7 ("no such vehicle"). |
| 9 | 36 | C>S | 21 | `8a 03 00 03 00 …` = requestToken(3, …). |
| 10 | 244 | S>C | 228 | `[13][ae]` + `1a 60 d5 02 …` = the 1a/60 `{databaseID, token}` dict, pushed unprompted ~every 12 s. |

**Counter semantics (now pinned, not guessed).** The `[13][tag]` tick
is `[tag][seq][cumul]` where `seq` is the server's own datagram counter
(continues across the chain: 503 at `[13][7a]`, 505 at `[13][7c]` — the
answer datagrams consume seq numbers too) and `cumul` is the client's
acknowledged-reliable watermark (3 at the terminator, 4+ after the
client's 84 B, rising to 9 over the tail). The tag ramp (`7a`, `7b`,
`7c`, … wrapping through `00`, `23`) is a per-tick stepper, so a mint
that walks tag+1/seq+1 per tick reproduces the genuine cadence shape.

**What the server does (v2).** `serveBulk` ends by sending the
terminator, then `sweepStage2` mints one tick per `PostTickPeriod`
(100 ms, measured `1562.609 → .810 → .911`) from the carrier's seed
tick (tag `7a`, seq 503, cumul 3 — the first tail tick replays
byte-exact). Incoming post-flood bundles are classified by their
leading doCmd call (`postDoCmd`: `[02][key2][A1][len][reqID][cmd]`,
cmd at clear[12:14], accepting the `0x95/0x1c` Int3 and `0x93/0x14`
Int2 shapes): **cmd 100** → the verbatim `[13][7b]` rev answer, once
per session; **cmd 501** → the verbatim 1a/5b stats answer per poll;
everything else (121 season-select, 600 dossier, doCmdStr, requestToken)
is **v1-cut and silent** — each wants per-account inventory we don't
hold, and the genuine server answers them with error smalls. Wire-shape
caveat carried forward: answering on `cmd` alone is deliberately
looser than the genuine, which correlates the answer to the exact
request chain.

**Two bugs the tests caught, both now regression-pinned.** (1) The sync
and the poll share the leading `0x95` A1 tag — matching the tag answers
every poll as a sync, and the real client then never receives its rev
answer (only the `cmd` field separates them). (2) The "sync answered"
latch must only be set when a cmd-100 bundle actually arrives; setting
it on the first post-flood datagram of any kind swallows the sync when
the client's per-tick acks arrive first. `TestBaseAppPostDoCmd` pins the
classification, `TestBaseAppPostFloodCarrier` pins the loaded frames
(term 317 B, seed tick, rev reply byte-exact). `TestBaseAppStageLoopback`
walks the whole chain with the real client builders and asserts the rev
answer byte-exactly against the capture at the genuine reliable-seq
timeline (below).

#### 18.7 Per-session "smalls" (v2.1, Oct-17): served pre-flood + minted post-flood

The v1-cut policy left three genuine script positions empty: the
stage-2 pre-flood infos (rotation → info → descriptor in the capture),
the mid-burst session dict, and the season-select answer. v2.1 serves
all three from the SAME flows3-s2 carrier, with the personal-data
riders cut.

**Pre-flood smalls (sent with EVERY rotation-2 reply, loss-robust —
capture idx 1/4/5, `+10 ms`/`+40 ms` spacing):**

| wire | clear | shape | served as |
|---|---|---|---|
| 36 | 20 | info app `02 0a 01 00 3f 8b 23 00 13 3f` + footers `[seq 1][cumul 0]` | app verbatim (`s.infoApp`), footers minted at the same values (no reliable client send processed yet) — byte-exact vs the capture |
| 76 | 61 | companion flags `78 04`, `[05 ff ff 17 34][03 00 01 00 00][vlen 0a][eu_2.4.0_2][nlen 0b][ExampleUser][24B tail]` | template replay with the ACCOUNT NAME substituted at [25] (1 B len + bytes); footers `seq 2 / cumul 1` ride INSIDE the tail verbatim (capture values — our client hasn't sent its auth yet at this point, a stale-cumul delta) |

* The name slot is the only per-session byte in the descriptor;
  substitution length-corrects but the 1 B length field caps names at
  255 (cryptic truncation, mirroring the same field serverside).
* Frame 396 in the capture is the mid-burst session-dict companion:
  `[1a 76 9c 00]` + 156 B = status byte `9b` + a 155 B proto-2 pickle
  `{serverUTC, databaseID, aogasStartedAt, sessionStartedAt,
  isAogasEnabled, collectUiStats, logUXEvents}` — with riders. The
  riders are CUT and NOT reserved on our wire: the `1a 73` clan block
  carries personal clan text, and `1a 79` embeds the capture's redirect
  target (`185.122.240.53`, port `80 bc` = 32956 in the sample —
  reserving the offer would push OUR client at a captured artefact).

**Session dict (v2.1 mint, at serveBulk START — before the burst):**
`[78 04][13 40]` + the 160 B small + footers `[seq 2][cumul live]`
(= the auth's watermark, floored at 1 — the genuine frame's cumul is
also 1). Four fields re-patch per send:
`serverUTC` (BINFLOAT, now), `aogasStartedAt` (= serverUTC −
0.001951 ms — the capture's playtime-watcher delta, replayed),
`sessionStartedAt` (BININT, admission), `databaseID` (BININT,
`pseudoAccountID(name)` — the same FNV-1a head the LoginApp token2
carries); the three booleans replay untouched. Value-layer honesty:
the pickle VALUES are ours, the STRUCTURE + booleans are the capture's.

**Minted post-flood answers (v2 adds the season leg):**
the rev answer and the 1a/5b stats answer keep their stale-reference
bodies (18.6), but the frames around them are minted per send
(`allocPost`/`mintPost`, one walk slot per S>C frame: tag = 7a+n mod
256, seq = 503+n, cumul = the live client watermark). cmd 121
(CMD_SET_ACTIVE_VEH_SEASON) now answers the 1a/5e error small:
`[13][tag][1a 5e 05][req u16 LE echo][00 00 00]` + footers
(capture idx 1210: req 225 → `e1 00`; we hold no garage, so the
genuine "no such vehicle" error small is the faithful answer instead
of inventing garage state).

**Documented Deltas (deliberate, each owes its note to the ordinal):**

1. *Session-dict position.* Genuine: mid-burst (idx 63, AFTER 62 flood
   frames, seq 176). Ours: just before the burst, seq 2 — the first
   post-rotation frame counter counts our pre-burst frame; the flood
   chunks then carry the carrier's own seq (the counter jumps 176
   positions in the capture ordering). A frame-ack-counting MITM sees
   the small one position off; the game decrypts and consumes either.
2. *Cumul ramp at the floor.* Our loopback client sends nothing
   reliable between auth1 (seq 0) and the burst, so its watermark at
   the tail is 1 vs the genuine 3 (token + tokres rode the reliable
   channel in the capture). `serveBulk` seeds
   `postCumul = max(live, carrier 3)`, keeping the seed tick and the
   rev answer byte-exact (cumul 3 / 4).
3. *Descriptor cumul=1 stale.* The descriptor replays the capture's
   in-clear footers; at send time our watermark is 0 (info had cumul 0
   too, which matches) — a one-frame-staleness the game never
   consumes because the field rides the descriptor's own body.
4. *Poll counters stale.* The capture's own two stats answers differ
   (0x5266/0xb590 → drifting); we replay the FIRST. A long-session
   observer sees frozen counters; short sessions (the game's own
   poll spacing is ~5 s but sessions end fast) don't get there.

Tests: `TestBaseAppPostFloodCarrier` pins the templates
byte-exact from the capture (incl. the descriptorFrame name splice and
255-truncation), `TestBaseAppPostDoCmd` pins req/cmd surfacing
(sync 224/100, poll 202/501, season 225/121), and
`TestBaseAppStageLoopback` walks the full loop with the real client
drivers: info byte-exact, descriptor name-spliced, dict decoded
(`lobby.DecodePrefix`) with per-session values, the seed tick + rev
reply byte-exact, the poll body + minted cumul 5, and the season 1a/5e
with the req echo + cumul 7.

## 19. Multi-battle session (Oct-31): key4 chain across battles, 9 battles, history mode

`../captures/proxy-20261031-1358.hex` (wotproxy MITM, 2.4.1.0) is the
first capture in the repo with **one login and nine battles**: 108,813
datagrams over 57 flows, 13:59:17.424 → 15:08:28.432 (69 min). The
login block key (MITM-recovered, `wotflood -recover-key`, id
`55a12d296f667200`) decrypts **every** flow — stage-1, all nine
stage-2 re-entries and all nine battle flows — 108,710/108,813
datagrams (the 103 skips are the plaintext 22 B handshakes and the
`-rewritten` proxy legs). No second key is needed anywhere in the
session.

### 19.1 Session map

| # | flow | window | what |
|---|------|--------|------|
| 1 | `:44002` LoginApp | 13:59:17.4–.7 | 534/55/728/232, status 1 |
| 2 | `:44002→.212:32852` | 13:59:17.7–18.0 | stage-1, 15 dgs |
| 3 | `:45734→.215:32874` | 13:59:18.0–14:00:33.1 | stage-2 **full flood**: 72 chunks / 892,217 B |
| 4 | `:50491→.79:32810` | 14:00:33.1–14:04:54.4 | battle 1 (30 vehicles) |
| 5 | `:35846→.215:32874` | 14:04:54.4–14:05:48.5 | stage-2 re-entry, 1 chunk |
| 6 | `:60262→.71:32813` | 14:05:48.5–14:16:45.9 | battle 2 (**history mode**) |
| … | | | 7 more battle ⇄ stage-2 round trips |
| 19 | `:32783→.75:32812` | 15:05:41.1–15:08:28.4 | battle 9 (capture ends mid-battle) |

Seven battles are ordinary 30-vehicle PvP random battles
(`QUEUE_TYPE.RANDOMS`, `bonusType 1` = REGULAR, 30 real player names).
**Two (b2, b3) are the game's "history" battle mode** — bot-only PvE
scenarios on WWII maps. The wire calls it story mode:
`CMD_ENQUEUE_IN_BATTLE_QUEUE` carries `QUEUE_TYPE.STORY_MODE = 100`
plus a mission id (`[100, 3]` / `[100, 4]`), and the post-battle delta
gains a `storyMode` key after these two battles only. b2 is
`spaces/08_ruinberg_sm24` with `ruinberg_objective1_start` …
`objective7_finish`; b3 is `spaces/105_germany_sm24` (Berlin) with
`berlin_objective1_push` … `objective7_typ`. Both field 30 bots
(`BotVeh_<n>_<team>_<type>`, `BotLoc_<n>`, names from the
`#story_mode.sm_battle:botNames` locale) and the player drives the
scripted `M4A3E8_Sherman_StoryMode_3_4` (APCR, 3.3 s reload).
A 16 B LoginApp ping flow (`:59777`, 40 pairs) runs in the background
from 14:16:53 to 15:01:17.

### 19.2 The key4 rotation chain now spans the battles — 19/19 links

§7 already pins the mechanism for the login→stage-1→stage-2 hops: the
22 B handshake carries a session key, the server's `[FF][len=8][rid]
[newkey]` reply rotates it, and stage-2 mints a fresh rid. What this
capture adds is that **the battle flows are full participants in the
same chain**: each battle's 22 B announces the key the previous flow
was assigned, the battle's own `ff 08` reply assigns a new one, and
the next stage-2 re-entry announces *that*. Nineteen flows, nineteen
links, zero exceptions:

```
22 B C>S  [prefix 4][01 00 00][rid u32][00 00][prev key4 u32][attempts u8][mtu u16][02 00]
13 B S>C  [ff][08][00 00 00][rid u32][new key4 u32]        (inside a 36 B datagram)
```

```
login 5bb8ed38 → 76175  a4d7f438  stage-1
              → 26477  a725a11f  stage-2 (full flood)
              → 63293  cb146d29  battle 1
              → 89999  913ed471  stage-2 re-entry
              → 78155  88be193a  battle 2 (story)
              → 99539  b17a2f1a  stage-2
              → 20499  a96b7aee  battle 3 (story)
              → 109947 2f9b92ec  stage-2
              → 17437  bf74b738  battle 4
              → 84015  47103a42  stage-2
              → 36535  4e273be6  battle 5
              → 31169  391af4ed  stage-2
              → 97481  ad548b79  battle 6
              → 41375  09fd9fe0  stage-2
              → 75891  c32ce4e2  battle 7
              → 57635  7440eae4  stage-2
              → 73349  0cd5961e  battle 8
              → 39733  d9b706a7  stage-2
              → 100543 9bdea916  battle 9
```

Each flow's announced value is byte-identical to the previous flow's
assigned value, so the key4 is a **session-continuity token**: opening
a flow proves knowledge of the one before it, and the game never opens
one cold. That is the client-side half of the session-continuity rule — a
client that announces a stale or guessed key4 is announcing a session
it does not hold. It
also means a battle is not a separate session: the arena server hands
the client a key that the *lobby* manager then accepts on re-entry.

Rid behaviour matches §7 exactly and extends it: stage-1 continues the
login sequence (login#1 76173, login#2 76174, stage-1 22 B 76175), and
every later flow mints a fresh value — 18 samples, all distinct, all
< 2^17 (26477 … 109947). The server echoes whatever rid it is given,
so the rid is not a gate; the key4 is.

### 19.3 Stage-2 re-entry after a battle

The first stage-2 is the full flood (72 chunks, 892,217 B, 730
datagrams). Each post-battle re-entry is a **re-sync, not a re-flood**:
1–3 chunks, 201–223 datagrams, and the base chunk is the **same
245,819 B lobby-state document every time** (identical size and
identical key census in all nine — 1,339 keys, `finishTime` top at
618, stack 375/376). Four of the eight re-entries carry that chunk
alone; the others append 20,783 B and/or 2,438 B. The 20,783 B chunk
decodes to a dict `{account, battlePass, cache, dogTags, inventory,
prevRev, quests, rev, sessionStats, stats, storyMode, wtr}` — the
post-battle delta (note `storyMode`, present after the two history
battles only).

### 19.4 Battle C>S framing — exact-consumption confirmed at scale

`[02][key4][SUB][len u16 LE][payload]` with records concatenated
(§14's Oct-14 correction) parses with **exact consumption on 50,000+
apps** across the nine battles (residual failures: 1–3 overruns and
1–13 short tails per battle, i.e. truncated datagrams). Nine distinct
key4 values, one per battle, each equal to the value the server
assigned in that flow's `ff 08` reply — the chain of §19.2 seen from
the battle side.

Per-battle C>S record census (chained records included, so this
supersedes the lead-SUB counts in §14):

| SUB | len | b1 | b2* | b3* | b4 | b5 | b6 | b7 | b8 | b9 |
|-----|-----|----|-----|-----|----|----|----|----|----|----|
| `1a` | 26 | 3459 | 0 | 0 | 9282 | 4020 | 7778 | 2587 | 2750 | 2983 |
| `1a` | 9 | 1 | 4 | 11 | 0 | 0 | 0 | 0 | 0 | 0 |
| `07` | 7 | 2218 | 6430 | 7592 | 4684 | 2098 | 4091 | 1288 | 1237 | 1285 |
| `18` | 16 | 1442 | 5771 | 6790 | 4167 | 1757 | 3550 | 1012 | 925 | 882 |
| `12` | 5 | 169 | 568 | 762 | 481 | 280 | 398 | 58 | 79 | 95 |
| `06` | 4 | 340 | 299 | 374 | 340 | 214 | 291 | 139 | 159 | 146 |
| `1c` | 9 | 28 | 121 | 157 | 90 | 21 | 50 | 10 | 17 | 10 |
| `10` | 4 | 2 | **86** | **117** | 20 | 4 | 11 | 3 | 4 | 2 |
| `1d` | 12 | 2 | 5 | 11 | 5 | 2 | 6 | 1 | 3 | 0 |
| `9d` | 27–46 | 2 | 0 | 0 | 6 | 0 | 4 | 1 | 0 | 0 |
| `13` | 5 | 1 | 1 | 7 | 0 | 0 | 0 | 2 | 0 | 0 |
| `19` | 9 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |
| `1b` | 9 | **3** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `14` | 5 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| `23` | 28 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| `96` | 20 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 |
| `01`,`04`,`39`,`89`,`8a`,`8b`,`8c` | 0 | | | | | | | | | |

\* history battle mode.

### 19.5 The own-shoot trigger is `0x10` — 203/203 (settles §14 vs `lobby/battle.go`)

§14 predicted the own shoot would be `0x1b` (doc-order `vehicle_shoot`,
own-cell[27]) and `lobby/battle.go` recorded the wire truth as `0x10`
on 8/8 Oct-14 samples. This capture settles it at scale: the observer
fires **86 times in b2 and 117 times in b3** (history battle mode,
3.3 s reload), and the C>S stream carries **exactly 86 and 117 `0x10`
records** — 203/203, one per shot, each 37–148 ms (median 85/89 ms)
ahead of the S>C `showShooting` the feed timestamps. b1 is the
zero-baseline control: the observer fires 0 times there and `0x10`
appears twice (equipment, not shots).

`0x1b` **does** appear on the wire — three times, all in b1 — which
retires the "0x1b never appears over 7,323 C>S" claim. But it is not
the own shoot: the observer fired zero times in b1, and the three
records are

```
02 cb146d29 1b 0900 00000000 00 91715d21   (+ chained 07 record on the first)
02 cb146d29 1b 0900 00000000 00 8b715d21
02 cb146d29 1b 0900 00000000 00 83715d21
```

at 14:04:02.234 / 14:04:03.315 / 14:04:08.415 — i.e. **after** the
observer's Challenger was killed at 14:03:57.230, and carrying
**other** vehicles' IDs (`0x215d7191/8b/83` against own `0x215d7192`).
So `0x1b` is a per-entity call, not the 0-arg own shoot; the
doc-order index (27) does not describe its wire behaviour, which is
the same index-space mismatch `0x10` (16 = `setEquipmentApplicationPoint`
in doc order) already shows. The index space is the binary's
registration order, which coincides with the `.def` order for the
`vehicle_*` block (`0x1a`/`0x1c`/`0x1d` = 26/28/29) but not for the
shoot — still open statically.

**Index-space status (Oct-31 re-check).** The `.def` order is now
pinned exactly: `Avatar.def` `<CellMethods>` has **38 direct children**
(a regex that misses self-closing `/>` tags loses 4 and yields 34), and
the order is **identical in 2.4.0.0 and 2.4.1.0** — `vehicle_moveWith`
= 26, `vehicle_shoot` = 27, `vehicle_trackWorldPointWithGun` = 28,
`vehicle_trackRelativePointWithGun` = 29,
`setEquipmentApplicationPoint` = 16. So the wire agrees with the `.def`
for 26/28/29 and disagrees only for the shoot. Ruled out as
explanations: alphabetical and reverse reorderings of the same list
(shoot lands at 34 and 10 respectively, moveWith at 33 and 11 — no
single offset reconciles 16 with 26), the `Vehicle` entity's own
`CellMethods` (moveWith = 1, shoot = 8), and the exposed-only
subsequence (19 entries; moveWith = 9, shoot = 10). Also ruled out
identity-wise: `setEquipmentApplicationPoint` takes
`(UINT16, VECTOR3, VECTOR2)` = 22 B, while the wire record is 4 B, so
the 4 zero bytes are not its args. The remaining candidate is the
binary's own registration order, which needs IDA on the method-table
build (`EntityType::init` `sub_140394440` / method visitor
`sub_142AA17D0`) — not resolvable from the shipped `.def`.

**Two framing corrections for anyone re-running this.** (1) The battle
flows in `captures/proxy-20261031-1358.hex` are the **arena**
connections on `:32810`–`:32815`, *not* the `:32874` BaseApp flows —
scanning `:32874` finds zero `0x10` records and zero 26 B `0x1a`
records. On the arena flows the counts reproduce exactly: 117 `0x10`
records on `127.0.0.1:50475->92.223.20.73:32815` and 86 on
`127.0.0.1:60262->92.223.20.71:32813`. (2) The C>S bundle head is
`[02][flowKey u32]` — the 4 bytes are the per-flow key the server
assigns in the first 36 B S>C reply (`lobby.BattleKeyLen`), **not** an
entity ID. So `02 cb146d29 1b 0900 …` reads `[02][flowKey][SUB 0x1b]
[len 9][args]`, and the "other vehicle's ID" in the `0x1b` records is
in the *args* (`91715d21` vs own `215d7192`), not the head.

### 19.6 History battle mode: no `moveWith` at all

The two history battles are the only ones with **zero 26 B `0x1a`
position records** (b2: 0, b3: 0, against 2,587–9,282 in every random
battle). Their `0x07`/`0x18` rates are unchanged per minute, so the
client is alive and reporting — it simply never sends
`vehicle_moveWith`. The 9 B `0x1a` form (`[u32 0][…][u32]`, 4 in b2 /
11 in b3) is the only `0x1a` traffic there, and it carries other
entities' IDs. Reading: in the history mode the player's own position
is not client-reported (scripted/AI-driven vehicle), so a
position-tracking consumer must not assume `0x1a` exists.

### 19.7 New C>S record classes

Not in §14's census, all shape-stable across battles:

* `0x9d` (27–46 B) — a **typed battle-event envelope**:
  `[u16 eventType][u16 seq][event payload]`. Types seen: `0x2a` (42,
  `[entity u32]` + zeros — a per-vehicle marker), `0x4a` (74,
  `[u16][u16]` + zeros + a length-prefixed string, live sample
  `"VEHICLE_MARKER_TYPE"`), `0x1d` (29, zeros + string + 2 floats),
  `0x16` (22, zeros + a length-prefixed string — battle chat, see
  §19.10), `0x18` (24, zeros). Six in b4, four in b6.
* `0x23` (28 B) + `0x8a` (0 B) — a **battle-exit pair**, sent together
  at the end of every battle (14:04:54.386, 14:16:45.878, 14:30:16.861,
  …), `0x23` = `[u32 0][f32][f32][f32][u32 0][u32 0][f32]`.
* `0x96` (20 B) — once per battle at start (`dd 00 79 00 …`).
* `0x19` (9 B) — exactly twice per battle, every battle.
* `0x14` (5 B), `0x13` (5 B), `0x39` (0 B + 1 tail byte), `0x01` (0 B),
  `0x89`/`0x8a`/`0x8b`/`0x8c` (0 B), `0x04` (0 B) — rare singles.

None of these are named: the index space is unresolved (§19.5), so
they stay shape-only.

### 19.8 The garage actions: research → buy+equip → sell → reload layout

The stage-2 command stream is otherwise a poll loop — `501`
CMD_REQ_SERVER_STATS ×136, `502` CMD_REQ_QUEUE_INFO ×19, `100`
CMD_SYNC_DATA ×8, `700` CMD_ENQUEUE_IN_BATTLE_QUEUE ×9, `121`
CMD_SET_ACTIVE_VEH_SEASON ×6, `205` CMD_BUY_SLOT ×2, `520`
CMD_REQ_PREBATTLES ×2. One flow carries the whole **research +
purchase** sequence: `34967`, the re-entry at 14:56:28 before battle 7.
It decodes end-to-end against `common/AccountCommands.py` and
`account_helpers/{Stats,shop,inventory}.py`:

| t | cmd | args (decoded) | server answer |
|---|-----|----------------|---------------|
| 14:56:50.392 | `10032` CMD_APPLY_ADDITIONAL_XP | `(cacheRev 3, arenaUniqueID 2384407815505965515, vehTypeCompDescr 3985)` | `stats.freeXP 12024` |
| 14:57:20.228 | `201` CMD_UNLOCK | `(vehTypeCompDescr 3985, unlockIdx 2, 0)` | `stats.unlocks [4244]`, `vehTypeXP {3985: None}`, `freeXP 12024→10412` |
| 14:57:32.382 | `308` CMD_BUY_AND_EQUIP_ITEM | `[cacheRev 3, compDescr 4244, vehInvID 288, slot 0, isPaidRemoval 0, gunCompDescr 0]` | `credits 12173402`, `inventory[gun] {4244: None, 3988: 2}`, `shellsLayout {288: {(6803,4244): [[519066,70,519322,0,519578,4]]}}` |
| 14:57:32.812 | `305` CMD_SELL_ITEM | `(shopRev 3, itemTypeIdx 4 = vehicleGun, itemInvID 3988, count 1)` | `inventory[gun] {3988: 1}`, `credits +25500` |
| 14:57:35.657 | `305` | same | `1a/5e` error `"COOLDOWN"` |
| 14:57:38.953 | `305` | same | `inventory[gun] {3988: None}`, `credits +25500` |
| 14:57:55.256 | `108` CMD_SET_AND_FILL_LAYOUTS | `[shopRev 3, vehInvID 288, 6, 519066,65, 519322,5, 519578,3, equipmentType 0, 0]` | `shells {288: [519066,65,519322,5,519578,3]}`, `credits −39570` |

Compact descriptors decode with `parseIntCompactDescr` (`type = cd &
15`, `nation = (cd>>4) & 15`, `id = cd>>8`), and the 2.4.0 item defs
(`lobby.GeneratedTable`) name them:

| cd | hex | type | nation | id | item |
|----|-----|------|--------|----|------|
| 3985 | `0x0F91` | 1 vehicle | 9 Poland | 15 | `Pl18_BUGI` |
| 4244 | `0x1094` | 4 gun | 9 | 16 | `_90mm_wz_39_40` — researched + installed |
| 3988 | `0x0F94` | 4 gun | 9 | 15 | `_75mm_wz_36_37` — stock gun, sold |
| 6803 | `0x1A93` | 3 turret | 9 | 26 | `Turret_1_Pl18_BUGI` |
| 519066/519322/519578 | `0x7EB9A/CA/FA` | 10 shell | 9 | 2027/2028/2029 | the 90 mm AP / APCR / HE |

So the wire is exactly the garage UI's chain, and every step is
confirmed by the server's own delta: the unlock list gains `4244`, the
vehicle's XP entry is cleared, free XP drops by 1,612; the gun swap
returns the old gun (`inventory[gun] {4244: None, 3988: 2}` — the
player already held one); two sells land at +25,500 each and the
second is refused with `COOLDOWN`; the final loadout is 65 AP + 5 APCR +
3 HE (73 of the 90 mm's 74 max ammo).

`CMD_APPLY_ADDITIONAL_XP(cacheRev, arenaUniqueID, vehTypeCompDescr)` is
the *funding* step: it converts the "additional XP" earned in one
specific arena into vehicle XP. `2384407815505965515` is battle 6's
`arenaUniqueID` — the battle fought in `vehInvID 288`, i.e. the BUGI,
enqueued at 14:48:55. The same call appears once earlier, at 14:40:17
in flow `35708`, with battle 4's `arenaUniqueID 80470384497257911` and
`vehTypeCompDescr 1569` (nation 2/USA, id 6).

Two more arg shapes worth recording:

* `CMD_ENQUEUE_IN_BATTLE_QUEUE` = `[QUEUE_TYPE, vehInvID, gameplaysMask,
  arenaTypeID]` (`Account.enqueueRandom`). `[1, 464, 67, 0]` is
  `QUEUE_TYPE.RANDOMS` with `gameplaysMask 0x43` = CTF|DOMINATION|
  ASSAULT2; `[100, 3]` / `[100, 4]` is `QUEUE_TYPE.STORY_MODE` plus a
  mission id. Full walk in §19.9.
* `CMD_SET_ACTIVE_VEH_SEASON` = `(vehTypeCompDescr, season)` — six
  calls, `(14161,4) (1569,4) (4257,2) (1905,2) (3985,2) (2561,4)`, i.e.
  the client re-stamping the camo season of the vehicles it touched.

### 19.9 Random-battle enqueue: one fire-and-forget command

`CMD_ENQUEUE_IN_BATTLE_QUEUE = 700`, sent with `doCmdIntArr` — the
`ARRAY<INT32>` variant of the command port (signature from the shipped
2.4.1 def `scripts-2.4.1/entity_defs/interfaces/ClientCommandsPort.def`,
unpacked with `wotunpack`). The request id is
`REQUEST_ID_NO_RESPONSE = 202` (`STREAM_ID_ACCOUNT_CMDS_MIN = 200` + 2,
`common/streamIDs.py`), so the client never waits for an
`onCmdResponse`: the outcome arrives later as unsolicited client-method
calls (§19.9.2).

#### 19.9.1 The 29 B app, field by field

Battle 1, 14:00:05.759:

```
02 a725a11f 9e 1500 ca00 bc02 04 01000000 d0010000 43000000 00000000
```

| bytes | meaning |
|---|---|
| `02` | packet type 2 (command) |
| `a7 25 a1 1f` | key4 — Blowfish-encrypted stream key (§19.2) |
| `9e` | element type `doCmdIntArr` |
| `15 00` | payload length 21 |
| `ca 00` | reqID 202 = `REQUEST_ID_NO_RESPONSE` |
| `bc 02` | cmd 700 = `CMD_ENQUEUE_IN_BATTLE_QUEUE` |
| `04` | array count 4 |
| `01 00 00 00` | `QUEUE_TYPE.RANDOMS` |
| `d0 01 00 00` | `vehInvID` 464 |
| `43 00 00 00` | `gameplaysMask` 67 |
| `00 00 00 00` | `arenaTypeID` 0 |

The four ints come from
`gui/prb_control/entities/random/pre_queue/entity.py:63` →
`Account.enqueueRandom(vehInvID, gameplaysMask=ctx.getGamePlayMask(),
randomFlags=ctx.getRandomFlags(), arenaTypeID=mmData)`:

* `vehInvID` is the **garage slot**, not the compact descriptor — 464
  here, and the same id the server locks (§19.9.2).
* `gameplaysMask 67 = 0x43` = bits 0, 1, 6 = `ctf | domination |
  assault2` (`ARENA_GAMEPLAY_NAMES = ('ctf','domination','assault',
  'nations','ctf2','domination2','assault2',…)`, mask built by
  `common/arenatype.py:48`). `account_helpers/gameplay_ctx.py getMask()`
  reads the server setting `GAMEPLAY/gameplayMask`, strips `nations`,
  and **force-ORs `ctf` in** — `ctf` is always present whatever the
  hangar checkboxes say. The hangar's "Assault" box is `assault2`
  (`_ASSAULT2_GP_NAME = ARENA_GAMEPLAY_NAMES[6]`), not `assault`.
  `ARENA_GAMEPLAY_MASK_DEFAULT = 1048575`.
* `arenaTypeID 0` = any map; non-zero pins one arena type.

**Version drift:** the shipped `2.4.0.0/res/scripts/client/Account.pyc`
(uncompyle6, `enqueueRandom`) sends **five** ints —
`[QUEUE_TYPE.RANDOMS, vehInvID, gameplaysMask, arenaTypeID,
randomFlags]` — while the 2.4.1.0 wire carries **four**: `randomFlags`
was dropped. Not trailing-zero trimming: `CMD_SET_AND_FILL_LAYOUTS` in
the same capture sent 11 ints ending in two zeros. `RANDOM_FLAGS` was
`IS_ONLY_10_MODE_ENABLED = 1`, `IS_MAPS_IN_DEVELOPMENT_ENABLED = 2`.

#### 19.9.2 The answer path — four unsolicited records, no response

| step | record | shape | client handler |
|---|---|---|---|
| ack | `1a/51` | 1 B payload: `01` random, `64` (=100) story | `onEnqueued(UINT8 queueType)` (`scripts-2.4.1/entity_defs/Account.def`) |
| lock | `1a/69` | cache delta `{prevRev: 165, cache: {vehsLock: {464: (2, 0)}}, rev: 166}` | `account_helpers/inventory.py:71-74` `synchronizeDicts(vehsLockDiff, itemInvCache['lock'])` |
| polls | `1a/67` | bare pickle dict, `alias.xml` `DEFAULT_QUEUE_INFO = {classes: ARRAY<UINT32>, players: UINT32}` | `receiveQueueInfo(QUEUE_INFO)`, `AllowUnsafeData=true` |
| go | `1a/4e` | no args | `onArenaCreated` |

The def also declares the two failure paths, unused here:
`onEnqueueFailure(UINT8, UINT8, UINT8)` and `onKickedFromQueue(UINT8)`.

`(2, 0)` is `(LOCK_REASON.IN_QUEUE, 0)` — `LOCK_REASON` in the shipped
`2.4.0.0/res/scripts/common/AccountCommands.pyc` is `NONE 0, ON_ARENA 1,
IN_QUEUE 2, PREBATTLE 4, UNIT 8, BREAKER 16, ANY_MASK 255`; `Account.py`
fires `events.onVehicleLockChanged(vehInvID, lockReason)` per entry,
which is what greys the tank out in the garage. The ack and the lock
delta arrive **bundled in one app** (b1: applen 76 =
`13 24 1a 69 44 43 <pickle 67 B> 1a 51 01`, the pickle being
`{'prevRev': 165, 'cache': {'vehsLock': {464: (2, 0)}}, 'rev': 166}`).

Polling is `CMD_REQ_QUEUE_INFO = 502` via `doCmdInt3(202, 502,
queueType, 0, 0)` every ~5 s — A1 `0x95` (3×INT64 args, 24 B) against
the enqueue's `0x9e` (`ARRAY<INT32>`), so the two are distinguishable by
tag alone. b1 samples: 524, 557, 656, 655, 641, 673 players, per-class
sums equal to `players`. `onArenaCreated` is a bare 4 B app
`13 xx 1a 4e`, sometimes at the tail of a larger app (flow 35846,
applen 94, offset 92); the client then opens the battle flow with its
own key4 rotation (§19.2).

b1 timeline: enqueue 14:00:05.759 → `onEnqueued` 05.835 → six polls
06.129 / 11.127 / 16.139 / 21.148 / 26.164 / 31.180 → `onArenaCreated`
14:00:32.353 → battle flow 14:00:33.137. **27.4 s in queue**, ack
latency 76–136 ms across all nine.

#### 19.9.3 No dequeue ever

`CMD_DEQUEUE_FROM_BATTLE_QUEUE = 701` (also 724, 914) appears **zero**
times across all C>S in this capture — all nine enqueues ran straight
through to a battle. The history battles reuse the same command with a
two-int array instead: `[100, 3]` and `[100, 4]`, i.e.
`[QUEUE_TYPE.STORY_MODE, missionId]` (§19.1, §19.6).

### 19.10 Battle chat: submit `0x9d`/22, relay `0x75`/23

Battle chat is a **different layer from the lobby chat handshake**
(§7's `(98,25)` `Chat.chatCommandFromClient` tails) and from XMPP
(§16). It rides the arena flows in two record classes, one per
direction, and both payloads are the same 24-byte header plus
`[u8 len][text][u16 0]`:

```
[u16 eventType][u16 seq][u32 channel][u32 sender][u32 0]
[f64 time][u8 len][text][u16 0]
```

* **C>S submit** — a bare record in the `[02][key4]` bundle, framed
  like every other C>S record: `[9d][len16le][payload]`, eventType
  **22**. The client leaves `sender` and `time` zero; `seq` is its own
  counter (7 then 8 on the two live submits). Every observed submit
  also carried the standard 29B position trailer after the record.
* **S>C relay** — a type-`0x75` small, `[1a][75][len8][payload]`, the
  same family as the marker records (§19.7's `ScanBattleMarkers`,
  which skips this subtype), eventType **23**, `seq` 0. The server
  fills in `sender` and `time`.

`sender` is the speaker's **arena entity ID**, not an account ID: the
Oct-31 value `0x016800ae` is the arena login name carried in the
handshake, and the position trailer's own entity.
`time` is a **float64 unix timestamp in UTC** — `1793453981.713`
decodes to `2026-10-31T13:39:41.713Z`, 28 ms before the relay packet
carrying it, and the other three samples land 20–120 ms before their
packets. `channel` is 0 in all 33 samples (battle-all); an ALL/TEAM
split is unproven.

Census over the 16 proxy dumps: **33 messages in 6 captures** —
`proxy-20261031-1358` 17 (the only capture with both directions and
the only own submits, `"lmao"`/`"gg"`), `proxy-20261017-1322` 9,
`proxy-20261014-1752` 2, `proxy-20261024-1751` 2,
`proxy-20261024-1806` 2, `proxy-20261024-1833` 1. Text is UTF-8
(Cyrillic and Polish samples present), so a consumer must not filter
on ASCII. The auto-spot callouts (`"Im Spotted at F6!"`) ride the same
relay and are indistinguishable from typed chat by shape alone.

Implemented in `lobby/battlechat.go` (`ScanBattleChatC2S`,
`ScanBattleChatS2C`, `BuildBattleChat`, `Observer.ObserveChat`),
surfaced as `CHAT` rows by `cmd/wotbattlefeed`.

## 20. Entity property elements and the in-battle tick (Nov-07)

The arena tick is a bundle of **elements**, each `[id][payload]`, and the
property elements among them carry no entity id: a bare property element
applies to whatever entity the last *selection* element named. That makes the
element id and the element order both load-bearing.

### 20.1 `ENTITY_PROPERTY_BASE` is `0xA7` for every entity

A property element's id is `0xA7 + FullIndex`, where `FullIndex` is the client's
`allocateClientServerFullIndexes` order — **fixed sizes first and ascending,
then the variable ones in declaration order**. That is
`entdef.Entity.CSPropsOrdered`, and it is *not* the def's declaration order.
The base is the reference toolkit's `ElementIdRange::new(0xA7, 0xFE)`.

Four ids in `captures/proxy-20261031-1358.hex` pin it, and each matches the
def's own table:

| element | FullIndex | `Vehicle` property | width |
|---|---|---|---|
| `0xa8` | 1 | `isStrafing` | 1 |
| `0xb3` | 12 | `botDisplayStatus` | 1 |
| `0xb4` | 13 | `gunAnglesPacked` | 2 |
| `0xb6` | 15 | `engineMode` | 2 |

Walking every `S>C` tick in that capture with the def's table parses **1184
packets cleanly** and finds exactly those four property ids — no others, and no
desync. `0xba` is the *Avatar's* `ownVehicleAuxPhysicsData` (FullIndex 19, 8 B),
which is why it follows `0x1a` SelectPlayerEntity and the Vehicle's two follow
`0x1d`.

The ids this server sends:

| element | property | width |
|---|---|---|
| `0xab` | `Vehicle.siegeState` | 1 |
| `0xb4` | `Vehicle.gunAnglesPacked` | 2 |
| `0xb6` | `Vehicle.engineMode` | 2 |
| `0xc2` | `Vehicle.wheelsScroll` | variable |
| `0xba` | `Avatar.ownVehicleAuxPhysicsData` | 8 |

### 20.2 Variable-length properties: header width, then a count

A property whose `VariableLengthHeaderSize` is 1 is `ElementLength::Variable8`:
one length byte. And a `Tuple[0]`/`ARRAY` has no fixed element count, so its
payload **starts with that count** — `Codec::write` does
`write_packed_u24(list.len())` then the elements, and `read` takes the count the
same way. So

```
id <len8> <count> <count bytes>          len8 = 1 + count
```

Omitting the count is not a cosmetic error: `c2 08 <8 bytes>` made the client
read the first element `0x80` as a count of 128 out of an 8-byte element and die
on `MF_ASSERT_DEV FAILED: pCurr_ + nBytes <= pEnd_`. That assert is the signature
of a mis-framed variable-length element, and it is what the earlier `0xc3`
attempts hit too — on top of `0xc3` being `perkEffects` (FullIndex 28), not
`wheelsScroll`.

`Vehicle.wheelsScroll` is `Tuple[0]{UINT8}`, one packed angular speed per
**non-track** wheel. The count is `getNonTrackWheelsCount()`, not the number of
`wheel` entries: `Vehicle.set_wheelsScroll` zips the tuple against the scroll
filters `createWheelFilters` builds from that same count. The EBR 105 declares
16 wheels and only 8 are non-track. `WoT.unpackWheelScroll` is
`(int8)byte * 0.19607845 - 24.90196`, i.e. a signed byte over `[-50, 0]` rad/s,
negative for forward travel.

### 20.3 `MOVEMENT_FLAGS` — the handbrake is bit 6

`cell.vehicle_moveWith` carries one flag byte (`client/avatar.py`):

| bit | flag |
|---|---|
| 1 | `FORWARD` |
| 2 | `BACKWARD` |
| 4 | `ROTATE_LEFT` |
| 8 | `ROTATE_RIGHT` |
| 16 | `CRUISE_CONTROL50` |
| 32 | `CRUISE_CONTROL25` |
| **64** | **`BLOCK_TRACKS`** — the handbrake |

The space bar is `CMD_BLOCK_TRACKS`, which `Avatar.moveVehicle` folds into the
same byte it sends to the cell. It locks the tracks: the hull brakes and a
stationary hull cannot pivot on the spot, but a moving hull keeps its momentum
— the lateral grip drops, so the steering turns the hull under the velocity
vector and the tank slides (the drift). A server that stops reading at bit 5
drives straight through the handbrake.

### 20.4 NRL property updates on a dynamic component

A component property update is a node record inside the `0x26` NRL data
element, consumed by the `0x25` flag:

```
26 <len16> <node_id u16 BE> <kind u8> <len packed-u24> <value>   25
```

`kind` 0 is the whole value; 1 and 2 are nested add/remove. A volatile property
carries its value alone, with no kind and no length. The node id is
`FirstChild + property index`, and the index is the component's
`CSPropsOrdered` position — for `OwnVehicle` that is `syncVehicleAttrs` 0 (the
only fixed-size property) then the variable ones in declaration order, so
`vehicleGunReloadTime` is 2 and `siegeStateStatus` is 10.

`OwnVehicle.siegeStateStatus` is the **only** route to
`Avatar.updateSiegeStateStatus`, which is not a def method: its setter
`OwnVehicleBase.update_siegeStateStatus` calls it, and that reaches
`Vehicle.onSiegeStateUpdated`. Measured live with only `Vehicle.siegeState`
sent, `Vehicle.siegeState` read 2 while `SiegeModeControl.__currentState` was
still 0 — so the HUD never showed siege, the composite descriptor never switched
to `VEHICLE_MODE.SIEGE`, and pressing X could only ever ask to ENABLE.
