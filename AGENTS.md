# AGENTS.md — wot (Go module `github.com/LockBlock-dev/wot`)

Single Go project for World of Tanks EU internals: LoginApp + BaseApp
client (`login`), LoginApp ping (`ping`), `.wotreplay` reader
(`replay`), entity-def reader + login digest (`entdef`), live key
dumper (`keydump`), transparent forwarder (`tproxy`). All 8 CLIs
live under `cmd/`. Run from here: `go run ./cmd/wotlogin -env
live.env -baseapp`. Protocol truth lives in `../NETWORK_PROTOCOL.md`
(login) and `../REPLAY.md` (replays); update them on wire changes.

## Layout

- `login/` — framing builders/parsers + `Client.Login()` flow (pure where
  possible; `SolveFunc` injected for tests; `Transport` interface over
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
  stage-1/stage-2 script), `lobby_alias.go` (re-exports of the lobby
  package: same symbols, new address), `hijack.go` (wotproxy dump parser +
  `SessionFromDump` + `LoginSourcePort`), `config.go` (stdlib `.env`
  parser + `Config`; sorted+spaced username JSON; `cpsaltSession`),
  `flood.go` (bulk chunk reassembly by channel-seq + NN headers,
  smalls taxonomy + census, keyfile/recover helpers).
- `lobby/` — offline application layer, stdlib-only (no transport):
  `pickle.go` (hand-rolled proto 0-2 decoder, triple-verified vs
  CPython execution + independent emulator on 3 captures; LONG1/4
  sign fix Sep 28; `DecodeAt`/`DecodePrefix`/`Inventory` resync +
  `Frag`), `lobby_state.go` (prefix salvage → plain maps/slices),
  `lobbycalls.go` (C>S base-call builders: doCmdInt2/3/4/Str,
  requestToken, primeBundle prefix, chat tails), `battle.go` (avatar
  position parser). Split out of `login/` Oct 2026; callers migrate
  from the `login/lobby_alias.go` re-exports to `lobby` directly
  (`cmd/wotflood` already does for inventory/stream).
  Tests: `login_test.go` (offline codec vectors), `hijack_test.go`,
  `paired_replay_test.go` (byte-identical replay of the paired genuine
  stage-1/stage-2 capture, `../captures/flows3` + `../captures/key3.txt`;
  fixtures rebuilt from those two files by
  `../captures/extract_flows3.py` — vectors to `/tmp/opencode/vectors`,
  stage-2 flow to `../captures/flows3-s2.txt`; re-run after any /tmp
  wipe),
  `scratch_flood_test.go`. Offline only.
- `ping/` — LoginApp ping library (`ping.go`: framing consts,
  `encodeRequestWithPrefix`, `decodeReply` for 16 B current and 18 B
  2022 replies, `Client`, `Classify`, `NewReplyID`) + `ping_test.go`.
  Offline only.
- `replay/` — `.wotreplay` reader: `replay.go` (`Open`/`Parse`,
  decrypt, inflate, `MetaField`, `ClientVersion`), `packets.go`,
  `dispatch.go`, `entities.go`, `values.go`, `methods.go` +
  `methods_gen.go` (GENERATED from 2.4.0.0 entity_defs via `entdef`
  DescribeDeep + iface-first stable size-sort; var lists doc order —
  see `../REPLAY.md` §6 before regenerating), `properties.go` +
  `properties_gen.go` (generated FullIndex table via entdef
  `CSPropsOrdered`), `nested.go`, `creates.go`, `misc.go`, `events.go`,
  `timeline.go`. Tests pin Prohorovka (2.4.0) + Mines (2.3.1) +
  Glacier (2.1.1) + 2.0 decrypt. Offline only.
- `entdef/` — entity-def reader (packed-section `.def` parser) + login
  digest computation over `../World_of_Tanks_EU/res/scripts`
  (entities/interfaces/alias) plus vendored `testdata/wotdefs/`
  (space defs, 339 component defs, 10 mode entities, 17 extension
  manifests): `components.go`, `digest.go` (`ComputeDigestFull`,
  318-entry map walk), `defs.go`, `packed.go`, `types.go`.
- `internal/cuckoo/` — vendored `ZiRo-/cuckgo` (MIT, see
  `LICENSE-THIRD-PARTY`): `cuckoo.go` verbatim, `miner.go` = upstream
  search adapted with early exit + our `SolveChallenge` driver.
- `testdata/wotdefs/` — vendored defs for offline digest/tests.
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
- `login/rewrite.go` — `RewriteLoginReply` + `encryptLogin` (login-path
  Blowfish mirror, no magic trailer).
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
  (wgcs_api.dll, see `../WGC.md`): pipe exactly
  `\\.\pipe\WGCS_IPC`; `GetLoginInfo` OUT = +0 WCHAR[64], +128
  WCHAR[256], +640 WCHAR[64], +768 UINT64 spaId, +776 DWORD
  (sub_180050190; all strings inline WCHAR, no pointer chasing);
  `GetRememberMeToken` = struct(+0 token area, +256 UINT64) +
  WCHAR[1024] buffer; `StoreRememberMeToken` = WCHAR[128] key +
  WCHAR[1024] token; LoginSession vtable @0x18015A588
  (slot0/4/5/8 = logininfo/store/get/generate workers).
  `wgc.exe` is a thin shell; the core is unpacked
  `dlls/game_center.dll` (see `../WGC.md` §7: AES-ECB seal for SSO
  material, Wine-DPAPI-hex seal for the user_info store).
- `cmd/wotdpapi/main.go` — Wine-DPAPI unwrap CLI (GOOS=windows,
  proton-run, prefix-local only): hex blob in, 0600 plaintext out,
  lengths only. No network/broker/game.
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
- `cmd/wotflood/main.go` — offline lobby analyzer (structure only):
  `-stream` bundle inventory + prefix salvage, `-dump -flow` chunk
  table + inventory, `-recover-key` (MITM key to keyfile, lengths
  only), `-smalls` census. Thin CLI, protocol in `login/`.
- `cmd/wotunpack/main.go` — packed binaries (`.def`/`.xml`, magic
  `0x62a14e45`) to readable XML on stdout.
- `cmd/wotreplay/main.go` — thin CLI (`file.wotreplay`, `-meta`,
  `-dump PREFIX` for `.stream.bin`).
- `cmd/wotverify/main.go` — genuineness CLI (structural only, see
  `../REPLAY.md` §verify); exit 0/1.
- `cmd/wotevents/main.go` — thin CLI (`file.wotreplay`, `-pretty`):
  prints the battle timeline JSON.

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
and `BaseAppLogin` now reaches the decrypt-verified lobby flood on p5
(2× reproduced) — basic → lobby is proven from OUR client, not just
genuine captures. Remaining: p2/EU2 managers stay silent at the 22B
(pre-rotation gate, server-side pending push suspected — our bytes
match there too; Sep 19 our client got zero bytes from
`92.223.20.215:32838`, the exact endpoint the game flooded Sep 18),
and lobby application parsing is offline-only so far (`wotflood`
inventory/salvage/census + `lobbycalls.go` C>S builders from game
vectors; live client still stops at the flood). Falsified Sep 19, same machine/hour:
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
  (stored session blob + `wg_ucpdata` decryption).
- `../captures/` — genuine traffic, indexed in `../captures/README.md`.

## Login — blockades

1. p2/EU2 silence at the 22B (pre-rotation, zero bytes on both
   sockets — managerside pending push suspected; our bytes match the
   game there, proven per-session Sep 19: zero bytes from
   `92.223.20.215:32838`, the endpoint the game flooded Sep 18).
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
    EU2 push stays per-session server-side. security_msg="old_pass",
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
    LoginApp traffic from us. OPEN: live probe (GetLoginInfo layout
    unknown statically; wgc.exe must be up, i.e. during/after a Steam
    session; needs the user's go).
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
   registers account-side (website-visible; probe 12:21:32 listed) —
   EU2 silence is manager-side only. Back-to-back byte proof
   (`captures/ours-p2-20260919.pcapng`): our stage-1 22B
   field-identical to the game's — per-session discrimination,
   nothing else. The push-routing probe now EXISTS: `-hijack DUMP`
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
   25× silent over 20 s, all in-window. VERDICT: EU2 gate is pure
   server-side session state (valid run). Stop chasing bytes. Next: EU2 lobby
   via our client. Launcher ruled
   out — the game runs launcherless here.
2. Offline digest CLOSED Sep 20 (`TestComputeDigestMatchesClient` green).
   Full client map recomputed byte-identically (`5df886f7…`): spaces +
   40 entities + static-component merge + 10 mode entities + 281
   dynamics (`ComputeDigestFull`, defs vendored in `testdata/wotdefs/`).
   Proven visit-for-visit by `ce/walkprobe.lua` (1242 visits),
   `ce/walkprobe2.lua` (flags/volatile), `ce/r8probe.lua` (2625 type
   tags in order), `ce/walkprobe3.lua` (entry names),
   `ce/walkfinal.lua` (entry pass/fail + gate85/varlen/descs); runs
   archived in `ce/`. Live logins carry the recomputed digest.

## Replay — key provenance

The 16 B stream key (`DE 72 BE A0 … AD BE EF`) is
community-published and verified here (test decrypts to a valid zlib
stream). It is NOT in the exe verbatim (contiguous/halves/XOR/mask/md5
all absent) — the client runtime-constructs or obfuscates it; the
green test is the proof. Cite this file, not the provenance.

## Replay — TODO: live EU5 lobby application (hangar)

Transport is done (`login` reaches a sustained, acked 1252B flood on
p5; EU2 stays server-side silent, see above). What is
missing is the *application*: parse the flood into lobby state and
speak back. Established Sep 20:

- Capture harness: TEMPORARY recorder in `login/baseapp.go`
  stageTwo (revert when done iterating) dumps S>C to
  `/tmp/opencode/flood.hex` (`<ts> <dir> <len> <hex>`); per-run block
  key alongside (`stage2.key`, RAW bytes, ephemeral session — dead in
  minutes). Plus TEMPORARY: C>S logging, 60 s window, 5 s
  `clientToServerHeartbeat` (`[0e]`, wire ID 14 = table index-1,
  FIXED-0 per sub_140240640), 4 MB rcvbuf (burst loss is real:
  175 frags vs ~150), redirect-follow (max 3), stage2.key raw write.
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
  like 804), NO Int4/Str (still unobserved).
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
  `NETWORK_PROTOCOL.md` §14): `[ID u8][posType0 6B][dirType0 4B]`;
  unpacker `0x140E37200` (+mirror `0x140E55350`), BitReader
  MSB-first, custom 1+4+N floats (bias −2.0, per-entity scale),
  direction (roll10, pitch11-half, yaw11) with absolute 2π scales;
  yaw tracking med-step 0.10 rad; 14 entities/snapshot + visitors.
  Open (runtime): position scale value, base-add mode, ID namespace,
  x/z convention.
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
  (98/5d/ab/4f/a2, one sample each, zero cross-session recurrence —
  session-specific content like 116 bursts: shape, not value).
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
  (2) redirect-policy retest (stay after hop #1), (3) doCmd probe
  (ARMED, codebook-correct: A1 0x95 `doCmdInt3(202, 501, 0, 0, 0)`,
  unreliable 60B, one per 2 s after flood+3 s — watch for any 36B+
  response); (4) entity attach (see createBasePlayer note below);
  (5) subsystem syncs (long-term).
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
- Lobby parsing is UNDERWAY (not blocked): `SalvageChunk`/`PlainValue`
  (`login/lobby_state.go`, tested) convert chunk-1 prefix salvage
  into plain maps/slices/scalars — verified on the live hangar dump
  (Sep-29 proxy session: 404 closed items = 103 maps + 55 lists +
  scalars; schema count/id/expires/tokens/customizations/
  vehTypeCompDescr/credits/seasonPoints… = shop/goodie/inventory
  state). Shape census (Sep-29 dump, names only): 79 top-level
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
  subsystem assembly + speak-back (needs a stage-2 window).
- Battle (CellApp arena) parsing is UNDERWAY (Sep-29 proxy match,
  11,421 datagrams, own channel key from the 790/984 token2-login
  leg — NOT the lobby keys): C>S = one family `[02 8b 58 4a][93
  SUB…]` at ~18 Hz, `ParseAvatarUpdate` (`login/battle.go`, tested)
  decodes the 60B/34B position shape (xyz LE f32 at [20:32];
  2535/2538 live packets parse; 60/60 sane + 59/59 smooth steps
  verified); other SUBs open with census (1a 2535×34B, 07 3019× mixed 44B-dominant,
  18 1443, 12 198, 06 62, 1c 23, 1d 11, 14 6, 01 5, 10 4, 13 2, 0b 1;
  07/44B sample embeds a position block + speed-like f32 7.14, separate
  9B `0x23` family). S>C = tick + opaque entity blobs (the apparent
  `1a ba` is a lobby-framing misparse — neither body- nor
  total-length fits, 12/4047; records show `35 00` separators +
  float tail, packed formats need engine tables); fragmented
  ff/45/46 shapes fail cleanly (16/3/3, need reassembly).
- STAGE-1 PARK (Sep 21 ~18:35–19:45, 12+ consecutive identical runs,
  plus Sep 27 ~22:43 p5 and ~22:55 p2, plus Sep 28 p5 live-fire:
  rotation-ok throughout, 250+ ticks, no redirect — opener unfired):
  server sends rotation (36B) + ticks only (cumul=0, no 52B reply, no
  0x44 redirect, auth1 never answered) then 25 s timeout. NOT the live
  game session (persists 40+ min after user logged off). SESSION/
  TEMPORARY matrix tested (fixed blob, fresh GUID, temp 0/1 — all log
  in fine, all park). No-auth1 tested (not poison). EU2 wall
  unchanged. ROOT DIFFERENCE FOUND (captures/CE.txt genuine params):
  game logs in with `auth_method: token2` (WGC-issued token) +
  `temporary: 0`; we use `basic` (password). Launcher-token path
  needs WGC (Proton env). Park = likely account-level velocity
  throttle (slow decay) and/or basic-auth deprioritization — STAND
  DOWN live attempts for hours, not minutes.
  Genuine stage-1 mirror fix ARMED in the same window: auth1 is now
  unreliable 28B `[02][key]` with NO early 0x0b (flows 38/10 prove
  the game sends 28+28, server sends the 52B; our reliable-52B+0x0b
  was tolerated only 3/11 runs). EnableEntities stays stage-2-only.
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
  148/84/68/60/token apps BYTE-IDENTICAL (requestIDs 221-224,
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
  249/252/253 stepping +9 throughout.
  804B infos = headerless text+binary interleave
  (`TargetAreaEnabled…`, zero interior docs ≥30B) — subsystem PINNED
  (sole `targetarea` hit: server_settings.pyc
  `_SpgRedesignFeatures.markTargetAreaEnabled`); framing open, two
  hypotheses: mid-bundle bulk fragment vs genuinely custom (test:
  decrypt + scan for pickle opcodes at higher offsets). ABSENT from
  the Sep-29 proxy session (session-dependent infos). That session's
  infos instead: 84B account-info (flood-burst HEAD position in both
  S>C 84s; mixed framing suggests engine packing; lead:
  AccountVersion.def version-as-property), 124B XMPP endpoint list
  (consumer XmppServerSettings; `woteu34…` = bosh host element;
  `b8→bc` walk + `KP` marker likely C++ XmppClient framing, no .pyc
  parser),
  220B = tick + 1a76 session dict (156B STOP-truncated pickle,
  salvaged) + 1a79 redirect (byte0 = IP-string length conjecture:
  `0d`=13 for 13-char IPs; then port u16 LE + 13B trailer, OPEN:
  constant→magic/version, varies→routing info; compare across
  sessions). 1a76 session dict + 1a5c queue blob re-verified here.
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
  OPEN: live fire from our client (builders offline-tested only);
  116B entity tables (envelope closed, content opaque — needs engine
  pack tables or a live experiment, not more offline grinding: Oct-02
  flows3 re-proof (correct-key channel decrypt) — 88B bodies uniform
  4.8b entropy at EVERY position 0–83, concat 2464B H=7.85 no
  zlib/ASCII/magic, ECB-2nd-layer under 6 key forms H≈6.1 unstructured,
  all rotation/login-key chained forms fail; envelope-only verdict
  stands).
- EU2 wall MOVED Sep 27: p2 (.213:32821) now gives rotation+ticks
  like p5 (was zero bytes at 22B) but still no redirect — the park
  is cross-cluster, the push is per-session. Game flows everywhere.
- Archive captures as `captures/ours-p5-lobby-<date>.hex` + key file
  when a run is worth keeping.

## Potential todos (untouched game surface, Oct-02)

1. Event-mode entities in vendored `testdata/wotdefs` (`white_tiger`,
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
   `NETWORK_PROTOCOL.md` §15): in-band UX events (7 subsystems ×
   ~35 types incl. keyDown/Up, 70/batch, ≤70/session, engine
   `logUXEvents`, server-gated); aogas = playtime-control;
   HTTP bootstrap mapped (CSIS, WebCache, Vivox, dcont, RSS).
4. Vehicle compDescr (10304 battle doc + `vehTypeCompDescr` blobs):
   tank descriptor format; unlocks dossier/vehicle parsing.
5. Token anatomy (`token`/`token2`/`session` structures) — DONE
   Oct-02 (offline, shapes only, see `WGC.md` §6): token2 =
   `{9-digit accountID}:{18–19-digit middle}:{39-digit tail}` all
   numeric (9 samples, 4 families); middle uniform-random-looking,
   NOT a standard session-md5 transform (needs `-middle-out`
   blob pairs live); `token` = 8 digits; 12-key login census pinned.
6. Battle-results answers (852B `CMD_REQ_BATTLE_RESULTS` replies):
   straight pickle decode from captures on hand — DONE Oct-02 (see
   `NETWORK_PROTOCOL.md` §17): full cache mechanism from shipped
   `.pyc`, 0x45 `(smallint, id)` shape on 2 live answers, stream
   found inside the 852's own train (63-list + roster pairs),
   1500/1501 linkage + direct-base A1 flavor; open: status→resultID
   mapping, 5472 semantics, full 63-field schema.
7. XMPP/bosh chat beyond the tails (gated on HTTP flows, maybe in
   `eu2-mitmproxy-flows`) — DONE Oct-02 (see `NETWORK_PROTOCOL.md`
   §16): TCP-first/BOSH-fallback, JID = DBID@domain/resource,
   XMPPCS token login, disconnects reported to server; 124B list
   proven bosh-only on lobby-#2 wire (per-flow key recovery);
   distinct layer from the (98,25) BaseApp tails.
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
