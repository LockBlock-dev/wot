# WGC.md — Wargaming Game Center (Steam variant) token broker

How the game obtains `token2` without a password: the WGC broker mints,
stores, and serves it over local IPC. This file documents the broker
side (pipe, DLL interface, auth flows, on-disk store). The LoginApp
wire side lives in `NETWORK_PROTOCOL.md`; the Go broker client in
`wgcs/` + `cmd/wotwgcs/`.

Conventions: `<STEAM>` = the Steam library folder,
`<PREFIX>` = the game's Proton prefix (`steamapps/compatdata/1407200`),
repo paths are relative to the checkout. No secret values appear here —
key names, shapes, and addresses only.

Status: interface + IPC + auth chain proven by static RE (IDA) and
broker logs. Live broker calls are user-gated (need a Steam session
with `wgc.exe` up).

## 1. Components and locations

- Broker: `<PREFIX>/drive_c/ProgramData/Wargaming.net/GameCenter
  for Steam/` — `wgc.exe` (~2.5 MB, unpacked thin shell),
  `api/wgcs_api.exe`, `dlls/game_center.dll` (~31 MB, unpacked Qt core —
  ALL logic lives here), `dlls/` (Qt5, libcrypto/libssl,
  sdkencryptedappticket64), `logs/wgc_*.log`,
  `data/wgc_{id,path,vending_id}.dat`.
- Client stub (what the game loads):
  `<STEAM>/steamapps/common/World of Tanks/eu/win64/wgcs_api.dll`
  (~2.4 MB, PE32+ x86-64, ImageBase `0x180000000`, internal name
  `wgc_api.dll`, linker 14.0). Exports the same `WGCApi*` surface as
  `wgc_api.dll`. The game tries `wgc_api.dll` → `wgc360_api.dll` →
  `lgc_api.dll` → `wgcs_api.dll` (wide strings, exe `0x1438AC2B0…`)
  and only the last exists under Steam.
- Dead ends: the external-drive `wgc_api.exe` copy and the prefix
  `wgc.exe` are packed-looking launcher stubs with no token/pipe
  strings. The top-level `wgcs_api.exe` (1 MB, PE32) has no IPC/token
  strings either.
- Game launch: Steam runs `WorldOfTanks.exe` directly (Proton);
  `wgc.exe` starts ~6 s earlier and persists for hours (logs span
  whole play evenings). No broker process outside sessions.

## 2. IPC transport

- Pipe name is exactly `\\.\pipe\WGCS_IPC` (wide `L"WGCS_IPC"` +
  `L"\\\\.\\pipe\\"`, `sub_180005820`). Overlapped `CreateFileW`
  (`GENERIC_READ|WRITE`, `OPEN_EXISTING`, `FILE_FLAG_OVERLAPPED`) +
  `SetNamedPipeHandleState(PIPE_READMODE_MESSAGE=2)`. No
  TransactNamedPipe/CallNamedPipe — custom overlapped R/W.
- Framing: cereal `BinaryOutput/InputArchive` polymorphic
  `Ipc::Command` objects. Each request carries a command UID
  (broker logs show hex UIDs) and a `CheckApiVersion`
  (gameFolder, version `22.2.1.9340`, second param) precedes most calls.
- Custom error codes (signed 32-bit): `0x80EE2006` no-instance,
  `0x80EE0001` bad-IID, `0x80EE1007` null-arg, `0x80EE0003/4/5/0F`
  pipe-connect failures, `-2131886077` "Running WGC instance is not
  found" (matches game.log verbatim).

## 3. DLL interface (static RE, defended)

- Instance: `HRESULT WGCApiCreateInstance(iid, IWGCApi**)` with
  `iid = 0x1600020001247C` (game `0x1424BE281`: `movabs rcx,…`);
  `WGCApiCreateInstanceEx(iid, ver, ppv)`; flat `binding_*` exports
  avoid the vtable entirely:
  `binding_WGCApiCreateGlobalInstance(iid)` (RVA `0x4D050`),
  `binding_WGCApiPrepare`, `binding_WGCApiGetLoginInfo`,
  `binding_WGCApiGetRememberMeToken`, `binding_WGCApiStoreRememberMeToken`,
  `binding_WGCApiGenerateAuthToken`, `binding_WGCApiFreeGlobalInstance`.
- Object graph (`WGCApiImpl` ctor `sub_180055B40`): `[3]` = LoginSession,
  `[4]` = GameClient, `[5]` = PremiumSpectate (`0x88`), `[6]` =
  InGameStore (`0xA8`).
- `WGC::LoginSession` vftable `@0x18015A588` (set in `sub_180052DE0`):
  slot0 = GetLoginInfo impl (`0x180052E80`), slot4 = StoreRememberMe
  (`0x180053180`), slot5 = GetRememberMe (`0x180053400`), slot8 =
  GenerateAuthToken (`0x1800537A0`). Each acquires the IPC channel
  (`sub_180003E70`) then calls its worker (`sub_180050750`,
  `sub_18004EDB0`, `sub_18004F220`, `sub_18004FA60`).

## 4. OUT struct layouts (IDA `sub_180050190` / `sub_18004F220`)

`GetLoginInfo` takes ONE caller buffer (≥780 B, we pass 1024 zeroed);
all strings are inline WCHAR — no pointer chasing:
`+0 WCHAR[64]`, `+128 WCHAR[256]` (token-sized), `+640 WCHAR[64]`,
`+768 UINT64` (`wcstoui64` decimal = spa/account id), `+776 DWORD`.
`GetRememberMeToken` takes a ≥264 B struct (+0 token area, +256
UINT64 id) plus a `WCHAR[1024]` buffer (responses over 1024 words
fail). `StoreRememberMeToken` takes `WCHAR[128]` key + `WCHAR[1024]`
token. `wgcs/token.go` shape-scans ASCII + UTF-16LE runs.

## 5. Login IPC sequence (broker log, Steam session)

`CheckApiVersion` → `VerifyGameImported` → `VerifyLogin` →
`LoadSpaToken2(gameFolder)` → game logs in with the stored tail →
`SaveSpaToken2(gameFolder, spaId)` rotates the store, interleaved with
`GetLoginInfo` / `GetHardwareId` / `GetAuthenticationOption
(peripheryRoutingEnabled)`. Game side: `[WGC] Token2 Login Prepared`
then `connection_mgr.py:266 User authentication method: token2`.

## 6. Token lifecycle and auth methods

- Shape: 3 colon-separated decimal segments, 67–69 chars total
  (`{9-digit accountID}:{19-digit stable middle}:{37–39-digit
  rotating tail}` — tail length varies even within one family);
  middle is machine/session-bound, tail rotates per login,
  single-use-forward (re-presented tails → `Invalid token2` /
  `Token2 expires time`).
- Family survey (Sep-29, offline, values never reproduced): 26
  distinct token2s across captures = 4 middles on ONE account —
  the Sep-27 Steam machine (23 rotating tails, 1 middle), two
  distinct Sep-20 middles (launcher vs basic-era machines), and the
  older CE reference machine. Middle is per-machine, not per-account.
- Game token2-login shape (Sep-29 B 790/984B legs, MITM-decrypted
  offline, lengths/classes only): 12-key JSON (`account_complete[1]`,
  `account_id[9 digits]`, `allowed_peripheries[7]`, `auth_method[6]`
  = `token2`, `auth_realm[2]`, `gameId[3]`, `login[0]` (empty),
  `publication[1]`, `requested_for[3]`, `session[32 hex]` = wire
  session-md5, `token[8 digits]`, `token2[69, 3 segs]`); both legs
  same 9:19:39 token2 shape.
- Segment stats (9 samples, 4 families 4957/6943/4234/5220):
  accountID always 9 digits (stable per account); middle 18–19
  digits, tail always 39 digits here (doc range 37–39 stands);
  pooled digits uniform (no structure, no observed zero-pad).
  Middle 19 digits in 8/9 samples — mildly off uniform-u64
  (P≈0.02); treat as observation, not conclusion.
- Middle origin, DECIDED Oct-02 (4 live logins, `-middle-out` pairs,
  shapes only): middle is a deterministic function of the session
  blob — same blob re-logged mints the SAME middle (repeat-match),
  three distinct blobs mint three distinct 19-digit middles — but NOT
  a standard session-md5 transform (u64 lo/hi/xor/sum mod 10^19/10^18
  all 0/3). Server-side keyed function or nonstandard derivation;
  exact function needs the unseen blob bytes or server source.
- Broker auth steps (`src/auth/steps/`): Steam external auth, WG
  password/openid/oauth, `query_spa_token1`, captcha, PoW challenge
  solver, persona merge, `bind_steam_account`. Steam flow:
  `Steam::QuerySteamAuthTicket::runProcessing`
  (`query_steam_auth_ticket.cpp:109`) → ISteamUser (`SteamUser023`,
  via `SteamInternal_FindOrCreateUserInterface`) vtable **+112
  (slot 14)** with NULL → nonzero `HAuthTicket` → async callback →
  ticket to WG SSO → `SpaToken1` → internal TOKEN login → token2
  upgrade → seal + store. Ticket released via vtable **+136
  (slot 17)** with the handle (cancel-then-zero). Other interfaces
  used: `SteamUtils010`, `SteamFriends017`, `STEAMAPPS_INTERFACE_VERSION008`.
- Game-side persistence (`Manager.pyc`, shipped 2.4.0.1): tail saved
  to `prefs['token2']` IFF remember-me (`temporary =
  str(int(not rememberUser))`); WGC path instead calls
  `WGC.storeToken2(token2, databaseID)` after account-done.
  `initiateRelogin` sends exactly
  `{login,token2,session,temporary,auth_method}` (no
  publication/auth_realm).

## 7. On-disk store (`user_info.xml`, protocol v1.20)

- Path: `<PREFIX>/drive_c/users/steamuser/AppData/Roaming/Wargaming.net/GameCenter
  for Steam/user_info.xml`. Nodes: `hwid` (DPAPI envelope),
  `has_ever_been_logged_in`, `sessions active` → `session{realm,
  data (~6 KB SSO blob), stats, game_attr, instances[WOT_EU],
  games_data[player[game, data (452 chars)]]}`. Every blob shares one
  binary envelope (base64 head `d35d34d34d34…`), NOT a DPAPI header.
- Sealing: AES-ECB-256 via CNG (`crypto/crypto_utils.cpp`, wide
  `"AES"`, `"ChainingModeECB"`, 32-byte key, `"No key was provided"`
  null-check). Call chain: `Auth::QueryExternalAuthSPAToken1::
  onWgnTaskCompleted` (`sub_1802BDEF0`) → worker `sub_1802BC7C0`
  (validates SSO JSON: "response missing required fields") → encrypt
  (`sub_180D37110`, single caller) seals one SSO JSON response field
  with key = query-object field `+456` (a QString copied from the
  Steam-ticket object at `+104+8`, guarded by "invalid ticket" +
  expiry ticks in `sub_1802BD300`).
- A separate DPAPI user-scope wrapper exists (`CryptProtectData`
  flags=0 + verify-via-unprotect, `sub_180D65D30`, 3 callers) but its
  callers sit in IPC/pipe-auth context — NOT proven on the token path.
- Offline decryption verdict REVISED Sep-29: the user_info store
  blobs are Wine-DPAPI + hex (`01000000` + `WinCrypt` provider tag,
  `sub_180800450` seal → `QByteArray::toHex`), NOT AES — the AES-ECB
  path seals SSO material in transit. All six blobs share a 141B
  hex-text envelope prefix; session-`data` == `games_data`
  byte-identical (deterministic seal); no repeated 16B blocks.
  `wotdpapi` unwraps via Wine's own crypt32 in-prefix (key storage
  never matters). First live target: the 146B stats/game_attr blob.
  No cold-box token source changes (broker still mints).

## 8. Go tooling (`wgcs/`, `cmd/wotwgcs/`)

- `GOOS=windows` helper (stdlib `syscall` LazyDLL only): global
  instance → Prepare → `GetLoginInfo` (1024 B) → remember-me fallback
  → shape-scan → scrub → 0600 keyfile. HRESULTs/lengths/hashes only.
- Build: `GOOS=windows GOARCH=amd64 go build -o wotwgcs.exe
  ./cmd/wotwgcs` (both-GOOS `go vet` clean, offline tests green).
- Run: raw `wine` in the game prefix works (no `proton` wrapper
  needed): `WINEPREFIX=<PREFIX>/pfx WINEESYNC=1 WINEFSYNC=1 wine
  wotwgcs.exe -probe-only`. Needs `wgc.exe` up with valid SSO.
  Bare prefix has no `S:` drive (Steam sets it at game launch), so
  pass `-dll` as a `Z:` absolute path. Default `-dll` is the
  in-prefix `S:` path (valid only under Steam launch).
- Live findings Oct-02 (broker up, game NOT logged in): load ok,
  create ok, `Prepare` takes a 16B struct `{u64 0, u32 1}` (NOT an
  int — 0 and 1 both fault the callee; game `sub_1424BE7D0`
  passes the struct to instance slot1). Game prepare is TWO calls:
  slot1(struct) + slot12(`+0x60`, controller `+0x110` struct whose
  worker only stamps `[0]=2`); no flat binding wraps slot12, so the
  helper Ex-constructs (`WGCApiCreateInstanceEx`) and drives
  slot1/slot12/slot3/session-slot0 manually (`-step manual`,
  `CallSlot`). Result: slot1 ok, slot12 ok (`[0]=2` observed),
  slot3 ok (session present), session-slot0 → `0x80EE1003`.
  Same `0x80EE1003` on flat `GetLoginInfo` and
  `GetRememberMeToken`; `IsLaunchedFromWgc`/`GetPublication`
  → `0x80EE1007` (null-arg: they take an out-param).
  Leading read: `0x80EE1003` = no game login session (sub_180003E70
  `[+8]`-null gate) — broker SSO is valid (`spa_id` stable in
  today's broker log) but no `LoadSpaToken2` ran without the game.
  Decisive test: log the game in, re-run `-step manual` while the
  session is live.
- Chained-tail handover CLOSED Oct-02 (live, game in hangar):
  `wgc-token-mod` captured the live 9-key loginData (wire order
  `[session, token2, gameId, publication, allowed_peripheries,
  auth_realm, login, auth_method, account_complete]` — NO account_id/
  requested_for/token on this session; the 12-key MITM census is a
  different broker state), `wotlogin -broker-params` fired it
  verbatim (534/728B, 365B params, empty password) → `LOGGED_ON`
  `.212:32835` (fresh tail ACCEPTED, not Invalid) → stage-1 parked
  BYTE-IDENTICALLY to basic (36B seq1 + 250 ticks 02→fb, cumul=0, no
  52B/redirect, 1:1 turn-taking). Auth path falsified at maximum
  strength: genuine broker-minted verbatim token2 parks exactly like
  basic. (Round-2 tail rotated before firing — only the latest
  unchanged tail is live; firing consumed it, game self-heals via
  WGC refresh.) Second flavor fired same night: fresh 12-key
  loginData (wire order `[gameId, token2, token, ...]` — live
  hash-order, NOT alphabetical, so sorted would be wrong bytes)
  reproduced the genuine 790/984B legs exactly in size (434B params,
  3 RSA chunks) → `LOGGED_ON` `.213:32893` → same park (36B + 250
  ticks 02→fb, cumul=0). Both broker flavors park like basic.
- Standalone launcher option: `proton run` with
  `STEAM_COMPAT_DATA_PATH=<PREFIX>` on
  `C:\ProgramData\Wargaming.net\GameCenter for Steam\wgc.exe`; log
  in once, leave resident — probe window without the game. A
  WG-password SSO may mint a different token2 family than Steam SSO
  (different auth source); any live tail tests our stage-1 equally.
- Open: the live probe itself (layouts recovered statically, untested
  against the running broker). Chained-tail stage-1 test after that.
  Oct-02: probe ran (prepare struct closed, manual slot1+slot12+slot3
  ok) but session-slot0 → `0x80EE1003` with no game logged in —
  re-run `-step manual` during a live game session to decide whether
  1003 is just session-absence.
  Oct-02 disk-tail recovery (broker restarted, SSO healthy, game
  still not logged in): `user_info.xml` `games_data/player/data`
  unwraps via `wotdpapi` to an 80B blob carrying a 69-char
  token2-shaped run (the sealed remember-me tail — broker-free
  recovery path proven); `stats`/`game_attr` unwrap to 2B,
  `games_data/game` to 24B, neither token-shaped. Fired from-zero
  (`AUTH_METHOD=token2`, empty password, 325B params) with the
  established `SESSION`: login shape first-class, tail rejected
  `status=68 Invalid token2` — stale chain-head, expiry, or
  tail↔session binding (indistinguishable offline). Needs a FRESH
  tail (live game login → broker `LoadSpaToken2` or fresh
  remember-me write) for the stage-1 test.
  Oct-02 live-game verdict (game IN HANGAR, broker `LoadSpaToken2`
  + `SaveSpaToken2(spaId <redacted>)` in the log): out-of-process
  minting is CLOSED — flat `GetLoginInfo`, manual
  slot1+slot12+slot3+session-slot0, and `GetRememberMeToken` ALL
  still `0x80EE1003`. Broker sessions are per-instance/per-process:
  only the game's own in-process instance holds the live session.
  Fresh post-login disk tail fired too → same `Invalid token2`
  (sealed remember-me ≠ login tail, or already consumed at login).
  Remaining route: in-game mod (`ctypes` →
  `binding_WGCApiGetLoginInfo` on the game's already-prepared
  global, dump to file) — needs a game restart to load.
