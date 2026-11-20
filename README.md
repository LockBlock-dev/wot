# wot

Go toolkit for World of Tanks EU internals: the LoginApp handshake and
BaseApp entry (`login`), LoginApp ping (`ping`), `.wotreplay` decoding
(`replay`), the entity-def reader and login digest (`entdef`), and the
private-server half (`server`, the server side of `login`, and
`cmd/wotserver`). Module `github.com/LockBlock-dev/wot`. Requires Go
1.27.1 or newer and no cgo.

Dependencies are deliberately small: `golang.org/x/crypto` (Blowfish),
`golang.org/x/sys` (ptrace and transparent-socket syscalls in
`keydump`/`tproxy`), and `modernc.org/sqlite` (the pure-Go account and
player-state store behind `server.Store`). External dependencies are
allowed when they carry their weight, for example a parsing library
instead of a hand-rolled one, but not for what a few lines of stdlib
already cover.

## Status

The client-side login path and the lobby-oriented private-server half are
the working surface: LoginApp, BaseApp stages 1 and 2, lobby, hangar, and
the matchmaking queue. Battle and cell simulation is incomplete. See
`docs/PRIVATE_SERVER.md` and `AGENTS.md` for the current details.

## Tools

All user-facing CLIs are thin wrappers under `cmd/` (`-h` is
authoritative):

| CLI | Purpose |
|---|---|
| `wotlogin` | Full login: RSA `LogOnParams`, Cuckoo PoW, session, optional BaseApp |
| `wotping` | LoginApp ping (Mercury ID 2, UDP 20016) |
| `wotproxy` | Transparent UDP log-and-forward proxy; BaseApp MITM relay |
| `wotflood` | Offline lobby analyzer: bundle inventory, chunk table, smalls census |
| `wotbundle` | Author and inspect lobby bundles |
| `wotcapwalk` | Walk a wotproxy capture's bulk stream element by element |
| `wotdefs` | Print client method ids and the client-server property table in wire order |
| `wotdigest` | Offline LoginApp entity-defs digest for one client version |
| `wotwalkdump` | Record the live entity-defs digest walk from a running client |
| `wotkeydump` | Recover the live LogOnParams Blowfish key without Cheat Engine |
| `wotunpack` | Packed `.def`/`.xml` (magic `0x62a14e45`) to readable XML |
| `wotreplay` | `.wotreplay` summary (`-meta`, `-dump`) |
| `wotverify` | Structural replay genuineness check (exit 0/1) |
| `wotevents` | Battle timeline JSON (`-pretty`) |
| `wotbattlefeed` | Replay a wotproxy battle dump as a SHOT/HIT/KILL feed |
| `wotserver` | Private server: LoginApp, BaseApp stages 1 and 2, XMPP |
| `wotaccounts` | Operator CLI for the private server's account store |
| `wotwgcs` | Mint WGC token2 through the local broker (GOOS=windows, Proton) |
| `wotdpapi` | Unwrap a Wine-DPAPI hex blob (GOOS=windows, Proton) |
| `wotxmpp` | Live XMPP endpoint client (TCP or BOSH, optional SASL PLAIN) |
| `wotgendata` | Generate `lobby/vehicle_data_gen.go` from an unpacked item_defs tree |
| `wotgarage` | Generate `lobby/garage_gen.go` from an unpacked item_defs tree |

`cmd/zzprobe` is a scratch reproduction probe and is not part of the
supported CLI surface.

## Build and run

```sh
go build ./cmd/...
test -z "$(gofmt -l .)" && go vet ./... && go test ./...
go run ./cmd/wotlogin -env live.env -baseapp  # live login + BaseApp
go run ./cmd/wotping login.p2.worldoftanks.eu
go run ./cmd/wotreplay file.wotreplay -meta
```

Secrets live only in `.env` files (see `.env.example`; `live.env` is
git-ignored). Tests are offline; the solver smoke test is skipped with
`-short`.

The private-server half (`wotserver`) additionally needs an RSA key
pair, the game's entity and item defs, and a stage-2 carrier. See
`docs/PRIVATE_SERVER.md` for the required material and the supported
configuration.

## Docs

- `AGENTS.md`: layout, standards, and current status.
- `docs/NETWORK_PROTOCOL.md`: LoginApp/BaseApp wire truth.
- `docs/PRIVATE_SERVER.md`: private-server architecture and status.
- `docs/REPLAY.md`: replay container, crypto, and playback (§6 before
  regenerating `replay/*_gen.go`).
- `docs/REPLAY_RENDER.md` and `docs/render_run_cmd.txt`: offline replay render.
- `docs/ENTITY_TYPE_IDS.md`: NRL entity and component type ids.
- `docs/WGC.md`: WGC token broker and the `wgcs` client.
- `docs/diagrams/`: login and ping sequence diagrams.

The docs cite captures, game installs, and entity-def trees from the
author's private analysis workspace (`../captures/`,
`../World_of_Tanks_EU/`, `../wotdefs-2.4.1/`, `../TODO.md`, etc.).
Those files are not part of this repository.

## Credits

- [theorzr/wg-toolkit-rs](https://github.com/theorzr/wg-toolkit-rs): an
  independent Rust implementation of the BigWorld/Core codecs (packed XML,
  package/VFS, entity defs, bundle/channel) and server-side LoginApp/BaseApp.
  Used as a cross-check for `entdef`'s digest/type model, the wire codecs,
  and `wotunpack`.
- [StranikS-Scan/WorldOfTanks-Decompiled](https://github.com/StranikS-Scan/WorldOfTanks-Decompiled):
  third-party decompiled World of Tanks client snapshots, used as a
  reading index for client-side logic. These are not the shipped build, so
  wire facts are confirmed against the actual `.pyc` files and binary.

## Data and licensing

The code is licensed under AGPL-3.0 (see `LICENSE`; third-party parts in
`LICENSE-THIRD-PARTY`, including the MIT-licensed Cuckoo miner). The
generated tables in `lobby/` (`vehicle_data_gen.go`, `garage_gen.go`) and
`wotserver.settings.json` are derived from World of Tanks game data and
are **not** covered by that license. That data remains the property of
Wargaming.net and is included only for interoperability.

World of Tanks is a trademark of Wargaming.net. This project is not
affiliated with or endorsed by Wargaming.net.
