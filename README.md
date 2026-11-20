# wot

World of Tanks EU internals, reverse-engineered and reimplemented in Go.

## What it covers

- LoginApp handshake and BaseApp entry (`login`)
- LoginApp ping (`ping`)
- `.wotreplay` decoding (`replay`)
- Entity-def reader and login digest (`entdef`)
- Lobby application layer (`lobby`)
- Private-server half (`server`, the server side of `login`, `cmd/wotserver`)
- XMPP (`xmpp` builders, `xmppserver` live service)
- Live key recovery and transparent proxying (`keydump`, `tproxy`)

## Requirements

- Go 1.27.1 or newer
- No cgo
- `golang.org/x/crypto` for Blowfish
- `golang.org/x/sys` for ptrace and transparent-socket syscalls in
  `keydump` and `tproxy`
- `modernc.org/sqlite` for the pure-Go account and player-state store
  behind `server.Store`

Prefer the standard library. Add a dependency only when it carries its
weight, for example a parsing library instead of a hand-rolled one.

## Client versions

- Private-server target: World of Tanks EU `2.4.1.1 (#993)`, from the
  Steam install.
- Protocol reference: EU `2.4.0.0 (#944)` captures. The wire shapes carry
  over to 2.4.1 unchanged; the entity defs do not.
- Entity defs: the `2.4.1.0` tree, extracted from that build's
  `res/packages/scripts.pkg`. `Vehicle.def` is byte-identical in 2.4.1.0
  and 2.4.1.1.
- Login digest truths: 2.4.0 `5df886f75e73b33cff9d87fb9c69389c`; 2.4.1
  `c0cc08a2f494f7087112009ce1d002db`.
- Replay fixtures: 2.4.0 (Prohorovka), 2.3.1 (Mines), 2.1.1 (Glacier),
  and a 2.0 decrypt.
- Generated tables: `lobby/vehicle_data_gen.go` from 2.4.0.0 item defs;
  `lobby/garage_gen.go` from 2.4.1.1 item defs; `wotserver.settings.json`
  from 2.4.1.1 client bytecode.

## Status

- Working: LoginApp, BaseApp stages 1 and 2, lobby, hangar, and the
  matchmaking queue.
- Incomplete: battle and cell simulation.
- Details: `docs/PRIVATE_SERVER.md` and `AGENTS.md`.

## Tools

All user-facing CLIs are thin wrappers under `cmd/`. `-h` is
authoritative.

### Client and protocol

- `wotlogin`: full login with RSA `LogOnParams`, Cuckoo PoW, session, and
  optional BaseApp
- `wotping`: LoginApp ping (Mercury ID 2, UDP 20016)
- `wotproxy`: transparent UDP log-and-forward proxy and BaseApp MITM relay
- `wotflood`: offline lobby analyzer with bundle inventory, chunk table,
  and smalls census
- `wotbundle`: author and inspect lobby bundles
- `wotcapwalk`: walk a wotproxy capture's bulk stream element by element
- `wotdefs`: print client method ids and the client-server property table
  in wire order
- `wotdigest`: offline LoginApp entity-defs digest for one client version
- `wotwalkdump`: record the live entity-defs digest walk from a running
  client
- `wotkeydump`: recover the live LogOnParams Blowfish key without Cheat
  Engine
- `wotunpack`: convert packed `.def` and `.xml` files (magic
  `0x62a14e45`) to readable XML

### Replay

- `wotreplay`: `.wotreplay` summary (`-meta`, `-dump`)
- `wotverify`: structural replay genuineness check (exit 0 or 1)
- `wotevents`: battle timeline JSON (`-pretty`)
- `wotbattlefeed`: replay a wotproxy battle dump as a SHOT/HIT/KILL feed

### Private server

- `wotserver`: LoginApp, BaseApp stages 1 and 2, and optional XMPP
- `wotaccounts`: operator CLI for the private server's account store

### Code generation

- `wotgendata`: generate `lobby/vehicle_data_gen.go` from an unpacked
  item defs tree
- `wotgarage`: generate `lobby/garage_gen.go` from an unpacked item defs
  tree

### External helpers

- `wotwgcs`: mint WGC token2 through the local broker (GOOS=windows,
  Proton)
- `wotdpapi`: unwrap a Wine-DPAPI hex blob (GOOS=windows, Proton)
- `wotxmpp`: live XMPP endpoint client (TCP or BOSH, optional SASL PLAIN)

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
- `docs/NETWORK_PROTOCOL.md`: LoginApp and BaseApp wire truth.
- `docs/PRIVATE_SERVER.md`: private-server architecture and status.
- `docs/REPLAY.md`: replay container, crypto, and playback (read section
  6 before regenerating `replay/*_gen.go`).
- `docs/REPLAY_RENDER.md` and `docs/render_run_cmd.txt`: offline replay
  render.
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
  Used as a cross-check for `entdef`'s digest and type model, the wire
  codecs, and `wotunpack`.
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
