# wot

Go client library + tools for World of Tanks EU internals:
LoginApp handshake and BaseApp entry (`login`), LoginApp ping
(`ping`), `.wotreplay` decoding (`replay`), and the entity-def
reader + login digest (`entdef`). Module
`github.com/LockBlock-dev/wot`, stdlib + `golang.org/x/crypto`
(Blowfish) + `golang.org/x/sys` (ptrace/transparent-socket syscalls
in `keydump`/`tproxy` only).

External dependencies are allowed when they carry their weight —
e.g. pulling in a parsing library instead of hand-rolling one — not
for what a few lines of stdlib already cover. Prefer the standard
library by default; justify anything beyond it.

## Tools

All CLIs are thin wrappers under `cmd/` (`-h` is authoritative):

| CLI | Purpose |
|---|---|
| `wotlogin` | Full login: RSA `LogOnParams`, Cuckoo PoW, session, optional `-baseapp` |
| `wotping` | LoginApp ping (Mercury ID 2, UDP 20016) |
| `wotproxy` | Transparent UDP log-and-forward proxy for the game client |
| `wotunpack` | Packed `.def`/`.xml` (magic `0x62a14e45`) → readable XML |
| `wotreplay` | `.wotreplay` summary (`-meta`, `-dump`) |
| `wotverify` | Structural genuineness check (exit 0/1) |
| `wotevents` | Battle timeline JSON (`-pretty`) |
| `wotflood` | Offline lobby analyzer (bundle inventory, chunk table, smalls census) |
| `wotkeydump` | Headless LogOnParams encryptionKey dumper (CE-free) |
| `wotwgcs` | Broker-mint CLI for WGC token2 (GOOS=windows, proton-run) |
| `wotdpapi` | Wine-DPAPI unwrap CLI (GOOS=windows, proton-run) |

## Run

```sh
gofmt -l . && go vet ./... && go test ./...   # gate: all clean/green
go run ./cmd/wotlogin -env live.env -baseapp  # live login + BaseApp
go run ./cmd/wotping login.p2.worldoftanks.eu
go run ./cmd/wotreplay file.wotreplay -meta
```

Secrets live only in `.env` files (see `.env.example`; `live.env`
is git-ignored). Tests are offline (only the PoW solver smoke test
touches the network path, skipped under `-short`).

## Docs

- `AGENTS.md` — layout, standards, and current status/blockades.
- `docs/NETWORK_PROTOCOL.md` — LoginApp/BaseApp wire truth.
- `docs/PRIVATE_SERVER.md` — private-server architecture and status.
- `docs/REPLAY.md` — replay container/crypto/playback (§6 before
  regenerating `replay/*_gen.go`).
- `docs/REPLAY_RENDER.md` + `docs/render_run_cmd.txt` — offline replay render.
- `docs/ENTITY_TYPE_IDS.md` — NRL entity/component type ids.
- `docs/WGC.md` — WGC token broker and the `wgcs` client.
- `docs/diagrams/` — login and ping sequence diagrams.

The docs cite captures, game installs, and entity-def trees from the
author's private analysis workspace (`../captures/`,
`../World_of_Tanks_EU/`, `../wotdefs-2.4.1/`, `../TODO.md`, …). Those files
are not part of this repository.

## Data and licensing

The code is licensed under AGPL-3.0 (see `LICENSE`; third-party parts in
`LICENSE-THIRD-PARTY`). The generated tables in `lobby/`
(`vehicle_data_gen.go`, `garage_gen.go`) and `wotserver.settings.json` are
derived from World of Tanks game data and are **not** covered by that
license — that data remains the property of Wargaming.net and is included
only for interoperability.
