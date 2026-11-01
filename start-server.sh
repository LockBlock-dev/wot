#!/usr/bin/env bash
#
# Start the private server for a client test.
#
#   ./start-server.sh                    # 127.0.0.1:20016 — the mod's CUSTOM entry
#   ./start-server.sh 0.0.0.0:20016      # listen on every interface
#   ADDR=192.168.1.10:20016 ./start-server.sh
#
# Nothing here points at an official server. The LOGGED_ON record and the
# [44] redirect both carry this host's own stage-1/stage-2, and the 1a/79
# lobby offer — the one small that carries a real server address — is cut
# from the carrier (see docs/PRIVATE_SERVER.md).
#
# The client must be pointed here: install mods/custom-server-mod (it adds a
# "CUSTOM" entry at 127.0.0.1:20016) and pick that server in game.
#
# A client on ANOTHER machine needs the advertised endpoints to be this
# host's real IP, not loopback — an unspecified bind host advertises
# 127.0.0.1 by design (the ip4 record holds literals, never 0.0.0.0):
#
#   S1=192.168.1.10:32850 S2=192.168.1.10:32851 \
#     ./start-server.sh 192.168.1.10:20016
#
# A Steam client authenticates with a token2 and sends no username, so
# those logins land on TOKEN_ACCOUNT (default: the default account) with
# no password check. Set TOKEN_ACCOUNT= to refuse them instead.
#
# Env overrides: ADDR, S1, S2, DB, DEFS, FLOOD, FLOODFLOW, FLOODKEY,
#                POST, POSTKEY, USER_NAME, USER_PASS, TOKEN_ACCOUNT, EXTRA
set -euo pipefail

cd "$(dirname "$0")"
ROOT=..

ADDR="${1:-${ADDR:-127.0.0.1:20016}}"
# Stage-1 is what the LOGGED_ON record advertises; stage-2 is the [44]
# redirect target. Both must sit in the manager window 32810-32999 or our
# own client's parseRedirectAt guard skips them.
S1="${S1:-127.0.0.1:32850}"
S2="${S2:-127.0.0.1:32851}"
DB="${DB:-$ROOT/wotserver.db}"
DEFS="${DEFS:-$ROOT/World_of_Tanks_EU/2.4.0.0/res/scripts/entity_defs}"

# The bulk carrier: the only capture whose flood carries both the static
# config and the account document.
# The live capture (a real login relayed through wotproxy) is the only
# one whose bundle chain is complete: [1,203] plus its [203,203] tail.
# The older captures lose the tail fragment, and the client then walks a
# short bundle and asserts (BundleDataPos::advance: Ran out of packets).
if [ -s "$ROOT/captures/live-flood.hex" ] && [ -s "$ROOT/captures/key-live.txt" ]; then
	FLOOD="${FLOOD:-$ROOT/captures/live-flood.hex}"
	FLOODFLOW="${FLOODFLOW:-52901->}"
	FLOODKEY="${FLOODKEY:-$ROOT/captures/key-live.txt}"
else
	FLOOD="${FLOOD:-$ROOT/captures/proxy-20261014-1752.hex}"
	FLOODFLOW="${FLOODFLOW:-35493->}"
	FLOODKEY="${FLOODKEY:-$ROOT/captures/key-1752.txt}"
fi
# The post-flood chain and the pre-flood smalls: the only capture with the
# 332B terminator, the rev answer, the poll answer and the seed tick.
POST="${POST:-$ROOT/captures/flows3-s2.txt}"
POSTKEY="${POSTKEY:-$ROOT/captures/key3.txt}"

PRIVKEY="$ROOT/mitm/loginapp_mitm.privkey"
PUBKEY="$ROOT/World_of_Tanks_EU/2.4.0.0/res/loginapp_wot.pubkey"

die() { printf 'start-server: %s\n' "$*" >&2; exit 1; }

for f in "$PRIVKEY" "$PUBKEY" "$FLOOD" "$POST" "$POSTKEY"; do
	[ -e "$f" ] || die "missing $f"
done
[ -d "$DEFS" ] || die "missing defs directory $DEFS (set DEFS=...)"

# The bulk carrier's block key is not in the repo: recover it from the
# capture's own login once and cache it.
if [ ! -s "$FLOODKEY" ]; then
	printf 'start-server: recovering the carrier key from %s (once)\n' "$(basename "$FLOOD")"
	go run ./cmd/wotflood \
		-dump "$FLOOD" -flow "$FLOODFLOW" -recover-key -keyfile "$FLOODKEY" \
		-mitm-privkey "$PRIVKEY" -mitm-pubkey "$PUBKEY" \
		|| die "key recovery failed"
fi

printf 'start-server: LoginApp %s, stage-1 %s, stage-2 %s\n' "$ADDR" "$S1" "$S2"
printf 'start-server: point the client at %s (mods/custom-server-mod)\n' "$ADDR"

exec go run ./cmd/wotserver \
	-addr "$ADDR" \
	-privkey "$PRIVKEY" \
	-s1 "$S1" -s2 "$S2" \
	-flood "$FLOOD" -floodflow "$FLOODFLOW" -floodkey "$FLOODKEY" \
	-post "$POST" -postkey "$POSTKEY" \
	-defs "$DEFS" \
	-db "$DB" \
	-user "${USER_NAME:-admin@wot.test}" -pass "${USER_PASS:-admin}" \
	-token-account "${TOKEN_ACCOUNT-${USER_NAME:-admin@wot.test}}" \
	${EXTRA:-}
