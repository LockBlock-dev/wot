#!/usr/bin/env bash
#
# Build and (re)start the private server detached, on the exact arguments the
# in-battle testing loop uses.
#
#   ./restart-server.sh                 # build, stop any running instance, start
#   BUILD=0 ./restart-server.sh         # restart the existing binary, no rebuild
#   ./restart-server.sh --stop          # stop it and exit
#
# This is the detached counterpart of ./start-server.sh, which runs `go run` in
# the foreground with the matchmaker at its default team size. The differences
# are deliberate and are what the battle work needs:
#
#   -garage-all            every ownable vehicle in the garage, so any tank can
#                          be picked without a lobby round-trip first
#   -battle-team-size 0    ONE queued player is enough to form a battle; the
#                          client still starts in the hangar and clicking
#                          Battle! forms the arena on its own
#
# The binary is built to ./wotserver (git-ignored) and started with setsid, so
# it survives the shell that launched it. Output goes to $LOG; the script waits
# for the LoginApp port to answer before returning.
#
# Env overrides: BIN, LOG, ADDR, S1, S2, DB, DEFS, SETTINGS, XMPP,
#                BATTLE_TEAM_SIZE, USER_NAME, USER_PASS, TOKEN_ACCOUNT,
#                GARAGE_ALL, BUILD, EXTRA
set -euo pipefail

cd "$(dirname "$0")"
ROOT=..

BIN="${BIN:-$PWD/wotserver}"
LOG="${LOG:-/tmp/wotserver.log}"

ADDR="${ADDR:-127.0.0.1:20016}"
# Stage-1 is what the LOGGED_ON record advertises; stage-2 is the [44] redirect
# target. Both must sit in the manager window 32810-32999 or the client's own
# parseRedirectAt guard skips them.
S1="${S1:-127.0.0.1:32850}"
S2="${S2:-127.0.0.1:32851}"
# The second BaseApp: a leave's re-entry is redirected here, because the client
# keeps a packet receiver per address and the battle's watermark would reject a
# fresh login's sequence numbers on the same one.
S3="${S3:-127.0.0.1:32852}"
DB="${DB:-$ROOT/wotserver.db}"
# The entity defs MUST be the build the client runs: the property tables are
# what the client decodes entity data against, and a type that changed between
# builds silently shifts every field after it.
DEFS="${DEFS:-$ROOT/scripts-2.4.1/entity_defs}"
# The client's own packages, so the synthetic roster only uses tanks it can
# actually draw. A vehicle whose model is not shipped (the event and story-mode
# variants the garage table still lists) makes the client fail to build the
# appearance and then crash with an access violation.
PKGS="${PKGS:-$HOME/.local/share/Steam/steamapps/common/World of Tanks/eu/res/packages}"
SETTINGS="${SETTINGS:-$ROOT/wot/wotserver.settings.json}"
# The client dials the (host, port) pairs in the settings document's
# `xmpp_connections`, so this must be the same address.
XMPP="${XMPP-127.0.0.1:5222}"
PRIVKEY="$ROOT/mitm/loginapp_mitm.privkey"

die() { printf 'restart-server: %s\n' "$*" >&2; exit 1; }

# The pids of every process whose argv[0] is exactly $BIN. Matching the whole
# command line would also hit this script and any editor holding the path open,
# so compare the first argument only.
running_pids() {
	ps -eo pid=,args= | awk -v b="$BIN" '$2 == b { print $1 }'
}

stop_running() {
	local pids pid
	pids="$(running_pids)"
	[ -n "$pids" ] || return 0
	for pid in $pids; do
		printf 'restart-server: stopping pid %s\n' "$pid"
		kill "$pid" 2>/dev/null || true
	done
	# Give it a moment to release the sockets, then insist.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[ -z "$(running_pids)" ] && return 0
		sleep 0.2
	done
	for pid in $(running_pids); do
		printf 'restart-server: pid %s ignored SIGTERM, killing\n' "$pid"
		kill -9 "$pid" 2>/dev/null || true
	done
	sleep 0.2
}

if [ "${1:-}" = "--stop" ]; then
	stop_running
	printf 'restart-server: stopped\n'
	exit 0
fi

[ -e "$PRIVKEY" ] || die "missing $PRIVKEY"
[ -d "$DEFS" ] || die "missing defs directory $DEFS (set DEFS=...)"
[ -e "$SETTINGS" ] || die "missing settings document $SETTINGS (set SETTINGS=...)"
PKGS_FLAG=
[ -d "$PKGS" ] && PKGS_FLAG="-pkgs $PKGS"

if [ "${BUILD:-1}" != "0" ]; then
	printf 'restart-server: building %s\n' "$BIN"
	go build -o "$BIN" ./cmd/wotserver || die "build failed"
fi
[ -x "$BIN" ] || die "no binary at $BIN (run without BUILD=0)"

stop_running

printf 'restart-server: LoginApp %s, stage-1 %s, stage-2 %s, stage-3 %s\n' "$ADDR" "$S1" "$S2" "$S3"
printf 'restart-server: log %s\n' "$LOG"

# GARAGE_ALL defaults to on; 0 disables it. Build the flag as a variable:
# `${GARAGE_ALL-1:+-garage-all}` parses as parameter GARAGE_ALL with the
# default word `1:+-garage-all`, so an unset GARAGE_ALL emitted the literal
# positional argument `1:+-garage-all`. Go's flag parser stops at the first
# non-flag argument, so every flag after it — including -battle-team-size —
# was silently ignored and the matchmaker stayed at its 15v15 default.
GARAGE_ALL_FLAG=-garage-all
[ "${GARAGE_ALL:-1}" = 0 ] && GARAGE_ALL_FLAG=

# setsid + nohup so the server outlives this shell; stdin from /dev/null so it
# never blocks on a terminal that goes away.
setsid nohup "$BIN" \
	-addr "$ADDR" \
	-privkey "$PRIVKEY" \
	-s1 "$S1" -s2 "$S2" -s3 "$S3" \
	-defs "$DEFS" \
	${PKGS_FLAG:+-pkgs "$PKGS"} \
	-settings "$SETTINGS" \
	-xmpp "$XMPP" \
	-db "$DB" \
	-user "${USER_NAME:-admin@wot.test}" -pass "${USER_PASS:-admin}" \
	-token-account "${TOKEN_ACCOUNT-admin@wot.test}" \
	${GARAGE_ALL_FLAG} \
	-battle-team-size "${BATTLE_TEAM_SIZE:-0}" \
	${EXTRA:-} \
	>"$LOG" 2>&1 </dev/null &

# Wait for the LoginApp socket rather than a fixed sleep: the defs load and the
# garage seed take a moment, and a client that connects early gets refused.
port="${ADDR##*:}"
for _ in $(seq 1 100); do
	if ss -lun 2>/dev/null | grep -q ":$port "; then
		printf 'restart-server: up on %s (pid %s)\n' "$ADDR" "$(running_pids | tr '\n' ' ')"
		exit 0
	fi
	sleep 0.1
done
die "did not come up on $ADDR — see $LOG"
