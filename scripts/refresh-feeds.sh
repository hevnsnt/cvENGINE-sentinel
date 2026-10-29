#!/bin/sh
# Refresh the OpenVAS feed data (vulnerability tests, notus, SCAP, CERT, data objects, report formats, GPG keys). Each feed container copies its
# image's data into a volume only when it is created, and update.sh pulls images only when a new commit arrives, so without this job the feeds
# would age for as long as the code does not change. scripts/install-updater.sh runs it daily as the checkout's owner.
#
# It does nothing (and says nothing) unless the stack runs with the openvas profile and the Sentinel holds no task, and never while update.sh runs.
set -eu
cd "$(dirname "$0")/.."

FEEDS="openvas-vulnerability-tests openvas-notus-data openvas-scap-data openvas-cert-bund-data openvas-dfn-cert-data openvas-data-objects openvas-report-formats openvas-gpg-data"
say() { echo "$(date -u +%FT%TZ) refresh-feeds: $*"; }

OWNER=$(stat -c %U . 2>/dev/null) || { say "cannot tell who owns $(pwd); refusing to run"; exit 1; }
[ "$(id -un)" = "$OWNER" ] || { say "this checkout belongs to $OWNER; run this as $OWNER, not as $(id -un)"; exit 1; }
command -v flock >/dev/null 2>&1 || { say "flock is not installed (util-linux); refusing to run"; exit 1; }
exec 9<.
flock -n 9 || exit 0  # update.sh holds the same lock, and it pulls everything itself
command -v docker >/dev/null 2>&1 || { say "docker is not installed or not on PATH"; exit 1; }

docker compose ps --status running --services 2>/dev/null | grep -qx openvas-gvmd || exit 0
docker compose exec -T sentinel python3 -m client.control status 2>/dev/null | grep -q '"in_flight": 0' || exit 0

# shellcheck disable=SC2086 # FEEDS is a fixed list of service names
docker compose pull --quiet $FEEDS
# shellcheck disable=SC2086
docker compose up -d --no-deps $FEEDS
say "feed images pulled; any feed whose image changed was recreated and copies its new data"
