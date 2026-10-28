#!/bin/sh
# Update this Sentinel from its git checkout: drain running tasks, fast-forward to origin/main, pull and rebuild the stack, report how it went.
#
#   scripts/update.sh            update when cvENGINE says so (its update mode is Automatic, or an administrator pressed Update now)
#   scripts/update.sh --now      update whatever cvENGINE says (still drains running tasks first)
#   scripts/update.sh --check    only say whether an update is available and whether cvENGINE wants it
#
# Run it by hand, from cron, or from the systemd timer scripts/install-updater.sh sets up. It runs on the Docker host and needs no access to the
# Docker socket from any container: it talks to the daemon through `docker compose exec sentinel python3 -m client.control` (see client/control.py).
# It never changes anything while cvENGINE's update mode is Manual and nobody asked for this Sentinel to update.
set -eu
cd "$(dirname "$0")/.."

NOW=0
CHECK=0
for arg in "$@"; do
  case "$arg" in
    --now) NOW=1 ;;
    --check) CHECK=1 ;;
    *) echo "usage: scripts/update.sh [--now|--check]" >&2; exit 2 ;;
  esac
done

DRAIN_TIMEOUT="${CVENGINE_SENTINEL_DRAIN_TIMEOUT:-1800}"
BRANCH="${CVENGINE_SENTINEL_BRANCH:-main}"
say() { echo "$(date -u +%FT%TZ) update: $*"; }
ctl() { docker compose exec -T sentinel python3 -m client.control "$@"; }

[ -d .git ] || { say "this is not a git checkout, so there is nothing to update from"; exit 1; }
command -v docker >/dev/null 2>&1 || { say "docker is not installed or not on PATH"; exit 1; }

# One update at a time (a timer firing while a long drain is still waiting).
exec 9>.update.lock
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { say "another update is running"; exit 0; }
fi

git fetch --quiet origin "$BRANCH"
CURRENT=$(git rev-parse --short=12 HEAD)
TARGET=$(git rev-parse --short=12 "origin/$BRANCH")
if [ "$CURRENT" = "$TARGET" ]; then
  say "up to date at $CURRENT"
  exit 0
fi
say "an update is available: $CURRENT -> $TARGET"

WANTED=no
if [ "$NOW" = 1 ]; then
  WANTED=yes
else
  WANTED=$(ctl wanted 2>/dev/null || echo no)
fi
[ "$CHECK" = 1 ] && { say "cvENGINE wants it updated now: $WANTED"; exit 0; }
if [ "$WANTED" != yes ]; then
  ctl report waiting --phase available --detail "update $TARGET is available; waiting for Automatic updates or an administrator" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  say "not updating: cvENGINE's update mode is Manual and nobody asked for this Sentinel to update"
  exit 0
fi

fail() {
  say "FAILED: $1"
  ctl undrain 2>/dev/null || true
  ctl report failed --phase "$2" --detail "$1" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  exit 1
}

ctl report draining --phase drain --detail "waiting for running tasks to finish" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
ctl drain || fail "could not ask the Sentinel to stop taking tasks" drain
ctl wait-idle --timeout "$DRAIN_TIMEOUT" || fail "running tasks did not finish within ${DRAIN_TIMEOUT}s" drain

ctl report updating --phase code --detail "fast-forwarding to $TARGET" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
git merge --ff-only --quiet "origin/$BRANCH" || fail "this checkout has local changes or commits, so it cannot fast-forward to origin/$BRANCH" code

# The version the rebuilt image reports (client/config.py version()), kept in .env so a plain `docker compose up -d` later reports it too.
touch .env
if grep -q '^CVENGINE_SENTINEL_VERSION=' .env; then
  sed -i "s/^CVENGINE_SENTINEL_VERSION=.*/CVENGINE_SENTINEL_VERSION=$TARGET/" .env
else
  echo "CVENGINE_SENTINEL_VERSION=$TARGET" >> .env
fi

ctl report updating --phase images --detail "pulling images" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
(docker compose pull --quiet --ignore-buildable || docker compose pull --quiet) || fail "docker compose pull failed" images
ctl report updating --phase build --detail "rebuilding and restarting the stack" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
docker compose up -d --build || fail "docker compose up failed" build

# The recreated Sentinel starts undrained and writes its status within a minute; wait for it before saying it worked.
i=0
until docker compose exec -T sentinel python3 -m client.control status 2>/dev/null | grep -q "\"version\": \"$TARGET\""; do
  i=$((i + 1))
  [ "$i" -gt 60 ] && fail "the updated Sentinel did not report version $TARGET within 5 minutes" start
  sleep 5
done
ctl report 'done' --phase finished --detail "running $TARGET" --from "$CURRENT" --to "$TARGET"
say "updated $CURRENT -> $TARGET"
