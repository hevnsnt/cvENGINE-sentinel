#!/bin/sh
# Update this Sentinel from its git checkout: fast-forward to origin/main, pull and build the new images while the old Sentinel keeps working, then
# drain running tasks, swap the stack and report how it went.
#
#   scripts/update.sh            update when this Sentinel's self-update setting says so: Automatic always, Manual only when an administrator
#                                pressed Update now, Off never (the setting is chosen in cvENGINE, or CVENGINE_SENTINEL_UPDATE here, which is a ceiling: a local off or manual caps what cvENGINE can ask for)
#   scripts/update.sh --now      update whatever the setting says (a person typing it here; still drains running tasks first)
#   scripts/update.sh --check    only say whether an update is available and whether the setting wants it
#
# Run it by hand, from cron, or from the systemd timer scripts/install-updater.sh sets up, always as the user who owns this checkout (a root run
# re-runs itself as that user). It runs on the Docker host and needs no access to the Docker socket from any container: it talks to the daemon
# through `docker compose exec sentinel python3 -m client.control` (see client/control.py). It never changes anything while the setting is Off, or
# Manual and nobody asked for this Sentinel to update. Every run records how it went in the state volume (client/control.py record_updater),
# which the Sentinel reports to cvENGINE, so a missing or stuck updater is visible there.
#
# What is deployed is the commit in .deployed-commit (git-ignored), written only once the new Sentinel reports that commit as its version. A run
# that failed after the fast-forward therefore leaves the marker behind HEAD, and the next run builds and swaps again instead of saying
# "up to date". A failed pull or build puts the checkout back where it was, and nothing is drained until the new image is built.
set -eu
SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
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
case "$DRAIN_TIMEOUT" in
  ''|*[!0-9]*|0) echo "CVENGINE_SENTINEL_DRAIN_TIMEOUT must be a positive whole number of seconds (got '$DRAIN_TIMEOUT')" >&2; exit 2 ;;
esac
BRANCH="${CVENGINE_SENTINEL_BRANCH:-main}"
MARKER=.deployed-commit
say() { echo "$(date -u +%FT%TZ) update: $*"; }
ctl() { docker compose exec -T sentinel python3 -m client.control "$@"; }

[ -e .git ] || { say "this is not a git checkout, so there is nothing to update from"; exit 1; }

# Only the checkout's owner may run this: git refuses another user's checkout, and a root run once left a root-owned lock that broke every later
# timer run. root is handed over to the owner; anyone else is refused.
OWNER=$(stat -c %U . 2>/dev/null) || { say "cannot tell who owns $(pwd); refusing to run"; exit 1; }
if [ "$(id -un)" != "$OWNER" ]; then
  if [ "$(id -u)" = 0 ] && command -v sudo >/dev/null 2>&1; then
    exec sudo -u "$OWNER" -- env CVENGINE_SENTINEL_DRAIN_TIMEOUT="$DRAIN_TIMEOUT" CVENGINE_SENTINEL_BRANCH="$BRANCH" sh "$SELF" "$@"
  fi
  say "this checkout belongs to $OWNER; run the updater as $OWNER (or as root, which hands over to $OWNER), not as $(id -un)"
  exit 1
fi

# One update at a time, and the lock comes first so a second run changes nothing, not even the last result. The lock is the checkout directory
# itself: no lock file to be created by the wrong user or swapped for a symlink. Without flock there is no mutual exclusion, so refuse.
command -v flock >/dev/null 2>&1 || { say "flock is not installed (util-linux), so two runs could overlap; refusing to run"; exit 1; }
exec 9<.
flock -n 9 || { say "another update is running"; exit 0; }

command -v docker >/dev/null 2>&1 || { say "docker is not installed or not on PATH"; exit 1; }

# Say how this run went, whichever way it ends (cvENGINE shows the last run and result, and notices when the runs stop), and never leave the
# Sentinel drained. dash runs the EXIT trap only on a normal exit, so a signal is turned into one.
RESULT=failed
DETAIL="the update script stopped before it finished"
DRAINED=0
finish() {
  if [ "$DRAINED" = 1 ]; then ctl undrain 2>/dev/null || true; fi
  ctl updater-run "$RESULT" --detail "$DETAIL" 2>/dev/null || true
}
trap finish EXIT
trap 'exit 1' INT TERM HUP

SETTING=$(ctl setting 2>/dev/null || echo unknown)
if [ "$SETTING" = off ] && [ "$NOW" = 0 ]; then
  RESULT=off
  DETAIL="self-update is Off for this Sentinel"
  say "self-update is Off for this Sentinel (set it to Manual or Automatic in cvENGINE); nothing to do"
  exit 0
fi

CURRENT=$(git rev-parse --short=12 HEAD)
TARGET=""
cannot() {
  DETAIL="cannot update: $1"
  say "$DETAIL"
  ctl report failed --phase preflight --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  exit 1
}

git fetch --quiet origin "$BRANCH" || cannot "git fetch from origin failed"
ON=$(git symbolic-ref --short -q HEAD || true)
[ "$ON" = "$BRANCH" ] || cannot "the checkout is on '${ON:-a detached HEAD}', not $BRANCH (git checkout $BRANCH)"
TARGET_FULL=$(git rev-parse "origin/$BRANCH")
TARGET=$(git rev-parse --short=12 "origin/$BRANCH")

# An install from before the marker existed counts as deployed at HEAD once the running Sentinel reports HEAD as its version.
if [ ! -f "$MARKER" ] && ctl status 2>/dev/null | grep -q "\"version\": \"$CURRENT\""; then
  git rev-parse HEAD > "$MARKER"
fi
DEPLOYED=$(cat "$MARKER" 2>/dev/null || true)
DEPLOYED_SHORT=$(printf '%s' "$DEPLOYED" | cut -c1-12)
if [ "$DEPLOYED" = "$TARGET_FULL" ]; then
  RESULT=ok
  DETAIL="up to date at $TARGET"
  say "up to date at $TARGET"
  exit 0
fi
CURRENT=${DEPLOYED_SHORT:-$CURRENT}
say "an update is available: $CURRENT -> $TARGET"

# Untracked and ignored files (.env, docker-compose.override.yml) do not count: only tracked changes would block the fast-forward.
[ -z "$(git status --porcelain --untracked-files=no)" ] || cannot "this checkout has local changes to tracked files (git status), so it cannot fast-forward"
git merge-base --is-ancestor HEAD "origin/$BRANCH" || cannot "this checkout has local commits that are not on origin/$BRANCH, so it cannot fast-forward"

WANTED=no
if [ "$NOW" = 1 ]; then
  WANTED=yes
else
  WANTED=$(ctl wanted 2>/dev/null || echo no)
fi
[ "$CHECK" = 1 ] && { RESULT=ok; DETAIL="update $TARGET is available; wanted now: $WANTED"; say "self-update is $SETTING; wanted now: $WANTED"; exit 0; }
if [ "$WANTED" != yes ]; then
  RESULT=waiting
  DETAIL="update $TARGET is available; waiting for Automatic updates or an administrator"
  ctl report waiting --phase available --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  say "not updating: self-update is $SETTING and nobody asked for this Sentinel to update"
  exit 0
fi

fail() {
  DETAIL="$1"
  say "FAILED: $1"
  if [ "$DRAINED" = 1 ]; then ctl undrain 2>/dev/null || true; DRAINED=0; fi
  ctl report failed --phase "$2" --detail "$1" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  exit 1
}
# Before anything is drained: a failed pull or build puts the checkout back on the commit it had, so the next run starts from a clean slate.
PREV=$(git rev-parse HEAD)
rollback() {
  git reset --hard --quiet "$PREV" || true
  fail "$@"
}

if [ "$PREV" != "$TARGET_FULL" ]; then
  ctl report updating --phase code --detail "fast-forwarding to $TARGET" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  git merge --ff-only --quiet "origin/$BRANCH" || fail "this checkout cannot fast-forward to origin/$BRANCH" code
fi
ctl report updating --phase images --detail "pulling images" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
docker compose pull --quiet --ignore-buildable || rollback "docker compose pull failed" images
ctl report updating --phase build --detail "building the new Sentinel image" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
docker compose build || rollback "docker compose build failed" build

# The image stamps its own commit (Dockerfile, VERSION); an old CVENGINE_SENTINEL_VERSION line in .env would report a stale version instead.
if [ -f .env ] && grep -q '^CVENGINE_SENTINEL_VERSION=' .env; then
  sed -i '/^CVENGINE_SENTINEL_VERSION=/d' .env
fi

# An OpenVAS scan runs for hours: draining for it would only stop the Sentinel taking other work until the deadline. Leave it running, keep the
# built image, and try again at the next run (the status file lists the kinds of the tasks running).
if ctl status 2>/dev/null | grep -q '"in_flight_kinds": \[[^]]*"openvas"'; then
  RESULT=waiting
  DETAIL="update $TARGET is built; an OpenVAS scan is running, will retry"
  ctl report waiting --phase drain --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  say "$DETAIL"
  exit 0
fi

# Only now stop taking tasks. An OpenVAS scan can run for hours: when tasks are still running at the deadline the Sentinel goes back to work and
# the next run tries again with the image already built. That is waiting, not a failure.
ctl report draining --phase drain --detail "waiting for running tasks to finish" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
ctl drain || fail "could not ask the Sentinel to stop taking tasks" drain
DRAINED=1
rc=0
ctl wait-idle --timeout "$DRAIN_TIMEOUT" || rc=$?
if [ "$rc" = 2 ]; then
  fail "client.control refused the wait-idle arguments (a bug in scripts/update.sh, not a reason to retry)" drain
elif [ "$rc" != 0 ]; then
  ctl undrain 2>/dev/null || true
  DRAINED=0
  RESULT=waiting
  DETAIL="update $TARGET is built; a task is still running, will retry"
  ctl report waiting --phase drain --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  say "$DETAIL"
  exit 0
fi

ctl report updating --phase restart --detail "restarting the stack on $TARGET" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
docker compose up -d || fail "docker compose up failed" restart

# The recreated Sentinel starts undrained and writes its status within a minute; its version is the commit stamped into the new image.
i=0
until docker compose exec -T sentinel python3 -m client.control status 2>/dev/null | grep -q "\"version\": \"$TARGET\""; do
  i=$((i + 1))
  [ "$i" -gt 60 ] && fail "the updated Sentinel did not report version $TARGET within 5 minutes" start
  sleep 5
done
DRAINED=0
printf '%s\n' "$TARGET_FULL" > "$MARKER.tmp" && mv "$MARKER.tmp" "$MARKER"
ctl report 'done' --phase finished --detail "running $TARGET" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
RESULT=updated
DETAIL="updated $CURRENT -> $TARGET"
say "updated $CURRENT -> $TARGET"
