#!/bin/sh
# Update this Sentinel from its git checkout: fast-forward to the commit cvENGINE named, pull and build the new images while the old Sentinel keeps
# working, then drain running tasks, swap the stack and report how it went.
#
#   scripts/update.sh            update when this Sentinel's self-update setting says so: Automatic always, Manual only when an administrator
#                                pressed Update now, Off never (the setting is chosen in cvENGINE, or CVENGINE_SENTINEL_UPDATE here, which is a ceiling: a local off or manual caps what cvENGINE can ask for).
#                                It moves to the commit cvENGINE named in the heartbeat (the target) and to no other: with no target it waits (reported once a day, not as a failure)
#   scripts/update.sh --now      update whatever the setting says (a person typing it here; still drains running tasks first). With no target from
#                                cvENGINE it moves to the head of origin/<branch> and prints that this is trusted only as far as the repository is
#   scripts/update.sh --to SHA   a person naming the commit (implies --now). It must be on origin/<branch>
#   scripts/update.sh --allow-non-descendant   with --now or --to: a person may move to a commit that is not a descendant of the running one (a rollback)
#   scripts/update.sh --check    only say whether an update is available and whether the setting wants it
#
# The target rules (scripts/update-target.sh): the commit must be in the history fetched from origin, reachable from origin/<branch> (a commit pushed
# to another branch is not an update) and a descendant of the commit running now (no downgrade, no sideways move; only --allow-non-descendant by hand
# lifts that one). After the checkout HEAD must equal the target before anything is built or restarted. Any refusal is reported to cvENGINE as a
# failed update, exits non-zero and leaves the running Sentinel unchanged. Commits are not signature-checked in 1.4.0 (README.md, "What Automatic trusts").
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
TO=""
ALLOW_MOVE=0
USAGE="usage: scripts/update.sh [--now|--check|--to COMMIT] [--allow-non-descendant]"
while [ $# -gt 0 ]; do
  case "$1" in
    --now) NOW=1 ;;
    --check) CHECK=1 ;;
    --to) [ $# -ge 2 ] || { echo "$USAGE" >&2; exit 2; }; TO=$2; NOW=1; shift ;;
    --allow-non-descendant) ALLOW_MOVE=1 ;;
    *) echo "$USAGE" >&2; exit 2 ;;
  esac
  shift
done
if [ "$ALLOW_MOVE" = 1 ] && [ "$NOW" = 0 ]; then
  echo "--allow-non-descendant is only for a person typing --now or --to by hand" >&2
  exit 2
fi

DRAIN_TIMEOUT="${CVENGINE_SENTINEL_DRAIN_TIMEOUT:-1800}"
case "$DRAIN_TIMEOUT" in
  ''|*[!0-9]*|0) echo "CVENGINE_SENTINEL_DRAIN_TIMEOUT must be a positive whole number of seconds (got '$DRAIN_TIMEOUT')" >&2; exit 2 ;;
esac
BRANCH="${CVENGINE_SENTINEL_BRANCH:-main}"
MARKER=.deployed-commit
say() { echo "$(date -u +%FT%TZ) update: $*"; }
# shellcheck source=scripts/update-target.sh
. ./scripts/update-target.sh
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
# Nothing is wrong on this machine, and nothing is done: the result is "waiting", told to cvENGINE once a day (a marker file), not by every hourly run.
wait_for_cvengine() {
  RESULT=waiting
  DETAIL="$1"
  say "$DETAIL"
  if [ -z "$(find .update-no-target -mmin -1440 2>/dev/null)" ]; then
    ctl report waiting --phase available --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
    : > .update-no-target 2>/dev/null || true
  fi
  exit 0
}
cannot() {
  DETAIL="cannot update: $1"
  say "$DETAIL"
  ctl report failed --phase preflight --detail "$DETAIL" --from "$CURRENT" --to "$TARGET" 2>/dev/null || true
  exit 1
}

git fetch --quiet origin "$BRANCH" || cannot "git fetch from origin failed"
ON=$(git symbolic-ref --short -q HEAD || true)
[ "$ON" = "$BRANCH" ] || cannot "the checkout is on '${ON:-a detached HEAD}', not $BRANCH (git checkout $BRANCH)"
# What is on the branch now. This is only what is AVAILABLE: the commit this run may move to is decided below (the server's named target).
TARGET_FULL=$(git rev-parse "origin/$BRANCH")
TARGET=$(git rev-parse --short=12 "origin/$BRANCH")
AVAILABLE_FULL=$TARGET_FULL
# The commit cvENGINE named in its last heartbeat answer (the daemon writes it to the status file; an older image has no such field, which reads as none).
SERVER_TARGET=$(ctl status 2>/dev/null | sed -n 's/.*"target": "\([0-9a-f]\{7,40\}\)".*/\1/p' | head -n 1)

# An install from before the marker existed counts as deployed at HEAD once the running Sentinel reports HEAD as its version.
if [ ! -f "$MARKER" ] && ctl status 2>/dev/null | grep -q "\"version\": \"$CURRENT\""; then
  git rev-parse HEAD > "$MARKER"
fi
DEPLOYED=$(cat "$MARKER" 2>/dev/null || true)
DEPLOYED_SHORT=$(printf '%s' "$DEPLOYED" | cut -c1-12)
if [ -z "$TO" ] && [ "$DEPLOYED" = "$TARGET_FULL" ]; then
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

# Which commit this run moves to, and why that is allowed. Nothing has been changed yet: a refusal leaves the running Sentinel as it is.
if [ -n "$TO" ]; then
  REQUESTED=$TO
  WHY="you named it with --to"
elif [ -n "$SERVER_TARGET" ]; then
  REQUESTED=$SERVER_TARGET
  WHY="cvENGINE named it as this Sentinel's target"
elif [ "$NOW" = 1 ]; then
  REQUESTED=$AVAILABLE_FULL
  WHY="cvENGINE named no target, so this is the head of origin/$BRANCH, which you asked for with --now; it is trusted only as far as the repository is (commits are not signature-checked)"
else
  # Nothing is wrong on this machine: an Automatic or requested update moves only to the commit cvENGINE names, and cvENGINE has named none (for now). That is waiting,
  # not a failure, and it is told to cvENGINE once a day (a marker file), not by every hourly run.
  wait_for_cvengine "waiting: the server named no target for this Sentinel, so it stays on $CURRENT (an update moves only to the commit cvENGINE names, never to whatever is on origin/$BRANCH; a person can run scripts/update.sh --now)"
  exit 0
fi
TARGET=$(printf '%s' "$REQUESTED" | cut -c1-12)
RUNNING_FULL=$(git rev-parse --verify --quiet "${DEPLOYED:-HEAD}^{commit}" 2>/dev/null || git rev-parse HEAD)
# A commit cvENGINE named that is older than what runs here (a server that pins an older build than this Sentinel, or a Sentinel that went ahead of its server) is no update
# and no failure: nothing moves, and it is said once a day like a missing target. A named commit that is not an ancestor of what runs is still refused below.
if [ -z "$TO" ] && [ "$NOW" != 1 ]; then
  OLDER=$(git rev-parse --verify --quiet "$REQUESTED^{commit}" 2>/dev/null || true)
  if [ -n "$OLDER" ] && [ "$OLDER" != "$RUNNING_FULL" ] && git merge-base --is-ancestor "$OLDER" "$RUNNING_FULL" 2>/dev/null; then
    wait_for_cvengine "waiting: the commit cvENGINE named ($TARGET) is older than the one this Sentinel runs ($CURRENT), so there is nothing to update to"
  fi
fi
check_update_target "$REQUESTED" "$BRANCH" "$ALLOW_MOVE" "$RUNNING_FULL" "$(git rev-parse HEAD)" || cannot "$REFUSAL"
TARGET=$(git rev-parse --short=12 "$TARGET_FULL")
if [ "$DEPLOYED" = "$TARGET_FULL" ] && [ "$(git rev-parse HEAD)" = "$TARGET_FULL" ]; then
  RESULT=ok
  DETAIL="up to date at $TARGET (the commit cvENGINE named)"
  say "$DETAIL"
  exit 0
fi
say "moving to $TARGET: $WHY"

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
  if git merge-base --is-ancestor "$PREV" "$TARGET_FULL"; then
    git merge --ff-only --quiet "$TARGET_FULL" || fail "this checkout cannot fast-forward to $TARGET" code
  else
    git reset --hard --quiet "$TARGET_FULL" || rollback "this checkout cannot move to $TARGET" code  # only --allow-non-descendant gets here
  fi
fi
# The checkout must be exactly the commit that was approved before anything is built or restarted from it.
[ "$(git rev-parse HEAD)" = "$TARGET_FULL" ] || rollback "after the checkout HEAD is not the target $TARGET, so nothing was built or restarted" code
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
DRAINED=1  # recorded before the flag is set: a signal landing between the two must still undrain (undrain is harmless when nothing was set)
ctl drain || fail "could not ask the Sentinel to stop taking tasks" drain
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
