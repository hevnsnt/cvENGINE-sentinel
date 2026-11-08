#!/bin/sh
# The supervisor for a Sentinel that leaves on purpose to be updated (CVENGINE_SENTINEL_UPDATE_EXIT=1 in .env, client/selfupdate.py).
#
#   scripts/pull-on-exit.sh            run in the checkout, under systemd, cron @reboot or `nohup`; it never exits by itself
#
# cvENGINE asks a Sentinel to update when the newest published build is ahead of the one it runs. The Sentinel then takes no new work, finishes the
# tasks it has, and exits with code 76. Compose's `restart: unless-stopped` starts it again at once, on the same image: this script is what brings the
# newest one first. On exit code 76 (and only that code) it fast-forwards the checkout, pulls the images and rebuilds, then recreates the container.
# Any other exit code is left to the restart policy. A checkout with local changes, or a build that fails, is reported and left running as it was; the
# Sentinel does not ask to leave again for the same build for six hours, so a broken update is never a restart loop.
#
# This is the second way to update. The hourly host updater (scripts/install-updater.sh, scripts/update.sh) already acts on cvENGINE's request, so a
# Sentinel with the updater installed does not need this script. A Sentinel whose image comes from a registry (and not from this checkout) can use any
# supervisor that pulls the image when the container stops, in place of this script.
set -u
cd "$(dirname "$0")/.." || exit 1
service=${CVENGINE_SENTINEL_SERVICE:-sentinel}
UPDATE_EXIT=76
log() { printf '%s pull-on-exit: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

while :; do
  id=$(docker compose ps -q "$service" 2>/dev/null | head -n 1)
  if [ -z "$id" ]; then
    sleep 10
    continue
  fi
  code=$(docker wait "$id" 2>/dev/null) || { sleep 10; continue; }
  [ "$code" = "$UPDATE_EXIT" ] || { sleep 2; continue; }
  log "the Sentinel drained and left to be updated (exit code $UPDATE_EXIT)"
  if git pull --ff-only -q && docker compose pull --ignore-buildable -q && docker compose build -q && docker compose up -d; then
    log "the newest build is running"
  else
    log "the update did not complete; the Sentinel keeps running what it had (check git status and docker compose build)"
    docker compose up -d >/dev/null 2>&1 || true
  fi
done
