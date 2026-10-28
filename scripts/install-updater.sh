#!/bin/sh
# Install a timer that runs scripts/update.sh every hour on this host, so a Sentinel follows cvENGINE's update mode with nothing done by hand:
# Automatic means it updates itself (after draining running tasks), Manual means it waits until an administrator presses Update now.
# Uses systemd when there is one, else a cron.d entry. It writes to /etc, so it needs root: run it as root, or as a user who can sudo (it asks).
#   scripts/install-updater.sh [--remove]
set -eu
DIR=$(cd "$(dirname "$0")/.." && pwd)
# The updater runs as whoever owns this checkout, not as root: git refuses a checkout owned by another user ("dubious ownership"), and update.sh
# writes .env and .update.lock here. That user needs Docker access (the docker group). A checkout owned by root is updated as root.
OWNER=$(stat -c %U "$DIR" 2>/dev/null || echo root)
if [ "$OWNER" != root ] && ! id -nG "$OWNER" | tr ' ' '\n' | grep -qx docker; then
  echo "warning: $OWNER owns this checkout but is not in the docker group, so the updater cannot run docker as $OWNER; run: usermod -aG docker $OWNER" >&2
fi
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "run this as root (it writes to /etc), or install sudo" >&2; exit 1; }
  exec sudo "$0" "$@"
fi

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now cvengine-sentinel-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/cvengine-sentinel-update.service /etc/systemd/system/cvengine-sentinel-update.timer /etc/cron.d/cvengine-sentinel-update
  systemctl daemon-reload 2>/dev/null || true
  (cd "$DIR" && docker compose exec -T sentinel python3 -m client.control updater-removed) >/dev/null 2>&1 || true  # so cvENGINE shows "not installed"
  echo "removed"
  exit 0
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  cat > /etc/systemd/system/cvengine-sentinel-update.service <<UNIT
[Unit]
Description=Update the cvENGINE Sentinel when cvENGINE says to
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=$DIR
User=$OWNER
ExecStart=$DIR/scripts/update.sh
UNIT
  cat > /etc/systemd/system/cvengine-sentinel-update.timer <<UNIT
[Unit]
Description=Check hourly whether the cvENGINE Sentinel should update

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now cvengine-sentinel-update.timer
  echo "installed: systemd timer cvengine-sentinel-update.timer (hourly); logs: journalctl -u cvengine-sentinel-update"
else
  echo "17 * * * * $OWNER cd $DIR && ./scripts/update.sh >> /var/log/cvengine-sentinel-update.log 2>&1" > /etc/cron.d/cvengine-sentinel-update
  echo "installed: /etc/cron.d/cvengine-sentinel-update (hourly); log: /var/log/cvengine-sentinel-update.log"
fi
# Tell the Sentinel an updater now exists, so cvENGINE shows it as installed straight away rather than after the first run an hour from now.
# Best effort: when the stack is not up yet, the first run of the updater says it.
(cd "$DIR" && docker compose exec -T sentinel python3 -m client.control updater-installed --interval 3600) >/dev/null 2>&1 || true
