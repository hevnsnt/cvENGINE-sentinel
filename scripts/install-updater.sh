#!/bin/sh
# Install a timer that runs scripts/update.sh every hour on this host, so a Sentinel follows cvENGINE's update mode with nothing done by hand:
# Automatic means it updates itself (after draining running tasks), Manual means it waits until an administrator presses Update now.
# Uses systemd when there is one, else a cron.d entry. Run as root: scripts/install-updater.sh [--remove]
set -eu
DIR=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run this as root (it writes to /etc)" >&2; exit 1; }

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now cvengine-sentinel-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/cvengine-sentinel-update.service /etc/systemd/system/cvengine-sentinel-update.timer /etc/cron.d/cvengine-sentinel-update
  systemctl daemon-reload 2>/dev/null || true
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
  echo "17 * * * * root cd $DIR && ./scripts/update.sh >> /var/log/cvengine-sentinel-update.log 2>&1" > /etc/cron.d/cvengine-sentinel-update
  echo "installed: /etc/cron.d/cvengine-sentinel-update (hourly); log: /var/log/cvengine-sentinel-update.log"
fi
