#!/bin/sh
# Install a timer that runs scripts/update.sh every hour on this host, so a Sentinel follows cvENGINE's update mode with nothing done by hand:
# Automatic means it updates itself (after draining running tasks), Manual means it waits until an administrator presses Update now. A second,
# daily timer runs scripts/refresh-feeds.sh so the OpenVAS feeds stay fresh between code updates.
# Uses systemd when there is one, else a cron.d entry (and removes the other one). Linux only. It writes to /etc, so it needs root: run it as
# root, or as a user who can sudo (it asks).
#   scripts/install-updater.sh [--remove] [--allow-root]
#     --allow-root   install even though root owns this checkout, so the updater runs as root (refused otherwise)
set -eu
PREFIX="${CVENGINE_SENTINEL_INSTALL_PREFIX:-}"  # only for tests: where /etc, /run and /var/log are
UNITS="$PREFIX/etc/systemd/system"
CRON="$PREFIX/etc/cron.d/cvengine-sentinel-update"
LOG="$PREFIX/var/log/cvengine-sentinel-update.log"

REMOVE=0
ALLOW_ROOT=0
for arg in "$@"; do
  case "$arg" in
    --remove) REMOVE=1 ;;
    --allow-root) ALLOW_ROOT=1 ;;
    *) echo "usage: scripts/install-updater.sh [--remove] [--allow-root]" >&2; exit 2 ;;
  esac
done

[ "$(uname -s)" = Linux ] || { echo "the updater installs only on Linux (it uses GNU stat, systemd or cron.d); update this Sentinel by hand with scripts/update.sh" >&2; exit 1; }
DIR=$(cd "$(dirname "$0")/.." && pwd)
# The path goes into a systemd unit and a cron line: keep it to characters neither can misread.
case "$DIR" in
  *[!A-Za-z0-9/._-]*) echo "the checkout path '$DIR' has characters the timer cannot use safely; move it to a path of letters, digits and / . _ - only" >&2; exit 1 ;;
esac
# The updater runs as whoever owns this checkout, not as root: git refuses a checkout owned by another user ("dubious ownership"), and update.sh
# works in this checkout. That user needs Docker access (the docker group).
OWNER=$(stat -c %U "$DIR" 2>/dev/null || echo UNKNOWN)
if [ "$OWNER" = UNKNOWN ]; then
  echo "cannot tell which user owns $DIR, so the updater has no one to run as; refusing" >&2
  exit 1
fi
if [ "$OWNER" = root ] && [ "$ALLOW_ROOT" = 0 ] && [ "$REMOVE" = 0 ]; then
  echo "root owns $DIR, so the updater would run as root every hour. Give the checkout to the user who runs docker (chown -R USER $DIR)," >&2
  echo "or pass --allow-root to run it as root anyway" >&2
  exit 1
fi
if [ "$OWNER" != root ] && ! id -nG "$OWNER" | tr ' ' '\n' | grep -qx docker; then
  echo "warning: $OWNER owns this checkout but is not in the docker group, so the updater cannot run docker as $OWNER; run: usermod -aG docker $OWNER" >&2
fi
if [ "$(id -u)" != 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "run this as root (it writes to /etc), or install sudo" >&2; exit 1; }
  exec sudo "$0" "$@"
fi

remove_systemd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now cvengine-sentinel-update.timer cvengine-sentinel-feeds.timer 2>/dev/null || true
  fi
  rm -f "$UNITS/cvengine-sentinel-update.service" "$UNITS/cvengine-sentinel-update.timer" \
    "$UNITS/cvengine-sentinel-feeds.service" "$UNITS/cvengine-sentinel-feeds.timer"
  if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload 2>/dev/null || true; fi
}

# Set or delete one KEY=value line of the checkout's .env without changing its owner or mode (cat into the file instead of replacing it).
env_marker() { # env_marker set|unset
  envfile="$DIR/.env"
  [ -f "$envfile" ] || { [ "$1" = set ] || return 0; : > "$envfile"; chown "$OWNER" "$envfile" 2>/dev/null || true; chmod 600 "$envfile"; }
  tmp=$(mktemp) || return 0
  grep -v '^CVENGINE_SENTINEL_UPDATER=' "$envfile" > "$tmp" || true
  if [ "$1" = set ]; then
    [ -z "$(tail -c1 "$tmp")" ] || echo >> "$tmp"
    echo "CVENGINE_SENTINEL_UPDATER=installed" >> "$tmp"
  fi
  cat "$tmp" > "$envfile"
  rm -f "$tmp"
}

if [ "$REMOVE" = 1 ]; then
  remove_systemd
  env_marker unset
  rm -f "$CRON"
  (cd "$DIR" && docker compose exec -T sentinel python3 -m client.control updater-removed) >/dev/null 2>&1 || true  # so cvENGINE shows "not installed"
  echo "removed"
  exit 0
fi

# Hardening that leaves docker working: the docker socket is under /run, which ProtectSystem=full does not touch.
unit() { # unit NAME DESCRIPTION SCRIPT TIMEOUT
  cat > "$UNITS/$1.service" <<UNIT
[Unit]
Description=$2
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=$DIR
User=$OWNER
ExecStart="$DIR/scripts/$3"
TimeoutStartSec=$4
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
UNIT
}

if command -v systemctl >/dev/null 2>&1 && [ -d "$PREFIX/run/systemd/system" ]; then
  rm -f "$CRON"
  unit cvengine-sentinel-update "Update the cvENGINE Sentinel when cvENGINE says to" update.sh 3h
  cat > "$UNITS/cvengine-sentinel-update.timer" <<UNIT
[Unit]
Description=Check hourly whether the cvENGINE Sentinel should update

[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
UNIT
  unit cvengine-sentinel-feeds "Refresh the cvENGINE Sentinel's OpenVAS feeds" refresh-feeds.sh 1h
  cat > "$UNITS/cvengine-sentinel-feeds.timer" <<UNIT
[Unit]
Description=Refresh the cvENGINE Sentinel's OpenVAS feeds daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now cvengine-sentinel-update.timer cvengine-sentinel-feeds.timer
  echo "installed: systemd timers cvengine-sentinel-update.timer (hourly) and cvengine-sentinel-feeds.timer (daily); logs: journalctl -u cvengine-sentinel-update -u cvengine-sentinel-feeds"
else
  remove_systemd
  # cron runs the jobs as the owner, who could not create a file in /var/log: create the log for them.
  touch "$LOG"
  chown "$OWNER" "$LOG"
  chmod 640 "$LOG"
  {
    echo "17 * * * * $OWNER cd \"$DIR\" && ./scripts/update.sh >> \"$LOG\" 2>&1"
    echo "43 4 * * * $OWNER cd \"$DIR\" && ./scripts/refresh-feeds.sh >> \"$LOG\" 2>&1"
  } > "$CRON"
  echo "installed: $CRON (update hourly, feeds daily); log: $LOG"
fi
# Tell the Sentinel an updater now exists, so cvENGINE shows it as installed straight away rather than after the first run an hour from now:
# through .env (read when the container is created, so it works before the stack has ever been up) and, when it is up, through the control CLI.
env_marker set
# Best effort: when the stack is not up yet, the first run of the updater says it.
(cd "$DIR" && docker compose exec -T sentinel python3 -m client.control updater-installed --interval 3600) >/dev/null 2>&1 || true
