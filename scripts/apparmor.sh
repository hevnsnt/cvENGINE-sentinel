#!/bin/sh
# Screenshots on a host whose AppArmor refuses the user namespace Chromium's sandbox needs (README.md, "Screenshots and AppArmor").
#
# Docker runs every container under its `docker-default` AppArmor profile. With AppArmor 4 (Ubuntu 24.04 and later, recent Debian and Kali) that
# profile refuses `userns_create`, so the screenshot browser dies at launch and the Sentinel stops declaring web_screenshot. The Ubuntu kernels say so
# with kernel.apparmor_restrict_unprivileged_userns=1; other kernels refuse it with no such setting (a Kali 7.1 kernel without the sysctl logged
# apparmor="DENIED" operation="userns_create" profile="docker-default"), so the test here is AppArmor enabled with a parser of version 4 or newer.
# config/apparmor/cvengine-sentinel is docker-default plus `userns,` and nothing else.
#
#   sudo scripts/apparmor.sh install   load the profile, keep it loaded across reboots, and run the Sentinel under it (CVENGINE_SENTINEL_APPARMOR in
#                                      .env); then `docker compose up -d` as the checkout's owner. Does nothing on a host that does not need it.
#   scripts/apparmor.sh status         say what this host needs and what is in place (changes nothing, needs no root)
#   sudo scripts/apparmor.sh remove    stop using the profile: the Sentinel goes back to Docker's default profile at its next `docker compose up -d`
#   cvengine-sentinel-apparmor boot    what the boot unit runs (a root-owned copy of this file, see below)
#
# What install leaves on the host, all owned by root: the profile in /etc/apparmor.d/cvengine-sentinel (AppArmor's own boot service loads that
# directory), a copy of this script in /usr/local/sbin/cvengine-sentinel-apparmor, and cvengine-sentinel-apparmor.service, a oneshot that loads the
# profile again before docker.service starts. Root never runs or parses a file the checkout's owner can change: the copies are taken at install
# time, so a profile changed by an update is loaded when install runs again (scripts/update.sh says when that is due).
#
# When the profile cannot be loaded at boot, the boot unit takes CVENGINE_SENTINEL_APPARMOR out of .env, so the Sentinel starts under Docker's
# default profile without screenshots instead of not starting at all (Docker refuses to start a container whose profile is not loaded).
# Sourced with CVENGINE_APPARMOR_LIB_ONLY=1 by scripts/update.sh for the detection functions only.
set -eu

AA_PREFIX="${CVENGINE_SENTINEL_INSTALL_PREFIX:-}"  # only for tests: where /sys, /proc, /etc and /usr/local are
AA_PROFILE=cvengine-sentinel
AA_UNIT=cvengine-sentinel-apparmor.service
AA_ETC_PROFILE="$AA_PREFIX/etc/apparmor.d/$AA_PROFILE"
AA_HELPER="$AA_PREFIX/usr/local/sbin/cvengine-sentinel-apparmor"
AA_UNITS="$AA_PREFIX/etc/systemd/system"
AA_ENV_KEY=CVENGINE_SENTINEL_APPARMOR

aa_parser() { # the apparmor_parser binary, or nothing. sbin is not on every user's PATH; a test's PATH stub wins and the real one is not looked for.
  command -v apparmor_parser 2>/dev/null && return 0
  [ -n "$AA_PREFIX" ] && return 0
  for p in /usr/sbin/apparmor_parser /sbin/apparmor_parser; do
    if [ -x "$p" ]; then echo "$p"; return 0; fi
  done
}

aa_enabled() { [ "$(cat "$AA_PREFIX/sys/module/apparmor/parameters/enabled" 2>/dev/null)" = Y ]; }

aa_parser_major() { # 4 for "AppArmor parser version 4.1.8"; 0 when there is no parser or it says no version
  _p=$(aa_parser)
  [ -n "$_p" ] || { echo 0; return 0; }
  _v=$("$_p" --version 2>/dev/null | sed -n '1s/.*[Vv]ersion \([0-9][0-9]*\)\..*/\1/p')
  echo "${_v:-0}"
}

aa_userns_sysctl() { cat "$AA_PREFIX/proc/sys/kernel/apparmor_restrict_unprivileged_userns" 2>/dev/null || true; } # 1, 0, or nothing (no such setting)

aa_needed() { # true when Docker's default profile can refuse the browser's user namespace on this host
  aa_enabled || return 1
  [ "$(aa_parser_major)" -ge 4 ] 2>/dev/null
}

aa_why() { # one line on what this host is, for the operator
  if ! aa_enabled; then echo "AppArmor is not enabled on this host, so Docker's AppArmor profile blocks nothing"; return 0; fi
  _m=$(aa_parser_major)
  if [ "$_m" -lt 4 ] 2>/dev/null; then
    echo "AppArmor is enabled with parser version ${_m} (below 4), which does not restrict user namespaces"; return 0
  fi
  case "$(aa_userns_sysctl)" in
    1) echo "AppArmor $_m restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1), so Docker's default profile refuses Chromium's sandbox" ;;
    *) echo "AppArmor $_m is enabled, and Docker's default profile can refuse the user namespace Chromium's sandbox needs" ;;
  esac
}

aa_loaded() { # 0 loaded, 1 not loaded, 2 cannot tell (the policy directory is not readable here)
  _d="$AA_PREFIX/sys/kernel/security/apparmor/policy/profiles"
  [ -d "$_d" ] && [ -r "$_d" ] && [ -x "$_d" ] || return 2
  for _e in "$_d"/*; do
    case "${_e##*/}" in "$AA_PROFILE".[0-9]*) return 0 ;; esac
  done
  return 1
}

aa_env_value() { # aa_env_value ENVFILE: the CVENGINE_SENTINEL_APPARMOR value in .env, or nothing
  [ -r "$1" ] || return 0
  sed -n "s/^$AA_ENV_KEY=//p" "$1" | tail -n 1 | tr -d "\"' \r"
}

aa_env_write() { # aa_env_write ENVFILE OWNER [VALUE]: set or (no VALUE) delete the line in place, so .env keeps its owner and mode
  _f=$1; _o=$2; _val=${3:-}
  if [ ! -f "$_f" ]; then
    [ -n "$_val" ] || return 0
    : > "$_f"; chown "$_o" "$_f" 2>/dev/null || true; chmod 600 "$_f"
  fi
  _t=$(mktemp) || return 1
  grep -v "^$AA_ENV_KEY=" "$_f" > "$_t" || true
  if [ -n "$_val" ]; then
    [ -z "$(tail -c1 "$_t")" ] || echo >> "$_t"
    echo "$AA_ENV_KEY=$_val" >> "$_t"
  fi
  cat "$_t" > "$_f"
  rm -f "$_t"
}

# shellcheck disable=SC2034 # AA_NOTE is read by scripts/update.sh, which sources this file
aa_update_note() { # aa_update_note ENVFILE PROFILEFILE: for scripts/update.sh. Sets AA_NOTE (what to say, empty when all is well) and exports the fallback.
  AA_NOTE=""
  _set=$(aa_env_value "$1")
  if [ "$_set" = "$AA_PROFILE" ]; then
    _rc=0; aa_loaded || _rc=$?
    if [ "$_rc" = 1 ]; then
      # Docker would refuse to start the Sentinel at all: run it under Docker's default profile for this run, without screenshots.
      CVENGINE_SENTINEL_APPARMOR=docker-default
      export CVENGINE_SENTINEL_APPARMOR
      AA_NOTE="the AppArmor profile $AA_PROFILE is not loaded, so the Sentinel starts under Docker's default profile and takes no screenshots until root runs: sudo scripts/apparmor.sh install"
    elif [ -r "$AA_ETC_PROFILE" ] && [ -r "$2" ] && ! cmp -s "$AA_ETC_PROFILE" "$2"; then
      AA_NOTE="config/apparmor/$AA_PROFILE changed in this update; the host keeps loading its previous copy until root runs: sudo scripts/apparmor.sh install"
    fi
  elif [ -z "$_set" ] && aa_needed; then
    AA_NOTE="screenshots stay off on this host until root runs once: sudo scripts/apparmor.sh install ($(aa_why); README.md, \"Screenshots and AppArmor\")"
  fi
  return 0
}

if [ "${CVENGINE_APPARMOR_LIB_ONLY:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

# --- the commands ---

say() { printf '%s\n' "apparmor: $*"; }
die() { printf '%s\n' "apparmor: $*" >&2; exit 1; }

CMD=${1:-status}
[ $# -gt 0 ] && shift
DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) [ $# -ge 2 ] || die "--dir needs a value"; DIR=$2; shift 2 ;;
    *) die "usage: scripts/apparmor.sh install|status|remove|boot [--dir CHECKOUT]" ;;
  esac
done
# The checkout: given (the boot unit names it), else the one this file sits in. The root-owned copy has no checkout around it.
if [ -z "$DIR" ]; then
  case "$0" in */scripts/apparmor.sh|scripts/apparmor.sh) DIR=$(cd "$(dirname "$0")/.." && pwd) ;; esac
fi
case "$DIR" in
  *[!A-Za-z0-9/._-]*) die "the checkout path '$DIR' has characters a systemd unit cannot hold safely; use letters, digits and / . _ - only" ;;
esac
ENVFILE="$DIR/.env"
SOURCE="$DIR/config/apparmor/$AA_PROFILE"

need_root() {
  [ "$(id -u)" = 0 ] && return 0
  command -v sudo >/dev/null 2>&1 || die "this needs root (it loads a kernel profile and writes to /etc); run it with sudo"
  exec sudo sh "$0" "$CMD" --dir "$DIR"
}

owner() { stat -c %U "$DIR" 2>/dev/null || echo root; }

status() {
  say "$(aa_why)"
  if aa_needed; then say "needed: yes"; else say "needed: no"; fi
  _rc=0; aa_loaded || _rc=$?
  case "$_rc" in 0) say "profile $AA_PROFILE: loaded" ;; 1) say "profile $AA_PROFILE: not loaded" ;; *) say "profile $AA_PROFILE: cannot tell from this user" ;; esac
  if [ -f "$AA_UNITS/$AA_UNIT" ]; then say "boot unit: $AA_UNIT installed"; else say "boot unit: not installed"; fi
  _v=""; [ -n "$DIR" ] && _v=$(aa_env_value "$ENVFILE")
  say "the Sentinel runs under: ${_v:-docker-default} ($AA_ENV_KEY in .env)"
}

install_profile() {
  [ -n "$DIR" ] && [ -f "$SOURCE" ] || die "no profile at $SOURCE: run this from the Sentinel's checkout (sudo scripts/apparmor.sh install)"
  if ! aa_needed; then
    say "not needed: $(aa_why). Nothing changed; the Sentinel runs under Docker's default profile."
    return 0
  fi
  need_root
  parser=$(aa_parser)
  [ -n "$parser" ] || die "apparmor_parser is not installed (package apparmor)"
  # Check before anything changes: a profile the parser refuses must not reach .env, or Docker would refuse to start the Sentinel.
  "$parser" -Q -K "$SOURCE" >/dev/null || die "apparmor_parser refused $SOURCE; nothing changed"
  mkdir -p "$(dirname "$AA_ETC_PROFILE")" "$(dirname "$AA_HELPER")" "$AA_UNITS"
  cp "$SOURCE" "$AA_ETC_PROFILE.tmp" && chmod 644 "$AA_ETC_PROFILE.tmp" && mv -f "$AA_ETC_PROFILE.tmp" "$AA_ETC_PROFILE"
  if ! "$parser" -r -W "$AA_ETC_PROFILE"; then
    rm -f "$AA_ETC_PROFILE"
    die "apparmor_parser could not load the profile; nothing else changed"
  fi
  say "loaded $AA_PROFILE (a root-owned copy in $AA_ETC_PROFILE, which AppArmor also loads at boot)"
  cp "$0" "$AA_HELPER.tmp" && chmod 755 "$AA_HELPER.tmp" && mv -f "$AA_HELPER.tmp" "$AA_HELPER"
  if command -v systemctl >/dev/null 2>&1 && [ -d "$AA_PREFIX/run/systemd/system" ]; then
    cat > "$AA_UNITS/$AA_UNIT" <<UNIT
[Unit]
Description=Load the cvENGINE Sentinel's AppArmor profile before Docker starts its containers
After=apparmor.service local-fs.target
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$AA_HELPER boot --dir $DIR

[Install]
WantedBy=multi-user.target docker.service
UNIT
    systemctl daemon-reload
    systemctl enable "$AA_UNIT" >/dev/null 2>&1 || systemctl enable "$AA_UNIT"
    say "installed $AA_UNIT (loads the profile at boot, before docker.service)"
  else
    say "no systemd here: AppArmor's own boot service loads $AA_ETC_PROFILE"
  fi
  aa_env_write "$ENVFILE" "$(owner)" "$AA_PROFILE"
  say "wrote $AA_ENV_KEY=$AA_PROFILE to $ENVFILE"
  say "next, as $(owner): cd $DIR && docker compose up -d sentinel   (the Sentinel proves its sandbox at start and takes screenshots again)"
}

boot() {
  parser=$(aa_parser)
  if [ -n "$parser" ] && [ -r "$AA_ETC_PROFILE" ] && "$parser" -r -W "$AA_ETC_PROFILE"; then
    say "loaded $AA_PROFILE"
    return 0
  fi
  if [ -n "$DIR" ] && [ "$(aa_env_value "$ENVFILE")" = "$AA_PROFILE" ]; then
    aa_env_write "$ENVFILE" "$(owner)"
    say "could not load $AA_PROFILE: took $AA_ENV_KEY out of $ENVFILE so the Sentinel starts under Docker's default profile (no screenshots)"
  fi
  exit 1
}

remove_profile() {
  need_root
  if command -v systemctl >/dev/null 2>&1; then systemctl disable "$AA_UNIT" >/dev/null 2>&1 || true; fi
  rm -f "$AA_UNITS/$AA_UNIT" "$AA_HELPER" "$AA_ETC_PROFILE"
  if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload 2>/dev/null || true; fi
  [ -z "$DIR" ] || aa_env_write "$ENVFILE" "$(owner)"
  say "removed; recreate the Sentinel (docker compose up -d sentinel) and it runs under Docker's default profile. The loaded profile stays until reboot (or: sudo apparmor_parser -R $AA_PROFILE once no container uses it)."
}

case "$CMD" in
  install) install_profile ;;
  status) status ;;
  boot) boot ;;
  remove) remove_profile ;;
  *) die "usage: scripts/apparmor.sh install|status|remove|boot [--dir CHECKOUT]" ;;
esac
