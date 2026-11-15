#!/usr/bin/env bash
# Install a cvENGINE Sentinel so that nothing about it runs as root: it creates a `cvengine` system user, puts the checkout in /opt/cvengine-sentinel
# owned by that user, runs setup.sh and `docker compose up -d` as that user, and installs the updater to run as that user too.
#
#   bash install.sh --full --external --name SENTINEL-NAME --yes --blob - <<'EOF_BLOB'
#   PASTE_THE_BLOB_VALUE_HERE
#   EOF_BLOB
#
# Run it as root, or as a user who can sudo (it runs itself again under sudo). Safe to run again: an existing user, group, checkout and .env are reused, and setup.sh keeps every .env line you
# did not give it a new value for.
#
# Options (the setup.sh ones are handed to setup.sh unchanged; see ./setup.sh --help):
#   --blob TEXT        the one-time provisioning blob; `--blob -` reads it from stdin (recommended: it stays out of the process list), and a
#                      CVENGINE_SENTINEL_BLOB in the environment is used too. It is handed to setup.sh on its stdin, never on a command line.
#   --name TEXT        the Sentinel's name on the Sentinels page
#   --full | --light, --external | --internal, --host-network, --yes
#   --updater | --no-updater   install the updater (default) or leave it out
#   --dir DIR          where the checkout goes (default /opt/cvengine-sentinel). Not under /root: the service user could not reach it.
#   --help
#
# What this does NOT do: the `cvengine` user is added to the `docker` group, and membership of that group is equivalent to root on this machine.
# The gain is that the checkout, git, setup.sh, the updater and every command you run for this Sentinel are an unprivileged user's, and nothing is
# owned by or runs as root by default. The container itself already runs as an unprivileged user (uid 10001) with two capabilities.
#
# To move an existing root-owned install (for example /root/cvengine-sentinel) here without losing its enrollment: scripts/migrate-to-service-user.sh
if [ -z "${BASH_VERSION:-}" ]; then echo "install.sh needs bash: run it with  sudo bash install.sh ..." >&2; exit 1; fi
set -euo pipefail

PREFIX="${CVENGINE_SENTINEL_INSTALL_PREFIX:-}"  # only for tests: where /etc, /opt and /home are, and a stand-in for being root on Linux
SERVICE_USER=cvengine
SERVICE_HOME="$PREFIX/home/$SERVICE_USER"
DEFAULT_DIR="$PREFIX/opt/cvengine-sentinel"
OFFICIAL_REPO=https://github.com/hevnsnt/cvengine-sentinel.git
# shellcheck disable=SC2034  # used by scripts/migrate-to-service-user.sh, which sources this file
PROJECT_NAME=cvengine-sentinel  # the compose project name docker-compose.yml pins; the volumes are called ${PROJECT_NAME}_sentinel-state and so on
# Only a test may point the clone somewhere else: the updater later builds and runs whatever the origin remote holds.
REPO="$OFFICIAL_REPO"
if [ -n "$PREFIX" ] && [ -n "${CVENGINE_SENTINEL_TEST_REPO:-}" ]; then REPO="$CVENGINE_SENTINEL_TEST_REPO"; fi

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- helpers shared with scripts/migrate-to-service-user.sh (it sources this file with CVENGINE_INSTALL_LIB_ONLY=1) ---

svc_require_root_linux() {
  [ -n "$PREFIX" ] || [ "$(uname -s)" = Linux ] || die "the Sentinel installer supports Linux only (it creates a system user and a systemd or cron updater)"
  [ "$(id -u)" = 0 ] || die "run this as root: sudo bash $0 ..."
}

svc_find_nologin() {
  local p
  for p in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false /usr/bin/false; do
    if [ -x "$p" ]; then printf '%s\n' "$p"; return 0; fi
  done
  printf '%s\n' /bin/false
}

svc_ensure_user() {
  if id "$SERVICE_USER" >/dev/null 2>&1; then
    [ "$(id -u "$SERVICE_USER")" != 0 ] || die "the user '$SERVICE_USER' has uid 0; refusing to use it as the service user"
    say "User $SERVICE_USER exists; reusing it."
    return 0
  fi
  command -v useradd >/dev/null 2>&1 || die "useradd is not installed, so the $SERVICE_USER user cannot be created; create it yourself (a system user, no login shell) and run this again"
  local group_args=(--user-group)
  # A leftover group of that name makes `useradd --user-group` fail; join it instead.
  if getent group "$SERVICE_USER" >/dev/null 2>&1; then group_args=(-g "$SERVICE_USER"); fi
  useradd --system "${group_args[@]}" --create-home --home-dir "$SERVICE_HOME" --shell "$(svc_find_nologin)" "$SERVICE_USER"
  say "Created system user $SERVICE_USER (home $SERVICE_HOME, no login shell)."
}

svc_check_docker() { # before anything is created: Docker, Compose v2 and the docker group must exist
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Engine with the Compose v2 plugin first (https://docs.docker.com/engine/install/), then run this again."
  getent group docker >/dev/null 2>&1 || die "there is no 'docker' group on this machine, so $SERVICE_USER could not be given Docker access. Install Docker Engine (it creates the group), or create the group, then run this again."
  docker compose version >/dev/null 2>&1 || die "'docker compose version' fails: this needs Docker Compose v2"
}

svc_add_to_docker_group() {
  if ! id -nG "$SERVICE_USER" | tr ' ' '\n' | grep -qx docker; then
    usermod -aG docker "$SERVICE_USER" || die "could not add $SERVICE_USER to the docker group"
    say "Added $SERVICE_USER to the docker group."
  fi
}

# Run a command as the service user, from the directory given, with a clean HOME. runuser (util-linux) needs no sudo; fall back to sudo.
svc_run() { # svc_run DIR command...
  local dir="$1"; shift
  if command -v runuser >/dev/null 2>&1; then
    (cd "$dir" && runuser -u "$SERVICE_USER" -- env HOME="$SERVICE_HOME" "$@")
  elif command -v sudo >/dev/null 2>&1; then
    (cd "$dir" && sudo -u "$SERVICE_USER" -H -- "$@")
  else
    die "neither runuser nor sudo is available to run commands as $SERVICE_USER"
  fi
}

svc_check_dir() { # svc_check_dir DIR: an absolute, plain path the service user can reach, which a systemd unit and a cron line can hold
  case "$1" in
    /*) ;;
    *) die "the directory must be an absolute path: $1" ;;
  esac
  case "$1" in
    *[!A-Za-z0-9/._-]*) die "the path '$1' has characters the updater timer cannot use safely; use letters, digits and / . _ - only" ;;
    /|/root|/root/*) die "the Sentinel directory cannot be '$1': the $SERVICE_USER user cannot reach /root (root's home is private). Use the default /opt/cvengine-sentinel." ;;
  esac
}

# The compose project name Docker Compose would derive from a directory name: lower case, only a-z 0-9 - _ kept.
svc_project_name_of() { printf '%s' "$(basename "$1")" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-' | sed 's/^[-_]*//'; }

svc_origin_ok() { # svc_origin_ok URL: the official repository, with or without .git
  case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
    https://github.com/hevnsnt/cvengine-sentinel|https://github.com/hevnsnt/cvengine-sentinel.git) return 0 ;;
  esac
  [ "$1" = "$REPO" ]
}

if [ "${CVENGINE_INSTALL_LIB_ONLY:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

# --- the installer ---

usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

main() {
  # Not root: run this same file again under sudo before anything is read (sudo keeps standard input, so `--blob -` still works; it drops
  # environment variables such as CVENGINE_SENTINEL_BLOB, which therefore only work when you are already root).
  if [ "$(id -u)" != 0 ]; then
    if command -v sudo >/dev/null 2>&1 && [ -f "$0" ]; then
      echo "install.sh creates a system user, so it needs root: running itself again with sudo (it asks for your password if it must)." >&2
      exec sudo bash "$0" "$@"
    fi
    die "run this as root: sudo bash install.sh ... (it needs sudo, or a root shell, to create the $SERVICE_USER user)"
  fi
  local dir="$DEFAULT_DIR" blob="" name="" updater=yes
  local setup_args=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --dir) dir="${2:?--dir needs a value}"; shift 2 ;;
      --blob) blob="${2:?--blob needs a value}"; shift 2 ;;
      --name) name="${2?--name needs a value}"; setup_args+=(--name "$name"); shift 2 ;;
      --full|--light|--external|--internal|--host-network|--yes|-y) setup_args+=("$1"); shift ;;
      --updater) updater=yes; shift ;;
      --no-updater) updater=no; shift ;;
      --help|-h) usage; exit 0 ;;
      *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
  done
  if [ "$blob" = - ]; then
    IFS= read -r blob || true
  elif [ -z "$blob" ] && [ -n "${CVENGINE_SENTINEL_BLOB:-}" ]; then
    blob="$CVENGINE_SENTINEL_BLOB"
  fi
  # The same checks setup.sh makes, so a typo fails before a user is created.
  [[ "$name" =~ ^[A-Za-z0-9._\ -]*$ ]] || { echo "the name may contain only letters, digits, spaces and . _ -" >&2; exit 2; }
  [[ "$blob" =~ ^[A-Za-z0-9+/_=-]*$ ]] || { echo "the blob is not a provisioning blob (expected base64 text from the Sentinels page)" >&2; exit 2; }

  svc_require_root_linux
  svc_check_dir "$dir"
  command -v git >/dev/null 2>&1 || die "git is not installed"

  svc_check_docker
  svc_ensure_user
  svc_add_to_docker_group

  if [ -e "$dir/.git" ]; then
    local owner origin
    owner=$(stat -c %U "$dir" 2>/dev/null || echo UNKNOWN)
    [ "$owner" = "$SERVICE_USER" ] || die "$dir is a checkout owned by $owner, not $SERVICE_USER. To move an existing install here, run its scripts/migrate-to-service-user.sh instead."
    origin=$(svc_run "$dir" git remote get-url origin 2>/dev/null || true)
    svc_origin_ok "$origin" || die "the checkout in $dir has origin '$origin', not $OFFICIAL_REPO; the updater builds whatever origin holds, so refusing to reuse it"
    say "Reusing the checkout in $dir."
  else
    if [ -e "$dir" ] && [ -n "$(ls -A "$dir" 2>/dev/null)" ]; then die "$dir exists and is not empty, and is not a Sentinel checkout"; fi
    mkdir -p "$(dirname "$dir")"
    install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 755 "$dir"
    svc_run "$dir" git clone "$REPO" "$dir" || die "git clone of $REPO failed"
    say "Cloned $REPO into $dir as $SERVICE_USER."
  fi

  # setup.sh as the service user. The updater is installed below, by root, once the checkout is the service user's; setup.sh would otherwise try sudo.
  if [ -n "$blob" ]; then
    printf '%s\n' "$blob" | svc_run "$dir" ./setup.sh "${setup_args[@]}" --no-updater --blob -
  else
    svc_run "$dir" ./setup.sh "${setup_args[@]}" --no-updater
  fi

  if [ "$updater" = yes ]; then
    if "$dir/scripts/install-updater.sh"; then
      say "Updater installed; it runs as $SERVICE_USER."
    else
      say "The updater was NOT installed (see above). Install it later with: sudo $dir/scripts/install-updater.sh" >&2
      updater=failed
    fi
  fi

  svc_run "$dir" docker compose up -d

  say ""
  say "cvENGINE Sentinel installed."
  say "  User:       $SERVICE_USER (uid $(id -u "$SERVICE_USER")), a system account with no login shell"
  say "  Directory:  $dir, owned by $SERVICE_USER:$SERVICE_USER"
  case "$updater" in
    yes) say "  Updater:    installed, runs as $SERVICE_USER" ;;
    no) say "  Updater:    not installed (--no-updater); later: sudo $dir/scripts/install-updater.sh" ;;
    *) say "  Updater:    NOT installed; later: sudo $dir/scripts/install-updater.sh" ;;
  esac
  say "  Privilege:  the checkout, git, setup.sh, the updater and the Sentinel's container (uid 10001) run unprivileged. $SERVICE_USER is in the"
  say "              docker group, which is equivalent to root on this machine; that is the one privilege it has."
  say "Check it:     cd $dir && sudo -u $SERVICE_USER docker compose ps"
  say "              cd $dir && sudo -u $SERVICE_USER docker compose logs --tail=50 sentinel"
}

main "$@"
