#!/usr/bin/env bash
# Move an existing, root-owned Sentinel install (for example /root/cvengine-sentinel) to the unprivileged service user, without losing its enrollment.
#
#   sudo /root/cvengine-sentinel/scripts/migrate-to-service-user.sh [--dry-run] [--from DIR] [--dir DIR] [--old-project-name NAME] [--updater] [--wait SECONDS]
#
#   --from DIR   the install to move (default: the checkout this script is in)
#   --dir DIR    where it goes (default /opt/cvengine-sentinel; not under /root)
#   --old-project-name NAME
#                override the Docker Compose project name this script works out for the old install (COMPOSE_PROJECT_NAME in its .env, else its
#                directory name lower-cased with other characters removed). The volume is NAME_sentinel-state (see `docker volume ls`).
#   --allow-no-volume
#                continue although no NAME_sentinel-state volume exists (only for a Sentinel that never started)
#   --updater    install the updater at the new place even if the old install had none (by default it is reinstalled only if one was there)
#   --wait N     wait up to N seconds (default 300) for the container to report healthy
#   --dry-run    print the plan and run only read-only checks
#
# What it does, in order: works out the Compose project name and checks its volume exists; creates the `cvengine` user (the same code as install.sh) and adds it
# to the docker group; `docker compose down` in the old directory (never with -v: the volumes sentinel-state, sentinel-badkeys and the OpenVAS ones,
# which hold the Sentinel's token, are untouched); moves the checkout, keeping .env, docker-compose.override.yml and every untracked file; chowns it
# to cvengine:cvengine; `docker compose up -d` as cvengine; reinstalls the updater (new path, User=cvengine; a cron.d entry for the old path goes);
# waits for the container to report healthy; prints a before and after summary.
#
# The Sentinel stays enrolled because the volumes are found by the compose project name, which this script keeps the same: when the new directory's
# name would give another project name, it writes COMPOSE_PROJECT_NAME=<old name> into the moved .env. It refuses, before changing anything, only when
# no NAME_sentinel-state volume exists for that name, so it never starts a fresh, unenrolled stack silently.
# Running it again after an interruption continues where it stopped (a checkout already in the new place is not moved again).
#
# What this does NOT do: cvengine is in the docker group, which is equivalent to root on this machine. See README.md, "Security model".
if [ -z "${BASH_VERSION:-}" ]; then echo "run this with bash: sudo bash $0 ..." >&2; exit 1; fi
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
CVENGINE_INSTALL_LIB_ONLY=1
export CVENGINE_INSTALL_LIB_ONLY
# shellcheck source=../install.sh
. "$HERE/install.sh"
unset CVENGINE_INSTALL_LIB_ONLY

UNITS="$PREFIX/etc/systemd/system"
CRON="$PREFIX/etc/cron.d/cvengine-sentinel-update"

src="$HERE" dest="$DEFAULT_DIR" given_old_name="" allow_fresh=0 force_updater=0 dry=0 wait_secs=300
while [ $# -gt 0 ]; do
  case "$1" in
    --from) src="${2:?--from needs a value}"; shift 2 ;;
    --dir) dest="${2:?--dir needs a value}"; shift 2 ;;
    --old-project-name) given_old_name="${2:?--old-project-name needs a value}"; shift 2 ;;
    --allow-no-volume) allow_fresh=1; shift ;;
    --updater) force_updater=1; shift ;;
    --wait) wait_secs="${2:?--wait needs a value}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --help|-h) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
case "$wait_secs" in ''|*[!0-9]*) echo "--wait takes a number of seconds" >&2; exit 2 ;; esac
[[ "$given_old_name" =~ ^[a-z0-9][a-z0-9_-]*$ || -z "$given_old_name" ]] || { echo "--old-project-name must be a Compose project name (lower case letters, digits, - and _)" >&2; exit 2; }

svc_require_root_linux
svc_check_docker
src=$(cd "$src" 2>/dev/null && pwd -P || printf '%s' "$src")
svc_check_dir "$dest"
case "$src" in "$dest"|"$dest"/*) die "the old install and the new directory are the same place ($dest): nothing to move" ;; esac

# Is the checkout still at the old place, or already moved by an interrupted run?
if [ -e "$src/docker-compose.yml" ]; then
  cur="$src"; moved=0
elif [ -e "$dest/.git" ] && [ -e "$dest/docker-compose.yml" ]; then
  cur="$dest"; moved=1
else
  die "no Sentinel checkout found at $src (and none at $dest); give the old install with --from DIR"
fi
[ -e "$cur/.git" ] || die "$cur is not a git checkout; this script moves a checkout made by git clone"
if [ "$moved" = 0 ] && [ -e "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
  die "$dest exists and is not empty; move it aside or choose another --dir"
fi

env_value() { [ -f "$cur/.env" ] && sed -n "s/^$1=//p" "$cur/.env" | tail -n 1 | tr -d '"'"'" || true; }
env_name=$(env_value COMPOSE_PROJECT_NAME)

# --- the project name: the volumes are called <project>_sentinel-state, so keeping the name is what keeps the token ---
old_name="${given_old_name:-${env_name:-$(svc_project_name_of "$src")}}"
if [ -n "$given_old_name" ] && [ -n "$env_name" ] && [ "$given_old_name" != "$env_name" ]; then
  die "--old-project-name $given_old_name disagrees with COMPOSE_PROJECT_NAME=$env_name in $cur/.env; one of them is wrong (docker volume ls shows the real name)"
fi
new_name="$old_name"  # the project does not change
write_name=""  # a COMPOSE_PROJECT_NAME line to add to .env, when the new directory's own name would give another project
if [ -z "$env_name" ] && [ "$(svc_project_name_of "$dest")" != "$old_name" ]; then write_name="$old_name"; fi

if docker volume inspect "${old_name}_sentinel-state" >/dev/null 2>&1; then
  say "Found the volume ${old_name}_sentinel-state: the Sentinel's token is kept (Compose project $old_name)."
elif [ "$allow_fresh" = 1 ]; then
  say "note: no volume ${old_name}_sentinel-state exists; continuing because of --allow-no-volume (the Sentinel will start unenrolled unless its .env still holds a blob)."
else
  die "there is no Docker volume ${old_name}_sentinel-state, so the new install would start a fresh, unenrolled Sentinel. Nothing was changed. Check the real name with: docker volume ls | grep sentinel-state   and pass it with --old-project-name NAME (or --allow-no-volume if this Sentinel never started)."
fi

# --- what is there now ---
before_owner=$(stat -c %U "$cur" 2>/dev/null || echo unknown)
updater_was=no
if [ "$force_updater" = 1 ] || [ "$(env_value CVENGINE_SENTINEL_UPDATER)" = installed ] \
  || grep -qsF "$src" "$UNITS/cvengine-sentinel-update.service" "$CRON"; then updater_was=yes; fi
before_user=$(sed -n 's/^User=//p' "$UNITS/cvengine-sentinel-update.service" 2>/dev/null | head -n 1 || true)
[ -n "$before_user" ] || before_user=$([ -f "$CRON" ] && awk 'NR==1 {print $6}' "$CRON" || echo "(none)")

plan() {
  say "Plan to move the Sentinel from $src to $dest as user $SERVICE_USER:"
  say "  1. create user/group $SERVICE_USER if missing; add it to the docker group"
  say "  2. docker compose -p $old_name down in $cur   (no -v: the volumes stay)"
  say "  3. move $cur to $dest (.env, docker-compose.override.yml and all untracked files come with it)"
  [ -z "$write_name" ] || say "  4. add COMPOSE_PROJECT_NAME=$write_name to $dest/.env so the volumes keep matching"
  say "  5. chown -R $SERVICE_USER:$SERVICE_USER $dest"
  say "  6. docker compose up -d as $SERVICE_USER (project $new_name)"
  if [ "$updater_was" = yes ]; then say "  7. reinstall the updater for $dest (User=$SERVICE_USER); remove cron.d entries for $src"; else say "  7. no updater was installed; none is added (pass --updater to add one)"; fi
  say "  8. wait up to ${wait_secs}s for the container to report healthy"
}
plan
if [ "$dry" = 1 ]; then say "Dry run: nothing was changed."; exit 0; fi

# --- do it ---
svc_ensure_user
svc_add_to_docker_group

if [ "$moved" = 0 ]; then
  # An update running right now would be moved from under; the updater holds a lock on the checkout directory.
  if command -v flock >/dev/null 2>&1; then
    exec 9<"$src"
    flock -n 9 || die "an update of this Sentinel is running right now (it holds a lock on $src); try again in a few minutes"
  fi
  say "Stopping the Sentinel (volumes are kept)..."
  (cd "$src" && docker compose -p "$old_name" down)
  mkdir -p "$(dirname "$dest")"
  [ ! -d "$dest" ] || rmdir "$dest"  # empty (checked above): mv would otherwise put the checkout inside it
  mv "$src" "$dest"
  say "Moved $src to $dest."
fi
if [ -n "$write_name" ] && ! grep -q '^COMPOSE_PROJECT_NAME=' "$dest/.env" 2>/dev/null; then
  [ -f "$dest/.env" ] || { : > "$dest/.env"; chmod 600 "$dest/.env"; }
  [ -z "$(tail -c1 "$dest/.env")" ] || echo >> "$dest/.env"
  echo "COMPOSE_PROJECT_NAME=$write_name" >> "$dest/.env"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$dest"
stray=$(find "$dest" ! -user "$SERVICE_USER" -print -quit 2>/dev/null || true)
[ -z "$stray" ] || die "$stray in $dest is not owned by $SERVICE_USER after the chown; not starting the Sentinel"

say "Starting the Sentinel as $SERVICE_USER..."
svc_run "$dest" docker compose -p "$new_name" up -d

if [ "$updater_was" = yes ]; then
  "$dest/scripts/install-updater.sh"
  # install-updater.sh replaces cron with the timers (or the cron file with the new path); a cron entry for the old path must not survive either way.
  if grep -qsF "$src" "$CRON"; then rm -f "$CRON"; say "Removed the cron.d entry that pointed at $src."; fi
  if grep -qsF "$src" "$UNITS"/cvengine-sentinel-*.service 2>/dev/null; then die "a systemd unit still points at $src; run $dest/scripts/install-updater.sh and check $UNITS"; fi
fi

# --- verify ---
health=unknown
waited=0
while :; do
  health=$(docker inspect -f '{{if .State.Running}}{{if .State.Health}}{{.State.Health.Status}}{{else}}running{{end}}{{else}}not-running{{end}}' cvengine-sentinel 2>/dev/null || echo missing)
  [ "$health" = healthy ] && break
  [ "$waited" -lt "$wait_secs" ] || break
  sleep 5
  waited=$((waited + 5))
done

say ""
say "Before:  owner $before_owner, directory $src, updater runs as $before_user"
say "After:   owner $SERVICE_USER, directory $dest, updater $([ "$updater_was" = yes ] && echo "runs as $SERVICE_USER" || echo "not installed"), Compose project $new_name"
say "         container cvengine-sentinel: $health"
say "         The docker group is equivalent to root on this machine: $SERVICE_USER has that, and nothing else beyond its own files."
if [ "$health" != healthy ]; then
  say "The container did not report healthy within ${wait_secs}s. It may still be starting (the full profile takes longer). Look: cd $dest && sudo -u $SERVICE_USER docker compose logs --tail=50 sentinel" >&2
  exit 1
fi
