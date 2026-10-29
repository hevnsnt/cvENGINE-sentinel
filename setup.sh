#!/usr/bin/env bash
# Interactive (or scripted) setup for a Sentinel: writes .env for you. Run it once, then: docker compose up -d
#
#   ./setup.sh                       asks every question
#   ./setup.sh --light --internal --name office-lan --blob - < blob.txt      no questions
#
# Options:
#   --blob TEXT        the one-time provisioning blob from the cvENGINE Sentinels page (Provision); `--blob -` reads it from stdin, and a
#                      CVENGINE_SENTINEL_BLOB already in the environment is used too, so it need not appear on the command line
#   --name TEXT        the Sentinel's name on the Sentinels page (default: the container's hostname); letters, digits, space, . _ -
#   --full | --light   full also runs OpenVAS/GVM (several GB, hours of feed sync on the first start); light does not
#   --external | --internal
#                      external: scans targets reachable from the internet side (the default); internal: this machine sits
#                      inside a private network (office LAN, VPC, VPN) and scans the internal ranges a project declared
#   --updater | --no-updater
#                      install the updater (an hourly timer on this machine, scripts/install-updater.sh) so this Sentinel can update itself when cvENGINE
#                      says to (the default; it asks for sudo when it is not root, and never waits for a password without a terminal). --no-updater
#                      leaves it out; install it later with `sudo ./scripts/install-updater.sh`. What it may do is the self-update setting (Off,
#                      Manual or Automatic) on the Sentinels page
#   --host-network     let the Sentinel scan this machine's LAN directly: writes docker-compose.override.yml (git-ignored) from
#                      docker-compose.override.yml.example, which puts the sentinel service on the host's network
#   --yes              do not ask; anything not given keeps its value in an existing .env, else the default (full, external, updater installed)
#   --help
#
# Running it again changes only what you give it: every other line of an existing .env is kept (a timestamped .env.bak.* copy is saved first).
set -euo pipefail
cd "$(dirname "$0")"

blob="" name="" profile="" network="" updater="" updater_answer="" yes=0 host_network=0 name_given=0
while [ $# -gt 0 ]; do
  case "$1" in
    --blob) blob="${2:?--blob needs a value}"; shift 2 ;;
    --name) name="${2?--name needs a value}"; name_given=1; shift 2 ;;
    --full) profile=full; shift ;;
    --light) profile=light; shift ;;
    --external) network=external; shift ;;
    --internal) network=internal; shift ;;
    --updater) updater=yes; shift ;;
    --no-updater) updater=no; shift ;;
    --host-network) host_network=1; shift ;;
    --yes|-y) yes=1; shift ;;
    --help|-h) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
if [ "$blob" = - ]; then
  IFS= read -r blob || true
elif [ -z "$blob" ] && [ -n "${CVENGINE_SENTINEL_BLOB:-}" ]; then
  blob="$CVENGINE_SENTINEL_BLOB"
fi

# What an existing .env says, so a re-run offers it as the default and leaves alone what it is not asked to change.
current() { [ -f .env ] && sed -n "s/^$1=//p" .env | tail -n 1 || true; }
old_profile=""
if [ -f .env ] && grep -q '^COMPOSE_PROFILES=' .env; then
  case "$(current COMPOSE_PROFILES)" in *openvas*) old_profile=full ;; *) old_profile=light ;; esac
fi
old_network="$(current CVENGINE_SENTINEL_NETWORK)"
old_name="$(current CVENGINE_SENTINEL_NAME)"

ask() { # ask VAR "question" "default"
  local var="$1" prompt="$2" default="$3" reply=""
  if [ "$yes" = 1 ] || [ ! -t 0 ]; then printf -v "$var" '%s' "$default"; return; fi
  read -r -p "$prompt [$default] " reply || true
  printf -v "$var" '%s' "${reply:-$default}"
}

if [ -z "$profile" ]; then
  echo "Full runs OpenVAS too (several GB of disk, hours of feed sync on the first start); light does not."
  ask profile "Profile (full/light)?" "${old_profile:-full}"
fi
if [ -z "$network" ]; then
  echo "Internal means this machine is inside a private network and will scan the internal ranges a project declared."
  ask network "Network (external/internal)?" "${old_network:-external}"
fi
[ "$name_given" = 1 ] || ask name "Name for this Sentinel (blank: the container hostname)?" "$old_name"
if [ -z "$blob" ] && [ "$yes" != 1 ] && [ -t 0 ]; then
  read -r -s -p "Provisioning blob from the Sentinels page (blank: keep the current one or add it to .env later)? " blob || true
  echo
fi

if [ -z "$updater" ]; then
  echo "The updater is a small hourly job on this machine that lets cvENGINE update this Sentinel (it does nothing unless self-update is Manual or Automatic for it)."
  ask updater_answer "Install the updater (yes/no)?" yes
  case "$updater_answer" in n|N|no|NO|No) updater=no ;; *) updater=yes ;; esac
fi

case "$profile" in full|light) ;; *) echo "profile must be full or light" >&2; exit 2 ;; esac
case "$network" in external|internal) ;; *) echo "network must be external or internal" >&2; exit 2 ;; esac
# compose reads .env itself and mangles #, $ and quotes, so a value is kept to characters it passes through unchanged.
[[ "$name" =~ ^[A-Za-z0-9._\ -]*$ ]] || { echo "the name may contain only letters, digits, spaces and . _ -" >&2; exit 2; }
[[ "$blob" =~ ^[A-Za-z0-9+/_=-]*$ ]] || { echo "the blob is not a provisioning blob (expected base64 text from the Sentinels page)" >&2; exit 2; }

umask 077  # .env holds the blob: no moment where it, its backup or the new copy is readable by others
if [ -f .env ]; then
  cp .env ".env.bak.$(date +%Y%m%d%H%M%S)"
  echo "Existing .env saved as a .env.bak.* file."
  cp .env .env.new
else
  {
    echo "# Written by setup.sh"
    echo "# Self-update (off, manual or automatic) is chosen in cvENGINE; set CVENGINE_SENTINEL_UPDATE here only to state this machine's own choice (the most recent change wins)."
    echo "# CVENGINE_SENTINEL_UPDATE="
  } > .env.new
fi
chmod 600 .env.new

set_key() { # set_key KEY VALUE: replace the KEY= line in place, or append one; every other line is kept as it is
  if grep -q "^$1=" .env.new; then
    KEY="$1" VALUE="$2" awk 'index($0, ENVIRON["KEY"] "=") == 1 { if (done) next; print ENVIRON["KEY"] "=" ENVIRON["VALUE"]; done = 1; next } { print }' \
      .env.new > .env.tmp
    cat .env.tmp > .env.new
    rm -f .env.tmp
  else
    [ -z "$(tail -c1 .env.new)" ] || echo >> .env.new  # a last line without its newline would swallow the new key
    echo "$1=$2" >> .env.new
  fi
}

[ -n "$blob" ] && set_key CVENGINE_SENTINEL_BLOB "$blob"
if [ -n "$name" ] || [ "$name_given" = 1 ] || [ -n "$old_name" ]; then set_key CVENGINE_SENTINEL_NAME "$name"; fi
set_key CVENGINE_SENTINEL_NETWORK "$network"
set_key CVENGINE_SENTINEL_PROFILE "$profile"  # what the daemon reads; COMPOSE_PROFILES only decides which containers compose starts
if [ "$profile" = full ]; then set_key COMPOSE_PROFILES openvas; else set_key COMPOSE_PROFILES ""; fi
mv .env.new .env
echo "Wrote .env: profile=$profile, network=$network."

if [ "$old_profile" = full ] && [ "$profile" = light ]; then
  echo "This Sentinel was full: \`docker compose up -d\` does not stop the OpenVAS containers of a profile that is no longer on. Stop them once with:"
  echo "  docker compose --profile openvas down && docker compose up -d"
fi

if [ "$host_network" = 1 ]; then
  if [ -f docker-compose.override.yml ]; then
    echo "docker-compose.override.yml already exists; left as it is (compare it with docker-compose.override.yml.example)."
  else
    cp docker-compose.override.yml.example docker-compose.override.yml
    chmod 644 docker-compose.override.yml
    echo "Wrote docker-compose.override.yml: the Sentinel uses this machine's network and can scan its LAN directly."
  fi
fi

if [ "$updater" = yes ]; then
  installed=0
  if [ "$(id -u)" = 0 ] || [ -t 0 ]; then
    ./scripts/install-updater.sh && installed=1
  else
    # No terminal to type a password into: sudo must fail rather than wait for one.
    sudo -n ./scripts/install-updater.sh && installed=1
  fi
  if [ "$installed" = 1 ]; then
    echo "Updater installed. Choose Off, Manual or Automatic for this Sentinel on the Sentinels page; until you do it follows the instance default."
    echo "The Sentinels page shows the updater as installed once the Sentinel is up (docker compose up -d)."
  else
    echo "The updater was NOT installed (see above). Install it later with: sudo ./scripts/install-updater.sh" >&2
    echo "Until then this Sentinel cannot update itself, and the Sentinels page will say so." >&2
  fi
else
  echo "No updater installed. To let cvENGINE update this Sentinel later: sudo ./scripts/install-updater.sh"
fi
echo "Next: docker compose up -d"
