#!/usr/bin/env bash
# Interactive (or scripted) setup for a Sentinel: writes .env for you. Run it once, then: docker compose up -d
#
#   ./setup.sh                       asks every question
#   ./setup.sh --light --internal --name office-lan --blob "$BLOB"      no questions
#
# Options:
#   --blob TEXT        the one-time provisioning blob from the cvENGINE Sentinels page (Provision)
#   --name TEXT        the Sentinel's name on the Sentinels page (default: the container's hostname)
#   --full | --light   full also runs OpenVAS/GVM (several GB, hours of feed sync on the first start); light does not
#   --external | --internal
#                      external: scans targets reachable from the internet side (the default); internal: this machine sits
#                      inside a private network (office LAN, VPC, VPN) and scans the internal ranges a project declared
#   --updater | --no-updater
#                      install the updater (an hourly timer on this machine, scripts/install-updater.sh) so this Sentinel can update itself when cvENGINE
#                      says to (the default; it asks for sudo when it is not root). --no-updater leaves it out; install it later with
#                      `sudo ./scripts/install-updater.sh`. What it may do is the self-update setting (Off, Manual or Automatic) on the Sentinels page
#   --yes              do not ask, use the defaults for anything not given (full, external, updater installed)
#   --help
set -euo pipefail
cd "$(dirname "$0")"

blob="" name="" profile="" network="" updater="" yes=0
while [ $# -gt 0 ]; do
  case "$1" in
    --blob) blob="${2:?--blob needs a value}"; shift 2 ;;
    --name) name="${2:?--name needs a value}"; shift 2 ;;
    --full) profile=full; shift ;;
    --light) profile=light; shift ;;
    --external) network=external; shift ;;
    --internal) network=internal; shift ;;
    --updater) updater=yes; shift ;;
    --no-updater) updater=no; shift ;;
    --yes|-y) yes=1; shift ;;
    --help|-h) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done

ask() { # ask VAR "question" "default"
  local var="$1" prompt="$2" default="$3" reply=""
  if [ "$yes" = 1 ] || [ ! -t 0 ]; then printf -v "$var" '%s' "$default"; return; fi
  read -r -p "$prompt [$default] " reply || true
  printf -v "$var" '%s' "${reply:-$default}"
}

if [ -z "$profile" ]; then
  echo "Full runs OpenVAS too (several GB of disk, hours of feed sync on the first start); light does not."
  ask profile "Profile (full/light)?" full
fi
if [ -z "$network" ]; then
  echo "Internal means this machine is inside a private network and will scan the internal ranges a project declared."
  ask network "Network (external/internal)?" external
fi
[ -z "$name" ] && ask name "Name for this Sentinel (blank: the container hostname)?" ""
if [ -z "$blob" ] && [ "$yes" != 1 ] && [ -t 0 ]; then
  read -r -p "Provisioning blob from the Sentinels page (blank: add it to .env later)? " blob || true
fi

if [ -z "$updater" ]; then
  echo "The updater is a small hourly job on this machine that lets cvENGINE update this Sentinel (it does nothing unless self-update is Manual or Automatic for it)."
  ask updater_answer "Install the updater (yes/no)?" yes
  case "$updater_answer" in n|N|no|NO|No) updater=no ;; *) updater=yes ;; esac
fi

case "$profile" in full|light) ;; *) echo "profile must be full or light" >&2; exit 2 ;; esac
case "$network" in external|internal) ;; *) echo "network must be external or internal" >&2; exit 2 ;; esac
case "$blob$name" in *$'\n'*|*"'"*|*'"'*) echo "the blob and name must not contain quotes or newlines" >&2; exit 2 ;; esac

[ -f .env ] && cp .env ".env.bak.$(date +%Y%m%d%H%M%S)" && echo "Existing .env saved as a .env.bak.* file."
{
  echo "# Written by setup.sh"
  [ -n "$blob" ] && echo "CVENGINE_SENTINEL_BLOB=$blob"
  [ -n "$name" ] && echo "CVENGINE_SENTINEL_NAME=$name"
  echo "CVENGINE_SENTINEL_NETWORK=$network"
  if [ "$profile" = full ]; then echo "COMPOSE_PROFILES=openvas"; else echo "COMPOSE_PROFILES="; fi
  echo "# Self-update (off, manual or automatic) is chosen in cvENGINE; set CVENGINE_SENTINEL_UPDATE here only to state this machine's own choice (the most recent change wins)."
  echo "# CVENGINE_SENTINEL_UPDATE="
} > .env
chmod 600 .env
echo "Wrote .env: profile=$profile, network=$network."

if [ "$updater" = yes ]; then
  if ./scripts/install-updater.sh; then
    echo "Updater installed. Choose Off, Manual or Automatic for this Sentinel on the Sentinels page; until you do it follows the instance default."
  else
    echo "The updater was NOT installed (see above). Install it later with: sudo ./scripts/install-updater.sh" >&2
    echo "Until then this Sentinel cannot update itself, and the Sentinels page will say so." >&2
  fi
else
  echo "No updater installed. To let cvENGINE update this Sentinel later: sudo ./scripts/install-updater.sh"
fi
echo "Next: docker compose up -d"
