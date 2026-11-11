# CVEngine Sentinel

A Sentinel is a Docker Compose stack you run on a machine on your own network. It registers itself with your
CVEngine instance, pulls scan work off a project's queue, runs it locally with its own copies of the scan tools, and
reports typed results back. This repository is the whole client: there is no separate download or per-OS package.

Running several Sentinels spreads scanning across machines or networks: each one pulls work independently from the
same queue.

The stack runs anywhere Docker runs (Linux, macOS and Windows with Docker Desktop). The self-updater
(`scripts/install-updater.sh`) is Linux only (systemd or cron). On macOS and Windows you update by hand (see
[Updates](#updates)).

For the design and the REST contract this client speaks, see the main CVEngine repository:
[docs/ARCHITECTURE.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/ARCHITECTURE.md#sentinels) and
[docs/AGENT-API.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/AGENT-API.md#sentinels-scan-stage-agents).

If an AI agent is setting this up, it should follow [AGENTS.md](AGENTS.md) instead. That file uses fixed commands and
takes only the provisioning blob from the server.

## Contents

- [Prerequisites](#prerequisites)
- [Set up](#set-up)
- [setup.sh reference](#setupsh-reference)
- [Everyday commands](#everyday-commands)
- [Stop, restart and remove](#stop-restart-and-remove)
- [Configuration](#configuration)
- [What a Sentinel runs](#what-a-sentinel-runs)
- [Scope: what a Sentinel never scans](#scope-what-a-sentinel-never-scans)
- [Managing a Sentinel from cvENGINE](#managing-a-sentinel-from-cvengine)
- [OpenVAS](#openvas)
- [Updates](#updates)
- [Runtime behaviour](#runtime-behaviour)
- [The built-in scanner](#the-built-in-scanner)
- [Testing](#testing)
- [Security model](#security-model)

## Prerequisites

| Requirement                                                                                                  | Why                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| Docker Engine (or Docker Desktop) with Docker Compose v2 (`docker compose`, not `docker-compose`)            | Runs the stack. The updater uses `docker compose pull --ignore-buildable` and `pull_policy: build`, so use a current Compose v2 release. |
| Permission to run `docker`: membership in the `docker` group, or `sudo`                                      | Every command below. Membership in the `docker` group is equivalent to root on that machine (see [Security model](#security-model)).     |
| `git`                                                                                                        | Cloning, and the updater (it fast-forwards this checkout).                                                                               |
| `bash`                                                                                                       | `./setup.sh`. On Windows run it from WSL or Git Bash, or write `.env` by hand.                                                           |
| For the updater only: Linux, systemd or cron, `flock` (util-linux), and `sudo` or a root shell to install it | See [Updates](#updates). The user who owns the checkout must be in the `docker` group, because the updater runs as that user.            |
| For the full profile: disk space for tens of GB of OpenVAS feed data                                         | See [Full or light](#full-or-light).                                                                                                     |

## Set up

1. Clone this repository onto the machine that will do the scanning:

   ```bash
   git clone https://github.com/hevnsnt/cvengine-sentinel.git
   cd cvengine-sentinel
   ```

2. On your CVEngine instance's **Sentinels** page (`/cve/sentinels/`), pick the project and click **Provision**. Copy
   the one-time blob it shows. It is single-use and expires in 30 minutes. You need the admin role in the project or
   its organization (see
   [docs/FRONTEND.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/FRONTEND.md#sentinels) in the main
   repository).

3. Create `.env`. The easy way is `./setup.sh`, which asks for the profile, the network, a name and the blob. To skip
   the questions, pass everything as options and give the blob on standard input, so it never appears in your shell
   history or the process list:

   ```bash
   ./setup.sh --light --internal --name office-lan --yes --blob - < blob.txt
   rm blob.txt
   ```

   Expected output (abridged):

   ```
   Wrote .env: profile=light, network=internal.
   ...
   Next: docker compose up -d
   ```

   Or write `.env` by hand. Keep it private (mode 600), because it holds the blob:

   ```bash
   install -m 600 .env.example .env
   # then edit .env: set CVENGINE_SENTINEL_BLOB=..., and COMPOSE_PROFILES / CVENGINE_SENTINEL_PROFILE (see "Full or light")
   ```

4. Start it:

   ```bash
   docker compose up -d
   ```

The first start decodes the blob, trades its one-time secret for this Sentinel's own token, and saves that token in the
`sentinel-state` Docker volume. Every later start uses the saved token, so the blob is read only once. You can then
remove the `CVENGINE_SENTINEL_BLOB` line from `.env` (it is ignored once a token is saved) and delete any
`.env.bak.*` backups, which also contain it.

Every start, including later ones, registers again with the server (name, capabilities, `max_concurrent`, the tools
found in the image and this machine's own settings), so cvENGINE always sees the current capacity.

The blob's server address must use `https`. To use plain `http` on a trusted lab network, set
`CVENGINE_SENTINEL_ALLOW_INSECURE=1` in `.env`; the Sentinel then logs an `INSECURE` warning at every start.

## setup.sh reference

`./setup.sh` writes `.env` and, by default, installs the updater. Run `./setup.sh --help` for the same list.

| Option                       | Effect                                                                                                                                                                                        |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--full` / `--light`         | Full also runs the OpenVAS/GVM stack. Light runs only the lightweight tools. Default: what `.env` already says, else full.                                                                    |
| `--external` / `--internal`  | Internal means this machine sits inside a private network and may scan private addresses (see [Scope](#scope-what-a-sentinel-never-scans)). Default: what `.env` already says, else external. |
| `--name TEXT`                | The name shown on the Sentinels page. Letters, digits, spaces and `. _ -` only. Default: the container's host name.                                                                           |
| `--blob TEXT`                | The provisioning blob. `--blob -` reads it from standard input (recommended). A `CVENGINE_SENTINEL_BLOB` already exported in your shell is used too. The interactive prompt does not echo it. |
| `--updater` / `--no-updater` | Install the updater (the default) or leave it out. Without a terminal, `setup.sh` runs `sudo -n`, so it never waits for a password; if that fails it prints how to install the updater later. |
| `--host-network`             | Copy `docker-compose.override.yml.example` to `docker-compose.override.yml` (an existing override file is left alone). See [Host networking](#host-networking).                               |
| `--yes` (or `-y`)            | Ask nothing. Anything not given keeps its value from an existing `.env`, else the default. Without a terminal it asks nothing either.                                                         |

What it does, in order:

- It sets `umask 077` before writing anything, so `.env`, the new copy and the backup are mode 600.
- When `.env` exists, it saves a timestamped copy as `.env.bak.YYYYMMDDHHMMSS`, then changes only the keys you gave
  (by option or answer) plus `CVENGINE_SENTINEL_NETWORK`, `CVENGINE_SENTINEL_PROFILE` and `COMPOSE_PROFILES`. Every
  other line, including ones you added by hand, is kept.
- It refuses a name or blob with characters Compose would misread (exit 2).
- When you switch a full Sentinel to light, it prints the command that stops the OpenVAS containers (see
  [Switching full to light](#switching-full-to-light)).
- It never starts the stack: run `docker compose up -d` afterwards.

## Everyday commands

Run these in the checkout directory.

| Command                                                         | What it does                                                                                                                               |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `docker compose up -d`                                          | Start, or apply a changed `.env` or override file (recreates what changed).                                                                |
| `docker compose ps`                                             | Container states. The `sentinel` service shows `healthy` or `unhealthy` (see [Health check](#health-check)).                               |
| `docker compose logs -f sentinel`                               | The Sentinel's log: bootstrap, registration, every task accepted and finished. The token is never logged.                                  |
| `docker compose exec sentinel python3 -m client.control status` | The daemon's status as JSON: `version`, `in_flight`, `draining`, `mode`, `setting` (the effective self-update setting), `requested`, `at`. |
| `docker compose exec sentinel python3 -m client.control health` | Exit 0 when healthy, else exit 1 with the reason on standard error.                                                                        |
| `docker compose stop`                                           | Stop without removing anything (see [Shutdown](#shutdown)).                                                                                |
| `docker compose down`                                           | Stop and remove the containers. Volumes (token, GVM data, feeds) are kept.                                                                 |

Check that it registered: open the **Sentinels** page on your CVEngine instance. The new Sentinel appears by its name
(`CVENGINE_SENTINEL_NAME`, else the container's host name), `pending` until an administrator approves it, then
`active`, and `live` once it heartbeats. It is administered like any other agent there (**Suspend**, **Revoke**), or
over the API and MCP tools (`GET /api/v1/agents?kind=scanner`, `list_sentinels`, `get_sentinel`).

## Stop, restart and remove

### Shutdown

On `docker compose stop` or `down` (SIGTERM), the Sentinel:

1. stops polling for new work,
2. gives running tasks 20 seconds to finish and report,
3. kills the tasks still running (the tool's whole process group; for OpenVAS, it stops and deletes the GVM task) and
   releases them back to the queue, so cvENGINE can hand them out again. A killed run's partial output is never
   reported as a result.

`docker-compose.yml` gives the container 75 seconds (`stop_grace_period`) before Docker kills it, which leaves time
for the OpenVAS stop and the release calls. `init: true` reaps the child processes testssl.sh leaves behind.

A result that is finished but not yet delivered stays in the spool across the stop and goes out at the next start.

On every start the daemon clears any drain flag an interrupted update left behind, and registers again.

### Switching full to light

`docker compose up -d` does not stop the containers of a profile that is no longer enabled. After switching a full
Sentinel to light (`./setup.sh --light`), run once:

```bash
docker compose --profile openvas down && docker compose up -d
```

This also restarts the Sentinel for a moment. The OpenVAS volumes are kept; remove them with `docker volume rm` if you
want the disk space back.

### Remove for good

```bash
docker compose --profile openvas down -v
```

This removes the containers and every volume (the token, the GVM data and the feeds). Then **Revoke** the Sentinel on
the CVEngine **Sentinels** page (or `PATCH /api/v1/agents/{id}` with `{"status": "revoked"}`) so its token can never be
used again, even if a copy of the `sentinel-state` volume survives somewhere.

### Revoked token

When cvENGINE answers 401 or 403, the Sentinel logs `this Sentinel's token was revoked or is invalid; stopping` and
exits with status 1. Docker's restart policy (`unless-stopped`) then restarts it, and it stops again each time.
Restarting does not help: provision it again. Delete only the saved token (the same volume holds the GVM login,
which you want to keep), put a new blob in `.env`, and start it:

```bash
docker compose stop sentinel
docker compose run --rm --no-deps --entrypoint rm sentinel -f /var/lib/cvengine-sentinel/token.json
./setup.sh --yes --no-updater --blob - < blob.txt
docker compose up -d
```

(`--no-updater` only means "do not install it again": an updater that is already installed stays.)

## Configuration

### Environment variables

`.env` is read by Docker Compose, which passes only the variables listed in `docker-compose.yml` to the `sentinel`
container. "Not passed by compose" below means a value in `.env` has no effect; set it under
`services.sentinel.environment` in `docker-compose.override.yml` if you need it.

| Variable                                                                                                        | Required         | Default                                               | Meaning                                                                                                                                                                                           | Read by                                                                   |
| --------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `CVENGINE_SENTINEL_BLOB`                                                                                        | First start only | none                                                  | The one-time provisioning blob. Ignored once a token is saved.                                                                                                                                    | daemon (`client/config.py`); `setup.sh` takes it from the environment too |
| `CVENGINE_SENTINEL_BLOB_FILE` | No | none | A file that holds the provisioning blob, in the same format, read when there is no saved token and `CVENGINE_SENTINEL_BLOB` is not set. Never logged. The built-in scanner reads its enrollment this way (see [The built-in scanner](#the-built-in-scanner)). | daemon (`client/config.py`) |
| `CVENGINE_SENTINEL_BUILTIN` | No | unset | `1` only on cvENGINE's own built-in scanner, which cvENGINE's compose file runs. Never set it on another Sentinel. See [The built-in scanner](#the-built-in-scanner). | daemon (`client/config.py`) |
| `CVENGINE_SENTINEL_NAME`                                                                                        | No               | the container's host name                             | The name on the Sentinels page. Reported to cvENGINE only when set, so a rename made in cvENGINE sticks across container recreates unless this is set.                                            | daemon                                                                    |
| `COMPOSE_PROFILES`                                                                                              | No               | unset: light (no OpenVAS containers)                  | `openvas` starts the OpenVAS/GVM stack (full). `setup.sh` and `.env.example` set it to `openvas`.                                                                                                 | Docker Compose                                                            |
| `CVENGINE_SENTINEL_PROFILE`                                                                                     | No               | unset                                                 | `full` or `light`. `light` never runs OpenVAS. Keep it in step with `COMPOSE_PROFILES`; `setup.sh` writes both.                                                                                   | daemon                                                                    |
| `CVENGINE_SENTINEL_NETWORK`                                                                                     | No               | `external`                                            | `internal` lets this Sentinel scan private addresses and run `discover`. Anything else means external. A ceiling: cvENGINE can lower it to external, never raise it.                              | daemon                                                                    |
| `CVENGINE_SENTINEL_DENY_RANGES`                                                                                | No               | none                                                  | Comma-separated CIDRs (a bare address is one host) this Sentinel never connects to, in every kind: a task whose target, or any address its name resolves to, is inside one is refused here with `refused:` in its error text, before anything is sent. Joins the ranges the task itself carries. A list with an entry that is not a network refuses every task until it is fixed. | daemon       |
| `CVENGINE_SENTINEL_DISABLE`                                                                                     | No               | none                                                  | Comma-separated kinds this Sentinel never runs (for example `openvas,wpscan`). Case-insensitive; an unknown entry is ignored and logged once. A veto: cvENGINE can add kinds, never remove these. | daemon                                                                    |
| `CVENGINE_SENTINEL_PROBE_PROXY`                                                                                 | No               | none                                                  | One proxy URL, or several separated by commas (`http://`, `socks5://` or `socks5h://`, a login in the URL if needed), that the in-process probes (`http_probe`) go through, round robin. The probe still vets every address itself and asks the proxy only for that numeric address; a proxy that fails fails the request, never a direct one. Loopback, private and tailnet addresses (unless `CVENGINE_PROXY_PRIVATE=1`) and anything in `CVENGINE_PROXY_BYPASS` or `NO_PROXY` go direct. cvENGINE never sends a proxy. | daemon (`cvengine_scanner/probes/egress_proxy.py`)                        |
| `CVENGINE_SENTINEL_MAX_CONCURRENT`                                                                              | No               | detected from the CPUs the container may use          | How many tasks run at once, OpenVAS not counted (see [Concurrency](#concurrency)). Capped at 10; a value that is not a number means 1.                                                            | daemon                                                                    |
| `CVENGINE_SENTINEL_UPDATE`                                                                                      | No               | unset (cvENGINE decides)                              | `off`, `manual` or `automatic`. A ceiling on the self-update setting (see [Updates](#updates)).                                                                                                   | daemon, and `scripts/update.sh` through it                                |
| `CVENGINE_SENTINEL_UPDATE_EXIT`                                                                                 | No               | unset                                                 | `1`: when cvENGINE asks this Sentinel to update it takes no new work, finishes the tasks it has and exits with code 76 (see [Updates](#updates)). For a supervisor that replaces the image after the exit (`scripts/pull-on-exit.sh`). Unset: the host updater acts on the request. Never used by the built-in scanner. | daemon |
| `CVENGINE_SENTINEL_SPOOL_HOURS` | No | `6` | How long a finished result that cvENGINE did not take (an update, an outage) is held on disk and offered again. `0` turns the spool off (the task is released instead). See [Polling, heartbeat and results](#polling-heartbeat-and-results). | daemon |
| `CVENGINE_SENTINEL_SPOOL_MAX_MB` | No | `256` | Size limit of the result spool directory. | daemon |
| `CVENGINE_SENTINEL_WATCHDOG` | No | on | `0` switches the Sentinel's own watchdog off (hard deadlines, no-progress kill, memory deadlock breaker, orphan reaper, liveness restart, disk guard). Thresholds: [docs/WATCHDOG.md](docs/WATCHDOG.md). | daemon |
| `CVENGINE_SENTINEL_UPDATER`                                                                                     | No               | unset                                                 | `installed` tells cvENGINE an updater exists before its first run. `install-updater.sh` writes it, and `--remove` deletes it. Do not set it by hand.                                              | daemon                                                                    |
| `CVENGINE_SENTINEL_ALLOW_INSECURE`                                                                              | No               | unset                                                 | Exactly `1` allows a plain `http` server address (lab use only).                                                                                                                                  | daemon                                                                    |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`                                                                         | No               | unset                                                 | A proxy for the Sentinel's connection to cvENGINE. testssl.sh and WPScan run with a minimal environment that leaves these out.                                                                    | daemon (through `requests`)                                               |
| `CVENGINE_OPENVAS_KEEP_TASKS`                                                                                   | No               | unset                                                 | `1` (or `true`, `yes`, `on`) keeps each GVM task, target and report after a run, to investigate a scan.                                                                                           | daemon (`client/openvas.py`)                                              |
| `CVENGINE_BADKEYS_REFRESH` | No | on | `0` (or `false`, `no`, `off`) turns off the daily refresh of the badkeys blocklist data the `ssh_probe` host key check reads, for an air-gapped Sentinel that cannot reach `update.badkeys.info`. The host key check then stays "not checked" (unverified) until you place `badkeysdata.json`, `blocklist.dat` and `lookup.txt` (from `sshamble badkeys-update` run elsewhere) in the data directory. The download address is fixed inside the tool and is not configurable. Passed by compose. | daemon (`client/badkeys.py`) |
| `CVENGINE_BADKEYS_DIR` | No | `/var/lib/cvengine-sentinel/badkeys` | Where the badkeys blocklist data lives (the refresh writes `current`, a link to the newest data, inside it). Not passed by compose: the named volume `sentinel-badkeys` is mounted at the default. | daemon (`client/tools.py`, `client/badkeys.py`) |
| `CVENGINE_SENTINEL_UPDATE_TEMPLATES`                                                                            | No               | empty (no refresh)                                    | `1` refreshes the nuclei templates baked into the image at every start (two minute limit), for tasks without the server's template policy                                                         | `docker-entrypoint.sh` (not passed by compose; set it in a compose override if you want it)|
| `OPENVAS_LOG_LEVEL`                                                                                             | No               | `127`                                                 | The OpenVAS scanner's own log level. `128` is debug (about 50 MB for one 40 minute scan of one host); set it only while debugging, then `docker compose up -d`.                                   | Docker Compose (`openvas-configure`)                                      |
| `CVENGINE_OPENVAS_MAX_HOURS`                                                                                    | No               | `24`                                                  | This machine's ceiling on one OpenVAS task's time budget, in hours (at least 1). **Not passed by compose.**                                                                                       | daemon                                                                    |
| `CVENGINE_SENTINEL_VERSION`                                                                                     | No               | the commit stamped into the image                     | Used only when the image has no stamp (built without `.git`). **Not passed by compose**, and `scripts/update.sh` deletes the line from `.env`.                                                    | daemon                                                                    |
| `CVENGINE_SENTINEL_DRAIN_TIMEOUT`                                                                               | No               | `1800`                                                | Seconds an update waits for running tasks. Must be a whole number above 0. **Not read from `.env`**: set it in the updater's environment (see [Updater settings](#updater-settings)).             | `scripts/update.sh`                                                       |
| `CVENGINE_SENTINEL_BRANCH`                                                                                      | No               | `main`                                                | The branch the updater follows; the checkout must be on it. **Not read from `.env`**: set it in the updater's environment.                                                                        | `scripts/update.sh`                                                       |
| `CVENGINE_SENTINEL_TOKEN_FILE`                                                                                  | No               | `/var/lib/cvengine-sentinel/token.json`               | Development and tests only: where the token is saved. The status files live in the same directory. Not passed by compose.                                                                         | daemon                                                                    |
| `CVENGINE_OPENVAS_SOCKET`                                                                                       | No               | `/run/gvmd/gvmd.sock`                                 | Development, tests and CI only: gvmd's socket. Not passed by compose.                                                                                                                             | daemon                                                                    |
| `CVENGINE_OPENVAS_CREDENTIALS_FILE`                                                                             | No               | `/var/lib/cvengine-sentinel/openvas-credentials.json` | Development, tests and CI only: the saved GVM login. Not passed by compose.                                                                                                                       | daemon                                                                    |
| `CVENGINE_NMAP_BIN`, `CVENGINE_NAABU_BIN`, `CVENGINE_NUCLEI_BIN`, `CVENGINE_TESTSSL_BIN`, `CVENGINE_WPSCAN_BIN`, `CVENGINE_WAFW00F_BIN`, `CVENGINE_BBOT_BIN`, `CVENGINE_KINGFISHER_BIN`, `CVENGINE_SSHAMBLE_BIN` | No               | `nmap`, `naabu`, `nuclei`, `testssl.sh`, `wpscan`, `wafw00f`, `bbot`, `kingfisher`, `sshamble`     | Development only: run a tool from another path. Not passed by compose.                                                                                                                            | daemon (`client/tools.py`)                                                |
| `CVENGINE_SENTINEL_SHOT_MAX_RSS_MB` | No | `1500` | The memory the screenshot browser and everything it started may hold together (300 to 16384) before the whole tree is killed and the page in flight is recorded `too_big`. Not passed by compose. | `web_screenshot` (`client/shot.py`) |
| `CVENGINE_SCRIPT_BODY_READ` | No | on | `0` (or `false`, `no`, `off`) stops the reading of a page's scripts for library versions (`http_probe`, `route_probe` and `page_read`): a script's name stays a hint and nothing is fetched. Not passed by compose. | `cvengine_scanner/probes/js_libraries.py` |
| `CVENGINE_SCRIPT_READ_MAX_REQUESTS`, `CVENGINE_SCRIPT_READ_MAX_SECONDS` | No | `300`, `600` | Most script requests, and seconds of reading, one scan of a host spends on that. Not passed by compose. | `cvengine_scanner/probes/js_libraries.py` |
| `CVENGINE_SENTINEL_INSTALL_PREFIX`                                                                              | No               | empty                                                 | Tests only: where `install-updater.sh` writes `/etc`, `/run` and `/var/log`. `sudo` drops it.                                                                                                     | `scripts/install-updater.sh`                                              |

### Full or light

| Profile | Containers                                                                                                | `.env` lines                                                      |
| ------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Full    | `sentinel` plus the OpenVAS/GVM stack (gvmd, the scanner, Postgres, Redis, notus and the feed containers) | `COMPOSE_PROFILES=openvas` and `CVENGINE_SENTINEL_PROFILE=full`   |
| Light   | `sentinel` only                                                                                           | `COMPOSE_PROFILES=` (empty) and `CVENGINE_SENTINEL_PROFILE=light` |

`COMPOSE_PROFILES` decides which containers Compose starts; `CVENGINE_SENTINEL_PROFILE` is what the daemon reads.
With `COMPOSE_PROFILES` unset (no `.env`, or no such line) Compose starts no OpenVAS containers. `.env.example` and
`setup.sh` default to full.

A light Sentinel never declares or runs `openvas`. Neither does a full one until its GVM stack is ready (see
[OpenVAS](#openvas)); every other kind works from the first start. To keep OpenVAS off a full machine without changing
the profile, set `CVENGINE_SENTINEL_DISABLE=openvas`.

### External or internal

`CVENGINE_SENTINEL_NETWORK=internal` says this machine sits inside a private network (an office LAN, a VPC, a VPN).
Only then does the Sentinel declare `network:internal`, scan private addresses, and run the `discover` sweep. An
external Sentinel refuses every private target, whatever the server sends.

### Addresses this Sentinel never touches

Set `CVENGINE_SENTINEL_DENY_RANGES` (comma separated CIDRs, for example `203.0.113.0/24,2001:db8::/32`) on this machine to
protect addresses even when the server is old and sends no list. The floor judges every address any kind is about to
connect to (a target, every address a name resolves to, a redirect hop), so nmap, naabu, nuclei, testssl, wpscan, the
probes, screenshots and the rest all refuse it before a connection or a process; a task refused this way ends with an
error text that starts `refused:` (the contract's outcomes are `done` and `error`). bbot is started with the list, and
the ranges the task carries (`scope.deny_ranges`), in its blacklist, and what it reports is held to them again.

### Host networking

By default the `sentinel` container is on Docker's bridge network. To scan your LAN directly (and for `discover` to
use ARP on the local segment), put the container on the host's network. Do not edit `docker-compose.yml`: the updater
refuses to update a checkout with changes to tracked files. Instead run `./setup.sh --host-network`, or:

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
docker compose up -d
```

`docker-compose.override.yml` is git-ignored, and Compose reads it automatically. Host networking needs no privileged
mode: nmap's OS detection, naabu's SYN scan and the UDP sweep use the `NET_RAW` and `NET_ADMIN` capabilities
`docker-compose.yml` already grants. Host networking in this form is a Linux feature; Docker Desktop on macOS and
Windows handles it differently.

### What docker-compose.yml sets

| Setting                     | Value                                                                                           | Why                                                                                                        |
| --------------------------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `image`                     | `cvengine-sentinel-local:latest`, `pull_policy: build`                                          | Built locally, never pulled from a registry. A plain `docker compose pull` does not ask Docker Hub for it. |
| `cap_add`                   | `NET_RAW`, `NET_ADMIN` (no `--privileged`)                                                      | Raw sockets for nmap, naabu and the UDP sweep. The Sentinel runs as an unprivileged user (uid 10001) and only nmap and naabu carry file capabilities that use these; no other process in the image holds a capability.                                                             |
| `init`, `stop_grace_period` | `true`, `75s`                                                                                   | See [Shutdown](#shutdown).                                                                                 |
| `pids_limit`, `mem_limit`   | `512`, `2g`                                                                                     | Bounds a runaway tool.                                                                                     |
| `healthcheck`               | `python3 -m client.control health` every 60 s                                                   | See [Health check](#health-check).                                                                         |
| `logging`                   | json-file, 3 files of 10 MB, on every service                                                   | Container logs stay bounded.                                                                               |
| Volumes                     | `sentinel-state` at `/var/lib/cvengine-sentinel`; `sentinel-badkeys` at `/var/lib/cvengine-sentinel/badkeys`; gvmd's socket volume read-only at `/run/gvmd` | The token, GVM login and status files; the badkeys blocklist data; the GMP socket.                         |
| Ports                       | none published                                                                                  | Nothing listens for inbound connections.                                                                   |

## What a Sentinel runs

A Sentinel runs only these task kinds, each with its own tool built into the image. The tools, their pinned versions and their licenses are listed on the About page of the cvENGINE server and in its `THIRD-PARTY.md`; the pins themselves are in this repository's `Dockerfile` and `requirements.txt`. Every tool call is a fixed
argument list plus the task's validated targets: no shell, and no server text is ever read as a flag or a command.

| Kind                                             | Tool                                                                             | Target the task names                                                         | Notes                                                                                                                                                                                                           |
| ------------------------------------------------ | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap`                                           | nmap (`-Pn -sV -O --top-ports 1000`, no reverse DNS)                             | up to 64 IP addresses or host names                                           | A host name is replaced by the first IPv4 address it resolved to. Time limit: 90 s per host, at least 600 s, at most 3600 s.                                                                                    |
| `naabu`                                          | naabu (all TCP ports, 1000 packets/s)                                            | up to 64 IP addresses or host names                                           | Names resolved as for nmap. Time limit 900 s.                                                                                                                                                                   |
| `nuclei_light`, `nuclei_targeted`, `nuclei_deep` | nuclei                                                                           | up to 64 hosts, `host:port`, `[ipv6]:port` or `http(s)` URLs                  | The same run for all three; cvENGINE picks the tags and severities. Denial-of-service templates never run (`-etags dos`). A tag filter with no usable tag is refused. At most 5000 findings. Time limit 3600 s. |
| `testssl`                                        | testssl.sh                                                                       | one host name (for SNI), one IP address, one port, optional STARTTLS protocol | Connects to the IP only (`--nodns none`). A timeout is reported as an error. Time limit 900 s.                                                                                                                  |
| `nmap_udp`                                       | nmap `-sU`                                                                       | one IP address or host name                                                   | 18 curated UDP ports at 20 packets/s. Time limit 1500 s.                                                                                                                                                        |
| `wpscan`                                         | WPScan                                                                           | one `http(s)` URL                                                             | Passive plugin and theme detection. A WPScan API token, when cvENGINE sends one with the task, is passed in the environment, never on the command line or in a log. Time limit 900 s.                           |
| `wpscan_thorough`                                | WPScan (mixed plugin and theme detection, `--enumerate ap,at,tt`)                | one `http(s)` URL, an optional API token and the run's `timeout_seconds`      | The thorough pass: every plugin and theme WPScan knows (about 170,000 requests), hours per site (contract version 3). The task's own time limit, 600 s to 24 h (12 h by default, `CVENGINE_WPSCAN_THOROUGH_TIMEOUT` on the server), ends the scan 30 s early and reports what it read. One at a time per Sentinel, and never the last free slot of a Sentinel that has several; set `CVENGINE_SENTINEL_DISABLE=wpscan_thorough` to keep a Sentinel free of it. The token is handled as for `wpscan`. |
| `waf`                                            | wafw00f (`-a -r`, JSON report)                                                   | one host name, its IP address, a port and `http` or `https`                   | Names the web application firewall in front of a site: a product name and no version. Needs contract version 2, which this Sentinel declares at registration and every heartbeat. A site that never answers is an error. Time limit 60 s. |
| `bbot_discovery`                                 | bbot (the presets, required flags and excluded modules the server chose for the mode) | one domain and the scope it must keep to | Discovery of a domain, streamed: what bbot finds is posted in numbered batches to `sentinel/tasks/{id}/partial` every few seconds while it runs (screenshots included, as PNG or JPEG of at most 2 MiB), and the result closes the run. A 409 from the server (the task was cancelled or its scan stopped) stops bbot. bbot is given the scope's denied ranges, every excluded name (with its subdomains) and this Sentinel's own floor as its blacklist, and everything it reports is held to the scope again before it is sent. A project's API keys for bbot's modules are read once from the server (the built-in scanner, or a Sentinel that reports `info.features` `bbot_keys` and that the owner has not opted out) into a private file (0600, in a fresh 0700 directory, removed when the run ends and swept at the next start if the run crashed), never onto the command line; every key is masked in the batches and the result. Needs contract version 3 and bbot in the image. Time limit: the task's own, up to 24 hours (six by default). |
| `http_probe`                                     | in-process HTTP GETs (`cvengine_scanner.probes.version_probes`)                  | up to 300 planned version and identity probes (host, probe, web base) and a scope policy | The version and identity probes cvENGINE plans for hosts whose product has no version: browser-like GETs, no cookie or credential, bounded bytes and time, at most 2 redirects inside the host's group. Every hop, redirects and script reads included, must pass the task's scope policy as well as the floor below; the result names every host asked (`touched`) and every hop refused (`refused`). Needs contract version 3. |
| `dns_resolve`                                    | this Sentinel's resolver                                                         | up to 500 host names and a scope policy                                        | Resolves the names cvENGINE's discovery records, from this Sentinel's view of DNS. A name outside the scope policy is not looked up; a lookup the resolver could not answer is reported as such, never as a name with no address. Needs contract version 3. |
| `nmap_full`                                      | nmap (`-p- --open -T4`, no reverse DNS)                                          | one IP address                                                                | Every TCP port, open ports only: cvENGINE's background full sweep. The raw report goes back and is read by the server's own parser. A host that answers on more than 100 ports (a tarpit or a filtering device) comes back as a normal result: its first 100 open ports and a `cvengine-note` element reading "port list truncated: this host answers on an unusually large number of ports (tarpit or filtering device)", never as a failed task. Contract version 3 (the note is inside the `xml` string; no field was added). Time limit 1500 s. |
| `nmap_verify`                                    | nmap `-sV` on named ports                                                        | one IP address, up to 64 ports, an intensity or `--version-all`, NSE script names | The scripts must be on the reviewed list in `cvengine_scanner/flags.py` (`NSE_SCRIPTS`); any other name is refused. Per-host timeout 10 to 600 s. Contract version 3. |
| `node2shell`                                     | Assetnote's node2shell detector (vendored in `client/vendor`, MIT)               | one `http(s)` URL                                                             | Read-only: uploads about 23 MB, executes nothing, sends no credential. Reports vulnerable, not vulnerable or inconclusive. Contract version 3. |
| `rdp_shot`                                       | aardwolf, RDP with no credentials                                                | one IP address and a port                                                     | A PNG of the pre-authentication screen (at most 4 MB). cvENGINE decides whether it is a real frame and reads it; nothing here looks at it. A server that cannot be reached or requires NLA paints nothing. Contract version 3. |
| `db_probe`                                       | one credential-less connection (`client/dbprobe.py`)                             | one IP address, a port and a database (`redis`, `memcached`, `postgres`, `elastic`, `couchdb`, `mysql`, `mongodb`) | Exactly one attempt, no password, nothing read past a version or a count of database names. Contract version 3. |
| `path_probe`                                     | nmap: a plain SYN and the FIN+PSH+URG probe                                      | up to 8 IPv4 addresses, each with a closed port                               | Measures whether this machine's own path loses a malformed probe (what makes OS detection unreliable). cvENGINE offers it only to its built-in scanner. Contract version 3. |
| `nuclei_validate`                                | nuclei                                                                           | a template, and for a test up to 64 targets                                   | Checks an AI-written template (`nuclei -validate` and a benign loopback page it must not match) or runs an approved one against the targets. A template with a `code`, `file`, `headless`, `javascript`, `flow` or workflow section is refused. cvENGINE offers it only to its built-in scanner. Contract version 3. |
| `alive_check`                                    | in-process GET or TCP connect (`cvengine_scanner.probes.alive`)                  | up to 600 checks (a retired name, its last known address and port, `http`, `https` or `tcp`) and a scope policy | Whether a name that vanished from DNS still answers on its old address (a zombie host): a GET of `/` to the address as the old name, any answer counting, or a bare connect with nothing sent. Each address is asked as itself and must pass the scope policy. Needs contract version 3. |
| `secrets_scan`                                   | Kingfisher 2.18.1 (`scan --no-validate --no-update-check --no-dedup`)            | up to 25 web hosts, each with up to 20 URLs and 8 of its own scripts          | Reads the named pages and scripts and the scripts' same-origin source maps (anonymous GET, no redirects, pinned to the address it judged, 8 scripts per host, 2 MB a script, 8 MB a map, 32 MB in all), then finds secrets in them with every proxy pointed at a closed port, so the detection pass has no network. Needs contract version 3. A second, validating pass runs only when cvENGINE asks for it (its built-in scanner, a project that opted in), with the rules cvENGINE allow-listed and only on the Kingfisher version they were reviewed for. One at a time; about 150 MB of memory for 32 MB of input. `revoke` and `self-update` are never run. Time limit 300 s per pass. |
| `bucket_check`                                   | in-process HTTPS GET and HEAD (`cvengine_scanner.probes.buckets`)                | up to 100 buckets (AWS S3, Google Cloud Storage, an Azure account and container), a request rate and a scope policy | Whether a bucket is public, private or not registered: verified HTTPS on 443 to the platforms' documented endpoints only, no credential, one listing page and one HEAD of a listed object, never an object's content, paced at the task's rate. Needs contract version 3. |
| `vhost_probe`                                    | in-process HTTP GETs (`cvengine_scanner.probes.vhost`)                           | up to 10 addresses, each with up to 200 host names the project already knows, a pace and a scope policy | Whether an address serves other sites than the one it shows: a GET of `/` at the address, then one as each name (the name as the Host header and TLS server name), no body, cookie or credential, no redirect followed, paced at the task's gap. A name that differs from the default gets its own site compared (the front page cvENGINE stored, else one GET of the name at its own address) and its page is returned for cvENGINE to read. An edge that challenges ends the address and is reported, never worked around; what could not be asked is not reported. Needs contract version 3. |
| `subdir_probe`                                   | in-process HTTP GETs (`cvengine_scanner.probes.subdir`, curated data `subdir_apps.json`) | up to 10 web hosts, the curated mount paths, the directories cvENGINE's own URLs show, a request budget, a pace and a scope policy | Which well-known applications (Jira, Grafana, phpMyAdmin ...) are mounted under a subdirectory of a web host: one GET of a path no site serves, `robots.txt`, `sitemap.xml`, each curated path and at most 10 directories the host's own data shows, GET only, nothing sent but the request, no redirect followed, at most the task's budget per host. Every answer that means "something is there" is returned with what the response says it is; cvENGINE decides what is a mount. Needs contract version 3. |
| `route_probe`                                    | in-process GET (`cvengine_scanner.probes.routes`)                                | up to 25 web hosts, each with up to 20 routes (URLs on that host) and a scope policy | How a web route answers an anonymous request: open, a login page, a session requirement, single sign-on, a redirect or not found, with the answer compared with the server's answer for a path that cannot exist (a route that answers like one is `catch_all`). A front page's own scripts are read for the libraries they state, and the sensitive data a body serves is counted and masked; a credential is also returned as its value over the authenticated channel, for cvENGINE's secrets inventory (it fingerprints and masks it at once, and never stores it). Anonymous: no credential, no cookie, no redirect followed, 64 KB of a page and 300 KB of a front page, every hop and address held to the scope policy. A route that could not be asked is reported with an error, never as a state. Needs contract version 3. |
| `route_probe_signed`                              | in-process GET with the stored sign-in (`cvengine_scanner.probes.routes_signed`, `client/signed_in.py`) | up to 25 web hosts with up to 20 routes each and a scope policy; the sign-in is named by reference, never carried | The routes of `route_probe` asked once each signed in, on the built-in scanner only (no other Sentinel declares or is offered it). The scanner reads the stored sign-in once through the server's single-use read, sends it only to a route whose host, scheme and port it was stored for (and the scope policy allows, not expired), verifies the server certificate unless the sign-in's owner allowed otherwise, follows no redirect, reads no script and searches the body for nothing. Each answer is the route's state with a few facts (status, title, redirect target); the values never appear in a result, log line or error (redacted). A route not asked is reported with an error, never as a state. Needs contract version 3. |
| `supplier_check`                                 | in-process DNS, TLS and HTTP(S) requests (`cvengine_scanner.probes.suppliers`)   | up to 25 exact domain names of one supplier, a pace, a request budget and a scope policy                            | Passive posture checks of a third-party supplier's public names, nothing else: each name is resolved once and every address must pass the scope policy, then the certificate and TLS versions on 443, SPF, DKIM, DMARC, MTA-STS and the MailFail checks from this machine's resolver (plus the one MTA-STS policy file over verified HTTPS), the front page over HTTPS and HTTP, and one plain GET per path of a short fixed list of well-known administration and login pages. Anonymous, no redirect followed, at most 64 KB a response, paced at the task's gaps and held to its request budget; an edge that challenges a request is recorded, never worked around. It reports what it found and what the front page announces; cvENGINE matches the CVE catalog itself. Needs contract version 3.|
| `hygiene_check`                                  | in-process TLS handshakes and DNS lookups (`cvengine_scanner.probes.hygiene`, `mailfail`) | up to 300 TLS endpoints, up to 101 names to review for mail, and a scope policy | The TLS and email half of a target's hygiene sweep: each endpoint's certificate, chain verdict and whether TLS 1.0 / 1.1 is accepted (verification off to read broken certificates, nothing sent), and for each mail domain the SPF, DMARC, DKIM, CAA and MailFail checks, read from this Sentinel's resolver, with the domain's MTA-STS policy fetched over verified HTTPS and a registry (RDAP) asked whether a referenced domain is registered. Every connection must pass the scope policy. cvENGINE decides what a certificate means and stores the findings. Needs contract version 3. |
| `dangling_dns_check`                             | in-process DNS questions and HTTP GET (`cvengine_scanner.probes.dangling_dns`)   | up to 50 baddns findings (a host, the kind of finding and its trigger names), cvENGINE's provider lists and a scope policy | Whether a dangling NS or CNAME is claimable by an outsider: the zone cut is found by non-recursive questions to the servers being evaluated (never to an address the policy or this Sentinel's floor refuses), the target's registration is asked of its registry (RDAP), and a provider's "not found" page is compared with a control request to the same addresses. A check with no usable answer is reported `unknown`. Needs contract version 3. |
| `identity_check`                                 | in-process DNS reads and a TLS handshake (`cvengine_scanner.probes.identity`)    | up to 200 DNS questions (`A`, `CNAME`, `NS`, `MX`, `PTR`), up to 50 TLS endpoints and a scope policy | What cvENGINE's own server used to read about a name or an address: the addresses of a name, the alias a hostname ends at, a domain's name and mail servers, an address's reverse name, and the names on the certificate an endpoint serves (verification off, nothing sent, closed at once). Each name must pass the scope policy; an answer the resolver could not give is reported `unknown`, never `none`. Needs contract version 3. |
| `page_read`                                      | in-process GETs and HEADs (`cvengine_scanner.probes.page_read`)                  | up to 10 reads (a HEAD of one URL, or the front pages of up to 6 web bases of a host and the scripts they load, or a control GET, or the readmes of up to 8 plugins) and a scope policy | A validation re-test's reads of a host's own pages: one HEAD of a URL (a GET only after a 405; status, `Server`, `X-Powered-By` and title, never a body), or each web base's front page and the scripts it loads, each fetched in full and searched whole for a library version banner, plus the files the host was seen to load the library from. Every hop passes the scope policy; a read that cannot be made says why and is unknown, never a state. Two more ops serve the server's last target reads: `control` (one GET of `/.cvengine-control-<12 hex>` on the host, nothing else is accepted; returns the status, redirect target, length and a SHA-256 of the whitespace-collapsed body, never the body, so the nuclei result screen can tell a catch-all page) and `readme` (the `readme.txt` of up to 8 plugin slugs of a WordPress site; returns each title found and how many could not be read). |
| `ssh_probe`                                      | sshamble 0.5.1 (`scan --checks badkeys-blocklist`, `cvengine_scanner.probes.ssh_probe`) | up to 25 addresses, each with a port, and a scope policy | Read-only look at an SSH service's own handshake: banner and software version, host key algorithms and sizes, the authentication methods offered, the algorithm lists and the extensions. Only the host key check runs (`check_argv` refuses any other command line): no password, key or user list is ever passed. A host key on the badkeys blocklist is a check hit. The blocklist data is a rolling public download that is not in the image: the daemon fetches it itself with `sshamble badkeys-update` at start when it is missing or older than 24 hours and then about every 24 hours (`CVENGINE_BADKEYS_DIR`, default `/var/lib/cvengine-sentinel/badkeys`, a named compose volume), validates it and swaps it in atomically, keeping the old data when a refresh fails. Each result says `host key blocklist data: N hours old`, and the heartbeat reports the data's age. Without data (or with `CVENGINE_BADKEYS_REFRESH=0`, for an air-gapped Sentinel) the result says the keys were not checked (unverified). An address that is refused, times out, writes nothing or is not SSH is unverified, never clean. 30 s per address. Needs contract version 3. |
| `web_screenshot`                                 | Playwright's headless Chromium (`client/shot.py`), inside Chromium's own sandbox, every connection through a vetting proxy | up to 6 `http(s)` pages, a scope policy and whether the open web may be reached for the page's own resources | A PNG of each page, its final address, status and title. The browser's sandbox is proved before any page is opened (a Sentinel that cannot prove it takes no picture and says why); the page, each redirect and each sub-resource are checked against the scope policy and this Sentinel's address floor before a byte leaves, so a page never reaches an internal address. Needs contract version 3, the image's browser and the seccomp profile `docker-compose.yml` applies. |
| `openvas`                                        | OpenVAS/GVM over GMP                                                             | up to 16 plain IP addresses                                                   | Full profile only, and only once the GVM stack is ready. See [OpenVAS](#openvas).                                                                                                                               |
| `discover`                                       | nmap ping sweep (`-sn`: ARP on the local segment, ICMP and a few TCP/UDP probes) | one private IPv4 network, at most 512 addresses                               | Internal Sentinels only: `CVENGINE_SENTINEL_NETWORK=internal` on this machine, and not lowered to external by cvENGINE. ARP discovery needs [host networking](#host-networking).                                |

A task of a kind this Sentinel does not run right now (disabled, OpenVAS on a light profile or without a ready GVM
stack, `discover` on a non-internal Sentinel) is refused with an error result, even if the server sends it.

### Concurrency

`max_concurrent` (from `CVENGINE_SENTINEL_MAX_CONCURRENT`, cvENGINE, or the detected CPU count, at most 10) is how many
non-OpenVAS tasks run at once. OpenVAS has its own slot: it does not count against `max_concurrent`, and at most one
OpenVAS task runs at a time. At most one `secrets_scan` task runs at a time, inside `max_concurrent`.

**Memory admission.** `max_concurrent` counts slots, not memory, and one nuclei run alone holds 500-730 MB (it loads the whole template set whatever its tags),
so a 2 GB container once ran its deep nuclei, several light ones and the screenshot browser together and the kernel killed them. The daemon now weighs each
kind (`client/admission.py`: nuclei 520 MB, `web_screenshot` 400, `bbot_discovery` 250, Kingfisher 150, nmap 100, other probes 40, from measured peaks) against a
budget taken from the container's own limit (cgroup `memory.max`, less 15% and 200 MB for the daemon; `CVENGINE_SENTINEL_MEMORY_MB` overrides it) and asks the
server only for kinds that fit beside what is running. A task alone is always taken. nuclei also starts with a soft Go memory limit (`GOMEMLIMIT` 400 MiB; peak
500 MB instead of 720-735 MB) and `-c`/`-rl` scaled down for a small budget. A tool the kernel killed reports `out of memory, retry later` (not a bare `-9`) and the
work stays due.

**Claim rate.** A poll and an accept each count against the server's claim limit (`max(60, 30 x max_concurrent)` calls a minute). The daemon keeps its own
calls to 75% of that, honours `Retry-After` on a 429 (for the poll, the accept, which is retried so a claimed task is not left to expire, and the result), and
releases a task it could not accept.

**Screenshots and AppArmor.** If the browser's sandbox cannot start (Docker's AppArmor profile refusing user namespaces says so in plain words), `web_screenshot` is
no longer declared, so the work stays due or goes to another Sentinel; the proof is tried again every ten minutes.

### Limits on output

A tool that prints more than 64 MB is stopped and the task reported as an error. Nuclei findings have their fields
clipped. A testssl.sh or WPScan report over 8 MB is not sent (a testssl.sh task then reports no findings). Stopping a task (time limit, server took it back,
shutdown) kills the tool's whole process group.

## Scope: what a Sentinel never scans

cvENGINE decides what is in scope for a project. The Sentinel also enforces its own floor (`cvengine_scanner/scope.py`, the scanner library), so a
buggy or compromised server cannot aim a scanner at the machine it runs on. Whatever a task says:

- **Never scanned by any Sentinel:** unspecified addresses, loopback, link-local (which includes the cloud metadata
  address 169.254.169.254), multicast, reserved and broadcast space, documentation and benchmarking ranges, the AWS
  IPv6 metadata range, and names such as `localhost`, `metadata.google.internal` and `host.docker.internal`. IPv4
  hidden inside an IPv6 address (mapped, 6to4, NAT64) is judged as the IPv4 address it is.
- **Never its own addresses:** the addresses this container's host name resolves to (with host networking, the
  machine's).
- **Private space only when internal:** RFC 1918, CGNAT (100.64.0.0/10) and unique local IPv6 (fc00::/7) are scanned
  only when this machine's `.env` says `CVENGINE_SENTINEL_NETWORK=internal` and cvENGINE has not lowered it to
  external.
- **One plain target per entry:** no CIDR, nmap ranges (`10.0-255.0-255.1-254`), wildcards, comma lists or numeric
  address forms (`2130706433`, `0x7f000001`). `host:port` only for nuclei. More than 64 entries is refused, not cut.
- **Host names are judged by every address they resolve to:** a name is refused when any of its addresses is refused.
  A name that does not resolve is let through (there is nothing to reach); nmap and naabu drop it.

A refused target fails the task with an error result naming the reason.

The probe kinds (`http_probe`, `dns_resolve`) also carry a **scope policy** (`target.scope`, the contract's `probe_scope`) that cvENGINE computed
when it built the task: the names the task may ask (each host, its apex and `www`, and for the script reads the same site's other hosts the project
holds and the public library CDNs), the names excluded, whether private addresses are allowed at all (a lab install), the private addresses the
project authorised (its own tailnet devices, reached only when asked for as themselves) and ranges cvENGINE never scans
(`cvengine_scanner/probes/policy.py`). It is asked at every hop, on top of the floor above: it can narrow the floor, never widen it. A name is
resolved once and only the vetted numeric addresses are connected to.

## Managing a Sentinel from cvENGINE

An administrator can change a Sentinel's settings from the cvENGINE Sentinels page (or `PATCH agents/{id}` with
`{"settings": {...}}`): its **name**, **network**, **profile**, the **kinds it never takes**, its **concurrency** and its
**self-update** setting. The same settings can be set in `.env` (`CVENGINE_SENTINEL_NAME`, `_NETWORK`, `_PROFILE`,
`_DISABLE`, `_MAX_CONCURRENT`, `_UPDATE`).

The Sentinel reports this machine's own values at every registration, and cvENGINE sends back the values to run with.
cvENGINE decides between the two (the most recent change wins there). Three settings are this machine's policy,
which the server can tighten but never loosen:

| Setting        | Rule enforced by the Sentinel                                                                               |
| -------------- | ----------------------------------------------------------------------------------------------------------- |
| Network        | A ceiling. cvENGINE can lower an internal Sentinel to external; it can never make an external one internal. |
| Disabled kinds | A veto. The effective list is this machine's plus cvENGINE's; a kind disabled here stays disabled.          |
| Self-update    | A ceiling. `off` here means never; `manual` here caps an Automatic setting from cvENGINE at Manual.         |

Settings from the server are data: the Sentinel checks every value, clips names and numbers, and ignores anything it
does not recognise. A profile set to light from cvENGINE stops OpenVAS work, but it cannot start or stop containers on
this machine; only `COMPOSE_PROFILES` does that.

## OpenVAS

On a full Sentinel, `docker-compose.yml` runs the Greenbone Community Edition stack beside the `sentinel` container:
gvmd, the OpenVAS scanner (`openvas-ospd`), notus (`openvas-openvasd`), their own Postgres and Redis, and the feed data
containers. The web interface (GSA) is not included. The daemon talks GMP to gvmd over a shared socket volume,
mounted read-only into the `sentinel` container.

### First start and readiness

The first start downloads the feeds: tens of GB, and it takes hours. Every other kind works meanwhile. The Sentinel
declares `openvas` only once gvmd is **ready**, which means:

- gvmd has created its socket and accepts this Sentinel's login,
- the "Full and fast" scan configuration, the "OpenVAS Default" scanner and the "All IANA assigned TCP" port list are
  loaded, and
- no feed is still syncing. This last check applies only until the Sentinel first sees the stack ready (it then
  writes an `openvas-ready` marker in the state volume), so a routine daily feed update does not take the capability
  away.

Readiness is checked again every 60 seconds while not ready and every 5 minutes once ready. When it changes, the log
says `capabilities changed: now ...` and the Sentinel registers again. The heartbeat tells cvENGINE whether the stack
can scan and why not (for example `GVM is still syncing its ... feed(s)`).

### How an OpenVAS task runs

- **Hosts:** each host entry must be one plain IP address the Sentinel may scan ([Scope](#scope-what-a-sentinel-never-scans)),
  at most 16 per task. Host names are labels only.
- **Alive test:** "Consider Alive", so a host that does not answer ping is still scanned.
- **Time budget:** cvENGINE's budget for the task, never more than `CVENGINE_OPENVAS_MAX_HOURS` (default 24) and never
  under 1 hour. A task that runs past it is stopped and what it found so far is reported with `partial: true`; with
  nothing found it fails.
- **Checks:** `max_checks` from the task (1 to 10, default 4), one host at a time.
- **Excluded families:** "Denial of Service" and "Brute force attacks" are always excluded, whatever the task says.
  The task can exclude more; a name that matches no family is logged as a warning.
- **Empty runs are errors:** a finished run that scanned no host is reported as an error naming the gvmd report id and
  gvmd's own errors (`gvmd scanned no host: ...`), not as a clean result. A report host counts as scanned only once
  gvmd finished it (it has an end time).
- **Unreadable results are errors:** when gvmd counts results for the task (in the task, the `get_results` answer or
  the report) but none could be read, the run is reported as an error (`gvmd counts results for the task but none
  could be read ...`), never as a host scanned clean, and its GVM task and report are kept until the Sentinel next
  starts.
- **Results:** results without a CVE are sent as address and port only; the body is kept under 20 MB, and a run whose
  CVE results had to be cut is marked partial. So is a run that hit the 5000-result cap, read fewer results than gvmd
  counts, or whose every result was unusable: a partial run never closes what earlier scans found.
- **Summary:** after every run the log has one line with the task's status, progress, report id, host count, results
  by severity, scan start and end, and gvmd's errors.
- **Cleanup:** the GVM task, target and report are deleted after the run, unless `CVENGINE_OPENVAS_KEEP_TASKS=1` (or
  its results could not be read, above). A
  task cvENGINE takes back, or a shutdown, stops and deletes the GVM task.
- **Leftovers:** once per start, when the stack first reports ready, the Sentinel sweeps `cvengine-sentinel-...` tasks
  and targets an earlier run left in gvmd. Finished ones are deleted; running ones are stopped and deleted only once
  they are older than the time budget ceiling. With `CVENGINE_OPENVAS_KEEP_TASKS=1`, finished ones are kept.

### The GVM login

The Greenbone containers start with the default login `admin`/`admin`. On first use the Sentinel replaces it:

1. It generates a password and writes the new login to a pending file
   (`/var/lib/cvengine-sentinel/openvas-credentials.json.pending`) before asking gvmd to change anything.
2. It gives `admin` the new password. If gvmd refuses that (some versions answer "Failed to find user"), it creates
   its own administrator login, `cvengine-sentinel`, instead, and then sets `admin`'s password to a random value that
   is saved nowhere. Either way the default `admin`/`admin` login stops working.
3. Once gvmd accepts the new login, it moves it to `/var/lib/cvengine-sentinel/openvas-credentials.json` (mode 600).

If gvmd later refuses the saved login (for example after its volume was recreated), the Sentinel sets up a new one
once by itself. To use a login you made by hand, save it to that file as `{"username": ..., "password": ...}` with mode 600. To recover `admin` after step 2, run `gvmd --user=admin --new-password=...` inside the `openvas-gvmd` container.

### Network

The OpenVAS services share a separate bridge network, `openvas_network`. It is **not** an internal Docker network:
the scanner's scans leave through it by this Docker host's default route, not through the `sentinel` container. It
publishes no ports, and the `sentinel` container is not on it (it reaches gvmd only through the socket volume). The
scanner container has `NET_RAW`, `NET_ADMIN` and unconfined seccomp and AppArmor profiles, as in Greenbone's own
compose file.

### Logs and feeds

- The scanner's own `openvas.log` lives in a volume. `openvas-configure` empties it once it passes 50 MB, when that
  container runs at `docker compose up -d`.
- The feed data containers follow Greenbone's moving `community` tags on purpose. A daily job
  (`scripts/refresh-feeds.sh`, installed with the updater) pulls them and recreates the ones that changed, so feeds
  stay fresh without a code update. It runs only when `openvas-gvmd` is running, no task is in flight and no update is
  running.
- The program images are pinned by digest. Greenbone publishes no version tags and replaces what `stable` points to,
  so an old pin can vanish from the registry (`artifact ... not found` on `docker compose up`).
  `./scripts/greenbone-digests.sh` checks every pin: `ok`, `CHANGED` (still exists, `stable` moved on) or `MISSING`
  (gone; exit 1). Replace the `sha256` of each `CHANGED` or `MISSING` image in `docker-compose.yml` with the digest it
  prints after `now=`.

## Updates

### The self-update setting

A Sentinel updates itself only under its self-update setting, chosen in cvENGINE per Sentinel (with an instance-wide
default, `GET/PUT sentinels/defaults`):

| Setting   | Behaviour                                                                                                              |
| --------- | ---------------------------------------------------------------------------------------------------------------------- |
| Off       | It never changes its own code.                                                                                         |
| Manual    | It updates only when an administrator presses **Update now** for it (or `PATCH agents/{id}` with `{"update": "now"}`). |
| Automatic | It updates at the next updater run after something new is on the branch.                                               |

`CVENGINE_SENTINEL_UPDATE` in `.env` is a ceiling on that setting, not just a starting value: `off` means this
Sentinel never self-updates, whatever cvENGINE says and even when an administrator presses **Update now**; `manual`
means it updates only when an administrator asks, even if cvENGINE says Automatic; `automatic` or unset lets
cvENGINE's setting apply. `scripts/update.sh --now`, run by a person on this machine, updates whatever the setting
says.

### cvENGINE asks for the newest version

By default cvENGINE keeps its Sentinels on the newest published build of this repository's `main` branch (Settings, Sentinels, **Keep Sentinels on the
newest version**, on unless an administrator turns it off; per Sentinel, set its self-update to Off to opt out). When a Sentinel reports a commit that is
behind the newest build, and that build speaks a contract version the server can run, cvENGINE asks it to update: the heartbeat answer's `update` object
carries `requested: true`, `target` (the newest commit) and `reason`. A client that does not know `target` ignores it. The contract version is unchanged:
this is an optional field of an object clients already read. At most one request per Sentinel every 6 hours, never while it holds a heavy task, never
to a build older than the one it runs, and a Sentinel that has not come back on a new build within the grace period (90 minutes) is flagged on the
Sentinels page and not asked again until an administrator presses **Update now**.

Who acts on the request:

| Setup | What happens |
| --- | --- |
| The host updater is installed (`scripts/install-updater.sh`, the default of `setup.sh`) | `scripts/update.sh` sees `requested` at its next run (hourly), builds, drains and swaps, exactly as for **Update now**. Nothing else to set. |
| `CVENGINE_SENTINEL_UPDATE_EXIT=1` and a supervisor that replaces the image on exit | The daemon takes no new work, waits for the running tasks (up to `CVENGINE_SENTINEL_DRAIN_TIMEOUT`, 1800 s; past that it goes back to work and keeps every task), then exits with **code 76**. `scripts/pull-on-exit.sh` (run it in the checkout) fast-forwards, pulls, builds and recreates the container on exit code 76 and nothing else; a registry-image setup can use any puller instead. The same target is not acted on twice within 6 hours, so a supervisor that brings nothing newer is not a restart loop. |
| The built-in scanner of a cvENGINE server | Not the daemon: the server asks its host (`scripts/update-watch.sh`, `scripts/scanner-update.sh`) to pull the newest image when the scanner is idle. |

Exit codes of the daemon: `0` stopped on request, `1` token refused or fatal, `3` heartbeats stopped (restart), `75` re-enrol (built-in scanner), `76` drained to be updated.
Command line equivalents (the interface is cvENGINE, these are the same actions): `scripts/update.sh --now` on this machine, `PATCH agents/{id}` with `{"update": "now"}` on the API, and `docker compose exec sentinel python3 -m client.control status` to see what the daemon was told.

### The updater

`scripts/update.sh` acts on the setting. It runs on the Docker host (Linux only), hourly, as the user who owns the
checkout. `./setup.sh` installs it by default; `./setup.sh --no-updater` leaves it out; `sudo ./scripts/install-updater.sh`
installs it later; `sudo ./scripts/install-updater.sh --remove` takes it away. On macOS and Windows, update by hand:
`git pull --ff-only && docker compose build && docker compose up -d`.

The updater never gets the Docker socket inside a container: it talks to the daemon only through
`docker compose exec sentinel python3 -m client.control` and files in the state volume.

### What one run does

1. **Who and when.** Run as root, it re-runs itself as the checkout's owner (`sudo -u`); any other user is refused.
   It needs `flock`; without it, it refuses to run. Only one run at a time: a second run (or the feed refresh) exits
   quietly and changes nothing.
2. **Setting.** Off (and no `--now`): it records `off` and stops.
3. **Preflight, before anything is drained.** It fetches `origin`, then refuses ("cannot update: ...", result
   `failed`, nothing drained) when the checkout is not on the update branch, has changes to tracked files, or has
   local commits that are not on `origin`. Untracked and git-ignored files (`.env`, `docker-compose.override.yml`) do
   not block it.
4. **Up to date?** "Deployed" is the commit in `.deployed-commit` (git-ignored), written only after a verified swap.
   When it equals `origin/main` (or the configured branch), the run records `ok`. An install from before this marker
   existed counts as deployed at HEAD when the running Sentinel reports HEAD as its version.
5. **Wanted?** Manual with nobody asking: it records `waiting` and stops. `--check` stops here and says what it would
   do.
6. **Build while the Sentinel keeps working.** It fast-forwards the checkout, pulls the images
   (`docker compose pull --ignore-buildable`, so a moved Greenbone pin reaches the stack) and builds the new Sentinel
   image. A failed pull or build puts the checkout back on the commit it had (`git reset --hard`) and records
   `failed`; the Sentinel never stopped taking work. It also deletes any `CVENGINE_SENTINEL_VERSION` line from `.env`.
7. **Drain.** It asks the Sentinel to stop taking tasks and waits up to `CVENGINE_SENTINEL_DRAIN_TIMEOUT` (default 1800
   seconds) for running tasks to finish. If one is still running at the deadline, it un-drains, records `waiting`
   ("update ... is built; a task is still running, will retry") and the Sentinel goes back to work.
8. **Swap.** `docker compose up -d`, then it waits up to 5 minutes for the new Sentinel to report the new commit as its
   version. Only then is `.deployed-commit` written and `updated` recorded. A failure here records `failed`, and
   because the marker was not written, the next run builds and swaps again instead of saying "up to date".

A drain expires on its own after two hours and is cleared whenever the Sentinel starts, so an updater that died half
way never leaves a Sentinel idle for good.

Note that while a long task runs (an OpenVAS scan can take hours), each hourly run with an update pending drains the
Sentinel for up to the drain timeout and then goes back to `waiting`. Raise `CVENGINE_SENTINEL_DRAIN_TIMEOUT` if you
prefer to wait longer per run, or lower it to drain for shorter periods.

### Results on the Sentinels page

Every run records when it ran and its result (`ok`, `waiting`, `off`, `updated` or `failed`, with a detail) in the
state volume, and the Sentinel reports it with its heartbeat. During a run the page also shows the update's progress
(`waiting`, `draining`, `updating`, `done` or `failed`).

| Updater state                    | What it means                                                                                                                                                          | What to do                                                                                                                                               |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `not installed`                  | No run recorded and no install marker. The Sentinel never updates itself.                                                                                              | `sudo ./scripts/install-updater.sh` in this checkout.                                                                                                    |
| `stopped`                        | Installed, but no run for more than 2.5 hours (the timer or cron stopped, the machine was off, or `update.sh` cannot start).                                           | `systemctl status cvengine-sentinel-update.timer` and `journalctl -u cvengine-sentinel-update`, or the cron log `/var/log/cvengine-sentinel-update.log`. |
| `running`, last result `failed`  | A step failed. The detail names it: a preflight refusal ("cannot update: ..."), `docker compose pull`, `build` or `up`, or the new Sentinel not reporting its version. | Fix what the detail says. The next run tries again from the start.                                                                                       |
| `running`, last result `waiting` | An update is available and either the setting is Manual and nobody asked, or the image is built and a task was still running at the drain deadline.                    | Press **Update now**, set Automatic, or wait for the next run.                                                                                           |
| `running`, last result `off`     | Self-update is Off for this Sentinel.                                                                                                                                  | Set it to Manual or Automatic in cvENGINE, and remove `CVENGINE_SENTINEL_UPDATE=off` from `.env` if it is there.                                         |

### install-updater.sh

```bash
sudo ./scripts/install-updater.sh               # install
sudo ./scripts/install-updater.sh --remove      # remove
sudo ./scripts/install-updater.sh --allow-root  # install although root owns the checkout
```

- Linux only. The checkout path may contain only letters, digits and `/ . _ -`.
- The jobs run as the checkout's owner, who must be in the `docker` group (it warns when not:
  `usermod -aG docker USER`). A root-owned checkout is refused unless you pass `--allow-root`, because the updater
  would then run as root every hour. Run as a normal user, it re-runs itself with `sudo`.
- With systemd it installs `cvengine-sentinel-update.timer` (10 minutes after boot, then hourly, with up to 5 minutes
  of random delay; each run may take up to 3 hours) and `cvengine-sentinel-feeds.timer` (daily). The services run
  with `NoNewPrivileges`, `PrivateTmp` and `ProtectSystem=full`. Logs:
  `journalctl -u cvengine-sentinel-update -u cvengine-sentinel-feeds`.
- Without systemd it writes `/etc/cron.d/cvengine-sentinel-update` (the update at minute 17 of every hour, the feeds
  at 04:43) and logs to `/var/log/cvengine-sentinel-update.log`, owned by the checkout's owner, mode 640. Installing
  one kind removes the other.
- It writes `CVENGINE_SENTINEL_UPDATER=installed` into `.env` (in place, keeping the file's owner and mode), so
  cvENGINE shows the updater as installed once the container is created or recreated (`docker compose up -d`); when
  the Sentinel is already running it also tells it directly. `--remove` deletes that line and tells the Sentinel.

### Updater settings

`CVENGINE_SENTINEL_DRAIN_TIMEOUT` and `CVENGINE_SENTINEL_BRANCH` are read by `scripts/update.sh` from its own
environment, not from `.env`. With systemd:

```bash
sudo systemctl edit cvengine-sentinel-update.service
```

and add under `[Service]`:

```ini
[Service]
Environment=CVENGINE_SENTINEL_DRAIN_TIMEOUT=7200
```

With cron, put the variable before `./scripts/update.sh` on the line in `/etc/cron.d/cvengine-sentinel-update`.
Re-running `install-updater.sh` rewrites that file (a `systemctl edit` drop-in survives it).

## Runtime behaviour

### Polling, heartbeat and results

- The Sentinel long-polls for work (15 seconds per call) and heartbeats every 60 seconds; the heartbeat keeps its
  leases alive and carries its version, updater state and, on a full Sentinel, the GVM stack's readiness.
- When cvENGINE answers a poll with no task and a `retry_after_seconds` above one second (it is holding the work for a
  less loaded Sentinel, or this one is over a limit), the Sentinel waits that long (at most 30 seconds, with a little
  jitter, and a stop request ends the wait) before asking again, so it is not parked by the rate limit. A full long poll
  is answered with one second and is asked again at once.
- A task the server takes back (it is no longer in the heartbeat's lease list) is killed and not reported.
- A result that fails to post (network error, 5xx, 429) is retried a few times within 20 seconds. If cvENGINE still
  does not answer (an update, a restart, an outage) the finished result goes to the **spool** and the task slot is free
  again: one file per task under `spool/` next to the token file (the `sentinel-state` volume, mode 0600, written
  atomically). The spool is delivered oldest first with a backoff that doubles to 60 seconds, for as long as
  `CVENGINE_SENTINEL_SPOOL_HOURS` (default 6) allows, and each entry is deleted when cvENGINE answers 2xx (which includes
  \"already have it\") or refuses it for good (400, 409, 410; one log line). A Sentinel that starts with a spool, and
  every heartbeat, delivers it before anything else, and a task whose result is held still counts as running in the
  heartbeat so the server does not end it. An entry older than the window is no longer offered (the server has long
  since given the task up) and is kept in `spool/expired/` for you; `expired/` is the first thing dropped when the
  directory goes over `CVENGINE_SENTINEL_SPOOL_MAX_MB` (default 256), and a result that still does not fit is refused,
  which releases the task as before. `CVENGINE_SENTINEL_SPOOL_HOURS=0` turns the spool off. The heartbeat carries
  `info.spool` (`count`, `oldest_seconds`) while results are held, which the Sentinels page shows; the field is
  optional and nothing in the contract changes.
- While cvENGINE is unreachable the heartbeat and the poll keep retrying with a capped backoff and log the outage once,
  then at most every 10 minutes, and once more when it ends.
- A malformed reply or task from the server is logged and skipped, with backoff; it never stops the daemon.
- If the server is unreachable at start, the Sentinel keeps running and retries its registration at every heartbeat.
- If the token cannot be saved after bootstrap (a read-only or full volume), the Sentinel keeps running with it in
  memory and retries the save at every heartbeat. Fix the volume before the container restarts, or it will need a new
  blob.
- The server address must be `https` (unless `CVENGINE_SENTINEL_ALLOW_INSECURE=1`), with no user name, password,
  query or fragment. Redirects are never followed: a server address that answers with a redirect fails with a clear
  error, so give the final `https` address. A saved token whose address breaks these rules stops the Sentinel at
  start with an error naming the file.

### Health check

`python3 -m client.control health` exits 0 when the daemon wrote its status within the last 180 seconds, else exits 1
and prints `unhealthy: <reason>`. A busy Sentinel is healthy. The daemon rewrites its status at every heartbeat and
whenever a task starts or ends. Docker shows the result in `docker compose ps`; it does not restart an unhealthy
container on its own. The image declares the same check (`HEALTHCHECK`), so a container started without the compose file has it too.

For the built-in scanner the check is stricter: it also fails when no heartbeat has reached the server for 180 seconds (counted from the start
while there has been none yet). It passes while the scanner waits for its first enrollment. `python3 -m client.control heartbeat` answers only
"has a heartbeat reached the server in the last 180 seconds": cvENGINE's updater asks it before it keeps a new scanner image.

With the watchdog on (the default) the check also fails when the watchdog has not ticked for 90 seconds, or the heartbeat loop for 420 seconds, or the poll
loop for 480 seconds, for every Sentinel; the watchdog itself ends a stuck process (exit code 3) so the restart policy restarts it.
See [docs/WATCHDOG.md](docs/WATCHDOG.md) for the rules, the deadline table and `autoheal` / systemd for a setup that restarts on `unhealthy`.

### Status files

The `sentinel-state` volume (`/var/lib/cvengine-sentinel` in the container) holds:

| File                                                             | Contents                                                                                                    |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `token.json`                                                     | This Sentinel's token and server address (mode 600).                                                        |
| `openvas-credentials.json` (and `.pending` during a first start) | The GVM login (mode 600).                                                                                   |
| `openvas-ready`                                                  | Marker: the GVM stack has been fully ready once.                                                            |
| `control.json`                                                   | The daemon's status for the updater (version, tasks in flight, drain state, effective self-update setting). |
| `update.json`                                                    | The progress of the current or last update.                                                                 |
| `updater.json`                                                   | When the updater last ran and how it went.                                                                  |
| `drain`                                                          | Present while the updater has asked the Sentinel to take no new tasks (expires after 2 hours).              |
| `blob.spent` | The built-in scanner only: the sha256 of the last enrollment blob it redeemed or the server refused, so it never tries one twice. |

### Files the checkout keeps out of git

`.gitignore` ignores `.env` and every `.env*` file except `.env.example` (so `.env.bak.*` backups too),
`.deployed-commit`, `.deployed-commit.tmp`, `.update.lock`, `docker-compose.override.yml` and Python caches.
`.dockerignore` keeps `.env*`, tests, docs and git history out of the image build; only git's `HEAD` and refs go in,
so the image can stamp its commit.

### Version

The image stamps the commit it was built from (the first 12 characters of HEAD) into itself, and that is the version
the Sentinels page shows. An image built from a download with no `.git` reports no version unless
`CVENGINE_SENTINEL_VERSION` is set in the container's environment.

### The published image

Every push to `main` and every `v*` tag builds the image for amd64 and arm64 and pushes it to `ghcr.io/hevnsnt/cvengine-sentinel`
(`.github/workflows/publish.yml`), with an SBOM and build provenance attached to each platform. It is tagged `sha-<version>` (the
12-character commit the client reports), `main` for the newest build of `main`, and `X.Y.Z` and `X.Y` for a tag `vX.Y.Z`; the run's summary
prints the digest. cvENGINE's built-in scanner pins this image by digest (`scanner.lock.json` in the cvENGINE repository), so a tag moving
never changes what an install runs. A tag cut by the *Tag a release* workflow does not start this one (GitHub never starts a workflow for
an event its own token made), so publish such a tag with Actions, Publish, Run workflow on the tag. A Sentinel set up with `setup.sh` still
builds its own image from this checkout.

The build is reproducible from the commit: the base image is pinned by digest, every tool by version and checksum, and WPScan with every gem it
needs at the versions and checksums in `docker/wpscan/Gemfile.lock` (regenerate it with `BUNDLE_FORCE_RUBY_PLATFORM=true bundle lock` in
`docker/wpscan` when `WPSCAN_VERSION` changes). Nothing is updated at build time: WPScan fetches its vulnerability database on the first run that
needs it, and the nuclei templates are the pinned release. The image has no git, no Go toolchain, no GVM stack and no docker socket; the image
workflow checks that on every pull request and the publish workflow on what it pushed.

### Checking that the tools are the newest

`python3 scripts/check_tool_versions.py` reads every pin of the image (the `ARG ..._VERSION` lines of the Dockerfile, the `name==version` lines of
`requirements.txt` and the test extra of `pyproject.toml`, the pip bootstrap pins, the Ubuntu base image digest and the Greenbone image digests in
`docker-compose.yml`), asks each upstream for its newest release (GitHub, PyPI, proxy.golang.org, go.dev, rubygems.org, nmap.org, Docker Hub, the
Greenbone registry) and prints a table: tool, pinned, latest, and whether it is current or behind. `--json` prints the rows as JSON, `--root DIR`
reads another checkout, and `--fail-if-behind` exits 1 when a tool is behind, a pin cannot be found, a version `ARG` has no known upstream or a
newest version cannot be read (it fails closed: a renamed pin or an unreachable site must not pass a release). The Chromium build of Playwright
is shown as a warning only, because it moves with the Playwright pin.

CI runs it in three places (`.github/workflows/tool-releases.yml`, `tag-release.yml`): every week it keeps one open issue listing what is behind;
every pull request gets a warning for each tool that is behind (never a failure); and *Tag a release* refuses to tag while a tool is behind,
unless the run ticks `tools_reviewed` after someone looked at the newer version and decided to wait (say why in the release notes). The tests
(`client/tests/test_tool_versions.py`) feed recorded upstream answers and never use the network. A new version `ARG` in the Dockerfile needs a row in
`DOCKERFILE_ARGS` in the script (its upstream), or the check fails.

## The built-in scanner

cvENGINE runs this image next to the server as its built-in scanner, shown as **CVEngine Scanner** (the `scanner` service of cvENGINE's own
`docker-compose.yml`, pinned there by digest). It is a Sentinel like any other, with `CVENGINE_SENTINEL_BUILTIN=1`, which changes these things:

- **Name and updates.** It is always called CVEngine Scanner, and its self-update setting is always `off`: cvENGINE's updater replaces its image,
  and rolls back to the previous image if the new one does not heartbeat.
- **No OpenVAS.** It has no GVM stack and its capability policy ships with OpenVAS denied, so it never declares the `openvas` kind. cvENGINE runs no OpenVAS of its own either: OpenVAS runs on a Full Sentinel with `COMPOSE_PROFILES=openvas` ([OpenVAS](#openvas)).
- **Enrollment with no person.** With no saved token it reads the blob from `CVENGINE_SENTINEL_BLOB_FILE`, which the server writes into a volume
  only the two share, and waits for it (healthy meanwhile). When the server stops accepting its token (expired or revoked) it forgets the token
  and enrols again with the next blob the server writes. A blob it redeemed, or one the server refused, is never tried twice; it waits for the
  file to change. The blob is never logged.
- **It restarts itself when its heartbeats stop.** When none has reached the server for 180 seconds it stops with exit code 3, and compose
  (`restart: unless-stopped`) starts a fresh process. Docker never restarts a container only because its health check fails.
- **What it reports.** `info.builtin = true` and `info.features` (`secret_read`, `vantage`). The server decides from the enrollment whether a
  Sentinel is its built-in scanner, never from this; the features tell it this image can do the two things below.
- **Signed-in nuclei.** A nuclei task marked `signed_in` names a stored sign-in. Only the built-in scanner runs it: it reads the credential once with
  `POST /api/v1/sentinel/tasks/<id>/secret`, writes it as a nuclei secrets file (mode 600, in a private directory on `/dev/shm`), runs nuclei with
  `-sf` and `-dr` (no redirects), then overwrites and removes the file. Any value of it that a finding echoes is replaced by `***`. Every other
  Sentinel refuses such a task, so it is never run signed out (`client/signed_in.py`).
- **The server's vantage point.** cvENGINE sends it, in its settings, the egress proxy of Settings > Proxy and the private networks the server's own
  scans may reach (the tailnet when cvENGINE's Tailscale sidecar is on, private space when `CVENGINE_ALLOW_PRIVATE_TARGETS` is set). It sends
  nuclei, WPScan, testssl.sh and wafw00f through that proxy, as the server does (nmap, naabu and the UDP sweep use raw sockets and go direct), and
  never directly when no proxy suits a tool. Its scope floor lets it scan those private networks and nothing else of private space. Only the built-in
  scanner applies these settings; on any other Sentinel they are ignored, so a server can never send it through a proxy or unlock private space for it.
  The proxy URLs can carry a login and are never logged (`client/egress.py`).

## Testing

Run the client tests from the checkout (CI uses Python 3.13 and 3.14 for them, and 3.12, 3.13 and 3.14 for the library's), with `requirements.txt` installed:

```bash
pip install -r requirements.txt ".[test]"
python -m unittest discover -s client/tests -t .
python -m unittest discover -s cvengine_scanner/tests -t .
```

The second command runs the scanner library's tests (see "The scanner library" below).

The tests never touch the host's gvmd, credentials or tool binaries. CI (`.github/workflows/`) runs them on every
pull request and push to `main` (the client on Python 3.13 and 3.14, the `cvengine_scanner` library on 3.12, 3.13 and 3.14: the
library's floor is 3.12 because the cvENGINE server imports it), runs the contract's own self-tests and checks that the commit sha the server pins is on `main` (it
retries the fetch three times and fails when the server's `web/requirements.txt` cannot be fetched; while the server still pins a tag it passes),
installs the library by git tag and by commit sha the way the server pins it, checks the shell scripts with `sh -n`, `bash -n` and
shellcheck, validates `docker-compose.yml` with and without the `openvas` profile, and builds the image and
smoke-tests it.

### The scanner library

`cvengine_scanner/` (see `pyproject.toml`) is the one copy of the scanner code that the client and the cvENGINE server both
import. The server keeps no copy of its own. It holds:

- `flags.py`, the scan policy: the nmap and nuclei flag builders, the reviewed NSE scripts, `-etags dos` on every nuclei
  run, the UDP port list, the probe ports and the per-task limits;
- `parsers.py` and `nmap.py`, the readers of tool output (nmap XML and its service inventory, naabu, nuclei JSON lines,
  testssl.sh, wafw00f);
- `fingerprint.py`, `cms.py`, `versions.py` and `soft404.py`, the pure readers of a web response (technologies and their
  versions, which CMS a page is, whether a "200" is really a not-found page). They never fetch anything: the server does
  the fetching and hands them what it read;
- `scope.py`, the Sentinel's own scope floor;
- `contract/sentinel_contract.json`, the **single source of truth** for the result contract (the server keeps no copy and reads it from
  its install of this library), with the fixtures for each kind in `fixtures/`. The fixtures under `fixtures/results/v1/` are frozen: they are what a Sentinel of
  contract version 1 sent, and their hashes are checked.

It needs Python 3.12 or newer, and its one dependency is `xmltodict`. Everything in it is pure: no subprocess, no network
and no Django. The image installs it with `pip install`.

**Releases.** The version is the git tag (`setuptools-scm`), so a release is just an annotated tag on `main`:

```bash
git tag -a v1.4.0 -m "cvengine-scanner 1.4.0" && git push origin v1.4.0
```

Or, without a local clone, run the **Tag a release** workflow (Actions, `tag-release.yml`) with the tag and, optionally, the commit
of `main` to tag. It refuses a tag that is not `vMAJOR.MINOR.PATCH`, a commit that is not on `main`, and a tag that already exists.

Use `vMAJOR.MINOR.PATCH`. Raise MAJOR when a function the server calls changes or goes away, and MINOR for a new kind or
function. A tag is never moved or reused. The server pins the tag in its `web/requirements.txt`, and its Docker build and its
CI both install it from there:

```
cvengine-scanner @ git+https://github.com/hevnsnt/cvENGINE-sentinel@v1.4.0
```

The server now pins a **commit sha of `main`** instead (a tag is a release and needs the owner's approval; a sha is not a version change):

```
cvengine-scanner @ git+https://github.com/hevnsnt/cvENGINE-sentinel@<40 character sha of a main commit>
```

**How a contract change lands.** Sentinel pull request first: change `contract/sentinel_contract.json` and its fixtures here, with
`cvengine_scanner/tests/test_contract.py` green, and merge it to `main`. Then a server pull request bumps the sha in
`web/requirements.txt` to that merge commit and carries the server side (the broker's limits and cleaners, its fixtures). The CI job
"Contract self-tests and the server's pinned sha is on main" runs the self-tests here and checks that the server's pin is an ancestor of (or equal
to) `main`, so it never goes red because of the server's pull request, and a server pin to an unmerged commit is caught. To ship any other
library change to the server, merge it here, then bump that sha on the server in a pull request of its own.

### Testing OpenVAS

`.github/workflows/openvas-integration.yml` checks the Greenbone pins, brings up the pinned gvmd (without feeds) and
runs the login bootstrap and readiness check against it with the pinned `python-gvm`. It runs when the OpenVAS client,
the compose pins, the image or `requirements.txt` change, weekly, and on demand. GitHub disables scheduled workflows
after 60 days without repository activity, so re-enable it from the Actions tab on a quiet repository. It does not run
a scan: that needs the feeds.

To prove the login bootstrap on a machine with Docker, on a **fresh** stack only:

```bash
docker compose up -d --build
docker compose exec sentinel python3 scripts/ci_openvas_bootstrap.py   # logs in, saves the login, prints whether GVM can scan yet
```

The script logs in with the default `admin`/`admin` login. Once the Sentinel has replaced that login (it does so at
its first readiness check, as soon as gvmd's socket exists), the script fails with "the default GVM login did not
work" and changes nothing. On a stack that is already set up, ask for readiness instead:

```bash
docker compose exec sentinel python3 -c "from client import openvas; print(openvas.readiness())"
docker compose logs -f sentinel     # "capabilities changed: now ..., openvas" once the feeds have finished syncing
```

Then dispatch an OpenVAS task from cvENGINE (Hosts, run an OpenVAS scan) and watch it finish. A task that arrives
before the stack is ready fails with "GVM is still syncing its ... feed(s)".

## Security model

### What is assumed

- **The cvENGINE server is not trusted** with this machine. A bug or a compromise there must not be able to make the
  Sentinel scan the machine it runs on, its local services, the cloud metadata service, or private networks it was not
  set up for, or run anything other than the listed tools.
- **Scan targets are not trusted.** Their responses are parsed with size limits; a hostile target can waste a task's
  time budget but not grow the Sentinel's memory or result size without bound.
- The connection to cvENGINE is `https` with certificate verification, and redirects are never followed.

### What the Sentinel enforces itself

- The scope floor in [Scope](#scope-what-a-sentinel-never-scans), for every tool, including OpenVAS.
- This machine's policy as ceilings: network (internal only if `.env` says so), disabled kinds (a veto), self-update
  (`off` or `manual` here cannot be raised).
- Only known task kinds, each run as a fixed argument list with no shell; a kind it does not run now is refused.
- nuclei never runs denial-of-service templates; a nuclei task that names the server's approved template bundle (`bundle_sha256`) runs on exactly
  that set: the bundle is downloaded from this Sentinel's own server, its hash checked, unpacked defensively (regular files and directories only,
  every path inside the target, bounded size) and kept in the state volume; if it cannot be fetched or does not verify, the task is an error and
  nothing unapproved runs. A task under the read-only policy that names no bundle is an error too; a task with no policy uses the pinned templates
  in the image. OpenVAS never runs the Denial of Service or Brute force families.
- The container runs as an unprivileged user (uid 10001). Raw sockets come from file capabilities on nmap and naabu only; a one-shot
  `sentinel-init` service (root, no capabilities, no network) hands an older state volume to that user before the Sentinel starts.
- A tool that exits with an error or is killed is reported as an error, never as an empty result; a result over the server's 24 MB limit is
  reported as an error instead of being sent; the heartbeat lists the ids of the tasks this Sentinel is running.
- Bounded output, findings and result sizes; whole process groups killed on stop.
- Secrets are never logged: the token, the GVM password, the blob, the WPScan API token.

What it does not cover: a host name is resolved when it is checked, and nuclei, the UDP sweep, WPScan, wafw00f and the node2shell detector resolve it
again when they run, so a DNS answer that changes in between is not caught (nmap and naabu get the checked address).
"Its own addresses" are those its host name resolves to, not necessarily every address of the machine.

### What the operator must do

- **Treat the `docker` group as root.** Anyone in it, including the updater's user, controls the machine.
- **Protect the code source.** Updates are not signature-checked: the updater builds and runs whatever is on
  `origin/main` (or the configured branch) of this checkout's `origin` remote. Anyone who can push there reaches every
  Automatic Sentinel within about an hour. Keep `origin` pointed at
  `https://github.com/hevnsnt/cvengine-sentinel.git` (or a fork you control), protect that repository, and use Manual
  or Off (`CVENGINE_SENTINEL_UPDATE=manual`) where that is not enough.
- **Mind other unpinned inputs.** The nuclei templates in the image are a pinned release (checksum-verified at build) and are not
  refreshed at start (`CVENGINE_SENTINEL_UPDATE_TEMPLATES=1` opts in); the Greenbone feed images follow moving tags; Python packages
  are pinned by version, not hash.
- **Set `CVENGINE_SENTINEL_NETWORK=internal` only on machines meant to scan private space.** An internal Sentinel may
  scan any private address, which includes this Docker host's bridge gateway and, with host networking, the
  machine's LAN neighbours.
- **Disable what you do not want run here** with `CVENGINE_SENTINEL_DISABLE`.
- **Keep `.env` private.** `setup.sh` writes it with mode 600; if you write it by hand, use `install -m 600` or
  `chmod 600 .env`. Remove the blob and the `.env.bak.*` backups after the first start.

### Where secrets live

| Secret            | Where                                                                              | Lifetime                                                                              |
| ----------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Provisioning blob | `.env` (and `.env.bak.*`), mode 600                                                | Single use, expires 30 minutes after it was generated. Ignored once a token is saved. |
| Sentinel token    | `token.json` in the `sentinel-state` volume, mode 600                              | Until the Sentinel is revoked in cvENGINE.                                            |
| GVM login         | `openvas-credentials.json` in the `sentinel-state` volume, mode 600                | Until gvmd's volume is recreated (the Sentinel then makes a new one).                 |
| WPScan API token  | Sent by cvENGINE with each `wpscan` task; passed to WPScan in its environment only | One task.                                                                             |
| bbot discovery API keys | Read once per `bbot_discovery` task from cvENGINE (only if this Sentinel reports `bbot_keys` and is not opted out); `keys.yml`, mode 600, in a private temp directory; masked in every batch and result | One task; the directory is removed when the run ends, and any left by a crash at the next start. |
