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
| `CVENGINE_SENTINEL_NAME`                                                                                        | No               | the container's host name                             | The name on the Sentinels page. Reported to cvENGINE only when set, so a rename made in cvENGINE sticks across container recreates unless this is set.                                            | daemon                                                                    |
| `COMPOSE_PROFILES`                                                                                              | No               | unset: light (no OpenVAS containers)                  | `openvas` starts the OpenVAS/GVM stack (full). `setup.sh` and `.env.example` set it to `openvas`.                                                                                                 | Docker Compose                                                            |
| `CVENGINE_SENTINEL_PROFILE`                                                                                     | No               | unset                                                 | `full` or `light`. `light` never runs OpenVAS. Keep it in step with `COMPOSE_PROFILES`; `setup.sh` writes both.                                                                                   | daemon                                                                    |
| `CVENGINE_SENTINEL_NETWORK`                                                                                     | No               | `external`                                            | `internal` lets this Sentinel scan private addresses and run `discover`. Anything else means external. A ceiling: cvENGINE can lower it to external, never raise it.                              | daemon                                                                    |
| `CVENGINE_SENTINEL_DISABLE`                                                                                     | No               | none                                                  | Comma-separated kinds this Sentinel never runs (for example `openvas,wpscan`). Case-insensitive; an unknown entry is ignored and logged once. A veto: cvENGINE can add kinds, never remove these. | daemon                                                                    |
| `CVENGINE_SENTINEL_MAX_CONCURRENT`                                                                              | No               | detected from the CPUs the container may use          | How many tasks run at once, OpenVAS not counted (see [Concurrency](#concurrency)). Capped at 10; a value that is not a number means 1.                                                            | daemon                                                                    |
| `CVENGINE_SENTINEL_UPDATE`                                                                                      | No               | unset (cvENGINE decides)                              | `off`, `manual` or `automatic`. A ceiling on the self-update setting (see [Updates](#updates)).                                                                                                   | daemon, and `scripts/update.sh` through it                                |
| `CVENGINE_SENTINEL_UPDATER`                                                                                     | No               | unset                                                 | `installed` tells cvENGINE an updater exists before its first run. `install-updater.sh` writes it, and `--remove` deletes it. Do not set it by hand.                                              | daemon                                                                    |
| `CVENGINE_SENTINEL_ALLOW_INSECURE`                                                                              | No               | unset                                                 | Exactly `1` allows a plain `http` server address (lab use only).                                                                                                                                  | daemon                                                                    |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`                                                                         | No               | unset                                                 | A proxy for the Sentinel's connection to cvENGINE. testssl.sh and WPScan run with a minimal environment that leaves these out.                                                                    | daemon (through `requests`)                                               |
| `CVENGINE_OPENVAS_KEEP_TASKS`                                                                                   | No               | unset                                                 | `1` (or `true`, `yes`, `on`) keeps each GVM task, target and report after a run, to investigate a scan.                                                                                           | daemon (`client/openvas.py`)                                              |
| `CVENGINE_SENTINEL_UPDATE_TEMPLATES`                                                                            | No               | empty (no refresh)                                    | `1` refreshes the nuclei templates baked into the image at every start (two minute limit), for tasks without the server's template policy                                                         | `docker-entrypoint.sh` (not passed by compose; set it in a compose override if you want it)|
| `OPENVAS_LOG_LEVEL`                                                                                             | No               | `127`                                                 | The OpenVAS scanner's own log level. `128` is debug (about 50 MB for one 40 minute scan of one host); set it only while debugging, then `docker compose up -d`.                                   | Docker Compose (`openvas-configure`)                                      |
| `CVENGINE_OPENVAS_MAX_HOURS`                                                                                    | No               | `24`                                                  | This machine's ceiling on one OpenVAS task's time budget, in hours (at least 1). **Not passed by compose.**                                                                                       | daemon                                                                    |
| `CVENGINE_SENTINEL_VERSION`                                                                                     | No               | the commit stamped into the image                     | Used only when the image has no stamp (built without `.git`). **Not passed by compose**, and `scripts/update.sh` deletes the line from `.env`.                                                    | daemon                                                                    |
| `CVENGINE_SENTINEL_DRAIN_TIMEOUT`                                                                               | No               | `1800`                                                | Seconds an update waits for running tasks. Must be a whole number above 0. **Not read from `.env`**: set it in the updater's environment (see [Updater settings](#updater-settings)).             | `scripts/update.sh`                                                       |
| `CVENGINE_SENTINEL_BRANCH`                                                                                      | No               | `main`                                                | The branch the updater follows; the checkout must be on it. **Not read from `.env`**: set it in the updater's environment.                                                                        | `scripts/update.sh`                                                       |
| `CVENGINE_SENTINEL_TOKEN_FILE`                                                                                  | No               | `/var/lib/cvengine-sentinel/token.json`               | Development and tests only: where the token is saved. The status files live in the same directory. Not passed by compose.                                                                         | daemon                                                                    |
| `CVENGINE_OPENVAS_SOCKET`                                                                                       | No               | `/run/gvmd/gvmd.sock`                                 | Development, tests and CI only: gvmd's socket. Not passed by compose.                                                                                                                             | daemon                                                                    |
| `CVENGINE_OPENVAS_CREDENTIALS_FILE`                                                                             | No               | `/var/lib/cvengine-sentinel/openvas-credentials.json` | Development, tests and CI only: the saved GVM login. Not passed by compose.                                                                                                                       | daemon                                                                    |
| `CVENGINE_NMAP_BIN`, `CVENGINE_NAABU_BIN`, `CVENGINE_NUCLEI_BIN`, `CVENGINE_TESTSSL_BIN`, `CVENGINE_WPSCAN_BIN` | No               | `nmap`, `naabu`, `nuclei`, `testssl.sh`, `wpscan`     | Development only: run a tool from another path. Not passed by compose.                                                                                                                            | daemon (`client/tools.py`)                                                |
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
| Volumes                     | `sentinel-state` at `/var/lib/cvengine-sentinel`; gvmd's socket volume read-only at `/run/gvmd` | The token, GVM login and status files; the GMP socket.                                                     |
| Ports                       | none published                                                                                  | Nothing listens for inbound connections.                                                                   |

## What a Sentinel runs

A Sentinel runs only these task kinds, each with its own tool built into the image. Every tool call is a fixed
argument list plus the task's validated targets: no shell, and no server text is ever read as a flag or a command.

| Kind                                             | Tool                                                                             | Target the task names                                                         | Notes                                                                                                                                                                                                           |
| ------------------------------------------------ | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nmap`                                           | nmap (`-Pn -sV -O --top-ports 1000`, no reverse DNS)                             | up to 64 IP addresses or host names                                           | A host name is replaced by the first IPv4 address it resolved to. Time limit: 90 s per host, at least 600 s, at most 3600 s.                                                                                    |
| `naabu`                                          | naabu (all TCP ports, 1000 packets/s)                                            | up to 64 IP addresses or host names                                           | Names resolved as for nmap. Time limit 900 s.                                                                                                                                                                   |
| `nuclei_light`, `nuclei_targeted`, `nuclei_deep` | nuclei                                                                           | up to 64 hosts, `host:port`, `[ipv6]:port` or `http(s)` URLs                  | The same run for all three; cvENGINE picks the tags and severities. Denial-of-service templates never run (`-etags dos`). A tag filter with no usable tag is refused. At most 5000 findings. Time limit 3600 s. |
| `testssl`                                        | testssl.sh                                                                       | one host name (for SNI), one IP address, one port, optional STARTTLS protocol | Connects to the IP only (`--nodns none`). A timeout is reported as an error. Time limit 900 s.                                                                                                                  |
| `nmap_udp`                                       | nmap `-sU`                                                                       | one IP address or host name                                                   | 18 curated UDP ports at 20 packets/s. Time limit 1500 s.                                                                                                                                                        |
| `wpscan`                                         | WPScan                                                                           | one `http(s)` URL                                                             | Passive plugin and theme detection. A WPScan API token, when cvENGINE sends one with the task, is passed in the environment, never on the command line or in a log. Time limit 900 s.                           |
| `openvas`                                        | OpenVAS/GVM over GMP                                                             | up to 16 plain IP addresses                                                   | Full profile only, and only once the GVM stack is ready. See [OpenVAS](#openvas).                                                                                                                               |
| `discover`                                       | nmap ping sweep (`-sn`: ARP on the local segment, ICMP and a few TCP/UDP probes) | one private IPv4 network, at most 512 addresses                               | Internal Sentinels only: `CVENGINE_SENTINEL_NETWORK=internal` on this machine, and not lowered to external by cvENGINE. ARP discovery needs [host networking](#host-networking).                                |

A task of a kind this Sentinel does not run right now (disabled, OpenVAS on a light profile or without a ready GVM
stack, `discover` on a non-internal Sentinel) is refused with an error result, even if the server sends it.

### Concurrency

`max_concurrent` (from `CVENGINE_SENTINEL_MAX_CONCURRENT`, cvENGINE, or the detected CPU count, at most 10) is how many
non-OpenVAS tasks run at once. OpenVAS has its own slot: it does not count against `max_concurrent`, and at most one
OpenVAS task runs at a time.

### Limits on output

A tool that prints more than 64 MB is stopped and the task reported as an error. Nuclei findings have their fields
clipped. A testssl.sh or WPScan report over 8 MB is not sent (a testssl.sh task then reports no findings). Stopping a task (time limit, server took it back,
shutdown) kills the tool's whole process group.

## Scope: what a Sentinel never scans

cvENGINE decides what is in scope for a project. The Sentinel also enforces its own floor (`client/scope.py`), so a
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
  gvmd's own errors (`gvmd scanned no host: ...`), not as a clean result.
- **Results:** results without a CVE are sent as address and port only; the body is kept under 20 MB, and a run whose
  CVE results had to be cut is marked partial.
- **Summary:** after every run the log has one line with the task's status, progress, report id, host count, results
  by severity, scan start and end, and gvmd's errors.
- **Cleanup:** the GVM task, target and report are deleted after the run, unless `CVENGINE_OPENVAS_KEEP_TASKS=1`. A
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
- A task the server takes back (it is no longer in the heartbeat's lease list) is killed and not reported.
- A result that fails to post is retried up to 5 times within 2 minutes (network errors, 5xx and 429, with backoff).
  If it still cannot be delivered, the Sentinel releases the task so cvENGINE can run it again. Other refusals (400,
  409, 410) are final.
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
container on its own.

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

### Files the checkout keeps out of git

`.gitignore` ignores `.env` and every `.env*` file except `.env.example` (so `.env.bak.*` backups too),
`.deployed-commit`, `.deployed-commit.tmp`, `.update.lock`, `docker-compose.override.yml` and Python caches.
`.dockerignore` keeps `.env*`, tests, docs and git history out of the image build; only git's `HEAD` and refs go in,
so the image can stamp its commit.

### Version

The image stamps the commit it was built from (the first 12 characters of HEAD) into itself, and that is the version
the Sentinels page shows. An image built from a download with no `.git` reports no version unless
`CVENGINE_SENTINEL_VERSION` is set in the container's environment.

## Testing

Run the client tests from the checkout (CI uses Python 3.13 and 3.14), with `requirements.txt` installed:

```bash
pip install -r requirements.txt
python -m unittest discover -s client/tests -t .
```

The tests never touch the host's gvmd, credentials or tool binaries. CI (`.github/workflows/`) runs them on every
pull request and push to `main` (Python 3.13 and 3.14), checks the shell scripts with `sh -n`, `bash -n` and
shellcheck, validates `docker-compose.yml` with and without the `openvas` profile, and builds the image and
smoke-tests it.

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

What it does not cover: a host name is resolved when it is checked, and nuclei, the UDP sweep and WPScan resolve it
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
