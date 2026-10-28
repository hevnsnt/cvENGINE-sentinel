# CVEngine Sentinel

A Sentinel is a Docker Compose stack you run on a machine on your own network. It registers itself with your
CVEngine instance, pulls scan-stage work off a project's queue (nmap, naabu, nuclei, testssl.sh, a UDP exposure
sweep, WPScan, and OpenVAS/GVM), runs it locally, and reports typed results back. There is no separate download or
per-OS package: this repository is the whole client, and it runs identically on Linux, macOS and Windows hosts
through Docker. Running one or more Sentinels lets you offload scanning from your CVEngine instance onto other
machines - spin up several across different VPSes or networks to parallelize and speed up scanning, each one pulling
work independently from the same queue.

OpenVAS is the one capability that makes a Sentinel heavy: `docker-compose.yml` includes the full Greenbone/GVM stack
(gvmd, the scanner, its own Postgres and Redis, and the NVT/SCAP/CERT feed syncs) alongside the lightweight tools, so
every Sentinel can take any kind of work cvENGINE dispatches. The first start downloads the vulnerability-test feeds,
which takes a long time and several GB of disk; every other capability works immediately, and OpenVAS tasks simply
wait for a Sentinel whose feed sync has finished.

See [docs/ARCHITECTURE.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/ARCHITECTURE.md#sentinels) in the
main [CVEngine](https://github.com/hevnsnt/CVEngine) repository for the design, and
[docs/AGENT-API.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/AGENT-API.md#sentinels-scan-stage-agents)
for the REST contract this client speaks. Nothing it runs is ever built from, or interprets, text the server sends:
see `client/tools.py`'s header for the argv discipline every tool call follows.

If an AI agent is setting this up (for example one with Docker and shell access to the target machine, and MCP or
REST access to the cvENGINE instance), see [AGENTS.md](AGENTS.md) instead: it is the same procedure below, but
driven entirely from the `generate_sentinel_enrollment` MCP tool's response, with no steps that need a human.

## Set up

1. Clone this repository onto the machine that will do the scanning (the same one you would otherwise have run nmap
   on by hand):
   ```
   git clone https://github.com/hevnsnt/cvengine-sentinel.git
   cd cvengine-sentinel
   ```
2. On your CVEngine instance's **Sentinels** page (`/cve/sentinels/`), pick the project and click **Provision**. Copy
   the one-time blob it shows (it is single-use and expires in 30 minutes). You need the admin role in the project or
   its organization to do this; see
   [docs/FRONTEND.md](https://github.com/hevnsnt/CVEngine/blob/develop/docs/FRONTEND.md#sentinels) in the main repo.
3. Create `.env`. The easy way is `./setup.sh`, which asks for the profile (full or light), the network (external or internal), a name and the blob, and writes `.env` for you; or pass everything as options and skip the questions:
   ```
   ./setup.sh --light --internal --name office-lan --blob "$BLOB"
   ```
   Or do it by hand:
   ```
   cp .env.example .env
   ```
   ```ini
   # .env
   CVENGINE_SENTINEL_BLOB=eyJlbnJvbGxtZW50X3Rva2VuIjoi...
   # CVENGINE_SENTINEL_NAME=office-scanner
   # CVENGINE_SENTINEL_MAX_CONCURRENT=2
   ```
4. Start it:
   ```
   docker compose up -d
   ```

The first start decodes the blob, bootstraps (trades the one-time secret for this Sentinel's own token) and saves
that token to the `sentinel-state` Docker volume. Every start after that uses the saved token directly: the blob in
`.env` is read only once and can be removed from `.env` (or left; it is ignored once a token is persisted). Every
start, including these later ones, also re-registers with the server (name, capabilities, `max_concurrent`), so a
restart always reports this Sentinel's current, freshly auto-detected capacity rather than whatever was true the
one time it originally bootstrapped.

## Check it registered

Open the **Sentinels** page on your CVEngine instance. The new Sentinel appears by its name (the container's
hostname, or `CVENGINE_SENTINEL_NAME` if you set one), `pending` until an administrator approves it, then `active`
and `live` once it starts heartbeating. From there it is administered exactly like any other agent: **Suspend** /
**Revoke**, and `GET /api/v1/agents?kind=scanner` / `GET /api/v1/agents/{id}` on the CVEngine instance if you prefer
the API or MCP tools (`list_sentinels`, `get_sentinel`).

```
docker compose logs -f
```
shows the bootstrap result and every task it picks up; the token itself is never logged.

## Stop and remove it

```
docker compose down
```
stops the container; its persisted token stays in the `sentinel-state` volume, so starting it again does not need a
new blob. To remove it for good, also drop the volume and revoke it server-side:

```
docker compose down -v
```

and, on the CVEngine instance's **Sentinels** page (or `PATCH /api/v1/agents/{id}` with `{"status": "revoked"}`),
**Revoke** the Sentinel so its token can never be used again, even if a copy of `sentinel-state` survives somewhere.
Revoking also hands back any task it was mid-run on to the queue immediately.

## Configuration

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `CVENGINE_SENTINEL_BLOB` | Only for the first start | - | The one-time provisioning blob from the Sentinels page. Ignored once a token is persisted. |
| `CVENGINE_SENTINEL_NAME` | No | the container's hostname | The Sentinel's name on the Sentinels page. |
| `COMPOSE_PROFILES` | No | `openvas` (full) | `openvas` runs the GVM stack too (full); empty is light. See "Full or light" below. |
| `CVENGINE_SENTINEL_DISABLE` | No | none | Comma-separated scan kinds this Sentinel never declares or polls for (for example `openvas`, or `openvas,wpscan`), whatever tools are installed. |
| `CVENGINE_SENTINEL_VERSION` | No | the commit the image was built from | The version shown on the Sentinels page. The image build stamps the checkout's git commit (the first 12 characters of HEAD) into it, so a plain `docker compose up -d --build` reports a version; `scripts/update.sh` sets this variable, which then wins. An image built from a download with no `.git` reports unknown. |
| `CVENGINE_SENTINEL_NETWORK` | No | `external` | Set to `internal` on a Sentinel deployed inside a private network (office LAN, VPC, VPN). It then declares `network:internal`, so the server will hand it work for the internal ranges a project declared (projects/{slug}/internal-ranges); an external Sentinel is never offered that work. |
| `CVENGINE_SENTINEL_MAX_CONCURRENT` | No | auto-detected from the container's CPU (capped at 10) | How many nmap/naabu/nuclei/testssl/wpscan runs this Sentinel executes at once (an OpenVAS task is one GVM job, counted separately by gvmd itself). Set a number to override the auto-detected value. |

`docker-compose.yml` adds `NET_RAW`/`NET_ADMIN` (not `--privileged`) to the `sentinel` service, which nmap's OS
detection, naabu's SYN scanning and the UDP sweep need; it runs on the Docker bridge network by default, so if your
targets are elsewhere on your LAN rather than reachable through that bridge, uncomment `network_mode: host`. The
`openvas-ospd` service gets its own `NET_RAW`/`NET_ADMIN` plus the unconfined seccomp/AppArmor profiles Greenbone's
own compose file uses, on a separate internal network (`openvas_network`); its scans leave by this Docker host's
default route, not through the `sentinel` container.

**Full or light.** The openvas-* services are the compose profile `openvas`, switched on by `COMPOSE_PROFILES=openvas` in `.env`. Full (the default in `.env.example`) also runs the OpenVAS/GVM stack so this Sentinel can take OpenVAS work; light leaves `COMPOSE_PROFILES` empty and runs only nmap, naabu, nuclei, testssl and WPScan on a small box. A light Sentinel simply never declares the `openvas` capability (`client/tools.gvm_available`). `./setup.sh` writes these choices for you (see below), and the Sentinels page's Provision form shows the exact `.env` lines.

**External or internal.** `CVENGINE_SENTINEL_NETWORK=internal` says this machine sits inside a private network (office LAN, VPC, VPN). It then declares `network:internal`, and the server hands it work for the internal ranges a project declared; an external Sentinel is never offered that work.

To keep OpenVAS off a box that has the stack, set `CVENGINE_SENTINEL_DISABLE=openvas`. The daemon never requires gvmd to be present: it declares the `openvas` capability only while gvmd is ready (`client/tools.gvm_ready`), and registers again by itself when that changes.

The Greenbone images are pinned by digest, and Greenbone publishes no version tags and replaces what `stable` points to, so
an old pin can vanish from the registry (`artifact ... not found` on `docker compose up`). `./scripts/greenbone-digests.sh`
prints which pinned digests no longer match `stable`; replace the `sha256` of any that changed in `docker-compose.yml`.

## Managing a Sentinel from cvENGINE

Once a Sentinel has checked in, an administrator can change its settings from the cvENGINE Sentinels page (or `PATCH agents/{id}` with
`{"settings": {...}}`) with nothing touched on this machine: its **name**, **network** (`external` or `internal`), **profile** (`full` or
`light`; light never runs OpenVAS), the **kinds it never takes**, its **concurrency** and its **self-update** setting (see Updates below). The same settings can be set here, in `.env`
(`CVENGINE_SENTINEL_NAME`, `_NETWORK`, `_PROFILE`, `_DISABLE`, `_MAX_CONCURRENT`, `_UPDATE`). **The most recent change wins, wherever it was made**: the
Sentinel reports this machine's own values at every start and cvENGINE keeps the time each last changed, so restarting with an unchanged `.env`
never undoes an edit made in cvENGINE, and an edit made in `.env` after the last dashboard edit takes over. Settings are only data: the Sentinel
checks every value and ignores anything it does not recognise, and what a Sentinel is allowed to scan is still decided by its scope, an
administrator's approval and limits.

## Updates

A Sentinel updates itself so nothing has to be done by hand on its machine, **under a setting chosen in cvENGINE**: **Off** (it never
changes its own code), **Manual** (it updates only when an administrator presses **Update now** for it, or `PATCH agents/{id}` with
`{"update": "now"}`) or **Automatic** (it updates as soon as the updater next runs and something new is out). It is set per Sentinel on the
Sentinels page, with an instance-wide default for every Sentinel that has no value of its own (`GET/PUT sentinels/defaults`, App Admin; until
one is chosen the default follows the main cvENGINE updater's own Automatic or Manual choice). It is stored with the other managed settings,
so **the most recent change wins, here or in cvENGINE**: set `CVENGINE_SENTINEL_UPDATE=off|manual|automatic` in `.env` to state this machine's own
choice, and leave it unset to let cvENGINE decide.

**The updater.** `scripts/update.sh` is what acts on the setting, and it runs on the Docker host, hourly. `./setup.sh` installs it for you by
default (a systemd timer, or a cron.d entry where there is no systemd; it asks for `sudo` when it is not root); `./setup.sh --no-updater` leaves
it out, and `sudo ./scripts/install-updater.sh` installs it later (`--remove` takes it away). Each run compares this checkout with `origin/main`
and, when there is something new **and the setting allows it**, drains the Sentinel (it finishes the tasks it holds and takes no new ones),
fast-forwards the checkout, pulls the images (so a moved Greenbone digest in `docker-compose.yml` reaches the stack too), rebuilds and restarts
it, waits for the new Sentinel to report the new version, and records each step, which the Sentinels page shows. `scripts/update.sh --check` says
what it would do; `--now` is a person at this machine asking for an update whatever the setting says. A failed step is reported
(`update.status: failed`) and the Sentinel is put back to work on the version it had; the checkout must be unmodified to fast-forward.

**A Sentinel that cannot update itself is visible.** Every run of the updater records when it ran and how it went (`ok`, `waiting`, `off`,
`updated` or `failed`, with a detail) in the state volume, and the Sentinel reports that with its heartbeat. The Sentinels page shows the
updater as `running`, `stopped` or `not installed` (or `unknown` for a Sentinel too old to say), the last run and its result, and, when the
setting is Manual or Automatic but no updater is running, a warning with the one-line install command. cvENGINE writes that command itself; it is
never taken from the Sentinel.

| Updater state | What it means | What to do |
| --- | --- | --- |
| `not installed` | No run has ever been recorded and the install script has not marked it. The Sentinel never updates itself. | `sudo ./scripts/install-updater.sh` in this checkout. |
| `stopped` | Installed, but no run for more than 2.5 hours (the timer or cron stopped, the machine was off, or `update.sh` cannot start). | `systemctl status cvengine-sentinel-update.timer` and `journalctl -u cvengine-sentinel-update`, or the cron log `/var/log/cvengine-sentinel-update.log`. |
| `running`, last result `failed` | It runs, but a step failed (the detail names it: `docker compose pull`/`up`, a checkout with local changes that cannot fast-forward, running tasks that did not finish while draining, the new Sentinel not reporting its version). | Fix what the detail says; the next run tries again. |
| `running`, last result `off` | Self-update is Off for this Sentinel. | Set it to Manual or Automatic in cvENGINE (or remove `CVENGINE_SENTINEL_UPDATE=off` from `.env`). |
| `running`, last result `waiting` | An update is available and the setting is Manual. | An administrator presses **Update now**, or the setting is changed to Automatic. |

The updater never gets the Docker socket inside a container: it reaches the daemon only through
`docker compose exec sentinel python3 -m client.control` (drain, wait-idle, report), files in the state volume. A drain expires after two
hours on its own and is cleared whenever the Sentinel starts, so an updater that died half way never leaves a Sentinel idle for good. Nothing
changes while the setting is Off, or Manual with nobody having asked. The version is stamped into the image when it is built (see the
`CVENGINE_SENTINEL_VERSION` row), so an install only needs to be rebuilt once (`docker compose up -d --build`) to report it.
An install that predates this has no updater until `sudo ./scripts/install-updater.sh` is run once on its machine.

## Testing OpenVAS

CI runs the client tests on every change, and `.github/workflows/openvas-integration.yml` brings up the pinned `gvmd` and runs the login
bootstrap and the readiness check against it with the pinned `python-gvm` (when the OpenVAS client, the compose pins or `requirements.txt`
change, weekly, and on demand), because a mock cannot catch gvmd refusing a request. It does not run a scan: a scan needs the vulnerability-test
feeds, which take hours and tens of GB to sync. To prove the whole path on a machine with Docker, once, after a change to the OpenVAS pins:

    docker compose up -d --build
    docker compose exec sentinel python3 scripts/ci_openvas_bootstrap.py     # logs in, saves the login, prints whether GVM can scan yet
    docker compose logs -f sentinel                                          # "capabilities changed: now ..., openvas" once the feeds finished syncing

then dispatch an OpenVAS task from cvENGINE (Hosts, run an OpenVAS scan) and watch it finish. The Sentinel declares `openvas` only once gvmd has
loaded its scan configuration, scanner and port lists and has stopped its first feed sync, and a task that arrives earlier fails with
"GVM is still syncing its ... feed(s)". The first sync downloads tens of GB. If gvmd will not let the default `admin` user change its own password
(it answers "Failed to find user", 404, on some versions) the Sentinel creates a login of its own (`cvengine-sentinel`) instead; to use a login you
made by hand, save it to `/var/lib/cvengine-sentinel/openvas-credentials.json` as `{"username": ..., "password": ...}` (mode 600).

## What it will and will not do

A Sentinel only ever runs one of a whitelisted set of tools - nmap, naabu, nuclei (light, targeted or weekly deep
pass), testssl.sh, a UDP exposure sweep, WPScan, or an OpenVAS/GVM scan - against the exact address, host, target
list or host set a `SentinelTask` names, built as a fixed argv list (or, for OpenVAS, a typed GMP call) never a shell
command. It never evaluates or interprets any text the server sends as code or as a command, and it reports typed,
bounded results back; see `client/tools.py` for the validation every target list passes through before a tool ever
runs against it, and `client/openvas.py` for the GMP session OpenVAS work runs over.
