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
3. Create `.env` from the example and paste the blob in:
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
| `CVENGINE_SENTINEL_DISABLE` | No | none | Comma-separated scan kinds this Sentinel never declares or polls for (for example `openvas`, or `openvas,wpscan`), whatever tools are installed. |
| `CVENGINE_SENTINEL_NETWORK` | No | `external` | Set to `internal` on a Sentinel deployed inside a private network (office LAN, VPC, VPN). It then declares `network:internal`, so the server will hand it work for the internal ranges a project declared (projects/{slug}/internal-ranges); an external Sentinel is never offered that work. |
| `CVENGINE_SENTINEL_MAX_CONCURRENT` | No | auto-detected from the container's CPU (capped at 10) | How many nmap/naabu/nuclei/testssl/wpscan runs this Sentinel executes at once (an OpenVAS task is one GVM job, counted separately by gvmd itself). Set a number to override the auto-detected value. |

`docker-compose.yml` adds `NET_RAW`/`NET_ADMIN` (not `--privileged`) to the `sentinel` service, which nmap's OS
detection, naabu's SYN scanning and the UDP sweep need; it runs on the Docker bridge network by default, so if your
targets are elsewhere on your LAN rather than reachable through that bridge, uncomment `network_mode: host`. The
`openvas-ospd` service gets its own `NET_RAW`/`NET_ADMIN` plus the unconfined seccomp/AppArmor profiles Greenbone's
own compose file uses, on a separate internal network (`openvas_network`); its scans leave by this Docker host's
default route, not through the `sentinel` container.

Only want the lightweight tools on a particular box, without the OpenVAS/GVM stack? Remove the `openvas-*` services
from `docker-compose.yml` and the `sentinel` service's `openvas_gvmd_socket_vol` mount and `depends_on`. The daemon
never requires gvmd to be present: it declares the `openvas` capability only while gvmd's socket exists
(`client/tools.gvm_available`), and registers again by itself when that changes (a first start can take hours to sync the
feeds), so a Sentinel without a working GVM stack is never handed OpenVAS work. To keep OpenVAS off a box that has the stack,
set `CVENGINE_SENTINEL_DISABLE=openvas`.

The Greenbone images are pinned by digest, and Greenbone publishes no version tags and replaces what `stable` points to, so
an old pin can vanish from the registry (`artifact ... not found` on `docker compose up`). `./scripts/greenbone-digests.sh`
prints which pinned digests no longer match `stable`; replace the `sha256` of any that changed in `docker-compose.yml`.

## Managing a Sentinel from cvENGINE

Once a Sentinel has checked in, an administrator can change its settings from the cvENGINE Sentinels page (or `PATCH agents/{id}` with
`{"settings": {...}}`) with nothing touched on this machine: its **name**, **network** (`external` or `internal`), **profile** (`full` or
`light`; light never runs OpenVAS), the **kinds it never takes** and its **concurrency**. The same settings can be set here, in `.env`
(`CVENGINE_SENTINEL_NAME`, `_NETWORK`, `_PROFILE`, `_DISABLE`, `_MAX_CONCURRENT`). **The most recent change wins, wherever it was made**: the
Sentinel reports this machine's own values at every start and cvENGINE keeps the time each last changed, so restarting with an unchanged `.env`
never undoes an edit made in cvENGINE, and an edit made in `.env` after the last dashboard edit takes over. Settings are only data: the Sentinel
checks every value and ignores anything it does not recognise, and what a Sentinel is allowed to scan is still decided by its scope, an
administrator's approval and limits.

## What it will and will not do

A Sentinel only ever runs one of a whitelisted set of tools - nmap, naabu, nuclei (light, targeted or weekly deep
pass), testssl.sh, a UDP exposure sweep, WPScan, or an OpenVAS/GVM scan - against the exact address, host, target
list or host set a `SentinelTask` names, built as a fixed argv list (or, for OpenVAS, a typed GMP call) never a shell
command. It never evaluates or interprets any text the server sends as code or as a command, and it reports typed,
bounded results back; see `client/tools.py` for the validation every target list passes through before a tool ever
runs against it, and `client/openvas.py` for the GMP session OpenVAS work runs over.
