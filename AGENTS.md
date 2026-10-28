# For an AI agent setting up a Sentinel

If you were asked to turn a machine you have Docker and shell access to into a cvENGINE Sentinel, and you (or
another agent you can ask) have MCP or REST access to the cvENGINE instance, here is the whole procedure. It needs
no manual steps and no separate download: this repository is the entire client.

## 1. Get a provisioning blob

Call the `generate_sentinel_enrollment` MCP tool on the cvENGINE instance, scoped to whichever of the three levels
the Sentinel should cover:

- **One project** (REST equivalent: `GET /api/v1/projects/{slug}/sentinels/enroll?format=blob`) — pass `project`
  with that project's slug. Needs the admin role in that project or its organization.
- **One organization, every project of it, present and future** (REST: `GET /api/v1/orgs/{slug}/sentinels/enroll?format=blob`)
  — pass `org` with that organization's slug. Needs the admin role in that organization.
- **The whole instance, every organization and project, present and future** (REST: `GET /api/v1/sentinels/enroll?format=blob`)
  — pass neither `project` nor `org`. Needs the App Admin (superuser) role.

Give at most one of `project`/`org`; both at once is refused. `list_projects`/`whoami` will tell you which level you
qualify for, and if none, say so and ask a human or another agent who does.

The response is everything you need, already assembled:

```json
{
  "enrollment_token": "senr_...",
  "server_url": "https://scanner.example.com",
  "expires_at": "2026-10-27T23:30:00Z",
  "blob": "eyJlbnJvbGxtZW50X3Rva2VuIjoi...",
  "setup": {
    "clone": "git clone https://github.com/hevnsnt/cvengine-sentinel.git && cd cvengine-sentinel",
    "configure": "cp .env.example .env && printf 'CVENGINE_SENTINEL_BLOB=%s\n' '<blob>' >> .env",
    "run": "docker compose up -d",
    "verify": "docker compose logs -f",
    "note": "..."
  }
}
```

Do not construct the blob by hand or reuse one from an earlier call: it is single-use and expires in 30 minutes
(`expires_at`). If `setup.run` has not happened within that window, call `generate_sentinel_enrollment` again for a
fresh one.

## 2. Run the four `setup` commands, in order, on the target machine

On the machine that will scan (the one with Docker and the network access you want a Sentinel to have), run exactly
the four commands in `setup`, substituting the real `blob` value for `<blob>` in `configure`. Nothing else needs to
be installed first beyond Docker itself; the image carries its own pinned nmap, naabu, nuclei, testssl.sh and
WPScan, and `docker compose up -d` also brings up this Sentinel's own OpenVAS/GVM stack alongside it. That stack
downloads several GB of vulnerability-test feeds on its first start, which can take hours; every other capability
(nmap/naabu/nuclei/testssl/UDP/WPScan) is usable immediately, and OpenVAS tasks simply wait until the feed sync
finishes. If this machine should stay lightweight and never run OpenVAS, tell the person or agent operating it to
remove the `openvas-*` services from `docker-compose.yml` before step 4 below, per README.md's "Configuration"
section.

If you only have MCP/REST access to cvENGINE but not shell access to the target machine yourself, stop here and hand
the `blob` and the four `setup` commands to whichever agent or person does have that access. Never paste a blob into
a chat log, issue, commit message or anywhere else it would be retained longer than needed to run `configure` once.

## 3. Confirm it registered

Call `list_sentinels` (or `get_system_status`, which now includes a `system.sentinels` block: counts by status,
how many are live, queue depth, and the last day's completed/failed/expired tasks) on the cvENGINE MCP server. The
new Sentinel appears `pending` until an administrator approves it (unless the account that generated the
enrollment was itself an admin, in which case it starts `active` immediately), then `live` once its heartbeat is
recent. If it never appears, read back `docker compose logs` on the target machine for the bootstrap error before
trying again; a wrong or expired blob fails loudly and says why.

## What this does and does not do

Provisioning a Sentinel this way only ever registers it and lets it begin claiming scan-stage work
(nmap, naabu, nuclei, testssl.sh, a UDP exposure sweep, WPScan, OpenVAS) that the cvENGINE instance already decided
to dispatch; it grants no other access to the target machine from cvENGINE's side, and nothing a Sentinel runs is
ever built from, or interprets, text the server sends (see `client/tools.py`, and `client/openvas.py` for the GMP
session OpenVAS work runs over). To remove a Sentinel, see `README.md`'s "Stop and remove it" section, or
`suspend_sentinel`/`revoke_sentinel` over MCP.
