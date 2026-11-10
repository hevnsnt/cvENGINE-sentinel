# Changelog

## Unreleased

### Fixed
- **OpenVAS: the `openvas-scanner` image pin points at an image that exists.** Greenbone replaced the image behind `stable` and removed the pinned digest on 11/10, so `docker compose up` with the OpenVAS profile failed to pull it (`scripts/greenbone-digests.sh`: MISSING). Both pins move to the current `stable` digest.
- **nuclei now runs on the server's approved template set.** The task names its bundle inside `template_policy`, and the Sentinel looked for it at the top level, so under the default read-only policy every nuclei task failed, and under the all-templates policy the Sentinel ran the templates baked into its image, never refreshed. A read-only task whose bundle is not packed yet is given back to be retried, not failed. The result names the template release the run used (`templates_release`).
- **A host nuclei never reached is not reported as scanned.** nuclei exits cleanly with no output for a host nothing answered. The run now reads nuclei's error log and names those hosts in `unreachable` (the template test reports them as errors).
- **nuclei findings keep their evidence.** The raw request and response are kept (clipped, credentials redacted) instead of dropped with `-omit-raw`, with the CVE ids, CVSS score, references and remediation text the template carries.
- **testssl reports whether a handshake happened and its exit code.** A port that completes no TLS handshake sends no "not vulnerable" answers, because nothing was tested.
- **nmap reports a host it gave up on as `timed_out`,** and an address it did not report gets no clean row.
- **naabu full-port discovery can finish.** One time-limit function serves nmap and naabu, a run that runs out of time reports the addresses it did not reach (`incomplete`, `unfinished`) instead of an error, and the fingerprint pass scans the ports of its task with the extended port set and the reviewed scripts.
- **A DNS timeout on a mail name is unknown, not "no mail".** The MX or CNAME lookup that failed is named in `unknown_names`.
- **OpenVAS: a host gvmd finished without any answer is reported in `unreached_hosts` and not as scanned,** so a host that was only offline closes none of its earlier findings.
- **bbot wildcard names are not subdomains.** A name tagged `wildcard` and the `_wildcard.<zone>` placeholder are dropped.
- **`detect_tools` declares a tool only when its version probe exits cleanly,** and **a discovery sweep that died is an error,** not "no host is up".

### Added
- A Sentinel that is not the built-in scanner now reports `info.features: ["bbot_keys"]` in its heartbeat: it reads a bbot discovery task's API keys through the
  single-use secret read (`POST sentinel/tasks/<id>/secret`), keeps them only in a 0600 file inside a fresh 0700 directory for the run, and masks them. A cvENGINE
  server sends the project's discovery API keys only to a Sentinel that says so (and that its owner has not opted out); an older Sentinel never says it and never gets
  them. Optional field, no contract change, no new task kind, task payload unchanged. Every key is now also masked in each batch posted and in the final result and
  any error text (not only in bbot's error stream), and a key directory a crashed run left in the temp directory is removed at the next start.
- A Sentinel watchdog (`client/watchdog.py`, docs/WATCHDOG.md): a thread apart from the task threads, ticking every 10 seconds, on by default
  (`CVENGINE_SENTINEL_WATCHDOG=0` switches it off). W1 stops a task's whole process group at a per-kind hard deadline (the tool's own budget plus a grace; the
  owner can raise it, never lower it) and reports `error` "timed out after N minutes"; W2 stops a group that used no CPU and moved no bytes for N minutes (a
  hung tool); a stopped nuclei run that had printed findings reports them as `done`, one with none is an `error`. W3 breaks the memory-budget deadlock: waiters that
  waited 3 minutes behind long runs may start inside an overcommit of at most 25 percent of the budget and only within the real free memory measured from /proc and
  the cgroup (a floor of the larger of 300 MB and 15 percent of the limit); nothing is killed for it. W4 kills tool process groups that outlived their task and reaps
  their zombies. W5 replaces a stuck heartbeat thread and ends the process (exit code 3) for a poll loop stuck for 5 minutes, for every Sentinel; the image health
  check also fails on a stale watchdog, heartbeat or poll loop. W6 stops taking work under 300 MB of free disk and removes only its own temp and cache files.
  W7 the heartbeat's optional `info.watchdog` (last tick, actions, kills, overcommit, reasons). W8 per-rule variables, one log line per action, and a kind
  stopped 3 times in an hour is not asked for for 30 minutes. No contract change, no new task kind.
- A durable result spool (`client/spool.py`): a result cvENGINE does not take (an update, a restart, an outage) is written to disk (0600, atomic) and delivered oldest
  first, with a capped backoff, for up to 6 hours (`CVENGINE_SENTINEL_SPOOL_HOURS`, `0` = off; size limit `CVENGINE_SENTINEL_SPOOL_MAX_MB`) instead of being released after
  5 tries in 2 minutes. It is delivered before the first heartbeat after a reconnect or a start, a held result's task still counts as running in the heartbeat, and the
  heartbeat reports `info.spool` (`count`, `oldest_seconds`, optional) for the Sentinels page. An entry past the window is kept under `spool/expired/`. No contract change.
- A Sentinel that cvENGINE asks to update (heartbeat answer `update.requested` with `update.target`) can drain and exit with code 76 so its supervisor brings the
  newest image: `CVENGINE_SENTINEL_UPDATE_EXIT=1`, `client/selfupdate.py`, `scripts/pull-on-exit.sh`. It never leaves while a task runs past the drain limit, never to the build it
  already runs, never twice for the same target within 6 hours, and never for the built-in scanner or a machine whose own self-update ceiling is off.

### Changed
- The heartbeat and the poll log an outage once, then at most every 10 minutes, instead of one line per attempt. The quick result retries are 4 tries within 20 seconds (were 5 within 120).
- README: "cvENGINE asks for the newest version" describes who acts on the request (the host updater, the exit-code supervisor, the server's host for the built-in scanner).
