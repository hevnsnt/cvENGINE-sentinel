# Changelog

## Unreleased

### Fixed
- **Tools and base image at their newest releases.** Go 1.27.4 (builds nuclei and naabu), testssl.sh 3.2.5 (now fetched from its GitHub release tag; the 3.2.4 file there is byte-identical to the one testssl.sh served), Playwright 1.65.0 with its Chromium 158.0.8127.18 (its seccomp profile is unchanged, so the vendored copy stays), the Ubuntu 26.04 base image's current digest, and aardwolf 0.2.17, PyMySQL 1.2.4 and dnspython 2.9.2. Kingfisher stays at 2.16.0 until the server's reviewed validation allow-list is moved with it.
- **nuclei: a tag filter no template matches is nothing to check, not a failure.** The server asks for tags such as `haproxy` at severity `info`; when no template in the set matches, nuclei exits 1 (`no templates provided for scan`) and the task failed. 29 tasks in two days on the VPS, the same tag sets every time, and those hosts stayed due for ever. With a filter the result is now no findings and `no_templates`; without one, an empty template set is still an error (the templates are missing).
- **nuclei: a run that runs out of time keeps what it found.** Before, the whole run was lost; now its findings are returned and every target is named unreachable, so none is recorded as scanned clean.
- **nuclei: each run ends before the server stops waiting for it.** The daemon passed no time limit, so every nuclei run could take 3600 s while the server waits 900 s (light), 1800 s (targeted) or 3600 s (deep) plus a little per target, and late results were thrown away (13 in two days). Limits now come from `cvengine_scanner.flags.TASK_LIMITS`, 60 s under the server's wait; the longest production runs fit.
- **A tool's failure message says its error, not nuclei's JSON-library warning.** The message keeps 200 characters of stderr and nuclei opens every run with a line about `sonic/ast`, so each failure read `...fallback to encoding/json[FTL] Could not run nuclei: no templ`. That line is left out of the message; the whole stderr stays on the exception.
- **WPScan without an API token is not asked for vulnerable plugins and themes.** WPScan refuses `vp`/`vt` without a token and aborts the whole scan, so sites of projects with no token were never scanned (14 of the last 90 runs). It now lists the plugins and themes it detects (`p`, `t`) and their versions, which the server's CVE feed reads.
- **WPScan follows a redirect on the same site once.** WPScan stops at a redirect rather than follow it, so a site that answers on its `www.` twin or another path was never scanned (32 of the last 90 runs). A redirect to the same host or its `www.` twin is scanned (scope-checked again like any URL); one that leaves the site is not followed.
- **secrets_scan: one name that does not resolve no longer fails its whole batch.** A resolver error is an `OSError`, not a scope refusal, so it escaped the per-host loop and ended the task: 22 batches of up to 25 hosts in two days. That host is skipped and the rest of the batch is read.
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
- **AI-written checks run on your own Sentinels (contract version 4).** With no built-in scanner, cvENGINE now sends its AI-written and approved
  nuclei checks (`nuclei_validate`) and its scan path survey (`path_probe`) to the project's own Sentinels. A Sentinel that is not the built-in scanner
  runs a check only when all of these hold: the task names the sha256 of the template (`template_sha256`), the file it wrote and read back hashes to it,
  its server names the same hash and mode for that task when asked separately (`GET sentinel/tasks/<id>/check`), the template passes the server's
  read-only rules (`cvengine_scanner.checks`, one shared test corpus) and it reaches only the task's own target and port (no literal port, no `port`
  key). A result line for a host the task did not name is never a hit, and the result echoes the hash it ran. The image gains PyYAML 6.0.3.
- Kingfisher 2.18.1 (was 2.16.0): the Dockerfile pin and both checksums (from the release's own files, build attestation verified), the library constant and the README row.
- **The image's tools are checked against their newest releases.** `scripts/check_tool_versions.py` reads every pin (the Dockerfile versions and base image digest, `requirements.txt`, the pip bootstrap pins, the Greenbone image digests) and prints each one beside the newest upstream release. A weekly run keeps one issue open while something is behind, every pull request gets a warning, and *Tag a release* refuses to tag while a tool is behind or a lookup fails (`--fail-if-behind`).
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
