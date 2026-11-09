# The Sentinel watchdog

A Sentinel can stop being useful without crashing: a tool that hangs and prints nothing, a memory budget that two long nuclei runs hold for an hour while every
waiter starves, tool processes that outlive their task, a heartbeat or poll loop stuck in a lookup that has no timeout, a full disk. The watchdog
(`client/watchdog.py`) is one thread, apart from every task thread, that ticks every 10 seconds (`CVENGINE_SENTINEL_WATCHDOG_TICK`, 2 to 60) and checks them.
It needs no network and no extra package: it reads `/proc`, the container's cgroup and the daemon's own state. A tick is one pass over `/proc` and the running
tasks (a few milliseconds).

`CVENGINE_SENTINEL_WATCHDOG=0` switches all of it off (no thread, no `info.watchdog`, no liveness block in the status file; the health check then judges as
before). Every action is one log line with a timestamp (`watchdog stopped_hung nuclei_light: task 1: ...`); no target, finding, token or secret is ever in one.
The result contract is not touched: no new task kind, no new outcome, the contract version is unchanged.

## What each rule does

| rule | what it checks | what it does |
|---|---|---|
| W1 deadline | a task's age against its kind's hard deadline (table below) | stops the whole process group (SIGTERM, SIGKILL 5 s later), reports `error` "timed out after N minutes: ...", frees the slot and the memory reservation |
| W2 no progress | the CPU time (utime+stime) and bytes read and written (`/proc/<pid>/io`) of the task's process group | no change for N minutes (default 15; nuclei, nmap, wpscan 20; bbot 30; none for OpenVAS and thorough WPScan) means the tool is hung: same stop, "no output and no CPU for N minutes" |
| W3 memory | waiters blocked on the memory budget, how long the holders have run, the real memory of every group | see below |
| W4 orphans | process groups of tasks that ended | a group still alive 15 s after its task ended is killed; the zombie children it leaves are reaped (`waitpid` on that pid only) |
| W5 liveness | the heartbeat loop and the poll loop each stamp the time they last turned | a heartbeat loop stale for 150 s is replaced by a new thread; stale again after that, or a poll loop stale for 300 s, ends the process with exit code 3 so the supervisor restarts it |
| W6 disk | free space of the state directory and the temp directory | under 300 MB: no new work is asked for, this Sentinel's own temp files and nuclei caches are removed, `low_disk` is reported; resumes at 450 MB |
| W7 report | | the optional heartbeat field `info.watchdog` (below) |
| W8 control | | the kill switch, per-rule variables, and a kind stopped 3 times in an hour is not asked for for 30 minutes |

A stopped task is reported with the existing `error` outcome and a plain sentence. A stopped nuclei run that had already printed findings reports them as
`done` (the findings are real); a stopped run that produced nothing is always an `error`, never an empty `done`, because that would read as a clean scan
(`CVENGINE_SENTINEL_WATCHDOG_PARTIAL=0` reports the error even then). The server counts the error towards "cooling off after repeated failures", and the
Sentinel itself withholds a kind it had to stop three times in an hour.

W1 is a backstop. Every tool already has its own time limit (`client/tools.py`), and that is what ends a normal overrun; the deadline is that limit plus a
grace, so the watchdog acts only when the tool's own limit failed (an in-process probe stuck in a socket call, a handle that does not die, `bbot`'s timer). The
effective protection against a hung tool is W2.

### Hard deadlines

The deadline is the tool's own budget plus 300 s (plus 600 s past a time limit the task itself carries). `CVENGINE_SENTINEL_DEADLINE_<KIND>_MIN` (for example
`CVENGINE_SENTINEL_DEADLINE_NUCLEI_DEEP_MIN=180`) and `CVENGINE_SENTINEL_DEADLINE_DEFAULT_MIN` raise it; a value below the tool's own budget is ignored.

| kind | tool's own budget | deadline |
|---|---|---|
| nuclei_light, nuclei_targeted, nuclei_deep | 60 min | 65 min |
| nuclei_validate | 10 min | 15 min |
| nmap | 10 to 60 min by host count | 65 min |
| nmap_verify | 15 min | 20 min |
| nmap_full, nmap_udp | 25 min | 30 min |
| discover, naabu, testssl, wpscan | 15 min | 20 min |
| waf, rdp_shot | 5 min | 10 min |
| web_screenshot, secrets_scan | 30 min | 35 min |
| bbot_discovery | the task's `timeout_seconds` (default 6 h, at most 24 h) | that plus 10 min |
| wpscan_thorough | the task's `timeout_seconds` (default 12 h) | that plus 10 min |
| openvas | `CVENGINE_OPENVAS_MAX_HOURS` (default 24 h) | 24 h plus 5 min |
| any other kind (in-process probes) | 15 min | 20 min |

A nuclei run of 13 minutes is inside its design: nothing below 60 minutes is an error.

## The memory budget deadlock (W3)

The budget is the container limit times 0.85 less 200 MB (1540 MB for a 2 GB container), and each nuclei run counts 520 MB. Two nuclei runs hold 1040 MB, so
500 MB is free and a third needs 520: it never fits while either runs, for up to 60 minutes. The weights are measured peaks, not what each run uses at every
moment.

When a kind has waited for memory for `CVENGINE_SENTINEL_WATCHDOG_MEM_WAIT_SECONDS` (default 180) behind heavy runs that have all been going for
`CVENGINE_SENTINEL_WATCHDOG_MEM_HOLD_SECONDS` (default 300), the watchdog lets the budget be exceeded by an overcommit:

- at most `CVENGINE_SENTINEL_WATCHDOG_OVERCOMMIT_PERCENT` (default 25) of the budget (385 MB of 1540), and
- never more than the real room: the container limit, less a floor (the larger of 300 MB and 15 percent of the limit, `CVENGINE_SENTINEL_WATCHDOG_MEM_FLOOR_MB`
  to set it), less the daemon's own 200 MB, less the estimated use of every running task. A run that has been going for two minutes is estimated at the
  most real memory its process group has shown (summed over the group from `/proc`) times 1.15; a younger one at its full weight. The new task is counted at
  its full weight.

So the overcommit is the difference between what the running tasks really use and what they are weighed at, never more, and it is recomputed every tick: it
ends the moment a holder grows, a holder ends or nobody waits. Nothing is killed for it. `CVENGINE_SENTINEL_WATCHDOG_MEM_KILL=1` adds a last resort, off by
default: when the real available memory falls under half the floor, the newest heavy run is stopped and reported as "out of memory, retry later" (the text the
server already treats as retryable) rather than leaving the choice to the kernel.

Measured, in the proof lab (a real Sentinel image with a 2 GB limit, two holders really using 300 MB each; see the pull request): without the watchdog the waiters
wait for the holders to end; with it the first waiter started two minutes after the holders had run long enough to be estimated, and the container's real
memory stayed far above the floor. When the holders really use close to their weight there is no slack, the overcommit is 0 and nothing changes: that is the
point of measuring.

## Liveness and the container (W5)

The daemon runs under the container restart policy (`restart: unless-stopped` in docker-compose.yml). A stuck heartbeat loop is replaced in place. A poll loop
that has not turned for 300 seconds (a lookup that never returns) or a heartbeat that cannot be revived makes the process exit with code 3 (`WEDGED`); if the
daemon's own shutdown cannot run because the loop is stuck, the watchdog ends the process after its shutdown grace. The restart policy then starts a fresh one.
This applies to every Sentinel; before, only the built-in scanner restarted itself, and only on a heartbeat that did not reach the server.

The Docker `HEALTHCHECK` (`python3 -m client.control health`) now also fails when the watchdog has not ticked for 90 seconds, the heartbeat loop has not turned
for 420 seconds or the poll loop has not turned for 480 seconds (the daemon writes `liveness` into `control.json`). Docker does not restart a container only
because it is unhealthy. Either rely on the exit above, or add:

- **autoheal** (`willfarrell/autoheal`): a container that restarts every container labelled `autoheal=true` whose health is `unhealthy`; or
- **systemd** for a non-container install: a unit with `Restart=always` for the process, and a `systemd` timer or `ExecStartPre` that runs
  `python3 -m client.control health` and restarts the unit when it exits 1.

## What the Sentinels page gets (W7)

`info.watchdog` in the heartbeat, optional (a server that does not know the field drops it): `last_tick`, `actions_last_hour`, `kills`, `overcommit_active`,
`overcommit_mb`, `low_disk`, `withheld` (kinds), `spool` (when results are held), `reasons` (up to 5 short sentences) and `actions` (up to 8 of
`{at, code, kind, minutes}`).

## Variables

| variable | default | |
|---|---|---|
| `CVENGINE_SENTINEL_WATCHDOG` | on | `0` switches everything off |
| `CVENGINE_SENTINEL_WATCHDOG_TICK` | 10 | seconds between passes |
| `CVENGINE_SENTINEL_DEADLINE_<KIND>_MIN`, `..._DEFAULT_MIN` | the table | minutes; never below the tool's own budget |
| `CVENGINE_SENTINEL_NOPROGRESS_<KIND>_MIN`, `..._DEFAULT_MIN` | 15 (20 nuclei/nmap/wpscan, 30 bbot) | minutes without CPU or I/O |
| `CVENGINE_SENTINEL_WATCHDOG_PARTIAL` | on | report findings a stopped nuclei run had printed |
| `CVENGINE_SENTINEL_WATCHDOG_MEM_WAIT_SECONDS`, `..._MEM_HOLD_SECONDS` | 180, 300 | W3 triggers |
| `CVENGINE_SENTINEL_WATCHDOG_OVERCOMMIT_PERCENT` | 25 | 0 turns the overcommit off |
| `CVENGINE_SENTINEL_WATCHDOG_MEM_FLOOR_MB` | max(300, 15 percent of the limit) | real free memory that is never gone below |
| `CVENGINE_SENTINEL_WATCHDOG_MEM_KILL` | off | last-resort stop of the newest heavy run |
| `CVENGINE_SENTINEL_WATCHDOG_HEARTBEAT_STALE_SECONDS`, `..._POLL_STALE_SECONDS` | 150, 300 | minimums 90 and 120 |
| `CVENGINE_SENTINEL_WATCHDOG_DISK_FLOOR_MB` | 300 | |
| `CVENGINE_SENTINEL_WATCHDOG_KILLS_PER_HOUR`, `..._WITHHOLD_MINUTES` | 3, 30 | |

## What the disk rule removes

Only this Sentinel's own files, older than 3 hours: `cvengine-*` and `secrets-*` work directories and `tmp*.txt` target lists in the temp directory, nuclei's
cache under `~/.cache/nuclei` (not while a task runs) and its `resume-*` files. Never the state volume (token, spool, badkeys), templates or anything else.
