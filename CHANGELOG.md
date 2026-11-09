# Changelog

## Unreleased

### Added
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
