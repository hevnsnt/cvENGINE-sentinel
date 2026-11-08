# Changelog

## Unreleased

### Added
- A Sentinel that cvENGINE asks to update (heartbeat answer `update.requested` with `update.target`) can drain and exit with code 76 so its supervisor brings the
  newest image: `CVENGINE_SENTINEL_UPDATE_EXIT=1`, `client/selfupdate.py`, `scripts/pull-on-exit.sh`. It never leaves while a task runs past the drain limit, never to the build it
  already runs, never twice for the same target within 6 hours, and never for the built-in scanner or a machine whose own self-update ceiling is off.

### Changed
- README: "cvENGINE asks for the newest version" describes who acts on the request (the host updater, the exit-code supervisor, the server's host for the built-in scanner).
