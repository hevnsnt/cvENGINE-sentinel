"""The hand-off between the daemon and the host-side updater (``scripts/update.sh``), through files in the state volume.

The updater runs on the Docker host, not in a container with the Docker socket, so it can only talk to the daemon by running this module inside
the Sentinel container (``docker compose exec sentinel python3 -m client.control ...``). It asks the daemon to stop taking tasks (``drain``),
waits until none are running (``wait-idle``), recreates the stack, and records how it went (``report``), which the daemon sends to cvENGINE with its
heartbeat. A drain flag expires on its own after ``DRAIN_TTL`` and is cleared at every daemon start, so an updater that died half way never leaves a
Sentinel drained for good. Nothing here is a command from the server: ``wanted`` only reads the update mode the server last reported, under this
machine's own ceiling (``config.capped_self_update``). ``health`` is the container's health check: the daemon wrote its status recently, and for the
built-in scanner a heartbeat reached the server within ``HEARTBEAT_MAX_AGE`` (or it is still waiting for its first enrollment). ``heartbeat`` answers
only the second half: cvENGINE's updater asks it before it keeps a new built-in scanner image, and rolls back to the previous one otherwise.
"""
import json
import os
import sys
import threading
import time

from . import config

DRAIN_TTL = 2 * 3600
STATUS_MAX_AGE = 180  # the daemon rewrites its status at every heartbeat; one older than this means it is not running
WATCHDOG_STALE = 90  # the watchdog ticks every 10 s: one that has not for this long is stuck or gone
HEARTBEAT_LOOP_STALE = 420  # the heartbeat loop finishes a pass every minute and the watchdog restarts it at 150 s: still stale at this age, the watchdog is not doing it
POLL_LOOP_STALE = 480  # the poll loop turns every few seconds and the watchdog ends the process at 300 s
HEARTBEAT_MAX_AGE = 180  # the built-in scanner is unhealthy when no heartbeat reached the server for this long (and restarts itself: daemon.WEDGED)
UPDATE_STATUSES = ('waiting', 'draining', 'updating', 'done', 'failed')
UPDATER_ENV = 'CVENGINE_SENTINEL_UPDATER'  # ``installed``: written into .env by the installer, which runs before the stack is up to be told directly


def state_dir():
    return os.path.dirname(config.token_path()) or '.'


def _path(name):
    return os.path.join(state_dir(), name)


def _write_json(name, data):
    """Write ``name`` atomically: a reader sees the old file or the new one, never a partial one, and a failed write leaves no temp file behind."""
    os.makedirs(state_dir(), exist_ok=True)
    tmp = _path(f'{name}.{os.getpid()}.{threading.get_ident()}.tmp')  # the heartbeat and a task thread may write at once
    try:
        with open(tmp, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, _path(name))
    finally:
        try:
            os.unlink(tmp)  # gone already after a successful replace
        except OSError:
            pass


def _read_json(name):
    try:
        with open(_path(name), encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# --- draining ----------------------------------------------------------------------------------------------------------------------------

def set_draining(on):
    flag = _path('drain')
    if on:
        os.makedirs(state_dir(), exist_ok=True)
        with open(flag, 'w', encoding='utf-8') as handle:
            handle.write(str(int(time.time())))
    else:
        try:
            os.unlink(flag)
        except OSError:
            pass


def is_draining(now=None):
    try:
        return ((now or time.time()) - os.path.getmtime(_path('drain'))) < DRAIN_TTL
    except OSError:
        return False


# --- the daemon's status, for the updater to read -----------------------------------------------------------------------------------------

def write_status(version, in_flight, update_reply, now=None, kinds=None, heartbeat_at=None, started_at=None, liveness=None):
    """Written by the daemon. ``setting`` is the daemon's effective self-update value: what cvENGINE said in the heartbeat (else the server's settings
    override), capped by this machine's own. The CLI runs in another process, which never sees the daemon's overrides, so it decides on this value.
    ``kinds`` are the kinds of the tasks running now: the updater does not drain for an OpenVAS scan that runs for hours. ``heartbeat_at`` is when a
    heartbeat last reached the server and ``started_at`` when the daemon started (seconds since the epoch), for ``health`` and ``heartbeat``."""
    update_reply = update_reply if isinstance(update_reply, dict) else {}
    server = update_reply.get('setting') if update_reply.get('setting') in config.SELF_UPDATE else config.overrides().get('self_update')
    setting = config.capped_self_update(server)
    _write_json('control.json', {'version': version, 'in_flight': in_flight, 'draining': is_draining(), 'mode': update_reply.get('mode'),
                                 'setting': setting, 'requested': bool(update_reply.get('requested')), 'in_flight_kinds': sorted({k for k in (kinds or []) if isinstance(k, str)}),
                                 'at': int(now or time.time()), 'phase': 'running', 'builtin': config.builtin(),
                                 'heartbeat_at': int(heartbeat_at) if heartbeat_at else None, 'started_at': int(started_at or now or time.time()),
                                 **({'liveness': {k: int(v) for k, v in liveness.items()}} if liveness else {})})


def write_enrolling(now=None):
    """Written by the entry point while a built-in scanner with no token waits for the server's enrollment (``CVENGINE_SENTINEL_BLOB_FILE``): it is
    alive and has nothing to heartbeat with yet, which is healthy (the server is the one that has not written a blob: its status says why)."""
    _write_json('control.json', {'version': config.version(), 'in_flight': 0, 'draining': False, 'phase': 'enrolling', 'builtin': config.builtin(),
                                 'at': int(now or time.time())})


def read_status():
    return _read_json('control.json')


def idle(now=None):
    """Whether the daemon is running and holds no task."""
    status = read_status()
    return bool(status) and (now or time.time()) - status.get('at', 0) <= STATUS_MAX_AGE and status.get('in_flight') == 0


def health(now=None):
    """``(ok, reason)``: ok when the daemon wrote its status within ``STATUS_MAX_AGE`` (the same freshness rule ``idle`` uses), and, for the built-in
    scanner once it runs, a heartbeat reached the server within ``HEARTBEAT_MAX_AGE`` (since it started, when it has not heartbeated yet)."""
    status = read_status()
    if not status:
        return False, f'no daemon status at {_path("control.json")}'
    at = status.get('at')
    if not isinstance(at, int) or isinstance(at, bool):
        return False, 'the daemon status has no timestamp'
    now = now or time.time()
    age = int(now - at)
    if age > STATUS_MAX_AGE:
        return False, f'the daemon status is {age}s old (more than {STATUS_MAX_AGE}s): the daemon is not running or is stuck'
    live = status.get('liveness')
    if isinstance(live, dict) and status.get('phase') == 'running':  # written only while the watchdog is on (CVENGINE_SENTINEL_WATCHDOG=0 leaves it out)
        for key, limit, what in (('wd', WATCHDOG_STALE, 'the watchdog'), ('hb', HEARTBEAT_LOOP_STALE, 'the heartbeat loop'), ('poll', POLL_LOOP_STALE, 'the poll loop')):
            stamp = live.get(key)
            if isinstance(stamp, int) and not isinstance(stamp, bool) and now - stamp > limit:
                return False, f'{what} has not run for {int(now - stamp)}s (more than {limit}s): this Sentinel is stuck'
    if status.get('builtin') and status.get('phase') == 'running':
        quiet = _quiet_for(status, now)
        if quiet is None or quiet > HEARTBEAT_MAX_AGE:
            return False, (f'no heartbeat has reached the server for {quiet}s (more than {HEARTBEAT_MAX_AGE}s)' if quiet is not None
                           else 'the daemon status has no heartbeat time')
    return True, ''


def _quiet_for(status, now):
    """Seconds since a heartbeat last reached the server, or since the daemon started when none has yet (it is given that long); ``None`` unknown."""
    stamps = [v for v in (status.get('heartbeat_at'), status.get('started_at')) if isinstance(v, int) and not isinstance(v, bool)]
    return int(now - max(stamps)) if stamps else None


def heartbeat(status=None, now=None):
    """``(ok, reason)``: ok when the daemon runs and a heartbeat reached the server within ``HEARTBEAT_MAX_AGE``: what the updater waits for before it
    keeps a new built-in scanner image."""
    status = status if status is not None else read_status()
    now = now or time.time()
    if status.get('phase') != 'running':
        return False, 'the daemon is not running (still waiting for its enrollment, or no status)'
    at = status.get('heartbeat_at')
    if not isinstance(at, int) or isinstance(at, bool):
        return False, 'no heartbeat has reached the server yet'
    age = int(now - at)
    if age > HEARTBEAT_MAX_AGE:
        return False, f'no heartbeat has reached the server for {age}s (more than {HEARTBEAT_MAX_AGE}s)'
    return True, ''


def setting(status=None):
    """This Sentinel's self-update setting (``off``, ``manual`` or ``automatic``): the effective value the daemon last wrote (else none from the
    server), always capped by this machine's own configuration, so a local ``off`` or ``manual`` holds whatever the server says. ``unknown`` when
    neither says anything (a server that predates the setting: its ``mode`` and ``requested`` are all there is)."""
    status = status if status is not None else read_status()
    return config.capped_self_update(status.get('setting')) or 'unknown'


def wanted(status=None):
    """Whether this Sentinel should be updated now: never while its setting is Off (an administrator's request included); Automatic always; Manual only
    when an administrator asked for this Sentinel. A server that predates the setting is read the old way (its update mode is automatic, or an
    administrator asked)."""
    status = status if status is not None else read_status()
    current = setting(status)
    if current == 'off':
        return False
    if current == 'automatic':
        return True
    if current == 'manual':
        return bool(status.get('requested'))
    return status.get('mode') == 'auto' or bool(status.get('requested'))


# --- the updater's own progress ----------------------------------------------------------------------------------------------------------

def record_update(status, phase='', detail='', previous='', target=''):
    if status not in UPDATE_STATUSES:
        raise ValueError(f'status must be one of {", ".join(UPDATE_STATUSES)}')
    _write_json('update.json', {'status': status, 'phase': phase[:60], 'detail': detail[:300], 'from': previous[:64], 'to': target[:64],
                                'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})


# --- the updater's own heartbeat: is one installed, and is it running -------------------------------------------------------------------------

UPDATER_INTERVAL = 3600  # the hourly timer scripts/install-updater.sh sets up
UPDATER_SLACK = 2.5  # an updater that has not run for this many intervals is not running


def record_updater(result='', detail='', interval=UPDATER_INTERVAL, installed=False, now=None):
    """Written by ``scripts/update.sh`` at every run (and by ``install-updater.sh`` once, with ``installed``), so the daemon can report whether a host
    updater exists, whether it is running, and how its last run went. ``result`` is one of ``ok`` (nothing to update, or updated), ``waiting``,
    ``off``, ``updated`` or ``failed``."""
    previous = _read_json('updater.json')
    stamp = int(now or time.time())
    keep = installed and isinstance(previous.get('interval'), int) and previous['interval'] > 0  # an install marker does not change how often runs come
    data = {'installed_at': previous.get('installed_at') or stamp, 'interval': previous['interval'] if keep else (int(interval) if interval else UPDATER_INTERVAL)}
    if not installed:
        data.update(at=stamp, result=str(result)[:40], detail=''.join(c for c in str(detail) if c.isprintable())[:300])
    else:
        for key in ('at', 'result', 'detail'):
            if key in previous:
                data[key] = previous[key]
    _write_json('updater.json', data)


def remove_updater():
    try:
        os.unlink(_path('updater.json'))
    except OSError:
        pass


def updater_info(now=None):
    """``{installed, running, last_run, last_result, detail}`` for the heartbeat. Installed means the install script or an update run wrote its
    file, or ``CVENGINE_SENTINEL_UPDATER=installed`` is set: the installer runs before the stack is up on a first setup, so it cannot write the file
    then and puts that line in ``.env`` instead. Running means a run happened within ``UPDATER_SLACK`` intervals (the daemon only sees its own state
    volume, not the host's timer)."""
    data = _read_json('updater.json')
    if not data:
        return {'installed': (os.environ.get(UPDATER_ENV) or '').strip().lower() == 'installed', 'running': False}
    now = now or time.time()
    at = data.get('at')
    interval = data.get('interval') if isinstance(data.get('interval'), int) and data['interval'] > 0 else UPDATER_INTERVAL
    out = {'installed': True, 'running': isinstance(at, int) and now - at <= interval * UPDATER_SLACK}
    if isinstance(at, int):
        out['last_run'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(at))
    for key in ('result', 'detail'):
        if data.get(key):
            out['last_result' if key == 'result' else 'detail'] = data[key]
    return out


def read_update():
    data = _read_json('update.json')
    return data if data.get('status') in UPDATE_STATUSES else {}


# --- command line ------------------------------------------------------------------------------------------------------------------------

USAGE = ('usage: python3 -m client.control COMMAND\n'
         'commands: status, health, heartbeat, wanted, setting, drain, undrain, wait-idle [--timeout S], '
         'report STATUS [--phase P] [--detail D] [--from V] [--to V], updater-run RESULT [--detail D] [--interval S], '
         'updater-installed [--interval S], updater-removed')


class UsageError(Exception):
    """Bad arguments: the CLI prints the usage and exits 2, which the updater reads as a bug in its own call, not a failed update."""


def _options(args, allowed):
    """``--name value`` pairs, each name one of ``allowed``; anything else is a usage error."""
    if len(args) % 2:
        raise UsageError(f'expected --name value pairs, got {" ".join(args)!r}')
    out = {}
    for flag, value in zip(args[::2], args[1::2]):
        name = flag[2:] if flag.startswith('--') else ''
        if name not in allowed:
            raise UsageError(f'unknown option {flag!r}')
        out[name] = value
    return out


def _seconds(value, name):
    if not value.isdigit() or int(value) <= 0:
        raise UsageError(f'--{name} must be a whole number of seconds above 0, got {value!r}')
    return int(value)


def _status_json():
    """The daemon's status plus the effective self-update setting, as the updater and the feed refresh read it (``in_flight``, ``version``)."""
    status = read_status()
    return json.dumps({**status, 'setting': setting(status)})


def _run(command, rest):
    if command in ('status', 'health', 'heartbeat', 'wanted', 'setting', 'drain', 'undrain', 'updater-removed') and rest:
        raise UsageError(f'{command} takes no arguments')
    if command == 'status':
        print(_status_json())
    elif command == 'health':
        ok, why = health()
        if not ok:
            print(f'unhealthy: {why}', file=sys.stderr)
            return 1
    elif command == 'heartbeat':
        ok, why = heartbeat()
        if not ok:
            print(f'no heartbeat: {why}', file=sys.stderr)
            return 1
    elif command == 'wanted':
        print('yes' if wanted() else 'no')
    elif command == 'setting':
        print(setting())
    elif command == 'updater-run':
        if not rest or rest[0].startswith('--'):
            raise UsageError('updater-run needs a RESULT')
        opts = _options(rest[1:], ('detail', 'interval'))
        record_updater(rest[0], opts.get('detail', ''), _seconds(opts['interval'], 'interval') if 'interval' in opts else UPDATER_INTERVAL)
    elif command == 'updater-installed':
        opts = _options(rest, ('interval',))
        record_updater(interval=_seconds(opts['interval'], 'interval') if 'interval' in opts else UPDATER_INTERVAL, installed=True)
    elif command == 'updater-removed':
        remove_updater()
    elif command == 'drain':
        set_draining(True)
    elif command == 'undrain':
        set_draining(False)
    elif command == 'wait-idle':
        opts = _options(rest, ('timeout',))
        timeout = _seconds(opts['timeout'], 'timeout') if 'timeout' in opts else 1800
        deadline = time.time() + timeout
        while time.time() < deadline:
            if idle():
                return 0
            time.sleep(5)
        return 1
    elif command == 'report':
        if not rest or rest[0] not in UPDATE_STATUSES:
            raise UsageError(f'report needs a STATUS, one of {", ".join(UPDATE_STATUSES)}')
        opts = _options(rest[1:], ('phase', 'detail', 'from', 'to'))
        record_update(rest[0], opts.get('phase', ''), opts.get('detail', ''), opts.get('from', ''), opts.get('to', ''))
    else:
        raise UsageError(f'unknown command {command!r}')
    return 0


def main(argv):
    """Exit codes: 0 done (or yes/healthy), 1 a real negative answer (``wait-idle`` timed out, ``health`` failed), 2 bad usage."""
    try:
        return _run(argv[0] if argv else 'status', list(argv[1:]))
    except UsageError as exc:
        print(f'{exc}\n{USAGE}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
