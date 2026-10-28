"""The hand-off between the daemon and the host-side updater (``scripts/update.sh``), through files in the state volume.

The updater runs on the Docker host, not in a container with the Docker socket, so it can only talk to the daemon by running this module inside
the Sentinel container (``docker compose exec sentinel python3 -m client.control ...``). It asks the daemon to stop taking tasks (``drain``),
waits until none are running (``wait-idle``), recreates the stack, and records how it went (``report``), which the daemon sends to cvENGINE with its
heartbeat. A drain flag expires on its own after ``DRAIN_TTL`` and is cleared at every daemon start, so an updater that died half way never leaves a
Sentinel drained for good. Nothing here is a command from the server: ``wanted`` only reads the update mode the server last reported.
"""
import json
import os
import sys
import threading
import time

from . import config

DRAIN_TTL = 2 * 3600
STATUS_MAX_AGE = 180  # the daemon rewrites its status at every heartbeat; one older than this means it is not running
UPDATE_STATUSES = ('idle', 'waiting', 'draining', 'updating', 'done', 'failed')


def state_dir():
    return os.path.dirname(config.token_path()) or '.'


def _path(name):
    return os.path.join(state_dir(), name)


def _write_json(name, data):
    os.makedirs(state_dir(), exist_ok=True)
    tmp = _path(f'{name}.{os.getpid()}.{threading.get_ident()}.tmp')  # the heartbeat and a task thread may write at once
    with open(tmp, 'w', encoding='utf-8') as handle:
        json.dump(data, handle)
    os.replace(tmp, _path(name))


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

def write_status(version, in_flight, update_reply, now=None):
    update_reply = update_reply if isinstance(update_reply, dict) else {}
    _write_json('control.json', {'version': version, 'in_flight': in_flight, 'draining': is_draining(), 'mode': update_reply.get('mode'),
                                 'requested': bool(update_reply.get('requested')), 'at': int(now or time.time())})


def read_status():
    return _read_json('control.json')


def idle(now=None):
    """Whether the daemon is running and holds no task."""
    status = read_status()
    return bool(status) and (now or time.time()) - status.get('at', 0) <= STATUS_MAX_AGE and status.get('in_flight') == 0


def wanted(status=None):
    """Whether cvENGINE wants this Sentinel updated now: its update mode is automatic, or an administrator asked for this Sentinel."""
    status = status if status is not None else read_status()
    return status.get('mode') == 'auto' or bool(status.get('requested'))


# --- the updater's own progress ----------------------------------------------------------------------------------------------------------

def record_update(status, phase='', detail='', previous='', target=''):
    if status not in UPDATE_STATUSES:
        raise ValueError(f'status must be one of {", ".join(UPDATE_STATUSES)}')
    _write_json('update.json', {'status': status, 'phase': phase[:60], 'detail': detail[:300], 'from': previous[:64], 'to': target[:64],
                                'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})


def read_update():
    data = _read_json('update.json')
    return data if data.get('status') in UPDATE_STATUSES else {}


# --- command line ------------------------------------------------------------------------------------------------------------------------

def main(argv):
    command = argv[0] if argv else 'status'
    rest = argv[1:]
    if command == 'status':
        print(json.dumps(read_status()))
    elif command == 'wanted':
        print('yes' if wanted() else 'no')
    elif command == 'drain':
        set_draining(True)
    elif command == 'undrain':
        set_draining(False)
    elif command == 'wait-idle':
        timeout = int(rest[rest.index('--timeout') + 1]) if '--timeout' in rest else 1800
        deadline = time.time() + timeout
        while time.time() < deadline:
            if idle():
                return 0
            time.sleep(5)
        return 1
    elif command == 'report':
        if not rest:
            print('usage: report STATUS [--phase P] [--detail D] [--from V] [--to V]', file=sys.stderr)
            return 2
        opts = {rest[i].lstrip('-'): rest[i + 1] for i in range(1, len(rest) - 1, 2)}
        record_update(rest[0], opts.get('phase', ''), opts.get('detail', ''), opts.get('from', ''), opts.get('to', ''))
    else:
        print('commands: status, wanted, drain, undrain, wait-idle [--timeout S], report STATUS [...]', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
