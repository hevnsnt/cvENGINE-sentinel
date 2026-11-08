"""Drain and exit so a supervisor can bring the newest image: the daemon's half of "cvENGINE keeps Sentinels on the newest version".

cvENGINE asks a Sentinel to update through the heartbeat answer's ``update`` object: ``requested`` (true), ``target`` (the commit it wants this
Sentinel on) and ``reason``. A client that does not know ``target`` ignores it, and the host-side updater (scripts/update.sh) keeps acting on
``requested`` exactly as before. This module is the second way, for a Sentinel whose supervisor replaces the image when the container stops
(a compose file with an image pulled on start, a watchtower-style updater, ``scripts/pull-on-exit.sh``): with ``CVENGINE_SENTINEL_UPDATE_EXIT=1`` the
daemon stops taking work, waits for the tasks in flight, and exits with ``UPDATE_EXIT``. It never exits while a task runs past the drain limit (it
goes back to work and tries again after ``RETRY_AFTER``), never for the built-in scanner (its image is replaced from the host:
scripts/scanner-update.sh) or a machine whose own ceiling is ``off``, never to the build it already runs, and never twice for the same target
within ``RETRY_AFTER``: a supervisor that brought nothing newer must not turn into a restart loop.
"""
import json
import logging
import os
import re
import time

from . import config, control

logger = logging.getLogger('sentinel.selfupdate')

UPDATE_EXIT = 76  # exit code: drained, wants a newer image (documented in README "Updates"); compose restarts the container, a puller swaps the image first
RETRY_AFTER = 6 * 3600  # seconds before the same target may stop this Sentinel again
HEX = re.compile(r'^[0-9a-f]{7,40}$')
DEFAULT_DRAIN_SECONDS = 1800


def enabled():
    """CVENGINE_SENTINEL_UPDATE_EXIT: on only when the person running this Sentinel says a supervisor replaces the image after it exits."""
    return (os.environ.get('CVENGINE_SENTINEL_UPDATE_EXIT') or '').strip().lower() in ('1', 'true', 'yes', 'on')


def drain_seconds():
    try:
        value = int((os.environ.get('CVENGINE_SENTINEL_DRAIN_TIMEOUT') or '').strip())
    except ValueError:
        return DEFAULT_DRAIN_SECONDS
    return value if value > 0 else DEFAULT_DRAIN_SECONDS


def _state_path():
    return os.path.join(control.state_dir(), 'update-exit.json')


def last():
    """``{target, at}`` of the last time this Sentinel left to update, or ``{}``."""
    try:
        with open(_state_path(), encoding='utf-8') as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def remember(target, now=None):
    os.makedirs(control.state_dir(), exist_ok=True)
    with open(_state_path(), 'w', encoding='utf-8') as handle:
        json.dump({'target': target, 'at': int(now or time.time())}, handle)


def should_exit(reply, version, now=None):
    """``(True, target)`` when this Sentinel should drain and exit now, else ``(False, reason)``."""
    now = now or time.time()
    if not enabled():
        return False, 'CVENGINE_SENTINEL_UPDATE_EXIT is not set'
    if not isinstance(reply, dict) or not reply.get('requested'):
        return False, 'no update requested'
    setting = config.capped_self_update(reply.get('setting') if reply.get('setting') in config.SELF_UPDATE else None)
    if setting == 'off':
        return False, 'self-update is off for this Sentinel'
    target = str(reply.get('target') or '').strip().lower()
    if not HEX.match(target):
        return False, 'the request names no commit to update to'
    version = str(version or '').strip().lower()
    if version and HEX.match(version) and (target.startswith(version) or version.startswith(target)):
        return False, 'already running the requested build'
    seen = last()
    if seen.get('target') == target and now - float(seen.get('at') or 0) < RETRY_AFTER:
        return False, 'already left once for this build; the supervisor brought nothing newer, so not again yet'
    return True, target
