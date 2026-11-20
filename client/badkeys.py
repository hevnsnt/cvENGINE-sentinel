"""The badkeys blocklist data the ``ssh_probe`` host key check reads, kept fresh on the Sentinel.

``sshamble badkeys-update`` downloads the public badkeys blocklist (badkeys.info, a rolling data set) into ``$HOME/.cache/badkeys``: the files
``badkeysdata.json`` (the manifest), ``blocklist.dat`` and ``lookup.txt``. Nothing in the image holds that data, so the daemon refreshes it itself:
once at start when it is missing or older than ``MAX_AGE_SECONDS``, then about every 24 hours, on a background thread that never touches task handling.

A refresh runs the tool into a staging directory under ``CVENGINE_BADKEYS_DIR`` (the tool takes no directory argument, so staging is its ``HOME``), checks
what it wrote, and only then makes it the current data. The live data is ``<dir>/current``, a link to a ``data-*`` directory, replaced by one atomic
rename: a scan sees the old data or the new data, never half of either, and a failed, timed out or corrupt download leaves the old data in place. (The
directory itself is a volume mount point in compose, so it cannot be renamed; the link inside it can.) Data placed directly in ``<dir>`` by hand is still
used when there is no ``current``.

The tool is run with exactly ``badkeys-update`` and nothing else: no URL, no flag. The source is fixed inside the tool, so this adds no egress beyond what
the tool itself does (the Sentinel's own proxy settings are passed on, as for every other download). ``CVENGINE_BADKEYS_REFRESH=0`` turns the refresh off
(air-gapped Sentinels): the host key check then reports "not checked" until data is placed in the directory some other way.
"""
import json
import logging
import os
import random
import secrets
import shutil
import subprocess
import tempfile
import threading
import time

from . import tools

logger = logging.getLogger('sentinel.badkeys')

FILES = ('badkeysdata.json', 'blocklist.dat', 'lookup.txt')  # the three files the tool loads (badkeys/cache.go)
CURRENT = 'current'
STAMP = '.refreshed'
MAX_AGE_SECONDS = 24 * 3600
INTERVAL_SECONDS = 24 * 3600
JITTER_FRACTION = 0.1  # the next run is 24 h plus or minus up to 10 %, so a fleet of Sentinels does not hit the source together
RETRY_SECONDS = 3 * 3600  # after a failed refresh
START_DELAY_SECONDS = 20  # the daemon is up and serving before the first download starts
REFRESH_TIMEOUT = 1200  # seconds for the whole run (the tool's own limit for the big file is an hour)
MAX_STDOUT = 4096
MAX_FILE_BYTES = 512 * 1024 * 1024  # the tool's own response cap
LOOKUP_SAMPLE_LINES = 2000
KEEP_VERSIONS = 2  # the newest data directory and the one before it (a scan that started on it may still be reading it)
FALSE_VALUES = ('0', 'false', 'no', 'off')
ARGV_TAIL = ['badkeys-update']

_lock = threading.Lock()  # one refresh at a time
_state = {'attempted_at': None, 'ok': None, 'error': ''}
_running = {'handle': None}
_thread = {'thread': None}  # the refresh loop, so asking to start it again while it runs starts nothing


class RefreshError(RuntimeError):
    """A refresh that did not produce usable data. The message is short and safe to log."""


def enabled(environ=None):
    value = (os.environ if environ is None else environ).get('CVENGINE_BADKEYS_REFRESH', '')
    return value.strip().lower() not in FALSE_VALUES


def root_dir():
    return tools.BADKEYS_DIR


def _has_files(directory):
    return bool(directory) and all(os.path.isfile(os.path.join(directory, name)) for name in FILES)


def data_dir(root=None):
    """The directory the host key check reads: ``<root>/current`` when it holds the data, else ``<root>`` itself when data was placed there by hand,
    else ``None``. Resolved to a real path so a link swapped later does not move a scan that already started."""
    root = root_dir() if root is None else root
    if not root:
        return None
    current = os.path.join(root, CURRENT)
    if _has_files(current):
        return os.path.realpath(current)
    if _has_files(root):
        return root
    return None


def refreshed_at(directory):
    """When the data in ``directory`` was fetched (seconds since the epoch), or ``None``."""
    try:
        with open(os.path.join(directory, STAMP), encoding='ascii') as handle:
            return float(handle.read(32).strip())
    except (OSError, ValueError):
        pass
    try:  # data placed by hand has no stamp: the manifest's file time is the best there is
        return os.path.getmtime(os.path.join(directory, FILES[0]))
    except OSError:
        return None


def age_hours(root=None, now=None):
    """Whole hours since the data was fetched, or ``None`` when there is no data (or its age is unknown)."""
    directory = data_dir(root)
    if directory is None:
        return None
    stamp = refreshed_at(directory)
    if stamp is None:
        return None
    return max(0, int(((time.time() if now is None else now) - stamp) // 3600))


def status(root=None, now=None):
    """What the heartbeat reports: ``{present, age_hours, refresh, last_ok, error}``."""
    present = data_dir(root) is not None
    out = {'present': present, 'age_hours': age_hours(root, now), 'refresh': enabled()}
    if _state['ok'] is not None:
        out['last_ok'] = bool(_state['ok'])
        if _state['error']:
            out['error'] = _state['error'][:200]
    return out


def needs_refresh(root=None, now=None):
    age = age_hours(root, now)
    return age is None or age * 3600 >= MAX_AGE_SECONDS


# --- validation -----------------------------------------------------------------------------------------------------------------------

def validate(directory):
    """Raise ``RefreshError`` unless ``directory`` holds data the tool can load: every file there and not empty, a manifest that decodes as the tool
    reads it, and a lookup list whose lines are ``<hex id>;<path>``."""
    for name in FILES:
        path = os.path.join(directory, name)
        try:
            size = os.path.getsize(path) if os.path.isfile(path) and not os.path.islink(path) else 0
        except OSError:
            size = 0
        if size <= 0:
            raise RefreshError(f'{name} is missing or empty')
        if size > MAX_FILE_BYTES:
            raise RefreshError(f'{name} is larger than expected')
    try:
        with open(os.path.join(directory, FILES[0]), 'rb') as handle:
            manifest = json.loads(handle.read(MAX_FILE_BYTES // 64))
    except (OSError, ValueError):
        raise RefreshError('the manifest does not decode') from None
    if not isinstance(manifest, dict) or not isinstance(manifest.get('date'), str) or not manifest['date'] \
            or not isinstance(manifest.get('blocklists'), list) or not manifest['blocklists']:
        raise RefreshError('the manifest has no date or no blocklists')
    good = 0
    with open(os.path.join(directory, FILES[2]), 'rb') as handle:
        for number, line in enumerate(handle):
            if number >= LOOKUP_SAMPLE_LINES:
                break
            kid, sep, path = line.decode('utf-8', errors='replace').rstrip('\r\n').partition(';')
            try:
                int(kid, 16)
            except ValueError:
                raise RefreshError('the lookup list has a line that is not "<id>;<path>"') from None
            if not sep or not path:
                raise RefreshError('the lookup list has a line that is not "<id>;<path>"')
            good += 1
    if good == 0:
        raise RefreshError('the lookup list is empty')


# --- the refresh ----------------------------------------------------------------------------------------------------------------------

def _run_tool(argv, timeout, env):
    """The real runner: the tool in its own session with a time and output limit (client.tools._run)."""
    def register(handle):
        _running['handle'] = handle
    try:
        tools._run(argv, timeout, register, max_bytes=MAX_STDOUT, env=env)
    finally:
        _running['handle'] = None


def _env(home):
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': home, 'TERM': 'dumb', 'LC_ALL': 'C'}
    for name in ('HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy'):  # the Sentinel's corporate proxy, as for every download
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def build_argv(binary=None):
    return [binary or tools.SSHAMBLE_BIN] + list(ARGV_TAIL)


def _swap_in(root, source, now):
    """Move the validated ``source`` into ``root`` as a new data directory and make it current with one atomic rename."""
    with open(os.path.join(source, STAMP), 'w', encoding='ascii') as handle:
        handle.write(f'{now:.0f}\n')
    for name in os.listdir(source):
        os.chmod(os.path.join(source, name), 0o644)
    os.chmod(source, 0o755)
    name = f'data-{int(now)}-{secrets.token_hex(3)}'
    target = os.path.join(root, name)
    os.rename(source, target)
    link = os.path.join(root, f'.{CURRENT}-{os.getpid()}.tmp')
    try:
        os.unlink(link)
    except OSError:
        pass
    os.symlink(name, link)  # relative: the directory may be mounted anywhere
    try:
        previous = os.path.join(root, CURRENT)
        if os.path.exists(previous) and not os.path.islink(previous):  # something other than our link in the way (a directory made by hand)
            raise RefreshError(f'{CURRENT} exists and is not a link')
        os.replace(link, previous)
    except Exception:
        try:
            os.unlink(link)
        except OSError:
            pass
        shutil.rmtree(target, ignore_errors=True)
        raise
    return name


def _prune(root, keep):
    try:
        entries = [n for n in os.listdir(root) if n.startswith('data-') and os.path.isdir(os.path.join(root, n))]
    except OSError:
        return
    # The directory just made current is always kept, then the newest of the others fill the remaining places. Ranking all of them by file
    # time alone let two directories made within one clock tick push it out of the top places, leaving one more than KEEP_VERSIONS behind.
    others = sorted((n for n in entries if n != keep), key=lambda n: (os.path.getmtime(os.path.join(root, n)), n), reverse=True)
    kept = set(others[:max(0, KEEP_VERSIONS - 1)]) | {keep}
    for name in entries:
        if name not in kept:
            shutil.rmtree(os.path.join(root, name), ignore_errors=True)


def _clean_staging(root, keep_seconds=0, now=None):
    try:
        names = [n for n in os.listdir(root) if n.startswith('.staging-')]
    except OSError:
        return
    now = time.time() if now is None else now
    for name in names:
        path = os.path.join(root, name)
        try:
            if now - os.path.getmtime(path) >= keep_seconds:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def refresh(runner=None, root=None, now=None):
    """One refresh. Returns ``{'status': 'updated'|'failed'|'busy'|'disabled', 'detail': str}`` and never raises: the old data stays on every failure.
    ``runner(argv, timeout, env)`` is the tool runner (a fake in tests)."""
    if not enabled():
        return {'status': 'disabled', 'detail': 'CVENGINE_BADKEYS_REFRESH is off'}
    if not _lock.acquire(blocking=False):
        return {'status': 'busy', 'detail': 'a refresh is already running'}
    try:
        root = root_dir() if root is None else root
        now = time.time() if now is None else now
        _state['attempted_at'] = now
        try:
            detail = _refresh(runner or _run_tool, root, now)
        except Exception as exc:  # noqa: BLE001 - the daemon never sees a failure from here; the old data stays
            message = exc if isinstance(exc, RefreshError) else f'{type(exc).__name__}: {exc}'
            detail = ''.join(ch for ch in str(message)[:300] if ch.isprintable())
            _state.update(ok=False, error=detail)
            logger.warning('badkeys refresh failed, the previous data (if any) stays in use: %s', detail)
            return {'status': 'failed', 'detail': detail}
        _state.update(ok=True, error='')
        logger.info('badkeys data refreshed: %s', detail)
        return {'status': 'updated', 'detail': detail}
    finally:
        _lock.release()


def _refresh(runner, root, now):
    if not root:
        raise RefreshError('no data directory is configured')
    os.makedirs(root, exist_ok=True)
    _clean_staging(root, keep_seconds=REFRESH_TIMEOUT * 2, now=now)  # leftovers of a refresh that was killed
    staging = tempfile.mkdtemp(prefix='.staging-', dir=root)
    try:
        home = os.path.join(staging, 'home')
        cache = os.path.join(home, '.cache', 'badkeys')  # where the tool writes: $HOME/.cache/badkeys
        os.makedirs(cache)
        try:
            runner(build_argv(), REFRESH_TIMEOUT, _env(home))
        except subprocess.TimeoutExpired as exc:
            raise RefreshError(f'the download timed out after {REFRESH_TIMEOUT}s') from exc
        validate(cache)
        size = sum(os.path.getsize(os.path.join(cache, n)) for n in FILES)
        name = _swap_in(root, cache, now)
        _prune(root, keep=name)
        return f'{size} bytes in {name}'
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def stop():
    """Kill a download in progress (daemon shutdown)."""
    handle = _running.get('handle')
    if handle is not None:
        try:
            handle.kill()
        except Exception:  # noqa: BLE001
            pass


# --- the schedule ---------------------------------------------------------------------------------------------------------------------

def next_delay(root=None, now=None, rng=random):
    """Seconds until the next refresh: now when the data is missing or at least a day old (after the start delay), else when it becomes a day old,
    plus jitter."""
    age = age_hours(root, now)
    directory = data_dir(root)
    stamp = refreshed_at(directory) if directory else None
    if age is None or stamp is None:
        return START_DELAY_SECONDS
    now = time.time() if now is None else now
    remaining = MAX_AGE_SECONDS - (now - stamp)
    if remaining <= 0:
        return START_DELAY_SECONDS
    return remaining + rng.uniform(0, JITTER_FRACTION * INTERVAL_SECONDS)


def jittered_interval(rng=random):
    return INTERVAL_SECONDS * (1 + rng.uniform(-JITTER_FRACTION, JITTER_FRACTION))


def run_forever(stop_event, runner=None, rng=random):
    """The background loop: first run per ``next_delay``, then about every 24 hours (sooner after a failure). Never raises."""
    try:
        delay = next_delay(rng=rng)
    except Exception:  # noqa: BLE001
        delay = START_DELAY_SECONDS
    while not stop_event.wait(delay):
        try:
            result = refresh(runner=runner)
            delay = RETRY_SECONDS if result['status'] == 'failed' else jittered_interval(rng)
        except Exception:  # noqa: BLE001 - refresh() does not raise; this is the belt for the braces
            logger.exception('badkeys refresh loop failed')
            delay = RETRY_SECONDS


def start(stop_event):
    """Start the refresh thread unless it is switched off (``CVENGINE_BADKEYS_REFRESH=0``) or there is no sshamble to run. Returns the thread or ``None``.
    Safe to call again (the daemon does, whenever its capabilities become known): while the thread runs, that thread is returned and none is added."""
    try:
        running = _thread['thread']
        if running is not None and running.is_alive():
            return running
        if not enabled():
            logger.info('badkeys refresh is off (CVENGINE_BADKEYS_REFRESH): the host key blocklist check stays "not checked" unless data is provided in %s', root_dir())
            return None
        if not tools.sshamble_ready():
            logger.info('badkeys refresh not started: the sshamble tool is not available on this Sentinel')
            return None
        thread = threading.Thread(target=run_forever, args=(stop_event,), name='sentinel-badkeys', daemon=True)
        thread.start()
        _thread['thread'] = thread
        return thread
    except Exception:  # noqa: BLE001 - never stops the daemon from starting
        logger.exception('badkeys refresh could not start')
        return None
