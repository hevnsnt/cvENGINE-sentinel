"""The Sentinel daemon: bootstrap once, then loop long-polling for work, running it, and reporting back.

Startup: a persisted token (``config.token_path()``) is used directly when present, skipping bootstrap entirely. Only
without one is ``CVENGINE_SENTINEL_BLOB`` required, decoded, and traded for a token via ``POST sentinels/bootstrap``;
the token is then persisted (0600) and never logged.

Main loop: long-poll ``sentinel/tasks/next``, ``accept`` what is leased, run the matching tool against only the
task's own typed ``target`` (``tools.RUNNERS``, which never shell-interprets anything), and ``POST`` the typed result
back. A concurrent heartbeat thread keeps the lease alive every ``config.HEARTBEAT_SECONDS``. A network failure backs
off and retries; a bad task reports ``outcome: error`` and the loop continues, never crash-loops. SIGTERM stops new
polling and gives in-flight tasks ``config.SHUTDOWN_GRACE_SECONDS`` to finish, then releases (and kills) whichever
have not, rather than abandoning them silently.
"""
import json
import logging
import os
import platform
import threading
import time

import requests

from . import blob as blob_mod
from . import config
from . import httpclient
from . import tools

logger = logging.getLogger('sentinel.daemon')


def _describe_target(target):
    """A short, safe line about what a task is aimed at, for the log: a count, never the addresses or any secret in the target."""
    target = target if isinstance(target, dict) else {}
    for key in ('targets', 'addresses'):
        if isinstance(target.get(key), list):
            return f'{len(target[key])} target(s)'
    if isinstance(target.get('hosts'), (list, dict)):
        return f'{len(target["hosts"])} host(s)'
    return 'one target'

RECONCILE_GRACE_SECONDS = 10.0  # a task accepted this recently may not be in the heartbeat's lease list yet
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0


def load_token(path):
    """``(token, server_url)`` from a persisted token file, or ``(None, None)`` when there is none or it is unreadable:
    a Sentinel with no good persisted token simply falls through to bootstrapping from the blob again."""
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None, None
    token, server_url = data.get('token'), data.get('server_url')
    if isinstance(token, str) and token and isinstance(server_url, str) and server_url:
        return token, server_url
    return None, None


def save_token(path, token, server_url):
    """Persist the token at 0600, created if needed. Never logs ``token``."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'token': token, 'server_url': server_url}, handle)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def declared_kinds(kinds=None):
    """The scan kinds this Sentinel can run right now, which is what it tells the server it can do. ``openvas`` is declared only while this
    Sentinel's own GVM stack answers (its socket exists), so a Sentinel started without the stack, or whose stack is still syncing feeds,
    is never handed OpenVAS work it cannot run; and a kind the operator disabled (CVENGINE_SENTINEL_DISABLE) is never declared."""
    off = config.disabled_kinds()
    declared = [k for k in config.registered_capabilities(kinds) if k not in off]
    if 'openvas' in declared and not tools.gvm_available():
        declared.remove('openvas')
    return declared


def bootstrap(blob_raw, name, max_concurrent, client_factory=httpclient.Client):
    """Decode the provisioning blob and trade it for this Sentinel's own token. Returns ``(token, server_url)``; the
    caller persists it. Raises ``blob.BlobError`` on a bad blob, ``httpclient.ApiError``/``requests.RequestException``
    on a failed call - both are fatal at startup (there is nothing useful to retry without a human's new blob)."""
    payload = blob_mod.decode_blob(blob_raw)
    server_url = payload['server_url']
    client = client_factory(server_url)
    body = {'enrollment_token': payload['enrollment_token'], 'name': name, 'capabilities': declared_kinds(),
            'os': [config.os_family()] if config.os_family() else [], 'tools': tools.detect_tools(),
            'max_concurrent': max_concurrent}
    out = client.call('POST', 'sentinels/bootstrap', body)
    token = out.get('token')
    if not isinstance(token, str) or not token:
        raise httpclient.ApiError(502, 'bootstrap did not return a token')
    return token, server_url


def register(client, name, max_concurrent, kinds=None):
    """(Re-)register this Sentinel with the server: name, capabilities, os, tools and max_concurrent. Called on every
    startup, not just the first, so a restarted Sentinel always reports its current capacity
    (CVENGINE_SENTINEL_MAX_CONCURRENT, or the host's freshly auto-detected CPU count) instead of whatever was true
    the one time it originally bootstrapped. ``scope`` is left out on purpose: ``PUT sentinel`` only changes fields
    given in the body, so this never touches the scope an enrollment secret already assigned."""
    body = {'name': name, 'capabilities': declared_kinds(kinds), 'os': [config.os_family()] if config.os_family() else [],
            'tools': tools.detect_tools(), 'max_concurrent': max_concurrent}
    client.call('PUT', 'sentinel', body)


class Daemon:
    def __init__(self, server_url, token, max_concurrent=1, kinds=None, client=None, heartbeat_seconds=None):
        self.client = client or httpclient.Client(server_url, token)
        self.max_concurrent = max(1, max_concurrent)
        self.kinds = list(kinds or config.CAPABILITIES)
        self._kinds_given = bool(kinds)
        self.reregister = None  # set by the entry point: re-sends this Sentinel's registration when what it can run changes
        self._declared = declared_kinds(kinds)  # what startup registered, so a change after it is noticed
        self.heartbeat_seconds = heartbeat_seconds or config.HEARTBEAT_SECONDS
        self.stop_event = threading.Event()
        self._lock = threading.Lock()
        self._in_flight = {}  # task_id -> {'proc': Popen|None, 'done': threading.Event}
        self._backoff = MIN_BACKOFF

    # --- lifecycle --------------------------------------------------------------------------------------------

    def run(self):
        hb = threading.Thread(target=self._heartbeat_loop, name='sentinel-heartbeat', daemon=True)
        hb.start()
        try:
            while not self.stop_event.is_set():
                self._poll_once()
        finally:
            self._shutdown()
            hb.join(timeout=2)

    def request_stop(self):
        self.stop_event.set()

    def _active_count(self):
        with self._lock:
            return len(self._in_flight)

    # --- heartbeat ----------------------------------------------------------------------------------------------

    def _heartbeat_loop(self):
        while not self.stop_event.wait(self.heartbeat_seconds):
            try:
                out = self.client.call('POST', 'sentinel/heartbeat')
            except (httpclient.ApiError, requests.RequestException) as exc:
                logger.warning('heartbeat failed: %s', exc)
                continue
            self._reconcile((out or {}).get('leases'))
            self._refresh_registration()

    def _poll_kinds(self):
        """The kinds worth asking the server for now: the configured ones, less any the operator disabled and ``openvas`` while no GVM stack answers."""
        off = config.disabled_kinds()
        kinds = [k for k in self.kinds if k not in off]
        if 'openvas' in kinds and not tools.gvm_available():
            kinds.remove('openvas')
        return kinds

    def _refresh_registration(self):
        """A GVM stack that finished syncing after this Sentinel started (it can take hours the first time) makes ``openvas`` runnable, and
        one that stopped makes it not; register again when what this Sentinel can run has changed since it last told the server."""
        if self.reregister is None:
            return
        declared = declared_kinds(self.kinds if self._kinds_given else None)
        if declared == self._declared:
            return
        try:
            self.reregister()
        except (httpclient.ApiError, requests.RequestException) as exc:
            logger.warning('could not refresh registration: %s', exc)
            return
        logger.info('capabilities changed: now %s', ', '.join(declared))
        self._declared = declared

    def _reconcile(self, leases):
        """The heartbeat answers with the tasks the server still holds for this Sentinel. A task running here that is not among them was
        taken back (the stage that dispatched it gave up and ran the tool itself, a person cancelled it, this Sentinel was suspended): its
        result will be refused, so the run is killed instead of burning CPU for nothing. ``leases`` None (an answer with no list) judges nothing."""
        if not isinstance(leases, list):
            return
        held = {lease.get('task_id') for lease in leases if isinstance(lease, dict)}
        with self._lock:
            running = dict(self._in_flight)
        for task_id, state in running.items():
            if task_id in held or time.monotonic() - state.get('started', time.monotonic()) < RECONCILE_GRACE_SECONDS:
                continue
            logger.warning('task %s is no longer assigned to this Sentinel (taken back by the server); stopping it', task_id)
            state['dropped'] = True
            proc = state.get('proc')
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass

    # --- polling and task execution ------------------------------------------------------------------------------

    def _poll_once(self):
        if self._active_count() >= self.max_concurrent:
            time.sleep(0.5)
            return
        try:
            out = self.client.call('POST', 'sentinel/tasks/next', {'wait': config.DEFAULT_POLL_WAIT, 'kinds': self._poll_kinds()})
        except (httpclient.ApiError, requests.RequestException) as exc:
            logger.warning('poll failed: %s', exc)
            self._sleep_backoff()
            return
        self._backoff = MIN_BACKOFF
        task = (out or {}).get('task')
        if not task:
            return
        self._start_task(task)

    def _sleep_backoff(self):
        time.sleep(min(MAX_BACKOFF, self._backoff))
        self._backoff = min(MAX_BACKOFF, self._backoff * 2)

    def _start_task(self, task):
        task_id = task['id']
        try:
            self.client.call('POST', f'sentinel/tasks/{task_id}/accept')
        except (httpclient.ApiError, requests.RequestException) as exc:
            logger.warning('could not accept task %s: %s', task_id, exc)
            return
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False}
        with self._lock:
            self._in_flight[task_id] = state
        logger.info('task %s accepted: %s (%s)', task_id, task.get('kind'), _describe_target(task.get('target')))
        thread = threading.Thread(target=self._run_task, args=(task, state), name=f'sentinel-task-{task_id}', daemon=True)
        thread.start()

    def _register_proc(self, state):
        def register(proc):
            state['proc'] = proc
        return register

    def _run_task(self, task, state):
        task_id = task['id']
        outcome = 'error'
        try:
            result = self._execute(task, self._register_proc(state))
            outcome = result.get('outcome', 'done')
            self._report_unless_dropped(task_id, state, result)
        except tools.TargetError as exc:
            self._report_unless_dropped(task_id, state, {'outcome': 'error', 'error': str(exc)[:280]})
        except Exception as exc:  # noqa: BLE001 - one bad task must never take the daemon down
            if not state.get('dropped'):
                logger.exception('task %s failed', task_id)
            self._report_unless_dropped(task_id, state, {'outcome': 'error', 'error': str(exc)[:280]})
        finally:
            logger.info('task %s finished: %s, %s, %.1fs', task_id, task.get('kind'), 'dropped by the server' if state.get('dropped') else outcome,
                        time.monotonic() - state.get('started', time.monotonic()))
            state['done'].set()
            with self._lock:
                self._in_flight.pop(task_id, None)

    def _report_unless_dropped(self, task_id, state, result):
        if state.get('dropped'):  # the server took it back: it would refuse the result
            return
        self._report(task_id, result)

    def _execute(self, task, register):
        kind = task.get('kind')
        runner = tools.RUNNERS.get(kind)
        if runner is None:
            raise tools.TargetError(f'unknown task kind {kind!r}')
        target = task.get('target') or {}
        if kind in ('nmap', 'naabu'):
            out = runner(target.get('addresses') or [], register=register)
        elif kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            out = runner(target.get('targets') or [], tags=target.get('tags'), severities=target.get('severities'), register=register)
        elif kind == 'testssl':
            out = runner(target.get('host') or '', target.get('ip') or '', target.get('port'), target.get('starttls') or '', register=register)
        elif kind == 'nmap_udp':
            out = runner(target.get('address') or '', register=register)
        elif kind == 'wpscan':
            out = runner(target.get('url') or '', target.get('token') or '', register=register)
        elif kind == 'openvas':
            out = runner(target.get('hosts') or {}, target.get('excluded_families') or [], target.get('max_hours'), register=register)
        else:
            raise tools.TargetError(f'unknown task kind {kind!r}')
        return {'outcome': 'done', **out}

    def _report(self, task_id, result):
        try:
            self.client.call('POST', f'sentinel/tasks/{task_id}/result', result)
        except (httpclient.ApiError, requests.RequestException) as exc:
            logger.warning('could not report result for task %s: %s', task_id, exc)

    # --- shutdown -------------------------------------------------------------------------------------------------

    def _shutdown(self):
        """Give in-flight tasks ``config.SHUTDOWN_GRACE_SECONDS`` to finish and report normally; whichever have not,
        kill their subprocess (so nothing is left running orphaned) and release the task back to the queue instead of
        letting its lease simply expire."""
        deadline = time.monotonic() + config.SHUTDOWN_GRACE_SECONDS
        with self._lock:
            pending = dict(self._in_flight)
        for state in pending.values():
            remaining = max(0.0, deadline - time.monotonic())
            state['done'].wait(timeout=remaining)
        with self._lock:
            still_running = dict(self._in_flight)
        for task_id, state in still_running.items():
            proc = state.get('proc')
            if proc is not None and proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            try:
                self.client.call('POST', f'sentinel/tasks/{task_id}/release', {'reason': 'Sentinel shutting down'})
            except (httpclient.ApiError, requests.RequestException) as exc:
                logger.warning('could not release task %s on shutdown: %s', task_id, exc)
