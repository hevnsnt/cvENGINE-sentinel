"""The Sentinel daemon: bootstrap once, then loop long-polling for work, running it, and reporting back.

Startup: a persisted token (``config.token_path()``) is used directly when present, skipping bootstrap entirely. Only
without one is ``CVENGINE_SENTINEL_BLOB`` required, decoded, and traded for a token via ``POST sentinels/bootstrap``;
the token is then persisted (0600, written atomically) and never logged.

Main loop: long-poll ``sentinel/tasks/next``, ``accept`` what is leased, run the matching tool against only the
task's own typed ``target`` (``tools.RUNNERS``, which never shell-interprets anything), and ``POST`` the typed result
back, retrying a failed post with bounded backoff and releasing the task if it still cannot be delivered. A concurrent
heartbeat thread keeps the lease alive every ``config.HEARTBEAT_SECONDS``. A network failure backs off and retries; a
malformed reply is skipped and a bad task reports ``outcome: error``, so the loop never crash-loops. A revoked token
stops the daemon with a non-zero exit. SIGTERM stops new polling and gives in-flight tasks
``config.SHUTDOWN_GRACE_SECONDS`` to finish; whichever have not are marked dropped, killed and released exactly once,
and never report the killed run's output as a result.
"""
import json
import logging
import os
import random
import re
import tempfile
import threading
import time

import requests

from . import blob as blob_mod
from . import config
from . import control
from . import httpclient
from . import openvas
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


def _clip(value, limit=40):
    """``value`` as printable text cut to ``limit`` characters: what the server sends goes into log lines and messages only this way."""
    return ''.join(c for c in str(value) if c.isprintable())[:limit]


RECONCILE_GRACE_SECONDS = 10.0  # a task accepted this recently may not be in the heartbeat's lease list yet
MIN_BACKOFF = 1.0
MAX_BACKOFF = 60.0
REPORT_ATTEMPTS = 5  # a result POST is tried this many times at most
REPORT_BACKOFF = 2.0  # seconds before the first retry, doubling each time
REPORT_MAX_DELAY = 30.0
REPORT_RETRY_SECONDS = 120.0  # and never for longer than this in all, so a dead server cannot hold a finished task forever
RELEASE_WAIT_SECONDS = 10.0  # after the grace period, how long shutdown waits for a task thread that is still delivering its result
AUTH_STATUSES = (401, 403)  # the server no longer accepts this Sentinel's token
_TASK_ID = re.compile(r'[A-Za-z0-9_-]{1,64}')  # an id goes into URL paths, thread names and log lines


def _retryable(exc):
    """Whether a failed call may succeed if tried again: a network error, a server error or rate limiting. Any other refusal is final."""
    if isinstance(exc, requests.RequestException):
        return True
    status = getattr(exc, 'status', None)
    return isinstance(status, int) and (status >= 500 or status == 429)


def _valid_task(task):
    """Whether a leased task is well formed enough to accept: an object with an id safe to put in a URL path and a kind that is text."""
    if not isinstance(task, dict):
        return False
    task_id = task.get('id')
    if isinstance(task_id, bool):
        return False
    if isinstance(task_id, int):
        ok = 0 <= task_id < 2 ** 63
    else:
        ok = isinstance(task_id, str) and _TASK_ID.fullmatch(task_id) is not None
    return ok and isinstance(task.get('kind'), str)


def load_token(path):
    """``(token, server_url)`` from a persisted token file, or ``(None, None)`` when there is none or it is unreadable:
    a Sentinel with no good persisted token simply falls through to bootstrapping from the blob again."""
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    token, server_url = data.get('token'), data.get('server_url')
    if isinstance(token, str) and token and isinstance(server_url, str) and server_url:
        return token, server_url
    return None, None


def save_token(path, token, server_url):
    """Persist the token at 0600, created if needed. Never logs ``token``. Written to a temporary file in the same directory, synced, then
    renamed over the old one: a crash part way leaves the previous file (or none), never a truncated token, because the single-use blob that
    produced it cannot be traded again."""
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.token-', suffix='.tmp', dir=directory)  # mkstemp creates it 0600
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'token': token, 'server_url': server_url}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)  # make the rename itself durable
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def runnable_kinds():
    """The scan kinds this Sentinel runs right now: what it polls for, declares, and accepts. ``openvas`` only while this Sentinel's own GVM
    stack answers, never a kind the operator disabled, and the internal-only kinds (``discover``) only when this machine's own configuration
    says it sits inside a private network, whatever the server's ``network`` setting says."""
    off = config.disabled_kinds()
    kinds = [k for k in config.poll_kinds() if k not in off and (k not in config.INTERNAL_KINDS or config._local_internal())]
    if 'openvas' in kinds and not tools.gvm_ready():
        kinds.remove('openvas')
    return kinds


def declared_kinds():
    """What this Sentinel tells the server it can do: the kinds it runs (``runnable_kinds``) plus the capabilities that are not scan kinds
    (``network:internal``), so a Sentinel is never handed work it would refuse."""
    scan_kinds = set(config.poll_kinds())
    return runnable_kinds() + [c for c in config.registered_capabilities() if c not in scan_kinds]


_detected = {}


def detected_tools():
    """``tools.detect_tools()``, probed once per process: the tools only change with the image, and probing runs five subprocesses that would
    otherwise delay a heartbeat at every re-registration."""
    if 'tools' not in _detected:
        _detected['tools'] = tools.detect_tools()
    return _detected['tools']


def bootstrap(blob_raw, name, max_concurrent, client_factory=httpclient.Client):
    """Decode the provisioning blob and trade it for this Sentinel's own token. Returns ``(token, server_url)``; the
    caller persists it. Raises ``blob.BlobError`` on a bad blob, ``httpclient.ApiError``/``requests.RequestException``
    on a failed call: both are fatal at startup (there is nothing useful to retry without a human's new blob)."""
    payload = blob_mod.decode_blob(blob_raw)
    server_url = payload['server_url']
    client = client_factory(server_url)
    body = {'enrollment_token': payload['enrollment_token'], 'name': name, 'capabilities': declared_kinds(),
            'os': [config.os_family()] if config.os_family() else [], 'tools': detected_tools(),
            'max_concurrent': max_concurrent, 'settings': config.local_settings()}
    out = client.call('POST', 'sentinels/bootstrap', body)
    token = out.get('token')
    if not isinstance(token, str) or not token:
        raise httpclient.ApiError(502, 'bootstrap did not return a token')
    return token, server_url


def info():
    """What this Sentinel reports about itself: its client version (when known) and its host-side updater's last state."""
    out = {}
    if config.version():
        out['version'] = config.version()
    update = control.read_update()
    if update:
        out['update'] = update
    out['updater'] = control.updater_info()  # installed or not, running or not, and how its last run went: a Sentinel that cannot update itself shows
    if 'openvas' in config.registered_capabilities() and 'openvas' not in config.disabled_kinds():
        ready, why = tools.gvm_status()  # cached for a minute; lets cvENGINE say why a Sentinel is not scanning (still syncing feeds, no scan config)
        out['openvas'] = {'ready': bool(ready), 'reason': '' if ready else str(why or '')[:200]}
    return out


def register(client, name, max_concurrent):
    """(Re-)register this Sentinel with the server: name, capabilities, os, tools and max_concurrent. Called on every
    startup, not just the first, so a restarted Sentinel always reports its current capacity
    (CVENGINE_SENTINEL_MAX_CONCURRENT, or the host's freshly auto-detected CPU count) instead of whatever was true
    the one time it originally bootstrapped. ``scope`` is left out on purpose: ``PUT sentinel`` only changes fields
    given in the body, so this never touches the scope an enrollment secret already assigned."""
    body = {'name': name, 'capabilities': declared_kinds(), 'os': [config.os_family()] if config.os_family() else [],
            'tools': detected_tools(), 'max_concurrent': max_concurrent, 'settings': config.local_settings(), 'info': info()}
    return client.call('PUT', 'sentinel', body)


class Daemon:
    def __init__(self, server_url, token, max_concurrent=1, client=None, heartbeat_seconds=None):
        self.client = client or httpclient.Client(server_url, token)
        self.max_concurrent = max(1, max_concurrent)
        self.reregister = None  # set by the entry point: sends this Sentinel's registration and returns the server's reply
        self.exit_code = 0  # non-zero once the server stopped accepting this Sentinel's token
        self._update_reply = None  # what cvENGINE last said about updating (mode, requested)
        self._register_pending = False  # the last registration did not reach the server: retried at every heartbeat until it does
        self._settings_rev = None  # fingerprint of the server's settings this Sentinel last applied
        self._registered = self._registration()  # what the server was last told, so a change after it is noticed
        self._gvm_swept = False  # the one-time sweep of leftover GVM tasks has run (or been started)
        self._unsaved_token = None  # (path, token, server_url) when saving a freshly bootstrapped token failed: retried at every heartbeat
        self.heartbeat_seconds = heartbeat_seconds or config.HEARTBEAT_SECONDS
        self.stop_event = threading.Event()  # set by SIGTERM: take no new work
        self._halted = threading.Event()  # set when the shutdown grace period is over: stop retrying, kill what is left
        self._lock = threading.Lock()
        self._in_flight = {}  # task_id -> {'proc', 'done', 'started', 'dropped', 'finishing', 'kind', 'runnable'}
        self._polling = False  # a long poll is outstanding: it may return a task, so the updater must not see this Sentinel idle
        self._backoff = MIN_BACKOFF

    # --- lifecycle --------------------------------------------------------------------------------------------

    def run(self):
        control.set_draining(False)  # a fresh start is never drained, whatever an updater that died half way left behind
        self._write_control()
        hb = threading.Thread(target=self._heartbeat_loop, name='sentinel-heartbeat', daemon=True)
        hb.start()
        try:
            while not self.stop_event.is_set():
                try:
                    self._poll_once()
                except Exception:  # noqa: BLE001 - a bug or a reply nobody anticipated must never end the daemon
                    logger.exception('the poll loop failed; backing off')
                    self._sleep_backoff()
        finally:
            self._shutdown()
            hb.join(timeout=2)

    def request_stop(self):
        self.stop_event.set()

    def start_registration(self):
        """Startup: register once and run with the settings the server's reply carries. A server that is down leaves the registration pending
        (the heartbeat retries it); the settings register again only when they change what the server was just told."""
        reply = self._refresh_registration(force=True)
        self.apply_settings((reply or {}).get('settings') if isinstance(reply, dict) else None)

    def keep_saving_token(self, path, token, server_url):
        """The token from bootstrap could not be saved: keep it in memory and try saving it again at every heartbeat."""
        self._unsaved_token = (path, token, server_url)

    def _active_count(self):
        with self._lock:
            return len(self._in_flight)

    def _auth_failed(self, exc):
        """Stop for good when the server says this Sentinel's token is no longer valid: backing off and polling forever would hide it."""
        if getattr(exc, 'status', None) not in AUTH_STATUSES:
            return False
        if not self.exit_code:
            logger.error("this Sentinel's token was revoked or is invalid; stopping")
        self.exit_code = 1
        self.stop_event.set()
        return True

    # --- heartbeat ----------------------------------------------------------------------------------------------

    def _heartbeat_loop(self):
        while not self.stop_event.wait(self.heartbeat_seconds):
            self._heartbeat_once()

    def _heartbeat_once(self):
        """One heartbeat. Whatever goes wrong is logged and the thread lives on to the next one, and the updater's status file is rewritten
        either way, so it never goes stale while the server is unreachable."""
        update_reply = None
        try:
            self._retry_token_save()
            asked_at = time.monotonic()
            try:
                out = self.client.call('POST', 'sentinel/heartbeat', {'info': info()})
            except (httpclient.ApiError, requests.RequestException) as exc:
                if not self._auth_failed(exc):
                    logger.warning('heartbeat failed: %s', exc)
                return
            out = out if isinstance(out, dict) else {}
            update_reply = out.get('update')
            self._reconcile(out.get('leases'), asked_at)
            self.apply_settings(out.get('settings'))
            self._refresh_registration()
            self._sweep_gvm_orphans()
        except Exception:  # noqa: BLE001 - the heartbeat keeps every lease alive; one bad iteration must not end it
            logger.exception('heartbeat failed')
        finally:
            self._write_control(update_reply)

    def _sweep_gvm_orphans(self):
        """Once, when this Sentinel's GVM stack first reports ready: remove the ``cvengine-sentinel-`` tasks and targets an earlier process left in gvmd
        (a shutdown mid-scan leaves them for good). Runs in its own thread because it opens a GMP session; it never raises."""
        if self._gvm_swept or not tools.gvm_available() or not tools.gvm_ready():
            return
        self._gvm_swept = True

        def sweep():
            removed = openvas.cleanup_orphans()
            if removed and (removed.get('tasks') or removed.get('targets')):
                logger.info('removed %s leftover GVM task(s) and %s target(s) from an earlier run', removed.get('tasks'), removed.get('targets'))
        threading.Thread(target=sweep, name='gvm-sweep', daemon=True).start()

    def _retry_token_save(self):
        if self._unsaved_token is None:
            return
        path = self._unsaved_token[0]
        try:
            save_token(*self._unsaved_token)
        except OSError as exc:
            logger.error('still cannot save the token at %s (%s); a restart now would need a new blob', path, exc)
            return
        self._unsaved_token = None
        logger.info('token persisted at %s', path)

    def apply_settings(self, reply):
        """Run with the settings the server sent (``{values, rev}``: the most recent of what an administrator set in cvENGINE and what this machine's
        own configuration says). A change is applied at once, and this Sentinel registers again when it changes what the server was told (name,
        concurrency, capabilities). This machine's own values are what gets reported, never these, so applying them is not itself seen as a local change."""
        if not isinstance(reply, dict) or not isinstance(reply.get('values'), dict):
            return
        rev = reply.get('rev')
        if rev is not None and rev == self._settings_rev and not self._register_pending:
            return
        before = config.overrides()
        config.set_overrides(reply['values'])
        after = config.overrides()
        self.max_concurrent = max(1, config.max_concurrent())
        self._settings_rev = rev
        if before != after:
            logger.info('settings from the server: %s', ', '.join(f'{k}={v}' for k, v in sorted(after.items())) or 'none (this machine\'s own)')
        self._refresh_registration()

    def _registration(self):
        """What a registration tells the server, to notice when it has changed: name, concurrency and capabilities."""
        return config.sentinel_name(), config.max_concurrent(), tuple(declared_kinds())

    def _refresh_registration(self, force=False):
        """Register again when what the server was last told has changed (a GVM stack that finished syncing after this Sentinel started makes
        ``openvas`` runnable, a stopped one makes it not, a setting changed the name), or when the last attempt failed. Returns the server's reply
        when it registered, else ``None``."""
        if self.reregister is None:
            return None
        current = self._registration()
        if not force and not self._register_pending and current == self._registered:
            return None
        try:
            reply = self.reregister()
        except (httpclient.ApiError, requests.RequestException) as exc:
            if not self._auth_failed(exc):
                logger.warning('could not register with the server (will retry at the next heartbeat): %s', exc)
                self._register_pending = True
            return None
        if current[2] != self._registered[2]:
            logger.info('capabilities changed: now %s', ', '.join(current[2]))
        self._register_pending = False
        self._registered = current
        return reply

    def _reconcile(self, leases, asked_at=None):
        """The heartbeat answers with the tasks the server still holds for this Sentinel. A task running here that is not among them was
        taken back (the stage that dispatched it gave up and ran the tool itself, a person cancelled it, this Sentinel was suspended): its
        result will be refused, so the run is killed instead of burning CPU for nothing. ``leases`` None (an answer with no list) judges nothing.
        ``asked_at`` is when the heartbeat was sent: a task started after it (less a grace) cannot be in the answer yet, however slow the reply."""
        if not isinstance(leases, list):
            return
        asked_at = time.monotonic() if asked_at is None else asked_at
        held = {lease.get('task_id') for lease in leases if isinstance(lease, dict) and isinstance(lease.get('task_id'), (int, str))}
        stale = []
        with self._lock:
            for task_id, state in self._in_flight.items():
                if task_id in held or state.get('finishing') or state['done'].is_set():
                    continue
                if state.get('started', asked_at) > asked_at - RECONCILE_GRACE_SECONDS:
                    continue
                state['dropped'] = True
                stale.append((task_id, state.get('proc')))
        for task_id, proc in stale:
            logger.warning('task %s is no longer assigned to this Sentinel (taken back by the server); stopping it', task_id)
            self._kill(proc, background=True)

    def _write_control(self, update_reply=None):
        """Tell the host-side updater where this Sentinel stands: running tasks (plus one while a poll that may return a task is outstanding),
        drain state, and what cvENGINE said about updating. Rewritten whenever a task starts or ends and around every poll, not only at
        heartbeats, so an updater waiting for it to go idle never reads a stale count."""
        if update_reply is not None:
            self._update_reply = update_reply
        try:
            control.write_status(config.version(), self._active_count() + (1 if self._polling else 0), self._update_reply)
        except Exception as exc:  # noqa: BLE001 - the updater's status is a side channel; it must never stop a heartbeat or a task
            logger.warning('could not write the updater status: %s', exc)

    # --- polling and task execution ------------------------------------------------------------------------------

    def _poll_kinds(self):
        """The kinds worth asking the server for now (``runnable_kinds``), computed at every call so a setting the server changed applies at once."""
        return runnable_kinds()

    def _poll_plan(self):
        """The kinds to ask for in this poll, given what is running. OpenVAS has its own slot: it never counts against ``max_concurrent``, and
        at most one OpenVAS task runs at a time. With every other slot taken, only OpenVAS (if no OpenVAS task runs) is asked for."""
        kinds = self._poll_kinds()
        with self._lock:
            running = [state.get('kind') for state in self._in_flight.values()]
        if 'openvas' in running and 'openvas' in kinds:
            kinds.remove('openvas')
        if sum(1 for kind in running if kind != 'openvas') >= self.max_concurrent:
            kinds = [k for k in kinds if k == 'openvas']
        return kinds

    def _poll_once(self):
        if control.is_draining():  # the host-side updater asked this Sentinel to finish what it has and take nothing new
            self.stop_event.wait(2)
            return
        kinds = self._poll_plan()
        if not kinds:  # every slot taken
            self.stop_event.wait(0.5)
            return
        self._polling = True
        self._write_control()
        try:
            out = self.client.call('POST', 'sentinel/tasks/next', {'wait': config.DEFAULT_POLL_WAIT, 'kinds': kinds})
        except (httpclient.ApiError, requests.RequestException) as exc:
            self._polling = False
            self._write_control()
            if not self._auth_failed(exc):
                logger.warning('poll failed: %s', exc)
                self._sleep_backoff()
            return
        finally:
            self._polling = False  # a task it returned is counted as running from here on (``_start_task``)
        self._backoff = MIN_BACKOFF
        task = out.get('task') if isinstance(out, dict) else None
        if not task:
            self._write_control()
            return
        if not _valid_task(task):
            self._write_control()
            logger.warning('ignoring a malformed task from the server: %s', _clip(repr(task), 80))
            self._sleep_backoff()
            return
        self._start_task(task, kinds)
        self._write_control()

    def _sleep_backoff(self):
        self.stop_event.wait(min(MAX_BACKOFF, self._backoff) * random.uniform(0.5, 1.0))
        self._backoff = min(MAX_BACKOFF, self._backoff * 2)

    def _start_task(self, task, kinds):
        task_id, kind = task['id'], task['kind']
        if self.stop_event.is_set() or control.is_draining():  # set while the poll was outstanding: the updater may already have seen this Sentinel idle
            self._release(task_id, 'Sentinel shutting down' if self.stop_event.is_set() else 'Sentinel is draining')
            return
        try:
            self.client.call('POST', f'sentinel/tasks/{task_id}/accept')
        except (httpclient.ApiError, requests.RequestException) as exc:
            if not self._auth_failed(exc):
                logger.warning('could not accept task %s: %s', task_id, exc)
            return
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False,
                 'kind': kind, 'runnable': kind in kinds}
        with self._lock:
            self._in_flight[task_id] = state
        self._write_control()
        logger.info('task %s accepted: %s (%s)', task_id, _clip(kind), _describe_target(task.get('target')))
        thread = threading.Thread(target=self._run_task, args=(task, state), name=f'sentinel-task-{task_id}', daemon=True)
        thread.start()

    def _register_proc(self, state):
        """The ``register`` callback a runner calls with each process (or OpenVAS handle) it starts. A task already dropped, or a daemon past
        its grace period, has the new process killed at once, so a runner that starts a second one (nmap's IPv6 group) cannot outlive a kill."""
        def register(proc):
            with self._lock:
                state['proc'] = proc
                stop = state.get('dropped') or self._halted.is_set()
            if stop:
                self._kill(proc)
        return register

    @staticmethod
    def _kill(proc, background=False):
        """Kill a subprocess, or anything with the same ``poll()``/``kill()`` (an OpenVAS run's handle), if it is still running. An OpenVAS handle's
        ``kill()`` stops the GVM task and deletes it, which can take half a minute: callers that must not wait (the heartbeat thread) pass
        ``background``, and the kill then runs in its own thread."""
        if proc is None:
            return
        if background:
            threading.Thread(target=Daemon._kill, args=(proc,), name='task-kill', daemon=True).start()
            return
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception as exc:  # noqa: BLE001 - a process that is already gone, or a handle whose stop failed, must not stop the caller
            logger.warning('could not stop a task process: %s', exc)

    def _run_task(self, task, state):
        task_id, kind = task['id'], task['kind']
        outcome = 'error'
        try:
            if not state.get('runnable'):
                raise tools.TargetError(f'this Sentinel does not run {_clip(kind)} work')
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
            logger.info('task %s finished: %s, %s, %.1fs', task_id, _clip(kind), 'dropped' if state.get('dropped') else outcome,
                        time.monotonic() - state.get('started', time.monotonic()))
            with self._lock:  # gone from the in-flight list before it is marked done, so shutdown never releases a finished task
                self._in_flight.pop(task_id, None)
            state['done'].set()
            self._write_control()

    def _report_unless_dropped(self, task_id, state, result):
        """Report the result unless the task was dropped (taken back by the server, or stopped by shutdown, which releases it itself). Whoever
        gets here first decides: once this thread starts reporting, a dropped mark can no longer land, and once dropped, nothing is reported."""
        with self._lock:
            if state.get('dropped'):
                return
            state['finishing'] = True
        self._report(task_id, result)

    def _execute(self, task, register):
        kind = task.get('kind')
        runner = tools.RUNNERS.get(kind)
        if runner is None:
            raise tools.TargetError(f'unknown task kind {_clip(kind)!r}')
        if kind in config.INTERNAL_KINDS and not config._local_internal():
            raise tools.TargetError(f'this Sentinel does not run {kind} work: this machine is not set up as internal')
        target = task.get('target') or {}
        if not isinstance(target, dict):
            raise tools.TargetError('the task target is not an object')
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
        elif kind == 'discover':
            out = runner(target.get('cidr') or '', register=register)
        else:  # openvas, the only other kind with a runner
            out = runner(target.get('hosts') or {}, target.get('excluded_families') or [], target.get('max_hours'), register=register,
                         preferences=target.get('preferences'))
        return {'outcome': 'done', **out}

    def _report(self, task_id, result):
        """POST the result, retrying a network error, a server error or rate limiting with exponential backoff and jitter (at most
        ``REPORT_ATTEMPTS`` tries within ``REPORT_RETRY_SECONDS``, and none once the shutdown grace period is over). Any other refusal is final.
        A result that still cannot be delivered releases the task so the server can run it again now rather than wait for the lease to expire."""
        give_up_at = time.monotonic() + REPORT_RETRY_SECONDS
        for attempt in range(REPORT_ATTEMPTS):
            try:
                self.client.call('POST', f'sentinel/tasks/{task_id}/result', result)
                return
            except (httpclient.ApiError, requests.RequestException) as exc:
                if not _retryable(exc):
                    logger.warning('the server refused the result for task %s: %s', task_id, exc)
                    return
                error = exc
            delay = min(REPORT_MAX_DELAY, REPORT_BACKOFF * 2 ** attempt) * random.uniform(0.5, 1.0)
            if attempt == REPORT_ATTEMPTS - 1 or time.monotonic() + delay > give_up_at:
                break
            logger.warning('could not report the result for task %s (%s); retrying in %.1fs', task_id, error, delay)
            if self._halted.wait(delay):
                break
        logger.error('could not report the result for task %s (%s); releasing it so the server can run it again', task_id, error)
        self._release(task_id, 'Sentinel could not deliver the result')

    def _release(self, task_id, reason):
        try:
            self.client.call('POST', f'sentinel/tasks/{task_id}/release', {'reason': reason})
        except (httpclient.ApiError, requests.RequestException) as exc:
            logger.warning('could not release task %s: %s', task_id, exc)

    # --- shutdown -------------------------------------------------------------------------------------------------

    def _shutdown(self):
        """Give in-flight tasks ``config.SHUTDOWN_GRACE_SECONDS`` to finish and report normally. Whichever have not are marked dropped first
        (so their thread never reports the killed run's output as a result), then killed (so nothing is left running orphaned) and released
        back to the queue instead of letting the lease simply expire. A task whose thread was already delivering its result is left to it:
        that thread stops retrying now and releases the task itself if the result does not get through."""
        deadline = time.monotonic() + config.SHUTDOWN_GRACE_SECONDS
        with self._lock:
            pending = list(self._in_flight.values())
        for state in pending:
            state['done'].wait(timeout=max(0.0, deadline - time.monotonic()))
        self._halted.set()
        stopping, finishing = {}, []
        with self._lock:
            for task_id, state in self._in_flight.items():
                if state['done'].is_set():
                    continue
                if state.get('finishing'):
                    finishing.append(state)
                    continue
                state['dropped'] = True
                stopping[task_id] = state
        for task_id, state in stopping.items():
            logger.warning('task %s did not finish within the shutdown grace period; stopping and releasing it', task_id)
            with self._lock:
                proc = state.get('proc')
            self._kill(proc)
            self._release(task_id, 'Sentinel shutting down')
        release_by = time.monotonic() + RELEASE_WAIT_SECONDS
        for state in finishing:
            state['done'].wait(timeout=max(0.0, release_by - time.monotonic()))
