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
import math
import os
import random
import re
import tempfile
import threading
import time

import requests

from . import admission
from . import badkeys
from . import bbot
from . import blob as blob_mod
from . import config
from . import control
from . import httpclient
from . import openvas
from . import selfupdate
from . import spool as spool_mod
from . import shot
from . import signed_in
from . import templates
from . import tools
from . import watchdog as watchdog_mod

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


def _shown(key, value):
    """A setting as it may appear in the log: the vantage settings can carry a proxy login, so only their shape is shown."""
    if key != 'vantage' or not isinstance(value, dict):
        return value
    return (f"{len(value.get('proxies', []))} proxy(ies), {len(value.get('private_ranges', []))} private range(s)"
            + (' (built-in scanner only)' if not config.builtin() else ''))


def _clip(value, limit=40):
    """``value`` as printable text cut to ``limit`` characters: what the server sends goes into log lines and messages only this way."""
    return ''.join(c for c in str(value) if c.isprintable())[:limit]


MAX_ORPHAN_RELEASES = 20  # leases released per heartbeat, so a server with many stale ones cannot make one heartbeat very long
RECONCILE_GRACE_SECONDS = 10.0  # a task accepted this recently may not be in the heartbeat's lease list yet
MIN_BACKOFF = 1.0
MAX_RETRY_AFTER = 30.0  # the longest this Sentinel waits when the server answers "no task" and says when to ask again (retry_after_seconds)
IMMEDIATE_RETRY = 1.0  # a retry_after of this or less is the server's "ask again straight away", what it says after a full long poll: no extra wait
MAX_BACKOFF = 60.0
REPORT_ATTEMPTS = 4  # a result POST is tried this many times in a row before the result goes to the spool (a blip costs nothing on disk)
REPORT_BACKOFF = 2.0  # seconds before the first retry, doubling each time
REPORT_MAX_DELAY = 30.0
REPORT_RETRY_SECONDS = 20.0  # the quick retries stop after this long; a server still unreachable then gets the result from the spool (client/spool.py), for hours
SPOOL_MIN_BACKOFF = 2.0  # seconds between delivery passes while the server is unreachable, doubling to ...
SPOOL_MAX_BACKOFF = 60.0  # ... this, forever within the spool window
SPOOL_IDLE_SECONDS = 30.0  # how often an empty-handed spool thread looks again
QUIET_LOG_SECONDS = 600.0  # the same outage is named in the log this often (the first failure at once)
MAX_RESULT_BYTES = 23 * 1024 * 1024  # the server's result route refuses a body over 24 MB with a 400 that would end the task
RELEASE_WAIT_SECONDS = 10.0  # after the grace period, how long shutdown waits for a task thread that is still delivering its result
AUTH_STATUSES = (401, 403)  # the server no longer accepts this Sentinel's token
REENROLL = 75  # exit code of a built-in scanner whose token the server no longer accepts: the entry point re-enrols it from the blob file
UPDATE_EXIT = selfupdate.UPDATE_EXIT  # exit code of a Sentinel that drained because cvENGINE asked it to update and CVENGINE_SENTINEL_UPDATE_EXIT says a supervisor replaces the image (client/selfupdate.py)
WEDGED = 3  # exit code of a built-in scanner whose heartbeats have not reached the server for ``control.HEARTBEAT_MAX_AGE``: compose restarts it
WATCHDOG_EVERY = 30  # seconds between the built-in scanner's checks on its own heartbeats
TAKEN_BACK_KILL_SECONDS = 10.0  # a task taken back by the server is asked to stop (SIGTERM to its process group); this long after, it is killed (SIGKILL)
TAKEN_BACK_EVICT_SECONDS = 30.0  # and this long after, a task whose thread still has not ended no longer holds its slot or its memory budget
REAP_EVERY = 5.0  # seconds between the reaper's checks on stopping tasks
STARVE_AFTER_SECONDS = 60.0  # a heavy kind (Chromium, nuclei) that has not fitted the memory budget for this long gets the next free room (reserved)
RESERVE_SECONDS = 120.0  # how long the room is kept free for it before the wait starts over
WAIT_LOG_SECONDS = 300.0  # a kind that waits for memory is named in the log this often
WAIT_LOG_AFTER_SECONDS = 30.0  # ... once it has waited this long
THREAD_FAILURE_PAUSE = 5.0  # seconds to wait after a task thread could not be started (the container is out of threads)
HELD_STATUSES = ('pending', 'suspended')  # cvENGINE holds the Sentinel (approval, or an administrator's decision): its poll answers 403, its token still works
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
    says it sits inside a private network, whatever the server's ``network`` setting says. A kind the server's contract does not have
    (``waf`` on cvENGINE 1.3) is left out too: such a server refuses the whole poll with a 400 for it, and so is ``bbot_discovery`` when bbot is
    not installed here."""
    off = config.disabled_kinds()
    kinds = [k for k in config.poll_kinds()
             if k not in off and config.server_knows(k) and (k not in config.INTERNAL_KINDS or config._local_internal())]
    if 'openvas' in kinds and not tools.gvm_ready():
        kinds.remove('openvas')
    if 'bbot_discovery' in kinds and 'bbot' not in detected_tools():  # an image built without bbot (or a source checkout) never takes discovery work
        kinds.remove('bbot_discovery')
    if 'web_screenshot' in kinds and shot_blocked_reason():  # the sandbox proof failed: tasks stay due (or go to another Sentinel) instead of failing one by one
        kinds.remove('web_screenshot')
    if 'web_screenshot' in kinds and not shot.available():  # an image built without the browser (or a source checkout) never takes screenshot work
        kinds.remove('web_screenshot')
    if 'route_probe_signed' in kinds and not config.builtin():  # the stored sign-in is read by cvENGINE's own scanner only; no other Sentinel declares or takes the kind
        kinds.remove('route_probe_signed')
    if 'secrets_scan' in kinds and not tools.kingfisher_ready():  # the binary is in the image; a source checkout may have none
        kinds.remove('secrets_scan')
    if 'ssh_probe' in kinds and not tools.sshamble_ready():  # the binary is in the image; a source checkout may have none
        kinds.remove('ssh_probe')
    return kinds


_shot_state = {'blocked': None}
SHOT_RECHECK_SECONDS = 600  # a failed sandbox proof is tried again this often, so a host fixed in the meantime takes screenshots again


def shot_blocked_reason():
    """Why this Sentinel takes no screenshot work (its browser sandbox could not start), or None."""
    return _shot_state['blocked']


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


def _cap_concurrency(value):
    """``value`` as a whole number between 1 and the most the server grants (``config.MAX_AUTO_CONCURRENT``): whatever reaches a bootstrap, a
    registration or the daemon is held to it, so the server never answers 400 to an over-large explicit setting."""
    try:
        return max(1, min(int(value), config.MAX_AUTO_CONCURRENT))
    except (TypeError, ValueError):
        return 1


def bootstrap(blob_raw, name, max_concurrent, client_factory=httpclient.Client):
    """Decode the provisioning blob and trade it for this Sentinel's own token. Returns ``(token, server_url)``; the
    caller persists it. Raises ``blob.BlobError`` on a bad blob, ``httpclient.ApiError``/``requests.RequestException``
    on a failed call: both are fatal at startup (there is nothing useful to retry without a human's new blob)."""
    payload = blob_mod.decode_blob(blob_raw)
    server_url = payload['server_url']
    client = client_factory(server_url)
    body = {'enrollment_token': payload['enrollment_token'], 'name': name, 'capabilities': declared_kinds(),
            'os': [config.os_family()] if config.os_family() else [], 'tools': detected_tools(),
            'max_concurrent': _cap_concurrency(max_concurrent), 'settings': config.local_settings()}
    out = client.call('POST', 'sentinels/bootstrap', body)
    token = out.get('token')
    if not isinstance(token, str) or not token:
        raise httpclient.ApiError(502, 'bootstrap did not return a token')
    return token, server_url


_spool_report = {}  # set by the daemon: {count, oldest_seconds} while results are held for cvENGINE, empty otherwise (shown on the Sentinels page)
_watchdog_report = {}  # set by the watchdog at every tick: {last_tick, actions_last_hour, kills, overcommit_active, reasons, actions, ...} (info.watchdog, optional)
_waiting_report = []  # set by the daemon at every poll plan: [{kind, need_mb, free_mb, budget_mb, seconds, held_by: [{task, kind, mb, seconds}]}], or a stopping task


def info():
    """What this Sentinel reports about itself: the result contract version it speaks, its client version (when known) and its host-side
    updater's last state."""
    out = {'contract_version': config.CONTRACT_VERSION}
    if config.builtin():  # the server decides from the enrollment whether this is its built-in scanner; this only tells it the image knows it is
        out['builtin'] = True
        out['features'] = list(config.BUILTIN_FEATURES)
    else:
        out['features'] = list(config.EXTERNAL_FEATURES)
    if config.version():
        out['version'] = config.version()
    update = control.read_update()
    if update:
        out['update'] = update
    out['updater'] = control.updater_info()  # installed or not, running or not, and how its last run went: a Sentinel that cannot update itself shows
    if 'openvas' in config.registered_capabilities() and 'openvas' not in config.disabled_kinds():
        ready, why = tools.gvm_status()  # cached for a minute; lets cvENGINE say why a Sentinel is not scanning (still syncing feeds, no scan config)
        out['openvas'] = {'ready': bool(ready), 'reason': '' if ready else str(why or '')[:200]}
    if _spool_report.get('count'):
        out['spool'] = dict(_spool_report)  # optional: a server that does not know the field ignores it
    if _watchdog_report:
        out['watchdog'] = dict(_watchdog_report)  # optional: a server that does not know the field ignores it; no target, finding or secret is ever in it
    out['waiting'] = list(_waiting_report)[:6]  # heavy kinds that wait for memory, tasks taken back and still stopping: shown on the Sentinels page (empty says nothing waits now)
    if 'ssh_probe' in declared_kinds():
        try:
            out['badkeys'] = badkeys.status()  # {present, age_hours, refresh, last_ok}: a missing or stale host key blocklist is visible on the Sentinels page
        except Exception:  # noqa: BLE001 - a status line must never stop a heartbeat
            logger.exception('badkeys status could not be read')
    return out


def register(client, name, max_concurrent):
    """(Re-)register this Sentinel with the server: name, capabilities, os, tools and max_concurrent. Called on every
    startup, not just the first, so a restarted Sentinel always reports its current capacity
    (CVENGINE_SENTINEL_MAX_CONCURRENT, or the host's freshly auto-detected CPU count) instead of whatever was true
    the one time it originally bootstrapped. ``scope`` is left out on purpose: ``PUT sentinel`` only changes fields
    given in the body, so this never touches the scope an enrollment secret already assigned."""
    body = {'name': name, 'capabilities': declared_kinds(), 'os': [config.os_family()] if config.os_family() else [],
            'tools': detected_tools(), 'max_concurrent': _cap_concurrency(max_concurrent), 'settings': config.local_settings(), 'info': info()}
    return client.call('PUT', 'sentinel', body)


class Daemon:
    guard = None  # the watchdog (client/watchdog.py), set in __init__ unless CVENGINE_SENTINEL_WATCHDOG=0

    def __init__(self, server_url, token, max_concurrent=1, client=None, heartbeat_seconds=None):
        self.client = client or httpclient.Client(server_url, token)
        self.max_concurrent = _cap_concurrency(max_concurrent)
        self.reregister = None  # set by the entry point: sends this Sentinel's registration and returns the server's reply
        self.exit_code = 0  # non-zero once the server stopped accepting this Sentinel's token
        self._update_reply = None  # what cvENGINE last said about updating (mode, requested)
        self._badkeys_skip_logged = False  # the "badkeys refresh not started" line is logged once, not at every registration
        self._register_pending = False  # the last registration did not reach the server: retried at every heartbeat until it does
        self._settings_rev = None  # fingerprint of the server's settings this Sentinel last applied
        self._registered = self._registration()  # what the server was last told, so a change after it is noticed
        self._warned_internal = False  # the "granted internal, configured external" warning is logged once
        self._contract_warned = None  # the minimum contract version the server last said it needs, once it was logged that this Sentinel is behind it
        self._orphans_seen = set()  # leases the server held for this Sentinel, not running here, at the last heartbeat
        self._gvm_swept = False  # the one-time sweep of leftover GVM tasks has run (or been started)
        self._unsaved_token = None  # (path, token, server_url) when saving a freshly bootstrapped token failed: retried at every heartbeat
        self.heartbeat_seconds = heartbeat_seconds or config.HEARTBEAT_SECONDS
        self.stop_event = threading.Event()  # set by SIGTERM: take no new work
        self._halted = threading.Event()  # set when the shutdown grace period is over: stop retrying, kill what is left
        self._lock = threading.Lock()
        self._in_flight = {}  # task_id -> {'proc', 'done', 'started', 'dropped', 'finishing', 'kind', 'runnable'}
        self._polling = False  # a long poll is outstanding: it may return a task, so the updater must not see this Sentinel idle
        self._backoff = MIN_BACKOFF
        self.admission = admission.Admission()
        self._blocked_since = {}  # heavy kind -> when it first did not fit the memory budget (monotonic), cleared when it fits
        self._reserve = None  # (kind, since): the room that frees up next is kept for this kind
        self._reserve_poll = None  # the kind the plan just made the only one to ask for
        self._wait_logged = {}  # kind -> when its waiting line was last logged
        self.pacer = admission.ClaimPacer(config.claim_limit(self.max_concurrent), config.CLAIM_WINDOW)
        self._held_logged = None  # (status, note) of the hold last logged, so a held Sentinel says why once, not at every poll
        self.started_at = time.time()
        self.heartbeat_ok_at = None  # when a heartbeat last reached the server and was answered (wall clock: control.json is read by another process)
        self._update_exit_state = None  # None, 'draining' (a drain for an update request runs) or 'waiting' (it gave up; asks again after RETRY_AFTER)
        self._update_exit_logged = None
        self.spool = spool_mod.Spool()
        self._spool_lock = threading.Lock()  # one delivery pass at a time: the spool thread, the heartbeat and startup share it
        self._spool_wake = threading.Event()  # set when a result is added, so the spool thread delivers it without waiting
        self._spool_backoff = SPOOL_MIN_BACKOFF
        self._quiet = {}  # what -> [last logged (monotonic), suppressed count]: an outage is logged once, then rarely
        self.hb_beat_at = time.monotonic()  # when the heartbeat loop last finished a pass (monotonic), for the watchdog and the container health check
        self.poll_beat_at = time.monotonic()  # when the poll loop last turned
        self._hb_gen = 0  # a replacement heartbeat thread bumps it: the old thread, if it ever returns, ends
        self.guard = watchdog_mod.Watchdog(self) if watchdog_mod.enabled() else None  # client/watchdog.py: the Sentinel's own watchdog thread
        self.watchdog = config.builtin()  # the built-in scanner restarts itself when its heartbeats stop reaching the server

    # --- lifecycle --------------------------------------------------------------------------------------------

    def run(self):
        control.set_draining(False)  # a fresh start is never drained, whatever an updater that died half way left behind
        bbot.sweep_stale()  # a key file a crashed run left in the temp directory goes before any task starts
        self._write_control()
        self._deliver_spool_at_start()  # held results go out before the first heartbeat: that heartbeat's list of running tasks must not make the server drop them
        hb = threading.Thread(target=self._heartbeat_loop, args=(self._hb_gen,), name='sentinel-heartbeat', daemon=True)
        hb.start()
        if self.guard:
            self.guard.start()
        try:
            threading.Thread(target=self._spool_loop, name='sentinel-spool', daemon=True).start()
        except RuntimeError:
            logger.exception('the spool thread could not be started; the heartbeat delivers held results')
        if self.watchdog:
            threading.Thread(target=self._watchdog_loop, name='sentinel-watchdog', daemon=True).start()
        try:
            threading.Thread(target=self._reaper_loop, name='sentinel-reaper', daemon=True).start()
        except RuntimeError:  # out of threads: the poll loop and the heartbeat reap as well
            logger.exception('the reaper thread could not be started')
        self._ensure_badkeys()
        if shot.available():  # the browser's sandbox is checked once at every start, as the server's celery container once did (never blocks a start)
            threading.Thread(target=self._check_screenshot_sandbox, name='sentinel-shot-sandbox', daemon=True).start()
        try:
            while not self.stop_event.is_set():
                self.poll_beat_at = time.monotonic()
                if self.guard and not self.guard.alive():  # the watchdog thread itself died: the loop it guards starts it again
                    self.guard.start()
                try:
                    self._poll_once()
                except Exception:  # noqa: BLE001 - a bug or a reply nobody anticipated must never end the daemon
                    logger.exception('the poll loop failed; backing off')
                    self._sleep_backoff()
        finally:
            badkeys.stop()
            self._shutdown()
            hb.join(timeout=2)

    def _ensure_badkeys(self):
        """Start the host key blocklist refresh for ssh_probe (background; CVENGINE_BADKEYS_REFRESH=0 turns it off) once ssh_probe is declared. Asked at
        start and again whenever a registration succeeds: a server that was down at start leaves the kinds unknown, so the declaration, and with it the
        refresh, only becomes possible later. Says in the log, once, why it is not running yet."""
        try:
            if 'ssh_probe' not in declared_kinds():
                if not self._badkeys_skip_logged:
                    self._badkeys_skip_logged = True
                    logger.info('badkeys refresh not started: ssh_probe is not declared (the server has not said which kinds it takes, or the sshamble tool is missing); '
                                'it starts when the capabilities become known')
                return
            self._badkeys_skip_logged = False
            badkeys.start(self.stop_event)
        except Exception:  # noqa: BLE001 - never stops the daemon
            logger.exception('badkeys refresh could not be started')

    def _check_screenshot_sandbox(self):
        """Start the screenshot browser once and say whether Chromium's sandbox engaged. A task proves it again before it opens any page; this says early,
        in the log, what that proof will find, and while it fails ``web_screenshot`` is neither declared nor polled for (``runnable_kinds``): the work stays
        due or goes to another Sentinel. A failing proof is repeated every ``SHOT_RECHECK_SECONDS``, so fixing the host brings screenshots back."""
        while not self.stop_event.is_set():
            try:
                engaged, reason, version = shot.sandbox_probe()
            except Exception:  # noqa: BLE001 - a log line must never stop a Sentinel
                logger.exception('the screenshot sandbox check could not run')
                return
            if engaged is True:
                if _shot_state['blocked']:
                    logger.info('screenshots: the sandbox starts now; taking screenshot work again')
                _shot_state['blocked'] = None
                logger.info("screenshots: Chromium %s runs inside its sandbox", version or '(version unknown)')
                return
            if engaged is False:
                _shot_state['blocked'] = reason or "Chromium's sandbox could not start"
                logger.error('screenshots stay off on this Sentinel until its sandbox can start: %s', reason)
            else:
                logger.warning('the screenshot sandbox check did not finish: %s', reason)
                return
            self._register_pending = True  # the next heartbeat tells the server web_screenshot is no longer declared
            if self.stop_event.wait(SHOT_RECHECK_SECONDS):
                return

    def request_stop(self):
        self.stop_event.set()

    def start_registration(self):
        """Startup: register once and run with the settings the server's reply carries. A server that is down leaves the registration pending
        (the heartbeat retries it); the settings register again only when they change what the server was just told."""
        reply = self._refresh_registration(force=True)
        self.apply_settings((reply or {}).get('settings') if isinstance(reply, dict) else None)
        if reply is not None:  # the reply may name a newer contract than this Sentinel assumed before it: declare the kinds it adds now
            self._refresh_registration()

    def keep_saving_token(self, path, token, server_url):
        """The token from bootstrap could not be saved: keep it in memory and try saving it again at every heartbeat."""
        self._unsaved_token = (path, token, server_url)

    def _active_count(self):
        with self._lock:
            return len(self._in_flight)

    def _auth_failed(self, exc):
        """Stop for good when the server says this Sentinel's token is no longer valid: backing off and polling forever would hide it. The built-in
        scanner stops with ``REENROLL`` instead, and its entry point enrols it again with the next blob the server writes (no person is involved)."""
        if getattr(exc, 'status', None) not in AUTH_STATUSES:
            return False
        if config.builtin():
            if not self.exit_code:
                logger.error("the server no longer accepts the built-in scanner's token (expired or revoked); enrolling again with the next "
                             'enrollment the server writes')
            self.exit_code = REENROLL
            self.stop_event.set()
            return True
        if not self.exit_code:
            logger.error("this Sentinel's token is expired, revoked or invalid: re-enroll it (generate a new enrollment blob in cvENGINE and run "
                         "./setup.sh with it); a Sentinel switched off for more than 90 days must be re-enrolled. Stopping")
        self.exit_code = 1
        self.stop_event.set()
        return True

    # --- heartbeat ----------------------------------------------------------------------------------------------

    def _heartbeat_loop(self, gen=0):
        while not self.stop_event.wait(self.heartbeat_seconds):
            if gen != self._hb_gen:  # a newer heartbeat thread took over (restart_heartbeat)
                return
            self.hb_beat_at = time.monotonic()
            self._heartbeat_once()
            self.hb_beat_at = time.monotonic()

    def restart_heartbeat(self):
        """Start a new heartbeat thread in place of one that is stuck or gone (the watchdog's W5). Returns whether a thread was started."""
        self._hb_gen += 1
        self.hb_beat_at = time.monotonic()
        try:
            threading.Thread(target=self._heartbeat_loop, args=(self._hb_gen,), name='sentinel-heartbeat', daemon=True).start()
            return True
        except RuntimeError:
            logger.exception('the heartbeat thread could not be restarted')
            return False

    def _heartbeat_once(self):
        """One heartbeat. Whatever goes wrong is logged and the thread lives on to the next one, and the updater's status file is rewritten
        either way, so it never goes stale while the server is unreachable."""
        update_reply = None
        try:
            self._retry_token_save()
            self._flush_spool()  # held results first: a heartbeat that does not list them would let the server end their tasks as dropped
            asked_at = time.monotonic()
            try:
                with self._lock:
                    running = sorted(self._in_flight, key=str)
                listed = {str(r) for r in running}
                held = [int(t) for t in self.spool.task_ids() if t.isdigit() and t not in listed]  # the server's task ids are whole numbers
                out = self.client.call('POST', 'sentinel/heartbeat', {'info': info(), 'running': running + held})  # a held result's task still counts as running here
            except (httpclient.ApiError, requests.RequestException) as exc:
                if not self._auth_failed(exc):
                    self._quiet_warning('heartbeat', 'heartbeat failed: %s', exc)
                return
            self._quiet_recovered('heartbeat', 'heartbeat reaches cvENGINE again')
            out = out if isinstance(out, dict) else {}
            self.heartbeat_ok_at = time.time()
            update_reply = out.get('update')
            self._note_contract(out)
            self._consider_update_exit(update_reply)
            self._reconcile(out.get('leases'), asked_at)
            self._reap_dropped()
            self.apply_settings(out.get('settings'))
            self._refresh_registration()
            self._sweep_gvm_orphans()
        except Exception:  # noqa: BLE001 - the heartbeat keeps every lease alive; one bad iteration must not end it
            logger.exception('heartbeat failed')
        finally:
            self._write_control(update_reply)

    def _consider_update_exit(self, reply):
        """cvENGINE asked this Sentinel to update (``update.requested`` with a ``target`` commit): when a supervisor replaces the image on exit
        (CVENGINE_SENTINEL_UPDATE_EXIT) drain and leave with ``UPDATE_EXIT``. Everything else stays with the host-side updater."""
        try:
            if self._update_exit_state == 'draining' or self.stop_event.is_set():
                return
            ok, found = selfupdate.should_exit(reply, config.version())
            if not ok:
                if found != self._update_exit_logged and isinstance(reply, dict) and reply.get('requested') and selfupdate.enabled():
                    logger.info('not leaving to update: %s', found)
                self._update_exit_logged = found
                return
            self._update_exit_state = 'draining'
            threading.Thread(target=self._drain_and_exit, args=(found,), name='sentinel-update-exit', daemon=True).start()
        except Exception:  # noqa: BLE001 - an update request must never stop a heartbeat
            logger.exception('could not act on the update request')

    def _drain_and_exit(self, target, timeout=None):
        """Stop claiming, wait for the tasks in flight (and for an outstanding poll that may still hand one over), then stop with ``UPDATE_EXIT``. Past the
        drain limit the Sentinel goes back to work and keeps every task: nothing is interrupted for an update."""
        previous = config.version() or ''
        timeout = selfupdate.drain_seconds() if timeout is None else timeout
        logger.info('cvENGINE asked this Sentinel to update to %s: no new work, waiting for %s running task(s) (up to %ss)', target[:12], self._active_count(), timeout)
        control.set_draining(True)
        try:
            control.record_update('draining', 'draining', 'cvENGINE asked this Sentinel to update; it takes no new work', previous, target)
        except (OSError, ValueError):
            pass
        deadline = time.monotonic() + timeout
        while not self.stop_event.is_set():
            if self._active_count() == 0 and not self._polling:
                selfupdate.remember(target)
                try:
                    control.record_update('updating', 'exiting', f'idle: leaving with exit code {UPDATE_EXIT} so the supervisor brings the newest image', previous, target)
                except (OSError, ValueError):
                    pass
                logger.info('idle: exiting with code %s so the supervisor brings the newest image (%s)', UPDATE_EXIT, target[:12])
                self.exit_code = UPDATE_EXIT
                self.stop_event.set()
                return
            if time.monotonic() >= deadline:
                break
            self.stop_event.wait(1.0)
        if self.stop_event.is_set():
            return
        control.set_draining(False)
        try:
            control.record_update('waiting', 'drain', f'a task was still running after {timeout}s; this Sentinel went back to work and asks again later', previous, target)
        except (OSError, ValueError):
            pass
        logger.warning('a task was still running after %ss: not leaving to update now, back to work', timeout)
        selfupdate.remember(target)  # the same target is not tried again before RETRY_AFTER
        self._update_exit_state = None

    def _watchdog_loop(self):
        """The built-in scanner's own watchdog: when no heartbeat has reached the server for ``control.HEARTBEAT_MAX_AGE`` seconds (a wedged daemon, a
        dead connection), stop with ``WEDGED`` so compose (``restart: unless-stopped``) starts a fresh process; Docker never restarts a container only
        because its health check fails. If the stop itself does not end the process in time, it is ended at once."""
        while not self.stop_event.wait(WATCHDOG_EVERY):
            if self.heartbeat_stale():
                logger.error('no heartbeat has reached the server for more than %ss; restarting the built-in scanner', control.HEARTBEAT_MAX_AGE)
                self.exit_code = self.exit_code or WEDGED
                self.stop_event.set()
                if not self._halted.wait(config.SHUTDOWN_GRACE_SECONDS + RELEASE_WAIT_SECONDS + 15):
                    os._exit(WEDGED)
                return

    def heartbeat_stale(self, now=None):
        last = max(self.heartbeat_ok_at or 0, self.started_at)
        return (now or time.time()) - last > control.HEARTBEAT_MAX_AGE

    def _note_contract(self, reply):
        """A registration or heartbeat answer names the result contract the server speaks (``contract: {version, min_supported}``). A Sentinel whose
        own version is below the server's minimum is told once per minimum, in one line, and goes on heartbeating: the server withholds the work
        it cannot run, and an update is the operator's decision. The server's own version decides which kinds are asked for (``runnable_kinds``):
        an answer with no ``contract`` is a server from before it (cvENGINE 1.3), which has only the version 1 kinds."""
        before = config.server_contract()
        if config.set_server_contract(reply) != before:
            held = sorted(k for k in config.KNOWN_KINDS if not config.server_knows(k))
            logger.info('the server speaks result contract %s%s', config.server_contract(),
                        f'; not asking it for {", ".join(held)} work, which it does not have' if held else '')
        contract = reply.get('contract') if isinstance(reply, dict) else None
        minimum = contract.get('min_supported') if isinstance(contract, dict) else None
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum <= config.CONTRACT_VERSION or minimum == self._contract_warned:
            return
        self._contract_warned = minimum
        logger.warning('this Sentinel speaks contract %s, the server needs at least %s: update it', config.CONTRACT_VERSION, minimum)

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
        self.max_concurrent = _cap_concurrency(config.max_concurrent())
        self.pacer.limit = config.claim_limit(self.max_concurrent)
        self._settings_rev = rev
        if after.get('network') == 'internal' and not config._local_internal() and not self._warned_internal:
            self._warned_internal = True
            logger.warning('cvENGINE grants this Sentinel the internal network, but this machine is configured as external, so internal-range work '
                           'is refused here; set CVENGINE_SENTINEL_NETWORK=internal (./setup.sh with the internal flag) if it really sits inside the network')
        if before != after:
            logger.info('settings from the server: %s', ', '.join(f'{k}={_shown(k, v)}' for k, v in sorted(after.items())) or 'none (this machine\'s own)')
        self._refresh_registration()

    def _registration(self):
        """What a registration tells the server, to notice when it has changed: name, concurrency and capabilities, and the server's contract
        version, which decides which kinds and which disabled kinds are reported."""
        return config.sentinel_name(), config.max_concurrent(), tuple(declared_kinds()), config.server_contract()

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
        self.heartbeat_ok_at = time.time()  # the server answered: as good as a heartbeat for the health check and the updater's readiness question
        self._register_pending = False
        self._registered = current
        self._note_contract(reply)
        self._ensure_badkeys()  # the kinds are known now (a server that was down at start): ssh_probe may be declared for the first time
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
                if task_id in held or state.get('finishing') or state['done'].is_set() or state.get('dropped'):
                    continue  # (a task already told to stop is the reaper's: it is escalated there, not logged again at every heartbeat)
                if state.get('started', asked_at) > asked_at - RECONCILE_GRACE_SECONDS:
                    continue
                state['dropped'] = True
                state['dropped_at'] = time.monotonic()
                stale.append((task_id, state.get('proc')))
        for task_id, proc in stale:
            logger.warning('task %s is no longer assigned to this Sentinel (taken back by the server); stopping it', task_id)
            self._stop(proc)
        self._release_orphaned_leases(held)

    def _release_orphaned_leases(self, held):
        """The other half of reconciling: a lease the server still holds for this Sentinel that it is not running (left by a restart, a crash or a
        result that never arrived). The server counts it against this Sentinel's capacity and keeps extending it at every heartbeat, so unreleased
        ghosts add up until it believes the Sentinel is full and sends it nothing. A lease is released once it has been seen, and not running here, in
        two consecutive heartbeats, so a task accepted a moment ago is never released."""
        with self._lock:
            running = {str(task_id) for task_id in self._in_flight}
        running |= set(self.spool.task_ids())  # a result held for delivery is not an orphan: the server must keep its lease until it arrives
        orphans = {task_id for task_id in held if str(task_id) not in running}
        confirmed = [task_id for task_id in orphans if task_id in self._orphans_seen]
        self._orphans_seen = orphans  # a lease that went away, or is running here after all, is forgotten
        for task_id in sorted(confirmed, key=str)[:MAX_ORPHAN_RELEASES]:
            logger.warning('the server holds task %s for this Sentinel but it is not running here; releasing it', task_id)
            self._release(task_id, 'this Sentinel is not running the task (a lease left by a restart)')

    def _liveness(self):
        """When the watchdog, the heartbeat loop and the poll loop last turned, as seconds since the epoch, for ``control.health``; ``None`` with no watchdog."""
        if not self.guard:
            return None
        now_m, now_w = time.monotonic(), time.time()
        return {'wd': int(now_w - (now_m - self.guard.last_tick)), 'hb': int(now_w - (now_m - self.hb_beat_at)), 'poll': int(now_w - (now_m - self.poll_beat_at))}

    def _write_control(self, update_reply=None):
        """Tell the host-side updater where this Sentinel stands: running tasks (plus one while a poll that may return a task is outstanding),
        drain state, and what cvENGINE said about updating. Rewritten whenever a task starts or ends and around every poll, not only at
        heartbeats, so an updater waiting for it to go idle never reads a stale count."""
        if update_reply is not None:
            self._update_reply = update_reply
        try:
            with self._lock:
                kinds = [state.get('kind') for state in self._in_flight.values()]
            control.write_status(config.version(), self._active_count() + (1 if self._polling else 0), self._update_reply, kinds=kinds,
                                 heartbeat_at=self.heartbeat_ok_at, started_at=self.started_at, liveness=self._liveness())
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
        if self.guard:
            kinds = self.guard.filter_kinds(kinds)  # none while the disk is low, none of a kind the watchdog withholds after repeated stops
        with self._lock:
            running = [state.get('kind') for state in self._in_flight.values()]
        if 'openvas' in running and 'openvas' in kinds:
            kinds.remove('openvas')
        if 'secrets_scan' in running and 'secrets_scan' in kinds:  # one Kingfisher at a time: about 150 MB of memory each (measured, 32 MB of input)
            kinds.remove('secrets_scan')
        if 'wpscan_thorough' in kinds and ('wpscan_thorough' in running or (self.max_concurrent > 1 and len(running) + 1 >= self.max_concurrent)):
            kinds.remove('wpscan_thorough')  # one thorough pass at a time (it runs for hours), and never the last free slot of a Sentinel with several
        candidates = list(kinds)
        slots_full = sum(1 for kind in running if kind != 'openvas') >= self.max_concurrent
        if slots_full:
            kinds = [k for k in kinds if k == 'openvas']
        fit = self.admission.admissible(kinds, running)  # never a kind that would not fit in memory beside what runs (client.admission)
        return self._fair(candidates, fit, running, slots_full)

    def _fair(self, kinds, fit, running, slots_full=False):
        """Memory admission lets a cheap kind in whenever it fits, so a steady stream of cheap tasks can keep the room a heavy kind (Chromium, 400 MB) needs
        from ever being free: that kind would wait for ever while the others pass. Here a heavy kind that has not fitted for ``STARVE_AFTER_SECONDS`` is
        reserved the next free room: nothing new is started (what runs finishes), and when it fits it is asked for alone and at once. Whether or not the
        server had such a task, the wait then starts over. ``RESERVE_SECONDS`` bounds the hold. Each waiting kind is named in the log and in the heartbeat's
        ``info.waiting`` (what it needs, what is free, which tasks hold the memory)."""
        now = time.monotonic()
        with self._lock:
            held = sorted(((admission.weight(st.get('kind')), tid, st.get('kind'), now - st.get('started', now)) for tid, st in self._in_flight.items()
                           if st.get('kind') != 'openvas'), key=lambda row: (-row[0], str(row[1])))
        if slots_full:  # no slot is free, so memory is not what keeps a kind out right now: nobody's wait is judged (and none is forgotten), the clocks run on
            blocked = [k for k in kinds if k in self._blocked_since]
        else:
            blocked = [k for k in kinds if k not in fit and admission.weight(k) > admission.DEFAULT_WEIGHT_MB]
            for kind in list(self._blocked_since):
                if kind not in blocked:
                    del self._blocked_since[kind]
            for kind in blocked:
                self._blocked_since.setdefault(kind, now)
        used, budget = self.admission.used(running), self.admission.budget
        report = []
        for kind in blocked:
            waited = now - self._blocked_since[kind]
            holders = [{'task': tid, 'kind': k, 'mb': mb, 'seconds': int(age)} for mb, tid, k, age in held[:3] if mb > 0]
            report.append({'kind': kind, 'need_mb': admission.weight(kind), 'free_mb': max(0, budget - used), 'budget_mb': budget, 'seconds': int(waited), 'held_by': holders})
            if waited >= WAIT_LOG_AFTER_SECONDS and now - self._wait_logged.get(kind, -WAIT_LOG_SECONDS) >= WAIT_LOG_SECONDS:
                self._wait_logged[kind] = now
                logger.warning('%s waiting: needs %s MB, %s MB free of %s; held by %s (for %.0fs)', kind, admission.weight(kind), max(0, budget - used), budget,
                               ', '.join(f"task {h['task']} {h['kind']} {h['mb']} MB for {h['seconds']}s" for h in holders) or 'nothing it can name', waited)
        with self._lock:
            stopping = [{'kind': st.get('kind'), 'task': tid, 'seconds': int(now - st['dropped_at']), 'stopping': True}
                        for tid, st in self._in_flight.items() if st.get('dropped') and not st['done'].is_set() and st.get('dropped_at') is not None]
        _waiting_report[:] = report + stopping[:3]
        reserve = self._reserve
        if reserve and (reserve[0] not in kinds or now - reserve[1] > RESERVE_SECONDS):
            logger.info('%s: the reserved room was not used within %.0fs; the wait starts over', reserve[0], RESERVE_SECONDS)
            if reserve[0] in self._blocked_since:
                self._blocked_since[reserve[0]] = now
            self._reserve = reserve = None
        if reserve:
            if reserve[0] in fit:
                self._reserve_poll = reserve[0]
                return [reserve[0]]
            return []  # keep the room: nothing new starts until it fits
        # only a kind that WOULD fit once the cheap tasks have finished is worth keeping room for: a second nuclei beside two running ones never fits (they
        # run for hours), and holding everything else for it would only stop the Sentinel
        long_held = sum(w for w, _tid, _k, _age in held if w > admission.DEFAULT_WEIGHT_MB)
        starving = sorted((k for k in blocked if now - self._blocked_since[k] >= STARVE_AFTER_SECONDS and long_held + admission.weight(k) <= budget),
                          key=lambda k: self._blocked_since[k])
        if starving:
            self._reserve = (starving[0], now)
            logger.warning('%s has waited %.0fs for memory beside cheaper work; starting nothing new until it fits (at most %.0fs)',
                           starving[0], now - self._blocked_since[starving[0]], RESERVE_SECONDS)
            return []
        return fit

    def _poll_once(self):
        if control.is_draining():  # the host-side updater asked this Sentinel to finish what it has and take nothing new
            self.stop_event.wait(2)
            return
        self._reap_dropped()
        kinds = self._poll_plan()
        reserved, self._reserve_poll = self._reserve_poll, None
        if not kinds:  # every slot taken
            self.stop_event.wait(0.5)
            return
        pause = self.pacer.wait_needed()
        if pause > 0:  # this Sentinel's own calls to the claim endpoint are near what the server allows per minute: wait instead of being refused
            self.stop_event.wait(min(pause, 5.0))
            return
        self._polling = True
        self._write_control()
        self.pacer.note()
        try:
            out = self.client.call('POST', 'sentinel/tasks/next', {'wait': 0 if reserved else config.DEFAULT_POLL_WAIT, 'kinds': kinds})  # a reserved ask is a quick one: nothing else waits behind it
        except (httpclient.ApiError, requests.RequestException) as exc:
            self._polling = False
            self._write_control()
            if getattr(exc, 'status', None) == 403 and self._wait_while_held():
                return
            if getattr(exc, 'status', None) == 429:
                self._wait_rate_limited(exc)
                return
            if not self._auth_failed(exc):
                self._quiet_warning('poll', 'poll failed: %s', exc)
                self._sleep_backoff()
            return
        finally:
            self._polling = False  # a task it returned is counted as running from here on (``_start_task``)
            if reserved:  # asked for: the room did its job whether or not the server had such a task, the wait starts over
                self._reserve = None
                self._blocked_since.pop(reserved, None)
        self._backoff = MIN_BACKOFF
        self._quiet_recovered('poll', 'cvENGINE answers polls again')
        if self._held_logged is not None:
            logger.info('cvENGINE no longer holds this Sentinel; taking work again')
            self._held_logged = None
        task = out.get('task') if isinstance(out, dict) else None
        if not task:
            self._write_control()
            self._wait_retry_after(out)
            return
        if not _valid_task(task):
            self._write_control()
            logger.warning('ignoring a malformed task from the server: %s', _clip(repr(task), 80))
            self._sleep_backoff()
            return
        self._start_task(task, kinds)
        self._write_control()

    def _wait_while_held(self):
        """The poll was refused with a 403. A Sentinel cvENGINE holds (``pending`` approval, or ``suspended`` by an administrator or by the rule that
        holds a new agent of a user whose other agent was suspended or revoked) is answered so ("no work can be assigned: ...") while its token is
        fine, and stopping then would only crash-loop the container and tell the operator to re-enroll, which a held user's new Sentinel inherits
        anyway. So ask the server where this Sentinel stands (``GET sentinel``): when it is held, say why once, keep heartbeating and ask again after a
        heartbeat interval. Returns False when it is not held (revoked, or a refusal of the token itself), so the caller stops as before; a check
        that fails on the network or a server error backs off and is tried again, never read as revoked."""
        try:
            me = self.client.call('GET', 'sentinel')
        except (httpclient.ApiError, requests.RequestException) as exc:
            if _retryable(exc):
                logger.warning('the poll was refused (403) and the server could not say why (%s); backing off', exc)
                self._sleep_backoff()
                return True
            return False
        status = me.get('status') if isinstance(me, dict) else None
        if status not in HELD_STATUSES:
            return False
        note = _clip(me.get('status_note') or '', 300)
        if self._held_logged != (status, note):
            self._held_logged = (status, note)
            what = 'waiting for an administrator to approve it' if status == 'pending' else 'suspended'
            logger.warning('cvENGINE has this Sentinel %s, so it is given no work%s. Its token is fine: do not re-enroll. It keeps heartbeating and '
                           'takes work again once an administrator approves or reinstates it in cvENGINE', what, f' ({note})' if note else '')
        self.stop_event.wait(self.heartbeat_seconds)
        return True

    def _wait_retry_after(self, reply):
        """The server answered "no task" and said when to ask again (``retry_after_seconds``): wait that long, at most ``MAX_RETRY_AFTER``, instead of asking
        at once. The claim endpoint is rate limited, so a Sentinel that re-polls the moment an empty answer comes back (a server holding tasks for a less
        loaded Sentinel, a full waiter cap) soon gets a 429 and then a doubling backoff that parks it for a minute. A little jitter spreads Sentinels that
        were told the same thing, a stop request ends the wait, and a value that is not a plain number, or ``IMMEDIATE_RETRY`` seconds or less (what a full
        long poll is answered with), costs nothing."""
        seconds = reply.get('retry_after_seconds') if isinstance(reply, dict) else None
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) or seconds <= IMMEDIATE_RETRY:
            return
        self.stop_event.wait(min(MAX_RETRY_AFTER, min(seconds, MAX_RETRY_AFTER) * random.uniform(1.0, 1.2)))

    def _wait_rate_limited(self, exc):
        """The server refused a claim-endpoint call with 429: wait as long as its Retry-After says (jittered a little, at most ``MAX_RETRY_AFTER`` wide), or
        by the usual backoff when it said nothing. A refusal is never a reason to give up on the task, only on asking again at once."""
        seconds = getattr(exc, 'retry_after', None)
        if seconds is None:
            return self._sleep_backoff_logged(exc)
        logger.warning('the server is rate limiting this Sentinel (%s); waiting %.0f s as it asked', exc, seconds)
        self.stop_event.wait(min(MAX_BACKOFF, seconds) * random.uniform(1.0, 1.2) + 0.1)

    def _sleep_backoff_logged(self, exc):
        logger.warning('the server is rate limiting this Sentinel (%s); backing off', exc)
        self._sleep_backoff()

    def _sleep_backoff(self):
        self.stop_event.wait(min(MAX_BACKOFF, self._backoff) * random.uniform(0.5, 1.0))
        self._backoff = min(MAX_BACKOFF, self._backoff * 2)

    def _start_task(self, task, kinds):
        task_id, kind = task['id'], task['kind']
        if self.stop_event.is_set() or control.is_draining():  # set while the poll was outstanding: the updater may already have seen this Sentinel idle
            self._release(task_id, 'Sentinel shutting down' if self.stop_event.is_set() else 'Sentinel is draining')
            return
        with self._lock:
            running = [st.get('kind') for st in self._in_flight.values()]
        if self.guard and self.admission.used(running) + admission.weight(kind) > self.admission.budget and self.admission.can_start(kind, running):
            self.guard.note_overcommit_admit(kind)  # fits only inside the watchdog's bounded overcommit
        if not self.admission.can_start(kind, running):  # the plan said it fit; a task that does not any more goes back, never into an out-of-memory kill
            self._release(task_id, 'out of memory budget on this Sentinel, retry later')
            return
        if not self._accept(task_id):
            return
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False,
                 'kind': kind, 'runnable': kind in kinds, 'pgids': set(), 'signed_in': bool(task.get('signed_in'))}
        limit = (task.get('target') or {}).get('timeout_seconds') if isinstance(task.get('target'), dict) else None
        if isinstance(limit, int) and not isinstance(limit, bool):
            state['budget_s'] = limit  # a time limit the task carries (bbot, thorough wpscan): the watchdog's deadline is never under it
        with self._lock:
            self._in_flight[task_id] = state
        self._write_control()
        logger.info('task %s accepted: %s (%s)', task_id, _clip(kind), _describe_target(task.get('target')))
        thread = threading.Thread(target=self._run_task, args=(task, state), name=f'sentinel-task-{task_id}', daemon=True)
        state['thread'] = thread
        try:
            thread.start()
        except RuntimeError as exc:  # "can't start new thread": nothing would ever run, report or finish the task, and it would hold its slot and memory for ever
            with self._lock:
                self._in_flight.pop(task_id, None)
            state['done'].set()
            logger.error('task %s could not be started: no thread for it (%s); giving it back to the server', task_id, exc)
            self._release(task_id, 'this Sentinel could not start a worker for the task (out of threads), retry later')
            self._write_control()
            self.stop_event.wait(THREAD_FAILURE_PAUSE)

    ACCEPT_TRIES = 4

    def _accept(self, task_id):
        """Accept a claimed task. A 429 or a server error is waited out (Retry-After) and tried again a few times, because a claimed task nobody accepts runs out
        its lease and expires; only a refusal that is final (409: no longer ours) or a lease that cannot be kept ends it, by releasing the task so another Sentinel
        (or this one, later) takes it. Returns whether the task is accepted."""
        for attempt in range(self.ACCEPT_TRIES):
            pause = self.pacer.wait_needed()
            if pause > 0 and not self.stop_event.is_set():
                self.stop_event.wait(min(pause, 10.0))
            self.pacer.note()
            try:
                self.client.call('POST', f'sentinel/tasks/{task_id}/accept')
                return True
            except (httpclient.ApiError, requests.RequestException) as exc:
                if self._auth_failed(exc):
                    return False
                logger.warning('could not accept task %s: %s', task_id, exc)
                if not _retryable(exc) or attempt + 1 == self.ACCEPT_TRIES or self.stop_event.is_set():
                    break
                wait = getattr(exc, 'retry_after', None)
                self.stop_event.wait(min(15.0, wait if wait is not None else 1.0 + attempt) * random.uniform(1.0, 1.2))
        if not self.stop_event.is_set():
            self._release(task_id, 'could not accept the task in time (the server was busy); it is due again')
        return False

    def _register_proc(self, state):
        """The ``register`` callback a runner calls with each process (or OpenVAS handle) it starts. A task already dropped, or a daemon past
        its grace period, has the new process killed at once, so a runner that starts a second one (nmap's IPv6 group) cannot outlive a kill."""
        def register(proc):
            with self._lock:
                state['proc'] = proc
                pgid = watchdog_mod.pgid_of(proc)
                if pgid is not None:
                    state.setdefault('pgids', set()).add(pgid)
                stop = state.get('dropped') or self._halted.is_set()
            if stop:
                self._kill(proc)
        return register

    def _stop(self, proc):
        """Ask a taken-back task to stop: SIGTERM to its whole process group (``terminate()``), when the handle has one, else the hard kill at once.
        ``_reap_dropped`` follows with SIGKILL ``TAKEN_BACK_KILL_SECONDS`` later, and gives the slot back ``TAKEN_BACK_EVICT_SECONDS`` later, whatever the task does."""
        if proc is None:
            return
        term = getattr(proc, 'terminate', None)
        if term is None:
            return self._kill(proc, background=True)
        try:
            term()
        except Exception as exc:  # noqa: BLE001 - a process that is already gone must not stop the caller
            logger.warning('could not ask a task process to stop: %s', exc)

    def _reaper_loop(self):
        while not self.stop_event.wait(REAP_EVERY):
            self._reap_dropped()

    def _reap_dropped(self, now=None):
        """A task the server took back (or whose worker thread died) must not hold a slot and a share of the memory budget for ever, however it behaves:
        a task still running ``TAKEN_BACK_KILL_SECONDS`` after it was told to stop has its process group killed, and one whose thread still has not
        ended ``TAKEN_BACK_EVICT_SECONDS`` after is taken out of the in-flight list (its slot and weight are free again, the server already has the task
        back). Idempotent and cheap: called by the reaper thread, the heartbeat and the poll loop."""
        now = time.monotonic() if now is None else now
        kill, evict = [], []
        with self._lock:
            for task_id, state in self._in_flight.items():
                if state['done'].is_set() or state.get('finishing'):
                    continue
                thread = state.get('thread')
                if thread is not None and thread.ident is not None and not thread.is_alive() and not state.get('dropped'):  # a worker that died without ending the task: nothing will ever finish it
                    state['dropped'] = True
                    state['dropped_at'] = now - TAKEN_BACK_EVICT_SECONDS
                    state['dead_worker'] = True
                if not state.get('dropped') or self._halted.is_set():
                    continue
                age = now - state.get('dropped_at', now)
                if age >= TAKEN_BACK_EVICT_SECONDS:
                    evict.append((task_id, state, age))
                elif age >= TAKEN_BACK_KILL_SECONDS and not state.get('killed'):
                    state['killed'] = True
                    kill.append((task_id, state.get('proc'), age))
        for task_id, proc, age in kill:
            logger.warning('task %s did not stop %.0fs after it was taken back; killing its process group', task_id, age)
            self._kill(proc, background=True)
        for task_id, state, age in evict:
            with self._lock:
                if self._in_flight.get(task_id) is not state:
                    continue
                self._in_flight.pop(task_id, None)
                proc = state.get('proc')
            logger.error('task %s still has not ended %.0fs after it was %s; killing it and no longer counting it: its slot and memory budget are free',
                         task_id, age, 'found without a worker' if state.get('dead_worker') else 'taken back')
            self._kill(proc, background=True)
            state['done'].set()
            if self.guard:
                self.guard.task_ended(state)
            if state.get('dead_worker'):
                self._release(task_id, 'the worker running the task ended without a result')
            self._write_control()

    @staticmethod
    def _kill(proc, background=False):
        """Kill a subprocess, or anything with the same ``poll()``/``kill()`` (an OpenVAS run's handle), if it is still running. An OpenVAS handle's
        ``kill()`` stops the GVM task and deletes it, which can take half a minute: callers that must not wait (the heartbeat thread) pass
        ``background``, and the kill then runs in its own thread."""
        if proc is None:
            return
        if background:
            try:
                threading.Thread(target=Daemon._kill, args=(proc,), name='task-kill', daemon=True).start()
                return
            except RuntimeError:  # out of threads (the very state that leaves a task stuck): kill it here, a process group is quick
                logger.warning('no thread to kill a task process in; killing it here')
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
        except bbot.Stopped as exc:  # the server ended a streamed task (cancelled, expired, its scan stopped): nothing more is sent
            outcome = 'stopped by the server'
            if state.get('wd'):  # ... unless it was the watchdog that stopped it: that is reported
                outcome = 'stopped by the watchdog'
                self._report_unless_dropped(task_id, state, self._watchdog_result(state))
            logger.info('task %s was ended by the server: %s', task_id, _clip(str(exc), 200))
        except templates.BundlePending as exc:  # the server has not packed the approved set yet: not an error, the task is due again
            logger.info('task %s waits for its approved template bundle (%s); giving it back', task_id, _clip(str(exc), 120))
            with self._lock:
                give_back = not state.get('dropped')
                if give_back:
                    state['finishing'] = True
            if give_back:
                self._release(task_id, 'the approved template bundle is not ready yet, retry later')
        except (tools.TargetError, bbot.RunError) as exc:
            if isinstance(exc, tools.Refused) or str(exc).startswith('refused:'):
                logger.warning('task %s refused locally: %s', task_id, _clip(str(exc), 200))
            self._report_unless_dropped(task_id, state, self._watchdog_result(state, exc) or {'outcome': 'error', 'error': str(exc)[:280]})
        except Exception as exc:  # noqa: BLE001 - one bad task must never take the daemon down
            if not state.get('dropped') and not state.get('wd'):
                logger.exception('task %s failed', task_id)
            self._report_unless_dropped(task_id, state, self._watchdog_result(state, exc) or {'outcome': 'error', 'error': str(exc)[:280]})
        finally:
            logger.info('task %s finished: %s, %s, %.1fs', task_id, _clip(kind), 'dropped' if state.get('dropped') else outcome,
                        time.monotonic() - state.get('started', time.monotonic()))
            with self._lock:  # gone from the in-flight list before it is marked done, so shutdown never releases a finished task
                self._in_flight.pop(task_id, None)
            state['done'].set()
            if self.guard:
                self.guard.task_ended(state)
            self._write_control()

    def _report_in_thread(self, task_id, result):
        """Report a result from a thread of its own (the watchdog's: ``_report`` may retry for a while)."""
        try:
            threading.Thread(target=self._report, args=(task_id, result), name=f'sentinel-report-{task_id}', daemon=True).start()
        except RuntimeError:
            logger.error('no thread to report the result of task %s in', task_id)

    def _watchdog_result(self, state, exc=None):
        """The result of a task the watchdog stopped, or ``None`` when it did not. Findings a stopped nuclei run had already printed are reported as ``done``
        (they were found; an empty ``done`` would read as a clean scan, so none is ever sent); everything else is the plain error."""
        wd = state.get('wd')
        if not wd:
            return None
        partial = getattr(exc, 'partial', None)
        if self.guard and self.guard.cfg['partial'] and state.get('kind') in watchdog_mod.NUCLEI_KINDS and partial:
            try:
                findings = tools.parse_nuclei_jsonl(partial, evidence=not state.get('signed_in'))  # a signed-in run keeps no request or response
            except Exception:  # noqa: BLE001 - a cut last line, anything unreadable: the plain error
                findings = []
            if findings:
                logger.warning('watchdog: task stopped; delivering the %d finding(s) it had already produced', len(findings))
                return {'outcome': 'done', 'findings': findings}
        return {'outcome': 'error', 'error': wd['text']}

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
            addresses = target.get('addresses') or []
            # the time limit: the task's own when the server sends one, else sized from the host count (cvengine_scanner.flags.task_seconds)
            seconds = tools.task_seconds(kind, len(addresses) if isinstance(addresses, list) else 1, target.get('timeout'))
            if kind == 'nmap':  # ``ports``: what the fingerprint pass scans (the server's naabu result plus the extended set); absent means the top thousand
                out = runner(addresses, timeout=seconds, ports=target.get('ports'), register=register)
            else:
                out = runner(addresses, timeout=seconds, register=register)
        elif kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            targets = target.get('targets') or []

            def nuclei(secret_file=None):
                return runner(targets, tags=target.get('tags'), severities=target.get('severities'), register=register,
                              templates=self._approved_templates(target), secret_file=secret_file)
            if task.get('signed_in'):
                # a signed-in pass names a stored sign-in: only the built-in scanner reads it (signed_in.py), and nothing ever runs it signed out
                if not config.builtin():
                    raise tools.TargetError('signed-in work runs only on the built-in scanner; this Sentinel does not take it')
                try:
                    out = signed_in.run(self.client, task['id'], targets, lambda path: nuclei(secret_file=path))
                except signed_in.SignedInError as exc:
                    raise tools.TargetError(str(exc)) from None
            else:
                out = nuclei()
        elif kind == 'testssl':
            out = runner(target.get('host') or '', target.get('ip') or '', target.get('port'), target.get('starttls') or '', register=register)
        elif kind == 'nmap_udp':
            out = runner(target.get('address') or '', register=register)
        elif kind == 'wpscan':
            out = runner(target.get('url') or '', target.get('token') or '', register=register)
        elif kind == 'wpscan_thorough':  # hours per site: the task's own time limit travels in its target
            out = runner(target.get('url') or '', target.get('token') or '', target.get('timeout_seconds'), register=register)
        elif kind == 'discover':
            out = runner(target.get('cidr') or '', register=register)
        elif kind == 'waf':
            out = runner(target.get('host') or '', target.get('ip') or '', target.get('port'), target.get('scheme') or '', register=register)
        elif kind == 'bbot_discovery':  # streamed: it posts its batches itself and returns the result that closes the run
            return runner(target, self.client, task['id'], register=register, internal=config.is_internal(), halted=self._halted)
        elif kind == 'route_probe_signed':
            # a signed-in route check names a stored sign-in (task['signed_in']): only the built-in scanner reads it, and nothing ever runs it signed out
            if not config.builtin() or not task.get('signed_in'):
                raise tools.TargetError('the signed-in route check runs only on the built-in scanner, for a task that names a stored sign-in')
            try:
                out = signed_in.run_sign_in(self.client, task['id'], lambda sign_in: runner(target, sign_in, register=register))
            except signed_in.SignedInError as exc:
                raise tools.TargetError(str(exc)) from None
        elif kind in ('http_probe', 'dns_resolve', 'alive_check', 'bucket_check', 'vhost_probe', 'subdir_probe', 'route_probe', 'supplier_check', 'hygiene_check', 'dangling_dns_check', 'identity_check', 'web_screenshot', 'page_read', 'ssh_probe'):  # in-process probes: the whole target, scope policy included
            out = runner(target, register=register)
        elif kind == 'nmap_full':
            out = runner(target.get('address') or '', register=register)
        elif kind == 'nmap_verify':
            out = runner(target.get('address') or '', target.get('ports'), version_all=target.get('version_all') is True,
                         version_intensity=target.get('version_intensity'), scripts=target.get('scripts'), host_timeout=target.get('host_timeout'),
                         register=register)
        elif kind == 'node2shell':
            out = runner(target.get('url') or '', register=register)
        elif kind == 'rdp_shot':
            out = runner(target.get('address') or '', target.get('port'), register=register)
        elif kind == 'db_probe':
            out = runner(target.get('address') or '', target.get('port'), target.get('db'), register=register)
        elif kind == 'path_probe':
            out = runner(target.get('targets'), register=register)
        elif kind == 'nuclei_validate':
            out = runner(target.get('mode'), target.get('template'), target.get('targets'), register=register)
        elif kind == 'secrets_scan':
            out = runner(target, register=register, rules=self._secret_rules(target))
        else:  # openvas, the only other kind with a runner
            out = runner(target.get('hosts') or {}, target.get('excluded_families') or [], target.get('max_hours'), register=register,
                         preferences=target.get('preferences'))
        return {'outcome': 'done', **out}

    def _secret_rules(self, target):
        """The instance's custom secret rules a ``secrets_scan`` task names (``rules_bundle_sha256``), as YAML text, or ``None`` when it names none.
        A bundle that cannot be fetched or does not match its sha256 is an error: the task is not run on another set of rules."""
        sha256 = target.get('rules_bundle_sha256')
        if not sha256:
            return None
        try:
            return templates.secret_rules(self.client, sha256)
        except templates.TemplateError as exc:
            raise tools.TargetError(str(exc)) from None

    def _approved_templates(self, target):
        """The directory of the server's approved nuclei templates a task must run on, or ``None`` when the task names no bundle and the server asks
        for no policy (an older server: the templates baked into this image are used). A task under the read-only policy that names no bundle, or a
        bundle that cannot be fetched or verified, is an error: nothing unapproved is ever run in its place."""
        policy = target.get('template_policy') if isinstance(target.get('template_policy'), dict) else {}
        # the server's shape is ``template_policy.bundle_sha256`` (sentinel_dispatch._nuclei_target); the top level is read too
        sha256 = policy.get('bundle_sha256') or target.get('bundle_sha256')
        if sha256:
            try:
                return templates.ensure_bundle(self.client, sha256)
            except templates.TemplateError as exc:
                raise tools.TargetError(str(exc)) from None
        if policy.get('read_only'):
            raise templates.BundlePending('the approved template bundle is not packed yet; the task is given back and runs once it exists')
        return None

    def _report(self, task_id, result):
        """POST the result, retrying a network error, a server error or rate limiting a few times with backoff and jitter (``REPORT_ATTEMPTS``
        within ``REPORT_RETRY_SECONDS``, and no waiting once the shutdown grace period is over). A result that still cannot be delivered is
        written to the spool (client/spool.py) and delivered when cvENGINE answers again, for up to the spool window (6 hours by default): the
        finished scan is never thrown away for an update or an outage. Any other refusal is final. Only when the spool cannot hold it (turned off,
        full, or the disk refused) is the task released, as before, so the server can run it again now rather than wait for the lease to expire."""
        try:
            size = len(json.dumps(result))
        except (TypeError, ValueError):
            size = 0
        if size > MAX_RESULT_BYTES:  # better an error the server can act on than a refused body
            logger.error('the result for task %s is %s bytes, over the server\'s limit; reporting an error instead', task_id, size)
            result = {'outcome': 'error', 'error': 'the result was larger than the server accepts'}
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
            asked = getattr(error, 'retry_after', None)
            if asked is not None:  # the server said when to come back: never earlier
                delay = max(delay, min(asked, REPORT_MAX_DELAY))
            if attempt == REPORT_ATTEMPTS - 1 or time.monotonic() + delay > give_up_at:
                break
            logger.warning('could not report the result for task %s (%s); retrying in %.1fs', task_id, error, delay)
            if self._halted.wait(delay):
                break
        if self.spool.add(task_id, result):
            logger.warning('could not report the result for task %s (%s); holding it on disk (%s held) and delivering it when cvENGINE answers again, '
                           'for up to %s', task_id, error, self.spool.count(), spool_mod.window_text())
            self._update_spool_report()
            self._spool_wake.set()
            return
        logger.error('could not report the result for task %s (%s) and it cannot be held; releasing it so the server can run it again', task_id, error)
        self._release(task_id, 'Sentinel could not deliver the result')

    # --- the spool ----------------------------------------------------------------------------------------------

    def _update_spool_report(self):
        try:
            count = self.spool.count()
            if count:
                _spool_report.clear()
                _spool_report.update({'count': count, 'oldest_seconds': int(self.spool.oldest_age() or 0)})
            else:
                _spool_report.clear()
        except Exception:  # noqa: BLE001 - a status line must never stop delivery
            logger.exception('the spool status could not be read')

    def _quiet_warning(self, what, message, exc):
        """Log a repeated failure once, then at most every ``QUIET_LOG_SECONDS`` with how many were left out, so a six hour outage is a few lines."""
        now = time.monotonic()
        last = self._quiet.get(what)
        if last is None:
            self._quiet[what] = [now, 0]
            logger.warning(message + ' (further identical failures are logged every %d minutes)', exc, QUIET_LOG_SECONDS // 60)
        elif now - last[0] >= QUIET_LOG_SECONDS:
            logger.warning(message + ' (%d more since the last line)', exc, last[1])
            self._quiet[what] = [now, 0]
        else:
            last[1] += 1

    def _quiet_recovered(self, what, line):
        if self._quiet.pop(what, None) is not None:
            logger.info(line)

    def _deliver_spool_at_start(self):
        try:
            if self.spool.count():
                logger.info('%d result(s) were held by an earlier run: delivering them before anything else', self.spool.count())
                self._flush_spool()
        except Exception:  # noqa: BLE001 - never stops a start
            logger.exception('the spool could not be delivered at start')

    def _flush_spool(self):
        """One delivery pass: the held results, oldest first, each deleted once the server answered (2xx, which includes \"already have it\", or a
        final 4xx refusal that no retry changes). A server that is unreachable, errors or rate limits ends the pass, and the entry stays. Entries older
        than the window are moved aside, not offered. Returns True when nothing is left to deliver."""
        if not self._spool_lock.acquire(blocking=False):
            return False  # another pass is running
        try:
            expired = self.spool.expire_old()
            for task_id in expired:
                logger.error('the result for task %s was held longer than %s and is no longer offered to cvENGINE; it stays on disk under %s/',
                             task_id, spool_mod.window_text(), spool_mod.EXPIRED_DIR)
            for task_id, _age in self.spool.entries():
                if self.stop_event.is_set() and self._halted.is_set():
                    break
                result = self.spool.load(task_id)
                if result is None:
                    continue
                try:
                    self.client.call('POST', f'sentinel/tasks/{task_id}/result', result)
                except (httpclient.ApiError, requests.RequestException) as exc:
                    if self._auth_failed(exc):
                        break
                    if getattr(exc, 'status', None) in AUTH_STATUSES or _retryable(exc):
                        self._quiet_warning('spool', 'cvENGINE did not take the held results yet: %s', exc)
                        break
                    logger.warning('the server refused the held result for task %s (%s); dropping it', task_id, exc)
                    self.spool.remove(task_id)
                    continue
                self.spool.remove(task_id)
                self._quiet_recovered('spool', 'held results are being delivered again')
                logger.info('delivered the held result for task %s (%d left)', task_id, self.spool.count())
            left = self.spool.count()
            self._update_spool_report()
            if left == 0:
                self._spool_backoff = SPOOL_MIN_BACKOFF
            return left == 0
        finally:
            self._spool_lock.release()

    def _spool_loop(self):
        """Deliver held results with a capped backoff for as long as there are any. Quiet: one line per outage, one per delivery."""
        while not self.stop_event.is_set():
            try:
                if self.spool.count() == 0:
                    self._update_spool_report()
                    self._spool_wake.wait(SPOOL_IDLE_SECONDS)
                    self._spool_wake.clear()
                    continue
                if self._flush_spool():
                    continue
                delay = min(SPOOL_MAX_BACKOFF, self._spool_backoff) * random.uniform(0.5, 1.0)
                self._spool_backoff = min(SPOOL_MAX_BACKOFF, self._spool_backoff * 2)
                self.stop_event.wait(delay)
            except Exception:  # noqa: BLE001 - the spool thread must never end while results are held
                logger.exception('the spool delivery failed; trying again')
                self.stop_event.wait(SPOOL_MIN_BACKOFF)

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
        held = self.spool.count()
        if held:  # nothing to release: the results are on disk and go out at the next start
            logger.info('%d finished result(s) stay in the spool and are delivered the next time cvENGINE answers', held)

