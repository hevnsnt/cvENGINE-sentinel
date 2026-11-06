"""The ``web_screenshot`` kind: Chromium takes a picture of each page of a task and the PNGs go back to cvENGINE, which stores and reads them.

cvENGINE picks the pages and the scope policy (``cveFeed.web_shot``, ``cveFeed.probe_scope.for_screenshots``); this module runs the browser, the way
cvENGINE's own capture used to (``cveFeed.web_shot`` and ``cveFeed.shot_worker``, which the server no longer carries):

* **A child process.** Chromium runs in ``client/shot_child.py``, started in its own session, one browser for the task, a fresh context per page. The
  daemon can kill the whole group (a stop, the wall clock) and the memory of everything the browser started is watched (``MAX_RSS_MB``).
* **Every connection is vetted.** The browser cannot connect anywhere itself: all of its traffic, loopback included, goes to a loopback proxy in this
  process (``client/shotproxy.py``), which asks ``Guard`` about every connection: the task's scope policy (``cvengine_scanner.probes.screenshots``
  ``ShotPolicy``), this Sentinel's own floor, and this installation's own services; and connects to the address it vetted, through this Sentinel's
  probe proxy when one is set (``transport.open_socket``). A redirect to an internal address never leaves the proxy.
* **The sandbox, or no picture.** The child proves Chromium's sandbox engaged (renderer in its own user and PID namespace, under a seccomp filter of
  its own, no ``--no-sandbox``) before it opens any page, on every task. A browser that cannot prove it opens nothing: the result says so
  (``sandbox.engaged`` false, no pages) and cvENGINE shows why. There is no setting that turns it off.
* **Nothing the browser wrote is trusted.** Each picture is read from the working directory without following a link, must be a PNG of a sane size
  and show something (a single flat color is a blank page), is brought under the size cap the task allows, and is sent as base64. The page ids are
  cvENGINE's, the file names are this module's own.

``available()`` says whether this image has the browser (Playwright and the Chromium headless shell it drives); a Sentinel without it never declares
the kind.
"""
import base64
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

from cvengine_scanner.probes import screenshots as lib
from cvengine_scanner.probes import transport
from cvengine_scanner.probes.policy import ScopeRefused

from . import egress, shotproxy

logger = logging.getLogger('sentinel.shot')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_RSS_MB = max(300, min(16384, int(os.environ.get('CVENGINE_SENTINEL_SHOT_MAX_RSS_MB') or 1500)))  # the browser and everything it started
READ_LIMIT = 16 * 1024 * 1024  # a file the browser wrote that is larger than this is not a picture of a page
TOO_BIG = 'The picture is larger than the size allowed.'


class Unavailable(RuntimeError):
    """This Sentinel cannot take a picture (no browser here, or it could not start for a reason that is not the sandbox)."""


# ----------------------------------------------------------------------------- the browser on disk

def _playwright_root():
    import importlib.util
    spec = importlib.util.find_spec('playwright')
    return os.path.join(os.path.dirname(spec.origin), 'driver', 'package') if spec and spec.origin else ''


def pinned_browser():
    """``{'revision', 'version'}`` of the Chromium headless shell the installed Playwright drives (its own ``browsers.json``), or ``{}``."""
    try:
        with open(os.path.join(_playwright_root(), 'browsers.json'), encoding='utf-8') as handle:
            for entry in json.load(handle).get('browsers', []):
                if entry.get('name') == 'chromium-headless-shell':
                    return {'revision': str(entry.get('revision') or ''), 'version': str(entry.get('browserVersion') or '')}
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def browsers_dir():
    path = os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '').strip()
    return path if path and path != '0' else os.path.expanduser('~/.cache/ms-playwright')


def available():
    """Whether the headless Chromium this Playwright release drives is on disk (its installer's completion marker). Looks, never launches."""
    revision = pinned_browser().get('revision')
    return bool(revision) and os.path.isfile(os.path.join(browsers_dir(), f'chromium_headless_shell-{revision}', 'INSTALLATION_COMPLETE'))


# ----------------------------------------------------------------------------- what a page may reach

_stack = {'at': 0.0, 'value': frozenset()}


def stack_addresses(refresh=False):
    """The addresses this installation's own services answer on (the compose service names the built-in scanner shares a network with, ``egress.STACK_HOSTS``).
    A page is never allowed to reach them, whatever private ranges the scanner may scan: a picture of one would be a read of it. Kept for a minute."""
    if not refresh and _stack['at'] and time.monotonic() - _stack['at'] < 60:
        return _stack['value']
    found = set()
    for name in egress.STACK_HOSTS:
        try:
            for info in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP):
                found.add(info[4][0])
        except (OSError, UnicodeError):
            continue
    _stack.update(at=time.monotonic(), value=frozenset(found))
    return _stack['value']


class Guard:
    """The answer to "may this page's browser connect to host:port?", for ONE page being captured. The proxy asks it for every connection the page makes:
    its own address, each redirect hop and every sub-resource. The task's scope policy decides the name (``ShotPolicy``: the listed hosts, or with
    ``open_web`` anything not excluded), this Sentinel's floor and the policy's address rules decide every address the name resolves to
    (``transport.resolve``), and this installation's own services are never visited. ``denied`` records what was refused, in order, so the result can say
    why a page that never loaded is ``blocked``, and how many sub-resources were dropped."""

    def __init__(self, policy, primary, stack=None, resolver=None):
        self.policy, self.primary = policy, primary
        self.stack = stack if stack is not None else stack_addresses()
        self.resolver = resolver or transport.resolve
        self.denied = []  # [(host, reason)]
        self._verdicts = {}
        self._lock = threading.Lock()

    def admit(self, host, port):
        """``(addresses, '')`` to let a connection through, or ``(None, reason)``. Remembered per host for this page, so one page is judged consistently."""
        host = (host or '').lower().rstrip('.')
        with self._lock:
            if host in self._verdicts:
                return self._verdicts[host]
        verdict = self._judge(host, port)
        with self._lock:
            self._verdicts[host] = verdict
            if verdict[0] is None:
                self.denied.append((host, verdict[1]))
                self.policy.refuse(host)
        return verdict

    def _judge(self, host, port):
        if host in egress.STACK_HOSTS:
            return None, f"{host} is one of this installation's own services; it is never visited."
        try:
            addresses = self.resolver(host, port, self.policy)
        except ScopeRefused as exc:
            return None, f'{host} is not visited: {str(exc)[:160]}'
        except ValueError:
            return None, f'{host} resolves to an internal or reserved address; it is not visited.'
        except OSError as exc:
            return None, f'{host} could not be resolved ({str(exc)[:80] or "no answer"}).'
        own = self.stack
        if own and any(item[1][0] in own for item in addresses):
            return None, f"{host} resolves to an address of this installation's own services; it is never visited."
        return addresses, ''

    def relabel(self, outcome):
        """Whether a page that failed with ``outcome`` failed because a guard refused it: the page's own host was refused, or the connection failed
        outright and a redirect hop (any other host) was refused. A timeout, a TLS or other error is the page's own, whatever a sub-resource was refused."""
        if not self.denied:
            return False
        return self.refused_primary() or outcome == 'unreachable'

    def refused_primary(self):
        return any(h == self.primary for h, _ in self.denied)

    def blocked_reason(self):
        """Why a page that failed to load was refused, from the first refusal that is not just a sub-resource, else the first of any."""
        if not self.denied:
            return ''
        host, reason = next(((h, r) for h, r in self.denied if h == self.primary), self.denied[0])
        return reason if host == self.primary else f'Redirects to {host}, which is not visited: {reason}'


# ----------------------------------------------------------------------------- the child process

def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


class _Handle:
    """What ``register`` hands the daemon for the running browser: ``poll()`` as on the ``Popen`` and a ``kill()`` that ends the whole process group."""

    def __init__(self, proc):
        self.proc = proc

    def poll(self):
        return self.proc.poll()

    def kill(self):
        _kill_group(self.proc)


def tree_rss_mb(pid):
    """The resident memory of ``pid`` and everything below it, in MB, from /proc."""
    total = 0
    for one in lib.descendants(pid) | {pid}:
        for line in lib.proc_text(one, 'status').splitlines():
            if line.startswith('VmRSS:'):
                try:
                    total += int(line.split()[1])
                except (IndexError, ValueError):
                    pass
                break
    return total // 1024


def make_workdir():
    """A private directory the browser child writes into (its profile, its temporary files, the pictures before they are checked)."""
    path = tempfile.mkdtemp(prefix='cvengine-shots-')
    os.chmod(path, 0o700)
    return path


def child_env(workdir):
    keep = ('PATH', 'LANG', 'LC_ALL', 'PLAYWRIGHT_BROWSERS_PATH', 'TZ')
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault('PATH', '/usr/local/bin:/usr/bin:/bin')
    env['HOME'] = env['TMPDIR'] = workdir  # nothing of this process's environment (the Sentinel's token) reaches the browser
    env.setdefault('PLAYWRIGHT_BROWSERS_PATH', browsers_dir())
    return env


def run_child(job, on_message, wall_seconds, workdir, register=None, argv=None):
    """Run the browser child on ``job`` (see ``shot_child``), hand each of its messages to ``on_message``, and return ``''`` or why the child ended
    without finishing. A wall-clock limit and a memory ceiling kill the whole process group."""
    argv = argv or [sys.executable, '-m', 'client.shot_child']
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=ROOT,
                            env=child_env(workdir), start_new_session=True)
    if register is not None:
        register(_Handle(proc))
    over = {'mb': 0}
    stop_watch = threading.Event()
    timer = threading.Timer(wall_seconds, lambda: _kill_group(proc))
    timer.daemon = True
    timer.start()

    def watch():  # the browser and everything it started, however many sessions it used: a hostile page cannot eat the container
        while not stop_watch.wait(2):
            try:
                used = tree_rss_mb(proc.pid)
            except Exception:  # noqa: BLE001 - a failed measurement is not a reason to kill
                continue
            if used > MAX_RSS_MB:
                over['mb'] = used
                _kill_group(proc)
                return
    threading.Thread(target=watch, name='shot-rss', daemon=True).start()
    fatal, done = '', False
    try:
        proc.stdin.write(json.dumps(job, separators=(',', ':')) + '\n')
        proc.stdin.flush()
        proc.stdin.close()
        for line in proc.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            op = message.get('op')
            if op == 'fatal':
                fatal = str(message.get('reason') or 'the browser failed')
            elif op == 'done':
                done = True
            elif op in ('result', 'sandbox'):
                on_message(message)
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        timer.cancel()
        stop_watch.set()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except (OSError, ValueError, AttributeError):
                pass
    if over['mb']:
        return f'too_big:{over["mb"]}'
    if fatal:
        return fatal
    if not done:
        return f'the browser process ended before it finished (status {proc.returncode})'
    return ''


# ----------------------------------------------------------------------------- the pictures

def read_picture(workdir, name, limit):
    """The bytes of the file ``name`` the browser wrote in ``workdir``, or None. Opened without following a link (``O_NOFOLLOW``), checked to be a
    regular file on the descriptor itself, and read from it, so nothing here goes by the path twice."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    try:
        dirfd = os.open(workdir, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        return None
    try:
        fd = os.open(name, flags, dir_fd=dirfd)
    except OSError:
        return None
    finally:
        os.close(dirfd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return b'' if stat.S_ISREG(info.st_mode) else None
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            return handle.read(limit + 1)
    finally:
        os.close(fd)


def fit_png(data, limit):
    """``data`` when it is within ``limit`` bytes, else a smaller PNG of the same page (optimized, then a 256 color palette, then half the size), or
    ``None`` when none fits. Needs Pillow; without it only a picture that already fits is sent."""
    if len(data) <= limit:
        return data
    try:
        import io

        from PIL import Image
        with Image.open(io.BytesIO(data)) as image:
            rgb = image.convert('RGB')
        for scale in (1.0, 0.5):
            size = (max(1, int(rgb.width * scale)), max(1, int(rgb.height * scale)))
            picture = rgb if scale == 1.0 else rgb.resize(size)
            for variant in (picture, picture.quantize(colors=256)):
                out = io.BytesIO()
                variant.save(out, 'PNG', optimize=True)
                if out.tell() <= limit:
                    return out.getvalue()
    except Exception:  # noqa: BLE001 - a picture that cannot be reduced is not sent
        return None
    return None


def finish_page(message, guard, workdir, key, limit):
    """The result page of one message from the browser child: the picture checked and sized, or the outcome and why. ``blocked`` is this side's call: it
    knows which connections its proxy refused."""
    outcome, reason = message.get('outcome') or 'error', str(message.get('reason') or '')
    if outcome != 'ok' and guard.relabel(outcome):
        return lib.page_result(key, 'blocked', guard.blocked_reason())
    page = {'final_url': message.get('final_url'), 'status': message.get('status'), 'title': message.get('title')}
    if outcome != 'ok':
        return lib.page_result(key, outcome, reason, **page)
    data = read_picture(workdir, f'{key}.png', READ_LIMIT)  # the file is the one this side named, whatever the child says
    if not data:
        return lib.page_result(key, 'error', 'The browser reported a picture that was not written.', **page)
    problem = lib.png_problem(data) if len(data) <= READ_LIMIT else 'too large'
    if problem:
        return lib.page_result(key, 'error', 'The browser wrote a picture that is not a usable PNG.', **page)
    if lib.is_meaningful(data) is False:
        return lib.page_result(key, 'blank', 'The page rendered blank (a single flat color).', **page)
    fitted = fit_png(data, limit)
    if fitted is None or lib.png_problem(fitted):
        return lib.page_result(key, 'error', TOO_BIG, **page)
    return lib.page_result(key, 'ok', '', image=base64.b64encode(fitted).decode('ascii'), **page)


# ----------------------------------------------------------------------------- the task

def run(target, register=None, child=run_child, proxy_factory=shotproxy.VettingProxy, guard_factory=Guard):
    """The result of one ``web_screenshot`` task, in the contract's shape (``sandbox``, ``pages``, ``touched``, ``refused``, ``dropped_requests``).
    Raises ``ValueError`` for a task that is not usable and ``Unavailable`` when the browser could not run for a reason that is not its sandbox (the
    server leaves the pages queued). A browser that could not prove its sandbox returns ``sandbox.engaged`` false and no page: nothing was opened."""
    job = lib.parse_target(target)
    if not available():
        raise Unavailable('this Sentinel has no screenshot browser (Playwright and its Chromium headless shell are not installed)')
    workdir = make_workdir()
    keys = {str(index): page for index, page in enumerate(job.pages)}  # what the browser is told: this side's own keys, never the server's ids
    guards = {key: guard_factory(job.policy, page.host) for key, page in keys.items()}
    paths = {key: os.path.join(workdir, f'{key}.png') for key in keys}
    pages, state = {}, {'engaged': None, 'version': ''}

    def admit(key, host, port):
        guard = guards.get(key)
        return guard.admit(host, port) if guard else (None, 'unknown page')

    def connect(addresses, host, port, timeout):
        return transport.open_socket(addresses, timeout, job.policy, host=host)

    def on_message(message):
        if message.get('op') == 'sandbox':
            state['engaged'], state['version'] = message.get('engaged') is True, str(message.get('version') or '')[:60]
            return
        key = message.get('key')
        if key not in keys or key in pages:
            return
        pages[key] = finish_page(message, guards[key], workdir, key, job.max_bytes)
        pages[key]['id'] = keys[key].id

    secret = secrets.token_urlsafe(24)
    wall = len(keys) * (job.seconds + 10) + 60
    failure = ''
    try:
        with proxy_factory(admit, connect, secret) as proxy:
            run_job = {'targets': [{'key': key, 'url': page.url, 'out': paths[key]} for key, page in keys.items()],
                       'proxy': {'server': proxy.server, 'password': secret},
                       'settings': {'total_seconds': job.seconds, 'nav_timeout_ms': min(job.seconds - 3, 15) * 1000}}
            failure = child(run_job, on_message, wall, workdir, register=register)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    dropped = sum(len(g.denied) for k, g in guards.items() if pages.get(k, {}).get('outcome') == 'ok')
    if failure.startswith(lib.SANDBOX_PREFIX):  # the browser loaded nothing: its sandbox could not start or did not engage
        return {'sandbox': {'engaged': False, 'reason': failure[len(lib.SANDBOX_PREFIX):][:400], 'version': ''}, 'pages': [],
                'touched': job.policy.touched, 'refused': job.policy.refused, 'dropped_requests': 0}
    if state['engaged'] is not True:
        raise Unavailable(('the browser could not run: ' + failure) if failure else 'the browser never proved its sandbox')
    if failure.startswith('too_big:'):  # the page in flight held the browser over its memory ceiling: that page failed, the others are not blamed
        in_flight = next((k for k in keys if k not in pages), None)
        if in_flight is not None:
            pages[in_flight] = lib.page_result(keys[in_flight].id, 'too_big', f'The page needed more than {MAX_RSS_MB} MB of memory ({failure.split(":", 1)[1]} MB) and was stopped.')
        failure = ''
    for key, page in keys.items():  # nothing came back for the pages the browser never reached: say so, so they are not retried in a tight loop
        if key not in pages:
            pages[key] = lib.page_result(page.id, 'unavailable', f'The browser could not run: {failure}' if failure else 'The browser did not report this page.')
    return {'sandbox': {'engaged': True, 'reason': '', 'version': state['version']}, 'pages': [pages[key] for key in keys],
            'touched': job.policy.touched, 'refused': job.policy.refused, 'dropped_requests': dropped}


def sandbox_probe(register=None, argv=None):
    """Start the browser once, as a task does, and say whether its sandbox engaged: ``(engaged, reason, version)``, or ``(None, why, '')`` when the check
    itself did not finish (not a verdict on the sandbox). The daemon logs this at start; a task proves it again before every page."""
    argv = argv or [sys.executable, '-m', 'client.shot_child', '--probe']
    workdir = make_workdir()
    found = {}
    try:
        failure = run_child({}, found.update, 90, workdir, register=register, argv=argv)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if 'engaged' not in found:
        return None, failure or 'no answer', ''
    return found['engaged'], found.get('reason', ''), found.get('version', '')
