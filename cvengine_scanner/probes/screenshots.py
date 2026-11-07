"""The pure half of the ``web_screenshot`` kind: what a Sentinel's browser may open, what it may send back, and how it proves its sandbox.

cvENGINE (``cveFeed.web_shot``) picks the pages, computes the scope policy and sends up to six pages of one project as a task; the Sentinel client
(``client/shot.py``) runs Chromium on them. Everything here is code with no browser, no socket and no dependency of its own, so it is tested without one:

- ``parse_target``: the task, read and held to its bounds (a page is an ``http`` or ``https`` URL with no login in it, its id is the server's, the
  limits are clamped), with the scope policy as a ``ShotPolicy``;
- ``ShotPolicy``: the probes' ``ScopePolicy`` plus the one thing a browser needs that a probe does not: with ``open_web`` (the server sets it for a
  project that works no bug bounty program) a page's own sub-resources and redirects may reach any host the policy does not exclude, always under this
  Sentinel's address floor; without it only the hosts the policy lists are reachable. Exclusions are never open;
- ``png_problem``, ``png_size``, ``is_meaningful``: a picture is a PNG of a sane size that shows something (the server checks all of it again, and
  never trusts a name or a type a Sentinel reports);
- ``classify_error``: Chromium's and Playwright's navigation errors in plain words, as cvENGINE's own capture did;
- ``judge_sandbox``, ``browser_processes``: the proof that Chromium's sandbox engaged (the renderer in a user and PID namespace of its own, under a
  seccomp filter of its own, no ``--no-sandbox``), read from ``/proc``.

The sandbox words and the classification are copied from cvENGINE's ``cveFeed.shot_worker``, which the server no longer carries.
"""
import io
import os
import re
import struct
import zlib
from collections import namedtuple
from urllib.parse import urlsplit

from . import names
from .policy import ScopePolicy

MAX_PAGES = 6                      # pages in one task: six pictures of at most 2 MiB stay under the 24 MiB a result body may be
MAX_ID = 40
MAX_URL = 2000
MAX_IMAGE_BYTES = 2 * 1024 * 1024  # the contract's bound (``max_bytes`` may only lower it)
MIN_IMAGE_BYTES = 64 * 1024
MAX_IMAGE_SIDE = 4096              # a capture is VIEWPORT; a PNG that claims more is never opened
DEFAULT_SECONDS = 20               # the whole of one page: navigation, settling and the picture
MIN_SECONDS, MAX_SECONDS = 8, 60
VIEWPORT = (1280, 800)
OUTCOMES = ('ok', 'timeout', 'unreachable', 'tls_error', 'error', 'blank', 'blocked', 'too_big', 'unavailable')
SANDBOX_PREFIX = 'sandbox: '       # a fatal reason that starts with this: Chromium's sandbox could not start or did not engage, so nothing was loaded
NO_USERNS = ("Chromium's sandbox could not start: this container may not create the user namespaces it needs. The scanner container needs the seccomp "
             "profile config/seccomp/playwright-chromium.json (the compose file applies it when the container is recreated), and the host kernel must "
             "allow unprivileged user namespaces.")
AS_ROOT = "Chromium's sandbox cannot run as root: the screenshot browser must run as an unprivileged account (the Sentinel image runs as one)."

Page = namedtuple('Page', 'id url scheme host port')
Job = namedtuple('Job', 'pages policy open_web seconds max_bytes')

_PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
_PNG_END = b'\x00\x00\x00\x00IEND\xaeB`\x82'


# ----------------------------------------------------------------------------- the task

class ShotPolicy(ScopePolicy):
    """``ScopePolicy`` for a browser: ``open_web`` lets any host the policy does not exclude be reached (a page's fonts, scripts and redirects), still
    only at addresses this Sentinel's floor and the policy's address rules allow (``transport.resolve`` asks both for every name). Without it the
    policy is the probes' own: the listed hosts and nothing else."""

    def __init__(self, doc=None, open_web=False, internal=None):
        super().__init__(doc, internal=internal)
        self.open_web = open_web is True

    def host_refusal(self, host):
        why = super().host_refusal(host)
        if why == 'outside the scope policy' and self.open_web:
            name = names.clean(host).strip('[]') if isinstance(host, str) else ''
            return '' if name and not self._excluded(name) else why
        return why


def _page(raw):
    if not isinstance(raw, dict):
        raise ValueError('a page is an object with an id and a url')
    ident, url = raw.get('id'), raw.get('url')
    if not isinstance(ident, str) or not ident.strip() or len(ident) > MAX_ID:
        raise ValueError('a page has an id of 1 to %d characters' % MAX_ID)
    if not isinstance(url, str) or not url or len(url) > MAX_URL or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise ValueError('a page has a plain ASCII url of at most %d characters' % MAX_URL)
    try:
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except ValueError:
        raise ValueError('not a usable url: %r' % url[:100]) from None
    if parts.scheme not in ('http', 'https') or not host or parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError('a page is an http or https url with no login or fragment: %r' % url[:100])
    port = port or (443 if parts.scheme == 'https' else 80)
    if not 0 < port < 65536:
        raise ValueError('not a usable port: %r' % url[:100])
    return Page(ident, url, parts.scheme, names.clean(host), port)


def parse_target(target):
    """The task read and bounded: ``Job(pages, policy, open_web, seconds, max_bytes)``. Raises ``ValueError`` for anything that is not a usable task.
    A missing scope allows nothing (every host is refused), as for every probe."""
    if not isinstance(target, dict):
        raise ValueError('the target is not an object')
    raw = target.get('pages')
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_PAGES:
        raise ValueError('a web_screenshot task names 1 to %d pages' % MAX_PAGES)
    pages = [_page(p) for p in raw]
    if len({p.id for p in pages}) != len(pages):
        raise ValueError('page ids repeat')
    seconds, limit = target.get('timeout_seconds'), target.get('max_bytes')
    seconds = seconds if isinstance(seconds, int) and not isinstance(seconds, bool) else DEFAULT_SECONDS
    limit = limit if isinstance(limit, int) and not isinstance(limit, bool) else MAX_IMAGE_BYTES
    open_web = target.get('open_web') is True
    return Job(pages, ShotPolicy(target.get('scope'), open_web=open_web), open_web, max(MIN_SECONDS, min(MAX_SECONDS, seconds)),
               max(MIN_IMAGE_BYTES, min(MAX_IMAGE_BYTES, limit)))


def url_for(host, scheme, port):
    """The front page of ``host`` on ``scheme`` and ``port``, as cvENGINE writes it: ``https://host/``, ``http://host:8080/``, ``https://[::1]:8443/``."""
    name = f'[{host}]' if ':' in host else host
    return f'{scheme}://{name}' + ('' if port == (443 if scheme == 'https' else 80) else f':{port}') + '/'


# ----------------------------------------------------------------------------- pictures

def png_size(data):
    """``(width, height)`` of a PNG from its ``IHDR`` chunk, or ``None`` when ``data`` is not one (signature, a length of 13, a good checksum)."""
    if len(data) < 33 or not data.startswith(_PNG_SIGNATURE):
        return None
    length, kind = struct.unpack('>I4s', data[8:16])
    if length != 13 or kind != b'IHDR':
        return None
    header, crc = data[16:29], struct.unpack('>I', data[29:33])[0]
    if zlib.crc32(b'IHDR' + header) & 0xFFFFFFFF != crc:
        return None
    return struct.unpack('>II', header[:8])


def png_problem(data):
    """Why ``data`` is not a PNG the server will open (``''`` when it is): the signature, a checked ``IHDR``, sides from 1 to ``MAX_IMAGE_SIDE`` and the
    ``IEND`` chunk that closes every PNG. The same rules as ``agentapi.web_screenshot_results.png_problem`` on the server."""
    if len(data) < 45 or not data.startswith(_PNG_SIGNATURE):
        return 'not a PNG'
    size = png_size(data)
    if size is None:
        return 'no good IHDR chunk'
    if not (0 < size[0] <= MAX_IMAGE_SIDE and 0 < size[1] <= MAX_IMAGE_SIDE):
        return f'sides above {MAX_IMAGE_SIDE} pixels'
    if not data.endswith(_PNG_END):
        return 'no IEND chunk'
    return ''


def is_meaningful(data):
    """False for a single flat color (a page that painted nothing), ``True`` when the picture has two or more tones, ``None`` when this cannot be
    told here (Pillow is not installed): the server looks again and decides. An image that cannot be read is not a meaningful one. The same rule as
    cvENGINE's ``rdp_shot.is_meaningful``, which the server applies to every picture it stores."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(data)) as image:
            extrema = image.convert('L').getextrema()
        return extrema[0] != extrema[1]
    except Exception:  # noqa: BLE001 - an unreadable image is not a meaningful one
        return False


# ----------------------------------------------------------------------------- what a failed navigation says

def classify_error(message):
    """``(outcome, reason)`` for what a failed navigation raised. The text is Chromium's (``net::ERR_...``) or Playwright's own."""
    text = str(message or '')
    low = text.lower()
    if 'download is starting' in low:
        return 'error', 'The address is a file download, not a page.'
    if 'timeout' in low or 'err_timed_out' in low or 'err_connection_timed_out' in low:
        return 'timeout', 'The page did not load within the time allowed.'
    if 'err_name_not_resolved' in low or 'err_name_resolution_failed' in low:
        return 'unreachable', 'The name does not resolve.'
    if 'err_connection_refused' in low:
        return 'unreachable', 'The connection was refused.'
    if 'err_connection_reset' in low or 'err_connection_closed' in low or 'err_empty_response' in low:
        return 'unreachable', 'The connection was closed without an answer.'
    if 'err_address_unreachable' in low or 'err_network_changed' in low or 'err_internet_disconnected' in low:
        return 'unreachable', 'The address could not be reached.'
    if 'err_ssl' in low or 'err_cert' in low or ('tls' in low and 'err_' in low):
        return 'tls_error', 'The TLS handshake failed.'
    if 'err_too_many_redirects' in low:
        return 'error', 'The page redirects in a loop.'
    if 'err_tunnel_connection_failed' in low or 'err_proxy_connection_failed' in low:
        return 'unreachable', 'The connection could not be made.'
    if 'err_blocked_by_client' in low:
        return 'error', 'The request was blocked.'
    if 'err_http2' in low or 'err_http_' in low or 'err_invalid_http' in low:
        return 'error', 'The server answered with an invalid HTTP response.'
    if 'closed' in low and ('target' in low or 'browser' in low):
        return 'error', 'The browser closed while loading the page.'
    return 'error', re.sub(r'\s+', ' ', text.split('\n', 1)[0])[:200] or 'The page could not be captured.'


def page_result(page_id, outcome, reason='', final_url='', status=None, title='', image=None):
    """One page of the task's result, held to the contract (an unknown outcome is ``error``; text is clipped; a picture only with ``ok``)."""
    if outcome not in OUTCOMES:
        outcome = 'error'
    out = {'id': page_id, 'outcome': outcome, 'reason': re.sub(r'\s+', ' ', str(reason or ''))[:300], 'final_url': str(final_url or '')[:MAX_URL],
           'status': status if isinstance(status, int) and not isinstance(status, bool) and 0 <= status <= 999 else None,
           'title': re.sub(r'\s+', ' ', str(title or '')).strip()[:300]}
    if outcome == 'ok' and image:
        out['image'] = image
    return out


# ----------------------------------------------------------------------------- Chromium's sandbox

def proc_text(pid, name):
    try:
        with open(f'/proc/{pid}/{name}', 'rb') as handle:
            return handle.read().decode('utf-8', 'replace')
    except OSError:
        return ''


def seccomp_filters(status):
    """How many seccomp filters a process is under (``Seccomp_filters`` of /proc/<pid>/status, Linux 5.9 and later), or None."""
    for line in status.splitlines():
        if line.startswith('Seccomp_filters:'):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def descendants(root):
    """The pids below ``root``, by parent pid (Chromium starts processes of its own session and namespaces, so the process group says nothing)."""
    parents = {}
    for name in os.listdir('/proc'):
        if name.isdigit():
            try:
                parents[int(name)] = int(proc_text(name, 'stat').rsplit(')', 1)[1].split()[1])
            except (IndexError, ValueError):
                continue
    found, frontier = set(), {root}
    while frontier:
        frontier = {pid for pid, parent in parents.items() if parent in frontier and pid not in found}
        found |= frontier
    return found


def browser_processes(root=None):
    """``([{'cmdline', 'nspid', 'userns', 'filters'}], own)``: every process below ``root`` (this one), as /proc shows them, and the same of ``root``."""
    root = root or os.getpid()

    def read(pid):
        status = proc_text(pid, 'status')
        nspid = next((line.split()[1:] for line in status.splitlines() if line.startswith('NSpid:')), [])
        try:
            userns = os.readlink(f'/proc/{pid}/ns/user')
        except OSError:
            userns = ''
        return {'pid': pid, 'cmdline': proc_text(pid, 'cmdline').replace('\0', ' '), 'nspid': nspid, 'userns': userns, 'filters': seccomp_filters(status)}
    return [read(pid) for pid in sorted(descendants(root))], read(root)


def judge_sandbox(processes, own):
    """'' when the browser's renderers run inside Chromium's sandbox, else why not. A renderer must exist, be in a user namespace and a PID namespace
    other than this process's (the namespace sandbox), and be under more seccomp filters than this process (the sandbox's own system call filter on
    top of whatever the container has); and no process may carry --no-sandbox."""
    if any('--no-sandbox' in p['cmdline'] for p in processes):
        return 'the browser was started with --no-sandbox'
    renderers = [p for p in processes if '--type=renderer' in p['cmdline']]
    if not renderers:
        return 'no renderer process was found to check'
    for renderer in renderers:
        if len(renderer['nspid']) < 2:
            return 'the renderer shares the PID namespace of the browser'
        if not renderer['userns'] or not own['userns']:
            return 'the user namespace of the renderer could not be read'
        if renderer['userns'] == own['userns']:
            return 'the renderer shares the user namespace of the browser'
        if renderer['filters'] is not None and own['filters'] is not None and renderer['filters'] <= own['filters']:
            return 'the renderer has no seccomp filter of its own'
    return ''


def sandbox_words(message):
    """The plain reason for a launch that failed because of the sandbox, or '' for any other failure."""
    low = str(message or '').lower()
    if 'running as root without --no-sandbox' in low:
        return AS_ROOT
    if 'no usable sandbox' in low or ('sandbox' in low and ('namespace' in low or 'zygote' in low or 'clone' in low)):
        return NO_USERNS
    return ''
