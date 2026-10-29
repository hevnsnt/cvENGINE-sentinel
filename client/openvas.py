"""Drive OpenVAS (GVM) scans against this Sentinel's own gvmd, and report results in exactly the shape
``agentapi.sentinel_broker._clean_openvas_result`` expects, so the server's one import path
(``cveFeed.openvas_scan._apply_import``) stores a Sentinel-run task's results identically to a locally-run one.

Unlike nmap/naabu/nuclei/testssl/wpscan, there is no subprocess here: this Sentinel talks GMP (the Greenbone
Management Protocol) directly to the gvmd this container's own GVM stack runs (see docker-compose.yml), the same way
cvENGINE's own server talks to its sidecar (``cveFeed/openvas_scan.py``). The parsing logic below
(``parse_result``/``fetch_results``/``scanned_addresses``) is a direct, dependency-free port of that module's own
functions, since this client has no Django app to import them from; keep the two in step if either changes.

Every GMP exchange is a short session of its own (one poll, one fetch, one cleanup), so a gvmd restart or a dropped socket during a scan that
runs for hours costs a retry, not the run.

``python-gvm`` is only imported inside the functions that need it, so importing this module (and running the test
suite) never requires it to be installed."""
import json
import logging
import math
import os
import re
import secrets
import tempfile
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone

from . import scope

logger = logging.getLogger('sentinel.openvas')

DEFAULT_SOCKET = '/run/gvmd/gvmd.sock'
DEFAULT_LOGIN = ('admin', 'admin')  # the Greenbone community containers' own default login, replaced on first use
DEFAULT_CREDENTIALS_PATH = '/var/lib/cvengine-sentinel/openvas-credentials.json'
DEFAULT_MAX_HOURS = 24  # per task of one host; the server's task may lower it, never raise it

MAX_RESULTS = 5000  # matches cveFeed.openvas_scan.MAX_RESULTS and agentapi.sentinel_broker.MAX_OPENVAS_RESULTS
MAX_PAYLOAD_BYTES = 20 * 1024 * 1024  # the serialized results of one task, at most
RESULT_PAGE = 100
MAX_CVES = 50
MAX_URLS = 20
MAX_TEXT = 4000
MAX_HOSTS = 16  # the server sends one host per task; a few more are tolerated, a range never is
MAX_EXCLUDED = 200
POLL_INTERVAL = 15  # seconds between gmp.get_task polls while a scan runs
RETRIES = 3  # extra attempts of one GMP step after a transient failure (a gvmd restart, a dropped socket)
RETRY_DELAY = 10  # seconds between them
STOP_WAIT = 30  # seconds to wait for a stopped task to leave the active states before deleting it

NAME_PREFIX = 'cvengine-sentinel-'  # every task and target this Sentinel creates is named so; nothing else is ever swept
# Families never scanned from a Sentinel, whatever the server's excluded list says (it can add to these, never remove them).
MIN_EXCLUDED_FAMILIES = frozenset({'Denial of Service', 'Brute force attacks'})

# GVM community-edition built-ins (fixed ids; each is confirmed by name when looked up, see _find).
FULL_AND_FAST = ('daba56c8-73ec-11df-a475-002264764cea', 'Full and fast')
OPENVAS_SCANNER = ('08b69003-5fc2-4037-a479-93b440211c73', 'OpenVAS Default')
PORT_LIST = ('33d0cd82-57c6-11e1-8ed1-406186ea4fc5', 'All IANA assigned TCP')
CONFIG_NAME = 'cvengine-sentinel safe scan'
ALL_ROWS = 'rows=-1'  # gvmd pages list answers (10 rows by default); a built-in must never fall off the first page
TASK_PREFERENCES = {'max_checks': '4', 'max_hosts': '1'}  # the defaults (Greenbone's own 4 NVTs at a time); the server's task may set max_checks


def task_preferences(wanted=None):
    """The GVM task preferences: ``max_checks`` from the server's task when it names a whole number from 1 to 10, else the default; one host at a time
    always (a task carries one host)."""
    checks = (wanted or {}).get('max_checks') if isinstance(wanted, dict) else None
    try:
        checks = int(checks)
    except (TypeError, ValueError):
        checks = int(TASK_PREFERENCES['max_checks'])
    return {'max_checks': str(min(10, max(1, checks))), 'max_hosts': '1'}
ACTIVE_STATUSES = ('New', 'Requested', 'Queued', 'Running', 'Processing', 'Stop Requested')

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# One scan configuration is shared by every task: it is checked and changed by one caller at a time.
_CONFIG_LOCK = threading.Lock()
# The first-use login change must happen once, even when the heartbeat, the poll loop and a task all ask at the same moment.
_BOOTSTRAP_LOCK = threading.RLock()
# The gvmd task and target ids of the runs in this process, which the orphan sweep never touches.
_ACTIVE_IDS = set()
_ACTIVE_LOCK = threading.Lock()


class OpenvasError(RuntimeError):
    """gvmd could not be reached, logged into, or the scan did not finish usably."""


class TransientError(OpenvasError):
    """gvmd could not be reached or dropped the connection: worth another try in a moment."""


def reason(exc):
    """What gvmd or python-gvm said, for a message: the error type and its own text, clipped. (GMP error text names the failed command, never a
    password, so it is safe to show and log.)"""
    text = clean(str(exc), 200)
    return f'{type(exc).__name__}: {text}' if text else type(exc).__name__


def clean(value, limit=MAX_TEXT):
    """Third-party text as plain, bounded text: control characters removed, whitespace kept, clipped."""
    return _CONTROL.sub('', str(value or '')).strip()[:limit]


def socket_path():
    return os.environ.get('CVENGINE_OPENVAS_SOCKET', '').strip() or DEFAULT_SOCKET


def credentials_path():
    return os.environ.get('CVENGINE_OPENVAS_CREDENTIALS_FILE', '').strip() or DEFAULT_CREDENTIALS_PATH


def pending_credentials_path():
    """Where a generated login waits until gvmd has confirmed it (see ``bootstrap_credentials``)."""
    return credentials_path() + '.pending'


def max_hours():
    try:
        return max(1, int(os.environ.get('CVENGINE_OPENVAS_MAX_HOURS', DEFAULT_MAX_HOURS)))
    except ValueError:
        return DEFAULT_MAX_HOURS


def keep_tasks():
    """``CVENGINE_OPENVAS_KEEP_TASKS=1``: leave each task, target and report in gvmd after the run so an operator can inspect them."""
    return os.environ.get('CVENGINE_OPENVAS_KEEP_TASKS', '').strip().lower() in ('1', 'true', 'yes', 'on')


# ----------------------------------------------------------------------------- what the server asked for, checked here

def check_hosts(hosts):
    """The addresses of ``hosts`` (``{ip: hostname}``) this Sentinel will hand gvmd, and their labels. gvmd reads a target's host list as CIDR,
    ranges and comma lists, so every key must be one plain IP address the Sentinel may scan (``scope.check_ip``); the names are labels only."""
    if not isinstance(hosts, dict):
        raise OpenvasError('the hosts must be a mapping of IP address to host name')
    if not hosts:
        raise OpenvasError('no hosts were named')
    if len(hosts) > MAX_HOSTS:
        raise OpenvasError(f'too many hosts for one OpenVAS task ({len(hosts)}; at most {MAX_HOSTS})')
    labels = {}
    for key, name in hosts.items():
        try:
            address = scope.check_ip(key)
        except scope.ScopeError as exc:
            raise OpenvasError(f'refused host {clean(key, 64)!r}: {exc}') from None
        labels[address] = clean(name, 255) if isinstance(name, str) else ''
    return sorted(labels), labels


def budget_hours(requested):
    """The hours this task may run: the server's figure when it names one, never under 1 and never above this machine's own ceiling."""
    ceiling = max_hours()
    if requested is None or requested == '':
        return ceiling
    try:
        value = float(requested)
    except (TypeError, ValueError):
        logger.warning('ignoring an unusable OpenVAS time budget from the server; using %s hours', ceiling)
        return ceiling
    if not math.isfinite(value):
        return ceiling
    return min(ceiling, max(1.0, value))


def check_excluded_families(requested):
    """The NVT families to leave out: the server's list (a list of names) plus this Sentinel's own minimum, compared without regard to case."""
    if requested is None:
        requested = []
    if not isinstance(requested, (list, tuple)) or not all(isinstance(name, str) for name in requested):
        raise OpenvasError('excluded_families must be a list of family names')
    if len(requested) > MAX_EXCLUDED:
        raise OpenvasError(f'too many excluded families ({len(requested)})')
    names = {clean(name, 200) for name in requested} | MIN_EXCLUDED_FAMILIES
    return sorted(name for name in names if name)


# ----------------------------------------------------------------------------- credentials, persisted like the Sentinel's own token

def load_credentials(path=None):
    try:
        with open(path or credentials_path(), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    username, password = data.get('username'), data.get('password')
    if isinstance(username, str) and username and isinstance(password, str) and password:
        return username, password
    return None


def _write_credentials(path, username, password):
    """Write a login file whole or not at all: a temporary file in the same directory (0600), flushed to disk, then renamed over the old one, so a
    crash never leaves a truncated file behind."""
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.' + os.path.basename(path) + '.', suffix='.tmp', dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'username': username, 'password': password}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def save_credentials(username, password, path=None):
    _write_credentials(path or credentials_path(), username, password)


def _drop_pending():
    try:
        os.unlink(pending_credentials_path())
    except FileNotFoundError:
        pass


# ----------------------------------------------------------------------------- the GMP session

def _connection():
    from gvm.connections import UnixSocketConnection
    return UnixSocketConnection(path=socket_path(), timeout=120)


def _open_gmp(connection_factory=None):
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeCheckCommandTransform
    return GMP((connection_factory or _connection)(), transform=EtreeCheckCommandTransform())


DEDICATED_USER = 'cvengine-sentinel'  # the login this Sentinel makes for itself when it may not change the default one


def _create_dedicated_user(gmp, password):
    """Fall back to a login of this Sentinel's own: an administrator-role user created over the default login, for the case where gvmd will not let
    the default user change its own password. Returns the user name."""
    roles = {_text(r, 'name'): r.get('id') for r in gmp.get_roles().findall('role')}
    role_ids = [roles[name] for name in ('Admin', 'Super Admin') if name in roles][:1]
    existing = [u for u in gmp.get_users(filter_string=f'name={DEDICATED_USER}').findall('user') if _text(u, 'name') == DEDICATED_USER]
    if existing:  # left by an earlier attempt whose password was never saved
        gmp.modify_user(existing[0].get('id'), password=password)
    else:
        gmp.create_user(DEDICATED_USER, password=password, role_ids=role_ids or None)
    return DEDICATED_USER


def _login_works(connection_factory, username, password):
    """Whether gvmd accepts this login: False when it refuses it, raises when gvmd cannot be asked."""
    from gvm.errors import GvmResponseError
    try:
        with _open_gmp(connection_factory) as gmp:
            gmp.authenticate(username, password)
    except GvmResponseError:
        return False
    return True


def _retire_default_login(connection_factory, username, password):
    """After the fallback login is saved, take the default ``admin``/``admin`` login away too: anything that can reach the gvmd socket could
    otherwise still log in with it. The new admin password is random and deliberately not saved anywhere; recover it by hand with
    ``gvmd --user=admin --new-password=...`` inside the gvmd container. A failure here only leaves things as they were, so it is a warning."""
    from gvm.errors import GvmError
    try:
        with _open_gmp(connection_factory) as gmp:
            gmp.authenticate(username, password)
            users = [u for u in gmp.get_users(filter_string=f'name={DEFAULT_LOGIN[0]}').findall('user') if _text(u, 'name') == DEFAULT_LOGIN[0]]
            if users:
                gmp.modify_user(users[0].get('id'), password=secrets.token_urlsafe(24))
    except (GvmError, OSError) as exc:
        logger.warning('could not retire the default GVM login admin/admin (%s); it still works on this gvmd', reason(exc))


def bootstrap_credentials(connection_factory=None):
    """Replace the community containers' default login (admin/admin) on first use and persist the new one, the way cvENGINE's own
    ``cveFeed.openvas_scan.bootstrap`` does for its sidecar: first by giving the default user a generated password, and when gvmd refuses that
    (some gvmd versions answer "Failed to find user" to a user changing itself) by creating a user of this Sentinel's own with a generated
    password. Either way the password is set over GMP, so it is never on a command line or logged, and the new login is confirmed before it is
    trusted.

    The generated login is written to a pending file before gvmd is asked to change anything, and only promoted to the real file once gvmd has
    accepted it, so a crash or a failed save between the two never locks this Sentinel out: the next attempt tries the pending login first."""
    from gvm.errors import GvmError
    with _BOOTSTRAP_LOCK:
        try:
            return _bootstrap(connection_factory)
        except OpenvasError:
            raise
        except (GvmError, OSError) as exc:
            raise OpenvasError(f'setting up this Sentinel\'s GMP login failed ({reason(exc)})') from None


def _bootstrap(connection_factory):
    from gvm.errors import GvmError
    pending = load_credentials(pending_credentials_path())
    if pending is not None:
        if _login_works(connection_factory, *pending):
            logger.info('the GMP login from an interrupted first start works; keeping it')
            return _promote(connection_factory, *pending)
        logger.warning('the pending GMP login from an interrupted first start does not work; trying the default login')
    new = secrets.token_urlsafe(24)
    username = DEFAULT_LOGIN[0]
    try:
        with _open_gmp(connection_factory) as gmp:
            gmp.authenticate(*DEFAULT_LOGIN)
            users = [u for u in gmp.get_users(filter_string=f'name={DEFAULT_LOGIN[0]}').findall('user')
                     if _text(u, 'name') == DEFAULT_LOGIN[0]]
            if not users:
                raise OpenvasError('gvmd has no user "admin" to take over')
            _write_credentials(pending_credentials_path(), username, new)
            try:
                gmp.modify_user(users[0].get('id'), password=new)
            except GvmError as exc:
                logger.warning('gvmd would not change the default user\'s password (%s); creating a login of this Sentinel\'s own', reason(exc))
                _write_credentials(pending_credentials_path(), DEDICATED_USER, new)
                try:
                    username = _create_dedicated_user(gmp, new)
                except GvmError as second:
                    _drop_pending()  # gvmd refused both: nothing was changed
                    raise OpenvasError(f'gvmd would not set a password for the default user ({reason(exc)}) nor create a login of this '
                                       f'Sentinel\'s own ({reason(second)}); set one by hand and save it to {credentials_path()} as '
                                       f'{{"username": ..., "password": ...}}') from None
    except GvmError as exc:
        raise OpenvasError(f'the default GVM login did not work ({reason(exc)}); if it was already changed by '
                           f'hand, save the working one to {credentials_path()} as {{"username": ..., "password": ...}}') from None
    if not _login_works(connection_factory, username, new):  # confirm the new password actually works before trusting it
        raise OpenvasError('gvmd did not accept the login it was just given; it is kept and tried again on the next attempt')
    return _promote(connection_factory, username, new)


def _promote(connection_factory, username, password):
    save_credentials(username, password)
    _drop_pending()
    if username == DEDICATED_USER:
        _retire_default_login(connection_factory, username, password)
    return username, password


def ensure_credentials(connection_factory=None):
    saved = load_credentials()
    if saved:
        return saved
    with _BOOTSTRAP_LOCK:  # another thread may have just finished the bootstrap
        return load_credentials() or bootstrap_credentials(connection_factory)


def _rebootstrap(connection_factory, refused_login, refusal):
    """gvmd refused the saved login (its volume was recreated, or the password was changed by hand): set a new one up once, unless another thread
    already did. Raises ``OpenvasError`` saying both what gvmd said and why no new login could be made."""
    with _BOOTSTRAP_LOCK:
        current = load_credentials()
        if current and current != tuple(refused_login):
            return current
        logger.warning('gvmd refused the saved GMP login (%s); setting up a new one', reason(refusal))
        try:
            return bootstrap_credentials(connection_factory)
        except OpenvasError as exc:
            raise OpenvasError(f'gvmd refused the GMP login ({reason(refusal)}), and a new one could not be set up: {exc}') from None


def _authenticated(stack, connection_factory, username, password):
    from gvm.errors import GvmError
    try:
        gmp = stack.enter_context(_open_gmp(connection_factory))
    except (GvmError, OSError, ValueError) as exc:
        raise TransientError(f'gvmd could not be reached ({reason(exc)}): is the GVM stack up yet?') from None
    gmp.authenticate(username, password)
    return gmp


@contextmanager
def session(connection_factory=None):
    """An authenticated GMP session (``gmp``), bootstrapping and persisting this Sentinel's own GMP login on first use, and once more if gvmd stops
    accepting the saved one. Raises ``OpenvasError`` with a message that never holds the password; ``TransientError`` (a subclass) when gvmd could
    not be reached or dropped the connection, which is worth retrying."""
    from gvm.errors import GvmError, GvmResponseError
    try:
        credentials = ensure_credentials(connection_factory)
        with ExitStack() as stack:
            try:
                gmp = _authenticated(stack, connection_factory, *credentials)
            except GvmResponseError as refusal:
                stack.close()
                credentials = _rebootstrap(connection_factory, credentials, refusal)
                try:
                    gmp = _authenticated(stack, connection_factory, *credentials)
                except GvmResponseError as exc:
                    raise OpenvasError(f'gvmd refused the GMP login ({reason(exc)})') from None
            yield gmp
    except OpenvasError:
        raise
    except GvmResponseError as exc:
        raise OpenvasError(f'gvmd answered with an error: {reason(exc)}') from None
    except GvmError as exc:
        raise TransientError(f'the connection to gvmd failed ({reason(exc)})') from None
    except OSError as exc:
        raise TransientError(f'the connection to gvmd failed ({reason(exc)})') from None


def with_session(step, connection_factory=None, cancelled=None):
    """``step(gmp)`` in a short session of its own, tried again (``RETRIES`` times, ``RETRY_DELAY`` apart) when gvmd could not be reached or
    dropped the connection. Only for steps that are safe to repeat. ``cancelled`` (an Event) cuts the waiting short."""
    for attempt in range(RETRIES + 1):
        try:
            with session(connection_factory) as gmp:
                return step(gmp)
        except TransientError as exc:
            if attempt == RETRIES or (cancelled is not None and cancelled.is_set()):
                raise
            logger.warning('gvmd did not answer (%s); trying again in %ss', exc, RETRY_DELAY)
            if cancelled is not None:
                cancelled.wait(RETRY_DELAY)
            else:
                time.sleep(RETRY_DELAY)


# ----------------------------------------------------------------------------- reading GMP XML (ports cveFeed.openvas_scan's own)

def _text(element, path, default=''):
    found = element.find(path) if element is not None else None
    return (found.text or '').strip() if found is not None and found.text else default


def _find(items, spec, tag):
    """The entity (``<config>``, ``<scanner>``, ``<port_list>``) of ``spec`` = (id, name): by its id when the name
    agrees, else by name."""
    by_name = None
    for item in items.findall(tag):
        if item.get('id') == spec[0] and _text(item, 'name') == spec[1]:
            return item
        if _text(item, 'name') == spec[1] and by_name is None:
            by_name = item
    return by_name


def _tags(raw):
    out = {}
    for part in str(raw or '').split('|'):
        key, sep, value = part.partition('=')
        if sep and key.strip():
            out[key.strip()] = value.strip()
    return out


def _port(text):
    match = re.match(r'^(\d{1,5})/(tcp|udp)$', str(text or '').strip().lower())
    if match and 0 < int(match.group(1)) < 65536:
        return f'{int(match.group(1))}/{match.group(2)}', int(match.group(1))
    return 'general/tcp', 0


def _int(text, default=0):
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def parse_result(result):
    """One ``<result>`` element as a plain dict matching ``cveFeed.openvas_scan.parse_result``'s own shape (the shape
    ``agentapi.sentinel_broker._clean_openvas_result`` expects each entry of ``results`` to carry), or ``None`` when
    it is unusable (no host, no NVT OID)."""
    nvt = result.find('nvt')
    host_el = result.find('host')
    oid = (nvt.get('oid') or '').strip() if nvt is not None else ''
    address = (host_el.text or '').strip() if host_el is not None else ''
    if not re.fullmatch(r'[0-9.]{3,64}', oid) or not address:
        return None

    def number(path, default=0.0):
        try:
            return float(_text(result, path) or default)
        except ValueError:
            return default
    refs = nvt.findall('./refs/ref')
    cves = sorted({r.get('id', '').strip().upper() for r in refs
                   if r.get('type', '').lower() == 'cve' and CVE_RE.match(r.get('id', '').strip().upper())})
    cves = sorted(set(cves) | {c for c in (x.strip().upper() for x in re.split(r'[,\s]+', _text(nvt, 'cve'))) if CVE_RE.match(c)})[:MAX_CVES]
    urls = [clean(r.get('id'), 500) for r in refs if r.get('type', '').lower() == 'url' and re.match(r'^https?://', r.get('id', ''))][:MAX_URLS]
    tags = _tags(_text(nvt, 'tags'))
    port, port_number = _port(_text(result, 'port'))
    solution = nvt.find('solution')
    # Since GMP 20.08 the solution type is an attribute of <solution>; older feeds carried it in the tags.
    solution_type = (solution.get('type') if solution is not None else None) or tags.get('solution_type')
    return {
        'oid': oid, 'name': clean(_text(nvt, 'name') or _text(result, 'name'), 300), 'family': clean(_text(nvt, 'family'), 100),
        'address': address, 'hostname': clean(_text(host_el, 'hostname'), 255), 'port': port, 'port_number': port_number,
        'severity': max(0.0, min(10.0, number('severity'))), 'threat': clean(_text(result, 'threat'), 20),
        'qod': int(max(0, min(100, number('qod/value')))), 'qod_type': clean(_text(result, 'qod/type'), 40),
        'result': clean(_text(result, 'description'), 2000), 'summary': clean(tags.get('summary'), 1500),
        'insight': clean(tags.get('insight'), 1500), 'impact': clean(tags.get('impact'), 1500), 'affected': clean(tags.get('affected'), 800),
        'solution': clean(_text(nvt, 'solution') or tags.get('solution'), 1500), 'solution_type': clean(solution_type, 30),
        'cvss_vector': clean(tags.get('cvss_base_vector'), 200), 'cves': cves, 'urls': urls,
    }


def fetch_results(gmp, task_id):
    """Every result of a task as parsed dicts (at most ``MAX_RESULTS``), a page at a time, plus how many had no CVE
    reference and how many were unusable. Mirrors ``cveFeed.openvas_scan.fetch_results`` exactly: a result with no
    CVE is still kept in ``items`` (``cves: []``), for the scanned-host set only, never stored by the server."""
    items, no_cve, unusable, first = [], 0, 0, 1
    while first <= MAX_RESULTS:
        page = gmp.get_results(filter_string=f'task_id={task_id} levels=chmlg min_qod=0 apply_overrides=0 '
                                              f'sort-reverse=severity rows={RESULT_PAGE} first={first}', details=True)
        elements = page.findall('./results/result')
        for element in elements:
            parsed = parse_result(element)
            if parsed is None:
                unusable += 1
                continue
            if not parsed['cves']:
                no_cve += 1
            items.append(parsed)
        if len(elements) < RESULT_PAGE:
            break
        first += RESULT_PAGE
    return items, no_cve, unusable


def bound_results(items, limit=MAX_PAYLOAD_BYTES):
    """The ``results`` to send: items with a CVE as parsed, items without one compacted to ``{address, port}`` (the server only reads the
    scanned-host set from them) and de-duplicated, and the whole kept under ``limit`` bytes of JSON by dropping the lowest-severity entries,
    those without a CVE first. Returns ``(results, dropped_without_cve, dropped_with_cve)``."""
    by_severity = sorted(items, key=lambda i: i.get('severity', 0.0), reverse=True)
    with_cve = [i for i in by_severity if i.get('cves')]
    compact, seen = [], set()
    for item in by_severity:
        key = (item['address'], item['port'])
        if not item.get('cves') and key not in seen:
            seen.add(key)
            compact.append({'address': item['address'], 'port': item['port']})
    sizes = {id(i): len(json.dumps(i)) + 2 for i in with_cve + compact}  # the item plus its separator
    total = 2 + sum(sizes.values())
    dropped_compact = dropped_cve = 0
    while total > limit and compact:
        total -= sizes[id(compact.pop())]
        dropped_compact += 1
    while total > limit and with_cve:
        total -= sizes[id(with_cve.pop())]
        dropped_cve += 1
    return with_cve + compact, dropped_compact, dropped_cve


def _report_detail(gmp, report_id):
    """The report with every host gvmd scanned, whether it had results or not (``result_hosts_only=0``; ``details`` on, without which gvmd
    leaves out the ``<host>`` elements), its counts and errors, and at most one result."""
    return gmp.get_report(report_id, filter_string='result_hosts_only=0 rows=1 min_qod=0 levels=chmlg', details=True)


def _report_hosts(detail):
    return {_text(h, 'ip') for h in detail.findall('.//report/host') if _text(h, 'ip')} if detail is not None else set()


def _report_id(task_status):
    report = task_status.find('./task/last_report/report') if task_status is not None else None
    if report is None and task_status is not None:
        report = task_status.find('./task/current_report/report')
    return report.get('id') if report is not None and report.get('id') else None


def scanned_addresses(gmp, task_status, items):
    """The addresses gvmd really scanned: the hosts of the last report and every host that has a result. Mirrors
    ``cveFeed.openvas_scan.scanned_addresses``."""
    seen = {i['address'] for i in items}
    report_id = _report_id(task_status)
    if report_id:
        try:
            seen |= _report_hosts(_report_detail(gmp, report_id))
        except Exception:  # noqa: BLE001 - the report's host list is a bonus; the results are the floor
            logger.info('could not read the host list of the report')
    return seen


def report_summary(detail):
    """What a report says about its own run: host and result counts, result counts by severity, scan start and end, and gvmd's own errors."""
    if detail is None:
        return {}
    inner = detail.find('.//report/report')
    if inner is None:
        inner = detail.find('.//report')
    if inner is None:
        return {}
    by_level = {}
    counts = inner.find('result_count')
    if counts is not None:
        for child in counts:
            if child.find('full') is not None:
                by_level[child.tag] = _int(_text(child, 'full'))
    hosts = _text(inner, 'hosts/count')
    errors = '; '.join(clean(f'{_text(e, "host")} {_text(e, "description")}', 200) for e in inner.findall('errors/error'))
    return {
        'hosts': _int(hosts) if hosts else len(inner.findall('host')),
        'results': _int(_text(inner, 'result_count/full') or _text(inner, 'result_count'), sum(by_level.values())),
        'by_severity': by_level, 'scan_start': clean(_text(inner, 'scan_start'), 40), 'scan_end': clean(_text(inner, 'scan_end'), 40),
        'errors': clean(errors, 300),
    }


# ----------------------------------------------------------------------------- the scan configuration and target

def _config_element(answer):
    if answer is None:
        return None
    return answer if answer.tag == 'config' else answer.find('.//config')


def _selected_families(config):
    """The family names a scan configuration selects, and whether each of them grows; None when the answer lists no families."""
    families = config.findall('families/family') if config is not None else []
    if not families:
        return None
    return {_text(f, 'name'): _text(f, 'growing') == '1' for f in families
            if _text(f, 'name') and (_text(f, 'growing') == '1' or _int(_text(f, 'nvt_count')) > 0)}


def _safe_checks_on(config):
    for preference in config.findall('preferences/preference') if config is not None else []:
        if _text(preference, 'name') == 'safe_checks':
            return _text(preference, 'value') == 'yes'
    return False


def _nvt_count(config):
    return _int(_text(config, 'nvt_count')) if config is not None else 0


def _in_use(exc):
    return 'in use' in str(exc).lower()


def ensure_config(gmp, excluded):
    """The id of this Sentinel's own safe scan configuration: found by name, or built as a copy of "Full and fast", selecting every NVT family
    except ``excluded`` and this Sentinel's own minimum (compared without regard to case). The selection and the safe_checks preference are written only when what gvmd reports
    differs, one caller at a time, and the result is read back: a configuration with no NVTs would finish "Done" at once with nothing found."""
    from gvm.errors import GvmResponseError
    with _CONFIG_LOCK:
        configs = gmp.get_scan_configs(filter_string=ALL_ROWS)
        existing = [c for c in configs.findall('config') if _text(c, 'name') == CONFIG_NAME]
        if existing:
            config_id = existing[0].get('id')
        else:
            base = _find(configs, FULL_AND_FAST, 'config')
            if base is None:
                raise OpenvasError('the "Full and fast" scan configuration is not in gvmd yet (the feed is not loaded)')
            created = gmp.create_scan_config(base.get('id'), CONFIG_NAME,
                                             comment="cvENGINE Sentinel: Full and fast without the server's excluded families")
            config_id = created.get('id')
        families = [_text(f, 'name') for f in gmp.get_nvt_families().findall('./families/family') if _text(f, 'name')]
        if not families:
            raise OpenvasError('gvmd lists no NVT families (the vulnerability tests are not loaded yet)')
        excluded = set(excluded) | MIN_EXCLUDED_FAMILIES
        lowered = {name.lower() for name in excluded}
        known = {name.lower() for name in families}
        unknown = sorted(name for name in excluded if name.lower() not in known)
        if unknown:  # most likely misspelt: it excludes nothing
            logger.warning('excluded NVT families that match no family in the feed: %s', ', '.join(clean(n, 100) for n in unknown))
        wanted = [name for name in families if name.lower() not in lowered]
        current = _config_element(gmp.get_scan_config(config_id))
        if _selected_families(current) == {name: True for name in wanted} and _safe_checks_on(current):
            logger.info('the scan configuration already selects what this task asked for')
        else:
            # (family, add new NVTs automatically, include all NVTs): gvmd refuses a family that includes all VTs without also growing ("must be
            # growing and include all VTs or it must be static and empty"), so every kept family is (name, True, True); an excluded family is
            # left out, hence unselected.
            try:
                gmp.modify_scan_config_set_family_selection(config_id, [(name, True, True) for name in wanted], auto_add_new_families=False)
                gmp.modify_scan_config_set_scanner_preference(config_id, 'safe_checks', value='yes')
            except GvmResponseError as exc:
                if not _in_use(exc):
                    raise
                selected = _selected_families(current)
                # Only a configuration that already leaves out at least everything this task excludes is good enough to scan with.
                if selected is None or not set(selected) <= set(wanted) or not _safe_checks_on(current):
                    raise OpenvasError(f'the scan configuration is in use by another task and does not match what this one asked for '
                                       f'({reason(exc)})') from None
                logger.warning('the scan configuration is in use by another task (%s); scanning with it as it is', reason(exc))
            current = _config_element(gmp.get_scan_config(config_id))
        if _nvt_count(current) <= 0:
            raise OpenvasError('the scan configuration selects no NVTs (gvmd may still be loading its vulnerability tests); try again later')
        return config_id


def _syncing_feeds(gmp):
    """The feeds gvmd is still downloading (SCAP, CERT, data objects, vulnerability tests), by name; empty when none is or when gvmd cannot say."""
    try:
        feeds = gmp.get_feeds().findall('.//feed')
    except Exception:  # noqa: BLE001 - an older gvmd without the call: nothing to wait on
        return []
    out = []
    for feed in feeds:
        words = [(el.text or '').strip().upper() for el in feed.iter()]
        if feed.find('currently_syncing') is not None or 'SYNCING' in words:
            out.append(_text(feed, 'type') or _text(feed, 'name') or 'unnamed')
    return out


def _ready_marker():
    return os.path.join(os.path.dirname(credentials_path()) or '.', 'openvas-ready')


def readiness(connection_factory=None):
    """``(ready, why_not)``: whether this Sentinel's gvmd can run a scan now. The socket exists long before that: gvmd answers while it is still
    loading feeds (hours on a first start), with no scan configuration, scanner or port list to scan with, so a task dispatched then only fails.
    Ready means the three things a scan needs are present and, until the first time that is so, that no feed is still syncing; after that a
    routine daily feed update does not take the capability away (the scan data is already there). Never raises: the heartbeat and the poll loop
    call it, and any failure is a reason."""
    if not os.path.exists(socket_path()):
        return False, 'gvmd has not created its socket yet (the GVM stack is starting)'
    try:
        with session(connection_factory) as gmp:
            if _find(gmp.get_scan_configs(filter_string=ALL_ROWS), FULL_AND_FAST, 'config') is None:
                return False, 'GVM is still loading its feeds (the "Full and fast" scan configuration is not there yet)'
            if _find(gmp.get_scanners(filter_string=ALL_ROWS), OPENVAS_SCANNER, 'scanner') is None:
                return False, 'GVM is still starting (the OpenVAS scanner is not listed yet)'
            if _find(gmp.get_port_lists(filter_string=ALL_ROWS), PORT_LIST, 'port_list') is None:
                return False, 'GVM is still loading its feeds (the port lists are not there yet)'
            if not os.path.exists(_ready_marker()):
                syncing = _syncing_feeds(gmp)
                if syncing:
                    return False, f'GVM is still syncing its {", ".join(syncing)} feed(s)'
                try:
                    open(_ready_marker(), 'w').close()
                except OSError:
                    pass
    except ImportError:
        return False, 'python-gvm is not installed'
    except OpenvasError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 - an unreadable socket, a timeout, anything python-gvm raises: a reason, never a crash
        return False, f'gvmd could not be asked ({reason(exc)})'
    return True, ''


class OutOfBudget(OpenvasError):
    """The task ran past its time budget and was stopped; ``status`` is gvmd's last answer for it."""

    def __init__(self, status):
        super().__init__('the task ran past its time budget')
        self.status = status


class Interrupted(OpenvasError):
    """gvmd ended the task without finishing it (Interrupted, Stopped, an error state); ``status`` is its last answer."""

    def __init__(self, status, word):
        super().__init__(f'gvmd reports the task as "{clean(word, 30) or "unknown"}"')
        self.status = status


def _active(ids, add):
    with _ACTIVE_LOCK:
        for value in ids:
            if value:
                (_ACTIVE_IDS.add if add else _ACTIVE_IDS.discard)(value)


class OpenvasRun:
    """One OpenVAS run, and the handle the daemon holds for it (the same ``poll()``/``kill()`` a subprocess offers): ``kill()`` stops the gvmd
    task and removes it and its target, over a session of its own, and the run then ends with "the task was stopped"."""

    def __init__(self, connection_factory=None):
        self.connection_factory = connection_factory
        self.cancelled = threading.Event()
        self.finished = threading.Event()
        self.task_id = self.target_id = self.report_id = None
        self.status = None  # gvmd's last get_task answer
        self.detail = None  # the report, once read
        self.labels = {}
        self._removed = set()
        self._cleanup_lock = threading.Lock()

    def poll(self):
        """None while the run is going, then 0 (finished) or 1 (stopped)."""
        if not self.finished.is_set():
            return None
        return 1 if self.cancelled.is_set() else 0

    def kill(self):
        """Stop the run: never raises (the daemon calls it from its heartbeat and shutdown paths)."""
        if self.finished.is_set() or self.cancelled.is_set():
            return
        self.cancelled.set()
        logger.warning('stopping the GVM task %s', self.task_id or '(not created yet)')
        self.cleanup(stop=True)

    def may_be_active(self):
        """Whether the gvmd task may still be scanning: started, and not last seen in a final state."""
        if not self.task_id:
            return False
        return self.status is None or _text(self.status.find('./task'), 'status') in ACTIVE_STATUSES

    def call(self, step):
        return with_session(step, self.connection_factory, self.cancelled)

    def stop_quietly(self):
        if not self.task_id:
            return
        try:
            with session(self.connection_factory) as gmp:
                gmp.stop_task(self.task_id)
        except Exception as exc:  # noqa: BLE001 - the task may already be over
            logger.info('could not stop the GVM task %s (%s)', self.task_id, reason(exc))

    def cleanup(self, stop=False):
        """Remove this run's task (with its report) and target from gvmd, once, unless ``CVENGINE_OPENVAS_KEEP_TASKS`` asks to keep them. With
        ``stop`` the task is stopped first and given ``STOP_WAIT`` seconds to wind down. Never raises."""
        with self._cleanup_lock:
            task_id = self.task_id if self.task_id not in self._removed else None
            target_id = self.target_id if self.target_id not in self._removed else None
            if not task_id and not target_id:
                return
            try:
                with session(self.connection_factory) as gmp:
                    if task_id and stop:
                        _stop_and_wait(gmp, task_id)
                    if keep_tasks():
                        logger.info('keeping GVM task %s, target %s and report %s for inspection (CVENGINE_OPENVAS_KEEP_TASKS)',
                                    task_id, target_id, self.report_id)
                        self._removed.update(i for i in (task_id, target_id) if i)
                        return
                    if task_id:
                        _delete(gmp, 'task', task_id)
                        self._removed.add(task_id)
                    if target_id:
                        _delete(gmp, 'target', target_id)
                        self._removed.add(target_id)
            except Exception as exc:  # noqa: BLE001 - what is left is swept by cleanup_orphans later
                logger.info('could not remove GVM task %s / target %s (%s)', task_id, target_id, reason(exc))

    def log_summary(self):
        """One line on how the run went, before its task and report are removed: what is needed to tell a dead host from an empty config."""
        if not self.task_id:
            return
        if self.detail is None or self.status is None:
            try:
                with session(self.connection_factory) as gmp:
                    if self.status is None:
                        self.status = gmp.get_task(self.task_id)
                    self.report_id = self.report_id or _report_id(self.status)
                    if self.detail is None and self.report_id:
                        self.detail = _report_detail(gmp, self.report_id)
            except Exception as exc:  # noqa: BLE001 - the summary is a diagnosis aid
                logger.info('could not read the GVM task %s for its summary (%s)', self.task_id, reason(exc))
        task = self.status.find('./task') if self.status is not None else None
        summary = report_summary(self.detail)
        logger.info('GVM task %s (%s): status %s, progress %s, report %s, %s host(s), results %s, scan %s to %s, errors: %s',
                    self.task_id, ', '.join(f'{a} {n}'.strip() for a, n in self.labels.items()) or 'no host',
                    clean(_text(task, 'status'), 30) or 'unknown', clean(_text(task, 'progress'), 10) or '?', self.report_id or 'none',
                    summary.get('hosts', '?'), json.dumps(summary.get('by_severity', {}), sort_keys=True),
                    summary.get('scan_start') or '?', summary.get('scan_end') or '?', summary.get('errors') or 'none')


def _delete(gmp, kind, entity_id):
    try:
        getattr(gmp, f'delete_{kind}')(entity_id, ultimate=True)
    except Exception as exc:  # noqa: BLE001 - a leftover is swept by cleanup_orphans later
        logger.info('could not remove the GVM %s %s (%s)', kind, entity_id, reason(exc))


def _stop_and_wait(gmp, task_id):
    """Stop a gvmd task and give it about ``STOP_WAIT`` seconds to leave the active states (gvmd refuses to delete a task still stopping)."""
    try:
        gmp.stop_task(task_id)
    except Exception as exc:  # noqa: BLE001 - it may already be over
        logger.info('could not stop the GVM task %s (%s)', task_id, reason(exc))
    for attempt in range(max(1, STOP_WAIT // 2)):
        try:
            word = _text(gmp.get_task(task_id).find('./task'), 'status')
        except Exception:  # noqa: BLE001 - gone, or gvmd will not say: try the delete anyway
            return
        if word not in ACTIVE_STATUSES:
            return
        if attempt + 1 < max(1, STOP_WAIT // 2):
            time.sleep(2)


def _wait_for_task(run, task_id, deadline):
    """Poll gvmd (a fresh session each time) until the task is Done. Raises ``OutOfBudget`` past ``deadline`` (after stopping the task),
    ``Interrupted`` when gvmd ended it otherwise, and ``OpenvasError('the task was stopped')`` once the run was killed."""
    while True:
        if run.cancelled.is_set():
            run.stop_quietly()
            raise OpenvasError('the task was stopped')
        status = run.call(lambda gmp: gmp.get_task(task_id))
        run.status = status
        word = _text(status.find('./task'), 'status')
        if word == 'Done':
            return status
        if word not in ACTIVE_STATUSES:
            raise Interrupted(status, word)
        if time.monotonic() >= deadline:
            run.stop_quietly()
            raise OutOfBudget(status)
        run.cancelled.wait(POLL_INTERVAL)


def _start(run, gmp, addresses, excluded, preferences):
    """Build the configuration, target and task in one session and start the task. Not retried: none of it is safe to repeat."""
    from gvm.protocols.gmp.requests.v224 import AliveTest
    if not os.path.exists(_ready_marker()) and (syncing := _syncing_feeds(gmp)):
        raise OpenvasError(f'GVM is still syncing its {", ".join(syncing)} feed(s); it cannot scan yet')
    config_id = ensure_config(gmp, excluded)
    scanner = _find(gmp.get_scanners(filter_string=ALL_ROWS), OPENVAS_SCANNER, 'scanner')
    if scanner is None:
        raise OpenvasError('gvmd does not list the OpenVAS scanner yet')
    port_list = _find(gmp.get_port_lists(filter_string=ALL_ROWS), PORT_LIST, 'port_list')
    if port_list is None:
        raise OpenvasError('gvmd has no "All IANA assigned TCP" port list yet (the feed data is not loaded)')
    name = f'{NAME_PREFIX}{secrets.token_hex(6)}'
    # The server already decided the host is up and in scope; gvmd's default alive test (ICMP and TCP-ACK ping) would call a firewalled host
    # dead and finish "Done" with nothing scanned.
    target = gmp.create_target(name, hosts=addresses, port_list_id=port_list.get('id'), alive_test=AliveTest.CONSIDER_ALIVE,
                               comment='cvENGINE Sentinel: a server-vetted host set; created and removed by this Sentinel')
    run.target_id = target.get('id')
    _active([run.target_id], True)
    if run.cancelled.is_set():
        raise OpenvasError('the task was stopped')
    task = gmp.create_task(name, config_id, run.target_id, scanner.get('id'), comment='cvENGINE Sentinel scan',
                           preferences=task_preferences(preferences))
    run.task_id = task.get('id')
    _active([run.task_id], True)
    if run.cancelled.is_set():
        raise OpenvasError('the task was stopped')
    started = gmp.start_task(run.task_id)
    run.report_id = _text(started, 'report_id') or None


def _collect(run):
    def step(gmp):
        items, no_cve, unusable = fetch_results(gmp, run.task_id)
        run.report_id = run.report_id or _report_id(run.status)
        detail = None
        if run.report_id:
            try:
                detail = _report_detail(gmp, run.report_id)
            except Exception as exc:  # noqa: BLE001 - the report's host list is a bonus; the results are the floor
                logger.info('could not read the report %s (%s)', run.report_id, reason(exc))
        return items, no_cve, unusable, detail
    items, no_cve, unusable, run.detail = run.call(step)
    return items, no_cve, unusable


def _empty_error(run):
    summary = report_summary(run.detail)
    errors = f'; gvmd errors: {summary["errors"][:150]}' if summary.get('errors') else ''
    return OpenvasError(f'gvmd scanned no host: it was considered dead, or the scan configuration was empty (report {run.report_id or "none"}: '
                        f'{summary.get("hosts", 0)} host(s), {summary.get("results", 0)} result(s){errors})')


def _execute(run, addresses, excluded, hours, preferences):
    deadline = time.monotonic() + hours * 3600
    with session(run.connection_factory) as gmp:
        _start(run, gmp, addresses, excluded, preferences)
    ended = None  # why the task ended early, when it did
    try:
        status = _wait_for_task(run, run.task_id, deadline)
    except (OutOfBudget, Interrupted) as exc:
        if run.cancelled.is_set():
            raise OpenvasError('the task was stopped') from None
        status, ended = exc.status, str(exc)
        logger.warning('GVM task %s: %s; keeping what it found so far', run.task_id, ended)
    partial = ended is not None
    run.status = status
    items, no_cve, unusable = _collect(run)
    if partial and not items:
        raise OpenvasError(f'{ended} and found nothing')
    found = {i['address'] for i in items}
    scanned = found if partial else found | _report_hosts(run.detail)
    if not scanned:
        raise _empty_error(run)
    results, dropped_compact, dropped_cve = bound_results(items, MAX_PAYLOAD_BYTES)
    if dropped_compact or dropped_cve:
        logger.warning('the results of GVM task %s were over %s bytes: left out %s without a CVE and %s with one (lowest severity first)',
                       run.task_id, MAX_PAYLOAD_BYTES, dropped_compact, dropped_cve)
    # Results with a CVE left out must not read as fixed on the server: a cut result set is a partial one.
    return {'results': results, 'scanned_addresses': sorted(scanned), 'without_cve': no_cve, 'unusable': unusable,
            'partial': partial or bool(dropped_cve)}


def run_openvas(hosts, excluded_families=None, max_hours_=None, register=None, connection_factory=None, preferences=None):
    """Run one GVM task against ``hosts`` (``{ip: hostname}``) and return ``{'results', 'scanned_addresses',
    'without_cve', 'unusable', 'partial'}``, the exact shape ``agentapi.sentinel_broker._clean_openvas_result`` expects. A task that runs past its
    time budget, or that gvmd interrupts, is stopped and what it found so far is returned with ``partial: True`` (the server keeps it and closes
    nothing an earlier scan found); with nothing found it is the failure it always was, and so is a finished run that scanned no host at all.
    ``preferences`` is the server's task preferences (``max_checks``).

    ``register`` (the daemon's) is called with this run's handle as soon as it exists, so a task the server takes back, or a shutdown, stops the
    gvmd task and removes it instead of leaving it to scan for hours. Everything the server sent is checked here first: plain, allowed IP
    addresses only (``check_hosts``), a time budget within this machine's own ceiling, and a list of excluded families that always keeps this
    Sentinel's own minimum."""
    addresses, labels = check_hosts(hosts)
    excluded = check_excluded_families(excluded_families)
    hours = budget_hours(max_hours_)
    run = OpenvasRun(connection_factory)
    run.labels = labels
    if register is not None:
        register(run)
    try:
        return _execute(run, addresses, excluded, hours, preferences)
    except OpenvasError as exc:
        if run.cancelled.is_set():  # whatever failed after the kill, the cause is the kill
            raise OpenvasError('the task was stopped') from None
        if run.report_id and run.report_id not in str(exc):
            raise OpenvasError(f'{exc} (gvmd report {run.report_id})') from None
        raise
    finally:
        run.log_summary()
        run.cleanup(stop=run.may_be_active())
        _active([run.task_id, run.target_id], False)
        run.finished.set()


# ----------------------------------------------------------------------------- leftovers

def _age_hours(text, now):
    try:
        created = datetime.fromisoformat(str(text).strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (now - created).total_seconds() / 3600


def cleanup_orphans(max_age_hours=None, connection_factory=None, now=None):
    """Remove what earlier runs left in gvmd (a crash, a restart mid-scan): tasks and targets named ``cvengine-sentinel-...`` that are not part
    of a run in this process. A task that is not running is deleted; a running one is stopped and deleted only once it is older than
    ``max_age_hours`` (default: this machine's ``max_hours()``), since no run of this Sentinel lasts longer. With
    ``CVENGINE_OPENVAS_KEEP_TASKS`` set, finished tasks are kept for inspection and old running ones are only stopped. Objects without the
    prefix are never touched. Never raises; returns how many tasks and targets it removed."""
    removed = {'tasks': 0, 'targets': 0}
    limit = max_hours() if max_age_hours is None else max_age_hours
    now = now or datetime.now(timezone.utc)
    keep = keep_tasks()
    try:
        with _ACTIVE_LOCK:
            active = set(_ACTIVE_IDS)
        with session(connection_factory) as gmp:
            in_use = set()
            for task in gmp.get_tasks(filter_string=ALL_ROWS).findall('task'):
                task_id, name = task.get('id'), _text(task, 'name')
                target = task.find('target')
                target_id = target.get('id') if target is not None else None
                if not task_id or not name.startswith(NAME_PREFIX) or task_id in active:
                    in_use.add(target_id)
                    continue
                running = _text(task, 'status') in ACTIVE_STATUSES
                age = _age_hours(_text(task, 'creation_time'), now)
                if running and (age is None or age < limit):
                    in_use.add(target_id)
                    continue
                if running:
                    logger.warning('stopping the leftover GVM task %s (%s, %.0f hours old)', task_id, clean(name, 60), age)
                    _stop_and_wait(gmp, task_id)
                if keep:
                    in_use.add(target_id)
                    continue
                logger.info('removing the leftover GVM task %s (%s)', task_id, clean(name, 60))
                try:
                    gmp.delete_task(task_id, ultimate=True)
                    removed['tasks'] += 1
                except Exception as exc:  # noqa: BLE001
                    in_use.add(target_id)
                    logger.info('could not remove the leftover GVM task %s (%s)', task_id, reason(exc))
            for target in gmp.get_targets(filter_string=ALL_ROWS).findall('target'):
                target_id, name = target.get('id'), _text(target, 'name')
                if not target_id or not name.startswith(NAME_PREFIX) or target_id in active or target_id in in_use:
                    continue
                try:
                    gmp.delete_target(target_id, ultimate=True)
                    removed['targets'] += 1
                except Exception as exc:  # noqa: BLE001 - still used by a task gvmd did not let go of
                    logger.info('could not remove the leftover GVM target %s (%s)', target_id, reason(exc))
    except Exception as exc:  # noqa: BLE001 - a sweep that fails only leaves things as they were
        logger.warning('could not sweep leftover GVM tasks (%s)', reason(exc))
    return removed
