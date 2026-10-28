"""Drive OpenVAS (GVM) scans against this Sentinel's own gvmd, and report results in exactly the shape
``agentapi.sentinel_broker._clean_openvas_result`` expects, so the server's one import path
(``cveFeed.openvas_scan._apply_import``) stores a Sentinel-run task's results identically to a locally-run one.

Unlike nmap/naabu/nuclei/testssl/wpscan, there is no subprocess here: this Sentinel talks GMP (the Greenbone
Management Protocol) directly to the gvmd this container's own GVM stack runs (see docker-compose.yml), the same way
cvENGINE's own server talks to its sidecar (``cveFeed/openvas_scan.py``). The parsing logic below
(``parse_result``/``fetch_results``/``scanned_addresses``) is a direct, dependency-free port of that module's own
functions, since this client has no Django app to import them from; keep the two in step if either changes.

``python-gvm`` is only imported inside the functions that need it, so importing this module (and running the test
suite) never requires it to be installed."""
import json
import logging
import os
import re
import secrets
import time
from contextlib import ExitStack, contextmanager

logger = logging.getLogger('sentinel.openvas')

DEFAULT_SOCKET = '/run/gvmd/gvmd.sock'
DEFAULT_LOGIN = ('admin', 'admin')  # the Greenbone community containers' own default login, replaced on first use
DEFAULT_CREDENTIALS_PATH = '/var/lib/cvengine-sentinel/openvas-credentials.json'
DEFAULT_MAX_HOURS = 12

MAX_RESULTS = 5000  # matches cveFeed.openvas_scan.MAX_RESULTS and agentapi.sentinel_broker.MAX_OPENVAS_RESULTS
RESULT_PAGE = 100
MAX_CVES = 50
MAX_URLS = 20
MAX_TEXT = 4000
POLL_INTERVAL = 15  # seconds between gmp.get_task polls while a scan runs

# GVM community-edition built-ins (fixed ids; each is confirmed by name when looked up, see _find).
FULL_AND_FAST = ('daba56c8-73ec-11df-a475-002264764cea', 'Full and fast')
OPENVAS_SCANNER = ('08b69003-5fc2-4037-a479-93b440211c73', 'OpenVAS Default')
PORT_LIST = ('33d0cd82-57c6-11e1-8ed1-406186ea4fc5', 'All IANA assigned TCP')
CONFIG_NAME = 'cvengine-sentinel safe scan'
TASK_PREFERENCES = {'max_checks': '2', 'max_hosts': '1'}  # two NVTs at a time against one host at a time: slow on purpose
ACTIVE_STATUSES = ('New', 'Requested', 'Queued', 'Running', 'Processing', 'Stop Requested')

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
_CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


class OpenvasError(RuntimeError):
    """gvmd could not be reached, logged into, or the scan did not finish usably."""


def clean(value, limit=MAX_TEXT):
    """Third-party text as plain, bounded text: control characters removed, whitespace kept, clipped."""
    return _CONTROL.sub('', str(value or '')).strip()[:limit]


def socket_path():
    return os.environ.get('CVENGINE_OPENVAS_SOCKET', '').strip() or DEFAULT_SOCKET


def credentials_path():
    return os.environ.get('CVENGINE_OPENVAS_CREDENTIALS_FILE', '').strip() or DEFAULT_CREDENTIALS_PATH


def max_hours():
    try:
        return max(1, int(os.environ.get('CVENGINE_OPENVAS_MAX_HOURS', DEFAULT_MAX_HOURS)))
    except ValueError:
        return DEFAULT_MAX_HOURS


# ----------------------------------------------------------------------------- credentials, persisted like the Sentinel's own token

def load_credentials(path=None):
    try:
        with open(path or credentials_path(), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    username, password = data.get('username'), data.get('password')
    if isinstance(username, str) and username and isinstance(password, str) and password:
        return username, password
    return None


def save_credentials(username, password, path=None):
    path = path or credentials_path()
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump({'username': username, 'password': password}, handle)
    finally:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


# ----------------------------------------------------------------------------- the GMP session

def _connection():
    from gvm.connections import UnixSocketConnection
    return UnixSocketConnection(path=socket_path(), timeout=120)


def _open_gmp(connection_factory=None):
    from gvm.protocols.gmp import GMP
    from gvm.transforms import EtreeCheckCommandTransform
    return GMP((connection_factory or _connection)(), transform=EtreeCheckCommandTransform())


def bootstrap_credentials(connection_factory=None):
    """Replace the community containers' default login (admin/admin) with a generated password on first use and
    persist it, exactly like cvENGINE's own ``cveFeed.openvas_scan.bootstrap`` does for its sidecar. The password is
    set over GMP, so it is never on a command line or logged."""
    from gvm.errors import GvmError
    new = secrets.token_urlsafe(24)
    try:
        with _open_gmp(connection_factory) as gmp:
            gmp.authenticate(*DEFAULT_LOGIN)
            users = [u for u in gmp.get_users(filter_string=f'name={DEFAULT_LOGIN[0]}').findall('user')
                     if _text(u, 'name') == DEFAULT_LOGIN[0]]
            if not users:
                raise OpenvasError('gvmd has no user "admin" to take over')
            gmp.modify_user(users[0].get('id'), password=new)
    except GvmError as exc:
        raise OpenvasError(f'the default GVM login did not work ({type(exc).__name__}); if it was already changed by '
                           f'hand, save the working one to {credentials_path()} as {{"username": ..., "password": ...}}') from None
    with _open_gmp(connection_factory) as gmp:
        gmp.authenticate(DEFAULT_LOGIN[0], new)  # confirm the new password actually works before trusting it
    save_credentials(DEFAULT_LOGIN[0], new)
    return DEFAULT_LOGIN[0], new


def ensure_credentials(connection_factory=None):
    return load_credentials() or bootstrap_credentials(connection_factory)


@contextmanager
def session(connection_factory=None):
    """An authenticated GMP session (``gmp``), bootstrapping and persisting this Sentinel's own GMP login on first
    use. Raises ``OpenvasError`` with a message that never holds the password."""
    from gvm.errors import GvmError
    username, password = ensure_credentials(connection_factory)
    stack = ExitStack()
    try:
        with stack:
            try:
                gmp = stack.enter_context(_open_gmp(connection_factory))
            except GvmError as exc:
                raise OpenvasError(f'gvmd could not be reached ({type(exc).__name__}): is the GVM stack up yet?') from None
            except (OSError, ValueError) as exc:
                raise OpenvasError(f'gvmd could not be reached ({type(exc).__name__}): is the GVM stack up yet?') from None
            try:
                gmp.authenticate(username, password)
            except GvmError as exc:
                raise OpenvasError(f'gvmd refused the GMP login ({type(exc).__name__})') from None
            yield gmp
    except OpenvasError:
        raise
    except GvmError as exc:
        raise OpenvasError(f'gvmd answered with an error: {type(exc).__name__}') from None
    except OSError as exc:
        raise OpenvasError(f'the connection to gvmd failed ({type(exc).__name__})') from None


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
    return {
        'oid': oid, 'name': clean(_text(nvt, 'name') or _text(result, 'name'), 300), 'family': clean(_text(nvt, 'family'), 100),
        'address': address, 'hostname': clean(_text(host_el, 'hostname'), 255), 'port': port, 'port_number': port_number,
        'severity': max(0.0, min(10.0, number('severity'))), 'threat': clean(_text(result, 'threat'), 20),
        'qod': int(max(0, min(100, number('qod/value')))), 'qod_type': clean(_text(result, 'qod/type'), 40),
        'result': clean(_text(result, 'description'), 2000), 'summary': clean(tags.get('summary'), 1500),
        'insight': clean(tags.get('insight'), 1500), 'impact': clean(tags.get('impact'), 1500), 'affected': clean(tags.get('affected'), 800),
        'solution': clean(_text(nvt, 'solution') or tags.get('solution'), 1500), 'solution_type': clean(tags.get('solution_type'), 30),
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


def scanned_addresses(gmp, task_status, items):
    """The addresses gvmd really scanned: the hosts of the last report and every host that has a result. Mirrors
    ``cveFeed.openvas_scan.scanned_addresses``."""
    seen = {i['address'] for i in items}
    report = task_status.find('./task/last_report/report')
    if report is not None and report.get('id'):
        try:
            detail = gmp.get_report(report.get('id'), filter_string='rows=1 min_qod=0 levels=chmlg', details=False)
            seen |= {_text(h, 'ip') for h in detail.findall('.//report/host') if _text(h, 'ip')}
        except Exception:  # noqa: BLE001 - the report's host list is a bonus; the results are the floor
            logger.info('could not read the host list of the report')
    return seen


# ----------------------------------------------------------------------------- the scan configuration and target

def _apply_family_selection(gmp, config_id, excluded_families):
    families = [_text(f, 'name') for f in gmp.get_nvt_families().findall('./families/family')]
    wanted = [(name, False, True) for name in families if name and name not in excluded_families]
    gmp.modify_scan_config_set_family_selection(config_id, wanted, auto_add_new_families=False)


def ensure_config(gmp, excluded_families):
    """The id of this Sentinel's own safe scan configuration: found by name, or built as a copy of "Full and fast".
    ``excluded_families`` (this instance's own list, sent fresh in every task's target, never a copy this Sentinel
    might otherwise cache) is (re-)applied on every call, so a config made for an earlier task can never silently
    drift from what the current one asked for."""
    existing = [c for c in gmp.get_scan_configs().findall('config') if _text(c, 'name') == CONFIG_NAME]
    if existing:
        config_id = existing[0].get('id')
    else:
        base = _find(gmp.get_scan_configs(), FULL_AND_FAST, 'config')
        if base is None:
            raise OpenvasError('the "Full and fast" scan configuration is not in gvmd yet (the feed is not loaded)')
        created = gmp.create_scan_config(base.get('id'), CONFIG_NAME,
                                         comment="cvENGINE Sentinel: Full and fast without the server's excluded families")
        config_id = created.get('id')
    _apply_family_selection(gmp, config_id, excluded_families)
    gmp.modify_scan_config_set_scanner_preference(config_id, 'safe_checks', value='yes')
    return config_id


def _wait_for_task(gmp, task_id, deadline):
    while True:
        status = gmp.get_task(task_id)
        word = _text(status.find('./task'), 'status')
        if word == 'Done':
            return status
        if word not in ACTIVE_STATUSES:
            raise OpenvasError(f'gvmd reports the task as "{clean(word, 30) or "unknown"}"')
        if time.monotonic() >= deadline:
            try:
                gmp.stop_task(task_id)
            except Exception:  # noqa: BLE001 - the task may already be over
                logger.info('could not stop the timed-out GVM task %s', task_id)
            raise OpenvasError('the task ran past its time budget')
        time.sleep(POLL_INTERVAL)


def run_openvas(hosts, excluded_families=None, max_hours_=None, register=None, connection_factory=None):
    """Run one GVM task against ``hosts`` (``{ip: hostname}``) and return ``{'results', 'scanned_addresses',
    'without_cve', 'unusable'}``, the exact shape ``agentapi.sentinel_broker._clean_openvas_result`` expects.
    ``register`` is accepted for the same signature every other tool runner has, but is never called: unlike a
    subprocess there is nothing here for the daemon's shutdown handler to kill, and a SIGTERM during a scan simply
    releases the task back to the server (which retries it elsewhere) while this Sentinel's own gvmd finishes the
    orphaned task in the background, the same way an abandoned local run is left to finish on the main server."""
    addresses = sorted(hosts or {})
    if not addresses:
        raise OpenvasError('no hosts were named')
    deadline = time.monotonic() + max(1, int(max_hours_ or max_hours())) * 3600
    target_id = task_id = None
    with session(connection_factory) as gmp:
        try:
            config_id = ensure_config(gmp, list(excluded_families or ()))
            scanner = _find(gmp.get_scanners(), OPENVAS_SCANNER, 'scanner')
            if scanner is None:
                raise OpenvasError('gvmd does not list the OpenVAS scanner yet')
            port_list = _find(gmp.get_port_lists(), PORT_LIST, 'port_list')
            if port_list is None:
                raise OpenvasError('gvmd has no "All IANA assigned TCP" port list yet (the feed data is not loaded)')
            name = f'cvengine-sentinel-{secrets.token_hex(6)}'
            target = gmp.create_target(name, hosts=addresses, port_list_id=port_list.get('id'),
                                       comment='cvENGINE Sentinel: a server-vetted host set; created and removed by this Sentinel')
            target_id = target.get('id')
            task = gmp.create_task(name, config_id, target_id, scanner.get('id'), comment='cvENGINE Sentinel scan',
                                   preferences=TASK_PREFERENCES)
            task_id = task.get('id')
            gmp.start_task(task_id)
            status = _wait_for_task(gmp, task_id, deadline)
            items, no_cve, unusable = fetch_results(gmp, task_id)
            scanned = scanned_addresses(gmp, status, items)
            return {'results': items, 'scanned_addresses': sorted(scanned), 'without_cve': no_cve, 'unusable': unusable}
        finally:
            if task_id:
                try:
                    gmp.delete_task(task_id, ultimate=True)
                except Exception:  # noqa: BLE001 - the results are already read; a leftover task is harmless
                    logger.info('could not remove the finished GVM task %s', task_id)
            if target_id:
                try:
                    gmp.delete_target(target_id, ultimate=True)
                except Exception:  # noqa: BLE001
                    logger.info('could not remove the GVM target %s', target_id)
