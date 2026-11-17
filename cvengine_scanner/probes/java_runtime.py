"""The ``java_runtime`` kind (contract version 6): read the Java runtime a host runs from what it already says to anyone, and see whether a debug port
is open.

cvENGINE picks the hosts and what to ask (``cveFeed.java_runtime``: only a host already identified as the product a path belongs to is asked that
path, only a port that is a JDWP port or an unidentified debug port is sent the handshake) and builds the scope policy; this module runs the plan
under that policy and returns readings (``cvengine_scanner.java``). Nothing here decides a finding or stores anything.

Web checks (``target['web']``): a small fixed list of GETs per check, each a ``version_probes.fetch`` (pinned vetted address, every redirect hop
asked of the policy, bounded bytes and time, browser-like headers, no cookie, no credential), one host's requests one after another with a pause
between them, and each check stops at its first reading:

  actuator       /actuator/env/java.version, /actuator/info, /actuator/metrics/jvm.info, the legacy /env/java.version (one property, never the
                 whole environment)
  jolokia        /jolokia/version, and only when that is Jolokia's own answer, the two reads of the Runtime MXBean (VmVersion, VmVendor)
  solr           /solr/admin/info/system?wt=json
  geoserver      /geoserver/rest/about/status.json
  druid          /status/properties
  elasticsearch  /_nodes/jvm, filtered to the version fields (Elasticsearch and OpenSearch)

An answer is read only when it is the JSON shape its reader expects (a login page, a catch-all page or an error never gives a reading), and only
the Java version and vendor fields are read from it. The ``X-Powered-By`` and ``Server`` headers of every answer are read too.

JDWP (``target['jdwp']``): one TCP connection per endpoint to the vetted address, the 14-byte ``JDWP-Handshake``, and when the debuggee echoes it,
the one read-only command ``VirtualMachine.Version`` (exactly what nmap's jdwp-version sends). No other JDWP command is ever sent. ``speaks`` is true
when the handshake was echoed: an open JDWP port lets anyone who reaches it run code in that JVM, and cvENGINE files that as a critical exposure.
"""
import concurrent.futures
import logging
import socket
import time
from urllib.parse import urlsplit

from .. import java
from . import version_probes

logger = logging.getLogger(__name__)

KIND = 'java_runtime'
MAX_WEB = 50          # web hosts in one task
MAX_JDWP = 25         # JDWP endpoints in one task
MAX_READINGS = 10     # readings one web entry returns
MAX_ASKED = 20        # (path, status) pairs one web entry reports
REQUEST_GAP = 0.5     # seconds between two requests to one host
WORKERS = 4           # hosts asked side by side
BATCH_SECONDS = 900   # no check starts after this; the rest are reported as not run
JDWP_CONNECT_TIMEOUT = 3
JDWP_READ_SECONDS = 5  # the whole exchange with one endpoint
MAX_BODY = 128 * 1024

ES_FIELDS = 'nodes.*.jvm.version,nodes.*.jvm.vm_vendor,nodes.*.jvm.vm_name,nodes.*.jvm.vm_version,nodes.*.jvm.using_bundled_jdk'
# check -> [(path, reader)]; a reader takes the body and the path and returns a reading, a list of readings, or None
CHECKS = {
    'actuator': (('/actuator/env/java.version', java.from_actuator_env), ('/actuator/info', java.from_actuator_info),
                 ('/actuator/metrics/jvm.info', java.from_actuator_metric), ('/env/java.version', java.from_actuator_env)),
    'jolokia': (('/jolokia/version', None),),  # the reads follow only when this answer is Jolokia's (``_jolokia``)
    'solr': (('/solr/admin/info/system?wt=json', java.from_solr),),
    'geoserver': (('/geoserver/rest/about/status.json', java.from_geoserver),),
    'druid': (('/status/properties', java.from_druid),),
    'elasticsearch': ((f'/_nodes/jvm?filter_path={ES_FIELDS}', java.from_elasticsearch),),
}
JOLOKIA_READS = ('/jolokia/read/java.lang:type=Runtime/VmVersion', '/jolokia/read/java.lang:type=Runtime/VmVendor')


def _clean_web(raw):
    if not isinstance(raw, dict):
        return None
    ident, host, base, checks = raw.get('id'), raw.get('host'), raw.get('base'), raw.get('checks')
    if not all(isinstance(v, str) and v for v in (ident, host, base)) or len(base) > 300 or not isinstance(checks, list):
        return None
    checks = [c for c in dict.fromkeys(checks) if c in CHECKS]
    if not checks:
        return None
    try:
        parts = urlsplit(base)
        parts.port  # noqa: B018 - a bad port raises here
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.path not in ('', '/') or parts.query or parts.username:
        return None
    if parts.hostname.lower().rstrip('.') != host.lower().rstrip('.'):
        return None
    allowed = {str(n).lower().rstrip('.') for n in (raw.get('allowed') or []) if isinstance(n, str)} | {parts.hostname.lower().rstrip('.')}
    return {'id': ident[:200], 'host': host.lower().rstrip('.'), 'base': base.rstrip('/'), 'checks': checks, 'allowed': allowed}


def _clean_jdwp(raw):
    if not isinstance(raw, dict):
        return None
    ident, address, port = raw.get('id'), raw.get('address'), raw.get('port')
    if not (isinstance(ident, str) and ident and isinstance(address, str) and address) or isinstance(port, bool) or not isinstance(port, int) \
            or not 0 < port < 65536:
        return None
    return {'id': ident[:200], 'address': address.strip().strip('[]'), 'port': port}


# ----------------------------------------------------------------------------- web

def _readings(found):
    if not found:
        return []
    return [found] if isinstance(found, dict) else [r for r in found if r]


def run_web(entry, get, sleep=time.sleep):
    """The readings of one web entry: ``{'id', 'readings', 'asked'}``. ``get(url)`` is the fetch (the scope policy is inside it)."""
    readings, asked = [], []
    first = True

    def ask(path):
        nonlocal first
        if not first:
            sleep(REQUEST_GAP)
        first = False
        url = entry['base'] + path
        try:
            got = version_probes.own_answer(get(url), entry['base'])
        except (OSError, ValueError) as exc:
            asked.append({'path': path[:200], 'status': 0, 'error': type(exc).__name__[:40]})
            return None
        if got is None or got.get('challenge'):
            asked.append({'path': path[:200], 'status': (got or {}).get('status') or 0, **({'error': 'challenged'} if got else {})})
            return None
        asked.append({'path': path[:200], 'status': got.get('status') or 0})
        for header_reading in java.from_headers(got.get('raw_headers') or got.get('headers') or {}, url=path):
            if header_reading['version'] not in {r['version'] for r in readings}:
                readings.append(header_reading)
        return got if 200 <= (got.get('status') or 0) < 300 else None

    for check in entry['checks']:
        if check == 'jolokia':
            readings.extend(_jolokia(ask))
            continue
        for path, reader in CHECKS[check]:
            got = ask(path)
            found = _readings(reader((got or {}).get('body', '')[:MAX_BODY], path.split('?', 1)[0])) if got else []
            if found:
                readings.extend(found)
                break
    out, seen = [], set()
    for r in readings:
        key = (r['version'], r['vendor'], r['source'])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return {'id': entry['id'], 'readings': out[:MAX_READINGS], 'asked': asked[:MAX_ASKED]}


def _jolokia(ask):
    got = ask('/jolokia/version')
    if not got or not java.is_jolokia(got.get('body', '')):
        return []
    version = ask(JOLOKIA_READS[0])
    vendor = ask(JOLOKIA_READS[1]) if version else None
    found = java.from_jolokia((version or {}).get('body', ''), (vendor or {}).get('body', ''), url=JOLOKIA_READS[0]) if version else None
    return [found] if found else []


# ----------------------------------------------------------------------------- JDWP

def _recv(sock, size, deadline):
    data = b''
    while len(data) < size:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            chunk = sock.recv(min(4096, size - len(data)))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        data += chunk
    return data


def jdwp_exchange(address, port, connect=socket.create_connection):
    """``(speaks, reply)`` of one JDWP endpoint: the handshake and, when it is echoed, the VirtualMachine.Version command and its parsed reply
    (``java.parse_version_reply``, or None). ``speaks`` is True when the handshake was echoed, False when something else answered, None when nothing
    answered (refused, closed, timed out): unknown. Never raises for a network problem."""
    try:
        sock = connect((address, port), timeout=JDWP_CONNECT_TIMEOUT)
    except OSError:
        return None, None
    deadline = time.monotonic() + JDWP_READ_SECONDS
    try:
        sock.sendall(java.HANDSHAKE)
        echo = _recv(sock, len(java.HANDSHAKE), deadline)
        if not echo:
            return None, None
        if not java.is_handshake(echo):
            return False, None
        sock.sendall(java.version_command(1))
        header = _recv(sock, 11, deadline)
        if len(header) < 11:
            return True, None
        length = int.from_bytes(header[:4], 'big')
        rest = _recv(sock, max(0, min(length, java.MAX_REPLY_BYTES) - 11), deadline) if length > 11 else b''
        return True, java.parse_version_reply(header + rest, packet_id=1)
    except OSError:
        return None, None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def run_jdwp(entry, policy, connect=socket.create_connection):
    """One JDWP endpoint under ``policy``: refused (not asked) when the policy or this Sentinel's floor does not allow the address."""
    address, port = entry['address'], entry['port']
    try:
        policy.check_host(address)
        policy.check_address(address, literal=True)
    except ValueError as exc:
        policy.refuse(address)
        return {'id': entry['id'], 'speaks': None, 'reading': None, 'error': f'not run: {exc}'[:200]}
    policy.touch(address)
    speaks, reply = jdwp_exchange(address, port, connect=connect)
    found = java.from_jdwp(reply, port=port) if reply else None
    return {'id': entry['id'], 'speaks': speaks, 'reading': found}


# ----------------------------------------------------------------------------- the kind

def run_batch(target, probe=None, connect=socket.create_connection, sleep=time.sleep, clock=time.monotonic, workers=WORKERS,
              max_seconds=BATCH_SECONDS):
    """Run a ``java_runtime`` task: ``{'web': [...], 'jdwp': [...], 'scope': {...}}``. Returns ``{'web': [...], 'jdwp': [...], 'touched', 'refused'}``.
    A malformed entry fails the task (the server sent something it should not have); one entry failing never stops the others. ``probe`` replaces
    ``http.probe_url`` and ``connect`` the socket (tests)."""
    from .policy import ScopePolicy
    if not isinstance(target, dict):
        raise ValueError('a java_runtime target is an object')
    policy = ScopePolicy(target.get('scope'))
    web_raw = target.get('web') if isinstance(target.get('web'), list) else []
    jdwp_raw = target.get('jdwp') if isinstance(target.get('jdwp'), list) else []
    if len(web_raw) > MAX_WEB or len(jdwp_raw) > MAX_JDWP or not (web_raw or jdwp_raw):
        raise ValueError(f'a java_runtime task names 1 to {MAX_WEB} web hosts and up to {MAX_JDWP} JDWP endpoints')
    web = [_clean_web(item) for item in web_raw]
    jdwp = [_clean_jdwp(item) for item in jdwp_raw]
    if any(e is None for e in web) or any(e is None for e in jdwp):
        raise ValueError('a planned java_runtime entry is malformed')
    deadline = clock() + max_seconds
    web_out, jdwp_out = {}, {}

    def getter(entry):
        kwargs = {'probe': probe} if probe is not None else {}
        return lambda url: version_probes.fetch(url, policy, allowed=entry['allowed'], sleep=sleep, max_bytes=MAX_BODY, **kwargs)

    def run_host(entry):
        if clock() > deadline:
            web_out[entry['id']] = {'id': entry['id'], 'readings': [], 'asked': [], 'error': 'not run: the task ran out of time'}
            return
        why = policy.host_refusal(entry['host'])
        if why:
            web_out[entry['id']] = {'id': entry['id'], 'readings': [], 'asked': [], 'error': f'not run: the host is {why}'}
            return
        try:
            web_out[entry['id']] = run_web(entry, getter(entry), sleep=sleep)
        except Exception as exc:  # noqa: BLE001 - one host failing never stops the rest; the server asks it again later
            logger.info('java_runtime web check of %s failed: %s', entry['host'], type(exc).__name__)
            web_out[entry['id']] = {'id': entry['id'], 'readings': [], 'asked': [], 'error': f'{type(exc).__name__}: {exc}'[:200]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for future in [pool.submit(run_host, entry) for entry in web]:
            future.result()
    for index, entry in enumerate(jdwp):
        if clock() > deadline:
            jdwp_out[entry['id']] = {'id': entry['id'], 'speaks': None, 'reading': None, 'error': 'not run: the task ran out of time'}
            continue
        if index:
            sleep(REQUEST_GAP)
        jdwp_out[entry['id']] = run_jdwp(entry, policy, connect=connect)
    return {'web': [web_out[e['id']] for e in web if e['id'] in web_out], 'jdwp': [jdwp_out[e['id']] for e in jdwp if e['id'] in jdwp_out],
            'touched': policy.touched, 'refused': policy.refused}
