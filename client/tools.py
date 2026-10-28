"""Run nmap, naabu or nuclei against a server-issued SentinelTask's own typed target, and nothing else.

Every argv built here is a fixed list of flags plus the addresses or hosts the task named: there is no shell, no
string interpolation, and no text the server sent is ever read as a flag or a command. ``validate_targets`` is the one
gate every target list passes through before it reaches ``subprocess``; it is deliberately strict, because a
compromised or buggy server asking a Sentinel to run something other than a plain address, host name or host:port
must fail safe here. This mirrors, in reverse, the discipline ``agentapi``'s own header docstring states for what a
Sentinel reports back: nothing untrusted is ever built into, or interpreted as, a command, on either side of the wire.

Each run function returns the exact typed shape ``agentapi.sentinel_broker.clean_result`` expects for that task kind
(``{'hosts': [...]}`` for nmap, ``{'ports': {...}}`` for naabu, ``{'findings': [...]}`` for nuclei), ready to be sent
back under ``{'outcome': 'done', **result}``.
"""
import ipaddress
import json
import logging
import os
import re
import subprocess
import tempfile
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from . import openvas

logger = logging.getLogger('sentinel.tools')

MAX_TARGETS = 64  # matches agentapi.sentinel_broker.MAX_ADDRESSES: a task never names more than this many
_HOSTNAME = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,62})?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62})?)*\.?$')
_SHELL_META = set(' \t\n\r;|&$`<>(){}\'"\\')

NMAP_BIN = os.environ.get('CVENGINE_NMAP_BIN', 'nmap')
NAABU_BIN = os.environ.get('CVENGINE_NAABU_BIN', 'naabu')
NUCLEI_BIN = os.environ.get('CVENGINE_NUCLEI_BIN', 'nuclei')

NMAP_FLAGS = ['-Pn', '-sV', '--version-intensity', '5', '-O', '--osscan-limit', '-T4', '--open',
              '--top-ports', '1000', '--host-timeout', '8m', '--max-retries', '2']
NAABU_FLAGS = ['-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
NUCLEI_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1']
_TAG = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
_SEVERITY = re.compile(r'^(info|low|medium|high|critical|unknown)$')


class TargetError(ValueError):
    """A SentinelTask's ``target`` did not have the shape a Sentinel will ever act on. Always reported back as
    ``{'outcome': 'error', ...}``, never retried blindly, and the raw target is never passed to a shell."""


def _split_host_port(value):
    if value.count(':') == 1 and not value.startswith('['):
        host, _, port = value.partition(':')
        if port.isdigit() and 0 < int(port) < 65536:
            return host, port
    return value, None


def _validate_one(value):
    if not isinstance(value, str) or not value or len(value) > 260:
        raise TargetError(f'not a usable target: {value!r}')
    text = value.strip()
    if not text or '://' in text or any(ch in _SHELL_META for ch in text):
        raise TargetError(f'not a usable target: {value!r}')
    host, _port = _split_host_port(text)
    try:
        ipaddress.ip_address(host)
        return text
    except ValueError:
        pass
    if not _HOSTNAME.match(host.rstrip('.')):
        raise TargetError(f'not a usable target: {value!r}')
    return text


def validate_targets(values, limit=MAX_TARGETS):
    """The task's own address/host list, defensively checked: a plain IP, a host name, or ``host:port`` (for nuclei),
    nothing shell-meaningful and no URL, at most ``limit`` entries. Raises ``TargetError`` on anything else, rather
    than ever letting it reach an argv list."""
    if not isinstance(values, list) or not values:
        raise TargetError('target has no usable addresses')
    return [_validate_one(v) for v in values[:limit]]


def _targets_file(values):
    handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
    try:
        handle.write('\n'.join(values) + '\n')
    finally:
        handle.close()
    return handle.name


def _run(argv, timeout, register=None):
    """Run ``argv`` (a fixed list, never a string, never ``shell=True``) and return its stdout. ``register``, if given,
    is called with the live ``Popen`` right after it starts, so a caller (the daemon's SIGTERM handler) can terminate
    it without waiting out the full timeout."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if register is not None:
        register(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    if proc.returncode not in (0, None) and not out:
        logger.warning('%s exited %s: %s', argv[0], proc.returncode, (err or '')[:300])
    return out


# --- nmap -----------------------------------------------------------------------------------------------------------

def parse_nmap_xml(xml_text):
    hosts = []
    if not (xml_text or '').strip():
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        return {'hosts': hosts}
    for host_el in root.findall('host'):
        addr_el = None
        for kind in ('ipv4', 'ipv6'):
            addr_el = host_el.find(f"address[@addrtype='{kind}']")
            if addr_el is not None:
                break
        if addr_el is None:
            addr_el = host_el.find('address')
        if addr_el is None or not addr_el.get('addr'):
            continue
        os_guess = ''
        osmatch = host_el.find('os/osmatch')
        if osmatch is not None:
            os_guess = osmatch.get('name') or ''
        ports = []
        for port_el in host_el.findall('ports/port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            service_el = port_el.find('service')
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            ports.append({'number': number, 'protocol': port_el.get('protocol') or 'tcp', 'state': 'open',
                          'service_name': (service_el.get('name') if service_el is not None else '') or '',
                          'product': (service_el.get('product') if service_el is not None else '') or '',
                          'version': (service_el.get('version') if service_el is not None else '') or ''})
        hosts.append({'ip': addr_el.get('addr'), 'os_guess': os_guess, 'ports': ports})
    return {'hosts': hosts}


def _is_ipv6(address):
    try:
        return ipaddress.ip_address(str(address).strip().strip('[]')).version == 6
    except ValueError:
        return False


def run_nmap(addresses, timeout=600, register=None):
    """nmap scans one address family per run and needs ``-6`` for IPv6 (without it the address is "failed to resolve" and the report has no host),
    so the IPv4 and IPv6 addresses of the task run separately and their hosts are returned together."""
    addresses = validate_targets(addresses)
    out = []
    for group, flags in (([a for a in addresses if not _is_ipv6(a)], []), ([a for a in addresses if _is_ipv6(a)], ['-6'])):
        if not group:
            continue
        path = _targets_file(group)
        try:
            argv = [NMAP_BIN, *flags, *NMAP_FLAGS, '-oX', '-', '-iL', path]
            out.extend(parse_nmap_xml(_run(argv, timeout, register))['hosts'])
        finally:
            os.unlink(path)
    return {'hosts': out}


# --- discover: which addresses of an internal network answer -------------------------------------------------------

DISCOVER_FLAGS = ['-sn', '-T4', '-PE', '-PP', '-PS21,22,23,25,80,135,443,445,3389,8080', '-PA80,443', '-PU53,161', '--max-retries', '2',
                  '--host-timeout', '30s']
MAX_DISCOVER_ADDRESSES = 512  # a /23: the server sweeps in /24 chunks, so anything larger is not a task this server would send
MAX_DISCOVER_HOSTS = 512
_PRIVATE_V4 = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10')]


def validate_cidr(value):
    """The chunk of an internal network a ``discover`` task names, as a canonical string, or ``TargetError``. Only a small private IPv4
    network is ever swept: a public range, a huge one or an odd string is refused, whatever the server sent."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=True)
    except ValueError:
        raise TargetError('discover target is not a network in CIDR form')
    if net.version != 4 or not any(net.subnet_of(p) for p in _PRIVATE_V4):
        raise TargetError('discover only sweeps a private IPv4 network')
    if net.num_addresses > MAX_DISCOVER_ADDRESSES:
        raise TargetError(f'discover target covers {net.num_addresses} addresses; the most one task may sweep is {MAX_DISCOVER_ADDRESSES}')
    return str(net)


def parse_discover_xml(xml_text):
    """The addresses nmap's ping sweep found up, each with the host names it learned, from ``-oX`` output."""
    hosts = []
    if not (xml_text or '').strip():
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        return {'hosts': hosts}
    for host_el in root.findall('host'):
        status = host_el.find('status')
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if status is None or status.get('state') != 'up' or addr_el is None or not addr_el.get('addr'):
            continue
        names = [h.get('name') for h in host_el.findall('hostnames/hostname') if h.get('name')]
        hosts.append({'ip': addr_el.get('addr'), 'hostnames': names[:5]})
        if len(hosts) >= MAX_DISCOVER_HOSTS:
            break
    return {'hosts': hosts}


def run_discover(cidr, timeout=900, register=None):
    """A host-alive sweep of one chunk of an internal network: ARP on the local segment, ICMP and a few TCP/UDP probes elsewhere. Reports
    only which addresses answered; a firewall that drops every probe makes a host invisible here, and the server says so (it never reads a
    sweep as proof a host is absent)."""
    cidr = validate_cidr(cidr)
    argv = [NMAP_BIN, *DISCOVER_FLAGS, '-oX', '-', cidr]
    return parse_discover_xml(_run(argv, timeout, register))


# --- naabu ----------------------------------------------------------------------------------------------------------

MAX_OPEN_PER_IP = 500  # an address with more "open" ports than this is a tarpit or a firewall that accepts everything


def parse_naabu_output(text):
    found = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        ip, port = row.get('ip') or row.get('host'), row.get('port')
        if ip and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            found.setdefault(str(ip), set()).add(port)
    return {ip: sorted(ports) for ip, ports in found.items() if len(ports) <= MAX_OPEN_PER_IP}


def run_naabu(addresses, timeout=900, register=None):
    addresses = validate_targets(addresses)
    path = _targets_file(addresses)
    try:
        argv = [NAABU_BIN, '-list', path, *NAABU_FLAGS]
        return {'ports': parse_naabu_output(_run(argv, timeout, register))}
    finally:
        os.unlink(path)


# --- nuclei -----------------------------------------------------------------------------------------------------------

def host_of(line):
    """Hostname or IP a nuclei result line names (``host`` may be a URL or host:port); mirrors
    ``cveFeed.nuclei_scan.host_of`` so a Sentinel-reported finding names the same host a local run would."""
    raw = (line.get('host') or line.get('ip') or '').strip()
    if '://' in raw:
        return (urlparse(raw).hostname or '').lower()
    if raw.count(':') == 1:
        return raw.rsplit(':', 1)[0].strip('[]').lower()
    return raw.strip('[]').lower()


def parse_nuclei_jsonl(text):
    findings = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get('info') or {}
        findings.append({'template_id': row.get('template-id') or '', 'name': info.get('name') or '',
                         'severity': info.get('severity') or 'unknown', 'host': host_of(row),
                         'matched_at': row.get('matched-at') or '', 'description': info.get('description') or '',
                         'matcher_name': row.get('matcher-name') or '',
                         'extracted_results': [v for v in (row.get('extracted-results') or []) if isinstance(v, str)],
                         'tags': [t for t in (info.get('tags') or []) if isinstance(t, str)]})
    return findings


def _clean_words(values, pattern):
    return sorted({v for v in (values or []) if isinstance(v, str) and pattern.match(v)})


def run_nuclei(targets, tags=None, severities=None, timeout=3600, register=None):
    targets = validate_targets(targets)
    path = _targets_file(targets)
    flags = list(NUCLEI_FLAGS)
    clean_tags = _clean_words(tags, _TAG)
    if clean_tags:
        flags += ['-tags', ','.join(clean_tags)]
    clean_severities = _clean_words(severities, _SEVERITY)
    if clean_severities:
        flags += ['-severity', ','.join(clean_severities)]
    try:
        argv = [NUCLEI_BIN, '-l', path, *flags]
        return {'findings': parse_nuclei_jsonl(_run(argv, timeout, register))}
    finally:
        os.unlink(path)


# --- testssl.sh: one host:port at a time, raw report items, server-side evaluate() reads them ------------------------

TESTSSL_BIN = os.environ.get('CVENGINE_TESTSSL_BIN', 'testssl.sh')
MAX_TESTSSL_OUTPUT = 8 * 1024 * 1024
# Same options cveFeed.testssl_scan.BASE_ARGS uses: protocols, cipher categories, server defaults and certificate,
# vulnerabilities, forward secrecy. --nodns none: the task already names a vetted ip, never resolved again here.
TESTSSL_FLAGS = ['--quiet', '--warnings', 'off', '--color', '0', '--nodns', 'none', '--connect-timeout', '15',
                 '--openssl-timeout', '15', '--overwrite', '-p', '-s', '-S', '-U', '-f']
_HOST_OR_IP = re.compile(r'^[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}$')


def _validate_host(value, what='host'):
    if not isinstance(value, str) or not value.strip() or len(value) > 260:
        raise TargetError(f'not a usable {what}: {value!r}')
    text = value.strip()
    if any(ch in _SHELL_META for ch in text) or '://' in text or not _HOST_OR_IP.match(text):
        raise TargetError(f'not a usable {what}: {value!r}')
    return text


def _validate_port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise TargetError(f'not a usable port: {value!r}')
    return value


def parse_testssl_report(raw):
    """The finding objects of a testssl.sh JSON report, flat (``--jsonfile``) or grouped (``--jsonfile-pretty``); mirrors
    ``cveFeed.testssl_scan.flatten``."""
    if isinstance(raw, dict):
        results = raw.get('scanResult') or []
        raw = [item for group in results if isinstance(group, dict) for value in group.values()
               if isinstance(value, list) for item in value]
    return [i for i in raw if isinstance(i, dict) and i.get('id')] if isinstance(raw, list) else []


def run_testssl(host, ip, port, starttls=None, timeout=900, register=None):
    """Run testssl.sh against ``host:port`` at the server-vetted ``ip`` and return ``{'items': [...]}``: the exact four
    fields (``id``, ``severity``, ``finding``, ``cve``) ``cveFeed.testssl_scan.evaluate`` reads, everything else
    testssl.sh's own report carries dropped before it ever leaves this process."""
    host, ip = _validate_host(host), _validate_host(ip, 'ip')
    port = _validate_port(port)
    destination = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    with tempfile.TemporaryDirectory(prefix='testssl-') as work:
        out = os.path.join(work, 'out.json')
        argv = [TESTSSL_BIN, *TESTSSL_FLAGS, '--ip', ip, '--jsonfile', out]
        if starttls:
            argv += ['--starttls', _validate_host(starttls, 'starttls')]
        argv.append(destination)
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': work, 'TERM': 'dumb', 'LC_ALL': 'C'}
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if register is not None:
            register(proc)
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return {'items': []}
        try:
            if os.path.getsize(out) > MAX_TESTSSL_OUTPUT:
                return {'items': []}
            with open(out, encoding='utf-8', errors='replace') as handle:
                report = json.load(handle)
        except (OSError, ValueError):
            return {'items': []}
    items = parse_testssl_report(report)[:300]
    return {'items': [{'id': str(i.get('id') or ''), 'severity': str(i.get('severity') or ''),
                       'finding': str(i.get('finding') or ''), 'cve': str(i.get('cve') or '')} for i in items]}


# --- nmap -sU: raw XML returned as-is; cveFeed.nmap_scan.parse_xml reads UDP's own state vocabulary --------------------

UDP_PORTS = (53, 67, 68, 69, 123, 137, 161, 500, 514, 623, 1194, 1812, 1813, 1900, 4500, 5060, 5353, 11211)
UDP_NSE_SCRIPTS = ('snmp-sysdescr', 'snmp-info', 'ntp-info', 'upnp-info', 'ipmi-version')


def run_nmap_udp(address, timeout=1500, register=None):
    """Run ``nmap -sU`` against one address with the same curated port list and low-rate options
    ``cveFeed.udp_scan.nmap_flags`` uses, and return its raw XML report text (never parsed here: UDP's
    ``open|filtered`` vocabulary and NSE script output are only read correctly by the server's own
    ``cveFeed.nmap_scan.parse_xml``, so the Sentinel never duplicates that logic)."""
    address = _validate_host(address, 'address')
    ports = ','.join(str(p) for p in UDP_PORTS)
    scripts = ','.join(('nbstat', *UDP_NSE_SCRIPTS))
    argv = [NMAP_BIN, *(['-6'] if _is_ipv6(address) else []), '-sU', '-sV', '--version-intensity', '3', '-Pn', '-n', '--max-retries', '1',
            '--max-rate', '20', '--script', scripts, '--script-timeout', '30s', '-p', f'U:{ports}', '-oX', '-', address]
    return {'xml': _run(argv, timeout, register)}


# --- wpscan: raw report, exit code and a trailing line of stderr; cveFeed.wpscan_scan._classify reads them server-side -

WPSCAN_BIN = os.environ.get('CVENGINE_WPSCAN_BIN', 'wpscan')
MAX_WPSCAN_OUTPUT = 8 * 1024 * 1024
_URL = re.compile(r'^https?://[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}(/.*)?$')
# Same options cveFeed.wpscan_scan.wpscan_args builds for a passive pass: mixed detection, no TLS verification (the
# target is whatever the server named, already vetted there), a bounded max-scan-duration so a slow site still
# reports what it found before the process would be killed.
WPSCAN_ARGS = ['--format', 'json', '--no-banner', '--random-user-agent', '--throttle', '0', '--request-timeout', '30',
               '--connect-timeout', '15', '--detection-mode', 'mixed', '--plugins-detection', 'passive',
               '--themes-detection', 'passive', '--disable-tls-checks', '--enumerate', 'vp,vt,cb,dbe,u1-5']


def run_wpscan(url, token='', timeout=900, register=None):
    """Run WPScan on one site and return its raw outcome: ``{'report', 'returncode', 'stderr_tail'}``, exactly what
    ``cveFeed.wpscan_scan._classify`` already reads from a local run - the one function, local or dispatched, that
    turns a wpscan process's outcome into a report or a classified failure. The API token travels in the environment,
    never a command line argument, and never logged."""
    if not isinstance(url, str) or not url.strip() or not _URL.match(url.strip()):
        raise TargetError(f'not a usable url: {url!r}')
    url = url.strip()
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'GEM_HOME', 'GEM_PATH',
                                      'BUNDLE_PATH', 'RUBYLIB', 'RUBYOPT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if k in os.environ}
    if token:
        env['WPSCAN_API_TOKEN'] = token
    with tempfile.TemporaryDirectory(prefix='wpscan-') as work:
        out = os.path.join(work, 'report.json')
        argv = [WPSCAN_BIN, '--url', url, *WPSCAN_ARGS, '--max-scan-duration', str(max(30, timeout - 30)), '-o', out]
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if register is not None:
            register(proc)
        try:
            _, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
        report = None
        if os.path.exists(out) and os.path.getsize(out) <= MAX_WPSCAN_OUTPUT:
            with open(out, encoding='utf-8', errors='replace') as handle:
                try:
                    report = json.load(handle)
                except ValueError:
                    report = None
        stderr_tail = (err or '').strip().splitlines()[-1] if err else ''
        return {'report': report, 'returncode': proc.returncode if proc.returncode is not None else 1,
                'stderr_tail': stderr_tail[:300]}


RUNNERS = {'nmap': run_nmap, 'naabu': run_naabu, 'nuclei_light': run_nuclei, 'nuclei_targeted': run_nuclei,
           'nuclei_deep': run_nuclei, 'testssl': run_testssl, 'nmap_udp': run_nmap_udp, 'wpscan': run_wpscan,
           'openvas': openvas.run_openvas, 'discover': run_discover}


# --- version probing, for the capabilities a bootstrapping Sentinel declares ------------------------------------------

VERSION_ARGS = {'nmap': [NMAP_BIN, '--version'], 'naabu': [NAABU_BIN, '-version'], 'nuclei': [NUCLEI_BIN, '-version'],
                'testssl': [TESTSSL_BIN, '--version'], 'wpscan': [WPSCAN_BIN, '--version']}


def gvm_available():
    """Whether ``python-gvm`` is importable and this Sentinel's own gvmd socket exists: what a bootstrapping Sentinel
    checks before declaring the ``openvas`` capability, never raising just because the GVM stack is not finished
    starting (the socket is created once gvmd is ready, which can take hours on a first start while the feed syncs)."""
    try:
        import gvm  # noqa: F401
    except ImportError:
        return False
    return os.path.exists(openvas.socket_path())


_GVM_STATUS = {'at': 0.0, 'value': (False, 'not checked yet')}
GVM_STATUS_TTL = 60  # seconds a readiness answer is reused: it is asked at every poll and heartbeat, and each check is a GMP login


def gvm_status(now=None):
    """``(ready, why_not)`` for this Sentinel's own GVM stack, cached for a minute. Not ready while the socket is missing, python-gvm is not installed,
    or gvmd has not finished loading what a scan needs (see ``client.openvas.readiness``)."""
    import time
    now = time.monotonic() if now is None else now
    if not gvm_available():
        return False, 'the GVM stack is not running here (no gvmd socket, or python-gvm is not installed)'
    if now - _GVM_STATUS['at'] < GVM_STATUS_TTL and _GVM_STATUS['value'][0] is not None:
        return _GVM_STATUS['value']
    _GVM_STATUS.update(at=now, value=openvas.readiness())
    return _GVM_STATUS['value']


def gvm_ready():
    """Whether this Sentinel can run an OpenVAS task now: what decides whether it declares the ``openvas`` capability."""
    return gvm_status()[0]


def detect_tools():
    """The tool names whose binary actually ran when probed with its own version flag, plus ``gvm`` once this
    Sentinel's own GVM stack is reachable: what a Sentinel declares in ``tools`` at bootstrap. Never raises; a
    missing or broken tool (or a GVM stack still syncing its feeds) is simply left out."""
    found = []
    for name, argv in VERSION_ARGS.items():
        try:
            subprocess.run(argv, capture_output=True, timeout=10, check=False)
            found.append(name)
        except (OSError, subprocess.TimeoutExpired):
            continue
    if gvm_available():
        found.append('gvm')
    return found
