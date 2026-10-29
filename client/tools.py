"""Run a scan tool (nmap, naabu, nuclei, testssl.sh, nmap UDP, WPScan, an nmap discover sweep) against a server-issued SentinelTask's own
typed target, and nothing else. (OpenVAS work runs over GMP, in ``client.openvas``.)

Every argv built here is a fixed list of flags plus the addresses or hosts the task named: there is no shell, no
string interpolation, and no text the server sent is ever read as a flag or a command. ``validate_targets`` is the one
gate every target list passes through before it reaches ``subprocess``; it is deliberately strict, because a
compromised or buggy server asking a Sentinel to run something other than a plain address, host name or host:port
must fail safe here. Syntax is not enough: every target is also judged by ``client.scope``, this Sentinel's own floor
(no loopback, metadata, link-local, own addresses, and no private space on an external Sentinel), whatever the server
decided. This mirrors, in reverse, the discipline ``agentapi``'s own header docstring states for what a Sentinel
reports back: nothing untrusted is ever built into, or interpreted as, a command, on either side of the wire.

Each run function returns the exact typed shape ``agentapi.sentinel_broker.clean_result`` expects for that task kind
(``{'hosts': [...]}`` for nmap, ``{'ports': {...}}`` for naabu, ``{'findings': [...]}`` for nuclei), ready to be sent
back under ``{'outcome': 'done', **result}``.
"""
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from . import config, openvas, scope

logger = logging.getLogger('sentinel.tools')

MAX_TARGETS = 64  # matches agentapi.sentinel_broker.MAX_ADDRESSES: a task never names more than this many
_SHELL_META = set(' \t\n\r;|&$`<>(){}\'"\\')
_PORT = re.compile(r'[0-9]{1,5}')
_BRACKETED = re.compile(r'\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})')

NMAP_BIN = os.environ.get('CVENGINE_NMAP_BIN', 'nmap')
NAABU_BIN = os.environ.get('CVENGINE_NAABU_BIN', 'naabu')
NUCLEI_BIN = os.environ.get('CVENGINE_NUCLEI_BIN', 'nuclei')

# -n: no reverse DNS. parse_nmap_xml never reads host names, and the targets are already resolved addresses.
NMAP_FLAGS = ['-Pn', '-n', '-sV', '--version-intensity', '5', '-O', '--osscan-limit', '-T4', '--open',
              '--top-ports', '1000', '--host-timeout', '8m', '--max-retries', '2']
NAABU_FLAGS = ['-p', '-', '-rate', '1000', '-retries', '2', '-c', '25', '-warm-up-time', '2', '-json', '-silent', '-nc']
# -omit-raw: no raw request/response pairs in the output (parse_nuclei_jsonl never reads them, and they are most of its size).
# -etags dos: the exclusion floor for every nuclei kind. Denial-of-service templates never run, whatever tags the server asks for.
NUCLEI_FLAGS = ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1', '-omit-raw',
                '-etags', 'dos']
_TAG = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
_SEVERITY = re.compile(r'info|low|medium|high|critical|unknown')

MAX_TOOL_OUTPUT = 64 * 1024 * 1024  # bytes of stdout kept from nmap, naabu or nuclei: more than this stops the run
_STDERR_KEPT = 4096
_CHUNK = 64 * 1024

# nmap runs up to MAX_TARGETS hosts with -sV -O and an 8 minute per-host timeout: the run's own cap grows with the host count.
NMAP_MIN_TIMEOUT, NMAP_SECONDS_PER_TARGET, NMAP_MAX_TIMEOUT = 600, 90, 3600


class TargetError(ValueError):
    """A SentinelTask's ``target`` did not have the shape a Sentinel will ever act on, or named something this Sentinel never scans.
    Always reported back as ``{'outcome': 'error', ...}``, never retried blindly, and the raw target is never passed to a shell."""


class ToolExitError(RuntimeError):
    """A tool exited with a non-zero status or was killed. Its output, if any, is incomplete, so the run is reported as an error, never as an
    empty result ("no open ports", "no findings")."""


class ToolOutputError(RuntimeError):
    """A tool wrote more output than this Sentinel holds in memory. The run was stopped; the task is reported as an error."""


# --- target validation ------------------------------------------------------------------------------------------------

def _resolver():
    """A resolver for one task that remembers each answer, so the addresses a name was judged by are the ones a tool is given."""
    answers = {}

    def resolve(name, port):
        if name not in answers:
            try:
                answers[name] = socket.getaddrinfo(name, port)
            except (OSError, UnicodeError) as exc:
                answers[name] = exc
        if isinstance(answers[name], Exception):
            raise answers[name]
        return answers[name]
    return resolve


def _refused(value, why):
    return TargetError(f'not a usable target: {str(value)[:100]!r} ({why})')


def _port_text(port, value):
    if not _PORT.fullmatch(port) or not 0 < int(port) < 65536:
        raise _refused(value, 'the port must be 1 to 65535')
    return str(int(port))


def _endpoint(text, resolve):
    """An http(s) URL, ``host``, ``host:port`` or ``[ipv6]:port``: what nuclei takes. The host part is judged by scope either way."""
    if '://' in text:
        if not text.lower().startswith(('http://', 'https://')):
            raise _refused(text, 'only http and https URLs')
        return scope.check_url(text, resolve=True, resolver=resolve)
    bracketed = _BRACKETED.fullmatch(text)
    if bracketed:
        return f'[{scope.check_ip(bracketed.group(1))}]:{_port_text(bracketed.group(2), text)}'
    if text.count(':') == 1:
        host, port = text.split(':')
        return f'{scope.check_target(host, resolve=True, resolver=resolve)}:{_port_text(port, text)}'
    return scope.check_target(text, resolve=True, resolver=resolve)


def _validate_one(value, endpoint, resolve):
    if not isinstance(value, str) or not value or len(value) > 260:
        raise _refused(value, 'not a string of a usable length')
    text = value.strip()
    if not text or any(ch in _SHELL_META or not ch.isprintable() for ch in text):
        raise _refused(value, 'empty, or it contains whitespace or shell characters')
    try:
        if endpoint:
            return _endpoint(text, resolve)
        if '://' in text:
            raise _refused(value, 'a bare address or host name, not a URL')
        return scope.check_target(text, resolve=True, resolver=resolve)  # a name that does not resolve is allowed: there is nothing to reach
    except scope.ScopeError as exc:
        raise _refused(value, str(exc)) from None


def validate_targets(values, limit=MAX_TARGETS, endpoint=False, resolver=None):
    """The task's own address/host list, defensively checked: a plain IP or a host name (``endpoint``: also ``host:port``,
    ``[ipv6]:port`` or an http(s) URL, what nuclei takes), nothing shell-meaningful, every host allowed by ``client.scope``,
    at most ``limit`` entries, duplicates dropped in order. Raises ``TargetError`` on anything else, rather than ever letting
    it reach an argv list. More than ``limit`` entries is refused outright, never truncated."""
    if not isinstance(values, list) or not values:
        raise TargetError('target has no usable addresses')
    if len(values) > limit:
        raise TargetError(f'target names {len(values)} entries; the most one task may name is {limit}')
    resolve = resolver or _resolver()
    out = []
    for value in values:
        clean = _validate_one(value, endpoint, resolve)
        if clean not in out:
            out.append(clean)
    return out


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _pinned(targets, resolve):
    """``targets`` with every host name replaced by the first IPv4 address it resolved to when it was judged (what nmap and naabu
    would pick themselves), so the tool never resolves the name again and a DNS answer that changes in between cannot reach an
    address scope refused. A name with no IPv4 address is dropped: the tool would have found nothing to scan for it either."""
    out = []
    for target in targets:
        address = target if _is_ip(target) else None
        if address is None:
            try:
                infos = resolve(target, None)
            except (OSError, UnicodeError):
                infos = []
            address = next((i[4][0] for i in infos if _is_ip(i[4][0]) and ipaddress.ip_address(i[4][0]).version == 4), None)
        if address is not None and address not in out:
            out.append(address)
    return out


def _targets_file(values):
    handle = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
    try:
        handle.write('\n'.join(values) + '\n')
    finally:
        handle.close()
    return handle.name


# --- running a tool ---------------------------------------------------------------------------------------------------

def _kill_group(proc):
    """Kill the tool and everything it started (testssl.sh's openssl and dig, nmap's NSE helpers): each tool runs in its own session."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


class _ProcessGroup:
    """What ``register`` hands the daemon for a running tool: ``poll()`` as on the ``Popen``, and a ``kill()`` that ends the whole
    process group, not only the direct child."""

    def __init__(self, proc):
        self.proc = proc

    def poll(self):
        return self.proc.poll()

    def kill(self):
        _kill_group(self.proc)


def _start(argv, register, **kwargs):
    proc = subprocess.Popen(argv, start_new_session=True, **kwargs)
    if register is not None:
        register(_ProcessGroup(proc))
    return proc


def _drain(stream, sink, cap, overflow=None):
    """Read ``stream`` to its end, keeping at most ``cap`` bytes in ``sink``; ``overflow`` is called once when more than that arrives."""
    over = False
    for chunk in iter(lambda: stream.read(_CHUNK), b''):
        room = cap - len(sink)
        sink.extend(chunk[:max(room, 0)])
        if len(chunk) > room and not over and overflow is not None:
            over = True
            overflow()
    stream.close()


def _join(proc, readers):
    for reader in readers:
        reader.join(10)
        if reader.is_alive():  # something the tool started still holds the pipe open
            _kill_group(proc)
            reader.join(5)


def _run(argv, timeout, register=None, max_bytes=None):
    """Run ``argv`` (a fixed list, never a string, never ``shell=True``) in its own session and return its stdout, at most
    ``max_bytes`` of it (``MAX_TOOL_OUTPUT`` by default): more stops the run and raises ``ToolOutputError``. ``register``, if given, is called with a handle
    (``poll()``, ``kill()``) right after it starts, so a caller (the daemon's SIGTERM handler) can stop the whole process
    group without waiting out the full timeout. A timeout kills the group and raises ``subprocess.TimeoutExpired``."""
    max_bytes = max_bytes or MAX_TOOL_OUTPUT
    proc = _start(argv, register, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err, too_big = bytearray(), bytearray(), threading.Event()

    def overflow():
        too_big.set()
        _kill_group(proc)
    readers = [threading.Thread(target=_drain, args=(proc.stdout, out, max_bytes, overflow), daemon=True),
               threading.Thread(target=_drain, args=(proc.stderr, err, _STDERR_KEPT), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.wait()
        _join(proc, readers)
        raise
    _join(proc, readers)
    if too_big.is_set():
        raise ToolOutputError(f'{os.path.basename(argv[0])} wrote more than {max_bytes} bytes of output; the run was stopped')
    if proc.returncode not in (0, None):
        # A crashed or killed tool leaves nothing, or something incomplete: returning that would read as "no open ports" or "no findings".
        tail = ''.join(ch for ch in err.decode('utf-8', errors='replace')[:300] if ch.isprintable() or ch == ' ').strip()
        logger.warning('%s exited %s: %s', os.path.basename(argv[0]), proc.returncode, tail)
        raise ToolExitError(f'{os.path.basename(argv[0])} exited with status {proc.returncode}' + (f': {tail[:200]}' if tail else ''))
    return out.decode('utf-8', errors='replace')


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


def nmap_timeout(count):
    """Seconds one nmap run over ``count`` hosts may take before it is killed."""
    return min(NMAP_MAX_TIMEOUT, max(NMAP_MIN_TIMEOUT, NMAP_SECONDS_PER_TARGET * count))


def run_nmap(addresses, timeout=None, register=None):
    """nmap scans one address family per run and needs ``-6`` for IPv6 (without it the address is "failed to resolve" and the report has no host),
    so the IPv4 and IPv6 addresses of the task run separately and their hosts are returned together. Host names are replaced by the address
    they were judged by (the result is keyed by IP either way). ``timeout`` defaults to one sized from the number of hosts."""
    resolve = _resolver()
    addresses = _pinned(validate_targets(addresses, resolver=resolve), resolve)
    out = []
    for group, flags in (([a for a in addresses if not _is_ipv6(a)], []), ([a for a in addresses if _is_ipv6(a)], ['-6'])):
        if not group:
            continue
        path = _targets_file(group)
        try:
            argv = [NMAP_BIN, *flags, *NMAP_FLAGS, '-oX', '-', '-iL', path]
            out.extend(parse_nmap_xml(_run(argv, timeout or nmap_timeout(len(group)), register))['hosts'])
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
    sweep as proof a host is absent). Only a Sentinel whose own configuration says it is internal sweeps anything, whatever the server set."""
    if not config._local_internal():
        raise TargetError('discover only runs on an internal Sentinel')
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
    """Host names are replaced by the address they were judged by: naabu's result is keyed by IP either way."""
    resolve = _resolver()
    addresses = _pinned(validate_targets(addresses, resolver=resolve), resolve)
    if not addresses:
        return {'ports': {}}
    path = _targets_file(addresses)
    try:
        argv = [NAABU_BIN, '-list', path, *NAABU_FLAGS]
        return {'ports': parse_naabu_output(_run(argv, timeout, register))}
    finally:
        os.unlink(path)


# --- nuclei -----------------------------------------------------------------------------------------------------------

MAX_FINDINGS = 5000
MAX_FINDINGS_BYTES = 20 * 1024 * 1024  # the server's result route takes 24 MB; the findings stay well under it
MAX_LIST_ITEMS = 20  # tags and extracted results kept per finding
_LIMITS = {'template_id': 200, 'name': 500, 'severity': 20, 'host': 255, 'matched_at': 500, 'description': 4000, 'matcher_name': 200,
           'extracted': 500, 'tag': 100}


def host_of(line):
    """Hostname or IP a nuclei result line names (``host`` may be a URL or host:port); mirrors
    ``cveFeed.nuclei_scan.host_of`` so a Sentinel-reported finding names the same host a local run would."""
    raw = next((v for v in (line.get('host'), line.get('ip')) if isinstance(v, str) and v), '').strip()
    try:
        if '://' in raw:
            return (urlparse(raw).hostname or '').lower()
    except ValueError:
        return ''
    if raw.count(':') == 1:
        return raw.rsplit(':', 1)[0].strip('[]').lower()
    return raw.strip('[]').lower()


def _clip(value, limit):
    return value[:limit] if isinstance(value, str) else ''


def _strings(value, limit, split=False):
    """A list of strings from a field that should be one: a lone string is one item (or, with ``split``, a comma list), anything else none."""
    if isinstance(value, str):
        value = [v.strip() for v in value.split(',')] if split else [value]
    if not isinstance(value, list):
        return []
    return [v[:limit] for v in value if isinstance(v, str) and v][:MAX_LIST_ITEMS]


def parse_nuclei_jsonl(text):
    """Findings from nuclei's JSONL output. A line that is not an object is skipped and a field of the wrong type is read as empty, so one
    odd line never fails the task; every field is clipped and at most ``MAX_FINDINGS`` are kept."""
    findings, size = [], 0
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
        if len(findings) >= MAX_FINDINGS:
            logger.warning('nuclei reported more than %s findings; the rest were dropped', MAX_FINDINGS)
            break
        info = row.get('info') if isinstance(row.get('info'), dict) else {}
        finding = {'template_id': _clip(row.get('template-id'), _LIMITS['template_id']),
                   'name': _clip(info.get('name'), _LIMITS['name']),
                   'severity': _clip(info.get('severity'), _LIMITS['severity']) or 'unknown',
                   'host': host_of(row)[:_LIMITS['host']],
                   'matched_at': _clip(row.get('matched-at'), _LIMITS['matched_at']),
                   'description': _clip(info.get('description'), _LIMITS['description']),
                   'matcher_name': _clip(row.get('matcher-name'), _LIMITS['matcher_name']),
                   'extracted_results': _strings(row.get('extracted-results'), _LIMITS['extracted']),
                   'tags': _strings(info.get('tags'), _LIMITS['tag'], split=True)}
        size += len(json.dumps(finding))
        if size > MAX_FINDINGS_BYTES:
            logger.warning('nuclei findings passed %s bytes; the rest were dropped so the result fits the server\'s limit', MAX_FINDINGS_BYTES)
            break
        findings.append(finding)
    return findings


def _clean_words(values, pattern):
    if not isinstance(values, list):
        return []
    return sorted({v for v in values if isinstance(v, str) and pattern.fullmatch(v)})


def run_nuclei(targets, tags=None, severities=None, timeout=3600, register=None):
    """Host names are passed to nuclei as names, because each finding reports the host it was given. They were judged by scope (and by
    every address they resolved to) just before; nuclei resolves them again, so a name whose DNS answer changes in between is the one gap."""
    targets = validate_targets(targets, endpoint=True)
    flags = list(NUCLEI_FLAGS)
    clean_tags = _clean_words(tags, _TAG)
    if tags and not clean_tags:  # a filter was asked for and none of it is usable: never fall back to every template
        raise TargetError('none of the nuclei tags this task names is usable')
    if clean_tags:
        flags += ['-tags', ','.join(clean_tags)]
    clean_severities = _clean_words(severities, _SEVERITY)
    if clean_severities:
        flags += ['-severity', ','.join(clean_severities)]
    path = _targets_file(targets)
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
_STARTTLS = re.compile(r'[a-z][a-z0-9-]{0,19}')


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
    testssl.sh's own report carries dropped before it ever leaves this process. ``ip`` must be one plain address scope
    allows; ``host`` (a name or an address, no port) is judged as written, since testssl.sh connects to ``ip`` and never
    resolves it. A run that times out raises ``subprocess.TimeoutExpired``: an empty report would read as "no TLS issues"."""
    try:
        ip = scope.check_ip(ip)
        host = scope.check_target(host, resolve=False)
    except scope.ScopeError as exc:
        raise TargetError(f'not a usable testssl target: {str(host)[:100]!r} at {str(ip)[:50]!r} ({exc})') from None
    port = _validate_port(port)
    destination = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
    with tempfile.TemporaryDirectory(prefix='testssl-') as work:
        out = os.path.join(work, 'out.json')
        argv = [TESTSSL_BIN, *TESTSSL_FLAGS, '--ip', ip, '--jsonfile', out]
        if starttls:
            if not isinstance(starttls, str) or not _STARTTLS.fullmatch(starttls):
                raise TargetError(f'not a usable starttls: {str(starttls)[:30]!r}')
            argv += ['--starttls', starttls]
        argv.append(destination)
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': work, 'TERM': 'dumb', 'LC_ALL': 'C'}
        proc = _start(argv, register, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.communicate()
            raise
        try:
            if os.path.getsize(out) > MAX_TESTSSL_OUTPUT:
                raise ToolOutputError('testssl wrote a report over the size limit')  # an empty answer would read as "no TLS issues"
            with open(out, encoding='utf-8', errors='replace') as handle:
                report = json.load(handle)
        except (OSError, ValueError):
            raise ToolOutputError('testssl wrote no readable report') from None
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
    ``cveFeed.nmap_scan.parse_xml``, so the Sentinel never duplicates that logic). A host name stays a name, because
    the raw report carries it; it was judged by scope with every address it resolved to just before nmap resolves it
    again, so a DNS answer that changes in between is the one gap."""
    address = validate_targets([address], limit=1)[0]
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
    ``cveFeed.wpscan_scan._classify`` already reads from a local run: the one function, local or dispatched, that
    turns a wpscan process's outcome into a report or a classified failure. The API token travels in the environment,
    never a command line argument, and never logged. The URL's host is judged by scope (with every address it resolves
    to); WPScan resolves it again, so a DNS answer that changes in between is the one gap."""
    if not isinstance(url, str) or not url.strip() or not _URL.match(url.strip()) or any(not ch.isprintable() for ch in url.strip()):
        raise TargetError(f'not a usable url: {str(url)[:100]!r}')
    url = url.strip()
    try:
        scope.check_url(url, resolver=_resolver())
    except scope.ScopeError as exc:
        raise TargetError(f'not a usable url: {url[:100]!r} ({exc})') from None
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'GEM_HOME', 'GEM_PATH',
                                      'BUNDLE_PATH', 'RUBYLIB', 'RUBYOPT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if k in os.environ}
    if token:
        env['WPSCAN_API_TOKEN'] = token
    with tempfile.TemporaryDirectory(prefix='wpscan-') as work:
        out = os.path.join(work, 'report.json')
        argv = [WPSCAN_BIN, '--url', url, *WPSCAN_ARGS, '--max-scan-duration', str(max(30, timeout - 30)), '-o', out]
        proc = _start(argv, register, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            _, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
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
    """Whether ``python-gvm`` is importable and this Sentinel's own gvmd socket exists: what ``detect_tools`` reports as ``gvm``
    and the first thing ``gvm_status`` checks, never raising just because the GVM stack is not finished starting (the socket is
    created once gvmd is ready, which can take hours on a first start while the feed syncs). Whether the ``openvas`` capability
    is declared is ``gvm_ready``'s answer, not this one."""
    try:
        import gvm  # noqa: F401
    except ImportError:
        return False
    return os.path.exists(openvas.socket_path())


# Each readiness check is a GMP login and is asked at every poll and heartbeat, so the answer is reused: for a minute while
# the stack is not ready (so it is noticed soon once it is), for five once it is. The lock lets one thread check at a time;
# the others get the cached answer meanwhile.
_GVM_STATUS = {'at': None, 'value': (False, 'not checked yet')}
_GVM_LOCK = threading.Lock()
GVM_STATUS_TTL = 60
GVM_READY_TTL = 300


def gvm_status(now=None):
    """``(ready, why_not)`` for this Sentinel's own GVM stack, cached. Not ready while the socket is missing, python-gvm is not installed,
    or gvmd has not finished loading what a scan needs (see ``client.openvas.readiness``). Never raises."""
    if not gvm_available():
        return False, 'the GVM stack is not running here (no gvmd socket, or python-gvm is not installed)'
    if not _GVM_LOCK.acquire(blocking=False):
        return _GVM_STATUS['value']
    try:
        now = time.monotonic() if now is None else now
        at, value = _GVM_STATUS['at'], _GVM_STATUS['value']
        if at is not None and now - at < (GVM_READY_TTL if value[0] else GVM_STATUS_TTL):
            return value
        try:
            value = openvas.readiness()
        except Exception as exc:  # noqa: BLE001 - a readiness check must never take the poll or heartbeat thread down
            value = (False, f'could not check the GVM stack ({type(exc).__name__})')
        _GVM_STATUS.update(at=now, value=value)
        return value
    finally:
        _GVM_LOCK.release()


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
