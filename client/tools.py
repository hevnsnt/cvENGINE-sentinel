"""Run a scan tool (nmap, naabu, nuclei, testssl.sh, nmap UDP, WPScan, wafw00f, an nmap discover sweep) against a server-issued SentinelTask's own
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
import platform
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time

from cvengine_scanner.flags import (DISCOVER_FLAGS, KERNEL_MARKERS, MAX_DISCOVER_ADDRESSES, MAX_DISCOVER_HOSTS, MAX_OPEN_PER_IP,  # noqa: F401
                                    MAX_PATH_TARGETS, MAX_TARGETS, MAX_TEMPLATE_BYTES, MAX_VERIFY_PORTS, NAABU_FLAGS, NMAP_FLAGS, NMAP_FULL_FLAGS,
                                    NMAP_VERIFY_FLAGS, NSE_SCRIPT_TIMEOUT, NSE_SCRIPTS, NUCLEI_FIXTURE_FLAGS, NUCLEI_FLAGS, NUCLEI_TEMPLATE_FLAGS,
                                    NUCLEI_VALIDATE_FLAGS, PATH_PROBE_ODD, PATH_PROBE_PLAIN, TESTSSL_FLAGS, UDP_NSE_SCRIPTS, UDP_PORTS, WAFW00F_TIMEOUT,
                                    WPSCAN_ARGS, host_of, udp_nmap_flags, wafw00f_flags)
from cvengine_scanner.parsers import (MAX_FINDINGS, MAX_FINDINGS_BYTES, MAX_LIST_ITEMS, ToolOutputError, parse_discover_xml,  # noqa: F401
                                      parse_naabu_output, parse_nmap_xml, parse_nuclei_jsonl, parse_port_reasons, parse_testssl_report,
                                      parse_waf_output)

from . import bbot, config, dbprobe, egress, openvas, rdp, scope

logger = logging.getLogger('sentinel.tools')

_SHELL_META = set(' \t\n\r;|&$`<>(){}\'"\\')
_PORT = re.compile(r'[0-9]{1,5}')
_BRACKETED = re.compile(r'\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})')

NMAP_BIN = os.environ.get('CVENGINE_NMAP_BIN', 'nmap')
NAABU_BIN = os.environ.get('CVENGINE_NAABU_BIN', 'naabu')
NUCLEI_BIN = os.environ.get('CVENGINE_NUCLEI_BIN', 'nuclei')

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


def _proxy_args(tool, hosts):
    """The arguments that send ``tool`` through cvENGINE's egress proxy (a built-in scanner only, ``client.egress``), or ``TargetError`` when the proxy
    is on and none of its proxies suits the tool: the run never goes out directly then."""
    try:
        return egress.for_tool(tool, hosts)
    except egress.ProxyUnavailable as exc:
        raise TargetError(str(exc)) from None


class ToolExitError(RuntimeError):
    """A tool exited with a non-zero status or was killed. Its output, if any, is incomplete, so the run is reported as an error, never as an
    empty result ("no open ports", "no findings")."""


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


def _run(argv, timeout, register=None, max_bytes=None, env=None, ok_codes=(0,)):
    """Run ``argv`` (a fixed list, never a string, never ``shell=True``) in its own session and return its stdout, at most
    ``max_bytes`` of it (``MAX_TOOL_OUTPUT`` by default): more stops the run and raises ``ToolOutputError``. ``register``, if given, is called with a handle
    (``poll()``, ``kill()``) right after it starts, so a caller (the daemon's SIGTERM handler) can stop the whole process
    group without waiting out the full timeout. A timeout kills the group and raises ``subprocess.TimeoutExpired``. ``env`` replaces the
    environment of the run (Kingfisher's detection pass points every proxy at a closed port); ``ok_codes`` are the exit codes that are not a
    failure (Kingfisher says "findings" with 200 and 205)."""
    max_bytes = max_bytes or MAX_TOOL_OUTPUT
    proc = _start(argv, register, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **({'env': env} if env is not None else {}))
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
    if proc.returncode not in (*ok_codes, None):
        # A crashed or killed tool leaves nothing, or something incomplete: returning that would read as "no open ports" or "no findings".
        tail = ''.join(ch for ch in err.decode('utf-8', errors='replace')[:300] if ch.isprintable() or ch == ' ').strip()
        logger.warning('%s exited %s: %s', os.path.basename(argv[0]), proc.returncode, tail)
        raise ToolExitError(f'{os.path.basename(argv[0])} exited with status {proc.returncode}' + (f': {tail[:200]}' if tail else ''))
    return out.decode('utf-8', errors='replace')


# --- nmap -----------------------------------------------------------------------------------------------------------

def _is_ipv6(address):
    try:
        return ipaddress.ip_address(str(address).strip().strip('[]')).version == 6
    except ValueError:
        return False


def os_guess_reliable():
    """False when the kernel release says this container runs inside Docker Desktop, WSL2 or OrbStack; the server then keeps the packet-based OS
    guess out of the host's record. Anything else (a Linux host, host networking) is reliable."""
    release = platform.release().lower()
    return not any(marker in release for marker in KERNEL_MARKERS)


def _same_address(a, b):
    try:
        return ipaddress.ip_address(str(a).strip().strip('[]')) == ipaddress.ip_address(str(b).strip().strip('[]'))
    except ValueError:
        return str(a).strip() == str(b).strip()


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
            out.extend(parse_nmap_xml(_run(argv, timeout or nmap_timeout(len(group)), register), strict=True)['hosts'])
        finally:
            os.unlink(path)
    # A row for every requested address: the server reads a missing row as "this Sentinel did not cover it" (an external scan falls back to a
    # local one, an internal scan fails), and an address that answered nothing is a host with no open ports.
    for address in addresses:
        if not any(_same_address(address, row['ip']) for row in out):
            out.append({'ip': str(address).strip().strip('[]'), 'os_guess': '', 'ports': []})
    return {'hosts': out, 'os_reliable': os_guess_reliable()}


# --- discover: which addresses of an internal network answer -------------------------------------------------------

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

def _clean_words(values, pattern):
    if not isinstance(values, list):
        return []
    return sorted({v for v in values if isinstance(v, str) and pattern.fullmatch(v)})


def run_nuclei(targets, tags=None, severities=None, timeout=3600, register=None, templates=None, secret_file=None):
    """Host names are passed to nuclei as names, because each finding reports the host it was given. They were judged by scope (and by
    every address they resolved to) just before; nuclei resolves them again, so a name whose DNS answer changes in between is the one gap.
    ``templates`` is a directory of approved templates (the server's verified bundle, ``client.templates``): nuclei then runs exactly that set and
    nothing else; without it nuclei uses the templates baked into this image. ``secret_file`` is a signed-in run's nuclei secrets file
    (``client.signed_in``): passed with ``-sf`` and ``-dr`` (no redirects, so the sign-in is never carried to wherever one leads), as the server does."""
    targets = validate_targets(targets, endpoint=True)
    flags = list(NUCLEI_FLAGS) + _proxy_args('nuclei', targets)
    if secret_file is not None:
        if not isinstance(secret_file, str) or not os.path.isabs(secret_file) or not os.path.isfile(secret_file):
            raise TargetError('the signed-in run has no usable secrets file')
        flags += ['-sf', secret_file, '-dr']
    if templates is not None:
        if not isinstance(templates, str) or not os.path.isabs(templates) or not os.path.isdir(templates):
            raise TargetError('the approved template directory is not usable')
        flags += ['-t', templates]
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
_STARTTLS = re.compile(r'[a-z][a-z0-9-]{0,19}')


def _validate_port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise TargetError(f'not a usable port: {value!r}')
    return value


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
        argv = [TESTSSL_BIN, *TESTSSL_FLAGS, *_proxy_args('testssl', [host]), '--ip', ip, '--jsonfile', out]
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


# --- nmap -sU: raw XML returned as-is; the server reads it with cvengine_scanner.nmap.parse_xml -------------------------


def run_nmap_udp(address, timeout=1500, register=None):
    """Run ``nmap -sU`` against one address with the curated port list and low-rate options of ``cvengine_scanner.flags.udp_nmap_flags`` (the
    server's local sweep builds its flags with the same function), and return its raw XML report text. The contract carries the raw report for
    this kind: the server reads UDP's ``open|filtered`` vocabulary and the NSE script output with ``cvengine_scanner.nmap.parse_xml``. A host
    name stays a name, because the raw report carries it; it was judged by scope with every address it resolved to just before nmap resolves it
    again, so a DNS answer that changes in between is the one gap."""
    address = validate_targets([address], limit=1)[0]
    argv = [NMAP_BIN, *(['-6'] if _is_ipv6(address) else []), *udp_nmap_flags(), '-oX', '-', address]
    return {'xml': _run(argv, timeout, register)}


# --- wpscan: raw report, exit code and a trailing line of stderr; cveFeed.wpscan_scan._classify reads them server-side -

WPSCAN_BIN = os.environ.get('CVENGINE_WPSCAN_BIN', 'wpscan')
MAX_WPSCAN_OUTPUT = 8 * 1024 * 1024
_URL = re.compile(r'^https?://[A-Za-z0-9][A-Za-z0-9.:_-]{0,252}(/.*)?$')


def _failure_line(stderr, stdout, token=''):
    """The one line that says why WPScan failed: the last non-empty line of stderr, else of stdout (WPScan prints ``Scan Aborted: ...`` on
    stdout), clipped to 300 characters with the API token replaced by ``***``. Never more than that line: stdout can be large and can echo the URL."""
    for stream in (stderr, stdout):
        lines = [line.strip() for line in (stream or '').splitlines() if line.strip()]
        if lines:
            line = lines[-1]
            return (line.replace(token, '***') if token else line)[:300]
    return ''


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
        argv = [WPSCAN_BIN, '--url', url, *WPSCAN_ARGS, *_proxy_args('wpscan', [url]), '--max-scan-duration', str(max(30, timeout - 30)), '-o', out]
        proc = _start(argv, register, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            out_text, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            out_text, err = proc.communicate()
        report = None
        if os.path.exists(out) and os.path.getsize(out) <= MAX_WPSCAN_OUTPUT:
            with open(out, encoding='utf-8', errors='replace') as handle:
                try:
                    report = json.load(handle)
                except ValueError:
                    report = None
        return {'report': report, 'returncode': proc.returncode if proc.returncode is not None else 1,
                'stderr_tail': _failure_line(err, out_text, token)}


# --- wafw00f: which web application firewall answers for one site ------------------------------------------------------

WAFW00F_BIN = os.environ.get('CVENGINE_WAFW00F_BIN', 'wafw00f')
MAX_WAF_OUTPUT = 200_000  # characters of the report read: a handful of products fits in a few hundred, so more is not a report


def run_waf(host, ip, port, scheme, timeout=WAFW00F_TIMEOUT, register=None):
    """Run wafw00f at the root of ``scheme://host:port/`` and return ``{'products': [{'name', 'manufacturer'?}], 'generic': bool}``, the ``waf`` result of
    the contract: a product name and no version or confidence, since wafw00f gives none. ``ip`` (the address the server vetted) must be one plain address
    scope allows and ``host`` (a name or an address) is judged with every address it resolves to; wafw00f takes a URL and resolves the name again, so a
    DNS answer that changes in between is the one gap. A site that never answers is an error, never "no WAF"."""
    port = _validate_port(port)
    if scheme not in ('http', 'https'):
        raise TargetError(f'not a usable scheme: {str(scheme)[:20]!r}')
    try:
        ip = scope.check_ip(ip)
        host = scope.check_target(host, resolve=True, resolver=_resolver())
    except scope.ScopeError as exc:
        raise TargetError(f'not a usable waf target: {str(host)[:100]!r} at {str(ip)[:50]!r} ({exc})') from None
    netloc = f'[{host}]' if ':' in host else host
    if port != (443 if scheme == 'https' else 80):
        netloc += f':{port}'
    with tempfile.TemporaryDirectory(prefix='wafw00f-') as work:
        out = os.path.join(work, 'out.json')
        _run([WAFW00F_BIN, *wafw00f_flags(timeout), *_proxy_args('wafw00f', [host]), '-o', out, f'{scheme}://{netloc}/'], timeout, register)
        try:
            with open(out, encoding='utf-8', errors='replace') as handle:
                report = handle.read(MAX_WAF_OUTPUT)
        except OSError:
            raise ToolOutputError('wafw00f wrote no report') from None
    return parse_waf_output(report, strict=True)


def run_http_probe(target, register=None):
    """The ``http_probe`` kind: the version and identity probes cvENGINE planned, in this process (``cvengine_scanner.probes.version_probes``), under
    the scope policy the task carries; no tool is started, so ``register`` is unused."""
    from cvengine_scanner.probes import version_probes
    try:
        return version_probes.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable http_probe task ({exc})') from None


def run_bucket_check(target, register=None):
    """The ``bucket_check`` kind: anonymous checks of cloud storage buckets at the platforms' documented endpoints (``cvengine_scanner.probes.buckets``)."""
    from cvengine_scanner.probes import buckets
    try:
        return buckets.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable bucket_check task ({exc})') from None


def run_vhost_probe(target, register=None):
    """The ``vhost_probe`` kind: the other sites an address serves for the names cvENGINE already knows (``cvengine_scanner.probes.vhost``)."""
    from cvengine_scanner.probes import vhost
    try:
        return vhost.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable vhost_probe task ({exc})') from None


def run_subdir_probe(target, register=None):
    """The ``subdir_probe`` kind: the applications mounted under well-known subdirectories of a web host (``cvengine_scanner.probes.subdir``)."""
    from cvengine_scanner.probes import subdir
    try:
        return subdir.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable subdir_probe task ({exc})') from None


def run_route_probe(target, register=None):
    """The ``route_probe`` kind: how a host's web routes answer an anonymous GET, and the sensitive data and front page libraries they show
    (``cvengine_scanner.probes.routes``), under the scope policy the task carries."""
    from cvengine_scanner.probes import routes
    try:
        return routes.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable route_probe task ({exc})') from None


def run_supplier_check(target, register=None):
    """The ``supplier_check`` kind: passive posture checks of a third-party supplier's public names (``cvengine_scanner.probes.suppliers``)."""
    from cvengine_scanner.probes import suppliers
    try:
        return suppliers.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable supplier_check task ({exc})') from None


def run_hygiene_check(target, register=None):
    """The ``hygiene_check`` kind: the TLS certificates of a target's endpoints and the email authentication review of its mail names, read from this
    Sentinel's own vantage point (``cvengine_scanner.probes.hygiene``)."""
    from cvengine_scanner.probes import hygiene
    try:
        return hygiene.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable hygiene_check task ({exc})') from None


def run_dangling_dns_check(target, register=None):
    """The ``dangling_dns_check`` kind: the lookups that rate bbot's baddns findings by what an outsider can claim (``cvengine_scanner.probes.dangling_dns``)."""
    from cvengine_scanner.probes import dangling_dns
    try:
        return dangling_dns.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable dangling_dns_check task ({exc})') from None


def run_identity_check(target, register=None):
    """The ``identity_check`` kind: the CNAME, NS, MX and PTR reads and the certificate names cvENGINE used to read from its own server, answered by
    this Sentinel's own resolver and connection (``cvengine_scanner.probes.identity``)."""
    from cvengine_scanner.probes import identity
    try:
        return identity.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable identity_check task ({exc})') from None


def run_web_screenshot(target, register=None):
    """The ``web_screenshot`` kind: a headless Chromium photographs the pages of the task through a vetting proxy, after proving its own sandbox
    engaged (``client.shot``); the PNGs go back as base64 and cvENGINE checks, stores and reads them. A browser that cannot prove the sandbox opens
    nothing and says so in the result."""
    from . import shot
    try:
        return shot.run(target, register=register)
    except ValueError as exc:
        raise TargetError(f'not a usable web_screenshot task ({exc})') from None
    except shot.Unavailable as exc:
        raise ToolOutputError(str(exc)) from None


def run_dns_resolve(target, register=None):
    """The ``dns_resolve`` kind: this Sentinel's resolver answers for the names of the task (``cvengine_scanner.probes.dns``)."""
    from cvengine_scanner.probes import dns
    try:
        return dns.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable dns_resolve task ({exc})') from None


# --- nmap_full and nmap_verify: one address, the raw report read by the server's own parser -----------------------------------------------

MAX_NMAP_REPORT = 4 * 1024 * 1024  # agentapi.sentinel_broker.MAX_NMAP_UDP_XML: the server refuses a larger report


def _one_address(value):
    try:
        return scope.check_ip(value)
    except scope.ScopeError as exc:
        raise TargetError(f'not a usable address: {str(value)[:60]!r} ({exc})') from None


def _finished(xml):
    """``xml`` when it is a finished nmap report, else ``ToolOutputError``: a cut-off sweep must never read as "nothing open"."""
    parse_nmap_xml(xml, strict=True)
    return xml


def run_nmap_full(address, timeout=1500, register=None):
    """Every TCP port of one address, open ports only (the server's background full sweep), as the raw ``-oX`` report: the server reads it with the
    same parser as a local sweep and keeps only the address it asked about."""
    address = _one_address(address)
    argv = [NMAP_BIN, *(['-6'] if _is_ipv6(address) else []), *NMAP_FULL_FLAGS, '-oX', '-', address]
    return {'xml': _finished(_run(argv, timeout, register, max_bytes=MAX_NMAP_REPORT))}


def run_nmap_verify(address, ports, version_all=False, version_intensity=None, scripts=None, host_timeout=None, timeout=280, register=None):
    """Service detection on the named ports of one address, at full intensity (``version_all``) or the named one, with NSE scripts from the reviewed
    list only (``NSE_SCRIPTS``: a name not on it is refused, never run). Returns the raw ``-oX`` report."""
    address = _one_address(address)
    if not isinstance(ports, list) or not ports or len(ports) > MAX_VERIFY_PORTS:
        raise TargetError(f'nmap_verify names 1 to {MAX_VERIFY_PORTS} ports')
    numbers = sorted({_validate_port(p) for p in ports})
    flags = list(NMAP_VERIFY_FLAGS)
    if version_all is True:
        flags.append('--version-all')
    elif version_intensity is not None:
        if isinstance(version_intensity, bool) or not isinstance(version_intensity, int) or not 0 <= version_intensity <= 9:
            raise TargetError('version_intensity must be 0 to 9')
        flags += ['--version-intensity', str(version_intensity)]
    names = scripts or []
    if not isinstance(names, list) or any(n not in NSE_SCRIPTS for n in names):
        raise TargetError('nmap_verify names a script that is not on the reviewed list')
    if names:
        flags += ['--script', ','.join(sorted(set(names))), '--script-timeout', NSE_SCRIPT_TIMEOUT]
    seconds = 90
    if host_timeout is not None:
        if isinstance(host_timeout, bool) or not isinstance(host_timeout, int) or not 10 <= host_timeout <= 600:
            raise TargetError('host_timeout must be 10 to 600 seconds')
        seconds = host_timeout
    argv = [NMAP_BIN, *(['-6'] if _is_ipv6(address) else []), *flags, '--host-timeout', f'{seconds}s', '-p', ','.join(map(str, numbers)),
            '-oX', '-', address]
    return {'xml': _finished(_run(argv, max(timeout, seconds + 30), register, max_bytes=MAX_NMAP_REPORT))}


# --- node2shell: the vendored detector (client/vendor/node2shell.py, as on the server) -----------------------------------------------------

NODE2SHELL_TIMEOUT = 90  # cveFeed.node2shell_scan.DEFAULT_TIMEOUT
NODE2SHELL_EVIDENCE = 2048


def _checked_url(url):
    if not isinstance(url, str) or not url.strip() or not _URL.match(url.strip()) or any(not ch.isprintable() for ch in url.strip()):
        raise TargetError(f'not a usable url: {str(url)[:100]!r}')
    url = url.strip()
    try:
        scope.check_url(url, resolver=_resolver())
    except scope.ScopeError as exc:
        raise TargetError(f'not a usable url: {url[:100]!r} ({exc})') from None
    return url


def run_node2shell(url, timeout=NODE2SHELL_TIMEOUT, register=None):
    """Assetnote's read-only detector on one URL: about 23 MB is uploaded, nothing is executed and no credential is sent. Returns its verdict (``vulnerable``
    True, False or None for inconclusive), reason, status code and a bounded excerpt of the response. The URL's host is judged by scope; the detector
    resolves it again, so a DNS answer that changes in between is the one gap."""
    url = _checked_url(url)
    from .vendor import node2shell
    try:
        result = node2shell.check_vulnerability(url, timeout=timeout, verify_ssl=True)
    except Exception as exc:  # noqa: BLE001 - the detector folds its own errors into INCONCLUSIVE; anything else the same way here
        result = {'vulnerable': None, 'verdict': 'ERROR', 'reason': str(exc)[:200]}
    vulnerable = result.get('vulnerable')
    status = result.get('status_code')
    return {'vulnerable': vulnerable if vulnerable in (True, False) else None, 'verdict': str(result.get('verdict') or '')[:40],
            'reason': str(result.get('reason') or '')[:300],
            'status_code': status if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599 else None,
            'evidence': str(result.get('response') or '')[:NODE2SHELL_EVIDENCE]}


# --- rdp_shot: the pre-authentication screen, as a PNG; the reading of it stays on the server ----------------------------------------------

def run_rdp_shot(address, port, register=None):
    """One screenshot of an RDP server's pre-authentication screen, no credentials sent. A server that cannot be reached or paints nothing returns
    ``painted`` False, which the server records exactly as a local capture that failed."""
    address = _one_address(address)
    port = _validate_port(port)
    if not rdp.available():
        raise TargetError('this Sentinel has no RDP client (aardwolf is not installed)')
    try:
        png = rdp.capture(address, port)
    except Exception as exc:  # noqa: BLE001 - refused, reset, NLA required, timed out: nothing was painted
        logger.info('rdp capture of %s:%s failed: %s', address, port, type(exc).__name__)
        png = None
    if not png:
        return {'painted': False}
    if len(png) > rdp.MAX_IMAGE_BYTES:
        raise ToolOutputError('the capture is larger than the server accepts')
    import base64
    return {'painted': True, 'image': base64.b64encode(png).decode('ascii')}


# --- db_probe: one credential-less attempt -------------------------------------------------------------------------------------------------

def run_db_probe(address, port, db, register=None):
    """One credential-less connection attempt to the database on ``address:port`` (``client.dbprobe``). ``open`` None: no client for it here."""
    address = _one_address(address)
    port = _validate_port(port)
    if db not in dbprobe.CHECKS:
        raise TargetError(f'not a database this Sentinel probes: {str(db)[:20]!r}')
    return dbprobe.probe(address, port, db)


# --- path_probe: whether this Sentinel's own path loses a malformed segment --------------------------------------------------------------

def _reset_back(ip, port, flags, register):
    xml = _run([NMAP_BIN, *flags, '-p', str(port), '-oX', '-', ip], 30, register, max_bytes=256 * 1024)
    return parse_port_reasons(xml).get((ip, port), ('', ''))[1] == 'reset'


def run_path_probe(targets, register=None, pause=0.2):
    """For each address and closed port: did a plain SYN draw a reset, and did nmap's FIN+PSH+URG probe (sent only where the SYN was answered)?
    The server turns the rows into its verdict on this path (``cveFeed.path_probe.verdict``). An address nmap could not probe is left out: it is not
    evidence either way. IPv4 only, as on the server."""
    if not isinstance(targets, list) or not targets or len(targets) > MAX_PATH_TARGETS:
        raise TargetError(f'path_probe names 1 to {MAX_PATH_TARGETS} targets')
    clean = []
    for item in targets:
        if not isinstance(item, dict):
            raise TargetError('a path_probe target is an object with ip and port')
        ip = _one_address(item.get('ip'))
        if _is_ipv6(ip):
            raise TargetError('path_probe takes IPv4 addresses only')
        clean.append((ip, _validate_port(item.get('port'))))
    rows = []
    for ip, port in clean:
        try:
            plain = _reset_back(ip, port, PATH_PROBE_PLAIN, register)
            odd = _reset_back(ip, port, PATH_PROBE_ODD, register) if plain else None
        except (ToolExitError, ToolOutputError, subprocess.TimeoutExpired) as exc:
            logger.info('path probe: %s not probed: %s', ip, exc)
            continue
        rows.append({'ip': ip, 'port': port, 'plain': plain, 'odd': odd})
        time.sleep(pause)
    return {'results': rows}


# --- nuclei_validate: an AI-written or approved template, as cveFeed.templategen runs it ---------------------------------------------------

NUCLEI_VALIDATE_TIMEOUT = 60
NUCLEI_TEMPLATE_TIMEOUT = 540
# Top-level template keys this Sentinel never runs, whatever the server sent: they read local files, run local code or drive a browser. nuclei
# itself also needs -file, -code or -headless for them, which are never passed.
_REFUSED_PROTOCOLS = re.compile(r'^(code|file|headless|javascript|flow|workflows|self-contained)\s*:', re.MULTILINE)


def _template_text(text):
    if not isinstance(text, str) or not text.strip() or len(text.encode('utf-8', 'replace')) > MAX_TEMPLATE_BYTES or '\0' in text:
        raise TargetError(f'the template must be text of at most {MAX_TEMPLATE_BYTES} bytes')
    if _REFUSED_PROTOCOLS.search(text):
        raise TargetError('the template uses a protocol this Sentinel never runs (code, file, headless, javascript, flow or a workflow)')
    return text


def _run_status(argv, timeout, register):
    """``(returncode, stdout, stderr)`` of a run whose non-zero exit is an answer (nuclei -validate), each stream bounded."""
    proc = _start(argv, register, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        proc.communicate()
        raise
    return proc.returncode, out[-MAX_TOOL_OUTPUT:].decode('utf-8', 'replace'), err[-_STDERR_KEPT:].decode('utf-8', 'replace')


def is_hit(row):
    """Whether a nuclei result line is a matcher hit (cveFeed.templategen.is_hit): a matcher fired, not only an extractor."""
    if row.get('matcher-status') is False:
        return False
    return bool(row.get('matcher-name') or row.get('matcher-status') is True)


def _benign_fixture(path, register):
    """The template must not match a loopback page that only says "not found" (cveFeed.templategen.test_benign_fixture): ``(ok, note)``."""
    import http.server

    class Benign(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'CVEngine benign fixture: resource not found')

        do_HEAD = do_GET
        do_OPTIONS = do_GET

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Benign)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        code, out, _err = _run_status([NUCLEI_BIN, '-t', path, '-u', f'http://127.0.0.1:{server.server_port}', *NUCLEI_FIXTURE_FLAGS], 30, register)
        if code != 0:
            return False, 'local fixture execution failed'
        for line in out.splitlines():
            if line.strip():
                try:
                    row = json.loads(line)
                except ValueError:
                    return False, 'local fixture returned malformed output'
                if isinstance(row, dict) and is_hit(row):
                    return False, 'matched a benign local fixture (possible false positive)'
        return True, 'no match on benign local fixture; positive detection remains unverified'
    except (OSError, subprocess.TimeoutExpired):
        return False, 'local fixture test unavailable or timed out'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _host_key(value):
    """The bare lowercase host of a host or URL (cveFeed.templategen._host_key), to pair a result line with the host that was asked about."""
    value = str(value or '').strip().lower()
    value = value.split('://', 1)[-1].split('/', 1)[0]
    if value.startswith('['):
        return value.split(']', 1)[0].lstrip('[')
    return value.rsplit(':', 1)[0] if value.count(':') == 1 else value


def _trim_hit(row):
    return {k: (v[:8000] if isinstance(v, str) and k in ('request', 'response', 'curl-command') else v) for k, v in row.items()} if row else None


def _template_test(path, hosts, register):
    """One outcome per host, in order (cveFeed.templategen._run_template's shape). A host scope refuses is not tested, never run."""
    allowed, refused = [], {}
    resolve = _resolver()
    for host in hosts:
        try:
            _validate_one(host, True, resolve)
            allowed.append(host)
        except TargetError as exc:
            refused[host] = str(exc)[:300]
    rows, hits, error = {}, {}, ''
    if allowed:
        proxy = _proxy_args('nuclei', allowed)  # cvENGINE's egress proxy, as the server's own template test (cveFeed.templategen._run_template) takes it
        host_path = _targets_file(allowed)
        try:
            code, out, err = _run_status([NUCLEI_BIN, '-t', path, '-l', host_path, *NUCLEI_TEMPLATE_FLAGS, *proxy], NUCLEI_TEMPLATE_TIMEOUT, register)
        finally:
            os.unlink(host_path)
        if code != 0:
            error = (err or f'nuclei exited with status {code}').strip()[-300:]
        for line in out.splitlines() if not error else []:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                error = 'nuclei returned malformed JSON output'
                break
            if not isinstance(row, dict):
                error = 'nuclei returned malformed JSON output'
                break
            if is_hit(row):
                key = _host_key(row.get('host') or row.get('matched-at') or row.get('ip'))
                hits.setdefault(key, []).append(line)
                rows.setdefault(key, row)
    outcomes = []
    for host in hosts:
        if host in refused:
            outcomes.append({'host': host, 'vulnerable': False, 'output': '', 'error': refused[host]})
        elif error:
            outcomes.append({'host': host, 'vulnerable': False, 'output': '', 'error': error})
        else:
            key = _host_key(host)
            outcomes.append({'host': host, 'vulnerable': bool(hits.get(key)), 'output': '\n'.join(hits.get(key, []))[-2000:],
                             'hit': _trim_hit(rows.get(key))})
    return outcomes


def run_nuclei_validate(mode, template, targets=None, register=None):
    """Mode ``validate``: ``nuclei -validate`` on a new template and, when it passes, the benign loopback fixture. Mode ``test``: the approved template
    against ``targets`` (each judged by scope, as every nuclei target is), one outcome per target. The template is written to a private scratch
    directory and nothing else is loaded with it."""
    text = _template_text(template)
    with tempfile.TemporaryDirectory(prefix='nuclei-validate-') as work:
        path = os.path.join(work, 'template.yaml')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
        if mode == 'validate':
            code, out, err = _run_status([NUCLEI_BIN, *NUCLEI_VALIDATE_FLAGS[:1], '-t', path, *NUCLEI_VALIDATE_FLAGS[1:]], NUCLEI_VALIDATE_TIMEOUT,
                                         register)
            output = (out + err).strip()
            valid = code == 0 and 'error' not in output.lower()
            result = {'valid': valid, 'output': output[-2000:], 'fixture_ok': None, 'fixture_note': ''}
            if valid:
                result['fixture_ok'], result['fixture_note'] = _benign_fixture(path, register)
            return result
        if mode == 'test':
            if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS or not all(isinstance(t, str) for t in targets):
                raise TargetError(f'a template test names 1 to {MAX_TARGETS} targets')
            return {'outcomes': _template_test(path, targets, register)}
    raise TargetError(f'not a nuclei_validate mode: {str(mode)[:20]!r}')


def run_alive_check(target, register=None):
    """The ``alive_check`` kind: whether a retired name's last known addresses still answer (``cvengine_scanner.probes.alive``)."""
    from cvengine_scanner.probes import alive
    try:
        return alive.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable alive_check task ({exc})') from None


RUNNERS = {'nmap': run_nmap, 'naabu': run_naabu, 'nuclei_light': run_nuclei, 'nuclei_targeted': run_nuclei,
           'nuclei_deep': run_nuclei, 'testssl': run_testssl, 'nmap_udp': run_nmap_udp, 'wpscan': run_wpscan,
           'openvas': openvas.run_openvas, 'discover': run_discover, 'waf': run_waf, 'http_probe': run_http_probe, 'dns_resolve': run_dns_resolve,
           'bbot_discovery': bbot.run_bbot_discovery,  # streamed: the daemon passes it its client and task id (client/bbot.py)
           'nmap_full': run_nmap_full, 'nmap_verify': run_nmap_verify, 'node2shell': run_node2shell, 'rdp_shot': run_rdp_shot,
           'db_probe': run_db_probe, 'path_probe': run_path_probe, 'nuclei_validate': run_nuclei_validate,
           'alive_check': run_alive_check,
           'bucket_check': run_bucket_check, 'vhost_probe': run_vhost_probe, 'subdir_probe': run_subdir_probe,
           'route_probe': run_route_probe,
           'supplier_check': run_supplier_check,
           'hygiene_check': run_hygiene_check, 'dangling_dns_check': run_dangling_dns_check,
           'identity_check': run_identity_check, 'web_screenshot': run_web_screenshot}


def run_secrets_scan(target, register=None, rules=None):
    """The ``secrets_scan`` kind (``client.secrets_scan``): imported here so ``RUNNERS`` names every kind's entry point in one place."""
    from client import secrets_scan
    return secrets_scan.run(target, register=register, rules=rules)


RUNNERS['secrets_scan'] = run_secrets_scan
KINGFISHER_BIN = os.environ.get('CVENGINE_KINGFISHER_BIN', 'kingfisher')


def kingfisher_ready():
    """Whether the Kingfisher binary is here: the image carries it; a Sentinel run from a source checkout may not, and then it does not declare
    ``secrets_scan``."""
    import shutil
    return shutil.which(KINGFISHER_BIN) is not None


# --- version probing, for the capabilities a bootstrapping Sentinel declares ------------------------------------------

VERSION_ARGS = {'nmap': [NMAP_BIN, '--version'], 'naabu': [NAABU_BIN, '-version'], 'nuclei': [NUCLEI_BIN, '-version'],
                'testssl': [TESTSSL_BIN, '--version'], 'wpscan': [WPSCAN_BIN, '--version'], 'wafw00f': [WAFW00F_BIN, '--version'],
                'kingfisher': [KINGFISHER_BIN, '--version'],
                'bbot': [bbot.BBOT_BIN, '--version']}


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
