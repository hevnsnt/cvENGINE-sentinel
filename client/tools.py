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
import math
import os
import platform
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

from cvengine_scanner import flags, nuclei_allowlist
from cvengine_scanner.flags import (DISCOVER_FLAGS, KERNEL_MARKERS, MAX_DISCOVER_ADDRESSES, MAX_DISCOVER_HOSTS, MAX_OPEN_PER_IP,  # noqa: F401
                                    MAX_PATH_TARGETS, MAX_TARGETS, MAX_TEMPLATE_BYTES, MAX_VERIFY_PORTS, NAABU_FLAGS, NMAP_FULL_FLAGS, TASK_LIMITS,
                                    nmap_pass_flags, task_seconds,
                                    NMAP_VERIFY_FLAGS, NSE_SCRIPT_TIMEOUT, NSE_SCRIPTS, NUCLEI_FIXTURE_FLAGS, NUCLEI_FLAGS, NUCLEI_TEMPLATE_FLAGS,
                                    NUCLEI_VALIDATE_FLAGS, PATH_PROBE_ODD, PATH_PROBE_PLAIN, TESTSSL_FLAGS, UDP_NSE_SCRIPTS, UDP_PORTS, WAFW00F_TIMEOUT,
                                    WPSCAN_ARGS, WPSCAN_THOROUGH_ARGS, host_of, thorough_timeout, udp_nmap_flags, wafw00f_flags)
from cvengine_scanner.parsers import (MAX_FINDINGS, MAX_FINDINGS_BYTES, MAX_LIST_ITEMS, ToolOutputError, parse_discover_xml,  # noqa: F401
                                      parse_naabu_output, parse_nmap_xml, parse_nuclei_errors, parse_nuclei_jsonl, parse_port_reasons, parse_testssl_report,
                                      testssl_result, unreached_targets,
                                      parse_waf_output)

from . import admission, bbot, config, dbprobe, egress, openvas, rdp, scope

logger = logging.getLogger('sentinel.tools')

_SHELL_META = set(' \t\n\r;|&$`<>(){}\'"\\')
_PORT = re.compile(r'[0-9]{1,5}')
_BRACKETED = re.compile(r'\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})')

NMAP_BIN = os.environ.get('CVENGINE_NMAP_BIN', 'nmap')
NAABU_BIN = os.environ.get('CVENGINE_NAABU_BIN', 'naabu')
NUCLEI_BIN = os.environ.get('CVENGINE_NUCLEI_BIN', 'nuclei')
# The release of the nuclei templates baked into this image (the Dockerfile sets it): reported with every run that used them.
IMAGE_TEMPLATES_VERSION = (os.environ.get('CVENGINE_NUCLEI_TEMPLATES_VERSION') or 'unknown')[:40]

_TAG = re.compile(r'[a-z0-9][a-z0-9-]{0,39}')
_SEVERITY = re.compile(r'info|low|medium|high|critical|unknown')

MAX_ERROR_LOG_BYTES = 8 * 1024 * 1024  # bytes of a nuclei error log read: more is a runaway log, the rest is not needed to tell reached from not
MAX_TOOL_OUTPUT = 64 * 1024 * 1024  # bytes of stdout kept from nmap, naabu or nuclei: more than this stops the run
_STDERR_KEPT = 4096
_CHUNK = 64 * 1024

# The time a nmap or naabu run may take comes from cvengine_scanner.flags.task_seconds, the function the server reads too (review M7).
NMAP_MIN_TIMEOUT = TASK_LIMITS['nmap'][0]


class TargetError(ValueError):
    """A SentinelTask's ``target`` did not have the shape a Sentinel will ever act on, or named something this Sentinel never scans.
    Always reported back as ``{'outcome': 'error', ...}``, never retried blindly, and the raw target is never passed to a shell."""


class Refused(TargetError):
    """The target is inside a range this Sentinel never touches (the operator's deny list, ``scope.Denied``): refused here before anything connected. It
    is reported as an error whose text starts ``refused:`` (the contract has no other outcome), so the server can tell a refusal from a failure."""


def _scope_failure(message, exc):
    """``TargetError(message)``, or ``Refused`` when ``exc`` is a deny-list refusal."""
    if isinstance(exc, scope.Denied):
        return Refused(f'refused: {message}')
    return TargetError(message)


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


class ToolOOMError(ToolExitError):
    """A tool was killed by the system (SIGKILL nobody here sent): almost always the kernel's out-of-memory killer in this container's memory cgroup. It
    says so in plain words, so the operator reads a capacity problem and the server leaves the work due to be run again, instead of a bare ``-9``."""

    OOM_TEXT = 'out of memory, retry later'


def _oom_events():
    """The number of out-of-memory kills this container's memory cgroup has had (``memory.events``), or None when it cannot say."""
    try:
        with open('/sys/fs/cgroup/memory.events', encoding='ascii') as handle:
            for line in handle:
                if line.startswith('oom_kill '):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


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


def _refused(value, why, exc=None):
    return _scope_failure(f'not a usable target: {str(value)[:100]!r} ({why})', exc)


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
        raise _refused(value, str(exc), exc) from None


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

    def terminate(self):
        """SIGTERM to the whole group: a polite stop; ``kill()`` is the SIGKILL that follows when it is ignored."""
        self.proc.stopped_by_sentinel = True
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except OSError:
            pass

    def kill(self):
        self.proc.stopped_by_sentinel = True  # a -9 after this was the daemon's own stop, not the kernel's out-of-memory killer
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


def _run(argv, timeout, register=None, max_bytes=None, env=None, ok_codes=(0,), cut=None):
    """Run ``argv`` (a fixed list, never a string, never ``shell=True``) in its own session and return its stdout, at most
    ``max_bytes`` of it (``MAX_TOOL_OUTPUT`` by default): more stops the run and raises ``ToolOutputError``. ``register``, if given, is called with a handle
    (``poll()``, ``kill()``) right after it starts, so a caller (the daemon's SIGTERM handler) can stop the whole process
    group without waiting out the full timeout. A timeout kills the group and raises ``subprocess.TimeoutExpired``. ``env`` replaces the
    environment of the run (Kingfisher's detection pass points every proxy at a closed port); ``ok_codes`` are the exit codes that are not a
    failure (Kingfisher says "findings" with 200 and 205). ``cut``, a list, makes an oversized output a result instead of an error: the run is
    still stopped, ``True`` is appended to it and what was read so far is returned (the nmap_full sweep, ``run_nmap_full``)."""
    max_bytes = max_bytes or MAX_TOOL_OUTPUT
    oom_before = _oom_events()
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
    except subprocess.TimeoutExpired as exc:
        _kill_group(proc)
        proc.wait()
        _join(proc, readers)
        exc.partial = out.decode('utf-8', errors='replace')  # what it printed before it was stopped: a naabu run keeps what it found
        raise
    _join(proc, readers)
    if too_big.is_set():
        if cut is None:
            raise ToolOutputError(f'{os.path.basename(argv[0])} wrote more than {max_bytes} bytes of output; the run was stopped')
        cut.append(True)
        return out.decode('utf-8', errors='replace')
    if proc.returncode not in (*ok_codes, None):
        # A crashed or killed tool leaves nothing, or something incomplete: returning that would read as "no open ports" or "no findings".
        err_text = err.decode('utf-8', errors='replace')
        # nuclei opens every run with a warning about its JSON library on this CPU; left in, it took the whole 200 characters of every failure message and hid the
        # error itself (on the VPS each "no templates" failure read "...fallback to encoding/json[FTL] Could not run nuclei: no templ")
        said = '\n'.join(line for line in err_text.splitlines() if not _NOISE_LINE.search(line))
        tail = ''.join(ch for ch in said[:300] if ch.isprintable() or ch == ' ').strip()
        logger.warning('%s exited %s: %s', os.path.basename(argv[0]), proc.returncode, tail)
        if proc.returncode in (-9, 137) and not getattr(proc, 'stopped_by_sentinel', False):  # not this daemon's own stop (a timeout and an oversized output are handled above)
            oom_after = _oom_events()
            counted = None if oom_before is None or oom_after is None else oom_after - oom_before
            if counted is None or counted > 0:  # the container's memory cgroup counted a kill during the run, or cannot say (cgroup v1): it was memory
                logger.error('%s was killed by the system%s: out of memory in this container', os.path.basename(argv[0]),
                             '' if counted is None else f' (the cgroup counted {counted} out-of-memory kills during the run)')
                raise ToolOOMError(f'{ToolOOMError.OOM_TEXT} ({os.path.basename(argv[0])} was killed by the system)')
        failure = ToolExitError(f'{os.path.basename(argv[0])} exited with status {proc.returncode}' + (f': {tail[:200]}' if tail else ''))
        failure.partial = out.decode('utf-8', errors='replace')  # what it printed before it was stopped: the watchdog delivers a stopped nuclei run's findings
        failure.stderr = err_text  # what it said, whole (the message keeps 200 characters): a caller reads why it stopped
        raise failure
    return out.decode('utf-8', errors='replace')


_NOISE_LINE = re.compile(r'WARNING: sonic/ast only supports')


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


def nmap_timeout(count):
    """Seconds one nmap run over ``count`` hosts may take before it is killed."""
    return task_seconds('nmap', count)


def run_nmap(addresses, timeout=None, register=None, ports=None):
    """nmap scans one address family per run and needs ``-6`` for IPv6 (without it the address is "failed to resolve" and the report has no host),
    so the IPv4 and IPv6 addresses of the task run separately and their hosts are returned together. Host names are replaced by the address
    they were judged by (the result is keyed by IP either way). ``timeout`` defaults to one sized from the number of hosts. ``ports`` (the
    task's, from the naabu result) are the ports the fingerprint pass scans; without them it scans the top thousand (``flags.nmap_pass_flags``)."""
    try:
        pass_flags = nmap_pass_flags(ports)
    except ValueError as exc:
        raise TargetError(str(exc)) from None
    resolve = _resolver()
    addresses = _pinned(validate_targets(addresses, resolver=resolve), resolve)
    out = []
    for group, flags in (([a for a in addresses if not _is_ipv6(a)], []), ([a for a in addresses if _is_ipv6(a)], ['-6'])):
        if not group:
            continue
        path = _targets_file(group)
        try:
            argv = [NMAP_BIN, *flags, *pass_flags, '-oX', '-', '-iL', path]
            out.extend(parse_nmap_xml(_run(argv, timeout or nmap_timeout(len(group)), register), strict=True)['hosts'])
        finally:
            os.unlink(path)
    # nmap lists every host it scanned, with -Pn, whether or not any port is open. An address it does not list was not scanned, and gets no
    # row: the server reads a missing row as "this Sentinel did not cover it" (review H3: a padded row read as a clean host).
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
    try:
        scope.check_network(net)  # a sweep that touches any part of a denied range is refused whole
    except scope.Denied as exc:
        raise _scope_failure(f'discover target {str(net)!r} ({exc})', exc) from None
    return str(net)


def run_discover(cidr, timeout=900, register=None):
    """A host-alive sweep of one chunk of an internal network: ARP on the local segment, ICMP and a few TCP/UDP probes elsewhere. Reports
    only which addresses answered; a firewall that drops every probe makes a host invisible here, and the server says so (it never reads a
    sweep as proof a host is absent). Only a Sentinel whose own configuration says it is internal sweeps anything, whatever the server set."""
    if not config._local_internal():
        raise TargetError('discover only runs on an internal Sentinel')
    cidr = validate_cidr(cidr)
    argv = [NMAP_BIN, *DISCOVER_FLAGS, '-oX', '-', cidr]
    return parse_discover_xml(_run(argv, timeout, register), strict=True)


# --- naabu ----------------------------------------------------------------------------------------------------------

def run_naabu(addresses, timeout=None, register=None):
    """Host names are replaced by the address they were judged by: naabu's result is keyed by IP either way. A run that runs out of time is not
    an error (review H5: a whole chunk was lost and its addresses stayed due for ever): it returns the ports read so far with ``incomplete``
    and ``unfinished``. naabu says nothing about a host it finished, so every address of such a run is unfinished and stays due."""
    resolve = _resolver()
    addresses = _pinned(validate_targets(addresses, resolver=resolve), resolve)
    if not addresses:
        return {'ports': {}}
    seconds = timeout or task_seconds('naabu', len(addresses))
    path = _targets_file(addresses)
    try:
        argv = [NAABU_BIN, '-list', path, *NAABU_FLAGS]
        try:
            return {'ports': parse_naabu_output(_run(argv, seconds, register))}
        except subprocess.TimeoutExpired as exc:
            logger.warning('naabu ran out of its %s s for %d address(es); they stay due', seconds, len(addresses))
            return {'ports': parse_naabu_output(getattr(exc, 'partial', '')), 'incomplete': True, 'unfinished': addresses}
    finally:
        os.unlink(path)


# --- nuclei -----------------------------------------------------------------------------------------------------------

def _clean_words(values, pattern):
    if not isinstance(values, list):
        return []
    return sorted({v for v in values if isinstance(v, str) and pattern.fullmatch(v)})


def nuclei_flags_for_budget(flags, budget=None):
    """``flags`` with -c and -rl lowered to what this container's memory budget (``client.admission``) can carry; never raised above the flags' own values."""
    conc, rate = admission.scaled_nuclei(admission.budget_mb() if budget is None else budget)
    out = list(flags)
    for flag, cap in (('-c', conc), ('-rl', rate)):
        if flag in out and out.index(flag) + 1 < len(out):
            i = out.index(flag) + 1
            out[i] = str(min(int(out[i]), cap))
    return out


def nuclei_env():
    """The environment of a nuclei run: this one, plus a soft Go memory limit so one run stays near ``admission.WEIGHTS_MB['nuclei_deep']`` (measured 500 MB
    with it, 720-735 MB without)."""
    env = dict(os.environ)
    env.setdefault('GOMEMLIMIT', f'{admission.NUCLEI_GOMEMLIMIT_MB}MiB')
    return env


_NO_TEMPLATES = re.compile(r'no templates? (?:were )?(?:provided|found|loaded)', re.I)


def _target_port(target):
    """The port a nuclei target names (``host:port`` or ``[ipv6]:port``), or ``None`` for a bare host, an address or a URL."""
    if '://' in target:
        return None
    bracketed = _BRACKETED.fullmatch(target)
    if bracketed:
        return int(bracketed.group(2))
    if target.count(':') == 1:
        return int(target.rsplit(':', 1)[1])
    return None


def _service_labels(services):
    """The server's labels of a task's ``host:port`` targets, keyed by ``flags.nuclei_label_key`` (the same spelling the validated targets get);
    anything that is not a ``host:port`` and a text is no label."""
    if not isinstance(services, dict):
        return {}
    out = {}
    for key, value in services.items():
        spelled = flags.nuclei_label_key(key) if isinstance(key, str) else None
        if spelled and isinstance(value, str):
            out[spelled] = value
    return out


def _split_by_service(targets, services):
    """``(web, service_runs)``: the targets that are web (a bare host, an address, a URL, a port the server labelled web or one whose number is a
    well-known web port) and each other ``host:port`` with its class. A ``host:port`` the task does not label is read by its number, and a number in
    no table is the unknown class (the generic network templates): never web, so a lookup that misses can never send HTTP to a service. A label this
    library does not know is the unknown class too (``flags.nuclei_service_class``)."""
    labels = _service_labels(services)
    web, runs = [], []
    for target in targets:
        key = flags.nuclei_label_key(target)
        klass = flags.NUCLEI_WEB if key is None else flags.nuclei_service_class(key[1], labels.get(key))
        if klass == flags.NUCLEI_WEB:
            web.append(target)
        else:
            runs.append((target, klass))
    return web, runs


# The listing of the templates one service class runs (``nuclei -tl``: no network, about two seconds for the whole library), made once per template set,
# class, tags and severities and kept: a bundle is a fixed directory named by its sha256 and the baked set changes only with the image.
_TEMPLATE_LISTINGS = {}
_LISTING_KEPT = 64
_THREADS = re.compile(r'(?m)^[ \t]+(?:-[ \t]+)?threads:[ \t]*([0-9]+)')
_MAX_REQUEST = re.compile(r'(?m)^[ \t]+(?:-[ \t]+)?max-request:[ \t]*([0-9]+)')
_LISTED_FROM = re.compile(r'templates for (\S+)')
_clock = time.monotonic  # the clocks of the service passes: a test replaces them
_sleep = time.sleep


# Default deny: a service run sends only a template on the pinned allowlist (``cvengine_scanner/nuclei_allowlist.py``, made by scripts/generate_service_allowlist.py)
# whose file still has the sha256 the list records. The content rule below is the second line: it is applied to every allowlisted template that is not one a person
# read and restored (``reviewed_exceptions``), and it is one of the checks the generator makes.
# What a service run may never send: credentials. Nothing that sends one, guesses a password or can lock an account runs unless a project turns it on,
# and no such switch exists for nuclei, so it never runs. The tags (``default-login``, ``bruteforce``) are the template authors' word and miss most of them
# (``pgsql-default-db`` is tagged enum; ``mysql-empty-password`` vuln), so the template is read: a ``payloads`` block, a call that logs in, a command that
# authenticates, or an authentication step in bytes (a PostgreSQL startup naming a user, a SCRAM message). Measured on nuclei-templates v10.5.1 in docs/SENTINELS.md.
_PAYLOADS = re.compile(r'(?m)^[ \t]*(?:-[ \t]+)?(?:payloads|attack):')
# the calls of nuclei's javascript clients that open a session with an account (mysql, postgres, mssql, oracle, ldap, smb ListShares, vnc password), not the
# info-mode connects (``ConnectSSHInfoMode``, ``ConnectSMBInfoMode``) that read what a server offers and send no credential
_LOGIN_CALL = re.compile(r'\.(?:Connect|ConnectWithDB|ExecuteQuery|ExecuteQueryWithOpts|ListShares|Authenticate|Login|Bind|BindWithDN|SimpleBind)\(')
_CREDENTIAL_NAME = re.compile(r'(?im)^[ \t]*(?:-[ \t]+)?(?:user|username|pass|passwd|password)[ \t]*:|\{\{[ \t]*(?:user|username|pass|passwd|password)[ \t]*\}\}')
_AUTH_COMMAND = re.compile(r'(?i)(?:data|input)s?:[ \t]*["\']?(?:[A-Za-z0-9]{1,8} )?(?:USER|PASS|AUTH|AUTHENTICATE|LOGIN)\b')
_DATA_VALUE = re.compile(r'(?im)^[ \t]*(?:-[ \t]+)?data:[ \t]*["\']?([0-9a-f]{8,})["\']?[ \t]*(?:#.*)?$')
_AUTH_BYTES = re.compile(rb'\x00user\x00|SCRAM-SHA|(?i:(?:^|\s)(?:USER|PASS|AUTH|LOGIN)\s)')
_AUTH_ESCAPED = re.compile(r'\\u0000user\\u0000')


def _login_step(text):
    """Whether a template's text performs a login or an authentication step (see the note above)."""
    if _LOGIN_CALL.search(text) or _CREDENTIAL_NAME.search(text) or _AUTH_COMMAND.search(text) or _AUTH_ESCAPED.search(text):
        return True
    for value in _DATA_VALUE.findall(text):
        try:
            if _AUTH_BYTES.search(bytes.fromhex(value if len(value) % 2 == 0 else value[:-1])):
                return True
        except ValueError:
            continue
    return False


def _paced_template(path):
    """Whether a template is one a service run may send, else the reason it is not: it carries ``payloads`` (guessed values, mostly accounts), it logs in or
    authenticates (``_login_step``), it sets no parallelism of its own (a template's ``threads`` overrides nuclei's ``-pc``, so ten attempts run at once)
    and it does not declare more than ``flags.NUCLEI_SERVICE_MAX_REQUESTS`` requests (``max-request``)."""
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            text = handle.read(256 * 1024)
    except OSError:
        return 'the template file cannot be read'
    if _PAYLOADS.search(text):
        return 'the template carries payloads (guessed values, mostly accounts)'
    if _login_step(text):
        return 'the template performs a login or an authentication step (a service run never sends credentials)'
    if any(int(n) > 1 for n in _THREADS.findall(text)):
        return 'the template sets its own parallelism'
    if any(int(n) > flags.NUCLEI_SERVICE_MAX_REQUESTS for n in _MAX_REQUEST.findall(text)):
        return 'the template sends more requests than a service may receive'
    return None


def _service_templates(selection, templates, extra, register, timeout=120):
    """The template files a service class runs, from nuclei's own listing of the set (``templates``: the approved bundle directory, else the baked
    set) with the filters of ``selection`` and the task's severities in ``extra``: only a template on the service-port allowlist whose file has the recorded
    sha256 (default deny: one the list does not know, or that the library changed, is not run), and that still passes the content rule unless a person read and
    restored it. Cached per set. An empty list means nothing of this set may run for this class: nothing is started for it."""
    severities = tuple(extra[extra.index('-severity') + 1].split(',')) if '-severity' in extra else ()
    key = (templates or f'image:{IMAGE_TEMPLATES_VERSION}', tuple(selection['types']), tuple(selection['tags']), tuple(selection['etags']), severities)
    if key in _TEMPLATE_LISTINGS:
        return _TEMPLATE_LISTINGS[key]
    argv = [NUCLEI_BIN, *flags.nuclei_service_listing_flags(selection)] + (['-t', templates] if templates else []) + (['-severity', ','.join(severities)] if severities else [])
    output = _run(argv, max(1, math.ceil(timeout)), register, env=nuclei_env())
    base = templates or None
    paths = []
    for line in output.splitlines():
        line = line.strip()
        header = _LISTED_FROM.search(line) if line.startswith('Listing') else None
        if header and base is None:
            base = header.group(1)
        elif line.endswith('.yaml'):
            paths.append(line)
    base = base or os.path.join(os.path.expanduser('~'), 'nuclei-templates')
    allowlist = nuclei_allowlist.load_allowlist()
    files, skipped, unlisted = [], 0, 0
    for rel in paths:
        path = rel if os.path.isabs(rel) else os.path.join(base, rel)
        allowed, _why, tid = nuclei_allowlist.check_file(path, allowlist)
        if not allowed:
            unlisted += 1
        elif tid not in allowlist['reviewed_exceptions'] and _paced_template(path) is not None:
            skipped += 1
        else:
            files.append(path)
    if skipped or unlisted:
        logger.info('nuclei: of %d templates listed for this service %d are not on the service-port allowlist (or their file changed) and %d fail the content rule; %d run', len(paths), unlisted, skipped, len(files))
    if len(_TEMPLATE_LISTINGS) >= _LISTING_KEPT:
        _TEMPLATE_LISTINGS.clear()
    _TEMPLATE_LISTINGS[key] = files
    return files


def _allowed_on_port(path, port):
    """Whether a listed template may be sent to a target on ``port``: it is on the allowlist with the recorded sha256 now, and when it names a port of its own
    (``fixed_ports``: a literal port in its host or address) the target is on that port, so it never reaches a port the task did not name."""
    allowlist = nuclei_allowlist.load_allowlist()
    allowed, _why, tid = nuclei_allowlist.check_file(path, allowlist)
    if not allowed:
        return False
    fixed = allowlist['templates'][tid].get('fixed_ports') or ()
    return not fixed or port in fixed


def _run_service_port(target, klass, tags, budget, deadline, extra, templates, register, secret_file, listing_failed=None, spent=0.0):
    """One non-web ``host:port`` of class ``klass``: its template files, each as its own nuclei process, one at a time, with ``budget['pause_ms']`` between
    one run ending and the next starting, and ``budget['seconds']`` for the port (and never past ``deadline``). One connection is in flight at a time and a
    new template starts no sooner than the pause, which is the bound on what the port receives (see ``flags.NUCLEI_SERVICE_BUDGET``). The third run in a row
    that gets no answer at all ends the port: nothing is listening, and it is not asked again. A run that fails does not end the port, and a port whose every
    run failed is reported as not checked, with the reason.
    Returns ``{'findings', 'unreachable', 'incomplete', 'no_templates', 'reason'}``; ``reason`` is why the port was not fully checked, else ``None``."""
    selection = flags.nuclei_service_selection(klass, tags)
    out = {'findings': [], 'unreachable': False, 'incomplete': False, 'no_templates': False, 'reason': None}
    if selection is None:
        out['no_templates'] = True  # the task asked for nothing that speaks this protocol
        return out
    failed_before = listing_failed.get(klass) if listing_failed is not None else None
    if failed_before:
        out['unreachable'], out['incomplete'], out['reason'] = True, True, failed_before
        return out
    try:
        files = _service_templates(selection, templates, extra, register, max(1, min(120, deadline - _clock())))
    except (ToolExitError, subprocess.TimeoutExpired, OSError) as exc:  # the listing is the one step before the runs: its failure never costs the task its other findings
        out['unreachable'] = out['incomplete'] = True
        out['reason'] = f'the template listing failed ({str(exc)[:120]})'
        logger.warning('nuclei: the template listing for %s failed: %s', klass, str(exc)[:200])
        if listing_failed is not None:
            listing_failed[klass] = out['reason']
        return out
    port = (flags.nuclei_label_key(target) or (None, None))[1]
    files = [path for path in files if _allowed_on_port(path, port)]
    if not files:
        out['no_templates'] = True  # nothing of this set may run for this class on this port: no process is started
        return out
    argv = nuclei_flags_for_budget(flags.nuclei_service_flags(selection, budget)) + extra
    port_deadline = min(deadline, _clock() + budget['seconds'] - spent)  # what the banner probe took is part of the port's budget
    pause = flags.nuclei_service_pause_ms(klass, budget) / 1000.0
    reached = failed = quiet = silent = changed = 0
    last_error = None
    for index, path in enumerate(files):
        left = port_deadline - _clock()
        if left <= 0:
            out['incomplete'], out['reason'] = True, f'its time ran out after {index} of {len(files)} templates'
            break
        with tempfile.TemporaryDirectory(prefix='nuclei-svc-') as private:  # mode 0700: only the Sentinel's user can write there
            copy, _why, _tid = nuclei_allowlist.private_copy(path, private)  # read once, hashed, and written as it was hashed: nuclei opens this copy, never the library file
            if copy is None:  # one that changed since the list was made never runs
                changed += 1
                logger.warning('nuclei: %s changed since it was listed and is no longer on the service-port allowlist; it is not run', path)
                continue
            try:
                got = _nuclei_pass([target], argv + ['-t', copy], max(1, min(flags.NUCLEI_SERVICE_TEMPLATE_SECONDS, math.ceil(left))), register, secret_file, filtered=True)
            except ToolExitError as exc:  # one template that fails does not fail the port, or the task
                failed += 1
                last_error = str(exc)[:200]
                logger.warning('nuclei: a template run on %s failed: %s', target, last_error)
            else:
                out['findings'] += got['findings']
                out['incomplete'] = out['incomplete'] or got['incomplete']
                quiet += got['no_templates']
                if got['unreachable']:
                    silent += 1
                    if not reached and silent >= flags.NUCLEI_SERVICE_SILENT_RUNS:
                        out['unreachable'], out['reason'] = True, 'nothing answered on this port'
                        return out
                else:
                    reached += 1
        if index + 1 < len(files):
            _sleep(max(0.0, min(pause, deadline - _clock())))  # never a pause that runs past the task's own time
    if changed and not out['reason']:
        out['reason'] = f'{changed} of {len(files)} template files changed while the port was being checked and were not run'
    out['no_templates'] = quiet == len(files)  # every run said its filter matched no template: nothing to check
    if not reached and silent and not failed and not out['findings']:
        out['unreachable'], out['reason'] = True, 'nothing answered on this port'
    elif not reached and failed and not out['findings']:
        out['reason'] = f'every template run failed ({last_error})'
        out['unreachable'] = True
    elif out['reason'] or failed:
        out['reason'] = out['reason'] or f'{failed} of {len(files)} template runs failed'
        out['incomplete'] = True
    return out


BANNER_TIMEOUT = 3
BANNER_BYTES = 64


def _probe_banner(host, port, resolve=None):
    """The first bytes a service on ``host:port`` sends by itself on connect, or ``None``: one short connection, nothing sent. sshd names itself this way
    (``SSH-2.0-...``), and the one place it matters is a port the server could not name, which would otherwise get some 600 short connections that each count
    toward OpenSSH's per-source penalties. ``resolve`` is the task's own resolver (``_resolver``, the answers scope judged): a host name is connected by the first
    address it was judged by and is not resolved again."""
    if resolve is not None and not _is_ip(host):
        try:
            host = next(i[4][0] for i in resolve(host, None) if _is_ip(i[4][0]))
        except (OSError, UnicodeError, StopIteration):
            return None
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
            sock.settimeout(BANNER_TIMEOUT)
            return sock.recv(BANNER_BYTES)
    except OSError:
        return None


def _banner_is_ssh(target, resolve=None):
    key = flags.nuclei_label_key(target)
    banner = _probe_banner(key[0], key[1], resolve) if key else None
    return bool(banner) and banner.startswith(b'SSH-')


def run_nuclei(targets, tags=None, severities=None, timeout=3600, register=None, templates=None, secret_file=None, services=None, budget=None):
    """Host names are passed to nuclei as names, because each finding reports the host it was given. They were judged by scope (and by
    every address they resolved to) just before; nuclei resolves them again, so a name whose DNS answer changes in between is the one gap.
    ``templates`` is a directory of approved templates (the server's verified bundle, ``client.templates``): nuclei then runs exactly that set and
    nothing else; without it nuclei uses the templates baked into this image. ``secret_file`` is a signed-in run's nuclei secrets file
    (``client.signed_in``): passed with ``-sf`` and ``-dr`` (no redirects, so the sign-in is never carried to wherever one leads), as the server does.

    A port only receives the templates of the protocol that speaks there. ``services`` is the server's label of each ``host:port`` (``web``, ``unknown``,
    or a class of ``cvengine_scanner.flags.NUCLEI_SERVICES``: ssh, smtp, imap...). The web targets run first, together, without the raw tcp and javascript
    templates and with a per-host rate; the web pass is stopped when only ``flags.NUCLEI_SERVICE_TIME_SHARE`` of the task's time is left, which the non-web
    ports then share. Each non-web host:port runs its own templates one at a time, paced (``_run_service_port``), under the bound ``budget`` puts on one
    service (``flags.nuclei_service_budget``: a task can make it gentler, never harsher). A port or run that fails, or runs out of time, does not fail the
    task or lose the findings already found: the result's ``not_checked`` names each port not fully checked and why."""
    resolve = _resolver()  # one resolver for the task: the names are resolved once, for the scope judgment, and the banner probe connects to what was judged
    targets = validate_targets(targets, endpoint=True, resolver=resolve)
    web, service_runs = _split_by_service(targets, services)
    extra = _proxy_args('nuclei', targets)
    proxied = bool(extra)  # a run through the egress proxy never connects directly, so it reads no banner either
    if secret_file is not None:
        if not isinstance(secret_file, str) or not os.path.isabs(secret_file) or not os.path.isfile(secret_file):
            raise TargetError('the signed-in run has no usable secrets file')
        extra += ['-sf', secret_file, '-dr']
    if templates is not None and (not isinstance(templates, str) or not os.path.isabs(templates) or not os.path.isdir(templates)):
        raise TargetError('the approved template directory is not usable')
    clean_tags = _clean_words(tags, _TAG)
    if tags and not clean_tags:  # a filter was asked for and none of it is usable: never fall back to every template
        raise TargetError('none of the nuclei tags this task names is usable')
    clean_severities = _clean_words(severities, _SEVERITY)
    if clean_severities:
        extra += ['-severity', ','.join(clean_severities)]
    # the release a run used: the approved bundle is stored under its sha256 (client.templates.bundle_path), the baked set is the image's
    release = f'approved:{os.path.basename(os.path.normpath(templates))}' if templates is not None else f'image:{IMAGE_TEMPLATES_VERSION}'
    spend = flags.nuclei_service_budget(budget)
    started = _clock()
    deadline = started + timeout
    findings, unreachable, not_checked, incomplete = [], [], [], False
    quiet = []  # per pass: whether its filter matched no template (nothing to check)
    attempts = failures = 0
    last_error = None
    listing_failed = {}  # class -> why its template listing failed: tried once per class in a task

    def stop_for(pass_targets, reason):
        nonlocal incomplete
        unreachable.extend(pass_targets)
        not_checked.extend({'target': t, 'reason': reason} for t in pass_targets)
        incomplete = True

    if web:  # the main scan goes first, and may use all of the task's time except the share kept for the non-web ports
        reserve = timeout * flags.NUCLEI_SERVICE_TIME_SHARE if service_runs else 0
        left = deadline - reserve - _clock()
        if left <= 0:
            stop_for(web, 'the task ran out of time before the web pass')
        else:
            web_flags = nuclei_flags_for_budget(flags.nuclei_web_flags(len({host_of({'host': t}) for t in web}), spend)) + extra
            web_flags += (['-t', templates] if templates is not None else []) + (['-tags', ','.join(clean_tags)] if clean_tags else [])
            attempts += 1
            try:
                got = _nuclei_pass(web, web_flags, max(1, math.ceil(left)), register, secret_file, filtered=bool(clean_tags or clean_severities))
            except ToolExitError as exc:
                failures += 1
                last_error = exc
                logger.warning('nuclei: the web pass failed: %s', str(exc)[:200])
                stop_for(web, f'the web run failed ({str(exc)[:120]})')
            else:
                findings += got['findings']
                unreachable += got['unreachable']
                incomplete = incomplete or got['incomplete']
                if got['incomplete']:
                    not_checked.extend({'target': t, 'reason': 'the run ran out of time'} for t in got['unreachable'])
                quiet.append(got['no_templates'])
    for number, (target, klass) in enumerate(service_runs):
        if number >= flags.NUCLEI_SERVICE_MAX_PORTS:
            stop_for([target], f'a task checks at most {flags.NUCLEI_SERVICE_MAX_PORTS} non-web ports; this one is for another task')
            continue
        if deadline - _clock() <= 0:
            stop_for([target], 'the task ran out of time before this port')
            continue
        attempts += 1
        spent = 0.0
        if klass == flags.NUCLEI_UNKNOWN and not proxied:
            began = _clock()
            if _banner_is_ssh(target, resolve):
                klass = 'ssh'  # sshd on a port nothing named: it gets the ssh templates at the ssh pace
            spent = max(0.0, _clock() - began)  # the probe is charged to this port's budget
        got = _run_service_port(target, klass, clean_tags, spend, deadline, extra, templates, register, secret_file, listing_failed, spent)
        findings += got['findings']
        incomplete = incomplete or got['incomplete']
        quiet.append(got['no_templates'])
        if got['unreachable'] or got['reason']:
            unreachable.append(target)  # a port not fully checked (nothing answered, out of time, runs failed) is reported so the server keeps it due
            not_checked.append({'target': target, 'reason': got['reason'] or 'not fully checked'})
        if got['reason'] and got['reason'].startswith('every template run failed'):
            failures += 1
    if attempts and failures == attempts and not findings:
        raise last_error or ToolExitError('every nuclei run of this task failed')  # nothing ran: that is an error, not an answer
    if quiet and all(quiet) and not findings and not incomplete and not unreachable:
        # the filter this task asked for matches no template in this set: there is nothing to check on these targets, which is an answer, not a failure
        return {'findings': [], 'templates_release': release, 'unreachable': [], 'no_templates': True}
    out = {'findings': findings, 'templates_release': release, 'unreachable': [t for t in targets if t in set(unreachable)]}
    if incomplete:
        out['incomplete'] = True
    if not_checked:
        out['not_checked'] = not_checked[:MAX_TARGETS]
    return out


def _nuclei_pass(targets, argv_flags, timeout, register, secret_file, filtered):
    """One nuclei process over ``targets``: its findings, the targets it never reached, whether it ran out of time and whether its filter matched no
    template. A non-zero exit is an error (``ToolExitError``), except the no-template answer of a filter."""
    path = _targets_file(targets)
    with tempfile.TemporaryDirectory(prefix='nuclei-run-') as work:
        errlog = os.path.join(work, 'errors.jsonl')
        try:
            # -elog: nuclei logs every request that failed, with its input. A run that exits 0 with no findings says nothing about a target
            # nothing answered, so the error log is what tells the two apart (review H4).
            output = _run([NUCLEI_BIN, '-l', path, *argv_flags, '-elog', errlog], timeout, register, env=nuclei_env())
        except subprocess.TimeoutExpired as exc:
            # out of time: what it found so far is kept, and every target is named unfinished, so none of them is recorded as scanned clean (the server
            # keeps findings and puts each unreachable target back as due). Before, the whole run was lost: two deep passes of one host each ran their full hour
            # on the VPS and returned nothing.
            found = parse_nuclei_jsonl(getattr(exc, 'partial', '') or '', evidence=secret_file is None)
            logger.warning('nuclei ran out of its %s s for %d target(s); %d finding(s) kept, every target stays due', timeout, len(targets), len(found))
            return {'findings': found, 'unreachable': list(targets), 'incomplete': True, 'no_templates': False}
        except ToolExitError as exc:
            if filtered and _NO_TEMPLATES.search(getattr(exc, 'stderr', '') or str(exc)):
                # the filter this task asked for matches no template in this set (``haproxy`` at ``info``): it failed 29 tasks in two days on the VPS, the same tag
                # sets every time, and they stayed due for ever.
                logger.info('nuclei: no template matches this pass\'s tags and severities; nothing to check')
                return {'findings': [], 'unreachable': [], 'incomplete': False, 'no_templates': True}
            raise
        finally:
            os.unlink(path)
        found = parse_nuclei_jsonl(output, evidence=secret_file is None)  # a signed-in run keeps no request or response (its sign-in is in them)
        errors = parse_nuclei_errors(_read_error_log(errlog))
    return {'findings': found, 'unreachable': unreached_targets(targets, errors, {f['host'] for f in found}), 'incomplete': False, 'no_templates': False}


def _read_error_log(path):
    """The text of a nuclei error log, bounded; a run that logged nothing leaves no file (nothing failed)."""
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            return handle.read(MAX_ERROR_LOG_BYTES)
    except OSError:
        return ''


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
        raise _scope_failure(f'not a usable testssl target: {str(host)[:100]!r} at {str(ip)[:50]!r} ({exc})', exc) from None
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
    # testssl exits 9 when no server answered and 0 when the scan completed: the code is sent (a killed run is an error, never a report)
    code = proc.returncode
    if not isinstance(code, int) or code < 0:
        raise ToolExitError(f'testssl.sh was killed by the system (status {code})')
    result = testssl_result(parse_testssl_report(report), code)
    items = result['items'][:300]
    return {'items': [{'id': str(i.get('id') or ''), 'severity': str(i.get('severity') or ''),
                       'finding': str(i.get('finding') or ''), 'cve': str(i.get('cve') or '')} for i in items],
            'handshake': result['handshake'], 'returncode': code}


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


def wpscan_args_for(args, token):
    """``args`` as a run without an API token can use: WPScan refuses ``vp`` and ``vt`` (vulnerable plugins and themes) without one and aborts the whole
    scan, so a site of a project with no token was never scanned at all (14 of the last 90 runs on the VPS). Without a token the scan lists the plugins
    and themes it detects and their versions instead (``p``, ``t``), which the server's own CVE feed reads."""
    if token:
        return list(args)
    out = list(args)
    if '--enumerate' in out and out.index('--enumerate') + 1 < len(out):
        i = out.index('--enumerate') + 1
        out[i] = ','.join({'vp': 'p', 'vt': 't'}.get(part, part) for part in out[i].split(','))
    return out


_REDIRECTS_TO = re.compile(r'The URL supplied redirects to (https?://\S+?)\.?(?:\s|$)')


def _site(host):
    host = (host or '').lower().rstrip('.')
    return host[4:] if host.startswith('www.') else host


def same_site_redirect(url, outcome):
    """The URL an aborted scan says ``url`` redirects to, when it is the same site (the same host, or its ``www.`` twin, http or https), else None. WPScan stops
    at the redirect rather than follow it, so a site that answers on its other name (www to apex, a path) was never scanned: 32 of the last 90 runs on the
    VPS. Anything that leaves the site is left alone: the scan is never carried to a host it was not given."""
    report = outcome.get('report') if isinstance(outcome, dict) else None
    if outcome.get('returncode') != 4 or not isinstance(report, dict):
        return None
    found = _REDIRECTS_TO.search(str(report.get('scan_aborted') or ''))
    if not found:
        return None
    target = found.group(1)
    if not _URL.match(target) or target.rstrip('/') == url.rstrip('/'):
        return None
    from urllib.parse import urlsplit
    if _site(urlsplit(target).hostname) != _site(urlsplit(url).hostname):
        return None
    return target


def _wpscan_following(url, token, timeout, register, args):
    outcome = _wpscan(url, token, timeout, register, wpscan_args_for(args, token))
    target = same_site_redirect(url, outcome)
    if target is None:
        return outcome
    logger.info('wpscan: %s redirects to %s on the same site; scanning that', url, target)
    return _wpscan(target, token, timeout, register, wpscan_args_for(args, token))  # judged by scope again inside, as any URL


def run_wpscan(url, token='', timeout=900, register=None):
    """Run the quick pass of WPScan on one site and return its raw outcome: ``{'report', 'returncode', 'stderr_tail'}``, exactly what
    ``cveFeed.wpscan_scan._classify`` already reads from a local run: the one function, local or dispatched, that
    turns a wpscan process's outcome into a report or a classified failure. The API token travels in the environment,
    never a command line argument, and never logged. The URL's host is judged by scope (with every address it resolves
    to); WPScan resolves it again, so a DNS answer that changes in between is the one gap."""
    return _wpscan_following(url, token, timeout, register, WPSCAN_ARGS)


def run_wpscan_thorough(url, token='', timeout_seconds=None, register=None):
    """The thorough pass of WPScan on one site (task kind ``wpscan_thorough``): every plugin and theme WPScan knows in mixed detection mode, plus the
    timthumb check (``WPSCAN_THOROUGH_ARGS``, a fixed list), for as long as the task's ``timeout_seconds`` allows (hours; held to the contract's range by
    ``flags.thorough_timeout``). Same URL, scope, token and result handling as the quick pass: ``{'report', 'returncode', 'stderr_tail'}``, where a
    run cut at its limit still reports what it read (WPScan ends its scan 30 seconds before the process would be killed, exit code 4 with a partial
    report)."""
    return _wpscan_following(url, token, thorough_timeout(timeout_seconds), register, WPSCAN_THOROUGH_ARGS)


def _wpscan(url, token, timeout, register, args):
    if not isinstance(url, str) or not url.strip() or not _URL.match(url.strip()) or any(not ch.isprintable() for ch in url.strip()):
        raise TargetError(f'not a usable url: {str(url)[:100]!r}')
    url = url.strip()
    try:
        scope.check_url(url, resolver=_resolver())
    except scope.ScopeError as exc:
        raise _scope_failure(f'not a usable url: {url[:100]!r} ({exc})', exc) from None
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR', 'GEM_HOME', 'GEM_PATH',
                                      'BUNDLE_PATH', 'RUBYLIB', 'RUBYOPT', 'SSL_CERT_FILE', 'SSL_CERT_DIR') if k in os.environ}
    if token:
        env['WPSCAN_API_TOKEN'] = token
    with tempfile.TemporaryDirectory(prefix='wpscan-') as work:
        out = os.path.join(work, 'report.json')
        argv = [WPSCAN_BIN, '--url', url, *args, *_proxy_args('wpscan', [url]), '--max-scan-duration', str(max(30, timeout - 30)), '-o', out]
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
        raise _scope_failure(f'not a usable waf target: {str(host)[:100]!r} at {str(ip)[:50]!r} ({exc})', exc) from None
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


def run_route_probe_signed(target, sign_in, register=None):
    """The ``route_probe_signed`` kind: the routes of a web host asked once each with the stored sign-in the task names (``cvengine_scanner.probes.routes_signed``).
    Built-in scanner only: the daemon reads the credential once (``client.signed_in.run_sign_in``) and hands it here; it is sent only where it was stored for
    (host, scheme, port, not expired, inside the task's scope policy), no redirect is followed, and nothing of it is in the result."""
    from cvengine_scanner.probes import routes_signed
    try:
        return routes_signed.run_batch(target, sign_in)
    except ValueError as exc:
        raise TargetError(f'not a usable route_probe_signed task ({exc})') from None


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


def run_page_read(target, register=None):
    """The ``page_read`` kind: a validation re-test's HEAD of a URL and re-read of a host's front pages and scripts, made from this Sentinel
    (``cvengine_scanner.probes.page_read``); the server weighs what was read."""
    from cvengine_scanner.probes import page_read
    try:
        return page_read.run_batch(target)
    except ValueError as exc:
        raise TargetError(f'not a usable page_read task ({exc})') from None


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
        raise _scope_failure(f'not a usable address: {str(value)[:60]!r} ({exc})', exc) from None


def _finished(xml):
    """``xml`` when it is a finished nmap report, else ``ToolOutputError``: a cut-off sweep must never read as "nothing open"."""
    parse_nmap_xml(xml, strict=True)
    return xml


MAX_FULL_READ = 32 * 1024 * 1024  # what nmap_full reads of one report: all 65,535 ports open is about 10 MiB, so only a runaway reaches this
TARPIT_PORTS = 100  # an address with more open ports than this is a tarpit or a filtering device: its list is kept to this many
TARPIT_NOTE = 'port list truncated: this host answers on an unusually large number of ports (tarpit or filtering device)'
_OPEN_PORT = re.compile(r'<port protocol="tcp" portid="([0-9]{1,5})"><state state="open"')


def _tarpit_xml(address, numbers, seen, exact):
    """A finished nmap report of ``address`` with the first ``TARPIT_PORTS`` of ``numbers`` open and a ``cvengine-note`` element that says the list was cut
    (``seen`` open ports were counted, at least that many when not ``exact``). The server reads it with the same parser as any report: the element is
    one it does not know, so a server that predates it still gets a normal report of the ports kept."""
    kept = ''.join(f'<port protocol="tcp" portid="{n}"><state state="open" reason="syn-ack" reason_ttl="0"/></port>'
                   for n in numbers[:TARPIT_PORTS])
    return ('<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up" reason="user-set"/>'
            f'<address addr="{address}" addrtype="{"ipv6" if _is_ipv6(address) else "ipv4"}"/><ports>{kept}</ports></host>'
            f'<cvengine-note kind="port-list-truncated" open-ports="{seen}" kept="{min(len(numbers), TARPIT_PORTS)}" exact="{"1" if exact else "0"}">{TARPIT_NOTE}</cvengine-note>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')


def limit_open_ports(xml, address, cut=False):
    """``xml``, an nmap_full report of ``address``, unchanged when it names at most ``TARPIT_PORTS`` open TCP ports. More is a host that answers on
    nearly every port (a tarpit, a firewall that accepts everything, a filtering device): that is a normal, useful result, never a failure, and it
    comes back as a report of the first ``TARPIT_PORTS`` ports with the ``cvengine-note`` element (``_tarpit_xml``). ``cut`` is a report the size
    cap stopped: the ports read so far are the answer (nmap writes a host's ports after the sweep, so this is a runaway, not the usual case)."""
    if cut:
        numbers = sorted({int(n) for n in _OPEN_PORT.findall(xml)})
        return _tarpit_xml(address, numbers, len(numbers), False)
    parse_nmap_xml(xml, strict=True)
    root = ET.fromstring(xml)  # parse_nmap_xml has just read it: our own nmap's report
    numbers = sorted({int(p.get('portid')) for p in root.findall('host/ports/port')
                      if p.get('protocol') == 'tcp' and p.get('portid', '').isdigit() and p.find('state') is not None and p.find('state').get('state') == 'open'})
    if len(numbers) <= TARPIT_PORTS:
        return xml
    return _tarpit_xml(address, numbers, len(numbers), True)


def run_nmap_full(address, timeout=1500, register=None):
    """Every TCP port of one address, open ports only (the server's background full sweep), as the raw ``-oX`` report: the server reads it with the
    same parser as a local sweep and keeps only the address it asked about. A host that answers on more than ``TARPIT_PORTS`` ports (``limit_open_ports``),
    or whose report is larger than ``MAX_FULL_READ``, is reported as its first ports with a note that the list was cut, never as a failed task."""
    address = _one_address(address)
    argv = [NMAP_BIN, *(['-6'] if _is_ipv6(address) else []), *NMAP_FULL_FLAGS, '-oX', '-', address]
    cut = []
    xml = _run(argv, timeout, register, max_bytes=MAX_FULL_READ, cut=cut)
    if cut:
        logger.warning('nmap_full: the report of %s passed %s bytes; the ports read so far are the result', address, MAX_FULL_READ)
    return {'xml': limit_open_ports(xml, address, cut=bool(cut))}


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
        raise _scope_failure(f'not a usable url: {url[:100]!r} ({exc})', exc) from None
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
    rows, hits, error, unreached = {}, {}, '', set()
    if allowed:
        proxy = _proxy_args('nuclei', allowed)  # cvENGINE's egress proxy, as the server's own template test (cveFeed.templategen._run_template) takes it
        host_path = _targets_file(allowed)
        with tempfile.TemporaryDirectory(prefix='nuclei-test-') as work:
            errlog = os.path.join(work, 'errors.jsonl')
            try:
                code, out, err = _run_status([NUCLEI_BIN, '-t', path, '-l', host_path, *NUCLEI_TEMPLATE_FLAGS, '-elog', errlog, *proxy],
                                             NUCLEI_TEMPLATE_TIMEOUT, register)
            finally:
                os.unlink(host_path)
            errors = parse_nuclei_errors(_read_error_log(errlog))
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
        if not error:  # a host nothing answered is an error, never a negative test (review H4)
            unreached = set(unreached_targets(allowed, errors, set(hits)))
    outcomes = []
    for host in hosts:
        if host in refused:
            outcomes.append({'host': host, 'vulnerable': False, 'output': '', 'error': refused[host]})
        elif error:
            outcomes.append({'host': host, 'vulnerable': False, 'output': '', 'error': error})
        elif host in unreached:
            outcomes.append({'host': host, 'vulnerable': False, 'output': '', 'error': 'nuclei never reached this host (no answer to any request)'})
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
           'wpscan_thorough': run_wpscan_thorough,
           'openvas': openvas.run_openvas, 'discover': run_discover, 'waf': run_waf, 'http_probe': run_http_probe, 'dns_resolve': run_dns_resolve,
           'bbot_discovery': bbot.run_bbot_discovery,  # streamed: the daemon passes it its client and task id (client/bbot.py)
           'nmap_full': run_nmap_full, 'nmap_verify': run_nmap_verify, 'node2shell': run_node2shell, 'rdp_shot': run_rdp_shot,
           'db_probe': run_db_probe, 'path_probe': run_path_probe, 'nuclei_validate': run_nuclei_validate,
           'alive_check': run_alive_check,
           'bucket_check': run_bucket_check, 'vhost_probe': run_vhost_probe, 'subdir_probe': run_subdir_probe,
           'route_probe': run_route_probe, 'route_probe_signed': run_route_probe_signed,  # the second takes the stored sign-in the daemon read (built-in scanner only)
           'supplier_check': run_supplier_check,
           'hygiene_check': run_hygiene_check, 'dangling_dns_check': run_dangling_dns_check,
           'identity_check': run_identity_check, 'web_screenshot': run_web_screenshot, 'page_read': run_page_read}


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


# --- ssh_probe: sshamble's host key inspection, read-only ---------------------------------------------------------------------------------

SSHAMBLE_BIN = os.environ.get('CVENGINE_SSHAMBLE_BIN', 'sshamble')
# The directory the badkeys blocklist lives in (client/badkeys.py refreshes it with ``sshamble badkeys-update``; the tool's files are badkeysdata.json,
# blocklist.dat and lookup.txt). Optional: without data the check does nothing and the result says "not checked".
BADKEYS_DIR = os.environ.get('CVENGINE_BADKEYS_DIR', '/var/lib/cvengine-sentinel/badkeys')
SSH_PROBE_TIMEOUT = 30  # seconds for one target (the tool's own connect timeout is 5)
SSH_PROBE_STDOUT = 4096  # bytes of the tool's stdout kept: it writes its result to the file, and logs nowhere


def sshamble_ready():
    """Whether the sshamble binary is here: the image carries it; a Sentinel run from a source checkout may not, and then it does not declare ``ssh_probe``."""
    import shutil
    return shutil.which(SSHAMBLE_BIN) is not None


def badkeys_ready(directory=None):
    """Whether the badkeys blocklist data is present (all three files the tool loads)."""
    directory = BADKEYS_DIR if directory is None else directory
    return bool(directory) and all(os.path.isfile(os.path.join(directory, name)) for name in ('blocklist.dat', 'badkeysdata.json', 'lookup.txt'))


def _badkeys_age(badkeys_dir):
    """Whole hours since the blocklist data in ``badkeys_dir`` was fetched, or ``None`` when unknown."""
    from . import badkeys
    stamp = badkeys.refreshed_at(badkeys_dir)
    return None if stamp is None else max(0, int((time.time() - stamp) // 3600))


def _ssh_probe_one(address, port, register, badkeys_dir):
    from cvengine_scanner.probes import ssh_probe
    with tempfile.TemporaryDirectory(prefix='sshamble-') as work:
        out = os.path.join(work, 'out.jsonl')
        home = os.path.join(work, 'home')
        checked = badkeys_ready(badkeys_dir)
        age = _badkeys_age(badkeys_dir) if checked else None
        os.makedirs(os.path.join(home, '.cache'))
        if checked:  # the tool reads $HOME/.cache/badkeys: a link to the data, which a scan never writes
            os.symlink(badkeys_dir, os.path.join(home, '.cache', 'badkeys'))
        argv = ssh_probe.build_argv(SSHAMBLE_BIN, address, port, out)
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': home, 'TERM': 'dumb', 'LC_ALL': 'C'}
        try:
            _run(argv, SSH_PROBE_TIMEOUT, register, max_bytes=SSH_PROBE_STDOUT, env=env)
        except subprocess.TimeoutExpired:
            return ssh_probe.unverified(address, port, 'the inspection timed out', 'ssh_timeout', badkeys_checked=checked)
        except (ToolExitError, ToolOutputError) as exc:
            return ssh_probe.unverified(address, port, f'the tool failed: {exc}', badkeys_checked=checked)
        try:
            size = os.path.getsize(out)
        except OSError:  # no file: nothing was reachable or nothing there speaks SSH
            return ssh_probe.parse_host(address, port, '', checked, age)
        if size > ssh_probe.MAX_OUTPUT_BYTES:
            return ssh_probe.unverified(address, port, 'the tool output was larger than is read', 'ssh_oversized', badkeys_checked=checked)
        with open(out, 'rb') as handle:
            text = handle.read(ssh_probe.MAX_OUTPUT_BYTES + 1).decode('utf-8', errors='replace')
        return ssh_probe.parse_host(address, port, text, checked, age)


def run_ssh_probe(target, register=None, badkeys_dir=None):
    """The ``ssh_probe`` kind (``cvengine_scanner.probes.ssh_probe``): for each address and port, one read-only ``sshamble scan --checks badkeys-blocklist``.
    Every address is held to the task's scope policy and this Sentinel's floor before anything is sent; a target that is refused, times out, writes nothing or
    writes something unreadable is reported unverified (unknown), never as a clean host."""
    from cvengine_scanner.probes import ssh_probe
    from cvengine_scanner.probes.policy import ScopePolicy
    raw = target.get('targets') if isinstance(target, dict) else None
    if not isinstance(raw, list) or not raw or len(raw) > ssh_probe.MAX_TARGETS:
        raise TargetError(f'ssh_probe names 1 to {ssh_probe.MAX_TARGETS} targets')
    clean = []
    for item in raw:
        if not isinstance(item, dict):
            raise TargetError('an ssh_probe target is an object with address and port')
        clean.append((_one_address(item.get('address')), _validate_port(item.get('port'))))
    policy = ScopePolicy(target.get('scope'))
    if badkeys_dir is None:
        from . import badkeys
        badkeys_dir = badkeys.data_dir(BADKEYS_DIR) or BADKEYS_DIR  # the refreshed data (BADKEYS_DIR/current) or data placed there by hand
    hosts = []
    for address, port in clean:
        try:
            policy.check_host(address)
            policy.check_address(address, literal=True)
        except ValueError as exc:
            policy.refuse(address)
            hosts.append(ssh_probe.unverified(address, port, f'not run: {exc}', 'ssh_refused'))
            continue
        policy.touch(address)
        hosts.append(_ssh_probe_one(address, port, register, badkeys_dir))
    return {'hosts': hosts, 'touched': policy.touched, 'refused': policy.refused}


RUNNERS['ssh_probe'] = run_ssh_probe


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
            ran = subprocess.run(argv, capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if ran.returncode == 0:  # a binary that starts and then fails its own version probe is broken: declaring it would take tasks it cannot run (review L1)
            found.append(name)
    if gvm_available():
        found.append('gvm')
    return found
