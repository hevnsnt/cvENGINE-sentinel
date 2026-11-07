"""bbot discovery, a streamed task (``bbot_discovery``, contract version 3).

A discovery runs for up to six hours and finds hosts, ports, technologies, findings and screenshots all along the way, so it is reported as it goes:
every few seconds what bbot found since the last batch is POSTed to ``sentinel/tasks/<id>/partial`` with a ``seq`` that starts at 1 and grows by one,
and the usual result closes the run, naming the last ``seq`` sent. A batch is retried until the server takes it (a network error, a server error or
429, with backoff); a 409 or 404 means the task is no longer this Sentinel's (cancelled, expired, or its scan was stopped): bbot is stopped and
nothing more is sent (``Stopped``).

Scope. The task carries the scope it must keep to (``target.scope``). It is applied twice here: bbot is given every denied range, every excluded
name (with its subdomains: an exclusion of one exact name keeps its subdomains out too, the safe side) and this Sentinel's own floor (loopback,
link-local, metadata, documentation ranges, and private space unless this Sentinel is internal) as its blacklist, so none of its modules reaches
them; and everything bbot reports is held to the scope again before it is sent. The server applies the same rules a third time.

Proxy. On the built-in scanner, cvENGINE's egress proxy (``client.egress``) reaches bbot as its ``web.http_proxy`` setting, in the same private file as
the keys, exactly as the server's own bbot run used it; a proxy that suits no scheme bbot takes fails the run rather than go out directly.

Credentials. A task whose project stored API keys for bbot's modules says ``api_keys`` and carries none: they are read once through
``sentinel/tasks/<id>/secret`` (only the built-in scanner is offered such a task) and handed to bbot in a preset file only this user can read, in a
fresh private directory deleted when the run ends, never on its command line. Every key is masked in what bbot writes to its error stream.
"""
import base64
import collections
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

import requests

from cvengine_scanner import scope as floor

from . import egress, httpclient

logger = logging.getLogger('sentinel.bbot')

BBOT_BIN = os.environ.get('CVENGINE_BBOT_BIN', 'bbot')
FLUSH_SECONDS = 5.0  # a batch at most this often while bbot keeps finding things
FLUSH_ITEMS = 300  # or sooner once this many things are waiting
# The most of each list one batch may carry: the contract's maxItems ($defs/partials/bbot_discovery), which the server enforces with a 400.
LIMITS = {'subdomains': 1000, 'ips': 1000, 'ports': 2000, 'urls': 1000, 'technologies': 1000, 'resolutions': 2000, 'edges': 2000,
          'findings': 200, 'http': 500, 'events': 500, 'screenshots': 4}
MAX_EVENTS = 5000  # live feed lines sent in all (the server keeps this many per scan)
MAX_HTTP = 5000
MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024
MAX_SCREENSHOTS = 2000
IMAGE_TYPES = ((b'\x89PNG\r\n\x1a\n', 'image/png'), (b'\xff\xd8\xff', 'image/jpeg'))
SEVERITIES = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
INTERESTING = ('DNS_NAME', 'IP_ADDRESS', 'OPEN_TCP_PORT', 'URL', 'TECHNOLOGY', 'WAF', 'FINDING', 'VULNERABILITY', 'STORAGE_BUCKET',
               'EMAIL_ADDRESS', 'ASN', 'SOCIAL', 'CODE_REPOSITORY', 'WEBSCREENSHOT', 'PROTOCOL')
POST_GIVE_UP_SECONDS = 600.0  # a batch the server keeps refusing with a retryable answer for this long ends the run
POST_MAX_DELAY = 30.0
_NAME = re.compile(r'^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$')
_SCAN_NAME = re.compile(r'^[A-Za-z0-9_.-]{1,100}$')
_MODULE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_FILENAME = re.compile(r'[^A-Za-z0-9._-]')
_SOFT_FAIL = re.compile(r'Setup soft-failed for (\w+): (.{1,200})')
_HARD_FAIL = re.compile(r'Setup hard-failed for (\w+): (.{1,200})')
_CONFIG_REJECTED = re.compile(r'Error parsing command-line (?:config option|preset)|Could not find preset', re.I)
_PRESETS = ('subdomain-enum', 'web', 'web-screenshots', 'kitchen-sink')
_FLAGS = ('passive', 'safe')
_EXCLUDE = re.compile(r'^[a-z0-9_]{1,40}$')


class Stopped(Exception):
    """The server said the task is no longer this Sentinel's: stop, report nothing."""


class RunError(RuntimeError):
    """bbot could not run, or found nothing before it failed: the task's error."""


# --- the scope -------------------------------------------------------------------------------------------------------------------------

class Policy:
    """The task's scope policy (``$defs/scope_policy``) as this Sentinel applies it to what bbot reports, and the blacklist bbot is given."""

    def __init__(self, scope, internal=False):
        scope = scope if isinstance(scope, dict) else {}
        self.domains = [d.lower().rstrip('.') for d in scope.get('in_scope_domains') or [] if isinstance(d, str) and _NAME.match(d.lower().rstrip('.'))]
        if not self.domains:
            raise RunError('the task names no domain in scope')
        self.exact = scope.get('exact_host') is True
        rows = [r for r in scope.get('exclusions') or [] if isinstance(r, dict) and isinstance(r.get('host'), str)]
        self.excluded = {r['host'].lower().rstrip('.') for r in rows if _NAME.match(r['host'].lower().rstrip('.'))}
        self.excluded_trees = {r['host'].lower().rstrip('.') for r in rows if r.get('subtree') is True}
        self.denied = []
        for cidr in scope.get('deny_ranges') or []:
            try:
                self.denied.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError:
                continue
        self.internal = internal

    def blacklist(self):
        """What bbot must never touch: the denied ranges, the excluded names (each with what is under it) and this Sentinel's floor."""
        nets = [*self.denied, *floor.ALWAYS_DENIED, *(() if self.internal else floor.PRIVATE)]
        return sorted({str(n) for n in nets}) + sorted(self.excluded) + sorted(floor.DENIED_NAMES)

    def address(self, value):
        try:
            ip = ipaddress.ip_address(str(value).strip().strip('[]'))
        except ValueError:
            return None
        if any(ip.version == net.version and ip in net for net in self.denied):
            return None
        return ip.compressed

    def name(self, value):
        name = str(value or '').strip().lower().rstrip('.')
        if not name or len(name) > 253 or not _NAME.match(name):
            return None
        if not any(name == d or (not self.exact and name.endswith('.' + d)) for d in self.domains):
            return None
        if name in self.excluded or any(name.endswith('.' + t) for t in self.excluded_trees):
            return None
        return name

    def host(self, value):
        text = str(value or '').strip()
        return self.address(text) if text and (':' in text or text.replace('.', '').isdigit()) else self.name(text)

    def url(self, value):
        if not isinstance(value, str) or not value or len(value) > 2000:
            return None
        try:
            parts = urlsplit(value)
            host = parts.hostname
        except ValueError:
            return None
        if parts.scheme not in ('http', 'https') or not host or parts.username or parts.password or self.host(host) is None:
            return None
        return value


# --- what bbot reports, as batches ------------------------------------------------------------------------------------------------------

def _text(value, limit):
    return ''.join(c for c in str(value or '') if c.isprintable())[:limit]


def _payload(event):
    data = event.get('data')
    return data if data is not None else event.get('data_json')


def _label(etype, payload, host):
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        if etype == 'TECHNOLOGY':
            return f"{payload.get('technology', '?')} on {payload.get('host') or host or '?'}"
        if etype == 'WAF':
            return f"WAF {str(payload.get('waf') or '?')[:80]} on {payload.get('host') or host or '?'}"
        if etype in ('FINDING', 'VULNERABILITY'):
            return str(payload.get('description') or payload.get('name') or 'finding')[:200]
        if etype == 'ASN':
            return f"AS{payload.get('asn', '?')} {payload.get('name', '')}".strip()
        return str(payload.get('url') or payload.get('host') or next(iter(payload.values()), ''))[:200]
    return host or ''


def _status(tags):
    for tag in tags or []:
        if isinstance(tag, str) and tag.startswith('status-') and tag[7:].isdigit() and len(tag) <= 10:
            return int(tag[7:])
    return 0


def _image_type(raw):
    return next((kind for magic, kind in IMAGE_TYPES if raw.startswith(magic)), None)


class Collector:
    """Folds bbot's JSON events into what has not been sent yet, held to the scope, and cuts it into batches no list of which is over its cap."""

    def __init__(self, policy, scan_dir):
        self.policy, self.scan_dir = policy, scan_dir  # scan_dir: bbot's output directory (-o), where its scans' screenshots are written
        self.pending = {key: [] for key in LIMITS}
        self.seen = {key: set() for key in LIMITS if key not in ('findings', 'http', 'screenshots')}
        self.hosts = {}  # event id -> host, so a child event links to its parent's host
        self.scan_name = ''
        self.web_events = {'URL': 0, 'HTTP_RESPONSE': 0}
        self.sent_events = self.sent_http = self.sent_screenshots = 0
        self.found_any = False

    def _add(self, key, item, dedupe=None):
        marker = dedupe if dedupe is not None else item
        if key in self.seen:
            if marker in self.seen[key]:
                return
            self.seen[key].add(marker)
        self.pending[key].append(item)
        self.found_any = True

    def waiting(self):
        return sum(len(v) for v in self.pending.values())

    def add(self, event):
        """Fold one decoded bbot event in. Anything outside the scope, or that bbot itself marks as a neighbour (``scope_distance`` above 0), is
        dropped."""
        if not isinstance(event, dict):
            return
        etype, payload, host = event.get('type'), _payload(event), event.get('host')
        if etype == 'SCAN' and not self.scan_name and isinstance(payload, dict) and _SCAN_NAME.match(str(payload.get('name') or '')):
            self.scan_name = payload['name']
        if (event.get('scope_distance') or 0) > 0:
            return
        if etype in self.web_events:
            self.web_events[etype] += 1
        host = str(host) if isinstance(host, (str, int)) else ''
        if host and event.get('id'):
            self.hosts[str(event['id'])[:200]] = host
        parent_host = self.hosts.get(str(event.get('parent') or ''), '')
        p = self.policy
        if etype == 'DNS_NAME' and isinstance(payload, str):
            name = p.name(payload)
            if name:
                self._add('subdomains', name)
                for ip in event.get('resolved_hosts') or []:
                    address = p.address(ip) if isinstance(ip, str) and ':' not in ip else None
                    if address:
                        self._add('ips', address)
                        self._add('resolutions', {'name': name, 'ip': address}, (name, address))
        elif etype == 'IP_ADDRESS' and isinstance(payload, str):
            address = p.address(payload)
            if address:
                self._add('ips', address)
        elif etype == 'OPEN_TCP_PORT' and isinstance(payload, str) and ':' in payload:
            where, _, port = payload.rpartition(':')
            where = p.host(where.strip('[]'))
            if where and port.isdigit() and 1 <= int(port) <= 65535:
                self._add('ports', {'host': where, 'port': int(port)}, (where, int(port)))
        elif etype == 'URL' and isinstance(payload, str) and p.url(payload):
            self._add('urls', {'url': payload, 'status': min(_status(event.get('tags')), 999)}, payload)
        elif etype in ('TECHNOLOGY', 'WAF') and isinstance(payload, dict):
            where = p.host(payload.get('host') or host)
            name = payload.get('technology') if etype == 'TECHNOLOGY' else re.sub(r'\s*\([^)]*\)\s*$', '', str(payload.get('waf') or '')).strip()
            name = _text(name, 500)
            if where and name and name.lower() not in ('generic detection', 'unknown', 'none'):
                self._add('technologies', {'host': where, 'technology': name}, (where, name))
        elif etype == 'HTTP_RESPONSE' and isinstance(payload, dict):
            self._http(payload, host)
        elif etype == 'WEBSCREENSHOT' and isinstance(payload, dict):
            self._screenshot(payload, host)
        if etype in ('FINDING', 'VULNERABILITY') and isinstance(payload, dict):
            self._finding(payload, host, event.get('module'))
        edge_host, parent = p.host(host), p.host(parent_host)
        if edge_host and parent and edge_host != parent:
            self._add('edges', {'parent': parent, 'child': edge_host}, (parent, edge_host))
        if etype in INTERESTING and self.sent_events + len(self.pending['events']) < MAX_EVENTS:
            if (not host or p.host(host)) and (not parent_host or p.host(parent_host)):
                label = _text(_label(etype, payload, host), 500)
                self._add('events', {'type': etype, 'label': label, 'host': host[:500].lower(), 'parent_host': parent_host[:500].lower(),
                                     'module': _text(event.get('module'), 64)}, (etype, label))

    def _http(self, payload, host):
        url = payload.get('url')
        if not self.policy.url(url) or self.sent_http + len(self.pending['http']) >= MAX_HTTP:
            return
        parts = urlsplit(url)
        where = self.policy.host(payload.get('host') or parts.hostname or host)
        if not where:
            return
        headers = payload.get('header') if isinstance(payload.get('header'), dict) else {}
        lowered = {str(k).lower().replace('_', '-'): v for k, v in headers.items()}

        def header(name):
            value = lowered.get(name, '')
            return str(value[0] if isinstance(value, list) and value else value)

        def number(value, high):
            try:
                value = int(value or 0)
            except (TypeError, ValueError):
                return 0
            return value if 0 <= value <= high else 0
        port = number(payload.get('port') or parts.port or (443 if parts.scheme == 'https' else 80), 65535)
        self._add('http', {'host': where, 'url': url, 'port': port, 'status': number(payload.get('status_code'), 999),
                           'title': _text(payload.get('title'), 500), 'webserver': _text(payload.get('webserver') or header('server'), 300),
                           'content_type': _text(payload.get('content_type') or header('content-type'), 200),
                           'location': _text(payload.get('location') or header('location'), 500)})

    def _finding(self, payload, host, module):
        description = str(payload.get('description') or payload.get('name') or 'Finding')
        where = str(payload.get('host') or host or '').lower()
        url = payload.get('url') if isinstance(payload.get('url'), str) else ''
        if (where and not self.policy.host(where)) or (url and not self.policy.url(url)):
            return
        severity = SEVERITIES.get(str(payload.get('severity', 'INFO')).upper(), 0)
        name = _text(description.split(' - ')[0].split(': ')[0], 200).strip() or 'Finding'
        self._add('findings', {'name': name, 'informational': severity == 0, 'severity': severity, 'host': self.policy.host(where) if where else '',
                               'url': url, 'description': _text(description, 4000), 'module': _text(module, 64)})

    def _screenshot(self, payload, host):
        """A gowitness screenshot bbot wrote under its scan directory: read, checked to be the PNG or JPEG it looks like and at most 2 MiB, and kept
        for the next batch. A path outside the scan directory (event fields are tool output) is never read."""
        if not self.scan_name or self.sent_screenshots + len(self.pending['screenshots']) >= MAX_SCREENSHOTS:
            return
        where = self.policy.host(host or urlsplit(str(payload.get('url') or '')).hostname)
        rel = payload.get('path')
        if not where or not isinstance(rel, str) or not rel:
            return
        base = os.path.realpath(os.path.join(self.scan_dir, self.scan_name))
        source = os.path.realpath(os.path.join(base, rel))
        if not source.startswith(base + os.sep) or not os.path.isfile(source) or os.path.getsize(source) > MAX_SCREENSHOT_BYTES:
            return
        try:
            with open(source, 'rb') as handle:
                raw = handle.read(MAX_SCREENSHOT_BYTES + 1)
        except OSError:
            return
        kind = _image_type(raw)
        if not raw or len(raw) > MAX_SCREENSHOT_BYTES or kind is None:
            return
        name = _FILENAME.sub('_', os.path.basename(source)).lstrip('.')[:120] or 'screenshot.png'
        self._add('screenshots', {'host': where, 'url': self.policy.url(payload.get('url')) or '', 'filename': name, 'content_type': kind,
                                  'data': base64.b64encode(raw).decode('ascii')})

    def take(self, seq):
        """The next batch (``seq`` set), at most each list's cap; what does not fit stays for the one after."""
        body = {'seq': seq}
        if self.scan_name:
            body['scan_name'] = self.scan_name
        for key, cap in LIMITS.items():
            body[key], self.pending[key] = self.pending[key][:cap], self.pending[key][cap:]
        self.sent_events += len(body['events'])
        self.sent_http += len(body['http'])
        self.sent_screenshots += len(body['screenshots'])
        return body


# --- talking to the server ---------------------------------------------------------------------------------------------------------------

def _retryable(exc):
    if isinstance(exc, requests.RequestException):
        return True
    status = getattr(exc, 'status', None)
    return isinstance(status, int) and (status >= 500 or status == 429)


class Sender:
    """Posts batches in order, each until the server takes it."""

    def __init__(self, client, task_id, halted=None, sleep=None):
        self.client, self.task_id, self.seq = client, task_id, 0
        self.halted = halted or threading.Event()
        self.sleep = sleep or (lambda seconds: self.halted.wait(seconds))

    def send(self, body):
        seq = self.seq + 1
        body['seq'] = seq
        give_up_at, delay = time.monotonic() + POST_GIVE_UP_SECONDS, 1.0
        while True:
            try:
                self.client.call('POST', f'sentinel/tasks/{self.task_id}/partial', body)
                self.seq = seq  # taken, or a duplicate of one already taken (a retry whose answer was lost): either way the next is seq + 1
                return
            except (httpclient.ApiError, requests.RequestException) as exc:
                status = getattr(exc, 'status', None)
                if status in (404, 409):
                    raise Stopped(str(exc)) from None
                if not _retryable(exc):
                    raise RunError(f'the server refused a batch of results: {exc}') from None
                if time.monotonic() + delay > give_up_at:
                    raise RunError(f'could not deliver a batch of results for {int(POST_GIVE_UP_SECONDS)} seconds: {exc}') from None
                logger.warning('could not deliver batch %s of task %s (%s); retrying in %.0fs', seq, self.task_id, exc, delay)
                if self.sleep(delay * random.uniform(0.75, 1.0)):
                    raise Stopped('the Sentinel is shutting down') from None
                delay = min(POST_MAX_DELAY, delay * 2)


def read_keys(client, task_id):
    """The project's API keys for bbot's modules (``{modules: {...}}``) through the single-use secure read, or ``{}`` when they cannot be read (the
    run goes on without them; bbot then skips the modules that need one)."""
    try:
        reply = client.call('POST', f'sentinel/tasks/{task_id}/secret')
    except (httpclient.ApiError, requests.RequestException) as exc:
        logger.warning('could not read the API keys of task %s (%s); running without them', task_id, exc)
        return {}
    config = reply.get('bbot_config') if isinstance(reply, dict) else None
    modules = config.get('modules') if isinstance(config, dict) else None
    if not isinstance(modules, dict):
        return {}
    clean = {}
    for module, options in modules.items():
        if isinstance(module, str) and _MODULE.match(module) and isinstance(options, dict):
            kept = {k: v for k, v in options.items() if isinstance(k, str) and _MODULE.match(k) and isinstance(v, str) and v and len(v) <= 4096}
            if kept:
                clean[module] = kept
    return {'modules': clean} if clean else {}


def secrets_of(config):
    return [v for options in (config.get('modules') or {}).values() for v in options.values()]


def redact(text, secrets):
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, '***')
        for part in secret.split(':'):
            if len(part) >= 6:
                text = text.replace(part, '***')
    return text


# --- running bbot ------------------------------------------------------------------------------------------------------------------------

def build_command(target, out_dir, blacklist_file, keys_file=None):
    """The bbot command line for ``target`` (``$defs/targets/bbot_discovery``): what the server's own local run of the same mode runs. Every value is
    checked against the contract's enums and patterns: nothing from the task reaches the command line as free text but the target's domain, which
    must be a plain host name."""
    try:  # a plain host name (each label starts and ends with a letter or digit, so nothing reads as an option), never a local or metadata name
        domain = floor.check_host(str(target.get('domain') or ''), internal=True, resolve=False)
    except floor.ScopeError:
        raise RunError('the task target is not a host name') from None
    if not _NAME.match(domain):
        raise RunError('the task target is not a host name')
    presets = [p for p in target.get('presets') or [] if p in _PRESETS] or ['subdomain-enum']
    flags = [f for f in target.get('require_flags') or [] if f in _FLAGS]
    exclude = [m for m in target.get('exclude_modules') or [] if isinstance(m, str) and _EXCLUDE.match(m)]
    scope = target.get('scope') if isinstance(target.get('scope'), dict) else {}
    if (scope.get('bounty') is True or target.get('trufflehog') is not True) and 'trufflehog' not in exclude:
        exclude.append('trufflehog')  # it verifies a found secret against its issuer: never for a bug bounty project, never unless allowed
    cmd = [BBOT_BIN, '-t', domain, '-p', *presets, *([keys_file] if keys_file else [])]
    if exclude:
        cmd += ['-em', *exclude]
    if target.get('strict_scope') is True:
        cmd.append('--strict-scope')
    if flags:
        cmd += ['-rf', ','.join(flags)]
    if target.get('force') is True:
        cmd.append('--force')
    # --no-deps: this image installs every module's dependencies when it is built and a running Sentinel has no root and no sudo. Without it bbot
    # looks up each module in its own record of installed dependencies, which is keyed by (among other things) the container's hostname, finds
    # none, and tries to install as root: ``PermissionError: Permission denied: 'sudo'`` before it has scanned anything.
    return cmd + ['--no-deps', '-b', blacklist_file, '-o', out_dir, '--json', '-y', '--no-color']


_NEEDS_ROOT = re.compile(r"Permission denied: 'sudo'|No such file or directory: 'sudo'|needs root privileges to install its dependencies", re.I)


def start_failure(lines):
    """A plain sentence for a bbot that could not start for a cause this Sentinel knows (bbot's own text is a Python traceback), or ''."""
    text = '\n'.join(lines)
    if _NEEDS_ROOT.search(text):
        found = re.search(r'Installing dependencies for module "(\w+)"|Module "(\w+)" needs root', text)
        module = (found.group(1) or found.group(2)) if found else ''
        return ('bbot cannot start: it tried to install a module dependency' + (f' ({module})' if module else '') +
                ' and that needs root, which this Sentinel does not have. The image lacks something bbot needs; update or rebuild it')
    return ''


def _stop(proc):
    try:
        os.killpg(proc.pid, 15)
        proc.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass


class _Handle:
    def __init__(self, proc):
        self.proc = proc

    def poll(self):
        return self.proc.poll()

    def kill(self):
        _stop(self.proc)


def run_bbot_discovery(target, client, task_id, register=None, internal=False, halted=None, popen=subprocess.Popen):
    """Run the discovery a task describes, posting batches as it goes; returns the final result (``outcome: done``). Raises ``Stopped`` when the
    server ended the task (nothing is to be reported) and ``RunError`` when bbot could not run, or failed before it found anything."""
    if not isinstance(target, dict):
        raise RunError('the task target is not an object')
    policy = Policy(target.get('scope'), internal=internal)
    timeout = target.get('timeout_seconds') if isinstance(target.get('timeout_seconds'), int) and not isinstance(target.get('timeout_seconds'), bool) else 21600
    timeout = max(60, min(86400, timeout))
    keys = read_keys(client, task_id) if target.get('api_keys') is True else {}
    secrets = secrets_of(keys) if keys else []
    try:  # the built-in scanner's egress proxy (client.egress), as the server's own bbot run used it: bbot's web.http_proxy, in the private file
        proxy = egress.for_tool('bbot', [str(target.get('domain') or '')])
    except egress.ProxyUnavailable as exc:
        raise RunError(str(exc)) from None
    config = {**keys, **({'web': {'http_proxy': proxy[0]}} if proxy else {})}
    secrets += [proxy[0]] if proxy else []
    work = tempfile.mkdtemp(prefix='cvengine-bbot-')  # 0700: the key file and bbot's scan output live here and go with it
    sender = Sender(client, task_id, halted=halted)
    problems, hard_failures, stderr_tail = [], [], collections.deque(maxlen=40)
    try:
        blacklist_file = os.path.join(work, 'blacklist.txt')
        with open(blacklist_file, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(policy.blacklist()) + '\n')
        keys_file = None
        if config:
            keys_file = os.path.join(work, 'keys.yml')  # JSON is YAML: bbot reads the preset as is
            fd = os.open(keys_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump({'config': config}, handle)
        out_dir = os.path.join(work, 'scans')
        os.mkdir(out_dir, 0o700)
        collector = Collector(policy, out_dir)
        proc = popen(build_command(target, out_dir, blacklist_file, keys_file), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                     bufsize=1, start_new_session=True)
        if register is not None:
            register(_Handle(proc))

        def drain_stderr():
            for line in proc.stderr:
                line = redact(line.rstrip('\n'), secrets)
                stderr_tail.append(line[:500])
                for pattern, sink in ((_SOFT_FAIL, problems), (_HARD_FAIL, hard_failures)):
                    found = pattern.search(line)
                    if found and len(sink) < 50 and found.group(1) not in [m for m, _ in sink]:
                        sink.append((found.group(1)[:64], found.group(2).strip()[:200]))
        reader = threading.Thread(target=drain_stderr, name=f'bbot-stderr-{task_id}', daemon=True)
        reader.start()
        timed_out = threading.Event()

        def on_timeout():
            if proc.poll() is None:
                timed_out.set()
                _stop(proc)
        timer = threading.Timer(timeout, on_timeout)
        timer.daemon = True
        timer.start()
        last_flush = time.monotonic()
        try:
            for line in proc.stdout:
                line = line.strip()
                if line.startswith('{'):
                    try:
                        collector.add(json.loads(line))
                    except (ValueError, RecursionError):
                        continue
                if collector.waiting() >= FLUSH_ITEMS or (collector.waiting() and time.monotonic() - last_flush >= FLUSH_SECONDS):
                    while collector.waiting():
                        sender.send(collector.take(sender.seq + 1))
                    last_flush = time.monotonic()
        except BaseException:
            _stop(proc)
            raise
        finally:
            timer.cancel()
            if proc.poll() is None:
                _stop(proc)
            proc.wait()
            reader.join(timeout=5)
        while collector.waiting():
            sender.send(collector.take(sender.seq + 1))
        incomplete = ''
        if timed_out.is_set():
            incomplete = f'bbot reached its time limit of {timeout} seconds'
        elif proc.returncode not in (0, None):
            reason = next((ln for ln in reversed(stderr_tail) if ln.strip()), 'no error output')
            incomplete = ('bbot was killed, almost always for lack of memory' if proc.returncode in (-9, 137)
                          else start_failure(stderr_tail) or f'bbot exited with status {proc.returncode}: {reason}')[:300]
        elif not collector.found_any and any(_CONFIG_REJECTED.search(ln) for ln in stderr_tail):
            incomplete = 'bbot refused its configuration and scanned nothing'
        if incomplete and not collector.found_any:
            raise RunError(incomplete)
        return {'outcome': 'done', 'partials': sender.seq, 'mode': target.get('mode') if target.get('mode') in ('passive', 'standard', 'deep') else 'passive',
                'incomplete': redact(incomplete, secrets)[:300], 'scan_name': collector.scan_name, 'web_events': dict(collector.web_events),
                'problems': [{'module': m, 'reason': r} for m, r in problems if _MODULE.match(m)],
                'hard_failures': [{'module': m, 'reason': r} for m, r in hard_failures if _MODULE.match(m)]}
    finally:
        shutil.rmtree(work, ignore_errors=True)
