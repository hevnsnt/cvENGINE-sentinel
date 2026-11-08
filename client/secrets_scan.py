"""The ``secrets_scan`` kind: read a batch of web hosts' pages, their own scripts and those scripts' source maps, and run Kingfisher over them
(cvENGINE docs/SECRETS-PLAN.md section 6). The command lines and the report reader are ``cvengine_scanner.secrets``; this module fetches and runs.

The fetcher is the route check's kind of request: an anonymous GET (no cookies, no credentials, no redirect followed, ``Accept-Encoding: identity``)
to an address this Sentinel resolved and judged itself (``client.scope``: the floor of addresses it never touches), pinned for the whole host, with
a short gap between requests. It only reads:

* the URLs the task names, on the task's own hosts (``scope.names``), never an excluded one;
* the scripts the task names for a host, on that host's origin;
* the ``sourceMappingURL`` of a script read here, on the script's own origin;

and only text (or a source map), within the task's caps per script, per map and in total. Kingfisher then runs twice at most: detection, with
``--no-validate`` and every proxy pointing at a closed local port; and, only when the task says ``validate`` (the built-in scanner of a project that
opted in) and this Kingfisher is the version the server's allow-list was reviewed against, a second pass over the same files with the allow-listed
rules. The bodies live in a temporary directory that is removed when the task ends, however it ends; the values go back over the authenticated
channel and are never logged.
"""
import http.client
import ipaddress
import logging
import os
import shutil
import socket
import ssl
import tempfile
import time
from urllib.parse import urlsplit

from cvengine_scanner import secrets as kf

from . import scope, tools

logger = logging.getLogger('sentinel.secrets')

TIMEOUT = 10
REQUEST_GAP = 0.25  # seconds between two requests to one host
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_HOSTS = 25
USER_AGENT = 'Mozilla/5.0 (compatible; cvENGINE-Sentinel secrets scan)'


class _Pinned(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedTLS(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout):
        context = ssl.create_default_context()
        context.check_hostname = False  # an observation of what the site serves, like the server's route check: a bad certificate is not a refusal
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch(url, address, max_bytes, timeout=TIMEOUT):
    """``(status, content_type, body bytes, sourcemap header)`` of one anonymous GET of ``url`` at ``address``; at most ``max_bytes`` of the body
    (``None`` for the body when it is larger: a cut body is not scanned as if it were whole). Never follows a redirect."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    conn = (_PinnedTLS if parts.scheme == 'https' else _Pinned)(parts.hostname, address, port, timeout)
    path = (parts.path or '/') + (f'?{parts.query}' if parts.query else '')
    try:
        conn.request('GET', path, headers={'Host': parts.netloc, 'User-Agent': USER_AGENT, 'Accept': '*/*', 'Accept-Encoding': 'identity',
                                           'Connection': 'close'})
        response = conn.getresponse()
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            body = None
        return response.status, response.getheader('Content-Type') or '', body, response.getheader('SourceMap') or response.getheader('X-SourceMap') or ''
    finally:
        conn.close()


def _address_of(host, resolver):
    """The one address this Sentinel reads ``host`` at: every address it resolves to is judged by the scope floor, and the first is pinned."""
    host = scope.check_host(host, resolve=True, resolver=resolver)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    addresses = sorted({info[4][0].split('%')[0] for info in resolver(host, None)})
    if not addresses:
        raise scope.ScopeError('the name does not resolve')
    for address in addresses:
        scope.check_ip(address)
    return addresses[0]


def _same_origin(url, base):
    a, b = urlsplit(url), urlsplit(base)
    return a.scheme in ('http', 'https') and (a.scheme, (a.netloc or '').lower()) == (b.scheme, (b.netloc or '').lower())


class Reader:
    """Reads the bodies of one task into ``work/in`` and keeps the manifest, the fetched list and the references, within the caps."""

    def __init__(self, work, limits, fetcher=fetch, sleep=time.sleep):
        self.dir = os.path.join(work, 'in')
        os.makedirs(self.dir, exist_ok=True)
        self.max_scripts = min(int(limits.get('max_scripts_per_host', 8)), 8)
        self.max_script = min(int(limits.get('max_script_bytes', 2 * 1024 * 1024)), 2 * 1024 * 1024)
        self.max_map = min(int(limits.get('max_map_bytes', 8 * 1024 * 1024)), 8 * 1024 * 1024)
        self.budget = min(int(limits.get('max_total_bytes', 32 * 1024 * 1024)), 32 * 1024 * 1024)
        self.follow_maps = limits.get('follow_sourcemaps', True) is True
        self.fetcher, self.sleep = fetcher, sleep
        self.manifest, self.fetched, self.references, self.seen_refs = {}, [], [], set()
        self.total = 0
        self._n = 0

    def _keep(self, url, kind, status, content_type, body, sourcemap_of=None, extra=None):
        size = len(body or b'')
        entry = {'url': url, 'status': status, 'bytes': size, 'content_type': (content_type or '')[:100], 'kind': kind}
        if sourcemap_of:
            entry['sourcemap_of'] = sourcemap_of
        entry.update(extra or {})
        self.fetched.append(entry)
        if not body or not (200 <= (status or 0) < 300 or status == 404):
            return None
        if kind != 'sourcemap' and not kf.is_text(content_type):
            return None
        if self.total + size > self.budget:
            return None
        self.total += size
        name = kf.file_name(self._n, kind)
        self._n += 1
        with open(os.path.join(self.dir, name), 'wb') as handle:
            handle.write(body)
        self.manifest[name] = {'url': url, 'kind': kind}
        text = body.decode('utf-8', errors='replace')
        self.references += kf.references(text, url, self.seen_refs, kf.MAX_REFERENCES - len(self.seen_refs))
        return text

    def _get(self, url, address, limit):
        try:
            return self.fetcher(url, address, limit)
        except (OSError, http.client.HTTPException, ValueError) as exc:
            logger.info('could not read %s: %s', url, type(exc).__name__)
            return None

    def read_host(self, host, urls, scripts, address):
        first = True
        for url in urls[:20]:
            parts = urlsplit(url)
            if parts.scheme not in ('http', 'https') or (parts.hostname or '').lower() != host or parts.username or parts.password:
                continue
            if not first:
                self.sleep(REQUEST_GAP)
            first = False
            got = self._get(url, address, MAX_PAGE_BYTES)
            if got is not None:
                status, content_type, body, _ = got
                self._keep(url, 'page', status, content_type, body)
        for url in [s for s in scripts if (urlsplit(s).hostname or '').lower() == host][:self.max_scripts]:
            self.sleep(REQUEST_GAP)
            got = self._get(url, address, self.max_script)
            if got is None:
                continue
            status, content_type, body, map_header = got
            text = self._keep(url, 'script', status, content_type or 'application/javascript', body)
            map_url = kf.sourcemap_url(url, text or '', map_header) if self.follow_maps and text is not None else None
            if map_url and _same_origin(map_url, url):
                self.sleep(REQUEST_GAP)
                got = self._get(map_url, address, self.max_map)
                if got is not None:
                    status, content_type, body, _ = got
                    self._keep(map_url, 'sourcemap', status, content_type, body, sourcemap_of=url,
                               extra={'sources_content': kf.sources_content(body) if body else False})


def _kingfisher(argv, register, env=None):
    tools._run(argv, kf.WALL_SECONDS, register, max_bytes=1024 * 1024, env=env, ok_codes=(*kf.SUCCESS_CODES, kf.NO_INPUT_CODE))


def _version():
    try:
        return kf.version_of(tools._run([tools.KINGFISHER_BIN, '--version'], 10))
    except Exception:  # noqa: BLE001 - an unknown version only means no validation pass
        return ''


def _body_reader(directory):
    """``name -> text`` of a file this task fetched, for the masked context of a finding (``cvengine_scanner.secrets.read_report``); the files are
    this task's own, in its temporary directory, and are read with the size the fetch already allowed."""
    def read(name):
        try:
            with open(os.path.join(directory, os.path.basename(name)), encoding='utf-8', errors='replace') as handle:
                return handle.read(kf.MAX_FILE_MB * 1024 * 1024 + 1)
        except OSError:
            return None
    return read


def _report(path, manifest, keep_validation, directory=None):
    try:
        with open(path, encoding='utf-8', errors='replace') as handle:
            text = handle.read(kf.MAX_REPORT_BYTES + 1)
    except FileNotFoundError:
        return [], False  # exit 3, no inputs: nothing to report
    if len(text) > kf.MAX_REPORT_BYTES:
        raise tools.ToolOutputError('the Kingfisher report is larger than this Sentinel reads')
    return kf.read_report(text, manifest, keep_validation=keep_validation, body_of=_body_reader(directory) if directory else None)


def _clean_words(values, most, length):
    return [v for v in (values or []) if isinstance(v, str) and 0 < len(v) <= length][:most]


def run(target, register=None, rules=None, fetcher=fetch, resolver=None, sleep=time.sleep):
    """Run one ``secrets_scan`` task. Returns the contract's result (without ``outcome``: the daemon adds it)."""
    if not isinstance(target, dict) or not isinstance(target.get('hosts'), list) or not target['hosts']:
        raise tools.TargetError('a secrets scan names at least one host')
    resolver = resolver or tools._resolver()
    names = {str(n).lower() for n in (target.get('scope') or {}).get('names') or [] if isinstance(n, str)}
    excluded = {str(n).lower() for n in (target.get('scope') or {}).get('exclusions') or [] if isinstance(n, str)}
    work = tempfile.mkdtemp(prefix='secrets-')
    try:
        reader = Reader(work, target.get('limits') or {}, fetcher=fetcher, sleep=sleep)
        for item in target['hosts'][:MAX_HOSTS]:
            host = str((item or {}).get('host') or '').lower()
            if not host or host not in names or host in excluded:
                logger.info('secrets scan: %s is not in the task scope, skipped', host[:100])
                continue
            try:
                address = _address_of(host, resolver)
            except scope.ScopeError as exc:
                logger.info('secrets scan: %s refused (%s)', host[:100], exc)
                continue
            reader.read_host(host, [u for u in item.get('urls') or [] if isinstance(u, str)],
                             [u for u in item.get('script_urls') or [] if isinstance(u, str)], address)
        stats = {'files': len(reader.manifest), 'bytes': reader.total, 'findings': 0, 'truncated': False, 'validated': False}
        findings = []
        if reader.manifest:
            rules_path = None
            if rules:
                rules_path = os.path.join(work, 'custom.yml')
                with open(rules_path, 'w', encoding='utf-8') as handle:
                    handle.write(rules)
            out = os.path.join(work, 'detect.json')
            argv = kf.scan_argv(tools.KINGFISHER_BIN, reader.dir, out, rules_path=rules_path,
                                skip_words=_clean_words(target.get('skip_words'), 100, 100), skip_regex=_clean_words(target.get('skip_regex'), 50, 200))
            _kingfisher(argv, register, env=kf.env_without_egress(os.environ))
            findings, truncated = _report(out, reader.manifest, keep_validation=False, directory=reader.dir)
            stats['truncated'] = truncated
            version = _version()
            stats['kingfisher_version'] = version
            if target.get('validate') is True and findings:
                if version and version == target.get('validate_kingfisher'):
                    checked = os.path.join(work, 'validate.json')
                    _kingfisher(kf.validation_argv(tools.KINGFISHER_BIN, reader.dir, checked, target.get('validate_rules') or []), register)
                    validated, _ = _report(checked, reader.manifest, keep_validation=True)
                    findings = kf.merge_validation(findings, validated)
                    stats['validated'] = True
                else:
                    logger.warning('secrets scan: not validating, this Kingfisher is %s and the allow-list was reviewed for %s', version or 'unknown',
                                   target.get('validate_kingfisher'))
        stats['findings'] = len(findings)
        return {'summary': f'Kingfisher read {stats["files"]} files ({stats["bytes"]} bytes): {len(findings)} findings',
                'findings': findings, 'fetched': reader.fetched[:1000], 'references': reader.references[:kf.MAX_REFERENCES], 'stats': stats}
    finally:
        shutil.rmtree(work, ignore_errors=True)

