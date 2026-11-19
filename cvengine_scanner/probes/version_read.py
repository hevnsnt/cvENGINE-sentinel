"""The ``version_read`` kind (contract version 7), the ``version_digest`` kind (contract version 8) and the ``version_rows`` kind (contract
version 9): fetch the anonymous GETs cvENGINE's version source catalogue names, and hand back only the parts of each answer it asked for.

Why it is generic. The catalogue of version sources (which product states its version where, and how to read it) lives on the server
(``cveFeed.version_catalogue``): adding a product there is one entry and a test, and no Sentinel release. This module knows no product. It runs
the requests a task lists under the task's scope policy and returns clipped parts of each answer; the server decides what they mean.

What a task asks (``target['reads']``): per web base of a host, up to ``MAX_REQUESTS`` requests, each a path and how to read the answer:

  json     the answer is parsed as JSON (at most ``MAX_JSON_BYTES``) and only the dotted ``fields`` it names come back, each a scalar (a string
           clipped to ``MAX_VALUE``) or ``{"type": "object"|"array", "size": n}`` for a container. A part of a field that is a number indexes an
           array (``models.0.name``: the first model's name; ``MAX_INDEX`` at most), any other part an object's key. Nothing else of the body
           leaves the Sentinel: an actuator ``env``, Consul's ``DebugConfig`` or Nomad's agent config carry secrets, and only the version fields are read.
  text     ``MAX_TEXT`` characters of the body, control characters removed, from the first occurrence of the literal ``find`` (a plain substring,
           never a pattern) or from the start.
  metrics  the Prometheus exposition text, of which only the ``*_info`` samples come back (``go_info``, ``jvm_info``, ``python_info``,
           ``nodejs_version_info``, ``*_build_info`` ...), each rebuilt with only its version-like labels (``LABELS``, or a name ending in
           ``_version``); every other sample, label and value is dropped here.
  headers  nothing of the body.
  digest   (``version_digest`` only, contract 8) a digest of the body instead of the body: its SHA-256 (only when the whole body was read, at
           most ``MAX_DIGEST_BYTES``) and its first ``transport.WIRE_HEAD`` bytes as they came over the wire, in hex (a static asset's magic
           number and header: a gzip file's own timestamp). Nothing else of the body. An answer another path served after a redirect (a
           catch-all sending every unknown path to a login page) is ``redirected`` and carries no digest: the hash of a page the server did
           not ask for is never handed back as the asset's.
  rows     (``version_rows`` only, contract 9) only the named rows of a status page, each a short version-like value: a ``Name: value`` line
           of a plain-text page (Apache's ``/server-status?auto``: ``ServerVersion: Apache/2.4.57 (Debian) OpenSSL/3.0.11``) or the first two
           cells of an HTML table row (a phpinfo page: ``<tr><td class="e">OpenSSL Library Version </td><td class="v">OpenSSL 3.0.11 ...``).
           ``fields`` names the rows (at most ``MAX_FIELDS``); a row not named, a value that is not version-like text (``ROW_VALUE``, with a
           dotted number or a bare build number in it) and every other byte of the body stay here. A phpinfo page carries the environment, cookies and credentials: only the version rows
           the server names leave the Sentinel.

Why a second (and a third) kind. A Sentinel of contract 7 refuses a request it does not know (a malformed task fails whole), and cvENGINE's queue cannot
tell which Sentinel will claim a task. So the digest read is its own kind, ``version_digest`` (``kind_since`` 8): the same targets and
answers, with ``digest`` allowed, offered only to a Sentinel that declares contract 8. A ``version_read`` task never carries a digest read.
The rows read is the ``version_rows`` kind (``kind_since`` 9) for the same reason: the ``version_read`` reads and ``rows``, never ``digest``.

Every answer also carries its status, content type, size and the response headers the request names (never a cookie or an authorization
header). Every request is a GET (there is no method field: nothing else can be asked), anonymous (no cookie, no credential), through
``version_probes.fetch`` (pinned vetted address, every redirect hop asked of the policy and kept inside the host's group, bounded bytes and time,
an edge challenge never pushed against). One host's requests run one after another, ``REQUEST_GAP`` apart; an answer another host served after a
redirect is never attributed to the host asked (``version_probes.own_answer``).
"""
import concurrent.futures
import json
import logging
import math
import re
import time
from urllib.parse import urlsplit

from . import http, version_probes

logger = logging.getLogger(__name__)

KIND = 'version_read'
MAX_READS = 100       # read entries (one web base of a host each) in one task
MAX_REQUESTS = 4      # requests one entry may list: a product's version endpoint or two and a control path
MAX_FIELDS = 12       # dotted JSON fields one request may name
MAX_INDEX = 63        # the highest array index a dotted field may name (``models.9.name``)
MAX_HEADERS = 6       # response headers one request may name
MAX_VALUE = 200       # a JSON string value or a header value, clipped
MAX_TEXT = 1024       # a text excerpt
MAX_FIND = 80         # the literal a text read starts from
MAX_LINES = 40        # *_info samples one metrics read returns
MAX_LINE = 400        # one rebuilt sample
MAX_LABEL_VALUE = 80
MAX_SCAN_LINES = 50000  # lines of an exposition text looked at
MAX_JSON_BYTES = 256 * 1024
MAX_TEXT_BYTES = 64 * 1024
MAX_METRICS_BYTES = http.MAX_READ_BYTES
REQUEST_GAP = 0.5     # seconds between two requests to one host
WORKERS = 4           # hosts asked side by side
BATCH_SECONDS = 900   # no host starts after this; the rest are reported as not run
READS = ('json', 'text', 'metrics', 'headers', 'digest', 'rows')
DIGEST_KIND = 'version_digest'  # contract 8: version_read with the digest read
ROWS_KIND = 'version_rows'      # contract 9: version_read with the rows read
KIND_READS = {KIND: ('json', 'text', 'metrics', 'headers'), DIGEST_KIND: ('json', 'text', 'metrics', 'headers', 'digest'),
              ROWS_KIND: ('json', 'text', 'metrics', 'headers', 'rows')}
MAX_ROWS_BYTES = http.MAX_READ_BYTES  # the most of a status page a rows read looks at (a phpinfo page is 60 to 200 KB)
MAX_ROW_VALUE = 120
MAX_ROW_SCAN = 5000   # table rows or lines of a page looked at
MAX_DIGEST_BYTES = http.MAX_READ_BYTES  # the most of an asset a digest read hashes
_HEX = re.compile(r'^[0-9a-f]{0,64}$')
_ROW_NAME = re.compile(r'^[A-Za-z][A-Za-z0-9 ._()/-]{0,59}$')
ROW_VALUE = re.compile(r'^[A-Za-z0-9 ._+~:()/,#-]{1,120}$')  # what a version row's value may be: a release, a build date, a module list
_ROW_VERSION = re.compile(r'\d\.\d|^\d{1,6}$')  # and it states a version: a dotted number, or a bare build number (libxml's 20914)
# the first two cells of a table row, neither holding markup (bounded: the scanned host controls the page)
_TABLE_ROW = re.compile(r'<tr\b[^<>]{0,100}>\s{0,20}<t[dh]\b[^<>]{0,100}>([^<>]{1,80})</t[dh]>\s{0,20}<t[dh]\b[^<>]{0,100}>([^<>]{0,300})</t[dh]>',
                        re.IGNORECASE)
_TEXT_ROW = re.compile(r'^[ \t]{0,8}([A-Za-z][A-Za-z0-9 ._()/-]{0,59}?)[ \t]{0,8}(?::|=>)[ \t]{0,8}(.{0,300}?)[ \t\r]*$')
REQUEST_KEYS = frozenset({'path', 'read', 'fields', 'find', 'headers'})
NEVER_HEADERS = frozenset({'set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate', 'proxy-authenticate'})
LABELS = frozenset({'version', 'vendor', 'runtime', 'revision', 'goversion', 'implementation'})  # and any label named *_version

_PATH = re.compile(r'^/[A-Za-z0-9._~!$&\'()*+,;=:@%/?-]{0,199}$')
_FIELD = re.compile(r'^[A-Za-z0-9_-]{1,60}(?:\.[A-Za-z0-9_-]{1,60}){0,5}$')
_HEADER = re.compile(r'^[a-z0-9-]{1,40}$')
_METRIC = re.compile(r'^[A-Za-z_:][A-Za-z0-9_:]{0,120}_info$')
_LABEL = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,60}$')
_LABEL_VALUE = re.compile(r'^[A-Za-z0-9 ._+~:()/,-]{1,80}$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ​-‏‪-‮﻿]+')


def clean(text, limit):
    """Untrusted text as it leaves the Sentinel: control and bidirectional characters replaced by a space, whitespace collapsed, clipped."""
    return re.sub(r'\s+', ' ', _CONTROL.sub(' ', str(text or ''))).strip()[:limit]


# ----------------------------------------------------------------------------- the task

def _clean_request(raw, digest=False, kind=None):
    if not isinstance(raw, dict) or set(raw) - REQUEST_KEYS:  # a method, a body or a header to send is not a field: nothing but a GET exists
        return None
    kind = kind or (DIGEST_KIND if digest else KIND)
    path, read = raw.get('path'), raw.get('read')
    if not isinstance(path, str) or not _PATH.match(path) or path.startswith('//') or read not in READS:
        return None
    if read not in KIND_READS.get(kind, ()):
        return None  # a digest read is the version_digest kind's (contract 8), a rows read the version_rows kind's (contract 9), never version_read's
    if any(part in ('..', '.') for part in path.split('?', 1)[0].split('/')):
        return None
    fields = raw.get('fields') or []
    headers = raw.get('headers') or []
    find = raw.get('find')
    if not isinstance(fields, list) or not isinstance(headers, list) or len(fields) > MAX_FIELDS or len(headers) > MAX_HEADERS:
        return None
    if any(not isinstance(f, str) or not (_ROW_NAME if read == 'rows' else _FIELD).match(f) for f in fields):
        return None
    if any(not isinstance(h, str) or not _HEADER.match(h) or h in NEVER_HEADERS for h in headers):
        return None
    if read in ('json', 'rows') and not fields:
        return None
    if read not in ('json', 'rows') and fields:
        return None
    if find is not None and (read != 'text' or not isinstance(find, str) or not 0 < len(find) <= MAX_FIND or _CONTROL.search(find)):
        return None
    return {'path': path, 'read': read, 'fields': list(dict.fromkeys(fields)), 'headers': list(dict.fromkeys(headers)), 'find': find}


def _clean_read(raw, digest=False, kind=None):
    if not isinstance(raw, dict):
        return None
    ident, host, base, requests = raw.get('id'), raw.get('host'), raw.get('base'), raw.get('requests')
    if not all(isinstance(v, str) and v for v in (ident, host, base)) or len(base) > 300 or not isinstance(requests, list):
        return None
    if not 0 < len(requests) <= MAX_REQUESTS:
        return None
    cleaned = [_clean_request(r, digest=digest, kind=kind) for r in requests]
    if any(r is None for r in cleaned):
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
    return {'id': ident[:200], 'host': host.lower().rstrip('.'), 'base': base.rstrip('/'), 'requests': cleaned, 'allowed': allowed}


# ----------------------------------------------------------------------------- reading an answer (pure)

def _scalar(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value if abs(value) < 2 ** 53 else clean(value, MAX_VALUE)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean(value, MAX_VALUE)
    if isinstance(value, dict):
        return {'type': 'object', 'size': len(value)}
    if isinstance(value, list):
        return {'type': 'array', 'size': len(value)}
    return None


def json_fields(body, fields):
    """``(is_json, {field: value})``: only the dotted ``fields`` of a JSON object answer, each a scalar or a container's type and size; a part
    that is a number (at most ``MAX_INDEX``) indexes an array. A body that is not one JSON object (an HTML page, a list, truncated) reads as
    ``(False, {})``."""
    if not body or len(body) > MAX_JSON_BYTES:
        return False, {}
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError):
        return False, {}
    if not isinstance(doc, dict):
        return False, {}
    out = {}
    for field in fields:
        node, found = doc, True
        for part in field.split('.'):
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and len(part) <= 2 and int(part) <= MAX_INDEX and int(part) < len(node):
                node = node[int(part)]
            else:
                found = False
                break
        if found:
            out[field] = _scalar(node)
    return True, out


def text_excerpt(body, find=None):
    """``MAX_TEXT`` characters of ``body`` from the first ``find`` (a literal), or from the start; '' when ``find`` is not in it."""
    text = (body or '')[:MAX_TEXT_BYTES]
    if find:
        at = text.find(find)
        if at < 0:
            return ''
        text = text[at:at + MAX_TEXT * 2]
    return clean(text, MAX_TEXT)


def page_rows(body, names):
    """``{name: value}`` of the rows ``names`` of a status page: the first ``Name: value`` (or ``Name => value``) line or the first HTML table row
    whose first cell is the name (entities decoded, trailing blanks dropped), and whose value is version-like text (``ROW_VALUE``) that states a
    version (a dotted number, or a bare build number: ``_ROW_VERSION``), so even a named row holding a password or a token stays here. Nothing
    else of the body: a row not named, or one whose value is anything else (markup, a path with quotes, a long string), is never returned."""
    import html as html_lib
    wanted = {n: n for n in names}
    out = {}
    text = (body or '')[:MAX_ROWS_BYTES]

    def keep(name, value):
        name = clean(html_lib.unescape(name), 60)
        if name not in wanted or name in out:
            return
        value = clean(html_lib.unescape(value), MAX_ROW_VALUE + 1)
        if value and len(value) <= MAX_ROW_VALUE and ROW_VALUE.match(value) and _ROW_VERSION.search(value):
            out[name] = value

    for count, found in enumerate(_TABLE_ROW.finditer(text)):
        if count >= MAX_ROW_SCAN or len(out) == len(wanted):
            break
        keep(found.group(1), found.group(2))
    if len(out) < len(wanted) and '<tr' not in text[:4096].lower():  # a plain-text page: its lines (an HTML page's lines are markup)
        for count, line in enumerate(text.split('\n')):
            if count >= MAX_ROW_SCAN or len(out) == len(wanted):
                break
            if len(line) > 400:
                continue
            found = _TEXT_ROW.match(line)
            if found:
                keep(found.group(1), found.group(2))
    return out


def _labels(text):
    """The labels of one sample's ``{...}`` (``text`` is what follows the brace), parsed in one pass: ``({name: value}, closed)``."""
    out, i, n = {}, 0, len(text)
    while i < n:
        while i < n and text[i] in ' ,':
            i += 1
        if i < n and text[i] == '}':
            return out, True
        start = i
        while i < n and text[i] not in '=}':
            i += 1
        if i >= n or text[i] != '=':
            return out, False
        name = text[start:i].strip()
        i += 1
        if i >= n or text[i] != '"':
            return out, False
        i += 1
        value = []
        while i < n and text[i] != '"':
            if text[i] == '\\' and i + 1 < n:
                i += 1
                value.append({'n': ' '}.get(text[i], text[i]))
            else:
                value.append(text[i])
            i += 1
            if len(value) > 4 * MAX_LABEL_VALUE:
                return out, False
        if i >= n:
            return out, False
        i += 1
        if len(out) < 40:
            out[name] = ''.join(value)
    return out, False


def _label_kept(name):
    return bool(_LABEL.match(name)) and (name in LABELS or name.endswith('_version'))


def info_lines(body):
    """The ``*_info`` samples of a Prometheus exposition text, each rebuilt as ``name{label="value",...}`` with only the version-like labels
    (``LABELS``, ``*_version``) whose value is version-like text; no sample value, no other label, no other sample. At most ``MAX_LINES``."""
    out, seen = [], set()
    for count, raw in enumerate((body or '').split('\n')):
        if count >= MAX_SCAN_LINES or len(out) >= MAX_LINES:
            break
        line = raw.strip()
        if not line or line[0] == '#' or '_info' not in line[:130]:
            continue
        brace = line.find('{')
        name = line[:brace] if brace > 0 else line.split(' ', 1)[0]
        if not _METRIC.match(name):
            continue
        labels, closed = _labels(line[brace + 1:brace + 1 + 4096]) if brace > 0 else ({}, True)
        if not closed:
            continue
        kept = sorted((k, v) for k, v in labels.items() if _label_kept(k) and _LABEL_VALUE.match(v) and len(v) <= MAX_LABEL_VALUE)
        rebuilt = (name + '{' + ','.join(f'{k}="{v}"' for k, v in kept) + '}')[:MAX_LINE]
        if rebuilt not in seen:
            seen.add(rebuilt)
            out.append(rebuilt)
    return out


def answer_of(request, got):
    """What one answer hands back for ``request``: its status, content type, size, the headers named, and the part its ``read`` keeps."""
    headers = got.get('raw_headers') or {}
    out = {'path': request['path'], 'status': int(got.get('status') or 0), 'content_type': clean(got.get('content_type'), 100),
           'bytes': int(got.get('bytes') or 0), 'truncated': bool(got.get('truncated')),
           'headers': {h: clean(headers[h], MAX_VALUE) for h in request['headers'] if h in headers and h not in NEVER_HEADERS}}
    body = got.get('body') or ''
    if request['read'] == 'json':
        is_json, fields = json_fields(body if not out['truncated'] else '', request['fields'])
        out['json'] = fields if is_json else None
    elif request['read'] == 'text':
        out['text'] = text_excerpt(body, request['find'])
    elif request['read'] == 'metrics':
        out['lines'] = info_lines(body)
    elif request['read'] == 'rows':
        out['rows'] = page_rows(body, request['fields'])
    elif request['read'] == 'digest':
        if got.get('redirected_from'):
            out['redirected'] = True  # another path's answer (a login page a catch-all sent this one to): its hash is not the asset's
        else:
            head = str(got.get('wire_head') or '')[:2 * 16].lower()
            sha = str(got.get('sha256') or '').lower()
            out['digest'] = {**({'sha256': sha} if not out['truncated'] and len(sha) == 64 and _HEX.match(sha) else {}),
                             'head': head if _HEX.match(head) and len(head) % 2 == 0 else ''}
    return out


def _max_bytes(read):
    return {'json': MAX_JSON_BYTES, 'metrics': MAX_METRICS_BYTES, 'digest': MAX_DIGEST_BYTES, 'rows': MAX_ROWS_BYTES}.get(read, MAX_TEXT_BYTES)


# ----------------------------------------------------------------------------- running

def run_read(entry, get, sleep=time.sleep, first=True):
    """The answers of one read entry: ``{'id', 'answers'}``. ``get(url, read)`` is the fetch (the scope policy is inside it)."""
    answers = []
    for request in entry['requests']:
        if not first:
            sleep(REQUEST_GAP)
        first = False
        try:
            got = version_probes.own_answer(get(entry['base'] + request['path'], request['read']), entry['base'])
        except (OSError, ValueError) as exc:
            answers.append({'path': request['path'], 'status': 0, 'error': clean(type(exc).__name__, 40)})
            continue
        if got is None:
            answers.append({'path': request['path'], 'status': 0, 'error': 'no answer of its own'})
        elif got.get('challenge'):
            answers.append({'path': request['path'], 'status': int(got.get('status') or 0), 'error': 'challenged'})
        else:
            answers.append(answer_of(request, got))
    return {'id': entry['id'], 'answers': answers}


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic, workers=WORKERS, max_seconds=BATCH_SECONDS, kind=KIND):
    """Run a ``version_read`` task, a ``version_digest`` one (``kind``: the digest read allowed) or a ``version_rows`` one (the rows read
    allowed): ``{'reads': [...], 'scope': {...}}``.
    Returns ``{'reads': [...], 'touched', 'refused'}``. A malformed entry fails the task (the server sent something it should not have); one
    host failing never stops the others. ``probe`` replaces ``http.probe_url`` (tests)."""
    if kind not in KIND_READS:
        raise ValueError(f'not a version read kind: {kind}')
    from .policy import ScopePolicy
    if not isinstance(target, dict):
        raise ValueError('a version_read target is an object')
    policy = ScopePolicy(target.get('scope'))
    raw = target.get('reads') if isinstance(target.get('reads'), list) else []
    if not 0 < len(raw) <= MAX_READS:
        raise ValueError(f'a version_read task names 1 to {MAX_READS} reads')
    reads = [_clean_read(item, kind=kind) for item in raw]
    if any(e is None for e in reads):
        raise ValueError('a planned version_read entry is malformed')
    if len({e['id'] for e in reads}) != len(reads):
        raise ValueError('a version_read task names one entry id twice')
    deadline = clock() + max_seconds
    out = {}
    by_host = {}
    for entry in reads:
        by_host.setdefault(entry['host'], []).append(entry)

    def getter(entry):
        kwargs = {'probe': probe} if probe is not None else {}
        return lambda url, read: version_probes.fetch(url, policy, allowed=entry['allowed'], sleep=sleep, max_bytes=_max_bytes(read), **kwargs)

    def run_host(host, entries):
        why = policy.host_refusal(host)
        for index, entry in enumerate(entries):
            if clock() > deadline:
                out[entry['id']] = {'id': entry['id'], 'answers': [], 'error': 'not run: the task ran out of time'}
                continue
            if why:
                out[entry['id']] = {'id': entry['id'], 'answers': [], 'error': f'not run: the host is {why}'[:200]}
                continue
            try:
                out[entry['id']] = run_read(entry, getter(entry), sleep=sleep, first=index == 0)
            except Exception as exc:  # noqa: BLE001 - one entry failing never stops the rest; the server asks it again later
                logger.info('version_read of %s failed: %s', host, type(exc).__name__)
                out[entry['id']] = {'id': entry['id'], 'answers': [], 'error': clean(f'{type(exc).__name__}: {exc}', 200)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for future in [pool.submit(run_host, host, entries) for host, entries in by_host.items()]:
            future.result()
    return {'reads': [out[e['id']] for e in reads if e['id'] in out], 'touched': policy.touched, 'refused': policy.refused}
