"""Kingfisher for the ``secrets_scan`` kind (cvENGINE docs/SECRETS-PLAN.md section 6): the command line, the inputs, and the report read back into
the contract's result. Pure: nothing here runs Kingfisher, fetches a page or reads the environment (``client.tools.run_secrets_scan`` does).

* **Detection** (every task): ``scan_argv(...)`` with ``--no-validate`` and ``--no-update-check``, run with ``NO_EGRESS_ENV`` so any unexpected
  request fails closed at a dead local proxy. ``--no-dedup`` keeps every place a secret was served (cvENGINE deduplicates on its own fingerprint).
* **Validation** (a task with ``validate: true``, which only the built-in scanner of a project that opted in is ever given): a second pass over
  the same files with ``validation_argv(...)``: the task's allow-listed rules only, one request a second, ten seconds, no retry, strict TLS, no
  internal addresses. Only when the Kingfisher here is the version the allow-list was reviewed against (``validate_kingfisher``).
* ``check_argv`` refuses anything that could change or revoke a credential or update the binary (``revoke``, ``self-update``), or that drops the
  update or validation guard of a detection pass.

The inputs are one file per fetched body (``<n>.<ext>``) and a manifest from file name to URL, so every finding maps back to the URL that served it.
``read_report`` keeps the contract's fields only: never the validation response, never a command line (Kingfisher's ``validate_command`` holds the
value), never more than ``MAX_FINDINGS``.
"""
import json
import re
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit

from cvengine_scanner import context as masked_context

KINGFISHER_VERSION = '2.18.1'  # the Dockerfile pin (ARG KINGFISHER_VERSION); a test holds the two together
WALL_SECONDS = 300
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 500
MIN_SECRET, MAX_SECRET, MAX_PEM = 8, 1024, 8192
MAX_FILE_MB = 8
SUCCESS_CODES = (0, 200, 205)  # Kingfisher docs/USAGE.md "Exit Codes": no findings, findings, validated findings
NO_INPUT_CODE = 3
FORBIDDEN_WORDS = ('revoke', 'self-update', '--self-update', 'blast-radius', '--blast-radius', '--access-map', 'access-map')
DEAD_PROXY = 'http://127.0.0.1:9'
NO_EGRESS_ENV = {'HTTPS_PROXY': DEAD_PROXY, 'HTTP_PROXY': DEAD_PROXY, 'ALL_PROXY': DEAD_PROXY, 'https_proxy': DEAD_PROXY,
                 'http_proxy': DEAD_PROXY, 'all_proxy': DEAD_PROXY, 'NO_PROXY': '', 'no_proxy': ''}
OUTCOMES = ('verified_active', 'assumed', 'locally_derived', 'invalid_material', 'verified_inactive', 'unavailable', 'skipped', 'not_attempted')
META_KEYS = ('restriction', 'active_google_key', 'gemini_access', 'account_type')
RULE_ID = re.compile(r'^[a-z0-9][a-z0-9._:/-]{0,119}$')
TEXT_TYPES = ('application/json', 'application/javascript', 'application/xml', 'application/x-javascript', 'application/ecmascript')
EXTENSIONS = {'script': 'js', 'sourcemap': 'map', 'page': 'html'}
COMPONENTS = {'betterleaks.aws-access-token': ('AWS_SECRET_ACCESS_KEY', 'betterleaks.aws-secret-access-key')}  # a pair's secret half

_BASE = ['--format', 'json', '--no-update-check', '--no-dedup', '--git-history=none', '--no-extract-archives', '--no-binary',
         '--max-file-size', str(MAX_FILE_MB), '--confidence', 'medium', '--validation-filter', 'all', '--no-rule-cache', '--jobs', '2']


class ArgvError(ValueError):
    pass


def is_text(content_type):
    """Text, JSON, JavaScript and XML only, as the server's route check (``cveFeed.sensitive.is_text``)."""
    ct = (content_type or '').split(';')[0].strip().lower()
    return bool(ct) and (ct.startswith('text/') or ct in TEXT_TYPES or ct.endswith('+json') or ct.endswith('+xml'))


def _words(values, limit, length):
    out = []
    for value in values or ():
        if isinstance(value, str) and value.strip() and len(value) <= length and not value.startswith('-'):
            out.append(value.strip())
        if len(out) >= limit:
            break
    return out


def scan_argv(binary, in_dir, out_path, rules_path=None, skip_words=(), skip_regex=()):
    """The detection pass: no validation, no update check."""
    argv = [binary, 'scan', str(in_dir), '--output', str(out_path), '--no-validate', *_BASE]
    if rules_path:
        argv += ['--rules-path', str(rules_path)]
    for word in _words(skip_words, 100, 100):
        argv += ['--skip-word', word]
    for pattern in _words(skip_regex, 50, 200):
        argv += ['--skip-regex', pattern]
    check_argv(argv)
    return argv


def validation_argv(binary, in_dir, out_path, rules):
    """The validation pass: the allow-listed rules only (built-ins, never a custom rule), paced, one try, strict TLS."""
    rules = [r for r in rules or () if isinstance(r, str) and RULE_ID.match(r) and not r.startswith('custom.')]
    if not rules:
        raise ArgvError('a validation pass needs at least one allow-listed rule')
    argv = [binary, 'scan', str(in_dir), '--output', str(out_path), *_BASE, '--validation-rps', '1', '--validation-timeout', '10',
            '--validation-retries', '0', '--tls-mode', 'strict']
    for rule in rules[:20]:
        argv += ['--rule', rule]
    check_argv(argv, validating=True)
    return argv


def check_argv(argv, validating=False):
    """Refuse an argv that could do more than read: a revoke, a self update, an access map; a detection pass without ``--no-validate``; any pass
    without ``--no-update-check``; internal addresses for a validator."""
    words = [str(a) for a in argv]
    if len(words) < 2 or words[1] != 'scan':
        raise ArgvError('only "kingfisher scan" is ever run')
    bad = sorted({w for w in words if w in FORBIDDEN_WORDS or w.startswith('--self-update') or w.startswith('--blast-radius')})
    if bad:
        raise ArgvError(f'refused: {", ".join(bad)}')
    if '--no-update-check' not in words:
        raise ArgvError('every run passes --no-update-check')
    if not validating and '--no-validate' not in words:
        raise ArgvError('a detection pass passes --no-validate')
    if '--allow-internal-ips' in words or '--ignore-certs' in words:
        raise ArgvError('validators never reach internal addresses or skip certificate checks')
    return argv


def file_name(n, kind):
    return f'{n}.{EXTENSIONS.get(kind, "txt")}'


def manifest_entry(n, url, status, content_type, kind, size, sourcemap_of=None):
    entry = {'url': url, 'status': status, 'content_type': (content_type or '')[:100], 'kind': kind, 'bytes': size}
    if sourcemap_of:
        entry['sourcemap_of'] = sourcemap_of
    return file_name(n, kind), entry


# ----------------------------------------------------------------------------- what a body points at

_SOURCEMAP = re.compile(r'[#@]\s*sourceMappingURL=([^\s\'"*]{1,2000})')


def sourcemap_url(script_url, body, header=''):
    """The source map a script names (``//# sourceMappingURL=``, or the ``SourceMap`` header), absolute, when it is on the script's own origin;
    ``None`` otherwise (an inline ``data:`` map is part of the script already, and a map elsewhere is never fetched)."""
    found = (header or '').strip()
    if not found:
        matches = _SOURCEMAP.findall(body[-4096:] if isinstance(body, str) else '')
        found = matches[-1] if matches else ''
    if not found or found.startswith('data:'):
        return None
    url = urljoin(script_url, found)
    a, b = urlsplit(script_url), urlsplit(url)
    if (a.scheme, (a.netloc or '').lower()) != (b.scheme, (b.netloc or '').lower()):
        return None
    return b._replace(fragment='').geturl()


def sources_content(body):
    """Whether a source map embeds the original sources (a non-empty ``sourcesContent``)."""
    try:
        doc = json.loads(body)
    except (TypeError, ValueError):
        return False
    content = doc.get('sourcesContent') if isinstance(doc, dict) else None
    return isinstance(content, list) and any(isinstance(c, str) and c for c in content)


_REFERENCES = (
    ('firebase_rtdb', re.compile(r'(?i)\b([a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{2,30})?)\.(?:firebaseio\.com|firebasedatabase\.app)\b')),
    ('firebase_storage', re.compile(r'(?i)["\']([a-z0-9][a-z0-9-]{0,62}\.(?:appspot\.com|firebasestorage\.app))["\']')),
    ('s3', re.compile(r'(?i)\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b')),
    ('s3', re.compile(r'(?i)\bs3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b')),
    ('gcs', re.compile(r'(?i)\bstorage\.(?:googleapis|cloud\.google)\.com/([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])\b')),
    ('gcs', re.compile(r'(?i)\b([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])\.storage\.googleapis\.com\b')),
    ('azure', re.compile(r'(?i)\b([a-z0-9]{3,24})\.blob\.core\.windows\.net(?:/([a-z0-9](?:[a-z0-9]|-(?!-)){1,61}[a-z0-9]))?')),
)
MAX_REFERENCES = 200


def references(text, url, seen=None, limit=MAX_REFERENCES):
    """The storage and databases ``text`` (a body read from ``url``) points at: ``[{kind, value, url}]``, each ``(kind, value)`` once (``seen``
    is shared across bodies). Names only: nothing is fetched here, and the server checks them with its own bucket sweep."""
    seen = set() if seen is None else seen
    out = []
    for kind, pattern in _REFERENCES:
        for match in pattern.finditer(text or ''):
            value = match.group(1).lower()
            if kind == 'firebase_rtdb':
                value = match.group(0).lower()
            elif kind == 'azure' and match.lastindex and match.lastindex >= 2 and match.group(2):
                value = f'{value}/{match.group(2).lower()}'
            if value.startswith(('www.', 'storage.')) or (kind, value) in seen:
                continue
            seen.add((kind, value))
            out.append({'kind': kind, 'value': value[:255], 'url': url})
            if len(seen) >= limit:
                return out
    return out


# ----------------------------------------------------------------------------- the report

def _meta(response):
    """The allow-listed validation metadata in a validator's response (``metadata`` of a Betterleaks validator), or ``{}``. The response
    itself is never kept."""
    try:
        doc = json.loads(response) if isinstance(response, str) and response.strip().startswith('{') else None
    except ValueError:
        return {}
    if not isinstance(doc, dict):
        return {}
    source = doc.get('metadata') if isinstance(doc.get('metadata'), dict) else doc
    out = {}
    for key in META_KEYS:
        value = source.get(key)
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, str) and value:
            out[key] = value[:60]
    return out


def _secret_ok(value):
    if not isinstance(value, str):
        return False
    limit = MAX_PEM if 'PRIVATE KEY' in value[:80] else MAX_SECRET
    return MIN_SECRET <= len(value) <= limit


def read_report(text, manifest, keep_validation=False, body_of=None):
    """``(findings, truncated)`` from Kingfisher's JSON report: each finding mapped to the URL of its file (``manifest``: file name -> entry), with
    the contract's fields only. A pair's secret half (an AWS secret key in ``dependent_captures``) is a finding of its own at the same place.
    ``keep_validation`` keeps Kingfisher's outcome (a validation pass); otherwise every outcome is ``not_attempted``.

    ``body_of(file name)`` returns the text of a file Kingfisher read (or ``None``): with it each finding also carries ``context``, the line of that
    file around the match with the value and every other secret-looking token masked here (``cvengine_scanner.context``), so a person can see WHAT was
    found. Kingfisher's ``snippet`` is the value itself and ``line`` and ``column_start`` say where it is: the file is read for the text around it.
    A finding whose snippet cannot be proved clean, or whose value is not on its line, has no ``context`` (and keeps everything else).

    ``secret`` stays what it always was (the value, over the authenticated channel, for the server to fingerprint); the masked ``context`` never holds it."""
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        raise ValueError('the Kingfisher report is not JSON') from None
    records = doc.get('findings') if isinstance(doc, dict) else None
    if not isinstance(records, list):
        raise ValueError('the Kingfisher report has no findings list')
    out, truncated = [], False
    bodies = {}
    for record in records:
        rule = record.get('rule') if isinstance(record, dict) else None
        finding = record.get('finding') if isinstance(record, dict) else None
        if not isinstance(rule, dict) or not isinstance(finding, dict):
            continue
        entry = manifest.get(PurePosixPath(str(finding.get('path') or '')).name)
        rule_id = str(rule.get('id') or '')
        if entry is None or not RULE_ID.match(rule_id) or not _secret_ok(finding.get('snippet')):
            continue
        validation = finding.get('validation') if isinstance(finding.get('validation'), dict) else {}
        outcome = validation.get('outcome') if keep_validation and validation.get('outcome') in OUTCOMES else 'not_attempted'
        line = finding.get('line')
        row = {'rule_id': rule_id, 'rule_name': str(rule.get('name') or '')[:200], 'url': entry['url'], 'secret': finding['snippet'],
               'line': line if isinstance(line, int) and not isinstance(line, bool) and line >= 0 else None,
               'confidence': finding.get('confidence') if finding.get('confidence') in ('low', 'medium', 'high') else '',
               'entropy': str(finding.get('entropy') or '')[:20], 'validation': {'outcome': outcome}}
        meta = _meta(validation.get('response')) if keep_validation else {}
        if meta:
            row['validation_meta'] = meta
        if body_of is not None and row['line']:
            name = PurePosixPath(str(finding.get('path') or '')).name
            if name not in bodies:
                bodies[name] = body_of(name)
            others = [v for v in (finding.get('dependent_captures') or {}).values() if isinstance(v, str)] if isinstance(finding.get('dependent_captures'), dict) else []
            context = masked_context.finding_context(bodies[name], row['line'], finding['snippet'], finding.get('column_start'), others=others)
            if context:
                row['context'] = context
        rows = [row]
        component = COMPONENTS.get(rule_id)
        captures = finding.get('dependent_captures') if isinstance(finding.get('dependent_captures'), dict) else {}
        if component and _secret_ok(captures.get(component[0])):
            rows.append({**row, 'rule_id': component[1], 'rule_name': '', 'secret': captures[component[0]], 'validation': {'outcome': 'not_attempted'}})
            rows[-1].pop('validation_meta', None)
        for item in rows:
            if len(out) >= MAX_FINDINGS:
                truncated = True
                break
            out.append(item)
    return out, truncated


def merge_validation(findings, validated):
    """Detection findings with the outcomes (and metadata) of the validation pass, matched on rule, URL, line and value."""
    key = lambda f: (f['rule_id'], f['url'], f.get('line'), f['secret'])  # noqa: E731
    outcomes = {key(f): f for f in validated}
    out = []
    for f in findings:
        hit = outcomes.get(key(f))
        if hit is not None:
            f = {**f, 'validation': hit['validation'], **({'validation_meta': hit['validation_meta']} if hit.get('validation_meta') else {})}
        out.append(f)
    return out


def exit_ok(code):
    return code in SUCCESS_CODES or code == NO_INPUT_CODE


def version_of(text):
    """The version ``kingfisher --version`` prints (``kingfisher 2.18.1``), or ``''``."""
    found = re.search(r'(\d+\.\d+\.\d+)', text or '')
    return found.group(1) if found else ''


def env_without_egress(base):
    """The environment of a detection pass: ``base`` (the caller's environment), with every proxy variable pointing at a closed local port."""
    env = dict(base)
    env.update(NO_EGRESS_ENV)
    return env
