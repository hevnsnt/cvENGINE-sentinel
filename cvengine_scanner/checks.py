"""The rules an AI-written or approved nuclei template must meet before a Sentinel that is not the built-in scanner runs it (the ``nuclei_validate``
kind, contract version 4).

``readonly_problem`` is the cvENGINE server's own read-only classification (``cveFeed.validation.readonly_problem`` with
``cveFeed.templategen.destination_check`` and its no-alias YAML loader), carried here so a Sentinel judges a template by itself instead of trusting
that the server already did: plain GET, HEAD or OPTIONS requests, no request body, payloads, fuzzing, raw socket data, code, file access, browser,
flow, workflow or out-of-band step, and every destination a placeholder for the host nuclei was pointed at. Both sides test against one corpus of
templates (``fixtures/checks/corpus.json``), so the two cannot drift apart without a test failing on one of them.

``scope_problem`` is stricter than the server's read-only check: a check may reach only the task's own target and port. A literal port on a network
host (``{{Hostname}}:22``) or a ``port`` key would reach another port of the same host (or another loopback port of this machine during the benign
fixture run), so neither is accepted. ``check_problem`` is both, then the allowlist of ``check_allowlist`` (the whole document: YAML that
nuclei's parser reads alike, known keys only, only side-effect-free helpers in any expression, plain requests).

Pure: text in, a reason out (``''`` when acceptable). PyYAML is imported only when a template is read.
"""
import hashlib
import re

MAX_TEMPLATE_BYTES = 200_000  # cveFeed.validation.MAX_INSTALLED_TEMPLATE_BYTES: an AI-written one is at most 20,000 (the server's gate)
SHA256 = re.compile(r'^[0-9a-f]{64}$')

READONLY_METHODS = {'GET', 'HEAD', 'OPTIONS'}
READONLY_FORBIDDEN_KEYS = {'payloads', 'attack', 'fuzzing', 'iterate-all', 'body', 'unsafe', 'race', 'pipeline', 'cookie-reuse',
                           'code', 'javascript', 'headless', 'file', 'flow', 'workflows', 'self-contained', 'protocol-redirects'}
OAST_RE = re.compile(r'interactsh-url|interactsh_(?:protocol|request|response|ip)|interactsh server|\boast\b')
ALLOWED_PROTOCOLS = {'http', 'requests', 'network', 'tcp', 'dns', 'ssl'}
FORBIDDEN_PROTOCOLS = {'code', 'javascript', 'headless', 'file', 'workflows', 'flow'}
ALLOWED_TOP_KEYS = ALLOWED_PROTOCOLS | {'id', 'info', 'variables', 'self-contained', 'stop-at-first-match'}
FORBIDDEN_KEYS = {'self-contained', 'redirects', 'host-redirects', 'max-redirects', 'protocol-redirects', 'unsafe', 'race', 'pipeline',
                  'code', 'javascript', 'headless', 'file', 'flow', 'workflows', 'resolvers', 'proxy',
                  'payloads', 'attack', 'fuzzing', 'iterate-all', 'threads', 'cookie-reuse', 'skip-variables-check', 'body'}
PROTOCOL_SECTIONS = ('http', 'requests', 'network', 'tcp', 'dns', 'ssl')
SAFE_VARS = {'BaseURL', 'RootURL', 'Hostname', 'Host', 'Port', 'FQDN', 'Scheme', 'Path', 'randstr'}
MAX_REQUESTS = 6
HOST_REDIRECT_KEYS = {'host-redirects', 'max-redirects', 'redirects'}
MAX_HOST_REDIRECTS = 3
_VAR_RE = re.compile(r'\{\{\s*([^}]*?)\s*\}\}')
_HOST_OK = re.compile(r'^\{\{(?:Hostname|Host)\}\}(?::\{\{Port\}\}|:\d{1,5})?$')
_OWN_HOST = re.compile(r'^\{\{(?:Hostname|Host)\}\}(?::\{\{Port\}\})?$')  # scope_problem: no literal port


def digest(text):
    """The sha256 (lowercase hex) of ``text`` as UTF-8: the hash the server puts in a ``nuclei_validate`` task as ``template_sha256``."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _load(text):
    """``yaml.safe_load`` that refuses any anchor or alias (a few hundred bytes of nested aliases expand to billions of visits in a walker)."""
    import yaml

    class NoAliasLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            event = self.peek_event()
            if isinstance(event, yaml.events.AliasEvent) or getattr(event, 'anchor', None) is not None:
                raise yaml.constructor.ConstructorError(None, None, 'anchors and aliases are not allowed in a template', event.start_mark)
            return super().compose_node(parent, index)
    return yaml.load(text, Loader=NoAliasLoader)  # noqa: S506 - a SafeLoader subclass


def _only_safe_vars(text):
    return all(name.split('(')[0].strip() in SAFE_VARS or name.startswith('rand_') for name in _VAR_RE.findall(text))


def _bound_http_path(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value) or '\\' in value:
        return False
    return value == '{{BaseURL}}' or value.startswith('{{BaseURL}}/')


def _host_redirect_problem(key, value):
    if key == 'host-redirects':
        return '' if isinstance(value, bool) else 'host-redirects must be true or false'
    if key == 'redirects':
        return '' if value is False else 'redirects to other hosts are not allowed'
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_HOST_REDIRECTS:
        return f'max-redirects must be 0 to {MAX_HOST_REDIRECTS}'
    return ''


def destination_problem(doc):
    """Every request destination is a placeholder for the host nuclei was pointed at: no absolute URL, literal host, redirect to another host,
    resolver or proxy (``cveFeed.templategen.destination_check`` with same-host redirects allowed, as for an installed template)."""
    if not isinstance(doc, dict):
        return 'template must be a mapping'
    for proto in PROTOCOL_SECTIONS:
        if proto not in doc:
            continue
        blocks = doc[proto]
        if not isinstance(blocks, list) or not blocks or any(not isinstance(b, dict) for b in blocks):
            return f'malformed {proto} section'
        for block in blocks:
            for key in ('path', 'raw', 'inputs', 'matchers', 'extractors'):
                if key in block and not isinstance(block[key], list):
                    return f'malformed {proto} {key} list'

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                key = str(k).lower()
                if key in HOST_REDIRECT_KEYS:
                    found = _host_redirect_problem(key, v)
                    if found:
                        return found
                    continue
                if key in FORBIDDEN_KEYS:
                    return f'forbidden key {k!r}'
                found = walk(v)
                if found:
                    return found
        elif isinstance(node, list):
            for v in node:
                found = walk(v)
                if found:
                    return found
        return ''
    reason = walk({k: v for k, v in doc.items() if k != 'info'})
    if reason:
        return reason
    variables = doc.get('variables') or {}
    if not isinstance(variables, dict) or any(str(k).strip() in SAFE_VARS for k in variables):
        return 'template variables must not override built-in target variables'
    requests_seen = 0
    for proto in ('http', 'requests'):
        for block in doc.get(proto) or []:
            for p in block.get('path') or []:
                requests_seen += 1
                if not _bound_http_path(p) or '://' in str(p) or not _only_safe_vars(str(p)):
                    return f'http path must be {{{{BaseURL}}}} or {{{{BaseURL}}}}/path and contain no other URL: {str(p)[:80]!r}'
            for raw in block.get('raw') or []:
                requests_seen += 1
                text = str(raw)
                if '://' in text or not _only_safe_vars(text):
                    return 'raw request contains an absolute URL or an unknown variable'
                first = text.strip().splitlines()[0] if text.strip() else ''
                fields = first.split()
                target = fields[1] if len(fields) == 3 else ''
                relative = target.startswith('/') and not target.startswith('//') and '\\' not in target
                if not (relative or _bound_http_path(target)):
                    return f'raw request line must use /path or {{{{BaseURL}}}}/path: {first[:60]!r}'
                for line in text.splitlines()[1:]:
                    if line.lower().startswith('host:') and not _HOST_OK.match(line.split(':', 1)[1].strip()):
                        return 'raw Host header must be {{Hostname}} or {{Host}}'
    for proto in ('network', 'tcp'):
        for block in doc.get(proto) or []:
            inputs = block.get('inputs') or []
            if not isinstance(inputs, list) or any(not isinstance(i, dict) or i.get('data') for i in inputs):
                return 'network checks may only read banners; outgoing data is not allowed'
            for key in ('host', 'address'):
                values = block.get(key) or []
                for h in values if isinstance(values, list) else [values]:
                    requests_seen += 1
                    if not _HOST_OK.match(str(h)):
                        return f'network {key} must be {{{{Hostname}}}} or {{{{Host}}}} (optionally with a port): {str(h)[:60]!r}'
    for block in doc.get('ssl') or []:
        requests_seen += 1
        if isinstance(block, dict) and str(block.get('address', '{{Host}}:{{Port}}')) != '{{Host}}:{{Port}}':
            return 'ssl address must be {{Host}}:{{Port}}'
    for block in doc.get('dns') or []:
        requests_seen += 1
        if isinstance(block, dict) and str(block.get('name', '{{FQDN}}')) != '{{FQDN}}':
            return 'dns name must be {{FQDN}}'
    if requests_seen > MAX_REQUESTS:
        return f'too many requests ({requests_seen}; the limit is {MAX_REQUESTS})'
    return ''


def _parse(text):
    """``(doc, problem)``: the template as data, or why it is not one."""
    if not isinstance(text, str) or not text or '\0' in text or len(text.encode('utf-8', 'replace')) > MAX_TEMPLATE_BYTES:
        return None, 'template not validated: empty or too large'
    import yaml
    try:
        doc = _load(text)
    except (yaml.YAMLError, RecursionError):  # a document nested thousands deep is no template
        return None, 'template not validated: not valid YAML, or nested too deeply'
    if not isinstance(doc, dict):
        return None, 'template not validated: not a template'
    return doc, ''


def readonly_problem(text):
    """Why a template may not run on a Sentinel other than the built-in scanner, or ``''`` when its text is read-only (the server's
    ``cveFeed.validation.readonly_problem``, rule for rule)."""
    doc, problem = _parse(text)
    if problem:
        return problem
    if set(doc) & FORBIDDEN_PROTOCOLS or set(doc) - ALLOWED_TOP_KEYS:
        return 'template not validated: unsupported protocol or top-level feature'
    destination = destination_problem(doc)
    if destination:
        return f'template not validated: {destination}'

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key).lower() in READONLY_FORBIDDEN_KEYS:
                    return f'template not validated: it uses {key!r}'
                found = walk(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = walk(value)
                if found:
                    return found
        return ''
    problem = walk({k: v for k, v in doc.items() if k != 'info'})
    if problem:
        return problem
    if not set(doc) & ALLOWED_PROTOCOLS:
        return 'template not validated: no protocol section'
    if OAST_RE.search(text.lower()):
        return 'template not validated: it uses out-of-band checks'
    for proto in ('http', 'requests'):
        for block in doc.get(proto) or []:
            if 'raw' not in block and str(block.get('method', 'GET')).upper() not in READONLY_METHODS:
                return f'template not validated: http method {str(block.get("method")).upper()} is not read-only'
            for raw in block.get('raw') or []:
                first = str(raw).strip().splitlines()[0] if str(raw).strip() else ''
                verb = first.split(' ', 1)[0].upper()
                if verb not in READONLY_METHODS:
                    return f'template not validated: raw request method {verb or "?"} is not read-only'
    return ''


def scope_problem(text):
    """Why a read-only template would reach something other than the task's own target and port, or ``''``. A network or tcp block may name
    only ``{{Hostname}}`` or ``{{Host}}``, optionally with ``:{{Port}}``, and no ``port`` key."""
    doc, problem = _parse(text)
    if problem:
        return problem
    for proto in ('network', 'tcp'):
        for block in doc.get(proto) or []:
            if not isinstance(block, dict):
                return f'template not validated: malformed {proto} section'
            if 'port' in {str(k).lower() for k in block}:
                return f'template not validated: a {proto} check names its own port; it may reach only the port of the task'
            for key in ('host', 'address'):
                values = block.get(key) or []
                for h in values if isinstance(values, list) else [values]:
                    if not _OWN_HOST.match(str(h)):
                        return f'template not validated: a {proto} {key} names a port of its own ({str(h)[:60]!r}); it may reach only the port of the task'
    return ''


def check_problem(text):
    """``readonly_problem``, then ``scope_problem``, then the allowlist (``check_allowlist.allowlist_problem``: one YAML document nuclei and PyYAML read
    alike, known keys only, only side-effect-free helpers and listed names in every expression, plain requests with no body, annotation,
    credential or steering header): the whole rule for a check a Sentinel that is not the built-in scanner runs. It refuses, it never raises: an
    error while judging a template is itself the reason to refuse it."""
    from cvengine_scanner import check_allowlist
    try:
        return readonly_problem(text) or scope_problem(text) or check_allowlist.allowlist_problem(text)
    except Exception as exc:  # noqa: BLE001 - a gate that crashes must refuse
        return f'template not validated: it could not be checked ({type(exc).__name__}), so it is refused'
