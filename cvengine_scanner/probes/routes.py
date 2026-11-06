"""How a web route answers an anonymous request, copied from cvENGINE's ``cveFeed.route_auth`` (the ``route_probe`` kind).

cvENGINE plans the routes (the hosts' web bases, the common paths, the paths bbot saw), keeps the ledger and stores what comes back
(``RouteAuth`` rows, auth changes, zombie and retired routes, the secrets inventory). This module asks and classifies: for each route one plain
GET (no credential, no cookie, a redirect is never followed, at most ``ROUTE_SAMPLE_BYTES`` of a body, ``ROOT_READ_BYTES`` of a front page), then

- the answer is classified as open, a login page, a session requirement, single sign-on, a redirect or not found (``classify``, pure);
- an answer that could be a route's own is compared with the server's answer for a path that cannot exist in the same directory and of the same
  kind (``soft404``): the same answer is ``catch_all``, no evidence that the route is there;
- a front page's own scripts (and the public library CDNs and same-site hosts the scope policy names) are read for the libraries their files
  state (``js_libraries``), the way the server read them;
- the kinds of sensitive data a body serves are counted and masked (``sensitive``); a credential is also returned as its value, over the
  authenticated channel only, for the server's secrets inventory, which fingerprints and masks it at once.

Every request is made through ``http.probe_url``: the task's scope policy is asked at every hop and every address, and the hosts touched are
reported. A route that could not be asked is reported with an error, never as a state: cvENGINE reads it as unknown and asks again.
Classification, planning rules and limits are the server's own; ``tests/fixtures/route_classify.json`` is the table both sides are held to.
"""
import concurrent.futures
import logging
import re
import secrets
import time
from urllib.parse import urljoin, urlsplit, urlparse

from .. import soft404
from . import fingerprint, http, js_libraries, sensitive
from .http import page_title  # noqa: F401 - the same title reader as the server's route_auth.page_title
from .version_probes import challenge_of

logger = logging.getLogger(__name__)

MAX_HOSTS = 25  # hosts in one task
MAX_URLS_PER_HOST = 20  # cveFeed.route_auth.MAX_URLS_PER_HOST
MAX_URL_LENGTH = 2000
PER_REQUEST_GAP = 0.2  # seconds between two requests to the same host
HOST_WORKERS = 8  # hosts probed side by side; one host's routes go one after another
BATCH_SECONDS = 1200  # no route starts after this; the rest are reported as not run and stay due on the server
ROUTE_SAMPLE_BYTES = http.ROUTE_SAMPLE_BYTES
ROOT_READ_BYTES = http.ROOT_READ_BYTES
MAX_BASELINES_PER_BASE = 8
MAX_BASELINES_PER_HOST = 12
MAX_SCRIPT_URLS = 8
CATCH_ALL = 'catch_all'
STATES = ('open', 'login', 'sso', 'session_required', 'redirect', 'not_found', 'error', CATCH_ALL)

# (host regex, vendor label, optional path regex that must also match)
SSO_PROVIDERS = (
    (re.compile(r'^(login\.microsoftonline\.com|login\.microsoft\.com|[^.]+\.b2clogin\.com)$', re.I), 'Entra ID', None),
    (re.compile(r'^accounts\.google\.com$', re.I), 'Google', None),
    (re.compile(r'(^|\.)(okta\.com|oktapreview\.com|okta-emea\.com)$', re.I), 'Okta', None),
    (re.compile(r'(^|\.)auth0\.com$', re.I), 'Auth0', None),
    (re.compile(r'(^|\.)onelogin\.com$', re.I), 'OneLogin', None),
    (re.compile(r'(^|\.)(pingidentity\.com|pingone\.com)$', re.I), 'Ping', None),
    (re.compile(r'(^|\.)duosecurity\.com$', re.I), 'Duo', None),
    (re.compile(r'(^|\.)cloudflareaccess\.com$', re.I), 'Cloudflare Access', None),
    (re.compile(r'^login\.salesforce\.com$', re.I), 'Salesforce', None),
    (re.compile(r'^github\.com$', re.I), 'GitHub', re.compile(r'^/login/oauth', re.I)),
)
SSO_PATH_RE = re.compile(r'/(adfs/ls|saml2?|sso|oauth2?/authorize|openid-connect/auth|auth/realms/|connect/authorize)', re.I)
LOGIN_PATH_RE = re.compile(r'(?:^|[/_-])(login|log-in|signin|sign-in|logon|session/new|wp-login\.php|account/login|user/login|auth)'
                           r'(/|\.|\?|$)', re.I)
# '[^<>]' stops each scan at the next tag, so a body of repeated '<input ' / '<meta ' with no '>' is read in linear time
PASSWORD_INPUT_RE = re.compile(r'<input\b[^<>]{0,1000}?type=["\']?password', re.I)
LOGIN_TITLE_RE = re.compile(r'\b(sign in|log in|login|logon|anmelden|connexion)\b', re.I)
SSO_BODY_RE = re.compile(r'(okta-sign-in|auth0|keycloak|SAMLRequest|microsoftonline|Sign in with (Microsoft|Google|Okta)|'
                         r'login\.microsoftonline)', re.I)
SSO_BODY_PROVIDER = (('okta', 'Okta'), ('auth0', 'Auth0'), ('keycloak', 'Keycloak'), ('samlrequest', 'SAML'),
                     ('microsoft', 'Entra ID'), ('google', 'Google'))
META_REFRESH_RE = re.compile(r'<meta\b[^<>]{0,1000}?http-equiv=["\']?refresh[^<>]{0,1000}?content=["\'][^"\'<>]{0,1000}?url=([^"\'<>\s]+)', re.I)
_STUB_TITLE_RE = re.compile(r'maintenance|under construction|coming soon|cookie|consent|privacy preferences|just a moment|redirect|loading', re.I)
_JS_REDIRECT_RE = re.compile(r'(?:window|document|top|self)\.location(?:\.href)?\s{0,4}=|location\.(?:replace|assign)\(', re.I)


# ----------------------------------------------------------------------------- classification (pure)

def sso_provider(location, base_url=''):
    """The identity provider label when ``location`` (absolute or relative to ``base_url``) points at a known one, or an
    empty string."""
    parsed = urlparse(urljoin(base_url, location))
    host, path = (parsed.hostname or '').lower(), parsed.path or ''
    for host_re, label, path_re in SSO_PROVIDERS:
        if host_re.search(host) and (path_re is None or path_re.search(path)):
            return label
    return ''


def _redirect_state(location, base_url):
    """(state, provider) for a redirect target: single sign-on, a login page, or just a redirect."""
    provider = sso_provider(location, base_url)
    if provider:
        return 'sso', provider
    path = urlparse(urljoin(base_url, location)).path or ''
    if SSO_PATH_RE.search(path):
        return 'sso', ''
    if LOGIN_PATH_RE.search(path):
        return 'session_required', ''
    return 'redirect', ''


def _truncated(probe):
    """Whether the body of a probe answer stopped at the read limit (a page longer than what was read)."""
    if 'truncated' in probe:
        return bool(probe['truncated'])
    size = probe.get('bytes')
    if size is None:
        size = len((probe.get('body') or '').encode('utf-8', 'ignore'))
    return size >= int(probe.get('read_limit') or ROUTE_SAMPLE_BYTES)


def _stub_page(body, title, page_scripts):
    """Whether a front page is a stand-in rather than the site: a meta refresh or script redirect, a maintenance, consent or loading page,
    or a page that loads no script of its own. Such a page proves nothing about which libraries the site loads."""
    if META_REFRESH_RE.search(body or '') or _STUB_TITLE_RE.search(title or ''):
        return True
    if not any(entry.get('url') for entry in page_scripts):
        return True
    return len(body or '') < 4096 and bool(_JS_REDIRECT_RE.search(body or ''))


def classify(probe):
    """``(state, evidence)`` for one probe (the dict ``http.probe_url`` returns: status, location, www_authenticate, cookies,
    content_type, body, title, url). ``evidence`` carries the markers matched, the bytes sampled and the cookie names; it
    never carries the body."""
    status = probe.get('status') or 0
    body = probe.get('body') or ''
    evidence = {'markers': [], 'bytes': probe.get('bytes', len(body)), 'cookies': sorted(probe.get('cookies') or [])}
    markers = evidence['markers']
    # what the response says it runs: kept (headers cut short, never the body) so the host record can show it
    for key, field in (('server', 'server'), ('powered_by', 'powered_by')):
        if probe.get(field):
            evidence[key] = str(probe[field])[:100]
    page_url = probe.get('url', '')
    root = (urlparse(page_url).path or '/') == '/'
    scripts = fingerprint.script_sources(body, page_url)[0] if root else []
    # the script names are hints only (a library and a version a file name carries, never a query string); _read_scripts replaces them
    # with what the files themselves state
    found = fingerprint.from_response(probe.get('server', ''), probe.get('powered_by', ''), body, probe.get('content_type', ''),
                                      scripts=scripts, headers=probe.get('headers'))
    if probe.get('headers') and root:
        evidence['headers'] = probe['headers']  # the root page's kept response headers: host metadata for the AI and the host page
    # a front page's scripts are the host's: its own page (2xx) or the page it serves for "/" when that is missing (a hosted site's 404
    # still loads its scripts); never an edge's challenge, a redirect or an error
    script_root = root and js_libraries.page_status(probe.get('status')) and not challenge_of(probe)
    page_scripts = js_libraries.parse_page(body, page_url) if script_root else []
    if any(entry['url'] for entry in page_scripts):
        evidence['page_scripts'] = {'page': page_url, 'scripts': page_scripts}  # read by _read_scripts, which removes it before anything is returned
    if script_root:
        # the front page was parsed for its scripts: a library no script of it is cannot be this page's, and a ?ver= string a theme's or
        # plugin's script carries is that script's cache-buster. Only a complete page that is the site itself proves an absence: one cut at
        # the read limit, a redirect stub or a page that loads no script at all does not
        evidence['script_page'] = {**js_libraries.script_page(page_scripts), 'truncated': _truncated(probe),
                                   'stub': _stub_page(body, probe.get('title') or '', page_scripts)}
    if found:
        evidence['fingerprints'] = found
        evidence['fingerprint_names'] = [f['name'] for f in found]  # flat text for search: the dicts also hold the word "source"

    def done(state, provider='', redirect_to=''):
        evidence['provider'] = provider
        evidence['redirect_to'] = redirect_to
        return state, evidence

    if status == 401:
        header = (probe.get('www_authenticate') or '').strip()
        scheme = header.split(' ', 1)[0] if header else ''
        evidence['www_authenticate'] = scheme
        if scheme.lower() in ('negotiate', 'ntlm'):
            return done('sso', 'Windows integrated')
        markers.append('401')
        return done('session_required')
    if status == 403:
        markers.append('forbidden')
        evidence['reason'] = 'forbidden'
        return done('session_required')
    if 300 <= status < 400:
        location = (probe.get('location') or '').strip()
        if not location:
            return done('redirect')
        state, provider = _redirect_state(location, probe.get('url', ''))
        markers.append('redirect')
        return done(state, provider, location[:2000])
    if status in (404, 410):
        return done('not_found')
    if 200 <= status < 300 or status == 405:
        title = probe.get('title') or ''
        state, provider = 'open', ''
        if PASSWORD_INPUT_RE.search(body):
            markers.append('password_input')
            state = 'login'
        elif title and LOGIN_TITLE_RE.search(title):
            markers.append('login_title')
            state = 'login'
        match = SSO_BODY_RE.search(body)
        if match:
            markers.append('sso_marker')
            state = 'sso'
            lowered = match.group(0).lower()
            provider = next((label for key, label in SSO_BODY_PROVIDER if key in lowered), '')
        if state == 'open':
            refresh = META_REFRESH_RE.search(body)
            if refresh:
                target, found = refresh.group(1), _redirect_state(refresh.group(1), probe.get('url', ''))
                markers.append('meta_refresh')
                if found[0] != 'redirect':
                    return done(found[0], found[1], target[:2000])
                return done('open')
        return done(state, provider)
    return done('error')


def analyse(result):
    """Everything kept from one probe response: its state and evidence, and the kinds of sensitive data in it (counts and masked samples), plus
    the credentials' values for the server's inventory. The body is read here and dropped."""
    state, evidence = classify(result)
    content_type = (result.get('content_type') or '')[:100]
    body = result.get('body') or ''
    found = sensitive.scan_text(body) if sensitive.is_text(content_type) else {}
    credentials = sensitive.credential_values(body) if any(t in found for t in sensitive.CREDENTIAL_TYPES) else []
    return {'credentials': credentials, 'status': result.get('status'), 'title': (result.get('title') or '')[:300], 'content_type': content_type,
            'state': state, 'evidence': evidence, 'sensitive': found, 'sensitive_score': sensitive.sensitive_score(found),
            # what the page was, for comparing it with the answer to a path that cannot exist; held here, never returned. The front page is never
            # compared with a path that cannot exist (_against_missing_page): no fingerprint, so a 300 KB page is not normalised for nothing
            'fp': (None if (urlparse(result.get('url') or '').path or '/') == '/' else
                   soft404.fingerprint(result, urlparse(result.get('url') or '').path)), 'bytes': result.get('bytes', len(body))}


# ----------------------------------------------------------------------------- the server's answer for a path that cannot exist

def _split_route(path):
    """``(directory, shape, extension)`` of a route path: the directory it is in (``/api/v1/``), and how a name for it that cannot exist
    should look, because servers answer a missing ``.php`` file, a missing directory and a missing bare name differently."""
    directory = path.rsplit('/', 1)[0] + '/'
    name = path.rsplit('/', 1)[1]
    if path.endswith('/') and path != '/':
        return path.rsplit('/', 2)[0] + '/', 'slash', ''
    ext = name.rsplit('.', 1)[1].lower() if '.' in name else ''
    return directory, ('ext' if re.fullmatch(r'[a-z0-9]{1,5}', ext) else 'bare'), ext


def _baseline_path(directory, shape, ext):
    name = f'cvengine-{secrets.token_hex(6)}'
    return directory + (name + '/' if shape == 'slash' else f'{name}.{ext}' if shape == 'ext' else name)


def _baseline(base, directory, shape, ext, get, known, sleep):
    """The fingerprint of the server's answer for a path that cannot exist in ``directory``, of the kind ``shape`` names, read once per
    web base, directory and shape. ``known`` is one host's. None when it could not be read or this host or base has used up its requests for it."""
    key = (base, directory, shape, ext if shape == 'ext' else '')
    if key not in known:
        if len(known) >= MAX_BASELINES_PER_HOST or sum(1 for k in known if k[0] == base) >= MAX_BASELINES_PER_BASE:
            return None
        sleep(PER_REQUEST_GAP)
        path = _baseline_path(directory, shape, ext)
        try:
            known[key] = soft404.fingerprint(get(base + path), path)
        except Exception:  # noqa: BLE001 - no answer to compare with: the route stands as it was read
            known[key] = None
    return known[key]


def _against_missing_page(answer, url, get, known, sleep=time.sleep):
    """``answer`` for ``url`` as it stands, or as ``catch_all`` when the server gives the same answer for a path that cannot exist in the
    same directory and of the same kind (soft404). Every answer that could be a route's own is compared, not only an open one: a server
    that sends every path to its login page, or answers 403 to all of them, says as little about a route as one that serves a shell.
    The root is never compared."""
    parts = urlparse(url)
    path = parts.path or '/'
    status = answer.get('status') or 0
    if path == '/' or status in (404, 410) or not (200 <= status < 400 or status in (401, 403, 405)) or answer.get('state') == 'error':
        return answer
    fp = answer.get('fp')
    if fp is None:
        return answer
    base = f'{parts.scheme}://{parts.netloc}'
    directory, shape, ext = _split_route(path)
    # where a path that cannot exist is asked for: beside the route, in its own kind and as a plain name (what ffuf, feroxbuster and
    # dirsearch calibrate per directory). Below the route is not asked: a server that answers every path under /api alike has an /api
    for kind in dict.fromkeys((shape, 'bare')):
        missing = _baseline(base, directory, kind, ext if kind == 'ext' else '', get, known, sleep)
        if missing is not None and soft404.same(fp, missing):
            evidence = {**answer['evidence'], 'catch_all': {**soft404.public(missing), 'kind': kind,
                                                            'note': 'the same answer as for a path that cannot exist'}}
            return {**answer, 'state': CATCH_ALL, 'evidence': evidence, 'sensitive': {}, 'sensitive_score': 0, 'credentials': []}
    return answer


# ----------------------------------------------------------------------------- the front page's scripts

def script_urls(entries, page_url):
    """The front page's scripts on its own host (same scheme, host and port), absolute, without query strings, at most MAX_SCRIPT_URLS: what the
    secrets scan reads besides the routes. A script on any other host is left to the library reader's own vetting."""
    base = urlparse(page_url)
    out = []
    for entry in entries or ():
        src = (entry.get('url') or entry.get('src')) if isinstance(entry, dict) else entry
        if not isinstance(src, str) or not src.strip():
            continue
        try:
            url = urlparse(urljoin(page_url, src.strip()))
        except ValueError:
            continue
        if url.scheme not in ('http', 'https') or (url.scheme, url.netloc.lower()) != (base.scheme, base.netloc.lower()):
            continue
        clean = url._replace(query='', fragment='').geturl()[:2000]
        if clean not in out:
            out.append(clean)
        if len(out) >= MAX_SCRIPT_URLS:
            break
    return out


def _read_scripts(result, get_script, policy, budget, reader, sleep=time.sleep):
    """Read the scripts the front page loads and record the libraries their own files state: the page's own host, the same site and public library
    CDNs the scope policy names, at most ``budget['left']`` scripts for the host and MAX_SCRIPT_BYTES each, through the same bounded, anonymous
    GET as every route check with the same gap between requests. Every copy of a library is kept in ``evidence['libraries']`` with the one that
    runs marked; the fingerprints name the libraries by what the files say, a file name only when the file could not be read."""
    evidence = result.get('evidence') or {}
    page = evidence.pop('page_scripts', None) or {}
    entries, page_url = page.get('scripts') or [], page.get('page') or ''
    if not entries:
        return
    own = script_urls(entries, page_url)
    if own:
        evidence['script_urls'] = own  # the page's own scripts, read again by the server's secrets_scan stage
    coverage = {}
    records = js_libraries.read_page(entries, page_url, get_script, js_libraries.vetter(page_url, policy), budget,
                                     before_each=lambda: sleep(PER_REQUEST_GAP), reader=reader, coverage=coverage)
    if isinstance(evidence.get('script_page'), dict):  # how many of the page's scripts were read whole: a script not read may hold anything
        evidence['script_page']['unread'] = max(0, coverage.get('scripts', 0) - coverage.get('read', 0))
    # a file-name hint gives way only to a library the page's scripts were resolved for; any other stays as it was
    resolved = {r['product'].lower() for r in records.values()}
    hints = {f['name'] for f in evidence.get('fingerprints') or []
             if f.get('source') == 'script:filename' and f['name'].split(':', 1)[0].strip().lower() in resolved}
    kept = [f for f in evidence.get('fingerprints') or [] if f['name'] not in hints]
    found = fingerprint.extend(kept, js_libraries.names_of(records))
    if records:
        evidence['libraries'] = records
    if found:
        evidence['fingerprints'] = found
        evidence['fingerprint_names'] = [f['name'] for f in found]
    else:
        evidence.pop('fingerprints', None)
        evidence.pop('fingerprint_names', None)


# ----------------------------------------------------------------------------- a task

def _group(raw):
    """One host of a task: ``{'host', 'urls'}`` with every URL on that host (http or https, no credentials), or None when it is malformed."""
    if not isinstance(raw, dict) or not isinstance(raw.get('host'), str) or not raw['host'] or not isinstance(raw.get('urls'), list):
        return None
    host = raw['host'].strip().lower().rstrip('.')
    if len(raw['urls']) > MAX_URLS_PER_HOST or not raw['urls']:
        return None
    urls = []
    for url in raw['urls']:
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH or any(ord(c) <= 32 or ord(c) == 127 for c in url):
            return None
        try:
            parts = urlsplit(url)
            parts.port  # noqa: B018 - a bad port raises here
        except ValueError:
            return None
        if parts.scheme not in ('http', 'https') or parts.username is not None or parts.password is not None:
            return None
        if (parts.hostname or '').lower().rstrip('.') != host:
            return None  # a route is the host's own: what is asked is what the server planned for that host
        if url not in urls:
            urls.append(url)
    return {'host': host, 'urls': urls}


def _row(url, result):
    return {'id': url, 'status': result.get('status') if isinstance(result.get('status'), int) else None, 'title': result['title'],
            'content_type': result['content_type'], 'state': result['state'], 'evidence': result['evidence'], 'sensitive': result['sensitive'],
            'sensitive_score': result['sensitive_score'], 'bytes': int(result.get('bytes') or 0),
            'credentials': [{'type': t, 'value': v} for t, v in result.get('credentials') or []]}


def run_host(host, urls, policy, probe=None, reader=None, sleep=time.sleep, clock=time.monotonic, deadline=None):
    """The rows for one host's routes, one after another (PER_REQUEST_GAP between requests): ``{url: row}``. ``probe(url, policy, **kw)`` replaces
    ``http.probe_url`` (tests)."""
    probe = probe or http.probe_url
    reader = reader if reader is not None else js_libraries.Reader()

    def get(url, max_bytes=ROUTE_SAMPLE_BYTES, headers=None):
        return probe(url, policy, max_bytes=max_bytes, **({'headers': headers} if headers else {}))

    def get_script(url, headers=None):  # a library file is read further than a page
        return get(url, max_bytes=js_libraries.MAX_SCRIPT_BYTES, headers=headers)

    out = {}
    why = policy.host_refusal(host)
    if why:
        policy.refuse(host)
        return {url: {'id': url, 'error': f'not run: the host is {why}'} for url in urls}
    scripts_left = {'left': js_libraries.MAX_SCRIPTS_PER_HOST}  # the host's scripts read, over both its web bases
    missing_pages = {}  # web base -> the answer to a path that cannot exist, read once if a route came out open
    for i, url in enumerate(urls):
        if deadline is not None and clock() > deadline:
            out[url] = {'id': url, 'error': 'not run: the task ran out of time'}
            continue
        if i:
            sleep(PER_REQUEST_GAP)
        try:
            root = (urlparse(url).path or '/') == '/'
            result = _against_missing_page(analyse(get(url, max_bytes=ROOT_READ_BYTES if root else ROUTE_SAMPLE_BYTES)), url, get, missing_pages, sleep)
            _read_scripts(result, get_script, policy, scripts_left, reader, sleep)
            out[url] = _row(url, result)
        except Exception as exc:  # noqa: BLE001 - a timeout or refused connection is not an auth state; the server asks again
            logger.info('route probe of %s failed: %s', host, type(exc).__name__)
            out[url] = {'id': url, 'error': f'{type(exc).__name__}: {exc}'[:200]}
    return out


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic, workers=HOST_WORKERS, max_seconds=BATCH_SECONDS):
    """Run a ``route_probe`` task: ``target['hosts']`` (``[{'host', 'urls'}]``, see ``_group``) under ``target['scope']`` (``policy.ScopePolicy``).
    Returns ``{'routes': [{'id': url, ...}], 'touched': [hosts asked], 'refused': [hosts a hop was refused for]}``. A route whose host the policy
    refuses is not asked (its error says so); a route that fails is reported with its error and no state, never as clean."""
    from .policy import ScopePolicy
    policy = ScopePolicy(target.get('scope'))
    raw = target.get('hosts') if isinstance(target.get('hosts'), list) else []
    if not raw or len(raw) > MAX_HOSTS:
        raise ValueError(f'a task names from 1 to {MAX_HOSTS} hosts')
    groups = [_group(item) for item in raw]
    if any(g is None for g in groups):
        raise ValueError('a host of the task is malformed')
    reader = js_libraries.Reader()  # one task's script budget, shared by every host
    deadline = clock() + max_seconds
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(run_host, g['host'], g['urls'], policy, probe, reader, sleep, clock, deadline) for g in groups]
        results = [future.result() for future in futures]
    rows = []
    for group, got in zip(groups, results):
        rows += [got[url] for url in group['urls'] if url in got]
    return {'routes': rows, 'touched': policy.touched, 'refused': policy.refused}
