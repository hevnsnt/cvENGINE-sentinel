"""A validation re-test's reads of a page, copied from cvENGINE's ``cveFeed.validation`` and ``cveFeed.probes`` (the ``page_read`` kind).

cvENGINE re-tests a finding on a host it already knows. Two of those re-tests are a read of the host's own pages, and the server no longer sends them
itself; a Sentinel does, under the scope policy the task carries (``policy.ScopePolicy``: the names, exclusions and addresses cvENGINE decided when it
built the task, asked at every hop, redirects and script reads included):

``head``       one HEAD of a URL on the host, a GET only when the server answers 405 to HEAD. The status, the ``Server`` and ``X-Powered-By`` headers
               and the title are kept; the body never is. Nothing is followed: a redirect is an answer.
``libraries``  the front page of each web base of the host, then the scripts it loads, each asked in full (never revalidated, no cache), the page and
               every script searched whole (``js_libraries.whole_body``). The files the host was seen to load the library from (``seen_urls``) that the
               pages did not load are fetched too, within what is left of the same per-host script budget, when a page still shows the library: a
               fixed version can be weighed against them. The reading is returned as data; cvENGINE decides what it means for the finding.
``control``    one GET of a path no site serves (``/.cvengine-control-<12 hex>``, nothing else is accepted), for the nuclei result screen: does the host answer
               anything with one page? Returns the status, the redirect target, the length and the SHA-256 of the body with its whitespace collapsed;
               never the body. Nothing is followed.
``readme``     the ``readme.txt`` of up to 8 plugin slugs of a WordPress site (``<base>/wp-content/plugins/<slug>/readme.txt``), the title line of each
               kept (an advisory names a plugin by its title). A slug whose readme gave no title is absent from ``titles``; one that could not be read
               is counted in ``unread``.

Every request is a GET or HEAD without a cookie or a credential, bounded in bytes and time, to a numeric address the policy accepted
(``http.probe_url``). A read that cannot be made is reported with its error: unknown, never "gone" or "fixed".
"""
import hashlib
import logging
import re
import time
from urllib.parse import urljoin, urlsplit

from . import http, js_libraries
from .policy import ScopePolicy
from .version_probes import REQUEST_GAP, _entry_kinds, _scanned, fetch, lazy_libraries, served_by

logger = logging.getLogger(__name__)

MAX_READS = 10         # reads in one task (cvENGINE sends one per check)
MAX_BASES = 6          # web bases of one host
MAX_SEEN = 20          # files a host was seen to load the library from
MAX_SLUGS = 8          # plugin readmes of one readme read
CONTROL_BYTES = 64 * 1024   # the most of a control answer that is read (cvENGINE's nuclei_fp.CONTROL_BYTES)
README_BYTES = 32 * 1024
CONTROL_PATH = re.compile(r'^/\.cvengine-control-[0-9a-f]{12}$')
SLUG = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')
README_TITLE = re.compile(r'^===\s*(.{1,120}?)\s*===', re.M)  # copied from cvENGINE's wpscan_scan.README_TITLE
BATCH_SECONDS = 540    # no read starts after this; the rest are reported as not run and stay due on the server


def _host_of(value):
    return (urlsplit(value or '').hostname or '').lower().rstrip('.')


def _base_ok(base, host):
    """Whether ``base`` is ``scheme://host[:port]`` of ``host`` itself."""
    try:
        parts = urlsplit(base)
        parts.port  # noqa: B018 - a bad port raises here
    except ValueError:
        return False
    return (parts.scheme in ('http', 'https') and bool(parts.hostname) and parts.path in ('', '/') and not parts.query and parts.username is None
            and _host_of(base) == host)


def _site_base_ok(base, host):
    """Whether ``base`` is ``scheme://host[:port]`` of ``host`` with at most a plain path (WordPress installed in a sub directory), no query, no user."""
    try:
        parts = urlsplit(base)
        parts.port  # noqa: B018
    except ValueError:
        return False
    return (parts.scheme in ('http', 'https') and bool(parts.hostname) and not parts.query and not parts.fragment and parts.username is None
            and _host_of(base) == host and bool(re.match(r'^(/[A-Za-z0-9._~-]{1,80}){0,4}/?$', parts.path)) and '..' not in parts.path)


def _entry(raw):
    """One read of a task, or None when it is malformed: ``id`` (the server's own key, echoed back), ``op``, ``host``, and for ``head`` a ``url`` on the host,
    for ``control`` a ``url`` that is a control path on the host, for ``readme`` the ``base`` and the ``slugs``, for ``libraries`` the ``bases`` of the host, the ``library`` key and the ``seen_urls``."""
    if not isinstance(raw, dict):
        return None
    ident, op, host = raw.get('id'), raw.get('op'), raw.get('host')
    if not isinstance(ident, str) or not ident or op not in ('head', 'libraries', 'control', 'readme') or not isinstance(host, str) or not host:
        return None
    host = host.lower().rstrip('.')
    if op == 'readme':
        base, slugs = raw.get('base'), raw.get('slugs')
        if (not isinstance(base, str) or len(base) > 300 or not _site_base_ok(base, host) or not isinstance(slugs, list) or not 1 <= len(slugs) <= MAX_SLUGS
                or not all(isinstance(x, str) and SLUG.match(x) and '..' not in x for x in slugs)):
            return None
        return {'id': ident[:200], 'op': op, 'host': host, 'base': base.rstrip('/'), 'slugs': list(dict.fromkeys(slugs))}
    if op in ('head', 'control'):
        url = raw.get('url')
        if not isinstance(url, str) or len(url) > 2000 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
            return None
        try:
            parts = urlsplit(url)
            parts.port  # noqa: B018
        except ValueError:
            return None
        if parts.scheme not in ('http', 'https') or parts.username is not None or _host_of(url) != host:
            return None  # a read is of the host the task names: what is asked is what the server planned
        if op == 'control' and (parts.query or parts.fragment or not CONTROL_PATH.match(parts.path)):
            return None  # a control read asks for a path no site serves, never a real page
        return {'id': ident[:200], 'op': op, 'host': host, 'url': url}
    bases = raw.get('bases')
    if not isinstance(bases, list) or not 1 <= len(bases) <= MAX_BASES or not all(isinstance(b, str) and len(b) <= 300 and _base_ok(b, host) for b in bases):
        return None
    seen = raw.get('seen_urls') if isinstance(raw.get('seen_urls'), list) else []
    return {'id': ident[:200], 'op': op, 'host': host, 'bases': list(dict.fromkeys(b.rstrip('/') for b in bases)),
            'library': raw.get('library') if isinstance(raw.get('library'), str) else '',
            'seen_urls': [u for u in seen[:MAX_SEEN] if isinstance(u, str) and len(u) <= 2000]}


def run_head(url, policy, probe=None):
    """One HEAD of ``url``; a GET only when the answer is 405. Returns ``{'status', 'method', 'server', 'powered_by', 'title'}``. The policy is asked
    first (a refusal raises ``ValueError``); a redirect is not followed."""
    probe = probe or http.probe_url
    host = _host_of(url)
    why = policy.host_refusal(host)
    if why:
        policy.refuse(host)
        raise ValueError(f'not read: the host is {why}')
    answer, used = probe(url, policy, method='HEAD', browser=False), 'HEAD'
    if answer.get('status') == 405:
        answer, used = probe(url, policy, method='GET', max_bytes=http.ROUTE_SAMPLE_BYTES, browser=False), 'GET'
    return {'status': answer.get('status'), 'method': used, 'server': str(answer.get('server') or '')[:300],
            'powered_by': str(answer.get('powered_by') or '')[:300], 'title': str(answer.get('title') or '')[:300]}


def _digest(body):
    """The SHA-256 of ``body`` with its whitespace collapsed (cvENGINE compares the same normal form of the response it holds)."""
    return hashlib.sha256(' '.join(str(body or '').split()).encode('utf-8', 'replace')).hexdigest()


def run_control(url, policy, probe=None):
    """One GET of ``url`` (a control path) and what the host answered: ``{'status', 'location', 'length', 'digest'}``. The policy is asked first (a
    refusal raises ``ValueError``); nothing is followed, no browser headers are sent. The body is hashed and dropped."""
    probe = probe or http.probe_url
    host = _host_of(url)
    why = policy.host_refusal(host)
    if why:
        policy.refuse(host)
        raise ValueError(f'not read: the host is {why}')
    answer = probe(url, policy, method='GET', max_bytes=CONTROL_BYTES, browser=False)
    body = answer.get('body') or ''
    status = answer.get('status')
    return {'status': status if isinstance(status, int) and not isinstance(status, bool) else 0, 'location': str(answer.get('location') or '')[:500],
            'length': min(len(body.encode('utf-8', 'replace')), 300 * 1024), 'digest': _digest(body)}


def run_readme(base, slugs, host, policy, probe=None, sleep=time.sleep):
    """The title of each plugin in ``slugs`` from its ``readme.txt`` under ``base`` (one GET each through ``fetch``: a redirect is followed only to the
    host's apex or ``www`` twin and passes the policy at every hop, a pause between two requests). Returns ``{'titles': {slug: title}, 'asked', 'unread'}``:
    a readme that gave no title is absent, one that could not be read (refused, no answer) is counted in ``unread``, never a title."""
    titles, unread = {}, 0
    for slug in slugs[:MAX_SLUGS]:
        sleep(REQUEST_GAP)
        try:
            got = fetch(f'{base.rstrip("/")}/wp-content/plugins/{slug}/readme.txt', policy, probe=probe, allowed=_group(host), sleep=sleep, max_bytes=README_BYTES)
        except (OSError, ValueError):
            unread += 1
            continue
        found = README_TITLE.search((got or {}).get('body') or '') if 200 <= ((got or {}).get('status') or 0) < 300 else None
        if found:
            titles[slug] = re.sub(r'[^A-Za-z0-9 ._+&()-]', '', found.group(1))[:120]
    return {'titles': titles, 'asked': len(slugs[:MAX_SLUGS]), 'unread': unread}


def read_host_libraries(bases, host, policy, probe=None, sleep=time.sleep, reader=None):
    """The html-libraries read of every web base of ``host`` for a validation re-test: each base's front page through the same gated GET as every probe
    (a redirect is followed only on the host itself, so a redirect to another host is seen as it is), then the scripts of every page through
    ``js_libraries`` (its vetter, one fresh ``Reader`` with the usual budgets, the per-host script limit shared by the bases), past every cache: every
    script is asked for in full (no ETag), and every script and page is searched whole (``js_libraries.whole_body``). Every hop of every request,
    redirects included, passes ``policy``. Returns ``{'pages': [...], 'scanned': {url: _scanned}, 'budget_left': n}``, one page per base: ``outcome``
    is ``read`` (the host's own page answered 2xx and its scripts were read), ``redirect`` (``status`` and ``location``), ``challenged``,
    ``error_page``, ``unanswered`` or ``refused`` (the policy refused the host). A read page carries ``records`` (``js_libraries.resolve``),
    ``entries`` (its scripts with a source), ``skipped`` (scripts it wanted and did not read, with why), ``truncated``, ``read_whole``, ``capped``,
    ``page_truncated``, ``inline`` (``[library key, version]`` inline scripts state), ``inline_unread``, ``scripts``, ``lazy`` (libraries the page adds
    at run time) and ``page_scan`` (the page's own text searched whole)."""
    own = {host}
    scanned = {}
    page_get = lambda url: fetch(url, policy, probe=probe, allowed=own, sleep=sleep)  # noqa: E731
    raw_get = lambda url: fetch(url, policy, probe=probe, allowed=_group(host), sleep=sleep, max_bytes=js_libraries.MAX_SCRIPT_BYTES)  # noqa: E731

    def script_get(url, headers=None):
        # asked in full, never revalidated with an ETag: a 304 would leave nothing to search whole
        try:
            got = raw_get(url)
        except (OSError, ValueError) as exc:
            scanned[url] = {'status': 0, 'whole': False, 'error': 'refused by the scope policy' if isinstance(exc, ValueError) else type(exc).__name__}
            raise
        scanned[url] = _scanned(got)
        return got
    reader = reader or js_libraries.Reader(fresh=True)
    budget = {'left': js_libraries.MAX_SCRIPTS_PER_HOST}
    pages = []
    for base in bases:
        page = {'base': base, 'outcome': '', 'status': 0}
        try:
            first = page_get(base.rstrip('/') + '/') or {}
        except ValueError:
            page['outcome'] = 'refused'
            pages.append(page)
            continue
        except OSError as exc:
            page.update(outcome='unanswered', error=type(exc).__name__)
            pages.append(page)
            continue
        status = first.get('status') or 0
        final = first.get('final_url') or first.get('url') or base
        page.update(status=status, final_url=str(final)[:500])
        if first.get('challenge'):
            page.update(outcome='challenged', challenge=first['challenge'])
        elif 300 <= status < 400:
            page.update(outcome='redirect', location=urljoin(final, (first.get('location') or '').strip())[:500])
        elif 200 <= status < 300 and not served_by(first, base):
            # followed to another host: the host's own answer, when fetch kept it, says which redirect it was
            origin = first.get('redirected_from') or {}
            page.update(outcome='redirect', location=urljoin(origin.get('final_url') or base, (origin.get('location') or '').strip())[:500]
                        if origin.get('location') else str(final)[:500], status=origin.get('status') or status)
        elif not 200 <= status < 300:
            page['outcome'] = 'error_page'
        else:
            body = first.get('body', '')
            entries = js_libraries.parse_page(body, final)
            report, coverage = {}, {}
            records = js_libraries.read_page(entries, final, script_get, js_libraries.vetter(final, policy), budget, before_each=lambda: sleep(REQUEST_GAP),
                                             reader=reader, report=report, coverage=coverage)
            page.update(outcome='read', records=records, skipped=list(report.get('skipped') or [])[:40], truncated=list(report.get('truncated') or [])[:20],
                        scripts=sum(1 for e in entries if e.get('url')), read_whole=coverage.get('read', 0),
                        capped=bool(getattr(entries, 'capped', False)), inline_unread=int(getattr(entries, 'inline_unread', 0)),
                        inline=[list(pair) for pair in getattr(entries, 'inline', ())][:20],
                        lazy=lazy_libraries(body, final, entries), entries=_entry_kinds(entries, final)[:js_libraries.MAX_ENTRIES],
                        page_truncated=bool(first.get('truncated')), page_scan=js_libraries.whole_body(body, page=True))
        pages.append(page)
    return {'pages': pages, 'scanned': scanned, 'budget_left': budget['left']}


def _group(host):
    """The names a script's redirect may lead to: the host and its apex or ``www`` twin (what cvENGINE's ``probes.allowed_names`` lists for it)."""
    return {host, host[4:] if host.startswith('www.') else f'www.{host}'}


def refetch_script(url, host, policy, probe=None, sleep=time.sleep, page_url=None):
    """A script file the host was seen to load the library from, fetched again when the pages did not load it: through ``js_libraries.vetter`` for
    ``page_url`` (its port rule, a third-party or analytics host never, another host only when the policy names it) and the same gated GET as the
    page read. Returns ``_scanned`` (the file searched whole), or ``{'status': 0, 'whole': False, 'error': why}`` when it may not be read."""
    page_url = page_url or f'https://{host}/'
    try:
        refusal = js_libraries.vetter(page_url, policy)(url)
    except Exception:  # noqa: BLE001 - a host that cannot be vetted is not read
        refusal = 'not vetted'
    if refusal:
        return {'status': 0, 'whole': False, 'error': f'not read ({refusal})'}
    try:
        got = fetch(url, policy, probe=probe, allowed={_host_of(url)}, sleep=sleep, max_bytes=js_libraries.MAX_SCRIPT_BYTES)
    except ValueError:
        return {'status': 0, 'whole': False, 'error': 'refused by the scope policy'}
    except OSError as exc:
        return {'status': 0, 'whole': False, 'error': type(exc).__name__}
    return _scanned(got or {})


def _library_records(reading, key):
    """``[(page, record)]``: the record of library ``key`` on every page that was read."""
    return [(page, (page.get('records') or {}).get(key)) for page in reading.get('pages') or []
            if page.get('outcome') == 'read' and (page.get('records') or {}).get(key)]


def fetch_seen(reading, host, library, seen_urls, policy, probe=None, sleep=time.sleep):
    """Fetch, within the read's remaining script budget, each file in ``seen_urls`` that the pages' read did not fetch, when a page still shows
    ``library`` (otherwise nothing can close and nothing is asked). Each lands in ``reading['extra']``; one the budget does not cover is recorded as not
    read. Returns how many were fetched."""
    scanned = reading.get('scanned') or {}
    wanted = [u for u in seen_urls if u not in scanned and u not in reading['extra']]
    if not wanted or not _library_records(reading, library):
        return 0
    page = next((p.get('final_url') or p.get('base') for p in reading.get('pages') or [] if p.get('outcome') == 'read'), None)
    fetched = 0
    for url in wanted[:js_libraries.MAX_SCRIPTS_PER_HOST]:
        if reading.get('budget_left', 0) <= 0:
            reading['extra'][url] = {'status': 0, 'whole': False, 'error': 'page host limit'}
            continue
        reading['budget_left'] = reading.get('budget_left', 0) - 1
        reading['extra'][url] = refetch_script(url, host, policy, probe=probe, sleep=sleep, page_url=page)
        fetched += 1
    return fetched


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic, max_seconds=BATCH_SECONDS):
    """Run a ``page_read`` task: ``target['reads']`` (see ``_entry``) under ``target['scope']`` (``policy.ScopePolicy``), one after another.
    Returns ``{'reads': [{'id', 'head' | 'reading' | 'error'}], 'touched': [hosts asked], 'refused': [hosts a hop was refused for]}``. A read whose host the
    policy refuses is not made (its error says so); one that fails is reported with its error, never as an answer. ``probe`` replaces
    ``http.probe_url``, the network (tests): every request still goes through ``fetch`` or ``run_head``, so the policy is asked at every hop."""
    policy = ScopePolicy(target.get('scope'))
    raw = target.get('reads') if isinstance(target.get('reads'), list) else []
    if not raw or len(raw) > MAX_READS:
        raise ValueError(f'a task names between 1 and {MAX_READS} reads')
    entries = [e for e in (_entry(item) for item in raw) if e is not None]
    if len(entries) != len(raw):
        raise ValueError('a read is malformed')
    deadline = clock() + max_seconds
    out = []
    for entry in entries:
        if clock() > deadline:
            out.append({'id': entry['id'], 'error': 'not run: the task ran out of time'})
            continue
        why = policy.host_refusal(entry['host'])
        if why:
            policy.refuse(entry['host'])
            out.append({'id': entry['id'], 'error': f'not run: the host is {why}'})
            continue
        try:
            if entry['op'] == 'head':
                out.append({'id': entry['id'], 'head': run_head(entry['url'], policy, probe=probe)})
            elif entry['op'] == 'control':
                out.append({'id': entry['id'], 'control': run_control(entry['url'], policy, probe=probe)})
            elif entry['op'] == 'readme':
                out.append({'id': entry['id'], 'readme': run_readme(entry['base'], entry['slugs'], entry['host'], policy, probe=probe, sleep=sleep)})
            else:
                reading = read_host_libraries(entry['bases'], entry['host'], policy, probe=probe, sleep=sleep)
                reading['extra'] = {}
                fetch_seen(reading, entry['host'], entry['library'], entry['seen_urls'], policy, probe=probe, sleep=sleep)
                out.append({'id': entry['id'], 'reading': reading})
        except Exception as exc:  # noqa: BLE001 - one read failing never stops the rest; the server retries it, never records it as an answer
            logger.info('page_read %s on %s failed: %s', entry['op'], entry['host'], type(exc).__name__)
            out.append({'id': entry['id'], 'error': f'{type(exc).__name__}: {exc}'[:200]})
    return {'reads': out, 'touched': policy.touched, 'refused': policy.refused}
