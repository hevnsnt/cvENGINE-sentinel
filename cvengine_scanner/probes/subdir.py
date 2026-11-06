"""Applications mounted under a subdirectory of a web host, copied from cvENGINE's ``cveFeed.subdir_apps`` (the ``subdir_probe`` kind).

A product installed under a path (``/jira``, ``/grafana``, ``/phpmyadmin`` ...) is invisible to every check that reads only the front page.
cvENGINE picks the hosts and decides what an answer means and what is stored; this module asks and reads what answered. For each host of a
task, within the task's request budget:

- one GET of a path no site serves (the baseline that tells a real mount from a server that answers every path alike), ``/robots.txt`` and
  ``/sitemap.xml``;
- one GET of each curated mount path the task names (``subdir_apps.json``, about 40 paths, each with the product it indicates and the
  signatures that confirm it) and of at most ``MAX_LEADS`` directories the host's own data shows (the ones cvENGINE sends from its crawled and
  archived URLs, plus those ``robots.txt`` and ``sitemap.xml`` name);
- GET only, no body, no cookie, no credential, redirects never followed, at the task's ``gap``; every request passes the task's scope policy and
  this Sentinel's floor. A host with a virtual-host address (``connect_ip``) is asked at that address with its name as the Host header.

Only 200, 301, 302, 401 and 403 count as "something is there". Every such answer is reported with its fingerprint and, when it is not the
server's answer to a path nobody serves, what the response says it is (``identify``). An edge that challenges ends the host (reported, never
retried or worked around); a plain 429 or 503 ends it too (``busy``). A path the policy refuses, or that could not be asked, is simply not
reported as probed: cvENGINE never retires an earlier find on it.
"""
import functools
import json
import re
import time
from collections import Counter
from http.client import HTTPException
from pathlib import Path
from urllib.parse import urlsplit

from . import http, names
from .policy import ScopePolicy
from .vhost import Gap, _Asker, authority, clamp_gap, fingerprint_of, similar

DATA_FILE = Path(__file__).with_name('subdir_apps.json')
THERE = (200, 301, 302, 401, 403)  # the only answers that mean "something is there"
CONFIRM = 0.7  # a signature at or above this names the product; below it the path is a lead with a hint
BASELINE_PATH = '/.cvengine-probe/404'
ROBOTS_PATH, SITEMAP_PATH = '/robots.txt', '/sitemap.xml'
MAX_LEADS = 10
MAX_HOSTS = 10
MAX_PATHS = 100
MIN_REQUESTS, MAX_REQUESTS = 10, 150
BODY_SCAN = 64 * 1024
SOURCES = ('crawled', 'archive')
NOISE = frozenset({
    'assets', 'static', 'images', 'image', 'img', 'css', 'js', 'fonts', 'font', 'media', 'files', 'file', 'uploads', 'upload', 'download', 'downloads',
    'wp-content', 'wp-includes', 'wp-admin', 'wp-json', 'cgi-bin', 'api', 'search', 'tag', 'tags', 'category', 'categories', 'page', 'pages', 'node',
    'user', 'users', 'login', 'logout', 'content', 'themes', 'theme', 'sites', 'public', 'dist', 'build', 'vendor', 'lib', 'libs', 'scripts', 'script',
    'styles', 'style', 'template', 'templates', 'resources', 'res', 'inc', 'include', 'includes', 'tmp', 'cache', 'data', 'news', 'blog', 'about',
    'contact', 'products', 'product', 'services', 'service', 'support', 'help', 'faq', 'cart', 'checkout', 'account', 'profile', 'sitemap', 'feed', 'rss',
})
_SEGMENT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$')
_MOUNT = re.compile(r'^/[A-Za-z0-9][A-Za-z0-9_-]{1,39}/$')
_PLAIN_PATH = re.compile(r'/[A-Za-z0-9][A-Za-z0-9_./-]{0,58}')
_ROBOTS_LINE = re.compile(r'(?im)^\s*(?:dis)?allow:\s*(/\S*)')
_SITEMAP_LOC = re.compile(r'(?is)<loc>\s*([^<\s]{1,500})\s*</loc>')


# ----------------------------------------------------------------------------- the curated data

class CatalogueError(ValueError):
    """The data file is not what it must be (a path that is not a plain mount path, a duplicate, a pattern that does not compile)."""


@functools.lru_cache(maxsize=1)
def catalogue():
    """The curated entries with their patterns compiled: ``[{'path', 'product', 'indicates', 'signatures': [(where, regex, confidence)],
    'version': [(where, regex)]}]``. Validated on load: every path is a plain absolute mount path, paths and products are unique."""
    raw = json.loads(DATA_FILE.read_text(encoding='utf-8'))
    entries, paths, products = [], set(), set()
    for item in raw:
        path, product = item.get('path'), item.get('product')
        if not isinstance(path, str) or not _PLAIN_PATH.fullmatch(path) or '..' in path:
            raise CatalogueError(f'not a plain mount path: {path!r}')
        if not product or path in paths or product in products or not item.get('indicates'):
            raise CatalogueError(f'duplicate or incomplete entry: {path}')
        paths.add(path)
        products.add(product)
        try:
            signatures = [(s['where'], re.compile(s['regex']), float(s['confidence'])) for s in item['signatures']]
            version = [(v['where'], re.compile(v['regex'])) for v in item.get('version', [])]
        except (KeyError, re.error, ValueError) as exc:
            raise CatalogueError(f'{path}: {exc}') from None
        entries.append({'path': path, 'product': product, 'indicates': item['indicates'], 'signatures': signatures, 'version': version})
    return entries


def curated_paths():
    return [entry['path'] for entry in catalogue()]


# ----------------------------------------------------------------------------- reading a response (pure)

def _value(response, where):
    if where == 'title':
        title = response.get('title')
        return http.page_title(response.get('body') or '') if title is None else title
    if where == 'body':
        return (response.get('body') or '')[:BODY_SCAN]
    if where == 'location':
        return str(response.get('location') or '')
    headers = {k.lower(): v for k, v in (response.get('raw_headers') or response.get('headers') or {}).items()}
    return str(headers.get(where.split(':', 1)[1], ''))


def identify(response, path=''):
    """``{'product', 'confidence', 'source', 'version', 'indicated'}`` for what the response says it is, or None. Every entry's signatures are
    tried on the response (a mount can hold a product the path does not suggest), the strongest signature wins and the requested path's own
    entry wins a tie. ``version`` is '' unless one of the product's own version patterns reads it from the response. A signature below
    ``CONFIRM`` leaves ``confidence`` low: cvENGINE treats that as a lead."""
    best = None
    for entry in catalogue():
        for where, pattern, confidence in entry['signatures']:
            if pattern.search(_value(response, where)):
                rank = (confidence, entry['path'] == path)
                if best is None or rank > best[0]:
                    best = (rank, entry, f'{where}:{pattern.pattern[:30]}')
    if best is None:
        return None
    (confidence, _), entry, source = best
    version = ''
    for where, pattern in entry['version']:
        found = pattern.search(_value(response, where))
        if found:
            version = found.group(1)[:100]
            break
    return {'product': entry['product'], 'confidence': confidence, 'source': source[:48], 'version': version, 'indicated': entry['path']}


def _location_key(location):
    """Where a redirect leads, without host or query: a server that sends every path to its login page sends them all to the same place."""
    if not location:
        return ''
    try:
        return (urlsplit(location.strip()).path or '/').lower()[:200]
    except ValueError:
        return ''


def is_catch_all(fp, baselines):
    """Whether a path's answer is the answer the server gives to a path nobody serves (or to its front page): not a mount."""
    for base in baselines:
        if not base:
            continue
        if 300 <= fp['status'] < 400 and 300 <= base['status'] < 400:
            if _location_key(fp['location']) == _location_key(base['location']):
                return True
        elif similar(fp, base):
            return True
    return False


def mount_of(url_or_path):
    """The mount directory (``/portal/``) a crawled or archived URL points into, or None for a root-level page, an asset or a common
    directory that holds content, not an application."""
    try:
        path = urlsplit(url_or_path).path or ''
    except ValueError:
        return None
    segments = [s for s in path.split('/') if s]
    if not segments or (len(segments) < 2 and not path.endswith('/')):
        return None
    segment = segments[0]
    if not _SEGMENT.match(segment) or segment.lower() in NOISE or (len(segment) == 2 and segment.isalpha()):
        return None
    return f'/{segment}/'


def robots_paths(body):
    return [m.group(1) for m in _ROBOTS_LINE.finditer(body or '')][:200]


def sitemap_paths(body, host):
    out = []
    for m in _SITEMAP_LOC.finditer((body or '')[:BODY_SCAN]):
        try:
            parts = urlsplit(m.group(1))
        except ValueError:
            continue
        if (parts.hostname or '').lower() == host.lower():
            out.append(parts.path or '/')
    return out[:500]


def lead_plan(seen, urls_by_source, known):
    """``[(path, source)]`` for at most ``MAX_LEADS`` mount directories: the ones cvENGINE sent (``seen``: ``[{'path', 'count', 'source'}]``,
    most often seen first) with the ones ``urls_by_source`` (``{source: [url or path]}``: ``robots.txt`` and ``sitemap.xml``) add, most often seen
    first, excluding the curated paths and ``known``."""
    counts, source_of = Counter(), {}
    for item in seen:
        if item['path'] not in known:
            counts[item['path']] += item['count']
            source_of.setdefault(item['path'], item['source'])
    for source, urls in urls_by_source.items():
        for url in urls:
            mount = mount_of(url)
            if mount and mount not in known:
                counts[mount] += 1
                source_of.setdefault(mount, source)
    return [(path, source_of[path]) for path, _n in counts.most_common(MAX_LEADS)]


# ----------------------------------------------------------------------------- the task

def _fingerprint(raw):
    if raw is None:
        return None
    try:
        return {'status': int(raw['status']), 'title': str(raw['title'])[:200], 'length': int(raw['length']), 'location': str(raw['location'])[:200],
                'server': str(raw['server'])[:60]}
    except (KeyError, TypeError, ValueError):
        raise ValueError('a stored front page is malformed') from None


def _host(raw):
    if not isinstance(raw, dict):
        return None
    ident, name, scheme, port = raw.get('id'), raw.get('name'), raw.get('scheme'), raw.get('port')
    if not all(isinstance(v, str) and v for v in (ident, name)) or scheme not in ('http', 'https'):
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    name = names.clean(name)
    if not name or len(name) > 253 or any(c.isspace() or ord(c) < 32 or c in '/\\@' for c in name):
        return None
    connect_ip = raw.get('connect_ip')
    if connect_ip is not None and (not isinstance(connect_ip, str) or not names.is_ip(connect_ip)):
        return None
    leads = []
    for lead in raw.get('leads') or []:
        if (not isinstance(lead, dict) or not isinstance(lead.get('path'), str) or not _MOUNT.match(lead['path']) or lead.get('source') not in SOURCES
                or isinstance(lead.get('count'), bool) or not isinstance(lead.get('count'), int) or lead['count'] < 1):
            return None
        leads.append({'path': lead['path'], 'count': lead['count'], 'source': lead['source']})
    return {'id': str(ident)[:300], 'name': name, 'scheme': scheme, 'port': port, 'connect_ip': connect_ip.strip('[]') if connect_ip else None,
            'root': _fingerprint(raw.get('root')), 'leads': leads[:25]}


def sweep_host(host, paths, budget, ask, policy):
    """The report of one host: its baseline, what answered and what was asked. ``ask(url, connect_ip=)`` is one paced GET."""
    name, scheme, port, connect_ip = host['name'], host['scheme'], host['port'], host['connect_ip']
    base = f'{scheme}://{authority(name, port, scheme)}'
    state = {'state': 'done', 'stopped': False, 'requests': 0, 'challenge': None}

    def get(path):
        """One GET, or None (stopped, over budget, refused, no answer). A challenge or a busy server ends this host's sweep."""
        if state['stopped'] or state['requests'] >= budget:
            return None
        state['requests'] += 1
        try:
            response = ask(base + path, connect_ip=connect_ip)
        except ValueError:
            policy.refuse(name)
            return None
        except (OSError, HTTPException):
            return None
        if response.get('challenge'):
            state.update(state='challenged', stopped=True, challenge={'edge': str(response['challenge'])[:60], 'status': int(response.get('status') or 0),
                                                                      'path': path[:500]})
            return None
        if (response.get('status') or 0) in (429, 503):
            state.update(state='busy', stopped=True)
            return None
        return response

    baseline_response = get(BASELINE_PATH)
    baseline = fingerprint_of(baseline_response) if baseline_response is not None else None
    baselines = [baseline, host['root']]
    robots = get(ROBOTS_PATH) if not state['stopped'] else None
    sitemap = get(SITEMAP_PATH) if not state['stopped'] else None
    seen_urls = {'robots': robots_paths(robots.get('body')) if robots and robots.get('status') == 200 else [],
                 'sitemap': sitemap_paths(sitemap.get('body'), name) if sitemap and sitemap.get('status') == 200 else []}
    plan = [(path, 'curated') for path in paths] + lead_plan(host['leads'], seen_urls, set(paths))
    probed, answers = [], []
    for path, source in plan:
        response = get(path)
        if response is None:  # skipped (a challenge, the budget) or failed: nothing was learned
            continue
        probed.append(path)
        fp = fingerprint_of(response)
        if fp['status'] not in THERE:
            continue
        found = None if is_catch_all(fp, baselines) else identify(response, path)
        answers.append({'path': path, 'source': source, 'fingerprint': fp, 'found': found})
    out = {'id': host['id'], 'state': state['state'], 'requests': state['requests'], 'baseline': baseline, 'probed': probed[:200],
           'answers': answers[:200]}
    if state['challenge']:
        out['challenge'] = state['challenge']
    return out


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic):
    """Run a ``subdir_probe`` task: ``target['hosts']`` and the curated ``target['paths']`` under ``target['scope']``, at most
    ``target['max_requests']`` requests per host, ``target['gap']`` seconds between requests. Returns ``{'hosts': [...], 'touched', 'refused'}``.
    ``probe(url, policy, max_bytes=, connect_ip=)`` replaces the network (tests)."""
    raw = target.get('hosts') if isinstance(target.get('hosts'), list) else []
    if not raw or len(raw) > MAX_HOSTS:
        raise ValueError(f'a task names between 1 and {MAX_HOSTS} hosts')
    hosts = [_host(h) for h in raw]
    if any(h is None for h in hosts):
        raise ValueError('a host is malformed')
    paths = target.get('paths')
    if not isinstance(paths, list) or not paths or len(paths) > MAX_PATHS or not all(isinstance(p, str) and _PLAIN_PATH.fullmatch(p) and '..' not in p for p in paths):
        raise ValueError('the curated paths are malformed')
    budget = target.get('max_requests')
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise ValueError('max_requests is malformed')
    budget = min(MAX_REQUESTS, max(MIN_REQUESTS, budget))
    policy = ScopePolicy(target.get('scope'))
    ask = _Asker(policy, Gap(clamp_gap(target.get('gap')), sleep, clock), probe or http.probe_url)
    out = [sweep_host(host, list(dict.fromkeys(paths)), budget, ask, policy) for host in hosts]
    return {'hosts': out, 'touched': policy.touched, 'refused': policy.refused}
