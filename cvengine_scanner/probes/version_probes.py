"""Version and identity probes, copied from cvENGINE's ``cveFeed.probes``: the probe table, the GET that follows a redirect only where the task's
scope policy allows, the pure readers of the answers, and one probe run against one web base.

cvENGINE plans which probes a host needs (``plan_for_host``, the ledger, the per-scan cap) and stores what they find (``ProbeObservation`` rows,
technologies, correlation). A Sentinel runs the plan it is handed (``run_batch``, the ``http_probe`` kind) and returns the observations; every hop
of every request, redirects and script reads included, is asked of the task's ``policy.ScopePolicy``, and the hosts actually asked are reported.

A probe only ever sends a GET, never a cookie or a credential, caps its requests, response sizes and time, and pins the vetted address
(``http.probe_url``)."""
import itertools
import logging
import re
import time
from urllib.parse import urljoin, urlsplit

from . import cms, fingerprint, http, js_libraries, versions

logger = logging.getLogger(__name__)

SERVICE = 'probe'
WEB = '*web'  # a probe that helps with any web product
MAX_PROBES_PER_HOST = 5
MAX_REDIRECTS = 2
REQUEST_GAP = 0.2  # seconds between two requests to one host
RETRY_DELAYS = (3.0,)  # a "try later" (429, 503) is asked again once after this pause; a challenge is not asked again at all
NMAP_TIMEOUT = 150
PROBE_PATH = '/.cvengine-probe/404'  # a path no site serves: the answer is the server's own error page
EDGE_STATUSES = (202, 403, 429, 503)
BODY_SCAN = 64 * 1024  # a response is read for markers in its first 64 KB only: a hostile page cannot make a pattern cost time by being long

# ----------------------------------------------------------------------------- the catalogue (data)
# A rule reads one response: ``request`` is the index of the request in the probe, ``where`` is body, title or header:<name>, ``regex`` the
# pattern, ``version`` the group (or groups, joined with dots) holding the version, ``kind`` version or identity, ``outcome`` hidden when
# the pattern shows the product answering without a version, and ``variant`` which look-alike product answered.
PROBES = (
    {'id': 'headers-root', 'label': 'Response headers and page markers of the front page', 'family': 'http', 'leads': WEB,
     'requests': (('GET', '/'),), 'handler': 'headers', 'safety': 'one GET of the front page'},
    {'id': 'error-page', 'label': 'Server error page signature (nginx, Apache, Tomcat, Jetty, IIS footers)', 'family': 'http',
     'leads': r'nginx|openresty|apache|httpd|tomcat|jetty|iis|internetinformation|express|nextjs|springboot|ingress', 'requests': (('GET', PROBE_PATH),),
     'safety': 'one GET of a path no site serves', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'<center>nginx/(\d+\.\d+\.\d+)</center>', 'product': 'nginx', 'version': 1,
          'kind': 'version', 'confidence': 0.95, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<center>openresty/(\d+\.\d+\.\d+(?:\.\d+)?)</center>', 'product': 'OpenResty', 'version': 1,
          'kind': 'version', 'confidence': 0.95, 'source': 'body:openresty-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<hr><center>nginx</center>', 'product': 'nginx', 'kind': 'version', 'outcome': 'hidden',
          'confidence': 0.8, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<hr><center>nginx</center>', 'product': 'nginx', 'variant': 'nginx', 'kind': 'identity',
          'confidence': 0.7, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'(?i)Apache/(\d+\.\d+\.\d+) (?:\([^)]{1,30}\) )?Server at', 'product': 'Apache HTTP Server',
          'version': 1, 'kind': 'version', 'confidence': 0.9, 'source': 'body:apache-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'Apache Tomcat/(\d+\.\d+\.\d+[\w.-]*)', 'product': 'Apache Tomcat', 'version': 1,
          'kind': 'version', 'confidence': 0.9, 'source': 'body:tomcat-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'Powered by Jetty:// (\d+\.\d+\.\d+[\w.-]*)', 'product': 'Jetty', 'version': 1,
          'kind': 'version', 'confidence': 0.9, 'source': 'body:jetty-error-page'},
         {'request': 0, 'where': 'title', 'regex': r'IIS (\d+\.\d+) Detailed Error', 'product': 'Microsoft IIS', 'version': 1,
          'kind': 'version', 'confidence': 0.85, 'source': 'title:iis-detailed-error'},
         {'request': 0, 'where': 'body', 'regex': r'^[ \t]{0,8}default backend - 404[ \t]{0,8}$', 'product': 'nginx', 'variant': 'kubernetes-ingress',
          'kind': 'identity', 'confidence': 0.8, 'source': 'body:default-backend'},
         {'request': 0, 'where': 'body', 'regex': r'<pre>Cannot GET /', 'product': 'Express', 'variant': 'express', 'kind': 'identity',
          'confidence': 0.8, 'source': 'body:express-404'},
         {'request': 0, 'where': 'body', 'regex': r'Whitelabel Error Page', 'product': 'Spring Boot', 'variant': 'spring-boot', 'kind': 'identity',
          'confidence': 0.85, 'source': 'body:spring-whitelabel'},
         {'request': 0, 'where': 'body', 'regex': r'__NEXT_DATA__|This page could not be found', 'product': 'Next.js', 'variant': 'next.js',
          'kind': 'identity', 'confidence': 0.6, 'source': 'body:next-404'},
     )},
    {'id': 'nginx-variants', 'label': 'Tell nginx apart from nginx-ui, Nginx Proxy Manager and an ingress controller', 'family': 'http',
     'leads': r'nginx', 'requests': (('GET', '/'), ('GET', '/api/')), 'safety': 'two GETs', 'rules': (
         {'request': 0, 'where': 'title', 'regex': r'(?i)\bnginx ui\b', 'product': 'nginx', 'variant': 'nginx-ui', 'kind': 'identity',
          'confidence': 0.85, 'source': 'title:nginx-ui'},
         {'request': 0, 'where': 'title', 'regex': r'(?i)nginx proxy manager', 'product': 'nginx', 'variant': 'nginx-proxy-manager',
          'kind': 'identity', 'confidence': 0.85, 'source': 'title:nginx-proxy-manager'},
         {'request': 1, 'where': 'body', 'regex': r'"version"\s*:\s*\{\s*"major"\s*:\s*(\d+)\s*,\s*"minor"\s*:\s*(\d+)\s*,\s*"revision"\s*:\s*(\d+)',
          'product': 'Nginx Proxy Manager', 'version': (1, 2, 3), 'kind': 'version', 'confidence': 0.9, 'source': 'body:npm-api'},
     )},
    {'id': 'nextjs-version', 'label': 'Next.js version from the framework script the page loads', 'family': 'http', 'leads': r'nextjs',
     'requests': (('GET', '/'),), 'handler': 'nextjs', 'safety': 'the front page and up to three of its own framework scripts'},
    {'id': 'html-libraries', 'label': 'JavaScript library versions from the script files themselves', 'family': 'http',
     'leads': r'jquery|bootstrap|angular|lodash|moment|underscore|vue|react|swiper|datatables', 'requests': (('GET', '/'),),
     'handler': 'libraries', 'safety': 'the front page and up to six of the scripts it loads (its own site or a public library CDN, 300 KB each)'},
    {'id': 'drupal-changelog', 'label': 'Drupal version from its change log', 'family': 'http', 'leads': r'drupal',
     'requests': (('GET', '/core/CHANGELOG.txt'), ('GET', '/CHANGELOG.txt')), 'safety': 'two GETs', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'(?m)^Drupal (\d+\.\d+(?:\.\d+)?)', 'product': 'Drupal', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:drupal-changelog'},
         {'request': 1, 'where': 'body', 'regex': r'(?m)^Drupal (\d+\.\d+(?:\.\d+)?)', 'product': 'Drupal', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:drupal-changelog'},
     )},
    {'id': 'joomla-manifest', 'label': 'Joomla version from its manifest', 'family': 'http', 'leads': r'joomla',
     'requests': (('GET', '/administrator/manifests/files/joomla.xml'), ('GET', '/language/en-GB/en-GB.xml'),
                  ('GET', '/administrator/components/com_content/content.xml')), 'safety': 'three GETs of version files', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:joomla-manifest'},
         {'request': 1, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:joomla-language'},
         {'request': 2, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.8, 'source': 'body:joomla-component'},
     )},
    {'id': 'magento-version', 'label': 'Magento version from its admin login page and release notes', 'family': 'http', 'leads': r'magento',
     'requests': (('GET', '/magento_version'), ('GET', '/admin'), ('GET', '/RELEASE_NOTES.txt')), 'safety': 'three GETs, no login attempt', 'rules': (
         # /magento_version answers "Magento/2.4 (Community)": the branch, never the patch release, so it names the product and no version
         {'request': 0, 'where': 'body', 'regex': r'^Magento/\d+\.\d+ \((?:Community|Enterprise)\)', 'product': 'Magento', 'kind': 'version',
          'outcome': 'hidden', 'confidence': 0.7, 'source': 'body:magento_version'},
         {'request': 1, 'where': 'body', 'regex': r'Magento ver\. (\d+\.\d+\.\d+(?:-p\d+)?)', 'product': 'Magento', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:magento-admin'},
         {'request': 2, 'where': 'body', 'regex': r'(?m)^=== (\d+\.\d+\.\d+\.\d+) ===', 'product': 'Magento', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:magento-release-notes'},
     )},
    {'id': 'robots-txt', 'label': 'robots.txt hints at the CMS behind the site', 'family': 'http', 'leads': WEB, 'requests': (('GET', '/robots.txt'),),
     'safety': 'one GET', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'(?i)Disallow:\s*/wp-admin/|/wp-sitemap\.xml', 'product': 'WordPress', 'variant': 'wordpress',
          'kind': 'identity', 'confidence': 0.6, 'source': 'body:robots-txt'},
     )},
    {'id': 'wordpress-detect', 'label': 'Is this WordPress? (login page, REST API, generator, readme)', 'family': 'http', 'leads': r'wordpress|wpengine|woocommerce',
     'requests': (('GET', '/'), ('GET', '/wp-login.php'), ('GET', '/wp-json/')), 'handler': 'wordpress',
     'safety': 'up to four GETs, browser-like headers, no login attempt'},
    {'id': 'nmap-version-all', 'label': 'nmap service probe at full intensity with the safe banner scripts', 'family': 'nmap', 'leads': '*port',
     'safety': 'nmap -sV --version-all on one port, safe scripts only'},
)
BY_ID = {p['id']: p for p in PROBES}
IDENTITY_PROBES = ('error-page', 'nginx-variants')  # the probes that say which look-alike product answers, whatever the version
# the safe scripts for a service (all are in nmap_scan.NSE_SCRIPTS, which is the reviewed list)
NMAP_SCRIPTS = {'http': 'http-server-header,http-headers,http-generator,http-title,ssl-cert,banner', 'ssh': 'ssh2-enum-algos,ssh-hostkey,banner',
                'mysql': 'mysql-info', 'redis': 'redis-info', 'memcached': 'memcached-info', 'mongodb': 'mongodb-info',
                'ms-sql': 'ms-sql-info', 'smtp': 'banner', 'ftp': 'banner,ftp-anon', 'imap': 'banner', 'pop3': 'banner'}
# products that only look like another product by name: an advisory for one of these is not an advisory for the base product
LOOKALIKES = {'nginx': {'ingressnginx', 'nginxingress', 'nginxui', 'nginxproxymanager', 'nginxunit', 'nginxrtmpmodule'}}
LOOKALIKE_VARIANTS = {'nginx': {'nginx-ui', 'nginx-proxy-manager', 'kubernetes-ingress'}}
PLAIN_VARIANTS = {'nginx': 'nginx', 'express': 'express', 'next.js': 'next.js'}


def _compiled():
    for probe in PROBES:
        for rule in probe.get('rules', ()):
            rule['_re'] = re.compile(rule['regex'], re.M)
    return True


_COMPILED = _compiled()


def _token(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


def challenge_of(response):
    """The edge that challenged or blocked this answer ('' when it is the site's own answer): Cloudflare's challenge header or page, an
    Akamai, Sucuri or Imperva block page, or a 202, 403, 429 or 503 an edge sent with no origin signature. cvENGINE never tries to get past
    one; it records that the edge answered and says what the owner can allow."""
    headers = {k.lower(): v for k, v in (response.get('headers') or {}).items()}
    body = (response.get('body') or '')[:20000]
    lowered = body.lower()
    if headers.get('cf-mitigated') == 'challenge' or 'cf-browser-verification' in lowered or '_cf_chl_opt' in lowered \
            or ('just a moment' in lowered and 'cloudflare' in lowered):
        return 'Cloudflare'
    if 'sucuri website firewall' in lowered or 'access denied - sucuri' in lowered:
        return 'Sucuri'
    if 'incapsula incident' in lowered or '_incapsula_' in lowered:
        return 'Imperva'
    if 'reference #' in lowered and 'edgesuite' in lowered:
        return 'Akamai'
    status = response.get('status') or 0
    edges = versions.edges_from_headers(headers)
    if status in EDGE_STATUSES and edges and not (response.get('title') or '').strip():
        return edges[0]
    return ''


def fetch(url, policy, probe=None, sleep=time.sleep, allowed=None, max_bytes=None, headers=None, hop=None):
    """One probe GET with browser-like headers, following at most MAX_REDIRECTS redirects that stay inside ``allowed`` (the names of this host's
    group: apex and www answer for each other) and that ``policy`` (the task's ``ScopePolicy``: names, exclusions, addresses) accepts at every
    hop, and ``hop(host)`` too when given (a further rule of the caller: '' when the host may be asked, else why not). A refusal raises
    ValueError. A "try later" (429, 503) is asked again once after a pause; an edge challenge is never retried and never pushed against: it is
    returned with ``challenge`` naming the edge. Returns the probe dict plus ``final_url`` and ``challenge``, and, after a redirect,
    ``redirected_from``: the first answer (the asked URL's own redirect, its headers without a body)."""
    probe = probe or http.probe_url
    last = None
    for attempt in range(len(RETRY_DELAYS) + 1):
        current, hops, first = url, 0, None
        while True:
            if policy.host_refusal(urlsplit(current).hostname or ''):
                policy.refuse(urlsplit(current).hostname or '')
                raise ValueError('probe destination is not allowed')
            if hop is not None and hop(urlsplit(current).hostname or ''):
                raise ValueError('probe destination is outside the scope')
            response = probe(current, policy, max_bytes=max_bytes or http.MAX_PROBE_BYTES, browser=True,
                             **({'headers': headers} if headers else {}))
            location = response.get('location') or ''
            if 300 <= (response.get('status') or 0) < 400 and location and hops < MAX_REDIRECTS:
                nxt = urljoin(current, location)
                if urlsplit(nxt).hostname and (allowed is None or urlsplit(nxt).hostname.lower() in allowed):
                    first = first or {**response, 'url': current, 'final_url': current, 'body': '', 'title': '', 'challenge': ''}
                    current, hops = nxt, hops + 1
                    sleep(REQUEST_GAP)
                    continue
            break
        last = {**response, 'final_url': current, 'challenge': challenge_of(response)}
        if first is not None:
            last['redirected_from'] = first  # the asked host's own answer (a redirect), headers only: what it says about itself
        if last['challenge'] or (response.get('status') or 0) not in (429, 503):
            return last
        if attempt < len(RETRY_DELAYS):
            sleep(RETRY_DELAYS[attempt])
    return last


# ----------------------------------------------------------------------------- reading answers (pure)


# ----------------------------------------------------------------------------- reading answers (pure)

def _observation(kind, product, version='', variant='', outcome='found', confidence=0.0, source='', port=0, url='', evidence=None):
    return {'kind': kind, 'product': str(product)[:120], 'version': str(version)[:100], 'variant': str(variant)[:60], 'outcome': outcome,
            'confidence': confidence, 'source': str(source)[:48], 'port': port, 'url': str(url)[:500], 'evidence': evidence or {}}


def _where(response, where):
    if where == 'body':
        return (response.get('body') or '')[:BODY_SCAN]
    if where == 'title':
        return response.get('title') or ''
    return str((response.get('headers') or {}).get(where.split(':', 1)[1], ''))


def apply_rules(probe, responses):
    """Observations from the probe's data rules over ``responses`` (one response dict per request, in order, None for a request that failed)."""
    out = []
    for rule in probe.get('rules', ()):
        index = rule['request']
        response = responses[index] if index < len(responses) else None
        if not response or response.get('challenge'):  # an edge's challenge page says nothing about the site behind it
            continue
        found = rule['_re'].search(_where(response, rule['where']))
        if not found:
            continue
        number = rule.get('version')
        version = ''
        if isinstance(number, tuple):
            version = '.'.join(found.group(i) for i in number)
        elif number:
            version = found.group(number)
        out.append(_observation(rule['kind'], rule['product'], version, rule.get('variant', ''), rule.get('outcome', 'found'),
                                rule['confidence'], rule['source'], url=probe['requests'][index][1]))
    return out


def observations_from_page(response, source_prefix='page'):
    """Versions and markers a front page states, as observations: its headers (Server and modules, X-Powered-By, ASP.NET and framework
    headers, Via), every generator tag, the library versions in script names and the edge that answered. A product named with no version is
    ``hidden``, not guessed."""
    out = []
    headers = response.get('headers') or {}
    seen = set()

    def add(name, source):
        base, _, version = name.partition(':')
        if (base.lower(), version) in seen:
            return
        seen.add((base.lower(), version))
        hint = source == 'script:filename'  # a library version a script's file name carries: a hint (js_libraries)
        out.append(_observation('version', base, version, outcome='found' if version else 'hidden',
                                confidence=(js_libraries.CONFIDENCE['filename'] if hint else 0.9) if version else 0.7, source=source, url='/'))
    found = fingerprint.from_response(response.get('server', ''), response.get('powered_by', ''), response.get('body', ''),
                                      response.get('content_type', ''), scripts=fingerprint.script_sources(response.get('body', ''), response.get('final_url') or response.get('url', ''))[0],
                                      headers=headers)
    for item in found:
        add(item['name'], item['source'])
    for product in cms.SOURCES:  # a version the front page already carries (Drupal's core scripts); WordPress has its own probe
        if product != 'WordPress':
            version, label = cms.best(product, [('/', response)])
            if version:
                add(f'{product}:{version}', label)
    stated = {o['product'].lower() for o in out if o['kind'] == 'version' and o['version']}
    out = [o for o in out if not (o['kind'] == 'version' and not o['version'] and o['product'].lower() in stated)]  # a version replaces the bare name
    for provider in versions.edges_from_headers({**headers, 'server': response.get('server', '')}):
        out.append(_observation('edge', provider, outcome='edge', confidence=0.8, source='header:edge', url='/'))
    return out


def next_version(body):
    """The Next.js version a framework script states (``window.next={version:"14.1.0"}``), or ''."""
    found = re.search(r'\bnext\s{0,8}=\s{0,8}\{\s{0,8}version\s{0,8}:\s{0,8}["\'](\d+\.\d+\.\d+[\w.-]{0,20})["\']', body or '')
    return found.group(1) if found else ''


_NEXT_CHUNK = re.compile(r'/_next/static/chunks/(?:main|main-app|framework|webpack)-[A-Za-z0-9]{8,}\.js')


def _wordpress_signals(responses):
    """``(signals, version)`` for the WordPress probe: every signature found in a response's headers or body, and the core version a
    generator tag, a readme or a core asset states."""
    signals, generator = [], ''
    for path, response in responses:
        if not response:
            continue
        headers = {k.lower(): v for k, v in (response.get('headers') or {}).items()}
        body = (response.get('body') or '')[:BODY_SCAN]
        link = headers.get('link', '').replace("'", '"')
        if 'rel="https://api.w.org/"' in link:
            signals.append(('header:link-api.w.org', path))
        if 'xmlrpc.php' in headers.get('x-pingback', ''):
            signals.append(('header:x-pingback', path))
        if path == '/wp-login.php' and re.search(r'id=["\']loginform["\']|name=["\']log["\']|wp-submit', body):
            signals.append(('body:login-form', path))
        if path.startswith('/wp-json') and re.search(r'"namespaces"\s*:\s*\[|"wp/v2"|"code"\s*:\s*"rest_', body):
            signals.append(('body:rest-api', path))
        if path == '/' and re.search(r'/wp-content/|/wp-includes/', body):
            signals.append(('body:wp-content', path))
        for product, found in versions.generator_tags(body if path == '/' else ''):
            if product.lower() == 'wordpress':
                signals.append(('meta:generator', path))
                generator = generator or found
    # the version: the generator tag, the core's own versioned assets, the feed, the readme (cms: best source wins, a library's ?ver= never)
    pages = [(path, response) for path, response in responses if response and not (path == '/readme.html' and 'wordpress' not in (response.get('body') or '').lower())]
    candidates = cms.read('WordPress', pages) + ([(generator, 'meta:generator', 0.9)] if generator else [])
    candidates.sort(key=lambda c: -c[2])
    if any(label.startswith('asset:') for _v, label, _c in candidates):
        signals.append(('body:core-asset-ver', '/'))
    return signals, (candidates[0][0] if candidates else '')


def wordpress_observations(responses):
    """The observations of the WordPress probe from its responses ``[(path, response)]``: found (with how and the version when stated),
    challenged (an edge answered and no signature was readable: the owner is told what to allow), absent, or none when nothing answered."""
    signals, version = _wordpress_signals(responses)
    probed = [{'path': path, 'status': (r or {}).get('status'), 'challenge': (r or {}).get('challenge', '')} for path, r in responses]
    if signals:
        order = list(dict.fromkeys(s for s, _ in signals))
        evidence = {'signals': order, 'probed': probed}
        found = [_observation('wordpress', 'WordPress', version, 'wordpress', 'found', min(0.95, 0.6 + 0.1 * len(order)), order[0],
                              url=next(p for s, p in signals), evidence=evidence)]
        from . import wp_core
        answers = dict(responses)
        if wp_core.UPGRADE_PATH in answers:  # the directory an update is extracted into: whether the web server serves it (wp_core)
            state = wp_core.classify_dir(answers[wp_core.UPGRADE_PATH], answers.get(wp_core.UPGRADE_MISSING))
            status = (answers[wp_core.UPGRADE_PATH] or {}).get('status')
            found.append(_observation('wp-upgrade-dir', 'WordPress', variant=state, source='probe:upgrade-dir', url=wp_core.UPGRADE_PATH,
                                      outcome='found' if state in (wp_core.LISTING, wp_core.REACHABLE) else 'absent' if state == wp_core.DENIED else 'hidden',
                                      confidence=0.9 if state in (wp_core.LISTING, wp_core.DENIED) else 0.7 if state == wp_core.REACHABLE else 0.0,
                                      evidence={'status': status, 'state': state}))
        return found
    challenged = next((r['challenge'] for _p, r in responses if r and r.get('challenge')), '')
    reachable = [r for _p, r in responses if r]
    if not reachable:
        return []  # the host did not answer at all: nothing was learned, so nothing is recorded
    if challenged or (reachable and all((r.get('status') or 0) in EDGE_STATUSES for r in reachable)):
        provider = challenged or (versions.edges_from_headers((reachable[0].get('headers') or {})) or ['an edge'])[0]
        evidence = {'probed': probed, 'edge': provider,
                    'hint': (f'The edge ({provider}) answered cvENGINE\'s requests with a challenge or a block, so it could not be read whether '
                             'this host runs WordPress. Allow the scanner\'s address (or its user agent) in the WAF or bot rules for this host, '
                             'then rescan.')}
        return [_observation('wordpress', 'WordPress', outcome='challenged', confidence=0.0, source='edge', evidence=evidence)]
    return [_observation('wordpress', 'WordPress', outcome='absent', confidence=0.7, source='probe', evidence={'probed': probed})]


def technology_names(observations):
    """The Technology names a set of observations adds to a host: a stated version ("nginx:1.24.0"), WordPress and any identity variant
    that is a product of its own. A hidden version adds nothing (the lead stays a lead), and an edge is a hosting fact, not a technology."""
    names = []
    for o in observations:
        library = (o.get('evidence') or {}).get('library') if isinstance(o.get('evidence'), dict) else None
        if o['kind'] == 'version' and isinstance(library, dict) and library.get('tech_names'):
            names += [str(n)[:500] for n in library['tech_names'] if ':' in str(n)]  # the effective copy, or each copy of an unresolved set
        elif o['kind'] == 'version' and o['outcome'] == 'found' and o['version']:
            names.append(f"{o['product']}:{o['version']}")
        elif o['kind'] == 'wordpress' and o['outcome'] == 'found':
            names.append(f"WordPress:{o['version']}" if o['version'] else 'WordPress')
        elif o['kind'] == 'identity' and o['variant'] and o['variant'] not in PLAIN_VARIANTS.values() and o['variant'] != 'kubernetes-ingress':
            names.append(o['variant'])
    return list(dict.fromkeys(names))


# ----------------------------------------------------------------------------- running one probe


# ----------------------------------------------------------------------------- running one probe

def run_http_probe(probe_id, base, allowed, policy=None, get=None, sleep=time.sleep, reader=None):
    """Run one http probe against ``base`` and return its observations. Without ``get`` every request is a ``fetch`` under ``policy`` (the task's
    ``ScopePolicy``, required then); ``get(url)`` replaces that fetch (``run_batch`` and tests). Without a policy no script of another host is read."""
    if get is None and policy is None:
        raise ValueError('a probe needs the task\'s scope policy')
    probe = BY_ID[probe_id]
    # a script is read further than a page (js_libraries.MAX_SCRIPT_BYTES); a test's ``get`` reads both
    script_get = None if get else (lambda url, headers=None: fetch(url, policy, allowed=allowed, sleep=sleep,
                                                                   max_bytes=js_libraries.MAX_SCRIPT_BYTES, headers=headers))
    get = get or (lambda url: fetch(url, policy, allowed=allowed, sleep=sleep))
    handler = probe.get('handler')
    if handler == 'wordpress':
        return wordpress_observations(_wordpress_responses(base, get, sleep))
    responses = []
    for index, (method, path) in enumerate(probe['requests']):
        if index:
            sleep(REQUEST_GAP)
        try:
            responses.append(get(base.rstrip('/') + path))
        except (OSError, ValueError) as exc:
            logger.info('probe %s: %s did not answer (%s)', probe_id, path, type(exc).__name__)
            responses.append(None)
    # fetch follows a redirect inside the host's group (apex and www answer for each other): a page another host served is that host's
    # (its scripts, Server header and generator tags; the other host's own probe records them). Only what this host answered itself, its
    # redirect, is read for it
    responses = [own_answer(r, base) for r in responses]
    out = []
    first = responses[0] if responses else None
    if handler == 'headers' and first:
        out += observations_from_page(first)
    elif handler == 'nextjs' and first:
        out += _nextjs_observations(first, get, sleep)
    elif handler == 'libraries' and first:
        out += _library_observations(first, script_get or get, sleep, policy, reader=reader)
    out += apply_rules(probe, responses)
    if first and first.get('challenge') and not any(o['kind'] == 'edge' for o in out):
        out.append(_observation('edge', first['challenge'], outcome='challenged', confidence=0.8, source='edge-challenge', url=probe['requests'][0][1]))
    return out


def own_answer(response, base):
    """``response`` when ``base``'s own host served it, else that host's own first answer (``redirected_from``: a redirect, headers only),
    or None when there is none to read: what another host served is never attributed to this one."""
    if not response or served_by(response, base):
        return response
    origin = response.get('redirected_from')
    return origin if origin and served_by(origin, base) else None


def served_by(response, base):
    """Whether ``response`` (a ``fetch`` result) is the page of ``base``'s own host: where its redirects ended (``final_url``) is that host. A
    host that only redirects to another one serves none of the scripts of the page it sends visitors to."""
    final = response.get('final_url') or response.get('url') or ''
    try:
        here, there = (urlsplit(base).hostname or '').lower().rstrip('.'), (urlsplit(final).hostname or '').lower().rstrip('.')
    except ValueError:
        return False
    return not there or here == there


def _wordpress_responses(base, get, sleep):
    paths = ['/', '/wp-login.php', '/wp-json/']
    responses = []
    for index, path in enumerate(paths):
        if index:
            sleep(REQUEST_GAP)
        try:
            responses.append((path, get(base.rstrip('/') + path)))
        except (OSError, ValueError):
            responses.append((path, None))
    if _wordpress_signals(responses)[0]:  # only a site that is WordPress is asked for its readme, and for the directory updates are extracted into
        sleep(REQUEST_GAP)
        try:
            responses.append(('/readme.html', get(base.rstrip('/') + '/readme.html')))
        except (OSError, ValueError):
            pass
        for path, _sources in cms.asked('WordPress'):
            if path == '/readme.html' or _wordpress_signals(responses)[1]:
                continue   # the readme was asked above; the feed only while no page states the version
            sleep(REQUEST_GAP)
            try:
                responses.append((path, get(base.rstrip('/') + path)))
            except (OSError, ValueError):
                pass
        from . import wp_core
        sleep(REQUEST_GAP)
        try:
            answer = get(base.rstrip('/') + wp_core.UPGRADE_PATH)
        except (OSError, ValueError):
            answer = None
        responses.append((wp_core.UPGRADE_PATH, answer))
        if wp_core.classify_dir(answer) == wp_core.REACHABLE:  # an empty page: ask once for a path that cannot exist beside it, to tell a catch-all
            sleep(REQUEST_GAP)
            try:
                responses.append((wp_core.UPGRADE_MISSING, get(base.rstrip('/') + wp_core.UPGRADE_MISSING)))
            except (OSError, ValueError):
                pass
    return responses


def _same_host_scripts(response, pattern=None, limit=4):
    page = response.get('final_url') or response.get('url') or ''
    _every, local = fingerprint.script_sources(response.get('body', ''), page, limit=40)
    return [u for u in local if pattern is None or pattern.search(u)][:limit]


def _nextjs_observations(first, get, sleep):
    scripts = _same_host_scripts(first, _NEXT_CHUNK, limit=3)
    for url in scripts:
        sleep(REQUEST_GAP)
        try:
            got = get(url)
        except (OSError, ValueError):
            continue
        number = next_version(got.get('body'))
        if number:
            return [_observation('version', 'Next.js', number, outcome='found', confidence=0.9, source='script:next-chunk', url=urlsplit(url).path)]
    seen = bool(scripts) or '__NEXT_DATA__' in (first.get('body') or '')
    if seen:
        return [_observation('version', 'Next.js', outcome='hidden', confidence=0.7, source='script:next-chunk', url='/')]
    return []


def _library_observations(first, get, sleep, policy, reader=None):
    """The library versions the front page's scripts state (js_libraries): one observation per library, its effective copy's
    version, with every copy and which one runs in ``evidence['library']``. A version from a file name only (the file could not be read or
    states none) is kept at low confidence; a query string is never a version."""
    if not 200 <= (first.get('status') or 0) < 300 or first.get('challenge'):
        return []  # an error page or an edge's challenge is not the site's page: its scripts say nothing (as for the route check)
    page = first.get('final_url') or first.get('url') or ''
    entries = js_libraries.parse_page(first.get('body', ''), page)
    records = js_libraries.read_page(entries, page, get, js_libraries.vetter(page, policy),
                                     {'left': js_libraries.MAX_SCRIPTS_PER_HOST}, before_each=lambda: sleep(REQUEST_GAP), reader=reader)
    return _library_records_observations(records)


def _library_records_observations(records):
    """One ``version`` observation per library record (``js_libraries.resolve``), carrying the record in ``evidence['library']``."""
    out = []
    for record in records.values():
        version = record['version']
        out.append(_observation('version', record['product'], version, source='script:body' if record['version_source'] == 'body' else 'script:filename',
                                confidence=record['version_confidence'] if version else 0.7, outcome='found' if version else 'hidden', url='/',
                                evidence={'library': record}))
    return out


_JS_STRING = re.compile(r'''["']([^"'\s<>]{1,300}?\.js(?:\?[^"'\s<>]{0,200})?)["']''')


def lazy_libraries(body, page_url, entries):
    """The library keys a page names in a script file path that is not one of its ``<script src>`` tags (``parse_page`` ``entries``): a loader,
    a consent manager or inline code that adds the script at run time (``createElement('script')``, a ``src`` set later, an import map). Such a
    copy is not read by the page read, so it can never be ruled out."""
    seen = {e['url'] for e in entries or [] if e.get('url')}
    out = set()
    for found in itertools.islice(_JS_STRING.finditer((body or '').replace('\\/', '/')), 2000):
        url = js_libraries._absolute(found.group(1), page_url)
        key = js_libraries.identify(url)['library'] if url else ''
        if key and url not in seen:
            out.add(key)
    return sorted(out)


def _scanned(got, error=''):
    """What one fetched script says, searched whole (``js_libraries.whole_body``): ``status``, ``whole`` (a 2xx body read to its end, not a
    challenge), ``truncated`` and, for a whole body, ``versions``, ``unplaceable``, ``blocks``, ``loaders`` and ``overflow``."""
    if got is None:
        return {'status': 0, 'whole': False, 'error': error or 'not read'}
    status = got.get('status') or 0
    text = got.get('body') or ''
    raw = got.get('bytes')
    size = raw if isinstance(raw, int) else len(text.encode('utf-8', 'replace'))
    truncated = size >= js_libraries.MAX_SCRIPT_BYTES or bool(got.get('truncated'))
    out = {'status': status, 'truncated': truncated, 'whole': 200 <= status < 300 and not truncated and not got.get('challenge')}
    if not out['whole']:
        out['error'] = ('cut at the read limit' if truncated else f"challenged by {got['challenge']}" if got.get('challenge')
                        else f'answered {status}')
        return out
    return {**out, **js_libraries.whole_body(text)}


def _entry_kinds(entries, page_url):
    """The page's scripts with a source, as a script read needs them: ``url``, ``kind`` (``js_libraries.kind_of``), ``library`` (the library
    its name is, ``js_libraries.identify``) and ``fallback``."""
    out = []
    for entry in entries:
        if entry.get('url'):
            out.append({'url': entry['url'], 'kind': js_libraries.kind_of(entry['url'], page_url),
                        'library': js_libraries.identify(entry['url'])['library'], 'fallback': bool(entry.get('fallback'))})
    return out



# ----------------------------------------------------------------------------- the http_probe kind: a batch of planned probes

MAX_ENTRIES = 300          # planned probes in one task (cvENGINE's per-scan cap is 60 hosts of at most 5 probes)
MAX_OBSERVATIONS = 40      # observations one probe returns at most
HOST_WORKERS = 8           # hosts probed side by side; one host's probes go one after another (REQUEST_GAP between requests)
BATCH_SECONDS = 1200       # no probe starts after this; the rest are reported as not run and stay due on the server
HTTP_PROBES = frozenset(p['id'] for p in PROBES if p['family'] == 'http')


def _entry(raw):
    """One planned probe of a task, or None when it is malformed: ``id`` (the server's own key, echoed back), ``host``, ``probe`` (an http
    probe of ``PROBES``), ``base`` (``scheme://host[:port]`` of that host) and ``allowed`` (the names a redirect may lead to)."""
    if not isinstance(raw, dict):
        return None
    ident, host, probe_id, base = raw.get('id'), raw.get('host'), raw.get('probe'), raw.get('base')
    if not all(isinstance(v, str) and v for v in (ident, host, probe_id, base)) or probe_id not in HTTP_PROBES or len(base) > 300:
        return None
    try:
        parts = urlsplit(base)
        parts.port  # noqa: B018 - a bad port raises here
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.path not in ('', '/') or parts.query or parts.username:
        return None
    if parts.hostname.lower().rstrip('.') != host.lower().rstrip('.'):
        return None  # a base is the host's own: what is asked is what the server planned for that host
    allowed = {str(n).lower().rstrip('.') for n in (raw.get('allowed') or []) if isinstance(n, str)}
    allowed.add(parts.hostname.lower().rstrip('.'))
    return {'id': ident[:200], 'host': host.lower().rstrip('.'), 'probe': probe_id, 'base': base.rstrip('/'), 'allowed': allowed}


def run_batch(target, probe=None, sleep=time.sleep, clock=time.monotonic, workers=HOST_WORKERS, max_seconds=BATCH_SECONDS):
    """Run an ``http_probe`` task: ``target['probes']`` (planned probes, see ``_entry``) under ``target['scope']`` (``policy.ScopePolicy``).
    Returns ``{'probes': [{'id', 'observations', 'error'?}], 'touched': [hosts asked], 'refused': [hosts a hop was refused for]}``. A probe whose host the policy refuses is not run (its
    error says so); a probe that fails is reported with its error and no observations, never as clean. ``probe`` replaces ``http.probe_url``,
    the network (tests): every request still goes through ``fetch``, so the policy is asked at every hop, redirects included."""
    import concurrent.futures

    from .policy import ScopePolicy
    policy = ScopePolicy(target.get('scope'))
    raw = target.get('probes') if isinstance(target.get('probes'), list) else []
    if len(raw) > MAX_ENTRIES:
        raise ValueError(f'a task names at most {MAX_ENTRIES} probes')
    entries = [_entry(item) for item in raw]
    if any(e is None for e in entries):
        raise ValueError('a planned probe is malformed')
    reader = js_libraries.Reader()  # one task's script budget, shared by every host's library probe
    deadline = clock() + max_seconds
    by_host = {}
    for entry in entries:
        by_host.setdefault(entry['host'], []).append(entry)
    results = {}

    def getter(entry):
        if probe is None:
            return None  # run_http_probe builds its own fetch through http.probe_url
        return lambda url, headers=None: fetch(url, policy, probe=probe, allowed=entry['allowed'], sleep=sleep, headers=headers)

    def run_host(host, mine):
        for entry in mine:
            if clock() > deadline:
                results[entry['id']] = {'id': entry['id'], 'observations': [], 'error': 'not run: the task ran out of time'}
                continue
            why = policy.host_refusal(host)
            if why:
                results[entry['id']] = {'id': entry['id'], 'observations': [], 'error': f'not run: the host is {why}'}
                continue
            try:
                found = run_http_probe(entry['probe'], entry['base'], entry['allowed'], policy, get=getter(entry), sleep=sleep, reader=reader)
                results[entry['id']] = {'id': entry['id'], 'observations': found[:MAX_OBSERVATIONS]}
            except Exception as exc:  # noqa: BLE001 - one probe failing never stops the rest; the server retries it, never records it clean
                logger.info('probe %s on %s failed: %s', entry['probe'], host, type(exc).__name__)
                results[entry['id']] = {'id': entry['id'], 'observations': [], 'error': f'{type(exc).__name__}: {exc}'[:200]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for future in [pool.submit(run_host, host, mine) for host, mine in by_host.items()]:
            future.result()
    return {'probes': [results[e['id']] for e in entries if e['id'] in results], 'touched': policy.touched, 'refused': policy.refused}
