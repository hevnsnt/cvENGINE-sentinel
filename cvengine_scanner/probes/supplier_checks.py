"""What a third-party supplier's public services say about their own security, as findings: copied from cvENGINE's ``cveFeed.supplier_checks``
(the ``supplier_check`` kind). Pure evaluators, no network.

Four categories are decided here, on the Sentinel: ``tls`` (the certificate and protocol of the name on 443), ``email`` (SPF, DKIM, DMARC, MTA-STS
and the MailFail checks), ``web`` (HTTP security headers of the front page) and ``exposed`` (a short fixed list of well-known administration
and login pages). The fifth, ``cve``, needs cvENGINE's CVE catalog: the Sentinel reports what the response announces (``suppliers`` returns the
fingerprints, the edge and the distribution) and cvENGINE matches it. The text of what to ask the supplier (``ask_for``) is cvENGINE's too: it
writes it again from the check name and never stores the Sentinel's.
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import tls
from .http import page_title

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4


LEVELS = ('info', 'low', 'medium', 'high', 'critical')


CATEGORIES = ('tls', 'email', 'web', 'exposed', 'cve')


HSTS_MIN_AGE = 15552000  # 180 days


EMAIL_SEVERITY = {'mta_sts_missing': LOW}  # an INFO in the owned-host review that matters for a supplier that receives your mail


@dataclass
class Posture:
    check: str
    severity: int
    title: str
    detail: str
    category: str
    domain: str
    ask: str = ''
    evidence: dict = field(default_factory=dict)


def level(severity):
    return LEVELS[max(0, min(len(LEVELS) - 1, int(severity)))]


def ask_for(check, domain, title=''):
    """The plain-text note about what to ask the supplier, by check name. Never says to do anything to the supplier's systems."""
    if check in ('tls_expired', 'tls_expiring'):
        return f'Ask the supplier to renew and deploy a new certificate for {domain}, and to monitor certificate expiry so it does not happen again.'
    if check == 'tls_hostname_mismatch':
        return f'Ask the supplier to serve a certificate that names {domain} (in its subject alternative names) on that service.'
    if check in ('tls_self_signed', 'tls_untrusted_chain'):
        return f'Ask the supplier to install a certificate from a publicly trusted authority, with its full chain, on {domain}.'
    if check in ('tls_weak_signature', 'tls_weak_key'):
        return f'Ask the supplier to reissue the certificate for {domain} with a SHA-256 signature and an RSA key of at least 2048 bits (or an ECDSA key).'
    if check == 'tls_legacy_protocol':
        return f'Ask the supplier to disable TLS 1.0 and 1.1 on {domain} and keep TLS 1.2 and 1.3.'
    if check.startswith('spf_'):
        return f'Ask the supplier to publish one SPF record for {domain} that lists only its real senders and ends in -all.'
    if check.startswith('dmarc_'):
        return f'Ask the supplier to publish a DMARC policy for {domain} of at least p=quarantine (then p=reject) with an aggregate report address (rua).'
    if check.startswith('dkim_'):
        return f'Ask the supplier to rotate the DKIM keys of {domain} to 2048 bits.'
    if check.startswith('mta_sts_'):
        return f'Ask the supplier to publish an MTA-STS policy for {domain} in mode: enforce and to keep its policy file reachable.'
    if check == 'hsts_missing':
        return f'Ask the supplier to send a Strict-Transport-Security header (max-age of at least six months) from {domain}.'
    if check == 'hsts_weak':
        return f'Ask the supplier to raise the Strict-Transport-Security max-age of {domain} to at least six months.'
    if check == 'security_headers_missing':
        return f'Ask the supplier to add the missing security response headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) on {domain}.'
    if check == 'http_no_redirect':
        return f'Ask the supplier to redirect every plain HTTP request for {domain} to HTTPS.'
    if check == 'no_https':
        return f'Ask the supplier to serve {domain} over HTTPS only, with a valid certificate.'
    if check.startswith('exposed_'):
        return (f'Ask the supplier to take this page off the public internet or restrict it to a VPN or an allow list, and to require '
                f'multi-factor sign-in where it must stay reachable ({domain}).')
    if check.startswith('cve_'):
        return (f'Ask the supplier which version runs on {domain}, whether it already has the fixes for the listed CVEs (a distribution may have '
                'backported them) and by when it will be updated.')
    return f'Ask the supplier to review and fix this on {domain}: {title}'.strip()


def _discriminator(host, domain):
    """Several findings of one check on one domain (a DKIM key per selector, a DANE record per mail host) must not overwrite each other: the
    host they are about, minus the domain, keeps their keys apart. A host that is the domain itself, a ``name:port``, or a service label
    (``_dmarc``) is one per domain and needs none."""
    host = (host or '').strip().lower().rstrip('.')
    if not host or host == domain or host.startswith(f'{domain}:'):
        return ''
    if host.endswith('.' + domain):
        host = host[:-len(domain) - 1]
    return '' if host.startswith('_') else host


def _from_hygiene(found, domain, category):
    key = found.check
    disc = _discriminator(found.host, domain)
    if disc:
        key = f'{key}@{disc}'[:60]
    return Posture(key, EMAIL_SEVERITY.get(found.check, found.severity), found.title[:300], found.detail, category, domain,
                   ask_for(found.check, domain, found.title), {**(found.evidence or {}), 'where': found.host})


def tls_postures(domain, info, now=None):
    """The certificate findings of ``domain:443`` at LOW or worse, from the probed ``info`` (``hygiene.probe_tls``)."""
    return [_from_hygiene(f, domain, 'tls') for f in tls.evaluate_cert({**info, 'host': domain, 'port': 443}, now=now) if f.severity >= LOW]


def email_postures(domain, findings):
    """The SPF, DKIM, DMARC, MTA-STS and MailFail findings of ``domain`` at LOW or worse (``findings`` are ``hygiene.Finding`` rows)."""
    out = []
    for found in findings:
        severity = EMAIL_SEVERITY.get(found.check, found.severity)
        if severity >= LOW:
            out.append(_from_hygiene(found, domain, 'email'))
    return out


def _headers(response):
    return {str(k).lower(): str(v) for k, v in ((response or {}).get('raw_headers') or (response or {}).get('headers') or {}).items()}


def hsts_max_age(value):
    found = re.search(r'max-age\s*=\s*"?(\d+)', value or '', re.IGNORECASE)
    return int(found.group(1)) if found else None


def answered(response):
    """Whether a response is the site's own answer: it came, no edge challenged it and it was not a plain "try later"."""
    return bool(response) and not response.get('challenge') and (response.get('status') or 0) not in (429, 503)


def web_postures(domain, https, http):
    """``(postures, evaluated)`` for the front page over HTTPS and over plain HTTP (each a response dict, or None when nothing answered).
    ``evaluated`` is the set of check-name prefixes this run could decide, so a finding it no longer finds resolves and one it could not
    look at is left alone."""
    out, evaluated = [], set()
    https_ok, http_ok = answered(https), answered(http)
    if https_ok:
        status = https.get('status') or 0
        headers = _headers(https)
        if status < 400:
            evaluated.add('hsts_')
            age = hsts_max_age(headers.get('strict-transport-security'))
            if 'strict-transport-security' not in headers:
                out.append(Posture('hsts_missing', MEDIUM, f'{domain} does not send Strict-Transport-Security',
                                   'Without HSTS a browser can be tricked into using plain HTTP on first contact or after a downgrade.', 'web', domain,
                                   ask_for('hsts_missing', domain), {'header': ''}))
            elif age is not None and age < HSTS_MIN_AGE:
                out.append(Posture('hsts_weak', LOW, f'{domain} sends a short Strict-Transport-Security max-age ({age} seconds)',
                                   'A max-age under six months gives little protection once a visitor has not been back for a while.', 'web', domain,
                                   ask_for('hsts_weak', domain), {'max_age': age}))
        if 200 <= status < 300 and 'html' in (https.get('content_type') or ''):
            evaluated.add('security_headers_missing')
            csp = headers.get('content-security-policy', '')
            missing = []
            if not csp:
                missing.append('Content-Security-Policy')
            if 'x-frame-options' not in headers and 'frame-ancestors' not in csp.lower():
                missing.append('X-Frame-Options')
            if headers.get('x-content-type-options', '').strip().lower() != 'nosniff':
                missing.append('X-Content-Type-Options')
            if missing:
                out.append(Posture('security_headers_missing', LOW, f'{domain} is missing security headers: {", ".join(missing)}',
                                   'These response headers limit what a browser lets a page do (script sources, framing, content sniffing).',
                                   'web', domain, ask_for('security_headers_missing', domain), {'missing': missing}))
    if https_ok or http_ok:
        evaluated.update(('http_no_redirect', 'no_https'))
        http_status = (http or {}).get('status') or 0
        if http_ok and 200 <= http_status < 300:
            if https_ok:
                out.append(Posture('http_no_redirect', MEDIUM, f'{domain} serves its site over plain HTTP instead of redirecting to HTTPS',
                                   f'A plain HTTP request for http://{domain}/ was answered with the page itself (status {http_status}).', 'web', domain,
                                   ask_for('http_no_redirect', domain), {'http_status': http_status}))
            else:
                out.append(Posture('no_https', HIGH, f'{domain} answers only over plain HTTP',
                                   f'Nothing answered over HTTPS, and http://{domain}/ answered with the page itself (status {http_status}).', 'web', domain,
                                   ask_for('no_https', domain), {'http_status': http_status}))
    return out, evaluated


@dataclass(frozen=True)
class Page:
    key: str
    path: str
    label: str
    # (regex over the body and title, severity, label suffix) tried in order; the first that matches names the finding
    rules: tuple
    statuses: tuple = (200,)
    guard_catch_all: bool = False  # a page that looks like the front page is a single-page app answering everything: not a finding


WELL_KNOWN = (
    Page('wp_login', '/wp-login.php', 'WordPress login', ((r'id=["\']loginform["\']|name=["\']log["\']|wp-submit', LOW, ''),)),
    Page('joomla_admin', '/administrator/', 'Joomla administrator login', ((r'Joomla|mod-login|name=["\']passwd["\']', LOW, ''),)),
    Page('phpmyadmin', '/phpmyadmin/', 'phpMyAdmin', ((r'phpMyAdmin', MEDIUM, ''),)),
    Page('tomcat_manager', '/manager/html', 'Apache Tomcat Manager', ((r'Tomcat Web Application Manager', CRITICAL, ''), (r'Tomcat Manager', MEDIUM, '')),
         statuses=(200, 401)),
    Page('server_status', '/server-status', 'Apache server status page', ((r'Apache Server Status', MEDIUM, ''),)),
    Page('login', '/login', 'login page', ((r'Jenkins', MEDIUM, 'Jenkins'), (r'Grafana', LOW, 'Grafana'))),
    Page('solr', '/solr/', 'Apache Solr admin', ((r'Solr Admin', HIGH, ''),)),
    Page('console', '/console/', 'web console', ((r'H2 Console', CRITICAL, 'H2'), (r'WebLogic Server Administration Console|Oracle WebLogic', MEDIUM, 'WebLogic'))),
    Page('owa', '/owa/', 'Outlook on the web login', ((r'Outlook Web App|OutlookWebApp|owaLogon', LOW, ''),), statuses=(200, 302)),
    Page('fortinet', '/remote/login', 'Fortinet SSL VPN login', ((r'FortiGate|fortinet|/remote/logincheck', LOW, ''),)),
    Page('admin', '/admin/', 'administration login', ((r'<input[^>]{0,200}type=["\']password["\']', LOW, ''),), guard_catch_all=True),
)


PATHS = tuple(page.path for page in WELL_KNOWN)


def exposed_postures(domain, scheme, results, front=None):
    """``(postures, evaluated)`` for the well-known pages. ``results`` maps a path of ``WELL_KNOWN`` to its response (or None when the request
    failed). A page counts only when its status is one the page uses and what it says matches the product's own wording, so a catch-all
    "200 for everything" is not a finding. ``front`` is the front page's response, for the catch-all comparison."""
    out, evaluated = [], set()
    for page in WELL_KNOWN:
        response = results.get(page.path)
        if not answered(response):
            continue
        evaluated.add(f'exposed_{page.key}')
        status = response.get('status') or 0
        if status not in page.statuses:
            continue
        text = ' '.join(((response.get('title') or ''), (response.get('www_authenticate') or ''), (response.get('body') or '')[:65536]))
        if page.key == 'login' and any(k in _headers(response) for k in ('x-jenkins',)):
            text += ' Jenkins'
        for pattern, severity, suffix in page.rules:
            if not re.search(pattern, text, re.IGNORECASE):
                continue
            if page.guard_catch_all and front and answered(front) and similar(fingerprint_of(response), fingerprint_of(front)):
                break
            if page.key == 'tomcat_manager' and status == 401 and severity == CRITICAL:
                severity = MEDIUM
            label = f'{page.label} ({suffix})' if suffix else page.label
            key = f'exposed_{page.key}' + (f'_{suffix.lower()}' if suffix else '')
            url = f'{scheme}://{domain}{page.path}'
            out.append(Posture(key, severity, f'{label} is reachable from the internet at {domain}{page.path}',
                               f'A plain GET of {url} answered with status {status} and the page identifies itself as {label}. '
                               'An administration or login page on the public internet is a target for password guessing and for the product\'s '
                               'known flaws.', 'exposed', domain, ask_for('exposed_', domain), {'url': url, 'status': status, 'path': page.path}))
            break
    return out, evaluated

# ----------------------------------------------------------------------------- the catch-all comparison (``cveFeed.vhost_scan``'s fingerprint and similarity)

def _location_path(location):
    """The part of a redirect target that says where it leads, without the host (a name redirects to itself, an address to its address)."""
    if not location:
        return ''
    try:
        parts = urlsplit(location.strip())
    except ValueError:
        return ''
    return ((parts.path or '/') + ('?' + parts.query if parts.query else '')).lower()[:200]


def fingerprint_of(response):
    """What is compared between two answers: status, title, length and where a redirect leads. Never the body."""
    body = response.get('body') or ''
    title = response.get('title')
    if title is None:
        title = page_title(body)
    return {'status': int(response.get('status') or 0), 'title': ' '.join(str(title or '').split())[:200],
            'length': int(response.get('bytes') if response.get('bytes') is not None else len(body)),
            'location': _location_path(response.get('location')), 'server': str(response.get('server') or '')[:60]}


def similar(a, b):
    """Whether two fingerprints are the same answer: both redirect to the same place, or the same status, the same title and a length within
    10% (or 64 bytes)."""
    a_redirect, b_redirect = 300 <= a['status'] < 400, 300 <= b['status'] < 400
    if a_redirect or b_redirect:
        return a_redirect and b_redirect and a['location'] == b['location']
    if a['status'] != b['status'] or a['title'].lower() != b['title'].lower():
        return False
    return abs(a['length'] - b['length']) <= max(64, 0.1 * max(a['length'], b['length']))
