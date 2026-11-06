"""Passive posture checks of a third-party supplier's public names, copied from cvENGINE's ``cveFeed.supplier_scan`` (the ``supplier_check`` kind).

cvENGINE keeps what a supplier is (the list, the tier, the weekly schedule, the request budget, the ledger, the stored findings and host cards)
and sends the names it validated: this module asks the network. For each name, and nothing else (no wildcard, no neighbouring name, no port other
than 443 and 80), in this order:

* the name is resolved once and every address must pass the task's scope policy (loopback, private, link-local and metadata addresses refuse the
  whole name); every connection after that goes to those vetted numeric addresses;
* email authentication (SPF, DKIM, DMARC, MTA-STS and the MailFail checks) from this Sentinel's resolver, plus the one MTA-STS policy file over
  verified HTTPS;
* the certificate and protocol on 443 (``tls``);
* the front page over HTTPS and over HTTP, then one plain GET per path of ``supplier_checks.WELL_KNOWN``, anonymous, no redirect followed, at most
  64 KB read, paced by the gaps the task carries. An edge that challenges a request is recorded and never worked around.

The result is what cvENGINE's ``DomainResult`` holds, minus the one part that needs its CVE catalog: the findings of the categories decided here
(``postures``), the categories a later run may resolve (``resolvable``), the host card's sections, and for the catalog match the fingerprints the
front page showed, the edge in front of it and the distribution build. cvENGINE matches those against the catalog and writes the supplier's text
itself; nothing a Sentinel reports is stored as it is. A name the policy refuses is not asked and has no row.

Requests are counted as cvENGINE counts them (a certificate read is three) against the task's ``max_requests``; a name that does not fit is
partial, never silently skipped. dnspython and cryptography are imported only when a lookup or a certificate read happens.
"""
import http.client
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

from .. import fingerprint as shared_fingerprint
from .. import versions
from . import fingerprint as page_fingerprint
from . import http as web
from . import mail_checks, mailfail, names, supplier_checks as checks, tls, transport
from .policy import ScopePolicy
from .version_probes import challenge_of

logger = logging.getLogger(__name__)

MAX_DOMAINS = 25  # the contract's bound (cvENGINE's CVENGINE_SUPPLIERS_MAX_DOMAINS tops out at 25)
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUESTS = 5000  # the contract's bound
MAX_SECONDS = 1500  # one task's wall clock: a name still running at the end is reported stopped, never skipped
MIN_GAP, MIN_HOST_GAP, MAX_GAP = 0.25, 0.5, 60.0  # a task can slow the checks down as far as it likes, never below a polite pace
DEFAULT_GAP, DEFAULT_HOST_GAP = 1.0, 2.0
TLS_COST = 3  # a certificate read is up to three handshakes: it is counted as three requests
MTA_STS_TIMEOUT = 5
MAX_POLICY_BYTES = mailfail.MAX_POLICY_BYTES
FORBIDDEN_SUFFIXES = ('localhost', 'local', 'internal', 'lan', 'intranet', 'corp', 'home', 'home.arpa', 'onion', 'invalid')


# ----------------------------------------------------------------------------- the address gate

def numeric_addresses(ips, port=443):
    """The transport's numeric ``(family, sockaddr)`` pairs for vetted address strings."""
    out = []
    for ip in ips:
        out.append((socket.AF_INET6, (ip, port, 0, 0)) if ':' in ip else (socket.AF_INET, (ip, port)))
    return tuple(out)


def public_addresses(name, net, policy):
    """``(addresses, state)`` for a name: ``ok`` with every address it resolves to (IPv4 first) when ALL of them pass the policy; ``blocked`` when
    any is one a scanner must not touch (the whole name is then refused); ``none`` when the name has no address; ``unknown`` when the lookup failed."""
    try:
        found = list(dict.fromkeys(net.resolve(name)))
    except socket.gaierror as exc:
        return [], ('none' if exc.errno in (socket.EAI_NONAME, getattr(socket, 'EAI_NODATA', -5)) else 'unknown')
    except (OSError, ValueError):
        return [], 'unknown'
    if not found:
        return [], 'none'
    if any(policy.address_refusal(ip) for ip in found):
        return [], 'blocked'
    return sorted(found, key=lambda ip: (':' in ip, ip)), 'ok'


# ----------------------------------------------------------------------------- the network (injectable)

class Network:
    """The real network of the checks. A test injects an object with the same methods and never touches the internet. Every connection goes to
    addresses ``public_addresses`` admitted, through the pinned transport under the task's policy; DNS questions go to this machine's resolver."""

    def __init__(self, policy):
        self.policy = policy

    def resolve(self, name):
        self.policy.check_host(name)
        return [info[4][0] for info in socket.getaddrinfo(name, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)]

    def fetch(self, url, ip):
        """One bounded, anonymous GET connected to the vetted ``ip`` (the URL's name is the Host and TLS name); says which edge challenged it."""
        response = web.probe_url(url, self.policy, max_bytes=MAX_RESPONSE_BYTES, connect_ip=ip)
        return {**response, 'challenge': challenge_of(response)}

    def tls(self, name, addresses):
        return tls.probe_tls(name, 443, self.policy, numeric_addresses(addresses))

    def dns_state(self, name):
        import dns.exception
        import dns.resolver
        try:
            mail_checks._resolver().resolve(name, 'MX')
            return 'ok'
        except dns.resolver.NoAnswer:
            return 'ok'
        except dns.resolver.NXDOMAIN:
            return 'nxdomain'
        except (dns.resolver.NoNameservers, dns.exception.DNSException):
            return 'unknown'

    def txt(self, name):
        return mail_checks.fetch_txt(name)

    def records(self, name, rtype):
        return mail_checks.fetch_records(name, rtype)

    def has_record(self, name, rtype):
        return mail_checks.has_record(name, rtype)

    def mta_sts_policy(self, domain, addresses):
        """The MTA-STS policy file over verified HTTPS (RFC 8461), to the vetted addresses only, no redirects, at most 64 KB. None when there is none."""
        host = f'mta-sts.{domain}'
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = transport.HTTPConnection(host, 443, numeric_addresses(addresses), MTA_STS_TIMEOUT, self.policy, context=context)
        try:
            conn.request('GET', '/.well-known/mta-sts.txt', headers={'Host': host, 'User-Agent': 'CVEngine supplier check'})
            response = conn.getresponse()
            if response.status != 200:
                return None
            body = transport.read_body(response, MAX_POLICY_BYTES + 1)  # gzip despite identity is decoded, capped after decoding
            return None if len(body) > MAX_POLICY_BYTES else body.decode('utf-8', 'replace')
        except (OSError, http.client.HTTPException, ValueError):
            return None
        finally:
            conn.close()


class Pace:
    """Waits before each request: the per-host gap since the last request to that host, then the gap since any request of this task.
    ``sleep`` and ``clock`` are injectable so a test checks the pacing without waiting. (cvENGINE shares the global gap across its workers; a
    Sentinel paces its own task.)"""

    def __init__(self, gap=DEFAULT_GAP, host_gap=DEFAULT_HOST_GAP, sleep=time.sleep, clock=time.monotonic):
        self.gap, self.host_gap, self.sleep, self.clock = gap, host_gap, sleep, clock
        self.last, self.last_any = {}, None
        self.requests = 0
        self._lock = threading.Lock()

    def wait(self, host):
        key = str(host).lower()
        with self._lock:
            now = self.clock()
            delay = 0.0
            if key in self.last:
                delay = max(delay, self.host_gap - (now - self.last[key]))
            if self.last_any is not None:
                delay = max(delay, self.gap - (now - self.last_any))
            delay = max(0.0, delay)
        if delay > 0:
            self.sleep(delay)
        with self._lock:
            self.last[key] = self.last_any = self.clock()
            self.requests += 1


class Budget:
    """The requests one task may still make (a certificate read counts as ``TLS_COST``)."""

    def __init__(self, limit):
        self.limit, self.used = limit, 0

    def spend(self, units=1):
        self.used += units

    def left(self):
        return self.limit - self.used


class _Stopped(Exception):
    """The task's time ran out, or its request budget, in the middle of a name."""


# ----------------------------------------------------------------------------- one name

class DomainResult:
    """What one name's checks found: ``postures`` (``supplier_checks.Posture``), ``resolvable`` (category -> check-name prefixes this run could
    decide), ``summary``, ``card`` (the sections of the host card this run could read), the fingerprints, edge and distribution of the front page
    for cvENGINE's CVE match, and the ``answered``, ``stopped`` and ``partial`` flags."""

    def __init__(self, domain):
        self.domain = domain
        self.postures, self.resolvable, self.summary, self.card = [], {}, {}, {}
        self.fingerprints, self.edges, self.distro = [], [], ''
        self.answered = self.stopped = self.partial = False
        self.requests = 0


def _email(res, domain, net, pace, budget, policy):
    """SPF, DKIM, DMARC, MTA-STS and the MailFail checks, DNS only, for a name that handles mail."""
    state = net.dns_state(domain)
    res.card.setdefault('evidence', {})['dns'] = state
    if state != 'ok':
        return
    has_mx = net.has_record(domain, 'MX')
    mail = has_mx or any('v=spf1' in t.lower() for t in net.txt(domain)) or any('v=dmarc1' in t.lower() for t in net.txt(f'_dmarc.{domain}'))
    res.card['mail'] = {'handles_mail': bool(mail), 'mx': bool(has_mx)}
    if not mail:
        return
    found, has_mx = mail_checks.email_findings(domain, fetch=net.txt, mx=net.has_record, records=net.records)
    sts = net.txt(f'_mta-sts.{domain}')
    if any('v=stsv1' in t.lower() for t in sts):  # the one policy file, fetched only to the addresses vetted for mta-sts.<domain>
        addresses, sts_state = public_addresses(f'mta-sts.{domain}', net, policy)
        if sts_state in ('ok', 'none', 'blocked'):
            policy_text = None
            if sts_state == 'ok':
                budget.spend(1)
                pace.wait(f'mta-sts.{domain}')
                policy_text = net.mta_sts_policy(domain, addresses)
            found = [f for f in found if not f.check.startswith('mta_sts_')] + mailfail.evaluate_mta_sts(domain, sts, policy_text, has_mx)
    if net.dns_state(domain) != 'ok':  # the resolver failed on the way: an empty answer is not "no record"
        res.card['evidence']['dns'] = 'unknown'
        return
    res.postures += checks.email_postures(domain, found)
    res.resolvable['email'] = {''}
    res.answered = True


def _http_section(https, http_page, base, scheme, domain):
    """The ``http`` section of the card: the front page's status over both schemes and the raw response headers of the one that answered."""
    section = {'https_status': (https or {}).get('status'), 'http_status': (http_page or {}).get('status')}
    if base:
        section.update({'url': f'{scheme}://{domain}/', 'status': base.get('status'), 'title': (base.get('title') or '')[:200],
                        'content_type': base.get('content_type') or '', 'server': str(base.get('server') or '')[:200],
                        'powered_by': str(base.get('powered_by') or '')[:200], 'location': str(base.get('location') or '')[:300],
                        'cookies': sorted(base.get('cookies') or [])[:20], 'bytes': base.get('bytes'),
                        'headers': dict(list((base.get('raw_headers') or {}).items())[:60])})
    return section


def _tls_section(info, now=None):
    """The ``tls`` section: the certificate and protocol as read, text clipped to what the card stores."""
    info = tls.clip_certificate(info)
    not_after = info.get('not_after')
    days = (not_after - (now or datetime.now(timezone.utc))).days if not_after else None
    return {'subject': info['subject'], 'issuer': info['issuer'], 'sans': info['sans'][:50], 'not_before': info['not_before'].isoformat() if info.get('not_before') else None,
            'not_after': not_after.isoformat() if not_after else None, 'days_left': days, 'key': info['key_description'],
            'signature': info['signature_algorithm'], 'protocol': info['protocol'], 'cipher': info['cipher'], 'chain_error': info['chain_error'],
            'legacy_tls': bool(info.get('legacy_tls'))}


def _fingerprints(base, scheme, domain):
    """What the front page says it runs: the same fingerprinting cvENGINE's route check gives an owned host (headers, generator tags, markers in the
    page, script names), read from this one page."""
    page_url = f'{scheme}://{domain}/'
    scripts = page_fingerprint.script_sources(base.get('body') or '', page_url)[0]
    return shared_fingerprint.from_response(base.get('server', ''), base.get('powered_by', ''), base.get('body') or '', base.get('content_type', ''),
                                            from_scripts=page_fingerprint.from_script_urls(scripts), headers=base.get('headers'))


def check_domain(domain, net, pace, budget, policy, stop=lambda: False, now=None):
    """Every check of one supplier name: its host card first (certificate, response headers, fingerprints), then the findings. Returns a
    ``DomainResult``; the one part cvENGINE does itself is the CVE match."""
    started = budget.used
    res = DomainResult(domain)
    addresses, state = public_addresses(domain, net, policy)
    res.summary['address'] = state
    res.card = {'state': {'ok': 'unreachable', 'none': 'no_address', 'blocked': 'blocked'}.get(state, 'unreachable'), 'addresses': addresses[:6],
                'evidence': {'address': state}}
    try:
        if stop():
            raise _Stopped
        _email(res, domain, net, pace, budget, policy)
        if state != 'ok':
            if state == 'blocked':
                res.card['evidence']['note'] = 'The name resolves to an address that is not public, so it was not contacted.'
            return res
        ip = addresses[0]

        def spend(units):
            if stop():
                raise _Stopped
            if budget.left() < units:
                res.partial = True
                raise _Stopped
            budget.spend(units)
            pace.wait(domain)

        def get(url):
            spend(1)
            try:
                return net.fetch(url, ip)
            except (OSError, ValueError, http.client.HTTPException):
                return None

        spend(TLS_COST)
        try:
            info = net.tls(domain, addresses)
        except Exception as exc:  # noqa: BLE001 - a certificate the library cannot read must not stop the rest
            logger.info('supplier: could not read the certificate of %s (%s)', domain, type(exc).__name__)
            info = None
        if info:
            res.postures += checks.tls_postures(domain, info, now=now)
            res.resolvable['tls'] = {'tls_'}
            res.answered = True
            res.card['tls'] = _tls_section(info, now=now)

        https, http_page = get(f'https://{domain}/'), get(f'http://{domain}/')
        front = https if checks.answered(https) else http_page if checks.answered(http_page) else None
        challenge = (https or {}).get('challenge') or (http_page or {}).get('challenge') or ''
        if challenge:
            res.card['evidence']['challenged'] = challenge  # an edge refused the request: recorded, never retried or worked around
            res.card['state'] = 'challenged'
        if any(_busy(r) for r in (https, http_page) if r):
            res.partial = True
        web_found, evaluated = checks.web_postures(domain, https, http_page)
        res.postures += web_found
        if evaluated:
            res.resolvable['web'] = evaluated
            res.answered = True
        res.card['http'] = _http_section(https, http_page, None, '', domain) if front is None else None
        if front is None or challenge:
            return res
        res.card['state'] = 'ok'
        scheme = 'https' if checks.answered(https) else 'http'
        base = https if scheme == 'https' else http_page
        res.card['http'] = _http_section(https, http_page, base, scheme, domain)
        res.fingerprints = _fingerprints(base, scheme, domain)
        res.edges = versions.edges_from_headers({**(base.get('headers') or {}), 'server': base.get('server', '')})
        res.distro = versions.parse_server_header(base.get('server', '')).get('distro', '')
        if not res.edges:
            res.resolvable['cve'] = {'cve_'}
        results = {}
        for page in checks.WELL_KNOWN:
            response = get(f'{scheme}://{domain}{page.path}')
            results[page.path] = response
            if response and response.get('challenge'):
                res.card['evidence']['challenged'] = response['challenge']
                break
            if response and _busy(response):
                res.partial = True
                break
        exposed, evaluated = checks.exposed_postures(domain, scheme, results, front=base)
        res.postures += exposed
        if evaluated:
            res.resolvable['exposed'] = evaluated
    except _Stopped:
        res.stopped = not res.partial
    finally:
        res.requests = budget.used - started
    return res


def _busy(response):
    """A plain "try later" (429, 503 with no edge signature): not a result, and not asked again at this task."""
    return (response.get('status') or 0) in (429, 503) and not response.get('challenge')


# ----------------------------------------------------------------------------- the supplier_check kind

def _domain(raw):
    """The exact, lowercase DNS name in ``raw``, or None: a supplier is looked at by name only (never an address, a URL, a wildcard or a private name)."""
    if not isinstance(raw, str):
        return None
    name = raw.strip().lower().rstrip('.')
    if not name or len(name) > 253 or any(c in name for c in '*/@?#:%\\') or any(c.isspace() or ord(c) < 32 for c in name):
        return None
    if names.is_ip(name) or not names.is_domain(name):
        return None
    if any(name == suffix or name.endswith('.' + suffix) for suffix in FORBIDDEN_SUFFIXES):
        return None
    return name


def _number(value, default, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return min(high, max(low, value))


def posture_doc(p):
    """A ``supplier_checks.Posture`` as the result carries it. The text to ask the supplier is left out: cvENGINE writes it from the check name."""
    return {'check': p.check, 'severity': int(p.severity), 'title': p.title[:300], 'detail': p.detail[:4000], 'category': p.category,
            'evidence': p.evidence if isinstance(p.evidence, dict) else {}}


def domain_doc(res):
    """A ``DomainResult`` as one row of the result."""
    return {'domain': res.domain, 'postures': [posture_doc(p) for p in res.postures],
            'resolvable': {category: sorted(prefixes) for category, prefixes in res.resolvable.items()},
            'summary': res.summary, 'card': res.card, 'fingerprints': [{'name': str(f.get('name', ''))[:120], 'source': str(f.get('source', ''))[:40]}
                                                                   for f in res.fingerprints[:shared_fingerprint.MAX_FINGERPRINTS]],
            'edges': [str(e)[:60] for e in res.edges[:10]], 'distro': str(res.distro or '')[:60],
            'answered': res.answered, 'stopped': res.stopped, 'partial': res.partial, 'requests': res.requests}


def run_batch(target, net=None, pace=None, now=None, sleep=time.sleep, clock=time.monotonic):
    """Run a ``supplier_check`` task: ``target['domains']`` under ``target['scope']``, paced by ``target['pace']`` and held to
    ``target['max_requests']``. Returns ``{'domains': [row], 'touched', 'refused'}``: one row per name that was asked, in the order given, and the
    rows after the one that ran out of budget or time are left out (cvENGINE asks for them again). ``net`` and ``pace`` replace the network and the
    pacing in tests; the policy is asked first either way."""
    raw = target.get('domains') if isinstance(target.get('domains'), list) else []
    if not raw or len(raw) > MAX_DOMAINS:
        raise ValueError(f'a task names between 1 and {MAX_DOMAINS} domains')
    domains = [_domain(item) for item in raw]
    if any(d is None for d in domains):
        raise ValueError('a domain is malformed')
    policy = ScopePolicy(target.get('scope'))
    limits = target.get('pace') if isinstance(target.get('pace'), dict) else {}
    pace = pace or Pace(_number(limits.get('gap'), DEFAULT_GAP, MIN_GAP, MAX_GAP), _number(limits.get('host_gap'), DEFAULT_HOST_GAP, MIN_HOST_GAP, MAX_GAP),
                        sleep=sleep, clock=clock)
    budget = Budget(int(_number(target.get('max_requests'), 600, 1, MAX_REQUESTS)))
    net = net or Network(policy)
    deadline = clock() + MAX_SECONDS
    stop = lambda: clock() > deadline  # noqa: E731
    rows = []
    for domain in dict.fromkeys(domains):
        if policy.host_refusal(domain):
            policy.refuse(domain)
            continue
        if stop():
            break
        res = check_domain(domain, net, pace, budget, policy, stop=stop, now=now)
        rows.append(domain_doc(res))
        if res.stopped or res.partial:
            break
    return {'domains': rows, 'touched': policy.touched, 'refused': policy.refused}
