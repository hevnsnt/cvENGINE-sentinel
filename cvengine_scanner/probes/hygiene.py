"""The DNS and mail half of cvENGINE's hygiene sweep, copied from ``cveFeed.hygiene`` (the ``hygiene_check`` kind).

cvENGINE picks what to check (the target's TLS endpoints, the names that may have mail) and what the answers mean for a certificate
(``evaluate_cert`` stays on the server, which also stores everything). This module asks:

- ``probe_tls``: the certificate and TLS posture of ``host:port``, read without verification so broken certificates can be read, plus the
  system trust store's verdict and whether TLS 1.0 / 1.1 is accepted. Every connection goes through ``transport`` under the task's scope policy;
- ``email_findings``: the SPF, DMARC, DKIM and CAA review of one mail domain and the MailFail checks (``probes.mailfail``). DNS is read from this
  Sentinel's resolver. The rules are the server's own, so a finding means the same wherever it was computed. The server clips every field it
  gets back and takes only the check families this module raises.
"""
import base64
import concurrent.futures
import datetime
import functools
import logging
import re
import socket
import ssl
from dataclasses import dataclass, field

from . import legacy_tls, names, transport

logger = logging.getLogger(__name__)

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
DNS_TIMEOUT = 5
TLS_TIMEOUT = 5
TLS_PORTS = (443, 8443, 9443, 993, 995, 465, 636)
MAX_TLS_TARGETS = 300
TLS_WORKERS = 20
# Mail providers rotate selector names; these cover Google, Microsoft 365, Mailchimp, SendGrid and the usual defaults.
DKIM_SELECTORS = ('default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
                  'mandrill', 'mxvault', 'zoho', 'protonmail', 'fm1', 'fm2')
SPF_LOOKUP_LIMIT = 10
SPF_MAX_QUERIES = 50  # records fetched for one domain: the owner of a scanned domain controls how wide its include tree is
SPF_MAX_TERMS = 200  # terms read from one record
EXPIRY_BANDS = ((0, CRITICAL, 'has expired'), (7, HIGH, 'expires within 7 days'),
                (30, MEDIUM, 'expires within 30 days'), (60, LOW, 'expires within 60 days'))


@dataclass
class Finding:
    check: str
    severity: int
    title: str
    detail: str = ''
    host: str = ''
    evidence: dict = field(default_factory=dict)



# ----------------------------------------------------------------------------- SPF

def _txt_value(record):
    return record.strip().strip('"')


def evaluate_spf(domain, txt_records, has_mx, lookup_count=None):
    """SPF review. ``txt_records`` are the domain's TXT strings; ``lookup_count`` the resolved DNS-lookup total."""
    spf = [_txt_value(r) for r in txt_records if _txt_value(r).lower().startswith('v=spf1')]
    if not spf:
        sev, why = (MEDIUM, 'This domain receives mail, so anyone can spoof it.') if has_mx else \
            (LOW, 'The domain does not appear to send mail; publish "v=spf1 -all" so nobody can spoof it.')
        return [Finding('spf_missing', sev, 'No SPF record', why, domain)]
    if len(spf) > 1:
        return [Finding('spf_multiple', HIGH, 'More than one SPF record',
                        'Receivers treat several SPF records as a permanent error, so SPF fails for everyone.', domain,
                        {'records': spf})]
    record, findings = spf[0], []
    terms = record.lower().split()
    all_term = next((t for t in terms if re.fullmatch(r'[+\-~?]?all', t)), None)
    redirect = any(t.startswith('redirect=') for t in terms)
    if all_term in ('+all', 'all'):
        findings.append(Finding('spf_allow_all', CRITICAL, 'SPF allows any server to send as this domain',
                                f'"{record}" ends in +all, which authorises the whole internet.', domain, {'record': record}))
    elif all_term == '?all':
        findings.append(Finding('spf_neutral', MEDIUM, 'SPF ends in ?all (neutral)',
                                'A neutral result gives receivers no reason to reject spoofed mail. Use -all.', domain, {'record': record}))
    elif all_term == '~all':
        findings.append(Finding('spf_softfail', LOW, 'SPF ends in ~all (soft fail)',
                                'Spoofed mail is marked, not rejected. Move to -all once all senders are listed.', domain, {'record': record}))
    elif all_term is None and not redirect:
        findings.append(Finding('spf_no_all', MEDIUM, 'SPF has no "all" mechanism',
                                'Without a closing -all or redirect, unlisted servers are not told to fail.', domain, {'record': record}))
    if 'ptr' in terms or any(t.lstrip('+-~?').startswith('ptr') for t in terms):
        findings.append(Finding('spf_ptr', LOW, 'SPF uses the discouraged ptr mechanism',
                                'ptr is slow and unreliable; list explicit ip4/ip6/include instead.', domain, {'record': record}))
    if lookup_count is not None and lookup_count > SPF_LOOKUP_LIMIT:
        findings.append(Finding('spf_too_many_lookups', MEDIUM, f'SPF needs {lookup_count} DNS lookups (limit {SPF_LOOKUP_LIMIT})',
                                'Over the limit, SPF returns a permanent error and legitimate mail can fail.', domain,
                                {'lookups': lookup_count}))
    return findings


def count_spf_lookups(domain, fetch_txt, depth=0, seen=None):
    """DNS-lookup cost of a domain's SPF record, following include/redirect (a, mx, ptr, exists, include, redirect each cost one)."""
    seen = seen if seen is not None else set()
    if depth > 10 or domain in seen or len(seen) >= SPF_MAX_QUERIES:
        return 0  # past the budget the count is already far over the limit of 10
    seen.add(domain)
    spf = next((_txt_value(r) for r in fetch_txt(domain) if _txt_value(r).lower().startswith('v=spf1')), None)
    if not spf:
        return 0
    total = 0
    for term in spf.split()[1:SPF_MAX_TERMS]:
        t = term.lstrip('+-~?').lower()
        if t.startswith(('include:', 'redirect=')):
            total += 1 + count_spf_lookups(re.split('[:=]', t, 1)[1], fetch_txt, depth + 1, seen)
        elif t.split(':')[0].split('/')[0] in ('a', 'mx', 'ptr', 'exists'):
            total += 1
    return total


# ----------------------------------------------------------------------------- DMARC

def parse_tags(record):
    tags = {}
    for part in _txt_value(record).split(';'):
        if '=' in part:
            k, _, v = part.partition('=')
            tags[k.strip().lower()] = v.strip()
    return tags


def evaluate_dmarc(domain, txt_records, has_mx):
    dmarc = [_txt_value(r) for r in txt_records if _txt_value(r).lower().startswith('v=dmarc1')]
    if not dmarc:
        sev, why = (HIGH, 'Mail for this domain can be spoofed and receivers have no policy to follow.') if has_mx else \
            (LOW, 'Publish "v=DMARC1; p=reject" so the domain cannot be used to send spoofed mail.')
        return [Finding('dmarc_missing', sev, 'No DMARC record', why, domain)]
    if len(dmarc) > 1:
        return [Finding('dmarc_multiple', MEDIUM, 'More than one DMARC record', 'Receivers ignore DMARC when several records exist.',
                        domain, {'records': dmarc})]
    tags, findings = parse_tags(dmarc[0]), []
    policy = tags.get('p', '').lower()
    if policy not in ('none', 'quarantine', 'reject'):
        findings.append(Finding('dmarc_invalid', MEDIUM, 'DMARC record has no valid policy', f'"{dmarc[0]}" is missing p=none|quarantine|reject.',
                                domain, {'record': dmarc[0]}))
        return findings
    if policy == 'none':
        findings.append(Finding('dmarc_none', MEDIUM, 'DMARC policy is p=none (monitoring only)',
                                'Spoofed mail is still delivered. Move to quarantine, then reject, once reports look clean.', domain,
                                {'record': dmarc[0]}))
    elif policy == 'quarantine':
        findings.append(Finding('dmarc_quarantine', INFO, 'DMARC policy is p=quarantine',
                                'Good. p=reject is the strongest setting.', domain, {'record': dmarc[0]}))
    pct = tags.get('pct')
    if pct and pct.isdigit() and int(pct) < 100 and policy != 'none':
        weaker = 'quarantine' if policy == 'reject' else 'none'
        findings.append(Finding('dmarc_partial', LOW, f'DMARC applies to only {pct}% of mail',
                                f'The other {100 - int(pct)}% of failing mail is treated as p={weaker} (RFC 7489 §6.6.4). Raise pct to 100.',
                                domain, {'pct': int(pct)}))
    if not tags.get('rua'):
        findings.append(Finding('dmarc_no_reports', LOW, 'DMARC has no aggregate report address (rua)',
                                'Without reports you cannot see who is sending as this domain.', domain, {'record': dmarc[0]}))
    sp = tags.get('sp', '').lower()
    if sp == 'none' and policy in ('quarantine', 'reject'):
        findings.append(Finding('dmarc_subdomain_weak', MEDIUM, 'DMARC subdomain policy is weaker (sp=none)',
                                'Attackers can spoof subdomains even though the apex is protected.', domain, {'record': dmarc[0]}))
    return findings


def has_dmarc_record(records):
    return any(_txt_value(r).lower().startswith('v=dmarc1') for r in records)


def dmarc_policy(records, subdomain=False):
    """The policy a receiver applies from a DMARC record set (``sp`` for a subdomain when it is valid, else ``p``), '' when there is no
    single valid record or it covers less than all mail (pct below 100)."""
    values = [_txt_value(r) for r in records if _txt_value(r).lower().startswith('v=dmarc1')]
    if len(values) != 1:
        return ''
    tags = parse_tags(values[0])
    policy, sp = tags.get('p', '').lower(), tags.get('sp', '').lower()
    if subdomain and sp in ('none', 'quarantine', 'reject'):
        policy = sp
    pct = tags.get('pct', '100')
    if policy not in ('none', 'quarantine', 'reject') or (pct.isdigit() and int(pct) < 100):
        return ''
    return policy


def evaluate_inherited_dmarc(domain, apex, records, has_mx):
    """DMARC review of a name that publishes no record of its own: a receiver falls back to the organizational domain's record
    (RFC 7489 section 6.6.3) and applies its ``sp`` tag to subdomains, so the apex's policy is the one the name has. When that policy is
    weak the cause is the apex's record, so the finding is the apex's (host ``apex``, the same check the apex's own review raises),
    listing the names it covers in ``evidence['covers']``: one row for the parent, not one per subdomain. An enforcing policy is no
    finding for the name."""
    values = [_txt_value(r) for r in records if _txt_value(r).lower().startswith('v=dmarc1')]
    own = evaluate_dmarc(apex, records, has_mx)
    if len(values) != 1:
        wanted = {'dmarc_multiple'}
    else:
        tags = parse_tags(values[0])
        policy, sp = tags.get('p', '').lower(), tags.get('sp', '').lower()
        effective = sp if sp in ('none', 'quarantine', 'reject') else policy
        if policy not in ('none', 'quarantine', 'reject'):
            wanted = {'dmarc_invalid'}
        elif effective == 'none':
            wanted = {'dmarc_none'} if policy == 'none' else {'dmarc_subdomain_weak'}
        else:
            wanted = set()
    found = []
    for f in own:
        if f.check in wanted:
            f.host = apex
            f.evidence = {**f.evidence, 'inherited_from': apex, 'covers': [domain]}
            found.append(f)
    return found


# ----------------------------------------------------------------------------- DKIM

def dkim_key_bits(record):
    """RSA key size in bits from a DKIM TXT record, 0 if revoked/unparseable."""
    p = parse_tags(record).get('p', '').replace(' ', '')
    if not p:
        return 0
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(base64.b64decode(p + '=' * (-len(p) % 4)))
        return getattr(key, 'key_size', 0)
    except Exception:  # noqa: BLE001
        return 0


def evaluate_dkim(domain, found, has_mx):
    """``found`` maps selector -> TXT record for the selectors that exist."""
    if not found:
        if not has_mx:
            return []
        return [Finding('dkim_not_found', INFO, 'No DKIM key found on common selectors',
                        'Not conclusive: DKIM selectors are arbitrary names. Check your mail provider that outbound mail is signed.',
                        domain, {'tried': list(DKIM_SELECTORS)})]
    findings = []
    found = {s: r for s, r in found.items() if parse_tags(r).get('p', '')}  # revoked selectors do not count as present
    if not found and has_mx:
        return [Finding('dkim_not_found', INFO, 'No DKIM key found on common selectors',
                        'Not conclusive: DKIM selectors are arbitrary names. Check your mail provider that outbound mail is signed.',
                        domain, {'tried': list(DKIM_SELECTORS)})]
    for selector, record in sorted(found.items()):
        bits = dkim_key_bits(record)
        host = f'{selector}._domainkey.{domain}'
        if parse_tags(record).get('p', '') == '':
            continue  # an empty key is a revoked selector (or a wildcard placeholder): nothing to fix
        if 0 < bits < 1024:
            findings.append(Finding('dkim_weak_key', HIGH, f'DKIM key for {selector} is only {bits} bits',
                                    'Keys under 1024 bits can be factored. Rotate to 2048.', host, {'selector': selector, 'bits': bits}))
        elif bits == 1024:
            findings.append(Finding('dkim_short_key', LOW, f'DKIM key for {selector} is 1024 bits', 'Rotate to 2048 bits.', host,
                                    {'selector': selector, 'bits': bits}))
    return findings


def evaluate_caa(domain, caa_records):
    if caa_records:
        return []
    return [Finding('caa_missing', INFO, 'No CAA record', 'A CAA record limits which certificate authorities may issue for this domain.', domain)]



# ----------------------------------------------------------------------------- TLS

def _fetch_cert(host, port, policy, timeout=TLS_TIMEOUT, legacy=False, addresses=None):
    """Connect without verification (so broken certs can still be read), return a plain info dict or None."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if legacy:  # a modern client cannot read servers that only speak TLS 1.0 / 1.1: legacy_tls is the one module that speaks those
        got = legacy_tls.handshake(host, port, timeout, policy, addresses=addresses)
        if got is None:
            return None
        der, protocol, cipher = got
    else:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # explicit: legacy_tls is the only place old protocols are spoken
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with transport.open_socket(addresses if addresses is not None else transport.resolve(host, port, policy), timeout, policy, host=host) as raw, \
                    ctx.wrap_socket(raw, server_hostname=host) as tls:
                der, protocol, cipher = tls.getpeercert(binary_form=True), tls.version(), (tls.cipher() or ('',))[0]
        except (OSError, ssl.SSLError, socket.timeout, ValueError):
            return None
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    pub = cert.public_key()
    key = f'RSA {pub.key_size}' if isinstance(pub, rsa.RSAPublicKey) else \
        f'EC {pub.curve.name}' if isinstance(pub, ec.EllipticCurvePublicKey) else type(pub).__name__
    cn = next((a.value for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), '')
    issuer = next((a.value for a in cert.issuer if a.oid == x509.NameOID.ORGANIZATION_NAME), '') or \
        next((a.value for a in cert.issuer if a.oid == x509.NameOID.COMMON_NAME), '')
    sig = getattr(cert.signature_hash_algorithm, 'name', '')
    return {'host': host, 'port': port, 'subject': cn, 'issuer': issuer, 'sans': sans,
            'not_before': getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc),
            'not_after': getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc),
            'signature_algorithm': f'{sig} ({cert.signature_algorithm_oid._name})' if sig else cert.signature_algorithm_oid._name,
            'key_description': key, 'protocol': protocol, 'cipher': cipher}


def _chain_error(host, port, policy, timeout=TLS_TIMEOUT, addresses=None):
    """Empty string if the system trust store accepts the certificate for this host, else the reason."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with transport.open_socket(addresses if addresses is not None else transport.resolve(host, port, policy), timeout, policy, host=host) as raw, \
                ctx.wrap_socket(raw, server_hostname=host):
            return ''
    except ssl.SSLCertVerificationError as exc:
        return (exc.verify_message or str(exc))[:300]
    except (OSError, ssl.SSLError, ValueError):
        return ''


def _accepts_legacy_tls(host, port, policy, timeout=TLS_TIMEOUT, addresses=None):
    """``{'protocol', 'cipher'}`` of the TLS 1.0 / 1.1 handshake the server completed (the evidence), or None: only a negotiated TLS 1.0 or
    1.1 counts (a successful handshake alone proves nothing)."""
    return legacy_tls.negotiated(host, port, timeout, policy, addresses=addresses)


def probe_tls(host, port, policy, addresses=None):
    """Read the certificate and TLS posture of ``host:port`` under ``policy`` (the task's scope policy, which judges the name and every address
    it resolves to; a refusal raises ``ValueError``). None when nothing there speaks TLS."""
    policy.check_host(host)
    if addresses is None:
        try:
            addresses = transport.resolve(host, port, policy)
        except ValueError:
            raise
        except OSError:
            return None
    info = _fetch_cert(host, port, policy, addresses=addresses)
    if info:
        info['chain_error'] = _chain_error(host, port, policy, addresses=addresses)
        legacy = _accepts_legacy_tls(host, port, policy, addresses=addresses)
        info['legacy_tls'] = bool(legacy)
        if isinstance(legacy, dict):
            info['legacy_handshake'] = legacy
        return info
    info = _fetch_cert(host, port, policy, legacy=True, addresses=addresses)  # a modern client cannot read servers that only speak TLS 1.0 / 1.1
    if info:
        info['chain_error'] = 'cannot be verified: the server only speaks TLS 1.0 / 1.1'
        info['legacy_tls'] = True
        info['legacy_handshake'] = {'protocol': info.get('protocol') or '', 'cipher': info.get('cipher') or ''}
    return info


def certificate_doc(info):
    """A probed certificate as the result carries it: the two dates as ISO 8601 text, the rest as probed."""
    out = dict(info)
    for key in ('not_before', 'not_after'):
        value = out.get(key)
        out[key] = value.isoformat() if isinstance(value, datetime.datetime) else None
    return out


# ----------------------------------------------------------------------------- DNS

def _resolver():
    import dns.resolver
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = DNS_TIMEOUT
    return r


def fetch_txt(name, resolver=None):
    import dns.exception
    import dns.resolver
    try:
        return [b''.join(rdata.strings).decode('utf-8', 'replace') for rdata in (resolver or _resolver()).resolve(name, 'TXT')]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return []


def has_record(name, rtype, resolver=None):
    import dns.exception
    import dns.resolver
    try:
        return bool(list((resolver or _resolver()).resolve(name, rtype)))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return False


def fetch_records(name, rtype, resolver=None):
    """Any record type as text (MX "10 mx.example.com.", TLSA, DNSKEY, NS), [] when there is none or DNS fails."""
    import dns.exception
    import dns.resolver
    try:
        return [rdata.to_text() for rdata in (resolver or _resolver()).resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException):
        return []


# A DNS finding that says a record is missing opens only when two resolvers agree it is, or when the next run sees the same thing: a
# one-off timeout or SERVFAIL is not a missing record. By default only this Sentinel's own resolver is asked, so a missing record needs two
# consecutive observations, and no client name leaves for a third party. The task carries the confirming resolvers the cvENGINE installation
# opted in to (CVENGINE_HYGIENE_CONFIRM_RESOLVERS on the server); each is sent the names whose record seems missing.
CONFIRM_TIMEOUT = 3
MAX_CONFIRM_RESOLVERS = 5


def ask_txt(resolver, name):
    """One resolver's answer for ``name`` TXT: ``{'result': answer|nxdomain|noanswer|error, 'records': [...], 'cname': ...}``. A CNAME is
    followed (the answer is the target's records) and named, so an SPF record published by the platform a name points at is read."""
    import dns.exception
    import dns.resolver
    try:
        answer = resolver.resolve(name, 'TXT')
    except dns.resolver.NXDOMAIN:
        return {'result': 'nxdomain', 'records': []}
    except dns.resolver.NoAnswer:
        return {'result': 'noanswer', 'records': []}
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.exception.DNSException) as exc:
        return {'result': 'error', 'records': [], 'error': type(exc).__name__}
    out = {'result': 'answer', 'records': [b''.join(rdata.strings).decode('utf-8', 'replace') for rdata in answer]}
    canonical = str(getattr(answer, 'canonical_name', '') or '').rstrip('.').lower()
    if canonical and canonical != name.rstrip('.').lower():
        out['cname'] = canonical
    return out


def dns_askers(confirm=()):
    """``[(label, ask(name) -> answer dict)]``: the system resolver, then the confirming resolvers the installation opted in to (none by
    default, when an absence is confirmed by the next run instead)."""
    import dns.resolver
    askers = [('system', functools.partial(ask_txt, _resolver()))]
    for address in list(confirm)[:MAX_CONFIRM_RESOLVERS]:
        r = dns.resolver.Resolver(configure=False)
        try:
            r.nameservers = [address]
        except ValueError:  # not an address: a typo in the setting never stops the review
            logger.warning('ignoring confirming resolver %r: not an IP address', address)
            continue
        r.lifetime = r.timeout = CONFIRM_TIMEOUT
        askers.append((address, functools.partial(ask_txt, r)))
    return askers


def consensus_txt(name, askers, prefix, votes=2):
    """``(records, confirmed, observations)`` for the ``prefix`` record (v=spf1, v=DMARC1) at ``name``. The first resolver that has the
    record wins. Otherwise the record is missing only when ``votes`` resolvers answered without it (NXDOMAIN, no answer, or other TXT
    records); an error is no vote. ``observations`` is the evidence either way."""
    observations, absent, first = [], 0, None
    for label, ask in askers:
        got = ask(name)
        records = list(got.get('records') or [])
        observations.append({'resolver': label, 'result': got.get('result', 'error'), 'records': [r[:300] for r in records[:5]],
                             **({'cname': got['cname']} if got.get('cname') else {})})
        if any(_txt_value(r).lower().startswith(prefix) for r in records):
            return records, True, observations
        if got.get('result') in ('answer', 'nxdomain', 'noanswer'):
            absent += 1
            first = records if first is None else first
            if absent >= votes:
                return first, True, observations
    return first or [], False, observations


def _injected(fetch):
    """An injected TXT reader (tests, the supplier checks) as the one resolver: it is taken at its word."""
    return [('dns', lambda name: {'result': 'answer', 'records': list(fetch(name) or [])})]


def organizational_domain(name):
    return names.apex_domain(name)


def _observed(findings, check, observations, confirmed):
    """Attach the DNS answers behind an absence finding, and whether two resolvers agreed on it (``store_findings`` holds an
    unconfirmed one back until the next run sees it too)."""
    for f in findings:
        if f.check == check:
            f.evidence = {**(f.evidence or {}), 'dns': observations, 'dns_confirmed': bool(confirmed)}


def email_findings(domain, fetch=fetch_txt, mx=has_record, records=None, askers=None, scope=None, confirm=(), rdap=True):
    """SPF, DMARC, DKIM and CAA review for one domain, plus the checks adapted from MailFail (``probes.mailfail``), with
    injectable DNS for tests. With injected DNS, other record types default to none and no outbound request is made.

    The records whose absence is a finding (SPF, the name's DMARC record and its organizational domain's) are read through
    ``consensus_txt``: with real DNS a missing record must be missing at two resolvers (``askers``, default ``dns_askers()``: the system
    resolver alone unless confirming resolvers are configured, so by default the next run's sighting is the second), and the answers are
    kept as the finding's evidence. An injected ``fetch`` is taken at its word unless ``askers`` is given too."""
    from . import mailfail
    real_dns = fetch is fetch_txt
    records = records or (fetch_records if real_dns else (lambda name, rtype: []))
    if askers is None:
        askers, votes = (dns_askers(confirm), 2) if real_dns else (_injected(fetch), 1)
    else:
        votes = 2
    has_mx = mx(domain, 'MX')
    txt, spf_ok, spf_seen = consensus_txt(domain, askers, 'v=spf1', votes)
    spf_fetch = lambda name: txt if name == domain else fetch(name)  # noqa: E731 - the agreed answer, not a second lookup
    findings = evaluate_spf(domain, txt, has_mx, count_spf_lookups(domain, spf_fetch))
    _observed(findings, 'spf_missing', spf_seen, spf_ok)
    dmarc, own_ok, own_seen = consensus_txt(f'_dmarc.{domain}', askers, 'v=dmarc1', votes)
    apex = organizational_domain(domain)
    subdomain = bool(apex) and apex != domain
    policy = dmarc_policy(dmarc)
    if has_dmarc_record(dmarc):
        findings += evaluate_dmarc(domain, dmarc, has_mx)
    elif subdomain:  # RFC 7489 6.6.3: no record of its own, so the organizational domain's record (and its sp=) applies
        parent, parent_ok, parent_seen = consensus_txt(f'_dmarc.{apex}', askers, 'v=dmarc1', votes)
        if has_dmarc_record(parent):
            findings += evaluate_inherited_dmarc(domain, apex, parent, has_mx)
            policy = dmarc_policy(parent, subdomain=True)
        else:
            missing = evaluate_dmarc(domain, dmarc, has_mx)
            _observed(missing, 'dmarc_missing', own_seen + parent_seen, own_ok and parent_ok)
            findings += missing
    else:
        missing = evaluate_dmarc(domain, dmarc, has_mx)
        _observed(missing, 'dmarc_missing', own_seen, own_ok)
        findings += missing
    if subdomain and policy in ('quarantine', 'reject'):
        for f in findings:  # spoofed mail from this name fails DMARC (no aligned SPF or DKIM) and is quarantined or rejected
            if f.check == 'spf_missing':
                f.severity = INFO
                f.detail = (f'{f.detail} DMARC p={policy} already applies to this name, so mail spoofing it fails DMARC and is '
                            f'{"rejected" if policy == "reject" else "quarantined"}; publish "v=spf1 -all" if it never sends mail.')
                f.evidence = {**f.evidence, 'dmarc_policy': policy}
    selectors = DKIM_SELECTORS + mailfail.EXTRA_DKIM_SELECTORS
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        answers = pool.map(lambda selector: fetch(f'{selector}._domainkey.{domain}'), selectors)
        found = {}
        for selector, rows in zip(selectors, answers):
            for record in rows:
                if 'v=dkim1' in record.lower() or 'p=' in record.lower():
                    found[selector] = record
    findings += evaluate_dkim(domain, found, has_mx)
    findings += evaluate_caa(domain, mx(domain, 'CAA'))
    try:
        findings += mailfail.review(domain, has_mx, txt, dmarc, found, fetch, records, http=real_dns, scope=scope, rdap_on=rdap)
    except Exception:  # noqa: BLE001 - the established checks above stand on their own
        logger.exception('MailFail checks failed for %s', domain)
    return findings, has_mx


def is_ip(value):
    return bool(re.fullmatch(r'[\d.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*', value or ''))



# ----------------------------------------------------------------------------- the task

MAX_TLS_TARGETS = 300
MAX_MAIL_NAMES = 101
MAIL_WORKERS = 4
MAX_FINDING_TEXT = {'check': 64, 'title': 300, 'detail': 2000, 'host': 300}


def _tls_target(raw):
    if not isinstance(raw, dict):
        return None
    host, port = raw.get('host'), raw.get('port')
    if not isinstance(host, str) or not names.clean(host) or len(host) > 260 or any(c.isspace() or ord(c) < 32 for c in host):
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    return names.clean(host), port


def _mail_name(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get('name'), str) or not names.clean(raw['name']) or len(raw['name']) > 253:
        return None
    return names.clean(raw['name']), raw.get('always') is True


def finding_doc(finding):
    """One finding as the result carries it: text clipped, the evidence reduced to JSON data."""
    import json
    try:
        evidence = json.loads(json.dumps(finding.evidence or {}, default=str))
    except (TypeError, ValueError):
        evidence = {}
    return {'check': str(finding.check)[:64], 'severity': int(finding.severity), 'title': str(finding.title)[:300],
            'detail': str(finding.detail or '')[:2000], 'host': str(finding.host or '')[:300], 'evidence': evidence if isinstance(evidence, dict) else {}}


def _tls_row(target, policy, probe):
    host, port = target
    try:
        info = probe(host, port, policy)
    except ValueError as exc:  # the policy or the floor refused the name or an address: not asked, so unknown (never "nothing there")
        policy.refuse(host)
        return {'host': host, 'port': port, 'found': False, 'error': f'not run: {exc}'[:200]}
    except Exception as exc:  # noqa: BLE001 - one endpoint failing never stops the rest
        logger.warning('TLS probe of %s:%s failed: %s', host, port, type(exc).__name__)
        return {'host': host, 'port': port, 'found': False, 'error': f'probe failed: {type(exc).__name__}'}
    if not info:
        return {'host': host, 'port': port, 'found': False}
    return {'host': host, 'port': port, 'found': True, 'cert': certificate_doc(info)}


def _mail_row(name, policy, confirm, rdap_on, emailer):
    findings, has_mx = emailer(name, scope=policy, confirm=confirm, rdap=rdap_on)
    return {'name': name, 'has_mx': bool(has_mx), 'findings': [finding_doc(f) for f in findings]}


def run_batch(target, probe=None, emailer=None, mx=None, cname=None, workers=TLS_WORKERS):
    """Run a ``hygiene_check`` task: the certificates of ``target['tls']`` and the email review of ``target['mail']`` under ``target['scope']``.
    Returns ``{'certs': [{'host', 'port', 'found', 'cert'?, 'error'?}], 'mail': [{'name', 'has_mx', 'findings'}], 'touched', 'refused'}``.

    A name flagged ``always`` is reviewed whatever its records; any other is reviewed only when it has an MX record of its own and is not a CNAME
    (a CNAME has no MX of its own, the one a lookup returns is its target's). A TLS endpoint the policy refused, or a mail review that failed, is
    left out of ``mail`` or carries an ``error``: cvENGINE reads that as unknown, never as clean. ``probe``, ``emailer``, ``mx`` and ``cname``
    replace the network (tests)."""
    from .policy import ScopePolicy
    raw_tls = target.get('tls') if isinstance(target.get('tls'), list) else []
    raw_mail = target.get('mail') if isinstance(target.get('mail'), list) else []
    if len(raw_tls) > MAX_TLS_TARGETS or len(raw_mail) > MAX_MAIL_NAMES:
        raise ValueError(f'a task names at most {MAX_TLS_TARGETS} TLS endpoints and {MAX_MAIL_NAMES} mail names')
    tls = [_tls_target(item) for item in raw_tls]
    mail = [_mail_name(item) for item in raw_mail]
    if any(t is None for t in tls) or any(m is None for m in mail):
        raise ValueError('an endpoint or a name is malformed')
    confirm = [a for a in (target.get('confirm_resolvers') if isinstance(target.get('confirm_resolvers'), list) else []) if isinstance(a, str)]
    confirm = confirm[:MAX_CONFIRM_RESOLVERS]
    rdap_on = target.get('rdap') is not False
    policy = ScopePolicy(target.get('scope'))
    probe = probe or probe_tls
    emailer = emailer or email_findings
    mx = mx or (lambda name: has_record(name, 'MX'))
    cname = cname or (lambda name: has_record(name, 'CNAME'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        certs = list(pool.map(lambda t: _tls_row(t, policy, probe), list(dict.fromkeys(tls))))

    def selected(item):
        name, always = item
        return name if always or (not is_ip(name) and mx(name) and not cname(name)) else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAIL_WORKERS) as pool:
        chosen = [n for n in pool.map(selected, list(dict.fromkeys(mail))) if n]

        def review(name):
            try:
                return _mail_row(name, policy, confirm, rdap_on, emailer)
            except Exception as exc:  # noqa: BLE001 - one domain failing never stops the rest; it is left out, which cvENGINE reads as unknown
                logger.warning('email review of %s failed: %s', name, type(exc).__name__)
                return None
        rows = [r for r in pool.map(review, chosen) if r is not None]
    return {'certs': certs, 'mail': rows, 'touched': policy.touched, 'refused': policy.refused}
