"""SPF, DKIM, DMARC and CAA review of one domain's DNS records, copied from cvENGINE's ``cveFeed.hygiene`` (the ``supplier_check`` kind).

The evaluators are pure functions over plain data. ``email_findings`` is the supplier checks' use of cvENGINE's: DNS is always the caller's (a
Sentinel's resolver through ``suppliers.Network``), so every record is taken at its word, from one resolver, and nothing leaves for a third party
(no confirming resolver, no RDAP lookup). The DNS helpers read this Sentinel's resolver; dnspython is imported only when one is asked, so the
module imports with no dependency of its own.
"""
import base64
import concurrent.futures
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4


DNS_TIMEOUT = 5


# Mail providers rotate selector names; these cover Google, Microsoft 365, Mailchimp, SendGrid and the usual defaults.
DKIM_SELECTORS = ('default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
                  'mandrill', 'mxvault', 'zoho', 'protonmail', 'fm1', 'fm2')


SPF_LOOKUP_LIMIT = 10


SPF_MAX_QUERIES = 50  # records fetched for one domain: the owner of a scanned domain controls how wide its include tree is


SPF_MAX_TERMS = 200  # terms read from one record


@dataclass
class Finding:
    check: str
    severity: int
    title: str
    detail: str = ''
    host: str = ''
    evidence: dict = field(default_factory=dict)


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
            total += 1 + count_spf_lookups(re.split('[:=]', t, maxsplit=1)[1], fetch_txt, depth + 1, seen)
        elif t.split(':')[0].split('/')[0] in ('a', 'mx', 'ptr', 'exists'):
            total += 1
    return total


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
                                f'The other {100 - int(pct)}% of failing mail is treated as p={weaker} (RFC 7489 \u00a76.6.4). Raise pct to 100.',
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


def _observed(findings, check, observations, confirmed):
    """Attach the DNS answers behind an absence finding, and whether two resolvers agreed on it (``store_findings`` holds an
    unconfirmed one back until the next run sees it too)."""
    for f in findings:
        if f.check == check:
            f.evidence = {**(f.evidence or {}), 'dns': observations, 'dns_confirmed': bool(confirmed)}


def is_ip(value):
    return bool(re.fullmatch(r'[\d.]+|[0-9a-fA-F:]+:[0-9a-fA-F:]*', value or ''))


def organizational_domain(name):
    from .names import apex_domain
    return apex_domain(name)


def email_findings(domain, fetch, mx, records):
    """SPF, DMARC, DKIM and CAA review for one domain, plus the checks adapted from MailFail (``mailfail``). Same rules as cvENGINE's
    ``hygiene.email_findings`` called with injected DNS: ``fetch(name)`` reads TXT records, ``mx(name, rtype)`` says whether a record exists and
    ``records(name, rtype)`` returns any other type as text. Every answer is taken at its word, from the one resolver the caller asks."""
    from . import mailfail
    askers, votes = _injected(fetch), 1
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
        findings += mailfail.review(domain, has_mx, txt, dmarc, found, fetch, records)
    except Exception:  # noqa: BLE001 - the established checks above stand on their own
        logger.exception('MailFail checks failed for %s', domain)
    return findings, has_mx
