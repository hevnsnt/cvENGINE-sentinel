"""Is a domain registered, asked of its registry (RDAP): copied from cvENGINE's ``cveFeed.mailfail.rdap_registered``.

Used by the mail checks (a domain an SPF include or a DMARC report address names that nobody has registered can be taken) and by the dangling DNS
rating (a CNAME target whose registrable domain is free can be taken). IANA's bootstrap file names each registry's RDAP server; only an HTTPS server
is used, no redirect is followed, and only an explicit "not found" counts as unregistered. A registry is a public service no task names, so every
connection is made under a policy derived from the task's own, which allows that one host, keeps the task's exclusions and address rules, and
(like every probe connection) the Sentinel's floor: it never reaches a private address, whatever the bootstrap file says.
"""
import json
import ssl
import time
from urllib.parse import quote, urlsplit

from . import transport
from .policy import ScopePolicy

HTTP_TIMEOUT = 5
MAX_BODY = 1024 * 1024
BOOTSTRAP = 'https://data.iana.org/rdap/dns.json'
_CACHE = {'at': 0.0, 'services': None}


def _derived(policy, host):
    """A policy that allows ``host`` and nothing else, with the task's exclusions, address rules and network setting."""
    doc = policy.to_doc() if policy is not None else {}
    doc.update({'hosts': [host], 'domains': [], 'excluded_trees': doc.get('excluded_trees', [])})
    return ScopePolicy(doc, internal=getattr(policy, 'internal', None))


def get_https(url, policy):
    """``(status, body)`` of a GET of an https URL (no redirect, at most 1 MB), or None when it cannot be asked or got no answer."""
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    if parts.scheme != 'https' or not host or parts.username or parts.password:
        return None
    derived = _derived(policy, host)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        addresses = transport.resolve(host, parts.port or 443, derived)
        conn = transport.HTTPConnection(host, parts.port or 443, addresses, HTTP_TIMEOUT, derived, context=context)
    except (OSError, ValueError):
        _carry(policy, derived)
        return None
    try:
        conn.request('GET', (parts.path or '/') + (f'?{parts.query}' if parts.query else ''),
                     headers={'Host': host, 'Accept': 'application/rdap+json, application/json', 'User-Agent': 'CVEngine'})
        resp = conn.getresponse()
        return resp.status, transport.read_body(resp, MAX_BODY)
    except Exception:  # noqa: BLE001 - no answer is never a finding
        return None
    finally:
        conn.close()
        _carry(policy, derived)


def _carry(policy, derived):
    if policy is not None:
        for host in derived.touched:
            policy.touch(host)
        for host in derived.refused:
            policy.refuse(host)


def _services(get, policy):
    """IANA's RDAP bootstrap for domains (RFC 9224), cached for a day."""
    if _CACHE['services'] is None or time.time() - _CACHE['at'] > 86400:
        got = get(BOOTSTRAP, policy)
        if not got or got[0] != 200:
            raise OSError('no RDAP bootstrap')
        _CACHE['services'], _CACHE['at'] = json.loads(got[1].decode('utf-8', 'replace')).get('services', []), time.time()
    return _CACHE['services']


def registered(name, policy, get=None):
    """True or False when the domain's registry answers, None when it cannot tell (no RDAP server, an error, a redirect, a policy refusal).
    ``get(url, policy)`` replaces the network (tests)."""
    get = get or get_https
    try:
        tld = name.rsplit('.', 1)[-1].lower()
        base = next((urls[0] for tlds, urls in _services(get, policy) if tld in [t.lower() for t in tlds] and urls), None)
        if not base or not base.lower().startswith('https://'):
            return None
        got = get(base.rstrip('/') + f'/domain/{quote(name, safe=".-_")}', policy)
    except Exception:  # noqa: BLE001 - no answer is never a finding
        return None
    if got is None:
        return None
    if got[0] == 200:
        return True
    if got[0] == 404:
        return False
    return None
