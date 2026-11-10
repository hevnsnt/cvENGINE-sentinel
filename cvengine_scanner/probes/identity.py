"""Who a name or an address says it is, read from this Sentinel (the ``identity_check`` kind): the DNS reads and the certificate read that
cvENGINE used to make from its own server.

cvENGINE asks, and decides what an answer means (``cveFeed.hosting.canonical_name``, ``cveFeed.domain_ownership``, ``cveFeed.discovery.discover_ip``);
this module only asks. Two lists, both under the task's scope policy:

- ``dns``: ``[{id, name, type}]`` with ``type`` one of ``A`` (the addresses of a name, A and AAAA records: what cvENGINE's archived-host and
  unresolved-host checks read), ``CNAME`` (the name a hostname's alias chain ends at: the answer's canonical name when the
  name has an address, none when it does not), ``NS`` and ``MX`` (the record texts of a domain) and ``PTR`` (``name`` is an address). Each answer is
  ``ok`` (with its records), ``none`` (the resolver answered that there is nothing: NXDOMAIN or no such record) or ``unknown`` (a timeout, a
  failure, a refusal by the policy): cvENGINE never reads ``unknown`` as ``none``.
- ``certs``: ``[{id, host, port}]``: the names on the certificate a TLS endpoint serves (the subject's common name, then every DNS subject
  alternative name). The handshake verifies nothing (a broken certificate still names its hosts), sends nothing and is closed at once.

Every name must pass the policy before it is asked and every address the policy and this Sentinel's floor allow before it is connected to.
"""
import logging
import socket
import ssl

from . import names, transport
from .policy import ScopePolicy

logger = logging.getLogger(__name__)

MAX_DNS = 200
MAX_CERTS = 50
MAX_RECORDS = 50
MAX_NAMES = 100
DNS_TYPES = ('A', 'CNAME', 'NS', 'MX', 'PTR')
DNS_TIMEOUT = 5  # seconds one question may take in all (the resolver's lifetime)
TLS_TIMEOUT = 3  # cveFeed.discovery.IP_LOOKUP_TIMEOUT: the connection and the handshake


def _dns_item(raw):
    if not isinstance(raw, dict):
        return None
    ident, name, rtype = raw.get('id'), raw.get('name'), raw.get('type')
    if not all(isinstance(v, str) and v for v in (ident, name)) or rtype not in DNS_TYPES:
        return None
    if len(name) > 260 or any(c.isspace() or ord(c) < 32 for c in name):
        return None
    name = names.clean(name).strip('[]')
    if (rtype == 'PTR') != names.is_ip(name):  # a PTR asks about an address, every other type about a name
        return None
    return {'id': ident[:200], 'name': name, 'type': rtype}


def _cert_item(raw):
    if not isinstance(raw, dict):
        return None
    ident, host, port = raw.get('id'), raw.get('host'), raw.get('port')
    if not all(isinstance(v, str) and v for v in (ident, host)) or len(host) > 260 or any(c.isspace() or ord(c) < 32 for c in host):
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    return {'id': ident[:200], 'host': names.clean(host).strip('[]'), 'port': port}


def _resolver():
    import dns.resolver
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver


def _texts(rrset, limit=MAX_RECORDS):
    return [rd.to_text()[:260] for rd in list(rrset)[:limit]]


def ask(item, policy, resolver):
    """``{'id', 'status', 'records', 'canonical'?, 'error'?}`` for one DNS question. Raises ``ValueError`` when the policy refuses it."""
    name = item['name']
    policy.check_host(name)
    if item['type'] == 'PTR':
        policy.check_address(name, literal=True)
    import dns.exception
    import dns.resolver
    import dns.reversename
    try:
        if item['type'] == 'A':
            found, unanswered = [], False
            for rtype in ('A', 'AAAA'):
                try:
                    found += [rd.to_text() for rd in resolver.resolve(name, rtype).rrset]
                except dns.resolver.NXDOMAIN:
                    break  # the name does not exist: there is no AAAA either
                except dns.resolver.NoAnswer:
                    continue
                except (dns.exception.DNSException, OSError):
                    unanswered = True
            if found:
                return {'id': item['id'], 'status': 'ok', 'records': list(dict.fromkeys(found))[:MAX_RECORDS]}
            if unanswered:  # a family nobody answered: that says nothing about the name
                return {'id': item['id'], 'status': 'unknown', 'records': [], 'error': 'no answer'}
            return {'id': item['id'], 'status': 'none', 'records': []}
        if item['type'] == 'CNAME':
            for rtype in ('A', 'AAAA'):  # the canonical name of a name that has an address: what getaddrinfo's CANONNAME gave
                answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
                if answer.rrset is not None:
                    canonical = names.clean(answer.canonical_name.to_text())
                    return {'id': item['id'], 'status': 'ok', 'records': [], 'canonical': '' if canonical == name else canonical}
            return {'id': item['id'], 'status': 'none', 'records': []}
        qname = dns.reversename.from_address(name) if item['type'] == 'PTR' else name
        answer = resolver.resolve(qname, item['type'])
        return {'id': item['id'], 'status': 'ok', 'records': _texts(answer.rrset)}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'id': item['id'], 'status': 'none', 'records': []}
    except (dns.exception.DNSException, OSError) as exc:  # a timeout, SERVFAIL, no nameserver: no answer, which says nothing about the name
        return {'id': item['id'], 'status': 'unknown', 'records': [], 'error': f'{type(exc).__name__}'[:200]}


def certificate_names(host, port, policy, timeout=TLS_TIMEOUT, handshake=None):
    """The names a TLS endpoint's certificate carries (the common name, then the DNS subject alternative names), or ``None`` when no certificate
    could be read. Raises ``ValueError`` when the policy refuses the endpoint."""
    literal = names.is_ip(host)
    if literal:
        policy.check_host(host)
        policy.check_address(host, literal=True)
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        addresses = ((family, (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)),)
    else:
        addresses = transport.resolve(host, port, policy)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # a broken certificate still says what it is for
    try:
        if handshake is not None:
            der = handshake(host, port, addresses, policy, context)
        else:
            with transport.open_socket(addresses, timeout, policy, host=host, literal=literal) as raw:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=None if literal else host) as tls:
                    der = tls.getpeercert(binary_form=True)
    except ValueError:
        raise
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 - a library that is missing or a certificate it cannot read: no names, reported as unknown
        return None
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    cn = next((str(a.value) for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), '')
    return [n[:260] for n in [cn, *sans] if n][:MAX_NAMES]


def run_batch(target, resolver=None, handshake=None):
    """Run an ``identity_check`` task: ``target['dns']`` and ``target['certs']`` under ``target['scope']``. Returns ``{'dns': [...], 'certs': [...],
    'touched', 'refused'}``. A question the policy refuses is reported ``unknown`` with an error; cvENGINE reads that as no answer, never as none."""
    raw_dns = target.get('dns') if isinstance(target.get('dns'), list) else []
    raw_certs = target.get('certs') if isinstance(target.get('certs'), list) else []
    if len(raw_dns) > MAX_DNS or len(raw_certs) > MAX_CERTS:
        raise ValueError(f'a task asks at most {MAX_DNS} DNS questions and {MAX_CERTS} certificates')
    dns_items = [_dns_item(i) for i in raw_dns]
    cert_items = [_cert_item(i) for i in raw_certs]
    if any(i is None for i in dns_items) or any(i is None for i in cert_items):
        raise ValueError('a question is malformed')
    policy = ScopePolicy(target.get('scope'))
    dns_out, cert_out = [], []
    for item in dns_items:
        try:
            if resolver is None:
                resolver = _resolver()
            dns_out.append(ask(item, policy, resolver))
        except ImportError:
            dns_out.append({'id': item['id'], 'status': 'unknown', 'records': [], 'error': 'no DNS library on this Sentinel'})
        except ValueError as exc:
            policy.refuse(item['name'])
            dns_out.append({'id': item['id'], 'status': 'unknown', 'records': [], 'error': f'not run: {exc}'[:200]})
        else:
            policy.touch(item['name'])
    for item in cert_items:
        try:
            found = certificate_names(item['host'], item['port'], policy, handshake=handshake)
        except ValueError as exc:
            policy.refuse(item['host'])
            cert_out.append({'id': item['id'], 'status': 'unknown', 'names': [], 'error': f'not run: {exc}'[:200]})
            continue
        if found is None:  # no certificate could be read (a closed port, a timeout, a refused handshake): no names, but not an answer either
            cert_out.append({'id': item['id'], 'status': 'unknown', 'names': []})
        else:
            cert_out.append({'id': item['id'], 'status': 'ok', 'names': found})
    return {'dns': dns_out, 'certs': cert_out, 'touched': policy.touched, 'refused': policy.refused}
