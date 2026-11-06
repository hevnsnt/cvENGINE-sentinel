"""The certificate and TLS posture of one name on port 443, copied from cvENGINE's ``cveFeed.hygiene`` (the ``supplier_check`` kind).

``evaluate_cert`` and the clip are pure. ``probe_tls`` reads the certificate without verifying it (so a broken certificate can still be read),
then asks the system trust store whether it would be accepted, then whether TLS 1.0 / 1.1 are still spoken (``legacy_tls``, the one module that
speaks them). Every connection goes to numeric addresses the caller vetted against the task's scope policy (``transport``), never to a name.
The ``cryptography`` package is imported only when a certificate is read.
"""
import datetime
import re
import socket
import ssl

from . import legacy_tls, transport
from .mail_checks import CRITICAL, HIGH, LOW, MEDIUM, Finding, is_ip

TLS_TIMEOUT = 5


EXPIRY_BANDS = ((0, CRITICAL, 'has expired'), (7, HIGH, 'expires within 7 days'),
                (30, MEDIUM, 'expires within 30 days'), (60, LOW, 'expires within 60 days'))


def hostname_matches(hostname, names):
    """Certificate name match with single-label wildcards (``*.example.com``)."""
    hostname = hostname.lower().rstrip('.')
    for name in names:
        name = name.lower().rstrip('.')
        if name == hostname:
            return True
        if name.startswith('*.') and hostname.count('.') >= name.count('.') and hostname.split('.', 1)[1:] == [name[2:]]:
            return True
    return False


def evaluate_cert(info, now=None):
    """Findings for one certificate. ``info`` keys: host, port, not_after (datetime), sans, subject, signature_algorithm,
    key_description ('RSA 2048'), protocol, chain_error, legacy_tls."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    host, port = info['host'], info['port']
    where = f'{host}:{port}'
    findings = []
    if info.get('not_after'):
        days = (info['not_after'] - now).days
        for limit, severity, phrase in EXPIRY_BANDS:
            if days < limit or (limit == 0 and info['not_after'] <= now):
                code = 'tls_expired' if limit == 0 else 'tls_expiring'
                title = f'Certificate for {where} {phrase}' if limit else f'Certificate for {where} expired {-days} days ago'
                if limit and days >= 0:
                    title += f' ({days} days left)'
                findings.append(Finding(code, severity, title, f'Valid until {info["not_after"]:%Y-%m-%d}.', where,
                                        {'days_left': days, 'not_after': info['not_after'].isoformat(),
                                         **({'issuer': str(info['issuer'])[:200]} if info.get('issuer') else {})}))
                break
    names = list(info.get('sans') or [])
    if info.get('subject') and info['subject'] not in names:
        names.append(info['subject'])
    if names and not is_ip(host) and not hostname_matches(host, names):
        findings.append(Finding('tls_hostname_mismatch', HIGH, f'Certificate for {where} does not cover {host}',
                                f'It is valid for: {", ".join(names[:6])}.', where, {'names': names[:20]}))
    err = (info.get('chain_error') or '').lower()
    if err and 'hostname mismatch' not in err and 'ip address mismatch' not in err and 'expired' not in err:
        if 'self-signed' in err or 'self signed' in err:
            findings.append(Finding('tls_self_signed', MEDIUM, f'{where} uses a self-signed certificate',
                                    'Browsers and clients will not trust it.', where, {'error': info['chain_error']}))
        else:
            findings.append(Finding('tls_untrusted_chain', MEDIUM, f'{where} certificate chain is not trusted',
                                    info['chain_error'], where, {'error': info['chain_error']}))
    sig = (info.get('signature_algorithm') or '').lower()
    if 'md5' in sig or 'sha1' in sig:
        findings.append(Finding('tls_weak_signature', HIGH, f'{where} certificate is signed with {info["signature_algorithm"]}',
                                'SHA-1 and MD5 signatures can be forged. Reissue with SHA-256.', where, {'signature': info['signature_algorithm']}))
    key = info.get('key_description') or ''
    m = re.fullmatch(r'RSA (\d+)', key)
    if m and int(m.group(1)) < 2048:
        findings.append(Finding('tls_weak_key', HIGH, f'{where} uses a {m.group(1)}-bit RSA key', 'Use at least 2048 bits.', where, {'key': key}))
    if info.get('protocol') in ('TLSv1', 'TLSv1.1', 'SSLv3') or info.get('legacy_tls'):
        findings.append(Finding('tls_legacy_protocol', MEDIUM, f'{where} still accepts TLS 1.0 / 1.1',
                                'Disable TLS 1.0 and 1.1; keep TLS 1.2 and 1.3.', where, legacy_evidence(info)))
    return findings


def legacy_evidence(info):
    """The evidence of a legacy-protocol finding: the TLS 1.0 / 1.1 handshake that completed (the version the server chose and the cipher),
    not the modern handshake the certificate was read over. ``protocol`` is the legacy version; ``modern_protocol`` the one a current client
    got, when it got one."""
    legacy = info.get('legacy_handshake') if isinstance(info.get('legacy_handshake'), dict) else {}
    protocol, cipher = legacy.get('protocol') or '', legacy.get('cipher') or ''
    if not protocol and info.get('protocol') in ('TLSv1', 'TLSv1.1', 'SSLv3'):  # the certificate itself was read over the old protocol
        protocol, cipher = info.get('protocol'), info.get('cipher') or ''
    evidence = {'protocol': protocol or 'TLSv1.0 / 1.1', 'cipher': cipher,
                'handshake': (f'{protocol} handshake completed' + (f' with {cipher}' if cipher else '')) if protocol else
                             'a TLS 1.0 / 1.1 handshake completed'}
    if info.get('protocol') and info.get('protocol') != protocol:
        evidence['modern_protocol'] = info.get('protocol')
    return evidence


CERT_TEXT_LIMITS = {'subject': 500, 'issuer': 500, 'signature_algorithm': 100, 'key_description': 100, 'protocol': 20, 'cipher': 100,
                    'chain_error': 300}


MAX_CERT_SANS = 200


MAX_CERT_SAN_LENGTH = 255


def clip_certificate(info):
    """A copy of a probed certificate whose text fits the TlsCertificate columns and whose name list is bounded. A server can present
    a certificate with a 10 KB subject or 50,000 names; storing it as is would raise and drop the rest of the domain's TLS review."""
    out = dict(info)
    for key, limit in CERT_TEXT_LIMITS.items():
        out[key] = str(out.get(key) or '')[:limit]
    out['sans'] = [str(name)[:MAX_CERT_SAN_LENGTH] for name in (out.get('sans') or [])[:MAX_CERT_SANS]]
    return out


def _fetch_cert(host, port, policy, addresses, timeout=TLS_TIMEOUT, legacy=False):
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
            with transport.open_socket(addresses, timeout, policy, host=host) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
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


def _chain_error(host, port, policy, addresses, timeout=TLS_TIMEOUT):
    """Empty string if the system trust store accepts the certificate for this host, else the reason."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with transport.open_socket(addresses, timeout, policy, host=host) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return ''
    except ssl.SSLCertVerificationError as exc:
        return (exc.verify_message or str(exc))[:300]
    except (OSError, ssl.SSLError, ValueError):
        return ''


def probe_tls(host, port, policy, addresses):
    """Read the certificate and TLS posture of ``host:port`` at ``addresses`` (numeric ``(family, sockaddr)`` pairs the caller vetted against
    ``policy``). ``None`` when no certificate could be read."""
    info = _fetch_cert(host, port, policy, addresses)
    if info:
        info['chain_error'] = _chain_error(host, port, policy, addresses)
        legacy = legacy_tls.negotiated(host, port, TLS_TIMEOUT, policy, addresses=addresses)
        info['legacy_tls'] = bool(legacy)
        if isinstance(legacy, dict):
            info['legacy_handshake'] = legacy
        return info
    info = _fetch_cert(host, port, policy, addresses, legacy=True)  # a modern client cannot read servers that only speak TLS 1.0 / 1.1
    if info:
        info['chain_error'] = 'cannot be verified: the server only speaks TLS 1.0 / 1.1'
        info['legacy_tls'] = True
        info['legacy_handshake'] = {'protocol': info.get('protocol') or '', 'cipher': info.get('cipher') or ''}
    return info
