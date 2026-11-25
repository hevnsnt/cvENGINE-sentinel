"""Is Direct Send open on a Microsoft 365 tenant: tested over SMTP, never guessed from DNS.

Direct Send lets anyone on the internet hand mail to a tenant's MX host (``<tenant>.mail.protection.outlook.com``) with one of the tenant's own
domains as the sender, so it lands looking internal. Microsoft's ``RejectDirectSend`` setting refuses that at the recipient step with
``550 5.7.68 TenantInboundAttribution``. A finding is raised only when the tenant was asked and accepted: an MX pointing at Microsoft 365 alone
proves nothing (new tenants reject Direct Send by default), so it is never a finding.

The test stops before any message exists: one connection to the vetted MX address on port 25, EHLO, STARTTLS when offered, ``MAIL FROM`` an
address in the domain under test, ``RCPT TO`` a role address of that domain (the next one only while the answer decides nothing), then RSET and
QUIT. ``DATA`` is never sent, so nothing is delivered and nothing on the tenant changes. The MX host is a public Microsoft service the task does
not name, so the connection is made under a policy derived from the task's own (that host only, the task's exclusions and address rules, this
Sentinel's floor), like the registry lookups of ``probes.rdap``. Anything but a clear answer (no route to port 25, a timeout, an unknown
recipient everywhere, any other reply) is ``inconclusive`` and is never a finding.
"""
import smtplib
import ssl

from . import transport
from .policy import ScopePolicy

PORT = 25
TIMEOUT = 15
PROBE_LOCAL = 'cvengine-direct-send-test'
RECIPIENTS = ('postmaster', 'abuse', 'security', 'admin', 'info')
REJECTED_MARK = '5.7.68'
M365_MX = ('mail.protection.outlook.com', 'mail.protection.partner.outlook.cn')
MAX_REPLY = 200


def m365_hosts(mx_hosts):
    """The MX hosts that are Microsoft 365 tenant endpoints, cleaned and in order."""
    hosts = [h.rstrip('.').lower() for h in mx_hosts if isinstance(h, str)]
    return [h for h in hosts if h.endswith(M365_MX)]


def _derived(policy, host):
    """A policy that allows ``host`` and nothing else, with the task's exclusions, address rules and network setting."""
    doc = policy.to_doc() if policy is not None else {}
    doc.update({'hosts': [host], 'domains': []})
    return ScopePolicy(doc, internal=getattr(policy, 'internal', None))


def _carry(policy, derived):
    if policy is not None:
        for host in derived.touched:
            policy.touch(host)
        for host in derived.refused:
            policy.refuse(host)


def _reply(code, message):
    text = message.decode('utf-8', 'replace') if isinstance(message, bytes) else str(message or '')
    return f'{code} {" ".join(text.split())}'[:MAX_REPLY]


def classify(code, message):
    """'accepted', 'rejected' or None (this answer decides nothing) for the reply to MAIL FROM or RCPT TO."""
    text = message.decode('utf-8', 'replace') if isinstance(message, bytes) else str(message or '')
    if REJECTED_MARK in text:
        return 'rejected'
    if code in (250, 251):
        return 'accepted'
    return None


class _PinnedSMTP(smtplib.SMTP):
    """smtplib over a socket this module opened to a vetted numeric address (the name is kept for STARTTLS's server name check)."""

    def __init__(self, sock, server_name):
        self._pinned, self._server_name = sock, server_name
        super().__init__(timeout=TIMEOUT)

    def _get_socket(self, host, port, timeout):
        return self._pinned


def session(domain, mx_host, smtp, recipients=RECIPIENTS):
    """Run the dialog on a connected ``smtp`` (an smtplib.SMTP-like object) and return the result; never sends DATA."""
    mail_from = f'{PROBE_LOCAL}@{domain}'
    transcript = []
    result = {'outcome': 'inconclusive', 'mx': mx_host, 'mail_from': mail_from, 'rcpt': '', 'reply': '', 'transcript': transcript}
    try:
        code, msg = smtp.connect(mx_host, PORT)
        transcript.append(_reply(code, msg))
        if code != 220:
            return result
        smtp.ehlo('cvengine-sentinel.invalid')
        if smtp.has_extn('starttls'):
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            code, msg = smtp.starttls(context=context)
            transcript.append('STARTTLS ' + _reply(code, msg))
            smtp.ehlo('cvengine-sentinel.invalid')
        code, msg = smtp.mail(mail_from)
        transcript.append(f'MAIL FROM:<{mail_from}> ' + _reply(code, msg))
        verdict = classify(code, msg)
        if verdict == 'rejected' or code != 250:
            result.update(outcome=verdict or 'inconclusive', reply=_reply(code, msg))
            return result
        for local in recipients:
            rcpt = f'{local}@{domain}'
            code, msg = smtp.rcpt(rcpt)
            transcript.append(f'RCPT TO:<{rcpt}> ' + _reply(code, msg))
            verdict = classify(code, msg)
            if verdict:
                result.update(outcome=verdict, rcpt=rcpt, reply=_reply(code, msg))
                return result
        return result
    except (OSError, smtplib.SMTPException, ssl.SSLError, ValueError):
        return result
    finally:
        for step in ('rset', 'quit'):
            try:
                getattr(smtp, step)()
            except Exception:  # noqa: BLE001 - the connection may already be gone
                pass
        try:
            smtp.close()
        except Exception:  # noqa: BLE001
            pass


def test(domain, mx_host, policy, connect=None):
    """The Direct Send result for ``domain`` at ``mx_host``. ``connect(mx_host, derived_policy)`` returns a connected smtplib-like object
    (tests); by default the MX name is resolved once, every address is judged, and only a vetted numeric address is connected to."""
    derived = _derived(policy, mx_host)
    try:
        if connect is not None:
            smtp = connect(mx_host, derived)
        else:
            addresses = transport.resolve(mx_host, PORT, derived)
            sock = transport.open_socket(addresses, TIMEOUT, derived, host=mx_host)
            smtp = _PinnedSMTP(sock, mx_host)
    except (OSError, ValueError, smtplib.SMTPException):
        _carry(policy, derived)
        return {'outcome': 'inconclusive', 'mx': mx_host, 'mail_from': f'{PROBE_LOCAL}@{domain}', 'rcpt': '', 'reply': '',
                'transcript': []}
    try:
        return session(domain, mx_host, smtp)
    finally:
        _carry(policy, derived)
