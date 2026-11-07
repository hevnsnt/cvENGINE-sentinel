"""The signed-in web route check, the ``route_probe_signed`` kind: the routes of ``routes`` asked once each with the stored sign-in the task names.

cvENGINE (``cveFeed.auth_routes``) decides which routes a sign-in covers and stores what comes back beside the anonymous answer; this module asks. It is the
one probe that sends a credential, so every rule below is checked here again, from the credential itself, whatever the task says:

- the credential is sent only to a route whose host, scheme and port the stored sign-in was stored for (``SignIn.applies``: the exact stored host, or for a
  target-wide one the target's own name and, unless the target is host-only, its subdomains; ``scheme:port`` among its origins; not expired) and that the
  task's scope policy allows;
- one GET per route, no redirect followed (a redirect is classified from its ``Location`` and never requested), no script read, no comparison request,
  nothing else is asked of the host;
- the server certificate is verified before anything is sent, unless the stored sign-in's owner switched that off; a route not sent for that reason is
  reported with the error ``http.UNTRUSTED_CERTIFICATE``;
- the body of a signed-in page is classified (open, a login page, a redirect...) and dropped: never searched for sensitive data, never returned, no
  credential taken from it; the evidence kept is the markers, the byte count, the redirect target and the provider;
- a route that could not be asked is reported with an error and no state (cvENGINE reads it as unknown and asks again).

The values are never put in an error, a log line or the result: ``client.signed_in.run_sign_in`` redacts the whole result and every error, and nothing here
logs more than an exception's type.
"""
import concurrent.futures
import datetime
import ipaddress
import logging
import re
import time
from urllib.parse import urlsplit

from . import http, routes

logger = logging.getLogger(__name__)

MAX_HEADERS = 12
FORBIDDEN_HEADERS = frozenset({'host', 'content-length', 'transfer-encoding', 'connection', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'expect'})
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
KEEP_EVIDENCE = ('markers', 'bytes', 'provider', 'redirect_to')


class SignInError(ValueError):
    """The stored sign-in cannot be used. The message never contains a value."""


def _bare(host):
    host = str(host or '').strip().lower().rstrip('.')
    return host[1:-1] if host.startswith('[') and host.endswith(']') else host


def _clean_value(value):
    return isinstance(value, str) and value != '' and len(value) <= 8192 and not any((ord(c) < 32 and c != '\t') or ord(c) == 127 for c in value)


class SignIn:
    """One stored credential as the server hands it over: ``headers`` (``[(name, value)]``, the cookie last as ``Cookie``), and where it may go."""

    def __init__(self, headers, target, host, origins, host_scoped, allow_untrusted, expires_at):
        self.headers, self.target, self.host, self.origins = headers, target, host, origins
        self.host_scoped, self.allow_untrusted, self.expires_at = host_scoped, allow_untrusted, expires_at

    @classmethod
    def parse(cls, raw):
        """A ``SignIn`` from the server's credential document, or ``SignInError``. Every header name must be a plain token that is not one that frames the
        request, and every value one line without control characters; the destination fields must be well formed, or nothing is sent."""
        headers = []
        for pair in raw.get('headers') or []:
            if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
                continue
            name, value = pair
            if not isinstance(name, str) or not _TOKEN.match(name.strip()) or name.strip().lower() in FORBIDDEN_HEADERS or name.strip().lower() == 'cookie':
                raise SignInError('the stored sign-in has a header this check will not send')
            if not _clean_value(value):
                raise SignInError('the stored sign-in has a header value this check will not send')
            headers.append((name.strip(), value))
        cookie = raw.get('cookie')
        if isinstance(cookie, str) and cookie:
            if not _clean_value(cookie):
                raise SignInError('the stored sign-in has a cookie this check will not send')
            headers.append(('Cookie', cookie))
        if not headers or len(headers) > MAX_HEADERS:
            raise SignInError('the stored sign-in has nothing to send' if not headers else 'the stored sign-in has too many headers')
        origins = raw.get('origins')
        if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
            raise SignInError('the stored sign-in names no origin')
        host = _bare(raw.get('host')) if raw.get('host') else ''
        target = _bare(raw.get('target'))
        if not host and not target:
            raise SignInError('the stored sign-in names no host and no target')
        expires = raw.get('expires_at')
        if expires in (None, ''):
            expires_at = None
        else:
            try:
                expires_at = datetime.datetime.fromisoformat(str(expires).replace('Z', '+00:00'))
            except ValueError:
                raise SignInError('the stored sign-in has an expiry this check cannot read') from None
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        return cls(headers, target, host, {o.strip().lower() for o in origins}, raw.get('host_scoped') is not False,  # unknown reads as host-only: the strict rule
                   raw.get('allow_untrusted_certificate') is True, expires_at)

    def clear(self):
        self.headers.clear()

    def expired(self, now=None):
        now = now or datetime.datetime.now(datetime.timezone.utc)
        return self.expires_at is not None and self.expires_at <= now

    def applies(self, host, scheme, port, now=None):
        """Whether this sign-in may be sent to ``scheme://host:port`` (the server's ``AuthScope.credential`` rule for one credential)."""
        host, scheme = _bare(host), str(scheme or '').lower()
        if not host or scheme not in ('http', 'https') or self.expired(now):
            return False
        try:
            if f'{scheme}:{int(port)}' not in self.origins:
                return False
        except (TypeError, ValueError):
            return False
        if self.host:
            return host == self.host
        if host == self.target:
            return True
        try:
            ipaddress.ip_address(self.target)
            return False  # a target that is an address has no subdomains
        except ValueError:
            return not self.host_scoped and host.endswith('.' + self.target)


def _port(parts):
    return parts.port if parts.port is not None else (443 if parts.scheme == 'https' else 80)


def _signed_row(url, probe_result):
    """The row for one signed-in answer: its state and the few facts a signed-in answer keeps. Never the body, never a value found in it."""
    state, evidence = routes.classify({**probe_result, 'body': probe_result.get('body') or ''})
    kept = {key: evidence[key] for key in KEEP_EVIDENCE if key in evidence}
    status = probe_result.get('status')
    return {'id': url, 'status': status if isinstance(status, int) and not isinstance(status, bool) else None, 'title': (probe_result.get('title') or '')[:300],
            'content_type': (probe_result.get('content_type') or '')[:100], 'state': state, 'evidence': kept, 'sensitive': {}, 'sensitive_score': 0,
            'bytes': int(probe_result.get('bytes') or 0), 'credentials': []}


def run_host(host, urls, policy, sign_in, probe=None, sleep=time.sleep, clock=time.monotonic, deadline=None, now=None):
    """The rows for one host's routes, one after another (``routes.PER_REQUEST_GAP`` between requests): ``{url: row}``."""
    probe = probe or http.probe_url
    out = {}
    why = policy.host_refusal(host)
    if why:
        policy.refuse(host)
        return {url: {'id': url, 'error': f'not run: the host is {why}'} for url in urls}
    asked = 0
    for url in urls:
        parts = urlsplit(url)
        if not sign_in.applies(parts.hostname, parts.scheme, _port(parts), now):
            out[url] = {'id': url, 'error': 'not run: the stored sign-in does not cover this route'}
            continue
        if deadline is not None and clock() > deadline:
            out[url] = {'id': url, 'error': 'not run: the task ran out of time'}
            continue
        if asked:
            sleep(routes.PER_REQUEST_GAP)
        asked += 1
        try:
            answer = probe(url, policy, max_bytes=routes.ROOT_READ_BYTES if (parts.path or '/') == '/' else routes.ROUTE_SAMPLE_BYTES,
                           signed=sign_in.headers, verify=not sign_in.allow_untrusted)
            out[url] = _signed_row(url, answer)
        except http.UntrustedCertificate:
            out[url] = {'id': url, 'error': http.UNTRUSTED_CERTIFICATE}
        except Exception as exc:  # noqa: BLE001 - a timeout or refused connection is not an auth state; the type is all that is logged
            logger.info('signed-in route probe of %s failed: %s', host, type(exc).__name__)
            out[url] = {'id': url, 'error': f'{type(exc).__name__}: {exc}'[:200]}
    return out


def run_batch(target, sign_in, probe=None, sleep=time.sleep, clock=time.monotonic, workers=routes.HOST_WORKERS, max_seconds=routes.BATCH_SECONDS):
    """Run a ``route_probe_signed`` task: ``target['hosts']`` (as ``route_probe``) under ``target['scope']``, with ``sign_in`` (a ``SignIn``).
    Returns ``{'routes': [...], 'touched': [hosts asked], 'refused': [hosts a hop was refused for]}`` in the shape of ``route_probe``'s result."""
    from .policy import ScopePolicy
    policy = ScopePolicy(target.get('scope'))
    raw = target.get('hosts') if isinstance(target.get('hosts'), list) else []
    if not raw or len(raw) > routes.MAX_HOSTS:
        raise ValueError(f'a task names from 1 to {routes.MAX_HOSTS} hosts')
    groups = [routes._group(item) for item in raw]
    if any(g is None for g in groups):
        raise ValueError('a host of the task is malformed')
    deadline = clock() + max_seconds
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(run_host, g['host'], g['urls'], policy, sign_in, probe, sleep, clock, deadline) for g in groups]
        results = [future.result() for future in futures]
    rows = []
    for group, got in zip(groups, results):
        rows += [got[url] for url in group['urls'] if url in got]
    return {'routes': rows, 'touched': policy.touched, 'refused': policy.refused}
