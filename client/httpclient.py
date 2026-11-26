"""A small, typed wrapper over ``requests`` for the handful of REST calls the Sentinel client makes
(``docs/AGENT-API.md``): bootstrap, ``PUT sentinel`` (registration), heartbeat, tasks/next, accept, result, release. No
retry logic lives here; the daemon's own poll loop decides when to back off (see ``daemon.Daemon._poll_once``), so one
place owns that policy.

The server URL must be ``https`` (``validate_server_url``), so the enrollment token, this Sentinel's bearer token and
every result travel encrypted, and redirects are never followed: a 3xx is an ``ApiError``, so a POST never silently
turns into a GET elsewhere. The session keeps ``trust_env`` on, so ``HTTPS_PROXY``/``NO_PROXY`` still work behind a
corporate proxy.
"""
import hashlib
import json
import logging
from urllib.parse import urlsplit

import requests

from . import config

logger = logging.getLogger('sentinel.http')

MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # the most a ``call`` reads of one answer: a task, a heartbeat or an error is a few kilobytes, a hostile or broken server must not fill the 2 GB of memory
DEFAULT_TIMEOUT = 30  # seconds per call; the long poll's own wait (config.DEFAULT_POLL_WAIT) fits well inside it


MAX_RETRY_AFTER = 120.0


def parse_retry_after(value):
    """The seconds in a ``Retry-After`` header (delta-seconds; an HTTP date is not used by this server), at most ``MAX_RETRY_AFTER``, or None."""
    try:
        seconds = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if seconds != seconds or seconds < 0 or seconds == float('inf'):
        return None
    return min(seconds, MAX_RETRY_AFTER)


class ApiError(Exception):
    """The server answered with a 3xx/4xx/5xx. ``status`` and ``message`` are set; the message is already a short string
    the server chose to show (or one this client wrote), never a raw response body (which could be arbitrarily large or
    not be JSON at all)."""

    def __init__(self, status, message, retry_after=None, code=None, reason=None, refusal=None, json_error=None, excerpt=None):
        super().__init__(f'{status}: {message}')
        self.status = status
        self.message = message
        self.retry_after = retry_after  # seconds the server asked to wait (Retry-After on a 429 or 503), or None
        self.code = code  # the machine-readable ``code`` of the error body (``agent_blocked``, ``token_revoked``, ...), or None from an older server
        self.reason = reason  # the error body's human ``reason`` next to that code, or None
        self.refusal = refusal  # ``X-CVEngine-Refusal``: the server refused this ADDRESS (``banned``, ``not_allowlisted``), never the token; None when absent
        self.json_error = json_error  # True when the body was the server's JSON error (``{"error": ...}``), False when it was not, None when unknown
        self.excerpt = excerpt  # the first printable characters of a body that was not a JSON error (a ban or proxy page), for the log, or None


REFUSAL_HEADER = 'X-CVEngine-Refusal'  # the server marks a 403 that refuses this Sentinel's ADDRESS (a ban, its IP allowlist) with it
EXCERPT_MAX = 200


def body_excerpt(raw):
    """The first ``EXCERPT_MAX`` printable characters of a reply body (markup tags dropped, runs of space folded), for one log line; '' when empty."""
    import re
    text = raw[:4096].decode('utf-8', 'replace') if isinstance(raw, (bytes, bytearray)) else str(raw or '')[:4096]
    text = re.sub(r'<[^>]{0,200}>', ' ', text)
    text = ''.join(c if c.isprintable() else ' ' for c in text)
    return ' '.join(text.split())[:EXCERPT_MAX]


class ServerURLError(ValueError):
    """A server URL this client refuses to talk to. The message says why and never repeats the URL, which could carry
    credentials in its userinfo or query."""


def validate_server_url(url):
    """``url`` unchanged when it is a usable CVEngine base URL, else ``ServerURLError``. It must be ``https`` (plain
    ``http`` only with ``CVENGINE_SENTINEL_ALLOW_INSECURE=1``, which logs a warning every time), name a host, and carry
    no userinfo, query or fragment. Called for the blob's URL, the token file's, and by every ``Client``."""
    if not isinstance(url, str) or not url.strip() or any(not c.isprintable() or c.isspace() for c in url):
        raise ServerURLError('the server URL is empty or contains spaces or control characters')
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 (raises ValueError on a port that is not a number in range)
    except ValueError as exc:
        raise ServerURLError('the server URL cannot be parsed') from exc
    scheme = parts.scheme.lower()
    if scheme == 'http' and config.allow_insecure():
        logger.warning('INSECURE: talking to the server over plain http because CVENGINE_SENTINEL_ALLOW_INSECURE=1; the tokens and every '
                       'result travel unencrypted')
    elif scheme != 'https':
        raise ServerURLError('the server URL must start with https:// (set CVENGINE_SENTINEL_ALLOW_INSECURE=1 to allow http:// on a trusted '
                             'network)')
    if '@' in parts.netloc:
        raise ServerURLError('the server URL must not contain a user name or password')
    if '?' in url or '#' in url:
        raise ServerURLError('the server URL must not contain a query or fragment')
    if not parts.hostname:
        raise ServerURLError('the server URL names no host')
    return url


class Client:
    """One Sentinel's connection to one CVEngine instance. ``token`` is optional only for the very first call
    (``sentinels/bootstrap``, which needs none); every other call requires it. Raises ``ServerURLError`` for a
    server URL ``validate_server_url`` refuses."""

    def __init__(self, server_url, token=None, timeout=DEFAULT_TIMEOUT, session=None):
        self.base = validate_server_url(server_url).rstrip('/') + '/api/v1/'
        self.token = token
        self.timeout = timeout
        self.session = session or requests.Session()

    def _headers(self):
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def call(self, method, path, body=None, timeout=None, max_bytes=MAX_RESPONSE_BYTES):
        """One REST call; returns the decoded JSON body. Raises ``ApiError`` on a 3xx (never followed), 4xx or 5xx, or on an answer larger than
        ``max_bytes`` (502: read only up to that, never the whole body), or ``requests.RequestException`` on a network failure (connection refused,
        DNS, timeout): the caller (``daemon``) decides how to back off from each, never this method."""
        url = self.base + path.lstrip('/')
        data = json.dumps(body).encode('utf-8') if body is not None else None
        response = self.session.request(method, url, data=data, headers=self._headers(), allow_redirects=False, stream=True,
                                        timeout=timeout if timeout is not None else self.timeout)
        try:
            if 300 <= response.status_code < 400:
                raise ApiError(response.status_code, 'the server answered with a redirect, which this Sentinel never follows: '
                                                     'check the server URL (scheme, host and path)')
            too_big = ApiError(502, f'the server answered with more than the {max_bytes} bytes this Sentinel reads of one answer')
            declared = (response.headers or {}).get('Content-Length', '')
            if str(declared).isdigit() and int(declared) > max_bytes:
                raise too_big
            raw = b''
            for chunk in response.iter_content(chunk_size=64 * 1024):
                raw += chunk
                if len(raw) > max_bytes:
                    raise too_big
        finally:
            response.close()
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {}
        if response.status_code >= 400:
            body = payload if isinstance(payload, dict) else {}
            message = body.get('error') or f'HTTP {response.status_code}'
            code, reason = body.get('code'), body.get('reason')
            refusal = str((response.headers or {}).get(REFUSAL_HEADER) or '').strip()[:32] or None
            json_error = bool(body.get('error'))
            raise ApiError(response.status_code, str(message)[:300], retry_after=parse_retry_after(response.headers.get('Retry-After')),
                           code=code[:64] if isinstance(code, str) and code else None, reason=reason[:300] if isinstance(reason, str) and reason else None,
                           refusal=refusal, json_error=json_error, excerpt=None if json_error else body_excerpt(raw))
        return payload if isinstance(payload, dict) else {}

    def download(self, path, destination, max_bytes, timeout=None):
        """GET ``path`` and write the body to ``destination`` (a binary file object), at most ``max_bytes`` of it; returns ``(sha256 hex of exactly the
        bytes written, their count)``. Same rules as ``call``: redirects are never followed and any 3xx/4xx/5xx is an ``ApiError``; a body past
        ``max_bytes`` is an ``ApiError`` too, so a hostile or broken server cannot fill the disk."""
        url = self.base + path.lstrip('/')
        headers = {'Accept': 'application/octet-stream, application/gzip, */*'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        response = self.session.request('GET', url, headers=headers, allow_redirects=False, stream=True,
                                        timeout=timeout if timeout is not None else self.timeout)
        try:
            if 300 <= response.status_code < 400:
                raise ApiError(response.status_code, 'the server answered with a redirect, which this Sentinel never follows')
            if response.status_code >= 400:
                raise ApiError(response.status_code, f'HTTP {response.status_code}')
            digest, size = hashlib.sha256(), 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise ApiError(413, f'the download is larger than the {max_bytes} bytes this Sentinel accepts')
                digest.update(chunk)
                destination.write(chunk)
            return digest.hexdigest(), size
        finally:
            response.close()
