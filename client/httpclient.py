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

DEFAULT_TIMEOUT = 30  # seconds per call; the long poll's own wait (config.DEFAULT_POLL_WAIT) fits well inside it


class ApiError(Exception):
    """The server answered with a 3xx/4xx/5xx. ``status`` and ``message`` are set; the message is already a short string
    the server chose to show (or one this client wrote), never a raw response body (which could be arbitrarily large or
    not be JSON at all)."""

    def __init__(self, status, message):
        super().__init__(f'{status}: {message}')
        self.status = status
        self.message = message


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

    def call(self, method, path, body=None, timeout=None):
        """One REST call; returns the decoded JSON body. Raises ``ApiError`` on a 3xx (never followed), 4xx or 5xx, or
        ``requests.RequestException`` on a network failure (connection refused, DNS, timeout): the caller (``daemon``)
        decides how to back off from each, never this method."""
        url = self.base + path.lstrip('/')
        data = json.dumps(body).encode('utf-8') if body is not None else None
        response = self.session.request(method, url, data=data, headers=self._headers(), allow_redirects=False,
                                        timeout=timeout if timeout is not None else self.timeout)
        if 300 <= response.status_code < 400:
            raise ApiError(response.status_code, 'the server answered with a redirect, which this Sentinel never follows: '
                                                 'check the server URL (scheme, host and path)')
        try:
            payload = response.json() if response.content else {}
        except ValueError:
            payload = {}
        if response.status_code >= 400:
            message = (payload.get('error') if isinstance(payload, dict) else None) or f'HTTP {response.status_code}'
            raise ApiError(response.status_code, str(message)[:300])
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
