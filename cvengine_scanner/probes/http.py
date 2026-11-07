"""The one HTTP GET every probe makes, copied from cvENGINE's ``route_auth`` (``probe_url``, ``page_title`` and the limits they use).

Every request is bounded (bytes, per-read timeouts and a total time budget), read-only (GET or HEAD), anonymous (no cookie, no credential, only a
Host override or a cached script's ETag may be added) and goes to a numeric address the task's scope policy accepted (``transport``). The one exception is
the signed-in route check (``routes_signed``): it passes ``signed`` (the stored sign-in's header pairs, already checked) and then the server certificate is
verified unless that sign-in's owner switched verification off for it."""
import http.client
import re
import socket
import threading

from .. import versions
from . import transport

CONNECT_TIMEOUT, READ_TIMEOUT = 3, 6
UNTRUSTED_CERTIFICATE = 'sign-in not sent: the server certificate does not verify'  # the error of a signed-in route whose certificate did not verify (cvENGINE reads it, cveFeed.auth_routes)


class UntrustedCertificate(ValueError):
    """A stored sign-in was not sent because the server's certificate does not verify and the sign-in's owner has not allowed that. Holds no value."""
PROBE_TOTAL_SECONDS = 20  # wall-clock budget for one probe: the per-read timeouts alone let a host that trickles bytes hold a worker thread for good
ROUTE_SAMPLE_BYTES = 64 * 1024
MAX_PROBE_BYTES = 256 * 1024  # the most a version probe may ask for (a JavaScript bundle names its framework version deep inside)
MAX_READ_BYTES = 300 * 1024  # the most any probe reads of one decoded body: a library file (js_libraries.MAX_SCRIPT_BYTES)
# a front page is read further than another route: the script tags of a large WordPress page (the theme's and plugins' scripts sit in its
# footer, 230 KB in) decide which libraries the host serves; a page still longer than this is marked truncated and proves no absence
ROOT_READ_BYTES = MAX_READ_BYTES
# what an ordinary browser sends. Some CDNs answer an obvious scanner request with a challenge page instead of the site, so the version
# probes (never the route check) present as a browser; the headers say nothing a browser would not, and no cookie or credential is sent.
BROWSER_HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9'}


def page_title(text):
    """The first <title> of ``text``, whitespace collapsed and clipped. Found with plain string searches (one pass, no backtracking):
    a body of repeated '<title' with no '>' or '</title>' cost a regex quadratic time."""
    lowered = text.lower()
    start = lowered.find('<title')
    while start != -1:
        after = start + len('<title')
        if after < len(lowered) and lowered[after] not in '> \t\r\n/':  # <titles>, not <title>
            start = lowered.find('<title', after)
            continue
        open_end = lowered.find('>', after)
        if open_end == -1:
            return ''
        close = lowered.find('</title', open_end + 1)
        if close == -1:
            return ''
        return re.sub(r'\s+', ' ', text[open_end + 1:close]).strip()[:300]
    return ''


# ----------------------------------------------------------------------------- planning (pure)


def probe_url(url, policy, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), max_bytes=ROUTE_SAMPLE_BYTES, headers=None, method='GET', browser=False,
              connect_ip=None, signed=None, verify=True):
    """Bounded anonymous GET/HEAD using a pinned numeric destination and original Host/SNI, copied from cvENGINE's ``route_auth.probe_url``.
    The URL's host must pass ``policy`` (a ``policy.ScopePolicy``) and so must every address it resolves to; a redirect is never followed here
    (``version_probes.fetch`` follows one, asking the policy again). ``connect_ip`` connects to that vetted address instead of resolving the URL's
    name: the name is still sent as the Host header and the TLS server name. No credential is sent and the server certificate is never verified,
    so a broken-certificate site is still inspected, unless ``signed`` is given: ``signed`` (``[(name, value)]``, the stored sign-in, checked by
    ``routes_signed``) is the one way a credential is sent, and then the certificate is verified (unless the caller passes ``verify=False``, the
    sign-in owner's explicit switch) and one that does not verify raises ``UntrustedCertificate`` before anything is sent."""
    import ssl
    from http.cookies import SimpleCookie, CookieError
    from urllib.parse import quote, urlsplit

    if method not in ('GET', 'HEAD'):
        raise ValueError('route probes are read-only: GET or HEAD')
    max_bytes = min(int(max_bytes), MAX_READ_BYTES)
    if max_bytes < 0:
        raise ValueError('invalid probe byte limit')
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError('invalid probe URL')
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('probe URL must be HTTP(S) without credentials')
    if headers and any(key.lower() not in ('host', 'if-none-match') for key in headers):
        raise ValueError('only a Host override (and the ETag of a cached script) is allowed for anonymous probes')
    host = parsed.hostname.encode('idna').decode('ascii')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    literal = False
    if connect_ip:
        import ipaddress
        policy.check_host(host)
        pinned = ipaddress.ip_address(str(connect_ip))
        policy.check_address(str(pinned), literal=True)
        literal = True
        addresses = ((socket.AF_INET6, (str(pinned), port, 0, 0)) if pinned.version == 6 else (socket.AF_INET, (str(pinned), port)),)
    else:
        addresses = transport.resolve(host, port, policy)
    context = None
    if parsed.scheme == 'https':
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if not signed or not verify:
            context.check_hostname = False  # an anonymous check inspects broken-certificate sites too
            context.verify_mode = ssl.CERT_NONE
    connection = transport.HTTPConnection(host, port, addresses, timeout[0], policy, context=context, literal=literal)
    authority = f'[{host}]' if ':' in host else host
    if parsed.port is not None:
        authority += f':{port}'
    request_headers = {'User-Agent': 'CVEngine route check', 'Accept': 'text/html,*/*;q=0.5',
                       'Accept-Encoding': 'identity', 'Host': authority}
    if browser:
        request_headers.update(BROWSER_HEADERS)
    request_headers.update({key.title(): value for key, value in (headers or {}).items()})
    for name, value in signed or ():  # the stored sign-in replaces a header of the same name, whatever its case
        for existing in [k for k in request_headers if k.lower() == name.lower()]:
            del request_headers[existing]
        request_headers[name] = value
    path = quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += '?' + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    response = None
    expired = threading.Event()

    def abort():  # closes the connection under a blocked read; the read then ends and the budget breach is raised below
        expired.set()
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    watchdog = threading.Timer(PROBE_TOTAL_SECONDS, abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.connect()
        connection.sock.settimeout(timeout[1])
        connection.request(method, path, headers=request_headers)
        response = connection.getresponse()
        raw = transport.read_body(response, max_bytes)  # gzip and deflate from a device that ignores identity are decoded, capped after decoding
        if expired.is_set():
            raise TimeoutError('probe exceeded its total time budget')
        encoding = response.headers.get_content_charset() or 'utf-8'
        try:
            text = raw.decode(encoding, errors='replace')
        except LookupError:
            text = raw.decode('utf-8', errors='replace')
        title = page_title(text)
        cookies = SimpleCookie()
        for value in response.headers.get_all('Set-Cookie', []):
            try:
                cookies.load(value)
            except CookieError:
                pass
        return {'url': url, 'status': response.status, 'location': response.getheader('Location', ''),
                'www_authenticate': response.getheader('WWW-Authenticate', ''), 'cookies': list(cookies.keys()),
                'content_type': (response.getheader('Content-Type') or '').split(';')[0].strip().lower(),
                'body': text, 'title': title, 'bytes': len(raw), 'read_limit': max_bytes, 'truncated': len(raw) >= max_bytes,
                'server': response.getheader('Server', ''),
                'powered_by': response.getheader('X-Powered-By', ''), 'headers': versions.keep_headers(response.headers.items()),
                'raw_headers': {k.lower(): ' '.join(v.split())[:200] for k, v in list(response.headers.items())[:60]
                                if k.lower() not in ('set-cookie', 'authorization', 'proxy-authorization')}}
    except ssl.SSLCertVerificationError:
        if signed:  # nothing was sent: the handshake failed before the request
            raise UntrustedCertificate(UNTRUSTED_CERTIFICATE) from None
        raise
    except (OSError, http.client.HTTPException):
        if expired.is_set():
            raise TimeoutError('probe exceeded its total time budget') from None
        raise
    finally:
        watchdog.cancel()
        if response is not None:
            response.close()
        connection.close()


# ----------------------------------------------------------------------------- the stage
