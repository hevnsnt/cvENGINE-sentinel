"""Service-feature readings of web services and of SLP (``cvengine_scanner.features``): whether a feature a CVE needs is turned on.

What is read, and from what:

- ``http3`` and ``php_windows`` come free from the front page answer the ``headers-root`` version probe already fetches (``page_readings``):
  the ``Alt-Svc`` header (``h3`` or ``h3-NN`` advertised: HTTP/3 over QUIC) and the ``X-Powered-By`` / ``Server`` headers (PHP together with
  IIS, Win32 or Win64, or with a Unix or Linux distribution token). No request is added. A QUIC handshake is not attempted: nginx serves QUIC only
  where it is configured and advertises it only where ``add_header Alt-Svc`` says so, so ``no`` means "not advertised", never "not served".
- ``webdav`` and ``http_methods`` come from one ``OPTIONS /`` per web base (``methods_readings``), asked only when the server's plan names the
  ``webdav`` read on an ``http_probe`` entry. WebDAV is believed only from a DAV compliance header (``DAV: 1``, ``2`` or ``3``) or
  ``MS-Author-Via: DAV``: an ``Allow`` list alone is what a framework or a catch-all writes for any path. An answer that is the server's front
  page again (the same page for any method: ``soft404.same``) is not an OPTIONS answer and is not read at all.
- ``vpn_*``: one GET of each portal page of an appliance the server already identified as that vendor (``PORTALS``, ``portal_reading``),
  asked only when the plan names that read. A page counts as the portal when it carries the vendor's own markers (with the requested path taken
  out of the page first, so a "not found" page naming the path is not one) and a path that cannot exist beside it is answered differently
  (``soft404``: a server that answers every path with the same login page is not read as "present"). A 404 for every portal path is ``no``.
  No form is posted, no credential is sent, and no path a known flaw is reached by is asked (the GlobalProtect gateway is read from its
  pre-login page, never from ``hipreport.esp``).
- ``slp``: one SLPv2 Service Request for ``service:VMwareInfrastructure`` over TCP 427 (``read_slp``), from the ``hygiene_check`` kind's
  optional ``slp`` list (ESXi hosts, or hosts with 427 open). One small request, over TCP, never a registration: SLP's amplification
  (CVE-2023-29552) needs a registration and spoofed UDP, neither of which is sent. UDP 427 is not read (the probe proxy, when set, carries
  TCP only).

Every request goes through the task's scope policy and ``transport`` (``http.probe_url``, ``version_probes.fetch``, ``transport.open_socket``),
bounded in bytes and time. A reading that was not taken is no item: unknown, never "no".
"""
import logging
import re
import secrets
import socket
import time
from urllib.parse import quote, unquote, urlsplit

from .. import soft404, versions

logger = logging.getLogger(__name__)

# the extra-request reads an http_probe entry may name in its optional ``features`` list; a name a Sentinel does not know is ignored
READS = ('webdav', 'vpn_fortinet', 'vpn_globalprotect', 'vpn_cisco', 'vpn_citrix', 'vpn_ivanti')
MAX_READS = len(READS)
OPTIONS_BYTES = 4096   # an OPTIONS answer has no body worth reading; enough to tell a page served for any method
PORTAL_BYTES = 64 * 1024
DETAIL = 200
METHOD_TOKENS = 40     # an Allow list longer than this is not a server's own list (an echo of everything)

# --- the front page: HTTP/3 and PHP on Windows (no request of its own) ---------------------------------------------------------------------

_ALT_ENTRY = re.compile(r'\s*([A-Za-z0-9!#$%&\'*+.^_`|~-]{1,40})\s*=\s*"([^"]{0,100})"')
_H3 = re.compile(r'^h3(?:-[A-Za-z0-9]{1,8})?$', re.I)


def alt_svc_h3(value):
    """``(advertised, ports)``: whether an ``Alt-Svc`` header value names an HTTP/3 alternative (``h3`` or a draft ``h3-NN``), and the UDP ports
    it names for it (``h3=":443"``; an empty host means the same host). ``clear`` and anything unparsable advertise nothing."""
    advertised, ports = False, []
    for part in str(value or '')[:2000].split(','):
        found = _ALT_ENTRY.match(part)
        if not found or not _H3.match(found.group(1)):
            continue
        advertised = True
        port = found.group(2).rsplit(':', 1)[-1]
        if port.isdigit() and 0 < int(port) < 65536 and int(port) not in ports:
            ports.append(int(port))
    return advertised, ports


_PHP = re.compile(r'\bPHP/(\d{1,2}\.\d{1,3}(?:\.\d{1,3})?)([^\s,;()]{0,60})', re.I)
_WINDOWS = re.compile(r'Microsoft-IIS/|\(Win(?:32|64)\)|\bWin(?:32|64)\b|\bWindows\b', re.I)
_UNIX = re.compile(r'\((?:Ubuntu|Debian|CentOS|CentOS Stream|Red Hat|Red Hat Enterprise Linux|Fedora|Unix|Amazon|Amazon Linux|Rocky Linux|AlmaLinux|'
                   r'Oracle Linux|SUSE|openSUSE|Gentoo|Alpine|FreeBSD|OpenBSD|NetBSD|Raspbian|Linux|Mageia|Slackware|Arch Linux|Darwin)\)', re.I)
# a distribution's own PHP build names itself in its version: 8.1.2-1ubuntu2.14, 8.2.7-1~deb12u1, 7.4.33-1+deb11u5, 5.4.16-48.el7
_PHP_DISTRO = re.compile(r'^-[^\s]{0,40}(?:ubuntu|~deb|\+deb|deb\d|\.el\d|\.fc\d|\.amzn|sury)', re.I)
_XAMPP = re.compile(r'Apache/\d[\d.]* \(Win(?:32|64)\) .{0,80}\bPHP/', re.I)


def _header(response, name):
    raw = response.get('raw_headers') or {}
    kept = response.get('headers') or {}
    return str(raw.get(name) or kept.get(name) or '')


def php_windows_reading(host, port, server, powered_by):
    """The ``php_windows`` item for one answer's ``Server`` and ``X-Powered-By`` headers, or None: PHP must be named (``PHP/x`` in either),
    and the operating system must be named too (IIS, Win32 or Win64 for yes; a distribution token or a distribution's PHP build for no). Both
    named, or neither: None (unknown). Whether PHP runs as CGI and which code page Windows uses are not readable from outside: the detail says so."""
    server, powered_by = str(server or '')[:300], str(powered_by or '')[:300]
    php = _PHP.search(powered_by) or _PHP.search(server)
    if not php:
        return None
    windows = bool(_WINDOWS.search(server)) or ('asp.net' in powered_by.lower() and 'microsoft-iis' in server.lower())
    unix = bool(_UNIX.search(server)) or bool(_PHP_DISTRO.match(php.group(2) or ''))
    if windows == unix:
        return None
    where = f'Server: {server}' if server else 'X-Powered-By'
    if windows:
        detail = f'PHP/{php.group(1)} on Windows ({where[:90]})'
        if _XAMPP.search(server):
            detail += '; a XAMPP-style banner (XAMPP exposes php-cgi by default)'
        detail += '; CGI mode and the code page are not read remotely'
    else:
        detail = f'PHP/{php.group(1)}{php.group(2) or ""} not on Windows ({where[:90]})'
    return _item(host, port, 'php_windows', 'yes' if windows else 'no', detail)


def page_readings(host, port, scheme, response):
    """The readings the front page answer of ``host:port`` (a ``version_probes.fetch`` result, the host's own: ``own_answer``) gives with no
    request of its own: ``http3`` (an HTTPS answer only: HTTP/3 is always TLS) and ``php_windows``. An edge's challenge page says nothing about
    the site: no items. ``[]`` when nothing was read."""
    if not response or response.get('challenge') or not (response.get('status') or 0):
        return []
    out = []
    if scheme == 'https':
        advertised, ports = alt_svc_h3(_header(response, 'alt-svc'))
        edge = versions.edges_from_headers({**(response.get('headers') or {}), 'server': response.get('server', '')})
        through = f' (answered through {edge[0]})' if edge else ''
        if advertised:
            udp = ', '.join(f'udp {p}' for p in ports) or 'the same port'
            out.append(_item(host, port, 'http3', 'yes', f'Alt-Svc advertises h3 on {udp}{through}'))
        else:
            out.append(_item(host, port, 'http3', 'no', f'no h3 in Alt-Svc{through}; a QUIC listener that is not advertised is not read'))
    php = php_windows_reading(host, port, response.get('server') or _header(response, 'server'),
                              response.get('powered_by') or _header(response, 'x-powered-by'))
    if php:
        out.append(php)
    return out


# --- OPTIONS: WebDAV and the methods a server lists ------------------------------------------------------------------------------------

_METHOD = re.compile(r'^[A-Z][A-Z-]{1,20}$')
DAV_METHODS = ('PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK')
LISTED = ('PUT', 'DELETE', 'TRACE', 'PROPFIND')


def _methods(value):
    tokens = [t.strip().upper() for t in str(value or '')[:600].split(',') if t.strip()]
    return [t for t in tokens if _METHOD.match(t)], len(tokens)


def methods_readings(host, port, options, page=None):
    """The ``webdav`` and ``http_methods`` items of one ``OPTIONS /`` answer (``options``, an ``http.probe_url`` result) of ``host:port``, or
    ``[]``. ``page`` is the GET answer for ``/`` when there is one: an OPTIONS answer that is that same page (``soft404.same``) is a server
    that answers every method with its page, so nothing in it is an OPTIONS answer.

    ``webdav``: yes when the answer carries a DAV compliance class (``DAV: 1``, ``2`` or ``3``) or ``MS-Author-Via: DAV``; no when a 2xx answer
    carries neither and lists no WebDAV method, or the server refuses OPTIONS (405, 501); nothing when it lists a WebDAV method without the
    header (a list written for any path is not a WebDAV server). ``http_methods``: which of PUT, DELETE, TRACE and PROPFIND ``Allow`` and
    ``Public`` list (``none``), when there is such a list and it is not an echo of every method."""
    if not options or options.get('challenge'):
        return []
    status = options.get('status') or 0
    if status in (405, 501):
        return [_item(host, port, 'webdav', 'no', f'OPTIONS / answered {status}: no WebDAV at /')]
    if not 200 <= status < 300:
        return []
    if page and (page.get('status') or 0) == status and (options.get('body') or '').strip() \
            and soft404.same(soft404.fingerprint(options, '/'), soft404.fingerprint(page, '/')):
        return []  # the front page again: a server (or a catch-all) that answers every method alike
    dav = _header(options, 'dav')
    author = _header(options, 'ms-author-via')
    classes = [t.strip() for t in dav.split(',') if t.strip() in ('1', '2', '3')]
    allow, allow_count = _methods(_header(options, 'allow'))
    public, public_count = _methods(_header(options, 'public'))
    listed = list(dict.fromkeys(allow + public))
    echo = allow_count > METHOD_TOKENS or public_count > METHOD_TOKENS or '*' in _header(options, 'allow')
    shown = f'Allow: {", ".join(allow[:12])}' if allow else (f'Public: {", ".join(public[:12])}' if public else 'no Allow header')
    out = []
    if classes or 'dav' in author.lower():
        said = f'DAV: {", ".join(classes)}' if classes else 'MS-Author-Via: DAV'
        out.append(_item(host, port, 'webdav', 'yes', f'OPTIONS / answered {said}; {shown}'))
    elif not echo and not any(m in DAV_METHODS for m in listed):
        out.append(_item(host, port, 'webdav', 'no', f'no DAV header in the OPTIONS / answer ({shown}); WebDAV on a path below / is not read'))
    if listed and not echo:
        risky = [m.lower() for m in LISTED if m in listed]
        out.append(_item(host, port, 'http_methods', ','.join(risky) or 'none', shown))
    return out


# --- VPN and gateway portals ----------------------------------------------------------------------------------------------------------

PORTALS = {
    'vpn_fortinet': {'label': 'Fortinet SSL-VPN portal', 'paths': ('/remote/login',),
                     'markers': r'/remote/logincheck|launchFortiClient|fgt_lang|/sslvpn/js/|ftnt-fortinet-grid|/remote/saml/start'},
    'vpn_globalprotect': {'label': 'GlobalProtect', 'paths': ('/global-protect/login.esp', '/ssl-vpn/prelogin.esp'),
                          'markers': r'GlobalProtect Portal|/global-protect/portal/(?:css|images|js)/|<prelogin-response>|global-protect/login\.esp'},
    'vpn_cisco': {'label': 'Cisco WebVPN / AnyConnect', 'paths': ('/+CSCOE+/logon.html',),
                  'markers': r'/\+CSCOE\+/|/\+CSCOU\+/|/\+webvpn\+/|webvpnlogin|SSL VPN Service|CSCO_WebVPN|webvpnLang'},
    'vpn_citrix': {'label': 'NetScaler Gateway / AAA', 'paths': ('/vpn/index.html', '/logon/LogonPoint/index.html'),
                   'markers': r'/vpn/js/|/vpn/images/|/vpn/resources/|NetScaler Gateway|Citrix Gateway|Citrix Access Gateway|/logon/LogonPoint/|'
                              r'_ctxstxt_|/logon/themes/|nsg-epa'},
    'vpn_ivanti': {'label': 'Ivanti Connect Secure sign-in', 'paths': ('/dana-na/auth/url_default/welcome.cgi',),
                   'markers': r'/dana-na/|/dana-cached/|Ivanti Connect Secure|Pulse Connect Secure|Pulse Secure|welcome\.cgi'},
}
for _spec in PORTALS.values():
    _spec['_re'] = re.compile(_spec['markers'], re.I)
WHERE = {'/global-protect/login.esp': 'portal', '/ssl-vpn/prelogin.esp': 'gateway', '/vpn/index.html': 'Gateway', '/logon/LogonPoint/index.html': 'AAA'}


def control_path(path):
    """A path that cannot exist beside ``path``, of the same kind (``/remote/cvengine-1a2b3c4d5e6f``, ``/vpn/cvengine-....html``)."""
    directory, name = path.rsplit('/', 1)
    ext = name.rsplit('.', 1)[1] if '.' in name else ''
    return f'{directory}/cvengine-{secrets.token_hex(6)}' + (f'.{ext}' if ext else '')


def _without_path(text, path):
    """``text`` with the requested ``path`` taken out (raw, percent-encoded and decoded): a "not found" page that names it is no portal."""
    forms = sorted({path, quote(path), unquote(path), quote(path, safe='')}, key=len, reverse=True)
    return re.sub('|'.join(re.escape(f) for f in forms), ' ', str(text or ''), flags=re.I)


def _portal_page(spec, path, answer):
    body = _without_path((answer.get('body') or '')[:PORTAL_BYTES], path)
    return bool(spec['_re'].search(body) or spec['_re'].search(_without_path(answer.get('title') or '', path)))


def path_state(spec, path, answer, missing=None):
    """What one portal path's ``answer`` says: ``present`` (the vendor's page, answered differently from ``missing``, a path that cannot exist
    beside it), ``absent`` (404 or 410, or the same answer as ``missing``: not served on its own) or ``unknown`` (no answer, an edge's
    challenge, a page that is neither, or a portal page that every path gets)."""
    if not answer or answer.get('challenge'):
        return 'unknown'
    status = answer.get('status') or 0
    if status in (404, 410):
        return 'absent'
    same = bool(missing) and not missing.get('challenge') and soft404.same(soft404.fingerprint(answer, path), soft404.fingerprint(missing, path))
    if status == 200 and _portal_page(spec, path, answer):
        return 'unknown' if same or missing is None else 'present'
    if same:
        return 'absent'
    return 'unknown'


def portal_reading(host, port, feature, states):
    """The ``vpn_*`` item from the states of its paths (``[(path, state)]``, in ``PORTALS`` order): yes when one is present, no when every one
    is absent, else None (unknown)."""
    spec = PORTALS[feature]
    present = [p for p, s in states if s == 'present']
    if present:
        where = ' and '.join(WHERE.get(p, p) for p in present)
        return _item(host, port, feature, 'yes', f'{spec["label"]} answers ({where}: {", ".join(present)})')
    if states and all(s == 'absent' for _p, s in states) and len(states) == len(spec['paths']):
        return _item(host, port, feature, 'no', f'{spec["label"]}: not served ({", ".join(p for p, _s in states)} not found)')
    return None


def read_portal(feature, base, get, sleep=time.sleep, gap=0.5):
    """``[(path, state)]`` for ``feature``'s portal paths on ``base``, asked with ``get(url)`` (a ``version_probes.fetch`` under the task's
    policy). A path that looks like the portal is compared with one path that cannot exist beside it; the reads stop at the first portal found."""
    spec = PORTALS[feature]
    states = []
    for index, path in enumerate(spec['paths']):
        if index:
            sleep(gap)
        answer = _get(get, base + path)
        missing = None
        if answer and not answer.get('challenge') and (answer.get('status') or 0) not in (404, 410):
            sleep(gap)
            control = control_path(path)
            missing = _get(get, base + control)
        state = path_state(spec, path, answer, missing)
        states.append((path, state))
        if state == 'present':
            break
    return states


def _get(get, url):
    try:
        return get(url)
    except (OSError, ValueError) as exc:
        logger.info('feature read %s did not answer (%s)', urlsplit(url).path, type(exc).__name__)
        return None


# --- one web base: the reads an entry names ----------------------------------------------------------------------------------------------

def base_port(base):
    parts = urlsplit(base)
    return parts.port or (443 if parts.scheme == 'https' else 80)


def run_reads(host, base, reads, get, options, page=None, sleep=time.sleep, gap=0.5):
    """The items of the extra-request ``reads`` (names of ``READS``) on ``base``: ``get(url)`` fetches a page, ``options(url)`` sends one
    OPTIONS (both under the task's policy; either may raise). ``page`` is the base's front page answer when one was fetched."""
    port = base_port(base)
    out = []
    for index, name in enumerate(r for r in dict.fromkeys(reads) if r in READS):
        if index:
            sleep(gap)
        if name == 'webdav':
            out += methods_readings(host, port, _get(options, base + '/'), page)
        else:
            item = portal_reading(host, port, name, read_portal(name, base, get, sleep=sleep, gap=gap))
            if item:
                out.append(item)
    return out


# --- SLP (TCP 427) ----------------------------------------------------------------------------------------------------------------------

SLP_PORT = 427
SLP_TIMEOUT = 5
SLP_MAX_REPLY = 4096
SLP_SERVICE = 'service:VMwareInfrastructure'
SLP_SCOPE = 'DEFAULT'
SLP_FUNCTIONS = {2: 'SrvRply', 10: 'SAAdvert', 8: 'DAAdvert', 5: 'SrvAck'}


def _string(value):
    data = value.encode('utf-8')
    return len(data).to_bytes(2, 'big') + data


def slp_request(xid, service=SLP_SERVICE, scope=SLP_SCOPE, lang='en'):
    """One SLPv2 Service Request (RFC 2608, function 1): no previous responders, the service type, the scope, no predicate, no SPI. Never a
    registration."""
    body = _string('') + _string(service) + _string(scope) + _string('') + _string('')
    tag = lang.encode('ascii')
    header_length = 14 + len(tag)
    length = header_length + len(body)
    header = bytes([2, 1]) + length.to_bytes(3, 'big') + (0).to_bytes(2, 'big') + (0).to_bytes(3, 'big') + int(xid).to_bytes(2, 'big') \
        + len(tag).to_bytes(2, 'big') + tag
    return header + body


def parse_slp_reply(data, xid=None):
    """``{'function', 'error', 'urls'}`` of an SLPv2 reply, or None when ``data`` is not one: version 2, a reply function, a length that fits,
    and (when ``xid`` is given) the request's transaction id."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16 or data[0] != 2 or data[1] not in SLP_FUNCTIONS:
        return None
    length = int.from_bytes(data[2:5], 'big')
    if length < 16 or length > SLP_MAX_REPLY or len(data) < length:
        return None
    if xid is not None and int.from_bytes(data[10:12], 'big') != int(xid):
        return None
    tag_length = int.from_bytes(data[12:14], 'big')
    offset = 14 + tag_length
    if offset > length:
        return None
    error, urls = 0, 0
    if data[1] in (2, 5, 8) and offset + 2 <= length:
        error = int.from_bytes(data[offset:offset + 2], 'big')
    if data[1] == 2 and offset + 4 <= length:
        urls = int.from_bytes(data[offset + 2:offset + 4], 'big')
    return {'function': SLP_FUNCTIONS[data[1]], 'error': error, 'urls': urls}


def _recv_reply(sock, deadline):
    data = b''
    want = 5
    while len(data) < want:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        chunk = sock.recv(min(SLP_MAX_REPLY, want) - len(data))
        if not chunk:
            break
        data += chunk
        if len(data) >= 5 and want == 5:
            want = min(max(int.from_bytes(data[2:5], 'big'), 5), SLP_MAX_REPLY)
    return data


def read_slp(host, port, policy, timeout=SLP_TIMEOUT, connect=None):
    """The ``slp`` item of ``host:port`` (TCP), or None when nothing could be concluded. yes: an SLPv2 reply came back; no: the connection was
    refused (direct connections only: a refusal through the probe proxy is the proxy's and says nothing). Raises ``ValueError`` when the policy
    refuses the endpoint. ``connect(addresses, timeout, policy, host, literal)`` replaces ``transport.open_socket`` (tests)."""
    from . import names, transport
    literal = names.is_ip(host)
    if literal:
        policy.check_host(host)
        policy.check_address(host, literal=True)
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        addresses = ((family, (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)),)
    else:
        addresses = transport.resolve(host, port, policy)
    direct = transport._proxy_for(addresses, host) is None
    connect = connect or (lambda a, t, p, h, lit: transport.open_socket(a, t, p, host=h, literal=lit))
    xid = secrets.randbelow(0xFFFF) + 1
    deadline = time.monotonic() + timeout
    try:
        sock = connect(addresses, timeout, policy, host, literal)
    except ConnectionRefusedError:
        return _item(host, port, 'slp', 'no', f'{port}/tcp refused the connection; UDP 427 is not read') if direct else None
    except (OSError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        return None
    try:
        sock.sendall(slp_request(xid))
        reply = parse_slp_reply(_recv_reply(sock, deadline), xid)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if reply is None:
        return None
    detail = f'SLPv2 {reply["function"]} on {port}/tcp (error {reply["error"]}'
    detail += f', {reply["urls"]} service URL{"s" if reply["urls"] != 1 else ""})' if reply['function'] == 'SrvRply' else ')'
    return _item(host, port, 'slp', 'yes', detail)


def _item(host, port, feature, value, detail):
    return {'host': str(host).lower().rstrip('.'), 'port': int(port), 'transport': 'tcp', 'feature': feature, 'value': value,
            'detail': re.sub(r'\s+', ' ', str(detail)).strip()[:DETAIL]}
