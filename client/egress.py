"""The built-in scanner's egress proxy: cvENGINE's Settings > Proxy, applied to the tools that take a proxy, exactly as the server applies it to its own
scans (``cveFeed.egress_proxy.for_tool`` there), so moving a kind to the built-in scanner does not change where its traffic leaves from.

Only the built-in scanner has a proxy (``config.vantage``, from the server's settings reply); every other Sentinel keeps its own egress. nuclei, WPScan,
testssl.sh, wafw00f and bbot (its web modules) go through it; nmap, naabu and the UDP sweep use raw sockets and connect directly, as on the server. A destination that never goes
through a proxy (loopback, this stack's services, private and tailnet addresses unless ``proxy_private``, and the server's bypass list) leaves a run
direct when every destination of the run is one. A proxy that suits no tool fails the task: there is no fallback to a direct connection, which would
reveal the address the proxy is there to hide. A proxy URL can carry a login: never log it (``describe`` is what may be logged).
"""
import ipaddress
import itertools
import threading
from urllib.parse import unquote, urlsplit

from . import config

STACK_HOSTS = frozenset({'localhost', 'db', 'redis', 'web', 'celery', 'celery-beat', 'proxy', 'certs', 'tailscale', 'scanner'})
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
                                                          'fc00::/7', 'fe80::/10'))
_turn = itertools.count()
_lock = threading.Lock()


class ProxyUnavailable(ValueError):
    """cvENGINE's proxy is on but none of its proxies suits this tool: the run must not go out directly."""


class Spec:
    __slots__ = ('scheme', 'host', 'port', 'username', 'password', 'url')

    def __init__(self, url):
        parts = urlsplit(url)
        self.scheme, self.host, self.url = parts.scheme, parts.hostname, url
        self.port = parts.port or {'http': 80, 'https': 443}.get(parts.scheme, 1080)
        self.username, self.password = unquote(parts.username or ''), unquote(parts.password or '')

    @property
    def netloc(self):
        return f'[{self.host}]:{self.port}' if ':' in self.host else f'{self.host}:{self.port}'

    @property
    def plain_url(self):
        return f'{self.scheme}://{self.netloc}'

    @property
    def credentials(self):
        return f'{self.username}:{self.password}' if (self.username or self.password) else ''

    def __repr__(self):
        return f'Spec({describe(self)})'


def describe(spec):
    """What may be logged about a proxy: its kind and address, never its login."""
    return f'{spec.scheme}://{spec.netloc}'


def configured():
    """The proxies the built-in scanner must use, in order, or an empty list (no proxy, or not the built-in scanner)."""
    out = []
    for url in config.vantage().get('proxies', []):
        try:
            out.append(Spec(url))
        except ValueError:
            continue
    return out


def bypass(host):
    """True for a destination that never goes through a proxy (the server's ``egress_proxy.bypass``): loopback, this stack's services, private,
    link-local and tailnet addresses unless the server sends private traffic through the proxy, and what its bypass list names."""
    settings = config.vantage()
    name = str(host or '').strip().strip('[]').lower().rstrip('.')
    if not name:
        return True
    entries = settings.get('bypass', [])
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_unspecified:
            return True
        if not settings.get('proxy_private') and any(ip in net for net in PRIVATE_NETWORKS if net.version == ip.version):
            return True
        for entry in entries:
            try:
                if ('/' in entry and ip in ipaddress.ip_network(entry, strict=False)) or ip == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False
    if name in STACK_HOSTS or name.endswith('.localhost'):
        return True
    for entry in entries:
        entry = entry.lstrip('*').lstrip('.')
        if entry and (name == entry or name.endswith('.' + entry)):
            return True
    return False


def hostname(target):
    """The host of a tool target: a URL, ``host:port``, a bare host or an IP literal (IPv6 included)."""
    text = str(target or '').strip()
    if '://' in text:
        return urlsplit(text).hostname or ''
    if text.startswith('['):
        return text[1:].split(']', 1)[0]
    return text.rsplit(':', 1)[0] if text.count(':') == 1 else text


def _wpscan(spec):
    return ['--proxy', spec.plain_url] + (['--proxy-auth', spec.credentials] if spec.credentials else [])


# tool -> (schemes it can use, its arguments for a proxy): the same table as the server's cveFeed.egress_proxy.TOOLS
TOOLS = {
    'nuclei': (('http', 'https', 'socks5'), lambda s: ['-proxy', s.url]),
    'wpscan': (('http', 'https', 'socks5', 'socks5h'), _wpscan),
    'wafw00f': (('http', 'https', 'socks5'), lambda s: ['-p', s.url]),
    'testssl': (('http',), lambda s: ['--proxy', s.netloc]),  # testssl.sh speaks to a plain HTTP proxy only, and cannot give it a login
    # bbot's own web.http_proxy setting: the URL alone, which client/bbot.py puts in its private preset file (a login never reaches a command line)
    'bbot': (('http', 'https', 'socks5', 'socks5h'), lambda s: [s.url]),
}


def for_tool(tool, hosts):
    """The arguments (a list, empty for a direct run) that send ``tool`` through cvENGINE's proxy for a run against ``hosts``. Raises
    ``ProxyUnavailable`` when a proxy is set and none suits the tool."""
    schemes, build = TOOLS[tool]
    specs = configured()
    if not specs or all(bypass(hostname(h)) for h in hosts):
        return []
    usable = [s for s in specs if s.scheme in schemes and (tool != 'testssl' or not s.credentials)]
    if not usable:
        raise ProxyUnavailable(f"cvENGINE's egress proxy is on, but {tool} cannot use any of its proxies (it takes " + ', '.join(schemes) +
                               (' without a login' if tool == 'testssl' else '') + '); not running it directly')
    with _lock:
        turn = next(_turn)
    return build(usable[turn % len(usable)])
