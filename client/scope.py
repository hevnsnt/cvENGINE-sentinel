"""The Sentinel's own scope floor: addresses it never scans, whatever a task asks.

The cvENGINE server (or anything that controls its dispatch path) names the targets a Sentinel scans, and a Sentinel runs on an operator's
own machine or inside their network. The server decides what is in scope for a project; this module is the part the Sentinel decides for
itself, so a buggy or compromised server cannot aim a scanner at the machine it runs on, at loopback, at the cloud metadata service, or at the
private ranges an external Sentinel was never meant to reach.

Two rules:

* Never, on any Sentinel: unspecified, loopback, link-local (which includes 169.254.169.254), multicast, reserved and broadcast, documentation
  and benchmarking ranges, the AWS IPv6 metadata range, and this container's own addresses. IPv4 hidden inside an IPv6 address (mapped, 6to4,
  NAT64) is unwrapped and judged as the IPv4 it is.
* Not on an external Sentinel: private space (RFC 1918, CGNAT, unique local IPv6). An internal Sentinel (CVENGINE_SENTINEL_NETWORK=internal set on
  this machine) may scan it. The decision uses this machine's own setting, never a value the server sent, so the server cannot unlock private
  space by declaring the Sentinel internal.

A name is checked twice: as written (no ranges, no numeric forms, no well-known local names) and, when it resolves, by every address it resolves
to. A tool resolves the name again when it runs, so a name that changes its answer in between is not covered; callers that can pass the resolved
address to the tool should do so.
"""
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from . import config


class ScopeError(ValueError):
    """A target the Sentinel will not scan. The message says why and never contains more than the offending target."""


def _nets(*names):
    return tuple(ipaddress.ip_network(n) for n in names)


# Never scanned, by any Sentinel.
ALWAYS_DENIED = _nets(
    '0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
    '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
    '::/128', '::1/128', 'fe80::/10', 'ff00::/8', 'fd00:ec2::/32', '2001:db8::/32',
)
# Private space: only an internal Sentinel scans it.
PRIVATE = _nets('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7')
_NAT64 = ipaddress.ip_network('64:ff9b::/96')

DENIED_NAMES = frozenset({
    'localhost', 'ip6-localhost', 'ip6-loopback', 'localhost.localdomain', 'metadata', 'metadata.google.internal', 'instance-data',
    'host.docker.internal', 'gateway.docker.internal', 'kubernetes.docker.internal',
})

_LABEL = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
_IP_CHARS = re.compile(r'^[0-9A-Fa-f:.]+$')
_NUMERIC_NAME = re.compile(r'^[0-9.\-\[\],/*]+$')  # digits, dots, dashes and nmap range punctuation only: an address form, never a name
MAX_NAME = 253

_own_cache = {'value': None}


def own_addresses():
    """The addresses of this container (or this machine, with host networking): never a scan target. Looked up once."""
    if _own_cache['value'] is None:
        found = set()
        try:
            name = socket.gethostname()
            for info in socket.getaddrinfo(name, None):
                found.add(info[4][0].split('%')[0])
        except OSError:
            pass
        _own_cache['value'] = frozenset(found)
    return _own_cache['value']


def internal_allowed():
    """Whether this machine was told, by its own configuration, that it sits inside a private network."""
    return config._local_internal()


def _unwrap(ip):
    """The IPv4 address hidden in an IPv6 one (mapped, 6to4, NAT64), else the address itself."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip.sixtofour is not None:
            return ip.sixtofour
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def _judge(ip, internal):
    ip = _unwrap(ip)
    if any(ip in net for net in ALWAYS_DENIED if net.version == ip.version):
        raise ScopeError('that address is never scanned (loopback, link-local, metadata, multicast, reserved or documentation space)')
    if str(ip) in own_addresses():
        raise ScopeError('that is this Sentinel\'s own address')
    if not internal and any(ip in net for net in PRIVATE if net.version == ip.version):
        raise ScopeError('private addresses are only scanned by a Sentinel configured as internal')
    return ip


def check_ip(value, internal=None):
    """The canonical text of ``value`` when it is one plain IP address this Sentinel may scan; raises ScopeError otherwise. No ranges, no CIDR, no
    scope ids, no numeric shortcuts (``2130706433``, ``0x7f000001``)."""
    internal = internal_allowed() if internal is None else internal
    text = value.strip() if isinstance(value, str) else ''
    if not text or len(text) > 45 or not _IP_CHARS.match(text):
        raise ScopeError('not a plain IP address')
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        raise ScopeError('not a plain IP address') from None
    _judge(ip, internal)
    return str(ip)


def _resolved(name, resolver):
    try:
        return {info[4][0].split('%')[0] for info in resolver(name, None)}
    except (OSError, UnicodeError):
        return set()  # does not resolve: nothing to reach


def check_host(value, internal=None, resolve=True, resolver=socket.getaddrinfo):
    """The normalised form of ``value`` when it is a host name this Sentinel may scan; an IP address is judged as one. A name that is really an
    address form (numeric, a range, a CIDR) is refused. With ``resolve`` the addresses the name resolves to are judged too."""
    internal = internal_allowed() if internal is None else internal
    text = value.strip().rstrip('.') if isinstance(value, str) else ''
    if not text or len(text) > MAX_NAME:
        raise ScopeError('not a host name')
    if ':' in text or _NUMERIC_NAME.match(text):
        return check_ip(text, internal)  # an address form: it must be one plain, allowed address
    lowered = text.lower()
    labels = lowered.split('.')
    # The last label of a real name is a top-level domain, which starts with a letter; that also refuses address shortcuts a resolver would
    # expand (``0x7f000001``, ``0177.1``) and anything numeric.
    if not all(_LABEL.match(label) for label in labels) or not labels[-1][0].isalpha():
        raise ScopeError('not a host name')
    if lowered in DENIED_NAMES or lowered.endswith('.localhost'):
        raise ScopeError('that name refers to this machine or a metadata service')
    if resolve:
        for address in _resolved(lowered, resolver):
            try:
                _judge(ipaddress.ip_address(address), internal)
            except ScopeError as exc:
                raise ScopeError(f'the name resolves to a refused address ({exc})') from None
            except ValueError:
                continue
    return lowered


def check_target(value, internal=None, resolve=True, resolver=socket.getaddrinfo):
    """One scan target, an IP address or a host name, judged as above."""
    return check_host(value, internal=internal, resolve=resolve, resolver=resolver)


def check_url(value, internal=None, resolve=True, resolver=socket.getaddrinfo):
    """An http or https URL whose host this Sentinel may scan; returns the URL unchanged. No userinfo."""
    try:
        parts = urlsplit(value) if isinstance(value, str) else None
        host = parts.hostname if parts else None
        parts and parts.port  # raises ValueError on a bad port
    except ValueError:
        raise ScopeError('not a valid URL') from None
    if not parts or parts.scheme not in ('http', 'https') or not host or parts.username or parts.password:
        raise ScopeError('not an http or https URL with a plain host')
    check_target(host, internal=internal, resolve=resolve, resolver=resolver)
    return value
