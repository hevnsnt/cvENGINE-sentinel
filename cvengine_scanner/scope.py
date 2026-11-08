"""The Sentinel's own scope floor: addresses it never scans, whatever a task asks.

The cvENGINE server (or anything that controls its dispatch path) names the targets a Sentinel scans, and a Sentinel runs on an operator's
own machine or inside their network. The server decides what is in scope for a project; this module is the part the Sentinel decides for
itself, so a buggy or compromised server cannot aim a scanner at the machine it runs on, at loopback, at the cloud metadata service, or at the
private ranges an external Sentinel was never meant to reach.

Three rules:

* Never, on any Sentinel: unspecified, loopback, link-local (which includes 169.254.169.254), multicast, reserved and broadcast, documentation
  and benchmarking ranges, the AWS IPv6 metadata range, and this container's own addresses. IPv4 hidden inside an IPv6 address (mapped, 6to4,
  NAT64) is unwrapped and judged as the IPv4 it is.
* Not on an external Sentinel: private space (RFC 1918, CGNAT, unique local IPv6). An internal Sentinel (CVENGINE_SENTINEL_NETWORK=internal set on
  this machine) may scan it. The decision uses this machine's own setting, never a value the server sent, so the server cannot unlock private
  space by declaring the Sentinel internal. The one exception is cvENGINE's built-in scanner (CVENGINE_SENTINEL_BUILTIN=1 on this machine), which
  runs next to its server and scans from the server's vantage point: it may scan the private networks the server's own scans may (the tailnet,
  or private space where the server allows private targets), as its vantage setting names them (``use_private_ranges``).
* Never a range on the deny list: the operator's own (``CVENGINE_SENTINEL_DENY_RANGES``, comma separated CIDRs, registered with ``use_denied_ranges``)
  and, for a task that carries one, the task's (the bbot blacklist, a probe's ``blocked`` list). Checked in ``_judge`` first, so every address any tool or probe
  is about to connect to passes it, and refused as ``Denied``.

A name is checked twice: as written (no ranges, no numeric forms, no well-known local names) and, when it resolves, by every address it resolves
to. A tool resolves the name again when it runs, so a name that changes its answer in between is not covered; callers that can pass the resolved
address to the tool should do so.
"""
import ipaddress
import os
import re
import socket
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """A target the Sentinel will not scan. The message says why and never contains more than the offending target."""


class Denied(ScopeError):
    """A target inside a range this Sentinel was told never to touch (the task's deny list, or the operator's ``CVENGINE_SENTINEL_DENY_RANGES``):
    refused here before anything connects, and reported as refused rather than failed."""


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


def interface_addresses(fib_trie='', if_inet6=''):
    """The addresses configured on this machine's interfaces, read from the text of /proc/net/fib_trie (IPv4: a ``|-- addr`` line followed by a
    ``/32 host LOCAL`` line) and /proc/net/if_inet6 (IPv6: 32 hex digits first on each line). With host networking these are the machine's own
    addresses, its LAN address and the Docker bridge's included."""
    found, previous = set(), None
    for line in fib_trie.splitlines():
        text = line.strip()
        if text.startswith('|--'):
            previous = text[3:].strip()
        elif text.startswith('/32 host LOCAL') and previous:
            found.add(previous)
    for line in if_inet6.splitlines():
        word = line.split()[0] if line.split() else ''
        if len(word) == 32:
            try:
                found.add(str(ipaddress.IPv6Address(int(word, 16))))
            except ValueError:
                continue
    return found


def _read(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return handle.read()
    except OSError:
        return ''


def own_addresses():
    """The addresses of this container (or this machine, with host networking): never a scan target. What the host name resolves to plus every
    interface address. Looked up once."""
    if _own_cache['value'] is None:
        found = interface_addresses(_read('/proc/net/fib_trie'), _read('/proc/net/if_inet6'))
        try:
            name = socket.gethostname()
            for info in socket.getaddrinfo(name, None):
                found.add(info[4][0].split('%')[0])
        except OSError:
            pass
        _own_cache['value'] = frozenset(found)
    return _own_cache['value']


_internal_setting = None  # where this machine's own network setting comes from; see ``use_internal_setting``


def use_internal_setting(check):
    """Say where this machine's own network setting comes from: ``check()`` returns True when the machine's own configuration says it sits inside a
    private network. The Sentinel client registers its configuration here (``client.scope``); until something does, nothing is internal, which is
    the safe answer for any other caller (the cvENGINE server only judges addresses with an explicit ``internal`` argument)."""
    global _internal_setting
    _internal_setting = check


_private_setting = None  # where the private networks a non-internal Sentinel may still scan come from; see ``use_private_ranges``


def use_private_ranges(ranges):
    """Say where the private networks come from that this Sentinel may scan although it is not internal: ``ranges()`` returns a list of
    ``ipaddress`` networks. The Sentinel client registers the built-in scanner's vantage setting here (the tailnet when cvENGINE's Tailscale sidecar
    is on, private space when cvENGINE allows private targets), which an external Sentinel never has. Until something does, there are none."""
    global _private_setting
    _private_setting = ranges


def _allowed_private(ip):
    try:
        ranges = _private_setting() if _private_setting is not None else ()
    except Exception:  # noqa: BLE001 - a setting that cannot be read allows nothing
        return False
    return any(ip.version == net.version and ip in net for net in ranges)


def internal_allowed():
    """Whether this Sentinel may scan private space: this machine's own configuration says it sits inside a private network, and the server has
    not pulled it back to external. The server can never grant it (``config.is_internal`` is a ceiling, and is what the client registers)."""
    return bool(_internal_setting()) if _internal_setting is not None else False


_deny_setting = None  # where the operator's deny list comes from; see ``use_denied_ranges`` (None: the environment variable itself)
DENY_ENV = 'CVENGINE_SENTINEL_DENY_RANGES'


def parse_denied_ranges(text):
    """``(networks, bad)`` from a comma, space or semicolon separated list of CIDRs (a bare address is one host). ``bad`` names every entry that is not
    an address or a CIDR: the caller must not run with a list it only half understood."""
    nets, bad = [], []
    for token in re.split(r'[,;\s]+', str(text or '')):
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token.strip('[]'), strict=False))
        except ValueError:
            bad.append(token[:60])
    return tuple(nets), bad


def use_denied_ranges(setting):
    """Say where this machine's own deny list comes from: ``setting()`` returns ``(networks, bad_entries)``; ``None`` goes back to the environment
    variable. The Sentinel client registers its own reader (``client.config``, which logs a bad entry once); with none registered the environment
    variable is read directly, so nothing in this process can run without it."""
    global _deny_setting
    _deny_setting = setting


def _from_environment():
    return parse_denied_ranges(os.environ.get(DENY_ENV, ''))


def denied_ranges():
    """The networks this machine's own deny list names: ``CVENGINE_SENTINEL_DENY_RANGES`` unless the client registered its own reader. Read from the
    environment by default, so a caller that never imported the client's configuration (bbot, a probe) is held to it too. An entry that is not a network
    refuses everything (fail closed): ``Denied``."""
    nets, bad = (_deny_setting or _from_environment)()
    if bad:
        raise Denied(f'the deny list of this Sentinel ({DENY_ENV}) holds an entry that is not an address or a CIDR ({bad[0]!r}); nothing is scanned until it is fixed')
    return tuple(nets)


def denied_by(ip, nets=None):
    """The network of the deny list ``ip`` is in (looked at as written, and as the IPv4 address hidden in an IPv6 one), or None."""
    nets = denied_ranges() if nets is None else nets
    for candidate in {ip, _unwrap(ip)}:
        for net in nets:
            if candidate.version == net.version and candidate in net:
                return net
    return None


def check_network(net):
    """``net`` (an ``ipaddress`` network) when no part of it is in the deny list; ``Denied`` if it overlaps one (a sweep cannot skip part of itself)."""
    for denied in denied_ranges():
        if denied.version == net.version and (net.overlaps(denied)):
            raise Denied('that network overlaps a range this Sentinel never touches')
    return net


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
    if denied_by(ip) is not None:
        raise Denied('that address is in a range this Sentinel never touches (its deny list)')
    ip = _unwrap(ip)
    if any(ip in net for net in ALWAYS_DENIED if net.version == ip.version):
        raise ScopeError('that address is never scanned (loopback, link-local, metadata, multicast, reserved or documentation space)')
    if str(ip) in own_addresses():
        raise ScopeError('that is this Sentinel\'s own address')
    if not internal and any(ip in net for net in PRIVATE if net.version == ip.version) and not _allowed_private(ip):
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
            except Denied as exc:  # stays a deny-list refusal: it is reported as refused, not failed
                raise Denied(f'the name resolves to a refused address ({exc})') from None
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
