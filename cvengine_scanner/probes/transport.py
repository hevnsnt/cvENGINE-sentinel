"""Numeric socket connections for the probes, copied from cvENGINE's ``cveFeed.pinned_transport``.

Admission and connection share the same addresses: a name is resolved once, every address it resolves to is judged by the task's scope policy
(``cvengine_scanner.probes.policy``, which applies this Sentinel's own floor first), and only those numeric addresses are ever connected to. Each
host a connection is made to is recorded in the policy's ``touched`` list.

When ``CVENGINE_SENTINEL_PROBE_PROXY`` is set (``cvengine_scanner.probes.egress_proxy``) the connection goes through the proxy, but the decision stays here: every address is
vetted (``resolve``, and again in ``open_socket``) before anything is sent, and the proxy is only ever asked for that numeric address (an HTTP
CONNECT or SOCKS5 request to the IP, or an absolute-URI request to it for plain HTTP), with the original Host header and TLS server name
untouched. A failed proxy fails the connection; it never falls back to a direct one.
"""
import http.client
import ipaddress
import socket
import time
import zlib

from .. import printers
from . import egress_proxy


def _is_literal(host, ip):
    try:
        return ipaddress.ip_address(host.strip('[]')) == ip
    except ValueError:
        return False


def resolve(host, port, policy):
    """Resolve once, rejecting a name the policy refuses, failed or empty answers, or any address the policy refuses. A private address the
    project authorised is allowed only when ``host`` is that address itself: a name that resolves into a tailnet never is."""
    if not isinstance(host, str) or not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise ValueError('invalid probe hostname')
    if any(c in host for c in '/\\@%') or not 0 < int(port) < 65536:
        raise ValueError('invalid probe destination')
    printers.check_port(port)  # a raw print port is never sent data, whatever the task or a redirect named
    policy.check_host(host)
    answers = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC,
                                 type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    pinned = []
    for family, kind, proto, _name, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError('unsupported address family')
        ip = ipaddress.ip_address(address[0])
        if policy.address_refusal(str(ip), literal=_is_literal(host, ip)):
            raise ValueError('probe destination is prohibited')
        # Reconstruct numeric sockaddr; never pass an untrusted hostname to connect.
        numeric = (str(ip), int(port)) if family == socket.AF_INET else (str(ip), int(port), 0, 0)
        item = (family, numeric)
        if item not in pinned:
            pinned.append(item)
    if not pinned:
        raise ValueError('probe destination did not resolve')
    return tuple(pinned)


_AUTO = object()


def open_socket(addresses, timeout, policy, host=None, proxy=_AUTO, literal=False):
    """Connect only to vetted numeric addresses within one connection budget; every address is judged by ``policy`` again here (``literal``: the
    caller was given the address itself, not a name's answer). With a probe proxy set, the connection is a tunnel through the proxy to that same
    vetted address (``host``, when given, is the name, for the proxy bypass list and the ``touched`` record; ``proxy`` is the choice a caller already
    made, None for a direct connection)."""
    if proxy is _AUTO:
        proxy = _proxy_for(addresses, host)
    deadline = time.monotonic() + timeout
    last_error = OSError('no probe address available')
    for family, address in addresses:
        printers.check_port(address[1])  # a raw print port is never sent data (printers.PRINT_PORTS)
        ip = ipaddress.ip_address(address[0])
        if policy.address_refusal(str(ip), literal=literal or (host is not None and _is_literal(host, ip))):
            raise ValueError('probe destination is prohibited')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('probe connection timed out')
        policy.touch(host or str(ip))
        if proxy is not None:
            try:
                return egress_proxy.open_tunnel(proxy, str(ip), address[1], remaining)
            except OSError as exc:
                last_error = exc
                continue
        sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(remaining)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise last_error


def _proxy_for(addresses, host=None, schemes=egress_proxy.IN_PROCESS_SCHEMES):
    """The proxy this connection goes through, None for a direct one: the setting is off, or the destination (its name or any vetted address)
    is loopback or one of this stack's own services."""
    if not egress_proxy.configured():
        return None
    if (host is not None and egress_proxy.bypass(host)) or any(egress_proxy.bypass(address[0]) for _family, address in addresses):
        return None
    return egress_proxy.pick(schemes=schemes)


class HTTPConnection(http.client.HTTPConnection):
    """Single-origin HTTP, optionally over TLS, with no hostname fallback. Through an HTTP proxy, plain HTTP is sent as an absolute-URI request
    to the vetted address (the proxy then needs no CONNECT permission for the port); TLS, and every SOCKS proxy, use a tunnel."""
    def __init__(self, host, port, addresses, timeout, policy, context=None, literal=False):
        super().__init__(host, port, timeout=timeout)
        self.addresses = addresses
        self.context = context
        self.policy = policy
        self.literal = literal
        self._forward = None  # (proxy, 'ip:port') while a plain request is forwarded by an HTTP proxy

    def connect(self):
        self._forward = None
        proxy = _proxy_for(self.addresses, self.host)
        if proxy is not None and proxy.scheme == 'http' and self.context is None:
            self.sock = self._connect_forward(proxy)
            return
        raw = open_socket(self.addresses, self.timeout, self.policy, host=self.host, proxy=proxy, literal=self.literal)
        try:
            self.sock = self.context.wrap_socket(raw, server_hostname=self.host) if self.context else raw
        except Exception:
            raw.close()
            raise

    def _connect_forward(self, proxy):
        """Plain HTTP through an HTTP proxy: vet every address as ``open_socket`` does, connect to the proxy, remember the first vetted address
        to name in each request line."""
        for _family, address in self.addresses:
            if self.policy.address_refusal(str(ipaddress.ip_address(address[0])), literal=self.literal):
                raise ValueError('probe destination is prohibited')
        if not self.addresses:
            raise OSError('no probe address available')
        _family, address = self.addresses[0]
        self.policy.touch(self.host)
        numeric = f'[{address[0]}]' if ':' in address[0] else address[0]
        sock = egress_proxy.connect_proxy(proxy, self.timeout)
        self._forward = (proxy, f'{numeric}:{address[1]}')
        return sock

    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        forward = self._forward is not None and url.startswith('/')
        if forward:  # absolute-URI to the vetted address; the Host header stays the original name (http.client would derive it from the URL)
            url = f'http://{self._forward[1]}{url}'
        super().putrequest(method, url, skip_host=skip_host or forward, skip_accept_encoding=skip_accept_encoding)
        if forward and not skip_host:
            name = f'[{self.host}]' if ':' in self.host else self.host
            self.putheader('Host', name if self.port == 80 else f'{name}:{self.port}')
        if forward and self._forward[0].credentials:
            self.putheader('Proxy-Authorization', self._forward[0].authorization())

    def getresponse(self):
        response = super().getresponse()
        if self._forward is not None and response.status == 407:
            response.close()
            raise OSError('the proxy refused the login or asked for one')
        return response


COMPRESSED_SLACK = 4096  # compressed bytes the reader may consume beyond the decoded cap
WIRE_HEAD = 16  # leading body bytes, as received before decoding, reported in ``wire['head']`` (a version digest reads a gzip header)

# Size of one read from the response on the compressed path.
_PIECE = 4096


def _pick_wbits(encoding, first):
    """Choose zlib window bits from the encoding and the first piece."""
    if encoding == 'gzip':
        return 16 + zlib.MAX_WBITS
    # Deflate: zlib-wrapped when the two byte header looks valid, else bare.
    if (
        len(first) >= 2
        and (first[0] & 0x0F) == 8
        and ((first[0] << 8) | first[1]) % 31 == 0
    ):
        return zlib.MAX_WBITS
    return -zlib.MAX_WBITS


def read_body(response, max_bytes, wire=None):
    """Read a response body, decoding gzip or deflate, capped at max_bytes.

    The probes ask for an uncompressed answer, but some embedded servers (printers, relays, cameras) compress anyway, so a gzip or
    deflate body (zlib wrapped or bare) is decoded here. The cap applies to the decoded output and the compressed input is bounded by
    ``max_bytes + COMPRESSED_SLACK``, so a decompression bomb stops at the cap. ``wire``, a dict when given, receives ``head``: the first
    ``WIRE_HEAD`` bytes as they came over the connection. Raises ``ValueError`` for another encoding, a stream that does not decode, and
    a stream that ends before its end marker while the cap is not reached.
    """
    max_bytes = max(int(max_bytes), 0)

    header = response.getheader('Content-Encoding')
    encoding = (header or '').strip().lower()

    if encoding in ('', 'identity'):
        data = response.read(max_bytes)
        if data is None:
            data = b''
        if wire is not None:
            wire['head'] = data[:WIRE_HEAD]
        return data

    if encoding not in ('gzip', 'deflate'):
        raise ValueError('unsupported probe content encoding')

    out_left = max_bytes
    in_left = max_bytes + COMPRESSED_SLACK
    decoder = None
    parts = []

    while out_left > 0 and in_left > 0 and not (decoder is not None and decoder.eof):
        piece = response.read(min(_PIECE, in_left))
        if not piece:
            break
        in_left -= len(piece)

        if decoder is None:
            # First non-empty piece: report its head and pick the decoder.
            if wire is not None:
                wire['head'] = piece[:WIRE_HEAD]
            decoder = zlib.decompressobj(_pick_wbits(encoding, piece))

        try:
            chunk = decoder.decompress(piece, out_left)
        except zlib.error as exc:
            raise ValueError('invalid compressed probe response') from exc
        out_left -= len(chunk)
        parts.append(chunk)

    if out_left > 0 and decoder is not None and not decoder.eof:
        raise ValueError('incomplete compressed probe response')

    return b''.join(parts)
