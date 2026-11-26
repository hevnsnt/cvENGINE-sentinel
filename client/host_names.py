"""The names a discovery sweep gives the hosts it found inside a network: what the hosts and the network's own resolvers call them.

nmap's ping sweep already asks this Sentinel's resolver for each address's reverse DNS name (the router of a home or office network usually
answers for the devices it leased an address to: ``brwa8934a937f17.lan``). Two more names are read here, each with one small read-only
question that changes nothing on the host:

- mDNS: one unicast DNS question to the address's own port 5353 for its reverse name (``x.x.x.x.in-addr.arpa`` PTR). Apple devices, Linux with
  Avahi, printers, speakers and cameras answer with their ``.local`` name (RFC 6762 section 6.7, a legacy unicast answer).
- NetBIOS: one node status question (NBSTAT, UDP 137), what ``nmblookup -A`` and nmap's ``nbstat`` script send. Windows and Samba answer with
  their computer name.

Only addresses the sweep found up are asked, each at most once per question, with a short timeout and a bound on the whole step, so a large
chunk never makes the sweep late. A name that is not plain host name text is dropped. Nothing here is a scan of a service.
"""
import ipaddress
import logging
import os
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, wait

logger = logging.getLogger(__name__)

TIMEOUT = 1.0  # seconds one question waits for its answer
WORKERS = 32
BUDGET_SECONDS = 30  # the whole naming step of one chunk
MDNS_PORT = 5353
NETBIOS_PORT = 137
_LABEL = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$')
_NETBIOS = re.compile(r'^[A-Za-z0-9!#$%&\'()\-.@^_{}~]{1,15}$')


def clean_host_name(value):
    """``value`` as a lower-case host name without the trailing dot, or '' when it is not plain host name text (each label letters, digits,
    hyphens or underscores, at most 253 characters in all)."""
    if not isinstance(value, str):
        return ''
    name = value.strip().rstrip('.').lower()
    if not name or len(name) > 253 or not all(_LABEL.match(label) for label in name.split('.')):
        return ''
    return name


def clean_netbios_name(value):
    """A NetBIOS computer name as sent (trailing spaces cut), or '' when it is not one."""
    if not isinstance(value, str):
        return ''
    name = value.rstrip(' \x00')
    return name if _NETBIOS.match(name) else ''


def _ask(address, port, payload, timeout):
    """Send one UDP datagram and return the first answer from that address, or None."""
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (address, port))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(4096)
            except (TimeoutError, socket.timeout):
                return None
            if peer[0] == address:
                return data
    return None


# --- mDNS ----------------------------------------------------------------------------------------------------------------------------------

def _encode_name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        raw = label.encode('ascii')
        out += bytes([len(raw)]) + raw
    return out + b'\x00'


def mdns_question(address, query_id=None):
    """The unicast mDNS question for ``address``'s reverse name (PTR, class IN)."""
    reverse = ipaddress.ip_address(address).reverse_pointer
    query_id = int.from_bytes(os.urandom(2), 'big') if query_id is None else query_id
    return struct.pack('!HHHHHH', query_id, 0, 1, 0, 0, 0) + _encode_name(reverse) + struct.pack('!HH', 12, 1)


def _read_name(data, offset, depth=0):
    """``(name, next offset)`` of a DNS name at ``offset``, following compression pointers (at most 20)."""
    labels, end = [], None
    while True:
        if offset >= len(data) or depth > 20:
            raise ValueError('a name runs past the answer')
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError('a cut pointer')
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            end = offset + 2 if end is None else end
            offset, depth = pointer, depth + 1
            continue
        if length == 0:
            return '.'.join(labels), (offset + 1 if end is None else end)
        labels.append(data[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
        offset += 1 + length


def parse_mdns_answer(data):
    """The ``.local`` name in a reverse (PTR) answer, cleaned, or ''."""
    try:
        _id, _flags, qd, an, _ns, _ar = struct.unpack('!HHHHHH', data[:12])
        offset = 12
        for _ in range(qd):
            _name, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an):
            _name, offset = _read_name(data, offset)
            kind, _klass, _ttl, length = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            if kind == 12:
                target, _ = _read_name(data, offset)
                name = clean_host_name(target)
                if name:
                    return name
            offset += length
    except (ValueError, struct.error, IndexError):
        return ''
    return ''


def mdns_name(address, timeout=TIMEOUT, ask=_ask):
    """The host's own mDNS name for ``address``, or ''."""
    try:
        data = ask(address, MDNS_PORT, mdns_question(address), timeout)
    except OSError:
        return ''
    return parse_mdns_answer(data) if data else ''


# --- NetBIOS -------------------------------------------------------------------------------------------------------------------------------

def netbios_question(query_id=None):
    """The NetBIOS node status question (NBSTAT for the wildcard name ``*``)."""
    query_id = int.from_bytes(os.urandom(2), 'big') if query_id is None else query_id
    raw = b'*' + b'\x00' * 15
    encoded = bytes(c for b in raw for c in (ord('A') + (b >> 4), ord('A') + (b & 0x0F)))
    return struct.pack('!HHHHHH', query_id, 0, 1, 0, 0, 0) + bytes([32]) + encoded + b'\x00' + struct.pack('!HH', 0x21, 1)


def parse_netbios_answer(data):
    """The computer name (the first unique name with suffix 0x00) of a node status answer, or ''."""
    try:
        _id, _flags, _qd, an, _ns, _ar = struct.unpack('!HHHHHH', data[:12])
        if an < 1:
            return ''
        _name, offset = _read_name(data, 12)
        kind, _klass, _ttl, _length = struct.unpack('!HHIH', data[offset:offset + 10])
        if kind != 0x21:
            return ''
        offset += 10
        count = data[offset]
        offset += 1
        for index in range(count):
            entry = data[offset + 18 * index:offset + 18 * (index + 1)]
            if len(entry) < 18:
                break
            suffix, flags = entry[15], struct.unpack('!H', entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:
                return clean_netbios_name(entry[:15].decode('ascii', 'replace'))
    except (ValueError, struct.error, IndexError):
        return ''
    return ''


def netbios_name(address, timeout=TIMEOUT, ask=_ask):
    """The NetBIOS computer name ``address`` gives, or ''."""
    try:
        data = ask(address, NETBIOS_PORT, netbios_question(), timeout)
    except OSError:
        return ''
    return parse_netbios_answer(data) if data else ''


# --- the step ------------------------------------------------------------------------------------------------------------------------------

def name_hosts(hosts, budget=BUDGET_SECONDS, mdns=None, netbios=None, workers=WORKERS):
    """Add ``names`` to each discover row of ``hosts`` (``{'ip', 'hostnames'}``) that any question answered: ``{'mdns': name, 'netbios':
    name}``, each only when found. Rows are changed in place and returned. What did not finish inside ``budget`` seconds has no name from it."""
    rows = [h for h in hosts if isinstance(h, dict) and isinstance(h.get('ip'), str)]
    if not rows:
        return hosts
    mdns, netbios = mdns or mdns_name, netbios or netbios_name  # read when called, so a test's patch of either is the one used

    def one(row):
        names = {}
        found = mdns(row['ip'])
        if found:
            names['mdns'] = found
        found = netbios(row['ip'])
        if found:
            names['netbios'] = found
        return row, names

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(rows))), thread_name_prefix='discover-names')
    try:
        futures = [pool.submit(one, row) for row in rows]
        done, _late = wait(futures, timeout=budget)
        for future in done:
            try:
                row, names = future.result()
            except Exception:  # noqa: BLE001 - one host's question never fails the sweep
                logger.debug('a discover name question failed', exc_info=True)
                continue
            if names:
                row['names'] = names
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return hosts
