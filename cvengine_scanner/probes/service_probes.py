"""Service feature readings (``cvengine_scanner.features``) for SSH, SMTP, SMB and RDP: what a CVE's precondition needs to know about the service.

Where each reading comes from, and what it costs the scanned host:

- **SSH** (``ssh_terrapin``, ``ssh_cbc``, ``ssh_aes_gcm``; ``ssh_auth_methods`` from the ``ssh_probe`` kind only): the algorithm lists of the
  server's KEXINIT, which it sends before any login. No new connection: the ``nmap`` fingerprint pass already runs ``ssh2-enum-algos`` on every SSH
  port (``nse_readings`` reads its structured output from the XML report, which lists every algorithm even when the text shows only the counts),
  and the ``ssh_probe`` kind's sshamble record carries the same lists (``ssh_probe.parse_host``).
- **RDP** (``rdp_nla``): no new connection either. The fingerprint pass already runs ``rdp-enum-encryption`` on every RDP port: one X.224 Connection
  Request per security protocol (standard RDP, TLS, CredSSP, RDSTLS, CredSSP with early user authorization), nothing after the answer. A server
  that accepts standard RDP security or TLS without CredSSP does not require Network Level Authentication; one that accepts only CredSSP does.
- **SMTP** (``smtp_*``): one connection to each cleartext SMTP port the fingerprint pass found open: read the greeting, send one ``EHLO``, read the
  reply, send ``QUIT``. Never MAIL FROM, never AUTH, never STARTTLS (so when STARTTLS is listed the AUTH reading carries ``tls_unread``: the list after
  STARTTLS may hold more, and such a reading never rules a mechanism out).
- **SMB** (``smb_*``, ``smbv1``): two connections to port 445 when the fingerprint pass found it open: one SMB2 NEGOTIATE offering 2.0.2 to 3.1.1
  with the pre-authentication integrity, encryption and compression contexts (the dialect chosen, whether signing is required, the compression
  algorithms), and one SMB1 NEGOTIATE naming only the NT LM 0.12 dialect (whether SMBv1 is accepted). Nothing is sent after NEGOTIATE: no session
  setup, no authentication, no tree connect.

Every connection goes to an address the task named and this Sentinel's floor allows (``policy.ScopePolicy``, ``transport.open_socket``), with a
connect timeout, a read deadline and a byte cap. A reading that was not taken (refused, timed out, closed, not understood) is no item: unknown,
never "no". The parsers are pure and take bytes, so the tests feed them captured replies.
"""
import concurrent.futures
import logging
import os
import re
import socket
import time
import xml.etree.ElementTree as ET

from .. import features

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5      # seconds to open one connection
READ_SECONDS = 8         # seconds one exchange (greeting to QUIT, or one NEGOTIATE) may take in all
MAX_SMTP_REPLY = 8192    # bytes of one SMTP reply read
MAX_SMB_REPLY = 16384    # bytes of one SMB NEGOTIATE response read
MAX_ENDPOINTS = 64       # SMTP and SMB endpoints asked after one fingerprint pass; the rest are named in cuts
WORKERS = 8
BUDGET_SECONDS = 120     # the most the follow-up probes add to one fingerprint task; an endpoint not started by then is not asked
EHLO_NAME = 'cvengine-sentinel.invalid'  # the name EHLO announces: a reserved name, never a host of the scanned network
SMTP_PORTS = (25, 587, 2525)
SMTP_SERVICES = ('smtp', 'submission')
SMB_PORT = 445
DETAIL = features.MAX_DETAIL

_PRINTABLE = re.compile(r'[^\x20-\x7e]')


def _clip(text, size=DETAIL):
    text = _PRINTABLE.sub('?', str(text or '')).strip()
    return text if len(text) <= size else text[:size - 3] + '...'


def _item(host, port, feature, value, detail=''):
    return features.clean_item({'host': host, 'port': port, 'transport': 'tcp', 'feature': feature, 'value': value, 'detail': _clip(detail)})


# ----------------------------------------------------------------------------- SSH: the KEXINIT lists

STRICT_KEX = 'kex-strict-s-v00@openssh.com'
CHACHA20 = 'chacha20-poly1305@openssh.com'
AES_GCM = ('aes128-gcm@openssh.com', 'aes256-gcm@openssh.com')
_CBC = re.compile(r'-cbc(?:@|$)')
_ETM = re.compile(r'-etm@openssh\.com$')
AUTH_METHODS = features.FEATURES['ssh_auth_methods']['values']


def _names(values):
    """The algorithm names of a list (or None when it was not read), lower case, deduplicated, in order."""
    if values is None:
        return None
    out = []
    for value in values:
        if isinstance(value, str) and value.strip() and value.strip().lower() not in out:
            out.append(value.strip().lower())
    return out


def ssh_readings(host, port, kex=None, ciphers=None, macs=None, methods=None):
    """The SSH feature items of one server from its KEXINIT lists (``kex``, ``ciphers`` and ``macs``: the algorithm names, both directions
    together; None for a list that was not read) and, when given, the authentication methods it listed (``methods``). A list that was not read
    gives no item that depends on it.

    Terrapin (CVE-2023-48795): an affected mode is ChaCha20-Poly1305, or a CBC cipher together with an Encrypt-then-MAC MAC; strict key exchange
    (``kex-strict-s-v00@openssh.com``) offered by the server is the fix (it takes effect when the client offers it too)."""
    kex, ciphers, macs = _names(kex), _names(ciphers), _names(macs)
    out = []
    if ciphers:
        chacha = CHACHA20 in ciphers
        cbc = [c for c in ciphers if _CBC.search(c)]
        gcm = [c for c in ciphers if c in AES_GCM]
        etm = [m for m in macs or () if _ETM.search(m)]
        cbc_etm = bool(cbc and etm)
        modes = ([CHACHA20] if chacha else []) + ([f'{cbc[0]} with {etm[0]}'] if cbc_etm else [])
        if not chacha and not cbc_etm and (macs is not None or not cbc):
            out.append(_item(host, port, 'ssh_terrapin', 'no_affected_mode',
                             'offers neither chacha20-poly1305@openssh.com nor a CBC cipher with an -etm@openssh.com MAC'))
        elif modes and kex:
            strict = STRICT_KEX in kex
            out.append(_item(host, port, 'ssh_terrapin', 'strict_kex' if strict else 'exposed',
                             f'offers {" and ".join(modes)}; ' + (f'offers {STRICT_KEX}' if strict else f'does not offer {STRICT_KEX}')))
        out.append(_item(host, port, 'ssh_cbc', 'yes' if cbc else 'no', ('CBC ciphers: ' + ', '.join(cbc)) if cbc else 'no CBC cipher offered'))
        out.append(_item(host, port, 'ssh_aes_gcm', 'yes' if gcm else 'no', ('offers ' + ', '.join(gcm)) if gcm else 'no AES-GCM cipher offered'))
    names = _names(methods)
    if names:
        known = [m for m in AUTH_METHODS if m in names]
        if known:
            out.append(_item(host, port, 'ssh_auth_methods', ','.join(known), 'listed: ' + ', '.join(names)))
    return [i for i in out if i]


# ----------------------------------------------------------------------------- nmap's NSE output: ssh2-enum-algos, rdp-enum-encryption

_RDP_LINE = re.compile(r'^\s*(CredSSP \(NLA\)|CredSSP with Early User Auth|Native RDP|RDSTLS|SSL):\s*(SUCCESS|FAILED|Unknown)\b', re.M)
_CREDSSP = ('CredSSP (NLA)', 'CredSSP with Early User Auth')


def rdp_reading(host, port, text):
    """The ``rdp_nla`` item from ``rdp-enum-encryption``'s text, or None. nmap prints a protocol the server accepted as SUCCESS and (outside
    debug mode) leaves out the ones it refused; a protocol the server gave no negotiation answer for is Unknown, which makes the reading unknown
    unless standard RDP or TLS was accepted."""
    if not isinstance(text, str):
        return None
    lines = dict(_RDP_LINE.findall(text[:4000]))
    if not lines:
        return None
    accepted = [name for name, state in lines.items() if state == 'SUCCESS']
    if lines.get('Native RDP') == 'SUCCESS' or lines.get('SSL') == 'SUCCESS':
        return _item(host, port, 'rdp_nla', 'not_required', 'accepts ' + ', '.join(accepted) + ' (a session without CredSSP)')
    if 'Unknown' in lines.values():
        return None
    if any(lines.get(name) == 'SUCCESS' for name in _CREDSSP):
        return _item(host, port, 'rdp_nla', 'required', 'accepts only ' + ', '.join(accepted) + ': standard RDP security and TLS were refused')
    return None


def _nse_tables(script_el):
    """``{key: [names]}`` of a script's structured output (``<table key="kex_algorithms"><elem>...</elem></table>``)."""
    out = {}
    for table in script_el.findall('table'):
        key = table.get('key')
        if key:
            out[key] = [(e.text or '') for e in table.findall('elem')][:100]
    return out


def ssh_from_nse(host, port, tables):
    """The SSH items of ``ssh2-enum-algos``'s tables: it lists a pair of directions once when they are the same and both otherwise."""
    def both(name):
        if name in tables:
            return tables[name]
        parts = [tables[k] for k in (f'{name}_client_to_server', f'{name}_server_to_client') if k in tables]
        return [x for part in parts for x in part] if parts else None
    return ssh_readings(host, port, kex=tables.get('kex_algorithms'), ciphers=both('encryption_algorithms'), macs=both('mac_algorithms'))


def nse_readings(xml_text):
    """The SSH and RDP items of an nmap ``-oX`` report: the structured output of ``ssh2-enum-algos`` and the text of ``rdp-enum-encryption`` on
    each open TCP port. [] for a report that cannot be read."""
    if not isinstance(xml_text, str) or not xml_text.strip() or '<!ENTITY' in xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    out = []
    for host_el in root.findall('host'):
        addr_el = next((a for a in host_el.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), None)
        if addr_el is None or not addr_el.get('addr'):
            continue
        ip = addr_el.get('addr')
        for port_el in host_el.findall('ports/port'):
            state = port_el.find('state')
            if port_el.get('protocol', 'tcp') != 'tcp' or state is None or state.get('state') != 'open':
                continue
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            for script in port_el.findall('script'):
                if script.get('id') == 'ssh2-enum-algos':
                    out.extend(ssh_from_nse(ip, number, _nse_tables(script)))
                elif script.get('id') == 'rdp-enum-encryption':
                    item = rdp_reading(ip, number, script.get('output'))
                    if item:
                        out.append(item)
    return out


# ----------------------------------------------------------------------------- SMTP: one EHLO

_REPLY_LINE = re.compile(r'^(\d{3})([ -])(.*)$')
SMTP_FLAGS = (('CHUNKING', 'smtp_chunking'), ('STARTTLS', 'smtp_starttls'), ('SMTPUTF8', 'smtp_smtputf8'), ('8BITMIME', 'smtp_8bitmime'),
              ('PIPELINING', 'smtp_pipelining'))
AUTH_TOKENS = features.FEATURES['smtp_auth']['values']


def parse_reply(data):
    """``(code, [text of each line])`` of one complete SMTP reply in ``data`` (bytes), or None when it is not a complete, well-formed reply."""
    text = data.decode('latin-1') if isinstance(data, (bytes, bytearray)) else str(data or '')
    lines, code = [], None
    for raw in text.split('\n'):
        raw = raw.rstrip('\r')
        if not raw:
            continue
        match = _REPLY_LINE.match(raw)
        if not match or (code is not None and match.group(1) != code):
            return None
        code = match.group(1)
        lines.append(match.group(3))
        if match.group(2) == ' ':
            return int(code), lines
    return None


def _auth_tokens(mechanisms):
    names = []
    for word in mechanisms:
        word = word.lower()
        token = word if word in AUTH_TOKENS and word not in ('other', 'none') else 'other'
        token = 'tls_unread' if word == 'tls_unread' else token
        if token not in names:
            names.append(token)
    ordered = [t for t in AUTH_TOKENS if t in names]
    value = ''
    for token in ordered:  # the rule-bearing mechanisms come first in AUTH_TOKENS, so a cut never drops them
        if len(value) + len(token) + (1 if value else 0) > features.MAX_VALUE:
            break
        value = f'{value},{token}' if value else token
    return value


def ehlo_readings(host, port, lines):
    """The SMTP items of one EHLO reply (``lines``: the text of each line; the first is the server's greeting, the rest its keywords)."""
    keywords = [line.strip() for line in lines[1:] if line.strip()][:60]
    names = {re.split(r'[ =]', k, maxsplit=1)[0].upper() for k in keywords}
    out = [_item(host, port, feature, 'yes' if keyword in names else 'no', f'EHLO {"lists" if keyword in names else "does not list"} {keyword}')
           for keyword, feature in SMTP_FLAGS]
    auth = [k for k in keywords if re.match(r'(?i)^AUTH[ =]', k)]
    starttls = 'STARTTLS' in names  # a server may list more mechanisms (or AUTH at all) only after STARTTLS, which is never sent
    if auth:
        mechanisms = [m for k in auth for m in re.split(r'\s+', k[5:].strip()) if m][:20]
        value = _auth_tokens(mechanisms + (['tls_unread'] if starttls else []))
        if value:
            out.append(_item(host, port, 'smtp_auth', value, 'AUTH ' + ' '.join(mechanisms) + ('; more may follow STARTTLS' if starttls else '')))
    elif starttls:
        out.append(_item(host, port, 'smtp_auth', 'tls_unread', 'EHLO lists no AUTH before STARTTLS; the list after STARTTLS is not read'))
    else:
        out.append(_item(host, port, 'smtp_auth', 'none', 'EHLO lists no AUTH and no STARTTLS'))
    return [i for i in out if i]


def _read_reply(sock, deadline, limit=MAX_SMTP_REPLY):
    data = b''
    while len(data) < limit:
        parsed = parse_reply(data)
        if parsed:
            return parsed
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        sock.settimeout(left)
        try:
            chunk = sock.recv(min(4096, limit - len(data)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return parse_reply(data)
        data += chunk
    return parse_reply(data)


def smtp_exchange(sock, deadline):
    """Greeting, one EHLO, QUIT on an open connection. The EHLO reply's lines, or None when the server did not greet with 220 or did not answer
    EHLO with 250."""
    greeting = _read_reply(sock, deadline)
    if not greeting or greeting[0] != 220:
        return None
    sock.sendall(f'EHLO {EHLO_NAME}\r\n'.encode('ascii'))
    reply = _read_reply(sock, deadline)
    try:
        sock.sendall(b'QUIT\r\n')
    except OSError:
        pass
    if not reply or reply[0] != 250:
        return None
    return reply[1]


# ----------------------------------------------------------------------------- SMB: NEGOTIATE only

DIALECTS = {0x0202: '2.0.2', 0x0210: '2.1', 0x0300: '3.0', 0x0302: '3.0.2', 0x0311: '3.1.1'}
COMPRESSION = {0: 'none', 1: 'LZNT1', 2: 'LZ77', 3: 'LZ77+Huffman', 4: 'Pattern_V1', 5: 'LZ4'}
OFFERED_COMPRESSION = (1, 2, 3)  # LZNT1, LZ77, LZ77+Huffman: what Windows' SMB 3.1.1 compression implements
PREAUTH, ENCRYPTION, COMPRESSION_CONTEXT = 1, 2, 3
SIGNING_REQUIRED = 0x02


def _pad8(data):
    return data + b'\0' * (-len(data) % 8)


def smb2_negotiate_request(client_guid=None, salt=None):
    """One SMB2 NEGOTIATE request (with its 4-byte transport header): dialects 2.0.2 to 3.1.1, signing enabled (not required), and for 3.1.1 the
    pre-authentication integrity (SHA-512), encryption (AES-128-GCM, AES-128-CCM) and compression (LZNT1, LZ77, LZ77+Huffman) contexts."""
    client_guid = client_guid if client_guid is not None else os.urandom(16)
    salt = salt if salt is not None else os.urandom(32)
    header = (b'\xfeSMB' + (64).to_bytes(2, 'little') + b'\0\0' + b'\0' * 4 + (0).to_bytes(2, 'little') + (1).to_bytes(2, 'little')
              + b'\0' * 4 + b'\0' * 4 + (0).to_bytes(8, 'little') + b'\0' * 4 + b'\0' * 4 + b'\0' * 8 + b'\0' * 16)
    dialects = b''.join(d.to_bytes(2, 'little') for d in DIALECTS)
    contexts = [
        (PREAUTH, (1).to_bytes(2, 'little') + (32).to_bytes(2, 'little') + (0x0001).to_bytes(2, 'little') + salt),
        (ENCRYPTION, (2).to_bytes(2, 'little') + (0x0002).to_bytes(2, 'little') + (0x0001).to_bytes(2, 'little')),
        (COMPRESSION_CONTEXT, len(OFFERED_COMPRESSION).to_bytes(2, 'little') + b'\0\0' + b'\0' * 4
         + b''.join(a.to_bytes(2, 'little') for a in OFFERED_COMPRESSION)),
    ]
    fixed_len = 36
    context_offset = len(header) + fixed_len + len(dialects)
    context_offset += -context_offset % 8
    body = ((36).to_bytes(2, 'little') + len(DIALECTS).to_bytes(2, 'little') + (0x0001).to_bytes(2, 'little') + b'\0\0' + b'\0' * 4
            + client_guid + context_offset.to_bytes(4, 'little') + len(contexts).to_bytes(2, 'little') + b'\0\0' + dialects)
    message = _pad8(header + body)
    for index, (kind, data) in enumerate(contexts):
        context = kind.to_bytes(2, 'little') + len(data).to_bytes(2, 'little') + b'\0' * 4 + data
        message += context if index == len(contexts) - 1 else _pad8(context)
    return len(message).to_bytes(4, 'big') + message


def smb1_negotiate_request():
    """One SMB1 NEGOTIATE (``SMB_COM_NEGOTIATE``) naming only the NT LM 0.12 dialect, with its transport header: a server that has SMBv1 off
    refuses it or closes the connection; a multi-protocol server is never offered an SMB2 dialect to move to."""
    header = (b'\xffSMB' + bytes([0x72]) + b'\0' * 4 + bytes([0x18]) + (0xC801).to_bytes(2, 'little') + b'\0' * 2 + b'\0' * 8 + b'\0' * 2
              + b'\0' * 2 + (0xFEFF).to_bytes(2, 'little') + b'\0' * 2 + b'\0' * 2)
    dialects = b'\x02NT LM 0.12\x00'
    message = header + b'\x00' + len(dialects).to_bytes(2, 'little') + dialects
    return len(message).to_bytes(4, 'big') + message


def _message(data):
    """The SMB message of a direct-TCP frame (``data``: what was read, header included), or None."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 4 or data[0] != 0:
        return None
    length = int.from_bytes(data[1:4], 'big')
    body = bytes(data[4:4 + length])
    return body if len(body) == length or len(body) >= MAX_SMB_REPLY - 4 else None


def parse_smb2_negotiate(data):
    """``{'dialect', 'signing_required', 'compression': [names] | None}`` of an SMB2 NEGOTIATE response, or None when it is not a successful
    one. ``compression`` is None when the response carries no compression context."""
    msg = _message(data)
    if msg is None or len(msg) < 64 + 65 - 1 or msg[:4] != b'\xfeSMB':
        return None
    status = int.from_bytes(msg[8:12], 'little')
    command = int.from_bytes(msg[12:14], 'little')
    if status != 0 or command != 0 or int.from_bytes(msg[64:66], 'little') != 65:
        return None
    security_mode = int.from_bytes(msg[66:68], 'little')
    revision = int.from_bytes(msg[68:70], 'little')
    if revision not in DIALECTS:
        return None
    out = {'dialect': DIALECTS[revision], 'signing_required': bool(security_mode & SIGNING_REQUIRED), 'compression': None}
    if revision == 0x0311:
        count = int.from_bytes(msg[70:72], 'little')
        offset = int.from_bytes(msg[124:128], 'little')
        for _ in range(min(count, 16)):
            if offset + 8 > len(msg):
                break
            kind = int.from_bytes(msg[offset:offset + 2], 'little')
            size = int.from_bytes(msg[offset + 2:offset + 4], 'little')
            data_ = msg[offset + 8:offset + 8 + size]
            if len(data_) < size:
                break
            if kind == COMPRESSION_CONTEXT and size >= 8:
                n = int.from_bytes(data_[0:2], 'little')
                ids = [int.from_bytes(data_[8 + 2 * i:10 + 2 * i], 'little') for i in range(min(n, 8)) if 10 + 2 * i <= size]
                out['compression'] = [COMPRESSION.get(i, f'0x{i:04x}') for i in ids]
            offset += 8 + size
            offset += -offset % 8
    return out


def parse_smb1_negotiate(data):
    """True when an SMB1 NEGOTIATE response accepts the dialect offered, False when it answers that it accepts none (dialect index 0xFFFF), an
    error status or an SMB2 message; None when it is not an SMB answer at all."""
    msg = _message(data)
    if msg is None or len(msg) < 4:
        return None
    if msg[:4] == b'\xfeSMB':
        return False
    if msg[:4] != b'\xffSMB' or len(msg) < 33 or msg[4] != 0x72:
        return None
    if int.from_bytes(msg[5:9], 'little') != 0:
        return False
    words = msg[32]
    if words < 1 or len(msg) < 35:
        return False
    return int.from_bytes(msg[33:35], 'little') == 0


def smb_readings(host, port, negotiate, smbv1):
    """The SMB items from the SMB2 NEGOTIATE answer (``parse_smb2_negotiate``'s, or None) and the SMB1 verdict (True, False or None)."""
    out = []
    if negotiate:
        out.append(_item(host, port, 'smb_dialect', negotiate['dialect'], f'SMB2 NEGOTIATE chose dialect {negotiate["dialect"]}'))
        out.append(_item(host, port, 'smb_signing', 'required' if negotiate['signing_required'] else 'not_required',
                         'the server requires signing' if negotiate['signing_required'] else 'signing is enabled but not required'))
        algorithms = [a for a in negotiate['compression'] or () if a != 'none']
        if negotiate['dialect'] != '3.1.1':
            out.append(_item(host, port, 'smb_compression', 'no', f'dialect {negotiate["dialect"]}: compression needs SMB 3.1.1'))
        elif algorithms:
            out.append(_item(host, port, 'smb_compression', 'yes', 'SMB 3.1.1 with compression: ' + ', '.join(algorithms)))
        else:
            out.append(_item(host, port, 'smb_compression', 'no', 'SMB 3.1.1 without a compression algorithm'))
    if smbv1 is not None:
        out.append(_item(host, port, 'smbv1', 'yes' if smbv1 else 'no',
                         'accepts an SMB1 NEGOTIATE (NT LM 0.12)' if smbv1 else 'refuses SMB1 (NT LM 0.12)'))
    return [i for i in out if i]


def _read_frame(sock, deadline, limit=MAX_SMB_REPLY):
    """``(state, data)``: ``reply`` with the bytes of one direct-TCP frame (at most ``limit``), ``closed`` when the peer closed or reset the
    connection before answering, ``timeout`` when nothing complete came before ``deadline``."""
    data, want = b'', 4
    while len(data) < want:
        left = deadline - time.monotonic()
        if left <= 0:
            return 'timeout', data
        sock.settimeout(left)
        try:
            chunk = sock.recv(min(4096, want - len(data)))
        except socket.timeout:
            return 'timeout', data
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return ('closed', data) if not data else ('timeout', data)
        except OSError:
            return 'timeout', data
        if not chunk:
            return ('closed', data) if not data else ('timeout', data)
        data += chunk
        if len(data) >= 4 and want == 4:
            want = min(limit, 4 + int.from_bytes(data[1:4], 'big'))
    return 'reply', data


# ----------------------------------------------------------------------------- the network half

def _connect(address, port, policy, timeout=CONNECT_TIMEOUT):
    from . import transport
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    numeric = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    return transport.open_socket(((family, numeric),), timeout, policy, host=address, literal=True)


def probe_smtp(address, port, policy, connect=_connect):
    """The SMTP items of one endpoint ([] when the exchange did not complete)."""
    try:
        sock = connect(address, port, policy)
    except (OSError, ValueError):
        return []
    try:
        lines = smtp_exchange(sock, time.monotonic() + READ_SECONDS)
    except OSError:
        lines = None
    finally:
        _close(sock)
    return ehlo_readings(address, port, lines) if lines else []


def _smb_exchange(address, port, policy, request, connect):
    try:
        sock = connect(address, port, policy)
    except (OSError, ValueError):
        return 'error', b''
    try:
        sock.sendall(request)
        return _read_frame(sock, time.monotonic() + READ_SECONDS)
    except OSError:
        return 'closed', b''
    finally:
        _close(sock)


def probe_smb(address, port, policy, connect=_connect):
    """The SMB items of one endpoint: one SMB2 NEGOTIATE, then one SMB1 NEGOTIATE on a second connection. A server that answered SMB2 and then
    closed or reset the SMB1 connection without a word refuses SMBv1; with no SMB2 answer either, that says nothing."""
    state, data = _smb_exchange(address, port, policy, smb2_negotiate_request(), connect)
    negotiate = parse_smb2_negotiate(data) if state == 'reply' else None
    state1, data1 = _smb_exchange(address, port, policy, smb1_negotiate_request(), connect)
    smbv1 = parse_smb1_negotiate(data1) if state1 == 'reply' else (False if state1 == 'closed' and negotiate else None)
    return smb_readings(address, port, negotiate, smbv1)


def _close(sock):
    try:
        sock.close()
    except OSError:
        pass


def is_smtp_port(port):
    """A cleartext SMTP port of a fingerprint row: nmap named it smtp or submission, or it is 25, 587 or 2525 and nmap named nothing else. A
    TLS-wrapped one (465) is never asked."""
    if port.get('tunnel') == 'ssl' or port.get('protocol', 'tcp') != 'tcp':
        return False
    service = str(port.get('service_name') or '').lower()
    return service in SMTP_SERVICES or (port.get('number') in SMTP_PORTS and service in ('', 'smtp', 'unknown', 'tcpwrapped'))


def is_smb_port(port):
    return port.get('protocol', 'tcp') == 'tcp' and port.get('number') == SMB_PORT


def endpoints(hosts, vetted):
    """``[(kind, address, port)]``: the SMTP and SMB endpoints of a fingerprint pass's hosts (``parsers.parse_nmap_xml``'s rows) whose address
    is one the task named (``vetted``)."""
    out = []
    for host in hosts or ():
        address = host.get('ip')
        if address not in vetted:
            continue
        for port in host.get('ports') or ():
            if is_smtp_port(port):
                out.append(('smtp', address, port['number']))
            elif is_smb_port(port):
                out.append(('smb', address, port['number']))
    return out


PROBES = {'smtp': probe_smtp, 'smb': probe_smb}


def follow_up(hosts, vetted, budget=BUDGET_SECONDS, connect=_connect, workers=WORKERS, clock=time.monotonic):
    """``(items, skipped)``: the SMTP and SMB readings of a fingerprint pass's open ports. Each endpoint is asked at most once; at most
    ``MAX_ENDPOINTS``, and none is started after ``budget`` seconds (``skipped`` counts the ones not asked). The addresses are held to a policy
    that names exactly the task's own (``vetted``) on top of this Sentinel's floor."""
    from .policy import ScopePolicy
    vetted = {str(a) for a in vetted}
    todo = endpoints(hosts, vetted)
    skipped = max(0, len(todo) - MAX_ENDPOINTS)
    todo = todo[:MAX_ENDPOINTS]
    if not todo or budget <= 0:
        return [], skipped + len(todo)
    policy = ScopePolicy({'hosts': sorted(vetted), 'addresses': sorted(vetted)})
    stop = clock() + budget
    late = []

    def one(entry):
        kind, address, port = entry
        if clock() >= stop:
            late.append(entry)
            return []
        try:
            return PROBES[kind](address, port, policy, connect=connect)
        except Exception:  # noqa: BLE001 - one endpoint never fails the fingerprint pass
            logger.warning('%s feature probe of %s:%s failed', kind, address, port, exc_info=True)
            return []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(one, todo))
    return [item for items in results for item in items], skipped + len(late)


# the order items are kept in when a result has more than features.MAX_ITEMS: the readings a CVE rule reads first
PRIORITY = ('ssh_terrapin', 'rdp_nla', 'smbv1', 'smb_compression', 'smtp_chunking', 'smtp_auth', 'smtp_starttls', 'ssh_cbc', 'ssh_aes_gcm',
            'smb_dialect', 'smb_signing', 'smtp_smtputf8', 'smtp_8bitmime', 'smtp_pipelining', 'ssh_auth_methods')


def bounded(items):
    """``(items, dropped)``: the readings cleaned (``features.clean_features``), the rule-bearing features first, at most ``features.MAX_ITEMS``."""
    rank = {key: index for index, key in enumerate(PRIORITY)}
    ordered = sorted((i for i in items if i), key=lambda i: rank.get(i['feature'], len(PRIORITY)))
    kept = features.clean_features(ordered[:features.MAX_ITEMS])
    return kept, max(0, len(ordered) - features.MAX_ITEMS)
