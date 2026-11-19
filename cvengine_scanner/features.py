"""Service features: the shared vocabulary of what a Sentinel may report about one feature of the service on a host and port.

Some flaws are only reachable when a service has a feature turned on (the nginx HTTP/2 module flaws need HTTP/2; Terrapin needs an SSH algorithm;
an SMBv3 compression flaw needs compression). A Sentinel reads such a feature where it already talks to the service, and any result kind may carry
the readings as an optional ``service_features`` list:

    "service_features": [{"host": "www.example.com", "port": 443, "transport": "tcp", "feature": "http2", "value": "yes", "detail": "ALPN h2"}]

``FEATURES`` is the closed vocabulary, one copy shared by the Sentinel (which writes the readings) and the cvENGINE server (which imports this module
from the pinned library, validates every list with ``clean_features`` and decides what a reading means for a CVE match). A feature is added here
first, with its values; a reading of a feature or a value not listed here is dropped by both sides.

Item rules (``clean_features``): ``feature`` is a key of ``FEATURES`` (keys match ``[a-z0-9_]{1,32}``); ``value`` is one allowed token of that
feature, or several joined by commas (at most 64 characters, each token allowed, no repeats); ``detail`` is optional plain text (at most 200
characters, control characters removed); ``host`` is a host name or address (at most 253 characters); ``port`` is 1 to 65535; ``transport`` is
``tcp`` or ``udp`` and fits the feature's; a list holds at most ``MAX_ITEMS`` items. Anything else is dropped, never repaired.

A reading that was not taken is no item: an absent item is unknown, never "no". Pure: no I/O.
"""
import re

MAX_ITEMS = 128
MAX_VALUE = 64
MAX_DETAIL = 200
MAX_HOST = 253
TRANSPORTS = ('tcp', 'udp')

# key -> {'values': the allowed tokens, 'transport': 'tcp' | 'udp' | 'any', 'about': one line}
FEATURES = {
    'http2': {'values': ('yes', 'no'), 'transport': 'tcp',
              'about': 'whether the TLS service offers HTTP/2: the ALPN protocol it chose from h2 and http/1.1 (yes: h2; no: http/1.1 or none); '
                       'the ALPN answer is in detail'},
    # SSH, read from the server's KEXINIT (unauthenticated, sent before any login): nmap's ssh2-enum-algos in the fingerprint pass, or the
    # ssh_probe kind's sshamble record (cvengine_scanner.probes.service_probes.ssh_readings)
    'ssh_terrapin': {'values': ('exposed', 'strict_kex', 'no_affected_mode'), 'transport': 'tcp',
                     'about': 'the Terrapin prefix truncation (CVE-2023-48795) preconditions of the SSH server: exposed (it offers '
                              'chacha20-poly1305@openssh.com, or a CBC cipher with an -etm@openssh.com MAC, and not strict kex), strict_kex (an '
                              'affected mode, but kex-strict-s-v00@openssh.com is offered) or no_affected_mode (neither mode is offered)'},
    'ssh_cbc': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the SSH server offers a cipher in CBC mode'},
    'ssh_aes_gcm': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the SSH server offers aes128-gcm@openssh.com or aes256-gcm@openssh.com'},
    'ssh_auth_methods': {'values': ('publickey', 'password', 'keyboard-interactive', 'hostbased', 'gssapi-with-mic', 'gssapi-keyex', 'none'),
                         'transport': 'tcp',
                         'about': 'the authentication methods the SSH server lists to a client that sent no credential (the ssh_probe kind only)'},
    # SMTP, read from one EHLO on a cleartext SMTP port (then QUIT: no MAIL FROM, no AUTH)
    'smtp_chunking': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the EHLO reply lists CHUNKING (the BDAT command)'},
    'smtp_starttls': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the EHLO reply lists STARTTLS'},
    'smtp_smtputf8': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the EHLO reply lists SMTPUTF8'},
    'smtp_8bitmime': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the EHLO reply lists 8BITMIME'},
    'smtp_pipelining': {'values': ('yes', 'no'), 'transport': 'tcp', 'about': 'whether the EHLO reply lists PIPELINING'},
    'smtp_auth': {'values': ('external', 'ntlm', 'tls_unread', 'gssapi', 'cram-md5', 'digest-md5', 'plain', 'login', 'xoauth2', 'oauthbearer',
                             'scram-sha-1', 'scram-sha-256', 'other', 'none'), 'transport': 'tcp',
                  'about': 'the AUTH mechanisms the cleartext EHLO reply lists; tls_unread: STARTTLS is listed too, and the list after STARTTLS '
                           '(never sent) may hold more; none: no AUTH and no STARTTLS'},
    # SMB, read from one SMB2 NEGOTIATE (with a compression context) and one SMB1 NEGOTIATE on port 445: nothing after NEGOTIATE, no session
    'smb_dialect': {'values': ('2.0.2', '2.1', '3.0', '3.0.2', '3.1.1'), 'transport': 'tcp',
                    'about': 'the SMB2 dialect the server chose from 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 (its highest)'},
    'smb_compression': {'values': ('yes', 'no'), 'transport': 'tcp',
                        'about': 'whether the server negotiates SMB 3.1.1 with compression (the algorithms are in detail); no when it does not '
                                 'choose 3.1.1 or returns no compression algorithm'},
    'smb_signing': {'values': ('required', 'not_required'), 'transport': 'tcp', 'about': 'whether the SMB2 server requires message signing'},
    'smbv1': {'values': ('yes', 'no'), 'transport': 'tcp',
              'about': 'whether the server accepts an SMB1 NEGOTIATE for the NT LM 0.12 dialect (no: it refused the dialect or closed the connection)'},
    # RDP, read from nmap's rdp-enum-encryption in the fingerprint pass (one X.224 Connection Request per security protocol, nothing after it)
    'rdp_nla': {'values': ('required', 'not_required'), 'transport': 'tcp',
                'about': 'whether the RDP server requires Network Level Authentication (CredSSP): not_required when it accepts standard RDP '
                         'security or TLS without CredSSP'},
}

KEY = re.compile(r'[a-z0-9_]{1,32}')
_TOKEN = re.compile(r'[A-Za-z0-9_.@+/-]{1,64}')
_HOST = re.compile(r'[A-Za-z0-9_.:\-\[\]]{1,253}')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]')


def clean_value(feature, value):
    """``value`` when it is one allowed token of ``feature`` or several joined by commas (no repeats, at most MAX_VALUE characters), else None."""
    spec = FEATURES.get(feature)
    if spec is None or not isinstance(value, str) or not 0 < len(value) <= MAX_VALUE:
        return None
    tokens = value.split(',')
    if len(set(tokens)) != len(tokens) or not all(_TOKEN.fullmatch(t) and t in spec['values'] for t in tokens):
        return None
    return value


def clean_item(item):
    """One reading as the vocabulary allows it, or None."""
    if not isinstance(item, dict):
        return None
    feature, host, port, transport = item.get('feature'), item.get('host'), item.get('port'), item.get('transport')
    if not isinstance(feature, str) or not KEY.fullmatch(feature) or feature not in FEATURES:
        return None
    if not isinstance(host, str) or not _HOST.fullmatch(host) or host.startswith(('.', '-')):
        return None
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        return None
    wanted = FEATURES[feature]['transport']
    if transport not in TRANSPORTS or (wanted != 'any' and transport != wanted):
        return None
    value = clean_value(feature, item.get('value'))
    if value is None:
        return None
    detail = item.get('detail', '')
    if detail is None:
        detail = ''
    if not isinstance(detail, str):
        return None
    detail = _CONTROL.sub('', detail).strip()
    if len(detail) > MAX_DETAIL:
        return None
    return {'host': host.lower().rstrip('.'), 'port': port, 'transport': transport, 'feature': feature, 'value': value, 'detail': detail}


def clean_features(items):
    """The readings of a ``service_features`` list that the vocabulary allows, in order, without duplicates (the first reading of one host, port,
    transport and feature wins). Not a list, or longer than MAX_ITEMS: nothing. Malformed or unknown items are dropped, never repaired."""
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        return []
    out, seen = [], set()
    for raw in items:
        item = clean_item(raw)
        if item is None:
            continue
        key = (item['host'], item['port'], item['transport'], item['feature'])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def http2_reading(host, port, alpn):
    """The ``http2`` item for the ALPN answer of one TLS handshake (``probes.hygiene.ALPN_VALUES``), or None when the answer was not read."""
    value = {'h2': 'yes', 'http/1.1': 'no', 'none': 'no'}.get(alpn)
    if value is None:
        return None
    detail = 'ALPN h2' if alpn == 'h2' else 'ALPN http/1.1' if alpn == 'http/1.1' else 'no ALPN protocol chosen'
    return {'host': host, 'port': port, 'transport': 'tcp', 'feature': 'http2', 'value': value, 'detail': detail}
