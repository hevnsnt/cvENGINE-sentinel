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
}

# --- web service features (``probes.service_reads``): read from the answers the http_probe kind already gets, one OPTIONS request, the portal pages of
# an appliance already identified as that vendor, and one SLP question (hygiene_check). Kept as one block so other features merge beside it.
FEATURES.update({
    'http3': {'values': ('yes', 'no'), 'transport': 'tcp',
              'about': 'whether the HTTPS service advertises HTTP/3 (QUIC) in its Alt-Svc response header (yes: h3 or h3-NN; no: an HTTPS answer '
                       'without it). An HTTP/3 listener that is not advertised is not read, so no only means not advertised'},
    'php_windows': {'values': ('yes', 'no'), 'transport': 'tcp',
                    'about': 'whether the PHP this web service names (X-Powered-By or Server: PHP/x) runs on Windows, from the same answer\'s Server '
                             'and X-Powered-By headers (yes: IIS, Win32 or Win64; no: a Unix or Linux distribution token). CGI mode and the code '
                             'page are not read'},
    'webdav': {'values': ('yes', 'no'), 'transport': 'tcp',
               'about': 'whether the web service answers OPTIONS / with a DAV compliance header (yes: DAV: 1, 2 or 3, or MS-Author-Via: DAV; no: an '
                        'OPTIONS answer without one, or 405/501). WebDAV turned on only below / is not read'},
    'http_methods': {'values': ('put', 'delete', 'trace', 'propfind', 'none'), 'transport': 'tcp',
                     'about': 'which of PUT, DELETE, TRACE and PROPFIND the OPTIONS / answer lists in Allow or Public (none: it lists none of them)'},
    'vpn_fortinet': {'values': ('yes', 'no'), 'transport': 'tcp',
                     'about': 'whether a FortiGate answers its SSL-VPN web portal login page (/remote/login)'},
    'vpn_globalprotect': {'values': ('yes', 'no'), 'transport': 'tcp',
                          'about': 'whether a PAN-OS firewall answers a GlobalProtect portal (/global-protect/login.esp) or gateway '
                                   '(/ssl-vpn/prelogin.esp) page; detail says which'},
    'vpn_cisco': {'values': ('yes', 'no'), 'transport': 'tcp',
                  'about': 'whether a Cisco ASA or FTD answers its WebVPN / AnyConnect login page (/+CSCOE+/logon.html)'},
    'vpn_citrix': {'values': ('yes', 'no'), 'transport': 'tcp',
                   'about': 'whether a NetScaler answers a Gateway (/vpn/index.html) or AAA (/logon/LogonPoint/index.html) login page; detail says which'},
    'vpn_ivanti': {'values': ('yes', 'no'), 'transport': 'tcp',
                   'about': 'whether an Ivanti (Pulse) Connect Secure answers its user sign-in page (/dana-na/auth/url_default/welcome.cgi)'},
    'slp': {'values': ('yes', 'no'), 'transport': 'tcp',
            'about': 'whether the Service Location Protocol (OpenSLP on VMware ESXi) answers one SLPv2 service request on TCP 427 (yes: an SLP reply; '
                     'no: the connection was refused). UDP 427 is not read'},
})
# --- end of the web service features

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
