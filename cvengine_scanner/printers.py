"""Printer safety: the raw print ports no tool of this library or the Sentinel ever sends a byte to, and how a printer is recognised.

A network printer prints whatever arrives on its raw print port. HP JetDirect and its clones listen on TCP 9100 to 9107 (one port per
parallel port of the old print servers) and treat every byte received as a page description; the LPD daemon on TCP 515 accepts a job in its
own small protocol and many printers print the rest of what they are sent. On Bill's home network on 2026-11-26 the fingerprint pass (nmap
``-sV`` with the reviewed scripts) sent a TLS ClientHello to 9100 and HTTP, TLS and RPC probes to 515 of two printers, and a printer printed
garbage. nmap's own service probe file excludes only 9100 to 9107 from ``-sV``; its scripts and the other tools have no exclusion at all.

The rule, fail closed: no tool sends any payload to ``PRINT_PORTS`` on any target. Finding that such a port is open (a SYN, or a connection
closed at once without data) is allowed, because it sends nothing the printer could print. Every argument builder and every socket opener
calls ``check_port`` (or ``refusal``), and each has a test. ``nmap_exclude_argument`` is the text of nmap's ``--exclude-ports``.

``is_printer`` reads the evidence a fingerprint pass already holds (open print ports, nmap's device type, an IPP or printer web server, an
SNMP description) and is the same rule the server uses to mark a host as a printer and scan it gently. Pure: no network, no Django.
"""
import re

JETDIRECT_PORTS = tuple(range(9100, 9108))  # HP JetDirect raw printing, one port per print server port
LPD_PORT = 515  # the line printer daemon
IPP_PORT = 631  # the Internet Printing Protocol: HTTP, safe for a read, but a POST of a job prints (never sent by any tool here)
PRINT_PORTS = frozenset((*JETDIRECT_PORTS, LPD_PORT))
REFUSAL = 'a raw print port (9100 to 9107, 515) is never sent data: a printer prints what it receives there'


class PrintPortRefused(ValueError):
    """A tool was asked to send data to a raw print port."""


def _number(port):
    if isinstance(port, bool):
        return None
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def is_print_port(port):
    """True when ``port`` (a number or its text) is one of ``PRINT_PORTS``."""
    return _number(port) in PRINT_PORTS


def refusal(port):
    """The reason ``port`` may not be sent data, or '' when it may."""
    return REFUSAL if is_print_port(port) else ''


def check_port(port):
    """``port`` unchanged, or ``PrintPortRefused`` when it is a raw print port."""
    if is_print_port(port):
        raise PrintPortRefused(REFUSAL)
    return port


def without_print_ports(ports):
    """``ports`` with every raw print port left out, order kept."""
    return [p for p in ports if not is_print_port(p)]


def _ranges(ports):
    ports = sorted(set(ports))
    parts, start, prev = [], None, None
    for port in ports + [None]:
        if start is None:
            start = prev = port
        elif port is not None and port == prev + 1:
            prev = port
        else:
            parts.append(str(start) if start == prev else f'{start}-{prev}')
            start = prev = port
    return ','.join(parts)


def nmap_exclude_argument():
    """The value of nmap's ``--exclude-ports``: ``515,9100-9107``."""
    return _ranges(PRINT_PORTS)


# --- recognising a printer ---------------------------------------------------------------------------------------------------------------

_PRINTER_WORDS = re.compile(r'\b(printer|jetdirect|laserjet|officejet|deskjet|pagewide|designjet|imagerunner|bizhub|workcentre|'
                            r'versalink|altalink|ecosys|taskalfa|mfc-|hl-l|dcp-|brother|epson|lexmark|kyocera|ricoh|xerox|sharp mx|'
                            r'konica|canon mf|pixma|imageclass|cups|ipp)\b', re.I)
# the embedded web servers printers ship (nmap's product or the Server header): Brother's debut, HP's Virata-EmWeb and HP HTTP Server,
# Epson's, Lexmark's, Xerox's and Canon's own
_PRINTER_SERVERS = re.compile(r'(debut/|debut embedded|virata-emweb|hp http server|hp-chaiserver|epson[_ -]http|lexmark|xerox_microserver|'
                              r'canon http server|kyocera command center|rapid logic|ews-nic|gsoap/2\.7)', re.I)


def printer_evidence(ports, os_guess='', snmp_text=''):
    """What says a host is a printer: a list of short reasons (empty when nothing does). ``ports`` are the fingerprint pass's port rows
    (``number``, ``state``, ``method``, ``service_name``, ``product``, ``devicetype``, ``service_extra``, ``scripts``). Both are needed: an open
    print port (9100 to 9107, 515) or IPP (631), and a printer's own description (nmap's device type or OS guess, a printer web server, an SNMP
    description). A lone open 9100 is not enough, because Prometheus' node exporter listens there too; the port guard keeps every tool off it
    either way."""
    reasons = []
    open_ports = set()
    described = False
    for row in ports or ():
        if not isinstance(row, dict) or (row.get('state') or 'open') != 'open':
            continue
        number = _number(row.get('number'))
        if number is None:
            continue
        open_ports.add(number)
        # nmap's port table names 515 "printer" and 9100 "jetdirect" without asking anything: only a name a probe confirmed counts
        keys = ('service_name', 'product', 'devicetype', 'service_extra') if row.get('method') == 'probed' else ('product', 'devicetype', 'service_extra')
        text = ' '.join(str(row.get(k) or '') for k in keys)
        scripts = row.get('scripts') if isinstance(row.get('scripts'), dict) else {}
        text += ' ' + ' '.join(str(scripts.get(k) or '') for k in ('http-server-header', 'http-title', 'http-headers'))
        if str(row.get('devicetype') or '').lower() == 'printer' or _PRINTER_WORDS.search(text) or _PRINTER_SERVERS.search(text):
            described = True
    jetdirect = sorted(open_ports & set(JETDIRECT_PORTS))
    if jetdirect:
        reasons.append(f'raw print port {jetdirect[0]} (JetDirect) open')
    if LPD_PORT in open_ports:
        reasons.append('LPD port 515 open')
    if IPP_PORT in open_ports:
        reasons.append('IPP port 631 open')
    if described:
        reasons.append('a service describes itself as a printer')
    if os_guess and _PRINTER_WORDS.search(str(os_guess)):
        reasons.append(f'OS guess: {str(os_guess)[:80]}')
        described = True
    if snmp_text and _PRINTER_WORDS.search(str(snmp_text)):
        reasons.append('SNMP describes a printer')
        described = True
    if described and open_ports & {*PRINT_PORTS, IPP_PORT}:
        return reasons
    return []


def is_printer(ports, os_guess='', snmp_text=''):
    """True when ``printer_evidence`` finds a printer."""
    return bool(printer_evidence(ports, os_guess, snmp_text))
