"""The pure parsers: what a tool wrote to its output, turned into the typed shape ``agentapi.sentinel_broker.clean_result`` expects for each
task kind (and ``cvengine_scanner/contract/sentinel_contract.json`` describes). No parser starts a process, reads the environment or touches the
network, so the Sentinel and the cvENGINE server run the same code over the same bytes.
"""
import json
import logging
import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .flags import GENERIC_WAF_NAMES, NSE_SCRIPT_SET, MAX_DISCOVER_HOSTS, MAX_OPEN_PER_IP, MAX_WAF_PRODUCTS, WAF_NAME_LEN, host_of

logger = logging.getLogger('cvengine_scanner.parsers')


class ToolOutputError(RuntimeError):
    """A tool wrote more output than this Sentinel holds in memory. The run was stopped; the task is reported as an error."""


# --- cuts: what a result left out, said in one shape (contract 5, ``$defs/cuts``) -----------------------------------------------------------

MAX_CUTS = 24


class Cuts:
    """What a result cut, collected for its ``cuts`` field: a list capped (``items``: how many were dropped), a text clipped (``chars``: how many characters
    were lost) or a tool stopped at its time limit (``time``: the limit in seconds). The same cut reported twice is added up, so a thousand clipped
    scripts are one line. At most ``MAX_CUTS`` lines: past that a cut loses its target and is added to the line of its kind, so the count stays whole."""

    def __init__(self):
        self.rows = {}

    def _add(self, what, kind, limit, dropped, target):
        key = (what, kind, target)
        if key not in self.rows and len(self.rows) >= MAX_CUTS - 1:
            key = (what, kind, None)
        row = self.rows.get(key)
        if row is None:
            row = self.rows[key] = {'what': what, 'kind': kind}
            if limit is not None:
                row['limit'] = int(limit)
            if kind != 'time':
                row['dropped'] = 0
            if key[2]:
                row['target'] = str(key[2])[:260]
        if kind != 'time':
            row['dropped'] += int(dropped)

    def items(self, what, limit, dropped, target=None):
        if dropped > 0:
            self._add(what, 'items', limit, dropped, target)

    def chars(self, what, limit, dropped, target=None):
        if dropped > 0:
            self._add(what, 'chars', limit, dropped, target)

    def time(self, what, seconds, target=None):
        self._add(what, 'time', seconds, 0, target)

    def merge(self, rows):
        """Fold in the ``cuts`` list of another part of the same run (the IPv4 and the IPv6 nmap run, one nuclei pass of several)."""
        for row in rows or []:
            if row.get('kind') == 'time':
                self._add(row['what'], 'time', row.get('limit'), 0, row.get('target'))
            else:
                self._add(row['what'], row['kind'], row.get('limit'), row.get('dropped', 0), row.get('target'))

    def __bool__(self):
        return bool(self.rows)

    def as_list(self):
        return list(self.rows.values())


_CONTROL = re.compile('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]')
SCRIPT_OUTPUT_CAP = 4000  # one NSE script's text; the same bound as ``nmap.SCRIPT_OUTPUT_CAP`` and the contract's
PORT_SCRIPT_CAP = 16000  # all the scripts of one port (or of one host) together
BANNER_CAP = 1024
MAX_PORTS_PER_HOST = 500  # the contract's ``port`` list bound, the server's own
MAX_SCANNED_RANGES = 4096
NMAP_HOST_TIMEOUT_SECONDS = 480  # ``flags.NMAP_HOST_TIMEOUT``, '8m'


def _plain(value, limit, multiline=False):
    """``(text, clipped)``: ``value`` (text a scanned host controls) without control characters, clipped to ``limit``, and how many characters the clip
    removed. A single-line field loses newlines and tabs too; a script's output keeps them."""
    text = _CONTROL.sub('', str(value or ''))
    if not multiline:
        text = ' '.join(text.split())
    else:
        text = text.replace('\r', '')
    return text[:limit], max(0, len(text) - limit)


def _one(cuts, what, value, limit, target=None):
    text, lost = _plain(value, limit)
    cuts.chars(what, limit, lost, target)
    return text


def _script_texts(parent, cuts, target):
    """``{script id: output}`` of the reviewed scripts under ``parent`` (a port or a hostscript element): each at most ``SCRIPT_OUTPUT_CAP`` characters,
    all together at most ``PORT_SCRIPT_CAP``, the clipped characters counted as ``script_output``. A script nobody reviewed (a version scan runs some on its
    own) is left out, exactly as the server leaves it out."""
    out, budget = {}, PORT_SCRIPT_CAP
    for script in (parent.findall('script') if parent is not None else []):
        sid = script.get('id') or ''
        if sid not in NSE_SCRIPT_SET or sid in out:
            continue
        text, lost = _plain(script.get('output'), SCRIPT_OUTPUT_CAP, multiline=True)
        text = text.strip('\n')
        if len(text) > budget:
            lost += len(text) - budget
            text = text[:budget]
        budget -= len(text)
        cuts.chars('script_output', SCRIPT_OUTPUT_CAP, lost, target)
        out[sid] = text
    return out


def _tls_summary(cert_text, cuts, target):
    """The certificate summary of an ``ssl-cert`` script's output, each field cleaned and clipped: ``{}`` when nmap printed no certificate."""
    from .nmap import parse_ssl_cert  # imported here: nmap.py imports ToolOutputError from this module
    cert = parse_ssl_cert(cert_text)
    out = {}
    for key, value in cert.items():
        if key == 'sans':
            out[key] = [_plain(v, 200)[0] for v in value][:40]
        elif key.startswith('fingerprint_'):
            out[key] = value
        else:
            out[key] = _one(cuts, 'certificate', value, {'subject': 300, 'issuer': 300, 'not_before': 40, 'not_after': 40, 'key_type': 20, 'key_bits': 10, 'signature': 60}.get(key, 60), target)
    return out


def _scanned_ranges(root, cuts, target):
    """The TCP ports nmap says it probed (``<scaninfo protocol="tcp" services="1-3,5">``) as merged ``[low, high]`` ranges, clamped to real port numbers; ``[]``
    when the report does not say."""
    spans = []
    for info in root.findall('scaninfo'):
        if (info.get('protocol') or 'tcp') != 'tcp':
            continue
        for part in str(info.get('services') or '').split(','):
            lo, _, hi = part.strip().partition('-')
            if lo.isdigit() and (not hi or hi.isdigit()):
                lo, hi = max(int(lo), 1), min(int(hi or lo), 65535)
                if lo <= hi:
                    spans.append([lo, hi])
    merged = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    cuts.items('scanned_ranges', MAX_SCANNED_RANGES, len(merged) - MAX_SCANNED_RANGES, target)  # a shorter set only makes the server close fewer ports
    return merged[:MAX_SCANNED_RANGES]


def _port_row(port_el, number, cuts, target):
    service_el = port_el.find('service')
    service = service_el if service_el is not None else ET.Element('service')
    row = {'number': number, 'protocol': port_el.get('protocol') or 'tcp', 'state': 'open',
           'service_name': _one(cuts, 'service', service.get('name'), 64, target), 'product': _one(cuts, 'service', service.get('product'), 120, target),
           'version': _one(cuts, 'service', service.get('version'), 80, target)}
    extra = _one(cuts, 'service', service.get('extrainfo'), 200, target)
    if extra:
        row['service_extra'] = extra
    if service.get('method') in ('probed', 'table'):
        row['method'] = service.get('method')
    if service.get('tunnel') == 'ssl':
        row['tunnel'] = 'ssl'  # the service speaks TLS: name http with tunnel ssl is HTTPS
    for attr, key, limit in (('ostype', 'ostype', 40), ('hostname', 'hostname', 255), ('devicetype', 'devicetype', 64)):
        value = _one(cuts, 'service', service.get(attr), limit, target)
        if value:
            row[key] = value
    if re.fullmatch(r'([0-9]|10)', service.get('conf') or ''):
        row['confidence'] = service.get('conf')
    cpes = []
    for cpe in service.findall('cpe'):
        text, _ = _plain(cpe.text, 255)
        if text.startswith('cpe:/') and text not in cpes:
            cpes.append(text)
    cuts.items('cpes', 8, len(cpes) - 8, target)
    if cpes:
        row['cpes'], row['cpe'] = cpes[:8], cpes[0]
    raw_scripts = {sc.get('id'): sc.get('output') for sc in port_el.findall('script') if sc.get('id') in NSE_SCRIPT_SET}
    scripts = _script_texts(port_el, cuts, target)
    if scripts:
        row['scripts'] = scripts
    banner, lost = _plain(raw_scripts.get('banner') or service.get('servicefp') or '', BANNER_CAP, multiline=True)
    cuts.chars('banner', BANNER_CAP, lost, target)
    if banner.strip():
        row['banner'] = banner.strip()
    tls = _tls_summary(raw_scripts.get('ssl-cert'), cuts, target) if raw_scripts.get('ssl-cert') else {}
    if tls:
        row['tls'] = tls
    return row


def _os_detail(host_el, cuts, target):
    """``(os_guess, extra)``: the best guess's name and, in ``extra``, its accuracy, the runners-up and the closed TCP port OS detection used."""
    extra = {}
    matches = []
    for match in host_el.findall('os/osmatch')[:3]:
        accuracy = match.get('accuracy')
        cpe = match.find('osclass/cpe')
        entry = {'name': _one(cuts, 'os', match.get('name'), 100, target), 'accuracy': int(accuracy) if (accuracy or '').isdigit() and int(accuracy) <= 100 else None}
        if cpe is not None and cpe.text:
            entry['cpe'] = _plain(cpe.text, 120)[0]
        matches.append(entry)
    if matches:
        extra['os_accuracy'] = matches[0]['accuracy']
        extra['os_matches'] = matches
    for used in host_el.findall('os/portused'):
        if used.get('state') == 'closed' and used.get('proto') == 'tcp' and (used.get('portid') or '').isdigit() and 0 < int(used.get('portid')) < 65536:
            extra['closed_tcp'] = int(used.get('portid'))
            break
    return (matches[0]['name'] if matches else ''), extra


def parse_nmap_xml(xml_text, strict=False):
    """The hosts of an nmap ``-oX`` report: for each, its address, OS guess and open ports, and (contract 5) what nmap learned besides. A port keeps its extra
    info, CPEs, how the service was found, whether it is wrapped in TLS (``tunnel``), its banner, the certificate summary nmap read (``tls``) and the output of the
    reviewed NSE scripts (each at most ``SCRIPT_OUTPUT_CAP`` characters, a port's together at most ``PORT_SCRIPT_CAP``); a host keeps the OS accuracy and runners-up,
    the host scripts, the closed TCP port OS detection used (``closed_tcp``), the TCP ports the run probed (``scanned_ranges``) and the states of the ports nmap
    did not list (``extraports``). Every text came from a scanned host: control characters are removed and each field is clipped. What was cut is returned as
    ``cuts`` (only when something was). ``strict`` (the scan runner) refuses a report that is empty, unparseable, not an ``nmaprun`` or
    that never reached ``<finished exit="success">``: an nmap that died part way must be an error, never "no hosts, nothing open"."""
    hosts = []
    cuts = Cuts()
    if not (xml_text or '').strip():
        if strict:
            raise ToolOutputError('nmap produced no report')
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        if strict:
            raise ToolOutputError('nmap produced a report that could not be read') from None
        return {'hosts': hosts}
    if strict and (root.tag != 'nmaprun' or root.find('runstats/finished[@exit="success"]') is None):
        raise ToolOutputError('nmap did not finish its report')
    for host_el in root.findall('host'):
        addr_el = None
        for kind in ('ipv4', 'ipv6'):
            addr_el = host_el.find(f"address[@addrtype='{kind}']")
            if addr_el is not None:
                break
        if addr_el is None:
            addr_el = host_el.find('address')
        if addr_el is None or not addr_el.get('addr'):
            continue
        ip = addr_el.get('addr')
        os_guess, os_extra = _os_detail(host_el, cuts, ip)
        ports = []
        dropped = 0
        for port_el in host_el.findall('ports/port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            if len(ports) >= MAX_PORTS_PER_HOST:
                dropped += 1
                continue
            ports.append(_port_row(port_el, number, cuts, ip))
        cuts.items('ports', MAX_PORTS_PER_HOST, dropped, ip)
        row = {'ip': ip, 'os_guess': os_guess, 'ports': ports, **os_extra}
        state = host_el.find('status')
        row['status'] = 'down' if state is not None and state.get('state') == 'down' else 'up'
        extraports = [_plain(e.get('state'), 20)[0] for e in host_el.findall('ports/extraports')][:8]
        if extraports:
            row['extraports'] = extraports
        scanned = _scanned_ranges(root, cuts, ip)
        if scanned:
            row['scanned_ranges'] = scanned
        hostscripts = _script_texts(host_el.find('hostscript'), cuts, ip)
        if hostscripts:
            row['hostscripts'] = hostscripts
        if host_el.get('timedout') == 'true':  # nmap gave up on the host (its host timeout): it was not fingerprinted, whatever ports it lists
            row['timed_out'] = True
            cuts.time('host_timeout', NMAP_HOST_TIMEOUT_SECONDS, ip)
        hosts.append(row)
    return {'hosts': hosts, 'cuts': cuts.as_list()} if cuts else {'hosts': hosts}


def nmap_scanned_total(xml_text):
    """How many addresses nmap says it scanned (``<runstats><hosts total=...>``) in a finished ``-oX`` report, or ``None`` when the report does not say. With
    ``--open`` nmap lists only the hosts that have an open port, so this count is the only sign that the others were scanned too."""
    try:
        root = ET.fromstring(xml_text or '')
    except ET.ParseError:
        return None
    total = root.find('runstats/hosts')
    value = total.get('total') if total is not None else None
    return int(value) if value and value.isdigit() else None


def parse_port_reasons(xml_text):
    """``{(address, port): (state, reason)}`` from an nmap ``-oX --reason`` report: what each probed port answered (``closed``/``reset``, a reset
    came back; ``filtered``/``no-response``, nothing did). Used by the path survey, which reads only whether a reset came back."""
    out = {}
    try:
        root = ET.fromstring(xml_text or '')
    except ET.ParseError:
        raise ToolOutputError('nmap produced a report that could not be read') from None
    if root.tag != 'nmaprun' or root.find('runstats/finished[@exit="success"]') is None:
        raise ToolOutputError('nmap did not finish its report')
    for host_el in root.findall('host'):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None or not addr_el.get('addr'):
            continue
        for port_el in host_el.findall('ports/port'):
            state_el = port_el.find('state')
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            if state_el is not None:
                out[(addr_el.get('addr'), number)] = (state_el.get('state') or '', state_el.get('reason') or '')
    return out


def parse_discover_xml(xml_text, strict=False):
    """The addresses nmap's ping sweep found up, each with the host names it learned, from ``-oX`` output. ``strict`` (the sweep runner) refuses a report
    that is empty, unparseable, not an ``nmaprun`` or that never reached ``<finished exit="success">``: a sweep that died part way is an error, never "no
    host is up" (review L3), exactly as ``parse_nmap_xml(strict=True)`` does for a scan."""
    hosts = []
    if not (xml_text or '').strip():
        if strict:
            raise ToolOutputError('the discovery sweep produced no report')
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        if strict:
            raise ToolOutputError('the discovery sweep produced a report that could not be read') from None
        return {'hosts': hosts}
    if strict and (root.tag != 'nmaprun' or root.find('runstats/finished[@exit="success"]') is None):
        raise ToolOutputError('the discovery sweep did not finish its report')
    for host_el in root.findall('host'):
        status = host_el.find('status')
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if status is None or status.get('state') != 'up' or addr_el is None or not addr_el.get('addr'):
            continue
        names = [h.get('name') for h in host_el.findall('hostnames/hostname') if h.get('name')]
        hosts.append({'ip': addr_el.get('addr'), 'hostnames': names[:5]})
        if len(hosts) >= MAX_DISCOVER_HOSTS:
            break
    return {'hosts': hosts}


def parse_naabu_output(text):
    found = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        ip, port = row.get('ip') or row.get('host'), row.get('port')
        if ip and isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            found.setdefault(str(ip), set()).add(port)
    # An address with more open ports than that is a tarpit: it is sent as null (never clipped, never dropped) and the server scans its default ports.
    return {ip: (sorted(ports) if len(ports) <= MAX_OPEN_PER_IP else None) for ip, ports in found.items()}


MAX_FINDINGS = 5000
MAX_FINDINGS_BYTES = 20 * 1024 * 1024  # the server's result route takes 24 MB; the findings stay well under it
MAX_LIST_ITEMS = 20  # tags and extracted results kept per finding
_LIMITS = {'template_id': 200, 'name': 500, 'severity': 20, 'host': 255, 'matched_at': 500, 'description': 4000, 'matcher_name': 200,
           'extracted': 500, 'tag': 100, 'reference': 500, 'remediation': 500, 'type': 40}


def _clip(value, limit):
    return value[:limit] if isinstance(value, str) else ''


def _clipped(value, limit, cuts, what):
    """``_clip`` that tells ``cuts`` how many characters it removed."""
    if isinstance(value, str) and len(value) > limit:
        cuts.chars(what, limit, len(value) - limit)
    return _clip(value, limit)


def _strings(value, limit, split=False):
    """A list of strings from a field that should be one: a lone string is one item (or, with ``split``, a comma list), anything else none."""
    if isinstance(value, str):
        value = [v.strip() for v in value.split(',')] if split else [value]
    if not isinstance(value, list):
        return []
    return [v[:limit] for v in value if isinstance(v, str) and v][:MAX_LIST_ITEMS]


# The request and the response a finding keeps: the first characters, as the server keeps them (contract: finding.request/response).
EVIDENCE_LIMIT = 4096
# A header whose name says it carries a credential: its value is never kept (review M2). The name is matched as a whole word fragment so
# Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-Api-Key, X-Auth-Token and the like are all covered.
_SECRET_HEADER = re.compile(r'^([A-Za-z0-9-]*(?:auth|cookie|token|secret|password|passwd|api-?key|session|csrf)[A-Za-z0-9-]*)[ \t]*:.*$',
                            re.IGNORECASE | re.MULTILINE)
_BEARER = re.compile(r'\b(bearer|basic)[ \t]+[A-Za-z0-9._~+/=-]{4,}', re.IGNORECASE)


def redact_evidence(text):
    """``text`` (a request or response) with every credential-bearing header's value and every bearer or basic token replaced by
    ``[REDACTED]``. What was matched stays readable: only the secret goes."""
    text = _SECRET_HEADER.sub(lambda m: f'{m.group(1)}: [REDACTED]', text)
    return _BEARER.sub(lambda m: f'{m.group(1)} [REDACTED]', text)


def _cve_ids(value):
    values = value if isinstance(value, list) else [value]
    return sorted({v.upper() for v in values if isinstance(v, str) and _CVE_ID.fullmatch(v)})[:MAX_LIST_ITEMS]


def _cvss(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
        return None
    return float(value)


_CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,7}', re.IGNORECASE)


def parse_nuclei_jsonl(text, evidence=True, cuts=None):
    """Findings from nuclei's JSONL output. A line that is not an object is skipped and a field of the wrong type is read as empty, so one
    odd line never fails the task; every field is clipped and at most ``MAX_FINDINGS`` are kept. ``evidence=False`` (a signed-in run, whose
    requests carry a sign-in) keeps no request or response at all; otherwise they are kept clipped and redacted. ``cuts`` (a ``Cuts``) is told what this
    reading left out: findings over ``MAX_FINDINGS`` or ``MAX_FINDINGS_BYTES`` (counted, not just logged) and the characters a description or the evidence lost."""
    cuts = cuts if cuts is not None else Cuts()
    findings, size, dropped, full = [], 0, 0, False
    for line in (text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        if full or len(findings) >= MAX_FINDINGS:
            if not full:
                logger.warning('nuclei reported more than %s findings; the rest were dropped', MAX_FINDINGS)
            full, dropped = True, dropped + 1  # every further finding is counted, never silently lost
            continue
        info = row.get('info') if isinstance(row.get('info'), dict) else {}
        finding = {'template_id': _clip(row.get('template-id'), _LIMITS['template_id']),
                   'name': _clip(info.get('name'), _LIMITS['name']),
                   'severity': _clip(info.get('severity'), _LIMITS['severity']) or 'unknown',
                   'host': host_of(row)[:_LIMITS['host']],
                   'matched_at': _clip(row.get('matched-at'), _LIMITS['matched_at']),
                   'description': _clipped(info.get('description'), _LIMITS['description'], cuts, 'description'),
                   'matcher_name': _clip(row.get('matcher-name'), _LIMITS['matcher_name']),
                   'extracted_results': _strings(row.get('extracted-results'), _LIMITS['extracted']),
                   'tags': _strings(info.get('tags'), _LIMITS['tag'], split=True)}
        classification = info.get('classification') if isinstance(info.get('classification'), dict) else {}
        cve_ids = _cve_ids(classification.get('cve-id'))
        if cve_ids:
            finding['cve_ids'] = cve_ids
        cvss = _cvss(classification.get('cvss-score'))
        if cvss is not None:
            finding['cvss_score'] = cvss
        references = _strings(info.get('reference'), _LIMITS['reference'])
        if references:
            finding['references'] = references
        remediation = _clip(info.get('remediation'), _LIMITS['remediation'])
        if remediation:
            finding['remediation'] = remediation
        kind = _clip(row.get('type'), _LIMITS['type']).lower()
        if kind:
            finding['type'] = kind
        if evidence:
            for key in ('request', 'response'):
                text_value = _clipped(row.get(key), EVIDENCE_LIMIT, cuts, 'evidence')
                if text_value:
                    finding[key] = redact_evidence(text_value)
        size += len(json.dumps(finding))
        if size > MAX_FINDINGS_BYTES:
            logger.warning('nuclei findings passed %s bytes; the rest were dropped so the result fits the server\'s limit', MAX_FINDINGS_BYTES)
            full, dropped = True, dropped + 1
            continue
        findings.append(finding)
    cuts.items('findings', len(findings) if len(findings) < MAX_FINDINGS else MAX_FINDINGS, dropped)
    return findings


# The errors that mean nothing answered a request: nothing listens, the name does not resolve, the connection or the answer timed out.
# A failure of another kind (a broken body, a bad header) means something answered, so the host is reached.
NUCLEI_CONNECTION_ERRORS = re.compile(r'connection refused|no such host|timeout|deadline exceeded|no route to host|network is unreachable|'
                                      r'connection reset|could not resolve|dial tcp|no address|port closed or filtered', re.IGNORECASE)  # the last is nuclei 3.11's own wording for a host that is down or a port nothing answers on


# Errors a template logs about itself, not about the host: with -ni (no interactsh) every template that needs it logs the first, and a network template with no
# port logs the second. They say nothing of whether the host answered, so they are left out of the judgement of ``unreached_targets``.
NUCLEI_TEMPLATE_PROBLEMS = re.compile(r'interactsh client not initialized|no port provided in network protocol request', re.IGNORECASE)


class NucleiErrors(dict):
    """``{host: [error text, ...]}`` as ``parse_nuclei_errors`` always gave it, and ``ports``: ``{host: [(port or None, error text), ...]}``, the port each
    failed request went to (nuclei's ``address``), which ``unreached_targets`` needs to tell a host that is down from a host that answered where it was asked
    and was only found closed on a port some template tries (an AJP template asks for 8009 of every web server)."""

    def __init__(self):
        super().__init__()
        self.ports = {}


def parse_nuclei_errors(text):
    """``{host: [error text, ...]}`` from nuclei's error log (``-elog``): one JSON object per line, naming the input it failed on (``input``)
    and the error. A line that is not an object, or names no input, is skipped."""
    errors = NucleiErrors()
    for line in (text or '').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        target = next((row[k] for k in ('input', 'host', 'target', 'matched-at', 'url') if isinstance(row.get(k), str) and row[k]), '')
        if target:
            host, said = host_of({'host': target}), _clip(row.get('error'), 500)
            errors.setdefault(host, []).append(said)
            address = row.get('address') if isinstance(row.get('address'), str) else ''
            port = address.rsplit(':', 1)[1] if ':' in address else ''
            errors.ports.setdefault(host, []).append((int(port) if port.isdigit() else None, said))
    return errors


def _target_ports(target):
    """The ports a request for ``target`` goes to first: its own port (``host:port``, ``[v6]:port``, a URL's), else the two web ports."""
    text = str(target).strip()
    if '://' in text:
        try:
            parts = urlsplit(text)
            return {parts.port or (443 if parts.scheme.lower() == 'https' else 80)}
        except ValueError:
            return {80, 443}
    own = text.rsplit(':', 1)[1] if (text.count(':') == 1 or text.startswith('[')) and ':' in text else ''
    return {int(own)} if own.isdigit() else {80, 443}


def unreached_targets(targets, errors, answered_hosts):
    """The ``targets`` (as they were asked) that nuclei never reached: every request it logged for their host failed to connect, at least one of them to the
    port the target itself names (or the web ports, for a bare host), and no finding names that host. A host with no logged error is not counted: nothing
    says it was not reached. Errors a template logs about itself (``NUCLEI_TEMPLATE_PROBLEMS``) are not read as evidence either way, and a closed port that
    only some template asks for (8009) does not make a host that answered where it was asked unreachable."""
    out = []
    for target in targets:
        host = host_of({'host': target})
        rows = getattr(errors, 'ports', {}).get(host)
        if rows is None:  # a plain dict of texts (a caller that built its own): no port to judge by
            rows = [(None, text) for text in errors.get(host) or []]
        rows = [(port, text) for port, text in rows if not NUCLEI_TEMPLATE_PROBLEMS.search(text)]
        if not rows or host in answered_hosts or not all(NUCLEI_CONNECTION_ERRORS.search(text) for _port, text in rows):
            continue
        own = _target_ports(target)
        if any(port is None or port in own for port, _text in rows):
            out.append(target)
    return out


def parse_testssl_report(raw):
    """The finding objects of a testssl.sh JSON report, flat (``--jsonfile``) or grouped (``--jsonfile-pretty``); mirrors
    ``cveFeed.testssl_scan.flatten``."""
    if isinstance(raw, dict):
        results = raw.get('scanResult') or []
        raw = [item for group in results if isinstance(group, dict) for value in group.values()
               if isinstance(value, list) for item in value]
    return [i for i in raw if isinstance(i, dict) and i.get('id')] if isinstance(raw, list) else []


# testssl's protocol checks: "offered" on one of these is a handshake the scan completed. Every other test needs one.
TESTSSL_PROTOCOLS = frozenset({'SSLv2', 'SSLv3', 'TLS1', 'TLS1_1', 'TLS1_2', 'TLS1_3'})


def testssl_handshake(items):
    """Whether testssl completed a TLS handshake with the endpoint: a protocol it reports as offered, and no scan problem (a WARN or FATAL
    ``scanProblem``). Without one, its other answers, including "not vulnerable", were never tested (review H2)."""
    if any(str(i.get('id')) == 'scanProblem' and str(i.get('severity') or '').upper() in ('WARN', 'FATAL') for i in items):
        return False
    return any(str(i.get('id')) in TESTSSL_PROTOCOLS and str(i.get('finding') or '').lower().startswith('offered') for i in items)


def testssl_result(items, returncode):
    """``{'items', 'handshake', 'returncode'}`` for one testssl.sh run: the finding objects of its report (``items``, as
    ``parse_testssl_report`` reads them) with, when no handshake happened, every clear answer left out (a test marked OK, or "not
    vulnerable", that testssl printed without a handshake). The protocols and the scan problem stay, so the server sees what happened."""
    handshake = testssl_handshake(items)
    kept = list(items) if handshake else [i for i in items if not _clear_answer(i)]
    return {'items': kept, 'handshake': handshake, 'returncode': returncode}


def _clear_answer(item):
    if str(item.get('id')) in TESTSSL_PROTOCOLS:
        return False
    return str(item.get('severity') or '').upper() == 'OK' or str(item.get('finding') or '').lower().startswith('not vulnerable')


def parse_waf_output(text, strict=False):
    """The result of a ``waf`` task from wafw00f's JSON report: ``{'products': [{'name', 'manufacturer'?}], 'generic': bool}``. A generic detection
    (something blocks, no product known) and "no WAF" name nothing; names are stripped and cut, a generic or empty name and a repeat (any case)
    are dropped, and at most ``MAX_WAF_PRODUCTS`` are kept. ``generic`` is true when something blocked and no product was named. ``strict`` (the
    scan runner) refuses a report that is unreadable, not a list, or empty: wafw00f writes ``[]`` when the site never answered ("appears to be
    down"), and that must be an error, never "no WAF"."""
    try:
        rows = json.loads(text or '[]')
    except ValueError:
        rows = None
    rows = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    if strict and not rows:
        raise ToolOutputError('wafw00f wrote no readable result (the site may not have answered)')
    products = waf_products((row.get('firewall'), row.get('manufacturer')) for row in rows if row.get('detected'))
    return {'products': products, 'generic': any(row.get('detected') for row in rows) and not products}


def waf_products(pairs):
    """``[{'name', 'manufacturer'?}]`` from ``(name, manufacturer)`` pairs: the one rule for a product, whether wafw00f's own report or a Sentinel's
    ``waf`` result names it. Names are stripped and cut, a generic or empty name and a repeat (any case) are dropped, an empty manufacturer is left
    out, and at most ``MAX_WAF_PRODUCTS`` are kept."""
    products, seen = [], set()
    for name, manufacturer in pairs:
        name = str(name or '').strip()[:WAF_NAME_LEN]
        if name.lower() in GENERIC_WAF_NAMES or name.lower() in seen:
            continue
        seen.add(name.lower())
        product = {'name': name}
        manufacturer = str(manufacturer or '').strip()[:WAF_NAME_LEN]
        if manufacturer:
            product['manufacturer'] = manufacturer
        products.append(product)
        if len(products) >= MAX_WAF_PRODUCTS:
            break
    return products
