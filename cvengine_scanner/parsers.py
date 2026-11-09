"""The pure parsers: what a tool wrote to its output, turned into the typed shape ``agentapi.sentinel_broker.clean_result`` expects for each
task kind (and ``cvengine_scanner/contract/sentinel_contract.json`` describes). No parser starts a process, reads the environment or touches the
network, so the Sentinel and the cvENGINE server run the same code over the same bytes.
"""
import json
import logging
import re
from xml.etree import ElementTree as ET

from .flags import GENERIC_WAF_NAMES, MAX_DISCOVER_HOSTS, MAX_OPEN_PER_IP, MAX_WAF_PRODUCTS, WAF_NAME_LEN, host_of

logger = logging.getLogger('cvengine_scanner.parsers')


class ToolOutputError(RuntimeError):
    """A tool wrote more output than this Sentinel holds in memory. The run was stopped; the task is reported as an error."""


def parse_nmap_xml(xml_text, strict=False):
    """The hosts of an nmap ``-oX`` report. ``strict`` (the scan runner) refuses a report that is empty, unparseable, not an ``nmaprun`` or
    that never reached ``<finished exit="success">``: an nmap that died part way must be an error, never "no hosts, nothing open"."""
    hosts = []
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
        os_guess = ''
        osmatch = host_el.find('os/osmatch')
        if osmatch is not None:
            os_guess = osmatch.get('name') or ''
        ports = []
        for port_el in host_el.findall('ports/port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            service_el = port_el.find('service')
            try:
                number = int(port_el.get('portid'))
            except (TypeError, ValueError):
                continue
            ports.append({'number': number, 'protocol': port_el.get('protocol') or 'tcp', 'state': 'open',
                          'service_name': (service_el.get('name') if service_el is not None else '') or '',
                          'product': (service_el.get('product') if service_el is not None else '') or '',
                          'version': (service_el.get('version') if service_el is not None else '') or ''})
        row = {'ip': addr_el.get('addr'), 'os_guess': os_guess, 'ports': ports}
        if host_el.get('timedout') == 'true':  # nmap gave up on the host (its host timeout): it was not fingerprinted, whatever ports it lists
            row['timed_out'] = True
        hosts.append(row)
    return {'hosts': hosts}


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


def parse_discover_xml(xml_text):
    """The addresses nmap's ping sweep found up, each with the host names it learned, from ``-oX`` output."""
    hosts = []
    if not (xml_text or '').strip():
        return {'hosts': hosts}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.warning('could not parse nmap XML output')
        return {'hosts': hosts}
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


def parse_nuclei_jsonl(text, evidence=True):
    """Findings from nuclei's JSONL output. A line that is not an object is skipped and a field of the wrong type is read as empty, so one
    odd line never fails the task; every field is clipped and at most ``MAX_FINDINGS`` are kept. ``evidence=False`` (a signed-in run, whose
    requests carry a sign-in) keeps no request or response at all; otherwise they are kept clipped and redacted."""
    findings, size = [], 0
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
        if len(findings) >= MAX_FINDINGS:
            logger.warning('nuclei reported more than %s findings; the rest were dropped', MAX_FINDINGS)
            break
        info = row.get('info') if isinstance(row.get('info'), dict) else {}
        finding = {'template_id': _clip(row.get('template-id'), _LIMITS['template_id']),
                   'name': _clip(info.get('name'), _LIMITS['name']),
                   'severity': _clip(info.get('severity'), _LIMITS['severity']) or 'unknown',
                   'host': host_of(row)[:_LIMITS['host']],
                   'matched_at': _clip(row.get('matched-at'), _LIMITS['matched_at']),
                   'description': _clip(info.get('description'), _LIMITS['description']),
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
                text_value = _clip(row.get(key), EVIDENCE_LIMIT)
                if text_value:
                    finding[key] = redact_evidence(text_value)
        size += len(json.dumps(finding))
        if size > MAX_FINDINGS_BYTES:
            logger.warning('nuclei findings passed %s bytes; the rest were dropped so the result fits the server\'s limit', MAX_FINDINGS_BYTES)
            break
        findings.append(finding)
    return findings


# The errors that mean nothing answered a request: nothing listens, the name does not resolve, the connection or the answer timed out.
# A failure of another kind (a broken body, a bad header) means something answered, so the host is reached.
NUCLEI_CONNECTION_ERRORS = re.compile(r'connection refused|no such host|timeout|deadline exceeded|no route to host|network is unreachable|'
                                      r'connection reset|could not resolve|dial tcp|no address', re.IGNORECASE)


def parse_nuclei_errors(text):
    """``{host: [error text, ...]}`` from nuclei's error log (``-elog``): one JSON object per line, naming the input it failed on (``input``)
    and the error. A line that is not an object, or names no input, is skipped."""
    errors = {}
    for line in (text or '').splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        target = next((row[k] for k in ('input', 'host', 'target', 'matched-at', 'url') if isinstance(row.get(k), str) and row[k]), '')
        if target:
            errors.setdefault(host_of({'host': target}), []).append(_clip(row.get('error'), 500))
    return errors


def unreached_targets(targets, errors, answered_hosts):
    """The ``targets`` (as they were asked) that nuclei never reached: every request it logged for their host failed to connect, and no finding
    names that host. A host with no logged error is not counted: nothing says it was not reached, so it is not reported as unreachable."""
    out = []
    for target in targets:
        host = host_of({'host': target})
        failed = errors.get(host)
        if failed and host not in answered_hosts and all(NUCLEI_CONNECTION_ERRORS.search(text) for text in failed):
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
