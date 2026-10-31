"""The pure parsers: what a tool wrote to its output, turned into the typed shape ``agentapi.sentinel_broker.clean_result`` expects for each
task kind (and ``cvengine_scanner/contract/sentinel_contract.json`` describes). No parser starts a process, reads the environment or touches the
network, so the Sentinel and the cvENGINE server run the same code over the same bytes.
"""
import json
import logging
from xml.etree import ElementTree as ET

from .flags import MAX_DISCOVER_HOSTS, MAX_OPEN_PER_IP, host_of

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
        hosts.append({'ip': addr_el.get('addr'), 'os_guess': os_guess, 'ports': ports})
    return {'hosts': hosts}


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
           'extracted': 500, 'tag': 100}


def _clip(value, limit):
    return value[:limit] if isinstance(value, str) else ''


def _strings(value, limit, split=False):
    """A list of strings from a field that should be one: a lone string is one item (or, with ``split``, a comma list), anything else none."""
    if isinstance(value, str):
        value = [v.strip() for v in value.split(',')] if split else [value]
    if not isinstance(value, list):
        return []
    return [v[:limit] for v in value if isinstance(v, str) and v][:MAX_LIST_ITEMS]


def parse_nuclei_jsonl(text):
    """Findings from nuclei's JSONL output. A line that is not an object is skipped and a field of the wrong type is read as empty, so one
    odd line never fails the task; every field is clipped and at most ``MAX_FINDINGS`` are kept."""
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
        size += len(json.dumps(finding))
        if size > MAX_FINDINGS_BYTES:
            logger.warning('nuclei findings passed %s bytes; the rest were dropped so the result fits the server\'s limit', MAX_FINDINGS_BYTES)
            break
        findings.append(finding)
    return findings


def parse_testssl_report(raw):
    """The finding objects of a testssl.sh JSON report, flat (``--jsonfile``) or grouped (``--jsonfile-pretty``); mirrors
    ``cveFeed.testssl_scan.flatten``."""
    if isinstance(raw, dict):
        results = raw.get('scanResult') or []
        raw = [item for group in results if isinstance(group, dict) for value in group.values()
               if isinstance(value, list) for item in value]
    return [i for i in raw if isinstance(i, dict) and i.get('id')] if isinstance(raw, list) else []
