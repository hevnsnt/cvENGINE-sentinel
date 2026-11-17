"""What a host gives away about the Java runtime it runs, read from the outside: the pure half of the ``java_runtime`` kind, shared with cvENGINE.

A runtime CVE (one in the JDK or JRE itself) matches nothing while the runtime's version is unknown, and from outside it almost always is. These
readers turn what a service already says about itself into one normalised *reading*: the version (``17.0.9``, ``8u392``, ``21.0.2``), the major
line, the vendor, and where it came from. Nothing here asks the network; ``probes.java_runtime`` makes the requests and the JDWP exchange, and the
version probes (``probes.version_probes``) read the headers and pages they already fetched.

Every reader takes text or bytes a scanned host sent: it is untrusted. Each reads a fixed set of fields and nothing else (an actuator ``env`` or a
Druid properties page carries secrets: only the ``java.*`` version and vendor keys are ever looked at, and nothing else is returned), clips every
string, and returns ``None`` when the answer is not the shape it expects (a catch-all page, a login page, an error). A reading is never a guess:
a version is reported only when the answer states it.

``normalize_version`` is the one spelling cvENGINE stores and compares: ``1.8.0_392`` and ``8u392`` are ``8u392``; ``17.0.9+9``, ``17.0.9+9-LTS``
and ``17.0.9+9-Ubuntu-0ubuntu122.04`` are ``17.0.9`` (the build stays in ``build``); a bare ``17`` is the line only. ``dotted`` turns any of them
(and an advisory's bound, ``8u391`` or ``1.8.0_391``) into a dotted version a range can be tested with: ``8u392`` is ``8.0.392``.
"""
import json
import re
import struct

TEXT_LEN = 200       # a vendor, a runtime name or a description is clipped to this
EVIDENCE_LEN = 300   # the excerpt a reading carries: what the host said, clipped (untrusted text, shown escaped)
MAX_JSON_BYTES = 256 * 1024  # a status page bigger than this is not parsed

# ----------------------------------------------------------------------------- versions

_LEGACY = re.compile(r'^1\.(\d)\.0(?:_(\d{1,4}))?(?:[-+]b?(\d{1,3}))?')    # 1.8.0_392, 1.8.0_392-b08, 1.7.0_80, 1.8.0
_UPDATE = re.compile(r'^(\d{1,2})u(\d{1,4})(?:-b(\d{1,3}))?')                # 8u392, 8u392-b08
_MODERN = re.compile(r'^(\d{1,3})((?:\.\d{1,5}){0,3})(?:\+(\d{1,4}))?')     # 17, 17.0.9, 17.0.9+9, 11.0.20.1+1, 21+35
_HOTSPOT8 = re.compile(r'^(2[45])\.(\d{1,4})-b(\d{1,3})')                     # the HotSpot VM version of Java 8 (25.392-b08) and 7 (24.80-b11)


def normalize_version(text):
    """``{'version', 'major', 'build', 'line_only'}`` for a Java version string, or None when it is not one.

    ``version`` is the one spelling cvENGINE stores: ``8u392`` for Java 8 and older (``1.8.0_392``, ``8u392-b08``), the dotted feature release for
    9 and later (``17.0.9``, ``11.0.20.1``, the ``+build`` and any vendor suffix left out). ``build`` keeps what followed (``9-LTS``,
    ``9-Ubuntu-0ubuntu122.04``). ``line_only`` is true when only the major line is known (``17``, ``1.8``, ``21+35``): such a reading names the
    line, never a release inside it, and must not be compared with an advisory's bounds as if it were ``17.0.0``."""
    if not isinstance(text, str):
        return None
    raw = text.strip()[:TEXT_LEN]
    value = re.sub(r'^(?:java(?:\s+version)?|openjdk(?:\s+version)?|jdk|jre|v)[\s:=/-]*', '', raw, flags=re.I).strip().strip('"\'')
    found = _LEGACY.match(value)
    if found:
        major = int(found.group(1))
        update = found.group(2)
        build = _rest(value, found.end(), found.group(3))
        if update is None:
            return {'version': str(major), 'major': major, 'build': build, 'line_only': True}
        return {'version': f'{major}u{int(update)}', 'major': major, 'build': build, 'line_only': False}
    if re.match(r'^1\.(\d)$', value):  # "1.8": the line, as a GlassFish banner prints it
        major = int(value[2])
        return {'version': str(major), 'major': major, 'build': '', 'line_only': True}
    found = _UPDATE.match(value)
    if found:
        major = int(found.group(1))
        return {'version': f'{major}u{int(found.group(2))}', 'major': major, 'build': _rest(value, found.end(), found.group(3)), 'line_only': False}
    found = _MODERN.match(value)
    if not found:
        return None
    major = int(found.group(1))
    if not 1 <= major <= 99 or major in (2, 3, 4, 5, 6, 7) and not found.group(2):
        return None  # "2" or "5" alone is not a Java line anyone runs, and 100+ is not a version
    if major < 9 and found.group(2):
        return None  # "8.0.1" is not how Java 8 spells itself: some other product's version
    parts = [int(p) for p in found.group(2).split('.')[1:]] if found.group(2) else []
    while len(parts) > 1 and parts[-1] == 0 and len(parts) > 2:
        parts.pop()  # 17.0.9.0 is 17.0.9
    build = _rest(value, found.end(), found.group(3))
    if not parts:
        return {'version': str(major), 'major': major, 'build': build, 'line_only': True}
    if len(parts) == 1:
        parts.append(0)  # "17.0" is 17.0.0: the GA release has no update number (JEP 322 drops the trailing zeros)
    return {'version': '.'.join(str(p) for p in [major, *parts]), 'major': major, 'build': build, 'line_only': False}


def _rest(value, end, build):
    tail = value[end:].lstrip('+-_ ')
    out = (f'{build}-{tail}' if tail else build) if build else tail
    return re.sub(r'\s+', ' ', out)[:60].strip('-')


def dotted(text):
    """A Java version, or an advisory's bound for one, as a plain dotted version a range can be tested with: ``8u392`` and ``1.8.0_392`` are
    ``8.0.392``, ``17.0.9+9`` is ``17.0.9``, ``Oracle Java SE:8u391`` is ``8.0.391``; anything else is returned unchanged (``0``, ``*``). A line
    alone (``17``) stays ``17``: the caller decides what a line means."""
    if not isinstance(text, str):
        return text
    value = text.strip()
    if ':' in value and not value[:1].isdigit():
        value = value.rsplit(':', 1)[1].strip()  # "Oracle Java SE:8u391", "update_391" is handled below
    update = re.match(r'^update[_ ]?(\d+)$', value, re.I)
    if update:
        return text
    norm = normalize_version(value)
    if norm is None:
        return text
    version = norm['version']
    if 'u' in version:
        major, update = version.split('u', 1)
        return f'{major}.0.{update}'
    return version


def major_of(text):
    norm = normalize_version(text) if isinstance(text, str) else None
    return norm['major'] if norm else 0


# ----------------------------------------------------------------------------- vendors

UNKNOWN = 'unknown'
VENDORS = ('Oracle', 'Eclipse Temurin', 'Azul', 'Amazon Corretto', 'Red Hat', 'Microsoft', 'IBM Semeru', 'BellSoft Liberica', 'SAP Machine',
           'Debian', 'Ubuntu', 'OpenJDK', UNKNOWN)
# (pattern over what the host said, vendor): the first that matches wins, so a distribution build ("Red Hat, Inc.", "Ubuntu") is never read as the
# Oracle trademark its java.vm.name carries
_VENDOR_RULES = (
    (r'temurin|adoptium|adoptopenjdk', 'Eclipse Temurin'),
    (r'\bazul|zulu|\bzing\b', 'Azul'),
    (r'corretto|amazon(?:\.com)?', 'Amazon Corretto'),
    (r'red\s*hat', 'Red Hat'),
    (r'microsoft', 'Microsoft'),
    (r'semeru|\bibm\b|international business machines|openj9', 'IBM Semeru'),
    (r'bellsoft|liberica', 'BellSoft Liberica'),
    (r'\bsap\b|sapmachine', 'SAP Machine'),
    (r'\bubuntu\b|private build', 'Ubuntu'),
    (r'\bdebian\b', 'Debian'),
    (r'oracle|sun microsystems|java\s*hotspot|\(tm\)', 'Oracle'),
    (r'openjdk|jdk\.java\.net', 'OpenJDK'),
)
_VENDOR_RES = tuple((re.compile(p, re.I), v) for p, v in _VENDOR_RULES)
DISTRO_VENDORS = {'Red Hat': 'rhel', 'Debian': 'debian', 'Ubuntu': 'ubuntu'}  # builds a distribution patches by backporting


def normalize_vendor(*texts):
    """The vendor named by the first of ``texts`` that names one (java.vendor, java.vendor.version, java.vm.vendor, a runtime name, a build
    suffix), else ``unknown``. A build suffix decides a distribution build: ``17.0.9+9-Ubuntu-0ubuntu122.04`` is Ubuntu's whatever java.vendor says."""
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            continue
        for pattern, vendor in _VENDOR_RES:
            if pattern.search(text[:TEXT_LEN]):
                return vendor
    return UNKNOWN


# ----------------------------------------------------------------------------- one reading

SOURCES = ('jdwp', 'actuator', 'jolokia', 'status_page', 'header', 'error_page', 'bundled_inference', 'jenkins_minimum', 'tls_fingerprint')
CONFIDENCES = ('exact', 'inferred', 'weak')


def clip(text, limit=EVIDENCE_LEN):
    """Untrusted text from a host, as a reading carries it: printable characters only, whitespace collapsed, clipped."""
    text = ''.join(ch if ch.isprintable() else ' ' for ch in str(text or ''))
    return re.sub(r'\s+', ' ', text).strip()[:limit]


def reading(version, source, vendor_texts=(), confidence='exact', runtime='', url='', port=0, evidence=''):
    """One reading, or None when ``version`` is not a Java version: ``{version, major, vendor, runtime, build, line_only, source, confidence,
    url, port, evidence}``. ``vendor_texts`` are what the host said about the vendor, best first (the build suffix is asked last)."""
    norm = normalize_version(version)
    if norm is None:
        return None
    vendor = normalize_vendor(norm['build'] if re.search(r'ubuntu|debian|red\s*hat|\.el\d', norm['build'], re.I) else '', *vendor_texts,
                              norm['build'], runtime)
    return {'version': norm['version'], 'major': norm['major'], 'vendor': vendor, 'runtime': clip(runtime, TEXT_LEN), 'build': norm['build'],
            'line_only': norm['line_only'], 'source': source, 'confidence': confidence if confidence in CONFIDENCES else 'weak',
            'url': clip(url, 300), 'port': int(port or 0), 'evidence': clip(evidence)}


# ----------------------------------------------------------------------------- JDWP

# The Java Debug Wire Protocol handshake (14 ASCII bytes, echoed by the debuggee) and the ONE command ever sent after it: VirtualMachine.Version
# (command set 1, command 1), a packet of 11 header bytes and no data. This is exactly what nmap's jdwp-version script sends. No other JDWP
# command is ever built here: the protocol has no authentication, and any other command can run code in the target VM.
HANDSHAKE = b'JDWP-Handshake'
VERSION_COMMAND_SET, VERSION_COMMAND = 1, 1
REPLY_FLAG = 0x80
MAX_REPLY_BYTES = 4096


def version_command(packet_id=1):
    """The VirtualMachine.Version command packet: length 11, ``packet_id``, flags 0, command set 1, command 1."""
    return struct.pack('>IIBBB', 11, packet_id & 0xFFFFFFFF, 0, VERSION_COMMAND_SET, VERSION_COMMAND)


def _jdwp_string(data, offset):
    if offset + 4 > len(data):
        raise ValueError('truncated')
    size = struct.unpack('>I', data[offset:offset + 4])[0]
    if size > MAX_REPLY_BYTES or offset + 4 + size > len(data):
        raise ValueError('bad string length')
    return data[offset + 4:offset + 4 + size].decode('utf-8', 'replace'), offset + 4 + size


def parse_version_reply(data, packet_id=1):
    """The fields of a VirtualMachine.Version reply packet (``data``: the bytes after the 14-byte handshake echo), or None when it is not one:
    ``{'description', 'jdwp_major', 'jdwp_minor', 'vm_version', 'vm_name'}``. The reply is a header (length, the same packet id, flags 0x80, an
    error code of 0) and then a string, two ints and two strings."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 11:
        return None
    data = bytes(data[:MAX_REPLY_BYTES])
    try:
        length, ident, flags, error = struct.unpack('>IIBH', data[:11])
        if flags != REPLY_FLAG or ident != packet_id or error != 0 or length < 11 or length > len(data):
            return None
        body = data[11:length]
        description, at = _jdwp_string(body, 0)
        if at + 8 > len(body):
            return None
        jdwp_major, jdwp_minor = struct.unpack('>ii', body[at:at + 8])
        vm_version, at = _jdwp_string(body, at + 8)
        vm_name, at = _jdwp_string(body, at)
    except (ValueError, struct.error):
        return None
    return {'description': clip(description, EVIDENCE_LEN), 'jdwp_major': jdwp_major, 'jdwp_minor': jdwp_minor,
            'vm_version': clip(vm_version, 60), 'vm_name': clip(vm_name, TEXT_LEN)}


def is_handshake(data):
    """Whether ``data`` starts with the debuggee's echo of the handshake: the port speaks JDWP (and so lets anyone who reaches it run code)."""
    return isinstance(data, (bytes, bytearray)) and bytes(data[:len(HANDSHAKE)]) == HANDSHAKE


def from_jdwp(reply, port=0):
    """A reading from a parsed VirtualMachine.Version reply (``parse_version_reply``), or None."""
    if not reply:
        return None
    version = reply.get('vm_version') or ''
    jvm = re.search(r'JVM version (\S+)\s*\(([^)]{0,120})', reply.get('description') or '')
    if not normalize_version(version) and jvm:
        version = jvm.group(1)
    return reading(version, 'jdwp', (reply.get('description'), reply.get('vm_name'), jvm.group(2) if jvm else ''), runtime=reply.get('vm_name') or '',
                   port=port, evidence=f"{reply.get('description') or ''} | {reply.get('vm_name') or ''}")


# nmap's jdwp-version (a version-category script that -sV runs on a port that closed on its NULL probe, at intensity 7 or more) stores what it read
# as the port's product and version: "Java Debug Wire Protocol (Reference Implementation) version 17.0" and "17.0.9". A port nmap names "jdwp".
NMAP_JDWP_PRODUCT = re.compile(r'^Java Debug Wire Protocol\b', re.I)


def from_nmap_port(service, product, version, port=0):
    """A reading from a port nmap's jdwp-version identified (service ``jdwp``, the product and the VM version it stored), or None. A port nmap
    named jdwp with no version still speaks JDWP: the caller files the exposure either way."""
    if (service or '').lower() != 'jdwp' and not NMAP_JDWP_PRODUCT.match(product or ''):
        return None
    return reading(version or '', 'jdwp', (product,), runtime=product or '', port=port, evidence=f'nmap: {product or ""} {version or ""}')


# ----------------------------------------------------------------------------- JSON answers

def load_json(text):
    """``text`` parsed as JSON when it is a JSON object (bounded), else None."""
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode('utf-8', 'replace')
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_JSON_BYTES or text.lstrip()[:1] != '{':
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _value(item):
    """A property's value as Spring Boot writes it: ``{"value": "17.0.9"}`` (2.x and later) or the string itself (1.x). A masked value is none."""
    if isinstance(item, dict):
        item = item.get('value')
    if not isinstance(item, (str, int, float)) or isinstance(item, bool):
        return ''
    text = str(item)
    return '' if set(text) <= set('*') else text[:TEXT_LEN]


JAVA_KEYS = ('java.version', 'java.runtime.version', 'java.vendor', 'java.vendor.version', 'java.vm.vendor', 'java.vm.name', 'java.runtime.name')


def _from_properties(props, source, url, label):
    """A reading from a flat mapping of system properties (only ``JAVA_KEYS`` are read; the rest of the mapping, which may hold secrets, is never
    looked at or returned)."""
    got = {k: _value(props.get(k)) for k in JAVA_KEYS if k in props}
    version = got.get('java.runtime.version') or got.get('java.version') or ''
    if normalize_version(got.get('java.version') or '') and not normalize_version(version):
        version = got['java.version']
    if not version:
        return None
    shown = ', '.join(f'{k}={v}' for k, v in got.items() if v)
    return reading(version, source, (got.get('java.vendor.version'), got.get('java.vendor'), got.get('java.vm.vendor'), got.get('java.vm.name')),
                   runtime=got.get('java.runtime.name') or got.get('java.vm.name') or '', url=url, evidence=f'{label}: {shown}')


def from_actuator_env(text, url='/actuator/env'):
    """A reading from a Spring Boot ``env`` endpoint: the whole ``/actuator/env`` (2.x and later: ``propertySources[].properties``), one property
    (``/actuator/env/java.version``: ``property.value``) or Boot 1's ``/env`` (``systemProperties``). None for anything else."""
    doc = load_json(text)
    if doc is None:
        return None
    if isinstance(doc.get('property'), dict) and url.rstrip('/').endswith('java.version'):
        version = _value(doc['property'])
        found = reading(version, 'actuator', (), url=url, evidence=f'java.version={version}') if version else None
        if found:
            return found
    props = {}
    for source in doc.get('propertySources') or []:
        if isinstance(source, dict) and isinstance(source.get('properties'), dict):
            for key in JAVA_KEYS:
                if key in source['properties'] and key not in props:
                    props[key] = source['properties'][key]
    if not props and any(key in doc for key in ('java.version', 'java.runtime.version')):
        props = {k: v for k, v in doc.items() if k in JAVA_KEYS}  # Boot 1's one property (/env/java.version): {"java.version": "1.8.0_151"}
    if not props:
        for key in ('systemProperties', 'systemEnvironment'):
            if isinstance(doc.get(key), dict):
                props = {k: v for k, v in doc[key].items() if k in JAVA_KEYS}
                if props:
                    break
    return _from_properties(props, 'actuator', url, 'actuator env') if props else None


def from_actuator_info(text, url='/actuator/info'):
    """A reading from ``/actuator/info``'s ``java`` section (Spring Boot 3's JavaInfoContributor: ``version``, ``vendor``, ``runtime``, ``jvm``).
    Nothing else of the document is read."""
    doc = load_json(text)
    java = doc.get('java') if doc else None
    if not isinstance(java, dict):
        return None
    vendor = java.get('vendor') if isinstance(java.get('vendor'), dict) else {'name': java.get('vendor')}
    runtime = java.get('runtime') if isinstance(java.get('runtime'), dict) else {}
    jvm = java.get('jvm') if isinstance(java.get('jvm'), dict) else {}
    version = _value(runtime.get('version')) or _value(java.get('version')) or _value(jvm.get('version'))
    if not normalize_version(version):
        version = _value(java.get('version'))
    names = (_value(vendor.get('version')), _value(vendor.get('name')), _value(jvm.get('vendor')), _value(jvm.get('name')))
    return reading(version, 'actuator', names, runtime=_value(runtime.get('name')), url=url,
                   evidence=f"actuator info: java.version={_value(java.get('version'))}, vendor={_value(vendor.get('name'))}, "
                            f"runtime={_value(runtime.get('version'))}") if version else None


def from_actuator_metric(text, url='/actuator/metrics/jvm.info'):
    """A reading from Micrometer's ``jvm.info`` gauge (``availableTags``: ``version``, ``vendor``, ``runtime``)."""
    doc = load_json(text)
    if not doc or doc.get('name') != 'jvm.info':
        return None
    tags = {}
    for tag in doc.get('availableTags') or []:
        if isinstance(tag, dict) and isinstance(tag.get('values'), list) and tag['values']:
            tags[str(tag.get('tag'))] = _value(tag['values'][0])
    version = tags.get('version', '')
    return reading(version, 'actuator', (tags.get('vendor'),), runtime=tags.get('runtime', ''), url=url,
                   evidence=f"jvm.info: version={version}, vendor={tags.get('vendor', '')}, runtime={tags.get('runtime', '')}") if version else None


def is_jolokia(text):
    """Whether ``text`` is Jolokia's own answer to ``/version`` (an agent version in ``value``): only then are its read requests sent."""
    doc = load_json(text)
    value = doc.get('value') if doc else None
    return isinstance(value, dict) and isinstance(value.get('agent'), str) and bool(value['agent'])


def _jolokia_value(text):
    doc = load_json(text)
    if not doc or doc.get('status') not in (200, None) or 'error' in doc:
        return ''
    return _value(doc.get('value'))


def from_jolokia(version_text, vendor_text='', url='/jolokia/read/java.lang:type=Runtime/VmVersion'):
    """A reading from Jolokia's reads of the Runtime MXBean: ``VmVersion`` (and ``VmVendor``). The VM version of a Java 8 HotSpot is its own
    numbering (``25.392-b08`` is 8u392, ``24.80-b11`` 7u80) and is read as such; anything else is read as a Java version."""
    vm_version = _jolokia_value(version_text)
    vendor = _jolokia_value(vendor_text) if vendor_text else ''
    if not vm_version:
        return None
    hotspot = _HOTSPOT8.match(vm_version)
    version = f"{8 if hotspot.group(1) == '25' else 7}u{int(hotspot.group(2))}" if hotspot else vm_version
    return reading(version, 'jolokia', (vendor,), url=url, evidence=f'Runtime.VmVersion={vm_version}, VmVendor={vendor}')


def from_solr(text, url='/solr/admin/info/system?wt=json'):
    """A reading from Solr's ``/admin/info/system``: ``jvm.jre`` (version, vendor), else ``jvm.version`` and ``jvm.vm``."""
    doc = load_json(text)
    jvm = doc.get('jvm') if doc else None
    if not isinstance(jvm, dict):
        return None
    jre = jvm.get('jre') if isinstance(jvm.get('jre'), dict) else {}
    vm = jvm.get('vm') if isinstance(jvm.get('vm'), dict) else {}
    version = _value(vm.get('version')) or _value(jre.get('version')) or (_value(jvm.get('version')).split(' ')[-1])
    if not normalize_version(version):
        version = _value(jre.get('version')) or _value(jvm.get('version')).split(' ')[0]
    return reading(version, 'status_page', (_value(jre.get('vendor')), _value(vm.get('vendor')), _value(jvm.get('name'))),
                   runtime=_value(vm.get('name')) or _value(jvm.get('name')), url=url,
                   evidence=f"solr jvm: version={_value(jvm.get('version'))}, name={_value(jvm.get('name'))}") if version else None


def from_geoserver(text, url='/geoserver/rest/about/status.json'):
    """A reading from GeoServer's REST status: the module ``jvm`` (its ``version`` is java.version) and ``system-properties`` (its ``component``
    is java.runtime.name and its ``version`` java.runtime.version). The modules' messages are never read."""
    doc = load_json(text)
    if not doc:
        return None
    statuses = doc.get('statuss') if isinstance(doc.get('statuss'), dict) else doc
    rows = statuses.get('status') if isinstance(statuses, dict) else None
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return None
    jvm = next((r for r in rows if isinstance(r, dict) and r.get('module') == 'jvm'), {})
    props = next((r for r in rows if isinstance(r, dict) and r.get('module') == 'system-properties'), {})
    version = _value(props.get('version')) or _value(jvm.get('version'))
    if not normalize_version(version):
        version = _value(jvm.get('version'))
    return reading(version, 'status_page', (_value(props.get('component')),), runtime=_value(props.get('component')), url=url,
                   evidence=f"geoserver status: jvm={_value(jvm.get('version'))}, runtime={_value(props.get('component'))} "
                            f"{_value(props.get('version'))}") if version else None


def from_druid(text, url='/status/properties'):
    """A reading from Apache Druid's ``/status/properties`` (a flat map of system properties: only ``JAVA_KEYS`` are read)."""
    doc = load_json(text)
    return _from_properties(doc, 'status_page', url, 'druid properties') if doc and ('java.version' in doc or 'java.runtime.version' in doc) else None


def from_elasticsearch(text, url='/_nodes/jvm'):
    """The readings of Elasticsearch's or OpenSearch's ``/_nodes/jvm``: one per distinct node JVM (``nodes.*.jvm``: version, vm_vendor, vm_name,
    vm_version), at most 10. ``using_bundled_jdk`` is kept in the evidence."""
    doc = load_json(text)
    nodes = doc.get('nodes') if doc else None
    if not isinstance(nodes, dict):
        return []
    out, seen = [], set()
    for node in list(nodes.values())[:50]:
        jvm = node.get('jvm') if isinstance(node, dict) else None
        if not isinstance(jvm, dict):
            continue
        version = _value(jvm.get('vm_version')) or _value(jvm.get('version'))
        if not normalize_version(version):
            version = _value(jvm.get('version'))
        bundled = jvm.get('using_bundled_jdk')
        found = reading(version, 'status_page', (_value(jvm.get('vm_vendor')), _value(jvm.get('vm_name'))), runtime=_value(jvm.get('vm_name')),
                        url=url, evidence=f"_nodes jvm: version={_value(jvm.get('version'))}, vm_vendor={_value(jvm.get('vm_vendor'))}, "
                                          f"vm_version={_value(jvm.get('vm_version'))}"
                                          + (f", using_bundled_jdk={bool(bundled)}" if isinstance(bundled, bool) else ''))
        if found and (found['version'], found['vendor']) not in seen:
            seen.add((found['version'], found['vendor']))
            out.append(found)
    return out[:10]


# ----------------------------------------------------------------------------- headers and pages

# X-Powered-By of GlassFish, Payara and some JBoss builds: "Servlet/4.0 JSP/2.3 (Payara Server 5.2022.5 #badassfish Java/Azul Systems, Inc./17)",
# "Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition 4.1 Java/Oracle Corporation/1.8)". The vendor sits between "Java/" and the last "/".
_POWERED_JAVA = re.compile(r'\bJava/(?:([^/()]{1,80})/)?(\d[\w.+\-]{0,40})', re.I)
# a Server or X-Powered-By header that names the runtime by itself: "Java/1.8.0_181", "JDK/17.0.2", "OpenJDK/21.0.1"
_HEADER_RUNTIME = re.compile(r'(?:^|[\s(;,])(?:Java|JDK|JRE|OpenJDK)[/ ](\d[\w.+\-]{0,40})', re.I)


def from_headers(headers, url='/'):
    """The readings ``X-Powered-By`` and ``Server`` give (``headers`` a mapping, any case), each at most once."""
    lowered = {str(k).lower(): str(v)[:500] for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}
    out = []
    for name in ('x-powered-by', 'server'):
        value = lowered.get(name, '')
        if not value:
            continue
        found = _POWERED_JAVA.search(value)
        if found:
            got = reading(found.group(2), 'header', (found.group(1) or '',), url=url, evidence=f'{name}: {value}')
        else:
            plain = _HEADER_RUNTIME.search(value)
            got = reading(plain.group(1), 'header', (value,), url=url, evidence=f'{name}: {value}') if plain else None
        if got and got['version'] not in {o['version'] for o in out}:
            out.append(got)
    return out


# Banners a JVM prints that a page (a stack trace, a status page, a debug page) may carry: java -version's lines, a HotSpot crash or version
# line, and a java.version property printed as text or JSON. Each pattern is bounded and anchored on a fixed phrase, so a long page costs linear time.
_BANNERS = (
    (re.compile(r'OpenJDK Runtime Environment ([^()\n]{0,60})\(build ([\w.+\-]{1,60})\)'), 2, 1),
    (re.compile(r'Java\(TM\) SE Runtime Environment ([^()\n]{0,60})\(build ([\w.+\-]{1,60})\)'), 2, 1),
    (re.compile(r'(?:Java HotSpot\(TM\)|OpenJDK|Eclipse OpenJ9) (?:64-Bit |Client |Server )*(?:Server )?VM ([^()\n]{0,60})\((?:build )?([\w.+\-]{1,60})'), 2, 1),
    (re.compile(r'["\']?java\.(?:runtime\.)?version["\']?\s{0,4}[=:]\s{0,4}["\']?(\d[\w.+\-]{0,40})'), 1, None),
)
BODY_SCAN = 64 * 1024


def from_body(text, source='error_page', url=''):
    """The readings a page's body states (``_BANNERS``), at most three distinct versions. A build id ``17.0.9+9-LTS-211`` is read as 17.0.9."""
    body = (text or '')[:BODY_SCAN] if isinstance(text, str) else ''
    out = []
    for pattern, vgroup, vendor_group in _BANNERS:
        for found in pattern.finditer(body):
            line = body[max(0, found.start() - 40):found.end() + 40]
            got = reading(found.group(vgroup), source, (found.group(vendor_group) if vendor_group else '', line), runtime='', url=url,
                          evidence=line)
            if got and got['version'] not in {o['version'] for o in out}:
                out.append(got)
            if len(out) >= 3:
                return out
    return out
