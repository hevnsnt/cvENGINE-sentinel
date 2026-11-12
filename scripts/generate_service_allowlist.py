#!/usr/bin/env python3
"""Make the nuclei service-port allowlist from a nuclei-templates release.

  python3 scripts/generate_service_allowlist.py --templates DIR [--release v10.5.2] [--write | --check] [--summary]

A nuclei run on a service port (every port that is not web) runs only the templates on this list (``cvengine_scanner/nuclei_allowlist.py``): default deny.
This script decides what is on it. Start: every template of the library that has a tcp, javascript or ssl block (the types a service run selects). A template
is KEPT only when all of these hold, and is otherwise left out with each reason that applies (``nuclei_service_left_out.json``):

  1. it carries none of the tags a service run excludes (``flags.NUCLEI_SERVICE_EXCLUDED_TAGS``: dos, default-login, bruteforce, fuzz, intrusive, ...);
  2. it has no block of another protocol (http, dns, file, headless, code, websocket, whois): a service port never receives those;
  3. it is not ``self-contained`` (a self-contained template runs once, against what the template names, not against the target), sends no UDP (a service
     port is a TCP port) and, for a javascript template, calls only the library functions on ``JS_CALLS`` (net and bytes helpers and the read-only info calls
     such as ConnectSSHInfoMode);
  4. it passes the content rule the Sentinel already had (``client.tools._paced_template``: no payloads, no login step, no own parallelism, at most 10 requests);
  5. it passes the independent decode (``cvengine_scanner.nuclei_allowlist.credential_findings``): no string, read as plain text, hex or base64, and no key, names a
     user, a password, a token, a cookie, a community string, an authorization header or an authentication message;
  6a. it does not send a hex control frame nobody read: a template whose hex inputs (``type: hex`` or ``hex_decode``) are binary (not empty, not all zero bytes, not plain\n     text) cannot be judged by the decode, so it needs an entry in ``frames_read`` (or ``read_only``, or ``restored``) of the review file with the sha256 of the file a person\n     read, else it is left out as \"not read\". A template read and found to change state is listed under ``refused`` with the reason (rtl-tcp-server-detect: set frequency).\n  6. it does not change state on the target and does nothing a person refused. Every template of the exploit class (tag cve, rce, kev, exploit...; or severity
     medium or higher) has to appear in ``cvengine_scanner/data/nuclei_service_review.json`` under ``read_only`` with the sha256 of the file a person read; one
     under ``refused`` (any severity) is left out with the recorded reason; an exploit-class template in neither is left out as "not reviewed". A new release
     therefore never adds an exploit-class template by itself.

A template that names a port of its own (a literal port in its ``host`` or ``address``, or a javascript argument such as ``CpmiPort``) is listed with
``fixed_ports``: the run sends it only to a target on one of those ports, so it never reaches a port the task did not name. A ``Port`` argument or a tcp
``port:`` field follows the target's port (measured on nuclei 3.11.1: scratch/nuc4/lab).

Two templates the content rule refuses by name were read and are restored (``restored`` in the review file, with the sha256 read): they do not authenticate
(see the review file for why). A restored template is marked in the list (``reviewed_exceptions``) so the run does not apply the content rule to it.

--write writes ``nuclei_service_allowlist.json`` and ``nuclei_service_left_out.json``; --check regenerates and exits 1 when either differs from the shipped files.
The agreement of rules 4 and 5 is printed with --summary. Needs PyYAML (a development tool: the Sentinel itself never imports it).
"""
import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from client import tools  # noqa: E402
from cvengine_scanner import flags, nuclei_allowlist as al  # noqa: E402

_JS_COMMENT = al._JS_COMMENT
NETWORK_KEYS = {'tcp': 'tcp', 'network': 'tcp', 'javascript': 'javascript', 'ssl': 'ssl'}
OTHER_KEYS = ('http', 'requests', 'dns', 'file', 'headless', 'code', 'websocket', 'whois', 'workflows', 'flow_http')
EXPLOIT_TAGS = {'cve', 'rce', 'kev', 'vkev', 'exploit', 'oast', 'sqli', 'lfi', 'ssrf', 'injection', 'deserialization', 'xxe', 'ssti', 'traversal', 'intrusive'}
EXPLOIT_SEVERITIES = {'medium', 'high', 'critical'}
# the javascript library calls a service template may make: byte and socket helpers, and the nuclei library calls that read what a server offers and send no
# credential (ConnectSSHInfoMode and ConnectSMBInfoMode do not authenticate, ListSMBv2Metadata is a negotiate, GetServerInfo is PING and INFO with no password...).
# A call that starts with a capital and is not here (Connect, ExecuteQuery, Authenticate, ListShares, Login, Bind...) leaves the template out.
JS_CALLS = frozenset(('Open', 'Close', 'Send', 'SendHex', 'Recv', 'RecvString', 'RecvFull', 'RecvFullString', 'RecvHex', 'RecvFullHex', 'SetTimeout', 'NewBuffer', 'Buffer',
                      'Write', 'WriteString', 'Hex', 'Pack', 'Export', 'OpenTLS', 'ConnectSSHInfoMode', 'ConnectSMBInfoMode', 'ListSMBv2Metadata', 'GetServerInfo', 'FingerprintMySQL',
                      'IsMssql', 'IsOracle', 'IsRDP', 'IsRsync', 'CollectMetadata', 'SSHClient', 'SMBClient', 'MySQLClient', 'MSSQLClient', 'Client', 'Config'))
JS_MODULES = frozenset(('net', 'bytes', 'ssh', 'smb', 'mysql', 'mssql', 'oracle', 'rdp', 'rsync', 'redis', 'ldap'))
_JS_CALL = re.compile(r'(?:\.|\bnew\s+)([A-Z][A-Za-z0-9]*)\s*\(')
JS_BUILTINS = frozenset(('Array', 'Uint8Array', 'Uint16Array', 'Uint32Array', 'ArrayBuffer', 'DataView', 'Date', 'Error', 'RegExp', 'Set', 'Map', 'Object', 'String', 'Number',
                         'Math', 'JSON', 'Buffer', 'Promise', 'TextDecoder', 'TextEncoder'))
_JS_REQUIRE = re.compile(r'require\(\s*[\'"]nuclei/(\w+)')
_UDP = re.compile(r'(?i)isUDPPortOpen|[\'"`]udp[\'"`]')
_HEX_DECODE = re.compile(r'''hex_decode\(\s*['"]([0-9a-fA-F]*)['"]\s*\)''')
_LITERAL_PORT = re.compile(r':(\d{1,5})\s*$')
SKIP_DIRS = {'.git', '.github'}


def release_from_dockerfile(root=ROOT):
    text = (Path(root) / 'Dockerfile').read_text(encoding='utf-8')
    found = re.search(r'(?m)^ARG NUCLEI_TEMPLATES_VERSION=(\S+)$', text)
    return found.group(1) if found else ''


def templates_in(directory):
    """``[(relative path, bytes)]`` of every .yaml file of the library, sorted."""
    base = Path(directory)
    out = []
    for folder, dirs, names in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name.endswith(('.yaml', '.yml')):
                path = Path(folder) / name
                out.append((path.relative_to(base).as_posix(), path.read_bytes()))
    return sorted(out)


def classes_of(tags, types):
    """The service classes a template with these tags and types can run on, as ``flags.nuclei_service_selection`` selects with no task tag."""
    owned = {tag for own, _ in flags.NUCLEI_SERVICES.values() for tag in own}
    out = []
    for klass, (own, class_types) in flags.NUCLEI_SERVICES.items():
        if set(types) & set(class_types) and (not own or set(tags) & set(own)):
            out.append(klass)
    if set(types) & set(flags.NUCLEI_NETWORK_TYPES) and not set(tags) & owned:
        out.append(flags.NUCLEI_UNKNOWN)
    return out


def fixed_ports(doc):
    """The ports a template names for itself: a literal port in a tcp ``host`` or an ssl ``address``, a javascript argument named like a port (other than ``Port``,
    which nuclei sets to the target's) with a literal number."""
    ports = set()
    for block in doc.get('tcp') or doc.get('network') or []:
        for entry in (block.get('host') or block.get('address') or []) if isinstance(block, dict) else []:
            found = _LITERAL_PORT.search(str(entry))
            if found:
                ports.add(int(found.group(1)))
    for block in doc.get('ssl') or []:
        found = _LITERAL_PORT.search(str(block.get('address') or '')) if isinstance(block, dict) else None
        if found:
            ports.add(int(found.group(1)))
    for block in doc.get('javascript') or []:
        for key, value in ((block.get('args') or {}) if isinstance(block, dict) else {}).items():
            if re.search(r'(?i)port', str(key)) and str(key) != 'Port' and re.fullmatch(r'\d{1,5}', str(value).strip()):
                ports.add(int(str(value).strip()))
    return sorted(ports)


def _text_doc(text):
    """The template read with no number or boolean resolvers (an unquoted ``00000000`` or ``01000000`` hex string is a string here, not the integer 0 or 1)."""
    try:
        doc = yaml.load(text, Loader=al._text_loader())  # noqa: S506 - a safe loader with the number resolvers removed
    except yaml.YAMLError:
        return {}
    return doc if isinstance(doc, dict) else {}


def hex_frames(doc):
    """The bytes a tcp template sends as hex: every input of ``type: hex`` and every ``hex_decode('..')`` literal of an input's data. ``[bytes]``."""
    frames = []
    for block in doc.get('tcp') or doc.get('network') or []:
        for item in (block.get('inputs') or []) if isinstance(block, dict) else []:
            if not isinstance(item, dict):
                continue
            data = str(item.get('data') if item.get('data') is not None else '')
            literals = _HEX_DECODE.findall(data)
            candidates = literals if literals else ([re.sub(r'\s+', '', data)] if str(item.get('type')) == 'hex' else [])
            for text in candidates:
                try:
                    frames.append(bytes.fromhex(text))
                except ValueError:
                    frames.append(b'\xff')  # hex that does not decode cannot be read: treat it as a control frame
    return frames


def binary_frames(doc):
    """The hex frames a decode of the strings cannot judge: not empty, not all zero bytes (the FTP banner probe), not plain printable text (the decode reads that).
    A command frame of a binary protocol (set a frequency, write a register...) looks like random bytes to the word search, so a person has to read it."""
    return [f for f in hex_frames(doc) if any(f) and not all(32 <= b < 127 or b in (9, 10, 13) for b in f)]


def javascript_reasons(doc):
    reasons = []
    for block in doc.get('javascript') or []:
        code = _JS_COMMENT.sub(' ', str(block.get('code') or '')) if isinstance(block, dict) else ''
        modules = set(_JS_REQUIRE.findall(code))
        calls = set(_JS_CALL.findall(code)) - JS_BUILTINS
        if modules - JS_MODULES:
            reasons.append('uses the javascript library ' + ', '.join(sorted(modules - JS_MODULES)))
        if calls - JS_CALLS:
            reasons.append('calls ' + ', '.join(sorted(calls - JS_CALLS)) + ', which is not on the read-only list of library calls')
    return reasons


def exploit_class(tags, severity):
    return bool(set(tags) & EXPLOIT_TAGS) or severity in EXPLOIT_SEVERITIES


def load_review(path=al.REVIEW_FILE):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        data = {}
    return {'read_only': data.get('read_only') or {}, 'refused': data.get('refused') or {}, 'restored': data.get('restored') or {}, 'frames_read': data.get('frames_read') or {}}


def analyse(directory, review, release):
    """``(allowlist, left_out, facts)`` for the library in ``directory``."""
    kept, left, facts = {}, {}, []
    for rel, raw in templates_in(directory):
        text = raw.decode('utf-8', 'replace')
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            doc = None
        if not isinstance(doc, dict) or not doc.get('id') or not isinstance(doc.get('info'), dict):
            continue
        types = sorted({NETWORK_KEYS[k] for k in NETWORK_KEYS if doc.get(k)})
        if not types:
            continue
        tid = str(doc['id'])
        info = doc['info']
        tags = [t.strip() for t in (info['tags'] if isinstance(info.get('tags'), list) else str(info.get('tags') or '').split(',')) if str(t).strip()]
        severity = str(info.get('severity') or 'unknown').lower()
        digest = al.sha256_of(raw)
        reasons, hard = [], False
        excluded = sorted(set(tags) & set(flags.NUCLEI_SERVICE_EXCLUDED_TAGS))
        if excluded:
            reasons.append('carries the excluded tag ' + ', '.join(excluded))
            hard = True
        others = sorted(k for k in OTHER_KEYS if doc.get(k))
        if others:
            reasons.append('also has a block of another protocol (' + ', '.join(others) + '), which a service port never receives')
            hard = True
        udp = bool(_UDP.search(text))
        if udp:
            reasons.append('sends UDP: a service port is a TCP port, so the datagrams would go to a port nobody named')
            hard = True
        script = javascript_reasons(doc)
        if script:
            reasons += script
            hard = True
        if doc.get('self-contained'):
            reasons.append('self-contained: it runs once against what the template names, not against the target')
            hard = True
        with_rule = tools._paced_template(str(Path(directory) / rel))
        with_decode = al.credential_findings(text)
        restored = review['restored'].get(tid)
        restored_ok = isinstance(restored, dict) and restored.get('sha256') == digest
        soft = []
        if with_rule:
            soft.append('content rule: ' + with_rule)
        if with_decode:
            soft.append('decode: ' + '; '.join(with_decode[:4]) + (f' (+{len(with_decode) - 4} more)' if len(with_decode) > 4 else ''))
        if soft and not restored_ok:
            reasons += soft
        state = review['refused'].get(tid)
        if not reasons and binary_frames(_text_doc(text)) and not state and digest not in ((review.get('frames_read') or {}).get(tid), review['read_only'].get(tid)) and not restored_ok:
            reasons.append('sends hex control frames of a binary protocol, which the decode cannot judge, and a person has not read them for this file content (not read)')
        exploit = exploit_class(tags, severity)
        if state:
            reasons.append('read by a person and refused: ' + str(state))
        elif exploit and review['read_only'].get(tid) != digest:
            reasons.append('exploit class (tags %s, severity %s) and not reviewed as read-only for this file content' % (', '.join(sorted(set(tags) & EXPLOIT_TAGS)) or 'none', severity))
        facts.append({'id': tid, 'path': rel, 'rule': bool(with_rule), 'decode': bool(with_decode), 'hard': hard, 'exploit': exploit, 'severity': severity, 'tags': tags})
        classes = classes_of(tags, types)
        if reasons or not classes:
            left[tid] = {'path': rel, 'severity': severity, 'sha256': digest, 'reasons': reasons or ['no service class selects it']}
        else:
            entry = {'sha256': digest, 'path': rel, 'severity': severity, 'classes': classes}
            ports = fixed_ports(doc)
            if ports:
                entry['fixed_ports'] = ports
            if soft and restored_ok:
                entry['restored'] = True
            kept[tid] = entry
    allowlist = {'nuclei_templates': release, 'generated_by': 'scripts/generate_service_allowlist.py',
                 'reviewed_exceptions': sorted(t for t, e in kept.items() if e.get('restored')), 'templates': dict(sorted(kept.items()))}
    left_out = {'nuclei_templates': release, 'generated_by': 'scripts/generate_service_allowlist.py', 'templates': dict(sorted(left.items()))}
    return allowlist, left_out, facts


def dump(obj):
    return json.dumps(obj, indent=1, sort_keys=False, ensure_ascii=True) + '\n'


def summary(allowlist, left_out, facts):
    per = collections.Counter()
    sev = collections.Counter()
    for entry in allowlist['templates'].values():
        sev[entry['severity']] += 1
        for klass in entry['classes']:
            per[klass] += 1
    lines = [f"allowlisted {len(allowlist['templates'])} of {len(allowlist['templates']) + len(left_out['templates'])} tcp, javascript and ssl templates"]
    lines.append('per class (a template can run on several): ' + ', '.join(f'{k} {per[k]}' for k in [*flags.NUCLEI_SERVICES, flags.NUCLEI_UNKNOWN]))
    lines.append('by severity: ' + ', '.join(f'{k} {v}' for k, v in sorted(sev.items())))
    soft = [f for f in facts if not f['hard']]
    both = sum(1 for f in soft if f['rule'] and f['decode'])
    only_rule = sum(1 for f in soft if f['rule'] and not f['decode'])
    only_decode = sum(1 for f in soft if f['decode'] and not f['rule'])
    lines.append(f'content rule and decode, among templates with no hard reason: both flag {both}, only the rule {only_rule}, only the decode {only_decode}')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--templates', required=True, help='a directory holding the nuclei-templates release')
    parser.add_argument('--release', default='', help='the release name (default: the Dockerfile pin)')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--summary', action='store_true')
    parser.add_argument('--disagree', action='store_true', help='list the templates only one of the two checks flags')
    args = parser.parse_args(argv)
    release = args.release or release_from_dockerfile()
    allowlist, left_out, facts = analyse(args.templates, load_review(), release)
    if args.summary or not (args.write or args.check):
        print(summary(allowlist, left_out, facts))
    if args.disagree:
        for f in facts:
            if not f['hard'] and f['rule'] != f['decode']:
                print(('rule only  ' if f['rule'] else 'decode only'), f['id'], f['path'])
    if args.write:
        al.ALLOWLIST_FILE.write_text(dump(allowlist), encoding='utf-8')
        al.LEFT_OUT_FILE.write_text(dump(left_out), encoding='utf-8')
        print(f'wrote {al.ALLOWLIST_FILE} and {al.LEFT_OUT_FILE}')
    if args.check:
        same = al.ALLOWLIST_FILE.read_text(encoding='utf-8') == dump(allowlist) and al.LEFT_OUT_FILE.read_text(encoding='utf-8') == dump(left_out)
        print('the shipped allowlist and left-out list match this library' if same else 'the shipped allowlist or left-out list DIFFERS from this library: regenerate and review')
        return 0 if same else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
