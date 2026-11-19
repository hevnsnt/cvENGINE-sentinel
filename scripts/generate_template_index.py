#!/usr/bin/env python3
"""Make the nuclei template index (``cvengine_scanner/data/nuclei_template_index.json``) from a nuclei-templates release.

  python3 scripts/generate_template_index.py --templates DIR [--release v10.5.2] [--write | --check]

The index is what the cvENGINE server knows about the template library (it keeps no copy of it) and what a Sentinel builds its approved set from
(``cvengine_scanner/template_index.py`` says how both read it). For every template file of the release (a ``.yaml`` or ``.yml`` file with an ``id``, outside
the hidden directories), it records the file's sha256, its id, tags, metadata vendor and product, the CPE it names, and the verdicts of this library's rules:

  refuse  larger than 200,000 bytes or not UTF-8: never runs;
  ro      ``checks.readonly_problem(text, allow_credentials=True)``: not read-only or not bound to the target (the read-only policy refuses it);
  cred    ``checks.credential_problem``: it sends a credential of its own (refused unless a person allowed checks that send credentials);
  ctag    tagged ``default-login`` or ``bruteforce`` (``flags.NUCLEI_CREDENTIAL_TAGS``), the checks that send credentials, whatever their text says.

The verdicts are the server's rule for an installed template, rule for rule (``cveFeed.validation.installed_template_problem``): measured equal on all
14,265 files of v10.5.2. The files' hashes are cross-checked with the service-port allowlist, made from the same release: a template both record must have
one sha256, so the two never describe different releases.

--write writes the index; --check makes it again and exits 1 when it differs from the shipped file. Needs PyYAML (a development tool: a Sentinel run never
imports it).
"""
import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from cvengine_scanner import checks, flags, nuclei_allowlist, template_index  # noqa: E402

RULES = 1  # the version of what this script records: a change to a rule or a field bumps it
SUFFIXES = ('.yaml', '.yml')
_ID = nuclei_allowlist._ID
_WORD = re.compile(r'^[a-z0-9][a-z0-9_.+-]{0,60}$')
_CPE = re.compile(r'^cpe:2\.3:([aho]):([^:\s]+):([^:\s]+)')


def release_from_dockerfile(root=ROOT):
    text = (Path(root) / 'Dockerfile').read_text(encoding='utf-8')
    found = re.search(r'(?m)^ARG NUCLEI_TEMPLATES_VERSION=(\S+)$', text)
    return found.group(1) if found else ''


def files_in(directory):
    """``[(relative path, bytes)]`` of every .yaml or .yml file outside hidden directories, sorted by path."""
    base = Path(directory)
    out = []
    for current, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for name in sorted(files):
            if name.endswith(SUFFIXES) and not name.startswith('.'):
                full = Path(current) / name
                if full.is_symlink() or not full.is_file():
                    continue
                out.append((full.relative_to(base).as_posix(), full.read_bytes()))
    return sorted(out)


def _words(value):
    items = value if isinstance(value, list) else str(value or '').split(',')
    return sorted({str(item).strip().lower() for item in items if _WORD.match(str(item).strip().lower())})


def _info(text):
    """``info`` of the template, or {} when PyYAML cannot read it (nuclei may: the verdicts then refuse it unless credentials are allowed)."""
    try:
        doc = checks._load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return {}
    info = doc.get('info') if isinstance(doc, dict) else None
    return info if isinstance(info, dict) else {}


def credential_tag_problem(text, info):
    """The server's ``credential_tag_problem``: a template whose ``info.tags`` has a credential tag."""
    lowered = text.lower()
    if not any(tag in lowered for tag in flags.NUCLEI_CREDENTIAL_TAGS):
        return ''
    found = sorted(set(_words(info.get('tags'))) & set(flags.NUCLEI_CREDENTIAL_TAGS))
    return f'template not validated: it is tagged {found[0]}, a check that sends credentials' if found else ''


def entry_for(raw, reasons):
    """The index entry of one file's bytes, or ``None`` when it is no template (no ``id``). ``reasons`` is the list each verdict's text is put in once."""
    def number(text):
        if not text:
            return None
        if text not in reasons:
            reasons.append(text)
        return reasons.index(text)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        text = None
    ident = _ID.search(text if text is not None else raw.decode('utf-8', 'replace'))
    if not ident:
        return None
    entry = {'sha256': hashlib.sha256(raw).hexdigest(), 'id': ident.group(1)}
    if text is None or len(raw) > template_index.MAX_TEMPLATE_BYTES or '\0' in text:
        entry['refuse'] = number('template not validated: larger than the template size limit' if len(raw) > template_index.MAX_TEMPLATE_BYTES
                                 else 'template not validated: not UTF-8 text')
        return entry
    info = _info(text)
    tags = _words(info.get('tags'))
    if tags:
        entry['tags'] = tags
    metadata = info.get('metadata') if isinstance(info.get('metadata'), dict) else {}
    for key in ('vendor', 'product'):
        value = str(metadata.get(key) or '').strip().lower()
        if value and len(value) <= 60:
            entry[key] = value
    classification = info.get('classification') if isinstance(info.get('classification'), dict) else {}
    cpe = _CPE.match(str(classification.get('cpe') or '').strip().lower())
    if cpe:
        entry['cpe'] = ':'.join(cpe.groups())
    for verdict, problem in (('ro', checks.readonly_problem(text, allow_credentials=True)), ('cred', checks.credential_problem(text)),
                             ('ctag', credential_tag_problem(text, info))):
        if problem:
            entry[verdict] = number(problem)
    return entry


def build(directory, release):
    reasons, templates = [], {}
    for path, raw in files_in(directory):
        entry = entry_for(raw, reasons)
        if entry is not None:
            templates[path] = entry
    allowlist = nuclei_allowlist.load_allowlist()
    by_id = {}
    for path, entry in templates.items():
        by_id.setdefault(entry['id'], set()).add(entry['sha256'])
    for ident, listed in sorted(allowlist['templates'].items()):
        if ident in by_id and listed.get('sha256') not in by_id[ident]:
            raise SystemExit(f'{ident}: the service-port allowlist records another sha256 than this release: the two describe different releases')
    return {'nuclei_templates': release, 'rules': RULES, 'reasons': reasons, 'templates': templates}


def dump(index):
    """One template a line, so a new release reads as a diff of the templates that changed."""
    lines = ['{', f'"nuclei_templates": {json.dumps(index["nuclei_templates"])},', f'"rules": {index["rules"]},',
             '"reasons": [', ',\n'.join(json.dumps(r) for r in index['reasons']), '],', '"templates": {']
    items = sorted(index['templates'].items())
    lines += [f'{json.dumps(path)}: {json.dumps(entry, sort_keys=True, separators=(",", ":"))}' + (',' if n < len(items) - 1 else '')
              for n, (path, entry) in enumerate(items)]
    lines += ['}', '}']
    return '\n'.join(lines) + '\n'


def summary(index):
    templates = index['templates']
    counts = {name: len(template_index.approved(read_only, credentials, {**index, 'sha256': ''}))
              for name, read_only, credentials in (('readonly', True, False), ('readonly-cred', True, True), ('all', False, False), ('all-cred', False, True))}
    return f'{index["nuclei_templates"]}: {len(templates):,} templates; approved ' + ', '.join(f'{k} {v:,}' for k, v in counts.items())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--templates', required=True, help='a directory holding the nuclei-templates release')
    parser.add_argument('--release', default='', help='the release name (default: the Dockerfile pin)')
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    index = build(args.templates, args.release or release_from_dockerfile())
    print(summary(index))
    if args.write:
        template_index.INDEX_FILE.write_text(dump(index), encoding='utf-8')
        print(f'wrote {template_index.INDEX_FILE}')
    if args.check:
        same = template_index.INDEX_FILE.read_text(encoding='utf-8') == dump(index)
        print('the shipped template index matches this release and library' if same else 'the shipped template index DIFFERS: regenerate it and review the diff')
        return 0 if same else 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
