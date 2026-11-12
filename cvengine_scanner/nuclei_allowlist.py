"""The templates a nuclei service run may send: a pinned allowlist, and the reading of it.

A nuclei run on a service port (every port that is not web) runs ONLY a template whose id is on the allowlist shipped with this library and whose file content
has the sha256 the list records, for the nuclei-templates release the Sentinel image pins. Everything else is refused: a template the list does not know
(a new one, one that was never read), and one whose content differs (the library changed it). This replaces a rule that named what must not run (a deny
rule: three reviews in a row found a template it missed).

The list is made by ``scripts/generate_service_allowlist.py`` (read it: it states what is kept and why), from the templates a service run could select, and it
is reviewed by a person each time the pinned release moves (``scripts/check_tool_versions.py`` fails the release gate when it is not regenerated).
``nuclei_service_left_out.json`` records, for every template of the candidate set that is not on the list, the reason.

This module has no side effect: it reads two JSON files and, for the check of a template's strings, PyYAML (imported only there, never by a run).
"""
import base64
import hashlib
import json
import os
import re
from pathlib import Path

DATA = Path(__file__).resolve().parent / 'data'
ALLOWLIST_FILE = DATA / 'nuclei_service_allowlist.json'
LEFT_OUT_FILE = DATA / 'nuclei_service_left_out.json'
REVIEW_FILE = DATA / 'nuclei_service_review.json'
_ID = re.compile(r'(?m)^id:[ \t]*["\']?([A-Za-z0-9_.-]+)["\']?[ \t]*(?:#.*)?\r?$')
MAX_TEMPLATE_BYTES = 256 * 1024

_cache = {}


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def template_id(text):
    """The ``id:`` of a template file's text, or ``None``."""
    found = _ID.search(text)
    return found.group(1) if found else None


def load_allowlist(path=ALLOWLIST_FILE):
    """The allowlist's ``{'nuclei_templates', 'templates': {id: {'sha256', ...}}, 'reviewed_exceptions'}``. A missing or unreadable file is an empty list: nothing runs
    on a service port (the safe side), never everything. Read once."""
    key = str(path)
    if key not in _cache:
        try:
            data = json.loads(Path(path).read_text(encoding='utf-8'))
            templates = data['templates']
            if not isinstance(templates, dict):
                raise TypeError('templates')
            _cache[key] = {'nuclei_templates': str(data.get('nuclei_templates') or ''), 'templates': templates,
                           'reviewed_exceptions': set(data.get('reviewed_exceptions') or ())}
        except (OSError, ValueError, KeyError, TypeError):
            _cache[key] = {'nuclei_templates': '', 'templates': {}, 'reviewed_exceptions': set()}
    return _cache[key]


def forget():
    """Drop what was read (a test that points the list elsewhere)."""
    _cache.clear()


def covers(klass, allowlist=None):
    """Whether the list names any template for the service class ``klass`` at all (a missing, unreadable or empty list covers none). A class it does not cover has no
    check: a port of that class is reported as not checked, never as scanned clean."""
    allowlist = allowlist if allowlist is not None else load_allowlist()
    return any(isinstance(e, dict) and klass in (e.get('classes') or ()) for e in allowlist['templates'].values())


def check_bytes(raw, allowlist=None):
    """``(allowed, reason, template_id)`` for the bytes of a template file: allowed only when its id is on the list and the sha256 of the bytes is the one
    recorded. The reason says which of the two failed."""
    allowlist = allowlist if allowlist is not None else load_allowlist()
    if len(raw) > MAX_TEMPLATE_BYTES:
        return False, 'the template file is larger than any allowlisted template', None
    tid = template_id(raw.decode('utf-8', 'replace'))
    entry = allowlist['templates'].get(tid) if tid else None
    if not isinstance(entry, dict):
        return False, 'the template is not on the service-port allowlist', tid
    if entry.get('sha256') != sha256_of(raw):
        return False, 'the template file differs from the one the service-port allowlist was made from (its sha256 changed)', tid
    return True, None, tid


def _read_template(path):
    try:
        return Path(path).read_bytes()[:MAX_TEMPLATE_BYTES + 1], None
    except OSError:
        return None, 'the template file cannot be read'


def check_file(path, allowlist=None):
    """``(allowed, reason, template_id)`` for a template file on disk (see ``check_bytes``)."""
    raw, why = _read_template(path)
    if raw is None:
        return False, why, None
    return check_bytes(raw, allowlist)


def private_copy(path, directory, allowlist=None):
    """Read the template file ONCE, check those bytes against the list and write exactly those bytes to a new file (mode 0600) in ``directory``, which the caller
    made private (mode 0700, its own user). Returns ``(copy_path, reason, template_id)``; ``copy_path`` is None when the template is not allowed. nuclei is given the
    copy, so a library file replaced after this check is never what it opens: the bytes that were hashed are the bytes that run."""
    raw, why = _read_template(path)
    if raw is None:
        return None, why, None
    allowed, reason, tid = check_bytes(raw, allowlist)
    if not allowed:
        return None, reason, tid
    target = os.path.join(directory, os.path.basename(str(path)) or 'template.yaml')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
    return target, None, tid


# --------------------------------------------------------------------------------------------------------------- the decode check
# An independent reading of every string of a template, in plain text, as hex and as base64, for what authenticates: a user name, a password, a token, a cookie,
# a community string, an authorization header or an authentication message. It does not look at the calls ``client.tools._paced_template`` names; the two are
# made to agree on the whole library (the generator prints where they differ).
_WORDS = re.compile(
    r'(?i)(?<![a-z0-9])(username|user|usr|login|logon|passwd|password|pass|pwd|passphrase|auth|authenticate|authentication|authorization|authorisation|bearer|basic|token|jwt|'
    r'apikey|api[_-]key|api_token|community|secret|cookie|session[_-]?id|credential|credentials|scram|ntlmssp|ntlm|sasl|bind|kerberos|negotiate)(?![a-z0-9])')
# a name that is a user, a password or a secret as a key of a template (args, variables, payloads, inputs)
_KEYS = re.compile(r'(?i)user|usr|pass|pwd|cred|token|community|secret|auth|login|bind|cookie|jwt|bearer')
# words that are accounts: in a binary packet they stand where a user name does
_ACCOUNTS = re.compile(
    r'(?i)(?<![a-z0-9])(root|admin|administrator|guest|anonymous|anon|ftp|test|default|cisco|ubnt|sa|postgres|mysql|oracle|monster|zte\w*|nuclei|operator|user\w*|pass\w*)(?![a-z0-9])')
# what a binary login or hello says in bytes whatever the names: the plugin of a MySQL login, a PostgreSQL startup, a ClickHouse client name
_BINARY_AUTH = re.compile(rb'mysql_native_password|caching_sha2_password|mysql_clear_password|SCRAM-SHA|\x00user\x00|\x00database\x00|PLAIN\x00|ClickHouse client', re.I)
_HEX = re.compile(r'(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){4,})(?![0-9A-Fa-f])')
_B64 = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])')
_HEX_CALL = re.compile(r'(?i)hex_decode\(\s*["\']([0-9a-f \\x]+)["\']\s*\)')
_ESCAPES = re.compile(r'\\x([0-9a-fA-F]{2})')
_SKIP_PLAIN = re.compile(r'(?i)/(?:matchers|extractors)(?:\[|/)')  # what a reply must hold: never sent
_JS_COMMENT = re.compile(r'(?ms)/\*.*?\*/|(?:^|(?<=\s))//[^\n]*')


def _walk(obj, path=''):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield f'{path}/{key}', None, str(key)
            yield from _walk(value, f'{path}/{key}')
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield from _walk(value, f'{path}[{index}]')
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        yield path, str(obj), None


def decoded_variants(value):
    """The readings of one string: ``(kind, bytes)`` for plain, for hex (also written as ``\\xNN`` escapes or ``hex_decode("...")``) and for base64, wherever the
    string, or a piece of it that looks like one, decodes."""
    out = [('plain', value.encode('utf-8', 'replace'))]
    squeezed = value.strip().replace(' ', '').replace('\n', '')
    pieces = {squeezed} | set(_HEX.findall(value)) | {m.replace(' ', '') for m in _HEX_CALL.findall(value)}
    if _ESCAPES.search(value):
        out.append(('hex', bytes(int(h, 16) for h in _ESCAPES.findall(value))))
        pieces |= {''.join(_ESCAPES.findall(value))}
    for piece in sorted(p for p in pieces if p):
        text = piece.replace('\\x', '')
        if re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', text) and len(text) >= 8:
            try:
                out.append(('hex', bytes.fromhex(text)))
            except ValueError:
                pass
    for piece in set(_B64.findall(value)) | ({squeezed} if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', squeezed) else set()):
        try:
            raw = base64.b64decode(piece + '=' * (-len(piece) % 4), validate=True)
        except Exception:  # noqa: BLE001 - not base64
            continue
        if raw and sum(32 <= c < 127 or c in (0, 9, 10, 13) for c in raw) > 0.8 * len(raw):
            out.append(('base64', raw))
    return out


def _text_loader():
    """A YAML loader that leaves numbers as the text they were written as: ``data: 00000000`` and ``data: 1e10`` are hex strings of a template, and a loader that
    reads them as numbers would lose their zeros and change their bytes."""
    import yaml
    loader = type('TextLoader', (yaml.SafeLoader,), {})
    loader.yaml_implicit_resolvers = {key: [(tag, regex) for tag, regex in resolvers if tag not in ('tag:yaml.org,2002:int', 'tag:yaml.org,2002:float')]
                                      for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()}
    return loader


_SENT = re.compile(r'(?i)/(?:inputs|data|args|variables|payloads)(?:\[|/|$)')
_WHOLE_ACCOUNT = re.compile(r'(?i)(?:root|admin|administrator|guest|anonymous|anon|ftp|default|cisco|ubnt|sa|postgres|mysql|oracle|operator|test|user\w*)')


def credential_findings(text):
    """What in a template's text looks like a credential or an authentication step: a list of short strings (empty: nothing found). Every string of the template
    outside ``info`` is read as plain text, as hex and as base64 (the strings of ``matchers`` and ``extractors`` are not read: they say what a reply holds, not
    what is sent), every key is read for a name that is a user, a password, a token, a cookie or a secret, and a sent string that is just an account name
    (``root``) is a finding. A text PyYAML cannot read is a finding (the template cannot be checked, so it is not allowed)."""
    import yaml  # the generator and the tests read templates; a run never calls this
    try:
        doc = yaml.load(text, Loader=_text_loader())  # noqa: S506 - a safe loader with the number resolvers removed
    except yaml.YAMLError:
        return ['the template is not valid YAML, so its strings cannot be read']
    if not isinstance(doc, dict):
        return ['the template is not a mapping']
    body = {key: value for key, value in doc.items() if key not in ('info', 'id')}
    found = []
    for path, value, key in _walk(body):
        if key is not None:
            if _KEYS.search(key) and not _SKIP_PLAIN.search(path):
                found.append(f'key {path}')
            continue
        if _SKIP_PLAIN.search(path) or path.endswith('/name'):
            continue  # a matcher or an extractor says what a reply holds; it is never sent
        if path.endswith('/code') and path.startswith('/javascript'):
            value = _JS_COMMENT.sub(' ', value)  # a comment is not sent
        if _SENT.search(path) and _WHOLE_ACCOUNT.fullmatch(value.strip()):
            found.append(f'plain {path}: {value.strip().lower()} (a sent account name)')
        for kind, raw in decoded_variants(value):
            if kind == 'plain':
                match = _WORDS.search(value)
                if match:
                    found.append(f'plain {path}: {match.group(1).lower()}')
                continue
            word = _WORDS.search(raw.decode('latin-1'))
            if word:
                found.append(f'{kind} {path}: {word.group(1).lower()}')
            elif _BINARY_AUTH.search(raw):
                found.append(f'{kind} {path}: an authentication packet')
            else:
                for run in re.findall(rb'[\x20-\x7e]{3,}', raw):
                    account = _ACCOUNTS.search(run.decode('latin-1'))
                    if account:
                        found.append(f'{kind} {path}: {account.group(1).lower()} (an account name in a packet)')
                        break
    # a value that decodes to words in more than one place is one finding of the template; keep each kind of finding once
    seen, unique = set(), []
    for item in found:
        marker = re.sub(r'\[\d+\]', '[]', item)
        if marker not in seen:
            seen.add(marker)
            unique.append(item)
    return unique
