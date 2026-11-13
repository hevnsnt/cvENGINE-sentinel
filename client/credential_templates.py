"""Which installed nuclei templates send a credential of their own, and the exclusion file that keeps them out of a run (TL-2, item 3).

A nuclei run that does not carry ``allow_credential_checks`` (the server's "Allow checks that send credentials", off unless a person turned it on) must not run
a template with a fixed ``Authorization`` or ``Cookie`` header or a user name in a URL (``cvengine_scanner.checks.credential_problem``). The templates baked into
this image, and a bundle the server packed, are far too many to judge per task (about 37 seconds for the 14,248 files of v10.5.2), so the list of paths is made
once per templates release and kept on disk; a run hands it to nuclei as ``-exclude-templates <file>`` (one path per line, measured on nuclei 3.11.1).

The list is keyed on the templates directory, its release marker, a cheap fingerprint of the files (their number and newest time) and this library's version
and rule revision: any change makes it be made again. A template that cannot be read or parsed (unreadable, over ``MAX_INSTALLED_BYTES``, not YAML) is on the list too, counted apart: when in doubt it is
left out. A large template is judged at its real size. A cache that is missing, unreadable or stale means "make it now"; if that fails, ``CredentialListError`` is raised and the caller does not run the
unfiltered set.
"""
import hashlib
import json
import logging
import os
import re
import tempfile

from cvengine_scanner import checks

logger = logging.getLogger(__name__)

MAX_INSTALLED_BYTES = 32 * 1024 * 1024  # the ceiling for a template read from this Sentinel's own disk; the rule's 200,000 is for text handed to it
RULE_REV = 2  # bump when ``checks.credential_problem`` changes what it refuses: every list is then made again
CACHE_NAME = '.cvengine-credential-templates.json'
# a template with none of these words cannot carry a fixed credential header or a user name in a URL, so it is not parsed (the rule parses the rest)
_CANDIDATE = re.compile(r'(?i)authorization|cookie|api[-_]?key|token|secret|passw|session|credential|jwt|csrf|xsrf|signature|bearer|://[^/\s?#"\']*@')


class CredentialListError(RuntimeError):
    """The list of templates that send a credential could not be made, so the unfiltered set must not run."""


def _library():
    import cvengine_scanner
    return f'{getattr(cvengine_scanner, "__version__", "?")}/rule{RULE_REV}'


def _files(directory):
    for base, dirs, names in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in ('.git', '.github') and not os.path.islink(os.path.join(base, d)))
        for name in sorted(names):
            if name.endswith(('.yaml', '.yml')):
                path = os.path.join(base, name)
                if not os.path.islink(path):
                    yield path


def fingerprint(directory):
    """``'<files>:<newest mtime>'`` of the templates under ``directory``: cheap, and it changes when a template is added, removed or rewritten."""
    count, newest = 0, 0
    for path in _files(directory):
        count += 1
        try:
            newest = max(newest, int(os.stat(path).st_mtime))
        except OSError:
            pass
    return f'{count}:{newest}'


def compute(directory):
    """``(with_credentials, unreadable)``: the sorted absolute paths of the templates under ``directory`` that send a credential of their own, and of those that
    cannot be read or parsed (so cannot be judged). Raises ``CredentialListError`` when the directory cannot be read at all."""
    if not os.path.isdir(directory):
        raise CredentialListError('the template directory is not readable')
    credential, unreadable = [], []
    for path in _files(directory):
        absolute = os.path.abspath(path)
        try:
            with open(path, 'rb') as handle:
                raw = handle.read(MAX_INSTALLED_BYTES + 1)
        except OSError:
            unreadable.append(absolute)
            continue
        if len(raw) > MAX_INSTALLED_BYTES:
            unreadable.append(absolute)
            continue
        text = raw.decode('utf-8', 'replace')
        if not _CANDIDATE.search(text):
            continue
        try:
            problem = checks.credential_problem(text, MAX_INSTALLED_BYTES)
        except Exception:  # noqa: BLE001 - a rule that crashes on a file has not cleared it
            problem = 'not judged'
        if problem:
            (credential if 'sends a credential' in problem else unreadable).append(absolute)
    return sorted(credential), sorted(unreadable)


def _cache_paths(directory, beside=False):
    """Where the list is kept: beside the templates when asked (the image's own directory, which this Sentinel's user owns), and in this user's cache directory.
    A server bundle is verified by its hash, so nothing is ever written into one."""
    key = hashlib.sha1(os.path.abspath(directory).encode()).hexdigest()[:16]
    home = os.path.join(os.path.expanduser('~'), '.cache', 'cvengine-sentinel', f'credential-templates-{key}.json')
    return [os.path.join(directory, CACHE_NAME), home] if beside else [home]


def _read(path, want):
    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) and all(data.get(k) == v for k, v in want.items()):
        lists = (data.get('credential'), data.get('unreadable'))
        if all(isinstance(x, list) and all(isinstance(p, str) for p in x) for x in lists):
            return lists
    return None


def _write(paths, want, credential, unreadable):
    body = json.dumps({**want, 'credential': credential, 'unreadable': unreadable})
    for path in paths:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.cred-')
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write(body)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            return True
        except OSError:
            continue
    return False  # nothing writable: the list is made again next time, never skipped


def lists_for(directory, release, beside=False):
    """``(with_credentials, unreadable)``, the paths of the templates under ``directory`` to leave out of a run that may not send credentials: read from the cache when it is for this directory,
    release, file fingerprint and library, else made now and kept. Raises ``CredentialListError`` when it cannot be made."""
    directory = os.path.abspath(directory)
    want = {'directory': directory, 'release': str(release), 'files': fingerprint(directory), 'library': _library()}
    for path in _cache_paths(directory, beside):
        cached = _read(path, want)
        if cached is not None:
            return cached
    try:
        credential, unreadable = compute(directory)
    except CredentialListError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise CredentialListError(f'the list could not be made ({type(exc).__name__})') from None
    _write(_cache_paths(directory, beside), want, credential, unreadable)
    logger.info('nuclei: %d of the templates under %s send a credential of their own and %d cannot be read or parsed; they are left out of runs that may not send one',
                len(credential), directory, len(unreadable))
    return credential, unreadable


def exclusion_file(directory, release, beside=False):
    """``(path, with_credentials, unreadable)``: a temporary file listing the templates to exclude, one absolute path a line, for ``-exclude-templates``, or
    ``(None, 0, 0)`` when none is to be left out. The caller removes the file. Raises ``CredentialListError`` as ``lists_for`` does."""
    credential, unreadable = lists_for(directory, release, beside)
    found = sorted(set(credential) | set(unreadable))
    if not found:
        return None, 0, 0
    fd, path = tempfile.mkstemp(prefix='nuclei-exclude-', suffix='.txt')
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(found) + '\n')
    return path, len(credential), len(unreadable)
