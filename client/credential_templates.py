"""Which installed nuclei templates send a credential of their own, and the exclusion file that keeps them out of a run (TL-2, item 3).

A nuclei run that does not carry ``allow_credential_checks`` (the server's "Allow checks that send credentials", off unless a person turned it on) must not run
a template with a fixed ``Authorization`` or ``Cookie`` header or a user name in a URL (``cvengine_scanner.checks.credential_problem``). The templates baked into
this image, and a bundle the server packed, are far too many to judge per task (a minute, and far more memory than a Sentinel can spare, if every file were parsed), so the list of paths is made
once per templates release and kept on disk, in a child process with a memory and time limit that parses only the files whose bytes could hold a credential (``checks.might_send_credential``); a run hands it to nuclei as ``-exclude-templates <file>`` (one path per line, measured on nuclei 3.11.1).

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
import subprocess
import sys
import tempfile
import threading
import time

try:
    from cvengine_scanner import checks
except ImportError:  # run as a script by compute(): the library is next to the client package
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from cvengine_scanner import checks

logger = logging.getLogger(__name__)

MAX_INSTALLED_BYTES = 32 * 1024 * 1024  # the ceiling for a template read from this Sentinel's own disk; the rule's 200,000 is for text handed to it
RULE_REV = 4  # bump when ``checks.credential_problem`` changes what it refuses: every list is then made again
CACHE_NAME = '.cvengine-credential-templates.json'


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


def scan(directory, after=None, emit=None):
    """Judge the templates under ``directory`` one at a time (the child process's loop; tests run it in process). A file whose bytes cannot hold a credential
    (``checks.might_send_credential``) is never parsed; a candidate is parsed alone, nothing kept between files. ``after`` skips every path up to and including
    it (a restart after a crash). ``emit(kind, path)`` hears ``P`` before a parse, ``D`` after it, ``C`` for a template with a credential and ``U`` for one that
    cannot be read or parsed. Returns ``(with_credentials, unreadable)``, sorted."""
    credential, unreadable = [], []
    emit = emit or (lambda kind, path: None)
    skipping = after is not None
    for path in _files(directory):
        absolute = os.path.abspath(path)
        if skipping:
            skipping = absolute != after
            continue
        try:
            with open(path, 'rb') as handle:
                raw = handle.read(MAX_INSTALLED_BYTES + 1)
        except OSError:
            unreadable.append(absolute)
            emit('U', absolute)
            continue
        if len(raw) > MAX_INSTALLED_BYTES:
            unreadable.append(absolute)
            emit('U', absolute)
            continue
        if not checks.might_send_credential(raw):
            continue
        emit('P', absolute)
        try:
            problem = checks.credential_problem(raw.decode('utf-8', 'replace'), MAX_INSTALLED_BYTES)
        except Exception:  # noqa: BLE001 - MemoryError, RecursionError or a rule that crashes on a file has not cleared it
            problem = 'not judged'
        del raw
        emit('D', absolute)
        if problem:
            if 'sends a credential' in problem:
                credential.append(absolute)
                emit('C', absolute)
            else:
                unreadable.append(absolute)
                emit('U', absolute)
    return sorted(credential), sorted(unreadable)


SCAN_MEMORY_MB = 512  # the address-space limit of the child (its resident size is far less: see the measurement in the changelog)
SCAN_SECONDS = 300  # the whole computation, restarts included
SCAN_RESTARTS = 25  # a file that kills the child is named unreadable and the scan goes on; this many deaths in one scan is a fault


def _child_command(directory, after):
    return [sys.executable, '-I', os.path.abspath(__file__), '--scan', directory] + (['--after', after] if after else [])


def compute(directory):
    """``(with_credentials, unreadable)`` for the templates under ``directory``, computed in a CHILD process with an address-space limit and a time limit, so the
    worst case kills the child and not the daemon. A file that kills the child is recorded unreadable and the scan goes on after it. Raises
    ``CredentialListError`` when the directory cannot be read, when the time runs out or when the child keeps dying."""
    if not os.path.isdir(directory):
        raise CredentialListError('the template directory is not readable')
    deadline = time.monotonic() + SCAN_SECONDS
    credential, unreadable, after, deaths = set(), set(), None, 0
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise CredentialListError('the list took too long to make')
        try:
            child = subprocess.Popen(_child_command(directory, after), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True,
                                     encoding='utf-8', errors='replace', env={**os.environ, 'CVENGINE_CREDENTIAL_SCAN_MB': str(SCAN_MEMORY_MB)})
        except OSError as exc:
            raise CredentialListError(f'the list could not be started ({type(exc).__name__})') from None
        timer = threading.Timer(left, child.kill)
        timer.start()
        in_flight, finished = None, False
        try:
            for line in child.stdout:
                kind, _tab, path = line.rstrip('\n').partition('\t')
                if kind == 'P':
                    in_flight = path
                elif kind == 'D':
                    after, in_flight = path, None
                elif kind == 'C':
                    credential.add(path)
                elif kind == 'U':
                    unreadable.add(path)
                elif kind == 'END':
                    finished = True
            child.wait()
        finally:
            timer.cancel()
            if child.poll() is None:
                child.kill()
                child.wait()
            child.stdout.close()
        if finished and child.returncode == 0:
            return sorted(credential), sorted(unreadable)
        if time.monotonic() >= deadline:
            raise CredentialListError('the list took too long to make')
        deaths += 1
        if in_flight is None or deaths > SCAN_RESTARTS:
            raise CredentialListError('the process that makes the list failed')
        unreadable.add(in_flight)  # the file in hand when the child died: it cannot be judged, so it is left out, and the rest goes on
        after = in_flight


def _limit_memory():
    megabytes = os.environ.get('CVENGINE_CREDENTIAL_SCAN_MB', '')
    if megabytes.isdigit() and int(megabytes) > 0:
        import resource
        limit = int(megabytes) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def _main(argv):
    """The child: ``--scan DIR [--after PATH]``. One line per event on stdout, ``END`` last."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    _limit_memory()
    directory = argv[argv.index('--scan') + 1]
    after = argv[argv.index('--after') + 1] if '--after' in argv else None

    def emit(kind, path):
        sys.stdout.write(f'{kind}\t{path}\n')
        sys.stdout.flush()
    scan(directory, after, emit)
    sys.stdout.write('END\t\n')
    sys.stdout.flush()
    return 0


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


if __name__ == '__main__':
    sys.exit(_main(sys.argv[1:]))
