"""The nuclei template set the server approved, fetched as a verified bundle.

The cvENGINE server decides which nuclei templates a project may run (its read-only approved set) and publishes that set as one deterministic
tar.gz. A nuclei task names the bundle it must run on (``bundle_sha256``); this module downloads it from the Sentinel's own server, checks the
hash of exactly the bytes it received against the one in the task, unpacks it without trusting a single path in it, and hands nuclei the directory.
Nothing the server did not approve ever runs: a bundle that cannot be fetched or does not match is an error, never a fallback to other templates.

Unpacking is deliberately strict because the archive is data from the network: only regular files and directories are accepted, every path must
stay inside the target directory, and the number of entries and their total size are bounded. A bundle is unpacked once into the state volume and
reused by every later task that names the same hash; the newest few are kept.
"""
import hashlib
import logging
import os
import re
import shutil
import tarfile
import tempfile
import threading
import time

from . import control

logger = logging.getLogger('sentinel.templates')

BUNDLE_PATH = 'sentinel/template-policy/bundle'
SHA256 = re.compile(r'^[0-9a-f]{64}$')
MAX_BUNDLE_BYTES = 64 * 1024 * 1024  # the compressed download (the whole community set is about 10 MB)
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 200_000
MAX_PATH_LENGTH = 400
KEEP_BUNDLES = 3
UNUSED_SECONDS = 24 * 3600  # a bundle beyond the newest KEEP_BUNDLES is removed once it has been unused this long
DOWNLOAD_TIMEOUT = 120
VERIFIED = '.verified'

_lock = threading.Lock()  # one download or unpack at a time: two tasks that need the same bundle fetch it once


class TemplateError(RuntimeError):
    """The approved template bundle could not be obtained or did not verify. The message is safe to report back to the server."""


def bundles_dir():
    return os.path.join(control.state_dir(), 'templates')


def bundle_path(sha256):
    return os.path.join(bundles_dir(), sha256)


def _complete(path, sha256):
    try:
        with open(os.path.join(path, VERIFIED), encoding='utf-8') as handle:
            return handle.read().strip() == sha256
    except OSError:
        return False


def ensure_bundle(client, sha256):
    """The directory holding the approved templates whose archive hashes to ``sha256``, downloading and unpacking it first when this Sentinel does
    not have it yet. Raises ``TemplateError`` for anything that stops it being exactly that set."""
    sha256 = sha256.strip().lower() if isinstance(sha256, str) else ''
    if not SHA256.match(sha256):
        raise TemplateError('the task names no valid template bundle hash')
    path = bundle_path(sha256)
    with _lock:
        if _complete(path, sha256):
            _touch(path)
            return path
        try:
            _fetch(client, sha256, path)
        except TemplateError:
            raise
        except Exception as exc:  # noqa: BLE001 - whatever failed (network, disk, a hostile archive), the task reports that the set is not available
            logger.warning('could not obtain the template bundle %s: %s', sha256[:12], exc)
            raise TemplateError(f'the approved template bundle could not be fetched ({type(exc).__name__})') from None
        _prune(keep={sha256})
    return path


def _touch(path):
    try:
        os.utime(path, None)
    except OSError:
        pass


def _fetch(client, sha256, path):
    root = bundles_dir()
    os.makedirs(root, exist_ok=True)
    archive = tempfile.NamedTemporaryFile(prefix='.download-', suffix='.tgz', dir=root, delete=False)
    scratch = None
    try:
        with archive:
            digest, size = client.download(BUNDLE_PATH, archive, MAX_BUNDLE_BYTES, timeout=DOWNLOAD_TIMEOUT)
        if digest != sha256:
            raise TemplateError('the template bundle the server sent does not match the approved hash; nothing was run')
        scratch = tempfile.mkdtemp(prefix='.unpack-', dir=root)
        count = _unpack(archive.name, scratch)
        with open(os.path.join(scratch, VERIFIED), 'w', encoding='utf-8') as handle:
            handle.write(sha256 + '\n')
        os.chmod(scratch, 0o755)
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)  # an unfinished earlier attempt (no verified marker)
        os.rename(scratch, path)
        scratch = None
        logger.info('template bundle %s ready: %s file(s), %s bytes downloaded', sha256[:12], count, size)
    finally:
        try:
            os.unlink(archive.name)
        except OSError:
            pass
        if scratch:
            shutil.rmtree(scratch, ignore_errors=True)


def _safe_name(name):
    """The member's path relative to the target, or ``None`` when it could land anywhere else."""
    if not name or len(name) > MAX_PATH_LENGTH or '\x00' in name or name.startswith('/') or '\\' in name:
        return None
    parts = [p for p in name.split('/') if p not in ('', '.')]
    if not parts or any(p == '..' for p in parts):
        return None
    return '/'.join(parts)


def _unpack(archive, target):
    """Unpack ``archive`` into ``target``; returns the number of files. Regular files and directories only (no links, devices or special files),
    every path inside ``target``, entries and bytes bounded, permissions set by us (never taken from the archive)."""
    count, total = 0, 0
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar:
            relative = _safe_name(member.name)
            if member.isdir():
                if relative:
                    os.makedirs(os.path.join(target, relative), mode=0o755, exist_ok=True)
                continue
            if not member.isreg() or relative is None:
                raise TemplateError('the template bundle holds an entry that is not allowed (a link, a special file or a path outside the bundle)')
            count += 1
            total += member.size
            if count > MAX_ENTRIES or total > MAX_EXTRACTED_BYTES:
                raise TemplateError('the template bundle is larger than this Sentinel accepts')
            destination = os.path.join(target, relative)
            os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
            source = tar.extractfile(member)
            with open(destination, 'wb') as handle:
                shutil.copyfileobj(source, handle)
            os.chmod(destination, 0o644)
    if count == 0:
        raise TemplateError('the template bundle is empty')
    return count


def _prune(keep):
    """Remove bundles beyond the newest KEEP_BUNDLES that have not been used for a day (a running scan keeps its bundle's directory fresh), and
    leftovers of interrupted downloads."""
    root = bundles_dir()
    now = time.time()
    try:
        entries = [(name, os.path.join(root, name)) for name in os.listdir(root)]
    except OSError:
        return
    bundles = []
    for name, full in entries:
        if name.startswith('.download-') or name.startswith('.unpack-'):
            if now - _mtime(full) > UNUSED_SECONDS:
                _remove(full)
        elif SHA256.match(name):
            bundles.append((name, full, _mtime(full)))
    bundles.sort(key=lambda item: item[2], reverse=True)
    for name, full, mtime in bundles[KEEP_BUNDLES:]:
        if name not in keep and now - mtime > UNUSED_SECONDS:
            _remove(full)


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def _remove(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)
    except OSError:
        pass


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()
