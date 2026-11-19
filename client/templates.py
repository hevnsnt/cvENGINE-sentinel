"""The nuclei template set a task may run: built here from the template index (contract 11), or, for an older server, fetched as a verified bundle.

From contract 11 the server keeps no copy of the template library: a task's ``template_policy`` says ``source: "index"`` and names the policy (read-only or
every template, credentials allowed or not). ``ensure_index_set`` then builds the approved set from the templates baked into this image and the template
index this library ships (``cvengine_scanner.template_index``): a file is copied in only when the index records its path with exactly its sha256 and the
recorded verdict passes the policy. A file that is missing or differs is left out, never run unjudged. The set is built once per index and policy into the
state volume and reused. ``installed_text`` reads one template of the same baked set for a ``nuclei_validate`` test that names it by ``template_path``.

The rest of this module is the older path, for a server before contract 11:

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


class BundlePending(TemplateError):
    """The server has not packed the approved bundle yet (its ``bundle_sha256`` is still null). That is not a fault of this Sentinel and
    not a final answer about the task: the task is given back to the server, which hands it out again once the bundle exists."""


INDEX_PREFIX = 'index-'  # an index set's directory: ``index-<index sha256 prefix>-<policy name>`` (``index_set_path``)


def image_templates_dir():
    """Where the templates baked into this image are (the Dockerfile puts the pinned release in the run-time user's home, where nuclei looks)."""
    return os.environ.get('CVENGINE_NUCLEI_TEMPLATES_DIR') or os.path.join(os.path.expanduser('~'), 'nuclei-templates')


def index_set_path(read_only, allow_credentials, index=None):
    from cvengine_scanner import template_index
    return os.path.join(bundles_dir(), f'{INDEX_PREFIX}{template_index.digest(index)[:16]}-{template_index.policy_name(read_only, allow_credentials)}')


def _baked_file(source, relative):
    """The bytes of ``relative`` under ``source`` when it is a regular file inside it (no link anywhere on the way) and not over the size limit, else ``None``."""
    from cvengine_scanner import template_index
    parts = relative.split('/')
    if not relative or relative.startswith('/') or '\\' in relative or '\x00' in relative or any(p in ('', '.', '..') for p in parts):
        return None
    path = os.path.join(source, *parts)
    real = os.path.realpath(path)
    if real != os.path.join(os.path.realpath(source), *parts) or os.path.islink(path) or not os.path.isfile(path):
        return None
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(template_index.MAX_TEMPLATE_BYTES + 1)
    except OSError:
        return None
    return raw if len(raw) <= template_index.MAX_TEMPLATE_BYTES else None


def ensure_index_set(read_only=True, allow_credentials=False, source=None, index=None):
    """The directory of the templates the policy approves, from the baked set and the template index (contract 11), built once and reused. Only a file whose
    path the index records with exactly its sha256, and whose verdicts pass the policy, is in it. Raises ``TemplateError`` when the index is missing or empty,
    or when none of the approved templates is in this image as the index recorded it (the image holds another release than the index describes)."""
    from cvengine_scanner import template_index
    index = index or template_index.load()
    if not index['templates'] or not index['sha256']:
        raise TemplateError('this Sentinel has no template index, so it has no approved template set; nothing was run')
    read_only, allow_credentials = read_only is not False, allow_credentials is True  # anything but a plain false is read-only; only a real true allows credentials
    source = source or image_templates_dir()
    path = index_set_path(read_only, allow_credentials, index)
    marker = f'{index["sha256"]}:{template_index.policy_name(read_only, allow_credentials)}'
    with _lock:
        if _complete(path, marker):
            _touch(path)
            return path
        if not os.path.isdir(source):
            raise TemplateError('this Sentinel has no baked nuclei templates, so it has no approved template set; nothing was run')
        root = bundles_dir()
        os.makedirs(root, exist_ok=True)
        scratch = tempfile.mkdtemp(prefix='.unpack-', dir=root)
        copied = missing = differs = 0
        try:
            for relative, entry in template_index.approved(read_only, allow_credentials, index).items():
                raw = _baked_file(source, relative)
                if raw is None:
                    missing += 1
                    continue
                if hashlib.sha256(raw).hexdigest() != entry.get('sha256'):
                    differs += 1
                    continue
                destination = os.path.join(scratch, *relative.split('/'))
                os.makedirs(os.path.dirname(destination), mode=0o755, exist_ok=True)
                with open(destination, 'wb') as handle:
                    handle.write(raw)
                os.chmod(destination, 0o644)
                copied += 1
            if not copied:
                raise TemplateError(f'none of the templates the index approves is in this image as the index recorded it (index {template_index.release(index)}); '
                                    'nothing was run')
            with open(os.path.join(scratch, VERIFIED), 'w', encoding='utf-8') as handle:
                handle.write(marker + '\n')
            os.chmod(scratch, 0o755)
            if os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)
            os.rename(scratch, path)
            scratch = None
        finally:
            if scratch:
                shutil.rmtree(scratch, ignore_errors=True)
        (logger.warning if missing or differs else logger.info)(
            'approved template set %s ready: %s template(s); %s missing from the image, %s differing from the index', os.path.basename(path), copied, missing, differs)
        _prune(keep={os.path.basename(path)})
    return path


def installed_text(relative, sha256, source=None, index=None):
    """The text of the baked template at ``relative`` (a path of the pinned release) for a ``nuclei_validate`` test that names it by ``template_path``
    (contract 11), when the index records it with ``sha256`` and the file in this image is exactly that. Raises ``TemplateError`` otherwise: a template
    this image holds differently is never run in place of the one the server approved."""
    from cvengine_scanner import template_index
    entry = template_index.entry_for(relative, index)
    if not isinstance(relative, str) or entry is None or not isinstance(sha256, str) or entry.get('sha256') != sha256:
        raise TemplateError('the task names a template the template index does not record with that hash; nothing was run')
    if template_index.reason(entry, 'refuse', index):
        raise TemplateError('the template index refuses this template; nothing was run')
    raw = _baked_file(source or image_templates_dir(), relative)
    if raw is None or hashlib.sha256(raw).hexdigest() != sha256:
        raise TemplateError('this image does not hold the template the task names as the index recorded it; nothing was run')
    return raw.decode('utf-8')


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
        elif SHA256.match(name) or name.startswith(INDEX_PREFIX):
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


# --- the instance's custom secret rules (cvENGINE GET sentinel/secret-rules/bundle) -------------------------------------------------

SECRET_RULES_PATH = 'sentinel/secret-rules/bundle'
MAX_SECRET_RULES_BYTES = 64 * 1024  # the server's own cap (cveFeed.secret_rules.MAX_BYTES)
_SECRET_RULES = {}  # sha256 -> the verified YAML text, for this process


def secret_rules(client, sha256):
    """The custom Kingfisher rules a ``secrets_scan`` task names by sha256, as text: fetched once per process, and used only when the bytes match.
    The server checked them (detection only: a custom rule never carries a validator); the scanner only runs them."""
    import io
    if sha256 in _SECRET_RULES:
        return _SECRET_RULES[sha256]
    sink = io.BytesIO()
    try:
        digest, _size = client.download(SECRET_RULES_PATH, sink, MAX_SECRET_RULES_BYTES, timeout=DOWNLOAD_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - any failure is the same answer: the task does not run on other rules
        raise TemplateError(f'the custom secret rules could not be fetched: {exc}') from None
    if digest != sha256:
        raise TemplateError('the custom secret rules the server sent do not match the task; nothing was run')
    text = sink.getvalue().decode('utf-8', errors='replace')
    _SECRET_RULES.clear()  # only the current set is ever kept
    _SECRET_RULES[sha256] = text
    return text
