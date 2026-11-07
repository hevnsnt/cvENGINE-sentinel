"""Signed-in nuclei on the built-in scanner: the one place a stored credential reaches this client.

A nuclei task the server marks ``signed_in`` names a stored sign-in (its ``secret_ref``, a reference the task row keeps; never the value). Only cvENGINE's
built-in scanner runs such a task: any other Sentinel refuses it, so it is never run signed out and reported as signed in (the server never offers it one
either). The built-in scanner reads the credential with ``POST sentinel/tasks/<id>/secret``, which the server answers once per task and audits. The value
lives in this process's memory and, for the run, in a nuclei secrets file (the ``static`` format, the same document the server writes for its own
signed-in runs) of mode 0600 in a private 0700 directory on a memory file system (``/dev/shm`` when it is writable). The file is overwritten and removed
when the run ends, however it ends. Nothing of the value is logged, put in an error or sent back: a finding that echoes it has it replaced by ``***``.

The signed-in web route check (``route_probe_signed``) uses the same one read (``read_sign_in`` / ``run_sign_in``): the credential lives only in this process's
memory for the run (no file), is sent only where ``cvengine_scanner.probes.routes_signed`` says the stored sign-in applies, and every string of the result and
every error of the run goes through ``redact`` before it leaves.
"""
import contextlib
import json
import logging
import os
import shutil
import tempfile
from urllib.parse import urlsplit

logger = logging.getLogger('sentinel.signed_in')

MEMORY_DIRS = ('/dev/shm',)  # a tmpfs in every container: the file never reaches a disk
MIN_REDACT = 4  # shorter values would redact ordinary words


class SignedInError(ValueError):
    """The credential could not be read or used for this task. The message never contains any of it."""


def read_credential(client, task_id):
    """The decrypted credential of one task (``{'headers': [[name, value], ...], 'cookie': str, ...}``), read once from the server."""
    from . import httpclient
    try:
        out = client.call('POST', f'sentinel/tasks/{task_id}/secret')
    except httpclient.ApiError as exc:
        raise SignedInError(f'the server did not hand over the stored sign-in for this task (HTTP {exc.status})') from None
    credential = out.get('credential') if isinstance(out, dict) else None
    if not isinstance(credential, dict):
        raise SignedInError('the server answered the sign-in read without a credential')
    headers = []
    for pair in credential.get('headers') or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and all(isinstance(v, str) for v in pair) and pair[0].strip():
            headers.append((pair[0], pair[1]))
    cookie = credential.get('cookie') if isinstance(credential.get('cookie'), str) else ''
    if cookie:
        headers.append(('Cookie', cookie))
    if not headers:
        raise SignedInError('the stored sign-in has nothing to send')
    return headers


def domain_of(target):
    """How nuclei's secrets file names a destination (the server's ``auth_checks._domain_key``): the host, with the port only when it is not 80 or 443."""
    text = str(target)
    parts = urlsplit(text if '://' in text else f'//{text}')
    host = parts.hostname or ''
    try:
        port = parts.port
    except ValueError:
        port = None
    name = f'[{host}]' if ':' in host else host
    return name if port in (None, 80, 443) else f'{name}:{port}'


def secrets_document(headers, targets):
    """The nuclei secrets file for a run over ``targets`` with ``headers``: one ``Header`` secret, limited to exactly the run's destinations."""
    domains = list(dict.fromkeys(d for d in (domain_of(t) for t in targets) if d))
    if not domains:
        raise SignedInError('the signed-in task names no destination')
    return {'id': 'cvengine-authenticated-checks', 'info': {'name': 'cvENGINE authenticated checks', 'author': 'cvENGINE'},
            'static': [{'type': 'Header', 'domains': domains, 'headers': [{'key': k, 'value': v} for k, v in headers]}]}


def _scratch_parent():
    for path in MEMORY_DIRS:
        if os.path.isdir(path) and os.access(path, os.W_OK | os.X_OK):
            return path
    return None


@contextlib.contextmanager
def secrets_file(document):
    """Write ``document`` to a 0600 file in a private 0700 directory (on a memory file system when there is one), yield its path, then overwrite and
    remove both, whatever happens."""
    scratch = tempfile.mkdtemp(prefix='cvengine-signed-in-', dir=_scratch_parent())
    path = os.path.join(scratch, 'secrets.json')
    try:
        os.chmod(scratch, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(document, handle)
        yield path
    finally:
        _wipe(path)
        shutil.rmtree(scratch, ignore_errors=True)


def _wipe(path):
    try:
        size = os.path.getsize(path)
        with open(path, 'r+b') as handle:
            handle.write(b'\0' * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


MIN_REDACT_PART = 8  # a word inside a header value ("Bearer <token>") is redacted on its own only when it is this long


def secret_values(headers):
    """Every value worth redacting, longest first: each whole header value, each cookie value, and each long word of a header value (the token of
    ``Bearer <token>``, which a finding can echo without its scheme)."""
    values = set()
    for name, value in headers:
        if not isinstance(value, str):
            continue
        if len(value) >= MIN_REDACT:
            values.add(value)
        values.update(word for word in value.split() if len(word) >= MIN_REDACT_PART)
        if name.lower() == 'cookie':
            values.update(part.split('=', 1)[1].strip() for part in value.split(';')
                          if '=' in part and len(part.split('=', 1)[1].strip()) >= MIN_REDACT)
    return sorted(values, key=len, reverse=True)


def redact(value, secrets):
    """``value`` (a result: dicts, lists and strings) with every secret value replaced by ``***``."""
    if isinstance(value, str):
        for secret in secrets:
            if secret in value:
                value = value.replace(secret, '***')
        return value
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    return value


def run(client, task_id, targets, runner):
    """Read the task's credential, run ``runner(secret_file)`` with it, and return the runner's result with every value redacted. The credential is
    dropped from memory as soon as the run ends."""
    headers = read_credential(client, task_id)
    try:
        secrets = secret_values(headers)
        with secrets_file(secrets_document(headers, targets)) as path:
            result = runner(path)
        logger.info('task %s: signed-in nuclei run finished; the stored sign-in was wiped', task_id)
        return redact(result, secrets)
    finally:
        headers.clear()


def read_sign_in(client, task_id):
    """The stored sign-in of one task as ``routes_signed.SignIn`` (its headers, cookie and where it may go), read once from the server. Every header is
    checked (``routes_signed.SignIn.parse``); the error never contains a value."""
    from . import httpclient
    from cvengine_scanner.probes import routes_signed
    try:
        out = client.call('POST', f'sentinel/tasks/{task_id}/secret')
    except httpclient.ApiError as exc:
        raise SignedInError(f'the server did not hand over the stored sign-in for this task (HTTP {exc.status})') from None
    credential = out.get('credential') if isinstance(out, dict) else None
    if not isinstance(credential, dict):
        raise SignedInError('the server answered the sign-in read without a credential')
    try:
        return routes_signed.SignIn.parse(credential)
    except routes_signed.SignInError as exc:
        raise SignedInError(str(exc)) from None


def run_sign_in(client, task_id, runner):
    """Read the task's stored sign-in once, run ``runner(sign_in)`` with it and return the runner's result with every value redacted. Whatever the runner
    raises is re-raised as a ``SignedInError`` whose message is the exception's type and text with every value redacted (a library may quote a header it
    refuses). The sign-in is dropped from memory as soon as the run ends."""
    sign_in = read_sign_in(client, task_id)
    secrets = secret_values(sign_in.headers)
    try:
        result = runner(sign_in)
        logger.info('task %s: signed-in run finished', task_id)
        return redact(result, secrets)
    except SignedInError:
        raise
    except Exception as exc:  # noqa: BLE001 - nothing of the value may reach a log or a result: only its type and a redacted message do
        raise SignedInError(redact(f'{type(exc).__name__}: {exc}', secrets)[:300]) from None
    finally:
        sign_in.clear()
