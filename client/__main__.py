"""Entry point: ``python -m client`` (the Dockerfile's CMD). Loads a persisted token if one exists, otherwise
bootstraps from ``CVENGINE_SENTINEL_BLOB`` (or the file ``CVENGINE_SENTINEL_BLOB_FILE`` names), then runs the daemon's main loop until SIGTERM/SIGINT.
Exits non-zero when the server no longer accepts this Sentinel's token.

The built-in scanner (``CVENGINE_SENTINEL_BUILTIN=1``) never needs a person: with no token it waits for the server to write its enrollment into the blob
file, and when the server stops accepting its token (expired, revoked) it forgets that token and enrols again with the next blob the server writes. A
blob it has already redeemed, or one the server refused, is not tried again; it waits for the file to change.
"""
import hashlib
import logging
import os
import signal
import sys
import threading

from . import config
from . import control
from . import daemon as daemon_mod
from . import httpclient

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger('sentinel.main')

BLOB_POLL_SECONDS = 5  # how often a built-in scanner with no token looks at the blob file
BLOB_RETRY_SECONDS = 60  # how long it waits after a bootstrap the server could not answer before it tries the same blob again
WAITING_LOG_EVERY = 600  # the "still waiting" line, at most this often
SPENT_FILE = 'blob.spent'  # in the state volume: the sha256 of the last blob redeemed or refused, so a restart does not try it again


class _Stop:
    """What the signal handlers stop: the daemon running now, or the wait for a blob."""

    def __init__(self):
        self.event = threading.Event()
        self.engine = None

    def handle(self, signum, _frame):
        logger.info('received signal %s; finishing or releasing in-flight tasks', signum)
        self.event.set()
        if self.engine is not None:
            self.engine.request_stop()


def _digest(raw):
    return hashlib.sha256(raw.strip().encode('utf-8')).hexdigest()


def _spent_path():
    return os.path.join(control.state_dir(), SPENT_FILE)


def _spent():
    try:
        with open(_spent_path(), encoding='utf-8') as handle:
            return handle.read(100).strip()
    except OSError:
        return ''


def _mark_spent(raw):
    try:
        os.makedirs(control.state_dir(), exist_ok=True)
        with open(_spent_path(), 'w', encoding='utf-8') as handle:
            handle.write(_digest(raw))
    except OSError:
        logger.warning('could not note the redeemed enrollment in %s', _spent_path())


def _wait_for_blob(stop):
    """A built-in scanner with no token: wait for a blob in the blob file that it has not redeemed or been refused before. Returns it, or None when
    asked to stop. Healthy meanwhile (``control.write_enrolling``)."""
    waited = 0
    while not stop.event.is_set():
        raw = config.blob()
        if raw and _digest(raw) != _spent():
            return raw
        if waited % WAITING_LOG_EVERY == 0:
            logger.info('waiting for the server to write the enrollment to %s (it does when CVENGINE_BUILTIN_SCANNER is on and there is an '
                        'App Admin)', config.blob_file())
        try:
            control.write_enrolling()
        except OSError:
            pass
        stop.event.wait(BLOB_POLL_SECONDS)
        waited += BLOB_POLL_SECONDS
    return None


def _bootstrap(stop):
    """``(token, server_url)`` from a fresh enrollment, persisted when possible, plus whether saving it failed; ``(None, None, False)`` when stopping.
    Exits for a Sentinel that is not built-in and has no usable blob (a person must provide one)."""
    path = config.token_path()
    builtin = config.builtin() and config.blob_file()
    while True:
        raw_blob = _wait_for_blob(stop) if builtin else config.blob()
        if raw_blob is None and stop.event.is_set():
            return None, None, False
        if not raw_blob:
            logger.error('no persisted token at %s and CVENGINE_SENTINEL_BLOB is not set; cannot start', path)
            sys.exit(1)
        logger.info('bootstrapping from %s', 'the enrollment file' if builtin else 'CVENGINE_SENTINEL_BLOB')
        try:
            token, server_url = daemon_mod.bootstrap(raw_blob, config.sentinel_name(), config.max_concurrent())
        except Exception as exc:  # noqa: BLE001 - a bad blob or unreachable server: said once, never with the blob in it
            if not builtin:
                logger.exception('bootstrap failed')
                sys.exit(1)
            if daemon_mod._retryable(exc):
                logger.warning('bootstrap failed (%s); trying again in %ss', type(exc).__name__ if not getattr(exc, 'status', None) else exc,
                               BLOB_RETRY_SECONDS)
                stop.event.wait(BLOB_RETRY_SECONDS)
            else:
                logger.error('the server refused the enrollment in %s (%s); waiting for a new one', config.blob_file(), exc)
                _mark_spent(raw_blob)
            continue
        if builtin:
            _mark_spent(raw_blob)  # single use: never offered again, even if the server has not removed the file yet
        try:
            daemon_mod.save_token(path, token, server_url)
            logger.info('bootstrap succeeded; token persisted at %s', path)
            return token, server_url, False
        except OSError:  # the blob is single use and now spent: keep running on the token in memory rather than lose it
            logger.error('bootstrap succeeded but the token could not be saved at %s; running with it in memory and retrying the save at every '
                         'heartbeat. Fix the state volume before this container restarts, or it will need a new blob', path, exc_info=True)
            return token, server_url, True


def _forget_token(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def main():
    stop = _Stop()
    signal.signal(signal.SIGTERM, stop.handle)
    signal.signal(signal.SIGINT, stop.handle)
    path = config.token_path()
    while True:
        token, server_url = daemon_mod.load_token(path)
        unsaved = False
        if token:
            try:
                httpclient.validate_server_url(server_url)
            except ValueError as exc:  # the message never repeats the URL; falling back to the (single use) blob would not help
                logger.error('the server address in %s is not acceptable (%s); correct or remove that file', path, exc)
                sys.exit(1)
            logger.info('using the persisted token at %s; skipping bootstrap', path)
        else:
            token, server_url, unsaved = _bootstrap(stop)
            if token is None:
                logger.info('Sentinel stopped')
                return

        client = httpclient.Client(server_url, token)
        engine = daemon_mod.Daemon(server_url, token, max_concurrent=config.max_concurrent(), client=client)
        engine.reregister = lambda client=client: daemon_mod.register(client, config.sentinel_name(), config.max_concurrent())
        if unsaved:
            engine.keep_saving_token(path, token, server_url)
        stop.engine = engine
        if stop.event.is_set():
            return
        engine.start_registration()  # a server that is down leaves it pending; the heartbeat retries it
        if not engine.exit_code:
            logger.info('Sentinel %s starting, max_concurrent=%s, server=%s', config.sentinel_name(), config.max_concurrent(), server_url)
            engine.run()
        stop.engine = None
        if engine.exit_code == daemon_mod.REENROLL and config.builtin() and config.blob_file() and not stop.event.is_set():
            _forget_token(path)  # dead on the server: the next start must enrol again, not reuse it
            continue
        logger.info('Sentinel stopped')
        if engine.exit_code:
            sys.exit(engine.exit_code)
        return


if __name__ == '__main__':
    main()
