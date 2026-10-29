"""Entry point: ``python -m client`` (the Dockerfile's CMD). Loads a persisted token if one exists, otherwise
bootstraps from ``CVENGINE_SENTINEL_BLOB``, then runs the daemon's main loop until SIGTERM/SIGINT. Exits non-zero when
the server no longer accepts this Sentinel's token.
"""
import logging
import signal
import sys

from . import config
from . import daemon as daemon_mod
from . import httpclient

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger('sentinel.main')


def main():
    path = config.token_path()
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
        raw_blob = config.blob()
        if not raw_blob:
            logger.error('no persisted token at %s and CVENGINE_SENTINEL_BLOB is not set; cannot start', path)
            sys.exit(1)
        logger.info('bootstrapping from CVENGINE_SENTINEL_BLOB')
        try:
            token, server_url = daemon_mod.bootstrap(raw_blob, config.sentinel_name(), config.max_concurrent())
        except Exception:  # noqa: BLE001 - a bad blob or unreachable server is fatal at startup; say why, then exit
            logger.exception('bootstrap failed')
            sys.exit(1)
        try:
            daemon_mod.save_token(path, token, server_url)
            logger.info('bootstrap succeeded; token persisted at %s', path)
        except OSError:  # the blob is single use and now spent: keep running on the token in memory rather than lose it
            logger.error('bootstrap succeeded but the token could not be saved at %s; running with it in memory and retrying the save at every '
                         'heartbeat. Fix the state volume before this container restarts, or it will need a new blob', path, exc_info=True)
            unsaved = True

    client = httpclient.Client(server_url, token)
    engine = daemon_mod.Daemon(server_url, token, max_concurrent=config.max_concurrent(), client=client)
    engine.reregister = lambda: daemon_mod.register(client, config.sentinel_name(), config.max_concurrent())
    if unsaved:
        engine.keep_saving_token(path, token, server_url)
    engine.start_registration()  # a server that is down leaves it pending; the heartbeat retries it
    if engine.exit_code:
        sys.exit(engine.exit_code)

    def handle_signal(signum, _frame):
        logger.info('received signal %s; finishing or releasing in-flight tasks', signum)
        engine.request_stop()
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info('Sentinel %s starting, max_concurrent=%s, server=%s', config.sentinel_name(), config.max_concurrent(), server_url)
    engine.run()
    logger.info('Sentinel stopped')
    if engine.exit_code:
        sys.exit(engine.exit_code)


if __name__ == '__main__':
    main()
