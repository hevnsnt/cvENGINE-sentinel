"""Tests never touch the host: the daemon writes its updater hand-off files beside the token file, OpenVAS looks for its gvmd socket and
credentials at paths of its own, and the tool probe is never run for real. All of them point into a temporary directory for the test run."""
import atexit
import logging
import os
import shutil
import tempfile
import threading
import time
import weakref

_state = tempfile.mkdtemp(prefix='sentinel-test-state-')
os.environ['CVENGINE_SENTINEL_TOKEN_FILE'] = os.path.join(_state, 'token.json')
os.environ['CVENGINE_OPENVAS_SOCKET'] = os.path.join(_state, 'no-gvmd.sock')  # never created: GVM reads as not running unless a test fakes it
os.environ['CVENGINE_OPENVAS_CREDENTIALS_FILE'] = os.path.join(_state, 'openvas-credentials.json')
atexit.register(shutil.rmtree, _state, ignore_errors=True)

from client import daemon  # noqa: E402 - after the environment above, so nothing reads the real paths first



# Daemon threads a test left behind keep running into interpreter shutdown: one that logs (or writes the updater status, which fails and logs
# once the state directory above is gone) while the interpreter finalizes aborts the whole run with exit 134 ("could not acquire lock for
# <stderr> at interpreter shutdown"), after every test has passed. So at exit, and before the state directory is removed (atexit runs last in,
# first out, and this is registered after the removal): stop every Daemon the run made, give the threads a moment to end, and silence logging.
_daemons = weakref.WeakSet()
_init = daemon.Daemon.__init__


def _tracked_init(self, *args, **kwargs):
    _init(self, *args, **kwargs)
    _daemons.add(self)


daemon.Daemon.__init__ = _tracked_init


def _quiesce():
    for d in list(_daemons):
        d.stop_event.set()
    deadline = time.monotonic() + 10
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and thread is not threading.main_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
    logging.disable(logging.CRITICAL)  # whatever is still running must not write to a closing stderr


atexit.register(_quiesce)

daemon._detected['tools'] = []  # registration never probes the real tool binaries; a test that checks the probe sets its own
