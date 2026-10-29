"""Tests never touch the host: the daemon writes its updater hand-off files beside the token file, OpenVAS looks for its gvmd socket and
credentials at paths of its own, and the tool probe is never run for real. All of them point into a temporary directory for the test run."""
import atexit
import os
import shutil
import tempfile

_state = tempfile.mkdtemp(prefix='sentinel-test-state-')
os.environ['CVENGINE_SENTINEL_TOKEN_FILE'] = os.path.join(_state, 'token.json')
os.environ['CVENGINE_OPENVAS_SOCKET'] = os.path.join(_state, 'no-gvmd.sock')  # never created: GVM reads as not running unless a test fakes it
os.environ['CVENGINE_OPENVAS_CREDENTIALS_FILE'] = os.path.join(_state, 'openvas-credentials.json')
atexit.register(shutil.rmtree, _state, ignore_errors=True)

from client import daemon  # noqa: E402 - after the environment above, so nothing reads the real paths first

daemon._detected['tools'] = []  # registration never probes the real tool binaries; a test that checks the probe sets its own
