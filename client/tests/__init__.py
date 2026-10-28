"""Tests never touch the real state directory: the daemon writes its updater hand-off files beside the token file."""
import atexit
import os
import shutil
import tempfile

_state = tempfile.mkdtemp(prefix='sentinel-test-state-')
os.environ['CVENGINE_SENTINEL_TOKEN_FILE'] = os.path.join(_state, 'token.json')
atexit.register(shutil.rmtree, _state, ignore_errors=True)
