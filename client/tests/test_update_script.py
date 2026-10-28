"""scripts/update.sh against a local git origin and a stand-in `docker`: what each self-update setting lets it do, and what every run records.

The stand-in `docker` sends `docker compose exec ... python3 -m client.control` to the real module (against a temporary state directory) and
records `compose pull` and `compose up`; after `compose up` it writes the daemon status a rebuilt Sentinel would write. It proves the script's
decisions, not Docker itself.
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from client import control

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHIM = """#!/bin/sh
# stand-in docker: compose exec -T sentinel <command> runs the command here; pull and up are recorded
echo "docker $*" >> "$SHIM_LOG"
[ "$1" = compose ] || exit 0
shift
case "$1" in
  exec) shift; shift; shift; cd "$SENTINEL_SRC" && exec "$@" ;;
  up) cd "$SENTINEL_SRC" && python3 - <<PY
from client import control
import subprocess, os
head = subprocess.check_output(['git', '-C', os.environ['WORK'], 'rev-parse', '--short=12', 'HEAD'], text=True).strip()
control.set_draining(False)  # a recreated daemon starts undrained (client/daemon.py)
control.write_status(head, 0, {'setting': os.environ.get('SHIM_SETTING'), 'mode': 'manual', 'requested': False})
PY
  ;;
  *) exit 0 ;;
esac
"""


def put(path, text, mode='w'):
    with open(path, mode) as handle:
        handle.write(text)


def run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


@unittest.skipUnless(shutil.which('git') and shutil.which('sh') and shutil.which('python3'), 'needs git, sh and python3')
class UpdateScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-update-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.origin, self.work, self.bin, self.state = (os.path.join(self.tmp, n) for n in ('origin.git', 'work', 'bin', 'state'))
        for d in (self.bin, self.state):
            os.makedirs(d)
        git = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.test']
        self.git = git
        run(git + ['init', '-q', '--bare', '-b', 'main', self.origin], self.tmp)
        run(git + ['clone', '-q', self.origin, self.work], self.tmp)
        os.makedirs(os.path.join(self.work, 'scripts'))
        shutil.copy(os.path.join(ROOT, 'scripts', 'update.sh'), os.path.join(self.work, 'scripts', 'update.sh'))
        put(os.path.join(self.work, 'README'), 'one\n')
        run(git + ['checkout', '-q', '-b', 'main'], self.work)
        run(git + ['add', '-A'], self.work)
        run(git + ['commit', '-q', '-m', 'one'], self.work)
        run(git + ['push', '-q', 'origin', 'main'], self.work)
        put(os.path.join(self.bin, 'docker'), SHIM)
        os.chmod(os.path.join(self.bin, 'docker'), 0o755)
        self.log = os.path.join(self.tmp, 'docker.log')
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'SHIM_LOG': self.log, 'SENTINEL_SRC': ROOT, 'WORK': self.work,
                    'PYTHONPATH': ROOT, 'CVENGINE_SENTINEL_TOKEN_FILE': os.path.join(self.state, 'token.json'),
                    'CVENGINE_SENTINEL_DRAIN_TIMEOUT': '10', 'CVENGINE_SENTINEL_BRANCH': 'main'}
        self.env.pop('CVENGINE_SENTINEL_UPDATE', None)
        patch = mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_TOKEN_FILE': self.env['CVENGINE_SENTINEL_TOKEN_FILE']})
        patch.start()
        self.addCleanup(patch.stop)

    def publish(self):
        """A new commit on origin, as a release of the Sentinel would be."""
        other = os.path.join(self.tmp, 'other')
        run(self.git + ['clone', '-q', self.origin, other], self.tmp)
        put(os.path.join(other, 'README'), 'two\n', 'a')
        run(self.git + ['commit', '-q', '-am', 'two'], other)
        run(self.git + ['push', '-q', 'origin', 'main'], other)

    def head(self):
        return run(['git', 'rev-parse', '--short=12', 'HEAD'], self.work).stdout.strip()

    def status(self, setting, requested=False):
        control.write_status('v0', 0, {'setting': setting, 'mode': 'manual', 'requested': requested})
        self.env['SHIM_SETTING'] = setting

    def update(self, *args):
        return run(['sh', os.path.join(self.work, 'scripts', 'update.sh'), *args], self.work, self.env)

    def calls(self):
        try:
            with open(self.log) as handle:
                return handle.read()
        except OSError:
            return ''

    def test_off_never_changes_anything_and_says_so(self):
        self.publish()
        before = self.head()
        self.status('off', requested=True)
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.head(), before)
        self.assertNotIn('compose up', self.calls())
        info = control.updater_info()
        self.assertEqual((info['installed'], info['running'], info['last_result']), (True, True, 'off'))

    def test_manual_waits_until_an_administrator_asks(self):
        self.publish()
        before = self.head()
        self.status('manual')
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.head(), before)
        self.assertEqual(control.updater_info()['last_result'], 'waiting')
        self.assertEqual(control.read_update()['status'], 'waiting')

    def test_manual_with_a_request_updates_and_records_it(self):
        self.publish()
        before = self.head()
        self.status('manual', requested=True)
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotEqual(self.head(), before)
        self.assertIn('compose up -d --build', self.calls())
        self.assertEqual(control.updater_info()['last_result'], 'updated')
        self.assertEqual(control.read_update()['status'], 'done')
        self.assertFalse(control.is_draining())

    def test_automatic_updates_without_a_request(self):
        self.publish()
        before = self.head()
        self.status('automatic')
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotEqual(self.head(), before)
        self.assertEqual(control.updater_info()['last_result'], 'updated')

    def test_a_person_running_it_by_hand_with_now_updates_even_while_off(self):
        self.publish()
        before = self.head()
        self.status('off')
        out = self.update('--now')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotEqual(self.head(), before)

    def test_up_to_date_is_recorded_as_a_run(self):
        self.status('automatic')
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        info = control.updater_info()
        self.assertEqual((info['last_result'], info['running']), ('ok', True))
        self.assertNotIn('compose up', self.calls())

    def test_a_checkout_that_cannot_fast_forward_fails_cleanly_and_is_reported(self):
        self.publish()
        put(os.path.join(self.work, 'README'), 'local edit\n', 'a')
        run(self.git + ['commit', '-q', '-am', 'local'], self.work)  # a local commit: no fast-forward is possible
        before = self.head()
        self.status('automatic')
        out = self.update()
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(self.head(), before)
        self.assertEqual(control.updater_info()['last_result'], 'failed')
        self.assertIn('fast-forward', control.updater_info()['detail'])
        self.assertFalse(control.is_draining())  # a failed update never leaves the Sentinel drained


if __name__ == '__main__':
    unittest.main()
