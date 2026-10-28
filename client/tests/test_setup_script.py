"""./setup.sh: the .env it writes, and the updater it installs by default (with a clear opt-out). scripts/install-updater.sh is replaced by a stub that
records it was called, so nothing is installed on the machine running the tests."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def put(path, text):
    with open(path, 'w') as handle:
        handle.write(text)


def read(path):
    with open(path) as handle:
        return handle.read()


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class SetupScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-setup-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        os.makedirs(os.path.join(self.tmp, 'scripts'))
        shutil.copy(os.path.join(ROOT, 'setup.sh'), self.tmp)
        self.calls = os.path.join(self.tmp, 'installer.calls')
        put(os.path.join(self.tmp, 'scripts', 'install-updater.sh'), f'#!/bin/sh\necho called >> "{self.calls}"\n[ -z "${{STUB_FAIL:-}}" ]\n')
        os.chmod(os.path.join(self.tmp, 'scripts', 'install-updater.sh'), 0o755)

    def setup(self, *args, fail=False):
        env = {**os.environ, 'STUB_FAIL': '1' if fail else ''}
        return subprocess.run(['bash', os.path.join(self.tmp, 'setup.sh'), *args], cwd=self.tmp, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def installed(self):
        return os.path.exists(self.calls)

    def test_the_updater_is_installed_by_default(self):
        out = self.setup('--yes', '--light', '--external', '--blob', 'b64')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertTrue(self.installed())
        self.assertIn('Updater installed', out.stdout)
        env = read(os.path.join(self.tmp, '.env'))
        self.assertIn('CVENGINE_SENTINEL_BLOB=b64', env)
        self.assertIn('# CVENGINE_SENTINEL_UPDATE=', env)  # left unset: cvENGINE decides

    def test_no_updater_is_the_clear_opt_out_and_says_how_to_add_it_later(self):
        out = self.setup('--yes', '--light', '--external', '--no-updater')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(self.installed())
        self.assertIn('sudo ./scripts/install-updater.sh', out.stdout)

    def test_a_failed_install_is_said_loudly_but_does_not_fail_the_setup(self):
        out = self.setup('--yes', '--light', '--external', fail=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('was NOT installed', out.stderr)
        self.assertIn('cannot update itself', out.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, '.env')))

    def test_help_lists_the_option_and_nothing_of_the_script_body(self):
        out = self.setup('--help')
        self.assertIn('--no-updater', out.stdout)
        self.assertNotIn('set -euo pipefail', out.stdout)

    def test_an_unknown_option_is_refused(self):
        self.assertEqual(self.setup('--nope').returncode, 2)


if __name__ == '__main__':
    unittest.main()
