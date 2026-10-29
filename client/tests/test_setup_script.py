"""./setup.sh: the .env it writes, and the updater it installs by default (with a clear opt-out). scripts/install-updater.sh is replaced by a stub that
records it was called, and `sudo` by a stand-in that records its arguments and runs the command, so nothing is installed on the machine running the
tests."""
import os
import shutil
import stat
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
        shutil.copy(os.path.join(ROOT, 'docker-compose.override.yml.example'), self.tmp)
        self.bin = os.path.join(self.tmp, 'bin')
        os.makedirs(self.bin)
        self.sudo_calls = os.path.join(self.tmp, 'sudo.calls')
        put(os.path.join(self.bin, 'sudo'), f'#!/bin/sh\necho "$*" >> "{self.sudo_calls}"\n[ "$1" = -n ] && shift\nexec "$@"\n')
        os.chmod(os.path.join(self.bin, 'sudo'), 0o755)

    def setup(self, *args, fail=False, stdin=None, **extra):
        env = {k: v for k, v in os.environ.items() if k != 'CVENGINE_SENTINEL_BLOB'}
        env.update(STUB_FAIL='1' if fail else '', PATH=f'{self.bin}:{os.environ["PATH"]}', **extra)
        return subprocess.run(['bash', os.path.join(self.tmp, 'setup.sh'), *args], cwd=self.tmp, env=env, capture_output=True, text=True,
                              input=stdin, stdin=None if stdin is not None else subprocess.DEVNULL)

    def env_file(self):
        return read(os.path.join(self.tmp, '.env'))

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

    def test_a_rerun_changes_only_what_it_is_given_and_keeps_every_other_line(self):
        put(os.path.join(self.tmp, '.env'), '# mine\nCVENGINE_SENTINEL_BLOB=keep\nCVENGINE_SENTINEL_MAX_CONCURRENT=3\nCOMPOSE_PROFILES=\n'
            'CVENGINE_SENTINEL_NETWORK=internal\nCVENGINE_SENTINEL_NAME=lab\nOPENVAS_LOG_LEVEL=128')  # no newline at the end
        out = self.setup('--yes', '--no-updater', '--full')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        env = self.env_file()
        for line in ('# mine', 'CVENGINE_SENTINEL_BLOB=keep', 'CVENGINE_SENTINEL_MAX_CONCURRENT=3', 'CVENGINE_SENTINEL_NETWORK=internal',
                     'CVENGINE_SENTINEL_NAME=lab', 'OPENVAS_LOG_LEVEL=128', 'COMPOSE_PROFILES=openvas', 'CVENGINE_SENTINEL_PROFILE=full'):
            self.assertIn(line + '\n', env)
        self.assertEqual(env.count('COMPOSE_PROFILES='), 1)
        self.assertTrue(any(f.startswith('.env.bak.') for f in os.listdir(self.tmp)))

    def test_a_rerun_keeps_light_when_no_profile_is_given(self):
        self.assertEqual(self.setup('--yes', '--no-updater', '--light').returncode, 0)
        self.assertEqual(self.setup('--yes', '--no-updater').returncode, 0)
        self.assertIn('CVENGINE_SENTINEL_PROFILE=light\n', self.env_file())
        self.assertIn('COMPOSE_PROFILES=\n', self.env_file())

    def test_the_profile_the_daemon_reads_is_written_next_to_compose_profiles(self):
        self.assertEqual(self.setup('--yes', '--no-updater', '--light').returncode, 0)
        self.assertIn('CVENGINE_SENTINEL_PROFILE=light\n', self.env_file())
        out = self.setup('--yes', '--no-updater', '--full')
        self.assertIn('CVENGINE_SENTINEL_PROFILE=full\n', self.env_file())
        self.assertNotIn('--profile openvas down', out.stdout)

    def test_switching_full_to_light_says_how_to_stop_the_openvas_containers(self):
        self.assertEqual(self.setup('--yes', '--no-updater', '--full').returncode, 0)
        out = self.setup('--yes', '--no-updater', '--light')
        self.assertIn('docker compose --profile openvas down', out.stdout)

    def test_env_and_backups_are_private_and_ignored_by_git(self):
        put(os.path.join(self.tmp, '.env'), 'CVENGINE_SENTINEL_BLOB=old\n')
        os.chmod(os.path.join(self.tmp, '.env'), 0o644)
        self.assertEqual(self.setup('--yes', '--no-updater', '--blob', 'bmV3').returncode, 0)
        backups = [f for f in os.listdir(self.tmp) if f.startswith('.env')]
        self.assertGreaterEqual(len(backups), 2)
        for f in backups:
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.tmp, f)).st_mode), 0o600, f)
        self.assertNotIn('.env.new', backups)
        ignored = subprocess.run(['git', 'check-ignore', '--no-index', '.env', '.env.bak.20260101000000', 'docker-compose.override.yml', '.deployed-commit'],
                                 cwd=ROOT, capture_output=True, text=True).stdout.split()
        self.assertEqual(ignored, ['.env', '.env.bak.20260101000000', 'docker-compose.override.yml', '.deployed-commit'])
        self.assertNotEqual(subprocess.run(['git', 'check-ignore', '--no-index', '-q', '.env.example'], cwd=ROOT).returncode, 0)

    def test_the_file_is_never_written_with_a_permissive_umask(self):
        with open(os.path.join(self.tmp, 'setup.sh')) as handle:
            body = handle.read()
        self.assertLess(body.index('umask 077'), body.index('> .env.new'))

    def test_a_name_compose_would_mangle_is_refused(self):
        for bad in ('office lan #2', 'a$b', "it's", 'x"y'):
            out = self.setup('--yes', '--no-updater', '--name', bad)
            self.assertEqual(out.returncode, 2, bad)
            self.assertIn('the name may contain only', out.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, '.env')))
        self.assertEqual(self.setup('--yes', '--no-updater', '--name', 'office lan-2.b_c').returncode, 0)
        self.assertIn('CVENGINE_SENTINEL_NAME=office lan-2.b_c\n', self.env_file())

    def test_a_blob_outside_the_base64_alphabet_is_refused(self):
        out = self.setup('--yes', '--no-updater', '--blob', 'abc$def')
        self.assertEqual(out.returncode, 2)
        self.assertNotIn('abc$def', out.stdout + out.stderr)  # never echoed back

    def test_the_blob_can_come_from_stdin_or_the_environment(self):
        self.assertEqual(self.setup('--yes', '--no-updater', '--blob', '-', stdin='ZnJvbS1zdGRpbg==\n').returncode, 0)
        self.assertIn('CVENGINE_SENTINEL_BLOB=ZnJvbS1zdGRpbg==\n', self.env_file())
        self.assertEqual(self.setup('--yes', '--no-updater', CVENGINE_SENTINEL_BLOB='ZnJvbS1lbnY=').returncode, 0)
        self.assertIn('CVENGINE_SENTINEL_BLOB=ZnJvbS1lbnY=\n', self.env_file())

    def test_without_a_terminal_sudo_never_waits_for_a_password(self):
        out = self.setup('--yes', '--light')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        if os.geteuid() != 0:
            self.assertEqual(read(self.sudo_calls).split()[0], '-n')

    def test_the_marker_is_left_to_the_running_sentinel(self):
        out = self.setup('--yes', '--light')
        self.assertIn('once the Sentinel is up', out.stdout)

    def test_host_network_writes_the_ignored_override_file(self):
        out = self.setup('--yes', '--no-updater', '--host-network')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('network_mode: host', read(os.path.join(self.tmp, 'docker-compose.override.yml')))


if __name__ == '__main__':
    unittest.main()
