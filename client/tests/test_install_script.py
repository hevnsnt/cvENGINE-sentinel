"""scripts/install-updater.sh in a temporary directory, with CVENGINE_SENTINEL_INSTALL_PREFIX standing in for / and stand-ins for `id` (root),
`systemctl` and `docker`, so nothing is installed on the machine running the tests. It proves what the script writes and refuses, not systemd."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ME = subprocess.run(['id', '-un'], capture_output=True, text=True).stdout.strip()


def put(path, text, mode=0o755):
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, mode)


def read(path):
    with open(path) as handle:
        return handle.read()


@unittest.skipUnless(shutil.which('sh') and shutil.which('stat') and os.uname().sysname == 'Linux', 'needs Linux, sh and GNU stat')
class InstallUpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-install-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.prefix, self.bin = os.path.join(self.tmp, 'root'), os.path.join(self.tmp, 'bin')
        for d in ('etc/systemd/system', 'etc/cron.d', 'var/log', 'run/systemd/system'):
            os.makedirs(os.path.join(self.prefix, d))
        os.makedirs(self.bin)
        self.log = os.path.join(self.tmp, 'calls.log')
        put(os.path.join(self.bin, 'id'), '#!/bin/sh\n[ "$1" = -u ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n')
        for tool in ('systemctl', 'docker'):
            put(os.path.join(self.bin, tool), f'#!/bin/sh\necho "{tool} $*" >> "{self.log}"\n')
        self.checkout = self.make_checkout(os.path.join(self.tmp, 'sentinel'))
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'CVENGINE_SENTINEL_INSTALL_PREFIX': self.prefix}

    def make_checkout(self, path):
        os.makedirs(os.path.join(path, 'scripts'))
        shutil.copy(os.path.join(ROOT, 'scripts', 'install-updater.sh'), os.path.join(path, 'scripts'))
        return path

    def install(self, *args, checkout=None, **env):
        return subprocess.run(['sh', os.path.join(checkout or self.checkout, 'scripts', 'install-updater.sh'), *args],
                              env={**self.env, **env}, capture_output=True, text=True)

    def unit(self, name):
        return read(os.path.join(self.prefix, 'etc/systemd/system', name))

    def calls(self):
        return read(self.log) if os.path.exists(self.log) else ''

    def test_systemd_units_run_as_the_owner_with_a_timeout_and_hardening(self):
        out = self.install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        service = self.unit('cvengine-sentinel-update.service')
        self.assertIn(f'User={ME}\n', service)
        self.assertIn(f'ExecStart="{self.checkout}/scripts/update.sh"', service)
        for line in ('TimeoutStartSec=3h', 'NoNewPrivileges=true', 'PrivateTmp=true', 'ProtectSystem=full'):
            self.assertIn(line + '\n', service)
        self.assertIn(f'ExecStart="{self.checkout}/scripts/refresh-feeds.sh"', self.unit('cvengine-sentinel-feeds.service'))
        self.assertIn('OnCalendar=daily', self.unit('cvengine-sentinel-feeds.timer'))
        self.assertIn('enable --now cvengine-sentinel-update.timer cvengine-sentinel-feeds.timer', self.calls())

    def test_installing_systemd_removes_a_stale_cron_entry_and_the_reverse(self):
        cron = os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update')
        put(cron, 'old\n', 0o644)
        self.assertEqual(self.install().returncode, 0)
        self.assertFalse(os.path.exists(cron))
        os.rmdir(os.path.join(self.prefix, 'run/systemd/system'))  # no systemd now: cron instead
        out = self.install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertTrue(os.path.exists(cron))
        self.assertFalse(os.path.exists(os.path.join(self.prefix, 'etc/systemd/system/cvengine-sentinel-update.service')))

    def test_cron_runs_as_the_owner_with_a_log_the_owner_can_write(self):
        os.rmdir(os.path.join(self.prefix, 'run/systemd/system'))
        out = self.install()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        cron = read(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update'))
        logfile = os.path.join(self.prefix, 'var/log/cvengine-sentinel-update.log')
        self.assertIn(f'17 * * * * {ME} cd "{self.checkout}" && ./scripts/update.sh >> "{logfile}" 2>&1\n', cron)
        self.assertIn('./scripts/refresh-feeds.sh', cron)
        self.assertEqual(subprocess.run(['stat', '-c', '%U', logfile], capture_output=True, text=True).stdout.strip(), ME)

    def test_a_path_the_timer_cannot_quote_safely_is_refused(self):
        odd = self.make_checkout(os.path.join(self.tmp, 'my sentinel'))
        out = self.install(checkout=odd)
        self.assertEqual(out.returncode, 1)
        self.assertIn('characters the timer cannot use', out.stderr)
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/systemd/system')), [])

    def fake_stat(self, owner):
        put(os.path.join(self.bin, 'stat'), f'#!/bin/sh\necho {owner}\n')

    def test_an_unknown_owner_is_refused(self):
        put(os.path.join(self.bin, 'stat'), '#!/bin/sh\nexit 1\n')
        out = self.install()
        self.assertEqual(out.returncode, 1)
        self.assertIn('cannot tell which user owns', out.stderr)

    def test_a_root_owned_checkout_needs_allow_root(self):
        self.fake_stat('root')
        out = self.install()
        self.assertEqual(out.returncode, 1)
        self.assertIn('--allow-root', out.stderr)
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/systemd/system')), [])
        out = self.install('--allow-root')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('User=root\n', self.unit('cvengine-sentinel-update.service'))

    def test_non_linux_is_refused(self):
        put(os.path.join(self.bin, 'uname'), '#!/bin/sh\necho Darwin\n')
        out = self.install()
        self.assertEqual(out.returncode, 1)
        self.assertIn('only on Linux', out.stderr)

    def test_remove_takes_out_both_timers_and_the_cron_entry(self):
        self.assertEqual(self.install().returncode, 0)
        put(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update'), 'old\n', 0o644)
        out = self.install('--remove')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/systemd/system')), [])
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/cron.d')), [])
        self.assertIn('disable --now cvengine-sentinel-update.timer cvengine-sentinel-feeds.timer', self.calls())
        self.assertIn('updater-removed', self.calls())

    def test_an_unknown_option_is_refused(self):
        self.assertEqual(self.install('--nope').returncode, 2)


if __name__ == '__main__':
    unittest.main()
