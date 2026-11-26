"""scripts/apparmor.sh in a temporary directory, with CVENGINE_SENTINEL_INSTALL_PREFIX standing in for / (so /sys, /proc, /etc and /usr/local are the
test's own) and stand-ins for `id` (root), `apparmor_parser` and `systemctl`. It proves the detection, what the script writes and refuses, and the
boot fallback; that the kernel really loads the profile and that the browser's sandbox then engages is proven in CI (.github/workflows/image.yml)."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(ROOT, 'config', 'apparmor', 'cvengine-sentinel')


def put(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, mode)


def read(path):
    with open(path) as handle:
        return handle.read()


@unittest.skipUnless(shutil.which('sh') and shutil.which('stat') and os.uname().sysname == 'Linux', 'needs Linux, sh and GNU stat')
class AppArmorScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-apparmor-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.prefix, self.bin = os.path.join(self.tmp, 'root'), os.path.join(self.tmp, 'bin')
        os.makedirs(os.path.join(self.prefix, 'run/systemd/system'))
        os.makedirs(self.bin)
        self.log = os.path.join(self.tmp, 'calls.log')
        put(os.path.join(self.bin, 'id'), '#!/bin/sh\n[ "$1" = -u ] && { echo "${FAKE_UID:-0}"; exit 0; }\nexec /usr/bin/id "$@"\n')
        put(os.path.join(self.bin, 'systemctl'), f'#!/bin/sh\necho "systemctl $*" >> "{self.log}"\n')
        put(os.path.join(self.bin, 'sudo'), f'#!/bin/sh\necho "sudo $*" >> "{self.log}"\n')
        # the parser: --version prints PARSER_VERSION; -Q (a parse check) fails when PARSE_FAIL is set, a load (-r) when LOAD_FAIL is set
        put(os.path.join(self.bin, 'apparmor_parser'), f'''#!/bin/sh
echo "apparmor_parser $*" >> "{self.log}"
case "$1" in
  --version) echo "AppArmor parser version ${{PARSER_VERSION:-4.1.8}}"; echo "Copyright (C) 1999-2008 Novell Inc." ;;
  -Q) [ -z "$PARSE_FAIL" ] ;;
  -r) [ -z "$LOAD_FAIL" ] ;;
esac
''')
        self.checkout = os.path.join(self.tmp, 'sentinel')
        os.makedirs(os.path.join(self.checkout, 'scripts'))
        shutil.copy(os.path.join(ROOT, 'scripts', 'apparmor.sh'), os.path.join(self.checkout, 'scripts'))
        shutil.copytree(os.path.join(ROOT, 'config', 'apparmor'), os.path.join(self.checkout, 'config', 'apparmor'))
        self.envfile = os.path.join(self.checkout, '.env')
        put(self.envfile, 'CVENGINE_SENTINEL_NAME=lab-1\nCOMPOSE_PROFILES=openvas', 0o600)  # no trailing newline: the new line must start its own
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'CVENGINE_SENTINEL_INSTALL_PREFIX': self.prefix}
        for key in ('CVENGINE_SENTINEL_APPARMOR', 'PARSE_FAIL', 'LOAD_FAIL', 'PARSER_VERSION', 'FAKE_UID'):
            self.env.pop(key, None)

    def apparmor(self, enabled=True, sysctl=None):
        put(os.path.join(self.prefix, 'sys/module/apparmor/parameters/enabled'), 'Y\n' if enabled else 'N\n', 0o644)
        if sysctl is not None:
            put(os.path.join(self.prefix, 'proc/sys/kernel/apparmor_restrict_unprivileged_userns'), f'{sysctl}\n', 0o644)

    def loaded(self, *names):
        d = os.path.join(self.prefix, 'sys/kernel/security/apparmor/policy/profiles')
        os.makedirs(d, exist_ok=True)
        for name in names:
            os.makedirs(os.path.join(d, name))

    def run_script(self, *args, script=None, **env):
        return subprocess.run(['sh', script or os.path.join(self.checkout, 'scripts', 'apparmor.sh'), *args], env={**self.env, **env},
                              capture_output=True, text=True)

    def calls(self):
        return read(self.log) if os.path.exists(self.log) else ''

    def at(self, path):
        return os.path.join(self.prefix, path)

    def note(self, **env):
        """What scripts/update.sh gets from the library: AA_NOTE and the exported fallback."""
        code = ('set -eu; CVENGINE_APPARMOR_LIB_ONLY=1; . ./scripts/apparmor.sh; aa_update_note .env config/apparmor/cvengine-sentinel; '
                'printf "NOTE=%s\\nOPT=%s\\n" "$AA_NOTE" "${CVENGINE_SENTINEL_APPARMOR:-}"')
        out = subprocess.run(['sh', '-c', code], cwd=self.checkout, env={**self.env, **env}, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        lines = dict(line.split('=', 1) for line in out.stdout.splitlines())
        return lines['NOTE'], lines['OPT']

    # --- the profile itself ---

    def test_the_profile_is_docker_default_plus_userns_under_the_sentinels_name(self):
        text = read(PROFILE)
        self.assertIn('abi <abi/4.0>,', text)
        self.assertIn('profile cvengine-sentinel flags=(attach_disconnected,mediate_deleted) {', text)
        self.assertIn('\n  userns,\n', text)
        self.assertIn('signal (send,receive) peer=cvengine-sentinel,', text)
        self.assertNotIn('cvengine-scanner', text.split('abi <abi/4.0>')[1])  # the server's name stays in the header comment only
        for kept in ('deny mount,', 'deny @{PROC}/sysrq-trigger rwklx,', 'deny /sys/kernel/security/** rwklx,', 'deny /sys/firmware/** rwklx,'):
            self.assertIn(kept, text)
        rules = [line.strip() for line in text.split('{', 1)[1].splitlines() if line.strip() and not line.strip().startswith('#')]
        self.assertEqual([r for r in rules if not r.startswith(('deny ', 'signal ', 'ptrace ', '}'))],
                         ['network,', 'capability,', 'file,', 'umount,', 'userns,'])

    # --- detection ---

    def test_a_host_without_apparmor_needs_nothing_and_nothing_is_written(self):
        self.apparmor(enabled=False)
        out = self.run_script('install')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('not needed: AppArmor is not enabled', out.stdout)
        self.assertNotIn('apparmor_parser -r', self.calls())
        self.assertFalse(os.path.exists(self.at('etc/apparmor.d/cvengine-sentinel')))
        self.assertNotIn('CVENGINE_SENTINEL_APPARMOR', read(self.envfile))

    def test_no_sys_at_all_counts_as_no_apparmor(self):
        out = self.run_script('install')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('not needed', out.stdout)
        self.assertEqual(os.listdir(self.prefix), ['run'])

    def test_apparmor_3_needs_nothing(self):
        self.apparmor()
        out = self.run_script('install', PARSER_VERSION='3.0.8')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('parser version 3 (below 4)', out.stdout)
        self.assertNotIn('apparmor_parser -r', self.calls())

    def test_apparmor_4_needs_it_with_or_without_the_ubuntu_sysctl(self):
        # Ubuntu's kernels say it with the sysctl; a Kali 7.1 kernel has no such sysctl and docker-default still denied userns_create there
        for sysctl, words in ((1, 'kernel.apparmor_restrict_unprivileged_userns=1'), (None, 'can refuse the user namespace')):
            with self.subTest(sysctl=sysctl):
                shutil.rmtree(os.path.join(self.prefix, 'proc'), ignore_errors=True)
                self.apparmor(sysctl=sysctl)
                out = self.run_script('status', FAKE_UID='1000')
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn('needed: yes', out.stdout)
                self.assertIn(words, out.stdout)

    def test_status_needs_no_root_and_changes_nothing(self):
        self.apparmor(sysctl=1)
        self.loaded('cvengine-sentinel.7', 'docker-default.3')
        before = read(self.envfile)
        out = self.run_script('status', FAKE_UID='1000')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('profile cvengine-sentinel: loaded', out.stdout)
        self.assertIn('the Sentinel runs under: docker-default', out.stdout)
        self.assertEqual(read(self.envfile), before)
        self.assertNotIn('sudo', self.calls())

    # --- install ---

    def test_install_loads_a_root_copy_installs_the_boot_unit_and_names_the_profile_in_env_in_place(self):
        self.apparmor(sysctl=1)
        inode = os.stat(self.envfile).st_ino
        out = self.run_script('install')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        etc = self.at('etc/apparmor.d/cvengine-sentinel')
        self.assertEqual(read(etc), read(PROFILE))
        self.assertEqual(os.stat(etc).st_mode & 0o777, 0o644)
        calls = self.calls()
        self.assertLess(calls.index('apparmor_parser -Q -K'), calls.index(f'apparmor_parser -r -W {etc}'))  # parsed before anything changes
        helper = self.at('usr/local/sbin/cvengine-sentinel-apparmor')
        self.assertEqual(read(helper), read(os.path.join(ROOT, 'scripts', 'apparmor.sh')))
        self.assertEqual(os.stat(helper).st_mode & 0o777, 0o755)
        unit = read(self.at('etc/systemd/system/cvengine-sentinel-apparmor.service'))
        self.assertIn('Before=docker.service\n', unit)
        self.assertIn('Type=oneshot\n', unit)
        self.assertIn(f'ExecStart={helper} boot --dir {self.checkout}\n', unit)  # root runs its own copy, never the checkout's
        self.assertIn('WantedBy=multi-user.target docker.service\n', unit)
        self.assertIn('systemctl daemon-reload', calls)
        self.assertIn('systemctl enable cvengine-sentinel-apparmor.service', calls)
        self.assertEqual(read(self.envfile), 'CVENGINE_SENTINEL_NAME=lab-1\nCOMPOSE_PROFILES=openvas\nCVENGINE_SENTINEL_APPARMOR=cvengine-sentinel\n')
        self.assertEqual(os.stat(self.envfile).st_ino, inode)
        self.assertEqual(os.stat(self.envfile).st_mode & 0o777, 0o600)
        self.assertIn('docker compose up -d sentinel', out.stdout)

    def test_install_twice_keeps_one_line(self):
        self.apparmor()
        for _ in range(2):
            self.assertEqual(self.run_script('install').returncode, 0)
        self.assertEqual(read(self.envfile).count('CVENGINE_SENTINEL_APPARMOR='), 1)

    def test_a_profile_the_parser_refuses_changes_nothing(self):
        self.apparmor()
        out = self.run_script('install', PARSE_FAIL='1')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('nothing changed', out.stderr)
        self.assertNotIn('apparmor_parser -r', self.calls())
        self.assertFalse(os.path.exists(self.at('etc/apparmor.d/cvengine-sentinel')))
        self.assertNotIn('CVENGINE_SENTINEL_APPARMOR', read(self.envfile))

    def test_a_failed_load_changes_nothing(self):
        self.apparmor()
        out = self.run_script('install', LOAD_FAIL='1')
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse(os.path.exists(self.at('etc/apparmor.d/cvengine-sentinel')))
        self.assertFalse(os.path.exists(self.at('etc/systemd/system/cvengine-sentinel-apparmor.service')))
        self.assertNotIn('CVENGINE_SENTINEL_APPARMOR', read(self.envfile))

    def test_not_root_runs_itself_again_under_sudo(self):
        self.apparmor()
        out = self.run_script('install', FAKE_UID='1000')
        self.assertIn(f'sudo sh {self.checkout}/scripts/apparmor.sh install --dir {self.checkout}', self.calls())
        self.assertNotIn('apparmor_parser -r', self.calls())

    def test_without_systemd_the_profile_still_goes_where_apparmor_loads_it_at_boot(self):
        self.apparmor()
        shutil.rmtree(self.at('run/systemd'))
        out = self.run_script('install')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(os.path.exists(self.at('etc/apparmor.d/cvengine-sentinel')))
        self.assertFalse(os.path.exists(self.at('etc/systemd/system/cvengine-sentinel-apparmor.service')))

    # --- boot and remove ---

    def test_boot_loads_the_root_copy(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        helper = self.at('usr/local/sbin/cvengine-sentinel-apparmor')
        out = self.run_script('boot', '--dir', self.checkout, script=helper)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.calls().count(f'apparmor_parser -r -W {self.at("etc/apparmor.d/cvengine-sentinel")}'), 2)
        self.assertIn('CVENGINE_SENTINEL_APPARMOR=cvengine-sentinel', read(self.envfile))

    def test_a_boot_that_cannot_load_it_takes_it_out_of_env_so_the_sentinel_still_starts(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        inode = os.stat(self.envfile).st_ino
        out = self.run_script('boot', '--dir', self.checkout, script=self.at('usr/local/sbin/cvengine-sentinel-apparmor'), LOAD_FAIL='1')
        self.assertEqual(out.returncode, 1)
        self.assertEqual(read(self.envfile), 'CVENGINE_SENTINEL_NAME=lab-1\nCOMPOSE_PROFILES=openvas\n')
        self.assertEqual(os.stat(self.envfile).st_ino, inode)

    def test_remove_takes_everything_out(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        out = self.run_script('remove')
        self.assertEqual(out.returncode, 0, out.stderr)
        for path in ('etc/apparmor.d/cvengine-sentinel', 'usr/local/sbin/cvengine-sentinel-apparmor', 'etc/systemd/system/cvengine-sentinel-apparmor.service'):
            self.assertFalse(os.path.exists(self.at(path)), path)
        self.assertNotIn('CVENGINE_SENTINEL_APPARMOR', read(self.envfile))
        self.assertIn('systemctl disable cvengine-sentinel-apparmor.service', self.calls())

    # --- what scripts/update.sh is told ---

    def test_update_note_names_the_root_step_on_a_host_that_needs_it(self):
        self.apparmor(sysctl=1)
        note, opt = self.note()
        self.assertIn('sudo scripts/apparmor.sh install', note)
        self.assertEqual(opt, '')

    def test_update_note_is_silent_where_nothing_is_needed_or_all_is_in_place(self):
        self.apparmor(enabled=False)
        self.assertEqual(self.note(), ('', ''))
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        self.loaded('cvengine-sentinel.4')
        self.assertEqual(self.note(), ('', ''))

    def test_a_profile_named_in_env_but_not_loaded_falls_back_to_dockers_default_for_the_run(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        self.loaded('docker-default.2')
        note, opt = self.note()
        self.assertEqual(opt, 'docker-default')
        self.assertIn('not loaded', note)

    def test_when_loading_cannot_be_seen_the_setting_is_kept(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        self.assertEqual(self.note(), ('', ''))  # no readable policy directory: unknown, never a reason to drop the profile

    def test_a_profile_changed_by_an_update_asks_for_the_root_step_again(self):
        self.apparmor()
        self.assertEqual(self.run_script('install').returncode, 0)
        self.loaded('cvengine-sentinel.4')
        with open(os.path.join(self.checkout, 'config', 'apparmor', 'cvengine-sentinel'), 'a') as handle:
            handle.write('# changed\n')
        note, opt = self.note()
        self.assertIn('changed in this update', note)
        self.assertEqual(opt, '')

    def test_update_sh_reads_it_before_the_sentinel_is_restarted(self):
        text = read(os.path.join(ROOT, 'scripts', 'update.sh'))
        self.assertIn('[ -f scripts/apparmor.sh ]', text)  # an older checkout has no such file
        self.assertLess(text.index('aa_update_note .env config/apparmor/cvengine-sentinel'), text.index('docker compose up -d $SENTINEL_SERVICES'))


if __name__ == '__main__':
    unittest.main()
