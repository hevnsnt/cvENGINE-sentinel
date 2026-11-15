"""install.sh and scripts/migrate-to-service-user.sh in a temporary directory, with CVENGINE_SENTINEL_INSTALL_PREFIX standing in for / and stand-ins for
`id`, `useradd`, `usermod`, `getent`, `docker`, `git`, `runuser`, `chown`, `install`, `stat`, `systemctl` and `sleep`, so no user is created and nothing is
installed on the machine running the tests. It proves the paths, the user-creation commands, the project-name guard, the order of the steps and the
refusals, and runs the real setup.sh and install-updater.sh inside the fake root. It does not prove that Docker starts a container or that useradd works."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BASH = shutil.which('bash') or 'bash'
SHARED = ('install.sh', 'setup.sh', 'docker-compose.yml', '.env.example', 'docker-compose.override.yml.example')
SCRIPTS = ('install-updater.sh', 'migrate-to-service-user.sh', 'update.sh', 'refresh-feeds.sh')


def put(path, text, mode=0o755):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as handle:
        handle.write(text)
    os.chmod(path, mode)


def read(path):
    with open(path) as handle:
        return handle.read()


def copy_repo(dest):
    """What a checkout of the repository holds that these scripts use, plus a fake .git that remembers its origin."""
    os.makedirs(os.path.join(dest, 'scripts'), exist_ok=True)
    for name in SHARED:
        shutil.copy(os.path.join(ROOT, name), dest)
    for name in SCRIPTS:
        shutil.copy(os.path.join(ROOT, 'scripts', name), os.path.join(dest, 'scripts'))
    return dest


@unittest.skipUnless(shutil.which('bash') and shutil.which('sh') and shutil.which('flock') and os.uname().sysname == 'Linux', 'needs Linux, bash, sh and flock')
class ServiceUserBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-svcuser-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.prefix, self.bin, self.state = (os.path.join(self.tmp, d) for d in ('root', 'bin', 'state'))
        for d in ('etc/systemd/system', 'etc/cron.d', 'var/log', 'run/systemd/system', 'opt', 'home'):
            os.makedirs(os.path.join(self.prefix, d))
        os.makedirs(self.bin)
        os.makedirs(self.state)
        self.log = os.path.join(self.tmp, 'calls.log')
        self.template = copy_repo(os.path.join(self.tmp, 'template'))
        self.make_stubs(self.bin)
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'CVENGINE_SENTINEL_INSTALL_PREFIX': self.prefix,
                    'CVENGINE_SENTINEL_TEST_REPO': 'https://example.com/test/cvengine-sentinel.git', 'STUB_STATE': self.state, 'STUB_LOG': self.log,
                    'STUB_TEMPLATE': self.template, 'STUB_VOLUMES': 'cvengine-sentinel_sentinel-state'}
        self.env.pop('CVENGINE_SENTINEL_BLOB', None)

    def make_stubs(self, bin_dir):
        log = '"$STUB_LOG"'
        put(os.path.join(bin_dir, 'id'), f'''#!/bin/sh
case "$*" in
  "-u") echo "${{FAKE_UID:-0}}" ;;
  "-u cvengine") echo 998 ;;
  "cvengine") [ -f "$STUB_STATE/user" ] ;;
  "-nG cvengine") if [ -f "$STUB_STATE/docker" ]; then echo "cvengine docker"; else echo cvengine; fi ;;
  *) exec /usr/bin/id "$@" ;;
esac
''')
        put(os.path.join(bin_dir, 'useradd'), f'#!/bin/sh\necho "useradd $*" >> {log}\ntouch "$STUB_STATE/user"\n')
        put(os.path.join(bin_dir, 'usermod'), f'#!/bin/sh\necho "usermod $*" >> {log}\ntouch "$STUB_STATE/docker"\n')
        put(os.path.join(bin_dir, 'getent'), '''#!/bin/sh
[ "$1" = group ] || exit 2
case "$2" in
  docker) [ -z "$STUB_NO_DOCKER_GROUP" ] ;;
  cvengine) [ -n "$STUB_GROUP_EXISTS" ] ;;
  *) exit 2 ;;
esac
''')
        put(os.path.join(bin_dir, 'docker'), f'''#!/bin/sh
echo "docker $*" >> {log}
case "$*" in
  "compose version") echo "Docker Compose version v2.0.0" ;;
  "volume inspect "*) case " $STUB_VOLUMES " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  "inspect "*) echo "${{STUB_HEALTH:-healthy}}" ;;
esac
exit 0
''')
        put(os.path.join(bin_dir, 'git'), f'''#!/bin/sh
echo "git $*" >> {log}
case "$1" in
  clone) mkdir -p "$3"; cp -a "$STUB_TEMPLATE"/. "$3"/; mkdir -p "$3/.git"; echo "$2" > "$3/.git/origin" ;;
  remote) cat "$PWD/.git/origin" ;;
esac
''')
        # runuser -u USER -- command...: run the command, remember who it was meant for (never its stdin, so the blob cannot be in the log)
        put(os.path.join(bin_dir, 'runuser'), f'#!/bin/sh\necho "runuser $*" >> {log}\nshift 3\nexec "$@"\n')
        put(os.path.join(bin_dir, 'chown'), f'#!/bin/sh\necho "chown $*" >> {log}\n')
        put(os.path.join(bin_dir, 'install'), f'''#!/bin/sh
echo "install $*" >> {log}
for last; do :; done
mkdir -p "$last"
''')
        put(os.path.join(bin_dir, 'stat'), '''#!/bin/sh
if [ "$1 $2" = "-c %U" ]; then cat "$STUB_STATE/owner" 2>/dev/null || echo cvengine; exit 0; fi
exec /usr/bin/stat "$@"
''')
        put(os.path.join(bin_dir, 'sudo'), f'#!/bin/sh\necho "sudo $*" >> {log}\n')
        put(os.path.join(bin_dir, 'systemctl'), f'#!/bin/sh\necho "systemctl $*" >> {log}\n')
        put(os.path.join(bin_dir, 'sleep'), '#!/bin/sh\nexit 0\n')

    def run_script(self, path, *args, stdin='', **env):
        return subprocess.run([BASH, path, *args], env={**self.env, **env}, input=stdin, capture_output=True, text=True)

    def calls(self):
        return read(self.log) if os.path.exists(self.log) else ''

    def unit(self, name):
        return read(os.path.join(self.prefix, 'etc/systemd/system', name))


class InstallTests(ServiceUserBase):
    BLOB = 'QUJDREVGR0hJSktMTU5PUA=='

    def install(self, *args, stdin=BLOB + '\n', **env):
        return self.run_script(os.path.join(ROOT, 'install.sh'), *args, stdin=stdin, **env)

    @property
    def dest(self):
        return os.path.join(self.prefix, 'opt/cvengine-sentinel')

    def test_a_fresh_install_creates_the_user_clones_as_it_and_never_runs_as_root(self):
        out = self.install('--light', '--internal', '--name', 'lab-1', '--yes', '--blob', '-')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        calls = self.calls()
        home = os.path.join(self.prefix, 'home/cvengine')
        useradd = [line for line in calls.splitlines() if line.startswith('useradd ')]
        self.assertEqual(len(useradd), 1)
        self.assertRegex(useradd[0], rf'^useradd --system --user-group --create-home --home-dir {home} --shell \S*(nologin|false) cvengine$')
        self.assertIn('usermod -aG docker cvengine', calls)
        self.assertIn(f'install -d -o cvengine -g cvengine -m 755 {self.dest}', calls)
        # the clone, setup.sh and compose up are all the service user's
        runs = [line for line in calls.splitlines() if line.startswith('runuser ')]
        self.assertTrue(runs and all(line.startswith('runuser -u cvengine -- env HOME=') for line in runs), runs)
        self.assertTrue(any(' git clone https://example.com/test/cvengine-sentinel.git ' in line for line in runs))
        self.assertTrue(any('./setup.sh --light --internal --name lab-1 --yes --no-updater --blob -' in line for line in runs))
        self.assertTrue(any(line.endswith('docker compose up -d') for line in runs))
        # the blob reached .env through stdin and is nowhere in what was run
        env = read(os.path.join(self.dest, '.env'))
        self.assertIn(f'CVENGINE_SENTINEL_BLOB={self.BLOB}\n', env)
        self.assertIn('CVENGINE_SENTINEL_NETWORK=internal\n', env)
        self.assertNotIn(self.BLOB, calls)
        self.assertNotIn(self.BLOB, out.stdout + out.stderr)
        self.assertEqual(os.stat(os.path.join(self.dest, '.env')).st_mode & 0o777, 0o600)
        # the updater runs as the service user from the new path
        service = self.unit('cvengine-sentinel-update.service')
        self.assertIn('User=cvengine\n', service)
        self.assertIn(f'WorkingDirectory={self.dest}\n', service)
        self.assertNotIn('--allow-root', calls)
        self.assertLess(calls.index('git clone'), calls.index('docker compose up -d'))
        # the summary says who, where and how much that is
        self.assertIn('User:       cvengine', out.stdout)
        self.assertIn(f'Directory:  {self.dest}', out.stdout)
        self.assertIn('equivalent to root', out.stdout)

    def test_the_blob_can_come_from_the_environment_and_still_goes_through_stdin(self):
        out = self.install('--light', '--external', '--yes', stdin='', CVENGINE_SENTINEL_BLOB=self.BLOB)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn(f'CVENGINE_SENTINEL_BLOB={self.BLOB}\n', read(os.path.join(self.dest, '.env')))
        self.assertNotIn(self.BLOB, self.calls())

    def test_running_it_again_reuses_everything_and_duplicates_nothing(self):
        self.assertEqual(self.install('--light', '--external', '--yes', '--blob', '-').returncode, 0)
        out = self.install('--light', '--external', '--yes', '--blob', '-')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        calls = self.calls()
        self.assertEqual(calls.count('useradd '), 1)
        self.assertEqual(calls.count('usermod '), 1)
        self.assertEqual(len([x for x in calls.splitlines() if x.startswith('git clone')]), 1)
        self.assertIn('Reusing the checkout', out.stdout)
        env = read(os.path.join(self.dest, '.env'))
        self.assertEqual(env.count('CVENGINE_SENTINEL_BLOB='), 1)
        self.assertEqual(env.count('CVENGINE_SENTINEL_UPDATER=installed'), 1)

    def test_no_updater_installs_none(self):
        out = self.install('--light', '--external', '--yes', '--no-updater', '--blob', '-')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/systemd/system')), [])
        self.assertIn('not installed', out.stdout)

    def test_a_group_left_behind_is_joined_not_recreated(self):
        out = self.install('--light', '--external', '--yes', '--blob', '-', STUB_GROUP_EXISTS='1')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        line = [x for x in self.calls().splitlines() if x.startswith('useradd ')][0]
        self.assertIn('-g cvengine', line)
        self.assertNotIn('--user-group', line)

    def test_dir_can_be_moved_but_not_under_root_or_to_an_odd_path(self):
        other = os.path.join(self.prefix, 'srv/sentinel')
        out = self.install('--light', '--external', '--yes', '--blob', '-', '--dir', other)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertTrue(os.path.exists(os.path.join(other, 'setup.sh')))
        self.assertIn(f'WorkingDirectory={other}\n', self.unit('cvengine-sentinel-update.service'))
        for bad, why in (('/root/cvengine-sentinel', 'cannot reach /root'), ('/root', 'cannot reach /root'), ('relative/dir', 'absolute'),
                         ('/opt/my sentinel', 'characters')):
            out = self.install('--yes', '--dir', bad)
            self.assertEqual(out.returncode, 1, bad)
            self.assertIn(why, out.stderr, bad)

    def test_refusals_happen_before_anything_is_created(self):
        cases = {
            'no docker group': (dict(STUB_NO_DOCKER_GROUP='1'), [], 1, "no 'docker' group"),
            'bad name': ({}, ['--name', 'a;b'], 2, 'letters, digits'),
            'bad blob': ({}, ['--blob', 'not a blob!'], 2, 'not a provisioning blob'),
            'unknown option': ({}, ['--nope'], 2, 'unknown option'),
        }
        for label, (env, args, code, message) in cases.items():
            with self.subTest(label):
                out = self.install('--yes', *args, **env)
                self.assertEqual(out.returncode, code, out.stdout + out.stderr)
                self.assertIn(message, out.stderr)
                self.assertNotIn('useradd', self.calls())
                self.assertFalse(os.path.exists(self.dest))

    def test_not_root_runs_itself_again_under_sudo_with_stdin_kept_and_the_blob_off_the_command_line(self):
        out = self.install('--light', '--external', '--yes', '--blob', '-', FAKE_UID='1000')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('running itself again with sudo', out.stderr)
        self.assertIn(f'sudo bash {os.path.join(ROOT, "install.sh")} --light --external --yes --blob -', self.calls())
        self.assertNotIn(self.BLOB, self.calls())
        self.assertNotIn('useradd', self.calls())  # the stub sudo did not run it, so nothing was created by this user

    def test_not_root_and_no_sudo_is_refused(self):
        bare = os.path.join(self.tmp, 'nosudo')
        os.makedirs(bare)
        self.make_stubs(bare)
        os.remove(os.path.join(bare, 'sudo'))
        out = self.install('--yes', FAKE_UID='1000', PATH=bare)
        self.assertEqual(out.returncode, 1)
        self.assertIn('run this as root', out.stderr)
        self.assertNotIn('useradd', self.calls())

    def test_docker_missing_is_refused_clearly(self):
        bare = os.path.join(self.tmp, 'bare')  # a PATH with the stubs but no docker at all
        os.makedirs(bare)
        self.make_stubs(bare)
        os.remove(os.path.join(bare, 'docker'))
        out = self.install('--yes', PATH=bare)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn('Docker is not installed', out.stderr)
        self.assertNotIn('useradd', self.calls())

    def test_a_checkout_that_is_not_the_service_users_is_refused_with_the_way_out(self):
        copy_repo(self.dest)
        os.makedirs(os.path.join(self.dest, '.git'))
        with open(os.path.join(self.state, 'owner'), 'w') as handle:
            handle.write('root\n')
        out = self.install('--yes')
        self.assertEqual(out.returncode, 1)
        self.assertIn('owned by root', out.stderr)
        self.assertIn('migrate-to-service-user.sh', out.stderr)

    def test_a_checkout_of_another_origin_is_refused(self):
        copy_repo(self.dest)
        put(os.path.join(self.dest, '.git', 'origin'), 'https://example.com/someone-else/fork.git\n')
        out = self.install('--yes')
        self.assertEqual(out.returncode, 1)
        self.assertIn('origin', out.stderr)
        self.assertNotIn('setup.sh', self.calls())

    def test_a_directory_with_other_things_in_it_is_refused(self):
        put(os.path.join(self.dest, 'precious.txt'), 'x', 0o644)
        out = self.install('--yes')
        self.assertEqual(out.returncode, 1)
        self.assertIn('not empty', out.stderr)

    def test_setup_sh_still_runs_by_hand_as_a_normal_user(self):
        """setup.sh is unchanged in behaviour: in a plain checkout, no root, no service user, it writes .env and says what to do next."""
        checkout = copy_repo(os.path.join(self.tmp, 'by-hand'))
        out = subprocess.run(['bash', os.path.join(checkout, 'setup.sh'), '--light', '--external', '--yes', '--no-updater', '--blob', '-'],
                             input=self.BLOB + '\n', capture_output=True, text=True, env=self.env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('Wrote .env: profile=light, network=external.', out.stdout)
        self.assertTrue(out.stdout.rstrip().endswith('Next: docker compose up -d'))
        self.assertNotIn('useradd', self.calls())


class MigrateTests(ServiceUserBase):
    def setUp(self):
        super().setUp()
        self.old = self.make_old(os.path.join(self.tmp, 'oldhome', 'cvengine-sentinel'))
        self.dest = os.path.join(self.prefix, 'opt/cvengine-sentinel')

    def make_old(self, path, updater=True):
        copy_repo(path)
        os.makedirs(os.path.join(path, '.git'))
        put(os.path.join(path, '.git', 'origin'), 'https://github.com/hevnsnt/cvengine-sentinel.git\n', 0o644)
        put(os.path.join(path, '.env'), 'CVENGINE_SENTINEL_BLOB=abc\nCVENGINE_SENTINEL_NAME=lab-1\n' + ('CVENGINE_SENTINEL_UPDATER=installed\n' if updater else ''), 0o600)
        put(os.path.join(path, 'docker-compose.override.yml'), 'services: {}\n', 0o644)
        put(os.path.join(path, 'notes-from-the-operator.txt'), 'keep me\n', 0o644)
        if updater:
            for name in ('update', 'feeds'):
                put(os.path.join(self.prefix, f'etc/systemd/system/cvengine-sentinel-{name}.service'), f'[Service]\nWorkingDirectory={path}\nUser=root\n', 0o644)
            put(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update'), f'17 * * * * root cd "{path}" && ./scripts/update.sh\n', 0o644)
        return path

    def migrate(self, *args, old=None, **env):
        old = old or self.old
        return self.run_script(os.path.join(old, 'scripts', 'migrate-to-service-user.sh'), '--from', old, '--wait', '0', *args, **env)

    def docker_lines(self):
        return [line for line in self.calls().splitlines() if line.startswith('docker ')]

    def test_the_whole_move_keeps_the_files_the_volumes_and_the_order(self):
        out = self.migrate()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertFalse(os.path.exists(self.old))
        self.assertEqual(read(os.path.join(self.dest, 'notes-from-the-operator.txt')), 'keep me\n')
        self.assertIn('CVENGINE_SENTINEL_NAME=lab-1', read(os.path.join(self.dest, '.env')))
        self.assertTrue(os.path.exists(os.path.join(self.dest, 'docker-compose.override.yml')))
        self.assertNotIn('COMPOSE_PROJECT_NAME', read(os.path.join(self.dest, '.env')))  # the pinned name already matches
        docker = self.docker_lines()
        down = [x for x in docker if ' down' in x]
        self.assertEqual(down, ['docker compose -p cvengine-sentinel down'])  # never -v
        up = [x for x in docker if x.endswith(' up -d')]
        self.assertEqual(up, ['docker compose -p cvengine-sentinel up -d'])
        calls = self.calls()
        self.assertLess(calls.index('useradd'), calls.index('compose -p cvengine-sentinel down'))
        self.assertLess(calls.index('compose -p cvengine-sentinel down'), calls.index(f'chown -R cvengine:cvengine {self.dest}'))
        self.assertLess(calls.index(f'chown -R cvengine:cvengine {self.dest}'), calls.index('compose -p cvengine-sentinel up -d'))
        self.assertIn('runuser -u cvengine -- env HOME=', calls)
        # the updater now points at the new path as the service user, and nothing points at the old one
        service = self.unit('cvengine-sentinel-update.service')
        self.assertIn('User=cvengine\n', service)
        self.assertIn(f'WorkingDirectory={self.dest}\n', service)
        self.assertNotIn(self.old, service + self.unit('cvengine-sentinel-feeds.service'))
        self.assertFalse(os.path.exists(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update')))
        self.assertIn('Before:  owner', out.stdout)
        self.assertIn(f'After:   owner cvengine, directory {self.dest}', out.stdout)
        self.assertIn('container cvengine-sentinel: healthy', out.stdout)

    def test_a_cron_entry_for_the_old_path_is_replaced_when_there_is_no_systemd(self):
        os.rmdir(os.path.join(self.prefix, 'run/systemd/system'))
        out = self.migrate()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        cron = read(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update'))
        self.assertIn(f'cd "{self.dest}"', cron)
        self.assertNotIn(self.old, cron)
        self.assertIn(' cvengine cd ', cron)

    def test_dry_run_prints_the_plan_and_changes_nothing(self):
        out = self.migrate('--dry-run')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('Plan to move the Sentinel', out.stdout)
        self.assertIn('Dry run: nothing was changed.', out.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.old, '.env')))
        self.assertFalse(os.path.exists(self.dest))
        calls = self.calls()
        for word in ('useradd', 'usermod', 'chown', ' down', ' up -d', 'runuser'):
            self.assertNotIn(word, calls)

    def test_a_directory_with_another_name_is_refused_unless_the_old_name_is_given(self):
        old = self.make_old(os.path.join(self.tmp, 'oldhome', 'My_Sentinel'))
        out = self.migrate(old=old)
        self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
        self.assertIn("'my_sentinel'", out.stderr)
        self.assertIn('--old-project-name my_sentinel', out.stderr)
        self.assertTrue(os.path.exists(old))
        self.assertNotIn(' down', self.calls())
        self.assertNotIn('useradd', self.calls())

        out = self.migrate('--old-project-name', 'my_sentinel', old=old)  # the volume my_sentinel_sentinel-state is not there
        self.assertEqual(out.returncode, 1)
        self.assertIn('no Docker volume my_sentinel_sentinel-state', out.stderr)
        self.assertTrue(os.path.exists(old))

        out = self.migrate('--old-project-name', 'my_sentinel', old=old, STUB_VOLUMES='my_sentinel_sentinel-state')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('COMPOSE_PROJECT_NAME=my_sentinel\n', read(os.path.join(self.dest, '.env')))
        self.assertIn('docker compose -p my_sentinel down', self.calls())
        self.assertIn('docker compose -p my_sentinel up -d', self.calls())

    def test_a_project_name_already_in_env_is_kept_without_the_flag(self):
        old = self.make_old(os.path.join(self.tmp, 'oldhome', 'sentinel'))
        with open(os.path.join(old, '.env'), 'a') as handle:
            handle.write('COMPOSE_PROJECT_NAME=sentinel\n')
        out = self.migrate(old=old, STUB_VOLUMES='sentinel_sentinel-state')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(read(os.path.join(self.dest, '.env')).count('COMPOSE_PROJECT_NAME='), 1)
        self.assertIn('docker compose -p sentinel up -d', self.calls())
        out = self.migrate('--old-project-name', 'other', old=old)
        self.assertNotEqual(out.returncode, 0)

    def test_an_install_without_an_updater_gets_none_unless_asked(self):
        old = self.make_old(os.path.join(self.tmp, 'noupdater', 'cvengine-sentinel'), updater=False)
        for name in os.listdir(os.path.join(self.prefix, 'etc/systemd/system')):
            os.remove(os.path.join(self.prefix, 'etc/systemd/system', name))
        os.remove(os.path.join(self.prefix, 'etc/cron.d/cvengine-sentinel-update'))
        out = self.migrate(old=old)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(os.listdir(os.path.join(self.prefix, 'etc/systemd/system')), [])
        out = self.migrate('--updater', '--dir', os.path.join(self.prefix, 'opt/second'), old=self.make_old(os.path.join(self.tmp, 'again', 'cvengine-sentinel'), updater=False))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('User=cvengine\n', self.unit('cvengine-sentinel-update.service'))

    def test_a_non_default_dir_whose_name_differs_gets_the_project_name_written_down(self):
        out = self.migrate('--dir', os.path.join(self.prefix, 'opt/lab-sentinel'))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('COMPOSE_PROJECT_NAME=cvengine-sentinel\n', read(os.path.join(self.prefix, 'opt/lab-sentinel/.env')))

    def test_a_run_interrupted_after_the_move_continues_without_moving_or_stopping_again(self):
        shutil.move(self.old, self.dest)
        out = self.run_script(os.path.join(self.dest, 'scripts', 'migrate-to-service-user.sh'), '--from', self.old, '--wait', '0')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotIn(' down', self.calls())
        self.assertIn('docker compose -p cvengine-sentinel up -d', self.calls())

    def test_refusals(self):
        put(os.path.join(self.dest, 'something'), 'x', 0o644)
        out = self.migrate()
        self.assertEqual(out.returncode, 1)
        self.assertIn('not empty', out.stderr)
        self.assertTrue(os.path.exists(self.old))
        shutil.rmtree(self.dest)
        out = self.migrate(FAKE_UID='1000')
        self.assertEqual(out.returncode, 1)
        self.assertIn('run this as root', out.stderr)
        out = self.migrate('--dir', '/root/new')
        self.assertEqual(out.returncode, 1)
        self.assertIn('cannot reach /root', out.stderr)
        out = self.migrate('--from', os.path.join(self.tmp, 'nowhere'))
        self.assertEqual(out.returncode, 1)
        self.assertIn('no Sentinel checkout found', out.stderr)
        self.assertEqual(self.migrate('--nope').returncode, 2)
        self.assertEqual(self.migrate('--wait', 'soon').returncode, 2)
        self.assertNotIn(' down', self.calls())

    def test_a_container_that_never_gets_healthy_is_reported_not_hidden(self):
        out = self.migrate(STUB_HEALTH='starting')
        self.assertEqual(out.returncode, 1)
        self.assertIn('container cvengine-sentinel: starting', out.stdout)
        self.assertIn('did not report healthy', out.stderr)
        self.assertTrue(os.path.exists(self.dest))  # it is moved and running; only the check failed


class ComposeProjectNameTests(unittest.TestCase):
    def test_the_project_name_is_pinned_to_what_a_checkout_called_cvengine_sentinel_always_got(self):
        self.assertRegex(read(os.path.join(ROOT, 'docker-compose.yml')), r'(?m)^name: cvengine-sentinel$')

    @unittest.skipUnless(shutil.which('docker'), 'needs the docker CLI (compose config needs no daemon)')
    def test_compose_resolves_that_name_whatever_the_directory_is_called_and_env_still_wins(self):
        import json
        tmp = tempfile.mkdtemp(prefix='sentinel-name-')
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        checkout = os.path.join(tmp, 'Some_Other.dir')
        os.makedirs(os.path.join(checkout, 'config', 'seccomp'))
        shutil.copy(os.path.join(ROOT, 'docker-compose.yml'), checkout)
        put(os.path.join(checkout, 'config', 'seccomp', 'playwright-chromium.json'), '{}', 0o644)

        def name(**env):
            out = subprocess.run(['docker', 'compose', 'config', '--format', 'json'], cwd=checkout, capture_output=True, text=True, env={**os.environ, **env})
            if out.returncode:
                self.skipTest('docker compose config is not usable here: ' + out.stderr[:200])
            return json.loads(out.stdout)['name']
        self.assertEqual(name(), 'cvengine-sentinel')
        self.assertEqual(name(COMPOSE_PROJECT_NAME='sentinel'), 'sentinel')
        # a checkout in a directory of exactly the old default name got that name before the pin: the volumes keep matching
        plain = os.path.join(tmp, 'cvengine-sentinel')
        shutil.copytree(checkout, plain)
        out = subprocess.run(['docker', 'compose', 'config', '--format', 'json'], cwd=plain, capture_output=True, text=True)
        if out.returncode == 0:
            self.assertEqual(json.loads(out.stdout)['name'], 'cvengine-sentinel')


if __name__ == '__main__':
    unittest.main()
