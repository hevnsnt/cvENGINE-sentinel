"""scripts/update.sh against a local git origin and a stand-in `docker`: what each self-update setting lets it do, and what every run records.

The stand-in `docker` sends `docker compose exec ... python3 -m client.control` to the real module (against a temporary state directory) and
records `compose pull`, `build` and `up` (each can be made to fail with SHIM_FAIL_PULL, SHIM_FAIL_BUILD or SHIM_FAIL_UP); after `compose up` it
writes the daemon status a rebuilt Sentinel would write. It proves the script's decisions, not Docker itself.
"""
import fcntl
import os
import shutil
import signal
import subprocess
import tempfile
import time
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
  pull) [ -z "${SHIM_FAIL_PULL:-}" ] ;;
  build) [ -z "${SHIM_FAIL_BUILD:-}" ] ;;
  up) [ -z "${SHIM_FAIL_UP:-}" ] || exit 1
    cd "$SENTINEL_SRC" && python3 - <<PY
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
        for name in ('update.sh', 'update-target.sh'):
            shutil.copy(os.path.join(ROOT, 'scripts', name), os.path.join(self.work, 'scripts', name))
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

    def origin_main(self):
        return run(['git', '--git-dir', self.origin, 'rev-parse', 'main'], self.work).stdout.strip()

    def status(self, setting, requested=False, target='tip'):
        target = self.origin_main() if target == 'tip' else target
        control.write_status('v0', 0, {'setting': setting, 'mode': 'manual', 'requested': requested, **({'target': target} if target else {})})
        self.env['SHIM_SETTING'] = setting

    def update(self, *args, **env):
        return run(['sh', os.path.join(self.work, 'scripts', 'update.sh'), *args], self.work, {**self.env, **env})

    def marker(self):
        try:
            with open(os.path.join(self.work, '.deployed-commit')) as handle:
                return handle.read().strip()[:12]
        except OSError:
            return ''

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
        calls = self.calls()  # built while the old Sentinel still works, then drained, then swapped
        self.assertLess(calls.index('compose build'), calls.index('client.control drain'))
        self.assertLess(calls.index('client.control drain'), calls.index('compose up -d'))
        self.assertEqual(self.marker(), self.head())
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

    def test_a_drain_timeout_that_is_not_a_positive_number_is_refused(self):
        for value in ('0', 'soon', '-5', '1.5'):
            out = self.update(CVENGINE_SENTINEL_DRAIN_TIMEOUT=value)
            self.assertEqual(out.returncode, 2, (value, out.stdout, out.stderr))
            self.assertIn('CVENGINE_SENTINEL_DRAIN_TIMEOUT', out.stderr)

    def test_up_to_date_is_recorded_as_a_run(self):
        # The running Sentinel reports HEAD (an install from before the deployed-commit marker): that counts as deployed, nothing is rebuilt.
        control.write_status(self.head(), 0, {'setting': 'automatic', 'mode': 'manual', 'requested': False})
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
        self.assertNotIn('client.control drain', self.calls())  # and a checkout that cannot update is never drained at all

    def test_a_running_openvas_scan_is_not_drained_for(self):
        self.publish()
        control.write_status('v0', 1, {'setting': 'automatic', 'mode': 'manual', 'requested': False, 'target': self.origin_main()}, kinds=['openvas'])
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(control.updater_info()['last_result'], 'waiting')
        self.assertIn('OpenVAS scan is running', control.updater_info()['detail'])
        self.assertIn('compose build', self.calls())  # the image is ready for the next run
        self.assertNotIn('client.control drain', self.calls())
        self.assertNotIn('compose up', self.calls())
        self.assertFalse(control.is_draining())

    def test_other_running_tasks_are_still_drained_for(self):
        self.publish()
        control.write_status('v0', 1, {'setting': 'automatic', 'mode': 'manual', 'requested': False, 'target': self.origin_main()}, kinds=['nmap'])
        out = self.update(CVENGINE_SENTINEL_DRAIN_TIMEOUT='1')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('client.control drain', self.calls())

    def test_a_dirty_checkout_is_refused_before_draining(self):
        self.publish()
        put(os.path.join(self.work, 'README'), 'local edit\n', 'a')
        self.status('automatic')
        out = self.update()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('cannot update', control.updater_info()['detail'])
        self.assertIn('local changes', control.updater_info()['detail'])
        self.assertNotIn('client.control drain', self.calls())
        self.assertNotIn('compose pull', self.calls())

    def test_an_untracked_ignored_file_does_not_block_the_update(self):
        self.publish()
        put(os.path.join(self.work, 'docker-compose.override.yml'), 'services: {}\n')
        self.status('automatic')
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(control.updater_info()['last_result'], 'updated')

    def test_a_checkout_on_another_branch_is_refused_before_draining(self):
        self.publish()
        run(self.git + ['checkout', '-q', '-b', 'mine'], self.work)
        self.status('automatic')
        out = self.update()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("is on 'mine', not main", control.updater_info()['detail'])
        self.assertNotIn('client.control drain', self.calls())

    def test_a_failed_pull_puts_the_checkout_back_and_never_drains(self):
        self.publish()
        before = self.head()
        self.status('automatic')
        out = self.update(SHIM_FAIL_PULL='1')
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(self.head(), before)
        info = control.updater_info()
        self.assertEqual(info['last_result'], 'failed')
        self.assertIn('pull failed', info['detail'])
        self.assertEqual(control.read_update()['status'], 'failed')
        self.assertNotIn('client.control drain', self.calls())
        self.assertFalse(control.is_draining())

    def test_a_failed_build_puts_the_checkout_back_and_the_next_run_tries_again(self):
        self.publish()
        before = self.head()
        self.status('automatic')
        out = self.update(SHIM_FAIL_BUILD='1')
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(self.head(), before)
        self.assertIn('build failed', control.updater_info()['detail'])
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotEqual(self.head(), before)
        self.assertEqual(control.updater_info()['last_result'], 'updated')

    def test_a_failure_after_the_fast_forward_is_retried_by_the_next_run(self):
        self.publish()
        self.status('automatic')
        out = self.update(SHIM_FAIL_UP='1')
        self.assertNotEqual(out.returncode, 0)
        target = self.head()  # the checkout stays on the new commit, but nothing reported it as deployed
        self.assertNotEqual(self.marker(), target)
        self.assertFalse(control.is_draining())
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertNotIn('up to date', out.stdout)
        self.assertEqual(self.calls().count('compose up -d'), 2)
        self.assertEqual(self.marker(), target)
        self.assertEqual(control.updater_info()['last_result'], 'updated')
        out = self.update()  # and now it is up to date
        self.assertIn('up to date', out.stdout)
        self.assertEqual(self.calls().count('compose up -d'), 2)

    # --- the commit an update moves to is the one cvENGINE named (SN-3) ---------------------------------------------------------------------

    def publish_two(self):
        """Two new commits on origin/main; returns (first, second) full ids."""
        self.publish()
        first = self.origin_main()
        self.publish()
        return first, self.origin_main()

    def assert_refused(self, out, words, before):
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.head(), before)  # the checkout is untouched
        info = control.updater_info()
        self.assertEqual(info['last_result'], 'failed')
        self.assertIn('cannot update', info['detail'])
        self.assertIn(words, info['detail'])
        self.assertEqual(control.read_update()['status'], 'failed')  # reported back to cvENGINE
        for call in ('compose pull', 'compose build', 'client.control drain', 'compose up'):
            self.assertNotIn(call, self.calls())  # nothing was built, drained or restarted: the running Sentinel keeps running
        self.assertFalse(control.is_draining())

    def test_a_target_older_than_the_fetched_head_moves_to_the_target_not_the_head(self):
        first, second = self.publish_two()
        self.status('automatic', target=first)
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(run(['git', 'rev-parse', 'HEAD'], self.work).stdout.strip(), first)
        self.assertNotEqual(first, second)
        self.assertEqual(self.marker(), first[:12])
        self.assertIn('cvENGINE named it', out.stdout)
        self.assertEqual(control.updater_info()['last_result'], 'updated')

    def test_a_short_target_is_resolved_and_the_commit_checked_out(self):
        self.publish()
        self.status('automatic', target=self.origin_main()[:9])
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(run(['git', 'rev-parse', 'HEAD'], self.work).stdout.strip(), self.origin_main())

    def assert_waiting_for_a_target(self, out, before):
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.head(), before)  # the checkout is untouched
        for call in ('compose pull', 'compose build', 'client.control drain', 'compose up'):
            self.assertNotIn(call, self.calls())
        info = control.updater_info()
        self.assertEqual(info['last_result'], 'waiting')  # not "failed": nothing is wrong on this machine
        self.assertIn('waiting: the server named no target', info['detail'])
        self.assertIn('--now', info['detail'])

    def test_automatic_without_a_target_waits_and_is_not_a_failure(self):
        # FB-7: with no target named (the server's "Keep Sentinels on the newest version" off, or no verdict from GitHub) the hourly run used to report "failed" every hour
        self.publish()
        before = self.head()
        self.status('automatic', target=None)
        self.assert_waiting_for_a_target(self.update(), before)
        self.assertEqual((control.read_update()['status'], control.read_update()['phase']), ('waiting', 'available'))
        self.assertIn('waiting: the server named no target', control.read_update()['detail'])

    def test_the_wait_for_a_target_is_reported_to_cvengine_once_a_day(self):
        self.publish()
        before = self.head()
        self.status('automatic', target=None)
        self.assert_waiting_for_a_target(self.update(), before)
        os.unlink(control._path('update.json'))
        self.assert_waiting_for_a_target(self.update(), before)  # the next hourly run: still recorded as the updater's own result, not reported again
        self.assertEqual(control.read_update(), {})
        old = time.time() - 25 * 3600
        os.utime(os.path.join(self.work, '.update-no-target'), (old, old))
        self.assert_waiting_for_a_target(self.update(), before)
        self.assertEqual(control.read_update()['status'], 'waiting')  # a day later it is said once more

    def test_a_requested_manual_update_without_a_target_waits_too(self):
        self.publish()
        before = self.head()
        self.status('manual', requested=True, target=None)
        self.assert_waiting_for_a_target(self.update(), before)

    def test_a_target_that_is_not_a_commit_id_is_refused(self):
        self.publish()
        before = self.head()
        self.status('manual')
        out = self.update('--to', 'origin/main')
        self.assert_refused(out, 'is not a commit id', before)

    def test_a_target_that_the_fetched_history_does_not_contain_is_refused(self):
        self.publish()
        before = self.head()
        self.status('automatic', target='0123456789abcdef0123456789abcdef01234567')
        self.assert_refused(self.update(), 'is not in the history fetched', before)

    def make_commit_on_other_branch(self):
        other = os.path.join(self.tmp, 'branchy')
        run(self.git + ['clone', '-q', self.origin, other], self.tmp)
        run(self.git + ['checkout', '-q', '-b', 'evil'], other)
        put(os.path.join(other, 'README'), 'evil\n', 'a')
        run(self.git + ['commit', '-q', '-am', 'evil'], other)
        run(self.git + ['push', '-q', 'origin', 'evil'], other)
        return run(['git', 'rev-parse', 'HEAD'], other).stdout.strip()

    def test_a_target_pushed_to_another_branch_is_not_an_update(self):
        self.publish()
        evil = self.make_commit_on_other_branch()
        before = self.head()
        self.status('automatic', target=evil)
        self.assert_refused(self.update(), 'is not in the history fetched', before)  # a branch-only fetch never brought it
        run(self.git + ['fetch', '-q', 'origin', 'evil'], self.work)  # and even with its objects already here it is not reachable from main
        self.assert_refused(self.update(), 'is not reachable from origin/main', before)

    def test_an_older_target_never_moves_a_sentinel_that_is_on_the_head(self):
        first, second = self.publish_two()
        self.status('automatic', target=second)
        self.assertEqual(self.update().returncode, 0)
        deployed = self.head()
        self.assertEqual(deployed, second[:12])
        self.status('automatic', target=first)  # the server (or whoever answers as it) names an older commit
        out = self.update()  # already on main's head: there is nothing to do, and certainly no move backwards
        self.assertIn('up to date', out.stdout)
        self.assertEqual(self.head(), deployed)
        self.assertEqual(self.marker(), deployed)
        self.assertEqual(self.calls().count('compose up -d'), 1)  # only the first update ever restarted anything

    def test_a_downgrade_is_never_made_and_is_waiting_not_a_failure(self):
        # FB-7: the server may pin an older commit than the Sentinel runs (a Sentinel that went ahead of its server): nothing moves, and the hourly run is not a failure
        first, second = self.publish_two()
        self.status('automatic', target=second)
        self.assertEqual(self.update().returncode, 0)
        self.publish()  # main moves on, so the deployed commit is no longer main's head and the early "up to date" exit does not apply
        self.status('automatic', target=first)
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(control.updater_info()['last_result'], 'waiting')
        self.assertIn('older than the one this Sentinel runs', control.updater_info()['detail'])
        self.assertEqual(self.head(), second[:12])
        self.assertEqual(self.calls().count('compose up -d'), 1)  # only the first update ever restarted anything

    def test_a_person_can_roll_back_only_with_the_explicit_flag(self):
        first, second = self.publish_two()
        self.status('automatic', target=second)
        self.assertEqual(self.update().returncode, 0)
        before = self.head()
        self.publish()
        out = self.update('--to', first)
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(self.head(), before)
        out = self.update('--to', first, '--allow-non-descendant')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(run(['git', 'rev-parse', 'HEAD'], self.work).stdout.strip(), first)
        self.assertEqual(self.marker(), first[:12])

    def test_the_flag_for_a_non_descendant_needs_a_person(self):
        out = self.update('--allow-non-descendant')
        self.assertEqual(out.returncode, 2, out.stdout + out.stderr)
        self.assertEqual(self.calls(), '')

    def test_a_person_with_no_target_moves_to_the_head_and_is_told_what_that_trusts(self):
        self.publish()
        self.status('off', target=None)
        out = self.update('--now')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(run(['git', 'rev-parse', 'HEAD'], self.work).stdout.strip(), self.origin_main())
        self.assertIn('head of origin/main', out.stdout)
        self.assertIn('trusted only as far as the repository is', out.stdout)

    def test_a_person_naming_a_target_gets_exactly_that_commit(self):
        first, second = self.publish_two()
        self.status('manual', target=None)
        out = self.update('--to', first[:12])
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(run(['git', 'rev-parse', 'HEAD'], self.work).stdout.strip(), first)

    def test_head_is_verified_before_anything_is_built(self):
        # A hook that moves HEAD after the merge stands for any way the checkout could end up elsewhere than the approved target.
        self.publish()
        before = self.head()
        hook = os.path.join(self.work, '.git', 'hooks', 'post-merge')
        put(hook, f'#!/bin/sh\ngit reset --hard --quiet {before}\n')
        os.chmod(hook, 0o755)
        self.status('automatic')
        out = self.update()
        self.assertNotEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.head(), before)
        self.assertIn('HEAD is not the target', control.updater_info()['detail'])
        for call in ('compose pull', 'compose build', 'client.control drain', 'compose up'):
            self.assertNotIn(call, self.calls())
        self.assertEqual(control.updater_info()['last_result'], 'failed')

    def test_the_exit_supervisor_follows_the_same_target_rules(self):
        with open(os.path.join(ROOT, 'scripts', 'pull-on-exit.sh')) as handle:
            text = handle.read()
        self.assertIn('. ./scripts/update-target.sh', text)
        self.assertIn('check_update_target', text)
        self.assertNotIn('git pull', text.replace('# ', '#'))  # no more "whatever origin/main is": it merges the named commit only
        self.assertIn('git merge --ff-only', text)
        self.assertIn('update-exit.json', text)  # where the daemon wrote the target it left for (client/selfupdate.py remember)

    def test_the_docs_say_what_automatic_trusts(self):
        with open(os.path.join(ROOT, 'README.md')) as handle:
            readme = handle.read()
        self.assertIn('What Automatic trusts', readme)
        self.assertIn('are not signature-checked in 1.4.0', readme)
        self.assertIn('CVENGINE_SENTINEL_UPDATE=manual', readme)


    def test_a_task_still_running_at_the_drain_deadline_is_waiting_not_a_failure(self):
        self.publish()
        control.write_status('v0', 1, {'setting': 'automatic', 'mode': 'manual', 'requested': False, 'target': self.origin_main()})
        out = self.update(CVENGINE_SENTINEL_DRAIN_TIMEOUT='1')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('compose build', self.calls())  # the image is built and ready for the next run
        self.assertNotIn('compose up', self.calls())
        self.assertEqual(control.updater_info()['last_result'], 'waiting')
        self.assertIn('still running', control.updater_info()['detail'])
        self.assertEqual(control.read_update()['status'], 'waiting')
        self.assertFalse(control.is_draining())

    def test_the_version_is_not_written_to_env_and_an_old_line_is_removed(self):
        self.publish()
        put(os.path.join(self.work, '.env'), 'CVENGINE_SENTINEL_VERSION=0123456789ab\nCVENGINE_SENTINEL_NAME=lab\nCVENGINE_SENTINEL_BLOB=abc')
        self.status('automatic')
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(os.path.join(self.work, '.env')) as handle:
            env = handle.read()
        self.assertNotIn('CVENGINE_SENTINEL_VERSION', env)
        self.assertEqual(env, 'CVENGINE_SENTINEL_NAME=lab\nCVENGINE_SENTINEL_BLOB=abc')  # the last line, with no newline, is left intact

    def test_no_env_file_is_created(self):
        self.publish()
        self.status('automatic')
        self.assertEqual(self.update().returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.work, '.env')))

    def test_another_user_is_refused_before_anything_runs(self):
        fake = os.path.join(self.tmp, 'fakeid')
        os.makedirs(fake)
        put(os.path.join(fake, 'id'), '#!/bin/sh\ncase "$1" in -un) echo someoneelse ;; -u) echo 4242 ;; *) exec /usr/bin/id "$@" ;; esac\n')
        os.chmod(os.path.join(fake, 'id'), 0o755)
        self.publish()
        self.status('automatic')
        out = self.update(PATH=f'{fake}:{self.env["PATH"]}')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('run the updater as', out.stdout)
        self.assertEqual(self.calls(), '')
        self.assertFalse(control.updater_info()['installed'])

    def test_the_lock_comes_first_and_a_second_run_changes_nothing(self):
        self.publish()
        self.status('automatic')
        fd = os.open(self.work, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        out = self.update()
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn('another update is running', out.stdout)
        self.assertEqual(self.calls(), '')  # not even the setting was read
        self.assertFalse(control.updater_info()['installed'])  # and no last result was overwritten

    def test_without_flock_it_refuses_to_run(self):
        bare = os.path.join(self.tmp, 'bare')
        os.makedirs(bare)
        for tool in ('sh', 'git', 'dirname', 'basename', 'stat', 'id', 'date', 'docker'):
            found = os.path.join(self.bin, tool) if tool == 'docker' else shutil.which(tool)
            os.symlink(found, os.path.join(bare, tool))
        out = self.update(PATH=bare)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('flock is not installed', out.stdout)
        self.assertEqual(self.calls(), '')

    def test_sigterm_while_draining_undrains_and_records_a_failure(self):
        self.publish()
        control.write_status('v0', 1, {'setting': 'automatic', 'mode': 'manual', 'requested': False, 'target': self.origin_main()})
        proc = subprocess.Popen(['sh', os.path.join(self.work, 'scripts', 'update.sh')], cwd=self.work, start_new_session=True,
                                env={**self.env, 'CVENGINE_SENTINEL_DRAIN_TIMEOUT': '120'}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while not control.is_draining() and time.time() < deadline:
            time.sleep(0.2)
        self.assertTrue(control.is_draining())
        os.killpg(proc.pid, signal.SIGTERM)  # what systemd does to the whole unit
        proc.communicate(timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(control.is_draining())
        self.assertEqual(control.updater_info()['last_result'], 'failed')


FEEDS_SHIM = """#!/bin/sh
echo "docker $*" >> "$SHIM_LOG"
case "$2" in
  ps) printf '%s\\n' $SHIM_RUNNING ;;
  exec) echo "$SHIM_STATUS" ;;
esac
"""


@unittest.skipUnless(shutil.which('sh') and shutil.which('flock'), 'needs sh and flock')
class RefreshFeedsTests(unittest.TestCase):
    """scripts/refresh-feeds.sh with a stand-in `docker` that says which services run and what the Sentinel's status is."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='sentinel-feeds-')
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        os.makedirs(os.path.join(self.tmp, 'scripts'))
        os.makedirs(os.path.join(self.tmp, 'bin'))
        shutil.copy(os.path.join(ROOT, 'scripts', 'refresh-feeds.sh'), os.path.join(self.tmp, 'scripts'))
        put(os.path.join(self.tmp, 'bin', 'docker'), FEEDS_SHIM)
        os.chmod(os.path.join(self.tmp, 'bin', 'docker'), 0o755)
        self.log = os.path.join(self.tmp, 'docker.log')

    def refresh(self, running, in_flight):
        env = {**os.environ, 'PATH': f'{self.tmp}/bin:{os.environ["PATH"]}', 'SHIM_LOG': self.log, 'SHIM_RUNNING': running,
               'SHIM_STATUS': '{"version": "abc", "in_flight": %d}' % in_flight}
        out = run(['sh', os.path.join(self.tmp, 'scripts', 'refresh-feeds.sh')], self.tmp, env)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        with open(self.log) as handle:
            return out.stdout, handle.read()

    def test_an_idle_openvas_stack_pulls_and_recreates_only_the_feeds(self):
        _, calls = self.refresh('sentinel openvas-gvmd openvas-ospd', 0)
        self.assertIn('compose pull --quiet openvas-vulnerability-tests openvas-notus-data', calls)
        up = [line for line in calls.splitlines() if ' up ' in line]
        self.assertEqual(len(up), 1)
        self.assertIn('up -d --no-deps', up[0])
        for program in ('openvas-gvmd', 'openvas-ospd', 'openvas-pg-gvm', 'sentinel '):
            self.assertNotIn(program, up[0])

    def test_a_running_task_leaves_everything_alone(self):
        out, calls = self.refresh('sentinel openvas-gvmd', 1)
        self.assertEqual(out, '')
        self.assertNotIn('pull', calls)

    def test_a_light_stack_leaves_everything_alone(self):
        out, calls = self.refresh('sentinel', 0)
        self.assertEqual(out, '')
        self.assertNotIn('pull', calls)
        self.assertNotIn('exec', calls)


if __name__ == '__main__':
    unittest.main()
