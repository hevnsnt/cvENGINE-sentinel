"""The badkeys blocklist refresh (``client.badkeys``): a fake runner stands in for ``sshamble badkeys-update``, so nothing here uses the network."""
import json
import os
import random
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import badkeys, daemon

MANIFEST = json.dumps({'bkformat': 1, 'date': '2026-11-01', 'blocklist_url': 'https://example.com/b.xz', 'blocklists': [{'id': 1, 'name': 'git'}]})


def write_data(cache, manifest=MANIFEST, blocklist=b'\x01' * 64, lookup='abcdef0123456789;git/example/keys\n0000000000000001;git/example/other\n'):
    os.makedirs(cache, exist_ok=True)
    for name, data in (('badkeysdata.json', manifest), ('blocklist.dat', blocklist), ('lookup.txt', lookup)):
        if data is None:
            continue
        with open(os.path.join(cache, name), 'wb') as handle:
            handle.write(data.encode() if isinstance(data, str) else data)


class FakeRunner:
    def __init__(self, writer=write_data, raises=None, hook=None):
        self.calls, self.writer, self.raises, self.hook = [], writer, raises, hook

    def __call__(self, argv, timeout, env):
        self.calls.append({'argv': list(argv), 'timeout': timeout, 'env': dict(env)})
        if self.hook:
            self.hook()
        if self.raises:
            raise self.raises
        if self.writer:
            self.writer(os.path.join(env['HOME'], '.cache', 'badkeys'))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, 'badkeys')
        env = mock.patch.dict(os.environ, {'CVENGINE_BADKEYS_REFRESH': ''})
        env.start()
        self.addCleanup(env.stop)
        state = mock.patch.dict(badkeys._state, {'attempted_at': None, 'ok': None, 'error': ''})
        state.start()
        self.addCleanup(state.stop)

    def refresh(self, runner, now=None):
        return badkeys.refresh(runner=runner, root=self.root, now=now)

    def current_text(self, name='lookup.txt'):
        with open(os.path.join(self.root, 'current', name), encoding='utf-8') as handle:
            return handle.read()


class RefreshTests(Base):
    def test_a_successful_refresh_makes_the_new_data_current(self):
        runner = FakeRunner()
        result = self.refresh(runner, now=time.time())
        self.assertEqual(result['status'], 'updated')
        self.assertTrue(os.path.islink(os.path.join(self.root, 'current')))
        self.assertEqual(badkeys.data_dir(self.root), os.path.realpath(os.path.join(self.root, 'current')))
        self.assertEqual(badkeys.age_hours(self.root), 0)
        self.assertFalse(badkeys.needs_refresh(self.root))
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith('.staging-')], [], 'staging is removed')

    def test_a_second_refresh_swaps_atomically_and_keeps_the_previous_directory(self):
        self.refresh(FakeRunner(writer=lambda c: write_data(c, lookup='0000000000000001;old/path\n')), now=time.time() - 100)
        first = os.path.realpath(os.path.join(self.root, 'current'))
        self.refresh(FakeRunner(writer=lambda c: write_data(c, lookup='0000000000000002;new/path\n')), now=time.time())
        self.assertIn('new/path', self.current_text())
        self.assertTrue(os.path.isdir(first), 'the data a scan that already started may be reading stays')
        for _ in range(3):
            self.refresh(FakeRunner(), now=time.time() + 1)
        data = [n for n in os.listdir(self.root) if n.startswith('data-')]
        self.assertLessEqual(len(data), badkeys.KEEP_VERSIONS)

    def test_a_failed_refresh_keeps_the_old_data(self):
        self.refresh(FakeRunner(writer=lambda c: write_data(c, lookup='0000000000000001;old/path\n')), now=time.time())
        for runner in (FakeRunner(raises=RuntimeError('network down')), FakeRunner(writer=None),
                       FakeRunner(raises=subprocess.TimeoutExpired('sshamble', 1200))):
            result = self.refresh(runner)
            self.assertEqual(result['status'], 'failed')
            self.assertIn('old/path', self.current_text())
        self.assertFalse(badkeys.status(self.root)['last_ok'])
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith('.staging-')], [])

    def test_a_timeout_says_so(self):
        result = self.refresh(FakeRunner(raises=subprocess.TimeoutExpired('sshamble', 1200)))
        self.assertIn('timed out', result['detail'])
        self.assertIsNone(badkeys.data_dir(self.root))

    def test_corrupt_downloads_are_rejected_and_old_data_stays(self):
        self.refresh(FakeRunner(writer=lambda c: write_data(c, lookup='0000000000000001;old/path\n')), now=time.time())
        bad = {
            'empty blocklist': lambda c: write_data(c, blocklist=b''),
            'missing lookup': lambda c: write_data(c, lookup=None),
            'empty lookup': lambda c: write_data(c, lookup=''),
            'garbage lookup': lambda c: write_data(c, lookup='<html>error</html>\n'),
            'no separator': lambda c: write_data(c, lookup='abcdef\n'),
            'manifest not json': lambda c: write_data(c, manifest='<html>'),
            'manifest without blocklists': lambda c: write_data(c, manifest='{"date": "2026-11-01"}'),
            'manifest not an object': lambda c: write_data(c, manifest='[]'),
            'missing manifest': lambda c: write_data(c, manifest=None),
        }
        for label, writer in bad.items():
            with self.subTest(label):
                result = self.refresh(FakeRunner(writer=writer))
                self.assertEqual(result['status'], 'failed', label)
                self.assertIn('old/path', self.current_text())
        self.assertEqual([n for n in os.listdir(self.root) if n.startswith('data-')].__len__(), 1, 'nothing rejected was kept')

    def test_a_link_in_place_of_a_file_is_rejected(self):
        def writer(cache):
            write_data(cache)
            os.unlink(os.path.join(cache, 'blocklist.dat'))
            os.symlink('/etc/hostname', os.path.join(cache, 'blocklist.dat'))
        self.assertEqual(self.refresh(FakeRunner(writer=writer))['status'], 'failed')

    def test_the_command_is_badkeys_update_alone_with_the_staging_home_as_the_only_path(self):
        runner = FakeRunner()
        with mock.patch('client.tools.SSHAMBLE_BIN', 'sshamble'):
            self.refresh(runner)
        call = runner.calls[0]
        self.assertEqual(call['argv'], ['sshamble', 'badkeys-update'])
        self.assertEqual(call['timeout'], badkeys.REFRESH_TIMEOUT)
        home = call['env']['HOME']
        self.assertTrue(home.startswith(os.path.join(self.root, '.staging-')))
        self.assertTrue(set(call['env']) <= {'PATH', 'HOME', 'TERM', 'LC_ALL', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'https_proxy', 'http_proxy', 'no_proxy'})

    def test_no_environment_variable_changes_what_is_downloaded(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BADKEYS_URL': 'https://evil.example/'}):
            runner = FakeRunner()
            self.refresh(runner)
        self.assertEqual(runner.calls[0]['argv'][1:], ['badkeys-update'])
        self.assertNotIn('CVENGINE_BADKEYS_URL', runner.calls[0]['env'])
        self.assertFalse(hasattr(badkeys, 'URL'))

    def test_the_real_runner_gives_the_tool_a_timeout_and_bounded_output(self):
        seen = {}

        def fake_run(argv, timeout, register=None, max_bytes=None, env=None, ok_codes=(0,)):
            seen.update(argv=argv, timeout=timeout, max_bytes=max_bytes, env=env)
            write_data(os.path.join(env['HOME'], '.cache', 'badkeys'))
            return b''
        with mock.patch('client.tools._run', fake_run):
            self.assertEqual(badkeys.refresh(root=self.root)['status'], 'updated')
        self.assertEqual((seen['timeout'], seen['max_bytes']), (badkeys.REFRESH_TIMEOUT, badkeys.MAX_STDOUT))


class SwitchTests(Base):
    def test_the_flag_turns_the_refresh_off(self):
        for value in ('0', 'false', 'NO', 'off', ' 0 '):
            with mock.patch.dict(os.environ, {'CVENGINE_BADKEYS_REFRESH': value}):
                runner = FakeRunner()
                self.assertEqual(self.refresh(runner)['status'], 'disabled')
                self.assertEqual(runner.calls, [])
                self.assertFalse(os.path.exists(self.root))
                self.assertIsNone(badkeys.start(threading.Event()))
                self.assertFalse(badkeys.status(self.root)['refresh'])
        for value in ('', '1', 'yes'):
            with mock.patch.dict(os.environ, {'CVENGINE_BADKEYS_REFRESH': value}):
                self.assertTrue(badkeys.enabled())

    def test_the_daemon_starts_the_refresh_only_with_the_kind_and_the_tool(self):
        with mock.patch('client.badkeys.tools.sshamble_ready', return_value=False):
            self.assertIsNone(badkeys.start(threading.Event()))
        stop = threading.Event()
        stop.set()
        with mock.patch('client.badkeys.tools.sshamble_ready', return_value=True):
            thread = badkeys.start(stop)
        self.assertEqual(thread.name, 'sentinel-badkeys')
        thread.join(2)
        self.assertFalse(thread.is_alive())


class NeverRaisesTests(Base):
    def test_whatever_the_tool_or_the_disk_does_the_caller_gets_a_result(self):
        for raises in (RuntimeError('x'), OSError(28, 'No space left on device'), MemoryError(), subprocess.SubprocessError('y')):
            result = self.refresh(FakeRunner(raises=raises))
            self.assertEqual(result['status'], 'failed')
        self.assertEqual(badkeys.refresh(runner=FakeRunner(), root='')['status'], 'failed')
        with tempfile.NamedTemporaryFile() as handle:  # the "directory" is a file
            self.assertEqual(badkeys.refresh(runner=FakeRunner(), root=handle.name)['status'], 'failed')

    def test_the_loop_survives_a_refresh_that_blows_up_and_stops_on_request(self):
        stop = threading.Event()
        calls = []

        def boom(runner=None):
            calls.append(1)
            if len(calls) >= 2:
                stop.set()
            raise RuntimeError('refresh itself is broken')
        with mock.patch('client.badkeys.refresh', boom), mock.patch('client.badkeys.RETRY_SECONDS', 0), mock.patch('client.badkeys.START_DELAY_SECONDS', 0), \
                mock.patch('client.badkeys.next_delay', return_value=0):
            thread = threading.Thread(target=badkeys.run_forever, args=(stop,))
            thread.start()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(calls), 2)

    def test_the_status_never_raises_for_a_directory_that_is_not_there(self):
        self.assertEqual(badkeys.status(os.path.join(self.root, 'nope'))['present'], False)
        self.assertIsNone(badkeys.age_hours(''))


class OverlapTests(Base):
    def test_two_refreshes_never_overlap(self):
        started, release = threading.Event(), threading.Event()
        results = []

        def slow():
            started.set()
            release.wait(5)
        first = threading.Thread(target=lambda: results.append(self.refresh(FakeRunner(hook=slow))))
        first.start()
        self.assertTrue(started.wait(5))
        second_runner = FakeRunner()
        second = self.refresh(second_runner)
        release.set()
        first.join(5)
        self.assertEqual(second['status'], 'busy')
        self.assertEqual(second_runner.calls, [])
        self.assertEqual(results[0]['status'], 'updated')


class ScheduleTests(Base):
    def test_it_runs_soon_when_the_data_is_missing_or_a_day_old_and_otherwise_when_it_becomes_one(self):
        now = 1_800_000_000.0
        self.assertEqual(badkeys.next_delay(self.root, now), badkeys.START_DELAY_SECONDS)
        self.refresh(FakeRunner(), now=now - 25 * 3600)
        self.assertTrue(badkeys.needs_refresh(self.root, now))
        self.assertEqual(badkeys.next_delay(self.root, now), badkeys.START_DELAY_SECONDS)
        self.refresh(FakeRunner(), now=now - 3 * 3600)
        self.assertFalse(badkeys.needs_refresh(self.root, now))
        delay = badkeys.next_delay(self.root, now, rng=random.Random(1))
        self.assertGreaterEqual(delay, 21 * 3600)
        self.assertLessEqual(delay, 21 * 3600 + 0.1 * 24 * 3600)

    def test_the_interval_is_a_day_with_jitter(self):
        values = {badkeys.jittered_interval(random.Random(n)) for n in range(50)}
        self.assertGreater(len(values), 10)
        self.assertTrue(all(0.9 * 86400 <= v <= 1.1 * 86400 for v in values))

    def test_data_placed_by_hand_is_used_and_aged_by_its_file_time(self):
        write_data(self.root)
        old = time.time() - 50 * 3600 - 60
        os.utime(os.path.join(self.root, 'badkeysdata.json'), (old, old))
        self.assertEqual(badkeys.data_dir(self.root), self.root)
        self.assertEqual(badkeys.age_hours(self.root), 50)
        self.assertTrue(badkeys.needs_refresh(self.root))


class StatusTests(Base):
    def test_the_heartbeat_reports_the_age_of_the_data(self):
        with mock.patch('client.daemon.declared_kinds', return_value=['ssh_probe']), mock.patch('client.badkeys.tools.BADKEYS_DIR', self.root):
            self.assertEqual(daemon.info()['badkeys'], {'present': False, 'age_hours': None, 'refresh': True})
            self.refresh(FakeRunner(), now=time.time() - 7 * 3600 - 60)
            reported = daemon.info()['badkeys']
        self.assertEqual((reported['present'], reported['age_hours'], reported['refresh'], reported['last_ok']), (True, 7, True, True))

    def test_no_badkeys_status_without_the_kind(self):
        with mock.patch('client.daemon.declared_kinds', return_value=['nmap']):
            self.assertNotIn('badkeys', daemon.info())


if __name__ == '__main__':
    unittest.main()
