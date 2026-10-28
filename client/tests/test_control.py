"""The hand-off between the daemon and the host-side updater: drain, status, the updater's own progress."""
import io
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

from client import config, control, daemon
from client.tests.test_daemon import FakeClient


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        patch = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_TOKEN_FILE': os.path.join(self.dir.name, 'token.json')})
        patch.start()
        self.addCleanup(patch.stop)


class DrainTests(Base):
    def test_a_drain_flag_expires_on_its_own_and_can_be_cleared(self):
        self.assertFalse(control.is_draining())
        control.set_draining(True)
        self.assertTrue(control.is_draining())
        self.assertFalse(control.is_draining(now=time.time() + control.DRAIN_TTL + 5))  # an updater that died never leaves a Sentinel drained
        control.set_draining(False)
        self.assertFalse(control.is_draining())

    def test_a_drained_daemon_polls_nothing(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        control.set_draining(True)
        with mock.patch('time.sleep') as sleep:
            d._poll_once()
        self.assertEqual(fc.paths(), [])
        sleep.assert_called()

    def test_a_daemon_start_clears_a_stale_drain_and_writes_its_status(self):
        control.set_draining(True)
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.request_stop()
        d.run()
        self.assertFalse(control.is_draining())
        self.assertEqual(control.read_status()['in_flight'], 0)


class StatusTests(Base):
    def test_idle_needs_a_fresh_status_with_no_task(self):
        self.assertFalse(control.idle())  # nothing written: the daemon is not running
        control.write_status('v1', 0, {'mode': 'manual', 'requested': False}, now=1000)
        self.assertTrue(control.idle(now=1050))
        self.assertFalse(control.idle(now=1000 + control.STATUS_MAX_AGE + 5))  # stale: the daemon stopped
        control.write_status('v1', 2, None, now=1000)
        self.assertFalse(control.idle(now=1001))

    def test_wanted_follows_the_mode_or_an_administrators_request(self):
        for update, expected in (({'mode': 'manual', 'requested': False}, False), ({'mode': 'auto', 'requested': False}, True),
                                 ({'mode': 'manual', 'requested': True}, True), (None, False)):
            control.write_status('v1', 0, update)
            self.assertEqual(control.wanted(), expected, update)
        self.assertFalse(control.wanted({}))

    def test_the_status_follows_each_task_not_only_the_heartbeat(self):
        fc = FakeClient()
        fc.next_responses = [{'task': {'id': 5, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        seen = []
        gate = __import__('threading').Event()

        def slow(*args, **kwargs):
            seen.append(control.read_status()['in_flight'])
            gate.wait(2)
            return {'hosts': []}
        with mock.patch.dict('client.tools.RUNNERS', {'nmap': slow}):
            d._poll_once()
            deadline = time.monotonic() + 3
            while not seen and time.monotonic() < deadline:
                time.sleep(0.01)
            gate.set()
            while d._active_count() and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertEqual(seen, [1])
        self.assertEqual(control.read_status()['in_flight'], 0)


class UpdateReportTests(Base):
    def test_progress_is_recorded_and_validated(self):
        control.record_update('draining', 'drain', '1 task running', 'abc', 'def')
        self.assertEqual(control.read_update(), {**control.read_update(), 'status': 'draining', 'phase': 'drain', 'from': 'abc', 'to': 'def'})
        with self.assertRaises(ValueError):
            control.record_update('exploding')

    def test_the_daemon_reports_its_version_and_the_updaters_state(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': 'abc123def456'}):
            control.record_update('done', 'up', 'ok', 'old', 'abc123def456')
            info = daemon.info()
            info.pop('openvas', None)  # the GVM readiness has its own test (test_daemon)
            self.assertEqual(info, {'version': 'abc123def456', 'update': control.read_update(), 'updater': {'installed': False, 'running': False}})
            fc = FakeClient()
            with mock.patch('client.tools.detect_tools', return_value=[]):
                daemon.register(fc, 'x', 1)
            self.assertEqual(fc.body_for('sentinel')['info']['version'], 'abc123def456')

    def test_an_unknown_or_odd_version_is_not_reported(self):
        for value in ('', 'has space', 'a' * 80, 'semi;colon'):
            with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': value}), mock.patch.object(config, 'build_version', return_value=None):
                self.assertIsNone(config.version(), value)
                self.assertNotIn('version', daemon.info())

    def test_the_commit_stamped_at_build_time_is_the_version_when_no_setting_names_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            stamp = os.path.join(tmp, 'VERSION')
            with open(stamp, 'w', encoding='utf-8') as handle:
                handle.write('47ffd47d2969')
            self.assertEqual(config.build_version(stamp), '47ffd47d2969')
            with mock.patch.object(config, 'BUILD_VERSION_FILE', stamp):
                with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': ''}):
                    self.assertEqual(config.version(), '47ffd47d2969')
                with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': 'abc123def456'}):
                    self.assertEqual(config.version(), 'abc123def456')  # the setting wins, as the updater writes it

    def test_a_missing_or_empty_build_stamp_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, 'VERSION')
            open(empty, 'w').close()
            self.assertIsNone(config.build_version(empty))
            self.assertIsNone(config.build_version(os.path.join(tmp, 'nope')))

    def test_the_command_line_drives_the_same_files(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(control.main(['drain']), 0)
            self.assertTrue(control.is_draining())
            self.assertEqual(control.main(['report', 'updating', '--phase', 'pull', '--from', 'a', '--to', 'b']), 0)
            self.assertEqual(control.main(['wanted']), 0)
            self.assertEqual(control.main(['undrain']), 0)
            self.assertEqual(control.main(['bogus']), 2)
        self.assertEqual(control.read_update()['phase'], 'pull')
        self.assertIn('no', out.getvalue())
        self.assertFalse(control.is_draining())

    def test_wait_idle_returns_when_idle_and_times_out_otherwise(self):
        control.write_status('v', 0, None)
        self.assertEqual(control.main(['wait-idle', '--timeout', '1']), 0)
        control.write_status('v', 3, None)
        with mock.patch('time.sleep'):
            clock = iter([0, 0, 10, 10, 10, 10])
            with mock.patch('time.time', side_effect=lambda: next(clock, 10)):
                self.assertEqual(control.main(['wait-idle', '--timeout', '5']), 1)


class SelfUpdateSettingTests(Base):
    """Off never updates, Manual only on an administrator's request, Automatic always; the server's most recent word, else this machine's own."""

    def status(self, setting, requested=False, mode='manual'):
        control.write_status('v1', 0, {'setting': setting, 'mode': mode, 'requested': requested})

    def test_off_manual_and_automatic(self):
        for setting, requested, expected in (('off', False, False), ('off', True, False), ('manual', False, False), ('manual', True, True),
                                             ('automatic', False, True), ('automatic', True, True)):
            self.status(setting, requested)
            self.assertEqual(control.wanted(), expected, (setting, requested))

    def test_an_older_server_with_no_setting_is_read_the_old_way(self):
        control.write_status('v1', 0, {'mode': 'auto', 'requested': False})
        self.assertEqual((control.setting(), control.wanted()), ('unknown', True))
        control.write_status('v1', 0, {'mode': 'manual', 'requested': False})
        self.assertFalse(control.wanted())

    def test_this_machines_own_setting_stands_in_until_the_server_says(self):
        control.write_status('v1', 0, {'mode': 'manual'})
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_UPDATE': 'automatic'}):
            self.assertEqual((control.setting(), control.wanted()), ('automatic', True))
            self.status('off')  # the server's later word beats the environment
            self.assertEqual((control.setting(), control.wanted()), ('off', False))

    def test_the_machines_own_setting_is_reported_only_when_stated_and_valid(self):
        self.assertNotIn('self_update', config.local_settings())
        for value, expected in (('Automatic', 'automatic'), (' off ', 'off'), ('sometimes', None), ('', None)):
            with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_UPDATE': value}):
                self.assertEqual(config.local_settings().get('self_update'), expected, value)

    def test_a_setting_from_the_server_is_applied_validated_and_clipped(self):
        try:
            config.set_overrides({'self_update': 'automatic'})
            self.assertEqual(config.self_update(), 'automatic')
            config.set_overrides({'self_update': 'rm -rf /'})  # data, never a command: anything unknown is dropped
            self.assertIsNone(config.self_update())
        finally:
            config.set_overrides({})

    def test_the_command_line_prints_the_setting(self):
        self.status('manual')
        out = io.StringIO()
        with redirect_stdout(out):
            control.main(['setting'])
        self.assertEqual(out.getvalue().strip(), 'manual')


class UpdaterStateTests(Base):
    """The daemon reports whether a host updater is installed and running, from the file every run of scripts/update.sh writes."""

    def test_no_file_means_not_installed(self):
        self.assertEqual(control.updater_info(), {'installed': False, 'running': False})

    def test_the_install_script_marks_it_installed_before_it_has_ever_run(self):
        control.record_updater(installed=True, now=1000)
        info = control.updater_info(now=1100)
        self.assertEqual((info['installed'], info['running']), (True, False))  # installed, but no run yet
        self.assertNotIn('last_run', info)

    def test_a_run_is_recorded_and_the_updater_counts_as_running_for_a_few_intervals(self):
        control.record_updater('waiting', 'update abc is available', now=1000)
        info = control.updater_info(now=1000 + 3600)
        self.assertEqual((info['installed'], info['running'], info['last_result'], info['detail']), (True, True, 'waiting', 'update abc is available'))
        self.assertTrue(info['last_run'].endswith('Z'))
        self.assertTrue(control.updater_info(now=1000 + int(3600 * control.UPDATER_SLACK))['running'])
        self.assertFalse(control.updater_info(now=1000 + int(3600 * control.UPDATER_SLACK) + 5)['running'])  # it stopped coming back

    def test_a_longer_interval_is_honoured_and_an_install_does_not_erase_the_last_run(self):
        control.record_updater('ok', 'up to date', interval=86400, now=1000)
        control.record_updater(installed=True, now=2000)
        info = control.updater_info(now=1000 + 86400)
        self.assertEqual((info['running'], info['last_result']), (True, 'ok'))

    def test_text_is_cleaned_and_clipped_and_removal_means_not_installed(self):
        control.record_updater('failed' * 20, 'x\x07y' * 200)
        info = control.updater_info()
        self.assertLessEqual(len(info['last_result']), 40)
        self.assertLessEqual(len(info['detail']), 300)
        self.assertNotIn('\x07', info['detail'])
        control.remove_updater()
        self.assertFalse(control.updater_info()['installed'])

    def test_the_heartbeat_carries_it(self):
        control.record_updater('ok', 'up to date at abc')
        self.assertEqual(daemon.info()['updater']['last_result'], 'ok')
        fc = FakeClient()
        with mock.patch('client.tools.detect_tools', return_value=[]):
            daemon.register(fc, 'x', 1)
        self.assertTrue(fc.body_for('sentinel')['info']['updater']['installed'])

    def test_the_command_line_writes_the_same_file(self):
        control.main(['updater-installed', '--interval', '7200'])
        self.assertEqual(control.updater_info(now=time.time())['installed'], True)
        control.main(['updater-run', 'failed', '--detail', 'git fetch failed'])
        info = control.updater_info()
        self.assertEqual((info['last_result'], info['detail'], info['running']), ('failed', 'git fetch failed', True))
        control.main(['updater-removed'])
        self.assertFalse(control.updater_info()['installed'])
