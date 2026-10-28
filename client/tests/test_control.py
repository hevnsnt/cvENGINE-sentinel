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
            self.assertEqual(daemon.info(), {'version': 'abc123def456', 'update': control.read_update()})
            fc = FakeClient()
            with mock.patch('client.tools.detect_tools', return_value=[]):
                daemon.register(fc, 'x', 1)
            self.assertEqual(fc.body_for('sentinel')['info']['version'], 'abc123def456')

    def test_an_unknown_or_odd_version_is_not_reported(self):
        for value in ('', 'has space', 'a' * 80, 'semi;colon'):
            with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_VERSION': value}):
                self.assertIsNone(config.version(), value)
                self.assertNotIn('version', daemon.info())

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
