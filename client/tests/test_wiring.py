"""Seams between the daemon and the OpenVAS client: the one-time sweep of leftover GVM objects, and stopping a slow handle without stalling the heartbeat."""
import threading
import time
import unittest
from unittest import mock

from client import daemon
from client.tests.test_daemon import FakeClient


def make_daemon():
    return daemon.Daemon('https://x.example', 'tok', client=FakeClient())


def run_threads_inline(**_kwargs):
    return mock.patch('client.daemon.threading.Thread', side_effect=lambda target, **kw: mock.Mock(start=target))


class SweepTests(unittest.TestCase):
    def test_leftover_gvm_objects_are_swept_once_when_the_stack_is_ready(self):
        d = make_daemon()
        with mock.patch('client.tools.gvm_available', return_value=True), mock.patch('client.tools.gvm_ready', return_value=True), \
                mock.patch('client.openvas.cleanup_orphans', return_value={'tasks': 1, 'targets': 1}) as sweep, run_threads_inline():
            d._sweep_gvm_orphans()
            d._sweep_gvm_orphans()
        sweep.assert_called_once_with()

    def test_nothing_is_swept_while_the_stack_is_absent_or_not_ready(self):
        d = make_daemon()
        with mock.patch('client.openvas.cleanup_orphans') as sweep, run_threads_inline():
            with mock.patch('client.tools.gvm_available', return_value=False):
                d._sweep_gvm_orphans()
            with mock.patch('client.tools.gvm_available', return_value=True), mock.patch('client.tools.gvm_ready', return_value=False):
                d._sweep_gvm_orphans()
        sweep.assert_not_called()
        self.assertFalse(d._gvm_swept)  # it will be tried again once the stack is ready

    def test_a_sweep_that_finds_nothing_or_returns_nothing_is_quiet(self):
        d = make_daemon()
        with mock.patch('client.tools.gvm_available', return_value=True), mock.patch('client.tools.gvm_ready', return_value=True), \
                mock.patch('client.openvas.cleanup_orphans', return_value=None), run_threads_inline():
            d._sweep_gvm_orphans()  # must not raise


class BackgroundKillTests(unittest.TestCase):
    def test_a_slow_handle_is_stopped_off_the_calling_thread(self):
        started, release = threading.Event(), threading.Event()

        class Slow:
            def poll(self):
                return None

            def kill(self):
                started.set()
                release.wait(5)
        begun = time.monotonic()
        daemon.Daemon._kill(Slow(), background=True)
        self.assertLess(time.monotonic() - begun, 1.0)  # the caller (the heartbeat thread) did not wait for the stop
        self.assertTrue(started.wait(2))
        release.set()

    def test_the_foreground_kill_still_waits_and_survives_a_failing_handle(self):
        class Broken:
            def poll(self):
                return None

            def kill(self):
                raise RuntimeError('gvmd gone')
        daemon.Daemon._kill(Broken())  # logged, never raised
        daemon.Daemon._kill(None)


if __name__ == '__main__':
    unittest.main()
