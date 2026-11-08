"""Why web_screenshot was never claimed while other kinds were: a task the server took back that never ended kept its slot and its share of the memory
budget, and the memory admission let cheap kinds in whenever they fitted, so Chromium's 400 MB was never free. Each test fails on the code before the fix."""
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from client import admission, daemon, tools
from client.tests.test_daemon import FakeClient


def make(budget=1540, max_concurrent=6):
    d = daemon.Daemon('https://cve.example.test', 'tok', client=FakeClient(), max_concurrent=max_concurrent)
    d.admission = admission.Admission(budget)
    d.stop_event.wait = mock.Mock(return_value=False)
    return d


def hold(d, task_id, kind, age=5.0, **extra):
    proc = mock.Mock()
    proc.poll.return_value = None
    state = {'proc': proc, 'done': threading.Event(), 'started': time.monotonic() - age, 'dropped': False, 'finishing': False, 'kind': kind, **extra}
    d._in_flight[task_id] = state
    return state, proc


KINDS = ['nuclei_light', 'nuclei_targeted', 'http_probe', 'naabu', 'web_screenshot']


class TakenBackTests(unittest.TestCase):
    def test_a_taken_back_task_is_asked_to_stop_then_killed_then_given_up_whatever_it_does(self):
        d = make()
        state, proc = hold(d, 7, 'naabu', age=600)
        d._reconcile([])  # the server no longer lists it
        self.assertTrue(state['dropped'])
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()
        d._reconcile([])  # a second heartbeat does not log or signal again
        proc.terminate.assert_called_once()
        t0 = state['dropped_at']
        d._reap_dropped(now=t0 + daemon.TAKEN_BACK_KILL_SECONDS - 1)
        proc.kill.assert_not_called()
        d._reap_dropped(now=t0 + daemon.TAKEN_BACK_KILL_SECONDS + 1)
        deadline = time.monotonic() + 3
        while not proc.kill.called and time.monotonic() < deadline:
            time.sleep(0.01)
        proc.kill.assert_called()
        self.assertIn(7, d._in_flight)  # killed, but its thread has not ended: still counted
        d._reap_dropped(now=t0 + daemon.TAKEN_BACK_EVICT_SECONDS + 1)
        self.assertNotIn(7, d._in_flight)  # slot and memory are free again, though the thread never returned
        self.assertTrue(state['done'].is_set())
        self.assertEqual(d._active_count(), 0)
        self.assertEqual(d.admission.used([s.get('kind') for s in d._in_flight.values()]), 0)

    def test_a_task_with_no_process_at_all_is_still_given_up(self):
        d = make()
        state, _ = hold(d, 8, 'naabu', age=600)
        state['proc'] = None  # the worker never got as far as starting a tool
        d._reconcile([])
        d._reap_dropped(now=state['dropped_at'] + daemon.TAKEN_BACK_EVICT_SECONDS + 1)
        self.assertNotIn(8, d._in_flight)

    def test_a_task_that_ends_on_its_own_is_left_alone_and_a_shutdown_is_not_reaped(self):
        d = make()
        state, proc = hold(d, 9, 'naabu', age=600)
        d._reconcile([])
        state['done'].set()
        d._reap_dropped(now=state['dropped_at'] + 999)
        self.assertIn(9, d._in_flight)  # (its own thread pops it)
        proc.kill.assert_not_called()

    def test_a_worker_thread_that_is_dead_is_found_and_its_task_released(self):
        d = make()
        state, _ = hold(d, 10, 'web_screenshot', age=50)
        thread = threading.Thread(target=lambda: None)
        thread.start()
        thread.join()
        state['thread'] = thread
        d._reap_dropped()
        self.assertNotIn(10, d._in_flight)
        self.assertIn(('POST', 'sentinel/tasks/10/release'), d.client.paths())

    def test_a_task_whose_thread_could_not_start_is_released_not_left_holding_a_slot(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, max_concurrent=6)
        d.stop_event.wait = mock.Mock(return_value=False)
        with mock.patch.object(threading.Thread, 'start', side_effect=RuntimeError("can't start new thread")):
            d._start_task({'id': 11, 'kind': 'naabu', 'target': {'addresses': ['192.0.2.1']}}, ['naabu'])
        self.assertEqual(d._active_count(), 0)  # before the fix it stayed in the list for ever, with no thread to end it
        self.assertIn(('POST', 'sentinel/tasks/11/release'), fc.paths())

    def test_the_kill_still_happens_when_no_thread_can_be_started_for_it(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(threading.Thread, 'start', side_effect=RuntimeError("can't start new thread")):
            daemon.Daemon._kill(proc, background=True)
        proc.kill.assert_called_once()

    def test_a_tool_that_ignores_sigterm_dies_by_sigkill_with_its_whole_group(self):
        proc = subprocess.Popen(['sh', '-c', 'trap "" TERM; sleep 60 & wait'], start_new_session=True)
        handle = tools._ProcessGroup(proc)
        try:
            time.sleep(0.3)
            handle.terminate()
            time.sleep(0.5)
            self.assertIsNone(proc.poll())  # it ignored the polite stop
            handle.kill()
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, -signal.SIGKILL)
            with self.assertRaises(ProcessLookupError):
                os.killpg(proc.pid, 0)  # nothing of its group is left (the sleep it started too)
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass


class StarvationTests(unittest.TestCase):
    """A 2 GB Sentinel (budget 1540 MB): two nuclei runs (1040 MB) leave room for Chromium (400 MB) only while almost nothing else runs."""

    def plan(self, d, now):
        with mock.patch.object(daemon, 'runnable_kinds', return_value=list(KINDS)), mock.patch('time.monotonic', return_value=now):
            return d._poll_plan()

    def busy(self, d, probes=3):
        hold(d, 1, 'nuclei_targeted')
        hold(d, 2, 'nuclei_light')
        for i in range(probes):
            hold(d, 10 + i, 'http_probe')

    def test_cheap_kinds_alone_would_keep_the_browser_out_for_ever(self):
        d = make()
        self.busy(d)
        t0 = time.monotonic()
        self.assertNotIn('web_screenshot', self.plan(d, t0))
        self.assertIn('http_probe', self.plan(d, t0 + 1))

    def test_a_heavy_kind_that_has_waited_is_reserved_the_next_free_room(self):
        d = make()
        self.busy(d)
        t0 = time.monotonic()
        self.plan(d, t0)
        late = t0 + daemon.STARVE_AFTER_SECONDS + 1
        self.assertEqual(self.plan(d, late), [])  # nothing new starts: what runs must finish first
        self.assertEqual(self.plan(d, late + 5), [])
        for i in range(3):  # the probes finish
            d._in_flight.pop(10 + i)
        self.assertEqual(self.plan(d, late + 10), ['web_screenshot'])  # and the browser is asked for, alone
        self.assertEqual(d._reserve_poll, 'web_screenshot')

    def test_a_wait_is_not_forgotten_while_every_slot_is_taken(self):
        d = make(max_concurrent=5)  # naabu + two nuclei + one probe leave one slot: a probe takes it at once, so the slots are full more often than not
        self.busy(d, probes=1)
        hold(d, 3, 'naabu')
        t0 = time.monotonic()
        self.assertNotIn('web_screenshot', self.plan(d, t0))  # one slot free, no room for the browser
        d._in_flight[99] = {'kind': 'http_probe', 'done': threading.Event(), 'started': t0}
        self.assertEqual(self.plan(d, t0 + 60), [])  # all slots taken: nothing to ask for, and the clock runs on
        d._in_flight.pop(99)
        self.assertEqual(self.plan(d, t0 + daemon.STARVE_AFTER_SECONDS + 1), [])  # a slot is free again: the long wait is honoured at once
        self.assertEqual(d._reserve[0], 'web_screenshot')

    def test_the_hold_is_bounded_and_the_wait_starts_over(self):
        d = make()
        self.busy(d)
        t0 = time.monotonic()
        self.plan(d, t0)
        late = t0 + daemon.STARVE_AFTER_SECONDS + 1
        self.assertEqual(self.plan(d, late), [])
        after = late + daemon.RESERVE_SECONDS + 1
        plan = self.plan(d, after)  # the room never freed (a nuclei runs for hours): the others may start again
        self.assertIn('http_probe', plan)
        self.assertNotIn('web_screenshot', plan)

    def test_the_poll_for_the_reserved_kind_is_quick_and_clears_the_reservation(self):
        d = make()
        d.client.next_responses = [{'task': None}]
        d._reserve = ('web_screenshot', time.monotonic())
        d._blocked_since['web_screenshot'] = time.monotonic() - 500
        with mock.patch.object(daemon, 'runnable_kinds', return_value=list(KINDS)):
            d._poll_once()
        body = d.client.body_for('sentinel/tasks/next')
        self.assertEqual(body['kinds'], ['web_screenshot'])
        self.assertEqual(body['wait'], 0)  # nothing else waits behind a long poll for it
        self.assertIsNone(d._reserve)
        self.assertNotIn('web_screenshot', d._blocked_since)

    def test_nothing_is_held_when_the_kind_fits(self):
        d = make()
        hold(d, 1, 'nuclei_targeted')
        t0 = time.monotonic()
        self.assertIn('web_screenshot', self.plan(d, t0))
        self.assertIsNone(self.plan(d, t0 + 10000) and d._reserve)

    def test_a_waiting_kind_is_named_in_the_log_with_what_holds_the_memory_and_in_the_heartbeat_info(self):
        d = make(max_concurrent=8)
        self.busy(d)
        hold(d, 3534, 'naabu', age=1800)
        t0 = time.monotonic()
        self.plan(d, t0)
        with self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            self.plan(d, t0 + daemon.WAIT_LOG_AFTER_SECONDS + 1)
        line = next(m for m in logs.output if 'web_screenshot waiting' in m)
        self.assertIn('needs 400 MB', line)
        self.assertIn('MB free of 1540', line)
        self.assertIn('task 1 nuclei_targeted 520 MB', line)
        with mock.patch.object(daemon, 'info', wraps=daemon.info):
            report = [r for r in daemon._waiting_report if r['kind'] == 'web_screenshot']
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0]['need_mb'], 400)
        self.assertEqual(report[0]['budget_mb'], 1540)
        self.assertTrue(report[0]['held_by'])
        self.assertIn('waiting', daemon.info())
        d._in_flight.clear()  # nothing waits: the report is gone with it
        self.plan(d, t0 + 100)
        self.assertEqual([r for r in daemon._waiting_report if r['kind'] == 'web_screenshot'], [])

    def test_a_stopping_task_is_shown_in_the_heartbeat_info(self):
        d = make()
        state, _ = hold(d, 3534, 'naabu', age=900)
        d._reconcile([])
        self.plan(d, state['dropped_at'] + 12)
        stopping = [r for r in daemon._waiting_report if r.get('stopping')]
        self.assertEqual([(r['task'], r['kind']) for r in stopping], [(3534, 'naabu')])
        self.assertGreaterEqual(stopping[0]['seconds'], 11)


if __name__ == '__main__':
    unittest.main()
