"""Deep bbot discoveries run one at a time on a Sentinel: three kitchen-sink runs started together were killed by the kernel (-9) under the 2 GB
container limit. A second deep task waits for the first to end and then runs; it never fails. Light (passive, standard) discoveries do not take the slot."""
import threading
import time
import unittest
from unittest import mock

from client import bbot, daemon
from client.tests.test_daemon import FakeClient


def _task(task_id, mode, presets):
    return {'id': task_id, 'kind': 'bbot_discovery', 'target': {'domain': 'example.com', 'mode': mode, 'presets': presets}}


class DeepBbotSerialTests(unittest.TestCase):
    def setUp(self):
        self.d = daemon.Daemon('https://cve.example.test', 'tok', client=FakeClient(), max_concurrent=6)
        self.d.DEEP_WAIT_STEP = 0.01
        self.lock = threading.Lock()
        self.running, self.peak, self.order = 0, 0, []

    def _fake_execute(self, task, _register):
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
            self.order.append(('start', task['id']))
        time.sleep(0.3)
        with self.lock:
            self.running -= 1
            self.order.append(('end', task['id']))
        return {'outcome': 'done'}

    def _run(self, tasks):
        reported = []
        states = {}
        with mock.patch.object(self.d, '_execute', side_effect=self._fake_execute), \
                mock.patch.object(self.d, '_report_unless_dropped', side_effect=lambda tid, st, result: reported.append((tid, result['outcome']))):
            threads = []
            for task in tasks:
                states[task['id']] = {'done': threading.Event(), 'started': time.monotonic(), 'kind': task['kind'], 'runnable': True, 'pgids': set()}
                threads.append(threading.Thread(target=self.d._run_task, args=(task, states[task['id']])))
                threads[-1].start()
                time.sleep(0.05)
            for thread in threads:
                thread.join(10)
        return reported, states

    def test_is_deep_reads_the_mode_and_the_kitchen_sink_preset(self):
        self.assertTrue(bbot.is_deep({'mode': 'deep', 'presets': ['subdomain-enum']}))
        self.assertTrue(bbot.is_deep({'presets': ['subdomain-enum', 'kitchen-sink']}))
        self.assertFalse(bbot.is_deep({'mode': 'standard', 'presets': ['subdomain-enum', 'web']}))
        self.assertFalse(bbot.is_deep(None))

    def test_two_deep_tasks_never_run_together_and_the_second_still_runs(self):
        reported, states = self._run([_task(1, 'deep', ['kitchen-sink']), _task(2, 'deep', ['kitchen-sink'])])
        self.assertEqual(self.peak, 1)
        self.assertEqual(self.order, [('start', 1), ('end', 1), ('start', 2), ('end', 2)])
        self.assertEqual(sorted(reported), [(1, 'done'), (2, 'done')])
        self.assertGreater(states[2]['started'], states[1]['started'] + 0.2)  # the watchdog's clock starts when the slot is had, not during the wait
        self.assertFalse(self.d._deep_bbot.locked())

    def test_light_discoveries_keep_their_concurrency(self):
        reported, _ = self._run([_task(1, 'deep', ['kitchen-sink']), _task(2, 'standard', ['subdomain-enum', 'web']), _task(3, 'passive', ['subdomain-enum'])])
        self.assertEqual(self.peak, 3)
        self.assertEqual(sorted(reported), [(1, 'done'), (2, 'done'), (3, 'done')])

    def test_a_shutdown_ends_the_wait_without_running_the_second(self):
        self.d._deep_bbot.acquire()
        self.d.stop_event.set()
        state = {'done': threading.Event(), 'started': time.monotonic(), 'kind': 'bbot_discovery', 'runnable': True, 'pgids': set()}
        with mock.patch.object(self.d, '_execute') as execute, mock.patch.object(self.d, '_report_unless_dropped'):
            self.d._run_task(_task(5, 'deep', ['kitchen-sink']), state)
        execute.assert_not_called()
        self.d._deep_bbot.release()


if __name__ == '__main__':
    unittest.main()
