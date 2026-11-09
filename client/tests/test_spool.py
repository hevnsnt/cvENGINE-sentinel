import json
import os
import stat
import threading
import time
import unittest
from unittest import mock

import requests

from client import daemon, httpclient, spool
from client.tests.test_daemon import DaemonTestCase, FakeClient, wait_for


def age(directory, task_id, seconds):
    path = os.path.join(directory, f'{task_id}.json')
    then = time.time() - seconds
    os.utime(path, (then, then))


class SpoolFileTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        self.spool = spool.Spool()

    def test_a_result_round_trips_and_the_file_is_private(self):
        self.assertTrue(self.spool.add(7, {'outcome': 'done', 'hosts': ['192.0.2.1']}))
        self.assertEqual(self.spool.load(7), {'outcome': 'done', 'hosts': ['192.0.2.1']})
        path = os.path.join(self.spool_dir, '7.json')
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(os.listdir(self.spool_dir), ['7.json'])  # no temporary file is left behind

    def test_a_failed_write_leaves_no_entry_and_no_temporary_file(self):
        with mock.patch('client.spool.os.replace', side_effect=OSError('disk')):
            self.assertFalse(self.spool.add(8, {'outcome': 'done'}))
        self.assertEqual(os.listdir(self.spool_dir), [])
        self.assertIsNone(self.spool.load(8))

    def test_entries_come_oldest_first(self):
        for task_id, seconds in ((3, 10), (1, 300), (2, 100)):
            self.spool.add(task_id, {'outcome': 'done'})
            age(self.spool_dir, task_id, seconds)
        self.assertEqual([t for t, _a in self.spool.entries()], ['1', '2', '3'])

    def test_adding_the_same_task_twice_keeps_one_entry(self):
        self.spool.add(5, {'outcome': 'done', 'n': 1})
        self.spool.add(5, {'outcome': 'done', 'n': 2})
        self.assertEqual(self.spool.count(), 1)
        self.assertEqual((self.spool.load(5) or {}).get('n'), 1)

    def test_an_id_that_is_not_a_plain_task_id_is_refused(self):
        for bad in ('../x', 'a/b', '', 'x' * 65, 'a b'):
            self.assertFalse(self.spool.add(bad, {'outcome': 'done'}), bad)
        self.assertEqual(os.listdir(self.spool_dir) if os.path.isdir(self.spool_dir) else [], [])

    def test_the_size_limit_refuses_a_result_that_does_not_fit(self):
        os.environ['CVENGINE_SENTINEL_SPOOL_MAX_MB'] = '0.001'  # about 1 KB
        self.assertTrue(self.spool.add(1, {'outcome': 'done', 'pad': 'x' * 300}))
        self.assertFalse(self.spool.add(2, {'outcome': 'done', 'pad': 'x' * 2000}))
        self.assertEqual(self.spool.task_ids(), ['1'])  # held results are never dropped for a new one

    def test_expired_entries_are_dropped_for_room_but_held_ones_never(self):
        os.environ['CVENGINE_SENTINEL_SPOOL_MAX_MB'] = '0.001'
        self.spool.add(1, {'outcome': 'done', 'pad': 'x' * 400})
        self.spool.add(2, {'outcome': 'done', 'pad': 'x' * 400})
        age(self.spool_dir, 1, 9 * 3600)
        self.assertEqual(self.spool.expire_old(6 * 3600), ['1'])
        self.assertTrue(os.path.exists(os.path.join(self.spool_dir, 'expired', '1.json')))  # kept on disk
        self.assertTrue(self.spool.add(3, {'outcome': 'done', 'pad': 'x' * 400}))  # room made by dropping the expired one
        self.assertFalse(os.path.exists(os.path.join(self.spool_dir, 'expired', '1.json')))
        self.assertEqual(sorted(self.spool.task_ids()), ['2', '3'])

    def test_an_unreadable_entry_is_moved_aside_not_retried_forever(self):
        os.makedirs(self.spool_dir, exist_ok=True)
        with open(os.path.join(self.spool_dir, '9.json'), 'w') as handle:
            handle.write('{not json')
        self.assertIsNone(self.spool.load(9))
        self.assertEqual(self.spool.count(), 0)
        self.assertTrue(os.path.exists(os.path.join(self.spool_dir, 'expired', '9.json')))

    def test_the_window_is_said_in_hours_or_in_seconds_when_it_is_short(self):
        self.assertEqual(spool.window_text(), '6.0 hours')
        os.environ['CVENGINE_SENTINEL_SPOOL_HOURS'] = '0.003'
        self.assertEqual(spool.window_text(), '10 seconds')

    def test_the_window_defaults_to_six_hours_and_is_configurable(self):
        self.assertEqual(spool.window_seconds(), 6 * 3600)
        os.environ['CVENGINE_SENTINEL_SPOOL_HOURS'] = '1.5'
        self.assertEqual(spool.window_seconds(), 5400)
        os.environ['CVENGINE_SENTINEL_SPOOL_HOURS'] = 'soon'
        self.assertEqual(spool.window_seconds(), 6 * 3600)
        os.environ['CVENGINE_SENTINEL_SPOOL_HOURS'] = '0'
        self.assertFalse(self.spool.add(1, {'outcome': 'done'}))  # 0 turns the spool off


class SpoolDeliveryTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(daemon, 'REPORT_BACKOFF', 0.001)
        p.start()
        self.addCleanup(p.stop)

    def down(self, task_id):
        self.fc.script[('POST', f'sentinel/tasks/{task_id}/result')] = [httpclient.ApiError(503, 'down')] * 10

    def test_a_result_that_cannot_be_delivered_is_held_not_released(self):
        self.down(41)
        d = self.make()
        d._report(41, {'outcome': 'done', 'hosts': []})
        self.assertEqual(self.fc.count('sentinel/tasks/41/release'), 0)
        self.assertEqual(d.spool.task_ids(), ['41'])
        self.assertEqual(daemon.info()['spool']['count'], 1)  # the Sentinels page can say it holds results

    def test_a_server_down_for_the_whole_quick_retry_still_costs_no_result(self):
        self.fc.script[('POST', 'sentinel/tasks/42/result')] = [requests.ConnectionError('refused')] * 10
        d = self.make()
        d._report(42, {'outcome': 'done', 'n': 1})
        self.assertEqual(d.spool.load(42), {'outcome': 'done', 'n': 1})

    def test_the_spool_is_delivered_oldest_first_and_deleted(self):
        d = self.make()
        for task_id, seconds in ((53, 10), (51, 300), (52, 100)):
            d.spool.add(task_id, {'outcome': 'done', 'id': task_id})
            age(self.spool_dir, task_id, seconds)
        self.assertTrue(d._flush_spool())
        self.assertEqual([p for _m, p, _b in self.fc.calls], ['sentinel/tasks/51/result', 'sentinel/tasks/52/result', 'sentinel/tasks/53/result'])
        self.assertEqual(d.spool.count(), 0)
        self.assertNotIn('spool', daemon.info())

    def test_a_server_that_already_has_the_result_is_a_delivery(self):
        d = self.make()
        d.spool.add(61, {'outcome': 'done'})
        self.fc.script[('POST', 'sentinel/tasks/61/result')] = [{'ok': True, 'duplicate': True}]
        self.assertTrue(d._flush_spool())
        self.assertEqual(d.spool.count(), 0)

    def test_a_final_refusal_deletes_the_entry_with_a_log_line(self):
        d = self.make()
        d.spool.add(62, {'outcome': 'done'})
        self.fc.script[('POST', 'sentinel/tasks/62/result')] = [httpclient.ApiError(410, 'gone')]
        with self.assertLogs('sentinel.daemon', 'WARNING') as logs:
            self.assertTrue(d._flush_spool())
        self.assertTrue(any('refused the held result for task 62' in line for line in logs.output))
        self.assertEqual(d.spool.count(), 0)

    def test_an_unreachable_server_keeps_every_entry_and_ends_the_pass(self):
        d = self.make()
        for task_id in (71, 72):
            d.spool.add(task_id, {'outcome': 'done'})
            age(self.spool_dir, task_id, 60 - task_id % 10)
        self.fc.script[('POST', 'sentinel/tasks/71/result')] = [requests.ConnectionError('refused')]
        self.assertFalse(d._flush_spool())
        self.assertEqual(sorted(d.spool.task_ids()), ['71', '72'])
        self.assertEqual(self.fc.count('sentinel/tasks/72/result'), 0)  # the pass stopped at the first failure

    def test_the_spool_goes_out_before_the_first_heartbeat(self):
        d = self.make()
        d.spool.add(81, {'outcome': 'done'})
        d._heartbeat_once()
        paths = [p for _m, p, _b in self.fc.calls]
        self.assertEqual(paths[:2], ['sentinel/tasks/81/result', 'sentinel/heartbeat'])
        self.assertNotIn('81', [str(r) for r in self.fc.body_for('sentinel/heartbeat')['running']])  # delivered: no longer held

    def test_a_held_task_still_counts_as_running_in_the_heartbeat_and_is_not_an_orphan(self):
        d = self.make()
        d.spool.add(82, {'outcome': 'done'})
        self.fc.script[('POST', 'sentinel/tasks/82/result')] = [httpclient.ApiError(503, 'down')] * 5
        self.fc.script[('POST', 'sentinel/heartbeat')] = [{'leases': ['82']}, {'leases': ['82']}, {'leases': ['82']}]
        for _ in range(3):
            d._heartbeat_once()
        self.assertEqual(self.fc.body_for('sentinel/heartbeat')['running'], [82])  # whole numbers: the server refuses any other id
        self.assertEqual(self.fc.count('sentinel/tasks/82/release'), 0)

    def test_a_started_sentinel_with_a_spool_delivers_it_first(self):
        spooled = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        spooled.spool.add(91, {'outcome': 'done', 'hosts': []})
        spooled.spool.add(92, {'outcome': 'done', 'hosts': []})
        age(self.spool_dir, 91, 500)
        fresh = self.make()  # a new process: nothing in memory, the same state directory
        thread = threading.Thread(target=fresh.run, daemon=True)
        thread.start()
        self.assertTrue(wait_for(lambda: fresh.spool.count() == 0))
        fresh.request_stop()
        thread.join(timeout=10)
        paths = [p for _m, p, _b in self.fc.calls]
        self.assertEqual(paths[:2], ['sentinel/tasks/91/result', 'sentinel/tasks/92/result'])
        self.assertLess(paths.index('sentinel/tasks/92/result'), paths.index('sentinel/heartbeat') if 'sentinel/heartbeat' in paths else 99)

    def test_shutdown_with_held_results_keeps_them_and_releases_nothing(self):
        d = self.make()
        d.spool.add(93, {'outcome': 'done'})
        d._shutdown()
        self.assertEqual(d.spool.task_ids(), ['93'])
        self.assertEqual(self.fc.count('sentinel/tasks/93/release'), 0)

    def test_an_entry_older_than_the_window_is_not_offered_and_stays_on_disk(self):
        d = self.make()
        d.spool.add(94, {'outcome': 'done'})
        age(self.spool_dir, 94, 7 * 3600)
        with self.assertLogs('sentinel.daemon', 'ERROR'):
            self.assertTrue(d._flush_spool())
        self.assertEqual(self.fc.count('sentinel/tasks/94/result'), 0)
        self.assertTrue(os.path.exists(os.path.join(self.spool_dir, 'expired', '94.json')))

    def test_a_server_down_past_the_window_does_not_crash_the_sentinel_and_keeps_the_data(self):
        os.environ['CVENGINE_SENTINEL_SPOOL_HOURS'] = '0.0001'  # about 0.36 s
        self.fc.script[('POST', 'sentinel/tasks/95/result')] = [requests.ConnectionError('refused')] * 50
        self.fc.script[('POST', 'sentinel/heartbeat')] = [requests.ConnectionError('refused')] * 50
        self.fc.script[('POST', 'sentinel/tasks/next')] = [requests.ConnectionError('refused')] * 50
        d = self.make(heartbeat_seconds=0.05)
        d._report(95, {'outcome': 'done', 'hosts': [{'address': '192.0.2.9'}]})
        thread = threading.Thread(target=d.run, daemon=True)
        with mock.patch.object(daemon, 'SPOOL_MIN_BACKOFF', 0.05), mock.patch.object(daemon, 'MIN_BACKOFF', 0.05):
            thread.start()
            expired = os.path.join(self.spool_dir, 'expired', '95.json')
            self.assertTrue(wait_for(lambda: os.path.exists(expired), timeout=5))
            self.assertTrue(thread.is_alive())
            d.request_stop()
            thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        with open(expired) as handle:
            self.assertEqual(json.load(handle)['result']['hosts'], [{'address': '192.0.2.9'}])

    def test_delivery_backoff_is_capped_and_resets_after_a_delivery(self):
        d = self.make()
        d.spool.add(96, {'outcome': 'done'})
        self.fc.script[('POST', 'sentinel/tasks/96/result')] = [httpclient.ApiError(503, 'down')] * 12 + [{}]
        delays = []

        def fake_wait(seconds=None):
            delays.append(seconds)
            return False
        with mock.patch.object(d.stop_event, 'wait', side_effect=fake_wait), mock.patch.object(d._spool_wake, 'wait', side_effect=lambda t=None: d.stop_event.set()):
            d._spool_loop()
        failed = [x for x in delays[:12]]
        self.assertTrue(all(x <= daemon.SPOOL_MAX_BACKOFF for x in failed), failed)
        self.assertGreater(max(failed), daemon.SPOOL_MAX_BACKOFF * 0.4)  # it did climb to the cap
        self.assertEqual(d.spool.count(), 0)
        self.assertEqual(d._spool_backoff, daemon.SPOOL_MIN_BACKOFF)

    def test_an_outage_is_logged_once_not_at_every_attempt(self):
        d = self.make()
        with self.assertLogs('sentinel.daemon', 'WARNING') as logs:
            for _ in range(40):
                d._quiet_warning('heartbeat', 'heartbeat failed: %s', 'refused')
        self.assertEqual(len(logs.output), 1)
        with self.assertLogs('sentinel.daemon', 'INFO') as logs:
            d._quiet_recovered('heartbeat', 'heartbeat reaches cvENGINE again')
        self.assertEqual(len(logs.output), 1)

    def test_a_heartbeat_that_fails_forever_logs_once(self):
        self.fc.script[('POST', 'sentinel/heartbeat')] = [requests.ConnectionError('refused')] * 30
        d = self.make()
        with self.assertLogs('sentinel.daemon', 'WARNING') as logs:
            for _ in range(30):
                d._heartbeat_once()
        self.assertEqual(len([line for line in logs.output if 'heartbeat failed' in line]), 1)

    def test_the_task_thread_reports_through_the_spool_end_to_end(self):
        task = {'id': 97, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}
        self.fc.script[('POST', 'sentinel/tasks/97/result')] = [httpclient.ApiError(503, 'down')] * daemon.REPORT_ATTEMPTS
        d = self.make()
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False, 'kind': 'nmap', 'runnable': True}
        d._in_flight[97] = state
        with mock.patch.object(d, '_execute', return_value={'outcome': 'done', 'hosts': []}):
            d._run_task(task, state)
        self.assertEqual(d.spool.task_ids(), ['97'])
        self.assertEqual(d._active_count(), 0)  # the slot is free while the result waits for cvENGINE
        self.assertTrue(d._flush_spool())
        self.assertEqual(d.spool.count(), 0)


if __name__ == '__main__':
    unittest.main()
