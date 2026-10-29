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


class ConcurrencyCapTests(unittest.TestCase):
    def test_no_request_to_the_server_carries_more_than_the_cap(self):
        fc = FakeClient()
        with mock.patch('client.tools.detect_tools', return_value=[]):
            daemon.register(fc, 'box', 50)
        self.assertEqual(fc.body_for('sentinel')['max_concurrent'], 10)

    def test_bootstrap_and_the_daemon_hold_to_the_cap_and_a_floor_of_one(self):
        self.assertEqual(daemon._cap_concurrency(50), 10)
        self.assertEqual(daemon._cap_concurrency(0), 1)
        self.assertEqual(daemon._cap_concurrency(-3), 1)
        self.assertEqual(daemon._cap_concurrency('7'), 7)
        self.assertEqual(daemon._cap_concurrency(None), 1)
        self.assertEqual(daemon._cap_concurrency('many'), 1)
        self.assertEqual(daemon.Daemon('https://x.example', 'tok', max_concurrent=99, client=FakeClient()).max_concurrent, 10)


class InternalGrantTests(unittest.TestCase):
    def test_a_grant_of_internal_on_a_machine_configured_external_is_warned_about_once(self):
        d = make_daemon()
        d.reregister = lambda: None
        self.addCleanup(daemon.config.set_overrides, {})
        with mock.patch.object(daemon.config, '_local_internal', return_value=False), self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            d.apply_settings({'values': {'network': 'internal'}, 'rev': 'r1'})
            d.apply_settings({'values': {'network': 'internal', 'max_concurrent': 2}, 'rev': 'r2'})
        warnings = [line for line in logs.output if 'configured as external' in line]
        self.assertEqual(len(warnings), 1)
        self.assertIn('CVENGINE_SENTINEL_NETWORK=internal', warnings[0])


class ResultSizeTests(unittest.TestCase):
    def test_a_result_over_the_servers_limit_is_replaced_by_an_error(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        d._report(5, {'outcome': 'done', 'blob': 'x' * (daemon.MAX_RESULT_BYTES + 10)})
        body = fc.body_for('sentinel/tasks/5/result')
        self.assertEqual(body['outcome'], 'error')
        self.assertIn('larger than the server accepts', body['error'])
        self.assertEqual(fc.count('sentinel/tasks/5/release'), 0)  # a final answer, not a retry loop or a release

    def test_a_normal_result_is_sent_unchanged(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        d._report(6, {'outcome': 'done', 'hosts': []})
        self.assertEqual(fc.body_for('sentinel/tasks/6/result'), {'outcome': 'done', 'hosts': []})

    def test_nuclei_findings_stop_before_the_servers_limit(self):
        import json
        from client import tools
        row = {'template-id': 't', 'info': {'name': 'n' * 400, 'severity': 'high', 'description': 'd' * 4000, 'tags': ['a'] * 20},
               'host': 'example.com', 'matched-at': 'm' * 400, 'extracted-results': ['e' * 480] * 20}
        text = '\n'.join(json.dumps(row) for _ in range(tools.MAX_FINDINGS))
        findings = tools.parse_nuclei_jsonl(text)
        self.assertLess(len(findings), tools.MAX_FINDINGS)
        self.assertLessEqual(len(json.dumps(findings)), tools.MAX_FINDINGS_BYTES + 100_000)


class OrphanedLeaseTests(unittest.TestCase):
    def make(self):
        fc = FakeClient()
        return daemon.Daemon('https://x.example', 'tok', client=fc), fc

    def releases(self, fc):
        return [(path, body) for method, path, body in fc.calls if path.endswith('/release')]

    def test_a_lease_the_server_holds_but_this_sentinel_is_not_running_is_released_when_seen_twice(self):
        d, fc = self.make()
        d._reconcile([{'task_id': 53}, {'task_id': 90}])
        self.assertEqual(self.releases(fc), [])  # a first sighting could be a task accepted a moment ago
        d._reconcile([{'task_id': 53}, {'task_id': 90}])
        self.assertEqual([p for p, _ in self.releases(fc)], ['sentinel/tasks/53/release', 'sentinel/tasks/90/release'])
        self.assertIn('not running the task', self.releases(fc)[0][1]['reason'])

    def test_a_task_that_is_running_here_is_never_released(self):
        d, fc = self.make()
        d._in_flight = {7: {'kind': 'nmap', 'started': time.monotonic(), 'done': threading.Event()}}
        for _ in range(3):
            d._reconcile([{'task_id': 7}])
        self.assertEqual(self.releases(fc), [])

    def test_a_lease_that_goes_away_in_between_is_forgotten(self):
        d, fc = self.make()
        d._reconcile([{'task_id': 5}])
        d._reconcile([])  # the server let it go
        d._reconcile([{'task_id': 5}])  # a new lease with the same id is a first sighting again
        self.assertEqual(self.releases(fc), [])

    def test_a_task_that_starts_running_here_between_heartbeats_is_not_released(self):
        d, fc = self.make()
        d._reconcile([{'task_id': 9}])
        d._in_flight = {9: {'kind': 'naabu', 'started': time.monotonic(), 'done': threading.Event()}}
        d._reconcile([{'task_id': 9}])
        self.assertEqual(self.releases(fc), [])

    def test_ids_are_compared_as_text_so_a_string_and_an_int_agree(self):
        d, fc = self.make()
        d._in_flight = {'12': {'kind': 'nmap', 'started': time.monotonic(), 'done': threading.Event()}}
        d._reconcile([{'task_id': 12}])
        d._reconcile([{'task_id': 12}])
        self.assertEqual(self.releases(fc), [])

    def test_no_list_judges_nothing_and_a_failing_release_never_raises(self):
        d, fc = self.make()
        d._reconcile(None)
        d._reconcile('nonsense')
        self.assertEqual(self.releases(fc), [])
        fc.fail_on.add(('POST', 'sentinel/tasks/3/release'))
        d._reconcile([{'task_id': 3}])
        d._reconcile([{'task_id': 3}])  # the release fails: logged, not raised

    def test_at_most_a_bounded_number_are_released_per_heartbeat(self):
        d, fc = self.make()
        leases = [{'task_id': i} for i in range(daemon.MAX_ORPHAN_RELEASES + 15)]
        d._reconcile(leases)
        d._reconcile(leases)
        self.assertEqual(len(self.releases(fc)), daemon.MAX_ORPHAN_RELEASES)


if __name__ == '__main__':
    unittest.main()
