import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import blob, config, daemon, httpclient, tools


class FakeClient:
    """A scripted stand-in for httpclient.Client: records every call, and answers ``sentinel/tasks/next`` from a
    queue the test fills in, so the daemon's own state machine (poll -> accept -> execute -> report) can be driven
    deterministically without a real server or real network I/O."""

    def __init__(self):
        self.calls = []
        self.next_responses = []
        self.fail_on = set()  # a set of (method, path) pairs this fake answers with an ApiError

    def call(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if (method, path) in self.fail_on:
            raise httpclient.ApiError(409, 'scripted failure')
        if path == 'sentinel/tasks/next':
            return self.next_responses.pop(0) if self.next_responses else {'task': None}
        return {}

    def paths(self):
        return [(m, p) for m, p, _b in self.calls]

    def body_for(self, path):
        return next(b for _m, p, b in self.calls if p == path)


class BootstrapTests(unittest.TestCase):
    def _blob(self, **overrides):
        payload = {'enrollment_token': 'senr_abc', 'server_url': 'https://cve.example.test', 'expires_at': '2030-01-01T00:00:00Z',
                   'project': 'demo'}
        payload.update(overrides)
        return blob.encode_blob(payload)

    def test_decodes_the_blob_and_posts_bootstrap_with_declared_capabilities(self):
        fc = FakeClient()
        fc.next_responses = []

        class Fake:
            def __init__(self, server_url):
                self.server_url = server_url
                self.fake = fc

            def call(self, method, path, body=None, timeout=None):
                fc.call(method, path, body, timeout)
                return {'token': 'cve_newtoken', 'id': 1, 'status': 'pending'}
        with mock.patch('client.tools.detect_tools', return_value=['nmap']), mock.patch('client.tools.gvm_available', return_value=True):
            token, server_url = daemon.bootstrap(self._blob(), 'my-sentinel', 2, client_factory=Fake)
        self.assertEqual(token, 'cve_newtoken')
        self.assertEqual(server_url, 'https://cve.example.test')
        method, path, body = fc.calls[0]
        self.assertEqual((method, path), ('POST', 'sentinels/bootstrap'))
        self.assertEqual(body['enrollment_token'], 'senr_abc')
        self.assertEqual(body['name'], 'my-sentinel')
        self.assertEqual(sorted(body['capabilities']),
                         sorted(['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan', 'openvas']))
        self.assertEqual(body['max_concurrent'], 2)
        self.assertEqual(body['tools'], ['nmap'])

    def test_raises_blob_error_without_any_http_call_on_a_bad_blob(self):
        calls = []

        class Fake:
            def __init__(self, server_url):
                calls.append(server_url)

            def call(self, *a, **k):
                calls.append(('call', a, k))
                return {}
        with self.assertRaises(blob.BlobError):
            daemon.bootstrap('not-a-valid-blob', 'x', 1, client_factory=Fake)
        self.assertEqual(calls, [])  # never even constructs a client for an undecodable blob

    def test_raises_when_the_server_does_not_return_a_token(self):
        class Fake:
            def __init__(self, server_url):
                pass

            def call(self, method, path, body=None, timeout=None):
                return {'id': 1}  # no 'token'
        with self.assertRaises(httpclient.ApiError):
            daemon.bootstrap(self._blob(), 'x', 1, client_factory=Fake)


class RegisterTests(unittest.TestCase):
    """register() is PUT sentinel, called on every startup (not just the first) so a restart always reports this
    Sentinel's current capacity; scope is deliberately left out of the body so it never touches what an enrollment
    secret already assigned (PUT sentinel only changes fields given, per agentapi.agent_broker.register)."""

    def test_sends_name_capabilities_tools_and_max_concurrent_but_no_scope(self):
        fc = FakeClient()
        with mock.patch('client.tools.detect_tools', return_value=['nmap', 'naabu']), mock.patch('client.tools.gvm_available', return_value=True):
            daemon.register(fc, 'my-sentinel', 5)
        self.assertEqual(fc.paths(), [('PUT', 'sentinel')])
        body = fc.body_for('sentinel')
        self.assertEqual(body['name'], 'my-sentinel')
        self.assertEqual(body['max_concurrent'], 5)
        self.assertEqual(body['tools'], ['nmap', 'naabu'])
        self.assertEqual(sorted(body['capabilities']), sorted(config.CAPABILITIES))
        self.assertNotIn('scope', body)

    def test_openvas_is_declared_only_while_the_gvm_stack_answers(self):
        for gvm, expected in ((True, True), (False, False)):
            fc = FakeClient()
            with mock.patch('client.tools.detect_tools', return_value=[]), mock.patch('client.tools.gvm_available', return_value=gvm):
                daemon.register(fc, 'x', 1)
            self.assertEqual('openvas' in fc.body_for('sentinel')['capabilities'], expected, gvm)

    def test_an_operator_can_turn_a_kind_off(self):
        fc = FakeClient()
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISABLE': 'openvas, wpscan'}), \
                mock.patch('client.tools.detect_tools', return_value=[]), mock.patch('client.tools.gvm_available', return_value=True):
            daemon.register(fc, 'x', 1)
            d = daemon.Daemon('https://x.example', 'tok', client=fc)
            kinds = d._poll_kinds()
        caps = fc.body_for('sentinel')['capabilities']
        self.assertTrue({'openvas', 'wpscan'}.isdisjoint(caps) and {'openvas', 'wpscan'}.isdisjoint(kinds))
        self.assertIn('nmap', caps)

    def test_the_poll_leaves_out_openvas_while_no_gvm_stack_answers(self):
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        with mock.patch('client.tools.gvm_available', return_value=False):
            self.assertNotIn('openvas', d._poll_kinds())
        with mock.patch('client.tools.gvm_available', return_value=True):
            self.assertIn('openvas', d._poll_kinds())

    def test_registration_is_sent_again_when_the_gvm_stack_comes_up_or_goes_away(self):
        sent = []
        with mock.patch('client.tools.gvm_available', return_value=False):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.reregister = lambda: sent.append(1)
        with mock.patch('client.tools.gvm_available', return_value=False):
            d._refresh_registration()
        self.assertEqual(sent, [])  # nothing changed since startup
        with mock.patch('client.tools.gvm_available', return_value=True):
            d._refresh_registration()
            d._refresh_registration()
        self.assertEqual(len(sent), 1)  # told the server once, not on every heartbeat
        with mock.patch('client.tools.gvm_available', return_value=False):
            d._refresh_registration()
        self.assertEqual(len(sent), 2)

    def test_a_failed_reregistration_is_retried_on_the_next_heartbeat(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise httpclient.ApiError(503, 'down')
        with mock.patch('client.tools.gvm_available', return_value=False):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.reregister = flaky
        with mock.patch('client.tools.gvm_available', return_value=True):
            d._refresh_registration()
            d._refresh_registration()
        self.assertEqual(len(calls), 2)

    def test_a_custom_kinds_list_overrides_the_default_capabilities(self):
        fc = FakeClient()
        with mock.patch('client.tools.detect_tools', return_value=[]):
            daemon.register(fc, 'x', 1, kinds=['nmap'])
        self.assertEqual(fc.body_for('sentinel')['capabilities'], ['nmap'])

    def test_a_sentinel_told_it_is_internal_declares_network_internal_and_only_then(self):
        for value, expected in ((None, False), ('external', False), (' Internal ', True)):
            fc = FakeClient()
            with mock.patch.dict('os.environ'), mock.patch('client.tools.detect_tools', return_value=[]):
                os.environ.pop('CVENGINE_SENTINEL_NETWORK', None)
                if value is not None:
                    os.environ['CVENGINE_SENTINEL_NETWORK'] = value
                daemon.register(fc, 'x', 1)
            self.assertEqual(config.INTERNAL_CAPABILITY in fc.body_for('sentinel')['capabilities'], expected, value)

    def test_the_poll_filter_never_carries_the_network_capability(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'}):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        self.assertNotIn(config.INTERNAL_CAPABILITY, d.kinds)

    def test_a_server_error_propagates_to_the_caller(self):
        fc = FakeClient()
        fc.fail_on.add(('PUT', 'sentinel'))
        with mock.patch('client.tools.detect_tools', return_value=[]):
            with self.assertRaises(httpclient.ApiError):
                daemon.register(fc, 'x', 1)


class TokenPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, 'nested', 'token.json')

    def test_missing_file_returns_none_none(self):
        self.assertEqual(daemon.load_token(self.path), (None, None))

    def test_save_then_load_round_trips_and_is_0600(self):
        daemon.save_token(self.path, 'cve_secrettoken', 'https://cve.example.test')
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(daemon.load_token(self.path), ('cve_secrettoken', 'https://cve.example.test'))

    def test_a_corrupt_file_is_treated_as_no_token(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write('not json')
        self.assertEqual(daemon.load_token(self.path), (None, None))


class PollAndExecuteTests(unittest.TestCase):
    def _wait_idle(self, d, timeout=2.0):
        deadline = time.monotonic() + timeout
        while d._active_count() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(d._active_count(), 0, 'task thread did not finish in time')

    def test_claims_accepts_executes_and_reports_a_done_result(self):
        fc = FakeClient()
        task = {'id': 7, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.10']}}
        fc.next_responses = [{'task': task}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        fake_result = {'hosts': [{'ip': '192.0.2.10', 'os_guess': '', 'ports': []}]}
        with mock.patch.dict(tools.RUNNERS, {'nmap': mock.Mock(return_value=fake_result)}):
            d._poll_once()
            self._wait_idle(d)
        self.assertIn(('POST', 'sentinel/tasks/next'), fc.paths())
        self.assertIn(('POST', 'sentinel/tasks/7/accept'), fc.paths())
        self.assertEqual(fc.body_for('sentinel/tasks/7/result'), {'outcome': 'done', **fake_result})

    def test_each_new_kind_is_dispatched_with_the_fields_its_target_carries(self):
        cases = [
            ('testssl', {'host': 'www.example.test', 'ip': '192.0.2.10', 'port': 443, 'starttls': ''},
             {'items': []}, (('www.example.test', '192.0.2.10', 443, ''), {})),
            ('nmap_udp', {'address': '192.0.2.10'}, {'xml': '<nmaprun/>'}, (('192.0.2.10',), {})),
            ('wpscan', {'url': 'https://www.example.test', 'token': 'tok'}, {'report': None, 'returncode': 0, 'stderr_tail': ''},
             (('https://www.example.test', 'tok'), {})),
            ('openvas', {'hosts': {'192.0.2.10': 'www.example.test'}, 'excluded_families': ['Denial of Service'], 'max_hours': 4},
             {'results': [], 'scanned_addresses': [], 'without_cve': 0, 'unusable': 0},
             (({'192.0.2.10': 'www.example.test'}, ['Denial of Service'], 4), {})),
        ]
        for kind, target, fake_result, expected_call in cases:
            with self.subTest(kind=kind):
                fc = FakeClient()
                fc.next_responses = [{'task': {'id': 100, 'kind': kind, 'target': target}}]
                d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
                fake_runner = mock.Mock(return_value=fake_result)
                with mock.patch.dict(tools.RUNNERS, {kind: fake_runner}):
                    d._poll_once()
                    self._wait_idle(d)
                self.assertEqual(fc.body_for('sentinel/tasks/100/result'), {'outcome': 'done', **fake_result})
                expected_args, expected_kwargs = expected_call
                actual_args, actual_kwargs = fake_runner.call_args
                self.assertEqual(actual_args, expected_args)
                self.assertEqual({k: v for k, v in actual_kwargs.items() if k != 'register'}, expected_kwargs)

    def test_an_unknown_task_kind_is_reported_as_an_error_not_a_crash(self):
        fc = FakeClient()
        task = {'id': 8, 'kind': 'bogus-kind', 'target': {}}
        fc.next_responses = [{'task': task}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        d._poll_once()
        self._wait_idle(d)
        body = fc.body_for('sentinel/tasks/8/result')
        self.assertEqual(body['outcome'], 'error')

    def test_a_malicious_target_in_the_task_is_reported_as_an_error_never_run(self):
        fc = FakeClient()
        task = {'id': 9, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.10; rm -rf /']}}
        fc.next_responses = [{'task': task}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        with mock.patch('client.tools.subprocess.Popen') as popen:
            d._poll_once()
            self._wait_idle(d)
        popen.assert_not_called()  # the bad target never reached a subprocess call
        body = fc.body_for('sentinel/tasks/9/result')
        self.assertEqual(body['outcome'], 'error')

    def test_a_tool_runner_exception_is_reported_as_an_error_and_the_loop_keeps_going(self):
        fc = FakeClient()
        task = {'id': 10, 'kind': 'naabu', 'target': {'addresses': ['192.0.2.10']}}
        fc.next_responses = [{'task': task}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        with mock.patch.dict(tools.RUNNERS, {'naabu': mock.Mock(side_effect=RuntimeError('boom'))}):
            d._poll_once()
            self._wait_idle(d)
        body = fc.body_for('sentinel/tasks/10/result')
        self.assertEqual(body['outcome'], 'error')
        self.assertIn('boom', body['error'])
        # the daemon itself is still usable: a second poll proceeds normally
        fc.next_responses = [{'task': None}]
        d._poll_once()
        self.assertIn(('POST', 'sentinel/tasks/next'), fc.paths())

    def test_no_task_available_makes_no_further_calls(self):
        fc = FakeClient()
        fc.next_responses = [{'task': None}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        d._poll_once()
        self.assertEqual(fc.paths(), [('POST', 'sentinel/tasks/next')])

    def test_at_capacity_skips_polling_entirely(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, max_concurrent=1)
        d._in_flight[1] = {'proc': None, 'done': threading.Event()}
        with mock.patch('client.daemon.time.sleep'):
            d._poll_once()
        self.assertEqual(fc.calls, [])  # at capacity: tasks/next was never even called

    def test_accept_failure_never_executes_the_task(self):
        fc = FakeClient()
        fc.fail_on = {('POST', 'sentinel/tasks/11/accept')}
        task = {'id': 11, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.10']}}
        fc.next_responses = [{'task': task}]
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        fake_runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'nmap': fake_runner}):
            d._poll_once()
        fake_runner.assert_not_called()
        self.assertEqual(d._active_count(), 0)


class HeartbeatTests(unittest.TestCase):
    def test_heartbeat_is_called_on_the_configured_interval_until_stopped(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, heartbeat_seconds=0.02)
        thread = threading.Thread(target=d._heartbeat_loop, daemon=True)
        thread.start()
        time.sleep(0.09)
        d.stop_event.set()
        thread.join(timeout=1)
        beats = [p for m, p, _b in fc.calls if p == 'sentinel/heartbeat']
        self.assertGreaterEqual(len(beats), 2)

    def test_a_failed_heartbeat_does_not_stop_the_loop(self):
        fc = FakeClient()
        fc.fail_on = {('POST', 'sentinel/heartbeat')}
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc, heartbeat_seconds=0.02)
        thread = threading.Thread(target=d._heartbeat_loop, daemon=True)
        thread.start()
        time.sleep(0.06)
        d.stop_event.set()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())


class ShutdownTests(unittest.TestCase):
    def test_a_task_still_running_past_the_grace_period_is_killed_and_released(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None  # still running
        d._in_flight[5] = {'proc': fake_proc, 'done': threading.Event()}  # never set: simulates a stuck task
        with mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 0):
            d._shutdown()
        fake_proc.kill.assert_called_once()
        self.assertEqual(fc.body_for('sentinel/tasks/5/release'), {'reason': 'Sentinel shutting down'})

    def test_a_task_that_finishes_within_the_grace_period_is_left_alone(self):
        fc = FakeClient()
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        done = threading.Event()
        fake_proc = mock.Mock()
        d._in_flight[6] = {'proc': fake_proc, 'done': done}

        def finish_quickly():
            time.sleep(0.02)
            done.set()
            with d._lock:
                d._in_flight.pop(6, None)
        threading.Thread(target=finish_quickly, daemon=True).start()
        with mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 2):
            d._shutdown()
        fake_proc.kill.assert_not_called()
        self.assertNotIn(('POST', 'sentinel/tasks/6/release'), fc.paths())

    def test_request_stop_ends_the_run_loop_and_runs_shutdown(self):
        fc = FakeClient()
        fc.next_responses = []  # every tasks/next answers {'task': None}: the loop just keeps polling until stopped
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        thread = threading.Thread(target=d.run, daemon=True)
        thread.start()
        time.sleep(0.1)
        d.request_stop()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()


class ReconcileAndLogTests(unittest.TestCase):
    def _daemon(self):
        return daemon.Daemon('https://x.example', 'tok', client=FakeClient())

    def _in_flight(self, d, task_id, age=60.0):
        proc = mock.Mock()
        proc.poll.return_value = None
        state = {'proc': proc, 'done': threading.Event(), 'started': time.monotonic() - age, 'dropped': False}
        d._in_flight[task_id] = state
        return state, proc

    def test_a_task_the_server_no_longer_lists_is_killed_and_not_reported(self):
        d = self._daemon()
        mine, mine_proc = self._in_flight(d, 1)
        gone, gone_proc = self._in_flight(d, 2)
        d._reconcile([{'task_id': 1, 'status': 'running'}])
        self.assertFalse(mine['dropped'])
        mine_proc.kill.assert_not_called()
        self.assertTrue(gone['dropped'])
        gone_proc.kill.assert_called_once()
        d._report_unless_dropped(2, gone, {'outcome': 'done'})
        self.assertEqual(d.client.paths(), [])  # nothing sent for a task the server took back

    def test_a_just_accepted_task_and_an_answer_without_a_list_are_left_alone(self):
        d = self._daemon()
        young, young_proc = self._in_flight(d, 3, age=1.0)
        d._reconcile([])
        self.assertFalse(young['dropped'])
        old, old_proc = self._in_flight(d, 4)
        d._reconcile(None)
        self.assertFalse(old['dropped'])
        old_proc.kill.assert_not_called()

    def test_start_and_finish_are_logged_at_info_without_the_targets(self):
        fc = FakeClient()
        fc.next_responses = [{'task': {'id': 9, 'kind': 'nuclei_light', 'target': {'targets': ['10.0.0.1', '10.0.0.2'], 'tags': [], 'severities': []}}}]
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        with mock.patch.object(d, '_execute', return_value={'outcome': 'done', 'findings': []}), self.assertLogs('sentinel.daemon', level='INFO') as logs:
            d._poll_once()
            deadline = time.monotonic() + 5
            while d._active_count() and time.monotonic() < deadline:
                time.sleep(0.01)
        text = '\n'.join(logs.output)
        self.assertIn('task 9 accepted: nuclei_light (2 target(s))', text)
        self.assertIn('task 9 finished: nuclei_light, done', text)
        self.assertNotIn('10.0.0.1', text)
