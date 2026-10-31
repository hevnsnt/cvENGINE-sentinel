import json
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

import requests

from client import blob, config, control, daemon, httpclient, tools
from cvengine_scanner import contract


class FakeClient:
    """A scripted stand-in for httpclient.Client: records every call, and answers ``sentinel/tasks/next`` from a
    queue the test fills in, so the daemon's own state machine (poll -> accept -> execute -> report) can be driven
    deterministically without a real server or real network I/O."""

    def __init__(self):
        self.calls = []
        self.next_responses = []
        self.fail_on = set()  # a set of (method, path) pairs this fake answers with an ApiError
        self.script = {}  # (method, path) -> answers used one per call: an exception is raised, anything else returned

    def call(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if (method, path) in self.fail_on:
            raise httpclient.ApiError(409, 'scripted failure')
        if self.script.get((method, path)):
            answer = self.script[(method, path)].pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        if path == 'sentinel/tasks/next':
            return self.next_responses.pop(0) if self.next_responses else {'task': None}
        return {}

    def paths(self):
        return [(m, p) for m, p, _b in self.calls]

    def body_for(self, path):
        return next(b for _m, p, b in self.calls if p == path)

    def count(self, path):
        return sum(1 for _m, p, _b in self.calls if p == path)


class FakeProc:
    """Stands in for a ``Popen`` or an OpenVAS run's handle: all the daemon may use is ``poll()`` (None while running) and ``kill()``."""

    def __init__(self):
        self.killed = threading.Event()
        self.kill_calls = 0

    def poll(self):
        return 0 if self.killed.is_set() else None

    def kill(self):
        self.kill_calls += 1
        self.killed.set()


def fresh_tool_probe(test):
    """Let one test see ``tools.detect_tools`` (patched by it) through the daemon's once-per-process cache."""
    daemon._detected.clear()
    test.addCleanup(daemon._detected.__setitem__, 'tools', [])


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
        fresh_tool_probe(self)
        with mock.patch('client.tools.detect_tools', return_value=['nmap']), mock.patch('client.tools.gvm_ready', return_value=True):
            token, server_url = daemon.bootstrap(self._blob(), 'my-sentinel', 2, client_factory=Fake)
        self.assertEqual(token, 'cve_newtoken')
        self.assertEqual(server_url, 'https://cve.example.test')
        method, path, body = fc.calls[0]
        self.assertEqual((method, path), ('POST', 'sentinels/bootstrap'))
        self.assertEqual(body['enrollment_token'], 'senr_abc')
        self.assertEqual(body['name'], 'my-sentinel')
        self.assertEqual(sorted(body['capabilities']),
                         sorted(['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'testssl', 'nmap_udp', 'wpscan', 'openvas', 'waf']))
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
        fresh_tool_probe(self)
        with mock.patch('client.tools.detect_tools', return_value=['nmap', 'naabu']), mock.patch('client.tools.gvm_ready', return_value=True):
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
            with mock.patch('client.tools.detect_tools', return_value=[]), mock.patch('client.tools.gvm_ready', return_value=gvm):
                daemon.register(fc, 'x', 1)
            self.assertEqual('openvas' in fc.body_for('sentinel')['capabilities'], expected, gvm)

    def test_the_heartbeat_info_says_whether_this_sentinels_gvm_can_scan_and_why_not(self):
        for ready, why in ((True, ''), (False, 'GVM is still syncing its nvt feed(s)')):
            with mock.patch('client.tools.gvm_status', return_value=(ready, why)), mock.patch('client.tools.gvm_ready', return_value=ready):
                self.assertEqual(daemon.info()['openvas'], {'ready': ready, 'reason': why})

    def test_a_sentinel_without_openvas_reports_nothing_about_it(self):
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_DISABLE': 'openvas'}):
            self.assertNotIn('openvas', daemon.info())

    def test_an_operator_can_turn_a_kind_off(self):
        fc = FakeClient()
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISABLE': 'openvas, wpscan'}), \
                mock.patch('client.tools.detect_tools', return_value=[]), mock.patch('client.tools.gvm_ready', return_value=True):
            daemon.register(fc, 'x', 1)
            d = daemon.Daemon('https://x.example', 'tok', client=fc)
            kinds = d._poll_kinds()
        caps = fc.body_for('sentinel')['capabilities']
        self.assertTrue({'openvas', 'wpscan'}.isdisjoint(caps) and {'openvas', 'wpscan'}.isdisjoint(kinds))
        self.assertIn('nmap', caps)

    def test_the_poll_leaves_out_openvas_while_no_gvm_stack_answers(self):
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        with mock.patch('client.tools.gvm_ready', return_value=False):
            self.assertNotIn('openvas', d._poll_kinds())
        with mock.patch('client.tools.gvm_ready', return_value=True):
            self.assertIn('openvas', d._poll_kinds())

    def test_registration_is_sent_again_when_the_gvm_stack_comes_up_or_goes_away(self):
        sent = []
        with mock.patch('client.tools.gvm_ready', return_value=False):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.reregister = lambda: sent.append(1)
        with mock.patch('client.tools.gvm_ready', return_value=False):
            d._refresh_registration()
        self.assertEqual(sent, [])  # nothing changed since startup
        with mock.patch('client.tools.gvm_ready', return_value=True):
            d._refresh_registration()
            d._refresh_registration()
        self.assertEqual(len(sent), 1)  # told the server once, not on every heartbeat
        with mock.patch('client.tools.gvm_ready', return_value=False):
            d._refresh_registration()
        self.assertEqual(len(sent), 2)

    def test_a_failed_reregistration_is_retried_on_the_next_heartbeat(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise httpclient.ApiError(503, 'down')
        with mock.patch('client.tools.gvm_ready', return_value=False):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.reregister = flaky
        with mock.patch('client.tools.gvm_ready', return_value=True):
            d._refresh_registration()
            d._refresh_registration()
        self.assertEqual(len(calls), 2)

    def test_a_sentinel_told_it_is_internal_declares_network_internal_and_only_then(self):
        for value, expected in ((None, False), ('external', False), (' Internal ', True)):
            fc = FakeClient()
            with mock.patch.dict('os.environ'), mock.patch('client.tools.detect_tools', return_value=[]):
                os.environ.pop('CVENGINE_SENTINEL_NETWORK', None)
                if value is not None:
                    os.environ['CVENGINE_SENTINEL_NETWORK'] = value
                daemon.register(fc, 'x', 1)
            self.assertEqual(config.INTERNAL_CAPABILITY in fc.body_for('sentinel')['capabilities'], expected, value)

    def test_discover_is_declared_and_polled_only_by_an_internal_sentinel(self):
        for value, expected in ((None, False), ('internal', True)):
            fc = FakeClient()
            with mock.patch.dict('os.environ'), mock.patch('client.tools.detect_tools', return_value=[]):
                os.environ.pop('CVENGINE_SENTINEL_NETWORK', None)
                if value is not None:
                    os.environ['CVENGINE_SENTINEL_NETWORK'] = value
                daemon.register(fc, 'x', 1)
                d = daemon.Daemon('https://x.example', 'tok', client=fc)
                kinds = d._poll_kinds()
            self.assertEqual('discover' in fc.body_for('sentinel')['capabilities'], expected, value)
            self.assertEqual('discover' in kinds, expected, value)

    def test_the_poll_filter_never_carries_the_network_capability(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'}):
            d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
            kinds = d._poll_kinds()
        self.assertIn('discover', kinds)
        self.assertNotIn(config.INTERNAL_CAPABILITY, kinds)

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
            ('discover', {'cidr': '10.20.0.0/24'}, {'hosts': [{'ip': '10.20.0.5', 'hostnames': []}]}, (('10.20.0.0/24',), {})),
            ('waf', {'host': 'www.example.test', 'ip': '192.0.2.10', 'port': 443, 'scheme': 'https'}, {'products': [{'name': 'FortiWeb'}], 'generic': False},
             (('www.example.test', '192.0.2.10', 443, 'https'), {})),
            ('openvas', {'hosts': {'192.0.2.10': 'www.example.test'}, 'excluded_families': ['Denial of Service'], 'max_hours': 4},
             {'results': [], 'scanned_addresses': [], 'without_cve': 0, 'unusable': 0},
             (({'192.0.2.10': 'www.example.test'}, ['Denial of Service'], 4), {'preferences': None})),
            ('openvas', {'hosts': {'192.0.2.10': 'www.example.test'}, 'excluded_families': [], 'max_hours': 24, 'preferences': {'max_checks': 3}},
             {'results': [], 'scanned_addresses': [], 'without_cve': 0, 'unusable': 0, 'partial': True},
             (({'192.0.2.10': 'www.example.test'}, [], 24), {'preferences': {'max_checks': 3}})),
        ]
        for kind, target, fake_result, expected_call in cases:
            with self.subTest(kind=kind):
                fc = FakeClient()
                fc.next_responses = [{'task': {'id': 100, 'kind': kind, 'target': target}}]
                d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
                fake_runner = mock.Mock(return_value=fake_result)
                with mock.patch.dict(tools.RUNNERS, {kind: fake_runner}), mock.patch('client.tools.gvm_ready', return_value=True), \
                        mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'}):
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


def wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


def blocking_runner(procs):
    """A runner that starts one process and blocks until it is killed, then returns the killed run's (empty) output, as nmap would."""
    def run(addresses, register=None):
        proc = FakeProc()
        procs.append(proc)
        register(proc)
        proc.killed.wait(5)
        return {'hosts': []}
    return run


class DaemonTestCase(unittest.TestCase):
    def setUp(self):
        config.set_overrides({})
        self.addCleanup(config.set_overrides, {})
        control.set_draining(False)
        self.addCleanup(control.set_draining, False)
        env = mock.patch.dict('os.environ')
        env.start()
        self.addCleanup(env.stop)
        for name in ('CVENGINE_SENTINEL_NETWORK', 'CVENGINE_SENTINEL_DISABLE', 'CVENGINE_SENTINEL_PROFILE'):
            os.environ.pop(name, None)
        self.fc = FakeClient()

    def make(self, **kwargs):
        return daemon.Daemon('https://x.example', 'tok', client=self.fc, **kwargs)


class ShutdownRaceTests(DaemonTestCase):
    def test_a_task_killed_by_shutdown_is_released_once_and_never_reports_the_killed_run(self):
        self.fc.next_responses = [{'task': {'id': 21, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()
        procs = []
        with mock.patch.dict(tools.RUNNERS, {'nmap': blocking_runner(procs)}), mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 0.05):
            d._poll_once()
            self.assertTrue(wait_for(lambda: procs))
            d.request_stop()
            d._shutdown()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(procs[0].kill_calls, 1)
        self.assertEqual(self.fc.count('sentinel/tasks/21/release'), 1)
        self.assertEqual(self.fc.count('sentinel/tasks/21/result'), 0)

    def test_a_task_marked_done_is_never_released(self):
        d = self.make()
        done = threading.Event()
        done.set()
        d._in_flight[22] = {'proc': None, 'done': done}  # finished, not yet popped: shutdown must not release it
        with mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 0):
            d._shutdown()
        self.assertEqual(self.fc.calls, [])

    def test_a_finished_task_leaves_the_in_flight_list_before_it_is_marked_done(self):
        self.fc.next_responses = [{'task': {'id': 23, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()
        seen = []

        class SpyDone(type(threading.Event())):
            def set(self):
                with d._lock:
                    seen.append(23 in d._in_flight)
                super().set()
        gate = threading.Event()

        def runner(addresses, register=None):
            gate.wait(5)
            return {'hosts': []}
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            d._poll_once()
            with d._lock:
                d._in_flight[23]['done'] = SpyDone()
            gate.set()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(seen, [False])

    def test_sigterm_with_a_running_task_stops_polling_waits_then_drops_kills_and_releases(self):
        """A19: stop taking work, wait out the grace period, then mark dropped, kill, release exactly once and post no result."""
        self.fc.next_responses = [{'task': {'id': 24, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make(max_concurrent=2)
        procs = []
        with mock.patch.dict(tools.RUNNERS, {'nmap': blocking_runner(procs)}), mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 0.3):
            thread = threading.Thread(target=d.run, daemon=True)
            thread.start()
            self.assertTrue(wait_for(lambda: procs))
            polls_at_stop = self.fc.count('sentinel/tasks/next')
            stopped_at = time.monotonic()
            d.request_stop()  # what the SIGTERM handler does
            thread.join(timeout=5)
            elapsed = time.monotonic() - stopped_at
        self.assertFalse(thread.is_alive())
        self.assertLessEqual(self.fc.count('sentinel/tasks/next'), polls_at_stop + 1)  # at most the poll already outstanding
        self.assertGreaterEqual(elapsed, 0.3)
        self.assertEqual(procs[0].kill_calls, 1)
        self.assertEqual(self.fc.paths().count(('POST', 'sentinel/tasks/24/release')), 1)
        self.assertEqual(self.fc.body_for('sentinel/tasks/24/release'), {'reason': 'Sentinel shutting down'})
        self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(self.fc.count('sentinel/tasks/24/result'), 0)

    def test_a_task_delivering_its_result_at_shutdown_releases_it_itself_when_that_fails(self):
        d = self.make()
        self.fc.script[('POST', 'sentinel/tasks/25/result')] = [httpclient.ApiError(503, 'down')] * 10
        task = {'id': 25, 'kind': 'nmap', 'target': {}}
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic(), 'dropped': False, 'finishing': False,
                 'kind': 'nmap', 'runnable': True}
        d._in_flight[25] = state
        with mock.patch.object(d, '_execute', return_value={'outcome': 'done', 'hosts': []}), mock.patch.object(daemon, 'REPORT_BACKOFF', 5), \
                mock.patch('client.daemon.config.SHUTDOWN_GRACE_SECONDS', 0.1):
            thread = threading.Thread(target=d._run_task, args=(task, state), daemon=True)
            thread.start()
            self.assertTrue(wait_for(lambda: self.fc.count('sentinel/tasks/25/result') == 1))
            d._shutdown()  # its thread is waiting to retry: shutdown ends that wait, and the thread releases the task
            thread.join(timeout=5)
        self.assertEqual(self.fc.count('sentinel/tasks/25/result'), 1)
        self.assertEqual(self.fc.count('sentinel/tasks/25/release'), 1)


class InterruptibleWaitTests(DaemonTestCase):
    def test_a_stop_during_a_backoff_ends_the_loop_at_once(self):
        self.fc.script[('POST', 'sentinel/tasks/next')] = [httpclient.ApiError(503, 'down')] * 50
        d = self.make()
        d._backoff = daemon.MAX_BACKOFF
        thread = threading.Thread(target=d.run, daemon=True)
        thread.start()
        self.assertTrue(wait_for(lambda: self.fc.count('sentinel/tasks/next') >= 1))
        started = time.monotonic()
        d.request_stop()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 3)

    def test_a_stop_while_drained_ends_the_loop_at_once(self):
        control.set_draining(True)
        d = self.make()
        thread = threading.Thread(target=d.run, daemon=True)
        with mock.patch('client.daemon.control.set_draining'):  # run() clears a stale drain at start; keep this one
            thread.start()
            time.sleep(0.1)
            started = time.monotonic()
            d.request_stop()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(self.fc.count('sentinel/tasks/next'), 0)


class ReportRetryTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        patch = mock.patch.object(daemon, 'REPORT_BACKOFF', 0.001)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_transient_failure_is_retried_until_the_result_gets_through(self):
        self.fc.script[('POST', 'sentinel/tasks/31/result')] = [httpclient.ApiError(503, 'down'), requests.ConnectionError('reset'),
                                                                 httpclient.ApiError(429, 'slow down'), {}]
        self.make()._report(31, {'outcome': 'done'})
        self.assertEqual(self.fc.count('sentinel/tasks/31/result'), 4)
        self.assertEqual(self.fc.count('sentinel/tasks/31/release'), 0)

    def test_a_final_refusal_is_not_retried(self):
        for status in (400, 409, 410):
            fc = FakeClient()
            fc.script[('POST', 'sentinel/tasks/32/result')] = [httpclient.ApiError(status, 'no')]
            daemon.Daemon('https://x.example', 'tok', client=fc)._report(32, {'outcome': 'done'})
            self.assertEqual((fc.count('sentinel/tasks/32/result'), fc.count('sentinel/tasks/32/release')), (1, 0), status)

    def test_a_result_that_never_gets_through_releases_the_task(self):
        self.fc.script[('POST', 'sentinel/tasks/33/result')] = [httpclient.ApiError(502, 'bad gateway')] * 20
        self.make()._report(33, {'outcome': 'done'})
        self.assertEqual(self.fc.count('sentinel/tasks/33/result'), daemon.REPORT_ATTEMPTS)
        self.assertEqual(self.fc.count('sentinel/tasks/33/release'), 1)

    def test_retries_stop_within_the_time_bound(self):
        self.fc.script[('POST', 'sentinel/tasks/34/result')] = [httpclient.ApiError(503, 'down')] * 20
        with mock.patch.object(daemon, 'REPORT_RETRY_SECONDS', 0), mock.patch.object(daemon, 'REPORT_BACKOFF', 1):
            self.make()._report(34, {'outcome': 'done'})
        self.assertEqual(self.fc.count('sentinel/tasks/34/result'), 1)
        self.assertEqual(self.fc.count('sentinel/tasks/34/release'), 1)

    def test_nothing_is_retried_once_the_grace_period_is_over(self):
        self.fc.script[('POST', 'sentinel/tasks/35/result')] = [httpclient.ApiError(503, 'down')] * 20
        d = self.make()
        d._halted.set()
        d._report(35, {'outcome': 'done'})
        self.assertEqual(self.fc.count('sentinel/tasks/35/result'), 1)
        self.assertEqual(self.fc.count('sentinel/tasks/35/release'), 1)


class MalformedReplyTests(DaemonTestCase):
    def test_a_malformed_task_is_skipped_never_accepted_and_never_crashes(self):
        bad = [{'kind': 'nmap'}, ['x'], 'task', 7, {'id': 'a/b', 'kind': 'nmap'}, {'id': '../x', 'kind': 'nmap'}, {'id': 'abc\n', 'kind': 'nmap'},
               {'id': 'x' * 65, 'kind': 'nmap'}, {'id': True, 'kind': 'nmap'}, {'id': -1, 'kind': 'nmap'}, {'id': 1.5, 'kind': 'nmap'},
               {'id': 1, 'kind': 5}, {'id': 1}, {'id': None, 'kind': 'nmap'}]
        for task in bad:
            with self.subTest(task=task):
                fc = FakeClient()
                fc.next_responses = [{'task': task}]
                d = daemon.Daemon('https://x.example', 'tok', client=fc)
                with mock.patch.object(d.stop_event, 'wait') as wait:
                    d._poll_once()
                self.assertEqual(fc.paths(), [('POST', 'sentinel/tasks/next')])
                wait.assert_called()  # backed off briefly
        for reply in (['task'], 'x', None):
            fc = FakeClient()
            fc.next_responses = [reply]
            daemon.Daemon('https://x.example', 'tok', client=fc)._poll_once()
            self.assertEqual(fc.paths(), [('POST', 'sentinel/tasks/next')])

    def test_a_well_formed_text_id_is_accepted(self):
        self.fc.next_responses = [{'task': {'id': 'task_01-ab', 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()
        with mock.patch.dict(tools.RUNNERS, {'nmap': mock.Mock(return_value={'hosts': []})}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertIn(('POST', 'sentinel/tasks/task_01-ab/accept'), self.fc.paths())

    def test_an_unexpected_error_in_the_poll_loop_is_logged_and_the_loop_goes_on(self):
        self.fc.script[('POST', 'sentinel/tasks/next')] = [ValueError('surprise'), RuntimeError('again'), {'task': None}]
        d = self.make()
        d._backoff = 0.01
        thread = threading.Thread(target=d.run, daemon=True)
        with self.assertLogs('sentinel.daemon', level='ERROR'):
            thread.start()
            self.assertTrue(wait_for(lambda: self.fc.count('sentinel/tasks/next') >= 3))
        d.request_stop()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    def test_an_unexpected_error_in_a_heartbeat_does_not_end_the_heartbeat_thread(self):
        d = self.make(heartbeat_seconds=0.01)
        with mock.patch.object(d, 'apply_settings', side_effect=RuntimeError('bug')), self.assertLogs('sentinel.daemon', level='ERROR'):
            thread = threading.Thread(target=d._heartbeat_loop, daemon=True)
            thread.start()
            self.assertTrue(wait_for(lambda: self.fc.count('sentinel/heartbeat') >= 3))
            d.request_stop()
            thread.join(timeout=2)

    def test_a_lease_list_with_odd_items_does_not_raise(self):
        d = self.make()
        proc = FakeProc()
        d._in_flight[1] = {'proc': proc, 'done': threading.Event(), 'started': time.monotonic() - 60, 'dropped': False}
        d._reconcile([{'task_id': ['unhashable']}, {'task_id': {'a': 1}}, 'x', None, {'task_id': 1}])
        self.assertEqual(proc.kill_calls, 0)

    def test_the_updater_status_is_written_even_when_the_heartbeat_fails(self):
        self.fc.fail_on = {('POST', 'sentinel/heartbeat')}
        control.write_status('v', 0, None, now=1000)
        self.make()._heartbeat_once()
        self.assertGreater(control.read_status()['at'], 1000)


class ContractVersionTests(DaemonTestCase):
    """The Sentinel declares the result contract it speaks at registration and every heartbeat, and says once when the server needs a newer one."""

    BEHIND = 'this Sentinel speaks contract %s, the server needs at least %s: update it'

    def test_the_version_is_the_packaged_contracts_and_waf_is_declared(self):
        with open(contract.PATH, encoding='utf-8') as handle:
            packaged = json.load(handle)['contract_version']
        self.assertEqual(config.CONTRACT_VERSION, packaged)
        self.assertGreaterEqual(config.CONTRACT_VERSION, 2)  # the version that introduced the waf kind
        self.assertEqual(daemon.info()['contract_version'], packaged)
        self.assertIn('waf', config.CAPABILITIES)
        self.assertIn('waf', daemon.declared_kinds())
        self.assertIn('waf', tools.RUNNERS)

    def test_registration_and_every_heartbeat_carry_it(self):
        with mock.patch('client.tools.detect_tools', return_value=[]):
            daemon.register(self.fc, 'x', 1)
        self.assertEqual(self.fc.body_for('sentinel')['info']['contract_version'], config.CONTRACT_VERSION)
        d = self.make()
        d._heartbeat_once()
        d._heartbeat_once()
        beats = [b for _m, p, b in self.fc.calls if p == 'sentinel/heartbeat']
        self.assertEqual([b['info']['contract_version'] for b in beats], [config.CONTRACT_VERSION] * 2)

    def test_a_sentinel_behind_the_server_says_so_once_and_keeps_heartbeating(self):
        behind = {'contract': {'version': config.CONTRACT_VERSION + 2, 'min_supported': config.CONTRACT_VERSION + 1}}
        self.fc.script[('POST', 'sentinel/heartbeat')] = [behind, behind, behind]
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            for _ in range(3):
                d._heartbeat_once()
        lines = [line for line in logs.output if 'contract' in line]
        self.assertEqual(len(lines), 1)
        self.assertIn(self.BEHIND % (config.CONTRACT_VERSION, config.CONTRACT_VERSION + 1), lines[0])
        self.assertEqual(self.fc.count('sentinel/heartbeat'), 3)

    def test_a_registration_reply_is_read_too_and_a_raised_minimum_is_said_again(self):
        d = self.make()
        d.reregister = lambda: {'contract': {'version': config.CONTRACT_VERSION + 1, 'min_supported': config.CONTRACT_VERSION + 1}}
        with self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            d.start_registration()
            d._note_contract({'contract': {'version': config.CONTRACT_VERSION + 1, 'min_supported': config.CONTRACT_VERSION + 1}})
            d._note_contract({'contract': {'version': config.CONTRACT_VERSION + 3, 'min_supported': config.CONTRACT_VERSION + 3}})
        self.assertEqual(len([line for line in logs.output if 'update it' in line]), 2)

    def test_nothing_is_logged_when_this_sentinel_is_current_or_the_reply_is_odd(self):
        d = self.make()
        replies = [{'contract': {'version': config.CONTRACT_VERSION, 'min_supported': config.CONTRACT_VERSION}},
                   {'contract': {'version': 1, 'min_supported': 1}}, {'contract': {'min_supported': True}}, {'contract': {'min_supported': '9'}},
                   {'contract': 'x'}, {'contract': None}, {}, [], None, 'x']
        with self.assertNoLogs('sentinel.daemon', level='WARNING'):
            for reply in replies:
                d._note_contract(reply)


class KindPolicyTests(DaemonTestCase):
    def _run_one(self, task, runner):
        self.fc.next_responses = [{'task': task}]
        d = self.make()
        with mock.patch.dict(tools.RUNNERS, {task['kind']: runner}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        return self.fc.body_for(f'sentinel/tasks/{task["id"]}/result')

    def test_a_kind_this_sentinel_does_not_poll_for_is_refused_not_run(self):
        os.environ['CVENGINE_SENTINEL_DISABLE'] = 'wpscan'
        runner = mock.Mock(return_value={})
        body = self._run_one({'id': 41, 'kind': 'wpscan', 'target': {'url': 'https://www.example.test'}}, runner)
        runner.assert_not_called()
        self.assertEqual(body, {'outcome': 'error', 'error': 'this Sentinel does not run wpscan work'})

    def test_discover_runs_only_where_this_machine_says_it_is_internal(self):
        config.set_overrides({'network': 'internal'})  # the server says internal; this machine does not
        d = self.make()
        self.assertNotIn('discover', d._poll_kinds())
        self.assertNotIn('discover', daemon.declared_kinds())
        runner = mock.Mock(return_value={'hosts': []})
        body = self._run_one({'id': 42, 'kind': 'discover', 'target': {'cidr': '10.0.0.0/24'}}, runner)
        runner.assert_not_called()
        self.assertEqual(body['outcome'], 'error')
        with mock.patch.dict(tools.RUNNERS, {'discover': runner}), self.assertRaises(tools.TargetError):
            d._execute({'id': 43, 'kind': 'discover', 'target': {'cidr': '10.0.0.0/24'}}, None)
        runner.assert_not_called()

    def test_the_polled_kinds_follow_a_network_setting_from_the_server(self):
        os.environ['CVENGINE_SENTINEL_NETWORK'] = 'internal'
        d = self.make()
        d.reregister = lambda: {}
        self.assertIn('discover', d._poll_kinds())
        d.apply_settings({'values': {'network': 'external'}, 'rev': 'r1'})
        self.assertNotIn('discover', d._poll_kinds())
        self.assertNotIn('discover', daemon.declared_kinds())
        d.apply_settings({'values': {'network': 'internal'}, 'rev': 'r2'})
        self.assertIn('discover', d._poll_kinds())
        self.assertIn('discover', daemon.declared_kinds())
        self.assertIn(config.INTERNAL_CAPABILITY, daemon.declared_kinds())


class DrainDuringPollTests(DaemonTestCase):
    def _poll_with(self, during):
        """One poll whose reply comes back after ``during(daemon)`` ran: what happens to the task it returns."""
        test = self

        class Client(FakeClient):
            def call(self, method, path, body=None, timeout=None):
                if path == 'sentinel/tasks/next':
                    test.status_during_poll = control.read_status().get('in_flight')
                    during(test.d)
                return super().call(method, path, body, timeout)
        self.fc = Client()
        self.fc.next_responses = [{'task': {'id': 51, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        self.d = self.make()
        runner = mock.Mock(return_value={'hosts': []})
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            self.d._poll_once()
        runner.assert_not_called()
        self.assertNotIn(('POST', 'sentinel/tasks/51/accept'), self.fc.paths())

    def test_a_drain_set_while_the_poll_was_out_releases_the_task_it_returned(self):
        self._poll_with(lambda d: control.set_draining(True))
        self.assertEqual(self.fc.body_for('sentinel/tasks/51/release'), {'reason': 'Sentinel is draining'})

    def test_a_stop_while_the_poll_was_out_releases_the_task_it_returned(self):
        self._poll_with(lambda d: d.request_stop())
        self.assertEqual(self.fc.body_for('sentinel/tasks/51/release'), {'reason': 'Sentinel shutting down'})

    def test_an_outstanding_poll_counts_as_busy_for_the_updater(self):
        self._poll_with(lambda d: control.set_draining(True))
        self.assertEqual(self.status_during_poll, 1)
        self.assertEqual(control.read_status()['in_flight'], 0)


class RegistrationLifecycleTests(DaemonTestCase):
    def test_a_registration_that_failed_at_startup_is_retried_by_the_heartbeat(self):
        d = self.make()
        attempts = []

        def flaky():
            attempts.append(1)
            if len(attempts) == 1:
                raise requests.ConnectionError('server down at boot')
            return {}
        d.reregister = flaky
        d.start_registration()
        self.assertTrue(d._register_pending)
        d._heartbeat_once()
        self.assertEqual(len(attempts), 2)
        self.assertFalse(d._register_pending)
        d._heartbeat_once()
        self.assertEqual(len(attempts), 2)  # registered: nothing more to send

    def test_startup_registers_once_when_the_servers_settings_change_nothing_it_reports(self):
        d = self.make()
        sent = []
        d.reregister = lambda: sent.append(1) or {'settings': {'values': {'self_update': 'off'}, 'rev': 'r1'}}
        d.start_registration()
        self.assertEqual(len(sent), 1)
        self.assertEqual(config.overrides(), {'self_update': 'off'})

    def test_startup_registers_again_when_the_servers_settings_change_what_it_reports(self):
        d = self.make()
        sent = []
        d.reregister = lambda: sent.append(config.max_concurrent()) or {'settings': {'values': {'max_concurrent': 7}, 'rev': 'r1'}}
        d.start_registration()
        self.assertEqual(sent[-1], 7)
        self.assertEqual(len(sent), 2)


class RevokedTokenTests(DaemonTestCase):
    def test_a_revoked_token_on_the_poll_stops_the_daemon_with_an_error(self):
        for status in (401, 403):
            fc = FakeClient()
            fc.script[('POST', 'sentinel/tasks/next')] = [httpclient.ApiError(status, 'no')]
            d = daemon.Daemon('https://x.example', 'tok', client=fc)
            with self.assertLogs('sentinel.daemon', level='ERROR') as logs:
                d._poll_once()
            self.assertTrue(d.stop_event.is_set())
            self.assertEqual(d.exit_code, 1)
            self.assertIn('re-enroll', '\n'.join(logs.output))

    def test_a_revoked_token_on_the_heartbeat_stops_the_daemon(self):
        self.fc.script[('POST', 'sentinel/heartbeat')] = [httpclient.ApiError(401, 'no')]
        d = self.make()
        d._heartbeat_once()
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (True, 1))

    def test_a_server_error_is_still_only_a_backoff(self):
        self.fc.script[('POST', 'sentinel/tasks/next')] = [httpclient.ApiError(503, 'busy')]
        d = self.make()
        with mock.patch.object(d.stop_event, 'wait'):
            d._poll_once()
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))

    def test_the_backoff_has_jitter(self):
        d = self.make()
        waits = []
        with mock.patch.object(d.stop_event, 'wait', side_effect=waits.append):
            for _ in range(20):
                d._backoff = 8.0
                d._sleep_backoff()
        self.assertTrue(all(4.0 <= w <= 8.0 for w in waits))
        self.assertGreater(len(set(waits)), 1)


class AtomicTokenTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, 'token.json')

    def test_a_failed_save_leaves_the_previous_token_and_no_temporary_file(self):
        daemon.save_token(self.path, 'cve_first', 'https://cve.example.test')
        for where in ('client.daemon.os.replace', 'client.daemon.os.fsync'):
            with mock.patch(where, side_effect=OSError('disk full')), self.assertRaises(OSError):
                daemon.save_token(self.path, 'cve_second', 'https://cve.example.test')
            self.assertEqual(daemon.load_token(self.path), ('cve_first', 'https://cve.example.test'), where)
            self.assertEqual(os.listdir(self.dir), ['token.json'], where)

    def test_the_token_is_synced_before_it_replaces_the_old_one(self):
        order = []
        real_fsync, real_replace = os.fsync, os.replace
        with mock.patch('client.daemon.os.fsync', side_effect=lambda fd: order.append('fsync') or real_fsync(fd)), \
                mock.patch('client.daemon.os.replace', side_effect=lambda a, b: order.append('replace') or real_replace(a, b)):
            daemon.save_token(self.path, 'cve_tok', 'https://cve.example.test')
        self.assertEqual(order[:2], ['fsync', 'replace'])
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_valid_json_that_is_not_an_object_is_no_token(self):
        for content in ('[]', '"x"', '3', 'null'):
            with open(self.path, 'w', encoding='utf-8') as handle:
                handle.write(content)
            self.assertEqual(daemon.load_token(self.path), (None, None), content)

    def test_a_token_that_could_not_be_saved_is_saved_by_a_later_heartbeat(self):
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.keep_saving_token(self.path, 'cve_tok', 'https://cve.example.test')
        with mock.patch('client.daemon.save_token', side_effect=OSError('read-only')):
            d._heartbeat_once()
        self.assertEqual(daemon.load_token(self.path), (None, None))
        d._heartbeat_once()
        self.assertEqual(daemon.load_token(self.path), ('cve_tok', 'https://cve.example.test'))
        self.assertIsNone(d._unsaved_token)


class EfficiencyTests(DaemonTestCase):
    def test_info_is_computed_once_per_heartbeat_and_per_registration(self):
        with mock.patch('client.daemon.info', return_value={'updater': {}}) as info:
            self.make()._heartbeat_once()
            self.assertEqual(info.call_count, 1)
            daemon.register(FakeClient(), 'x', 1)
            self.assertEqual(info.call_count, 2)

    def test_the_tools_are_probed_once_per_process(self):
        fresh_tool_probe(self)
        with mock.patch('client.tools.detect_tools', return_value=['nmap']) as probe:
            daemon.register(FakeClient(), 'x', 1)
            daemon.register(FakeClient(), 'x', 1)
        self.assertEqual(probe.call_count, 1)

    def test_a_task_started_after_the_heartbeat_was_sent_is_not_killed_by_its_late_reply(self):
        d = self.make()
        proc = FakeProc()
        d._in_flight[61] = {'proc': proc, 'done': threading.Event(), 'started': time.monotonic() - 30, 'dropped': False}
        d._reconcile([], asked_at=time.monotonic() - 60)  # the reply took a minute: it was asked before the task started
        self.assertEqual(proc.kill_calls, 0)
        self.assertFalse(d._in_flight[61]['dropped'])


class KillTests(DaemonTestCase):
    def test_a_process_started_after_the_task_was_dropped_is_killed_at_once(self):
        """A17: nmap runs its IPv4 group, then its IPv6 group; killing the first must not let the second run to its timeout."""
        self.fc.next_responses = [{'task': {'id': 71, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1', '2001:db8::1']}}}]
        d = self.make()
        procs = []

        def two_groups(addresses, register=None):
            for _ in range(2):
                proc = FakeProc()
                procs.append(proc)
                register(proc)
                proc.killed.wait(5)
            return {'hosts': []}
        with mock.patch.dict(tools.RUNNERS, {'nmap': two_groups}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: procs))
            with d._lock:
                d._in_flight[71]['started'] -= 60
            d._reconcile([])
            self.assertTrue(wait_for(lambda: d._active_count() == 0))
        self.assertEqual(len(procs), 2)
        self.assertTrue(all(p.killed.is_set() for p in procs))
        self.assertEqual(self.fc.count('sentinel/tasks/71/result'), 0)

    def test_a_process_registered_after_the_grace_period_is_killed_at_once(self):
        d = self.make()
        state = {'proc': None, 'done': threading.Event(), 'dropped': False}
        d._halted.set()
        proc = FakeProc()
        d._register_proc(state)(proc)
        self.assertEqual(proc.kill_calls, 1)

    def test_an_openvas_handle_is_stopped_like_a_process(self):
        class Handle:
            def __init__(self):
                self.stopped = False

            def poll(self):
                return 'stopped' if self.stopped else None

            def kill(self):
                self.stopped = True
        d = self.make()
        handle = Handle()
        state = {'proc': None, 'done': threading.Event(), 'started': time.monotonic() - 60, 'dropped': False, 'kind': 'openvas'}
        d._register_proc(state)(handle)
        d._in_flight[72] = state
        d._reconcile([])
        self.assertTrue(handle.stopped)
        d._kill(mock.Mock(poll=mock.Mock(return_value=None), kill=mock.Mock(side_effect=RuntimeError('gvmd gone'))))  # never raises


class OpenvasSlotTests(DaemonTestCase):
    def setUp(self):
        super().setUp()
        patch = mock.patch('client.tools.gvm_ready', return_value=True)
        patch.start()
        self.addCleanup(patch.stop)

    def _running(self, d, *kinds):
        for i, kind in enumerate(kinds):
            d._in_flight[100 + i] = {'proc': None, 'done': threading.Event(), 'kind': kind}

    def test_openvas_does_not_take_a_regular_slot(self):
        d = self.make(max_concurrent=1)
        self._running(d, 'openvas')
        plan = d._poll_plan()
        self.assertIn('nmap', plan)
        self.assertNotIn('openvas', plan)  # one OpenVAS at a time

    def test_with_every_regular_slot_taken_only_openvas_is_asked_for(self):
        d = self.make(max_concurrent=1)
        self._running(d, 'nmap')
        self.assertEqual(d._poll_plan(), ['openvas'])
        self.fc.next_responses = [{'task': None}]
        d._poll_once()
        self.assertEqual(self.fc.body_for('sentinel/tasks/next')['kinds'], ['openvas'])

    def test_with_everything_taken_nothing_is_polled(self):
        d = self.make(max_concurrent=1)
        self._running(d, 'nmap', 'openvas')
        with mock.patch.object(d.stop_event, 'wait'):
            d._poll_once()
        self.assertEqual(self.fc.calls, [])

    def test_a_second_openvas_task_sent_anyway_is_refused(self):
        d = self.make(max_concurrent=2)
        self._running(d, 'openvas')
        self.fc.next_responses = [{'task': {'id': 73, 'kind': 'openvas', 'target': {'hosts': {'192.0.2.1': ''}}}}]
        runner = mock.Mock(return_value={})
        with mock.patch.dict(tools.RUNNERS, {'openvas': runner}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: 73 not in d._in_flight))
        runner.assert_not_called()
        self.assertEqual(self.fc.body_for('sentinel/tasks/73/result')['outcome'], 'error')


if __name__ == '__main__':
    unittest.main()
