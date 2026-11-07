"""The signed-in route check on the built-in scanner (``route_probe_signed``): the credential is read once through the server's single-use read, only the
built-in scanner takes the kind, and a canary credential never appears in a result, a log line or an exception."""
import json
import logging
import os
import shutil
import tempfile
import unittest
from unittest import mock

from client import config, daemon, httpclient, signed_in, tools
from client.tests.test_builtin import Env
from cvengine_scanner.probes import http, routes_signed

WWW = 'www.example.test'
SCOPE = {'hosts': [WWW], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}
CANARY_HEADER = 'CANARYHEADER-9f3a77c1d2'
CANARY_COOKIE = 'CANARYCOOKIE-51be0a99e4'
CREDENTIAL = {'headers': [['Authorization', f'Bearer {CANARY_HEADER}'], ['X-Api-Key', f'key-{CANARY_HEADER}-k']], 'cookie': f'sid={CANARY_COOKIE}; theme=darkmode',
              'target': 'example.test', 'host': WWW, 'origins': ['https:443'], 'host_scoped': False, 'allow_untrusted_certificate': False, 'expires_at': None,
              'revision': '1.1'}
TARGET = {'hosts': [{'host': WWW, 'urls': [f'https://{WWW}/', f'https://{WWW}/account', f'https://{WWW}/boom']}], 'scope': SCOPE}
TASK = {'id': 11, 'kind': 'route_probe_signed', 'signed_in': True, 'target': TARGET}


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.text = []

    def emit(self, record):
        self.text.append(self.format(record))
        if record.exc_info:
            import traceback
            self.text.append(''.join(traceback.format_exception(*record.exc_info)))


def echoing_probe(url, policy, max_bytes=0, signed=None, verify=True, **kw):
    """A hostile application: it echoes every header it was sent into the title, the redirect target and the body, and one route fails with a library error
    that quotes a header value, the way a client library may."""
    policy.check_host(WWW)
    policy.touch(WWW)
    sent = ' '.join(f'{k}={v}' for k, v in signed or ())
    if url.endswith('/boom'):
        raise ValueError(f'Invalid header value {sent!r}')
    answer = {'url': url, 'status': 200, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html',
              'body': f'<h1>Hello</h1> {sent}', 'title': f'Welcome {sent}', 'bytes': 40}
    if url.endswith('/account'):
        answer.update(status=302, location=f'/login?echo={CANARY_HEADER}&c={CANARY_COOKIE}')
    return answer


class Base(Env):
    def setUp(self):
        super().setUp()
        self.logs = Capture()
        root = logging.getLogger()
        self.old_level = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(self.logs)
        self.addCleanup(root.removeHandler, self.logs)
        self.addCleanup(root.setLevel, self.old_level)
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch('cvengine_scanner.probes.routes.PER_REQUEST_GAP', 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def engine(self, credential=None, error=None):
        client = mock.Mock()
        if error:
            client.call.side_effect = error
        else:
            client.call.return_value = {'credential': dict(credential or CREDENTIAL), 'task_id': 11}
        return daemon.Daemon('https://cve.example.test', 't', client=client)

    def assertNoCanary(self, *things):
        blob = '\n'.join(str(t) if not isinstance(t, (dict, list)) else json.dumps(t) for t in things) + '\n'.join(self.logs.text)
        for value in (CANARY_HEADER, CANARY_COOKIE):
            self.assertNotIn(value, blob)


class RunTests(Base):
    def test_the_credential_is_read_once_and_the_result_has_the_route_probe_shape(self):
        engine = self.engine()
        sent_to = []

        def recording(url, policy, signed=None, verify=True, **kw):
            sent_to.append((url, list(signed or ()), verify))  # a copy: the run clears its own list at the end
            return echoing_probe(url, policy, signed=signed, verify=verify, **kw)
        with mock.patch.object(http, 'probe_url', side_effect=recording):
            out = engine._execute(TASK, lambda proc: None)
        engine.client.call.assert_called_once_with('POST', 'sentinel/tasks/11/secret')
        self.assertEqual(out['outcome'], 'done')
        rows = {r['id'].split(WWW)[1]: r for r in out['routes']}
        self.assertEqual((rows['/']['state'], rows['/account']['state']), ('open', 'session_required'))
        self.assertIn('error', rows['/boom'])
        self.assertNotIn('state', rows['/boom'])
        self.assertEqual(sent_to[0][1][0], ('Authorization', f'Bearer {CANARY_HEADER}'))  # it was really sent to the covered route
        self.assertTrue(sent_to[0][2])
        self.assertEqual(out['touched'], [WWW])

    def test_a_canary_credential_is_in_no_result_log_line_or_exception(self):
        engine = self.engine()
        with mock.patch.object(http, 'probe_url', side_effect=echoing_probe):
            out = engine._execute(TASK, lambda proc: None)
        self.assertNoCanary(out)
        self.assertIn('***', json.dumps(out))  # what the application echoed is replaced, not dropped silently
        rows = {r['id'].split(WWW)[1]: r for r in out['routes']}
        self.assertNotIn('theme=darkmode', rows['/']['title'])  # a long enough cookie part is redacted too

    def test_a_failure_of_the_whole_run_raises_an_error_without_the_value(self):
        engine = self.engine()

        def explode(target, sign_in, register=None):
            raise RuntimeError(f'could not send Authorization: Bearer {CANARY_HEADER} with {CANARY_COOKIE}')
        with mock.patch.dict(tools.RUNNERS, {'route_probe_signed': explode}), self.assertRaises(tools.TargetError) as caught:
            engine._execute(TASK, lambda proc: None)
        self.assertNoCanary(str(caught.exception), repr(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_a_malformed_stored_sign_in_is_refused_without_the_value(self):
        engine = self.engine({**CREDENTIAL, 'headers': [['Authorization', f'Bearer {CANARY_HEADER}\r\nX-Evil: 1']]})
        with mock.patch.object(http, 'probe_url') as probe, self.assertRaises(tools.TargetError) as caught:
            engine._execute(TASK, lambda proc: None)
        probe.assert_not_called()
        self.assertNoCanary(str(caught.exception))

    def test_a_refused_read_is_an_error_and_nothing_is_sent(self):
        engine = self.engine(error=httpclient.ApiError(409, 'already read'))
        with mock.patch.object(http, 'probe_url') as probe, self.assertRaises(tools.TargetError):
            engine._execute(TASK, lambda proc: None)
        probe.assert_not_called()

    def test_the_credential_is_dropped_from_memory_when_the_run_ends(self):
        kept = {}

        def runner(target, sign_in, register=None):
            kept['sign_in'] = sign_in
            return {'routes': [], 'touched': [], 'refused': []}
        with mock.patch.dict(tools.RUNNERS, {'route_probe_signed': runner}):
            self.engine()._execute(TASK, lambda proc: None)
        self.assertEqual(kept['sign_in'].headers, [])

    def test_a_route_outside_the_credentials_reach_is_never_sent_the_sign_in(self):
        target = {'hosts': [{'host': WWW, 'urls': [f'https://{WWW}/', f'http://{WWW}/', f'https://{WWW}:8443/']}], 'scope': SCOPE}
        with mock.patch.object(http, 'probe_url', side_effect=echoing_probe) as probe:
            out = self.engine()._execute({**TASK, 'target': target}, lambda proc: None)
        self.assertEqual([c.args[0] for c in probe.call_args_list], [f'https://{WWW}/'])
        self.assertEqual(sum('error' in r for r in out['routes']), 2)


class GateTests(Base):
    builtin = False

    def test_an_external_sentinel_refuses_the_task_and_never_reads_the_credential(self):
        engine = self.engine()
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'route_probe_signed': runner}), self.assertRaises(tools.TargetError):
            engine._execute(TASK, lambda proc: None)
        runner.assert_not_called()
        engine.client.call.assert_not_called()

    def test_an_external_sentinel_does_not_declare_the_kind(self):
        self.assertIn('route_probe_signed', config.CAPABILITIES)
        with mock.patch.object(config, 'server_knows', return_value=True), mock.patch.object(daemon, 'detected_tools', return_value=[]):
            self.assertNotIn('route_probe_signed', daemon.runnable_kinds())


class BuiltinDeclaresTests(Base):
    def test_the_builtin_scanner_declares_the_kind(self):
        with mock.patch.object(config, 'server_knows', return_value=True), mock.patch.object(daemon, 'detected_tools', return_value=[]):
            self.assertIn('route_probe_signed', daemon.runnable_kinds())

    def test_a_task_that_does_not_name_a_stored_sign_in_never_runs_signed_out(self):
        engine = self.engine()
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'route_probe_signed': runner}), self.assertRaises(tools.TargetError):
            engine._execute({**TASK, 'signed_in': False}, lambda proc: None)
        runner.assert_not_called()
        engine.client.call.assert_not_called()

    def test_the_kind_is_in_the_runner_table_and_the_contract(self):
        from cvengine_scanner import contract
        self.assertIn('route_probe_signed', tools.RUNNERS)
        self.assertEqual(config.KIND_SINCE['route_probe_signed'], 3)
        self.assertIn('route_probe_signed', contract.load()['$defs']['targets'])


if __name__ == '__main__':
    unittest.main()
