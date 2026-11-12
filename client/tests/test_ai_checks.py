"""AI-written checks (the ``nuclei_validate`` kind) on a Sentinel that is not the built-in scanner (contract version 4).

What runs is only what the server approved: the task names the sha256 of the template, the Sentinel hashes the text it wrote to disk and read back,
and asks its own server which hash it approves for that task (``sentinel/tasks/<id>/check``); all three must agree. Then the text must pass the
same read-only check the server applies (``cvengine_scanner.checks``) and aim only at the task's own target and port. A result line for a host the
task did not name is never a hit."""
import json
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

from client import config, daemon, httpclient, scope, tools
from client.tests.test_daemon import FakeClient
from cvengine_scanner import checks, contract

CORPUS = json.loads((contract.FIXTURES / 'checks' / 'corpus.json').read_text(encoding='utf-8'))['cases']
TEXT = next(c for c in CORPUS if c['name'] == 'plain_get')['template']
SHA = checks.digest(TEXT)
OTHER = 'b' * 64


def setUpModule():
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=OSError('no DNS in these tests')),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'})),
                    mock.patch.object(scope, 'internal_allowed', return_value=False)):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


def run(mode='validate', text=TEXT, targets=None, sha=SHA, approved=(SHA, 'validate', []), builtin=False):
    return tools.run_nuclei_validate(mode, text, targets, template_sha256=sha, approved=approved, builtin=builtin)


class RefusedBeforeAnythingRunsTests(unittest.TestCase):
    """Each refusal leaves nuclei unstarted: ``_run_status`` is the only way a template reaches it."""

    def assertRefused(self, **kwargs):
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')) as started, mock.patch.object(tools, '_benign_fixture') as fixture:
            with self.assertRaises(tools.Refused) as caught:
                run(**kwargs)
        started.assert_not_called()
        fixture.assert_not_called()
        self.assertTrue(str(caught.exception).startswith('refused:'), str(caught.exception))
        return str(caught.exception)

    def test_a_check_whose_hash_the_server_did_not_approve_is_refused(self):
        why = self.assertRefused(approved=(OTHER, 'validate', []))  # the task's hash matches its text, but the server approves another one
        self.assertIn('did not approve', why)

    def test_a_check_the_server_gave_no_answer_for_is_refused(self):
        self.assertRefused(approved=None)

    def test_a_check_approved_for_the_other_mode_is_refused(self):
        self.assertRefused(mode='test', targets=['https://93.184.215.14'], approved=(SHA, 'validate', ['https://93.184.215.14']))

    def test_a_check_altered_in_transit_is_refused(self):
        altered = TEXT.replace('marker-1.2.3', 'marker-9.9.9')
        why = self.assertRefused(text=altered)  # the hash and the server's answer are the original's; the text is not
        self.assertIn('hash', why)

    def test_a_check_with_no_hash_or_a_malformed_one_is_refused(self):
        for sha in (None, '', SHA.upper(), SHA[:40], 42):
            with self.subTest(sha=str(sha)[:8]):
                self.assertRefused(sha=sha)

    def test_a_check_changed_on_disk_after_it_was_written_is_refused(self):
        def write(path, text):
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(text + '\n# appended\n')
        with mock.patch.object(tools, '_write_template', side_effect=write):
            why = self.assertRefused()
        self.assertIn('hash', why)

    def test_a_check_that_is_not_read_only_is_refused(self):
        refused = 0
        for case in CORPUS:
            if case['read_only']:
                continue
            text = case['template']
            with self.subTest(case=case['name']), mock.patch.object(tools, '_run_status') as started:
                with self.assertRaises(tools.TargetError):
                    run(text=text, sha=checks.digest(text), approved=(checks.digest(text), 'validate', []))
                started.assert_not_called()
                refused += 1
        self.assertGreater(refused, 25)

    def test_a_check_aimed_at_another_port_of_the_host_is_refused(self):
        for case in CORPUS:
            if not case['read_only'] or case['own_target']:
                continue
            text = case['template']
            with self.subTest(case=case['name']):
                why = self.assertRefused(mode='test', text=text, targets=['https://93.184.215.14'], sha=checks.digest(text),
                                         approved=(checks.digest(text), 'test', ['https://93.184.215.14']))
                self.assertIn('port', why)

    def test_a_check_aimed_at_another_host_is_refused(self):
        for name in ('absolute_url', 'raw_absolute_url', 'raw_other_host_header', 'network_other_host', 'ssl_other_address', 'base_url_then_host'):
            text = next(c for c in CORPUS if c['name'] == name)['template']
            with self.subTest(case=name):
                self.assertRefused(mode='test', text=text, targets=['https://93.184.215.14'], sha=checks.digest(text),
                                   approved=(checks.digest(text), 'test', ['https://93.184.215.14']))

    def test_a_target_outside_this_sentinels_scope_is_never_handed_to_nuclei(self):
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')) as started:
            out = run(mode='test', targets=['https://10.0.0.1'], approved=(SHA, 'test', ['https://10.0.0.1']))
        started.assert_not_called()
        self.assertIn('error', out['outcomes'][0])


class ApprovedCheckTests(unittest.TestCase):
    def test_an_approved_unchanged_read_only_check_runs_on_exactly_the_verified_file(self):
        seen = {}

        def nuclei(argv, timeout, register, work=None):
            path = argv[argv.index('-t') + 1]
            with open(path, 'rb') as handle:
                seen['sha'] = checks.digest(handle.read().decode('utf-8'))
            seen['mode'] = oct(os.stat(path).st_mode & 0o777)
            return 0, '', ''
        with mock.patch.object(tools, '_run_status', side_effect=nuclei), mock.patch.object(tools, '_benign_fixture', return_value=(True, 'no match')):
            out = run()
        self.assertEqual(seen['sha'], SHA)
        self.assertEqual(seen['mode'], '0o400')  # read-only once verified: nothing in this process rewrites it after the check
        self.assertEqual((out['valid'], out['fixture_ok'], out['template_sha256']), (True, True, SHA))

    def test_a_result_line_for_a_host_the_task_did_not_name_is_never_a_hit(self):
        asked = ['https://93.184.215.14', 'https://93.184.215.20']
        lines = [{'host': 'https://93.184.215.99', 'matched-at': 'https://93.184.215.99/x', 'matcher-name': 'word'},  # not a target at all
                 {'host': 'https://93.184.215.14', 'matched-at': 'https://198.51.100.9/x', 'matcher-name': 'word'},  # filed under a target, but matched elsewhere
                 {'host': 'https://93.184.215.20', 'matched-at': 'https://93.184.215.20/x', 'matcher-name': 'word'}]
        out_text = '\n'.join(json.dumps(line) for line in lines) + '\n'
        with mock.patch.object(tools, '_run_status', return_value=(0, out_text, '')):
            out = run(mode='test', targets=asked, approved=(SHA, 'test', sorted(asked)))
        self.assertEqual([o['host'] for o in out['outcomes']], asked)
        first, second = out['outcomes']
        self.assertFalse(first['vulnerable'])
        self.assertNotIn('198.51.100.9', json.dumps(first))
        self.assertTrue(second['vulnerable'])
        self.assertNotIn('93.184.215.99', json.dumps(out))
        self.assertEqual(out['template_sha256'], SHA)


class BuiltinScannerTests(unittest.TestCase):
    """The built-in scanner runs with the server's own trust, as before: an older server sends no hash, and the all-templates setting may hand it an
    installed template that is not read-only. A hash it is given is still checked."""

    def test_an_older_server_without_a_hash_still_gets_its_checks_run(self):
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')), mock.patch.object(tools, '_benign_fixture', return_value=(True, '')):
            out = run(sha=None, approved=None, builtin=True)
        self.assertTrue(out['valid'])
        self.assertNotIn('template_sha256', out)

    def test_a_template_that_is_not_read_only_runs_on_the_builtin_scanner_only(self):
        text = next(c for c in CORPUS if c['name'] == 'post_method')['template']
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')):
            out = run(mode='test', text=text, targets=['https://93.184.215.14'], sha=checks.digest(text),
                      approved=(checks.digest(text), 'test', ['https://93.184.215.14']), builtin=True)
        self.assertEqual(len(out['outcomes']), 1)

    def test_a_hash_given_to_the_builtin_scanner_is_still_checked(self):
        with mock.patch.object(tools, '_run_status') as started, self.assertRaises(tools.Refused):
            run(text=TEXT + '\n', approved=None, builtin=True)
        started.assert_not_called()


class DaemonAsksTheServerTests(unittest.TestCase):
    TASK = {'id': 7, 'kind': 'nuclei_validate', 'target': {'mode': 'validate', 'template': TEXT, 'template_sha256': SHA}}

    def setUp(self):
        saved = config.server_contract()
        self.addCleanup(config.set_server_contract, {'contract': {'version': saved}})
        config.set_server_contract({'contract': {'version': 4}})

    def execute(self, fc, builtin=False, task=None):
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        with mock.patch.object(config, 'builtin', return_value=builtin), \
                mock.patch.object(tools, 'run_nuclei_validate', return_value={'valid': True}) as runner, \
                mock.patch.dict(tools.RUNNERS, {'nuclei_validate': tools.run_nuclei_validate}):
            try:
                return d._execute(task or self.TASK, None), runner
            except tools.TargetError as exc:
                return exc, runner

    def test_the_server_is_asked_for_the_approved_hash_of_that_task(self):
        fc = FakeClient()
        fc.script[('GET', 'sentinel/tasks/7/check')] = [{'template_sha256': SHA, 'mode': 'validate', 'targets': []}]
        out, runner = self.execute(fc)
        self.assertEqual(out, {'outcome': 'done', 'valid': True})
        self.assertIn(('GET', 'sentinel/tasks/7/check'), fc.paths())
        kwargs = runner.call_args.kwargs
        self.assertEqual((kwargs['template_sha256'], kwargs['approved'], kwargs['builtin']), (SHA, (SHA, 'validate', []), False))

    def test_a_server_that_does_not_approve_the_task_stops_it_here(self):
        for answer in (httpclient.ApiError(404, 'no such check'), httpclient.ApiError(403, 'not yours'), {'template_sha256': 'x'}, {},
                       {'template_sha256': SHA, 'mode': 'validate'}, {'template_sha256': SHA, 'mode': 'validate', 'targets': 'x'}):
            fc = FakeClient()
            fc.script[('GET', 'sentinel/tasks/7/check')] = [answer]
            with self.subTest(answer=str(answer)[:20]):
                out, runner = self.execute(fc)
                self.assertIsInstance(out, tools.Refused)
                runner.assert_not_called()

    def test_an_external_sentinel_never_runs_a_check_for_a_server_older_than_version_four(self):
        config.set_server_contract({'contract': {'version': 3}})
        fc = FakeClient()
        out, runner = self.execute(fc)
        self.assertIsInstance(out, tools.Refused)
        runner.assert_not_called()
        self.assertNotIn(('GET', 'sentinel/tasks/7/check'), fc.paths())

    def test_the_builtin_scanner_of_an_older_server_runs_as_before(self):
        config.set_server_contract({'contract': {'version': 3}})
        fc = FakeClient()
        task = {'id': 7, 'kind': 'nuclei_validate', 'target': {'mode': 'validate', 'template': TEXT}}
        out, runner = self.execute(fc, builtin=True, task=task)
        self.assertEqual(out['outcome'], 'done')
        self.assertEqual(fc.paths(), [])
        self.assertEqual((runner.call_args.kwargs['approved'], runner.call_args.kwargs['builtin']), (None, True))


class TargetsInTheAnswerTests(unittest.TestCase):
    """Review D4: the server's answer names the task's sorted targets too, and the hashes are compared in constant time."""

    def test_a_check_for_other_targets_than_the_server_approved_is_refused(self):
        asked = ['https://93.184.215.14', 'https://93.184.215.20']
        for approved in ((SHA, 'test', ['https://93.184.215.14']), (SHA, 'test', asked + ['https://93.184.215.99']), (SHA, 'test'),
                         (SHA, 'test', [])):
            with self.subTest(approved=str(approved)[-40:]), mock.patch.object(tools, '_run_status') as started:
                with self.assertRaises(tools.Refused) as caught:
                    run(mode='test', targets=asked, approved=approved)
                started.assert_not_called()
                self.assertIn('approve', str(caught.exception))

    def test_the_answers_targets_are_compared_sorted(self):
        asked = ['https://93.184.215.20', 'https://93.184.215.14']
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')) as started:
            run(mode='test', targets=asked, approved=(SHA, 'test', sorted(asked)))
        started.assert_called_once()

    def test_the_hashes_are_compared_with_compare_digest(self):
        import hmac
        with mock.patch.object(hmac, 'compare_digest', wraps=hmac.compare_digest) as compared, \
                mock.patch.object(tools, '_run_status', return_value=(0, '', '')), mock.patch.object(tools, '_benign_fixture', return_value=(True, '')):
            run()
        self.assertGreaterEqual(compared.call_count, 2)  # the server's answer, and the file read back

    def test_the_daemon_hands_on_the_sorted_targets_of_the_answer(self):
        fc = FakeClient()
        fc.script[('GET', 'sentinel/tasks/7/check')] = [{'template_sha256': SHA, 'mode': 'test', 'targets': ['b.example.test', 'a.example.test']}]
        saved = config.server_contract()
        self.addCleanup(config.set_server_contract, {'contract': {'version': saved}})
        config.set_server_contract({'contract': {'version': 4}})
        d = daemon.Daemon('https://cve.example.test', 'tok', client=fc)
        self.assertEqual(d._approved_check(7), (SHA, 'test', ['a.example.test', 'b.example.test']))


def _ask(resolvers_file, name, qtype=1):
    """Send one DNS question to the resolver ``resolvers_file`` names and return ``(rcode, [addresses])``."""
    host, port = open(resolvers_file, encoding='ascii').read().strip().rsplit(':', 1)
    query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00' + \
        qtype.to_bytes(2, 'big') + b'\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(query, (host, int(port)))
        reply = sock.recv(4096)
    count, pos, out = int.from_bytes(reply[6:8], 'big'), len(query), []
    for _ in range(count):
        size = int.from_bytes(reply[pos + 10:pos + 12], 'big')
        out.append(str(__import__('ipaddress').ip_address(reply[pos + 12:pos + 12 + size])))
        pos += 12 + size
    return reply[3] & 0x0f, out


class PinnedAddressTests(unittest.TestCase):
    """Review D5: a name is resolved once, judged by scope, and nuclei is pointed at a resolver of the Sentinel's own that answers only that."""

    def test_nuclei_reaches_only_the_address_the_name_was_judged_by(self):
        answers = iter(['93.184.215.14'] + ['169.254.169.254'] * 10)  # the name rebinds to the metadata address after its first answer
        calls = []

        def getaddrinfo(name, port, *args, **kwargs):
            calls.append(name)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (next(answers), 0))]
        seen = {}

        def nuclei(argv, timeout, register, work=None):
            stub = argv[argv.index('-r') + 1]
            seen['pinned'] = _ask(stub, 'app.example.test')
            seen['pinned_upper'] = _ask(stub, 'APP.example.test')
            seen['other'] = _ask(stub, 'x.attacker.example')
            seen['aaaa'] = _ask(stub, 'app.example.test', 28)
            return 0, '', ''
        with mock.patch('socket.getaddrinfo', side_effect=getaddrinfo), mock.patch.object(tools, '_run_status', side_effect=nuclei):
            out = run(mode='test', targets=['https://app.example.test'], approved=(SHA, 'test', ['https://app.example.test']))
        self.assertEqual(calls, ['app.example.test'])  # resolved once, by the scope check, never again
        self.assertEqual(seen['pinned'], (0, ['93.184.215.14']))
        self.assertEqual(seen['pinned_upper'], (0, ['93.184.215.14']))
        self.assertEqual(seen['other'], (3, []))  # NXDOMAIN: a template's own lookups get no answer and reach no outside resolver
        self.assertEqual(seen['aaaa'], (0, []))
        self.assertNotIn('error', out['outcomes'][0])

    def test_the_benign_fixture_run_is_given_a_resolver_that_answers_nothing(self):
        seen = {}

        def nuclei(argv, timeout, register, work=None):
            seen['argv'] = argv
            seen['answer'] = _ask(argv[argv.index('-r') + 1], 'x.attacker.example')
            return 0, '', ''
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, 'template.yaml')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(TEXT)
            with mock.patch.object(tools, '_run_status', side_effect=nuclei):
                ok, _note = tools._benign_fixture(path, None)
        self.assertTrue(ok)
        self.assertEqual(seen['answer'], (3, []))


class NucleiProcessLimitsTests(unittest.TestCase):
    """Review D6: a check's nuclei runs with a minimal environment, a memory cap, a timeout and a cap on the output read (real child processes)."""

    def test_the_run_gets_no_secret_of_this_sentinel(self):
        script = 'import json, os; print(json.dumps(dict(os.environ)))'
        with tempfile.TemporaryDirectory() as work, mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_BLOB': 'secret-blob-value',
                                                                                  'CVENGINE_SENTINEL_TOKEN_FILE': '/state/token', 'AWS_SECRET_ACCESS_KEY': 'k'}):
            code, out, _err = tools._run_status([sys.executable, '-c', script], 30, None, work=work)
            env = json.loads(out)
        self.assertEqual(code, 0)
        self.assertNotIn('secret-blob-value', out)
        self.assertFalse([k for k in env if k.startswith('CVENGINE') or 'SECRET' in k or 'TOKEN' in k])
        self.assertEqual(env['GOMEMLIMIT'], f'{tools.admission.NUCLEI_GOMEMLIMIT_MB}MiB')
        self.assertEqual(env['TMPDIR'], work)
        self.assertTrue(set(env) <= set(tools._CHECK_ENV_KEYS) | {'GOMEMLIMIT', 'TMPDIR'}, sorted(env))

    def test_the_run_has_a_hard_memory_limit(self):
        script = 'import resource; print(resource.getrlimit(resource.RLIMIT_DATA)[0])'
        _code, out, _err = tools._run_status([sys.executable, '-c', script], 30, None)
        self.assertEqual(int(out), tools.CHECK_MEMORY_BYTES)

    def test_more_output_than_the_cap_stops_the_run(self):
        script = 'import sys, time\nfor _ in range(200): sys.stdout.write("x" * 10000); sys.stdout.flush()\ntime.sleep(30)'
        with mock.patch.object(tools, 'CHECK_OUTPUT_BYTES', 50_000), self.assertRaises(tools.ToolOutputError):
            tools._run_status([sys.executable, '-c', script], 60, None)

    def test_the_run_is_stopped_at_its_timeout(self):
        import subprocess
        import time
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            tools._run_status([sys.executable, '-c', 'import time; time.sleep(30)'], 1, None)
        self.assertLess(time.monotonic() - started, 15)


if __name__ == '__main__':
    unittest.main()
