"""The ssh_probe runner (``client.tools.run_ssh_probe``): the command it runs, its temporary output file and the cases that must stay unverified."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from client import tools
from cvengine_scanner.probes import ssh_probe

# the captured sample, as if the tool had been pointed at 93.184.215.14 (the floor refuses documentation space, so a test target is a routable address)
SAMPLE = (Path(__file__).resolve().parents[2] / 'cvengine_scanner' / 'tests' / 'fixtures' / 'ssh_probe_openssh.jsonl').read_text(encoding='utf-8').replace(
    '192.0.2.10', '93.184.215.14')
SCOPE = {'hosts': ['93.184.215.14', '93.184.215.30'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}


def task(*pairs, scope=SCOPE):
    return {'targets': [{'address': a, 'port': p} for a, p in pairs], 'scope': scope}


class RunnerTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.calls = []

    def fake(self, writes=SAMPLE, raises=None):
        def run(argv, timeout, register=None, max_bytes=None, env=None, ok_codes=(0,)):
            self.calls.append({'argv': list(argv), 'timeout': timeout, 'max_bytes': max_bytes, 'env': env})
            if raises:
                raise raises
            if writes is not None:
                Path(argv[argv.index('-o') + 1]).write_text(writes, encoding='utf-8')
            return b''
        return mock.patch('client.tools._run', run)

    def test_it_runs_the_exact_command_with_a_timeout_bounded_output_and_a_temporary_file(self):
        with self.fake(), tempfile.TemporaryDirectory() as empty:
            out = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir=empty)
        call = self.calls[0]
        out_path = call['argv'][call['argv'].index('-o') + 1]
        self.assertEqual(call['argv'], ['sshamble', 'scan', '-p', '22', '--checks', 'badkeys-blocklist', '--timeout', '5', '-m', '4', '-o', out_path,
                                        '-l', '/dev/null', '93.184.215.14'])
        self.assertEqual((call['timeout'], call['max_bytes']), (tools.SSH_PROBE_TIMEOUT, tools.SSH_PROBE_STDOUT))
        self.assertFalse(os.path.exists(out_path), 'the output file is temporary')
        self.assertEqual(out['touched'], ['93.184.215.14'])
        self.assertEqual(out['refused'], [])
        self.assertTrue(out['hosts'][0]['reached'])

    def test_badkeys_data_is_linked_for_the_tool_only_when_both_files_are_there(self):
        with tempfile.TemporaryDirectory() as data:
            (Path(data) / 'blocklist.dat').write_bytes(b'x')
            self.assertFalse(tools.badkeys_ready(data))
            (Path(data) / 'badkeysdata.json').write_text('{}')
            self.assertTrue(tools.badkeys_ready(data))
            seen = {}

            def run(argv, timeout, register=None, max_bytes=None, env=None, ok_codes=(0,)):
                link = os.path.join(env['HOME'], '.cache', 'badkeys')
                seen['target'] = os.path.realpath(link)
                Path(argv[argv.index('-o') + 1]).write_text(SAMPLE)
            with mock.patch('client.tools._run', run):
                got = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir=data)
        self.assertEqual(seen['target'], os.path.realpath(data))
        ids = {o['id'] for o in got['hosts'][0]['observations']}
        self.assertIn('badkeys_blocklist_clear', ids)
        self.assertNotIn('badkeys_not_checked', ids)

    def test_without_badkeys_data_the_result_says_not_checked(self):
        with self.fake(), tempfile.TemporaryDirectory() as empty:
            got = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir=empty)
        ids = {o['id']: o for o in got['hosts'][0]['observations']}
        self.assertFalse(ids['badkeys_not_checked']['verified'])
        self.assertNotIn('badkeys_blocklist_clear', ids)

    def test_a_timeout_is_unverified(self):
        with self.fake(raises=subprocess.TimeoutExpired('sshamble', 30)):
            got = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir='')
        host = got['hosts'][0]
        self.assertFalse(host['reached'])
        self.assertIn('timed out', host['error'])
        self.assertFalse(any(o['verified'] for o in host['observations']))

    def test_a_target_that_writes_no_file_is_unverified(self):
        with self.fake(writes=None):
            host = tools.run_ssh_probe(task(('93.184.215.30', 22)), badkeys_dir='')['hosts'][0]
        self.assertFalse(host['reached'])
        self.assertTrue(host['error'])

    def test_a_port_that_is_not_ssh_is_unverified(self):
        not_ssh = json.dumps({**json.loads(SAMPLE), 'host': '93.184.215.30', 'port': 80, 'version': ''})
        with self.fake(writes=not_ssh):
            host = tools.run_ssh_probe(task(('93.184.215.30', 80)), badkeys_dir='')['hosts'][0]
        self.assertFalse(host['reached'])
        self.assertEqual(host['observations'][0]['id'], 'ssh_not_identified')

    def test_oversized_output_is_not_read(self):
        with self.fake(writes=SAMPLE + ' ' * (ssh_probe.MAX_OUTPUT_BYTES + 10)):
            host = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir='')['hosts'][0]
        self.assertFalse(host['reached'])
        self.assertEqual(host['observations'][0]['id'], 'ssh_oversized')

    def test_a_tool_that_exits_badly_or_floods_stdout_is_unverified(self):
        for exc in (tools.ToolExitError('sshamble exited with status 1'), tools.ToolOutputError('wrote more than 4096 bytes')):
            with self.subTest(exc=type(exc).__name__), self.fake(raises=exc):
                host = tools.run_ssh_probe(task(('93.184.215.14', 22)), badkeys_dir='')['hosts'][0]
            self.assertFalse(host['reached'])
            self.assertFalse(any(o['verified'] for o in host['observations']))

    def test_an_address_outside_the_scope_policy_is_never_asked(self):
        with self.fake():
            got = tools.run_ssh_probe(task(('93.184.215.99', 22), ('93.184.215.14', 22)), badkeys_dir='')
        self.assertEqual([c['argv'][-1] for c in self.calls], ['93.184.215.14'])
        self.assertFalse(got['hosts'][0]['reached'])
        self.assertIn('not run', got['hosts'][0]['error'])
        self.assertEqual(got['refused'], ['93.184.215.99'])

    def test_bad_targets_are_refused_before_anything_runs(self):
        bad = [None, {}, {'targets': []}, {'targets': ['93.184.215.14']}, task(('127.0.0.1', 22)), task(('10.0.0.1', 22)), task(('93.184.215.14', 0)),
               task(('93.184.215.14', '22')), task(('-oProxyCommand=x', 22)), task(*[('93.184.215.14', 22)] * (ssh_probe.MAX_TARGETS + 1))]
        with self.fake():
            for target in bad:
                with self.subTest(target=str(target)[:60]), self.assertRaises(tools.TargetError):
                    tools.run_ssh_probe(target, badkeys_dir='')
        self.assertEqual(self.calls, [])

    def test_the_kind_is_wired(self):
        from client import config
        self.assertIn('ssh_probe', tools.RUNNERS)
        self.assertIn('ssh_probe', config.CAPABILITIES)
        self.assertEqual(config.KIND_SINCE['ssh_probe'], 3)
        with mock.patch('shutil.which', return_value=None):
            self.assertFalse(tools.sshamble_ready())
        with mock.patch('shutil.which', return_value='/usr/local/bin/sshamble'):
            self.assertTrue(tools.sshamble_ready())


if __name__ == '__main__':
    unittest.main()
