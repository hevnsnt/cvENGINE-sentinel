import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from client import scope, tools
from cvengine_scanner import nuclei_allowlist

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
        self.assertIn('--top-ports', captured['argv'])  # no task ports: the fingerprint pass scans the top thousand
        # the sample report's two hosts; an address the report does not mention gets no row (it was not scanned: review H3)
        self.assertEqual(sorted(h['ip'] for h in result['hosts']), ['192.0.2.10', '198.51.100.20'])

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

    def test_an_address_nmap_did_not_report_is_not_a_scanned_host(self):
        # Review H3: a padded row used to make an address that nmap never reported read as a clean host with no services.
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'])
        self.assertEqual(result['hosts'], [])

    def test_a_host_nmap_timed_out_on_is_marked_and_is_not_a_clean_host(self):
        report = ('<nmaprun><host timedout="true"><status state="up" reason="user-set"/><address addr="8.8.8.8" addrtype="ipv4"/></host>'
                  '<host><status state="up" reason="user-set"/><address addr="1.1.1.1" addrtype="ipv4"/>'
                  '<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports></host>'
                  '<runstats><finished exit="success"/></runstats></nmaprun>')
        with mock.patch('client.tools._run', return_value=report):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'])
        by_ip = {h['ip']: h for h in result['hosts']}
        self.assertIs(by_ip['8.8.8.8'].get('timed_out'), True)
        self.assertNotIn('timed_out', by_ip['1.1.1.1'])  # a host nmap finished carries no flag
        self.assertEqual(by_ip['1.1.1.1']['ports'][0]['number'], 22)

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
        self.assertEqual(runs[1][0][:3], [tools.NMAP_BIN, '-6', *tools.nmap_pass_flags()[:1]])
        self.assertEqual(runs[1][1], '2606:4700:4700::1111\n')
        self.assertEqual(sorted(h['ip'] for h in result['hosts']), ['192.0.2.10', '198.51.100.20'])  # the IPv6 run reported nothing: no row, not scanned
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

    def test_naabu_gets_a_time_limit_sized_from_its_hosts_and_a_timeout_is_partial_not_an_error(self):
        with mock.patch('client.tools._run', return_value='') as fake_run:
            tools.run_naabu(['8.8.8.8'])
        self.assertEqual(fake_run.call_args[0][1], 900)  # one host: the floor of the naabu range
        partial = '{"ip":"8.8.8.8","port":22}\n'

        def runs_out(argv, timeout, register=None):
            err = subprocess.TimeoutExpired(argv, timeout)
            err.partial = partial
            raise err
        with mock.patch('client.tools._run', side_effect=runs_out):
            result = tools.run_naabu(['8.8.8.8', '1.1.1.1'])
        self.assertIs(result['incomplete'], True)
        self.assertEqual(result['unfinished'], ['8.8.8.8', '1.1.1.1'])
        self.assertEqual(result['ports'], {'8.8.8.8': [22]})  # the ports it read are kept

    def test_a_naabu_run_that_fits_its_chunk_gets_the_limit_of_its_hosts_and_is_complete(self):
        hosts = [f'8.8.{i // 256}.{i % 256}' for i in range(1, 25)]
        with mock.patch('client.tools._run', return_value='') as fake_run:
            result = tools.run_naabu(hosts)
        self.assertNotIn('incomplete', result)
        self.assertEqual(fake_run.call_args[0][1], tools.task_seconds('naabu', 24))

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

    def test_nuclei_always_excludes_dos_templates_and_keeps_the_raw_evidence(self):
        for tags in (None, [], ['cve'], ['dos', 'cve']):
            with self.subTest(tags=tags), mock.patch('client.tools._run', return_value='') as fake_run:
                tools.run_nuclei(['www.example.test'], tags=tags)
                argv = fake_run.call_args[0][0]
                self.assertEqual(argv[argv.index('-etags') + 1], 'dos')
                self.assertNotIn('-omit-raw', argv)  # the request and response are the finding's evidence (review M2)
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
            def capture(argv, timeout, register=None, env=None):
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


class NucleiTemplateReleaseTests(unittest.TestCase):
    """The result names the template set the run used, so a stale run is visible in the result (review L5)."""

    def test_a_run_on_an_approved_bundle_names_that_bundle(self):
        bundle = '/state/templates/' + 'e' * 64
        with mock.patch('client.tools.os.path.isdir', return_value=True), mock.patch('client.tools._run', return_value=''):
            result = tools.run_nuclei(['www.example.test'], templates=bundle)
        self.assertEqual(result['templates_release'], 'approved:' + 'e' * 64)

    def test_a_run_on_the_image_templates_names_the_image_release(self):
        with mock.patch.object(tools, 'IMAGE_TEMPLATES_VERSION', 'v10.5.1'), mock.patch('client.tools._run', return_value=''):
            result = tools.run_nuclei(['www.example.test'])
        self.assertEqual(result['templates_release'], 'image:v10.5.1')

    def test_a_release_is_always_a_short_plain_string(self):
        self.assertLessEqual(len(tools.IMAGE_TEMPLATES_VERSION), 40)
        with mock.patch('client.tools._run', return_value=''):
            release = tools.run_nuclei(['www.example.test'])['templates_release']
        self.assertRegex(release, r'^[A-Za-z0-9:._-]{1,80}$')


def _nuclei_run(stdout, errors):
    """A fake nuclei run: ``stdout`` is its JSONL findings and ``errors`` (a list of dicts) is what it writes to the -elog file it is given."""
    def fake(argv, timeout, register=None, env=None):
        if '-elog' in argv:
            with open(argv[argv.index('-elog') + 1], 'w', encoding='utf-8') as handle:
                handle.write(''.join(json.dumps(row) + '\n' for row in errors))
        return stdout
    return fake


REFUSED = {'input': 'closed.example.test:8080', 'error': 'Get "http://closed.example.test:8080": dial tcp 192.0.2.7:8080: connect: connection refused'}


class NucleiReachTests(unittest.TestCase):
    """Review H4: nuclei exits 0 with no output when nothing answered. The targets it never reached are listed as unreachable, never as scanned
    with no findings."""

    def test_a_closed_port_run_that_exits_clean_names_its_targets_as_unreachable(self):
        errors = [dict(REFUSED, input='www.example.test:8080', error='dial tcp: connect: connection refused'), dict(REFUSED)]
        with mock.patch('client.tools._run', side_effect=_nuclei_run('', errors)):
            result = tools.run_nuclei(['www.example.test:8080', 'closed.example.test:8080'])
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['unreachable'], ['www.example.test:8080', 'closed.example.test:8080'])

    def test_a_host_that_gave_a_finding_is_reached_even_when_some_requests_failed(self):
        finding = json.dumps({'template-id': 'tech-detect', 'host': 'www.example.test', 'matched-at': 'https://www.example.test/', 'info': {'name': 'n', 'severity': 'info'}})
        errors = [{'input': 'https://www.example.test/x', 'error': 'context deadline exceeded (Client.Timeout exceeded)'}]
        with mock.patch('client.tools._run', side_effect=_nuclei_run(finding, errors)):
            result = tools.run_nuclei(['https://www.example.test/'])
        self.assertEqual(result['unreachable'], [])
        self.assertEqual(len(result['findings']), 1)

    def test_an_error_that_is_not_a_connection_failure_leaves_the_host_reached(self):
        errors = [{'input': 'www.example.test', 'error': 'unexpected EOF in template response parser: bad json body'}, {'input': 'www.example.test', 'error': 'read tcp: broken pipe'}]
        with mock.patch('client.tools._run', side_effect=_nuclei_run('', errors)):
            result = tools.run_nuclei(['www.example.test'])
        # a host with an answer-level error (not a connection failure) is reached: only a connection-class error on every request counts
        self.assertEqual(result['unreachable'], [])

    def test_a_run_with_no_error_log_names_nothing_unreachable(self):
        with mock.patch('client.tools._run', return_value=''):
            self.assertEqual(tools.run_nuclei(['www.example.test'])['unreachable'], [])

    def test_the_error_log_is_requested_and_removed_with_the_run(self):
        seen = {}

        def capture(argv, timeout, register=None, env=None):
            seen['log'] = argv[argv.index('-elog') + 1]
            return ''
        with mock.patch('client.tools._run', side_effect=capture):
            tools.run_nuclei(['www.example.test'])
        self.assertFalse(os.path.exists(seen['log']))

    def test_a_template_test_host_nuclei_never_reached_is_an_error_not_a_negative(self):
        template = 'id: t\ninfo:\n  name: t\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - "{{BaseURL}}/"\n    matchers:\n      - type: status\n        status:\n          - 200\n'
        errors = [{'input': 'closed.example.test', 'error': 'dial tcp: connect: connection refused'}]

        def status(argv, timeout, register=None):
            if '-elog' in argv:
                with open(argv[argv.index('-elog') + 1], 'w', encoding='utf-8') as handle:
                    handle.write(json.dumps(errors[0]) + '\n')
            return 0, '', ''
        with mock.patch('client.tools._run_status', side_effect=status):
            outcomes = tools.run_nuclei_validate('test', template, ['closed.example.test', 'www.example.test'])['outcomes']
        by_host = {o['host']: o for o in outcomes}
        self.assertIn('never reached', by_host['closed.example.test']['error'])
        self.assertEqual(by_host['www.example.test'].get('error', ''), '')


class NmapPassWiringTests(unittest.TestCase):
    """Review M1 and M7 on the wire: the task's ports reach the fingerprint pass, the task's own time limit is used inside its range, and a
    port the server did not send right is a refusal, not a scan of something else."""

    def test_the_task_ports_replace_the_top_thousand_and_keep_the_extra_ports(self):
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT) as fake_run:
            tools.run_nmap(['8.8.8.8'], ports=[22, 80])
        argv = fake_run.call_args[0][0]
        self.assertNotIn('--top-ports', argv)
        covered = set()
        for part in argv[argv.index('-p') + 1].split(','):
            low, _, high = part.partition('-')
            covered.update(range(int(low), int(high or low) + 1))
        self.assertTrue({22, 80, 6379, 6380, 1, 3} <= covered)  # the task's ports, a Redis pair outside nmap's top thousand, the closed probes
        self.assertIn('--script', argv)

    def test_a_task_without_ports_scans_the_top_thousand(self):
        with mock.patch('client.tools._run', return_value=FINISHED_REPORT) as fake_run:
            tools.run_nmap(['8.8.8.8'])
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[argv.index('--top-ports') + 1], '1000')
        self.assertNotIn('-p', argv)

    def test_ports_that_are_not_ports_are_refused_before_anything_runs(self):
        for bad in (['22; id'], [0], [70000], 'x', [True]):
            with self.subTest(bad=bad), mock.patch('client.tools._run') as fake_run:
                with self.assertRaises(tools.TargetError):
                    tools.run_nmap(['8.8.8.8'], ports=bad)
            fake_run.assert_not_called()

    def test_the_daemon_sends_the_task_ports_and_its_time_limit_to_nmap(self):
        from client import daemon
        from client.tests.test_daemon import FakeClient
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        runner = mock.Mock(return_value={'hosts': []})
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            d._execute({'kind': 'nmap', 'target': {'addresses': ['8.8.8.8'], 'ports': [22, 80], 'timeout': 1800}}, None)
        self.assertEqual(runner.call_args.kwargs['ports'], [22, 80])
        self.assertEqual(runner.call_args.kwargs['timeout'], 1800)

    def test_the_daemon_sizes_a_naabu_task_from_its_hosts_unless_the_task_names_a_limit(self):
        from client import daemon
        from client.tests.test_daemon import FakeClient
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        runner = mock.Mock(return_value={'ports': {}})
        with mock.patch.dict(tools.RUNNERS, {'naabu': runner}):
            d._execute({'kind': 'naabu', 'target': {'addresses': ['8.8.8.8']}}, None)
            self.assertEqual(runner.call_args.kwargs['timeout'], tools.task_seconds('naabu', 1))
            d._execute({'kind': 'naabu', 'target': {'addresses': ['8.8.8.8'], 'timeout': 2400}}, None)
            self.assertEqual(runner.call_args.kwargs['timeout'], 2400)


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
            {'id': 'not_tracked', 'severity': 'INFO', 'finding': 'test ok', 'cve': ''}],
            'handshake': False, 'returncode': 0})  # no protocol was reported as offered: no handshake is shown, and the code is sent

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
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen), mock.patch('client.tools.ipv6_route', return_value=True):  # not this machine's own routes
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

    def test_a_listener_that_completes_no_handshake_sends_no_clear_vulnerability_tests(self):
        """Review H2: on a plain HTTP port testssl exits 9, offers no protocol and still prints "not vulnerable" for every test it could not run.
        Those must not reach the server as clear results. The protocols and the scan problem are kept, so the server can see what happened."""
        report = [{'id': 'SSLv2', 'severity': 'OK', 'finding': 'not offered'}, {'id': 'SSLv3', 'severity': 'OK', 'finding': 'not offered'},
                  {'id': 'TLS1_2', 'severity': 'OK', 'finding': 'not offered'}, {'id': 'TLS1_3', 'severity': 'OK', 'finding': 'not offered'},
                  {'id': 'scanProblem', 'severity': 'WARN', 'finding': 'Client problem: No server certificate could be retrieved'},
                  {'id': 'heartbleed', 'severity': 'OK', 'finding': 'not vulnerable, no heartbeat extension'},
                  {'id': 'ROBOT', 'severity': 'OK', 'finding': 'not vulnerable, no RSA key transport cipher'},
                  {'id': 'FREAK', 'severity': 'OK', 'finding': 'not vulnerable'}]

        class Plain(self._FakeProc):
            def __init__(self, argv, report, **kwargs):
                super().__init__(argv, report, **kwargs)
                self.returncode = 9  # testssl's own code for "no server answered a handshake"
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: Plain(argv, report, **kw)):
            result = tools.run_testssl('www.example.test', '8.8.8.8', 80)
        self.assertIs(result['handshake'], False)
        self.assertEqual(result['returncode'], 9)
        ids = [i['id'] for i in result['items']]
        self.assertEqual(ids, ['SSLv2', 'SSLv3', 'TLS1_2', 'TLS1_3', 'scanProblem'])

    def test_a_listener_that_completes_a_handshake_keeps_its_clear_tests(self):
        report = [{'id': 'TLS1_2', 'severity': 'OK', 'finding': 'offered (OK)'}, {'id': 'heartbleed', 'severity': 'OK', 'finding': 'not vulnerable'}]
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: self._FakeProc(argv, report, **kw)):
            result = tools.run_testssl('www.example.test', '8.8.8.8', 443)
        self.assertIs(result['handshake'], True)
        self.assertEqual(result['returncode'], 0)
        self.assertEqual([i['id'] for i in result['items']], ['TLS1_2', 'heartbleed'])

    def test_a_run_killed_by_a_signal_is_an_error(self):
        class Killed(self._FakeProc):
            def __init__(self, argv, report, **kwargs):
                super().__init__(argv, report, **kwargs)
                self.returncode = -9
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, **kw: Killed(argv, [], **kw)):
            with self.assertRaises(tools.ToolExitError):
                tools.run_testssl('www.example.test', '8.8.8.8', 443)


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

    def test_a_cloud_ipv6_literal_with_a_trailing_double_colon_is_scanned_with_dash_6_and_passed_through_as_written(self):
        # seen on cvedemo: 2600:1900:4001:370:8000:1a0:: (a Google Cloud range). The literal reaches nmap unchanged, after -6 and the fixed flags.
        with mock.patch('client.tools._run', return_value='<nmaprun/>') as fake_run:
            tools.run_nmap_udp('2600:1900:4001:370:8000:1a0::')
        argv = fake_run.call_args[0][0]
        self.assertEqual(argv[:2], [tools.NMAP_BIN, '-6'])
        self.assertEqual(argv[-3:], ['-oX', '-', '2600:1900:4001:370:8000:1a0::'])
        self.assertEqual(argv.count('-6'), 1)

    def test_a_report_that_scanned_no_host_is_returned_as_is_for_the_server_to_judge(self):
        # nmap exits 0 with 0 hosts scanned when it has no route to the target (a Sentinel without IPv6). The wrapper must not turn that
        # into a failure or an empty string: the server tells "host down" from "nothing was sent" by the report's own host counts.
        xml = '<nmaprun><runstats><finished exit="success"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>'
        with mock.patch('client.tools._run', return_value=xml):
            self.assertEqual(tools.run_nmap_udp('2600:1900:4001:370:8000:1a0::'), {'xml': xml})

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


class RunWpscanThoroughTests(unittest.TestCase):
    """The thorough pass (kind ``wpscan_thorough``): its own fixed option list and its own time limit, the same url, scope and token handling."""
    _FakeProc = WpscanRunnerTests._FakeProc

    def _run(self, **kwargs):
        captured = {}
        report = kwargs.pop('report', {'version': {'number': '6.4'}})

        def fake_popen(argv, env=None, **kw):
            proc = self._FakeProc(argv, env, report)
            captured.update(argv=argv, env=env)
            return proc
        real_communicate = self._FakeProc.communicate

        def communicate(proc, timeout=None):
            captured['timeout'] = timeout
            return real_communicate(proc, timeout=timeout)
        with mock.patch('client.tools.subprocess.Popen', side_effect=fake_popen), mock.patch.object(self._FakeProc, 'communicate', communicate):
            result = tools.run_wpscan_thorough('https://www.example.test', **kwargs)
        return result, captured

    def test_it_asks_for_every_plugin_and_theme_and_the_token_stays_in_the_environment(self):
        result, seen = self._run(token='super-secret-token', timeout_seconds=7200)
        argv = seen['argv']
        self.assertEqual(argv[0], tools.WPSCAN_BIN)
        self.assertEqual(argv[argv.index('--plugins-detection') + 1], 'mixed')
        self.assertEqual(argv[argv.index('--themes-detection') + 1], 'mixed')
        self.assertEqual(argv[argv.index('--enumerate') + 1], 'ap,at,tt')
        self.assertNotIn('super-secret-token', argv)
        self.assertEqual(seen['env'].get('WPSCAN_API_TOKEN'), 'super-secret-token')
        self.assertEqual(result, {'report': {'version': {'number': '6.4'}}, 'returncode': 0, 'stderr_tail': ''})

    def test_the_time_limit_is_the_tasks_own_and_the_scan_ends_thirty_seconds_before_it(self):
        _, seen = self._run(timeout_seconds=7200)
        self.assertEqual(seen['timeout'], 7200)
        self.assertEqual(seen['argv'][seen['argv'].index('--max-scan-duration') + 1], str(7200 - 30))

    def test_a_missing_or_out_of_range_limit_is_held_to_the_contracts_range(self):
        for given, want in ((None, 12 * 3600), (60, 600), (10 ** 9, 24 * 3600), (True, 12 * 3600), ('7200', 12 * 3600), (7200.0, 12 * 3600)):
            with self.subTest(given=given):
                _, seen = self._run(timeout_seconds=given)
                self.assertEqual(seen['timeout'], want)

    def test_the_quick_pass_keeps_its_passive_options(self):
        quick = [a for a in tools.WPSCAN_ARGS]
        self.assertEqual(quick[quick.index('--plugins-detection') + 1], 'passive')
        self.assertNotIn('tt', tools.WPSCAN_ARGS[tools.WPSCAN_ARGS.index('--enumerate') + 1].split(','))
        self.assertGreater(int(tools.WPSCAN_THOROUGH_ARGS[tools.WPSCAN_THOROUGH_ARGS.index('--throttle') + 1]), 0)

    def test_a_cut_short_run_reports_what_it_read_with_exit_code_4(self):
        report = {'scan_aborted': 'Scan Aborted: duration', 'version': {'number': '6.4'}}
        with mock.patch('client.tools.subprocess.Popen', side_effect=lambda argv, env=None, **kw: self._FakeProc(argv, env, report, returncode=4)):
            result = tools.run_wpscan_thorough('https://www.example.test', timeout_seconds=600)
        self.assertEqual((result['returncode'], result['report']), (4, report))

    def test_rejects_a_non_url_and_a_refused_address_before_anything_runs(self):
        with mock.patch('client.tools.subprocess.Popen') as popen:
            with self.assertRaises(tools.TargetError):
                tools.run_wpscan_thorough('not-a-url; rm -rf /')
            with self.assertRaises(tools.TargetError):
                tools.run_wpscan_thorough('http://127.0.0.1/')
        popen.assert_not_called()


class DetectToolsTests(unittest.TestCase):
    def test_a_missing_binary_is_left_out_not_fatal(self):
        with mock.patch('client.tools.subprocess.run', side_effect=FileNotFoundError), \
                mock.patch('client.tools.gvm_available', return_value=False):
            self.assertEqual(tools.detect_tools(), [])

    def test_an_installed_binary_is_reported(self):
        with mock.patch('client.tools.subprocess.run', return_value=mock.Mock(returncode=0)), \
                mock.patch('client.tools.gvm_available', return_value=False):
            self.assertEqual(sorted(tools.detect_tools()), ['bbot', 'kingfisher', 'naabu', 'nmap', 'nuclei', 'testssl', 'wafw00f', 'wpscan'])

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


class DetectToolsTests(unittest.TestCase):
    def test_a_tool_whose_version_probe_fails_is_not_declared(self):
        """A binary that starts and then exits non-zero on its own version flag is broken; declaring it would take tasks it cannot run (review L1)."""
        results = {'nuclei': mock.Mock(returncode=1), 'naabu': mock.Mock(returncode=0)}

        def fake_run(argv, **kw):
            for name, result in results.items():
                if argv == tools.VERSION_ARGS[name]:
                    return result
            return mock.Mock(returncode=0)
        with mock.patch('client.tools.subprocess.run', side_effect=fake_run), mock.patch('client.tools.gvm_available', return_value=False):
            found = tools.detect_tools()
        self.assertNotIn('nuclei', found)
        self.assertIn('naabu', found)

    def test_a_missing_binary_is_still_left_out(self):
        with mock.patch('client.tools.subprocess.run', side_effect=FileNotFoundError('x')), mock.patch('client.tools.gvm_available', return_value=False):
            self.assertEqual(tools.detect_tools(), [])


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
        with mock.patch('client.tools._oom_events', return_value=None), self.assertRaises(tools.ToolExitError) as ctx:  # a host that cannot count kills
            tools._run(['sh', '-c', 'kill -9 $$'], 10)
        self.assertIn('out of memory, retry later', str(ctx.exception))  # a bare "status -9" told the operator nothing (client.tools.ToolOOMError)

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


class SignedInEvidenceTests(unittest.TestCase):
    """Review M2 and the signed-in run: a signed-in nuclei run keeps no request or response, even when the watchdog stops it and delivers the
    findings it had printed (their requests carry the sign-in)."""

    def test_a_stopped_signed_in_run_delivers_its_findings_without_their_requests(self):
        from client import daemon
        from client.tests.test_daemon import FakeClient
        d = daemon.Daemon('https://x.example', 'tok', client=FakeClient())
        d.guard = mock.Mock(cfg={'partial': True})
        row = json.dumps({'template-id': 't', 'host': 'www.example.test', 'request': 'GET / HTTP/1.1\nCookie: session=abc\n',
                          'info': {'name': 'n', 'severity': 'info'}})
        exc = tools.ToolExitError('nuclei stopped')
        exc.partial = row + '\n'
        state = {'wd': {'text': 'stopped'}, 'kind': 'nuclei_light', 'signed_in': True}
        result = d._watchdog_result(state, exc)
        self.assertEqual(result['outcome'], 'done')
        self.assertEqual(len(result['findings']), 1)
        self.assertNotIn('request', result['findings'][0])


SONIC = 'WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json\n'
FINDING = json.dumps({'template-id': 'tech-detect', 'host': 'www.example.test', 'matched-at': 'https://www.example.test/', 'info': {'name': 'n', 'severity': 'info'}})


def _exit_error(stderr, partial=''):
    exc = tools.ToolExitError('nuclei exited with status 1: ' + stderr[:200])
    exc.stderr, exc.partial = stderr, partial
    return exc


class NucleiToolReviewTests(unittest.TestCase):
    """The production review of 11/10: what nuclei's two failure modes on the VPS now return."""

    def test_a_tag_filter_no_template_matches_is_nothing_to_check_not_a_failure(self):
        """The exact message of 29 failed tasks (tags ``haproxy`` at severity ``info``)."""
        error = _exit_error(SONIC + '[FTL] Could not run nuclei: no templates provided for scan\n')
        with mock.patch('client.tools._run', side_effect=error):
            result = tools.run_nuclei(['www.example.test'], tags=['haproxy'], severities=['info'])
        self.assertEqual((result['findings'], result['unreachable'], result['no_templates']), ([], [], True))

    def test_no_templates_without_any_filter_is_still_an_error(self):
        """With no filter, an empty set means the templates are missing from this Sentinel: that is broken, and must not read as a clean host."""
        error = _exit_error('[FTL] Could not run nuclei: no templates provided for scan\n')
        with mock.patch('client.tools._run', side_effect=error):
            with self.assertRaises(tools.ToolExitError):
                tools.run_nuclei(['www.example.test'])

    def test_any_other_exit_is_still_an_error(self):
        with mock.patch('client.tools._run', side_effect=_exit_error(SONIC + '[FTL] Could not create runner: bad config\n')):
            with self.assertRaises(tools.ToolExitError):
                tools.run_nuclei(['www.example.test'], tags=['haproxy'])

    def test_a_run_out_of_time_keeps_its_findings_and_leaves_every_target_due(self):
        exc = subprocess.TimeoutExpired(['nuclei'], 3600)
        exc.partial = FINDING + '\n'
        with mock.patch('client.tools._run', side_effect=exc):
            result = tools.run_nuclei(['www.example.test', 'api.example.test'], timeout=3600)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['unreachable'], ['www.example.test', 'api.example.test'])  # none is recorded as scanned clean
        self.assertTrue(result['incomplete'])

    def test_the_failure_message_says_the_error_not_the_json_library_warning(self):
        proc_err = SONIC + '[FTL] Could not run nuclei: something specific\n'
        script = f"import sys; sys.stderr.write({proc_err!r}); sys.exit(1)"
        with self.assertRaises(tools.ToolExitError) as caught:
            tools._run([sys.executable, '-c', script], 30)
        self.assertIn('something specific', str(caught.exception))
        self.assertNotIn('sonic', str(caught.exception))
        self.assertIn('sonic', caught.exception.stderr)  # kept whole for the caller


def _aborted(text):
    return {'report': {'scan_aborted': text}, 'returncode': 4, 'stderr_tail': ''}


class WpscanToolReviewTests(unittest.TestCase):
    def test_without_a_token_the_scan_does_not_ask_for_vulnerable_plugins_and_themes(self):
        self.assertIn('p,t,cb,dbe,u1-5', tools.wpscan_args_for(tools.WPSCAN_ARGS, ''))
        self.assertEqual(tools.wpscan_args_for(tools.WPSCAN_ARGS, 'tok'), list(tools.WPSCAN_ARGS))
        self.assertEqual(tools.wpscan_args_for(tools.WPSCAN_THOROUGH_ARGS, ''), list(tools.WPSCAN_THOROUGH_ARGS))  # ap,at,tt need no token

    def test_a_redirect_on_the_same_site_is_followed_once(self):
        msg = 'The URL supplied redirects to https://example.test/. Use the --follow-redirect option to automatically scan the redirected URL'
        self.assertEqual(tools.same_site_redirect('https://www.example.test', _aborted(msg)), 'https://example.test/')
        self.assertEqual(tools.same_site_redirect('https://example.test', _aborted(msg.replace('https://example.test/', 'https://example.test/career/'))),
                         'https://example.test/career/')

    def test_a_redirect_off_the_site_or_to_itself_is_not_followed(self):
        off = 'The URL supplied redirects to https://login.other.test/. Use the --follow-redirect option'
        self.assertIsNone(tools.same_site_redirect('https://www.example.test', _aborted(off)))
        sub = 'The URL supplied redirects to https://shop.example.test/. Use the --follow-redirect option'
        self.assertIsNone(tools.same_site_redirect('https://www.example.test', _aborted(sub)))  # another host under the domain is another site
        self.assertIsNone(tools.same_site_redirect('https://example.test/', _aborted('The URL supplied redirects to https://example.test/. Use')))
        self.assertIsNone(tools.same_site_redirect('https://example.test', {'report': {'scan_aborted': 'The remote website is up, but does not seem to be running WordPress.'}, 'returncode': 4}))
        self.assertIsNone(tools.same_site_redirect('https://example.test', {'report': {}, 'returncode': 0}))

    def test_the_run_follows_the_redirect_and_returns_the_second_scan(self):
        calls = []

        def fake(url, token, timeout, register, args):
            calls.append((url, args))
            if len(calls) == 1:
                return _aborted('The URL supplied redirects to https://example.test/. Use the --follow-redirect option')
            return {'report': {'version': {'number': '6.4'}}, 'returncode': 0, 'stderr_tail': ''}
        with mock.patch('client.tools._wpscan', side_effect=fake):
            out = tools.run_wpscan('https://www.example.test', '')
        self.assertEqual([c[0] for c in calls], ['https://www.example.test', 'https://example.test/'])
        self.assertEqual(out['returncode'], 0)
        self.assertTrue(all('p,t,cb,dbe,u1-5' in c[1] for c in calls))


REAL_PROBE = getattr(tools, '_probe_banner', None)  # before a test replaces it


def _slug(rel):
    return re.sub(r'[^A-Za-z0-9]+', '-', os.path.splitext(rel)[0]).strip('-')


def _bundle_allowlist(directory):
    """The service-port allowlist of a fake bundle: every template file in it, with the sha256 of its content now. The tests of the pacing, the classes and the content
    rule run on this list, so what they prove is not hidden behind the shipped list; the shipped list has its own tests (NucleiAllowlistTests)."""
    templates = {}
    for folder, _dirs, names in os.walk(directory):
        for name in names:
            if name.endswith('.yaml'):
                with open(os.path.join(folder, name), 'rb') as handle:
                    raw = handle.read()
                tid = nuclei_allowlist.template_id(raw.decode('utf-8', 'replace'))
                if tid:
                    templates[tid] = {'sha256': nuclei_allowlist.sha256_of(raw), 'classes': [*tools.flags.NUCLEI_SERVICES, tools.flags.NUCLEI_UNKNOWN]}  # the fake nuclei does the class selection
    return {'nuclei_templates': 'test', 'templates': templates, 'reviewed_exceptions': set()}


class FakeNuclei:
    """A miniature nuclei for the service runs: ``-tl`` lists the templates its filters (-pt, -tags, -etags) select, a run with ``-t <file>`` answers
    for that one template, and the clock a test replaces advances by what a run is told to take. Records every listing and every run."""

    def __init__(self, directory, templates, clock=None):
        self.dir, self.templates, self.clock = directory, templates, clock  # templates: {relative path: {'type', 'tags', 'text'}}
        self.listings, self.runs = [], []
        self.fail, self.duration, self.finding = set(), {}, {}
        self.on_run, self.original = None, {}
        for rel, spec in templates.items():
            path = os.path.join(directory, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(spec.get('text', f'id: {_slug(rel)}\n'))  # one id per file, as in the real library: the allowlist is keyed by id
            with open(path, 'rb') as handle:
                self.original[rel] = handle.read()

    def _selected(self, argv):
        types = set(_flag(argv, '-pt').split(',')) if '-pt' in argv else None
        tags = set(_flag(argv, '-tags').split(',')) if '-tags' in argv else None
        etags = set(_flag(argv, '-etags').split(',')) if '-etags' in argv else set()
        out = []
        for rel, spec in self.templates.items():
            if types is not None and spec['type'] not in types:
                continue
            if tags is not None and not tags & set(spec['tags']):
                continue
            if etags & set(spec['tags']):
                continue
            out.append(rel)
        return out

    def __call__(self, argv, timeout, register=None, env=None):
        if '-tl' in argv:
            self.listings.append(list(argv))
            return f'\nListing available  nuclei templates for {self.dir}\n' + ''.join(f'{rel}\n' for rel in self._selected(argv))
        with open(argv[argv.index('-l') + 1], encoding='utf-8') as handle:
            targets = handle.read().split()
        own = _flag(argv, '-t')
        given = None
        if own and own != self.dir:
            if self.on_run:
                self.on_run(own)  # a test swaps the library's file here: the moment between the hash check and nuclei opening its file
            with open(own, 'rb') as handle:
                given = {'path': own, 'bytes': handle.read(), 'mode': os.stat(own).st_mode & 0o777, 'dir_mode': os.stat(os.path.dirname(own)).st_mode & 0o777}
        if given and os.path.abspath(own).startswith(os.path.abspath(self.dir) + os.sep):
            rel = os.path.relpath(own, self.dir)
        elif given:  # a private copy of the verified bytes: the template is the bundle file that holds them
            rel = next((r for r in self.original if self.original[r] == given['bytes']), os.path.basename(own))
        else:
            rel = None
        self.runs.append({'argv': list(argv), 'targets': targets, 'timeout': timeout, 'template': rel, 'at': self.clock() if self.clock else None, 'given': given})
        if self.clock:
            self.clock.advance(min(timeout, self.duration.get(targets[0], self.duration.get(None, 0))))  # a run is stopped at its timeout
        if (targets[0], rel) in self.fail or (targets[0], None) in self.fail:
            raise tools.ToolExitError('nuclei exited with status 2')
        rows = self.finding.get((targets[0], rel), []) if rel else self.finding.get((targets[0], None), [])
        return ''.join(json.dumps(row) + '\n' for row in rows)

    @property
    def service_runs(self):
        return [r for r in self.runs if r['template']]

    @property
    def web_runs(self):
        return [r for r in self.runs if not r['template']]


class FakeClock:
    """The clocks of the service passes, replaced: ``advance`` moves the time, a pause (``tools._sleep``) moves it too and is recorded."""

    def __init__(self):
        self.now, self.pauses = 1000.0, []

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds

    def sleep(self, seconds):
        self.pauses.append(seconds)
        self.now += seconds


def _row(host, template_id='t'):
    return {'template-id': template_id, 'host': host, 'matched-at': host, 'info': {'name': 'n', 'severity': 'info'}}


NO_PARALLEL = 'id: x\njavascript:\n  - code: |\n      x\n'
TEMPLATES = {
    'http/exposures/web-one.yaml': {'type': 'http', 'tags': ['exposure']},
    'http/misconfiguration/web-two.yaml': {'type': 'http', 'tags': ['misconfig']},
    'http/technologies/tech-detect.yaml': {'type': 'http', 'tags': ['tech']},
    'network/detection/openssh-detect.yaml': {'type': 'tcp', 'tags': ['ssh', 'openssh', 'detect']},
    'network/detection/ssh-version.yaml': {'type': 'javascript', 'tags': ['ssh', 'detect']},
    'javascript/default-logins/ssh-default-logins.yaml': {'type': 'javascript', 'tags': ['ssh', 'default-login'], 'text': 'id: d\njavascript:\n  - threads: 10\n'},
    'network/detection/ssh-brute.yaml': {'type': 'javascript', 'tags': ['ssh', 'bruteforce']},
    'network/detection/ftp-detect.yaml': {'type': 'tcp', 'tags': ['ftp', 'detect']},
    'network/detection/ftp-banner.yaml': {'type': 'tcp', 'tags': ['ftp', 'detect']},
    'network/detection/smtp-detect.yaml': {'type': 'tcp', 'tags': ['smtp', 'detect']},
    'network/detection/imap-detect.yaml': {'type': 'tcp', 'tags': ['imap', 'detect']},
    'network/detection/weblogic-t3.yaml': {'type': 'tcp', 'tags': ['weblogic', 't3', 'detect']},
    'network/cves/activemq-openwire.yaml': {'type': 'tcp', 'tags': ['activemq', 'cve', 'rce']},
    'javascript/enumeration/zookeeper.yaml': {'type': 'javascript', 'tags': ['zookeeper', 'enum']},
    'network/dos/some-dos.yaml': {'type': 'tcp', 'tags': ['dos', 'zookeeper']},
    'ssl/tls-version.yaml': {'type': 'ssl', 'tags': ['ssl', 'tls']},
    'http/cves/web-and-raw.yaml': {'type': 'http', 'tags': ['cve', 'ssh']},
}


def _flag(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


HOST_PORTS = ['www.example.test', 'www.example.test:22', 'www.example.test:25', 'www.example.test:143', 'www.example.test:443']
LABELS = {'www.example.test:22': 'ssh', 'www.example.test:25': 'smtp', 'www.example.test:143': 'imap', 'www.example.test:443': 'web'}
BUDGET_CAP = {'pause_ms': 500, 'seconds': 300, 'web_rate': 25}


class NucleiTestCase(unittest.TestCase):
    def setUp(self):
        tools._TEMPLATE_LISTINGS.clear()
        self.addCleanup(tools._TEMPLATE_LISTINGS.clear)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, 'bundle')
        self.clock = FakeClock()
        self.nuclei = FakeNuclei(self.dir, dict(TEMPLATES), self.clock)  # a copy: a test adds templates to its own bundle
        self.banner = mock.Mock(return_value=None)  # no test connects to anything: the banner of an unknown port is read by ``tools._probe_banner``
        for target, value in (('_run', mock.Mock(side_effect=self.nuclei)), ('_clock', self.clock), ('_sleep', self.clock.sleep), ('_probe_banner', self.banner)):
            patcher = mock.patch.object(tools, target, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(nuclei_allowlist, 'load_allowlist', side_effect=lambda path=None: _bundle_allowlist(self.dir))
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_nuclei(self, targets=HOST_PORTS, **kwargs):
        kwargs.setdefault('templates', self.dir)
        return tools.run_nuclei(targets, **kwargs)

    def templates_run_on(self, target):
        return sorted(r['template'] for r in self.nuclei.service_runs if r['targets'] == [target])


class NucleiProtocolSplitTests(NucleiTestCase):
    """A port only receives the templates of the protocol that speaks there (production: 34,000 non-SSH connections to sshd in 20 minutes)."""

    def test_a_deep_task_sends_http_templates_to_the_web_port_only(self):
        self.run_nuclei(services=LABELS)
        self.assertEqual(len(self.nuclei.web_runs), 1)
        web = self.nuclei.web_runs[0]
        self.assertEqual(web['targets'], ['www.example.test', 'www.example.test:443'])
        self.assertEqual(_flag(web['argv'], '-ept'), 'tcp,javascript')  # a bare host name must not reach the ports the raw templates name
        self.assertNotIn('-pt', web['argv'])
        self.assertNotIn('-tags', web['argv'])  # a deep run's web ports keep every template, as before
        for run in self.nuclei.service_runs:  # and no service run ever has an http template, or a web port
            self.assertNotIn('http/', run['template'])
            self.assertNotIn('www.example.test:443', run['targets'])

    def test_the_ssh_port_gets_only_ssh_protocol_templates(self):
        self.run_nuclei(services=LABELS)
        self.assertEqual(self.templates_run_on('www.example.test:22'), ['network/detection/openssh-detect.yaml', 'network/detection/ssh-version.yaml'])
        self.assertEqual(self.templates_run_on('www.example.test:25'), ['network/detection/smtp-detect.yaml'])
        self.assertEqual(self.templates_run_on('www.example.test:143'), ['network/detection/imap-detect.yaml'])
        for run in self.nuclei.service_runs:
            self.assertEqual(_flag(run['argv'], '-pt'), 'tcp,javascript')
            self.assertIn('-nh', run['argv'])  # no http probe either

    def test_a_service_run_never_has_credential_fuzz_or_intrusive_templates(self):
        self.run_nuclei(services=LABELS)
        ran = {r['template'] for r in self.nuclei.service_runs}
        self.assertNotIn('network/detection/ssh-brute.yaml', ran)
        self.assertNotIn('javascript/default-logins/ssh-default-logins.yaml', ran)
        for run in self.nuclei.service_runs:  # the run itself excludes them too, whatever file it is given
            self.assertEqual(set(_flag(run['argv'], '-etags').split(',')), {'dos', 'default-login', 'bruteforce', 'fuzz', 'intrusive'})
        for listing in self.nuclei.listings:
            self.assertEqual(set(_flag(listing, '-etags').split(',')) & {'dos', 'default-login', 'bruteforce', 'fuzz', 'intrusive'},
                             {'dos', 'default-login', 'bruteforce', 'fuzz', 'intrusive'})

    def test_a_template_that_sets_its_own_parallelism_is_never_run_on_a_service(self):
        listed = tools._service_templates({'types': ['tcp', 'javascript'], 'tags': ['ssh'], 'etags': ['dos']}, self.dir, [], None)
        self.assertNotIn(os.path.join(self.dir, 'javascript/default-logins/ssh-default-logins.yaml'), listed)
        self.assertIn(os.path.join(self.dir, 'network/detection/openssh-detect.yaml'), listed)
        path = os.path.join(self.dir, 'x.yaml')
        for text, ok in (('id: a\nhttp:\n  - threads: 10\n', False), ('id: a\nhttp:\n  - threads: 1\n', True), ('info:\n  metadata:\n    max-request: 223\n', False),
                         ('info:\n  metadata:\n    max-request: 3\n', True), ('id: plain\n', True)):
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(text)
            self.assertEqual(tools._paced_template(path) is None, ok, text)

    def test_an_unlabelled_target_is_read_by_its_port_so_an_older_server_cannot_flood_ssh(self):
        self.run_nuclei(services=None)
        self.assertEqual(len(self.templates_run_on('www.example.test:22')), 2)
        self.assertEqual([r['targets'] for r in self.nuclei.web_runs], [['www.example.test', 'www.example.test:443']])

    def test_a_lookup_that_misses_never_falls_back_to_web(self):
        """The label of 2222 is spelled differently from the target (upper case, trailing dot, a leading zero); and 5000 has no label at all."""
        names = ['www.example.test', 'www.example.test:2222', 'www.example.test:5000', 'www.example.test:8080']
        labels = {'WWW.Example.Test.:2222': 'ssh', 'www.example.test:8080': 'web'}
        self.run_nuclei(names, services=labels)
        self.assertEqual([r['targets'] for r in self.nuclei.web_runs], [['www.example.test', 'www.example.test:8080']])  # 5000 is not in it
        self.assertEqual(len(self.templates_run_on('www.example.test:2222')), 2)  # found its label in spite of the spelling: ssh
        generic = self.templates_run_on('www.example.test:5000')
        self.assertTrue(generic)  # an unlisted port is the unknown class: generic network templates
        self.assertTrue(all(not t.startswith('http/') for t in generic))
        self.assertEqual(tools.flags.nuclei_label_key('[2001:DB8::1]:0080'), ('2001:db8::1', 80))
        self.assertEqual(tools.flags.nuclei_label_key('www.example.test:22'), tools.flags.nuclei_label_key('WWW.EXAMPLE.TEST.:022'))

    def test_a_port_with_no_class_or_an_unknown_one_gets_the_generic_network_templates_never_http(self):
        self.run_nuclei(['www.example.test:9999', 'www.example.test:61616', 'www.example.test:7001'],
                        services={'www.example.test:9999': 'unknown', 'www.example.test:61616': 'unknown', 'www.example.test:7001': 'a-class-from-the-future'})
        expected = ['javascript/enumeration/zookeeper.yaml', 'network/cves/activemq-openwire.yaml', 'network/detection/weblogic-t3.yaml', 'ssl/tls-version.yaml']
        for target in ('www.example.test:9999', 'www.example.test:61616', 'www.example.test:7001'):
            self.assertEqual(self.templates_run_on(target), expected)  # not ssh, smtp, imap (they have a class), not a dos one, not http
        self.assertEqual(self.nuclei.web_runs, [])
        listing = self.nuclei.listings[0]
        self.assertEqual(_flag(listing, '-pt'), 'tcp,javascript,ssl')
        self.assertTrue({'ssh', 'smtp', 'imap', 'ftp'} <= set(_flag(listing, '-etags').split(',')))

    def test_a_tag_filter_that_names_nothing_of_the_protocol_sends_it_nothing(self):
        self.run_nuclei(services=LABELS, tags=['tech'], severities=['info'])  # the light pass: technology templates over http only
        self.assertEqual(len(self.nuclei.web_runs), 1)
        self.assertEqual(self.nuclei.service_runs, [])  # no process for a class with no template: nothing in the set is tagged tech
        self.nuclei.runs.clear()
        self.run_nuclei(services=LABELS, tags=['openssh', 'apache'])
        self.assertEqual(self.templates_run_on('www.example.test:22'), ['network/detection/openssh-detect.yaml'])  # only the ssh tags the task asked for
        self.assertEqual(self.templates_run_on('www.example.test:25'), [])

    def test_a_tls_wrapped_service_gets_only_the_ssl_templates(self):
        self.run_nuclei(['www.example.test:993'], services={'www.example.test:993': 'tls'})
        self.assertEqual(self.templates_run_on('www.example.test:993'), ['ssl/tls-version.yaml'])
        self.assertEqual(_flag(self.nuclei.service_runs[0]['argv'], '-pt'), 'ssl')

    def test_findings_and_unreachable_targets_of_every_run_are_returned_together(self):
        self.nuclei.finding[('www.example.test:22', 'network/detection/openssh-detect.yaml')] = [_row('www.example.test:22', 'ssh-t')]
        result = self.run_nuclei(services=LABELS)
        self.assertEqual([f['template_id'] for f in result['findings']], ['ssh-t'])
        self.assertEqual(result['unreachable'], [])
        self.assertNotIn('not_checked', result)

    def test_the_web_pass_runs_before_every_service_port(self):
        self.run_nuclei(services=LABELS)
        self.assertEqual([bool(r['template']) for r in self.nuclei.runs], [False] + [True] * 4)


class NucleiServiceBudgetTests(NucleiTestCase):
    """One host:port of a non-web service receives a bounded number of connections in flight, a bounded pace and a bounded total from one task."""

    def ssh(self, budget=None, timeout=3600, **kwargs):
        self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'}, budget=budget, timeout=timeout, **kwargs)
        return self.nuclei.service_runs

    def ftp(self, budget=None, timeout=3600, **kwargs):
        result = self.run_nuclei(['www.example.test:21'], services={'www.example.test:21': 'ftp'}, budget=budget, timeout=timeout, **kwargs)
        return self.nuclei.service_runs, result

    def test_each_template_is_its_own_run_one_at_a_time_with_a_pause_between(self):
        runs, _result = self.ftp()
        self.assertEqual(len(runs), 2)
        for run in runs:
            argv = run['argv']
            self.assertEqual([_flag(argv, f) for f in ('-c', '-bs', '-pc', '-jsc', '-mhe', '-retries')], ['1', '1', '1', '1', '10', '0'])
        self.assertEqual(self.clock.pauses, [0.5])  # between the two, none after the last
        self.assertEqual(runs[1]['at'] - runs[0]['at'], 0.5)

    def test_the_ssh_class_pauses_long_enough_for_openssh_source_penalties(self):
        """OpenSSH 9.8+ refuses a source after 15 s of penalty, 5 s per failed authentication; each javascript ssh template makes one (measured on OpenSSH
        10.3: the 4th template at a 500 ms pause got every later connection dropped)."""
        runs = self.ssh()
        self.assertEqual(len(runs), 2)
        self.assertEqual(self.clock.pauses, [5.5])
        self.assertEqual(runs[1]['at'] - runs[0]['at'], 5.5)
        self.assertEqual(tools.flags.nuclei_service_pause_ms('ssh'), 5500)
        self.assertEqual(tools.flags.nuclei_service_pause_ms('ssh', {'pause_ms': 9000}), 9000)  # the task's own pause counts when it is longer
        self.assertEqual(tools.flags.nuclei_service_pause_ms('ftp'), 500)

    def test_a_task_can_make_the_budget_gentler_never_harsher(self):
        self.ftp({'pause_ms': 2000, 'seconds': 30})
        self.assertEqual(self.clock.pauses, [2.0])
        self.nuclei.runs.clear(); self.clock.pauses.clear()
        self.ftp({'pause_ms': 1, 'seconds': 99999, 'web_rate': 99999})
        self.assertEqual(self.clock.pauses, [0.5])  # a task cannot ask for faster than the library's ceiling
        self.assertEqual(tools.flags.nuclei_service_budget({'pause_ms': True, 'seconds': 'x', 'web_rate': -5}), {**BUDGET_CAP, 'web_rate': 1})
        self.assertEqual(tools.flags.nuclei_service_budget({'seconds': -5})['seconds'], 10)
        self.assertEqual(tools.flags.nuclei_service_budget({'pause_ms': 10 ** 9})['pause_ms'], 10000)
        self.assertEqual(tools.flags.nuclei_service_budget(None), BUDGET_CAP)

    def test_a_port_is_never_kept_busy_longer_than_its_seconds(self):
        self.nuclei.duration[None] = 30
        runs, _result = self.ftp({'seconds': 50})
        self.assertEqual(len(runs), 2)  # the second one starts at 30.5 s: 19.5 s are left, and it is stopped there
        self.assertEqual(runs[-1]['timeout'], 20)
        self.nuclei.runs.clear()
        self.nuclei.duration[None] = 80
        runs, result = self.ftp({'seconds': 10})
        self.assertEqual(len(runs), 1)  # out of time after the first
        self.assertEqual(result['not_checked'][0]['target'], 'www.example.test:21')
        self.assertEqual(result['not_checked'][0]['reason'], 'its time ran out after 1 of 2 templates')

    def test_in_flight_connections_stay_below_sshd_max_startups_for_every_policy(self):
        """sshd's default MaxStartups is 10:30:100: ten unauthenticated connections open at once start the drops. A service run has one template running
        (-c 1) with one host, one payload and one javascript runtime, and it has no template that sets its own parallelism: at most one connection."""
        for run in self.ssh():
            in_flight = int(_flag(run['argv'], '-c')) * int(_flag(run['argv'], '-bs')) * int(_flag(run['argv'], '-pc')) * int(_flag(run['argv'], '-jsc'))
            self.assertEqual(in_flight, 1)
        listed = tools._service_templates(tools.flags.nuclei_service_selection('ssh'), self.dir, [], None)
        for path in listed:
            with open(path, encoding='utf-8') as handle:
                self.assertNotIn('threads: 10', handle.read())

    def test_the_run_never_outlasts_the_task(self):
        self.assertLessEqual(self.ssh(timeout=45)[0]['timeout'], 30)  # one template run is stopped after 30 s
        self.nuclei.runs.clear()
        self.assertEqual(self.ssh(timeout=20)[0]['timeout'], 20)

    def test_the_third_run_in_a_row_that_gets_no_answer_ends_the_port(self):
        row = {'input': 'www.example.test:9999', 'error': 'dial tcp 192.0.2.1:9999: connect: connection refused'}
        original = self.nuclei.__call__

        def refused(argv, timeout, register=None, env=None):
            out = original(argv, timeout, register, env)
            if '-elog' in argv:
                with open(argv[argv.index('-elog') + 1], 'w', encoding='utf-8') as handle:
                    handle.write(json.dumps(row) + '\n')
            return out
        with mock.patch.object(tools, '_run', side_effect=refused):
            result = tools.run_nuclei(['www.example.test:9999'], services={'www.example.test:9999': 'unknown'}, templates=self.dir)
        self.assertEqual(len(self.nuclei.service_runs), 3)  # the fourth template is not sent to a port that did not answer three times
        self.assertEqual(result['unreachable'], ['www.example.test:9999'])
        self.assertEqual(result['not_checked'], [{'target': 'www.example.test:9999', 'reason': 'nothing answered on this port'}])


class NucleiResilienceTests(NucleiTestCase):
    """One small run that fails, or matches no template, never fails the task or loses what was found; a class with no template starts nothing."""

    def test_one_failing_run_keeps_the_findings_and_names_its_port(self):
        self.nuclei.finding[('www.example.test:22', 'network/detection/openssh-detect.yaml')] = [_row('www.example.test:22', 'ssh-t')]
        self.nuclei.fail.add(('www.example.test:22', 'network/detection/ssh-version.yaml'))
        self.nuclei.finding[('www.example.test', None)] = [_row('www.example.test', 'web-t')]
        result = self.run_nuclei(services=LABELS)
        self.assertEqual(sorted(f['template_id'] for f in result['findings']), ['ssh-t', 'web-t'])
        self.assertEqual(len(self.nuclei.runs), 1 + 2 + 1 + 1)  # nothing after the failure was skipped
        self.assertEqual(result['not_checked'], [{'target': 'www.example.test:22', 'reason': '1 of 2 template runs failed'}])
        self.assertTrue(result['incomplete'])
        self.assertIn('www.example.test:22', result['unreachable'])  # partly checked: reported so the server keeps it due (third pass, N1)

    def test_a_failing_web_run_does_not_lose_the_service_findings(self):
        self.nuclei.fail.add(('www.example.test', None))
        self.nuclei.finding[('www.example.test:25', 'network/detection/smtp-detect.yaml')] = [_row('www.example.test:25', 'smtp-t')]
        result = self.run_nuclei(services=LABELS)
        self.assertEqual([f['template_id'] for f in result['findings']], ['smtp-t'])
        self.assertEqual({n['target'] for n in result['not_checked']}, {'www.example.test', 'www.example.test:443'})
        self.assertIn('web run failed', result['not_checked'][0]['reason'])

    def test_when_every_run_failed_the_task_fails(self):
        self.nuclei.fail.add(('www.example.test', None))
        with self.assertRaises(tools.ToolExitError):
            self.run_nuclei(['www.example.test'])

    def test_a_service_run_that_matches_no_template_is_nothing_to_check_not_a_failure(self):
        original = self.nuclei.__call__

        def nothing(argv, timeout, register=None, env=None):
            if '-tl' not in argv:
                raise tools.ToolExitError('[FTL] Could not run nuclei: no templates provided for scan')
            return original(argv, timeout, register, env)
        with mock.patch.object(tools, '_run', side_effect=nothing):
            result = tools.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'}, templates=self.dir)  # no tags, no severities
        self.assertEqual((result['findings'], result['no_templates']), ([], True))  # an answer (nothing to check), not an error

    def test_a_class_with_no_template_in_the_set_starts_no_process(self):
        shutil_dir = os.path.join(self.tmp.name, 'empty')
        os.makedirs(shutil_dir)
        nuclei = FakeNuclei(shutil_dir, {'http/a.yaml': {'type': 'http', 'tags': ['exposure']}})
        with mock.patch.object(tools, '_run', side_effect=nuclei):
            result = tools.run_nuclei(['www.example.test:22', 'www.example.test:25'], services={'www.example.test:22': 'ssh', 'www.example.test:25': 'smtp'},
                                      templates=shutil_dir)
        self.assertEqual(nuclei.runs, [])  # listing only, which sends nothing
        self.assertEqual(len(nuclei.listings), 2)
        self.assertTrue(result['no_templates'])

    def test_the_listing_is_made_once_per_template_set(self):
        self.run_nuclei(services=LABELS)
        listed = len(self.nuclei.listings)
        self.run_nuclei(services=LABELS)
        self.assertEqual(len(self.nuclei.listings), listed)
        self.assertEqual(listed, 3)  # ssh, smtp, imap


class NucleiTimeShareTests(NucleiTestCase):
    """The web pass runs first and a task of many slow service ports still fits its time (30 slow ports, a faked clock)."""

    PORTS = [f'www.example.test:{30000 + n}' for n in range(30)]

    def run_slow(self, cap=None):
        names = ['www.example.test', *self.PORTS]
        for port in self.PORTS:
            self.nuclei.duration[port] = 40
        self.nuclei.duration['www.example.test'] = 600
        self.nuclei.finding[('www.example.test', None)] = [_row('www.example.test', 'web-t')]
        patch = mock.patch.object(tools.flags, 'NUCLEI_SERVICE_MAX_PORTS', cap or 6)
        with patch:
            return self.run_nuclei(names, services={p: 'unknown' for p in self.PORTS}, timeout=3540)

    def test_a_task_checks_at_most_six_non_web_ports_and_reports_the_rest(self):
        result = self.run_slow()
        ran = {r['targets'][0] for r in self.nuclei.service_runs}
        self.assertEqual(len(ran), 6)
        self.assertEqual([f['template_id'] for f in result['findings']], ['web-t'])  # the web pass ran first and its findings are kept
        self.assertEqual(len(self.nuclei.web_runs), 1)
        missed = {n['target'] for n in result['not_checked']}
        self.assertEqual(missed, set(self.PORTS) - ran)
        self.assertEqual(set(result['unreachable']), missed)  # none is recorded as scanned
        self.assertIn('another task', result['not_checked'][0]['reason'])
        self.assertLessEqual(self.clock.now - 1000.0, 3540)

    def test_service_ports_share_a_fixed_part_of_the_time_and_the_web_pass_is_never_starved(self):
        result = self.run_slow(cap=30)
        web = self.nuclei.web_runs[0]
        self.assertEqual(web['timeout'], math.ceil(3540 - 3540 * tools.flags.NUCLEI_SERVICE_TIME_SHARE))  # the web pass leaves the ports their share
        self.assertLessEqual(self.clock.now - 1000.0, 3540)  # nothing runs past the task's limit
        reached = {r['targets'][0] for r in self.nuclei.service_runs}
        self.assertTrue(0 < len(reached) < 30)
        missed = {n['target'] for n in result['not_checked']}
        self.assertEqual(missed | reached, set(self.PORTS))  # every port is either checked or named: none is silently lost
        self.assertTrue(any('ran out of time' in n['reason'] for n in result['not_checked']))
        self.assertTrue(result['incomplete'])


def _add_template(case, rel, text, kind='javascript', tags=('enum',)):
    """A template file in the fake bundle, listed by the fake ``nuclei -tl`` under the generic (unknown) class."""
    text = re.sub(r'(?m)^id: .*$', f'id: {_slug(rel)}', text, count=1)  # one id per file
    case.nuclei.templates[rel] = {'type': kind, 'tags': list(tags), 'text': text}
    path = os.path.join(case.dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    return path


JS = 'id: t\ninfo:\n  metadata:\n    max-request: 1\njavascript:\n  - code: |\n      {code}\n'
TCP = 'id: t\ntcp:\n  - inputs:\n      - data: {data}\n    host:\n      - "{{{{Hostname}}}}"\n    port: 9999\n'


class NucleiNoCredentialTests(NucleiTestCase):
    """Third pass, N3: nothing that sends credentials, guesses a password or can lock an account runs on a service, whatever its tags say (no switch
    for it exists for nuclei). Decided by what the template says, not by its tags."""

    def refused(self, text, kind='javascript'):
        path = _add_template(self, 'network/x/probe.yaml', text, kind)
        return tools._paced_template(path)

    def test_a_template_with_payloads_or_an_attack_is_refused(self):
        self.assertIn('payloads', self.refused('id: a\ntcp:\n  - inputs:\n      - data: "x"\n    attack: clusterbomb\n    payloads:\n      users:\n        - postgres\n', 'tcp'))
        self.assertIn('payloads', self.refused('id: a\njavascript:\n  - pre-condition: |\n      1\n    args:\n      Host: "{{Host}}"\n    payloads:\n      u:\n        - a\n'))
        self.assertIsNone(self.refused('id: a\ninfo:\n  description: sends payloads: none\ntcp:\n  - inputs:\n      - data: "x"\n', 'tcp'))

    def test_a_javascript_template_that_logs_in_is_refused(self):
        for code in ('const c = require("nuclei/mysql"); let m = new c.MySQLClient(); m.Connect(Host,Port,User,Pass)',
                     'client.ConnectWithDB(Host, Port, User, Pass, Db)',
                     'client.ExecuteQuery(Host, Port, User, Pass, Db, "select 1")',
                     'var r = c.ListShares(Host, Port, User, Pass)',
                     "client.Authenticate('', '')",
                     'c.Login(Host, Port)'):
            self.assertIn('login', self.refused(JS.format(code=code)), code)
        self.assertIn('login', self.refused('id: a\njavascript:\n  - args:\n      username: admin\n      password: admin\n    code: |\n      x\n'))

    def test_a_tcp_template_that_sends_an_authentication_command_is_refused(self):
        for data in ('"USER root\\r\\n"', '"PASS \\r\\n"', '"AUTH PLAIN {{base64(tok)}}\\r\\n"', '"a001 LOGIN user pass\\r\\n"', '"AUTHENTICATE PLAIN\\r\\n"',
                     '"{{hex_encode(\'x\\u0000user\\u0000{{users}}\')}}"',
                     '"00000054000300007573657200706f73746772657300646174616261736500"',  # a PostgreSQL startup packet naming a user
                     '"7000000036534352414d2d5348412d323536"'):  # a SCRAM-SHA-256 first message
            text = TCP.format(data=data) + ('        type: hex\n' if data[1:5] in ('0000', '7000') else '')
            self.assertIn('login', self.refused(text, 'tcp'), data)

    def test_more_than_ten_declared_requests_is_refused(self):
        self.assertIsNone(self.refused('id: a\ninfo:\n  metadata:\n    max-request: 10\n', 'tcp'))
        self.assertIn('requests', self.refused('id: a\ninfo:\n  metadata:\n    max-request: 11\n', 'tcp'))
        self.assertEqual(tools.flags.NUCLEI_SERVICE_MAX_REQUESTS, 10)

    def test_a_check_that_sends_no_credential_is_kept(self):
        for text, kind in ((JS.format(code='const s = new ssh.SSHClient(); s.ConnectSSHInfoMode(Host, Port)'), 'javascript'),
                           (JS.format(code='c.ConnectSMBInfoMode(Host, Port)'), 'javascript'),
                           (JS.format(code='c.FingerprintMySQL(Host, Port)'), 'javascript'),
                           (TCP.format(data='"\\r\\n"'), 'tcp'),
                           ('id: banner\ninfo:\n  description: the response to the PASS command and the user name\ntcp:\n  - inputs:\n      - data: "HELP\\r\\n"\n', 'tcp')):
            self.assertIsNone(self.refused(text, kind), text)

    def test_a_credential_template_with_harmless_tags_is_not_listed_for_any_service(self):
        _add_template(self, 'javascript/enumeration/pgsql/pgsql-default-db.yaml', JS.format(code='client.ConnectWithDB(Host, Port, User, Pass, Db)'), tags=('enum', 'js', 'pgsql'))
        _add_template(self, 'javascript/misconfiguration/mysql/mysql-empty-password.yaml', JS.format(code='c.Connect(Host,Port,User,Pass)'), tags=('mysql', 'vuln'))
        _add_template(self, 'network/enumeration/smtp-user-enum.yaml', 'id: u\ntcp:\n  - inputs:\n      - data: "VRFY {{users}}\\r\\n"\n    payloads:\n      users:\n        - root\n', 'tcp', tags=('smtp', 'enum'))
        _add_template(self, 'network/misconfig/ftp-anon.yaml', TCP.format(data='"USER anonymous\\r\\n"'), 'tcp', tags=('ftp', 'enum'))
        self.run_nuclei(['www.example.test:9999', 'www.example.test:25', 'www.example.test:21', 'www.example.test:3306', 'www.example.test:5432'],
                        services={'www.example.test:9999': 'unknown'})
        ran = {r['template'] for r in self.nuclei.service_runs}
        self.assertTrue(ran)
        for name in ('pgsql-default-db', 'mysql-empty-password', 'smtp-user-enum', 'ftp-anon'):
            self.assertFalse([t for t in ran if name in t], name)


class NucleiPartlyCheckedTests(NucleiTestCase):
    """Third pass, N1: a port only partly checked is reported unreachable too, so the server keeps it due."""

    def test_a_port_that_ran_out_of_time_part_way_is_named_unreachable(self):
        self.nuclei.duration[None] = 30
        result = self.run_nuclei(['www.example.test:21'], services={'www.example.test:21': 'ftp'}, budget={'seconds': 10})
        self.assertEqual(result['not_checked'][0]['reason'], 'its time ran out after 1 of 2 templates')
        self.assertEqual(result['unreachable'], ['www.example.test:21'])
        self.assertTrue(result['incomplete'])

    def test_a_port_some_runs_of_which_failed_is_named_unreachable(self):
        self.nuclei.fail.add(('www.example.test:21', 'network/detection/ftp-banner.yaml'))
        result = self.run_nuclei(['www.example.test:21'], services={'www.example.test:21': 'ftp'})
        self.assertEqual(result['not_checked'], [{'target': 'www.example.test:21', 'reason': '1 of 2 template runs failed'}])
        self.assertEqual(result['unreachable'], ['www.example.test:21'])

    def test_a_port_checked_in_full_is_not_unreachable(self):
        result = self.run_nuclei(['www.example.test:21'], services={'www.example.test:21': 'ftp'})
        self.assertEqual(result['unreachable'], [])
        self.assertNotIn('not_checked', result)


class NucleiListingFailureTests(NucleiTestCase):
    """Third pass, N2: a failing ``nuclei -tl`` loses neither the web findings nor the task."""

    def break_listing(self, error):
        original = self.nuclei.__call__

        def run(argv, timeout, register=None, env=None):
            if '-tl' in argv:
                raise error
            return original(argv, timeout, register, env)
        patcher = mock.patch.object(tools, '_run', side_effect=run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_listing_that_exits_with_an_error_keeps_the_web_findings_and_reports_the_ports(self):
        self.break_listing(tools.ToolExitError('nuclei exited with status 2'))
        self.nuclei.finding[('www.example.test', None)] = [_row('www.example.test', 'web-t')]
        result = self.run_nuclei(services=LABELS)
        self.assertEqual([f['template_id'] for f in result['findings']], ['web-t'])
        self.assertEqual(self.nuclei.service_runs, [])
        self.assertEqual({n['target'] for n in result['not_checked']}, {'www.example.test:22', 'www.example.test:25', 'www.example.test:143'})
        self.assertTrue(all('listing' in n['reason'] for n in result['not_checked']))
        self.assertTrue({'www.example.test:22', 'www.example.test:25', 'www.example.test:143'} <= set(result['unreachable']))
        self.assertTrue(result['incomplete'])

    def test_a_listing_that_times_out_is_the_same(self):
        self.break_listing(subprocess.TimeoutExpired('nuclei', 120))
        result = self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(result['unreachable'], ['www.example.test:22'])
        self.assertIn('listing', result['not_checked'][0]['reason'])

    def test_a_failed_listing_is_not_kept_and_is_tried_once_per_class_in_a_task(self):
        self.break_listing(tools.ToolExitError('boom'))
        self.run_nuclei(['www.example.test:9998', 'www.example.test:9999'], services={'www.example.test:9998': 'unknown', 'www.example.test:9999': 'unknown'})
        self.assertEqual(len(tools._TEMPLATE_LISTINGS), 0)


class NucleiSshBehindAnotherPortTests(NucleiTestCase):
    """Third pass, N5: an unknown port that answers with an SSH banner on connect is an ssh port (its pacing, its templates)."""

    def test_an_unknown_port_with_an_ssh_banner_gets_the_ssh_class(self):
        self.banner.return_value = b'SSH-2.0-OpenSSH_9.9\r\n'
        result = self.run_nuclei(['www.example.test:2200'], services={'www.example.test:2200': 'unknown'})
        self.assertEqual(self.templates_run_on('www.example.test:2200'), ['network/detection/openssh-detect.yaml', 'network/detection/ssh-version.yaml'])
        self.assertEqual(self.clock.pauses, [5.5])
        self.assertEqual(result['unreachable'], [])

    def test_an_unknown_port_with_any_other_answer_or_none_stays_unknown(self):
        for banner in (None, b'', b'220 mail ESMTP\r\n', b'HTTP/1.1 400 Bad Request'):
            self.banner.return_value = banner
            self.nuclei.runs.clear()
            self.run_nuclei(['www.example.test:9999'], services={'www.example.test:9999': 'unknown'})
            self.assertNotIn('network/detection/openssh-detect.yaml', self.templates_run_on('www.example.test:9999'), banner)

    def test_a_port_with_a_known_class_is_never_probed(self):
        self.run_nuclei(['www.example.test:25', 'www.example.test:22'], services={'www.example.test:25': 'smtp', 'www.example.test:22': 'ssh'})
        self.banner.assert_not_called()

    def test_the_probe_is_one_short_connection_that_reads_only_the_banner(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = b'SSH-2.0-x\r\n'
        with mock.patch.object(tools.socket, 'create_connection', return_value=sock) as connect:
            self.assertEqual(REAL_PROBE('www.example.test', 2200), b'SSH-2.0-x\r\n')
        connect.assert_called_once()
        self.assertLessEqual(connect.call_args.kwargs.get('timeout', connect.call_args.args[1] if len(connect.call_args.args) > 1 else 99), 5)
        sock.sendall.assert_not_called()  # it never sends: a banner is read on connect
        sock.recv.assert_called_once()
        with mock.patch.object(tools.socket, 'create_connection', side_effect=OSError('refused')):
            self.assertIsNone(REAL_PROBE('www.example.test', 2200))  # a port that does not answer is just unknown

    def test_a_proxied_run_does_not_probe(self):
        with mock.patch.object(tools, '_proxy_args', return_value=['-proxy', 'http://p:3128']):
            self.run_nuclei(['www.example.test:9999'], services={'www.example.test:9999': 'unknown'})
        self.banner.assert_not_called()


REAL_LOAD = nuclei_allowlist.load_allowlist  # the shipped list, before a test replaces it
_FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '..', 'cvengine_scanner', 'fixtures')


def _add_real(case, template_id, refused=False):
    """A real nuclei-templates v10.5.1 file in the fake bundle (a vendored allowlisted one, or one of the refused ten), listed by the fake ``nuclei -tl`` for the
    types and tags its own header gives, so the run meets what a run on the real library meets."""
    import yaml
    source = os.path.join(_FIXTURES, 'nuclei_service_refused', f'{template_id}.yaml') if refused else None
    if source is None:
        entry = REAL_LOAD()['templates'][template_id]
        source = os.path.join(_FIXTURES, 'nuclei_templates', entry['path'])
    with open(source, 'rb') as handle:
        raw = handle.read()
    doc = yaml.safe_load(raw.decode('utf-8'))
    kind = next(k for k in ('tcp', 'javascript', 'ssl') if doc.get(k))
    tags = doc['info'].get('tags', [])
    tags = [t.strip() for t in tags.split(',')] if isinstance(tags, str) else list(tags)
    rel = f'network/real/{template_id}.yaml'
    case.nuclei.templates[rel] = {'type': kind, 'tags': tags}
    path = os.path.join(case.dir, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(raw)
    return rel, path


class NucleiAllowlistRunTests(NucleiTestCase):
    """Fourth pass: a service port runs only what the shipped allowlist names, with the content it records (default deny)."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(nuclei_allowlist, 'load_allowlist', side_effect=lambda path=None: REAL_LOAD())  # the shipped list, not the fake bundle's
        patcher.start()
        self.addCleanup(patcher.stop)

    SEVEN = ('backdoored-zte', 'tidb-unauth', 'clickhouse-unauth', 'CVE-2022-24706', 'CVE-2026-83548', 'CVE-2026-55040', 'CVE-2024-54772')

    def ran(self, target):
        return sorted(os.path.basename(t)[:-5] for t in self.templates_run_on(target))

    def test_a_template_that_is_not_on_the_list_never_reaches_a_service_run(self):
        """The fake bundle holds a dozen templates no list names (including ones a content rule would accept): none is run, on any class."""
        self.run_nuclei(HOST_PORTS + ['www.example.test:9999'], services={**LABELS, 'www.example.test:9999': 'unknown'})
        self.assertEqual(self.nuclei.service_runs, [])
        self.assertEqual(len(self.nuclei.web_runs), 1)  # the web pass is not governed by the list

    def test_the_seven_templates_the_review_named_are_never_selected_on_any_class_or_tag(self):
        for tid in self.SEVEN:
            _add_real(self, tid, refused=True)
        _add_real(self, 'openssh-detect')
        ports = {'www.example.test:22': 'ssh', 'www.example.test:23': 'telnet', 'www.example.test:3306': 'mysql', 'www.example.test:4000': 'unknown',
                 'www.example.test:6379': 'redis', 'www.example.test:8291': 'unknown', 'www.example.test:9999': 'unknown', 'www.example.test:21': 'ftp'}
        for tags in (None, ['ssh'], ['mysql', 'redis'], ['telnet', 'cve']):
            self.nuclei.runs.clear()
            self.run_nuclei(list(ports), services=ports, tags=tags)
            ran = {os.path.basename(r['template'])[:-5] for r in self.nuclei.service_runs}
            self.assertFalse(ran & set(self.SEVEN), (tags, ran & set(self.SEVEN)))
            for tid in self.SEVEN:  # not even listed as a candidate that survives
                self.assertNotIn(tid, REAL_LOAD()['templates'])

    def test_an_allowlisted_template_runs_where_its_class_speaks_and_nowhere_else(self):
        _add_real(self, 'openssh-detect')
        _add_real(self, 'ftp-detect')
        self.run_nuclei(['www.example.test:22', 'www.example.test:21'], services={'www.example.test:22': 'ssh', 'www.example.test:21': 'ftp'})
        self.assertEqual(self.ran('www.example.test:22'), ['openssh-detect'])
        self.assertEqual(self.ran('www.example.test:21'), ['ftp-detect'])

    def test_a_template_whose_content_differs_from_the_listed_hash_never_runs(self):
        rel, path = _add_real(self, 'openssh-detect')
        self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(self.ran('www.example.test:22'), ['openssh-detect'])
        self.nuclei.runs.clear()
        tools._TEMPLATE_LISTINGS.clear()
        with open(path, 'ab') as handle:
            handle.write(b'# the library changed this file\n')  # one comment line: a different sha256
        result = self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(self.nuclei.service_runs, [])
        self.assertTrue(result.get('no_templates') or result['unreachable'] == [], result)

    def test_a_template_that_changes_after_it_was_listed_is_not_run(self):
        _add_real(self, 'openssh-detect')
        _rel2, second = _add_real(self, 'ssh-auth-methods')
        slept = []

        def pause(seconds):
            slept.append(seconds)
            with open(second, 'ab') as handle:
                handle.write(b'# swapped between the runs\n')
            self.clock.sleep(seconds)
        with mock.patch.object(tools, '_sleep', pause):
            result = self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(self.ran('www.example.test:22'), ['openssh-detect'])  # the second was listed, then changed: never sent
        self.assertEqual([n['target'] for n in result['not_checked']], ['www.example.test:22'])
        self.assertIn('changed', result['not_checked'][0]['reason'])
        self.assertEqual(result['unreachable'], ['www.example.test:22'])  # the port stays due

    def test_nuclei_is_given_a_private_copy_of_the_bytes_that_were_hashed_not_the_library_file(self):
        _rel, path = _add_real(self, 'openssh-detect')
        self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        given = [r['given'] for r in self.nuclei.service_runs]
        self.assertEqual(len(given), 1)
        self.assertFalse(os.path.abspath(given[0]['path']).startswith(os.path.abspath(self.dir) + os.sep), given[0]['path'])
        self.assertEqual(given[0]['mode'], 0o600)
        self.assertEqual(given[0]['dir_mode'], 0o700)  # a directory only the Sentinel's user can write
        with open(path, 'rb') as handle:
            self.assertEqual(given[0]['bytes'], handle.read())
        self.assertFalse(os.path.exists(os.path.dirname(given[0]['path'])))  # removed when the run ended

    def test_a_file_swapped_after_the_hash_check_is_not_what_nuclei_opens(self):
        """Review defect 3: the library file is replaced in the instant between the last hash check and nuclei opening the file."""
        _rel, path = _add_real(self, 'openssh-detect')
        with open(path, 'rb') as handle:
            verified = handle.read()

        def swap(_given):
            with open(path, 'wb') as handle:
                handle.write(verified + b'tcp:\n  - inputs:\n      - data: "USER root\\r\\n"\n')

        self.nuclei.on_run = swap
        self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual([r['given']['bytes'] for r in self.nuclei.service_runs], [verified])

    def test_a_port_whose_class_has_no_allowlisted_template_is_reported_not_checked_with_the_plain_reason(self):
        """postgres, mongodb (before mongodb-unauth) and ldap had no template: the port is named in ``not_checked``, even next to a port that ran."""
        _add_real(self, 'openssh-detect')
        ports = {'www.example.test:22': 'ssh', 'www.example.test:5432': 'postgres', 'www.example.test:389': 'ldap'}
        result = self.run_nuclei(list(ports), services=ports)
        self.assertEqual(self.ran('www.example.test:22'), ['openssh-detect'])
        self.assertEqual(self.ran('www.example.test:5432'), [])
        rows = {row['target']: row['reason'] for row in result['not_checked']}
        self.assertEqual(rows, {'www.example.test:5432': 'no check exists for this service', 'www.example.test:389': 'no check exists for this service'})
        self.assertIn('www.example.test:5432', result['unreachable'])  # the server keeps the port due, with its back-off
        self.assertNotIn('www.example.test:22', rows)

    def test_a_missing_list_reports_every_service_port_not_checked_never_an_empty_answer(self):
        _add_real(self, 'openssh-detect')
        with mock.patch.object(nuclei_allowlist, 'load_allowlist', side_effect=lambda path=None: {'nuclei_templates': '', 'templates': {}, 'reviewed_exceptions': set()}):
            result = self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(self.nuclei.service_runs, [])
        self.assertEqual([row['target'] for row in result['not_checked']], ['www.example.test:22'])
        self.assertEqual(result['not_checked'][0]['reason'], 'no check exists for this service')
        self.assertFalse(result.get('no_templates'))

    def test_a_filter_that_matches_nothing_on_a_class_that_has_templates_is_still_an_answer(self):
        _add_real(self, 'openssh-detect')
        result = self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'}, tags=['nonexistent-tag'])
        self.assertTrue(result.get('no_templates'))
        self.assertNotIn('not_checked', result)

    def test_a_missing_list_runs_nothing_on_a_service_port(self):
        _add_real(self, 'openssh-detect')
        with mock.patch.object(nuclei_allowlist, 'load_allowlist', side_effect=lambda path=None: {'nuclei_templates': '', 'templates': {}, 'reviewed_exceptions': set()}):
            self.run_nuclei(['www.example.test:22'], services={'www.example.test:22': 'ssh'})
        self.assertEqual(self.nuclei.service_runs, [])

    def test_a_template_that_names_a_port_of_its_own_runs_only_on_that_port(self):
        _add_real(self, 'perforce-detection')  # it connects to {{Host}}:1666 as well as to the target
        self.run_nuclei(['www.example.test:1666', 'www.example.test:9999'], services={'www.example.test:1666': 'unknown', 'www.example.test:9999': 'unknown'})
        self.assertEqual(self.ran('www.example.test:1666'), ['perforce-detection'])
        self.assertEqual(self.ran('www.example.test:9999'), [])

    def test_a_restored_template_runs_though_the_content_rule_would_refuse_it_and_any_other_is_still_held_to_the_rule(self):
        rel, path = _add_real(self, 'smb-signing')
        self.assertIsNotNone(tools._paced_template(path))  # User and Pass: the name rule refuses it; a person read it and it is restored
        self.run_nuclei(['www.example.test:445'], services={'www.example.test:445': 'smb'})
        self.assertEqual(self.ran('www.example.test:445'), ['smb-signing'])
        # a template on a list that is not a reviewed exception is held to the content rule as well
        _add_template(self, 'network/x/with-payloads.yaml', 'id: with-payloads\ntcp:\n  - inputs:\n      - data: "x"\n    attack: batteringram\n    payloads:\n      a:\n        - b\n', 'tcp', tags=('smb',))
        with open(os.path.join(self.dir, 'network/x/with-payloads.yaml'), 'rb') as handle:
            entry = {'sha256': nuclei_allowlist.sha256_of(handle.read()), 'classes': ['smb']}
        shipped = REAL_LOAD()
        patched = {**shipped, 'templates': {**shipped['templates'], 'with-payloads': entry}}
        self.nuclei.runs.clear()
        tools._TEMPLATE_LISTINGS.clear()
        with mock.patch.object(nuclei_allowlist, 'load_allowlist', side_effect=lambda path=None: patched):
            self.run_nuclei(['www.example.test:445'], services={'www.example.test:445': 'smb'})
        self.assertEqual(self.ran('www.example.test:445'), ['smb-signing'])


class NucleiBannerBudgetTests(NucleiTestCase):
    """Fourth pass, N12: the banner probe is part of the port's budget, and a name is resolved once."""

    def setUp(self):
        super().setUp()
        for i in range(3):
            _add_template(self, f'network/generic/unknown-{i}.yaml', f'id: u{i}\ntcp:\n  - inputs:\n      - data: "x"\n', 'tcp', tags=('generic',))

    def run_unknown(self, probe_seconds):
        def probe(host, port, resolve=None):
            self.clock.advance(probe_seconds)
            return None
        self.banner.side_effect = probe
        self.nuclei.duration[None] = 2
        return self.run_nuclei(['www.example.test:9999'], services={'www.example.test:9999': 'unknown'}, budget={'seconds': 10}, tags=['generic'])

    def test_without_the_probe_time_every_template_of_a_ten_second_port_runs(self):
        result = self.run_unknown(0)
        self.assertEqual(len(self.nuclei.service_runs), 3)
        self.assertNotIn('not_checked', result)

    def test_the_time_the_probe_took_is_taken_from_the_ports_budget(self):
        result = self.run_unknown(6)  # 6 s of the 10 are gone: only two of the three runs fit
        self.assertEqual(len(self.nuclei.service_runs), 2)
        self.assertIn('its time ran out after 2 of 3', result['not_checked'][0]['reason'])
        self.assertEqual(result['unreachable'], ['www.example.test:9999'])

    def test_a_host_name_is_resolved_once_for_the_judgment_and_the_probe_connects_to_what_was_judged(self):
        asked = []
        real = fake_getaddrinfo

        def counting(name, port, *args, **kwargs):
            asked.append(name)
            return real(name, port, *args, **kwargs)
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = b''
        with mock.patch('socket.getaddrinfo', side_effect=counting), mock.patch.object(tools, '_probe_banner', REAL_PROBE), \
                mock.patch.object(tools.socket, 'create_connection', return_value=sock) as connect:
            self.run_nuclei(['www.example.test:9999'], services={'www.example.test:9999': 'unknown'}, tags=['generic'])
        self.assertEqual(asked.count('www.example.test'), 1)  # not a second time for the probe
        connect.assert_called_once()
        self.assertEqual(connect.call_args.args[0], ('93.184.215.14', 9999))  # the address scope judged, not the name

    def test_the_probe_of_a_name_that_does_not_resolve_connects_to_nothing(self):
        with mock.patch.object(tools.socket, 'create_connection') as connect:
            self.assertIsNone(REAL_PROBE('gone.example.test', 2200, mock.Mock(side_effect=OSError('no such name'))))
        connect.assert_not_called()
