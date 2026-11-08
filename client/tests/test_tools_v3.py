"""The kinds of contract version 3: nmap_full, nmap_verify, node2shell, rdp_shot, db_probe, path_probe and nuclei_validate."""
import base64
import json
import socket
import socketserver
import struct
import threading
import unittest
from unittest import mock

from client import config, dbprobe, rdp, scope, tools
from cvengine_scanner import contract

FINISHED = ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')


def report(ip='93.184.215.14', ports=''):
    return FINISHED.format(ip=ip, ports=ports)


def setUpModule():
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=OSError('no DNS in these tests')),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'})),
                    mock.patch.object(scope, 'internal_allowed', return_value=False)):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


class NmapKindsTests(unittest.TestCase):
    def test_nmap_full_sweeps_every_port_of_one_address_and_returns_the_finished_report(self):
        xml = report(ports='<port protocol="tcp" portid="8443"><state state="open"/></port>')
        with mock.patch.object(tools, '_run', return_value=xml) as run:
            out = tools.run_nmap_full('93.184.215.14')
        self.assertEqual(out, {'xml': xml})
        argv = run.call_args[0][0]
        self.assertIn('-p-', argv)
        self.assertEqual(argv[-1], '93.184.215.14')
        self.assertEqual(run.call_args.kwargs['max_bytes'], tools.MAX_FULL_READ)  # read more than the server accepts: a long report is cut to 100 ports, not refused

    def test_a_cut_off_report_is_an_error_never_nothing_open(self):
        with mock.patch.object(tools, '_run', return_value='<nmaprun><host/></nmaprun>'), self.assertRaises(tools.ToolOutputError):
            tools.run_nmap_full('93.184.215.14')

    def test_the_scope_floor_refuses_a_private_or_loopback_address(self):
        for address in ('10.0.0.5', '127.0.0.1', '169.254.169.254', 'www.example.test'):
            with self.subTest(address=address), mock.patch.object(tools, '_run') as run, self.assertRaises(tools.TargetError):
                tools.run_nmap_full(address)
            run.assert_not_called()

    def test_nmap_verify_runs_only_reviewed_scripts(self):
        with mock.patch.object(tools, '_run', return_value=report()) as run:
            tools.run_nmap_verify('93.184.215.14', [8443, 443], version_all=True, scripts=['http-title', 'banner'], host_timeout=90)
        argv = run.call_args[0][0]
        self.assertIn('--version-all', argv)
        self.assertEqual(argv[argv.index('--script') + 1], 'banner,http-title')
        self.assertEqual(argv[argv.index('-p') + 1], '443,8443')
        self.assertEqual(argv[argv.index('--host-timeout') + 1], '90s')
        for bad in (['http-brute'], ['banner', 'vuln'], 'banner'):
            with self.subTest(scripts=bad), mock.patch.object(tools, '_run') as run, self.assertRaises(tools.TargetError):
                tools.run_nmap_verify('93.184.215.14', [80], scripts=bad)
            run.assert_not_called()

    def test_nmap_verify_checks_its_ports_and_intensity(self):
        for kwargs in ({'ports': []}, {'ports': [0]}, {'ports': list(range(1, 70))}, {'ports': [80], 'version_intensity': 10},
                       {'ports': [80], 'host_timeout': 5}):
            with self.subTest(kwargs=kwargs), mock.patch.object(tools, '_run') as run, self.assertRaises(tools.TargetError):
                tools.run_nmap_verify('93.184.215.14', **kwargs)
            run.assert_not_called()
        with mock.patch.object(tools, '_run', return_value=report()) as run:
            tools.run_nmap_verify('93.184.215.14', [22], version_intensity=5)
        argv = run.call_args[0][0]
        self.assertEqual(argv[argv.index('--version-intensity') + 1], '5')
        self.assertNotIn('--script', argv)


class Node2shellTests(unittest.TestCase):
    def test_the_detector_verdict_is_reshaped_and_bounded(self):
        from client.vendor import node2shell
        verdict = {'vulnerable': True, 'verdict': 'VULNERABLE', 'reason': 'same class', 'status_code': 502, 'response': 'x' * 5000}
        with mock.patch.object(tools, '_checked_url', side_effect=lambda url: url), \
                mock.patch.object(node2shell, 'check_vulnerability', return_value=verdict):
            out = tools.run_node2shell('https://www.example.test/')
        self.assertEqual(out['vulnerable'], True)
        self.assertEqual(len(out['evidence']), tools.NODE2SHELL_EVIDENCE)
        self.assertEqual(out['status_code'], 502)

    def test_a_detector_crash_is_inconclusive(self):
        from client.vendor import node2shell
        with mock.patch.object(tools, '_checked_url', side_effect=lambda url: url), \
                mock.patch.object(node2shell, 'check_vulnerability', side_effect=RuntimeError('boom')):
            out = tools.run_node2shell('https://www.example.test/')
        self.assertIsNone(out['vulnerable'])

    def test_a_url_outside_scope_is_refused(self):
        for url in ('http://127.0.0.1/', 'ftp://www.example.test/', 'https://10.0.0.1/'):
            with self.subTest(url=url), self.assertRaises(tools.TargetError):
                tools.run_node2shell(url)


class RdpShotTests(unittest.TestCase):
    def test_a_painted_screen_comes_back_as_base64(self):
        with mock.patch.object(rdp, 'available', return_value=True), mock.patch.object(rdp, 'capture', return_value=b'\x89PNG\r\n\x1a\nrest'):
            out = tools.run_rdp_shot('93.184.215.14', 3389)
        self.assertEqual(base64.b64decode(out['image']), b'\x89PNG\r\n\x1a\nrest')
        self.assertTrue(out['painted'])

    def test_a_refused_connection_or_a_blank_screen_painted_nothing(self):
        for side_effect in (ConnectionRefusedError('no'), lambda *a: None):
            with self.subTest(side_effect=side_effect), mock.patch.object(rdp, 'available', return_value=True), \
                    mock.patch.object(rdp, 'capture', side_effect=side_effect):
                self.assertEqual(tools.run_rdp_shot('93.184.215.14', 3389), {'painted': False})

    def test_no_client_is_an_error_not_an_empty_screen(self):
        with mock.patch.object(rdp, 'available', return_value=False), self.assertRaises(tools.TargetError):
            tools.run_rdp_shot('93.184.215.14', 3389)


class _Postgres(socketserver.BaseRequestHandler):
    code = 0

    def handle(self):
        self.request.recv(1024)
        self.request.sendall(b'R' + struct.pack('!ii', 8, self.code))
        if self.code == 0:
            body = b'server_version\x0016.2\x00'
            self.request.sendall(b'S' + struct.pack('!i', 4 + len(body)) + body + b'Z\x00\x00\x00\x05I')
            self.request.recv(16)


class DbProbeTests(unittest.TestCase):
    def serve(self, code):
        handler = type('Handler', (_Postgres,), {'code': code})
        server = socketserver.TCPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_postgres_open_only_on_authentication_ok(self):
        with mock.patch('socket.getaddrinfo', socket.getaddrinfo.__wrapped__ if hasattr(socket.getaddrinfo, '__wrapped__') else _real_getaddrinfo):
            self.assertEqual(dbprobe.check_postgres('127.0.0.1', self.serve(0)), (True, 'PostgreSQL 16.2'))
            for code in (3, 5, 10):  # cleartext, MD5, SASL: a password is asked for, and none is ever sent
                with self.subTest(code=code):
                    self.assertEqual(dbprobe.check_postgres('127.0.0.1', self.serve(code)), (False, ''))

    def test_a_checker_crash_is_not_open_and_evidence_is_clipped(self):
        with mock.patch.dict(dbprobe.CHECKS, {'redis': mock.Mock(side_effect=RuntimeError('x'))}):
            self.assertEqual(dbprobe.probe('93.184.215.14', 6379, 'redis'), {'open': False, 'evidence': ''})
        with mock.patch.dict(dbprobe.CHECKS, {'redis': mock.Mock(return_value=(True, 'PONG\x07' + 'v' * 400))}):
            out = dbprobe.probe('93.184.215.14', 6379, 'redis')
        self.assertEqual(len(out['evidence']), dbprobe.EVIDENCE_LEN)
        self.assertNotIn('\x07', out['evidence'])

    def test_an_unknown_database_or_an_address_outside_scope_is_refused(self):
        for args in (('93.184.215.14', 6379, 'oracle'), ('10.0.0.1', 6379, 'redis'), ('93.184.215.14', 0, 'redis')):
            with self.subTest(args=args), self.assertRaises(tools.TargetError):
                tools.run_db_probe(*args)


def _real_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (host, port))]


class PathProbeTests(unittest.TestCase):
    def test_reset_answers_become_rows_and_the_odd_probe_follows_an_answered_one(self):
        def fake_run(argv, timeout, register=None, max_bytes=None):
            ip, port, odd = argv[-1], argv[argv.index('-p') + 1], '-sF' in argv
            reason = 'reset' if (ip == '93.184.215.14' or not odd) and ip != '93.184.215.30' else 'no-response'
            state = 'closed' if reason == 'reset' else 'filtered'
            return report(ip, f'<port protocol="tcp" portid="{port}"><state state="{state}" reason="{reason}"/></port>')
        targets = [{'ip': '93.184.215.14', 'port': 81}, {'ip': '93.184.215.20', 'port': 9}, {'ip': '93.184.215.30', 'port': 9}]
        with mock.patch.object(tools, '_run', side_effect=fake_run):
            out = tools.run_path_probe(targets, pause=0)
        self.assertEqual(out['results'], [{'ip': '93.184.215.14', 'port': 81, 'plain': True, 'odd': True},
                                          {'ip': '93.184.215.20', 'port': 9, 'plain': True, 'odd': False},
                                          {'ip': '93.184.215.30', 'port': 9, 'plain': False, 'odd': None}])

    def test_an_address_nmap_could_not_probe_is_left_out(self):
        with mock.patch.object(tools, '_run', side_effect=tools.ToolExitError('nmap exited')):
            self.assertEqual(tools.run_path_probe([{'ip': '93.184.215.14', 'port': 81}], pause=0), {'results': []})

    def test_targets_are_checked(self):
        for targets in ([], [{'ip': '10.0.0.1', 'port': 9}], [{'ip': '2606:4700::1', 'port': 9}], [{'ip': '93.184.215.14', 'port': 9}] * 9):
            with self.subTest(targets=targets), self.assertRaises(tools.TargetError):
                tools.run_path_probe(targets)


TEMPLATE = 'id: example\ninfo:\n  name: Example\n  severity: info\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/"]\n'


class NucleiValidateTests(unittest.TestCase):
    def test_a_template_that_reads_files_or_runs_code_is_refused(self):
        for key in ('code', 'file', 'headless', 'javascript', 'flow', 'workflows'):
            with self.subTest(key=key), mock.patch.object(tools, '_run_status') as run, self.assertRaises(tools.TargetError):
                tools.run_nuclei_validate('validate', TEMPLATE + f'{key}:\n  - x\n')
            run.assert_not_called()

    def test_validate_runs_the_fixture_only_after_the_syntax_check_passes(self):
        with mock.patch.object(tools, '_run_status', return_value=(1, '', 'error: bad')), mock.patch.object(tools, '_benign_fixture') as fixture:
            out = tools.run_nuclei_validate('validate', TEMPLATE)
        self.assertEqual((out['valid'], out['fixture_ok']), (False, None))
        fixture.assert_not_called()
        with mock.patch.object(tools, '_run_status', return_value=(0, '', '')), \
                mock.patch.object(tools, '_benign_fixture', return_value=(True, 'no match')):
            out = tools.run_nuclei_validate('validate', TEMPLATE)
        self.assertEqual((out['valid'], out['fixture_ok'], out['fixture_note']), (True, True, 'no match'))

    def test_test_mode_gives_one_outcome_per_target_and_counts_only_matcher_hits(self):
        hit = {'host': 'https://93.184.215.14', 'matcher-name': 'word', 'request': 'r' * 9000, 'info': {'name': 'x'}}
        extract_only = {'host': 'https://93.184.215.20', 'matcher-status': False}
        lines = json.dumps(hit) + '\n' + json.dumps(extract_only) + '\n'
        with mock.patch.object(tools, '_run_status', return_value=(0, lines, '')):
            out = tools.run_nuclei_validate('test', TEMPLATE, ['https://93.184.215.14', 'https://93.184.215.20', 'https://10.0.0.1'])
        first, second, third = out['outcomes']
        self.assertTrue(first['vulnerable'])
        self.assertEqual(len(first['hit']['request']), 8000)
        self.assertFalse(second['vulnerable'])
        self.assertIn('error', third)  # outside scope: never handed to nuclei

    def test_the_template_test_takes_the_egress_proxy_and_the_loopback_fixture_does_not(self):
        with mock.patch.object(tools, '_proxy_args', return_value=['-proxy', 'http://proxy.example.test:3128']) as proxy, \
                mock.patch.object(tools, '_run_status', return_value=(0, '', '')) as run:
            tools.run_nuclei_validate('test', TEMPLATE, ['https://93.184.215.14'])
        proxy.assert_called_once_with('nuclei', ['https://93.184.215.14'])
        self.assertEqual(run.call_args[0][0][-2:], ['-proxy', 'http://proxy.example.test:3128'])

    def test_a_nuclei_failure_is_an_error_for_every_target(self):
        with mock.patch.object(tools, '_run_status', return_value=(2, '', 'boom')):
            out = tools.run_nuclei_validate('test', TEMPLATE, ['https://93.184.215.14'])
        self.assertEqual(out['outcomes'][0]['error'], 'boom')

    def test_an_unknown_mode_or_oversized_template_is_refused(self):
        for args in (('nope', TEMPLATE), ('validate', 'x' * 200_001), ('validate', ''), ('test', TEMPLATE, [])):
            with self.subTest(args=args[:1]), self.assertRaises(tools.TargetError):
                tools.run_nuclei_validate(*args)


class ContractVersionThreeTests(unittest.TestCase):
    NEW = ('nmap_full', 'nmap_verify', 'node2shell', 'rdp_shot', 'db_probe', 'path_probe', 'nuclei_validate')

    def test_the_new_kinds_are_declared_and_have_runners(self):
        for kind in self.NEW:
            with self.subTest(kind=kind):
                self.assertIn(kind, config.CAPABILITIES)
                self.assertIn(kind, tools.RUNNERS)
                self.assertEqual(contract.load()['kind_since'][kind], 3)

    def test_a_server_on_contract_two_is_never_asked_for_them(self):
        saved = config.server_contract()
        self.addCleanup(config.set_server_contract, {'contract': {'version': saved}})
        config.set_server_contract({'contract': {'version': 2}})
        self.assertFalse(any(config.server_knows(kind) for kind in self.NEW))
        self.assertTrue(config.server_knows('waf'))
        config.set_server_contract({'contract': {'version': 3}})
        self.assertTrue(all(config.server_knows(kind) for kind in self.NEW))


if __name__ == '__main__':
    unittest.main()
