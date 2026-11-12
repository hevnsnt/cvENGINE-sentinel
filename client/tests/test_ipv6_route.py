"""IPv6 targets on a Sentinel: the flags a tool needs for one, and what happens on a Sentinel that has no IPv6 route.

Found with real tools on a private IPv6 docker network: testssl.sh stops with 'Only IPv6 address(es) available, maybe add -6' unless it is given -6,
and on a machine with no IPv6 route naabu runs until its time limit and finds nothing. nmap already gets -6 (tests in test_tools.py) and says
'0 hosts scanned' when it has no route, which the server reads as 'this Sentinel cannot reach IPv6 addresses'."""
import socket
import unittest
from unittest import mock

from client import tools

V6 = '2606:4700:4700::1111'


class Stop(Exception):
    pass


class RouteProbeTests(unittest.TestCase):
    def test_a_route_is_a_udp_connect_that_sends_nothing(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        with mock.patch('client.tools.socket.socket', return_value=sock) as make:
            self.assertTrue(tools._kernel_route(V6))
        make.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect.assert_called_once_with((V6, 9))
        sock.send.assert_not_called()
        sock.sendto.assert_not_called()

    def test_no_route_is_false_whatever_the_os_says(self):
        for failure in (OSError(101, 'Network is unreachable'), OSError(97, 'Address family not supported')):
            sock = mock.MagicMock()
            sock.__enter__.return_value = sock
            sock.connect.side_effect = failure
            with self.subTest(failure=failure), mock.patch('client.tools.socket.socket', return_value=sock):
                self.assertFalse(tools._kernel_route(V6))
        with mock.patch('client.tools.socket.socket', side_effect=OSError(97, 'no ipv6')):
            self.assertFalse(tools._kernel_route(V6))


class TesstslTests(unittest.TestCase):
    def argv_of(self, ip):
        captured = {}

        def fake_start(argv, *args, **kwargs):
            captured['argv'] = argv
            raise Stop
        with mock.patch('client.tools._start', side_effect=fake_start), self.assertRaises(Stop):
            tools.run_testssl('www.example.test', ip, 443)
        return captured['argv']

    def test_an_ipv6_address_gets_dash_6_before_the_address_it_connects_to(self):
        with mock.patch('client.tools.ipv6_route', return_value=True):
            argv = self.argv_of('2606:4700:4700::1111')
        self.assertIn('-6', argv)
        self.assertLess(argv.index('-6'), argv.index('--ip'))
        self.assertEqual(argv[argv.index('--ip') + 1], '2606:4700:4700::1111')
        self.assertEqual(argv.count('-6'), 1)

    def test_an_ipv4_address_does_not(self):
        self.assertNotIn('-6', self.argv_of('8.8.8.8'))

    def test_a_sentinel_with_no_ipv6_route_says_so_and_runs_nothing(self):
        with mock.patch('client.tools.ipv6_route', return_value=False), mock.patch('client.tools._start') as start:
            with self.assertRaises(tools.NoIpv6Route) as caught:
                tools.run_testssl('www.example.test', '2606:4700:4700::1111', 443)
        start.assert_not_called()
        self.assertEqual(str(caught.exception), 'this Sentinel cannot reach IPv6 addresses')
        self.assertIsInstance(caught.exception, tools.ToolExitError)


class NaabuTests(unittest.TestCase):
    def test_an_ipv6_address_with_no_route_is_left_unfinished_and_never_given_to_naabu(self):
        seen = []

        def fake_run(argv, timeout, register=None):
            with open(argv[argv.index('-list') + 1], encoding='utf-8') as handle:
                seen.append(handle.read())
            return '{"ip":"8.8.8.8","port":22}\n'
        with mock.patch('client.tools._run', side_effect=fake_run), mock.patch('client.tools.ipv6_route', return_value=False):
            result = tools.run_naabu(['8.8.8.8', V6])
        self.assertEqual(seen, ['8.8.8.8\n'])
        self.assertEqual(result['ports'], {'8.8.8.8': [22]})
        self.assertIs(result['incomplete'], True)
        self.assertEqual(result['unfinished'], [V6])

    def test_only_unroutable_ipv6_addresses_run_nothing_at_all(self):
        with mock.patch('client.tools._run') as fake_run, mock.patch('client.tools.ipv6_route', return_value=False):
            result = tools.run_naabu([V6, '2606:4700:4700::1001'])
        fake_run.assert_not_called()
        self.assertEqual(result, {'ports': {}, 'incomplete': True, 'unfinished': [V6, '2606:4700:4700::1001']})

    def test_a_routable_ipv6_address_is_scanned_with_the_rest(self):
        seen = []

        def fake_run(argv, timeout, register=None):
            with open(argv[argv.index('-list') + 1], encoding='utf-8') as handle:
                seen.append(handle.read())
            return ''
        with mock.patch('client.tools._run', side_effect=fake_run), mock.patch('client.tools.ipv6_route', return_value=True):
            result = tools.run_naabu(['8.8.8.8', V6])
        self.assertEqual(seen, ['8.8.8.8\n2606:4700:4700::1111\n'])
        self.assertNotIn('incomplete', result)


class NmapKeepsDashSixTests(unittest.TestCase):
    def test_every_nmap_task_kind_gives_an_ipv6_address_dash_6(self):
        report = '<nmaprun><runstats><finished exit="success"/><hosts up="0" down="0" total="0"/></runstats></nmaprun>'
        calls = {'udp': lambda: tools.run_nmap_udp(V6), 'full': lambda: tools.run_nmap_full(V6),
                 'verify': lambda: tools.run_nmap_verify(V6, [443]), 'fingerprint': lambda: tools.run_nmap([V6])}
        for name, call in calls.items():
            with self.subTest(kind=name), mock.patch('client.tools._run', return_value=report) as fake_run:
                try:
                    call()
                except Exception:  # noqa: BLE001 - what the report makes of an empty run is tested elsewhere; the command line is what counts here
                    pass
                self.assertIn('-6', fake_run.call_args[0][0])
