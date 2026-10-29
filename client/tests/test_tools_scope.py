"""Every tool runs its targets through ``client.scope``: what this Sentinel never scans is refused before any process starts."""
import unittest
from unittest import mock

from client import scope, tools

NAMES = {'www.example.test': ['93.184.215.14'], 'rebind.example.test': ['93.184.215.14', '127.0.0.1'],
         'metadata.example.test': ['169.254.169.254'], 'lan.example.test': ['10.1.2.3']}


def fake_getaddrinfo(name, port, *args, **kwargs):
    if name not in NAMES:
        raise OSError('no such host')
    return [(2, 1, 6, '', (a, 0)) for a in NAMES[name]]


def setUpModule():
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=fake_getaddrinfo),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'}))):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


# Each tool, called with one target in the place the task names it.
TOOLS = {
    'nmap': lambda t: tools.run_nmap([t]),
    'naabu': lambda t: tools.run_naabu([t]),
    'nuclei': lambda t: tools.run_nuclei([t]),
    'nmap_udp': lambda t: tools.run_nmap_udp(t),
    'testssl ip': lambda t: tools.run_testssl('www.example.test', t, 443),
    'testssl host': lambda t: tools.run_testssl(t, '93.184.215.14', 443),
    'wpscan': lambda t: tools.run_wpscan(f'https://{t}/'),
}

NEVER = ('127.0.0.1', '127.1.2.3', '::1', '[::1]', '::ffff:127.0.0.1', '0.0.0.0', 'localhost', 'LOCALHOST', 'foo.localhost',
         '169.254.169.254', 'metadata.google.internal', 'metadata', 'host.docker.internal', 'host.docker.internal:2375',
         '127.0.0.1:2375', '172.19.0.2', '2130706433', '0x7f000001', '0177.0.0.1', '127.1', '0-255.0-255.0-255.0-255',
         '10.0-255.0-255.1-254', '8.8.8.0/24', '10.0.0.0/8', '8.8.8.8,1.1.1.1', 'www.example.test,localhost', '8.8.8.*',
         'rebind.example.test', 'metadata.example.test', 'fe80::1', '224.0.0.1', '255.255.255.255')
PRIVATE = ('10.1.2.3', '192.168.1.10', '172.16.5.5', '100.64.0.1', 'fd12:3456::1', 'lan.example.test')


class RefusedTargetTests(unittest.TestCase):
    def _assert_refused(self, target, internal):
        for name, call in TOOLS.items():
            if name == 'wpscan' and '/' in target:
                continue  # in a URL the slash starts the path: the host part is judged like any other
            if name == 'testssl host' and target in NAMES:
                continue  # testssl.sh connects to the ip it is given and never resolves the host name (see the next test)
            with self.subTest(tool=name, target=target, internal=internal), \
                    mock.patch.object(scope, 'internal_allowed', return_value=internal), \
                    mock.patch('client.tools._run') as fake_run, mock.patch('client.tools.subprocess.Popen') as popen:
                with self.assertRaises(tools.TargetError):
                    call(target)
                fake_run.assert_not_called()
                popen.assert_not_called()

    def test_never_scanned_by_any_sentinel(self):
        for target in NEVER:
            for internal in (False, True):
                self._assert_refused(target, internal)

    def test_testssl_judges_its_host_name_as_written_and_its_ip_as_the_address_it_connects_to(self):
        with mock.patch.object(scope, 'internal_allowed', return_value=False), \
                mock.patch('client.tools.subprocess.Popen', side_effect=OSError('started')) as popen:
            with self.assertRaises(OSError):
                tools.run_testssl('rebind.example.test', '93.184.215.14', 443)
            with self.assertRaises(tools.TargetError):
                tools.run_testssl('www.example.test', '127.0.0.1', 443)
        self.assertEqual(popen.call_count, 1)

    def test_private_space_is_refused_on_an_external_sentinel(self):
        for target in PRIVATE:
            self._assert_refused(target, False)

    def test_private_space_is_allowed_on_an_internal_sentinel(self):
        allowed = {'nmap': lambda t: tools.run_nmap([t]), 'naabu': lambda t: tools.run_naabu([t]), 'nuclei': lambda t: tools.run_nuclei([t]),
                   'nmap_udp': lambda t: tools.run_nmap_udp(t)}
        for target in PRIVATE:
            for name, call in allowed.items():
                with self.subTest(tool=name, target=target), mock.patch.object(scope, 'internal_allowed', return_value=True), \
                        mock.patch('client.tools._run', return_value='') as fake_run:
                    call(target)
                    fake_run.assert_called()
        with mock.patch.object(scope, 'internal_allowed', return_value=True), \
                mock.patch('client.tools.subprocess.Popen', side_effect=OSError('started')) as popen:
            with self.assertRaises(OSError):
                tools.run_testssl('lan.example.test', '10.1.2.3', 443)
            with self.assertRaises(OSError):
                tools.run_wpscan('http://lan.example.test/')
        self.assertEqual(popen.call_count, 2)

    def test_public_targets_run_on_either(self):
        for internal in (False, True):
            with mock.patch.object(scope, 'internal_allowed', return_value=internal), mock.patch('client.tools._run', return_value='') as fake_run:
                tools.run_nmap(['8.8.8.8', 'www.example.test'])
                tools.run_nuclei(['https://www.example.test/', '8.8.8.8:443'])
                tools.run_nmap_udp('2606:4700:4700::1111')
            self.assertEqual(fake_run.call_count, 3)

    def test_one_refused_entry_refuses_the_whole_task(self):
        with mock.patch.object(scope, 'internal_allowed', return_value=False), mock.patch('client.tools._run') as fake_run:
            with self.assertRaises(tools.TargetError):
                tools.run_nmap(['8.8.8.8', 'www.example.test', '169.254.169.254'])
        fake_run.assert_not_called()

    def test_host_port_is_refused_where_the_tool_cannot_take_it(self):
        with mock.patch.object(scope, 'internal_allowed', return_value=False), mock.patch('client.tools._run', return_value='') as fake_run:
            for call in (lambda: tools.run_nmap(['8.8.8.8:443']), lambda: tools.run_naabu(['www.example.test:443']),
                         lambda: tools.run_nmap_udp('8.8.8.8:53')):
                with self.assertRaises(tools.TargetError):
                    call()
            fake_run.assert_not_called()
            tools.run_nuclei(['8.8.8.8:443', 'www.example.test:8443'])
            fake_run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
