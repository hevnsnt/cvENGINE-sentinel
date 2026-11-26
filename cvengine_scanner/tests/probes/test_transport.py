"""Ported from cvENGINE's web/tests/test_pinned_transport.py, as ``transport`` (its tests that need no database), run against the library copy.
The body reader's tests are in test_read_body.py."""
import socket
from unittest import mock
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import transport
from cvengine_scanner.probes.policy import ScopePolicy
def answer(ip, family=socket.AF_INET):
    address = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address
POLICY = ScopePolicy({'domains': ['example.test']}, internal=False)
PUBLIC, PUBLIC6 = '93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'


class PinnedTransportTests(SimpleTestCase):
    def setUp(self):
        # the floor's own-address list is read once, through getaddrinfo, which these tests replace
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_connection_does_not_resolve_again_after_admission(self):
        sock = mock.Mock()
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer(PUBLIC)]) as dns:
            addresses = transport.resolve('asset.example.test', 443, POLICY)
            dns.side_effect = AssertionError('unexpected second DNS lookup')
            with mock.patch.object(socket, 'socket', return_value=sock):
                self.assertIs(transport.open_socket(addresses, 3, POLICY), sock)
        sock.connect.assert_called_once_with((PUBLIC, 443))
        dns.assert_called_once()

    def test_mixed_allowed_and_prohibited_answers_fail_closed(self):
        for bad in ('127.0.0.1', '169.254.169.254', '10.0.0.1'):
            with mock.patch.object(socket, 'getaddrinfo', return_value=[answer(PUBLIC), answer(bad)]):
                with self.assertRaises(ValueError):
                    transport.resolve('asset.example.test', 443, POLICY)

    def test_a_name_outside_the_policy_is_never_looked_up(self):
        with mock.patch.object(socket, 'getaddrinfo') as dns:
            with self.assertRaises(ValueError):
                transport.resolve('www.elsewhere.example', 443, POLICY)
        dns.assert_not_called()

    def test_empty_or_failed_dns_never_falls_back_to_hostname_connection(self):
        with mock.patch.object(socket, 'socket') as connect:
            for result in ([], OSError('DNS unavailable')):
                with mock.patch.object(socket, 'getaddrinfo') as dns:
                    if isinstance(result, Exception):
                        dns.side_effect = result
                    else:
                        dns.return_value = result
                    with self.assertRaises((ValueError, OSError)):
                        transport.resolve('asset.example.test', 443, POLICY)
            connect.assert_not_called()

    def test_ipv6_connects_to_numeric_sockaddr(self):
        sock = mock.Mock()
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer(PUBLIC6, socket.AF_INET6)]):
            addresses = transport.resolve('ipv6.example.test', 8443, POLICY)
        with mock.patch.object(socket, 'socket', return_value=sock):
            transport.open_socket(addresses, 3, POLICY, host='ipv6.example.test')
        sock.connect.assert_called_once_with((PUBLIC6, 8443, 0, 0))
        self.assertEqual(POLICY.touched[-1], 'ipv6.example.test')

    def test_connection_failure_closes_socket_without_dns_fallback(self):
        sock = mock.Mock()
        sock.connect.side_effect = OSError('refused')
        with mock.patch.object(socket, 'socket', return_value=sock), \
                mock.patch.object(socket, 'getaddrinfo') as dns:
            with self.assertRaises(OSError):
                transport.open_socket(((socket.AF_INET, (PUBLIC, 443)),), 3, POLICY)
        dns.assert_not_called()
        sock.close.assert_called_once()

    def test_open_socket_vets_every_address_again(self):
        with mock.patch.object(socket, 'socket') as connect:
            with self.assertRaises(ValueError):
                transport.open_socket(((socket.AF_INET, ('127.0.0.1', 443)),), 3, POLICY)
        connect.assert_not_called()

    def test_private_space_needs_the_server_and_this_machine_both(self):
        lab = ScopePolicy({'domains': ['example.test'], 'private': True}, internal=True)
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('10.0.0.1')]):
            self.assertTrue(transport.resolve('private.example.test', 443, lab))
            with self.assertRaises(ValueError):  # an external Sentinel never reaches private space, whatever the task says
                transport.resolve('private.example.test', 443, ScopePolicy({'domains': ['example.test'], 'private': True}, internal=False))
            with self.assertRaises(ValueError):  # an internal Sentinel reaches it only when the server allows it
                transport.resolve('private.example.test', 443, ScopePolicy({'domains': ['example.test']}, internal=True))
        with mock.patch.object(socket, 'getaddrinfo', return_value=[answer('127.0.0.1')]):
            with self.assertRaises(ValueError):
                transport.resolve('loop.example.test', 443, lab)

    def test_https_preserves_original_sni_and_closes_failed_tls_socket(self):
        raw, context = mock.Mock(), mock.Mock()
        connection = transport.HTTPConnection('original.example.test', 443, (), 3, POLICY, context=context)
        with mock.patch.object(transport, 'open_socket', return_value=raw):
            connection.connect()
        context.wrap_socket.assert_called_once_with(raw, server_hostname='original.example.test')
        context.wrap_socket.side_effect = OSError('TLS failed')
        with mock.patch.object(transport, 'open_socket', return_value=raw):
            with self.assertRaises(OSError):
                connection.connect()
        raw.close.assert_called_once()
