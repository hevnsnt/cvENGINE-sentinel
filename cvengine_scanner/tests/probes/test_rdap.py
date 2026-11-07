"""Registration checks (``probes.rdap``), ported from cvENGINE's tests of ``cveFeed.mailfail.rdap_registered``: only the registry's explicit "not found"
counts as unregistered, and the registry is reached only through the policy and the floor."""
import json
import unittest
from unittest import mock

from cvengine_scanner.probes import rdap
from cvengine_scanner.probes.policy import ScopePolicy

BOOTSTRAP = json.dumps({'services': [[['com'], ['https://rdap.registry.example/']], [['test'], ['http://plain.example/']]]}).encode()


class RegisteredTests(unittest.TestCase):
    def setUp(self):
        rdap._CACHE.update(at=0.0, services=None)

    def test_rdap_uses_the_registry_from_the_iana_bootstrap_and_only_a_404_means_unregistered(self):
        for status, expected in ((404, False), (200, True), (500, None), (301, None)):
            asked = []

            def get(url, policy, status=status):
                asked.append(url)
                return (200, BOOTSTRAP) if url == rdap.BOOTSTRAP else (status, b'')
            rdap._CACHE.update(at=0.0, services=None)
            self.assertIs(rdap.registered('gone-example.com', None, get=get), expected)
            self.assertEqual(asked, [rdap.BOOTSTRAP, 'https://rdap.registry.example/domain/gone-example.com'])

    def test_a_registry_not_on_https_or_missing_is_not_asked(self):
        asked = []

        def get(url, policy):
            asked.append(url)
            return (200, BOOTSTRAP)
        self.assertIsNone(rdap.registered('gone.test', None, get=get))
        self.assertIsNone(rdap.registered('gone.invalidtld', None, get=get))
        self.assertEqual(asked, [rdap.BOOTSTRAP])

    def test_no_answer_is_never_a_verdict(self):
        self.assertIsNone(rdap.registered('gone-example.com', None, get=lambda url, policy: None))
        self.assertIsNone(rdap.registered('gone-example.com', None, get=mock.Mock(side_effect=OSError('down'))))


class GetHttpsTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_https_without_credentials_is_asked(self):
        policy = ScopePolicy({})
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            for url in ('http://rdap.registry.example/x', 'https://user:pw@rdap.registry.example/x', 'ftp://rdap.registry.example/x', 'https:///x'):
                self.assertIsNone(rdap.get_https(url, policy), url)

    def test_a_registry_that_resolves_to_a_private_or_loopback_address_is_never_connected_to(self):
        policy = ScopePolicy({})
        answers = [(2, 1, 6, '', ('10.0.0.5', 443)), (2, 1, 6, '', ('127.0.0.1', 443))]
        with mock.patch('socket.getaddrinfo', return_value=answers), mock.patch('socket.socket', side_effect=AssertionError('connected')):
            self.assertIsNone(rdap.get_https('https://rdap.registry.example/domain/x.com', policy))

    def test_the_policy_exclusions_hold_for_a_registry_host_and_a_refusal_is_carried_back(self):
        policy = ScopePolicy({'excluded': ['rdap.registry.example']})
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            self.assertIsNone(rdap.get_https('https://rdap.registry.example/domain/x.com', policy))

    def test_a_good_answer_is_read_with_the_derived_policy_and_the_host_recorded(self):
        policy = ScopePolicy({})
        resp = mock.Mock(status=200)
        resp.read.side_effect = lambda n: b'{}'
        resp.getheader.return_value = None
        conn = mock.Mock()
        conn.getresponse.return_value = resp
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=((2, ('93.184.215.14', 443)),)), \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection', return_value=conn) as factory:
            self.assertEqual(rdap.get_https('https://rdap.registry.example/domain/x.com', policy), (200, b'{}'))
        self.assertEqual(conn.request.call_args.args[:2], ('GET', '/domain/x.com'))
        self.assertEqual(factory.call_args.args[:3][0], 'rdap.registry.example')


if __name__ == '__main__':
    unittest.main()
