import unittest
from unittest import mock

from client import scope
from client.scope import ScopeError


def resolver_for(table):
    def resolve(name, port):
        if name not in table:
            raise OSError('no such host')
        return [(2, 1, 6, '', (address, 0)) for address in table[name]]
    return resolve


class CheckIpTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_public_addresses_are_allowed_everywhere(self):
        for value in ('8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', ' 52.151.200.60 '):
            for internal in (False, True):
                self.assertTrue(scope.check_ip(value, internal=internal))

    def test_the_canonical_text_is_returned(self):
        self.assertEqual(scope.check_ip('2606:4700:4700:0:0:0:0:1111'), '2606:4700:4700::1111')

    def test_never_scanned_on_any_sentinel(self):
        for value in ('127.0.0.1', '127.255.255.254', '0.0.0.0', '169.254.169.254', '169.254.1.1', '224.0.0.1', '255.255.255.255', '240.0.0.1',
                      '192.0.2.1', '198.51.100.7', '203.0.113.9', '198.18.0.1', '::', '::1', 'fe80::1', 'ff02::1', 'fd00:ec2::254', '2001:db8::1'):
            for internal in (False, True):
                with self.subTest(value=value, internal=internal):
                    self.assertRaises(ScopeError, scope.check_ip, value, internal)

    def test_ipv4_hidden_in_ipv6_is_judged_as_ipv4(self):
        for value in ('::ffff:127.0.0.1', '::ffff:169.254.169.254', '64:ff9b::7f00:1', '2002:7f00:1::1', '2002:a9fe:a9fe::1'):
            with self.subTest(value=value):
                self.assertRaises(ScopeError, scope.check_ip, value, True)
        self.assertRaises(ScopeError, scope.check_ip, '::ffff:10.0.0.5', False)
        self.assertTrue(scope.check_ip('::ffff:10.0.0.5', True))

    def test_private_space_only_for_an_internal_sentinel(self):
        for value in ('10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '100.64.0.1', 'fd12:3456::1'):
            with self.subTest(value=value):
                self.assertRaises(ScopeError, scope.check_ip, value, False)
                self.assertTrue(scope.check_ip(value, True))

    def test_only_this_machines_own_setting_decides_internal(self):
        with mock.patch.object(scope.config, '_local_internal', return_value=False), \
                mock.patch.dict(scope.config._overrides, {'network': 'internal'}):
            self.assertRaises(ScopeError, scope.check_ip, '10.0.0.1')
        with mock.patch.object(scope.config, '_local_internal', return_value=True):
            self.assertTrue(scope.check_ip('10.0.0.1'))

    def test_this_containers_own_address_is_refused(self):
        self.assertRaises(ScopeError, scope.check_ip, '172.19.0.2', True)

    def test_address_shortcuts_and_forms_are_not_plain_addresses(self):
        for value in ('2130706433', '0x7f000001', '017700000001', '127.1', '1.2.3', '010.0.0.1', '1.2.3.4/24', '1.2.3.4-9', '1.2.3.0-255',
                      '1.2.3.4,5.6.7.8', 'fe80::1%eth0', '', ' ', '8.8.8.8 ', '8.8.8.8\n1.1.1.1', '[::1]', None, 5, '1.2.3.4:80'):
            with self.subTest(value=value):
                if value == '8.8.8.8 ':
                    self.assertEqual(scope.check_ip(value, False), '8.8.8.8')  # surrounding blanks are trimmed
                else:
                    self.assertRaises(ScopeError, scope.check_ip, value, True)


class CheckHostTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(scope, 'own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_ordinary_names_are_normalised(self):
        self.assertEqual(scope.check_host('Example.COM.', resolve=False), 'example.com')
        self.assertEqual(scope.check_host('router', resolve=False), 'router')
        self.assertEqual(scope.check_host('a-b.c-d.example.org', resolve=False), 'a-b.c-d.example.org')

    def test_an_ip_is_judged_as_an_ip(self):
        self.assertEqual(scope.check_host('8.8.8.8', internal=False), '8.8.8.8')
        self.assertRaises(ScopeError, scope.check_host, '127.0.0.1', False)
        self.assertRaises(ScopeError, scope.check_host, '10.0.0.1', False)

    def test_nmap_range_syntax_is_not_a_host_name(self):
        for value in ('0-255.0-255.0-255.0-255', '10.0-255.0-255.1-254', '10.0.0.1-3', '10.0.0.*', '192.168.0-1.1', '1.2.3.4/16', '10.0.0.0/8',
                      '10.0.0.1,10.0.0.2', '[10.0.0.1]'):
            for internal in (False, True):
                with self.subTest(value=value, internal=internal):
                    self.assertRaises(ScopeError, scope.check_host, value, internal, False)

    def test_well_known_local_names_are_refused(self):
        for value in ('localhost', 'LOCALHOST', 'foo.localhost', 'ip6-localhost', 'metadata.google.internal', 'host.docker.internal',
                      'gateway.docker.internal', 'instance-data', 'metadata'):
            with self.subTest(value=value):
                self.assertRaises(ScopeError, scope.check_host, value, True, False)

    def test_malformed_names_are_refused(self):
        for value in ('', ' ', 'a' * 64 + '.com', ('a.' * 130) + 'com', 'under_score.com', '-bad.com', 'bad-.com', 'a..b.com', 'a b.com', 'x.com/path',
                      'x.com:80', 'x.123', 'a;b.com', 'a$(id).com', None, 7, '0x7f000001', '0x7f.0x0.0x0.0x1', 'host.1x', '0177.0.0.1x'):
            with self.subTest(value=value):
                self.assertRaises(ScopeError, scope.check_host, value, False, False)

    def test_a_name_that_resolves_to_a_refused_address_is_refused(self):
        resolver = resolver_for({'evil.example': ['169.254.169.254'], 'lan.example': ['10.0.0.5'], 'mixed.example': ['8.8.8.8', '127.0.0.1'],
                                 'ok.example': ['8.8.8.8', '2606:4700:4700::1111']})
        self.assertRaises(ScopeError, scope.check_host, 'evil.example', False, True, resolver)
        self.assertRaises(ScopeError, scope.check_host, 'evil.example', True, True, resolver)
        self.assertRaises(ScopeError, scope.check_host, 'mixed.example', True, True, resolver)
        self.assertRaises(ScopeError, scope.check_host, 'lan.example', False, True, resolver)
        self.assertEqual(scope.check_host('lan.example', True, True, resolver), 'lan.example')
        self.assertEqual(scope.check_host('ok.example', False, True, resolver), 'ok.example')

    def test_a_name_that_does_not_resolve_is_allowed(self):
        self.assertEqual(scope.check_host('nxdomain.example', False, True, resolver_for({})), 'nxdomain.example')

    def test_check_target_is_check_host(self):
        self.assertEqual(scope.check_target('8.8.8.8', internal=False), '8.8.8.8')
        self.assertRaises(ScopeError, scope.check_target, '0-255.0-255.0-255.0-255', False, False)


class CheckUrlTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(scope, 'own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_public_http_or_https_url_passes_unchanged(self):
        for url in ('https://example.com/blog/', 'http://example.com:8080/', 'https://8.8.8.8/'):
            self.assertEqual(scope.check_url(url, internal=False, resolve=False), url)

    def test_other_schemes_userinfo_and_refused_hosts_do_not(self):
        for url in ('ftp://example.com/', 'file:///etc/passwd', 'http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:2375/',
                    'http://user:pw@example.com/', 'http://localhost/', 'http://10.0.0.1/', 'http://[::1]/', 'https://', 'http://example.com:99999/',
                    'example.com', '', None):
            with self.subTest(url=url):
                self.assertRaises(ScopeError, scope.check_url, url, False, False)


class OwnAddressesTests(unittest.TestCase):
    def test_it_is_looked_up_once_and_tolerates_a_failing_lookup(self):
        scope._own_cache['value'] = None
        with mock.patch.object(scope.socket, 'getaddrinfo', side_effect=OSError('no dns')):
            self.assertEqual(scope.own_addresses(), frozenset())
        with mock.patch.object(scope.socket, 'getaddrinfo', side_effect=AssertionError('must not be called again')):
            self.assertEqual(scope.own_addresses(), frozenset())
        scope._own_cache['value'] = None


if __name__ == '__main__':
    unittest.main()
