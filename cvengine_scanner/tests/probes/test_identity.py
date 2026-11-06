"""The identity_check kind (``probes.identity``): DNS reads and certificate names under the task's scope policy."""
import unittest
from unittest import mock

from cvengine_scanner.probes import identity

SCOPE = {'hosts': ['www.example.test', 'example.test', '93.184.215.14'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False,
         'addresses': [], 'blocked': []}


class FakeName:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeRdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class FakeAnswer:
    def __init__(self, rrset, canonical=''):
        self.rrset, self.canonical_name = rrset, FakeName(canonical)


class FakeResolver:
    """``script[(name, rtype)]`` is an answer, or an exception to raise."""

    def __init__(self, script):
        self.script, self.asked = script, []

    def resolve(self, name, rtype, raise_on_no_answer=True):
        self.asked.append((str(name), rtype))
        got = self.script[(str(name), rtype)]
        if isinstance(got, BaseException):
            raise got
        return got


def item(ident, name, rtype):
    return {'id': ident, 'name': name, 'type': rtype}


class DnsTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_dns(self, items, script):
        resolver = FakeResolver(script)
        return identity.run_batch({'scope': SCOPE, 'dns': items}, resolver=resolver), resolver

    def test_a_cname_read_gives_the_canonical_name_of_a_name_that_has_an_address(self):
        got, resolver = self.run_dns([item('a', 'www.example.test', 'CNAME')],
                                     {('www.example.test', 'A'): FakeAnswer([FakeRdata('1.2.3.4')], 'App.Herokudns.com.')})
        self.assertEqual(got['dns'], [{'id': 'a', 'status': 'ok', 'records': [], 'canonical': 'app.herokudns.com'}])
        self.assertEqual(got['touched'], ['www.example.test'])
        self.assertEqual(resolver.asked, [('www.example.test', 'A')])

    def test_a_name_that_is_not_an_alias_has_an_empty_canonical_name(self):
        got, _ = self.run_dns([item('a', 'www.example.test', 'CNAME')], {('www.example.test', 'A'): FakeAnswer([FakeRdata('1.2.3.4')], 'www.example.test.')})
        self.assertEqual(got['dns'][0]['canonical'], '')

    def test_a_name_with_no_address_over_ipv4_is_asked_over_ipv6(self):
        got, resolver = self.run_dns([item('a', 'www.example.test', 'CNAME')], {('www.example.test', 'A'): FakeAnswer(None),
                                                                           ('www.example.test', 'AAAA'): FakeAnswer([FakeRdata('::1')], 'x.example.net.')})
        self.assertEqual(got['dns'][0], {'id': 'a', 'status': 'ok', 'records': [], 'canonical': 'x.example.net'})
        self.assertEqual([r for _n, r in resolver.asked], ['A', 'AAAA'])

    def test_a_name_with_no_address_at_all_is_none(self):
        got, _ = self.run_dns([item('a', 'www.example.test', 'CNAME')], {('www.example.test', 'A'): FakeAnswer(None), ('www.example.test', 'AAAA'): FakeAnswer(None)})
        self.assertEqual(got['dns'], [{'id': 'a', 'status': 'none', 'records': []}])

    def test_ns_and_mx_return_the_record_texts_and_nothing_found_is_none(self):
        import dns.resolver
        got, _ = self.run_dns([item('n', 'example.test', 'NS'), item('m', 'example.test', 'MX')],
                              {('example.test', 'NS'): FakeAnswer([FakeRdata('ns1.example.net.'), FakeRdata('ns2.example.net.')]),
                               ('example.test', 'MX'): dns.resolver.NoAnswer()})
        self.assertEqual(got['dns'], [{'id': 'n', 'status': 'ok', 'records': ['ns1.example.net.', 'ns2.example.net.']},
                                      {'id': 'm', 'status': 'none', 'records': []}])

    def test_nxdomain_is_none_but_a_timeout_is_unknown_never_none(self):
        import dns.exception
        import dns.resolver
        got, _ = self.run_dns([item('a', 'example.test', 'NS'), item('b', 'www.example.test', 'NS')],
                              {('example.test', 'NS'): dns.resolver.NXDOMAIN(), ('www.example.test', 'NS'): dns.exception.Timeout()})
        self.assertEqual(got['dns'][0]['status'], 'none')
        self.assertEqual(got['dns'][1]['status'], 'unknown')
        self.assertEqual(got['dns'][1]['records'], [])
        self.assertIn('Timeout', got['dns'][1]['error'])

    def test_a_ptr_asks_the_reverse_name_of_an_address_the_policy_allows(self):
        got, resolver = self.run_dns([item('p', '93.184.215.14', 'PTR')], {('14.215.184.93.in-addr.arpa.', 'PTR'): FakeAnswer([FakeRdata('host.example.net.')])})
        self.assertEqual(got['dns'], [{'id': 'p', 'status': 'ok', 'records': ['host.example.net.']}])
        self.assertEqual(resolver.asked, [('14.215.184.93.in-addr.arpa.', 'PTR')])

    def test_a_question_the_policy_refuses_is_not_asked_and_is_unknown(self):
        got, resolver = self.run_dns([item('a', 'other.example.test', 'NS'), item('p', '10.0.0.5', 'PTR')], {})
        self.assertEqual(resolver.asked, [])
        self.assertEqual([r['status'] for r in got['dns']], ['unknown', 'unknown'])
        self.assertTrue(all(r['error'].startswith('not run:') for r in got['dns']))
        self.assertEqual(got['refused'], ['other.example.test', '10.0.0.5'])
        self.assertEqual(got['touched'], [])

    def test_a_malformed_question_fails_the_task(self):
        for bad in (item('a', 'example.test', 'TXT'), item('a', '93.184.215.14', 'NS'), item('a', 'example.test', 'PTR'), {'id': 'a'}, 'x'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                identity.run_batch({'scope': SCOPE, 'dns': [bad]}, resolver=FakeResolver({}))

    def test_the_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            identity.run_batch({'scope': SCOPE, 'dns': [item(str(i), 'example.test', 'NS') for i in range(identity.MAX_DNS + 1)]}, resolver=FakeResolver({}))
        with self.assertRaises(ValueError):
            identity.run_batch({'scope': SCOPE, 'certs': [{'id': str(i), 'host': '93.184.215.14', 'port': 443} for i in range(identity.MAX_CERTS + 1)]})


class CertTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def der(cn='www.example.test', sans=('www.example.test', 'api.example.test')):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
                   .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)))
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def run_certs(self, certs, handshake):
        return identity.run_batch({'scope': SCOPE, 'certs': certs}, handshake=handshake)

    def test_the_names_are_the_common_name_then_the_subject_alternative_names(self):
        seen = []

        def handshake(host, port, addresses, policy, context):
            seen.append((host, port, addresses))
            return self.der()
        got = self.run_certs([{'id': 'c', 'host': '93.184.215.14', 'port': 443}], handshake)
        self.assertEqual(got['certs'], [{'id': 'c', 'status': 'ok', 'names': ['www.example.test', 'www.example.test', 'api.example.test']}])
        self.assertEqual(seen, [('93.184.215.14', 443, ((2, ('93.184.215.14', 443)),))])

    def test_a_certificate_that_could_not_be_read_is_unknown_not_empty(self):
        def handshake(host, port, addresses, policy, context):
            raise OSError('refused')
        got = self.run_certs([{'id': 'c', 'host': '93.184.215.14', 'port': 443}], handshake)
        self.assertEqual(got['certs'], [{'id': 'c', 'status': 'unknown', 'names': []}])

    def test_an_endpoint_the_policy_refuses_is_never_connected_to(self):
        called = []
        got = self.run_certs([{'id': 'c', 'host': '203.0.113.9', 'port': 443}, {'id': 'd', 'host': '127.0.0.1', 'port': 443}],
                             lambda *a: called.append(a))
        self.assertEqual(called, [])
        self.assertEqual([c['status'] for c in got['certs']], ['unknown', 'unknown'])
        self.assertEqual(got['refused'], ['203.0.113.9', '127.0.0.1'])

    def test_a_name_is_resolved_through_the_policy_checked_transport(self):
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=((2, ('93.184.215.14', 443)),)) as resolve:
            got = self.run_certs([{'id': 'c', 'host': 'www.example.test', 'port': 443}], lambda *a: self.der(sans=()))
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(got['certs'][0]['names'], ['www.example.test'])

    def test_a_malformed_endpoint_fails_the_task(self):
        for bad in ({'id': 'c', 'host': '93.184.215.14', 'port': 0}, {'id': 'c', 'host': '93.184.215.14', 'port': True}, {'id': 'c', 'port': 443}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                identity.run_batch({'scope': SCOPE, 'certs': [bad]})


if __name__ == '__main__':
    unittest.main()
