"""The network helpers of the email review, ported from the tests cvENGINE's server kept for its own copies of them (web/tests/test_hygiene_mail.py,
test_hygiene_ratings.py) before those copies were deleted: the MTA-STS policy fetch, one resolver's TXT answer, the confirming resolvers and the DMARC policy the
review reads. Nothing here opens a socket."""
import gzip
import io
import ssl
import unittest
import zlib
from unittest import mock

import dns.exception
import dns.resolver

from cvengine_scanner.probes import hygiene as hy
from cvengine_scanner.probes import mailfail as mf
from cvengine_scanner.probes.policy import ScopePolicy

ADDRS = ((2, ('203.0.113.10', 443)),)
POLICY = ScopePolicy({'hosts': ['mta-sts.acme.example']}, internal=False)
TEXT = b'version: STSv1\nmode: enforce\nmx: mail.acme.example\nmax_age: 86400\n'


class FakeResponse:
    def __init__(self, body, encoding=None, status=200):
        self.stream, self.encoding, self.status = io.BytesIO(body), encoding, status

    def getheader(self, name, default=None):
        return self.encoding if name.lower() == 'content-encoding' and self.encoding is not None else default

    def read(self, amt=None):
        return self.stream.read(amt)


def conn(body=b'', status=200, encoding=None):
    connection = mock.Mock()
    connection.getresponse.return_value = FakeResponse(body, encoding, status)
    return connection


class MtaStsFetchTests(unittest.TestCase):
    def fetch(self, connection, resolve=None):
        with mock.patch('cvengine_scanner.probes.transport.resolve', **({'return_value': ADDRS} if resolve is None else {'side_effect': resolve})) as resolver, \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection', return_value=connection) as factory:
            return mf.fetch_mta_sts_policy('acme.example', POLICY), resolver, factory

    def test_a_host_resolving_to_a_blocked_address_is_never_fetched(self):
        got, _resolver, factory = self.fetch(conn(), resolve=ValueError('blocked'))
        self.assertIsNone(got)
        factory.assert_not_called()

    def test_fetch_is_the_well_known_path_on_the_admitted_addresses_verified_and_bounded(self):
        got, resolver, factory = self.fetch(conn(TEXT))
        self.assertIn('mode: enforce', got)
        resolver.assert_called_once_with('mta-sts.acme.example', 443, POLICY)
        args, kwargs = factory.call_args
        self.assertEqual(args[:3], ('mta-sts.acme.example', 443, ADDRS))
        self.assertEqual(kwargs['context'].verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(factory.return_value.request.call_args.args[:2], ('GET', '/.well-known/mta-sts.txt'))
        self.assertIsNone(self.fetch(conn(status=302))[0])  # redirects are not followed
        self.assertIsNone(self.fetch(conn(b'x' * (mf.MAX_POLICY_BYTES + 1)))[0])

    def test_a_policy_a_server_sends_compressed_despite_identity_is_read(self):
        for body, encoding in ((gzip.compress(TEXT), 'gzip'), (zlib.compress(TEXT), 'deflate')):
            text = self.fetch(conn(body, encoding=encoding))[0]
            self.assertIn('mode: enforce', text or '', encoding)
            self.assertEqual(mf.parse_mta_sts_mode(text), 'enforce')

    def test_a_compressed_policy_past_the_cap_or_in_an_unreadable_encoding_is_no_policy(self):
        self.assertIsNone(self.fetch(conn(gzip.compress(b'x' * 10_000_000, compresslevel=9), encoding='gzip'))[0])  # a bomb stops at the cap
        self.assertIsNone(self.fetch(conn(b'garbage', encoding='gzip'))[0])
        self.assertIsNone(self.fetch(conn(TEXT, encoding='br'))[0])


class Rdata:
    def __init__(self, text):
        self.strings = [text.encode()]


class Answer(list):
    canonical_name = 'mail1.example.net.'


class Resolver:
    def __init__(self, outcome):
        self.outcome = outcome

    def resolve(self, name, rtype):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class ResolverTests(unittest.TestCase):
    def test_ask_txt_classifies_answers_and_follows_a_cname(self):
        got = hy.ask_txt(Resolver(Answer([Rdata('v=spf1 include:_spf.example.net ~all')])), 'help.example.com')
        self.assertEqual(got, {'result': 'answer', 'records': ['v=spf1 include:_spf.example.net ~all'], 'cname': 'mail1.example.net'})
        self.assertEqual(hy.ask_txt(Resolver(dns.resolver.NXDOMAIN()), 'x.example.com')['result'], 'nxdomain')
        self.assertEqual(hy.ask_txt(Resolver(dns.resolver.NoAnswer()), 'x.example.com')['result'], 'noanswer')
        self.assertEqual(hy.ask_txt(Resolver(dns.exception.Timeout()), 'x.example.com')['result'], 'error')
        self.assertEqual(hy.ask_txt(Resolver(dns.resolver.NoNameservers()), 'x.example.com')['result'], 'error')

    def test_by_default_only_the_system_resolver_is_asked_and_the_confirming_resolvers_are_the_tasks(self):
        with mock.patch.object(hy, '_resolver', return_value=Resolver(Answer())), \
                mock.patch('dns.resolver.Resolver', side_effect=AssertionError('no extra resolver may be built')):
            self.assertEqual([label for label, _ in hy.dns_askers()], ['system'])
        built = []

        def build(configure=True):
            built.append(Resolver(Answer()))
            built[-1].nameservers = []
            return built[-1]
        with mock.patch.object(hy, '_resolver', return_value=Resolver(Answer())), mock.patch('dns.resolver.Resolver', side_effect=build):
            self.assertEqual([label for label, _ in hy.dns_askers(['192.0.2.53', '198.51.100.53'])], ['system', '192.0.2.53', '198.51.100.53'])
        self.assertEqual(built[0].nameservers, ['192.0.2.53'])


class ReviewPolicyTests(unittest.TestCase):
    def test_review_reads_the_dmarc_policy_from_the_record(self):
        found = mf.review('example.com', True, [], ['v=DMARC1; p=reject; rua=mailto:d@reports.example.net'], {}, lambda n: [], lambda n, t: [])
        self.assertEqual([f.severity for f in found if f.check == 'dmarc_report_unauthorized'], [hy.INFO])
