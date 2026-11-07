"""The hygiene_check kind (``probes.hygiene.run_batch``): TLS endpoints and mail names under the task's scope policy, and what is reported when a
probe is refused or fails (unknown, never "nothing there")."""
import datetime
import unittest
from unittest import mock

from cvengine_scanner.probes import hygiene as hy
from cvengine_scanner.probes.policy import ScopePolicy

SCOPE = {'hosts': ['www.example.com', 'mail.example.com', 'blocked.example.com'], 'domains': [], 'excluded': ['blocked.example.com'], 'excluded_trees': [],
         'private': False, 'addresses': [], 'blocked': []}
UTC = datetime.timezone.utc
INFO = {'host': 'www.example.com', 'port': 443, 'subject': 'www.example.com', 'issuer': 'Example CA', 'sans': ['www.example.com'],
        'not_before': datetime.datetime(2026, 1, 1, tzinfo=UTC), 'not_after': datetime.datetime(2026, 4, 1, tzinfo=UTC),
        'signature_algorithm': 'sha256 (sha256WithRSAEncryption)', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'cipher': 'X',
        'chain_error': '', 'legacy_tls': False}


def task(**over):
    return {'tls': [{'host': 'www.example.com', 'port': 443}], 'mail': [{'name': 'example.com', 'always': True}], 'scope': SCOPE, **over}


def finding(check='spf_missing', **evidence):
    return hy.Finding(check, hy.MEDIUM, 'No SPF record', 'why', 'example.com', evidence)


class RunBatchTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_batch(self, target, **kw):
        kw.setdefault('probe', lambda host, port, policy: dict(INFO, host=host, port=port))
        kw.setdefault('emailer', lambda name, **opts: ([finding()], True))
        kw.setdefault('mx', lambda name: True)
        kw.setdefault('cname', lambda name: False)
        return hy.run_batch(target, **kw)

    def test_a_certificate_comes_back_with_dates_as_text_and_a_mail_domain_with_its_findings(self):
        got = self.run_batch(task())
        self.assertEqual(got['certs'][0]['cert']['not_after'], '2026-04-01T00:00:00+00:00')
        self.assertEqual((got['certs'][0]['host'], got['certs'][0]['port'], got['certs'][0]['found']), ('www.example.com', 443, True))
        self.assertEqual(got['mail'], [{'name': 'example.com', 'has_mx': True, 'findings': [
            {'check': 'spf_missing', 'severity': hy.MEDIUM, 'title': 'No SPF record', 'detail': 'why', 'host': 'example.com', 'evidence': {}}]}])

    def test_nothing_speaking_tls_is_found_false_and_not_an_error(self):
        got = self.run_batch(task(), probe=lambda host, port, policy: None)
        self.assertEqual(got['certs'], [{'host': 'www.example.com', 'port': 443, 'found': False}])

    def test_an_endpoint_the_policy_refuses_is_not_probed_and_says_so(self):
        asked = []

        def probe(host, port, policy):
            asked.append(host)
            return hy.probe_tls(host, port, policy)
        target = task(tls=[{'host': 'blocked.example.com', 'port': 443}, {'host': 'other.example.com', 'port': 443}])
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('never resolved')):
            got = self.run_batch(target, probe=probe)
        self.assertEqual(sorted(c['host'] for c in got['certs']), ['blocked.example.com', 'other.example.com'])
        for row in got['certs']:
            self.assertFalse(row['found'])
            self.assertTrue(row['error'].startswith('not run:'), row)
        self.assertEqual(sorted(got['refused']), ['blocked.example.com', 'other.example.com'])

    def test_a_probe_that_fails_is_unknown_with_the_reason_class_only(self):
        def boom(host, port, policy):
            raise RuntimeError('secret detail')
        row = self.run_batch(task(), probe=boom)['certs'][0]
        self.assertEqual((row['found'], row['error']), (False, 'probe failed: RuntimeError'))

    def test_only_a_name_with_its_own_mx_that_is_not_a_cname_is_reviewed_unless_it_is_always(self):
        mail = [{'name': 'example.com', 'always': True}, {'name': 'mail.example.com'}, {'name': 'www.example.com'}, {'name': 'cname.example.com'},
                {'name': 'quiet.example.com'}]
        reviewed = []

        def emailer(name, **opts):
            reviewed.append(name)
            return [], True
        got = self.run_batch(task(mail=mail), emailer=emailer, mx=lambda name: name != 'quiet.example.com',
                             cname=lambda name: name in ('www.example.com', 'cname.example.com'))
        self.assertEqual(sorted(reviewed), ['example.com', 'mail.example.com'])
        self.assertEqual(sorted(r['name'] for r in got['mail']), ['example.com', 'mail.example.com'])

    def test_a_review_that_fails_is_left_out_so_the_server_reads_it_as_unknown(self):
        def emailer(name, **opts):
            if name == 'example.com':
                raise RuntimeError('boom')
            return [], False
        got = self.run_batch(task(mail=[{'name': 'example.com', 'always': True}, {'name': 'mail.example.com', 'always': True}]), emailer=emailer)
        self.assertEqual([r['name'] for r in got['mail']], ['mail.example.com'])

    def test_the_task_carries_the_resolvers_and_the_registry_switch_to_every_review(self):
        seen = []

        def emailer(name, scope=None, confirm=(), rdap=True):
            seen.append((confirm, rdap, scope is not None))
            return [], True
        self.run_batch(task(confirm_resolvers=['192.0.2.53'], rdap=False), emailer=emailer)
        self.assertEqual(seen, [(['192.0.2.53'], False, True)])

    def test_email_findings_hands_the_scope_policy_to_the_mailfail_checks(self):
        policy = ScopePolicy(SCOPE)
        with mock.patch('cvengine_scanner.probes.mailfail.review', return_value=[]) as review:
            hy.email_findings('example.com', fetch=lambda n: [], mx=lambda n, t: False, scope=policy, rdap=False)
        self.assertIs(review.call_args.kwargs['scope'], policy)
        self.assertIs(review.call_args.kwargs['rdap_on'], False)

    def test_a_malformed_task_is_refused(self):
        for bad in (task(tls=[{'host': 'x', 'port': 0}]), task(tls=[{'port': 443}]), task(mail=[{'name': ''}]), task(tls=[{'host': 'a.example.com', 'port': 443}] * 301)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.run_batch(bad)

    def test_a_finding_is_clipped_and_its_evidence_reduced_to_json(self):
        doc = hy.finding_doc(hy.Finding('x' * 100, hy.HIGH, 't' * 400, 'd' * 3000, 'h' * 400, {'when': datetime.date(2026, 1, 1), 'list': (1, 2)}))
        self.assertEqual((len(doc['check']), len(doc['title']), len(doc['detail']), len(doc['host'])), (64, 300, 2000, 300))
        self.assertEqual(doc['evidence'], {'when': '2026-01-01', 'list': [1, 2]})


class ProbeTlsTests(unittest.TestCase):
    ADDRS = ((2, ('203.0.113.10', 443)),)

    def policy(self):
        return ScopePolicy({'hosts': ['asset.example.com']})

    def test_all_tls_attempts_share_one_admitted_address_set(self):
        policy = self.policy()
        with mock.patch.object(hy.transport, 'resolve', return_value=self.ADDRS) as resolve, \
                mock.patch.object(hy, '_fetch_cert', return_value={'host': 'asset.example.com'}) as fetch, \
                mock.patch.object(hy, '_chain_error', return_value='') as chain, \
                mock.patch.object(hy, '_accepts_legacy_tls', return_value=False) as legacy:
            self.assertIsNotNone(hy.probe_tls('asset.example.com', 443, policy))
        resolve.assert_called_once_with('asset.example.com', 443, policy)
        for probe in (fetch, chain, legacy):
            probe.assert_called_once_with('asset.example.com', 443, policy, addresses=self.ADDRS)

    def test_a_server_that_only_speaks_tls_1_0_is_read_with_the_legacy_client(self):
        calls = []

        def fetch(host, port, policy, legacy=False, addresses=None):
            calls.append(legacy)
            return None if not legacy else {'host': host, 'port': port, 'protocol': 'TLSv1', 'cipher': 'AES128-SHA'}
        with mock.patch.object(hy.transport, 'resolve', return_value=self.ADDRS), mock.patch.object(hy, '_fetch_cert', fetch):
            info = hy.probe_tls('asset.example.com', 443, self.policy())
        self.assertEqual(calls, [False, True])
        self.assertTrue(info['legacy_tls'])
        self.assertEqual(info['legacy_handshake'], {'protocol': 'TLSv1', 'cipher': 'AES128-SHA'})
        self.assertIn('only speaks TLS 1.0', info['chain_error'])

    def test_a_name_the_policy_refuses_is_never_resolved(self):
        with mock.patch('socket.getaddrinfo', side_effect=AssertionError('resolved')):
            with self.assertRaises(ValueError):
                hy.probe_tls('elsewhere.example.com', 443, self.policy())

    def test_a_name_that_does_not_resolve_is_nothing_there(self):
        with mock.patch.object(hy.transport, 'resolve', side_effect=OSError('no such host')):
            self.assertIsNone(hy.probe_tls('asset.example.com', 443, self.policy()))


if __name__ == '__main__':
    unittest.main()
