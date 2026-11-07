"""The route_probe_signed kind (``probes.routes_signed``): where a stored sign-in may be sent, what is asked and kept, and that no value of it comes back."""
import json
import ssl
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner.probes import http, routes_signed
from cvengine_scanner.probes.policy import ScopePolicy
from cvengine_scanner.probes.routes_signed import SignIn, SignInError

WWW = 'www.example.test'
SCOPE = {'hosts': [WWW, 'api.example.test', 'other.example.test'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}
CANARY = 'CANARY-7c41d9e2b8-do-not-leak'


def credential(**kw):
    doc = {'headers': [['Authorization', f'Bearer {CANARY}']], 'cookie': f'sid={CANARY}-cookie; theme=dark', 'target': 'example.test', 'host': WWW,
           'origins': ['https:443'], 'host_scoped': False, 'allow_untrusted_certificate': False, 'expires_at': None}
    doc.update(kw)
    return doc


def answer(url, status=200, **kw):
    return {'url': url, 'status': status, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html', 'body': '', 'title': '',
            'bytes': len(kw.get('body', '')), **kw}


def task(*groups):
    return {'hosts': [{'host': h, 'urls': list(urls)} for h, urls in groups], 'scope': SCOPE}


class SignInRuleTests(unittest.TestCase):
    def applies(self, doc, host, scheme='https', port=443):
        return SignIn.parse(doc).applies(host, scheme, port)

    def test_a_host_specific_sign_in_goes_to_that_host_scheme_and_port_only(self):
        doc = credential()
        self.assertTrue(self.applies(doc, WWW))
        self.assertTrue(self.applies(doc, 'WWW.example.test.'))
        for host, scheme, port in (('example.test', 'https', 443), ('a.www.example.test', 'https', 443), ('evil-www.example.test', 'https', 443),
                                   ('www.example.test.evil.test', 'https', 443), (WWW, 'http', 443), (WWW, 'https', 8443), (WWW, 'http', 80),
                                   ('203.0.113.7', 'https', 443), ('', 'https', 443), (WWW, 'ftp', 443)):
            self.assertFalse(self.applies(doc, host, scheme, port), (host, scheme, port))

    def test_a_target_wide_sign_in_covers_the_target_and_its_subdomains_unless_the_target_is_host_only(self):
        doc = credential(host='', origins=['https:443', 'http:8080'])
        for host in ('example.test', 'api.example.test', 'a.b.example.test'):
            self.assertTrue(self.applies(doc, host), host)
        self.assertTrue(self.applies(doc, 'api.example.test', 'http', 8080))
        for host in ('example.test.evil.test', 'badexample.test', 'other.test'):
            self.assertFalse(self.applies(doc, host), host)
        self.assertFalse(self.applies({**doc, 'host_scoped': True}, 'api.example.test'))
        self.assertTrue(self.applies({**doc, 'host_scoped': True}, 'example.test'))
        missing = {k: v for k, v in doc.items() if k != 'host_scoped'}
        self.assertFalse(self.applies(missing, 'api.example.test'))  # unknown reads as host-only: the strict rule

    def test_an_address_target_has_no_subdomains(self):
        doc = credential(host='', target='203.0.113.7')
        self.assertTrue(self.applies(doc, '203.0.113.7'))
        self.assertFalse(self.applies(doc, 'x.203.0.113.7'))

    def test_an_expired_sign_in_or_one_with_an_unreadable_expiry_goes_nowhere(self):
        self.assertFalse(self.applies(credential(expires_at='2020-01-01T00:00:00+00:00'), WWW))
        self.assertFalse(self.applies(credential(expires_at='2020-01-01T00:00:00Z'), WWW))
        self.assertTrue(self.applies(credential(expires_at='2999-01-01T00:00:00+00:00'), WWW))
        with self.assertRaises(SignInError):
            SignIn.parse(credential(expires_at='tomorrow-ish'))

    def test_a_malformed_sign_in_is_refused_without_naming_a_value(self):
        bad = [credential(headers=[['Host', 'evil.example.test']]), credential(headers=[['Content-Length', '5']]), credential(headers=[['X A', 'value-one']]),
               credential(headers=[['Authorization', f'Bearer {CANARY}\r\nX-Evil: 1']]), credential(headers=[['Authorization', '']]),
               credential(headers=[], cookie=''), credential(cookie=f'sid={CANARY}\nx=1'), credential(origins='https:443'), credential(host='', target=''),
               credential(headers=[[f'X-{i}', 'value-xx'] for i in range(13)])]
        for doc in bad:
            with self.assertRaises(SignInError) as caught:
                SignIn.parse(doc)
            self.assertNotIn(CANARY, str(caught.exception))
            self.assertNotIn('evil.example.test', str(caught.exception))


class RunBatchTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.asked = []

    def net(self, pages=None):
        pages = pages or {}

        def probe(url, policy, max_bytes=http.ROUTE_SAMPLE_BYTES, signed=None, verify=True, **kw):
            authority = url.split('://', 1)[1].split('/', 1)[0]
            policy.check_host(authority.split(':')[0])
            policy.touch(authority)
            self.asked.append({'url': url, 'signed': list(signed or []), 'verify': verify, 'max_bytes': max_bytes})
            got = pages.get(url)
            if isinstance(got, Exception):
                raise got
            return answer(url, **(got if got is not None else {'status': 404, 'title': 'Not found'}))
        return probe

    def run_batch(self, target, doc=None, pages=None):
        return routes_signed.run_batch(target, SignIn.parse(doc or credential()), probe=self.net(pages), sleep=lambda s: None)

    def test_a_covered_route_is_asked_with_the_sign_in_once_and_classified(self):
        pages = {f'https://{WWW}/': {'title': 'Dashboard', 'body': '<h1>Hi</h1>'}, f'https://{WWW}/account': {'status': 302, 'location': '/login'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/account'])), pages=pages)
        self.assertEqual([(a['url'], a['verify']) for a in self.asked], [(f'https://{WWW}/', True), (f'https://{WWW}/account', True)])
        self.assertIn(('Authorization', f'Bearer {CANARY}'), self.asked[0]['signed'])
        self.assertEqual(self.asked[0]['max_bytes'], http.MAX_READ_BYTES)  # the front page is read as far as the anonymous check reads it
        rows = {r['id']: r for r in got['routes']}
        self.assertEqual((rows[f'https://{WWW}/']['state'], rows[f'https://{WWW}/']['title']), ('open', 'Dashboard'))
        self.assertEqual((rows[f'https://{WWW}/account']['state'], rows[f'https://{WWW}/account']['evidence']['redirect_to']), ('session_required', '/login'))
        self.assertEqual(got['touched'], [WWW])

    def test_the_result_has_the_shape_of_route_probe_and_validates_against_the_contract(self):
        pages = {f'https://{WWW}/': {'title': 'Dashboard', 'body': '<input type="password">'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/'])), pages=pages)
        doc = {'outcome': 'done', **got}
        self.assertEqual(Draft202012Validator(contract.result_schema('route_probe_signed')).validate(doc), None)
        row = got['routes'][0]
        self.assertEqual((row['sensitive'], row['sensitive_score'], row['credentials']), ({}, 0, []))
        self.assertEqual(set(row['evidence']), {'markers', 'bytes', 'provider', 'redirect_to'})  # no fingerprints, scripts, headers or cookie names
        self.assertEqual({'id', 'status', 'title', 'content_type', 'state', 'evidence', 'sensitive', 'sensitive_score', 'bytes', 'credentials'}, set(row))

    def test_a_body_is_never_searched_for_sensitive_data_or_credentials(self):
        body = 'AKIA' + '0' * 16 + ' user@example.test eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop'
        got = self.run_batch(task((WWW, [f'https://{WWW}/'])), pages={f'https://{WWW}/': {'body': body, 'content_type': 'text/html'}})
        row = got['routes'][0]
        self.assertEqual((row['sensitive'], row['credentials']), ({}, []))
        self.assertNotIn('AKIA', json.dumps(got))

    def test_a_route_the_sign_in_does_not_cover_is_never_asked(self):
        doc = credential(origins=['https:443'])
        urls = [f'https://{WWW}/', f'http://{WWW}/', f'https://{WWW}:8443/', 'https://other.example.test/']
        got = self.run_batch(task((WWW, urls[:3]), ('other.example.test', urls[3:])), doc)
        self.assertEqual([a['url'] for a in self.asked], [f'https://{WWW}/'])
        errors = {r['id']: r['error'] for r in got['routes'] if 'error' in r}
        self.assertEqual(set(errors), set(urls[1:]))
        self.assertTrue(all('does not cover this route' in e for e in errors.values()))
        self.assertTrue(all('state' not in r for r in got['routes'] if 'error' in r))

    def test_a_host_the_scope_policy_refuses_is_never_asked(self):
        target = task((WWW, [f'https://{WWW}/']))
        target['scope'] = {**SCOPE, 'hosts': ['api.example.test'], 'excluded': []}
        got = routes_signed.run_batch(target, SignIn.parse(credential()), probe=self.net(), sleep=lambda s: None)
        self.assertEqual(self.asked, [])
        self.assertIn('outside the scope policy', got['routes'][0]['error'])
        self.assertEqual(got['refused'], [WWW])

    def test_a_redirect_is_reported_and_never_followed(self):
        pages = {f'https://{WWW}/go': {'status': 302, 'location': 'https://evil.example.org/steal'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/go'])), pages=pages)
        self.assertEqual([a['url'] for a in self.asked], [f'https://{WWW}/go'])  # the other host was never asked, with or without the sign-in
        self.assertEqual((got['routes'][0]['state'], got['routes'][0]['evidence']['redirect_to']), ('redirect', 'https://evil.example.org/steal'))
        self.assertEqual(got['touched'], [WWW])

    def test_the_owners_switch_turns_certificate_verification_off_for_that_sign_in_only(self):
        self.run_batch(task((WWW, [f'https://{WWW}/'])), credential(allow_untrusted_certificate=True))
        self.assertIs(self.asked[0]['verify'], False)

    def test_a_certificate_that_does_not_verify_is_said_and_nothing_is_sent(self):
        got = self.run_batch(task((WWW, [f'https://{WWW}/'])), pages={f'https://{WWW}/': http.UntrustedCertificate(http.UNTRUSTED_CERTIFICATE)})
        self.assertEqual(got['routes'], [{'id': f'https://{WWW}/', 'error': http.UNTRUSTED_CERTIFICATE}])

    def test_a_route_that_could_not_be_asked_has_an_error_and_no_state(self):
        got = self.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/b'])), pages={f'https://{WWW}/': TimeoutError('slow')})
        rows = {r['id']: r for r in got['routes']}
        self.assertEqual(rows[f'https://{WWW}/']['error'], 'TimeoutError: slow')
        self.assertNotIn('state', rows[f'https://{WWW}/'])
        self.assertEqual(rows[f'https://{WWW}/b']['state'], 'not_found')

    def test_the_time_budget_leaves_the_rest_unasked(self):
        ticks = iter([0, 0, 10 ** 6, 10 ** 6, 10 ** 6])
        got = routes_signed.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/b'])), SignIn.parse(credential()), probe=self.net(), sleep=lambda s: None,
                                      clock=lambda: next(ticks))
        self.assertEqual([a['url'] for a in self.asked], [f'https://{WWW}/'])
        self.assertIn('ran out of time', got['routes'][1]['error'])

    def test_a_malformed_task_is_refused(self):
        for bad in ({'hosts': [], 'scope': SCOPE}, {'hosts': [{'host': WWW, 'urls': ['https://other.example.test/']}], 'scope': SCOPE}):
            with self.assertRaises(ValueError):
                routes_signed.run_batch(bad, SignIn.parse(credential()), probe=self.net())


class ProbeUrlTests(unittest.TestCase):
    """``http.probe_url`` with a sign-in: the certificate is verified before anything is sent, and an anonymous probe is unchanged."""

    def probe(self, signed=None, verify=True, connect_error=None, scheme='https'):
        response = mock.Mock(status=200)
        response.headers = __import__('email.message', fromlist=['Message']).Message()
        response.getheader.side_effect = lambda name, default=None: response.headers.get(name, default)
        connection = mock.Mock()
        connection.getresponse.return_value = response
        connection.connect.side_effect = connect_error
        policy = ScopePolicy(SCOPE)
        with mock.patch('cvengine_scanner.probes.transport.resolve', return_value=((2, ('203.0.113.10', 443)),)), \
                mock.patch('cvengine_scanner.probes.transport.read_body', return_value=b'<title>In</title>'), \
                mock.patch('cvengine_scanner.probes.transport.HTTPConnection', return_value=connection) as factory:
            try:
                got = http.probe_url(f'{scheme}://{WWW}/a', policy, signed=signed, verify=verify, headers={'Host': WWW} if signed is None else None)
                error = None
            except ValueError as exc:
                got, error = None, exc
        return factory.call_args.kwargs['context'], connection, error, got

    def test_a_signed_request_verifies_the_certificate_and_carries_the_headers(self):
        context, connection, error, got = self.probe(signed=[('Authorization', 'Bearer x'), ('Cookie', 'sid=1')])
        self.assertIsNone(error)
        self.assertEqual((context.verify_mode, context.check_hostname), (ssl.CERT_REQUIRED, True))
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual((headers['Authorization'], headers['Cookie']), ('Bearer x', 'sid=1'))
        self.assertEqual(got['status'], 200)

    def test_a_sign_in_replaces_a_header_of_the_same_name_whatever_its_case(self):
        _, connection, _, _ = self.probe(signed=[('user-agent', 'mine'), ('ACCEPT', 'x/y')])
        headers = connection.request.call_args.kwargs['headers']
        self.assertEqual({k: v for k, v in headers.items() if k.lower() in ('user-agent', 'accept')}, {'user-agent': 'mine', 'ACCEPT': 'x/y'})

    def test_an_untrusted_certificate_stops_the_signed_request_before_anything_is_sent(self):
        _, connection, error, _ = self.probe(signed=[('Authorization', 'Bearer x')], connect_error=ssl.SSLCertVerificationError('bad'))
        self.assertIsInstance(error, http.UntrustedCertificate)
        self.assertEqual(str(error), http.UNTRUSTED_CERTIFICATE)
        connection.request.assert_not_called()

    def test_the_owners_switch_sends_it_over_a_certificate_that_does_not_verify(self):
        context, _, error, _ = self.probe(signed=[('Authorization', 'Bearer x')], verify=False)
        self.assertIsNone(error)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)

    def test_an_anonymous_probe_still_never_verifies_and_sends_no_credential(self):
        context, connection, _, _ = self.probe()
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertNotIn('Authorization', connection.request.call_args.kwargs['headers'])
        with self.assertRaises(ValueError):
            http.probe_url(f'https://{WWW}/', ScopePolicy(SCOPE), headers={'Authorization': 'x'})  # the anonymous header rule is unchanged


if __name__ == '__main__':
    unittest.main()
