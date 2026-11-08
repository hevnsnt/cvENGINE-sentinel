"""The route_probe kind (``probes.routes``): the classification cvENGINE's route check makes, the soft 404 comparison, the front page's scripts, and a
task end to end under a scope policy with the network replaced."""
import json
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner.probes import http, routes, sensitive
from cvengine_scanner.probes.policy import ScopePolicy

TABLE = json.loads((Path(__file__).parent.parent / 'fixtures' / 'route_classify.json').read_text(encoding='utf-8'))
WWW = 'www.example.test'
SCOPE = {'hosts': [WWW, 'api.example.test', 'cdnjs.cloudflare.com'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False,
         'addresses': [], 'blocked': []}
AWS_KEY = 'AKIA' + '0' * 16


def answer(url, status=200, **kw):
    return {'url': url, 'status': status, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html', 'body': '', 'title': '',
            'bytes': len(kw.get('body', '')), **kw}


class ClassifyTableTests(unittest.TestCase):
    """The table ``tests/fixtures/route_classify.json`` is the one cvENGINE's own ``route_auth.classify`` is held to (the same file there)."""

    def test_every_case_of_the_shared_table(self):
        self.assertGreater(len(TABLE['cases']), 20)
        for case in TABLE['cases']:
            with self.subTest(case['name']):
                state, evidence = routes.classify(case['probe'])
                expect = case['expect']
                self.assertEqual((state, evidence['provider'], evidence['redirect_to'], evidence['markers']),
                                 (expect['state'], expect['provider'], expect['redirect_to'], expect['markers']))

    def test_the_evidence_carries_markers_bytes_and_cookie_names_never_the_body(self):
        _, evidence = routes.classify(answer('https://www.example.test/x', body='<input type="password">' + 'x' * 100, cookies=['sid', 'csrf'], bytes=123))
        self.assertEqual((evidence['markers'], evidence['bytes'], evidence['cookies']), (['password_input'], 123, ['csrf', 'sid']))
        self.assertNotIn('xxxx', json.dumps(evidence))

    def test_server_and_powered_by_headers_are_kept_clipped(self):
        _, evidence = routes.classify(answer('https://www.example.test/x', server='s' * 300, powered_by='PHP/8.2'))
        self.assertEqual((len(evidence['server']), evidence['powered_by']), (100, 'PHP/8.2'))


class PureReadersTests(unittest.TestCase):
    def test_sso_provider_by_host_and_a_path_only_where_the_host_needs_one(self):
        self.assertEqual(routes.sso_provider('https://tenant.b2clogin.com/x'), 'Entra ID')
        self.assertEqual(routes.sso_provider('/auth', 'https://login.salesforce.com/'), 'Salesforce')
        self.assertEqual(routes.sso_provider('https://github.com/login/oauth/authorize'), 'GitHub')
        self.assertEqual(routes.sso_provider('https://github.com/x'), '')
        self.assertEqual(routes.sso_provider('https://notokta.com/'), '')

    def test_a_login_path_is_a_session_requirement_and_an_sso_path_is_sso(self):
        self.assertEqual(routes._redirect_state('/session/new', 'https://a.example.test/'), ('session_required', ''))
        self.assertEqual(routes._redirect_state('/auth/realms/x/protocol', 'https://a.example.test/'), ('sso', ''))
        self.assertEqual(routes._redirect_state('/home', 'https://a.example.test/'), ('redirect', ''))

    def test_page_title(self):
        self.assertEqual(routes.page_title('<html><TITLE>\n  Hello   World </title>'), 'Hello World')
        self.assertEqual(routes.page_title('<titles>x</titles>'), '')
        self.assertEqual(routes.page_title('<title' * 20000), '')

    def test_hostile_bodies_are_read_in_linear_time(self):
        import time
        started = time.monotonic()
        for body in ('<input ' * 9000, '<meta ' * 9000, '<title' * 9000):
            routes.classify(answer('https://www.example.test/x', body=body))
        self.assertLess(time.monotonic() - started, 3.0)

    def test_truncated_reads_the_flag_then_the_size(self):
        self.assertTrue(routes._truncated({'truncated': True}))
        self.assertFalse(routes._truncated({'truncated': False, 'bytes': 10 ** 9}))
        self.assertTrue(routes._truncated({'bytes': routes.ROUTE_SAMPLE_BYTES}))
        self.assertFalse(routes._truncated({'body': 'short'}))

    def test_a_stub_front_page(self):
        self.assertTrue(routes._stub_page('<meta http-equiv="refresh" content="0; url=/x">', '', [{'url': 'a.js'}]))
        self.assertTrue(routes._stub_page('<p>hi</p>', 'Under construction', [{'url': 'a.js'}]))
        self.assertTrue(routes._stub_page('<p>hi</p>', 'Home', []))
        self.assertTrue(routes._stub_page('<script>window.location = "/x"</script>', 'Home', [{'url': 'a.js'}]))
        self.assertFalse(routes._stub_page('<p>hi</p>', 'Home', [{'url': 'a.js'}]))

    def test_script_urls_keeps_own_host_scripts_without_query_strings(self):
        entries = [{'url': 'https://www.example.test/a.js?v=1'}, {'url': 'https://cdn.example.net/b.js'}, {'url': 'http://www.example.test/c.js'},
                   {'url': 'https://www.example.test/a.js'}, {'url': ''}, 7]
        self.assertEqual(routes.script_urls(entries, 'https://www.example.test/'), ['https://www.example.test/a.js'])
        self.assertEqual(routes.script_urls(['/x.js'], 'https://www.example.test/'), ['https://www.example.test/x.js'])
        many = [{'url': f'https://www.example.test/{i}.js'} for i in range(20)]
        self.assertEqual(len(routes.script_urls(many, 'https://www.example.test/')), routes.MAX_SCRIPT_URLS)


class AnalyseTests(unittest.TestCase):
    def test_sensitive_data_is_counted_masked_and_a_credential_is_returned_as_its_value(self):
        body = json.dumps({'key': AWS_KEY, 'mail': 'alice.smith@acme-corp.io'})
        got = routes.analyse(answer('https://api.example.test/x', content_type='application/json', body=body))
        self.assertEqual(got['sensitive_score'], 25)
        self.assertEqual(got['sensitive']['aws_key']['count'], 1)
        self.assertNotIn(AWS_KEY, json.dumps(got['sensitive']) + json.dumps(got['evidence']))
        self.assertEqual(got['credentials'], [('aws_key', AWS_KEY)])

    def test_a_body_that_is_not_text_is_not_scanned(self):
        got = routes.analyse(answer('https://www.example.test/x', content_type='image/png', body=AWS_KEY))
        self.assertEqual((got['sensitive'], got['credentials'], got['sensitive_score']), ({}, [], 0))

    def test_a_root_page_has_no_fingerprint_and_any_other_route_has_one(self):
        self.assertIsNone(routes.analyse(answer('https://www.example.test/'))['fp'])
        self.assertIsNotNone(routes.analyse(answer('https://www.example.test/admin'))['fp'])

    def test_a_root_page_names_the_libraries_it_hints_at_and_keeps_its_scripts_for_reading(self):
        body = '<html><head><title>Home</title><script src="/static/jquery-3.6.0.min.js"></script></head><body>x</body></html>'
        got = routes.analyse(answer('https://www.example.test/', body=body, title='Home'))
        self.assertIn('jQuery:3.6.0', got['evidence']['fingerprint_names'])
        self.assertEqual(got['evidence']['page_scripts']['page'], 'https://www.example.test/')
        self.assertEqual(got['evidence']['script_page']['stub'], False)

    def test_an_edge_challenge_page_is_not_read_for_scripts(self):
        body = '<html><title>Just a moment...</title><script src="/a.js"></script> cloudflare</html>'
        got = routes.analyse(answer('https://www.example.test/', status=503, body=body, title='Just a moment...'))
        self.assertNotIn('page_scripts', got['evidence'])
        self.assertNotIn('script_page', got['evidence'])


class CatchAllTests(unittest.TestCase):
    SHELL = '<html><head><title>NAS</title></head><body><div id="root"></div></body></html>'

    def compare(self, url, serve):
        asked = []

        def get(u, max_bytes=0, headers=None):
            asked.append(u)
            return serve(u)
        got = routes._against_missing_page(routes.analyse(serve(url)), url, get, {}, sleep=lambda s: None)
        return got, asked

    def test_the_same_answer_for_a_path_that_cannot_exist_is_catch_all(self):
        got, asked = self.compare('https://www.example.test/admin', lambda u: answer(u, body=self.SHELL, title='NAS'))
        self.assertEqual(got['state'], 'catch_all')
        self.assertEqual(got['evidence']['catch_all']['kind'], 'bare')
        self.assertEqual((got['sensitive'], got['credentials']), ({}, []))
        self.assertTrue(any('/cvengine-' in u for u in asked))

    def test_a_route_that_differs_from_the_missing_page_stands(self):
        def serve(u):
            return answer(u, body='<html><title>Admin</title><input type="password"></html>', title='Admin') if u.endswith('/admin') else \
                answer(u, status=404, body='not found')
        got, _ = self.compare('https://www.example.test/admin', serve)
        self.assertEqual(got['state'], 'login')

    def test_the_root_and_a_not_found_are_never_compared(self):
        for url, status in (('https://www.example.test/', 200), ('https://www.example.test/x', 404)):
            got, asked = self.compare(url, lambda u, s=status: answer(u, status=s, body=self.SHELL))
            self.assertEqual(asked, [])
            self.assertNotEqual(got['state'], 'catch_all')

    def test_a_server_that_sends_every_path_to_a_login_redirect_says_nothing(self):
        got, _ = self.compare('https://www.example.test/admin', lambda u: answer(u, status=302, location='/login?next=' + u.split('example.test')[1]))
        self.assertEqual(got['state'], 'catch_all')

    def test_the_baseline_has_the_kind_of_the_route_and_is_asked_once_per_directory(self):
        known = {}
        asked = []

        def get(u, max_bytes=0, headers=None):
            asked.append(u)
            return answer(u, status=404, body='gone')
        for path in ('/a.php', '/b.php', '/dir/'):
            url = 'https://www.example.test' + path
            routes._against_missing_page(routes.analyse(answer(url, body=self.SHELL)), url, get, known, sleep=lambda s: None)
        names = [u.split('example.test', 1)[1] for u in asked]
        self.assertTrue(any(n.endswith('.php') for n in names))
        self.assertTrue(any(n.endswith('/') and '/cvengine-' in n for n in names))
        self.assertEqual(len(asked), len(set(asked)))
        self.assertEqual(len([n for n in names if n.endswith('.php')]), 1)  # the second .php route shares the first's baseline

    def test_the_baselines_a_host_may_ask_for_are_limited(self):
        known = {}
        asked = []

        def get(u, max_bytes=0, headers=None):
            asked.append(u)
            return answer(u, status=404)
        for i in range(30):
            url = f'https://www.example.test/d{i}/x'
            routes._against_missing_page(routes.analyse(answer(url, body=self.SHELL)), url, get, known, sleep=lambda s: None)
        self.assertLessEqual(len(asked), routes.MAX_BASELINES_PER_BASE)

    def test_a_baseline_that_cannot_be_read_leaves_the_route_as_it_was(self):
        def get(u, max_bytes=0, headers=None):
            raise OSError('refused')
        url = 'https://www.example.test/admin'
        got = routes._against_missing_page(routes.analyse(answer(url, body=self.SHELL)), url, get, {}, sleep=lambda s: None)
        self.assertEqual(got['state'], 'open')


def fake_net(pages, asked=None):
    """``probe(url, policy, **kw)`` for ``http.probe_url``: ``pages`` maps a URL to an answer (or an exception); anything else is a 404. The policy
    is asked for the host first, as the real probe's transport does."""
    def probe(url, policy, max_bytes=http.ROUTE_SAMPLE_BYTES, **kw):
        if asked is not None:
            asked.append((url, max_bytes))
        authority = url.split('://', 1)[1].split('/', 1)[0]
        policy.check_host(authority.split(':')[0])
        policy.touch(authority)
        got = pages.get(url)
        if isinstance(got, Exception):
            raise got
        return answer(url, **got) if got is not None else answer(url, status=404, body='not found', title='Not found')
    return probe


def task(*groups, scope=SCOPE):
    return {'hosts': [{'host': h, 'urls': list(urls)} for h, urls in groups], 'scope': scope}


class RunBatchTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_batch(self, target, pages=None, asked=None, **kw):
        return routes.run_batch(target, probe=fake_net(pages or {}, asked), sleep=lambda s: None, **kw)

    def test_each_route_is_classified_and_the_front_page_is_read_further(self):
        asked = []
        pages = {'https://www.example.test/': {'body': '<html><title>Home</title><p>hi</p></html>', 'title': 'Home'},
                 'https://www.example.test/login': {'body': '<input type="password">'},
                 'https://www.example.test/admin': {'status': 302, 'location': 'https://acme.okta.com/app/x'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}{p}' for p in ('/', '/login', '/admin', '/nope')])), pages, asked)
        states = {r['id'].split(WWW)[1]: (r['state'], r['evidence']['provider']) for r in got['routes']}
        self.assertEqual(states, {'/': ('open', ''), '/login': ('login', ''), '/admin': ('sso', 'Okta'), '/nope': ('not_found', '')})
        self.assertEqual(got['touched'], [WWW])
        self.assertEqual(got['refused'], [])
        limits = {u.split(WWW)[1]: m for u, m in asked if '/cvengine-' not in u}
        self.assertEqual(limits['/'], routes.ROOT_READ_BYTES)
        self.assertEqual(limits['/login'], routes.ROUTE_SAMPLE_BYTES)

    def test_a_route_row_has_the_shape_the_contract_gives_and_nothing_of_the_body(self):
        pages = {f'https://{WWW}/': {'body': '<title>Home</title>' + 'q' * 5000, 'title': 'Home'},
                 'https://api.example.test/': {'content_type': 'application/json', 'body': json.dumps({'k': AWS_KEY})}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/']), ('api.example.test', ['https://api.example.test/'])), pages)
        out = {'outcome': 'done', **got}
        doc = contract.load()
        schema = {'$schema': doc['$schema'], '$ref': '#/$defs/results/route_probe', '$defs': doc['$defs']}
        self.assertEqual(sorted(Draft202012Validator(schema).iter_errors(out), key=str), [])
        self.assertNotIn('qqqq', json.dumps(got))
        api = got['routes'][1]
        self.assertEqual([(c['type'], c['value']) for c in api['credentials']], [('aws_key', AWS_KEY)])
        self.assertEqual((api['credentials'][0]['line'], api['credentials'][0]['context']), (1, '{"k": "AKIA…' + AWS_KEY[-4:] + '"}'))  # where it was, the value masked
        self.assertNotIn(AWS_KEY, api['credentials'][0]['context'])
        self.assertEqual(api['sensitive_score'], 25)

    def test_a_script_of_the_front_page_is_read_and_its_library_recorded(self):
        jquery = '/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){"use strict"}(window);'
        pages = {f'https://{WWW}/': {'body': '<html><head><title>Home</title><script src="/static/app.js"></script></head><body>x</body></html>', 'title': 'Home'},
                 f'https://{WWW}/static/app.js': {'content_type': 'application/javascript', 'body': jquery}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/'])), pages)
        evidence = got['routes'][0]['evidence']
        self.assertNotIn('page_scripts', evidence)
        self.assertEqual(evidence['script_urls'], [f'https://{WWW}/static/app.js'])
        self.assertIn('libraries', evidence)
        self.assertIn('jQuery:3.6.0', evidence['fingerprint_names'])
        self.assertEqual(evidence['script_page']['unread'], 0)

    def test_a_script_on_a_host_the_policy_does_not_name_is_not_read_and_is_reported_refused(self):
        asked = []
        pages = {f'https://{WWW}/': {'body': '<html><title>Home</title><script src="https://evil.example.net/jquery-3.6.0.min.js"></script><p>x</p></html>',
                                     'title': 'Home'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/'])), pages, asked)
        self.assertEqual([u for u, _ in asked if 'evil.example.net' in u], [])
        self.assertNotIn('evil.example.net', got['touched'])

    def test_a_host_the_policy_refuses_is_not_asked_and_says_why(self):
        asked = []
        got = self.run_batch(task(('other.example.test', ['https://other.example.test/', 'https://other.example.test/login'])), {}, asked)
        self.assertEqual(asked, [])
        self.assertEqual([r['id'] for r in got['routes']], ['https://other.example.test/', 'https://other.example.test/login'])
        for row in got['routes']:
            self.assertEqual(set(row), {'id', 'error'})
            self.assertIn('outside the scope policy', row['error'])
        self.assertEqual(got['refused'], ['other.example.test'])

    def test_an_excluded_host_is_refused_whatever_else_says(self):
        scope = {**SCOPE, 'excluded': [WWW]}
        got = self.run_batch(task((WWW, [f'https://{WWW}/']), scope=scope), {})
        self.assertIn('excluded', got['routes'][0]['error'])

    def test_a_route_that_fails_is_reported_with_its_error_and_no_state(self):
        pages = {f'https://{WWW}/login': OSError('connection refused'), f'https://{WWW}/': {'title': 'Home', 'body': '<title>Home</title>'}}
        got = self.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/login'])), pages)
        by_id = {r['id']: r for r in got['routes']}
        self.assertEqual(by_id[f'https://{WWW}/']['state'], 'open')
        self.assertEqual(set(by_id[f'https://{WWW}/login']), {'id', 'error'})
        self.assertIn('OSError', by_id[f'https://{WWW}/login']['error'])

    def test_a_task_that_runs_out_of_time_reports_the_rest_as_not_run(self):
        now = [0.0]

        def clock():
            now[0] += 100
            return now[0]
        got = self.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/login'])), {}, max_seconds=150, clock=clock)
        errors = [r.get('error', '') for r in got['routes']]
        self.assertTrue(any('ran out of time' in e for e in errors))

    def test_hosts_run_side_by_side_and_rows_come_back_in_the_tasks_order(self):
        groups = [(f'h{i}.example.test', [f'https://h{i}.example.test/', f'https://h{i}.example.test/x']) for i in range(10)]
        scope = {**SCOPE, 'hosts': [h for h, _ in groups]}
        got = self.run_batch(task(*groups, scope=scope), {})
        self.assertEqual([r['id'] for r in got['routes']], [u for _, urls in groups for u in urls])

    def test_requests_to_one_host_keep_the_gap(self):
        waits = []
        routes.run_batch(task((WWW, [f'https://{WWW}/', f'https://{WWW}/a', f'https://{WWW}/b'])), probe=fake_net({}), sleep=waits.append)
        self.assertGreaterEqual(len([w for w in waits if w == routes.PER_REQUEST_GAP]), 2)

    def test_a_malformed_task_is_refused(self):
        bad = [task((WWW, [])),
               task((WWW, ['https://other.example.test/'])),           # a route on another host than the group's
               task((WWW, ['ftp://www.example.test/'])),
               task((WWW, ['https://user:pw@www.example.test/'])),
               task((WWW, [f'https://{WWW}/a b'])),
               task((WWW, [f'https://{WWW}/' + 'a' * 2001])),
               task((WWW, [f'https://{WWW}/{i}' for i in range(21)])),
               {'hosts': 'nope', 'scope': SCOPE}, {'hosts': [{'host': WWW}], 'scope': SCOPE}, {'hosts': [None], 'scope': SCOPE}]
        for target in bad:
            with self.subTest(target=str(target)[:80]):
                with self.assertRaises(ValueError):
                    self.run_batch(target)
        with self.assertRaises(ValueError):
            self.run_batch({'hosts': [{'host': f'h{i}.example.test', 'urls': [f'https://h{i}.example.test/']} for i in range(26)], 'scope': SCOPE})

    def test_a_task_with_no_scope_asks_nothing(self):
        got = routes.run_batch({'hosts': [{'host': WWW, 'urls': [f'https://{WWW}/']}]}, probe=fake_net({}), sleep=lambda s: None)
        self.assertIn('error', got['routes'][0])
        self.assertEqual(got['touched'], [])

    def test_the_real_probe_is_the_default_and_asks_the_policy_first(self):
        with mock.patch.object(http.transport, 'resolve', side_effect=OSError('no network in a test')) as resolve:
            got = routes.run_batch(task((WWW, [f'https://{WWW}/'])), sleep=lambda s: None)
        self.assertEqual(resolve.call_count, 1)
        self.assertIn('OSError', got['routes'][0]['error'])
        self.assertTrue(ScopePolicy(SCOPE).host_refusal('evil.example.net'))


class SensitiveCredentialsTests(unittest.TestCase):
    def test_credential_values_are_distinct_bounded_and_a_private_key_is_its_whole_block(self):
        pem = '-----BEGIN RSA ' + 'PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA ' + 'PRIVATE KEY-----'
        got = sensitive.credential_values(f'{AWS_KEY} {AWS_KEY} {pem}')
        self.assertEqual([t for t, _ in got], ['aws_key', 'private_key'])
        self.assertEqual(got[1][1], pem)
        many = ' '.join('AKIA' + f'{i:016d}' for i in range(40))
        self.assertEqual(len(sensitive.credential_values(many)), sensitive.MAX_CREDENTIAL_VALUES)
        self.assertEqual(sensitive.credential_values(''), [])


if __name__ == '__main__':
    unittest.main()
