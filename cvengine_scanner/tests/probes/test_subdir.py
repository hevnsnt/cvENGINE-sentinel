"""The subdir_probe kind (``probes.subdir``): the curated data, how a response is read, which answers count, the leads and the request budget."""
import hashlib
import unittest
from unittest import mock
from urllib.parse import urlsplit

from cvengine_scanner.probes import subdir

# The same table and digest are in the server's tests (tests/test_subdir_apps.py, ScannerParityTests): this module reads a response with its own
# copy of ``identify`` and of the curated data, and the two must agree. Change one, change the other.
DATA_SHA256 = '62fc583d66b8d00b034cb894d91f393c0b35446ddb83b4ca2e412a565c3d370c'
PARITY = [  # (path, status, title, body, headers, location) -> (product, confidence, version, indicated) or None
    ('/jenkins/', 403, 'Authentication required', '<html>x</html>', {'x-jenkins': '2.401.3'}, '', ('Jenkins', 0.9, '2.401.3', '/jenkins/')),
    ('/grafana/', 302, '', '', {}, 'https://www.example.com/grafana/login', ('Grafana', 0.7, '', '/grafana/')),
    ('/jira/', 200, 'Dashboard - Jira', '<html><meta name="ajs-version-number" content="9.4.1"><body data-name="jira" data-version="9.4.1"></body></html>', {}, '',
     ('Jira', 0.85, '9.4.1', '/jira/')),
    ('/phpmyadmin/', 200, 'phpMyAdmin', '<html>' + 'p' * 300 + '</html>', {}, '', ('phpMyAdmin', 0.8, '', '/phpmyadmin/')),
    ('/portal/', 200, 'Staff portal', '<html>' + 's' * 900 + '</html>', {}, '', None),
    ('/confluence/', 200, 'Home - Confluence', '<html>Atlassian Confluence 8.5.4</html>', {}, '', ('Confluence', 0.85, '8.5.4', '/confluence/')),
    ('/x/', 404, 'Not found', 'nothing', {}, '', None),
]
SCOPE = {'hosts': ['www.example.com', 'portal.example.com'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [],
         'blocked': []}
VHOST_ADDRESS = '93.184.215.14'  # a public address the scanner's floor lets through


def page(status=200, title='', body='', headers=None, location=''):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'status': status, 'title': title, 'body': body, 'bytes': len(body), 'location': location, 'server': headers.get('server', ''),
            'powered_by': '', 'content_type': 'text/html', 'headers': headers, 'raw_headers': headers}


NOT_FOUND = page(404, 'Not Found', '<html><title>Not Found</title>' + 'n' * 120)


class Site:
    """A fake host: answers by path (404 for anything else), records every request as ``(host, path, connect_ip)``."""

    def __init__(self, table=None):
        self.table, self.calls = dict(table or {}), []

    def __call__(self, url, policy, max_bytes=None, connect_ip=None, **kw):
        parts = urlsplit(url)
        self.calls.append((parts.hostname, parts.path, connect_ip))
        policy.check_host(parts.hostname)
        if connect_ip:
            policy.check_address(connect_ip, literal=True)
        policy.touch(parts.hostname)
        value = self.table.get(parts.path, NOT_FOUND)
        if isinstance(value, Exception):
            raise value
        return value

    def paths(self):
        return [path for _h, path, _ip in self.calls]


def host(**kw):
    return {'id': 'h0', 'name': 'www.example.com', 'scheme': 'https', 'port': 443, **kw}


def task(hosts=None, paths=('/jira/', '/grafana/', '/jenkins/'), max_requests=60, scope=None, gap=0.2):
    return {'hosts': hosts or [host()], 'paths': list(paths), 'max_requests': max_requests, 'gap': gap, 'scope': scope or SCOPE}


def run(target, table=None, **kw):
    site = Site(table)
    kw.setdefault('sleep', lambda s: None)
    return subdir.run_batch(target, probe=site, **kw), site


class ScannerParityTests(unittest.TestCase):
    def test_the_curated_data_is_the_file_the_server_carries(self):
        self.assertEqual(hashlib.sha256(subdir.DATA_FILE.read_bytes()).hexdigest(), DATA_SHA256)

    def test_a_response_is_read_as_the_server_reads_it(self):
        for path, status, title, body, headers, location, expected in PARITY:
            with self.subTest(path=path):
                got = subdir.identify(page(status, title, body, headers, location), path)
                self.assertEqual(None if got is None else (got['product'], got['confidence'], got['version'], got['indicated']), expected)


class CatalogueTests(unittest.TestCase):
    def test_the_paths_are_plain_mount_paths_and_unique(self):
        paths = subdir.curated_paths()
        self.assertEqual(len(paths), 43)
        self.assertEqual(len(set(paths)), len(paths))
        self.assertTrue(all(p.startswith('/') and '..' not in p for p in paths))
        self.assertTrue({'/jira/', '/phpmyadmin/', '/manager/html'} <= set(paths))

    def test_every_product_is_unique_and_every_signature_compiles(self):
        products = [e['product'] for e in subdir.catalogue()]
        self.assertEqual(len(set(products)), len(products))
        self.assertTrue(all(e['signatures'] for e in subdir.catalogue()))


class ReadingTests(unittest.TestCase):
    def test_a_signature_below_the_confirm_level_is_a_lead_not_a_product(self):
        found = subdir.identify(page(302, '', '', location='https://www.example.com/grafana/login'), '/grafana/')
        self.assertGreaterEqual(found['confidence'], subdir.CONFIRM)
        self.assertEqual(found['version'], '')

    def test_a_mount_is_the_first_directory_of_a_url_unless_it_is_noise(self):
        self.assertEqual(subdir.mount_of('https://www.example.com/portal/index.jsp'), '/portal/')
        self.assertEqual(subdir.mount_of('/portal/'), '/portal/')
        for none in ('/', '/index.html', '/assets/app.js', '/wp-content/x/', '/en/home', '/a/', 'https://[bad'):
            self.assertIsNone(subdir.mount_of(none), none)

    def test_robots_and_sitemap_name_directories(self):
        self.assertEqual(subdir.robots_paths('User-agent: *\nDisallow: /portal/\nAllow: /wiki/page\n# no\n'), ['/portal/', '/wiki/page'])
        body = '<urlset><url><loc>https://www.example.com/docs/a</loc></url><url><loc>https://other.example.com/x/y</loc></url></urlset>'
        self.assertEqual(subdir.sitemap_paths(body, 'www.example.com'), ['/docs/a'])

    def test_the_lead_plan_merges_the_server_s_mounts_with_robots_and_sitemap(self):
        seen = [{'path': '/portal/', 'count': 3, 'source': 'crawled'}, {'path': '/jira/', 'count': 9, 'source': 'archive'}]
        plan = subdir.lead_plan(seen, {'robots': ['/portal/x', '/humans/y'], 'sitemap': ['/humans/z', '/humans/w']}, {'/jira/'})
        self.assertEqual([p for p, _s in plan], ['/portal/', '/humans/'])
        self.assertEqual(dict(plan), {'/portal/': 'crawled', '/humans/': 'robots'})

    def test_at_most_ten_leads(self):
        seen = [{'path': f'/app{i}/', 'count': 1, 'source': 'crawled'} for i in range(25)]
        self.assertEqual(len(subdir.lead_plan(seen, {}, set())), subdir.MAX_LEADS)

    def test_the_answer_to_a_path_nobody_serves_is_not_a_mount(self):
        base = {'status': 200, 'title': 'App', 'length': 900, 'location': '', 'server': ''}
        self.assertTrue(subdir.is_catch_all(dict(base), [None, base]))
        self.assertFalse(subdir.is_catch_all({**base, 'title': 'Jira'}, [base]))
        redirect = {'status': 302, 'title': '', 'length': 0, 'location': '/login', 'server': ''}
        self.assertTrue(subdir.is_catch_all(dict(redirect), [redirect]))
        self.assertFalse(subdir.is_catch_all({**redirect, 'location': '/jira/login'}, [redirect]))


class RunTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.table = {'/jenkins/': page(403, 'Authentication required', '<html>x</html>', {'X-Jenkins': '2.401.3'}),
                      '/grafana/': page(302, '', '', location='https://www.example.com/grafana/login'),
                      '/jira/': page(500, 'Jira', 'e' * 100), '/portal/': page(200, 'Staff portal', '<html>' + 's' * 900 + '</html>')}

    def test_the_baseline_robots_sitemap_then_each_path_in_order(self):
        got, site = run(task(), self.table)
        self.assertEqual(site.paths(), [subdir.BASELINE_PATH, '/robots.txt', '/sitemap.xml', '/jira/', '/grafana/', '/jenkins/'])
        report = got['hosts'][0]
        self.assertEqual((report['id'], report['state'], report['requests']), ('h0', 'done', 6))
        self.assertEqual(report['baseline']['status'], 404)
        self.assertEqual(report['probed'], ['/jira/', '/grafana/', '/jenkins/'])

    def test_only_200_301_302_401_and_403_are_reported_with_what_they_say_they_are(self):
        got, _site = run(task(), self.table)
        answers = {a['path']: a for a in got['hosts'][0]['answers']}
        self.assertEqual(sorted(answers), ['/grafana/', '/jenkins/'])  # the 500 of /jira/ is nothing there
        self.assertEqual((answers['/jenkins/']['found']['product'], answers['/jenkins/']['found']['version']), ('Jenkins', '2.401.3'))
        self.assertEqual(answers['/grafana/']['found']['product'], 'Grafana')
        self.assertEqual(answers['/jenkins/']['source'], 'curated')

    def test_a_catch_all_answer_has_no_reading_but_is_still_reported(self):
        every = page(200, 'Single page app', '<html>' + 'a' * 800 + '</html>')
        site = Site()
        site.table = {}
        site.__class__ = type('Everywhere', (Site,), {'__call__': lambda self, url, policy, **kw: (Site.__call__(self, url, policy, **kw), every)[1]})
        got = subdir.run_batch(task(), probe=site, sleep=lambda s: None)
        report = got['hosts'][0]
        self.assertEqual(report['baseline']['title'], 'Single page app')
        self.assertTrue(report['answers'])
        self.assertTrue(all(a['found'] is None for a in report['answers']))

    def test_the_stored_front_page_is_a_baseline_too(self):
        root = {'status': 200, 'title': 'Staff portal', 'length': 910, 'location': '', 'server': ''}
        got, _site = run(task(hosts=[host(root=root, leads=[{'path': '/portal/', 'count': 2, 'source': 'crawled'}])]), self.table)
        answer = [a for a in got['hosts'][0]['answers'] if a['path'] == '/portal/'][0]
        self.assertEqual((answer['source'], answer['found']), ('crawled', None))

    def test_the_leads_follow_the_curated_paths_and_come_from_the_task_robots_and_sitemap(self):
        self.table['/robots.txt'] = page(200, '', 'User-agent: *\nDisallow: /humans/\n')
        self.table['/humans/'] = page(200, 'HR', '<html>' + 'h' * 700 + '</html>')
        got, site = run(task(hosts=[host(leads=[{'path': '/portal/', 'count': 2, 'source': 'crawled'}])]), self.table)
        self.assertEqual(site.paths()[-2:], ['/portal/', '/humans/'])
        answers = {a['path']: a['source'] for a in got['hosts'][0]['answers']}
        self.assertEqual((answers['/portal/'], answers['/humans/']), ('crawled', 'robots'))

    def test_robots_is_read_only_when_it_answered_200(self):
        self.table['/robots.txt'] = page(404, '', 'Disallow: /humans/\n')
        _got, site = run(task(), self.table)
        self.assertNotIn('/humans/', site.paths())

    def test_the_budget_caps_the_requests_of_a_host(self):
        got, site = run(task(max_requests=10, paths=[f'/p{i}/' for i in range(30)]), self.table)
        self.assertEqual(len(site.calls), 10)
        self.assertEqual(got['hosts'][0]['requests'], 10)

    def test_the_budget_is_clamped(self):
        _got, site = run(task(max_requests=1, paths=[f'/p{i}/' for i in range(30)]), self.table)
        self.assertEqual(len(site.calls), subdir.MIN_REQUESTS)
        _got, site = run(task(max_requests=10 ** 6, paths=[f'/p{i}/' for i in range(100)]), self.table)
        self.assertEqual(len(site.calls), 103)

    def test_a_challenge_ends_the_host_and_names_the_edge(self):
        self.table['/jira/'] = page(403, '', '<html>Just a moment... cloudflare _cf_chl_opt</html>', {'Server': 'cloudflare'})
        got, site = run(task(), self.table)
        report = got['hosts'][0]
        self.assertEqual(report['state'], 'challenged')
        self.assertEqual((report['challenge']['edge'], report['challenge']['status'], report['challenge']['path']), ('Cloudflare', 403, '/jira/'))
        self.assertEqual(site.paths()[-1], '/jira/')  # nothing after it was asked
        self.assertEqual(report['probed'], [])

    def test_a_busy_server_ends_the_host_without_a_result(self):
        self.table['/grafana/'] = page(503, 'Busy', 'later')
        got, site = run(task(), self.table)
        report = got['hosts'][0]
        self.assertEqual(report['state'], 'busy')
        self.assertEqual(report['probed'], ['/jira/'])
        self.assertEqual(site.paths()[-1], '/grafana/')

    def test_a_path_that_could_not_be_asked_is_not_reported_as_probed(self):
        self.table['/jira/'] = OSError('reset')
        got, _site = run(task(), self.table)
        self.assertEqual(got['hosts'][0]['probed'], ['/grafana/', '/jenkins/'])

    def test_a_virtual_host_is_asked_at_its_address_with_its_name(self):
        got, site = run(task(hosts=[host(name='portal.example.com', connect_ip=VHOST_ADDRESS)]), self.table)
        self.assertEqual({ip for _h, _p, ip in site.calls}, {VHOST_ADDRESS})
        self.assertEqual({h for h, _p, _ip in site.calls}, {'portal.example.com'})
        self.assertEqual(got['hosts'][0]['state'], 'done')

    def test_a_host_outside_the_policy_is_asked_nothing_and_says_so(self):
        scope = {**SCOPE, 'hosts': ['portal.example.com']}
        got, _site = run(task(scope=scope), self.table)
        self.assertEqual(got['hosts'][0]['probed'], [])
        self.assertEqual(got['hosts'][0]['answers'], [])
        self.assertIn('www.example.com', got['refused'])

    def test_requests_wait_the_gap_of_the_task(self):
        sleeps, clock = [], iter(range(0, 1000))
        run(task(gap=2.0, paths=('/jira/',)), self.table, sleep=sleeps.append, clock=lambda: next(clock) * 0.01)
        self.assertEqual(len(sleeps), 3)  # baseline, robots, sitemap, one path: four requests
        self.assertTrue(all(1.9 < s <= 2.0 for s in sleeps))

    def test_every_request_is_a_get_of_a_plain_path_with_no_query(self):
        _got, site = run(task(hosts=[host(leads=[{'path': '/portal/', 'count': 1, 'source': 'crawled'}])]), self.table)
        self.assertTrue(all(p.startswith('/') for p in site.paths()))
        self.assertEqual(len(site.paths()), len(set(site.paths())))

    def test_malformed_tasks_are_refused(self):
        for bad in ({}, {**task(), 'hosts': []}, {**task(), 'hosts': [{'id': 'h'}]}, {**task(), 'paths': []}, {**task(), 'paths': ['../etc']},
                    {**task(), 'paths': ['/ok/', 7]}, {**task(), 'max_requests': 'many'}, {**task(), 'hosts': [host(connect_ip='nope')]},
                    {**task(), 'hosts': [host(scheme='ftp')]}, {**task(), 'hosts': [host(name='a/b')]},
                    {**task(), 'hosts': [host(leads=[{'path': '/../', 'count': 1, 'source': 'crawled'}])]},
                    {**task(), 'hosts': [host(root={'status': 'x'})]}, {**task(), 'hosts': [host()] * 11}):
            with self.subTest(bad=str(bad)[:60]):
                with self.assertRaises(ValueError):
                    subdir.run_batch(bad, probe=Site(), sleep=lambda s: None)


class ContractShapeTests(unittest.TestCase):
    def test_a_result_and_a_target_validate_against_the_contract(self):
        from jsonschema import Draft202012Validator

        from cvengine_scanner import contract
        target = task(hosts=[host(root={'status': 200, 'title': 'Home', 'length': 5000, 'location': '', 'server': ''},
                                  leads=[{'path': '/portal/', 'count': 3, 'source': 'crawled'}])])
        self.assertEqual(sorted(Draft202012Validator(contract.target_schema('subdir_probe')).iter_errors(target), key=str), [])
        with mock.patch('cvengine_scanner.scope.own_addresses', return_value=frozenset()):
            got, _site = run(target, {'/jenkins/': page(403, 'x', '<html>x</html>', {'X-Jenkins': '2.401.3'}), '/portal/': page(200, 'Staff', 's' * 900)})
        result = {'outcome': 'done', **got}
        self.assertEqual(sorted(Draft202012Validator(contract.result_schema('subdir_probe')).iter_errors(result), key=str), [])


if __name__ == '__main__':
    unittest.main()
