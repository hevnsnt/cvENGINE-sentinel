"""The page_read kind (``probes.page_read``): a validation re-test's HEAD of a URL and re-read of a host's pages and scripts, under the task's scope policy,
with the network replaced. Every case below is one the server's own tests held its reader to while the server did the reading (cvENGINE's
``tests/test_client_library_validation.py`` and ``test_client_library_script_read_review.py``)."""
import hashlib
import json
import unittest

from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner.probes import http, page_read

WWW = 'www.example.test'
BASE = f'https://{WWW}'
JQ = f'{BASE}/js/jquery.min.js'
SCOPE = {'hosts': [WWW, 'cdnjs.cloudflare.com'], 'domains': [], 'excluded': [], 'excluded_trees': [], 'private': False, 'addresses': [], 'blocked': []}
JQUERY = '/*! jQuery v{v} | (c) OpenJS Foundation | jquery.org/license */\n!function(a,b){var c="{v}",n=function(a,b){};n.fn=n.prototype={jquery:c,constructor:n};}(window);\n'


def answer(url, status=200, **kw):
    return {'url': url, 'status': status, 'location': '', 'www_authenticate': '', 'cookies': [], 'content_type': 'text/html', 'body': '', 'title': '',
            'server': '', 'powered_by': '', 'bytes': len(kw.get('body', '')), **kw}


def page(*sources):
    return ''.join(f'<script src="{s}"></script>' for s in sources)


def fake_net(pages, asked=None, methods=None):
    def probe(url, policy, max_bytes=http.ROUTE_SAMPLE_BYTES, method='GET', **kw):
        policy.check_host(url.split('/')[2].split(':')[0])
        if asked is not None:
            asked.append(url)
        if methods is not None:
            methods.append((method, url))
        got = pages.get(url)
        if isinstance(got, BaseException):
            raise got
        policy.touch(url.split('/')[2].split(':')[0])
        return answer(url, **(got or {'status': 404}))
    return probe


def task(*reads, scope=None):
    return {'reads': list(reads), 'scope': scope or SCOPE}


def libraries(**kw):
    return {'id': 'libraries:' + WWW, 'op': 'libraries', 'host': WWW, 'bases': [BASE], 'library': 'jquery', 'seen_urls': [], **kw}


def head(url=f'{BASE}/', **kw):
    return {'id': 'head:' + url, 'op': 'head', 'host': WWW, 'url': url, **kw}


CTRL = f'{BASE}/.cvengine-control-0123456789ab'


def control(url=CTRL, **kw):
    return {'id': 'control:' + url, 'op': 'control', 'host': WWW, 'url': url, **kw}


def readme(slugs=('akismet', 'hello-dolly'), **kw):
    return {'id': 'readme:' + WWW, 'op': 'readme', 'host': WWW, 'base': BASE, 'slugs': list(slugs), **kw}


def run(target, pages, **kw):
    asked, methods = [], []
    out = page_read.run_batch(target, probe=fake_net(pages, asked, methods), sleep=lambda s: None, **kw)
    return out, asked, methods


class HeadTests(unittest.TestCase):
    def test_a_head_keeps_the_status_and_three_headers_and_asks_nothing_more(self):
        out, asked, methods = run(task(head()), {f'{BASE}/': {'status': 200, 'server': 'nginx/1.24.0', 'powered_by': 'PHP/8.1', 'title': 'Home'}})
        self.assertEqual(out['reads'], [{'id': f'head:{BASE}/', 'head': {'status': 200, 'method': 'HEAD', 'server': 'nginx/1.24.0', 'powered_by': 'PHP/8.1',
                                                                          'title': 'Home'}}])
        self.assertEqual((methods, out['touched'], out['refused']), ([('HEAD', f'{BASE}/')], [WWW], []))

    def test_a_get_is_made_only_after_a_405(self):
        out, _asked, methods = run(task(head()), {f'{BASE}/': {'status': 405}})
        self.assertEqual([m for m, _u in methods], ['HEAD', 'GET'])
        self.assertEqual(out['reads'][0]['head']['method'], 'GET')

    def test_a_redirect_is_an_answer_and_is_not_followed(self):
        out, asked, _m = run(task(head()), {f'{BASE}/': {'status': 301, 'location': 'https://other.example.test/'}})
        self.assertEqual((out['reads'][0]['head']['status'], asked), (301, [f'{BASE}/']))

    def test_a_host_the_policy_refuses_is_not_asked_and_is_said(self):
        scope = {**SCOPE, 'excluded': [WWW]}
        out, asked, _m = run(task(head(), scope=scope), {})
        self.assertEqual((asked, out['refused']), ([], [WWW]))
        self.assertIn('not run', out['reads'][0]['error'])

    def test_a_connection_that_fails_is_an_error_never_an_answer(self):
        out, _a, _m = run(task(head()), {f'{BASE}/': OSError('refused')})
        self.assertIn('error', out['reads'][0])
        self.assertNotIn('head', out['reads'][0])


class LibrariesTests(unittest.TestCase):
    def site(self, version='3.6.0', **more):
        return {f'{BASE}/': {'status': 200, 'body': page('/js/jquery.min.js')}, JQ: {'status': 200, 'body': JQUERY.replace('{v}', version)}, **more}

    def test_the_page_and_its_script_are_read_whole_and_the_record_names_the_version(self):
        out, asked, _m = run(task(libraries()), self.site())
        reading = out['reads'][0]['reading']
        (read_page,) = reading['pages']
        self.assertEqual((read_page['outcome'], read_page['read_whole'], read_page['scripts']), ('read', 1, 1))
        self.assertEqual(read_page['records']['jquery']['version'], '3.6.0')
        self.assertEqual(reading['scanned'][JQ]['whole'], True)
        self.assertEqual(asked, [f'{BASE}/', JQ])

    def test_every_script_is_asked_for_in_full_never_revalidated_with_an_etag(self):
        sent = []

        def probe(url, policy, max_bytes=0, method='GET', headers=None, **kw):
            sent.append(headers)
            policy.check_host(WWW)
            return answer(url, **self.site()[url])
        page_read.run_batch(task(libraries()), probe=probe, sleep=lambda s: None)
        self.assertEqual(sent, [None, None])

    def test_a_front_page_that_redirects_elsewhere_is_a_redirect_and_its_scripts_are_not_read(self):
        out, asked, _m = run(task(libraries()), {f'{BASE}/': {'status': 301, 'location': 'https://www.other.test/'}})
        (read_page,) = out['reads'][0]['reading']['pages']
        self.assertEqual((read_page['outcome'], read_page['location'], asked), ('redirect', 'https://www.other.test/', [f'{BASE}/']))

    def test_the_outcomes_of_a_page_that_is_not_read(self):
        for status, body, outcome in ((404, '', 'error_page'), (503, '', 'error_page')):
            with self.subTest(status):
                out, _a, _m = run(task(libraries()), {f'{BASE}/': {'status': status, 'body': body}})
                self.assertEqual(out['reads'][0]['reading']['pages'][0]['outcome'], outcome)
        out, _a, _m = run(task(libraries()), {f'{BASE}/': OSError('down')})
        self.assertEqual(out['reads'][0]['reading']['pages'][0]['outcome'], 'unanswered')

    def test_a_script_on_a_host_the_policy_does_not_name_is_not_read(self):
        other = 'https://static.other.test/jquery.min.js'
        out, asked, _m = run(task(libraries()), {f'{BASE}/': {'status': 200, 'body': page(other)}, other: {'status': 200, 'body': JQUERY.replace('{v}', '3.6.0')}})
        self.assertNotIn(other, asked)
        self.assertEqual(out['reads'][0]['reading']['pages'][0]['read_whole'], 0)

    def test_a_script_redirect_to_a_host_outside_the_policy_is_refused_and_said(self):
        apex = 'https://example.test/js/jquery.min.js'
        out, asked, _m = run(task(libraries()), self.site(**{JQ: {'status': 301, 'location': apex}, apex: {'status': 200, 'body': JQUERY.replace('{v}', '3.6.0')}}))
        self.assertNotIn(apex, asked)
        self.assertIn('example.test', out['refused'])

    def test_a_script_redirect_inside_the_policy_is_followed_and_read_whole(self):
        moved = f'{BASE}/static/jquery.min.js'
        out, asked, _m = run(task(libraries()), self.site(**{JQ: {'status': 301, 'location': moved}, moved: {'status': 200, 'body': JQUERY.replace('{v}', '3.6.0')}}))
        self.assertIn(moved, asked)
        self.assertEqual(out['reads'][0]['reading']['pages'][0]['read_whole'], 1)

    def test_a_host_scoped_policy_reads_its_own_host_only_at_every_hop(self):
        apex = 'https://example.test/js/jquery.min.js'
        scope = {**SCOPE, 'hosts': [WWW]}  # what cvENGINE sends for a target scoped to one host: no apex, no twin
        out, asked, _m = run(task(libraries(), scope=scope), self.site(**{JQ: {'status': 302, 'location': apex}, apex: {'status': 200, 'body': JQUERY.replace('{v}', '3.6.0')}}))
        self.assertIn(JQ, asked)
        self.assertNotIn(apex, asked)
        self.assertIn('example.test', out['refused'])

    def test_a_seen_file_the_pages_did_not_load_is_fetched_when_a_page_shows_the_library(self):
        seen = f'{BASE}/old/jquery-1.12.4.min.js'
        out, asked, _m = run(task(libraries(seen_urls=[seen])), self.site(**{seen: {'status': 200, 'body': JQUERY.replace('{v}', '1.12.4')}}))
        reading = out['reads'][0]['reading']
        self.assertIn(seen, asked)
        self.assertEqual(reading['extra'][seen]['whole'], True)
        self.assertEqual(reading['budget_left'], 4)

    def test_nothing_is_asked_for_a_seen_file_when_no_page_shows_the_library(self):
        seen = f'{BASE}/old/jquery-1.12.4.min.js'
        out, asked, _m = run(task(libraries(seen_urls=[seen])), {f'{BASE}/': {'status': 200, 'body': '<p>no scripts</p>'}})
        self.assertNotIn(seen, asked)
        self.assertEqual(out['reads'][0]['reading']['extra'], {})

    def test_a_seen_file_on_another_port_goes_through_the_vetters_port_rule(self):
        seen = f'{BASE}:9443/js/jquery.min.js'
        out, asked, _m = run(task(libraries(seen_urls=[seen])), self.site())
        self.assertNotIn(seen, asked)
        self.assertIn('port', out['reads'][0]['reading']['extra'][seen]['error'])

    def test_a_seen_file_past_the_scripts_left_in_the_budget_is_recorded_as_not_read(self):
        many = [f'{BASE}/old/jquery-{n}.min.js' for n in range(8)]
        pages = self.site(**{u: {'status': 200, 'body': JQUERY.replace('{v}', '1.12.4')} for u in many})
        out, asked, _m = run(task(libraries(seen_urls=many)), pages)
        extra = out['reads'][0]['reading']['extra']
        self.assertEqual(sum(1 for u in many if u in asked), 5)
        # at most MAX_SCRIPTS_PER_HOST (6) seen files are considered; the page's script took one of the six, so five are fetched and the sixth is not
        self.assertEqual(sum(1 for v in extra.values() if v.get('error') == 'page host limit'), 1)

    def test_a_script_that_cannot_be_fetched_is_recorded_with_why(self):
        out, _a, _m = run(task(libraries()), self.site(**{JQ: OSError('reset')}))
        self.assertEqual(out['reads'][0]['reading']['scanned'][JQ]['whole'], False)


class TaskTests(unittest.TestCase):
    def test_a_read_that_fails_does_not_stop_the_rest(self):
        out, _a, _m = run(task(head(), head(f'{BASE}/x')), {f'{BASE}/': OSError('x'), f'{BASE}/x': {'status': 200}})
        self.assertEqual(['error' in r for r in out['reads']], [True, False])

    def test_a_read_that_is_not_of_its_own_host_is_a_malformed_task(self):
        with self.assertRaises(ValueError):
            page_read.run_batch(task(head('https://elsewhere.example.test/')), probe=fake_net({}))
        with self.assertRaises(ValueError):
            page_read.run_batch(task(libraries(bases=['https://elsewhere.example.test'])), probe=fake_net({}))
        with self.assertRaises(ValueError):
            page_read.run_batch(task(), probe=fake_net({}))
        with self.assertRaises(ValueError):
            page_read.run_batch(task(*[head()] * 11), probe=fake_net({}))

    def test_a_task_out_of_time_reports_the_reads_it_did_not_start(self):
        ticks = iter([0, 0, 1000, 1000])
        out, _a, _m = run(task(head(), head(f'{BASE}/x')), {f'{BASE}/': {'status': 200}}, clock=lambda: next(ticks), max_seconds=10)
        self.assertEqual(['error' in r for r in out['reads']], [False, True])
        self.assertIn('out of time', out['reads'][1]['error'])

    def test_a_policy_that_names_nothing_refuses_everything(self):
        out, asked, _m = run({'reads': [head()], 'scope': {}}, {})
        self.assertEqual(asked, [])
        self.assertIn('not run', out['reads'][0]['error'])


class ControlTests(unittest.TestCase):
    def test_the_answer_is_kept_as_status_location_length_and_a_digest_of_the_body_never_the_body(self):
        body = '<h1>503   No server is\navailable</h1>'
        out, asked, methods = run(task(control()), {CTRL: {'status': 503, 'body': body}})
        want = hashlib.sha256(b'<h1>503 No server is available</h1>').hexdigest()
        self.assertEqual(out['reads'], [{'id': f'control:{CTRL}', 'control': {'status': 503, 'location': '', 'length': len(body), 'digest': want}}])
        self.assertEqual((asked, methods, out['touched']), ([CTRL], [('GET', CTRL)], [WWW]))
        self.assertNotIn('No server', json.dumps(out))

    def test_a_redirect_is_an_answer_and_is_not_followed(self):
        out, asked, _m = run(task(control()), {CTRL: {'status': 302, 'location': '/login'}})
        self.assertEqual((out['reads'][0]['control']['status'], out['reads'][0]['control']['location'], asked), (302, '/login', [CTRL]))

    def test_only_a_control_path_on_the_host_is_asked(self):
        for url in (f'{BASE}/', f'{BASE}/admin', f'{CTRL}?x=1', f'{BASE}/.cvengine-control-xyz', 'https://elsewhere.example.test/.cvengine-control-0123456789ab'):
            with self.assertRaises(ValueError, msg=url):
                page_read.run_batch(task(control(url)), probe=fake_net({}))

    def test_a_host_the_policy_refuses_is_not_asked_and_a_failed_read_is_an_error_never_an_answer(self):
        out, asked, _m = run(task(control(), scope={**SCOPE, 'excluded': [WWW]}), {})
        self.assertEqual((asked, out['refused']), ([], [WWW]))
        self.assertIn('not run', out['reads'][0]['error'])
        out, _a, _m = run(task(control()), {CTRL: OSError('timed out')})
        self.assertIn('error', out['reads'][0])
        self.assertNotIn('control', out['reads'][0])


class ReadmeTests(unittest.TestCase):
    def url(self, slug):
        return f'{BASE}/wp-content/plugins/{slug}/readme.txt'

    def test_the_title_of_each_plugin_is_read_and_a_missing_or_unreadable_one_is_counted(self):
        pages = {self.url('akismet'): {'status': 200, 'body': '=== Akismet Anti-Spam: Spam Protection ===\nContributors: x\n'},
                 self.url('hello-dolly'): {'status': 404}, self.url('broken'): OSError('reset')}
        out, asked, methods = run(task(readme(('akismet', 'hello-dolly', 'broken'))), pages)
        self.assertEqual(out['reads'][0]['readme'], {'titles': {'akismet': 'Akismet Anti-Spam Spam Protection'}, 'asked': 3, 'unread': 1})
        self.assertEqual((asked, {m for m, _u in methods}), ([self.url(s) for s in ('akismet', 'hello-dolly', 'broken')], {'GET'}))

    def test_a_malformed_read_is_refused(self):
        bad = [readme(slugs=()), readme(slugs=[f's{i}' for i in range(9)]), readme(slugs=['../etc']), readme(slugs=['a/b']), readme(slugs=['.hidden']),
               readme(base='https://elsewhere.example.test'), readme(base=f'{BASE}/blog?x=1'), readme(base=f'{BASE}/a/../b')]
        for read in bad:
            with self.assertRaises(ValueError, msg=str(read)):
                page_read.run_batch(task(read), probe=fake_net({}))

    def test_wordpress_in_a_sub_directory_is_read_under_its_path(self):
        url = f'{BASE}/blog/wp-content/plugins/akismet/readme.txt'
        out, asked, _m = run(task(readme(('akismet',), base=f'{BASE}/blog/')), {url: {'status': 200, 'body': '=== Akismet ===\n'}})
        self.assertEqual((out['reads'][0]['readme']['titles'], asked), ({'akismet': 'Akismet'}, [url]))

    def test_a_redirect_off_the_host_is_refused_and_counted_unread(self):
        pages = {self.url('akismet'): {'status': 301, 'location': 'https://elsewhere.example.test/x'}}
        out, asked, _m = run(task(readme(('akismet',))), pages)
        self.assertEqual(out['reads'][0]['readme'], {'titles': {}, 'asked': 1, 'unread': 0})
        self.assertEqual(asked, [self.url('akismet')])

    def test_a_host_the_policy_refuses_is_not_asked(self):
        out, asked, _m = run(task(readme(), scope={**SCOPE, 'excluded': [WWW]}), {})
        self.assertEqual((asked, out['refused']), ([], [WWW]))
        self.assertIn('not run', out['reads'][0]['error'])


class ContractTests(unittest.TestCase):
    def schema(self, section):
        doc = contract.load()
        return Draft202012Validator({**doc, '$ref': f'#/$defs/{section}/page_read'})

    def test_the_task_the_server_sends_and_the_result_this_returns_fit_the_contract(self):
        target = task(head(), libraries(seen_urls=[f'{BASE}/old.js']), control(), readme())
        self.assertEqual(list(self.schema('targets').iter_errors(target)), [])
        site = {f'{BASE}/': {'status': 200, 'body': page('/js/jquery.min.js')}, JQ: {'status': 200, 'body': JQUERY.replace('{v}', '3.6.0')},
                f'{BASE}/old.js': {'status': 200, 'body': JQUERY.replace('{v}', '1.12.4')}, CTRL: {'status': 404, 'body': 'not found'},
                f'{BASE}/wp-content/plugins/akismet/readme.txt': {'status': 200, 'body': '=== Akismet ===\n'}}
        out, _a, _m = run(target, site)
        result = {'outcome': 'done', **out}
        self.assertEqual([e.message for e in self.schema('results').iter_errors(json.loads(json.dumps(result)))], [])
