"""Ported from cvENGINE's web/tests/test_probes.py (its tests that need no database), run against the library copy."""
from unittest import mock
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import version_probes as probes
from cvengine_scanner.probes.policy import ScopePolicy
POLICY = ScopePolicy({'domains': ['rt.test']}, internal=False)
def page(status=200, headers=None, body='', title='', content_type='text/html', url='https://www.rt.test/'):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {'status': status, 'headers': headers, 'body': body, 'title': title, 'content_type': content_type, 'server': headers.get('server', ''),
            'powered_by': headers.get('x-powered-by', ''), 'final_url': url, 'url': url, 'location': '', 'challenge': ''}
def answers(table):
    """A ``get(url)`` that answers by path from ``table`` and 404s the rest."""
    def get(url):
        path = '/' + url.split('://', 1)[1].split('/', 1)[1]
        return table.get(path, page(404, body='not found'))
    return get
NGINX_404 = '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>'
NGINX_404_HIDDEN = NGINX_404.replace('nginx/1.24.0', 'nginx')
class RuleTests(SimpleTestCase):
    def run_probe(self, probe_id, table):
        return probes.run_http_probe(probe_id, 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_the_nginx_error_page_footer_states_a_version(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body=NGINX_404)})
        self.assertEqual([(o['kind'], o['product'], o['version'], o['outcome']) for o in found], [('version', 'nginx', '1.24.0', 'found')])

    def test_a_footer_without_a_version_is_hidden_not_guessed(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body=NGINX_404_HIDDEN)})
        kinds = {(o['kind'], o['outcome'], o['version'], o['variant']) for o in found}
        self.assertEqual(kinds, {('version', 'hidden', '', ''), ('identity', 'found', '', 'nginx')})

    def test_the_kubernetes_default_backend_is_not_plain_nginx(self):
        found = self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='default backend - 404', content_type='text/plain')})
        self.assertEqual([(o['product'], o['variant']) for o in found], [('nginx', 'kubernetes-ingress')])

    def test_apache_tomcat_jetty_and_iis_pages(self):
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<address>Apache/2.4.41 (Ubuntu) Server at x Port 80</address>')})[0]['version'], '2.4.41')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<h3>Apache Tomcat/9.0.50</h3>')})[0]['version'], '9.0.50')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='<hr>Powered by Jetty:// 9.4.51.v20230217<hr>')})[0]['version'], '9.4.51.v20230217')
        self.assertEqual(self.run_probe('error-page', {probes.PROBE_PATH: page(404, body='x', title='IIS 10.0 Detailed Error - 404.0')})[0]['version'], '10.0')

    def test_nginx_ui_and_proxy_manager_are_told_apart(self):
        found = self.run_probe('nginx-variants', {'/': page(title='Nginx UI')})
        self.assertEqual([(o['kind'], o['variant']) for o in found], [('identity', 'nginx-ui')])
        found = self.run_probe('nginx-variants', {'/api/': page(body='{"status":"OK","setup":true,"version":{"major":2,"minor":10,"revision":4}}')})
        self.assertEqual([(o['product'], o['version']) for o in found], [('Nginx Proxy Manager', '2.10.4')])

    def test_a_challenge_page_is_not_read_as_the_site(self):
        blocked = page(503, body=NGINX_404)
        blocked['challenge'] = 'Cloudflare'
        found = self.run_probe('error-page', {probes.PROBE_PATH: blocked})
        self.assertEqual([(o['kind'], o['outcome']) for o in found], [('edge', 'challenged')])  # the edge is noted; its page is not read as the site

    def test_the_nextjs_version_comes_from_its_framework_script(self):
        html = '<script src="/_next/static/chunks/main-app-0123456789abcdef.js"></script>'
        chunk = 'var a=1;window.next={version:"14.1.0",appDir:!0};'
        found = self.run_probe('nextjs-version', {'/': page(body=html), '/_next/static/chunks/main-app-0123456789abcdef.js': page(body=chunk)})
        self.assertEqual([(o['product'], o['version'], o['outcome']) for o in found], [('Next.js', '14.1.0', 'found')])
        hidden = self.run_probe('nextjs-version', {'/': page(body=html), '/_next/static/chunks/main-app-0123456789abcdef.js': page(body='nothing')})
        self.assertEqual([(o['version'], o['outcome']) for o in hidden], [('', 'hidden')])

    def test_script_urls_and_banners_give_library_versions(self):
        html = '<script src="/js/jquery-3.4.1.min.js"></script><script src="/js/app.js"></script>'
        found = self.run_probe('html-libraries', {'/': page(body=html), '/js/app.js': page(body='/*! Bootstrap v3.3.7 (https://getbootstrap.com) */')})
        self.assertEqual({(o['product'], o['version']) for o in found}, {('jQuery', '3.4.1'), ('Bootstrap', '3.3.7')})

    def test_the_front_page_reads_headers_modules_edges_and_generators(self):
        front = page(headers={'Server': 'Apache/2.4.6 (CentOS) PHP/5.4.16', 'CF-Ray': 'abc-AMS', 'X-AspNet-Version': '4.0.30319'},
                     body='<meta name="generator" content="Drupal 10 (https://www.drupal.org)">')
        found = self.run_probe('headers-root', {'/': front})
        names = {(o['product'], o['version']) for o in found if o['kind'] == 'version'}
        self.assertTrue({('Apache HTTP Server', '2.4.6'), ('PHP', '5.4.16'), ('.NET Framework CLR', '4.0.30319')} <= names)  # 1.3.5: not "ASP.NET"
        self.assertFalse([o for o in found if o['product'] == 'Drupal' and o['version']])  # "Drupal 10" states no version: a bare major is never evidence
        self.assertEqual([(o['product'], o['outcome']) for o in found if o['kind'] == 'edge'], [('Cloudflare', 'edge')])

    def test_hostile_pages_cannot_inject_names_or_overflow(self):
        found = self.run_probe('headers-root', {'/': page(headers={'Server': 'nginx/1.2 ' + 'Z' * 9000}, body='<meta name="generator" content="' + 'x' * 5000 + '">')})
        self.assertTrue(all(len(o['product']) <= 120 for o in found))
class WordPressProbeTests(SimpleTestCase):
    def detect(self, table, base='https://www.rt.test'):
        found = probes.run_http_probe('wordpress-detect', base, {'www.rt.test', 'rt.test'}, get=answers(table), sleep=lambda s: None)
        return found[0]

    def test_a_header_only_signature_is_a_positive_detection(self):
        link = {'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}
        found = self.detect({'/': page(200, headers=link, body='<html>welcome</html>')})
        self.assertEqual((found['outcome'], found['source']), ('found', 'header:link-api.w.org'))

    def test_the_login_page_the_rest_api_and_the_generator_each_detect_it(self):
        self.assertEqual(self.detect({'/wp-login.php': page(body='<form id="loginform">')})['outcome'], 'found')
        self.assertEqual(self.detect({'/wp-json/': page(401, body='{"code":"rest_forbidden","message":"x"}')})['outcome'], 'found')
        found = self.detect({'/': page(body='<meta name="generator" content="WordPress 6.4.2">'), '/readme.html': page(body='WordPress Version 6.4.2')})
        self.assertEqual((found['outcome'], found['version']), ('found', '6.4.2'))

    def test_an_edge_that_challenges_every_request_is_recorded_as_challenged_with_a_hint(self):
        challenge = page(403, body='<title>Just a moment...</title> cloudflare _cf_chl_opt')
        challenge['challenge'] = 'Cloudflare'
        found = self.detect({'/': challenge, '/wp-login.php': challenge, '/wp-json/': challenge})
        self.assertEqual(found['outcome'], 'challenged')
        self.assertIn('Allow the scanner', found['evidence']['hint'])

    def test_a_clean_site_that_is_not_wordpress_is_absent(self):
        found = self.detect({'/': page(body='<html>plain</html>')})
        self.assertEqual(found['outcome'], 'absent')

    def test_challenge_detection(self):
        self.assertEqual(probes.challenge_of(page(403, headers={'cf-mitigated': 'challenge'})), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(200, body='<h1>Just a moment...</h1> cloudflare')), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(503, headers={'server': 'cloudflare'}, title='')), 'Cloudflare')
        self.assertEqual(probes.challenge_of(page(404, headers={'server': 'nginx'})), '')
class FetchTests(SimpleTestCase):
    def test_redirects_stay_inside_the_group_and_the_gate(self):
        calls = []

        def fake(url, _policy=None, **kwargs):
            calls.append((url, kwargs.get('browser')))
            if url == 'https://rt.test/':
                return {**page(301, url=url), 'location': 'https://www.rt.test/'}
            if url == 'https://www.rt.test/':
                return {**page(301, url=url), 'location': 'https://elsewhere.example/'}
            return page(200, url=url)
        got = probes.fetch('https://rt.test/', POLICY, probe=fake, sleep=lambda s: None, allowed={'rt.test', 'www.rt.test'})
        self.assertEqual([c[0] for c in calls], ['https://rt.test/', 'https://www.rt.test/'])
        self.assertTrue(all(c[1] for c in calls))  # browser-like headers
        self.assertEqual(got['final_url'], 'https://www.rt.test/')

    def test_a_destination_outside_the_policy_is_refused_before_any_request(self):
        probe = mock.Mock()
        with self.assertRaises(ValueError):
            probes.fetch('https://elsewhere.example/', POLICY, probe=probe, sleep=lambda s: None)
        probe.assert_not_called()

    def test_an_edge_challenge_is_returned_at_once_and_never_pushed_against(self):
        challenge = {**page(503, headers={'server': 'cloudflare', 'cf-ray': 'x'}, title=''), 'challenge': ''}
        probe = mock.Mock(return_value=challenge)
        pauses = []
        got = probes.fetch('https://rt.test/', POLICY, probe=probe, sleep=pauses.append)
        self.assertEqual((probe.call_count, pauses), (1, []))
        self.assertEqual(got['challenge'], 'Cloudflare')

    def test_a_plain_try_later_is_asked_again_once_after_a_pause(self):
        probe = mock.Mock(return_value=page(503, headers={'server': 'nginx'}))
        pauses = []
        got = probes.fetch('https://rt.test/', POLICY, probe=probe, sleep=pauses.append)
        self.assertEqual(probe.call_count, len(probes.RETRY_DELAYS) + 1)
        self.assertEqual(pauses, list(probes.RETRY_DELAYS))
        self.assertEqual(got['challenge'], '')

    def test_a_redirect_to_an_excluded_name_is_not_followed(self):
        redirect = {**page(301), 'location': 'https://rt.test/'}
        probe = mock.Mock(return_value=redirect)
        policy = ScopePolicy({'domains': ['rt.test'], 'excluded': ['rt.test']}, internal=False)
        with self.assertRaises(ValueError):
            probes.fetch('https://www.rt.test/', policy, probe=probe, sleep=lambda s: None, allowed={'www.rt.test', 'rt.test'})
