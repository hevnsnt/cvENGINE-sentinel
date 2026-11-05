"""Ported from cvENGINE's web/tests/test_js_libraries_provenance.py (its tests that need no database), run against the library copy."""
import os
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import js_libraries, version_probes as probes
from cvengine_scanner.probes.policy import ScopePolicy
from cvengine_scanner.tests.probes.test_js_library_versions import JQ_371_MIN, NoCache
from cvengine_scanner.tests.probes.test_probes import answers, page
WORDPRESS_PAGE = ('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
                  '<script src="/wp-content/themes/acme/js/jquery.fancybox.js?ver=1.0.4"></script>'
                  '<script src="/wp-content/plugins/forms/js/forms.min.js?ver=3.2.1"></script>')
FANCYBOX = '/*! fancyBox v2.1.5 fancyapps.com | fancyapps.com/fancybox/#license */\n(function(r,G,f,v){})(window,document,jQuery);'
FANCYBOX_STRIPPED = '(function(r,G,f,v){})(window,document,jQuery);'
WP_BODIES = {'/wp-includes/js/jquery/jquery.min.js': JQ_371_MIN, '/wp-content/themes/acme/js/jquery.fancybox.js': FANCYBOX_STRIPPED}
class RedirectProbeTests(NoCache, SimpleTestCase):
    """2: the probes follow a redirect inside the host's group (apex and www); what the page they land on loads is not the alias's."""

    TARGET = {'/': page(body='<script src="/js/jquery-3.2.1.min.js"></script><script src="/js/bootstrap.min.js?ver=1.0.4"></script>',
                        url='https://rt.test/', headers={'Server': 'nginx/1.24.0'}),
              '/js/jquery-3.2.1.min.js': page(body='/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */',
                                              url='https://rt.test/js/jquery-3.2.1.min.js')}

    def run_probe(self, probe_id, base, table):
        return probes.run_http_probe(probe_id, base, {'blog.rt.test', 'rt.test', 'www.rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_the_libraries_probe_records_nothing_for_a_host_that_redirected_elsewhere(self):
        self.assertEqual([o for o in self.run_probe('html-libraries', 'https://blog.rt.test', self.TARGET) if o['kind'] == 'version'], [])

    def test_the_headers_probe_records_nothing_of_the_page_another_host_served(self):
        found = self.run_probe('headers-root', 'https://blog.rt.test', self.TARGET)
        self.assertEqual([o for o in found if js_libraries.is_library(o['product'])], [])
        self.assertNotIn('nginx', {o['product'] for o in found})  # the target's Server header is the target's, too

    def test_the_host_the_page_belongs_to_records_its_libraries(self):
        found = self.run_probe('html-libraries', 'https://rt.test', self.TARGET)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
        found = self.run_probe('headers-root', 'https://rt.test', self.TARGET)
        self.assertIn(('jQuery', '3.2.1'), {(o['product'], o['version']) for o in found})

    def test_through_the_real_redirect_following_fetch(self):
        def probe_url(url, _policy=None, **_kw):
            if url == 'https://blog.rt.test/':
                return {'status': 301, 'location': 'https://rt.test/', 'body': '', 'url': url, 'headers': {'server': 'cloudflare'},
                        'server': 'cloudflare', 'powered_by': '', 'content_type': 'text/html', 'title': '301 Moved Permanently'}
            path = '/' + url.split('://', 1)[1].split('/', 1)[1]
            return {**self.TARGET.get(path, page(404, body='not found')), 'url': url}

        policy = ScopePolicy({'domains': ['rt.test']}, internal=False)

        def get(url, **kw):
            return probes.fetch(url, policy, probe=probe_url, sleep=lambda s: None, allowed={'blog.rt.test', 'rt.test', 'www.rt.test'})
        alias = probes.run_http_probe('html-libraries', 'https://blog.rt.test', set(), policy, get=get, sleep=lambda s: None)
        target = probes.run_http_probe('html-libraries', 'https://rt.test', set(), policy, get=get, sleep=lambda s: None)
        self.assertEqual([o for o in alias if o['kind'] == 'version'], [])
        self.assertEqual([(o['product'], o['version']) for o in target if o['version']], [('jQuery', '3.2.1')])
        headers = probes.run_http_probe('headers-root', 'https://blog.rt.test', set(), policy, get=get, sleep=lambda s: None)
        products = {o['product'] for o in headers if o['kind'] == 'version'}
        self.assertIn('Cloudflare', products)  # what the alias's own redirect answer says about itself stays
        self.assertFalse(products & {'nginx', 'jQuery', 'Bootstrap'}, products)  # the page it leads to is not its

    def test_a_redirect_inside_the_same_host_still_records_the_page(self):
        table = {'/': {**self.TARGET['/'], 'final_url': 'https://blog.rt.test/en/', 'url': 'https://blog.rt.test/en/'},
                 '/js/jquery-3.2.1.min.js': self.TARGET['/js/jquery-3.2.1.min.js']}
        found = self.run_probe('html-libraries', 'https://blog.rt.test', table)
        self.assertEqual([(o['product'], o['version']) for o in found if o['version']], [('jQuery', '3.2.1')])
CONTRA = '<script src="/js/jquery.min.js"></script><script src="/site.js?ver=1.12.4"></script>'
ORACLE = os.path.join(os.path.dirname(__file__), 'fixtures', 'js_provenance')
def oracle(name):
    with open(os.path.join(ORACLE, name), encoding='utf-8') as handle:
        return handle.read()
def synthesized_page(key, cut):
    """A live front page rebuilt from its script tags at their original byte offsets (everything else is padding), as the route check reads
    it: the first ``cut`` bytes, marked truncated when the page is longer."""
    import json
    with open(os.path.join(ORACLE, 'front-page-script-offsets.json'), encoding='utf-8') as handle:
        page = json.load(handle)[key]
    body = bytearray(b' ' * page['size'])
    for offset, tag in page['scripts']:
        raw = tag.encode('utf-8')
        body[offset:offset + len(raw)] = raw
    body = bytes(body)
    return {'body': body[:cut].decode('utf-8', 'ignore'), 'bytes': min(len(body), cut), 'read_limit': cut, 'truncated': len(body) > cut}

