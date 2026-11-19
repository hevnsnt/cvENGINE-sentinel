"""Version tells in the pages the version probes already fetch: the error page's footers (Apache's whole banner, JBoss Web), the Server
header's own releases, generator tags that name two products (MkDocs) or only a line (Ghost), and Vue 3's bundle banner. Real-shaped samples,
and the look-alikes that must give nothing."""
import unittest

from cvengine_scanner import fingerprint, versions
from cvengine_scanner.probes import js_libraries, version_probes


def page(body='', title='', headers=None):
    return {'status': 404, 'body': body, 'title': title, 'headers': headers or {}}


def read_error_page(body, title=''):
    return [(o['product'], o['version'], o['outcome']) for o in version_probes.apply_rules(version_probes.BY_ID['error-page'], [page(body, title)])
            if o['kind'] == 'version']


class ErrorPageTests(unittest.TestCase):
    def test_apache_footer_with_modules_names_each_release(self):
        body = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n'
                '<p>The requested URL was not found on this server.</p>\n<hr>\n<address>Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 '
                'PHP/7.4.33 Server at www.example.com Port 443</address>\n</body></html>\n')
        self.assertEqual(read_error_page(body), [('Apache HTTP Server', '2.4.6', 'found'), ('OpenSSL', '1.0.2k', 'found'), ('PHP', '7.4.33', 'found')])

    def test_apache_footer_with_a_distribution_only(self):
        body = '<hr>\n<address>Apache/2.4.57 (Debian) Server at www.example.org Port 80</address>\n'
        self.assertEqual(read_error_page(body), [('Apache HTTP Server', '2.4.57', 'found')])

    def test_apache_footer_names_python_only_with_a_whole_release(self):
        self.assertEqual(read_error_page('<address>Apache/2.4.29 (Ubuntu) mod_wsgi/4.5.17 Python/3.6 Server at x Port 80</address>'),
                         [('Apache HTTP Server', '2.4.29', 'found')])
        self.assertIn(('Python', '3.11.4', 'found'),
                      read_error_page('<address>Apache/2.4.62 (Unix) mod_wsgi/5.0.0 Python/3.11.4 Server at x Port 80</address>'))

    def test_a_product_token_footer_states_no_release(self):
        self.assertEqual(read_error_page('<hr>\n<address>Apache Server at www.example.org Port 80</address>'), [])

    def test_a_page_that_mentions_openssl_outside_the_footer_gives_no_openssl(self):
        body = '<p>We upgraded to OpenSSL/3.0.13 last week.</p><address>Apache/2.4.58 (Ubuntu) Server at x Port 443</address>'
        self.assertEqual(read_error_page(body), [('Apache HTTP Server', '2.4.58', 'found')])

    def test_jboss_web_footers(self):
        as7 = ('<html><head><title>JBoss Web/7.0.13.Final - Error report</title></head><body><h1>HTTP Status 404 - /cvengine</h1>'
               '<HR size="1" noshade="noshade"><p><b>type</b> Status report</p><HR size="1" noshade="noshade"><h3>JBoss Web/7.0.13.Final</h3></body></html>')
        self.assertEqual(read_error_page(as7), [('JBoss Web', '7.0.13', 'found')])
        self.assertEqual(read_error_page('<HR size="1" noshade="noshade"><h3>JBossWeb/2.0.1.GA</h3></body></html>'), [('JBoss Web', '2.0.1', 'found')])
        self.assertEqual(read_error_page('<h3>JBoss Web</h3>'), [])

    def test_a_jboss_lead_asks_for_the_error_page(self):
        self.assertIn('jboss', version_probes.BY_ID['error-page']['leads'])


class ServerHeaderTests(unittest.TestCase):
    def test_servers_that_state_their_own_release(self):
        cases = {'Werkzeug/3.0.1 Python/3.12.1': ['Werkzeug:3.0.1', 'Python:3.12.1'], 'TornadoServer/6.4': ['Tornado:6.4'],
                 'CherryPy/18.9.0': ['CherryPy:18.9.0'], 'CouchDB/3.3.3 (Erlang OTP/25)': ['Apache CouchDB:3.3.3'], 'squid/5.7': ['Squid:5.7'],
                 'Allegro-Software-RomPager/4.07 UPnP/1.0': ['RomPager:4.07'], 'thttpd/2.29 23May2018': ['thttpd:2.29'],
                 'mini_httpd/1.30 26Oct2018': ['mini_httpd:1.30'], 'Boa/0.94.14rc21': ['Boa:0.94.14rc21'],
                 'WEBrick/1.8.1 (Ruby/3.2.2/2023-03-30)': ['WEBrick:1.8.1'], 'Resin/4.0.66': ['Resin:4.0.66'], 'Tengine/2.3.3': ['Tengine:2.3.3'],
                 'Cherokee/1.2.104 (Ubuntu)': ['Cherokee:1.2.104']}
        for header, want in cases.items():
            with self.subTest(header=header):
                self.assertEqual([c['name'] for c in versions.parse_server_header(header)['components']], want)

    def test_a_bare_name_or_a_major_is_no_release(self):
        self.assertEqual([c['name'] for c in versions.parse_server_header('Werkzeug')['components']], ['Werkzeug'])
        self.assertEqual([c['name'] for c in versions.parse_server_header('TornadoServer/6')['components']], ['Tornado'])


class GeneratorTests(unittest.TestCase):
    def test_mkdocs_names_itself_and_its_material_theme(self):
        html = '<meta name="generator" content="mkdocs-1.5.3, mkdocs-material-9.4.8">'
        self.assertEqual(versions.generator_tags(html), [('MkDocs', '1.5.3'), ('Material for MkDocs', '9.4.8')])
        self.assertEqual(versions.generator_tags('<meta name="generator" content="mkdocs-1.6.0, readthedocs-1.6.0">'), [('MkDocs', '1.6.0')])

    def test_generators_that_state_a_line_keep_the_product_without_a_version(self):
        for content, product in (('Ghost 5.75', 'Ghost'), ('Joomla! 1.5 - Open Source Content Management', 'Joomla'), ('TYPO3 4.5 CMS', 'TYPO3')):
            with self.subTest(content=content):
                self.assertEqual(versions.generator_tags(f'<meta name="generator" content="{content}">'), [(product, '')])

    def test_static_site_and_wiki_generators_that_state_their_release(self):
        cases = {'Hugo 0.120.4': ('Hugo', '0.120.4'), 'Gatsby 5.12.4': ('Gatsby', '5.12.4'), 'Docusaurus v3.0.1': ('Docusaurus', '3.0.1'),
                 'Jekyll v4.3.2': ('Jekyll', '4.3.2'), 'MediaWiki 1.41.0': ('MediaWiki', '1.41.0'),
                 'Discourse 3.2.0.beta4 - https://github.com/discourse/discourse version 1b0e5b4': ('Discourse', '3.2.0.beta4'),
                 'Drupal 10 (https://www.drupal.org)': ('Drupal', '10'), 'Odoo': ('Odoo', ''), 'DokuWiki': ('DokuWiki', ''),
                 'Plone - https://plone.org/': ('Plone', '')}
        for content, want in cases.items():
            with self.subTest(content=content):
                self.assertEqual(versions.generator_tags(f'<meta name="generator" content="{content}">'), [want])

    def test_the_fingerprint_keeps_only_whole_releases(self):
        html = ('<html><head><meta name="generator" content="Drupal 10 (https://www.drupal.org)"><meta name="generator" content="Ghost 5.75">'
                '<meta name="generator" content="mkdocs-1.5.3, mkdocs-material-9.4.8"></head></html>')
        names = [f['name'] for f in fingerprint.from_response(body=html, content_type='text/html')]
        self.assertEqual(names, ['Drupal', 'Ghost', 'MkDocs:1.5.3', 'Material for MkDocs:9.4.8'])


class VueBannerTests(unittest.TestCase):
    BANNER = '/**\n* @vue/runtime-dom v3.4.21\n* (c) 2018-present Yuxi (Evan) You and Vue contributors\n* @license MIT\n**/\n'

    def test_vue_3_package_banners_name_the_release(self):
        self.assertEqual(js_libraries.read_body(self.BANNER + 'var e=1;'), [('vue', '3.4.21', 'banner')])
        self.assertEqual(js_libraries.read_body(self.BANNER.replace('@vue/runtime-dom', 'vue')), [('vue', '3.4.21', 'banner')])

    def test_a_vue_3_banner_deep_in_a_bundle_is_found_by_the_whole_body_search(self):
        bundle = 'var a=' + '1,' * 3000 + '2;\n' + self.BANNER + 'function makeMap(){}'
        self.assertIn(('vue', '3.4.21'), {(k, v) for k, v, _how in js_libraries.whole_body(bundle)['versions']})

    def test_a_lookalike_banner_is_not_vue(self):
        self.assertEqual(js_libraries.read_body('/**\n* vue v3.4.21 port by someone\n*/'), [])
        self.assertEqual(js_libraries.read_body('/**\n* @vue/devtools v6.5.0\n* (c) 2018-present Yuxi (Evan) You and Vue contributors\n**/'), [])


if __name__ == '__main__':
    unittest.main()
