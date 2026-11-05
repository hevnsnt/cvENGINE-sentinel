"""What one response says it runs (``cvengine_scanner.fingerprint``): headers, the generator tag, page markers, and the order, de-duplication
and cap of the names. Ported from the cvENGINE server's tests (tests.test_host_record, tests.test_cms_products, tests.test_pipeline_limits)."""
import time
import unittest

from cvengine_scanner import fingerprint

DRUPAL_PAGE = ('<html><head><meta name="Generator" content="Drupal 10 (https://www.drupal.org)">'
               '<script src="/core/assets/vendor/jquery/jquery.min.js?v=3.7.1"></script>'
               '<script src="/core/misc/drupal.js?v=10.2.3"></script></head><body>x</body></html>')
JOOMLA_PAGE = '<html><head><meta name="generator" content="Joomla! - Open Source Content Management"><script src="/media/system/js/core.js?abc"></script></head></html>'
MAGENTO_PAGE = '<html><head><link rel="stylesheet" href="/static/version1700000000/frontend/Magento/luma/en_US/css/styles-m.css"></head></html>'
TYPO3_PAGE = '<html><head><link rel="stylesheet" href="/typo3temp/assets/compressed/merged-1.css"></head></html>'



def names(found):
    return [f['name'] for f in found]


def page_names(body, headers=None):
    return names(fingerprint.from_response(body=body, content_type='text/html', headers=headers or {}))


class FingerprintTests(unittest.TestCase):
    def test_a_netlify_nextjs_site(self):
        found = fingerprint.from_response(server='Netlify', content_type='text/html', body='<script id="__NEXT_DATA__"></script>')
        self.assertEqual(names(found), ['Netlify', 'Next.js'])
        self.assertEqual([f['source'] for f in found], ['header:server', 'page:_next'])

    def test_server_and_powered_by_headers_carry_versions(self):
        found = fingerprint.from_response(server='nginx/1.25.3 (Ubuntu)', powered_by='PHP/8.2.30')
        self.assertEqual(names(found), ['nginx:1.25.3', 'PHP:8.2.30'])
        self.assertEqual(names(fingerprint.from_response(server='Apache/2.4.58 (Ubuntu)')), ['Apache HTTP Server:2.4.58'])
        self.assertEqual(names(fingerprint.from_response(server='Microsoft-IIS/10.0')), ['Microsoft IIS:10.0'])

    def test_several_powered_by_values(self):
        self.assertEqual(names(fingerprint.from_response(server='cloudflare', powered_by='Craft CMS, SEOmatic')),
            ['Cloudflare', 'Craft CMS', 'SEOmatic'])

    def test_generator_meta_and_wordpress_paths(self):
        body = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/x.css">'
        self.assertEqual(names(fingerprint.from_response(body=body, content_type='text/html')), ['WordPress:6.4.2'])

    def test_a_php_link_names_php_and_a_header_version_replaces_it(self):
        body = '<a href="/index.php?x=1">x</a>'
        self.assertEqual(names(fingerprint.from_response(body=body, content_type='text/html')), ['PHP'])
        found = fingerprint.from_response(powered_by='PHP/8.2.30', body=body, content_type='text/html')
        self.assertEqual(names(found), ['PHP:8.2.30'])

    def test_a_page_with_no_php_signs_names_no_php(self):
        body = '<script src="/_next/static/a.js"></script><img src="https://www.datocms-assets.com/1/a.png">'
        self.assertNotIn('PHP', ' '.join(names(fingerprint.from_response(server='Netlify', body=body, content_type='text/html'))))

    def test_a_hostile_header_cannot_inject_a_name(self):
        for value in ('<script>alert(1)</script>/9', 'x' * 80, 'a"b', 'Robert\'); DROP TABLE'):
            self.assertEqual(names(fingerprint.from_response(powered_by=value)), [], value)
        found = fingerprint.from_response(server='nginx/1.2<b>', powered_by='')
        for name in names(found):
            self.assertNotRegex(name, r'[<>"\']')

    def test_names_are_capped(self):
        body = ''.join(f'<meta name="x{i}">' for i in range(100)) + '__NEXT_DATA__ /_nuxt/ /wp-content/ Drupal.settings cdn.shopify.com csrfmiddlewaretoken .php'
        self.assertLessEqual(len(fingerprint.from_response(server='Netlify', powered_by=', '.join(f'P{i}' for i in range(50)), body=body, content_type='text/html')),
            fingerprint.MAX_FINGERPRINTS)

    def test_a_body_that_is_not_html_is_not_searched(self):
        self.assertEqual(fingerprint.from_response(body='/wp-content/', content_type='application/json'), [])

    def test_categories(self):
        self.assertEqual(fingerprint.categorize('PHP:8.2.30'), 'language')
        self.assertEqual(fingerprint.categorize('nginx:1.25.3'), 'web server')
        self.assertEqual(fingerprint.categorize('Next.js'), 'framework')
        self.assertEqual(fingerprint.categorize('google-tag-manager'), 'analytics')
        self.assertEqual(fingerprint.categorize('datocms'), 'cms')
        self.assertEqual(fingerprint.categorize('Netlify'), 'hosting')
        self.assertEqual(fingerprint.categorize('mystery'), '')


    def test_script_names_the_caller_read_join_in_order_and_a_versioned_one_replaces_the_bare_name(self):
        found = fingerprint.from_response(server='nginx', body='<html>/wp-content/</html>', content_type='text/html',
                                          from_scripts=[('jQuery', 'script:filename'), ('jQuery:3.5.1', 'script:body')])
        self.assertEqual(names(found), ['nginx', 'WordPress', 'jQuery:3.5.1'])
        self.assertEqual(found[-1]['source'], 'script:body')

    def test_extend_keeps_the_first_and_replaces_a_bare_name_with_a_versioned_one(self):
        out = fingerprint.extend([{'name': 'jQuery', 'source': 'x'}], [('jQuery:3.4.1', 'script:banner')])
        self.assertEqual(out, [{'name': 'jQuery:3.4.1', 'source': 'script:banner'}])
        many = fingerprint.extend([], [(f'Lib{i}', 's') for i in range(50)])
        self.assertEqual(len(many), fingerprint.MAX_FINGERPRINTS)

    def test_versioned_needs_a_dotted_number(self):
        self.assertEqual(fingerprint.versioned('Drupal', '10'), 'Drupal')
        self.assertEqual(fingerprint.versioned('Drupal', '10.2.3'), 'Drupal:10.2.3')
        self.assertEqual(fingerprint.versioned('<>', '1.0'), '')


class MarkerTests(unittest.TestCase):
    def test_each_cms_names_itself_from_a_front_page(self):
        self.assertIn('Joomla', page_names(JOOMLA_PAGE))
        self.assertIn('Magento', page_names(MAGENTO_PAGE))
        self.assertIn('TYPO3', page_names(TYPO3_PAGE))
        self.assertTrue(any(n.startswith('Drupal') for n in page_names(DRUPAL_PAGE)))

    def test_a_page_that_only_mentions_a_path_in_text_is_not_that_cms(self):
        text = '<html><body><p>Our migration guide: move your files from /typo3conf/ and /skin/frontend/ to the new theme.</p></body></html>'
        found = page_names(text)
        self.assertNotIn('TYPO3', found)
        self.assertNotIn('Magento', found)

    def test_a_bare_major_in_the_generator_is_no_version(self):
        self.assertNotIn('Drupal:10', page_names(DRUPAL_PAGE))

    def test_version_headers_name_umbraco_and_magento(self):
        found = names(fingerprint.from_response(headers={'x-umbraco-version': '13.4.1', 'x-magento-tags': 'cms_b'}))
        self.assertIn('Umbraco:13.4.1', found)
        self.assertIn('Magento', found)


class BodyRegexTests(unittest.TestCase):
    def timed(self, fn):
        started = time.monotonic()
        result = fn()
        self.assertLess(time.monotonic() - started, 1.5)
        return result

    def test_pathological_pages_are_read_in_linear_time(self):
        for tag in ('<meta ', '<script ', '<input ', '<meta name="generator" '):
            body = tag * (64 * 1024 // len(tag))
            self.timed(lambda: fingerprint.from_response(body=body, content_type='text/html'))
            self.timed(lambda: fingerprint.script_srcs(body))

    def test_real_markup_still_matches(self):
        html = '<html><head><meta name="generator" content="WordPress 6.4.2"><script src="/js/jquery-3.6.0.min.js"></script></head></html>'
        self.assertEqual(fingerprint.generator_content(html), 'WordPress 6.4.2')
        self.assertEqual(fingerprint.generator_content('<meta content="Drupal 10" name="generator">'), 'Drupal 10')
        self.assertEqual(fingerprint.script_srcs(html), ['/js/jquery-3.6.0.min.js'])


if __name__ == '__main__':
    unittest.main()
