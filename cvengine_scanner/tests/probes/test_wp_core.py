"""Ported from cvENGINE's web/tests/test_wp_core.py (its tests that need no database), run against the library copy."""
from unittest import TestCase as SimpleTestCase
from cvengine_scanner.probes import version_probes as probes, wp_core
from cvengine_scanner.tests.probes.test_probes import answers, page
LISTING = '<html><head><title>Index of /wp-content/upgrade</title></head><body><h1>Index of /wp-content/upgrade</h1><a href="?C=N;O=D">Name</a></body></html>'
NGINX_LISTING = '<html><head><title>Index of /wp-content/upgrade/</title></head><body><h1>Index of /wp-content/upgrade/</h1><hr><pre></pre></body></html>'
LOGIN = '<form id="loginform">'
LINK = {'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}
class ClassifyDirTests(SimpleTestCase):
    def test_a_directory_listing_is_recognised(self):
        self.assertEqual(wp_core.classify_dir(page(200, body=LISTING)), wp_core.LISTING)
        self.assertEqual(wp_core.classify_dir(page(200, body=NGINX_LISTING)), wp_core.LISTING)
        self.assertEqual(wp_core.classify_dir(page(200, body='<html><body>[To Parent Directory]<br></body></html>')), wp_core.LISTING)

    def test_an_empty_page_is_wordpresss_own_index_and_says_nothing_denies_the_path(self):
        self.assertEqual(wp_core.classify_dir(page(200, body='')), wp_core.REACHABLE)
        self.assertEqual(wp_core.classify_dir(page(200, body='<?php\n// Silence is golden.\n')), wp_core.REACHABLE)

    def test_a_server_that_answers_every_path_with_an_empty_page_says_nothing(self):
        self.assertEqual(wp_core.classify_dir(page(200, body=''), missing=page(200, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(200, body=''), missing=page(404, body='not found')), wp_core.REACHABLE)

    def test_a_denied_or_absent_directory_is_denied(self):
        for status in (401, 403, 404, 410):
            self.assertEqual(wp_core.classify_dir(page(status, body='no')), wp_core.DENIED, status)

    def test_a_page_a_redirect_a_challenge_or_no_answer_says_nothing(self):
        self.assertEqual(wp_core.classify_dir(page(200, body='<html>' + 'welcome to the site ' * 50 + '</html>')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(301, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(500, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir({**page(200, body=''), 'challenge': 'Cloudflare'}), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(None), wp_core.UNKNOWN_DIR)
class ProbeTests(SimpleTestCase):
    def detect(self, table):
        table = {'/wp-login.php': page(200, headers=LINK, body=LOGIN), **table}
        return probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test', 'rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_a_wordpress_site_is_asked_for_the_upgrade_directory_and_the_wordpress_observation_stays_first(self):
        found = self.detect({'/wp-content/upgrade/': page(200, body=LISTING)})
        self.assertEqual(found[0]['kind'], 'wordpress')
        self.assertEqual((found[1]['kind'], found[1]['variant'], found[1]['outcome']), ('wp-upgrade-dir', 'listing', 'found'))

    def test_a_denied_directory_is_recorded_as_absent(self):
        found = self.detect({'/wp-content/upgrade/': page(403, body='Forbidden')})
        self.assertEqual((found[1]['variant'], found[1]['outcome']), ('denied', 'absent'))



    def test_a_site_that_is_not_wordpress_is_not_asked(self):
        asked = []

        def get(url):
            asked.append(url)
            return page(404, body='not found')
        found = probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test'}, get=get, sleep=lambda s: None)
        self.assertFalse(any('/wp-content/upgrade' in u for u in asked))
        self.assertEqual([o['kind'] for o in found], ['wordpress'])
        self.assertEqual(found[0]['outcome'], 'absent')

