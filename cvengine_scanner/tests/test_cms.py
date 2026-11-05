"""Where a CMS states its own version (``cvengine_scanner.cms``): the candidates and their order, and which of two versions of a one-per-host
core the evidence disproves. Ported from the cvENGINE server's tests (tests.test_cms, tests.test_cms_products, tests.test_cms_resolver)."""
import unittest

from cvengine_scanner import cms

HEAD = (
    "<link rel='stylesheet' href='https://rt.test/wp-content/themes/t/main.css?ver=1790752965' />\n"
    "<script src='https://rt.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/dom-ready.min.js?ver=3'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/i18n.min.js?ver=1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/a11y.min.js?ver=31'></script>\n"
    "<link rel='stylesheet' href='https://rt.test/wp-content/plugins/gravityforms/css/a.css?ver=3.2.1' />\n")
EMOJI = '{"source":{"concatemoji":"https://rt.test/wp-includes/js/wp-emoji-release.min.js?ver=7.1.4"}}'
FILLER = '<div>' + 'x' * 70_000 + '</div>\n'   # the core version sits in the footer of a large page, past the 64 KB a marker is read from



def page(status=200, body='', headers=None):
    return {'status': status, 'body': body, 'headers': {k.lower(): v for k, v in (headers or {}).items()}}


def front(*parts):
    return page(200, body='<html><head>' + ''.join(parts) + '</head></html>')


def pairs(*names):
    return [tuple(n.partition(':')[::2]) for n in names]


class ReadTests(unittest.TestCase):
    def test_candidates_keep_their_sources_best_first(self):
        found = cms.read('WordPress', [('/', front(EMOJI)), ('/feed/', page(200, body='<generator>https://wordpress.org/?v=7.1.4</generator>'))])
        self.assertEqual([(v, label) for v, label, _c in found], [('7.1.4', 'feed:generator'), ('7.1.4', 'asset:emoji-release')])

    def test_the_core_version_in_the_footer_of_a_large_page_is_read_and_jquerys_is_not(self):
        self.assertEqual(cms.best('WordPress', [('/', front(HEAD, FILLER, EMOJI))]), ('7.1.4', 'asset:emoji-release'))

    def test_a_site_whose_only_versioned_assets_are_libraries_has_no_core_version(self):
        self.assertEqual(cms.best('WordPress', [('/', front(HEAD))]), ('', ''))

    def test_an_asked_source_reads_only_its_own_path(self):
        self.assertEqual(cms.best('WordPress', [('/', page(200, body='Version 6.1.3'))]), ('', ''))
        self.assertEqual(cms.best('WordPress', [('/readme.html', page(200, body='<h1>WordPress<br /> Version 6.1.3</h1>'))]), ('6.1.3', 'readme'))
        self.assertEqual(cms.asked('WordPress'), [('/feed/', [s for s in cms.SOURCES['WordPress'] if s.path == '/feed/']),
                                                  ('/readme.html', [s for s in cms.SOURCES['WordPress'] if s.path == '/readme.html'])])

    def test_a_pre_release_core_script_is_no_version(self):
        self.assertEqual(cms.best('Drupal', [('/', page(200, body='<script src="/core/misc/drupal.js?v=10.3.0-beta1"></script>'))]), ('', ''))
        self.assertEqual(cms.best('Drupal', [('/', page(200, body='<script src="/core/misc/drupal.js?v=10.2.3"></script>'))]),
                         ('10.2.3', 'asset:drupal.js'))

    def test_a_version_header_is_read_from_the_header(self):
        self.assertEqual(cms.best('Vanilla', [('/', page(200, headers={'X-Garden-Version': 'Vanilla 4.0.1'}))]), ('4.0.1', 'header:x-garden-version'))


class DisprovenTests(unittest.TestCase):
    def test_a_core_version_that_is_a_libraries_version_on_the_same_host_is_the_libraries_number(self):
        wrong = cms.disproven(pairs('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1', 'jQuery:3.4.1'))
        self.assertEqual(wrong, {('wordpress', '3.7.1')})

    def test_a_version_a_probe_states_settles_it_and_the_rest_are_dropped(self):
        wrong = cms.disproven(pairs('WordPress:6.4.2', 'WordPress:7.1.4'), attested={'wordpress': {'7.1.4'}})
        self.assertEqual(wrong, {('wordpress', '6.4.2')})

    def test_a_probe_wins_over_a_library_match(self):
        # the attested core happens to equal a library's version: it is still the core
        wrong = cms.disproven(pairs('WordPress:3.7.1', 'WordPress:7.1.4', 'jQuery:3.7.1'), attested={'wordpress': {'3.7.1'}})
        self.assertEqual(wrong, {('wordpress', '7.1.4')})

    def test_a_dispute_nothing_settles_keeps_every_version(self):
        self.assertEqual(cms.disproven(pairs('WordPress:6.4.2', 'WordPress:7.1.4', 'jQuery:3.7.1')), set())

    def test_a_single_version_is_never_dropped_even_when_it_matches_a_library(self):
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1', 'jQuery:3.7.1')), set())

    def test_every_version_that_is_a_library_number_is_left_when_no_other_remains(self):
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1', 'WordPress:3.4.1', 'jQuery:3.7.1', 'jQuery:3.4.1')), set())

    def test_libraries_with_several_versions_are_not_disputes(self):
        self.assertEqual(cms.disproven(pairs('jQuery:3.7.1', 'jQuery:1.2.1', 'Bootstrap:3.3.7', 'Bootstrap:5.3.0')), set())

    def test_the_rule_covers_every_product_with_one_instance_per_host(self):
        wrong = cms.disproven(pairs('Drupal:3.7.1', 'Drupal:10.2.3', 'jQuery:3.7.1', 'MyBB:1.8.38', 'MyBB:3.7.1'))
        self.assertEqual(wrong, {('drupal', '3.7.1'), ('mybb', '3.7.1')})

    def test_a_product_without_a_version_is_ignored(self):
        self.assertEqual(cms.disproven(pairs('WordPress', 'WordPress:7.1.4', 'jQuery:3.7.1')), set())

    def test_a_core_version_a_library_file_states_is_dropped_unless_a_probe_attests_it(self):
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1'), stated={'3.7.1'}), {('wordpress', '3.7.1')})
        self.assertEqual(cms.disproven(pairs('WordPress:3.7.1'), attested={'wordpress': {'3.7.1'}}, stated={'3.7.1'}), set())


if __name__ == '__main__':
    unittest.main()
