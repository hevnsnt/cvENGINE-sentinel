"""The read-only and own-target rules a Sentinel applies to an AI-written or approved nuclei template before it runs one (``cvengine_scanner.checks``).

The corpus (``fixtures/checks/corpus.json``) is shared with the cvENGINE server, whose own read-only check (``cveFeed.validation.readonly_problem``)
must give the same verdict on every case (its ``tests.test_ai_checks_on_sentinels``)."""
import hashlib
import json
import unittest

from cvengine_scanner import check_allowlist, checks, contract

CORPUS = json.loads((contract.FIXTURES / 'checks' / 'corpus.json').read_text(encoding='utf-8'))['cases']


class CorpusTests(unittest.TestCase):
    def test_the_corpus_covers_both_verdicts_of_both_rules(self):
        self.assertGreaterEqual(len(CORPUS), 30)
        self.assertEqual({c['read_only'] for c in CORPUS}, {True, False})
        self.assertEqual({c['own_target'] for c in CORPUS}, {True, False})
        self.assertFalse([c['name'] for c in CORPUS if c['own_target'] and not c['read_only']])  # own target is checked on read-only text only

    def test_the_read_only_verdict_of_every_case(self):
        for case in CORPUS:
            with self.subTest(case=case['name']):
                problem = checks.readonly_problem(case['template'])
                self.assertEqual(problem == '', case['read_only'], problem)
                if problem:
                    self.assertTrue(problem.startswith('template not validated: '), problem)

    def test_the_own_target_verdict_of_every_case(self):
        for case in CORPUS:
            with self.subTest(case=case['name']):
                self.assertEqual(checks.check_problem(case['template']) == '', case['read_only'] and case['own_target'] and case['sentinel'])

    def test_the_sentinel_verdict_of_every_case(self):
        # the whole rule a Sentinel other than the built-in scanner applies: read-only, own target and port, and the allowlist (D1, D2)
        for case in CORPUS:
            with self.subTest(case=case['name']):
                problem = checks.check_problem(case['template'])
                self.assertEqual(problem == '', case['sentinel'], problem)
                self.assertEqual(check_allowlist.allowlist_problem(case['template']) == '' or not case['sentinel'], True)
                if case['sentinel']:
                    self.assertTrue(case['read_only'] and case['own_target'], case['name'])  # the allowlist only ever narrows

    def test_a_literal_port_or_a_port_key_aims_at_another_port(self):
        for name in ('network_literal_port', 'network_port_key'):
            case = next(c for c in CORPUS if c['name'] == name)
            with self.subTest(case=name):
                self.assertEqual(checks.readonly_problem(case['template']), '')
                self.assertIn('port', checks.scope_problem(case['template']))


HOSTILE = ('resolve_in_header', 'resolve_in_dsl_matcher', 'resolve_in_dsl_extractor', 'resolve_in_variable', 'resolve_bare_in_variable',
           'resolve_in_word_matcher', 'resolve_nested_in_allowed_helper', 'resolve_in_info', 'jarm_in_dsl', 'wait_for_in_dsl', 'public_ip_in_header',
           'print_debug_in_dsl', 'unix_time_in_header', 'rand_base_in_header', 'unknown_helper_in_dsl', 'member_access_in_dsl', 'section_sign_marker',
           'unclosed_expression', 'expression_split_by_yaml_folding', 'expression_split_in_folded_block', 'anchor_and_alias_for_a_header', 'merge_key',
           'second_document', 'document_end_then_more', 'duplicate_method_key', 'duplicate_top_key', 'explicit_tag', 'yaml_directive',
           'yaml11_word_value', 'yaml11_octal_value', 'unicode_lookalike_key', 'unicode_line_separator', 'case_variant_key', 'unknown_block_key',
           'json_extractor', 'raw_get_with_body', 'raw_get_with_body_no_length', 'raw_two_requests', 'raw_at_host_annotation', 'raw_annotation_after_request_line',
           'raw_host_literal_port', 'raw_transfer_encoding', 'raw_cookie', 'raw_http2', 'host_header', 'authorization_header', 'cookie_header',
           'api_key_header_name', 'credential_value_in_plain_header', 'jwt_value_in_header', 'x_forwarded_for_header', 'method_override_header',
           'lowercase_method')


class AllowlistTests(unittest.TestCase):
    """D1 and D2 of the second security review: the hostile corpus, one case per trick, every one refused by the Sentinel's whole rule."""

    def test_every_hostile_case_is_in_the_corpus_and_refused(self):
        by_name = {c['name']: c for c in CORPUS}
        for name in HOSTILE:
            with self.subTest(case=name):
                self.assertIn(name, by_name)
                self.assertFalse(by_name[name]['sentinel'])
                self.assertTrue(checks.check_problem(by_name[name]['template']).startswith('template not validated: '))

    def test_resolve_is_refused_in_every_position_with_the_reason(self):
        for case in CORPUS:
            if case['name'].startswith('resolve_') and case['read_only']:
                with self.subTest(case=case['name']):
                    self.assertIn('resolve', check_allowlist.allowlist_problem(case['template']))

    def test_only_listed_helpers_are_callable(self):
        for name in sorted(check_allowlist.FUNCTIONS):
            with self.subTest(helper=name):
                self.assertEqual(check_allowlist.expression_problem(f"{name}(body, 'a')"), '')
        for name in ('resolve', 'jarm', 'public_ip', 'publicip', 'wappalyzer', 'llm_prompt', 'wait_for', 'print_debug', 'unix_time', 'date_time',
                     'to_unix_time', 'rand_base', 'rand_int', 'rand_ip', 'repeat', 'gzip_decode', 'zlib_decode', 'inflate', 'generate_java_gadget',
                     'generate_jwt', 'env', 'file', 'getNetworkPort', 'ip_format'):
            with self.subTest(helper=name):
                self.assertIn(f'{name}()', check_allowlist.expression_problem(f"{name}('x')"))

    def test_a_name_must_be_a_placeholder_a_response_part_or_the_templates_own(self):
        self.assertEqual(check_allowlist.expression_problem('status_code_2 == 200 && contains(body_1, x)', frozenset({'x'})), '')
        self.assertIn("'x'", check_allowlist.expression_problem('contains(body, x)'))
        self.assertIn("'interactsh'", check_allowlist.expression_problem('interactsh-url'))
        for expr in ('body.Len()', 'body[0]', '{body}', '`x`', '$x', 'a; b'):
            with self.subTest(expr=expr):
                self.assertNotEqual(check_allowlist.expression_problem(expr), '')


class BoundsTests(unittest.TestCase):
    def test_empty_oversized_or_binary_text_is_refused(self):
        good = next(c for c in CORPUS if c['name'] == 'plain_get')['template']
        self.assertEqual(checks.check_problem(good), '')
        for text in ('', None, good + '#' * checks.MAX_TEMPLATE_BYTES, good + '\0'):
            with self.subTest(size=len(text or '')):
                self.assertNotEqual(checks.readonly_problem(text), '')

    def test_the_digest_is_the_sha256_of_the_utf8_text(self):
        text = 'id: x\ninfo:\n  name: caf\u00e9\n'
        self.assertEqual(checks.digest(text), hashlib.sha256(text.encode('utf-8')).hexdigest())
        self.assertTrue(checks.SHA256.match(checks.digest(text)))
        self.assertFalse(checks.SHA256.match('A' * 64))


if __name__ == '__main__':
    unittest.main()
