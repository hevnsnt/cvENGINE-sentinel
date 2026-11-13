"""The read-only and own-target rules a Sentinel applies to an AI-written or approved nuclei template before it runs one (``cvengine_scanner.checks``).

The corpus (``fixtures/checks/corpus.json``) is shared with the cvENGINE server, whose own read-only check (``cveFeed.validation.readonly_problem``)
must give the same verdict on every case (its ``tests.test_ai_checks_on_sentinels``)."""
import hashlib
import json
import unittest
from unittest import mock

import yaml

from cvengine_scanner import check_allowlist, checks, contract

CORPUS = json.loads((contract.FIXTURES / 'checks' / 'corpus.json').read_text(encoding='utf-8'))['cases']


class CorpusTests(unittest.TestCase):
    def test_the_corpus_covers_both_verdicts_of_both_rules(self):
        self.assertGreaterEqual(len(CORPUS), 30)
        self.assertEqual({c['read_only'] for c in CORPUS}, {True, False})
        self.assertEqual({c['own_target'] for c in CORPUS}, {True, False})
        self.assertFalse([c['name'] for c in CORPUS if c['own_target'] and not c['read_only']])  # own target is checked on read-only text only

    def test_credential_problem_names_the_header_and_the_read_only_rule_includes_it(self):
        cases = {c['name']: c['template'] for c in CORPUS}
        for name in ('credential_basic_header', 'credential_fixed_cookie', 'credential_userinfo_url', 'credential_in_raw_request_header'):
            with self.subTest(case=name):
                self.assertTrue(checks.readonly_problem(cases[name]).startswith('template not validated: '))
        self.assertIn('Authorization header', checks.credential_problem(cases['credential_basic_header']))
        # what a signed-in run or an extractor supplies is a placeholder, never a fixed value
        for name in ('authorization_from_a_placeholder_only', 'cookie_echoing_an_extracted_value', 'plain_user_agent_header'):
            with self.subTest(case=name):
                self.assertEqual(checks.credential_problem(cases[name]), '')

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
           'lowercase_method',
           # third pass: N1 (a quote of the other kind inside a string hides a helper call from the lexer), N7, N3, N4, N6 (still refused), N2
           'q_mixed_quote_dsl', 'q_mixed_quote_header', 'q_mixed_quote_variable', 'q_dq_with_sq_inside', 'raw_get_blank_line_then_header_like_body',
           'trailing_newline_in_header_name', 'trailing_newline_in_template_id', 'section_sign_by_escape_in_value', 'control_character_by_escape_in_value',
           'lone_carriage_return', 'float_with_exponent', 'float_with_underscore', 'float_sexagesimal', 'metadata_key_yes_word', 'type_is_a_list',
           'ssl_version_is_a_list', 'method_is_a_list', 'nested_6000_deep')
ACCEPTED = ('plain_float_cvss_score', 'crlf_line_endings', 'upper_case_metadata_key', 'list_of_authors')


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


def _case(name):
    return next(c for c in CORPUS if c['name'] == name)['template']


class ThirdPassTests(unittest.TestCase):
    """N1 to N7 of the third security review."""

    def test_a_string_with_a_quote_of_either_kind_is_refused_whatever_it_hides(self):
        for name in ('q_mixed_quote_dsl', 'q_mixed_quote_header', 'q_mixed_quote_variable', 'q_dq_with_sq_inside'):
            with self.subTest(case=name):
                self.assertEqual(checks.readonly_problem(_case(name)), '')  # nothing else refuses it: only the lexer rule does
                self.assertIn('quote character', checks.check_problem(_case(name)))
        for expr in ("contains(body, 'a\"b')", 'contains(body, "a\'b")', "contains(body, 'a\\'b')", "contains(body, 'a\"+resolve(\"x\",\"a\")+\"')"):
            with self.subTest(expr=expr):
                self.assertNotEqual(check_allowlist.expression_problem(expr), '')
        self.assertEqual(check_allowlist.expression_problem("contains(body, 'ab') && contains(header, \"cd\")"), '')

    def test_the_gate_refuses_and_never_raises(self):
        deep = 'id: c\ninfo:\n  name: c\n  severity: info\nhttp: ' + '[' * 6000 + ']' * 6000 + '\n'
        for name, text in (('deep', deep), ('type_list', _case('type_is_a_list')), ('ssl_list', _case('ssl_version_is_a_list')),
                           ('method_list', _case('method_is_a_list')), ('condition_list', _case('type_is_a_list').replace('type: [word]', 'type: word\n        condition: [and]'))):
            for gate in (checks.check_problem, check_allowlist.allowlist_problem):
                with self.subTest(case=name, gate=gate.__name__):
                    problem = gate(text)
                    self.assertTrue(problem.startswith('template not validated: '), problem)

    def test_a_document_nested_past_the_cap_is_refused_with_the_reason_and_the_cap_itself_passes(self):
        text = lambda n: 'id: c\ninfo:\n  name: c\n  severity: info\n  tags: ' + '[' * n + ']' * n + '\n'  # noqa: E731
        self.assertIn('nested', check_allowlist.yaml_problem(text(check_allowlist.MAX_DEPTH + 1)))
        self.assertEqual(check_allowlist.yaml_problem(text(2)), '')

    def test_an_error_inside_the_rules_is_a_refusal_with_a_reason(self):
        good = _case('plain_get')
        with mock.patch.object(check_allowlist, '_allowlist_problem', side_effect=ValueError('boom')):
            problem = check_allowlist.allowlist_problem(good)
        self.assertEqual(problem, 'template not validated: it could not be checked (ValueError), so it is refused')
        with mock.patch.object(checks, 'scope_problem', side_effect=RuntimeError('boom')):
            self.assertIn('RuntimeError', checks.check_problem(good))
        with mock.patch.object(checks, 'readonly_problem', side_effect=RecursionError()):
            self.assertIn('RecursionError', checks.check_problem(good))

    def test_the_names_are_matched_whole_so_a_trailing_newline_is_refused(self):
        self.assertIn('header name', check_allowlist.allowlist_problem(_case('trailing_newline_in_header_name')))
        self.assertIn('id', check_allowlist.allowlist_problem(_case('trailing_newline_in_template_id')))
        self.assertTrue(check_allowlist.header_problem('X-A\n', 'v'))
        meta = "id: c\ninfo:\n  name: c\n  severity: info\n  metadata:\n    \"k\\n\": v\n" + _case('plain_get').split('severity: info\n', 1)[1]
        self.assertIn('metadata', check_allowlist.allowlist_problem(meta))
        var = _case('plain_get').replace('http:', 'variables:\n  "v\\n": x\nhttp:')
        self.assertIn('variable name', check_allowlist.allowlist_problem(var))

    def test_the_control_and_section_sign_scans_run_on_the_decoded_strings_too(self):
        self.assertIn('U+00A7', check_allowlist.allowlist_problem(_case('section_sign_by_escape_in_value')))
        self.assertIn('U+000B', check_allowlist.allowlist_problem(_case('control_character_by_escape_in_value')))
        for escape, code in (('\\u202e', 'U+202E'), ('\\x00', 'U+0000'), ('\\x85', 'U+0085'), ('\\r', 'U+000D')):
            with self.subTest(escape=escape):
                text = _case('plain_get').replace('"marker-1.2.3"', f'"a{escape}b"')
                self.assertIn(code, check_allowlist.allowlist_problem(text))

    def test_what_both_yaml_readers_read_alike_is_accepted(self):
        for name in ACCEPTED:
            with self.subTest(case=name):
                self.assertEqual(checks.check_problem(_case(name)), '')
        self.assertTrue(_case('crlf_line_endings').count('\r\n') > 5)
        self.assertEqual(yaml.safe_load(_case('plain_float_cvss_score'))['info']['classification']['cvss-score'], 9.8)

    def test_a_crlf_document_decodes_to_the_same_strings_as_the_lf_one(self):
        lf = _case('raw_get_host_header')
        crlf = lf.replace('\n', '\r\n')
        self.assertEqual(yaml.safe_load(crlf), yaml.safe_load(lf))
        self.assertEqual(checks.check_problem(crlf), '')
        self.assertIn('U+000D', check_allowlist.yaml_problem(lf.replace('\n', '\r', 1)))

    def test_what_the_two_readers_read_differently_stays_refused_with_a_reason_the_author_can_act_on(self):
        for name in ('float_with_exponent', 'float_with_underscore', 'float_sexagesimal', 'metadata_key_yes_word'):
            with self.subTest(case=name):
                self.assertIn('reads differently in YAML 1.1 and 1.2', check_allowlist.allowlist_problem(_case(name)))
        for value in ('1e3', '.5', '0o7', '0x1F', '.inf', '1.', '09.8', '9.8.1x'):
            with self.subTest(value=value):
                text = _case('plain_get').replace('name: c', f'name: c\n  author: x\n  description: {value}', 1)
                self.assertEqual(('reads differently' in check_allowlist.allowlist_problem(text)), value != '9.8.1x', value)

    def test_the_raw_body_rule_alone_refuses_the_header_like_body(self):
        text = _case('raw_get_blank_line_then_header_like_body')
        self.assertEqual(checks.readonly_problem(text), '')
        self.assertEqual(checks.scope_problem(text), '')
        self.assertIn('body', check_allowlist.allowlist_problem(text))
        self.assertEqual(check_allowlist.raw_problem('GET /x HTTP/1.1\nHost: {{Hostname}}\na: b\n'), '')  # without the blank line it is a header
        self.assertIn('body', check_allowlist.raw_problem('GET /x HTTP/1.1\nHost: {{Hostname}}\n\na: b\n'))


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
