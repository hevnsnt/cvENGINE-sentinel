"""The masked ``context`` of a secret: what a Sentinel sends so a person can see WHAT was found, and the rule that the value is never in it."""
import json
import unittest

from jsonschema import Draft202012Validator

from cvengine_scanner import context, contract
from cvengine_scanner import secrets as kf

# A made-up key that only looks like one (assembled here so the repository holds no string a secret scanner takes for a real key).
CANARY = 'AIza' + 'SyD-CANARYfakeLABkey01234567890Zq9w'
OTHER = 'ghp_' + 'Fak3Canary0ther' + 'TokenAbCdEfGhIjKlMnOpQrSt'
HEX_KEY = 'f4k3canary' + '0123456789abcdef0123456789'


def schema(kind):
    return Draft202012Validator(contract.result_schema(kind))


class MaskTests(unittest.TestCase):
    def test_the_mask_is_the_servers_rule(self):
        self.assertEqual(context.mask(CANARY), 'AIza…' + CANARY[-4:])
        self.assertEqual(context.mask('AKIA' + '0' * 16), 'AKIA…0000')
        self.assertEqual(context.mask('short-value1'), '…')  # fewer than 16 characters: no character of its own
        self.assertEqual(context.mask('-----BEGIN RSA PRIVATE KEY-----\nMIIE'), 'PEM RSA PRIVATE KEY')
        self.assertEqual(context.mask('"' + CANARY + '"'), context.mask(CANARY))  # quotes are not part of a value

    def test_the_value_is_masked_everywhere_it_stands_in_the_text(self):
        got = context.mask_context(f'a={CANARY}; b="{CANARY}"; c=\\"{CANARY}\\"', CANARY)
        self.assertNotIn(CANARY, got)
        self.assertNotIn(CANARY[4:20], got)
        self.assertEqual(got.count('AIza…' + CANARY[-4:]), 3)

    def test_control_characters_go_and_white_space_collapses(self):
        got = context.mask_context('x\x00y\x1b[31m  red\x07 \t\n z', 'AIza' + 'q' * 35)
        self.assertEqual(got, 'x y [31m red z')
        self.assertEqual(context.mask_context('a\u202eb\u200bc', 'AIza' + 'q' * 35), 'a b c')  # a right-to-left override, a zero-width space

    def test_another_secret_in_the_snippet_is_masked_too(self):
        text = f'const a = "{CANARY}", b = "{OTHER}", url = "postgres://app:s3cretPass@db.example.com/x";'
        got = context.mask_context(text, CANARY)
        for leaked in (CANARY, OTHER, 's3cretPass', OTHER[4:30]):
            self.assertNotIn(leaked, got)
        self.assertIn('db.example.com', got)  # only the password goes

    def test_a_header_style_line_with_an_unknown_provider_key_is_masked(self):
        for line in (f'"x-api-key": "{HEX_KEY}",', f'x-api-key: {HEX_KEY}', f'  headers: {{ Authorization: "Bearer {HEX_KEY}" }}'):
            with self.subTest(line=line):
                got = context.mask_context(line, CANARY)
                self.assertNotIn(HEX_KEY, got)
                self.assertNotIn(HEX_KEY[:20], got)
                self.assertIn('redacted', got)

    def test_ordinary_words_numbers_and_paths_are_left_alone(self):
        text = 'var path = "/assets/images/hero-banner-final.png"; const version = 20240101; getElementsByClassName("x");'
        self.assertEqual(context.mask_runs(text), text)

    def test_a_snippet_in_which_the_value_can_still_be_read_is_not_sent(self):
        # the value is not in the text as written (a different escaping this module does not know), but a piece of it is
        text = 'k = "' + CANARY[:20] + '\\u002d' + CANARY[20:] + '"'
        self.assertEqual(context.mask_context(text, CANARY), context.mask_context(text, CANARY))
        self.assertNotIn(CANARY, context.mask_context(text, CANARY))
        piece = CANARY[8:30]
        self.assertEqual(context.mask_context('zz ' + piece + ' zz', CANARY), '')

    def test_masking_twice_changes_nothing(self):
        once = context.mask_context(f'a "{CANARY}" b "{OTHER}" c password=Hunter2!x', CANARY)
        self.assertEqual(context.redact_text(once), once)
        self.assertEqual(context.mask_runs(once), once)


class SnippetTests(unittest.TestCase):
    def test_it_is_the_matched_line_centred_on_the_match_and_at_most_200_characters(self):
        line = 'x' * 500 + f' var key = "{CANARY}"; ' + 'y' * 500
        out = context.snippet(line, line.index(CANARY), line.index(CANARY) + len(CANARY), CANARY)
        self.assertLessEqual(len(out), context.MAX_CONTEXT)
        self.assertTrue(out.startswith('... ') and out.endswith(' ...'))
        self.assertIn('AIza…' + CANARY[-4:], out)
        self.assertNotIn(CANARY, out)
        middle = out.index('AIza…')
        self.assertTrue(abs(middle - (len(out) - middle)) < 40, out)  # about as much either side

    def test_a_short_line_is_shown_whole_with_no_ellipsis(self):
        out = context.snippet(f'k="{CANARY}"', 3, 3 + len(CANARY), CANARY)
        self.assertEqual(out, f'k="AIza…{CANARY[-4:]}"')

    def test_context_snippet_finds_the_line_of_the_first_match(self):
        text = f'one\ntwo\nvar k = "{CANARY}";\nfour\n'
        self.assertEqual(context.context_snippet(text, CANARY), (3, f'var k = "AIza…{CANARY[-4:]}";'))
        self.assertEqual(context.context_snippet(text, 'AIza' + 'z' * 35), (None, ''))
        self.assertEqual(context.context_snippet(text, 'short'), (None, ''))

    def test_a_long_run_of_other_masks_still_fits(self):
        line = ' '.join(f'{OTHER[:-1]}{i}' for i in range(40)) + f' {CANARY} ' + ' '.join(f'{HEX_KEY}{i}' for i in range(40))
        out = context.snippet(line, line.index(CANARY), line.index(CANARY) + len(CANARY), CANARY)
        self.assertLessEqual(len(out), context.MAX_CONTEXT)
        for leaked in (CANARY, OTHER[:-1], HEX_KEY):
            self.assertNotIn(leaked, out)


class KingfisherFindingTests(unittest.TestCase):
    """Kingfisher's report: the value as ``snippet`` and where it is (``line``, ``column_start``)."""
    PAGE = f'<html>\n<script>\nfetch(u, {{headers: {{\n  "x-api-key": "{CANARY}",\n  "accept": "application/json"\n}}}});\n</script>\n</html>\n'

    def report(self, snippet, line=4, column=16, name='0.html'):
        return json.dumps({'findings': [{'rule': {'id': 'betterleaks.gcp-api-key', 'name': 'gcp-api-key'},
                                         'finding': {'snippet': snippet, 'path': f'/tmp/in/{name}', 'line': line, 'column_start': column,
                                                     'column_end': column + len(CANARY), 'confidence': 'high', 'entropy': '4.5',
                                                     'validation': {'outcome': 'not_attempted'}}}]})

    def read(self, report, text=None):
        manifest = {'0.html': {'url': 'https://www.example.test/'}}
        return kf.read_report(report, manifest, body_of=lambda name: self.PAGE if text is None else text)[0]

    def test_the_value_is_found_in_its_line_and_masked_there(self):
        [finding] = self.read(self.report(CANARY))
        self.assertEqual(finding['line'], 4)
        self.assertEqual(finding['context'], f'"x-api-key": "AIza…{CANARY[-4:]}",')
        # ``secret`` is the contract's value field (the server fingerprints it); everything else of the finding is free of the value
        self.assertEqual(finding['secret'], CANARY)
        rest = json.dumps({k: v for k, v in finding.items() if k != 'secret'})
        self.assertNotIn(CANARY, rest)
        self.assertNotIn(CANARY[6:-4], rest)

    def test_the_second_occurrence_on_a_line_is_the_one_at_the_column(self):
        text = f'a="{CANARY}"; b="{CANARY}";\n'
        at = text.rindex(CANARY)
        [finding] = self.read(self.report(CANARY, line=1, column=at), text)
        self.assertEqual(finding['context'], f'a="AIza…{CANARY[-4:]}"; b="AIza…{CANARY[-4:]}";')

    def test_without_the_file_there_is_no_context_and_the_rest_is_as_before(self):
        [bare] = kf.read_report(self.report(CANARY), {'0.html': {'url': 'https://www.example.test/'}})[0]
        self.assertNotIn('context', bare)
        [with_body] = self.read(self.report(CANARY))
        self.assertEqual({k: v for k, v in with_body.items() if k != 'context'}, bare)

    def test_a_line_that_does_not_hold_the_value_gives_no_context_and_never_a_guess(self):
        for report in (self.report(CANARY, line=1), self.report(CANARY, line=99), self.report(CANARY, line=0)):
            [finding] = self.read(report)
            self.assertNotIn('context', finding)

    def test_a_minified_file_one_line_of_300_kb_gives_a_short_centred_snippet(self):
        body = 'a' * 150_000 + f'var k="{CANARY}";' + 'b' * 150_000
        [finding] = self.read(self.report(CANARY, line=1, column=150_000 + 7), body)
        self.assertLessEqual(len(finding['context']), context.MAX_CONTEXT)
        self.assertIn('AIza…', finding['context'])
        self.assertNotIn(CANARY, finding['context'])

    def test_the_second_value_of_a_pair_is_masked_in_the_first_ones_context(self):
        secret = '1tUm636uS1yOEcfP5pvf' + 'qJ/ml36mF7AkyHsEU0IU'
        key_id = 'AK' + 'IAQYLPMN5HHHFPZAM2'
        text = f'const aws_access_key_id = "{key_id}", aws_secret_access_key = "{secret}";\n'
        report = json.dumps({'findings': [{'rule': {'id': 'betterleaks.aws-access-token', 'name': 'aws'},
                                           'finding': {'snippet': key_id, 'path': '0.js', 'line': 1, 'confidence': 'high', 'entropy': '3',
                                                       'validation': {'outcome': 'not_attempted'}, 'dependent_captures': {'AWS_SECRET_ACCESS_KEY': secret}}}]})
        rows = kf.read_report(report, {'0.js': {'url': 'https://www.example.test/a.js'}}, body_of=lambda name: text)[0]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertNotIn(secret, row.get('context', ''))
            self.assertNotIn(key_id, row.get('context', ''))
            self.assertIn('context', row)


class ContractTests(unittest.TestCase):
    def result(self, **finding):
        return {'outcome': 'done', 'findings': [{'rule_id': 'betterleaks.gcp-api-key', 'url': 'https://www.example.test/', 'secret': 'AIzaSy...TUVw', **finding}],
                'fetched': [{'url': 'https://www.example.test/', 'kind': 'page'}], 'references': [], 'stats': {}}

    def test_context_is_optional_and_bounded(self):
        check = schema('secrets_scan')
        self.assertTrue(check.is_valid(self.result()))  # a Sentinel that sends none is still in contract
        self.assertTrue(check.is_valid(self.result(context='k = "AIza…TUVw"', line=3)))
        self.assertTrue(check.is_valid(self.result(context='x' * 400)))
        self.assertFalse(check.is_valid(self.result(context='x' * 401)))
        self.assertFalse(check.is_valid(self.result(context=5)))

    def test_a_route_credential_may_carry_a_line_and_a_context(self):
        check = schema('route_probe')
        good = json.loads((contract.FIXTURES / 'results' / 'route_probe.json').read_text())
        self.assertTrue(check.is_valid(good))
        credential = next(r for r in good['routes'] if r['credentials'])['credentials'][0]
        self.assertEqual(sorted(credential), ['context', 'line', 'type', 'value'])
        for bad in ({'context': 'x' * 401}, {'line': 0}, {'line': 'a'}, {'surprise': 1}):
            with self.subTest(bad=bad):
                credential.update(bad)
                self.assertFalse(check.is_valid(good))
                for key in bad:
                    credential.pop(key, None)
                credential.update({'line': 1, 'context': 'ok'})
        del credential['context'], credential['line']
        self.assertTrue(check.is_valid(good))  # the shape every Sentinel before this one sends

    def test_the_contract_version_is_not_bumped_for_an_optional_field(self):
        doc = contract.load()
        self.assertEqual((doc['contract_version'], doc['min_supported_contract_version']), (3, 1))


if __name__ == '__main__':
    unittest.main()
