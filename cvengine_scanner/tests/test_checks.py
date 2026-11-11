"""The read-only and own-target rules a Sentinel applies to an AI-written or approved nuclei template before it runs one (``cvengine_scanner.checks``).

The corpus (``fixtures/checks/corpus.json``) is shared with the cvENGINE server, whose own read-only check (``cveFeed.validation.readonly_problem``)
must give the same verdict on every case (its ``tests.test_ai_checks_on_sentinels``)."""
import hashlib
import json
import unittest

from cvengine_scanner import checks, contract

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
                self.assertEqual(checks.check_problem(case['template']) == '', case['read_only'] and case['own_target'])

    def test_a_literal_port_or_a_port_key_aims_at_another_port(self):
        for name in ('network_literal_port', 'network_port_key'):
            case = next(c for c in CORPUS if c['name'] == name)
            with self.subTest(case=name):
                self.assertEqual(checks.readonly_problem(case['template']), '')
                self.assertIn('port', checks.scope_problem(case['template']))


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
