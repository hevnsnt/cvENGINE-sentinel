"""The masked context through a whole ``secrets_scan`` task on the Sentinel: pages with a made-up canary key in them, Kingfisher's report as the real
2.16 prints it (the value as ``snippet``, with the line and the columns), and the result that would be sent. The canary, in full, must be in the
result nowhere but in the contract's value field (``secret``, which the server fingerprints and never stores)."""
import json
import os
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from client import secrets_scan
from client.tests.test_secrets_scan import setUpModule, target  # noqa: F401 - setUpModule patches the resolver and the scope for this module too
from cvengine_scanner import contract

CANARY = 'AIza' + 'SyD-CANARYfakeLABkey01234567890Zq9w'
PAGE = (f'<!doctype html><html><head><title>Lab</title></head><body>\n<script>\nfetch("https://weather.example.test/v1", {{headers: {{\n'
        f'  "x-api-key": "{CANARY}",\n  "accept": "application/json"\n}}}});\n</script>\n<script src="/app.js"></script>\n</body></html>\n').encode()
SCRIPT = ('/* bundle */\nvar cfg = {region: "eu"};\n'
          f'var mapsKey = "{CANARY}"; var next = "https://example.test/?password=Hunter2!x"; function init(){{ return mapsKey; }}\n').encode()


class Site:
    def __call__(self, url, address, limit):
        pages = {'https://www.example.test/': (200, 'text/html', PAGE), 'https://www.example.test/app.js': (200, 'application/javascript', SCRIPT)}
        status, content_type, body = pages.get(url, (404, 'text/html', b'not found'))
        return status, content_type, body, ''


def kingfisher_report(directory):
    names = {name.rsplit('.', 1)[-1]: name for name in os.listdir(directory)}

    def finding(name, line, column):
        return {'rule': {'id': 'betterleaks.gcp-api-key', 'name': 'gcp-api-key'},
                'finding': {'snippet': CANARY, 'path': f'{directory}/{name}', 'line': line, 'column_start': column, 'column_end': column + 39, 'confidence': 'high',
                            'entropy': '4.5', 'validation': {'outcome': 'not_attempted', 'response': ''},
                            'validate_command': f"kingfisher validate --rule 'betterleaks.gcp-api-key' '{CANARY}'"}}
    return json.dumps({'findings': [finding(names['html'], 4, 16), finding(names['js'], 3, 14)]})


class ContextThroughATaskTests(unittest.TestCase):
    def run_task(self):
        def fake_kingfisher(argv, register, env=None):
            with open(argv[argv.index('--output') + 1], 'w') as handle:
                handle.write(kingfisher_report(argv[2]))
        with mock.patch.object(secrets_scan, '_kingfisher', side_effect=fake_kingfisher), mock.patch.object(secrets_scan, '_version', return_value='2.18.1'):
            return secrets_scan.run(target(), fetcher=Site(), sleep=lambda s: None)

    def test_each_finding_carries_its_line_and_a_masked_snippet_and_the_canary_is_nowhere(self):
        result = self.run_task()
        by_url = {f['url']: f for f in result['findings']}
        page, script = by_url['https://www.example.test/'], by_url['https://www.example.test/app.js']
        self.assertEqual((page['line'], page['context']), (4, f'"x-api-key": "AIza…{CANARY[-4:]}",'))
        self.assertEqual(script['line'], 3)
        self.assertIn(f'var mapsKey = "AIza…{CANARY[-4:]}";', script['context'])
        self.assertNotIn('Hunter2!x', script['context'])  # another secret on the same line is masked too
        self.assertIn('redacted', script['context'])
        self.assertEqual({f['secret'] for f in result['findings']}, {CANARY})
        sent = json.dumps({**result, 'findings': [{k: v for k, v in f.items() if k != 'secret'} for f in result['findings']]})
        self.assertNotIn(CANARY, sent)
        self.assertNotIn(CANARY[6:-4], sent)
        self.assertNotIn(CANARY[10:30], sent)
        for finding in result['findings']:
            self.assertLessEqual(len(finding['context']), 200)

    def test_the_result_is_in_contract(self):
        result = {'outcome': 'done', **self.run_task()}
        doc = contract.load()
        schema = {'$schema': doc['$schema'], '$ref': '#/$defs/results/secrets_scan', '$defs': doc['$defs']}
        self.assertEqual(sorted(Draft202012Validator(schema).iter_errors(result), key=str), [])

    def test_a_context_that_cannot_be_cut_safely_is_left_out_not_the_finding(self):
        def fake_kingfisher(argv, register, env=None):
            report = json.loads(kingfisher_report(argv[2]))
            for record in report['findings']:
                record['finding']['line'] = 999  # a line the file does not have
            with open(argv[argv.index('--output') + 1], 'w') as handle:
                handle.write(json.dumps(report))
        with mock.patch.object(secrets_scan, '_kingfisher', side_effect=fake_kingfisher), mock.patch.object(secrets_scan, '_version', return_value='2.18.1'):
            result = secrets_scan.run(target(), fetcher=Site(), sleep=lambda s: None)
        self.assertEqual(len(result['findings']), 2)
        self.assertTrue(all('context' not in f for f in result['findings']))


if __name__ == '__main__':
    unittest.main()
