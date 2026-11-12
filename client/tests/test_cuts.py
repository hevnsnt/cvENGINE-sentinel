"""SN-6, TL-9, TL-13: nothing is cut silently. A capped list, a clipped text or a tool stopped at its time limit is said in the result's ``cuts``, one shape for every
kind (contract 5, ``$defs/cuts``): what was cut, how it was counted, the limit and how many were dropped."""
import json
import subprocess
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from client import tools
from cvengine_scanner import contract, parsers


def line(i, **extra):
    row = {'template-id': f'tpl-{i}', 'type': 'http', 'host': 'www.example.test', 'matched-at': f'https://www.example.test/{i}', 'info': {'name': f'N{i}', 'severity': 'low', 'tags': ['x']}}
    row.update(extra)
    return json.dumps(row)


def valid(kind, result):
    return list(Draft202012Validator(contract.result_schema(kind)).iter_errors({'outcome': 'done', **result}))


class NucleiParserCutsTests(unittest.TestCase):
    def test_findings_over_the_cap_are_counted(self):
        cuts = parsers.Cuts()
        with mock.patch.object(parsers, 'MAX_FINDINGS', 3):
            found = parsers.parse_nuclei_jsonl('\n'.join(line(i) for i in range(8)), cuts=cuts)
        self.assertEqual(len(found), 3)
        self.assertEqual(cuts.as_list(), [{'what': 'findings', 'kind': 'items', 'limit': 3, 'dropped': 5}])

    def test_findings_over_the_byte_limit_are_counted_and_a_bad_line_is_not(self):
        cuts = parsers.Cuts()
        with mock.patch.object(parsers, 'MAX_FINDINGS_BYTES', 700):
            found = parsers.parse_nuclei_jsonl('\n'.join([line(0), 'not json', *[line(i) for i in range(1, 6)]]), cuts=cuts)
        self.assertGreaterEqual(len(found), 1)
        self.assertEqual(len(found) + cuts.as_list()[0]['dropped'], 6)  # six real findings: kept or counted, the bad line neither

    def test_a_clipped_description_and_evidence_are_counted_in_characters(self):
        cuts = parsers.Cuts()
        row = json.loads(line(1))
        row['info']['description'] = 'd' * 4100
        row['request'] = 'r' * (parsers.EVIDENCE_LIMIT + 10)
        parsers.parse_nuclei_jsonl(json.dumps(row), cuts=cuts)
        self.assertEqual({c['what']: (c['kind'], c['dropped']) for c in cuts.as_list()}, {'description': ('chars', 100), 'evidence': ('chars', 10)})

    def test_without_a_collector_the_parser_works_as_before(self):
        self.assertEqual(len(parsers.parse_nuclei_jsonl(line(1))), 1)


class RunNucleiCutsTests(unittest.TestCase):
    def test_a_capped_run_says_how_many_findings_it_dropped(self):
        with mock.patch.object(parsers, 'MAX_FINDINGS', 3), mock.patch('client.tools._run', return_value='\n'.join(line(i) for i in range(5))):
            result = tools.run_nuclei(['www.example.test'])
        self.assertEqual(len(result['findings']), 3)
        self.assertEqual(result['cuts'], [{'what': 'findings', 'kind': 'items', 'limit': 3, 'dropped': 2}])
        self.assertEqual(valid('nuclei_light', result), [])

    def test_a_run_that_ran_out_of_time_says_so_with_its_limit(self):
        def runs_out(argv, timeout, register=None, **kw):
            err = subprocess.TimeoutExpired(argv, timeout)
            err.partial = line(1)
            raise err
        with mock.patch('client.tools._run', side_effect=runs_out):
            result = tools.run_nuclei(['www.example.test'], timeout=90)
        self.assertTrue(result['incomplete'])
        self.assertEqual([(c['what'], c['kind']) for c in result['cuts']], [('time_limit', 'time')])
        self.assertLessEqual(result['cuts'][0]['limit'], 90)
        self.assertEqual(valid('nuclei_light', result), [])

    def test_a_run_that_cut_nothing_has_no_cuts_and_a_second_run_starts_clean(self):
        with mock.patch.object(parsers, 'MAX_FINDINGS', 1), mock.patch('client.tools._run', return_value=line(1) + '\n' + line(2)):
            self.assertIn('cuts', tools.run_nuclei(['www.example.test']))
        with mock.patch('client.tools._run', return_value=line(1)):
            self.assertNotIn('cuts', tools.run_nuclei(['www.example.test']))


class SecretsCutsTests(unittest.TestCase):
    def test_findings_over_the_cap_are_counted_by_the_reader(self):
        from cvengine_scanner import secrets
        record = {'rule': {'id': 'betterleaks.aws-access-token', 'name': 'AWS'}, 'finding': {'path': 'f1.txt', 'snippet': 'AKIAIOSFODNN7EXAMPLE', 'line': 1}}
        report = json.dumps({'findings': [record] * 7})
        cuts = parsers.Cuts()
        with mock.patch.object(secrets, 'MAX_FINDINGS', 4):
            found, truncated = secrets.read_report(report, {'f1.txt': {'url': 'https://www.example.test/'}}, cuts=cuts)
        self.assertEqual((len(found), truncated), (4, True))
        self.assertEqual(cuts.as_list(), [{'what': 'findings', 'kind': 'items', 'limit': 4, 'dropped': 3}])


if __name__ == '__main__':
    unittest.main()
