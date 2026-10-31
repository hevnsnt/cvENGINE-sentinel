import json
import unittest

from jsonschema import Draft202012Validator

from cvengine_scanner import contract


def validator(schema):
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def envelope_schema():
    doc = contract.load()
    return {'$schema': doc['$schema'], '$ref': '#/$defs/envelope', '$defs': doc['$defs']}


def fixture(half, name):
    return json.loads((contract.FIXTURES / half / f'{name}.json').read_text(encoding='utf-8'))


class ContractFixtureTests(unittest.TestCase):
    def test_the_contract_is_a_valid_schema(self):
        Draft202012Validator.check_schema(contract.load())

    def test_every_result_fixture_validates_against_the_schema_for_its_kind(self):
        files = sorted((contract.FIXTURES / 'results').glob('*.json'))
        self.assertTrue(files)
        for path in files:
            kind = path.stem
            with self.subTest(kind=kind):
                schema = envelope_schema() if kind == 'error' else contract.result_schema(kind)  # error.json is any kind's failure: the envelope alone
                errors = sorted(validator(schema).iter_errors(fixture('results', kind)), key=str)
                self.assertEqual(errors, [])

    def test_every_target_fixture_validates_against_the_schema_for_its_kind(self):
        files = sorted((contract.FIXTURES / 'targets').glob('*.json'))
        self.assertTrue(files)
        for path in files:
            with self.subTest(kind=path.stem):
                errors = sorted(validator(contract.target_schema(path.stem)).iter_errors(fixture('targets', path.stem)), key=str)
                self.assertEqual(errors, [])

    def test_the_waf_result_has_no_version_or_confidence_and_is_bounded(self):
        check = validator(contract.result_schema('waf'))
        good = {'outcome': 'done', 'products': [{'name': 'x' * 100, 'manufacturer': 'y' * 100}] * 20, 'generic': False}
        self.assertTrue(check.is_valid(good))
        for bad in ({**good, 'products': good['products'] + [{'name': 'z'}]},
                    {**good, 'products': [{'name': 'x' * 101}]},
                    {**good, 'products': [{'name': ''}]},
                    {**good, 'products': [{'name': 'x', 'version': '1'}]},
                    {**good, 'products': [{'name': 'x', 'confidence': 0.9}]},
                    {'outcome': 'done', 'products': []}):
            with self.subTest(bad=bad):
                self.assertFalse(check.is_valid(bad))


if __name__ == '__main__':
    unittest.main()
