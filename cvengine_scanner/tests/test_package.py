import json
import unittest
from pathlib import Path

import cvengine_scanner
from cvengine_scanner import contract


class PackageTests(unittest.TestCase):
    def test_the_package_has_a_version(self):
        self.assertRegex(cvengine_scanner.__version__, r'^\d+(\.\d+)*')

    def test_the_contract_is_packaged_and_readable(self):
        doc = contract.load()
        self.assertEqual(contract.version(), doc['contract_version'])
        self.assertLessEqual(contract.min_supported(), contract.version())
        self.assertEqual(set(doc['kind_since']), set(doc['$defs']['results']))

    def test_every_kind_the_contract_knows_has_a_result_and_a_target_schema(self):
        doc = contract.load()
        for kind in doc['kind_since']:
            with self.subTest(kind=kind):
                self.assertEqual(contract.result_schema(kind)['$ref'], f'#/$defs/results/{kind}')
                self.assertEqual(contract.target_schema(kind)['$ref'], f'#/$defs/targets/{kind}')
        with self.assertRaises(KeyError):
            contract.result_schema('no-such-kind')

    def test_every_fixture_is_json_and_names_a_kind_of_the_contract(self):
        kinds = set(contract.load()['kind_since'])
        for half in ('results', 'targets'):
            files = sorted((contract.FIXTURES / half).glob('*.json'))
            self.assertTrue(files)
            for path in files:
                with self.subTest(fixture=f'{half}/{path.name}'):
                    json.loads(path.read_text(encoding='utf-8'))
                    self.assertTrue(path.stem in kinds or (half == 'results' and path.stem == 'error'))

    def test_the_fixtures_are_packaged_beside_the_contract(self):
        self.assertTrue(Path(contract.FIXTURES, 'results', 'nmap.json').is_file())
        self.assertTrue(Path(contract.FIXTURES, 'targets', 'nmap.json').is_file())


if __name__ == '__main__':
    unittest.main()

    def test_every_library_package_is_installed(self):
        """``pyproject.toml`` lists its packages by name: a new one (``cvengine_scanner.probes``) left out would be missing from the image."""
        root = Path(cvengine_scanner.__file__).resolve().parent
        on_disk = {'cvengine_scanner'} | {'cvengine_scanner.' + p.parent.relative_to(root).as_posix().replace('/', '.')
                                          for p in root.glob('*/__init__.py') if p.parent.name != 'tests'}
        listed = (root.parent / 'pyproject.toml').read_text(encoding='utf-8')
        for name in sorted(on_disk):
            with self.subTest(package=name):
                self.assertIn(f'"{name}"', listed)
