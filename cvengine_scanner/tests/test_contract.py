import hashlib
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

    def test_every_partial_fixture_validates_against_the_schema_for_its_kind(self):
        files = sorted((contract.FIXTURES / 'partials').glob('*.json'))
        self.assertEqual([p.stem for p in files], list(contract.streamed()))
        for path in files:
            with self.subTest(kind=path.stem):
                errors = sorted(validator(contract.partial_schema(path.stem)).iter_errors(fixture('partials', path.stem)), key=str)
                self.assertEqual(errors, [])
        with self.assertRaises(KeyError):
            contract.partial_schema('nmap')

    def test_a_done_bbot_result_names_its_batches_and_mode(self):
        check = validator(contract.result_schema('bbot_discovery'))
        good = fixture('results', 'bbot_discovery')
        self.assertTrue(check.is_valid(good))
        for missing in ('partials', 'mode'):
            with self.subTest(missing=missing):
                self.assertFalse(check.is_valid({k: v for k, v in good.items() if k != missing}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'bbot exited 1'}))

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


# Each frozen set is what a Sentinel of that contract version sent, kept byte for byte (the server's tests.test_sentinel_contract holds the same
# hashes): the server keeps accepting it down to ``min_supported_contract_version``. A bump to version N copies the then-current results into
# ``fixtures/results/v<N>/`` and adds it to FROZEN; a fixture that needs to change belongs in a new version's set, never in an old one.
FROZEN = {'v1': contract.FIXTURES / 'results' / 'v1', 'v2': contract.FIXTURES / 'results' / 'v2'}
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'waf': 'waf', 'bbot_discovery': 'bbot_discovery', 'error': 'nmap', 'nmap_full': 'nmap_full', 'nmap_verify': 'nmap_verify',
           'node2shell': 'node2shell', 'rdp_shot': 'rdp_shot', 'db_probe': 'db_probe', 'path_probe': 'path_probe',
           'nuclei_validate': 'nuclei_validate', 'secrets_scan': 'secrets_scan', 'wpscan_thorough': 'wpscan_thorough'}  # fixture name -> the kind it is a result of
V1_SHA256 = {
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': '13328030712a13a881e8dbb94ccd109e10a72cb62ae2d2081e3b0b107dc057fd',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nuclei_light.json': 'ecb620b0742ef52e5af077d16f545fcc93791fc7ec33c95ced0a8a6153b7c60c',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}
V2_SHA256 = {**V1_SHA256, 'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec'}  # copied when version 3 added bbot_discovery

V2_SHA256 = {
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': '13328030712a13a881e8dbb94ccd109e10a72cb62ae2d2081e3b0b107dc057fd',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nuclei_light.json': 'ecb620b0742ef52e5af077d16f545fcc93791fc7ec33c95ced0a8a6153b7c60c',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}

class FrozenFixtureTests(unittest.TestCase):
    def test_every_frozen_set_is_complete_for_its_version(self):
        for v, folder in FROZEN.items():
            have = {p.stem for p in folder.glob('*.json')}
            want = {name for name, kind in KIND_OF.items() if contract.kind_since(kind) <= int(v[1:])}
            self.assertEqual(have, want, v)

    def test_the_oldest_supported_version_is_frozen(self):
        self.assertIn(f'v{contract.min_supported()}', FROZEN)

    def test_a_frozen_set_is_never_edited(self):
        for v, want in (('v1', V1_SHA256), ('v2', V2_SHA256)):
            digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FROZEN[v].glob('*.json')}
            self.assertEqual(digests, want, v)

    def test_every_frozen_fixture_is_still_in_contract(self):
        for v, folder in FROZEN.items():
            for path in sorted(folder.glob('*.json')):
                with self.subTest(fixture=f'{v}/{path.name}'):
                    sent = json.loads(path.read_text(encoding='utf-8'))
                    self.assertEqual(list(validator(contract.result_schema(KIND_OF[path.stem])).iter_errors(sent)), [])


if __name__ == '__main__':
    unittest.main()


class NucleiTargetServiceTests(unittest.TestCase):
    """The optional ``services`` and ``budget`` of a nuclei task: what speaks on each host:port, and the most one service may receive."""

    def test_the_fixture_names_a_service_and_a_budget_and_an_older_target_without_them_is_still_valid(self):
        good = fixture('targets', 'nuclei_light')
        self.assertEqual(good['services'], {'example.com:22': 'ssh'})
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            check = validator(contract.target_schema(kind))
            self.assertTrue(check.is_valid(good), kind)
            self.assertTrue(check.is_valid({k: v for k, v in good.items() if k not in ('services', 'budget')}), kind)

    def test_a_service_label_or_budget_outside_the_contract_is_rejected(self):
        good = fixture('targets', 'nuclei_deep') if (contract.FIXTURES / 'targets' / 'nuclei_deep.json').exists() else fixture('targets', 'nuclei_light')
        check = validator(contract.target_schema('nuclei_deep'))
        for change in ({'services': ['example.com:22']}, {'services': {'example.com:22': 22}}, {'services': {'example.com:22': 'x' * 21}},
                       {'budget': {'rate': 0}}, {'budget': {'rate': 1.5}}, {'budget': {'concurrency': 101}}, {'budget': {'seconds': 'long'}}, {'budget': {'surprise': 1}}):
            self.assertFalse(check.is_valid({**good, **change}), change)
        self.assertTrue(check.is_valid({**good, 'services': {}, 'budget': {}}))
