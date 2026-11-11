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
FROZEN = {'v1': contract.FIXTURES / 'results' / 'v1', 'v2': contract.FIXTURES / 'results' / 'v2', 'v3': contract.FIXTURES / 'results' / 'v3'}
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'waf': 'waf', 'bbot_discovery': 'bbot_discovery', 'error': 'nmap', 'nmap_full': 'nmap_full', 'nmap_verify': 'nmap_verify',
           'node2shell': 'node2shell', 'rdp_shot': 'rdp_shot', 'db_probe': 'db_probe', 'path_probe': 'path_probe',
           'nuclei_validate': 'nuclei_validate', 'secrets_scan': 'secrets_scan', 'wpscan_thorough': 'wpscan_thorough',
           'alive_check': 'alive_check', 'bucket_check': 'bucket_check', 'dangling_dns_check': 'dangling_dns_check', 'dns_resolve': 'dns_resolve',
           'http_probe': 'http_probe', 'hygiene_check': 'hygiene_check', 'identity_check': 'identity_check', 'route_probe': 'route_probe',
           'route_probe_signed': 'route_probe_signed', 'ssh_probe': 'ssh_probe', 'subdir_probe': 'subdir_probe', 'supplier_check': 'supplier_check',
           'vhost_probe': 'vhost_probe', 'web_screenshot': 'web_screenshot'}  # fixture name -> the kind it is a result of
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

V3_SHA256 = {  # every result fixture of contract version 3, copied when version 4 added the template hash of nuclei_validate
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': 'f883e593add75ca94820db4cdb0a6672fbf5ccfd6fe5f057ade9d28a270fdc54',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': '13328030712a13a881e8dbb94ccd109e10a72cb62ae2d2081e3b0b107dc057fd',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': 'ecb620b0742ef52e5af077d16f545fcc93791fc7ec33c95ced0a8a6153b7c60c',
    'nuclei_validate.json': '533c5e2f08d47d75f9b955bf6016855e67a1b78e294ad0e30ae2fe4199a6420f',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '421bcadc8d86a63959f8b5727aa1c37022360a2914d532c7e121d1b954428366',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'vhost_probe.json': 'acbe876c4ac3ca04b4660ebb2b021f362c7010384079f3c1ea591305d5eec8ad',
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
    'web_screenshot.json': 'dc0992e6f2842f93e765e2f1b42d85379afbeb8fc5521e6e3ea4501b2d330bfb',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
    'wpscan_thorough.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
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
        for v, want in (('v1', V1_SHA256), ('v2', V2_SHA256), ('v3', V3_SHA256)):
            digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FROZEN[v].glob('*.json')}
            self.assertEqual(digests, want, v)

    def test_every_frozen_fixture_is_still_in_contract(self):
        for v, folder in FROZEN.items():
            for path in sorted(folder.glob('*.json')):
                with self.subTest(fixture=f'{v}/{path.name}'):
                    sent = json.loads(path.read_text(encoding='utf-8'))
                    self.assertEqual(list(validator(contract.result_schema(KIND_OF[path.stem])).iter_errors(sent)), [])


SHA = 'a' * 64


class ContractVersionFourTests(unittest.TestCase):
    """Version 4: an AI-written check (nuclei_validate) carries the sha256 of its text, a Sentinel echoes it in its result, and ``external_since``
    says from which version a Sentinel other than the built-in scanner may be offered a kind the built-in scanner used to keep to itself."""

    def test_the_version_is_four_and_old_sentinels_are_still_served(self):
        self.assertEqual(contract.version(), 4)
        self.assertEqual(contract.min_supported(), 1)

    def test_external_since_names_the_two_kinds_and_never_predates_a_kind(self):
        table = contract.load()['external_since']
        self.assertEqual(table, {'nuclei_validate': 4, 'path_probe': 3})
        for kind, since in table.items():
            self.assertGreaterEqual(since, contract.kind_since(kind), kind)
            self.assertEqual(contract.external_since(kind), since)
        self.assertIsNone(contract.external_since('route_probe_signed'))  # never offered outside the built-in scanner
        self.assertIsNone(contract.external_since('no_such_kind'))

    def test_a_check_target_must_carry_the_hash_of_its_text(self):
        check = validator(contract.target_schema('nuclei_validate'))
        good = fixture('targets', 'nuclei_validate')
        self.assertEqual(good['template_sha256'], hashlib.sha256(good['template'].encode('utf-8')).hexdigest())
        self.assertTrue(check.is_valid(good))
        for bad in ({k: v for k, v in good.items() if k != 'template_sha256'}, {**good, 'template_sha256': SHA.upper()},
                    {**good, 'template_sha256': SHA[:-1]}, {**good, 'template_sha256': None}):
            with self.subTest(bad=str(bad.get('template_sha256'))[:8]):
                self.assertFalse(check.is_valid(bad))

    def test_a_check_result_may_echo_the_hash_and_nothing_else_new(self):
        check = validator(contract.result_schema('nuclei_validate'))
        good = fixture('results', 'nuclei_validate')
        self.assertTrue(SHA256_RE.match(good['template_sha256']))
        self.assertTrue(check.is_valid(good))
        self.assertTrue(check.is_valid({k: v for k, v in good.items() if k != 'template_sha256'}))  # a contract-3 Sentinel's result
        self.assertFalse(check.is_valid({**good, 'template_sha256': 'not-a-hash'}))


SHA256_RE = __import__('re').compile(r'^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
