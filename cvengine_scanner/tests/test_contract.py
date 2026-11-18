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
FROZEN = {'v1': contract.FIXTURES / 'results' / 'v1', 'v2': contract.FIXTURES / 'results' / 'v2', 'v3': contract.FIXTURES / 'results' / 'v3',
          'v4': contract.FIXTURES / 'results' / 'v4', 'v5': contract.FIXTURES / 'results' / 'v5',
          'v6': contract.FIXTURES / 'results' / 'v6', 'v7': contract.FIXTURES / 'results' / 'v7',
          'v8': contract.FIXTURES / 'results' / 'v8', 'v9': contract.FIXTURES / 'results' / 'v9'}
KIND_OF = {'nmap': 'nmap', 'naabu': 'naabu', 'nuclei_light': 'nuclei_light', 'testssl': 'testssl', 'nmap_udp': 'nmap_udp', 'wpscan': 'wpscan',
           'discover': 'discover', 'openvas': 'openvas', 'waf': 'waf', 'bbot_discovery': 'bbot_discovery', 'error': 'nmap', 'nmap_full': 'nmap_full', 'nmap_verify': 'nmap_verify',
           'node2shell': 'node2shell', 'rdp_shot': 'rdp_shot', 'db_probe': 'db_probe', 'path_probe': 'path_probe',
           'nuclei_validate': 'nuclei_validate', 'secrets_scan': 'secrets_scan', 'wpscan_thorough': 'wpscan_thorough',
           'alive_check': 'alive_check', 'bucket_check': 'bucket_check', 'dangling_dns_check': 'dangling_dns_check', 'dns_resolve': 'dns_resolve',
           'http_probe': 'http_probe', 'hygiene_check': 'hygiene_check', 'identity_check': 'identity_check', 'route_probe': 'route_probe',
           'route_probe_signed': 'route_probe_signed', 'ssh_probe': 'ssh_probe', 'subdir_probe': 'subdir_probe', 'supplier_check': 'supplier_check',
           'vhost_probe': 'vhost_probe', 'web_screenshot': 'web_screenshot', 'java_runtime': 'java_runtime',
           'version_read': 'version_read', 'version_digest': 'version_digest', 'version_rows': 'version_rows'}  # fixture name -> the kind it is a result of
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


V4_SHA256 = {  # every result fixture of contract version 4, copied when version 5 added the nmap detail, the cuts and the bbot finding port
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
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
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


V5_SHA256 = {  # every result fixture of contract version 5, copied when version 6 added java_runtime
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': '52e06dac5583e2980b367a4c286cb1687dd50f9e3d2716d517788371f6f32a72',
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
    'nmap.json': 'b68884c15e2fa12b6bc3bd7de551d02212d849f92cbcc58a22286c60e7ac6723',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': '67c100dde7fa5b9a4782e64fc76008bf08508fe12ac4f5db5c85aad89c6a64c7',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '32fc5c3af721579c63852774a4121d3e760b236c4cc3df3309954b707409fde3',
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


V6_SHA256 = {  # every result fixture of contract version 6, copied when version 7 added version_read
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': '52e06dac5583e2980b367a4c286cb1687dd50f9e3d2716d517788371f6f32a72',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'java_runtime.json': '06d985aafa1868ec16c5888ef29f889cb28d97bff36cdfbe6d31914bc5999c72',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': 'b68884c15e2fa12b6bc3bd7de551d02212d849f92cbcc58a22286c60e7ac6723',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': '67c100dde7fa5b9a4782e64fc76008bf08508fe12ac4f5db5c85aad89c6a64c7',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '32fc5c3af721579c63852774a4121d3e760b236c4cc3df3309954b707409fde3',
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


V7_SHA256 = {  # every result fixture of contract version 7, copied when version 8 added version_digest
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': '52e06dac5583e2980b367a4c286cb1687dd50f9e3d2716d517788371f6f32a72',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'java_runtime.json': '06d985aafa1868ec16c5888ef29f889cb28d97bff36cdfbe6d31914bc5999c72',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': 'b68884c15e2fa12b6bc3bd7de551d02212d849f92cbcc58a22286c60e7ac6723',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': '67c100dde7fa5b9a4782e64fc76008bf08508fe12ac4f5db5c85aad89c6a64c7',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '32fc5c3af721579c63852774a4121d3e760b236c4cc3df3309954b707409fde3',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'version_read.json': 'd3fa5932a93bb31678b6cf47b6cec1e21dcc1e7a907e24eff9de546218c3a84b',
    'vhost_probe.json': 'acbe876c4ac3ca04b4660ebb2b021f362c7010384079f3c1ea591305d5eec8ad',
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
    'web_screenshot.json': 'dc0992e6f2842f93e765e2f1b42d85379afbeb8fc5521e6e3ea4501b2d330bfb',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
    'wpscan_thorough.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}


V8_SHA256 = {  # every result fixture of contract version 8, copied when version 9 added version_rows
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': '52e06dac5583e2980b367a4c286cb1687dd50f9e3d2716d517788371f6f32a72',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'java_runtime.json': '06d985aafa1868ec16c5888ef29f889cb28d97bff36cdfbe6d31914bc5999c72',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': 'b68884c15e2fa12b6bc3bd7de551d02212d849f92cbcc58a22286c60e7ac6723',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': '67c100dde7fa5b9a4782e64fc76008bf08508fe12ac4f5db5c85aad89c6a64c7',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '32fc5c3af721579c63852774a4121d3e760b236c4cc3df3309954b707409fde3',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'version_digest.json': 'e9ca44bf76d392ec297934bfcf439767cf3fb55c40737284f53b069aaad9efd9',
    'version_read.json': 'd3fa5932a93bb31678b6cf47b6cec1e21dcc1e7a907e24eff9de546218c3a84b',
    'vhost_probe.json': 'acbe876c4ac3ca04b4660ebb2b021f362c7010384079f3c1ea591305d5eec8ad',
    'waf.json': '109fd92d329180c9ee7ba2e64337de0bd677023c6a85532e3154dd60aa69bcec',
    'web_screenshot.json': 'dc0992e6f2842f93e765e2f1b42d85379afbeb8fc5521e6e3ea4501b2d330bfb',
    'wpscan.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
    'wpscan_thorough.json': '548ae1d7ad40e9c5a81bf183a39fba3b3b7a270d92380da8602384db0d53b736',
}

V9_SHA256 = {  # every result fixture of contract version 9, copied when version 10 added the network detection pass (nuclei_light network_detection)
    'alive_check.json': '4a0f573792e25b1a3a11bb69975ec739479140733c4f5caad135d9a1743c2774',
    'bbot_discovery.json': '52e06dac5583e2980b367a4c286cb1687dd50f9e3d2716d517788371f6f32a72',
    'bucket_check.json': '4cfb30682f23402e37e43f2db93cfd051dcede5d0105830c7a75208f355377ae',
    'dangling_dns_check.json': 'b5365b04c46ba82f10d188b869c08837277cc93a66a737958a284b24718ed20e',
    'db_probe.json': '65706f26bb86e87d5663edacaedbf67e015b9bee7a12e93d448cc5a23fb04cc5',
    'discover.json': '6f9825383a3efbf69724ee168a07935d965b7b57add1605a79660d269cf8f5a6',
    'dns_resolve.json': 'd12186d5aff1986da8fb6520954b9a42223c7e72eea6f1e1603ff2d5d820d5c0',
    'error.json': 'f38516e7aecb480a2f749c9ee7fff22d0926d2056c82665754059ae05815f340',
    'http_probe.json': '87699372dff1cee946e0af5034996fd20bbff2c46188b9b669c2fb971a9a997c',
    'hygiene_check.json': '9a6b5f6fdbdf1c488ba46317e9e6d1a6e7262ab4eccacf95769d5a40375f387b',
    'identity_check.json': '07480dc1114d98efd8de3817b46c5a827db603c2115eb1d761c8d4c6798ec3b7',
    'java_runtime.json': '06d985aafa1868ec16c5888ef29f889cb28d97bff36cdfbe6d31914bc5999c72',
    'naabu.json': '91d1b7acdaeecedb10b027daf27dccac6cb1f833cfa58455264df3e7e846593d',
    'nmap.json': 'b68884c15e2fa12b6bc3bd7de551d02212d849f92cbcc58a22286c60e7ac6723',
    'nmap_full.json': '5239a81e847e9aef50931071469881e80feab7bdfc686b9e790a1b7e82b0b887',
    'nmap_udp.json': '517342dcf5e5c585cbd69aefd6a3f4849b9a4a26a9c9861d1f0a4f8eea4f666d',
    'nmap_verify.json': '32ce7fa875d4621b35aa744a0b738a21aa1100f84cbc81c15680af2579218254',
    'node2shell.json': 'a1e8bf54e04797a3a0db740d883b6b2d1ef61fd975bb9a15d5321a9dd9c2794c',
    'nuclei_light.json': '67c100dde7fa5b9a4782e64fc76008bf08508fe12ac4f5db5c85aad89c6a64c7',
    'nuclei_validate.json': 'c8cd0ec81b1f123c52aa4b623b2a399841168f3abd41ebffd723400e3c8b10d9',
    'openvas.json': '1f6166c56867cd631e6789455e5d83a2d47be7a5a3fdfb5b4e8988413862b224',
    'path_probe.json': 'fd7b7fd3666397df8a8f95a169912f30cf45d91ae9525ac90e507779a950d567',
    'rdp_shot.json': '3feabbb8d560f648ac6b72a4dff61c7370f2d66fee706e32e9608c63cc577f7d',
    'route_probe.json': '97473d76c5c39c8a82cdfd4225de9c3607ea7a029526ef998be5862d2afbb604',
    'route_probe_signed.json': '1f678106e041d5bf49d30a840e365d42ebd70274910e64d086f8c3ec4a186391',
    'secrets_scan.json': '32fc5c3af721579c63852774a4121d3e760b236c4cc3df3309954b707409fde3',
    'ssh_probe.json': '2e9a21973309044357eec19664b7c74e01e03d53b25fdf5e183bae4eee62dfd8',
    'subdir_probe.json': 'dbdbdb8319ff6136f819a1bc4db7b2da0d3b9564403fa6e4a332674cafffefba',
    'supplier_check.json': '2a7247d93165eec72b8ff2aef5f8722d92f5978254d04ae4c5f87dcf8f6f32d1',
    'testssl.json': '0c3e9354aa1432420761aece78877e727bfca1b760dd22e26dac1769c0ba5d80',
    'version_digest.json': 'e9ca44bf76d392ec297934bfcf439767cf3fb55c40737284f53b069aaad9efd9',
    'version_read.json': 'd3fa5932a93bb31678b6cf47b6cec1e21dcc1e7a907e24eff9de546218c3a84b',
    'version_rows.json': '27688bea93b1fdfef2e0547e09a42659bbca75a8017bd8dd10f1d2b5b7909c36',
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
        for v, want in (('v1', V1_SHA256), ('v2', V2_SHA256), ('v3', V3_SHA256), ('v4', V4_SHA256), ('v5', V5_SHA256), ('v6', V6_SHA256), ('v7', V7_SHA256), ('v8', V8_SHA256), ('v9', V9_SHA256)):
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

    def test_version_four_rules_hold_and_old_sentinels_are_still_served(self):
        self.assertEqual(contract.version(), 10)  # 10 since the network detection pass (class ContractVersionTenTests); the version-4 rules below still hold
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


class ContractVersionFiveTests(unittest.TestCase):
    """Version 5, strictly additive: the nmap fingerprint pass keeps what nmap learned (banner, extra info, CPEs, TLS, the certificate, the NSE output,
    the OS detail, the ports it scanned), every result that cut something says so in ``cuts``, a bbot finding carries its port. Every new field is
    optional, so a version 4 result (the frozen v4 fixtures) still validates."""

    def port(self, **extra):
        return {'number': 443, 'protocol': 'tcp', 'state': 'open', 'service_name': 'http', 'product': 'nginx', 'version': '1.25.3', **extra}

    def check_port(self, port):
        host = {'ip': '192.0.2.11', 'ports': [port]}
        return validator(contract.result_schema('nmap')).is_valid({'outcome': 'done', 'hosts': [host]})

    def test_the_fixture_carries_the_detail_and_a_version_four_result_is_still_valid(self):
        check = validator(contract.result_schema('nmap'))
        good = fixture('results', 'nmap')
        self.assertTrue(check.is_valid(good))
        for key in ('service_extra', 'method', 'tunnel', 'cpes', 'banner', 'scripts', 'tls'):
            self.assertTrue(any(key in port for port in good['hosts'][0]['ports']), key)
        for key in ('os_accuracy', 'os_matches', 'scanned_ranges', 'closed_tcp', 'hostscripts', 'status', 'extraports'):
            self.assertIn(key, good['hosts'][0])
        old = json.loads((FROZEN['v4'] / 'nmap.json').read_text(encoding='utf-8'))
        self.assertTrue(check.is_valid(old))

    def test_every_new_port_field_is_typed_and_bounded(self):
        cert = {'subject': 'commonName=web.example.test', 'issuer': 'commonName=R3', 'sans': ['DNS:web.example.test'], 'not_before': '2024-01-01T00:00:00',
                'not_after': '2024-04-01T00:00:00', 'key_type': 'rsa', 'key_bits': '2048', 'signature': 'sha256WithRSAEncryption', 'fingerprint_sha1': 'a' * 40}
        self.assertTrue(self.check_port(self.port(service_extra='Ubuntu', method='probed', tunnel='ssl', hostname='web.example.test', ostype='Linux', devicetype='',
                                                  confidence='10', cpe='cpe:/a:igor_sysoev:nginx:1.25.3', cpes=['cpe:/a:igor_sysoev:nginx:1.25.3'], banner='hello',
                                                  scripts={'http-title': 'Welcome'}, tls=cert)))
        for bad in ({'service_extra': 'x' * 201}, {'method': 'guessed'}, {'tunnel': 'tls'}, {'banner': 'x' * 1025}, {'cpes': ['cpe:/a:x'] * 9}, {'cpes': ['x' * 256]},
                    {'cpe': 5}, {'confidence': '11'}, {'scripts': {'banner': 'x' * 4001}}, {'scripts': {f's{i}': 'x' for i in range(25)}}, {'scripts': {'banner': 5}},
                    {'tls': {**cert, 'subject': 'x' * 301}}, {'tls': {**cert, 'sans': ['x'] * 41}}, {'tls': {**cert, 'fingerprint_sha1': 'zz'}},
                    {'tls': {**cert, 'surprise': 1}}, {'hostname': 'x' * 256}):
            with self.subTest(bad=str(bad)[:40]):
                self.assertFalse(self.check_port(self.port(**bad)))

    def test_every_new_host_field_is_typed_and_bounded(self):
        check = validator(contract.result_schema('nmap'))
        base = {'outcome': 'done', 'hosts': [{'ip': '192.0.2.11', 'ports': []}]}

        def with_host(**extra):
            return {**base, 'hosts': [{**base['hosts'][0], **extra}]}
        self.assertTrue(check.is_valid(with_host(os_accuracy=95, os_matches=[{'name': 'Linux 5.X', 'accuracy': 95, 'cpe': 'cpe:/o:linux:linux_kernel:5'}], closed_tcp=9999,
                                                 scanned_ranges=[[1, 1024], [8080, 8080]], hostscripts={'smb-os-discovery': 'OS: Windows'}, status='up', extraports=['closed'])))
        for bad in ({'os_accuracy': 101}, {'os_matches': [{'name': 'x' * 101}]}, {'os_matches': [{'name': 'a'}] * 4}, {'closed_tcp': 0}, {'closed_tcp': 65536},
                    {'scanned_ranges': [[0, 5]]}, {'scanned_ranges': [[1, 70000]]}, {'scanned_ranges': [[1]]}, {'scanned_ranges': [[1, 2, 3]]},
                    {'scanned_ranges': [[1, 2]] * 4097}, {'hostscripts': {'nbstat': 'x' * 4001}}, {'status': 'sideways'}, {'extraports': ['closed'] * 9}):
            with self.subTest(bad=str(bad)[:40]):
                self.assertFalse(check.is_valid(with_host(**bad)))

    def test_cuts_are_one_shape_on_every_result_that_can_cut(self):
        cut = {'what': 'events', 'kind': 'items', 'limit': 5000, 'dropped': 12}
        bases = {'nmap': {'outcome': 'done', 'hosts': []}, 'nuclei_light': {'outcome': 'done', 'findings': []}, 'nuclei_targeted': {'outcome': 'done', 'findings': []},
                 'nuclei_deep': {'outcome': 'done', 'findings': []}, 'bbot_discovery': fixture('results', 'bbot_discovery'), 'secrets_scan': fixture('results', 'secrets_scan')}
        for kind, base in bases.items():
            check = validator(contract.result_schema(kind))
            self.assertTrue(check.is_valid(base), kind)  # a version 4 Sentinel's result has none
            self.assertTrue(check.is_valid({**base, 'cuts': [cut, {'what': 'time_limit', 'kind': 'time', 'limit': 3600}, {'what': 'ports', 'kind': 'items', 'limit': 500, 'dropped': 3, 'target': '192.0.2.1'}]}), kind)
            for bad in ('events', [{'what': 'events'}], [{**cut, 'kind': 'bytes'}], [{**cut, 'dropped': -1}], [{**cut, 'what': 'x' * 41}], [{**cut, 'extra': 1}],
                        [{**cut, 'target': 'x' * 261}], [cut] * 25, [{**cut, 'dropped': 1.5}]):
                with self.subTest(kind=kind, bad=str(bad)[:40]):
                    self.assertFalse(check.is_valid({**base, 'cuts': bad}))

    def test_a_bbot_finding_may_carry_its_port(self):
        check = validator(contract.partial_schema('bbot_discovery'))
        good = fixture('partials', 'bbot_discovery')
        self.assertTrue(check.is_valid(good))
        finding = good['findings'][0]
        self.assertTrue(check.is_valid({**good, 'findings': [{**finding, 'port': 8443}]}))
        self.assertTrue(check.is_valid({**good, 'findings': [{k: v for k, v in finding.items() if k != 'port'}]}))
        for bad in (0, 65536, '443', 1.5, True):
            self.assertFalse(check.is_valid({**good, 'findings': [{**finding, 'port': bad}]}), bad)


SHA256_RE = __import__('re').compile(r'^[0-9a-f]{64}$')


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
                       {'budget': {'pause_ms': 0}}, {'budget': {'pause_ms': 1.5}}, {'budget': {'web_rate': 1001}}, {'budget': {'seconds': 'long'}}, {'budget': {'rate': 2}},
                       {'budget': {'surprise': 1}}):
            self.assertFalse(check.is_valid({**good, **change}), change)
        self.assertTrue(check.is_valid({**good, 'services': {}, 'budget': {}}))


class NucleiNotCheckedResultTests(unittest.TestCase):
    """A nuclei result names each port it did not fully check, and why, so no port is skipped in silence."""

    def test_the_result_may_name_the_ports_it_did_not_check(self):
        base = fixture('results', 'nuclei_light')
        for kind in ('nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            check = validator(contract.result_schema(kind))
            self.assertTrue(check.is_valid(base), kind)  # an older Sentinel's result has none
            self.assertTrue(check.is_valid({**base, 'not_checked': [{'target': 'example.com:22', 'reason': 'nothing answered on this port'}]}), kind)
            for bad in ([{'target': 'example.com:22'}], [{'target': 'example.com:22', 'reason': 'x' * 201}], 'example.com:22',
                        [{'target': 'example.com:22', 'reason': 'x', 'extra': 1}], [{'target': 'a', 'reason': 'b'}] * 65):
                self.assertFalse(check.is_valid({**base, 'not_checked': bad}), (kind, bad))


if __name__ == '__main__':
    unittest.main()


class ContractVersionSixTests(unittest.TestCase):
    """Version 6 adds one kind, ``java_runtime``: the Java runtime reads of web hosts already identified as a product and the JDWP handshake on debug
    ports. A Sentinel declaring 5 or older is never offered it (``kind_since``), and every other kind is unchanged (the frozen v5 set still validates)."""

    def test_the_kind_is_new_in_six(self):
        self.assertEqual(contract.kind_since('java_runtime'), 6)
        self.assertEqual(contract.version(), 10)  # 10 since the network detection pass (ContractVersionTenTests); java_runtime is unchanged
        self.assertEqual(contract.min_supported(), 1)

    def test_the_target_names_only_the_fixed_checks_and_needs_a_scope(self):
        check = validator(contract.target_schema('java_runtime'))
        good = fixture('targets', 'java_runtime')
        self.assertTrue(check.is_valid(good))
        web = good['web'][0]
        for bad in ({**good, 'web': [{**web, 'checks': ['actuator', 'heapdump']}]}, {**good, 'web': [{**web, 'checks': []}]},
                    {**good, 'web': [{**web, 'path': '/actuator/env'}]}, {k: v for k, v in good.items() if k != 'scope'},
                    {'scope': good['scope']}, {**good, 'jdwp': [{'id': 'x', 'address': '192.0.2.1', 'port': 0}]},
                    {**good, 'jdwp': [{'id': 'x', 'address': '192.0.2.1', 'port': 5005, 'command': 'classes'}]},
                    {**good, 'web': [web] * 51}):
            with self.subTest(bad=str(bad)[:60]):
                self.assertFalse(check.is_valid(bad))

    def test_a_reading_is_typed_and_bounded(self):
        check = validator(contract.result_schema('java_runtime'))
        good = fixture('results', 'java_runtime')
        self.assertTrue(check.is_valid(good))
        reading = good['web'][0]['readings'][0]
        for bad in ({**reading, 'source': 'bundled_inference'}, {**reading, 'confidence': 'certain'}, {**reading, 'major': 0},
                    {**reading, 'evidence': 'x' * 301}, {**reading, 'version': ''}, {**reading, 'secret': 'x'}):
            with self.subTest(bad=str(bad)[:60]):
                self.assertFalse(check.is_valid({**good, 'web': [{**good['web'][0], 'readings': [bad]}]}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'refused'}))
        self.assertFalse(check.is_valid({'outcome': 'done', 'web': []}))  # a done result lists both halves
        self.assertTrue(check.is_valid({**good, 'jdwp': [{'id': 'a', 'speaks': None, 'reading': None, 'error': 'not run: excluded'}]}))


class ContractVersionSevenTests(unittest.TestCase):
    """Version 7 adds one kind, ``version_read``: the anonymous GETs of the server's version source catalogue, each answer handed back only in the
    part the request names. A Sentinel declaring 6 or older is never offered it (``kind_since``), and every other kind is unchanged (the frozen v6
    set still validates)."""

    def test_the_kind_is_new_in_seven(self):
        self.assertEqual(contract.kind_since('version_read'), 7)
        self.assertEqual(contract.version(), 10)  # 10 since the network detection pass (ContractVersionTenTests); version_read is unchanged
        self.assertEqual(contract.min_supported(), 1)

    def test_the_target_is_get_only_bounded_and_needs_a_scope(self):
        check = validator(contract.target_schema('version_read'))
        good = fixture('targets', 'version_read')
        self.assertTrue(check.is_valid(good))
        read = good['reads'][0]
        request = read['requests'][0]
        for bad in ({**good, 'reads': [{**read, 'requests': [{**request, 'method': 'POST'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'path': 'https://other.example/'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'path': '/a b'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'read': 'body'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'headers': ['set-cookie']}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'headers': ['Authorization']}]}]},
                    {**good, 'reads': [{**read, 'requests': [request] * 5}]},
                    {**good, 'reads': [{**read, 'requests': []}]},
                    {**good, 'reads': [read] * 101}, {**good, 'reads': []},
                    {k: v for k, v in good.items() if k != 'scope'}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid(bad))

    def test_an_answer_never_carries_a_body(self):
        check = validator(contract.result_schema('version_read'))
        good = fixture('results', 'version_read')
        self.assertTrue(check.is_valid(good))
        answer = good['reads'][0]['answers'][0]
        for bad in ({**answer, 'body': '<html>'}, {**answer, 'json': {'version': 'x' * 201}}, {**answer, 'text': 'x' * 1025},
                    {**answer, 'lines': ['x'] * 41}, {**answer, 'json': {'env': {'secret': 'x'}}}, {**answer, 'status': 1000}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid({**good, 'reads': [{**good['reads'][0], 'answers': [bad]}]}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'refused'}))
        self.assertFalse(check.is_valid({'outcome': 'done', 'touched': []}))  # a done result lists its reads
        self.assertTrue(check.is_valid({**good, 'reads': [{'id': 'a', 'answers': [], 'error': 'not run: the host is excluded'}]}))


class ContractVersionEightTests(unittest.TestCase):
    """Version 8 adds one kind, ``version_digest``: a version_read whose requests may also ask for a digest of a static asset (its SHA-256 and
    first bytes) instead of the asset. A Sentinel declaring 7 or older is never offered it (``kind_since``); ``version_read`` itself is unchanged
    and never carries a digest read, so a contract 7 Sentinel keeps running it (the frozen v7 set still validates)."""

    def test_the_kind_is_new_in_eight(self):
        self.assertEqual(contract.kind_since('version_digest'), 8)
        self.assertEqual(contract.version(), 10)  # 10 since the network detection pass (ContractVersionTenTests); version_digest is unchanged
        self.assertEqual(contract.min_supported(), 1)

    def test_version_read_never_takes_a_digest_read(self):
        good = fixture('targets', 'version_read')
        read = good['reads'][0]
        self.assertFalse(validator(contract.target_schema('version_read')).is_valid(
            {**good, 'reads': [{**read, 'requests': [{'path': '/a.js', 'read': 'digest'}]}]}))

    def test_the_target_is_get_only_bounded_and_needs_a_scope(self):
        check = validator(contract.target_schema('version_digest'))
        good = fixture('targets', 'version_digest')
        self.assertTrue(check.is_valid(good))
        read = good['reads'][0]
        request = read['requests'][0]
        for bad in ({**good, 'reads': [{**read, 'requests': [{**request, 'method': 'POST'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'read': 'body'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'headers': ['cookie']}]}]},
                    {**good, 'reads': [{**read, 'requests': [request] * 5}]}, {**good, 'reads': []},
                    {k: v for k, v in good.items() if k != 'scope'}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid(bad))

    def test_an_answer_carries_a_digest_never_a_body(self):
        check = validator(contract.result_schema('version_digest'))
        good = fixture('results', 'version_digest')
        self.assertTrue(check.is_valid(good))
        answer = good['reads'][0]['answers'][0]
        for bad in ({**answer, 'body': 'x'}, {**answer, 'digest': {'head': 'ab' * 17}}, {**answer, 'digest': {'head': 'xyz'}},
                    {**answer, 'digest': {'sha256': 'a' * 63, 'head': ''}}, {**answer, 'digest': {'head': '', 'bytes': 'x'}},
                    {**answer, 'digest': {}}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid({**good, 'reads': [{**good['reads'][0], 'answers': [bad]}]}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'refused'}))
        self.assertFalse(check.is_valid({'outcome': 'done', 'touched': []}))


class ContractVersionNineTests(unittest.TestCase):
    """Version 9 adds one kind, ``version_rows``: a version_read whose requests may also ask for only the named version rows of a status page
    (Apache's ``/server-status?auto``, a phpinfo page) instead of any of its body. A Sentinel declaring 8 or older is never offered it
    (``kind_since``); ``version_read`` and ``version_digest`` are unchanged and never carry a rows read (the frozen v8 set still validates)."""

    def test_the_kind_is_new_in_nine(self):
        self.assertEqual(contract.kind_since('version_rows'), 9)
        self.assertEqual(contract.version(), 10)  # 10 since the network detection pass (ContractVersionTenTests); version_rows is unchanged
        self.assertEqual(contract.min_supported(), 1)

    def test_version_read_and_version_digest_never_take_a_rows_read(self):
        for kind in ('version_read', 'version_digest'):
            good = fixture('targets', kind)
            read = good['reads'][0]
            with self.subTest(kind=kind):
                self.assertFalse(validator(contract.target_schema(kind)).is_valid(
                    {**good, 'reads': [{**read, 'requests': [{'path': '/server-status?auto', 'read': 'rows', 'fields': ['ServerVersion']}]}]}))

    def test_the_target_is_get_only_bounded_and_needs_a_scope(self):
        check = validator(contract.target_schema('version_rows'))
        good = fixture('targets', 'version_rows')
        self.assertTrue(check.is_valid(good))
        read = good['reads'][0]
        request = read['requests'][0]
        for bad in ({**good, 'reads': [{**read, 'requests': [{**request, 'method': 'POST'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'read': 'digest'}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'fields': ['<td>']}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'fields': ['x'] * 13}]}]},
                    {**good, 'reads': [{**read, 'requests': [{**request, 'headers': ['cookie']}]}]},
                    {**good, 'reads': [{**read, 'requests': [request] * 5}]}, {**good, 'reads': []},
                    {k: v for k, v in good.items() if k != 'scope'}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid(bad))

    def test_an_answer_carries_rows_never_a_body(self):
        check = validator(contract.result_schema('version_rows'))
        good = fixture('results', 'version_rows')
        self.assertTrue(check.is_valid(good))
        answer = good['reads'][1]['answers'][0]
        for bad in ({**answer, 'body': 'x'}, {**answer, 'rows': {'PHP Version': '<b>8.2.12</b>'}}, {**answer, 'rows': {'PHP Version': 'x' * 121}},
                    {**answer, 'rows': {'<td>': '8.2.12'}}, {**answer, 'rows': {f'Row {i}': '1.0' for i in range(13)}},
                    {**answer, 'digest': {'head': ''}}):
            with self.subTest(bad=str(bad)[:80]):
                self.assertFalse(check.is_valid({**good, 'reads': [{**good['reads'][1], 'answers': [bad]}]}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'refused'}))
        self.assertFalse(check.is_valid({'outcome': 'done', 'touched': []}))


class ContractVersionTenTests(unittest.TestCase):
    """Version 10 adds no kind and changes no result: a ``nuclei_light`` target may carry ``network_detection: true``, which makes the task the network detection
    pass (the ``network/detection/`` templates of each non-web port's class, ``client.tools.run_nuclei``). The server sends it only to a Sentinel that declared 10
    or later (``flags.NUCLEI_DETECTION_SINCE``); the result is a nuclei_light result as before, so the frozen v9 set still validates."""

    def test_the_version_is_ten_and_no_kind_is_new(self):
        self.assertEqual(contract.version(), 10)
        self.assertEqual(contract.min_supported(), 1)
        self.assertEqual(max(contract.load()['kind_since'].values()), 9)
        from cvengine_scanner import flags
        self.assertEqual(flags.NUCLEI_DETECTION_SINCE, contract.version())

    def test_only_a_light_target_takes_the_field_and_only_as_a_boolean(self):
        good = fixture('targets', 'nuclei_light')
        light = validator(contract.target_schema('nuclei_light'))
        self.assertTrue(light.is_valid(good))  # a target without it is the light pass as before
        detection = {**good, 'targets': ['example.com:6379', 'example.com:3389'], 'tags': [], 'services': {'example.com:6379': 'redis', 'example.com:3389': 'rdp'},
                     'budget': {'pause_ms': 500, 'seconds': 240, 'web_rate': 25}, 'network_detection': True}
        self.assertTrue(light.is_valid(detection))
        for bad in ('yes', 1, None, {'on': True}):
            with self.subTest(bad=bad):
                self.assertFalse(light.is_valid({**detection, 'network_detection': bad}))
        for kind in ('nuclei_targeted', 'nuclei_deep'):
            with self.subTest(kind=kind):
                self.assertFalse(validator(contract.target_schema(kind)).is_valid({**fixture('targets', 'nuclei_light'), 'network_detection': True}))

    def test_a_light_result_of_the_pass_is_an_ordinary_light_result(self):
        check = validator(contract.result_schema('nuclei_light'))
        found = {'template_id': 'openssh-detect', 'name': 'OpenSSH Service - Detect', 'severity': 'info', 'host': 'example.com', 'matched_at': 'example.com:22',
                 'description': 'OpenSSH service was detected.', 'matcher_name': '', 'extracted_results': ['SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'],
                 'tags': ['network', 'ssh', 'openssh', 'detect'], 'type': 'tcp'}
        self.assertTrue(check.is_valid({'outcome': 'done', 'findings': [found], 'not_checked': [{'target': 'example.com:993', 'reason': 'no check exists for this service'}]}))
