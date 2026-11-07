"""The ssh_probe parser (``probes.ssh_probe``): the captured OpenSSH sample, an unreachable target, a port that is not SSH, bad and oversized output."""
import copy
import json
import re
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from cvengine_scanner import contract
from cvengine_scanner.probes import ssh_probe

SAMPLE = (Path(__file__).resolve().parent.parent / 'fixtures' / 'ssh_probe_openssh.jsonl').read_text(encoding='utf-8')
ADDRESS, PORT = '192.0.2.10', 22
REPO = Path(__file__).resolve().parents[3]


def by_id(entry):
    return {o['id']: o for o in entry['observations']}


def valid(hosts):
    schema = contract.result_schema('ssh_probe')
    doc = {'outcome': 'done', 'hosts': hosts, 'touched': [], 'refused': []}
    return sorted(Draft202012Validator(schema).iter_errors(doc), key=str)


class SampleTests(unittest.TestCase):
    def test_the_captured_openssh_sample_gives_banner_keys_methods_algorithms_and_extensions(self):
        entry = ssh_probe.parse_host(ADDRESS, PORT, SAMPLE, True)
        obs = by_id(entry)
        self.assertTrue(entry['reached'])
        self.assertNotIn('error', entry)
        self.assertIn('SSH-2.0-OpenSSH_10.3', obs['ssh_banner']['evidence'])
        self.assertEqual(obs['ssh_hostkeys']['evidence'], 'ecdsa-sha2-nistp256 256 bits; ssh-ed25519 256 bits; ssh-rsa 3072 bits')
        self.assertEqual(obs['ssh_auth_methods']['evidence'], 'publickey, password, keyboard-interactive')
        self.assertIn('mlkem768x25519-sha256', obs['ssh_algorithms_kexalgos']['evidence'])
        self.assertIn('chacha20-poly1305@openssh.com', obs['ssh_algorithms_cipherc2s']['evidence'])
        self.assertIn('ping@openssh.com', obs['ssh_extensions']['evidence'])
        self.assertTrue(all(o['verified'] for o in entry['observations']))
        self.assertEqual({o['severity'] for o in entry['observations']}, {0})
        self.assertEqual(entry['check_hits'], [])
        self.assertEqual(valid([entry]), [])

    def test_it_does_not_report_what_nuclei_already_reports(self):
        text = json.dumps(dict(json.loads(SAMPLE), version='SSH-2.0-OpenSSH_4.3', methods=['password'],
                               kex={**json.loads(SAMPLE)['kex'], 'cipherC2S': ['3des-cbc', 'arcfour']}))
        entry = ssh_probe.parse_host(ADDRESS, PORT, text, True)
        self.assertEqual({o['severity'] for o in entry['observations']}, {0})
        for o in entry['observations']:
            self.assertNotRegex(o['id'] + o['title'], r'(?i)weak|obsolete|outdated|password_auth|enabled')

    def test_without_the_blocklist_data_the_keys_are_unverified_never_clean(self):
        entry = ssh_probe.parse_host(ADDRESS, PORT, SAMPLE, False)
        obs = by_id(entry)
        self.assertFalse(obs['badkeys_not_checked']['verified'])
        self.assertNotIn('badkeys_blocklist_clear', obs)
        self.assertTrue(valid([entry]) == [])

    def test_with_the_data_and_no_hit_the_keys_are_reported_as_checked(self):
        obs = by_id(ssh_probe.parse_host(ADDRESS, PORT, SAMPLE, True))
        self.assertTrue(obs['badkeys_blocklist_clear']['verified'])
        self.assertNotIn('badkeys_not_checked', obs)

    def test_the_age_of_the_blocklist_data_is_in_the_evidence(self):
        for hours, text in ((0, '0 hours old'), (1, '1 hour old'), (30, '30 hours old'), (None, 'age unknown')):
            obs = by_id(ssh_probe.parse_host(ADDRESS, PORT, SAMPLE, True, hours))
            self.assertIn(f'host key blocklist data: {text}', obs['badkeys_blocklist_clear']['evidence'])
        obs = by_id(ssh_probe.parse_host(ADDRESS, PORT, SAMPLE, False))
        self.assertIn('host key blocklist data: not present', obs['badkeys_not_checked']['evidence'])

    def test_a_blocklisted_host_key_is_a_check_hit_and_a_critical_observation(self):
        doc = json.loads(SAMPLE)
        doc['vulns'] = [{'id': 'badkeys-git-example-keys-abc', 'ref': 'https://badkeys.info/', 'proof': 'https://example.com/keys/1'},
                        {'id': 'something-else', 'ref': 'x', 'proof': 'y'}]
        entry = ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), True)
        self.assertEqual(entry['check_hits'], [{'check': 'badkeys-blocklist', 'id': 'badkeys-git-example-keys-abc', 'ref': 'https://badkeys.info/',
                                                'proof': 'https://example.com/keys/1'}])
        hit = by_id(entry)['badkeys_blocklist_hit']
        self.assertEqual((hit['severity'], hit['verified']), (4, True))
        self.assertNotIn('badkeys_blocklist_clear', by_id(entry))
        self.assertEqual(valid([entry]), [])

    def test_a_hit_is_not_read_when_the_check_could_not_have_run(self):
        doc = json.loads(SAMPLE)
        doc['vulns'] = [{'id': 'badkeys-x', 'ref': '', 'proof': ''}]
        self.assertEqual(ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), False)['check_hits'], [])

    def test_key_sizes(self):
        self.assertEqual(ssh_probe.key_bits(json.loads(SAMPLE)['hostkeys']['ssh-rsa']), ('ssh-rsa', 3072))
        with self.assertRaises(ValueError):
            ssh_probe.key_bits('not base64!')
        with self.assertRaises(ValueError):
            ssh_probe.key_bits('AAAA')


class UnknownTests(unittest.TestCase):
    def assert_unknown(self, entry):
        self.assertFalse(entry['reached'])
        self.assertTrue(entry['error'])
        self.assertTrue(entry['observations'])
        self.assertFalse(any(o['verified'] for o in entry['observations']))
        self.assertEqual(entry['check_hits'], [])
        self.assertEqual(valid([entry]), [])

    def test_an_unreachable_target_writes_nothing_and_is_unverified(self):
        self.assert_unknown(ssh_probe.parse_host('198.51.100.7', 22, '', True))
        self.assert_unknown(ssh_probe.parse_host('198.51.100.7', 22, '\n  \n', True))

    def test_a_port_that_is_not_ssh_is_unverified(self):
        doc = dict(json.loads(SAMPLE), version='HTTP/1.1 400 Bad Request')
        entry = ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), True)
        self.assert_unknown(entry)
        self.assertEqual(entry['observations'][0]['id'], 'ssh_not_identified')
        doc.pop('version')
        self.assert_unknown(ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), True))

    def test_unparseable_output_is_unverified(self):
        self.assert_unknown(ssh_probe.parse_host(ADDRESS, PORT, '{"host": "192.0.2.10", "port": 22, "vers', True))
        self.assert_unknown(ssh_probe.parse_host(ADDRESS, PORT, '[1, 2]\n', True))

    def test_an_entry_for_another_address_or_port_is_not_this_targets(self):
        self.assert_unknown(ssh_probe.parse_host('192.0.2.99', PORT, SAMPLE, True))
        self.assert_unknown(ssh_probe.parse_host(ADDRESS, 2222, SAMPLE, True))

    def test_missing_pieces_are_unverified_observations_not_empty_ones(self):
        doc = json.loads(SAMPLE)
        doc.pop('methods')
        doc['hostkeys'] = {'ssh-rsa': 'AAAA'}
        doc['kex'].pop('macC2S')
        doc['kex']['kexAlgos'] = 'not a list'
        obs = by_id(ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), True))
        self.assertFalse(obs['ssh_auth_methods']['verified'])
        self.assertFalse(obs['ssh_hostkeys']['verified'])
        self.assertFalse(obs['ssh_algorithms_missing']['verified'])
        self.assertIn('MACs client-to-server', obs['ssh_algorithms_missing']['evidence'])
        self.assertNotIn('ssh_algorithms_macc2s', obs)

    def test_oversized_output_is_unverified(self):
        big = SAMPLE + ' ' * ssh_probe.MAX_OUTPUT_BYTES
        entry = ssh_probe.parse_host(ADDRESS, PORT, big, True)
        self.assert_unknown(entry)
        self.assertIn('larger', entry['error'])


class ClipTests(unittest.TestCase):
    def test_every_size_is_clipped_and_text_is_printable_ascii(self):
        doc = json.loads(SAMPLE)
        doc['version'] = 'SSH-2.0-' + 'A' * 1000 + '\x07\u00e9'
        doc['methods'] = ['m' * 500] * 500
        doc['kex']['kexAlgos'] = ['k' * 500] * 500
        doc['extensions'] = {f'e{i}': 'v' * 500 for i in range(500)}
        doc['vulns'] = [{'id': 'badkeys-' + 'i' * 900, 'ref': 'r' * 900, 'proof': 'p' * 900}] * 100
        entry = ssh_probe.parse_host(ADDRESS, PORT, json.dumps(doc), True)
        self.assertLessEqual(len(entry['observations']), ssh_probe.MAX_OBSERVATIONS)
        self.assertLessEqual(len(entry['check_hits']), ssh_probe.MAX_CHECK_HITS)
        for o in entry['observations']:
            self.assertLessEqual(len(o['evidence']), ssh_probe.EVIDENCE_LEN)
            self.assertLessEqual(len(o['title']), ssh_probe.TITLE_LEN)
            self.assertTrue(re.fullmatch(r'[\x20-\x7e]*', o['evidence']))
        for h in entry['check_hits']:
            self.assertLessEqual((len(h['id']), len(h['ref']), len(h['proof'])), (200, 200, 300))
        self.assertEqual(valid([entry]), [])


class ArgvTests(unittest.TestCase):
    def argv(self, **kw):
        return ssh_probe.build_argv('sshamble', kw.get('address', ADDRESS), kw.get('port', 22), '/tmp/out.jsonl')

    def test_the_command_line_is_the_one_in_the_notes(self):
        self.assertEqual(self.argv(), ['sshamble', 'scan', '-p', '22', '--checks', 'badkeys-blocklist', '--timeout', '5', '-m', '4', '-o', '/tmp/out.jsonl',
                                       '-l', '/dev/null', ADDRESS])

    def test_any_other_checks_value_is_refused(self):
        for checks in ('', 'badkeys-blocklist,vuln-sshhole', 'all', 'userenum', None, ['badkeys-blocklist']):
            with self.subTest(checks=checks), self.assertRaises(ssh_probe.ArgvError):
                ssh_probe.build_argv('sshamble', ADDRESS, 22, '/tmp/o', checks=checks)

    def test_no_credential_related_flag_can_ever_be_passed(self):
        base = self.argv()
        self.assertEqual(ssh_probe.check_argv(base), base)
        for flag in ssh_probe.FORBIDDEN_FLAGS:
            for extra in ([flag], [flag, 'x'], [flag + '=x']):
                for position in (2, len(base) - 1, len(base)):
                    argv = base[:position] + extra + base[position:]
                    with self.subTest(flag=flag, extra=extra, position=position), self.assertRaises(ssh_probe.ArgvError):
                        ssh_probe.check_argv(argv)
        # nor in place of an argument, nor as the address, port or output file
        for bad in (['sshamble', 'scan', '-p', '22', '--checks', 'badkeys-blocklist', '--timeout', '5', '-m', '4', '-o', '/tmp/o', '-l', '/dev/null', '--password'],
                    ['sshamble', 'analyze'] + base[2:], ['sshamble', 'badkeys-update'] + base[2:]):
            with self.assertRaises(ssh_probe.ArgvError):
                ssh_probe.check_argv(bad)
        for kw in ({'address': '--password'}, {'address': ''}, {'port': 0}, {'port': 70000}, {'port': '22; id'}):
            with self.subTest(kw=kw), self.assertRaises(ssh_probe.ArgvError):
                self.argv(**kw)
        with self.assertRaises(ssh_probe.ArgvError):
            ssh_probe.build_argv('sshamble', ADDRESS, 22, '--private-key')

    def test_the_dockerfile_pins_the_same_version(self):
        text = (REPO / 'Dockerfile').read_text(encoding='utf-8')
        self.assertEqual(re.search(r'^ARG SSHAMBLE_VERSION=(\S+)$', text, re.M).group(1), ssh_probe.SSHAMBLE_VERSION)
        for arch in ('AMD64', 'ARM64'):
            self.assertRegex(text, rf'(?m)^ARG SSHAMBLE_SHA256_{arch}=[0-9a-f]{{64}}$')


class FixtureTests(unittest.TestCase):
    def test_the_kind_is_in_contract_version_3_and_the_fixtures_validate(self):
        self.assertEqual(contract.kind_since('ssh_probe'), 3)
        fixture = json.loads((contract.FIXTURES / 'results' / 'ssh_probe.json').read_text(encoding='utf-8'))
        self.assertEqual(list(Draft202012Validator(contract.result_schema('ssh_probe')).iter_errors(fixture)), [])
        bad = copy.deepcopy(fixture)
        bad['hosts'][0]['observations'][0].pop('verified')
        self.assertTrue(list(Draft202012Validator(contract.result_schema('ssh_probe')).iter_errors(bad)))
        target = json.loads((contract.FIXTURES / 'targets' / 'ssh_probe.json').read_text(encoding='utf-8'))
        self.assertEqual(list(Draft202012Validator(contract.target_schema('ssh_probe')).iter_errors(target)), [])
        target['targets'][0]['extra'] = 1
        self.assertTrue(list(Draft202012Validator(contract.target_schema('ssh_probe')).iter_errors(target)))

    def test_a_done_result_names_its_hosts(self):
        check = Draft202012Validator(contract.result_schema('ssh_probe'))
        self.assertFalse(check.is_valid({'outcome': 'done'}))
        self.assertTrue(check.is_valid({'outcome': 'error', 'error': 'x'}))


if __name__ == '__main__':
    unittest.main()
