"""The secrets_scan kind on the Sentinel (cvENGINE docs/SECRETS-PLAN.md 5.1, 6.2 and 13): what Kingfisher may be asked to do, what the fetcher may
read, the report read back, the second pass only when allowed, and the temporary directory gone afterwards. Kingfisher itself is replaced here
(the real binary has its own module, test_secrets_kingfisher)."""
import json
import os
import unittest
from unittest import mock

from client import config, daemon, scope, secrets_scan, tools
from cvengine_scanner import contract
from cvengine_scanner import secrets as kf

NAMES = {'www.example.test': ['93.184.215.14'], 'inside.example.test': ['10.0.0.5']}
PAGE = b'<html><script src="/app.js"></script><script>var k="AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw";</script></html>'
SCRIPT = (b'var db="https://example-app-default-rtdb.firebaseio.com"; var b="example-assets.s3.amazonaws.com";\n'
          b'//# sourceMappingURL=app.js.map\n')
MAP = json.dumps({'version': 3, 'sources': ['a.ts'], 'sourcesContent': ['const x = 1;']}).encode()


def fake_getaddrinfo(name, port, *args, **kwargs):
    if name not in NAMES:
        raise OSError('no such host')
    return [(2, 1, 6, '', (a, 0)) for a in NAMES[name]]


def setUpModule():
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=fake_getaddrinfo),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'})),
                    mock.patch.object(scope, 'internal_allowed', return_value=False)):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


def target(**changes):
    out = json.loads((contract.FIXTURES / 'targets' / 'secrets_scan.json').read_text().replace('www.example.com', 'www.example.test'))
    out['hosts'][0]['urls'] = ['https://www.example.test/', 'https://elsewhere.example.net/']
    out['hosts'][0]['script_urls'] = ['https://www.example.test/app.js', 'https://cdn.example.net/lib.js']
    out.update(changes)
    return out


class Site:
    def __init__(self):
        self.asked = []

    def __call__(self, url, address, limit):
        self.asked.append((url, address))
        body = {'https://www.example.test/': (200, 'text/html', PAGE), 'https://www.example.test/app.js': (200, 'application/javascript', SCRIPT),
                'https://www.example.test/app.js.map': (200, 'application/json', MAP)}.get(url, (404, 'text/html', b'not found'))
        return body[0], body[1], body[2] if len(body[2]) <= limit else None, ''


def report(manifest_dir):
    """A Kingfisher report for what the reader wrote: the Google key in the page file."""
    page = next(name for name in os.listdir(manifest_dir) if name.endswith('.html'))
    return json.dumps({'findings': [
        {'rule': {'id': 'betterleaks.gcp-api-key', 'name': 'gcp-api-key'},
         'finding': {'snippet': 'AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw', 'path': f'{manifest_dir}/{page}', 'line': 1, 'confidence': 'high',
                     'entropy': '4.7', 'validation': {'outcome': 'verified_active', 'status': 'Active', 'response': '{"metadata": {"gemini_access": true, "x": 1}}'},
                     'validate_command': 'kingfisher validate AIza...'}}]})


class ArgvTests(unittest.TestCase):
    def test_detection_never_validates_or_updates(self):
        argv = kf.scan_argv('kingfisher', '/w/in', '/w/out.json', skip_words=['EXAMPLE', '--self-update'])
        self.assertIn('--no-validate', argv)
        self.assertIn('--no-update-check', argv)
        self.assertIn('--no-dedup', argv)
        self.assertNotIn('--self-update', argv)  # a skip word that looks like a flag is dropped
        for bad in (['kingfisher', 'revoke', 'x'], ['kingfisher', 'self-update'], argv + ['--self-update'], [a for a in argv if a != '--no-validate'],
                    [a for a in argv if a != '--no-update-check'], argv + ['--allow-internal-ips'], argv + ['--access-map']):
            with self.assertRaises(kf.ArgvError):
                kf.check_argv(bad)

    def test_validation_takes_listed_rules_only_and_never_a_custom_one(self):
        argv = kf.validation_argv('kingfisher', 'in', 'out', ['betterleaks.github-pat', 'custom.mine', 'Bad Rule'])
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == '--rule'], ['betterleaks.github-pat'])
        self.assertNotIn('--no-validate', argv)
        self.assertEqual(argv[argv.index('--tls-mode') + 1], 'strict')
        with self.assertRaises(kf.ArgvError):
            kf.validation_argv('kingfisher', 'in', 'out', ['custom.mine'])

    def test_the_detection_pass_has_no_egress(self):
        env = kf.env_without_egress({'PATH': '/bin', 'HTTPS_PROXY': 'http://proxy.example:3128', 'NO_PROXY': '*'})
        self.assertEqual((env['HTTPS_PROXY'], env['https_proxy'], env['NO_PROXY'], env['PATH']), (kf.DEAD_PROXY, kf.DEAD_PROXY, '', '/bin'))


class ReportTests(unittest.TestCase):
    def test_the_contract_fields_only_and_a_pairs_secret_half(self):
        text = json.dumps({'findings': [
            {'rule': {'id': 'betterleaks.aws-access-token', 'name': 'aws'},
             'finding': {'snippet': 'AKIAIOSFODNN7EXAMPLE', 'path': 'in/1.js', 'line': 2, 'confidence': 'high', 'entropy': '3.6',
                         'dependent_captures': {'AWS_SECRET_ACCESS_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'},
                         'validation': {'outcome': 'verified_active', 'response': 'arn:aws:iam::1:user/x'}, 'validate_command': 'secret'}},
            {'rule': {'id': 'betterleaks.github-pat'}, 'finding': {'snippet': 'short', 'path': 'in/1.js'}},
            {'rule': {'id': 'betterleaks.github-pat'}, 'finding': {'snippet': 'ghp_' + 'a' * 36, 'path': 'in/unknown.js'}}]})
        findings, truncated = kf.read_report(text, {'1.js': {'url': 'https://www.example.test/app.js'}})
        self.assertFalse(truncated)
        self.assertEqual([(f['rule_id'], f['secret'][:4]) for f in findings],
                         [('betterleaks.aws-access-token', 'AKIA'), ('betterleaks.aws-secret-access-key', 'wJal')])
        self.assertEqual({f['validation']['outcome'] for f in findings}, {'not_attempted'})  # a detection pass reports no outcome
        self.assertNotIn('arn:aws', json.dumps(findings))
        self.assertNotIn('validate_command', json.dumps(findings))

    def test_storage_references_and_source_maps(self):
        refs = kf.references(SCRIPT.decode(), 'https://www.example.test/app.js')
        self.assertEqual({(r['kind'], r['value']) for r in refs},
                         {('firebase_rtdb', 'example-app-default-rtdb.firebaseio.com'), ('s3', 'example-assets')})
        self.assertEqual(kf.sourcemap_url('https://www.example.test/app.js', SCRIPT.decode()), 'https://www.example.test/app.js.map')
        self.assertIsNone(kf.sourcemap_url('https://www.example.test/app.js', '//# sourceMappingURL=https://evil.example.net/x.map'))
        self.assertIsNone(kf.sourcemap_url('https://www.example.test/app.js', '//# sourceMappingURL=data:application/json;base64,e30='))
        self.assertTrue(kf.sources_content(MAP))


class RunTests(unittest.TestCase):
    def run_task(self, task, kingfisher_report, version=kf.KINGFISHER_VERSION):
        site, calls, dirs = Site(), [], []

        def fake_kingfisher(argv, register, env=None):
            calls.append((argv, env))
            in_dir = argv[2]
            dirs.append(os.path.dirname(in_dir))
            out = argv[argv.index('--output') + 1]
            with open(out, 'w') as handle:
                handle.write(kingfisher_report(in_dir))
        with mock.patch.object(secrets_scan, '_kingfisher', side_effect=fake_kingfisher), \
                mock.patch.object(secrets_scan, '_version', return_value=version):
            result = secrets_scan.run(task, fetcher=site, sleep=lambda s: None)
        return result, site, calls, dirs

    def test_it_reads_the_hosts_own_pages_scripts_and_maps_and_nothing_else(self):
        result, site, calls, dirs = self.run_task(target(), report)
        self.assertEqual([u for u, _ in site.asked], ['https://www.example.test/', 'https://www.example.test/app.js', 'https://www.example.test/app.js.map'])
        self.assertEqual({a for _, a in site.asked}, {'93.184.215.14'})  # pinned to the judged address
        self.assertEqual(len(calls), 1)  # detection only: the task did not ask to validate
        argv, env = calls[0]
        self.assertIn('--no-validate', argv)
        self.assertEqual(env['HTTPS_PROXY'], kf.DEAD_PROXY)
        self.assertEqual([f['validation']['outcome'] for f in result['findings']], ['not_attempted'])
        self.assertEqual({f['kind'] for f in result['fetched']}, {'page', 'script', 'sourcemap'})
        self.assertTrue(next(f for f in result['fetched'] if f['kind'] == 'sourcemap')['sources_content'])
        self.assertEqual({r['kind'] for r in result['references']}, {'firebase_rtdb', 's3'})
        self.assertFalse(os.path.exists(dirs[0]))  # the bodies are gone with the task

    def test_a_host_outside_the_scope_or_behind_the_floor_is_never_read(self):
        task = target(hosts=[{'host': 'inside.example.test', 'urls': ['https://inside.example.test/']},
                             {'host': 'other.example.test', 'urls': ['https://other.example.test/']}])
        task['scope']['names'] = ['inside.example.test']
        result, site, calls, _ = self.run_task(task, report)
        self.assertEqual(site.asked, [])  # 10.0.0.5 is private; other.example.test is not in the scope
        self.assertEqual((result['findings'], calls), ([], []))

    def test_the_second_pass_runs_only_when_asked_and_on_the_reviewed_version(self):
        task = target(validate=True, validate_rules=['betterleaks.gcp-api-key'], validate_kingfisher=kf.KINGFISHER_VERSION)
        result, _, calls, _ = self.run_task(task, report)
        self.assertEqual(len(calls), 2)
        argv, env = calls[1]
        self.assertNotIn('--no-validate', argv)
        self.assertIsNone(env)
        self.assertEqual(result['findings'][0]['validation'], {'outcome': 'verified_active'})
        self.assertEqual(result['findings'][0]['validation_meta'], {'gemini_access': True})
        self.assertTrue(result['stats']['validated'])
        result, _, calls, _ = self.run_task(task, report, version='2.17.0')
        self.assertEqual((len(calls), result['stats']['validated']), (1, False))

    def test_the_runner_is_registered_and_one_runs_at_a_time(self):
        self.assertIs(tools.RUNNERS['secrets_scan'], tools.run_secrets_scan)
        self.assertIn('secrets_scan', config.CAPABILITIES)
        self.assertEqual(config.KIND_SINCE['secrets_scan'], 3)


class DeclareTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(config.set_server_contract, {})

    def test_declared_only_to_a_server_that_knows_it_and_only_with_the_binary(self):
        with mock.patch.object(tools, 'gvm_ready', return_value=False), mock.patch.object(tools, 'kingfisher_ready', return_value=True):
            config.set_server_contract({'contract': {'version': 2, 'min_supported': 1}})
            self.assertNotIn('secrets_scan', daemon.runnable_kinds())
            config.set_server_contract({'contract': {'version': 3, 'min_supported': 1}})
            self.assertIn('secrets_scan', daemon.runnable_kinds())
        with mock.patch.object(tools, 'gvm_ready', return_value=False), mock.patch.object(tools, 'kingfisher_ready', return_value=False):
            self.assertNotIn('secrets_scan', daemon.runnable_kinds())
