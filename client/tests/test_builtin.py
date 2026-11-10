"""cvENGINE's built-in scanner (CVENGINE_SENTINEL_BUILTIN=1): its name, no self-update, no OpenVAS, info.builtin, the blob file and re-enrolment with
no person, the health check and watchdog on heartbeats, the vantage settings (egress proxy, private ranges) and signed-in nuclei."""
import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from unittest import mock

from client import __main__ as entry
from client import blob as blob_mod
from client import config, control, daemon, egress, httpclient, scope, signed_in, tools

BLOB = blob_mod.encode_blob({'enrollment_token': 'cve_enr_x', 'server_url': 'https://cve.example.test', 'scope': 'instance'})
BLOB2 = blob_mod.encode_blob({'enrollment_token': 'cve_enr_y', 'server_url': 'https://cve.example.test', 'scope': 'instance'})


class Env(unittest.TestCase):
    builtin = True

    def setUp(self):
        config.set_overrides({})
        self.addCleanup(config.set_overrides, {})
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.token = os.path.join(self.dir, 'token.json')
        self.blob_file = os.path.join(self.dir, 'blob')
        env = {'CVENGINE_SENTINEL_TOKEN_FILE': self.token, 'CVENGINE_SENTINEL_BLOB_FILE': self.blob_file}
        if self.builtin:
            env['CVENGINE_SENTINEL_BUILTIN'] = '1'
        patch = mock.patch.dict('os.environ', env)
        patch.start()
        self.addCleanup(patch.stop)
        for name in ('CVENGINE_SENTINEL_BLOB', 'CVENGINE_SENTINEL_NAME', 'CVENGINE_SENTINEL_UPDATE'):
            os.environ.pop(name, None)

    def write_blob(self, text):
        with open(self.blob_file, 'w', encoding='utf-8') as handle:
            handle.write(text + '\n')


class ConfigTests(Env):
    def test_the_built_in_scanner_has_its_name_no_self_update_and_no_openvas(self):
        os.environ['CVENGINE_SENTINEL_NAME'] = 'something else'
        os.environ['CVENGINE_SENTINEL_UPDATE'] = 'automatic'
        config.set_overrides({'name': 'renamed', 'self_update': 'automatic'})
        self.assertEqual(config.sentinel_name(), 'CVEngine Scanner')
        self.assertEqual(config.self_update(), 'off')
        self.assertEqual(config.local_settings()['self_update'], 'off')
        self.assertIn('openvas', config.disabled_kinds())

    def test_info_says_built_in_with_its_features(self):
        with mock.patch('client.control.updater_info', return_value={'installed': False}):
            out = daemon.info()
        self.assertIs(out['builtin'], True)
        self.assertEqual(out['features'], ['secret_read', 'vantage'])

    def test_an_external_sentinel_advertises_bbot_keys_and_nothing_else(self):
        with mock.patch('client.control.updater_info', return_value={'installed': False}), mock.patch.object(config, 'builtin', return_value=False):
            out = daemon.info()
        self.assertEqual(out['features'], ['bbot_keys'])
        self.assertNotIn('builtin', out)
        self.assertEqual(out['contract_version'], config.CONTRACT_VERSION)

    def test_the_blob_is_read_from_the_file_afresh(self):
        self.assertIsNone(config.blob())
        self.write_blob(BLOB)
        self.assertEqual(config.blob(), BLOB)
        self.write_blob(BLOB2)
        self.assertEqual(config.blob(), BLOB2)

    def test_vantage_settings_are_cleaned_and_applied(self):
        config.set_overrides({'vantage': {'proxies': ['socks5://user:pw@198.51.100.7:1080', 'ftp://198.51.100.7', 'http://x y'],
                                          'bypass': ['.example.org'], 'proxy_private': True,
                                          'private_ranges': ['100.64.0.0/10', '8.8.8.0/24', '127.0.0.0/8', 'nonsense']}})
        self.assertEqual(config.vantage(), {'proxies': ['socks5://user:pw@198.51.100.7:1080'], 'bypass': ['.example.org'], 'proxy_private': True,
                                            'private_ranges': ['100.64.0.0/10']})

    def test_the_private_ranges_open_the_scope_floor_for_those_networks_only(self):
        with self.assertRaises(scope.ScopeError):
            scope.check_ip('100.101.102.103')
        config.set_overrides({'vantage': {'private_ranges': ['100.64.0.0/10']}})
        self.assertEqual(scope.check_ip('100.101.102.103'), '100.101.102.103')
        for refused in ('10.0.0.5', '127.0.0.1', '169.254.169.254'):
            with self.assertRaises(scope.ScopeError):
                scope.check_ip(refused)


class ExternalTests(Env):
    builtin = False

    def test_an_external_sentinel_ignores_the_vantage_settings(self):
        config.set_overrides({'vantage': {'proxies': ['http://198.51.100.7:3128'], 'private_ranges': ['100.64.0.0/10']}})
        self.assertEqual(config.vantage(), {})
        self.assertEqual(egress.for_tool('nuclei', ['https://www.example.com']), [])
        with self.assertRaises(scope.ScopeError):
            scope.check_ip('100.101.102.103')

    def test_an_external_sentinel_reports_no_builtin_flag(self):
        with mock.patch('client.control.updater_info', return_value={'installed': False}):
            self.assertNotIn('builtin', daemon.info())

    def test_an_external_sentinel_refuses_a_signed_in_task(self):
        engine = daemon.Daemon('https://cve.example.test', 't', client=mock.Mock())
        task = {'id': 7, 'kind': 'nuclei_targeted', 'signed_in': True, 'target': {'targets': ['https://www.example.com']}}
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'nuclei_targeted': runner}), self.assertRaises(tools.TargetError):
            engine._execute(task, lambda proc: None)
        runner.assert_not_called()
        engine.client.call.assert_not_called()


class EgressTests(Env):
    def setUp(self):
        super().setUp()
        config.set_overrides({'vantage': {'proxies': ['http://u:p@198.51.100.7:3128'], 'bypass': ['internal.example.org']}})

    def test_each_tool_gets_the_proxy_the_server_would_give_it(self):
        self.assertEqual(egress.for_tool('nuclei', ['https://www.example.com']), ['-proxy', 'http://u:p@198.51.100.7:3128'])
        self.assertEqual(egress.for_tool('wpscan', ['https://www.example.com']), ['--proxy', 'http://198.51.100.7:3128', '--proxy-auth', 'u:p'])
        self.assertEqual(egress.for_tool('wafw00f', ['www.example.com']), ['-p', 'http://u:p@198.51.100.7:3128'])

    def test_a_run_whose_destinations_all_bypass_the_proxy_stays_direct(self):
        self.assertEqual(egress.for_tool('nuclei', ['https://a.internal.example.org', 'https://10.0.0.4']), [])

    def test_a_tool_no_proxy_suits_never_runs_directly(self):
        with self.assertRaises(egress.ProxyUnavailable):
            egress.for_tool('testssl', ['www.example.com'])  # testssl.sh cannot send a proxy login

    def test_the_proxy_login_is_not_logged_with_the_settings(self):
        self.assertNotIn('u:p', str(daemon._shown('vantage', config.vantage())))


class HealthTests(Env):
    def write(self, **kw):
        control.write_status('v', 0, None, **kw)

    def test_a_built_in_scanner_without_a_heartbeat_for_three_minutes_is_unhealthy(self):
        now = time.time()
        self.write(heartbeat_at=now - 200, started_at=now - 3600)
        ok, why = control.health(now=now)
        self.assertFalse(ok)
        self.assertIn('no heartbeat', why)
        self.assertFalse(control.heartbeat(now=now)[0])

    def test_a_recent_heartbeat_is_healthy(self):
        now = time.time()
        self.write(heartbeat_at=now - 30, started_at=now - 3600)
        self.assertEqual(control.health(now=now), (True, ''))
        self.assertEqual(control.heartbeat(now=now), (True, ''))

    def test_a_fresh_start_has_three_minutes_but_is_not_yet_ready_for_the_updater(self):
        now = time.time()
        self.write(heartbeat_at=None, started_at=now - 60)
        self.assertTrue(control.health(now=now)[0])
        self.assertFalse(control.heartbeat(now=now)[0])

    def test_waiting_for_the_enrollment_is_healthy(self):
        control.write_enrolling()
        self.assertTrue(control.health()[0])
        self.assertFalse(control.heartbeat()[0])
        self.assertEqual(control.main(['heartbeat']), 1)

    def test_the_watchdog_sees_a_stale_heartbeat(self):
        engine = daemon.Daemon('https://cve.example.test', 't', client=mock.Mock())
        self.assertTrue(engine.watchdog)
        engine.started_at = time.time() - 600
        self.assertTrue(engine.heartbeat_stale())
        engine.heartbeat_ok_at = time.time() - 10
        self.assertFalse(engine.heartbeat_stale())

    def test_a_successful_heartbeat_is_recorded(self):
        engine = daemon.Daemon('https://cve.example.test', 't', client=mock.Mock())
        engine.client.call.return_value = {}
        engine._heartbeat_once()
        self.assertIsNotNone(engine.heartbeat_ok_at)
        self.assertIsNotNone(control.read_status().get('heartbeat_at'))


class ReenrollTests(Env):
    def setUp(self):
        super().setUp()
        for patch in (mock.patch('client.__main__.signal.signal'), mock.patch('client.__main__.httpclient.Client'),
                      mock.patch.object(entry, 'BLOB_POLL_SECONDS', 0.01)):
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(mock.patch.stopall)

    def test_a_rejected_token_makes_it_enrol_again_from_the_next_blob(self):
        daemon.save_token(self.token, 'cve_old', 'https://cve.example.test')
        self.write_blob(BLOB)
        runs = []

        def run(engine):
            runs.append(engine)
            if len(runs) == 1:
                self.assertTrue(engine._auth_failed(httpclient.ApiError(401, 'expired')))
        with mock.patch.object(daemon.Daemon, 'run', autospec=True, side_effect=run), \
                mock.patch('client.daemon.register', return_value={}), \
                mock.patch('client.daemon.bootstrap', return_value=('cve_new', 'https://cve.example.test')) as bootstrap:
            entry.main()
        self.assertEqual(len(runs), 2)
        bootstrap.assert_called_once()
        self.assertEqual(bootstrap.call_args[0][0], BLOB)
        self.assertEqual(daemon.load_token(self.token), ('cve_new', 'https://cve.example.test'))

    def test_a_redeemed_blob_is_not_tried_again(self):
        self.write_blob(BLOB)
        entry._mark_spent(BLOB)
        stop = entry._Stop()
        calls = []

        def later(_seconds):
            calls.append(1)
            if len(calls) == 2:
                self.write_blob(BLOB2)
            return False
        with mock.patch.object(stop.event, 'wait', side_effect=later):
            self.assertEqual(entry._wait_for_blob(stop), BLOB2)

    def test_a_refused_blob_waits_for_a_new_one_and_never_exits(self):
        self.write_blob(BLOB)
        attempts = []

        def bootstrap(raw, *_args):
            attempts.append(raw)
            if raw == BLOB:
                self.write_blob(BLOB2)
                raise httpclient.ApiError(400, 'the enrollment was already used')
            return 'cve_tok', 'https://cve.example.test'
        with mock.patch('client.daemon.bootstrap', side_effect=bootstrap):
            token, url, unsaved = entry._bootstrap(entry._Stop())
        self.assertEqual(attempts, [BLOB, BLOB2])
        self.assertEqual(token, 'cve_tok')
        self.assertFalse(unsaved)


class SignedInTests(Env):
    def test_the_credential_is_read_once_used_through_a_private_file_and_wiped(self):
        client = mock.Mock()
        client.call.return_value = {'credential': {'headers': [['Authorization', 'Bearer s3cr3t-token']], 'cookie': 'sid=abcdef123'}}
        seen = {}

        def runner(targets, tags=None, severities=None, register=None, templates=None, secret_file=None, timeout=None):
            seen['path'] = secret_file
            seen['mode'] = stat.S_IMODE(os.stat(secret_file).st_mode)
            seen['dir_mode'] = stat.S_IMODE(os.stat(os.path.dirname(secret_file)).st_mode)
            with open(secret_file, encoding='utf-8') as handle:
                seen['document'] = json.load(handle)
            return {'findings': [{'name': 'x', 'matched_at': 'https://www.example.com/?t=s3cr3t-token', 'description': 'sid=abcdef123'}]}
        engine = daemon.Daemon('https://cve.example.test', 't', client=client)
        task = {'id': 9, 'kind': 'nuclei_targeted', 'signed_in': True,
                'target': {'targets': ['https://www.example.com', 'http://www.example.com:8080'], 'tags': ['cve'], 'severities': ['high']}}
        with mock.patch.dict(tools.RUNNERS, {'nuclei_targeted': runner}):
            out = engine._execute(task, lambda proc: None)
        client.call.assert_called_once_with('POST', 'sentinel/tasks/9/secret')
        self.assertEqual(seen['mode'], 0o600)
        self.assertEqual(seen['dir_mode'], 0o700)
        self.assertFalse(os.path.exists(seen['path']))
        secret = seen['document']['static'][0]
        self.assertEqual(secret['domains'], ['www.example.com', 'www.example.com:8080'])
        self.assertIn({'key': 'Cookie', 'value': 'sid=abcdef123'}, secret['headers'])
        self.assertNotIn('s3cr3t-token', json.dumps(out))
        self.assertNotIn('abcdef123', json.dumps(out))

    def test_a_refused_read_is_an_error_and_nothing_runs(self):
        client = mock.Mock()
        client.call.side_effect = httpclient.ApiError(409, 'already read')
        engine = daemon.Daemon('https://cve.example.test', 't', client=client)
        task = {'id': 9, 'kind': 'nuclei_targeted', 'signed_in': True, 'target': {'targets': ['https://www.example.com']}}
        runner = mock.Mock()
        with mock.patch.dict(tools.RUNNERS, {'nuclei_targeted': runner}), self.assertRaises(tools.TargetError):
            engine._execute(task, lambda proc: None)
        runner.assert_not_called()

    def test_nuclei_gets_the_secrets_file_without_redirects(self):
        path = os.path.join(self.dir, 'secrets.json')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write('{}')
        with mock.patch('client.tools._run', return_value='') as run, mock.patch('client.tools.validate_targets', return_value=['https://www.example.com']):
            tools.run_nuclei(['https://www.example.com'], secret_file=path)
        argv = run.call_args[0][0]
        self.assertEqual(argv[argv.index('-sf') + 1], path)
        self.assertIn('-dr', argv)

    def test_the_domains_follow_the_servers_rule(self):
        self.assertEqual(signed_in.domain_of('https://www.example.com:443'), 'www.example.com')
        self.assertEqual(signed_in.domain_of('www.example.com:8443'), 'www.example.com:8443')
        self.assertEqual(signed_in.domain_of('http://[2001:db8::1]:8080'), '[2001:db8::1]:8080')


if __name__ == '__main__':
    unittest.main()
