"""Settings the server manages: this machine's own are reported, the most recent of the two is applied."""
import threading
import time
import unittest
from unittest import mock

from client import config, daemon, httpclient
from client.tests.test_daemon import FakeClient


class Base(unittest.TestCase):
    def setUp(self):
        config.set_overrides({})
        patch = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NAME': 'box', 'CVENGINE_SENTINEL_MAX_CONCURRENT': '2'}, clear=False)
        patch.start()
        self.addCleanup(patch.stop)
        for name in ('CVENGINE_SENTINEL_NETWORK', 'CVENGINE_SENTINEL_DISABLE', 'CVENGINE_SENTINEL_PROFILE'):
            mock.patch.dict('os.environ').start()
            __import__('os').environ.pop(name, None)
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(config.set_overrides, {})
        gvm = mock.patch('client.tools.gvm_available', return_value=True)
        gvm.start()


class ConfigTests(Base):
    def test_local_settings_ignore_what_the_server_set(self):
        config.set_overrides({'network': 'internal', 'max_concurrent': 7, 'name': 'renamed'})
        self.assertEqual(config.local_settings(), {'name': 'box', 'network': 'external', 'disabled_kinds': [], 'max_concurrent': 2})
        self.assertEqual((config.is_internal(), config.max_concurrent(), config.sentinel_name()), (False, 7, 'renamed'))  # the server cannot raise the network

    def test_with_nothing_set_by_the_server_this_machine_is_in_charge(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal', 'CVENGINE_SENTINEL_DISABLE': 'wpscan'}):
            self.assertEqual((config.is_internal(), config.disabled_kinds(), config.max_concurrent(), config.sentinel_name()), (True, {'wpscan'}, 2, 'box'))
            self.assertEqual(config.local_settings()['network'], 'internal')

    def test_a_light_profile_never_runs_openvas_and_a_machine_can_state_its_profile(self):
        config.set_overrides({'profile': 'light'})
        self.assertIn('openvas', config.disabled_kinds())
        config.set_overrides({})
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_PROFILE': 'Light'}):
            self.assertEqual(config.local_settings()['profile'], 'light')
            self.assertIn('openvas', config.disabled_kinds())

    def test_the_server_can_add_disabled_kinds_but_never_lift_the_machines_own(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISABLE': 'wpscan'}):
            config.set_overrides({'disabled_kinds': ['testssl']})
            self.assertEqual(config.disabled_kinds(), {'wpscan', 'testssl'})
            config.set_overrides({'disabled_kinds': []})  # the server "re-enabling" everything: the local veto stands
            self.assertEqual(config.disabled_kinds(), {'wpscan'})
            self.assertNotIn('wpscan', daemon.declared_kinds())

    def test_local_disabled_entries_are_normalised_and_unknown_ones_logged_once(self):
        with mock.patch.object(config, '_warned_disabled', set()), \
                mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_DISABLE': ' WPScan, bogus ,openvas,,'}):
            with self.assertLogs('sentinel.config', 'WARNING') as logs:
                self.assertEqual(config.disabled_kinds(), {'wpscan', 'openvas'})
            self.assertIn('bogus', logs.output[0])
            with self.assertNoLogs('sentinel.config', 'WARNING'):
                config.disabled_kinds()
            self.assertEqual(config.local_settings()['disabled_kinds'], ['openvas', 'wpscan'])

    def test_an_unnamed_machine_reports_no_name_but_still_has_one(self):
        __import__('os').environ.pop('CVENGINE_SENTINEL_NAME', None)
        with mock.patch('socket.gethostname', return_value='0123456789ab'):
            self.assertNotIn('name', config.local_settings())  # a container id must never undo a rename made in cvENGINE
            self.assertEqual(config.sentinel_name(), '0123456789ab')
            fc = FakeClient()
            with mock.patch('client.tools.detect_tools', return_value=[]):
                daemon.register(fc, config.sentinel_name(), 2)
            body = fc.body_for('sentinel')
            self.assertEqual(body['name'], '0123456789ab')  # registration still names it, for first enrolment
            self.assertNotIn('name', body['settings'])
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NAME': 'office'}):
            self.assertEqual(config.local_settings()['name'], 'office')

    def test_the_polled_kinds_follow_the_effective_network_at_every_call(self):
        self.assertNotIn('discover', config.poll_kinds())
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'}):
            self.assertIn('discover', config.poll_kinds())
            self.assertIn('network:internal', config.registered_capabilities())
            config.set_overrides({'network': 'external'})  # the server pulls an internal Sentinel back
            self.assertNotIn('discover', config.poll_kinds())
            self.assertNotIn('network:internal', config.registered_capabilities())
            config.set_overrides({})
            self.assertIn('discover', config.poll_kinds())
        self.assertNotIn('discover', config.poll_kinds())
        self.assertEqual(config.poll_kinds(['nmap']), ['nmap'])  # an explicit list (tests only) is taken as given

    def test_the_server_cannot_make_an_external_sentinel_internal(self):
        config.set_overrides({'network': 'internal'})
        self.assertFalse(config.is_internal())
        self.assertNotIn('discover', config.poll_kinds())
        self.assertNotIn('network:internal', config.registered_capabilities())
        from client import scope
        self.assertFalse(scope.internal_allowed())

    def test_overrides_are_swapped_whole_never_mutated(self):
        config.set_overrides({'disabled_kinds': ['wpscan']})
        before = config._overrides
        config.set_overrides({'disabled_kinds': ['testssl']})
        self.assertIsNot(config._overrides, before)
        self.assertEqual(before, {'disabled_kinds': ['wpscan']})  # a reader still holding the old dict sees a whole one

    def test_a_concurrent_reader_never_sees_a_half_replaced_override(self):
        config.set_overrides({'disabled_kinds': ['wpscan']})
        stop = threading.Event()
        misses = []

        def read():
            while not stop.is_set():
                if 'wpscan' not in config.disabled_kinds():
                    misses.append(1)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        for _ in range(3000):
            config.set_overrides({'disabled_kinds': ['wpscan']})
        stop.set()
        reader.join(timeout=5)
        self.assertEqual(misses, [])

    def test_junk_from_the_server_is_dropped_not_obeyed(self):
        config.set_overrides({'name': 'a\nb\x07', 'network': 'dmz', 'profile': 'huge', 'disabled_kinds': ['nmap', 'rm -rf /', 3], 'max_concurrent': 99,
                              'extra': 'x'})
        self.assertEqual(config.overrides(), {'name': 'ab', 'disabled_kinds': ['nmap']})
        config.set_overrides({'max_concurrent': True, 'name': '   ', 'disabled_kinds': 'nmap'})
        self.assertEqual(config.overrides(), {})


class ApplyTests(Base):
    def make(self):
        fc = FakeClient()
        d = daemon.Daemon('https://x.example', 'tok', client=fc)
        sent = []
        d.reregister = lambda: sent.append(dict(config.overrides()))
        return d, sent

    def test_registration_reports_this_machines_own_settings(self):
        fc = FakeClient()
        config.set_overrides({'network': 'internal'})
        with mock.patch('client.tools.detect_tools', return_value=[]):
            daemon.register(fc, 'box', 2)
        self.assertEqual(fc.body_for('sentinel')['settings'], {'name': 'box', 'network': 'external', 'disabled_kinds': [], 'max_concurrent': 2})

    def test_a_new_setting_is_applied_and_registered_once(self):
        env = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'})
        env.start()
        self.addCleanup(env.stop)
        d, sent = self.make()
        self.assertIn('network:internal', daemon.declared_kinds())
        reply = {'values': {'network': 'external', 'max_concurrent': 5}, 'rev': 'r1'}
        d.apply_settings(reply)
        d.apply_settings(reply)  # the same revision again: nothing to do
        self.assertEqual(sent, [{'network': 'external', 'max_concurrent': 5}])
        self.assertEqual((config.is_internal(), d.max_concurrent), (False, 5))
        self.assertNotIn('network:internal', daemon.declared_kinds())

    def test_the_server_handing_a_setting_back_restores_this_machines_own(self):
        env = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'})
        env.start()
        self.addCleanup(env.stop)
        d, sent = self.make()
        d.apply_settings({'values': {'network': 'external'}, 'rev': 'r1'})
        self.assertFalse(config.is_internal())
        d.apply_settings({'values': {}, 'rev': 'r2'})
        self.assertEqual(sent, [{'network': 'external'}, {}])
        self.assertTrue(config.is_internal())

    def test_an_unchanged_effect_does_not_register_again(self):
        env = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_NETWORK': 'internal'})
        env.start()
        self.addCleanup(env.stop)
        d, sent = self.make()
        d.apply_settings({'values': {'network': 'external'}, 'rev': 'r1'})
        d.apply_settings({'values': {'network': 'external'}, 'rev': 'r2'})  # a new revision with the same effect
        self.assertEqual(len(sent), 1)

    def test_a_failed_registration_is_retried_on_the_next_heartbeat(self):
        d, _ = self.make()
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) == 1:
                raise httpclient.ApiError(503, 'down')
        d.reregister = flaky
        reply = {'values': {'max_concurrent': 4}, 'rev': 'r1'}
        d.apply_settings(reply)
        d.apply_settings(reply)
        self.assertEqual(len(calls), 2)

    def test_a_reply_without_settings_changes_nothing(self):
        d, sent = self.make()
        for reply in (None, {}, {'values': 'x'}, 'x'):
            d.apply_settings(reply)
        self.assertEqual(sent, [])

    def test_the_heartbeat_reply_carries_settings_to_the_daemon(self):
        class Beat(FakeClient):
            def call(self, method, path, body=None, timeout=None):
                if path == 'sentinel/heartbeat':
                    self.calls.append((method, path, body))
                    return {'leases': [], 'settings': {'values': {'max_concurrent': 6}, 'rev': 'h1'}}
                return super().call(method, path, body, timeout)
        d = daemon.Daemon('https://x.example', 'tok', client=Beat(), heartbeat_seconds=0.01)
        d.reregister = lambda: None
        thread = threading.Thread(target=d._heartbeat_loop, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        while d.max_concurrent != 6 and time.monotonic() < deadline:
            time.sleep(0.01)
        d.request_stop()
        thread.join(timeout=2)
        self.assertEqual(d.max_concurrent, 6)
