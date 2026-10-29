"""The entry point's startup order: token, registration, settings, run, and how it ends."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

import requests

from client import __main__ as entry
from client import config, daemon, httpclient


class MainTests(unittest.TestCase):
    def setUp(self):
        config.set_overrides({})
        self.addCleanup(config.set_overrides, {})
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, 'token.json')
        for patch in (mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_TOKEN_FILE': self.path, 'CVENGINE_SENTINEL_BLOB': 'blob'}),
                      mock.patch('client.__main__.signal.signal'), mock.patch('client.__main__.httpclient.Client')):
            patch.start()
            self.addCleanup(patch.stop)
        self.engines = []
        real_init = daemon.Daemon.__init__

        def init(engine, *args, **kwargs):
            real_init(engine, *args, **kwargs)
            self.engines.append(engine)
        patch = mock.patch.object(daemon.Daemon, '__init__', init)
        patch.start()
        self.addCleanup(patch.stop)
        self.run = mock.patch.object(daemon.Daemon, 'run').start()
        self.addCleanup(mock.patch.stopall)

    def test_a_revoked_token_at_startup_exits_non_zero_without_running(self):
        daemon.save_token(self.path, 'cve_tok', 'https://cve.example.test')
        with mock.patch('client.daemon.register', side_effect=httpclient.ApiError(401, 'revoked')), self.assertRaises(SystemExit) as end:
            entry.main()
        self.assertEqual(end.exception.code, 1)
        self.run.assert_not_called()

    def test_a_server_that_is_down_at_startup_leaves_the_registration_pending_and_runs(self):
        daemon.save_token(self.path, 'cve_tok', 'https://cve.example.test')
        with mock.patch('client.daemon.register', side_effect=requests.ConnectionError('down')):
            entry.main()
        self.run.assert_called_once()
        self.assertTrue(self.engines[0]._register_pending)

    def test_startup_registers_once_and_applies_the_settings_from_the_reply(self):
        daemon.save_token(self.path, 'cve_tok', 'https://cve.example.test')
        reply = {'settings': {'values': {'self_update': 'manual'}, 'rev': 'r1'}}
        with mock.patch('client.daemon.register', return_value=reply) as register:
            entry.main()
        register.assert_called_once()
        self.assertEqual(config.overrides(), {'self_update': 'manual'})

    def test_a_token_that_cannot_be_saved_after_bootstrap_is_kept_and_retried(self):
        with mock.patch('client.daemon.bootstrap', return_value=('cve_new', 'https://cve.example.test')), \
                mock.patch('client.daemon.save_token', side_effect=OSError('read-only')), mock.patch('client.daemon.register', return_value={}):
            entry.main()
        self.run.assert_called_once()
        self.assertEqual(self.engines[0]._unsaved_token, (self.path, 'cve_new', 'https://cve.example.test'))

    def test_a_daemon_stopped_for_a_revoked_token_exits_non_zero(self):
        daemon.save_token(self.path, 'cve_tok', 'https://cve.example.test')

        def revoked(engine):
            engine.exit_code = 1
        self.run.side_effect = lambda: revoked(self.engines[0])
        with mock.patch('client.daemon.register', return_value={}), self.assertRaises(SystemExit) as end:
            entry.main()
        self.assertEqual(end.exception.code, 1)


if __name__ == '__main__':
    unittest.main()
