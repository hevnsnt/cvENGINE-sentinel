"""A tool that ran out of time is reported in plain words (1.4.0 tool review).

The daemon reported ``str(exc)`` clipped to 280 characters, and ``subprocess.TimeoutExpired`` says ``Command '[<the whole argv>]' timed out after N seconds``:
for the fingerprint pass the argv alone is over 400 characters, so the user read the start of a command line and never the words ``timed out``."""
import subprocess
import unittest
from unittest import mock

from client import tools
from client.tests.test_daemon import DaemonTestCase, wait_for

LONG_ARGV = ['nmap', '-sV', '--version-intensity', '7', '-O', '--osscan-limit', '-Pn', '-T4', '--max-retries', '2', '--min-hostgroup', '32', '--script',
             'banner,ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers,http-title,http-server-header,http-generator,ftp-anon,rdp-ntlm-info,rdp-enum-encryption',
             '--script-timeout', '30s', '-n', '--open', '--host-timeout', '8m', '--top-ports', '1000', '-oX', '-', '-iL', '/tmp/targets.txt']


class TimeoutIsSaidInWords(DaemonTestCase):
    def reported(self, exc):
        self.fc.next_responses = [{'task': {'id': 55, 'kind': 'nmap', 'target': {'addresses': ['192.0.2.1']}}}]
        d = self.make()

        def runner(*args, **kwargs):
            raise exc
        with mock.patch.dict(tools.RUNNERS, {'nmap': runner}):
            d._poll_once()
            self.assertTrue(wait_for(lambda: self.fc.count('sentinel/tasks/55/result') == 1))
        return [body for _m, path, body in self.fc.calls if path.endswith('/55/result')][0]

    def test_a_tool_stopped_at_its_limit_says_which_tool_and_what_limit(self):
        body = self.reported(subprocess.TimeoutExpired(LONG_ARGV, 600))
        self.assertEqual(body['outcome'], 'error')
        self.assertNotIn('Command', body['error'])
        self.assertIn('nmap', body['error'])
        self.assertIn('600', body['error'])
        self.assertIn('time limit', body['error'])

    def test_any_other_error_is_reported_as_before(self):
        self.assertEqual(self.reported(RuntimeError('boom'))['error'], 'boom')


if __name__ == '__main__':
    unittest.main()
