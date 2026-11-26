"""A 403 that refuses this Sentinel's ADDRESS (cvENGINE's input guard banned it, its IP allowlist leaves it out, a proxy in front blocks it) is not a
refused token: the Sentinel says the server refused the address, backs off (doubling, at most 10 minutes) and never stops or asks to be re-enrolled.
A 401, or the server's JSON token error, still stops it as before."""
import unittest
from unittest import mock

from client import daemon, httpclient
from client.tests.test_daemon import DaemonTestCase, FakeClient
from client.tests.test_httpclient import FakeResponse, FakeSession

BANNED = httpclient.ApiError(403, 'HTTP 403', refusal='banned', json_error=False, excerpt='Access denied: this address is banned.')
OLD_SERVER_BAN = httpclient.ApiError(403, 'HTTP 403', json_error=False, excerpt='Access denied.')  # a server from before the mark
GUARD_JSON_BAN = httpclient.ApiError(403, 'This session or address has been blocked for sending malicious input.', refusal='banned', json_error=True)


class ReadingTheAnswer(unittest.TestCase):
    def call(self, status, body, headers=None):
        client = httpclient.Client('https://x.example', 'tok', session=FakeSession(FakeResponse(status, body, headers)))
        with self.assertRaises(httpclient.ApiError) as caught:
            client.call('POST', 'sentinel/heartbeat', {})
        return caught.exception

    def test_the_marked_ban_page_is_an_address_refusal_with_an_excerpt(self):
        exc = self.call(403, b'<html><body><h1>Access denied: this address is banned.</h1></body></html>', {'X-CVEngine-Refusal': 'banned'})
        self.assertEqual((exc.refusal, exc.json_error), ('banned', False))
        self.assertEqual(exc.excerpt, 'Access denied: this address is banned.')
        self.assertTrue(daemon._address_refused(exc))

    def test_an_unmarked_page_from_an_older_server_or_a_proxy_is_an_address_refusal(self):
        exc = self.call(403, b'Access denied.')
        self.assertIsNone(exc.refusal)
        self.assertTrue(daemon._address_refused(exc))

    def test_the_servers_token_and_rights_refusals_are_not(self):
        for status, body in ((401, b'{"error": "invalid, expired or revoked token"}'),
                             (403, b'{"error": "this token is not allowed to do that"}'),
                             (403, b'{"error": "no work can be assigned", "code": "agent_blocked"}'),
                             (403, b'{"error": "token revoked", "code": "token_revoked"}')):
            with self.subTest(status=status, body=body):
                exc = self.call(status, body)
                self.assertTrue(exc.json_error)
                self.assertFalse(daemon._address_refused(exc))

    def test_an_error_built_by_hand_is_unknown_and_never_read_as_a_ban(self):
        self.assertFalse(daemon._address_refused(httpclient.ApiError(403, 'no')))


class BackingOff(DaemonTestCase):
    def poll(self, d, answer):
        self.fc.script[('POST', 'sentinel/tasks/next')] = [answer]
        waits = []
        with mock.patch.object(d.stop_event, 'wait', side_effect=waits.append):
            d._poll_once()
        return waits

    def test_a_banned_poll_backs_off_doubling_to_ten_minutes_and_never_stops(self):
        d = self.make()
        seen = []
        with self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            for _ in range(8):
                seen += self.poll(d, BANNED)
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))
        self.assertEqual(self.fc.count('sentinel'), 0, 'asked GET sentinel although the address was refused')
        self.assertTrue(30 * 0.8 <= seen[0] <= 30, seen)
        self.assertTrue(all(b >= a * 0.8 for a, b in zip(seen, seen[1:])), seen)
        self.assertLessEqual(max(seen), daemon.REFUSED_MAX_BACKOFF)
        self.assertGreaterEqual(max(seen), daemon.REFUSED_MAX_BACKOFF * 0.8)
        text = '\n'.join(logs.output)
        self.assertIn('the server refused this address (banned or blocked): Access denied: this address is banned.', text)
        self.assertNotIn('re-enroll it', text)
        self.assertEqual(text.count('refused this address'), 1, 'logged at every poll')

    def test_an_unmarked_ban_from_an_older_server_backs_off_too(self):
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='WARNING'):
            self.poll(d, OLD_SERVER_BAN)
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))

    def test_the_guards_json_ban_is_read_by_its_mark(self):
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='WARNING'):
            self.poll(d, GUARD_JSON_BAN)
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))

    def test_a_banned_heartbeat_or_registration_never_stops_it(self):
        self.fc.script[('POST', 'sentinel/heartbeat')] = [BANNED]
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='WARNING') as logs:
            d._heartbeat_once()
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))
        self.assertNotIn('re-enroll it', '\n'.join(logs.output))
        d.reregister = mock.Mock(side_effect=BANNED)
        d._refresh_registration(force=True)
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (False, 0))
        self.assertTrue(d._register_pending)

    def test_the_backoff_starts_over_once_the_server_answers(self):
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='WARNING'):
            for _ in range(3):
                self.poll(d, BANNED)
        self.assertGreater(d._refused_backoff, daemon.REFUSED_MIN_BACKOFF)
        self.fc.next_responses = [{'task': None}]
        with mock.patch.object(d.stop_event, 'wait'):
            d._poll_once()
        self.assertEqual(d._refused_backoff, daemon.REFUSED_MIN_BACKOFF)

    def test_a_401_still_stops_it_with_the_re_enroll_advice(self):
        d = self.make()
        with self.assertLogs('sentinel.daemon', level='ERROR') as logs:
            self.poll(d, httpclient.ApiError(401, 'invalid, expired or revoked token', json_error=True))
        self.assertEqual((d.stop_event.is_set(), d.exit_code), (True, 1))
        self.assertIn('re-enroll', '\n'.join(logs.output))


if __name__ == '__main__':
    unittest.main()
