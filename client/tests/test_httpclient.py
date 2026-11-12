"""The REST wrapper: https only, redirects never followed, one default timeout."""
import unittest
from unittest import mock

from client import httpclient


class FakeResponse:
    def __init__(self, status, payload=b'{}', headers=None):
        self.status_code = status
        self.content = payload
        self.headers = headers or {}

    def json(self):
        return __import__('json').loads(self.content)

    def iter_content(self, chunk_size=None):
        for i in range(0, len(self.content), chunk_size or 65536):
            yield self.content[i:i + (chunk_size or 65536)]

    def close(self):
        pass


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.response


class Base(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_ALLOW_INSECURE': ''})
        patch.start()
        self.addCleanup(patch.stop)


class ServerUrlTests(Base):
    def test_validate_server_url_accepts_https_and_refuses_the_rest(self):
        self.assertEqual(httpclient.validate_server_url('https://cve.example.test'), 'https://cve.example.test')
        for bad in ('http://cve.example.test', 'https://u:p@cve.example.test', 'https://cve.example.test?x=1', 'https://cve.example.test#f',
                    'https:///path', '', None, 42, 'cve.example.test', 'https://cve.example.test/\nx'):
            with self.subTest(url=bad), self.assertRaises(httpclient.ServerURLError):
                httpclient.validate_server_url(bad)

    def test_the_error_is_a_value_error_for_callers_that_catch_those(self):
        self.assertTrue(issubclass(httpclient.ServerURLError, ValueError))

    def test_every_client_refuses_plain_http(self):
        with self.assertRaises(httpclient.ServerURLError):
            httpclient.Client('http://evil.example', 'tok', session=FakeSession(FakeResponse(200)))

    def test_plain_http_with_the_opt_in_warns_at_every_start(self):
        with mock.patch.dict('os.environ', {'CVENGINE_SENTINEL_ALLOW_INSECURE': '1'}):
            for _ in range(2):
                with self.assertLogs('sentinel.http', 'WARNING') as logs:
                    client = httpclient.Client('http://cve.lab.test', 'tok', session=FakeSession(FakeResponse(200)))
                self.assertIn('INSECURE', logs.output[0])
        self.assertEqual(client.base, 'http://cve.lab.test/api/v1/')

    def test_the_proxy_environment_is_still_honoured(self):
        client = httpclient.Client('https://cve.example.test', 'tok')
        self.assertTrue(client.session.trust_env)


class CallTests(Base):
    def make(self, response):
        session = FakeSession(response)
        return httpclient.Client('https://cve.example.test/', 'tok', session=session), session

    def test_redirects_are_never_followed_and_a_3xx_is_an_api_error(self):
        for status in (301, 302, 303, 307, 308):
            client, session = self.make(FakeResponse(status, b'', {'Location': 'http://evil.example/steal'}))
            with self.subTest(status=status), self.assertRaises(httpclient.ApiError) as ctx:
                client.call('POST', 'sentinel/heartbeat', {'a': 1})
            self.assertEqual(ctx.exception.status, status)
            self.assertIn('redirect', ctx.exception.message)
            self.assertNotIn('evil', ctx.exception.message)
            self.assertIs(session.calls[0][2]['allow_redirects'], False)

    def test_every_call_disables_redirects_and_uses_the_default_timeout(self):
        client, session = self.make(FakeResponse(200, b'{"ok": true}'))
        self.assertEqual(client.call('GET', '/sentinel'), {'ok': True})
        method, url, kwargs = session.calls[0]
        self.assertEqual((method, url), ('GET', 'https://cve.example.test/api/v1/sentinel'))
        self.assertEqual((kwargs['allow_redirects'], kwargs['timeout']), (False, httpclient.DEFAULT_TIMEOUT))
        self.assertEqual(httpclient.DEFAULT_TIMEOUT, 30)
        client.call('GET', 'sentinel', timeout=5)
        self.assertEqual(session.calls[1][2]['timeout'], 5)

    def test_an_answer_past_the_size_limit_is_refused_and_never_read_whole(self):
        """SN-13: a hostile or broken server cannot make the client hold an unbounded body (the same cap ``download`` has)."""
        class Endless(FakeResponse):
            read = 0

            def iter_content(self, chunk_size=None):
                while True:
                    Endless.read += chunk_size
                    yield b' ' * chunk_size

        client, _ = self.make(Endless(200))
        with self.assertRaises(httpclient.ApiError) as ctx:
            client.call('POST', 'sentinel/tasks/next')
        self.assertEqual(ctx.exception.status, 502)
        self.assertLessEqual(Endless.read, httpclient.MAX_RESPONSE_BYTES + 64 * 1024)
        client, _ = self.make(FakeResponse(200, b'{"ok": true}', {'Content-Length': str(httpclient.MAX_RESPONSE_BYTES + 1)}))
        with self.assertRaises(httpclient.ApiError):
            client.call('GET', 'sentinel')  # a server that declares too much is refused before its body is read
        client, _ = self.make(FakeResponse(200, b'{"a": "' + b'x' * 100 + b'"}'))
        with self.assertRaises(httpclient.ApiError):
            client.call('GET', 'sentinel', max_bytes=50)
        self.assertEqual(client.call('GET', 'sentinel', max_bytes=1000), {'a': 'x' * 100})

    def test_an_error_body_is_clipped_to_the_servers_message(self):
        client, _ = self.make(FakeResponse(403, b'{"error": "suspended"}'))
        with self.assertRaises(httpclient.ApiError) as ctx:
            client.call('POST', 'sentinel/tasks/next')
        self.assertEqual((ctx.exception.status, ctx.exception.message), (403, 'suspended'))


if __name__ == '__main__':
    unittest.main()
