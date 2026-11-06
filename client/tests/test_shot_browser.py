"""The real browser for the web_screenshot kind: Chromium, in its sandbox, photographs a page served from this machine, through the vetting proxy.
Skipped where the image's browser is not installed or its sandbox cannot start (a plain developer machine; the image's CI job runs the sandbox probe
in the container with and without the seccomp profile, .github/workflows/image.yml)."""
import base64
import http.server
import socket
import threading
import unittest
from unittest import mock

from client import shot
from cvengine_scanner.probes import screenshots as lib

PAGE = (b'<!doctype html><title>Hello screenshot</title><body style="margin:0;background:#fff">'
        b'<h1 style="color:#c00;font-size:80px">cvENGINE</h1><div style="width:300px;height:200px;background:#06c"></div>'
        b'<a href="/x">link</a></body>')


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'http://metadata.test/latest/')
            self.end_headers()
            return
        body = b'' if self.path == '/blank' else PAGE
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def sandbox_works():
    if not shot.available():
        return False
    try:
        return shot.sandbox_probe()[0] is True
    except Exception:  # noqa: BLE001
        return False


@unittest.skipUnless(sandbox_works(), "needs the image's Chromium and a container or host whose seccomp profile lets its sandbox start")
class RealBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def resolver(self, host, port, policy):
        """transport.resolve with fixed answers: the policy and the address floor judge them as in production."""
        policy.check_host(host)
        address = '169.254.169.254' if host == 'metadata.test' else '93.184.215.14'
        if policy.address_refusal(address):
            raise ValueError('probe destination is prohibited')
        return ((2, (address, port)),)

    def connect(self, addresses, timeout, policy, host=None, **kw):
        """The one place the test cheats: the vetted "public" address is served from this machine (the floor would refuse loopback)."""
        return socket.create_connection(('127.0.0.1', self.port), timeout)

    def run_task(self, pages):
        target = {'pages': pages, 'scope': {'hosts': ['site.test'], 'excluded': [], 'excluded_trees': []}, 'open_web': False, 'timeout_seconds': 25}
        guard = lambda pol, primary: shot.Guard(pol, primary, stack=frozenset(), resolver=self.resolver)  # noqa: E731
        with mock.patch.object(shot.transport, 'open_socket', side_effect=self.connect):
            return shot.run(target, guard_factory=guard)

    def test_a_page_is_photographed_and_the_picture_is_a_png_of_the_page(self):
        out = self.run_task([{'id': 'a', 'url': f'http://site.test:{self.port}/'}])
        self.assertTrue(out['sandbox']['engaged'], out)
        page = out['pages'][0]
        self.assertEqual((page['id'], page['outcome'], page['status'], page['title']), ('a', 'ok', 200, 'Hello screenshot'), page)
        data = base64.b64decode(page['image'])
        self.assertEqual(lib.png_problem(data), '')
        self.assertEqual(lib.png_size(data), lib.VIEWPORT)
        self.assertIsNot(lib.is_meaningful(data), False)

    def test_a_redirect_to_an_internal_address_is_never_followed(self):
        out = self.run_task([{'id': 'a', 'url': f'http://site.test:{self.port}/redirect'}])
        page = out['pages'][0]
        self.assertEqual(page['outcome'], 'blocked', page)
        self.assertNotIn('image', page)
        self.assertIn('metadata.test', out['refused'])

    def test_a_page_outside_the_scope_is_not_opened(self):
        out = self.run_task([{'id': 'a', 'url': f'http://elsewhere.test:{self.port}/'}])
        self.assertEqual(out['pages'][0]['outcome'], 'blocked', out)
        self.assertEqual(out['touched'], [])

    def test_a_blank_page_is_a_blank_outcome_when_pillow_can_tell(self):
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest('needs Pillow')
        out = self.run_task([{'id': 'a', 'url': f'http://site.test:{self.port}/blank'}])
        self.assertEqual(out['pages'][0]['outcome'], 'blank', out)

    def test_without_the_sandbox_nothing_is_opened(self):
        with mock.patch.object(shot, 'run_child', side_effect=lambda job, on_message, *a, **k: lib.SANDBOX_PREFIX + 'refused'):
            out = shot.run({'pages': [{'id': 'a', 'url': 'http://site.test/'}], 'scope': {'hosts': ['site.test']}}, child=shot.run_child)
        self.assertEqual((out['sandbox']['engaged'], out['pages']), (False, []))


if __name__ == '__main__':
    unittest.main()
