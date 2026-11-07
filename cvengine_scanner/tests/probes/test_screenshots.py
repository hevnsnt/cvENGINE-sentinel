"""The pure half of the web_screenshot kind: the task read and bounded, what a browser may reach, the pictures that may be sent, the words for a
failed page and the judgement of Chromium's sandbox. No browser, no socket."""
import base64
import json
import struct
import subprocess
import sys
import unittest
import zlib

from cvengine_scanner import contract
from cvengine_scanner.probes import screenshots as lib


def png(width=64, height=40, tones=2):
    """A real PNG: the first row a different gray than the rest when ``tones`` is 2, one flat color for 1."""
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xFFFFFFFF)
    rows = b''.join(b'\x00' + bytes([200 if (tones == 2 and y == 0) else 90]) * width for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 0, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))


def target(**changes):
    out = json.loads((contract.FIXTURES / 'targets' / 'web_screenshot.json').read_text())
    out.update(changes)
    return out


class TargetTests(unittest.TestCase):
    def test_the_contract_fixture_is_a_usable_task(self):
        job = lib.parse_target(target())
        self.assertEqual([(p.id, p.host, p.port, p.scheme) for p in job.pages], [('1', 'www.example.com', 443, 'https'), ('2', 'www.example.com', 8080, 'http')])
        self.assertTrue(job.open_web)
        self.assertEqual((job.seconds, job.max_bytes), (20, 2097152))

    def test_pages_are_bounded_and_plain(self):
        for pages in ([], [{'id': str(i), 'url': 'https://a.example/'} for i in range(7)], 'x', [{'id': '1'}], [{'id': '', 'url': 'https://a.example/'}],
                      [{'id': 'x' * 41, 'url': 'https://a.example/'}], [{'id': '1', 'url': 'ftp://a.example/'}], [{'id': '1', 'url': 'file:///etc/passwd'}],
                      [{'id': '1', 'url': 'https://user:pw@a.example/'}], [{'id': '1', 'url': 'https://a.example/#frag'}],
                      [{'id': '1', 'url': 'https://a.example/ x'}], [{'id': '1', 'url': 'https://a.example:99999/'}],
                      [{'id': '1', 'url': 'https://a.example/' + 'a' * 2000}], [{'id': '1', 'url': 'javascript:alert(1)'}],
                      [{'id': '1', 'url': 'https://a.example/'}, {'id': '1', 'url': 'https://b.example/'}]):
            with self.assertRaises(ValueError, msg=str(pages)[:60]):
                lib.parse_target(target(pages=pages))
        with self.assertRaises(ValueError):
            lib.parse_target('nope')

    def test_the_limits_are_clamped_never_widened(self):
        job = lib.parse_target(target(timeout_seconds=9999, max_bytes=10 ** 9))
        self.assertEqual((job.seconds, job.max_bytes), (lib.MAX_SECONDS, lib.MAX_IMAGE_BYTES))
        job = lib.parse_target(target(timeout_seconds=1, max_bytes=1))
        self.assertEqual((job.seconds, job.max_bytes), (lib.MIN_SECONDS, lib.MIN_IMAGE_BYTES))
        job = lib.parse_target(target(timeout_seconds=True, max_bytes='big'))
        self.assertEqual((job.seconds, job.max_bytes), (lib.DEFAULT_SECONDS, lib.MAX_IMAGE_BYTES))

    def test_url_for_matches_the_servers_spelling(self):
        self.assertEqual(lib.url_for('a.example', 'https', 443), 'https://a.example/')
        self.assertEqual(lib.url_for('a.example', 'http', 8080), 'http://a.example:8080/')
        self.assertEqual(lib.url_for('::1', 'https', 8443), 'https://[::1]:8443/')


class PolicyTests(unittest.TestCase):
    def policy(self, open_web, **scope):
        doc = {'hosts': ['www.example.com'], 'excluded': ['admin.example.com'], 'excluded_trees': ['secret.example.org']}
        doc.update(scope)
        return lib.ShotPolicy(doc, open_web=open_web)

    def test_a_closed_policy_reaches_only_the_listed_hosts(self):
        policy = self.policy(False)
        self.assertEqual(policy.host_refusal('www.example.com'), '')
        self.assertEqual(policy.host_refusal('fonts.example.net'), 'outside the scope policy')
        self.assertEqual(policy.host_refusal('admin.example.com'), 'excluded')

    def test_open_web_reaches_any_name_that_is_not_excluded(self):
        policy = self.policy(True)
        self.assertEqual(policy.host_refusal('fonts.example.net'), '')
        self.assertEqual(policy.host_refusal('admin.example.com'), 'excluded')
        self.assertEqual(policy.host_refusal('a.b.secret.example.org'), 'excluded')
        self.assertEqual(policy.host_refusal(''), 'no host')

    def test_open_web_still_stops_at_the_address_floor(self):
        policy = lib.ShotPolicy({'hosts': []}, open_web=True, internal=False)
        for address in ('127.0.0.1', '169.254.169.254', '10.0.0.5', '192.168.1.1', '::1'):
            self.assertNotEqual(policy.address_refusal(address), '', address)
        self.assertEqual(policy.address_refusal('93.184.215.14'), '')

    def test_open_web_is_only_what_the_task_says_with_true(self):
        for value in ('yes', 1, None, [True]):
            job = lib.parse_target(target(open_web=value))
            self.assertFalse(job.policy.open_web)
            self.assertNotEqual(job.policy.host_refusal('fonts.example.net'), '')

    def test_a_task_with_no_scope_reaches_nothing_unless_open(self):
        job = lib.parse_target({'pages': [{'id': '1', 'url': 'https://a.example/'}]})
        self.assertNotEqual(job.policy.host_refusal('a.example'), '')


class PictureTests(unittest.TestCase):
    def test_a_real_png_passes(self):
        data = png()
        self.assertEqual(lib.png_size(data), (64, 40))
        self.assertEqual(lib.png_problem(data), '')

    def test_what_is_not_a_png_is_named(self):
        good = png()
        self.assertEqual(lib.png_problem(b'GIF89a' + b'\0' * 100), 'not a PNG')
        self.assertEqual(lib.png_problem(b''), 'not a PNG')
        broken = bytearray(good)
        broken[20] ^= 0xFF  # inside IHDR: the checksum fails
        self.assertEqual(lib.png_problem(bytes(broken)), 'no good IHDR chunk')
        self.assertEqual(lib.png_problem(good[:-12]), 'no IEND chunk')
        self.assertEqual(lib.png_problem(good + b'junk'), 'no IEND chunk')

    def test_sides_above_the_cap_are_refused_without_opening_the_image(self):
        self.assertIn('sides above', lib.png_problem(png(lib.MAX_IMAGE_SIDE + 1, 2)))
        self.assertEqual(lib.png_problem(png(lib.MAX_IMAGE_SIDE, 2)), '')
        zero = bytearray(png())
        zero[16:20] = b'\0\0\0\0'
        zero[29:33] = struct.pack('>I', zlib.crc32(b'IHDR' + bytes(zero[16:29])) & 0xFFFFFFFF)
        self.assertIn('sides above', lib.png_problem(bytes(zero)))

    def test_a_flat_picture_is_blank_when_pillow_can_tell(self):
        try:
            import PIL  # noqa: F401
        except ImportError:
            self.assertIsNone(lib.is_meaningful(png()))
            return
        self.assertTrue(lib.is_meaningful(png(tones=2)))
        self.assertFalse(lib.is_meaningful(png(tones=1)))
        self.assertFalse(lib.is_meaningful(b'not an image'))

    def test_page_result_keeps_to_the_contract(self):
        image = base64.b64encode(png()).decode()
        ok = lib.page_result('1', 'ok', final_url='https://a.example/', status=200, title='  A\n title ', image=image)
        self.assertEqual((ok['title'], ok['status'], ok['image']), ('A title', 200, image))
        self.assertNotIn('image', lib.page_result('1', 'timeout', image=image))
        self.assertEqual(lib.page_result('1', 'weird')['outcome'], 'error')
        self.assertIsNone(lib.page_result('1', 'ok', status=True)['status'])
        self.assertIsNone(lib.page_result('1', 'ok', status=1000)['status'])
        self.assertEqual(len(lib.page_result('1', 'error', reason='x' * 999)['reason']), 300)

    def test_the_fixture_result_is_what_page_result_writes(self):
        fixture = json.loads((contract.FIXTURES / 'results' / 'web_screenshot.json').read_text())
        for page in fixture['pages']:
            built = lib.page_result(page['id'], page['outcome'], page['reason'], page['final_url'], page['status'], page['title'], page.get('image'))
            self.assertEqual(built, page)


class ErrorWordsTests(unittest.TestCase):
    def test_navigation_errors_have_an_outcome_and_a_reason(self):
        for message, outcome in (('Page.goto: Timeout 15000ms exceeded', 'timeout'), ('net::ERR_NAME_NOT_RESOLVED at https://x/', 'unreachable'),
                                 ('net::ERR_CONNECTION_REFUSED', 'unreachable'), ('net::ERR_CONNECTION_RESET', 'unreachable'),
                                 ('net::ERR_SSL_PROTOCOL_ERROR', 'tls_error'), ('net::ERR_CERT_COMMON_NAME_INVALID', 'tls_error'),
                                 ('net::ERR_TOO_MANY_REDIRECTS', 'error'), ('Download is starting', 'error'), ('something odd\nsecond line', 'error')):
            got, reason = lib.classify_error(message)
            self.assertEqual(got, outcome, message)
            self.assertTrue(reason and '\n' not in reason)
        self.assertEqual(lib.classify_error('something odd\nsecond line')[1], 'something odd')
        self.assertEqual(lib.classify_error('')[1], 'The page could not be captured.')


class SandboxTests(unittest.TestCase):
    OWN = {'userns': 'user:[1]', 'filters': 1}

    def renderer(self, **changes):
        out = {'cmdline': '/chrome --type=renderer', 'nspid': ['300', '12'], 'userns': 'user:[9]', 'filters': 2}
        out.update(changes)
        return out

    def test_a_renderer_in_its_own_namespaces_under_its_own_filter_passes(self):
        self.assertEqual(lib.judge_sandbox([{'cmdline': '/chrome', 'nspid': ['299'], 'userns': 'user:[1]', 'filters': 1}, self.renderer()], self.OWN), '')

    def test_each_missing_piece_fails(self):
        cases = (([], 'no renderer'), ([self.renderer(cmdline='/chrome --no-sandbox --type=renderer')], '--no-sandbox'),
                 ([self.renderer(nspid=['300'])], 'PID namespace'), ([self.renderer(userns='user:[1]')], 'user namespace of the browser'),
                 ([self.renderer(userns='')], 'could not be read'), ([self.renderer(filters=1)], 'no seccomp filter'))
        for processes, word in cases:
            self.assertIn(word, lib.judge_sandbox(processes, self.OWN), word)

    def test_a_kernel_that_reports_no_filter_count_is_judged_by_the_namespaces(self):
        self.assertEqual(lib.judge_sandbox([self.renderer(filters=None)], {'userns': 'user:[1]', 'filters': None}), '')

    def test_launch_failures_are_put_in_plain_words(self):
        self.assertIn('seccomp', lib.sandbox_words('No usable sandbox! clone() failed'))
        self.assertIn('root', lib.sandbox_words('Running as root without --no-sandbox is not supported'))
        self.assertEqual(lib.sandbox_words('net::ERR_FAILED'), '')

    def test_seccomp_filters_are_read_from_status(self):
        self.assertEqual(lib.seccomp_filters('Name: x\nSeccomp:\t2\nSeccomp_filters:\t3\n'), 3)
        self.assertIsNone(lib.seccomp_filters('Seccomp: 2\n'))

    def test_the_process_walk_finds_this_process_children(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            processes, own = lib.browser_processes()
            self.assertIn(child.pid, [p['pid'] for p in processes])
            self.assertTrue(own['userns'].startswith('user:'))
        finally:
            child.kill()
            child.wait()


if __name__ == '__main__':
    unittest.main()
