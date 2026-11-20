"""A site that answers through more than one redirect on its own site (http to https, then apex to www) is scanned at the end of the chain.

Pull request 74 followed exactly one redirect, so http://example.test -> https://example.test/ -> https://www.example.test/ stopped at the second
hop: WPScan's "redirects to" text came back as the outcome and the server read a failed scan. Up to MAX_REDIRECT_HOPS hops are followed, never to
another site and never back to a URL already scanned."""
import unittest
from unittest import mock

from client import tools

DONE = {'report': {'version': {'number': '6.4'}}, 'returncode': 0, 'stderr_tail': ''}


def moved(target):
    return {'report': {'scan_aborted': f'The URL supplied redirects to {target}. Use the --follow-redirect option to automatically scan the redirected URL'},
            'returncode': 4, 'stderr_tail': ''}


class RedirectChainTests(unittest.TestCase):
    def run_chain(self, start, answers):
        calls = []

        def fake(url, token, timeout, register, args):
            calls.append(url)
            return answers[len(calls) - 1] if len(calls) <= len(answers) else DONE
        with mock.patch('client.tools._wpscan', side_effect=fake):
            return tools.run_wpscan(start, ''), calls

    def test_http_to_https_to_www_is_scanned_at_the_end(self):
        out, calls = self.run_chain('http://example.test', [moved('https://example.test/'), moved('https://www.example.test/'), DONE])
        self.assertEqual(calls, ['http://example.test', 'https://example.test/', 'https://www.example.test/'])
        self.assertEqual(out['returncode'], 0)

    def test_at_most_three_hops_are_followed(self):
        answers = [moved('https://example.test/a'), moved('https://example.test/b'), moved('https://example.test/c'), moved('https://example.test/d')]
        out, calls = self.run_chain('http://example.test', answers)
        self.assertEqual(len(calls), 1 + tools.MAX_REDIRECT_HOPS)
        self.assertEqual(out['returncode'], 4)  # the last answer is the outcome the server reads (it says redirects)

    def test_a_loop_stops_at_the_first_repeat(self):
        out, calls = self.run_chain('https://example.test/', [moved('https://www.example.test/'), moved('https://example.test/')])
        self.assertEqual(calls, ['https://example.test/', 'https://www.example.test/'])

    def test_a_hop_to_another_site_is_never_followed_even_after_a_followed_hop(self):
        out, calls = self.run_chain('http://example.test', [moved('https://example.test/'), moved('https://login.other.test/')])
        self.assertEqual(calls, ['http://example.test', 'https://example.test/'])
        self.assertIn('login.other.test', out['report']['scan_aborted'])

    def test_a_site_that_does_not_redirect_is_scanned_once(self):
        out, calls = self.run_chain('https://example.test', [DONE])
        self.assertEqual(calls, ['https://example.test'])

    def test_the_thorough_pass_follows_the_same_way(self):
        calls = []

        def fake(url, token, timeout, register, args):
            calls.append(url)
            return [moved('https://example.test/'), moved('https://www.example.test/'), DONE][len(calls) - 1]
        with mock.patch('client.tools._wpscan', side_effect=fake):
            tools.run_wpscan_thorough('http://example.test', '')
        self.assertEqual(len(calls), 3)
