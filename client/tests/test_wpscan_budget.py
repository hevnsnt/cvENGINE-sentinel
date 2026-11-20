"""A WPScan run that follows same-site redirects shares ONE time limit across its hops (1.4.0 tool review). Before, each hop (up to four scans) got the
whole limit, so a chain of slow scans ran past the server's wait and past the watchdog's deadline and the result was lost."""
import unittest
from unittest import mock

from client import tools

DONE = {'report': {'version': {'number': '6.4'}}, 'returncode': 0, 'stderr_tail': ''}


def moved(target):
    return {'report': {'scan_aborted': f'The URL supplied redirects to {target}. Use the --follow-redirect option to automatically scan the redirected URL'},
            'returncode': 4, 'stderr_tail': ''}


class WpscanRedirectBudgetTests(unittest.TestCase):
    def chain(self, run, seconds_per_scan, *args):
        clock = {'now': 1000.0}
        asked = []
        answers = [moved('https://example.test/'), moved('https://www.example.test/'), moved('https://www.example.test/b'), moved('https://www.example.test/c'), DONE]

        def fake(url, token, timeout, register, wp_args):
            asked.append(timeout)
            clock['now'] += seconds_per_scan
            return answers[len(asked) - 1]
        with mock.patch('client.tools._wpscan', side_effect=fake), mock.patch.object(tools.time, 'monotonic', side_effect=lambda: clock['now']):
            out = run('http://example.test', '', *args)
        return out, asked

    def test_the_hops_of_a_quick_scan_never_add_up_to_more_than_its_one_limit(self):
        _out, asked = self.chain(tools.run_wpscan, 400)
        self.assertEqual(asked[0], 900)
        self.assertEqual(asked[1], 500)  # the second hop gets what the first left
        self.assertEqual(asked[2], 100)  # and the third what is left after that
        self.assertEqual(len(asked), 3)  # 300 s... the fourth would have nothing: 100 - 400 is over, so the chain ends there

    def test_a_hop_with_too_little_time_left_is_not_started(self):
        out, asked = self.chain(tools.run_wpscan, 880)
        self.assertEqual(len(asked), 1)  # 20 seconds left: not a scan, so the redirect text is the outcome the server reads
        self.assertEqual(out['returncode'], 4)

    def test_the_thorough_scan_shares_its_hours_the_same_way(self):
        _out, asked = self.chain(tools.run_wpscan_thorough, 3600, 7200)
        self.assertEqual(asked[0], 7200)
        self.assertEqual(asked[1], 3600)
        self.assertEqual(len(asked), 2)  # the third would have 0 left


if __name__ == '__main__':
    unittest.main()
