"""bbot that refuses to start for a missing module or preset is an error, never a discovery that found nothing (1.4.0 tool review).

bbot prints ``[ERRR] Could not find scan module "x"`` and exits 0 with no events, and the run came back as ``done`` with no hosts and no ``incomplete`` text:
a failed discovery read as a clean one. ``Could not find preset`` was already known; a module is the same kind of refusal."""
import unittest

from client import bbot
from client.tests.test_bbot import TARGET, FakeClient, FakeProc, event


def run(stderr, lines=(), code=0):
    return bbot.run_bbot_discovery(TARGET, FakeClient(), 7, popen=lambda *a, **k: FakeProc(list(lines), code=code, stderr=stderr))


class BbotRefusals(unittest.TestCase):
    def test_a_missing_module_with_nothing_found_is_an_error(self):
        with self.assertRaises(bbot.RunError) as caught:
            run('[ERRR] Could not find scan module "httpx". Did you mean "http"?\n')
        self.assertIn('refused', str(caught.exception))

    def test_a_missing_preset_is_still_an_error(self):
        with self.assertRaises(bbot.RunError):
            run('[ERRR] Could not find preset "nope"\n')

    def test_a_refusal_after_events_were_found_is_kept_as_incomplete_text_not_lost(self):
        out = run('[ERRR] Could not find scan module "x"\n', lines=[event('DNS_NAME', 'www.example.com', host='www.example.com')])
        self.assertEqual(out['outcome'], 'done')

    def test_a_clean_run_with_no_findings_is_still_done(self):
        out = run('[INFO] all quiet\n')
        self.assertEqual((out['outcome'], out['incomplete']), ('done', ''))


if __name__ == '__main__':
    unittest.main()
