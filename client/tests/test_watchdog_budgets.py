"""The watchdog's hard deadline, one kind at a time (1.4.0 tool review).

* The deadline of an in-process probe kind is past the probe's own batch limit, so a batch that stops starting probes at its limit still delivers
  what it read instead of being killed with an error at the default 20 minutes.
* The watchdog's figure for a tool is the limit the tool itself runs by."""
import inspect
import unittest

from client import tools, watchdog


class WatchdogDeadlineTests(unittest.TestCase):
    def test_a_probe_batch_is_never_killed_by_the_watchdog_before_it_stops_itself(self):
        from cvengine_scanner.probes import page_read, routes, suppliers, version_probes
        for kind, batch in (('http_probe', version_probes.BATCH_SECONDS), ('route_probe', routes.BATCH_SECONDS), ('route_probe_signed', routes.BATCH_SECONDS),
                            ('supplier_check', suppliers.MAX_SECONDS), ('page_read', page_read.BATCH_SECONDS)):
            self.assertGreaterEqual(watchdog.deadline_seconds(kind), batch + 120, f'{kind}: the watchdog stops it before its own batch limit of {batch} s')

    def test_the_watchdog_figure_of_a_tool_is_the_limit_the_tool_runs_by(self):
        for kind, runner in (('testssl', tools.run_testssl), ('nmap_udp', tools.run_nmap_udp), ('wpscan', tools.run_wpscan), ('discover', tools.run_discover),
                             ('nmap_full', tools.run_nmap_full)):
            default = inspect.signature(runner).parameters['timeout'].default
            self.assertEqual(watchdog.TOOL_BUDGET_SECONDS[kind], default, kind)


if __name__ == '__main__':
    unittest.main()
