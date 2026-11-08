"""nmap_full of a host that answers on tens of thousands of ports is a result with a note, never a failed task."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

from client import tools
from cvengine_scanner.parsers import parse_nmap_xml

HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>'
PORT = '<port protocol="tcp" portid="{n}"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="unknown" method="table" conf="3"/></port>'
TAIL = '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'


def fake_nmap(work, count, finish=True, hang=False):
    path = os.path.join(work, 'nmap')
    body = (f'#!{sys.executable}\nimport sys, time\nw = sys.stdout.write\nw({HEAD!r})\n'
            f'for n in range(1, {count} + 1):\n    w({PORT!r}.format(n=n))\n'
            + ('sys.stdout.flush()\ntime.sleep(60)\n' if hang else f'w({TAIL!r})\n'))
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(body)
    os.chmod(path, 0o755)
    return path


class TarpitSweepTests(unittest.TestCase):
    def run_full(self, binary, **patches):
        with mock.patch.multiple(tools, NMAP_BIN=binary, **patches):
            return tools.run_nmap_full('8.8.8.8')

    def test_a_report_past_the_old_four_mib_cap_is_a_result_with_the_note(self):
        with tempfile.TemporaryDirectory() as work:
            binary = fake_nmap(work, 65535)
            out = self.run_full(binary)
        self.assertGreater(len(PORT.format(n=65535)) * 65535, 4 * 1024 * 1024)  # the size that failed on the demo
        xml = out['xml']
        self.assertLess(len(xml), 20000)
        self.assertIn('port list truncated: this host answers on an unusually large number of ports (tarpit or filtering device)', xml)
        self.assertIn('open-ports="65535"', xml)
        hosts = parse_nmap_xml(xml, strict=True)['hosts']
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['ip'], '8.8.8.8')
        self.assertEqual([p['number'] for p in hosts[0]['ports']], list(range(1, tools.TARPIT_PORTS + 1)))

    def test_a_normal_host_report_comes_back_untouched(self):
        with tempfile.TemporaryDirectory() as work:
            binary = fake_nmap(work, tools.TARPIT_PORTS)
            out = self.run_full(binary)
        self.assertNotIn('cvengine-note', out['xml'])
        self.assertEqual(len(parse_nmap_xml(out['xml'], strict=True)['hosts'][0]['ports']), tools.TARPIT_PORTS)

    def test_one_port_more_than_the_limit_is_cut(self):
        with tempfile.TemporaryDirectory() as work:
            out = self.run_full(fake_nmap(work, tools.TARPIT_PORTS + 1))
        self.assertIn('exact="1"', out['xml'])
        self.assertEqual(len(parse_nmap_xml(out['xml'], strict=True)['hosts'][0]['ports']), tools.TARPIT_PORTS)

    def test_a_runaway_report_stops_nmap_and_keeps_the_ports_read_so_far(self):
        with tempfile.TemporaryDirectory() as work:
            binary = fake_nmap(work, 5000, hang=True)
            started = time.monotonic()
            out = self.run_full(binary, MAX_FULL_READ=100000)
            self.assertLess(time.monotonic() - started, 20)  # the sleeping nmap was killed, not waited out
        self.assertIn('exact="0"', out['xml'])
        hosts = parse_nmap_xml(out['xml'], strict=True)['hosts']
        self.assertEqual(len(hosts[0]['ports']), tools.TARPIT_PORTS)

    def test_a_cut_report_with_no_port_at_all_is_still_a_finished_empty_report(self):
        out = tools.limit_open_ports('<nmaprun>', '8.8.8.8', cut=True)
        self.assertEqual(parse_nmap_xml(out, strict=True)['hosts'][0]['ports'], [])

    def test_other_oversized_output_still_fails(self):
        with tempfile.TemporaryDirectory() as work:
            binary = fake_nmap(work, 5000)
            with mock.patch.object(tools, 'NMAP_BIN', binary), mock.patch.object(tools, 'MAX_TOOL_OUTPUT', 1000):
                with self.assertRaises(tools.ToolOutputError):
                    tools.run_nmap(['8.8.8.8'])

    def test_a_crashed_nmap_is_still_a_failure(self):
        with tempfile.TemporaryDirectory() as work:
            path = os.path.join(work, 'nmap')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(f'#!{sys.executable}\nimport sys\nsys.exit(3)\n')
            os.chmod(path, 0o755)
            with mock.patch.object(tools, 'NMAP_BIN', path), self.assertRaises(tools.ToolExitError):
                tools.run_nmap_full('8.8.8.8')


if __name__ == '__main__':
    unittest.main()
