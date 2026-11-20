"""A host nmap scanned and found nothing open is a scanned host with no open ports, not a host nobody covered (1.4.0 tool review).

The fingerprint pass runs with ``--open``, and with it nmap writes a ``<host>`` element only for a host that has an open port: a lab run over five addresses
listed four hosts while its own ``runstats`` said ``<hosts up="5" down="0" total="5"/>``. The Sentinel sent the four, and the server reads an address with no
row as "this Sentinel did not cover it" (``try_nmap``: ``a Sentinel finished N address(es) without reporting the host``), so a host with nothing open stayed due and
was asked again at every pass. When nmap's own count says it scanned every address it was given, the unlisted ones get a row with no ports."""
import unittest
from unittest import mock

from client import tools

HOST = ('<host><status state="up" reason="user-set"/><address addr="{ip}" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http"/></port></ports></host>')


def report(listed, total):
    hosts = f'<hosts up="{total}" down="0" total="{total}"/>' if total is not None else ''
    return ('<nmaprun>' + ''.join(HOST.format(ip=ip) for ip in listed) + f'<runstats><finished exit="success"/>{hosts}</runstats></nmaprun>')


def run(addresses, xml):
    with mock.patch('client.tools._run', return_value=xml):
        return tools.run_nmap(addresses)['hosts']


class UnlistedHostsAreScannedHostsWithNothingOpen(unittest.TestCase):
    def test_an_address_nmap_counted_as_scanned_but_did_not_list_gets_a_row_with_no_ports(self):
        rows = run(['8.8.8.8', '1.1.1.1', '9.9.9.9'], report(['8.8.8.8'], 3))
        self.assertEqual(sorted(h['ip'] for h in rows), ['1.1.1.1', '8.8.8.8', '9.9.9.9'])
        self.assertEqual({h['ip']: len(h['ports']) for h in rows}, {'8.8.8.8': 1, '1.1.1.1': 0, '9.9.9.9': 0})

    def test_when_nmap_counted_fewer_hosts_than_it_was_given_no_row_is_made_up(self):
        rows = run(['8.8.8.8', '1.1.1.1', '9.9.9.9'], report(['8.8.8.8'], 2))
        self.assertEqual([h['ip'] for h in rows], ['8.8.8.8'])

    def test_a_report_with_no_count_is_read_as_before(self):
        rows = run(['8.8.8.8', '1.1.1.1'], report(['8.8.8.8'], None))
        self.assertEqual([h['ip'] for h in rows], ['8.8.8.8'])

    def test_a_host_nmap_gave_up_on_is_not_turned_into_a_clean_one(self):
        xml = ('<nmaprun><host timedout="true"><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/></host>'
               '<runstats><finished exit="success"/><hosts up="2" down="0" total="2"/></runstats></nmaprun>')
        rows = {h['ip']: h for h in run(['8.8.8.8', '1.1.1.1'], xml)}
        self.assertTrue(rows['8.8.8.8'].get('timed_out'))
        self.assertEqual(rows['1.1.1.1']['ports'], [])

    def test_an_ipv6_address_is_matched_whatever_way_it_is_written(self):
        xml = ('<nmaprun><host><status state="up"/><address addr="2606:4700:4700::1111" addrtype="ipv6"/><ports><port protocol="tcp" portid="53"><state state="open"/></port></ports></host>'
               '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')
        with mock.patch('client.tools.ipv6_route', return_value=True):
            rows = run(['2606:4700:4700:0:0:0:0:1111'], xml)
        self.assertEqual(len(rows), 1)


if __name__ == '__main__':
    unittest.main()
