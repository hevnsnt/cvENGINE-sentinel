"""The nmap -sV/-O service extractor and the XML reader in front of it (``cvengine_scanner.nmap``), on real nmap XML samples."""
import unittest

import xmltodict

from cvengine_scanner.nmap import extract_nmap_inventory, parse_xml
from cvengine_scanner.parsers import ToolOutputError


SINGLE_HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu" ostype="Linux" method="probed" conf="10">
          <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
          <cpe>cpe:/o:canonical:ubuntu_linux</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.0 - 5.4" accuracy="96"/>
      <osmatch name="Linux 4.15" accuracy="90"/>
    </os>
  </host>
</nmaprun>"""

# Two hosts, and a host whose single port/address is NOT wrapped in a list
# (xmltodict collapses single children to a dict) -- the common real-world case.
MULTI_HOST_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http-proxy" product="Apache Tomcat" version="9.0.50"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="203.0.113.11" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestExtractNmapInventory(unittest.TestCase):
    def _inv(self, xml):
        return extract_nmap_inventory(xmltodict.parse(xml))

    def test_single_host_service_fields(self):
        inv = self._inv(SINGLE_HOST_XML)
        self.assertEqual(len(inv), 1)
        host = inv[0]
        self.assertEqual(host['ip'], '203.0.113.10')
        self.assertEqual(host['os_guess'], 'Linux 5.0 - 5.4')
        self.assertEqual(host['os_accuracy'], 96)

        by_num = {p['number']: p for p in host['ports']}
        self.assertEqual(set(by_num), {443, 22})
        https = by_num[443]
        self.assertEqual(https['product'], 'nginx')
        self.assertEqual(https['version'], '1.18.0')
        self.assertEqual(https['service_extra'], 'Ubuntu')
        self.assertEqual(https['protocol'], 'tcp')
        self.assertEqual(https['state'], 'open')
        self.assertEqual(https['ostype'], 'Linux')
        self.assertEqual(https['cpe'], 'cpe:/a:igor_sysoev:nginx:1.18.0')
        self.assertEqual(len(https['cpes']), 2)
        self.assertEqual(by_num[22]['product'], 'OpenSSH')
        self.assertEqual(by_num[22]['version'], '8.2p1')

    def test_single_children_collapse_to_dict(self):
        # xmltodict gives a dict (not a list) for single host/port/address.
        inv = self._inv(MULTI_HOST_XML)
        self.assertEqual(len(inv), 2)
        self.assertEqual(inv[0]['ip'], '203.0.113.10')
        self.assertEqual(inv[0]['ports'][0]['number'], 8080)
        self.assertEqual(inv[0]['ports'][0]['product'], 'Apache Tomcat')
        self.assertEqual(inv[0]['ports'][0]['version'], '9.0.50')
        # Host with no OS block -> empty guess, no accuracy.
        self.assertEqual(inv[1]['os_guess'], '')
        self.assertIsNone(inv[1]['os_accuracy'])
        self.assertEqual(inv[1]['ports'][0]['number'], 80)
        self.assertEqual(inv[1]['ports'][0]['state'], 'closed')

    def test_empty_and_malformed(self):
        self.assertEqual(extract_nmap_inventory({}), [])
        self.assertEqual(extract_nmap_inventory(None), [])
        self.assertEqual(extract_nmap_inventory({'nmaprun': {}}), [])

    def _scanned(self, services, protocol='tcp'):
        xml = ('<nmaprun><scaninfo protocol="%s" services="%s"/><host><address addr="203.0.113.5" addrtype="ipv4"/></host></nmaprun>'
               % (protocol, services))
        return self._inv(xml)[0]['scanned']

    def test_scanned_ports_parse_lists_and_ranges(self):
        self.assertEqual(self._scanned('22,80-82,81-84,8080'), {22, 80, 81, 82, 83, 84, 8080})

    def test_a_hostile_scaninfo_range_is_clamped_not_expanded(self):
        import time
        start = time.monotonic()
        scanned = self._scanned('1-4000000000')
        self.assertEqual(len(scanned), 65535)
        self.assertEqual(self._scanned('0-3,70000-90000'), {1, 2, 3})
        # a million overlapping full ranges merge instead of being expanded one by one
        self.assertEqual(len(self._scanned(','.join(['1-65535'] * 200000))), 65535)
        self.assertLess(time.monotonic() - start, 5)


FAST_XML = '''<?xml version="1.0"?>
<nmaprun><host>
<address addr="192.0.2.10" addrtype="ipv4"/>
<os><osmatch name="Linux 5.X" accuracy="95"/></os>
<ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
</port></ports>
</host><runstats><finished exit="success"/></runstats></nmaprun>'''


class ParseXmlTests(unittest.TestCase):
    def test_coverage_parser_rejects_missing_malformed_and_failed_reports(self):
        bad_reports = ('', '<nmaprun><host>', '<other/>', '<nmaprun>error</nmaprun>', '<nmaprun/>',
            '<nmaprun><runstats><finished/></runstats></nmaprun>',
            '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
            '<!DOCTYPE nmaprun [<!ENTITY x "x">]><nmaprun/>')
        for report in bad_reports:
            with self.subTest(report=report), self.assertRaises(ToolOutputError):
                parse_xml(report, strict=True)

    def test_coverage_parser_accepts_a_valid_report_with_no_open_ports(self):
        report = ('<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
            '<ports><extraports state="closed" count="1000"/></ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')
        self.assertEqual(parse_xml(report, strict=True)[0]['ports'], [])

    def test_a_completed_empty_nmap_report_is_valid(self):
        self.assertEqual(parse_xml('<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', strict=True), [])

    def test_blank_output_is_empty(self):
        self.assertEqual(parse_xml(''), [])
        self.assertEqual(parse_xml('   '), [])

    def test_unparseable_xml_is_empty_not_a_crash(self):
        self.assertEqual(parse_xml('<not xml'), [])

    def test_an_entity_expansion_payload_is_refused_not_expanded(self):
        # This function also reads XML a Sentinel reported (the server's agentapi.sentinel_dispatch.try_nmap_udp), not only the
        # server's own nmap subprocess, so a billion-laughs-style payload must fail safe (a custom ENTITY is refused
        # outright, real nmap output never declares one), same as any other malformed report - never expand, never
        # crash the pipeline.
        bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                ']><nmaprun><host><address addr="&lol2;" addrtype="ipv4"/></host></nmaprun>')
        self.assertEqual(parse_xml(bomb), [])

    def test_an_external_entity_is_refused_not_fetched(self):
        xxe = ('<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
              '<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>')
        self.assertEqual(parse_xml(xxe), [])

    def test_valid_report_extracts_host_os_and_service(self):
        inventory = parse_xml(FAST_XML)
        self.assertEqual(len(inventory), 1)
        host = inventory[0]
        self.assertEqual(host['ip'], '192.0.2.10')
        self.assertEqual((host['os_guess'], host['os_accuracy']), ('Linux 5.X', 95))
        self.assertEqual(host['ports'], [{
            'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
            'product': 'OpenSSH', 'version': '8.9', 'service_extra': 'Ubuntu', 'ostype': '',
            'cpe': '', 'cpes': [], 'method': '', 'scripts': {}, 'banner': '',
            'tunnel': '', 'hostname': '', 'devicetype': '', 'confidence': '', 'tls': {},
        }])

if __name__ == '__main__':
    unittest.main()
