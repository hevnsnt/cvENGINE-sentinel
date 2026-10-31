import json
import os
import unittest

from cvengine_scanner import flags, parsers

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as handle:
        return handle.read()


class NmapParsingTests(unittest.TestCase):
    def test_parses_the_sample_xml_into_the_typed_shape(self):
        result = parsers.parse_nmap_xml(_read('sample_nmap.xml'))
        self.assertEqual(len(result['hosts']), 2)
        first = result['hosts'][0]
        self.assertEqual(first['ip'], '192.0.2.10')
        self.assertEqual(first['os_guess'], 'Linux 5.X')
        # Only the open port is kept (closed 9999 is dropped), in document order.
        self.assertEqual(len(first['ports']), 2)
        self.assertEqual(first['ports'][0], {'number': 22, 'protocol': 'tcp', 'state': 'open', 'service_name': 'ssh',
                                             'product': 'OpenSSH', 'version': '8.9'})
        self.assertEqual(first['ports'][1]['number'], 80)
        self.assertEqual(first['ports'][1]['product'], 'nginx')
        second = result['hosts'][1]
        self.assertEqual(second['ip'], '198.51.100.20')
        self.assertEqual(second['os_guess'], '')  # no <os> block for this host

    def test_empty_or_malformed_xml_yields_no_hosts_not_a_crash(self):
        self.assertEqual(parsers.parse_nmap_xml(''), {'hosts': []})
        self.assertEqual(parsers.parse_nmap_xml('not xml at all'), {'hosts': []})


class NaabuParsingTests(unittest.TestCase):
    def test_parses_the_sample_output_into_the_typed_shape(self):
        result = parsers.parse_naabu_output(_read('sample_naabu.jsonl'))
        self.assertEqual(result, {'192.0.2.10': [22, 80], '198.51.100.20': [443], '203.0.113.5': [8080]})

    def test_non_json_lines_are_skipped_not_fatal(self):
        text = 'garbage\n{"ip": "192.0.2.1", "port": 80}\nmore garbage {{{\n'
        self.assertEqual(parsers.parse_naabu_output(text), {'192.0.2.1': [80]})

    def test_a_tarpit_address_over_the_cap_is_sent_as_null_not_clipped_or_dropped(self):
        lines = '\n'.join(f'{{"ip": "192.0.2.99", "port": {p}}}' for p in range(1, flags.MAX_OPEN_PER_IP + 10))
        lines += '\n{"ip": "192.0.2.5", "port": 22}'
        self.assertEqual(parsers.parse_naabu_output(lines), {'192.0.2.99': None, '192.0.2.5': [22]})


class NucleiParsingTests(unittest.TestCase):
    def test_parses_the_sample_jsonl_carrying_matcher_name_through(self):
        findings = parsers.parse_nuclei_jsonl(_read('sample_nuclei.jsonl'))
        self.assertEqual(len(findings), 2)
        tech = findings[0]
        self.assertEqual(tech['template_id'], 'tech-detect')
        self.assertEqual(tech['matcher_name'], 'jquery')  # the field this phase adds end to end
        self.assertEqual(tech['host'], 'www.example.test')
        panel = findings[1]
        self.assertEqual(panel['template_id'], 'exposed-panel')
        self.assertEqual(panel['matcher_name'], 'admin-panel')
        self.assertEqual(panel['severity'], 'high')
        self.assertEqual(panel['extracted_results'], ['panel'])
        self.assertEqual(panel['tags'], ['panel', 'exposure'])

    def test_host_of_matches_cveFeed_nuclei_scan_host_of_shape(self):
        self.assertEqual(flags.host_of({'host': 'https://www.example.test/admin'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test'}), 'www.example.test')

    def test_malformed_lines_are_skipped_or_coerced_never_fatal(self):
        lines = ['[1, 2]', '"a string"', '42', 'null', 'x' * 1_000_000, '{"broken": ',
                 json.dumps({'template-id': 'a', 'info': 'not an object'}),
                 json.dumps({'template-id': 7, 'host': 7, 'ip': '8.8.8.8', 'matched-at': ['x'], 'matcher-name': None,
                             'extracted-results': 'one value', 'info': {'name': 5, 'severity': ['high'], 'tags': 'cve,rce, ,x'}}),
                 json.dumps({'template-id': 'b', 'host': 'http://[::1', 'extracted-results': {'a': 1}, 'info': {'tags': 9}}),
                 json.dumps({'template-id': 'c', 'host': {'nested': True}, 'extracted-results': ['ok', 3, None, ''],
                             'info': {'tags': ['t', 1, None]}})]
        findings = parsers.parse_nuclei_jsonl('\n'.join(lines))
        self.assertEqual([f['template_id'] for f in findings], ['a', '', 'b', 'c'])
        self.assertEqual(findings[0]['name'], '')
        self.assertEqual(findings[0]['severity'], 'unknown')
        second = findings[1]
        self.assertEqual((second['host'], second['matched_at'], second['matcher_name'], second['name'], second['severity']),
                         ('8.8.8.8', '', '', '', 'unknown'))
        self.assertEqual(second['extracted_results'], ['one value'])
        self.assertEqual(second['tags'], ['cve', 'rce', 'x'])
        self.assertEqual((findings[2]['host'], findings[2]['extracted_results'], findings[2]['tags']), ('', [], []))
        self.assertEqual((findings[3]['host'], findings[3]['extracted_results'], findings[3]['tags']), ('', ['ok'], ['t']))

    def test_the_number_of_findings_is_capped(self):
        small = {'template-id': 't', 'host': 'www.example.test', 'info': {'name': 'n', 'severity': 'low'}}
        findings = parsers.parse_nuclei_jsonl('\n'.join([json.dumps(small)] * (parsers.MAX_FINDINGS + 5)))
        self.assertEqual(len(findings), parsers.MAX_FINDINGS)

    def test_findings_and_their_fields_are_capped(self):
        row = {'template-id': 't' * 1000, 'host': 'www.example.test', 'matched-at': 'm' * 5000, 'matcher-name': 'n' * 1000,
               'extracted-results': ['e' * 1000] * 50,
               'info': {'name': 'x' * 5000, 'severity': 's' * 100, 'description': 'd' * 10000, 'tags': [f'tag{i}' for i in range(50)]}}
        findings = parsers.parse_nuclei_jsonl('\n'.join([json.dumps(row)] * 3))
        first = findings[0]
        self.assertEqual(len(first['description']), 4000)
        self.assertEqual(len(first['matched_at']), 500)
        self.assertEqual(len(first['name']), 500)
        self.assertEqual(len(first['template_id']), 200)
        self.assertEqual(len(first['severity']), 20)
        self.assertEqual(len(first['tags']), 20)
        self.assertEqual(len(first['extracted_results']), 20)
        self.assertEqual({len(e) for e in first['extracted_results']}, {500})


class StrictNmapTests(unittest.TestCase):
    """The scan runner's strict reading: an nmap that died part way is an error, never "no hosts, nothing open"."""

    def test_a_missing_unreadable_or_unfinished_report_is_refused(self):
        for report in ('', 'not xml', '<other/>', '<nmaprun><host/></nmaprun>', '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>'):
            with self.subTest(report=report), self.assertRaises(parsers.ToolOutputError):
                parsers.parse_nmap_xml(report, strict=True)

    def test_a_finished_report_is_read(self):
        self.assertEqual(parsers.parse_nmap_xml('<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', strict=True), {'hosts': []})


class DiscoverParsingTests(unittest.TestCase):
    def test_only_up_hosts_with_an_ipv4_address_are_reported(self):
        self.assertEqual(parsers.parse_discover_xml(_read('sample_discover.xml'))['hosts'],
                         [{'ip': '10.20.0.5', 'hostnames': ['files.corp']}, {'ip': '10.20.0.9', 'hostnames': []}])
        self.assertEqual(parsers.parse_discover_xml('not xml'), {'hosts': []})
        self.assertEqual(parsers.parse_discover_xml(''), {'hosts': []})

    def test_the_number_of_hosts_is_capped(self):
        rows = ''.join(f'<host><status state="up"/><address addr="10.0.{i // 250}.{i % 250 + 1}" addrtype="ipv4"/></host>'
                       for i in range(flags.MAX_DISCOVER_HOSTS + 20))
        self.assertEqual(len(parsers.parse_discover_xml(f'<nmaprun>{rows}</nmaprun>')['hosts']), flags.MAX_DISCOVER_HOSTS)


class TestsslParsingTests(unittest.TestCase):
    ITEMS = [{'id': 'SSLv3', 'severity': 'OK', 'finding': 'not offered'}, {'id': 'cert_notAfter', 'severity': 'LOW', 'finding': '2030-01-01'}]

    def test_a_flat_report_keeps_the_items_that_have_an_id(self):
        self.assertEqual(parsers.parse_testssl_report(self.ITEMS + [{'severity': 'OK'}, 'junk', 7]), self.ITEMS)

    def test_a_grouped_report_is_flattened(self):
        grouped = {'scanResult': [{'protocols': [self.ITEMS[0]], 'serverDefaults': [self.ITEMS[1]], 'ignored': 'text'}, 'junk']}
        self.assertEqual(parsers.parse_testssl_report(grouped), self.ITEMS)

    def test_anything_else_is_empty(self):
        for raw in (None, 'text', 3, {}, {'scanResult': None}):
            with self.subTest(raw=raw):
                self.assertEqual(parsers.parse_testssl_report(raw), [])


class WafParsingTests(unittest.TestCase):
    @staticmethod
    def report(*rows):
        return json.dumps(list(rows))

    def test_products_are_named_without_version_or_confidence(self):
        text = self.report({'detected': True, 'firewall': 'FortiWeb', 'manufacturer': 'Fortinet', 'url': 'https://www.example.test/', 'trigger_url': None},
                           {'detected': True, 'firewall': ' fortiweb ', 'manufacturer': 'Fortinet'},
                           {'detected': True, 'firewall': 'Generic', 'manufacturer': 'Unknown'},
                           {'detected': True, 'firewall': 'ExampleShield', 'manufacturer': ''},
                           {'detected': False, 'firewall': 'None', 'manufacturer': 'None'})
        self.assertEqual(parsers.parse_waf_output(text),
                         {'products': [{'name': 'FortiWeb', 'manufacturer': 'Fortinet'}, {'name': 'ExampleShield'}], 'generic': False})

    def test_something_blocking_with_no_known_product_is_generic(self):
        self.assertEqual(parsers.parse_waf_output(self.report({'detected': True, 'firewall': 'Generic', 'manufacturer': 'Unknown'})),
                         {'products': [], 'generic': True})
        self.assertEqual(parsers.parse_waf_output(self.report({'detected': False, 'firewall': 'None'})), {'products': [], 'generic': False})

    def test_names_and_the_list_are_capped(self):
        rows = [{'detected': True, 'firewall': f'{i:02}' + 'n' * 150, 'manufacturer': 'm' * 150} for i in range(30)]
        products = parsers.parse_waf_output(self.report(*rows))['products']
        self.assertEqual(len(products), flags.MAX_WAF_PRODUCTS)
        self.assertEqual({len(p['name']) for p in products}, {flags.WAF_NAME_LEN})
        self.assertEqual({len(p['manufacturer']) for p in products}, {flags.WAF_NAME_LEN})

    def test_odd_rows_and_junk_name_nothing(self):
        for text in ('', 'not json', '{}', '"x"', '[1, "a", null, []]', '[{"detected": true}]'):
            with self.subTest(text=text):
                self.assertEqual(parsers.parse_waf_output(text)['products'], [])

    def test_a_report_with_nothing_in_it_is_an_error_when_strict(self):
        """wafw00f writes ``[]`` for a site that never answered: not "no WAF"."""
        for text in ('', '[]', 'not json', '{}', '[1, "a"]'):
            with self.subTest(text=text), self.assertRaises(parsers.ToolOutputError):
                parsers.parse_waf_output(text, strict=True)
        self.assertEqual(parsers.parse_waf_output(self.report({'detected': False, 'firewall': 'None'}), strict=True), {'products': [], 'generic': False})

    def test_the_flags_follow_the_runs_timeout(self):
        self.assertEqual(flags.wafw00f_flags(60), ['-a', '-r', '-T', '15', '--no-colors', '-f', 'json'])
        self.assertEqual(flags.wafw00f_flags(10)[flags.wafw00f_flags(10).index('-T') + 1], '10')


class FlagsTests(unittest.TestCase):
    def test_nuclei_never_runs_denial_of_service_templates(self):
        self.assertEqual(flags.NUCLEI_FLAGS[flags.NUCLEI_FLAGS.index('-etags') + 1], 'dos')

    def test_every_flag_list_is_plain_strings(self):
        for name in ('NMAP_FLAGS', 'NAABU_FLAGS', 'NUCLEI_FLAGS', 'TESTSSL_FLAGS', 'WPSCAN_ARGS', 'DISCOVER_FLAGS'):
            with self.subTest(name=name):
                self.assertTrue(all(isinstance(item, str) for item in getattr(flags, name)))

    def test_the_udp_sweep_is_the_curated_list(self):
        self.assertTrue(all(0 < port < 65536 for port in flags.UDP_PORTS))
        self.assertEqual(len(set(flags.UDP_PORTS)), len(flags.UDP_PORTS))
        self.assertIn('snmp-info', flags.UDP_NSE_SCRIPTS)

    def test_host_of_reads_urls_ports_and_bare_hosts(self):
        self.assertEqual(flags.host_of({'host': 'http://[::1'}), '')
        self.assertEqual(flags.host_of({'ip': '192.0.2.1'}), '192.0.2.1')
        self.assertEqual(flags.host_of({}), '')


if __name__ == '__main__':
    unittest.main()
