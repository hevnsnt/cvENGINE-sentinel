"""The raw print port rule (``cvengine_scanner.printers``) and every argument builder of ``flags`` that names ports."""
import unittest

from cvengine_scanner import flags, printers

# The fingerprint rows of the two printers on Bill's network (2026-11-26, Sentinel haxxxK), trimmed to the fields the rule reads.
BROTHER = [
    {'number': 80, 'state': 'open', 'method': 'probed', 'service_name': 'http', 'product': 'Debut embedded httpd', 'devicetype': 'printer',
     'service_extra': 'Brother/HP printer http admin'},
    {'number': 443, 'state': 'open', 'method': 'table', 'service_name': 'https'},
    {'number': 515, 'state': 'open', 'method': 'table', 'service_name': 'printer'},
    {'number': 631, 'state': 'open', 'method': 'probed', 'service_name': 'http', 'product': 'Debut embedded httpd', 'devicetype': 'printer'},
    {'number': 9100, 'state': 'open', 'method': 'table', 'service_name': 'jetdirect'},
]
HP = [
    {'number': 80, 'state': 'open', 'method': 'probed', 'service_name': 'soap', 'product': 'gSOAP',
     'scripts': {'http-server-header': '  Virata-EmWeb/R6_2_1\n  gSOAP/2.7'}},
    {'number': 443, 'state': 'open', 'method': 'probed', 'service_name': 'tcpwrapped'},
    {'number': 515, 'state': 'open', 'method': 'table', 'service_name': 'printer'},
    {'number': 631, 'state': 'open', 'method': 'probed', 'service_name': 'soap', 'product': 'gSOAP'},
    {'number': 9100, 'state': 'open', 'method': 'table', 'service_name': 'jetdirect'},
]
NODE_EXPORTER = [
    {'number': 22, 'state': 'open', 'method': 'probed', 'service_name': 'ssh', 'product': 'OpenSSH'},
    {'number': 9100, 'state': 'open', 'method': 'table', 'service_name': 'jetdirect'},
]


class PrintPortTests(unittest.TestCase):
    def test_the_print_ports(self):
        self.assertEqual(sorted(printers.PRINT_PORTS), [515, *range(9100, 9108)])
        self.assertEqual(printers.nmap_exclude_argument(), '515,9100-9107')
        self.assertTrue(printers.is_print_port('9100'))
        self.assertFalse(printers.is_print_port(True))  # a boolean is not a port
        self.assertFalse(printers.is_print_port(631))  # IPP is HTTP: a read is safe there, and no tool posts a job
        with self.assertRaises(printers.PrintPortRefused):
            printers.check_port(515)
        self.assertEqual(printers.without_print_ports([22, 515, 9100, 9108]), [22, 9108])


class PrinterEvidenceTests(unittest.TestCase):
    def test_the_brother_and_the_hp_printer_are_printers(self):
        self.assertTrue(printers.is_printer(BROTHER, 'Brother printer (VxWorks)'))
        self.assertTrue(printers.is_printer(BROTHER))  # nmap's device type alone
        self.assertTrue(printers.is_printer(HP, 'HP LaserJet M476dw printer'))
        self.assertTrue(printers.is_printer(HP))  # the HP embedded web server alone
        self.assertIn('raw print port 9100 (JetDirect) open', printers.printer_evidence(HP))

    def test_an_open_9100_without_a_printer_description_is_not_a_printer(self):
        # Prometheus' node exporter listens on 9100 too; the port guard still keeps every tool off it
        self.assertFalse(printers.is_printer(NODE_EXPORTER, 'Linux 5.4'))
        self.assertTrue(printers.is_printer(NODE_EXPORTER, snmp_text='HP ETHERNET MULTI-ENVIRONMENT, LaserJet'))

    def test_a_description_without_a_print_port_is_not_a_printer(self):
        self.assertFalse(printers.is_printer([{'number': 80, 'state': 'open', 'method': 'probed', 'devicetype': 'printer'}]))

    def test_closed_ports_are_not_evidence(self):
        self.assertFalse(printers.is_printer([{**row, 'state': 'closed'} for row in BROTHER]))


class FlagTests(unittest.TestCase):
    """Every builder of an nmap argv keeps the print ports out of anything that sends data."""

    def test_the_fingerprint_pass_excludes_print_ports(self):
        for argv in (flags.nmap_pass_flags(), flags.nmap_pass_flags([22, 515, 9100, 9103]), flags.NMAP_FAST_FLAGS):
            self.assertEqual(argv[argv.index('--exclude-ports') + 1], '515,9100-9107')
            self.assertNotIn('--allports', argv)
        listed = flags.nmap_pass_flags([22, 515, 9100, 9103])
        ports = listed[listed.index('-p') + 1].split(',')
        self.assertFalse(any(printers.is_print_port(p) for p in ports if '-' not in p))
        for part in (p for p in ports if '-' in p):
            low, high = map(int, part.split('-'))
            self.assertFalse(any(low <= port <= high for port in printers.PRINT_PORTS), part)
        self.assertNotIn(9100, flags.EXTRA_PORTS)

    def test_the_print_port_pass_is_syn_only(self):
        argv = flags.NMAP_PRINT_PORT_FLAGS
        self.assertIn('-sS', argv)
        for flag in ('-sV', '-sT', '-sC', '-A', '-O', '--script', '--version-all', '--allports'):
            self.assertNotIn(flag, argv)
        self.assertEqual(argv[argv.index('-p') + 1], '515,9100-9107')

    def test_the_version_probe_refuses_a_print_port(self):
        for port in (515, 9100, 9107):
            with self.assertRaises(printers.PrintPortRefused):
                flags.probe_nmap_flags(port, 'http')
        self.assertIn('--version-all', flags.probe_nmap_flags(631, 'http'))

    def test_nmap_verify_excludes_print_ports(self):
        argv = flags.NMAP_VERIFY_FLAGS
        self.assertEqual(argv[argv.index('--exclude-ports') + 1], '515,9100-9107')

    def test_the_sweeps_that_send_no_data_to_tcp_ports(self):
        # nmap_full is a SYN (or connect) scan with no service probe or script; discover pings; the UDP sweep names UDP ports only
        for flag in ('-sV', '--script', '-sC', '-A'):
            self.assertNotIn(flag, flags.NMAP_FULL_FLAGS)
            self.assertNotIn(flag, flags.DISCOVER_FLAGS)
        syn_probe = next(f for f in flags.DISCOVER_FLAGS if f.startswith('-PS'))
        self.assertFalse(any(printers.is_print_port(p) for p in syn_probe[3:].split(',')))
        udp = flags.udp_nmap_flags()
        self.assertTrue(udp[udp.index('-p') + 1].startswith('U:'))
        self.assertNotIn('T:', udp[udp.index('-p') + 1])

    def test_testssl_and_the_path_probes_name_no_port_of_their_own(self):
        self.assertFalse(any(printers.is_print_port(f) for f in flags.TESTSSL_FLAGS))
        self.assertFalse(any(printers.is_print_port(p) for p in flags.JDWP_PORTS))


if __name__ == '__main__':
    unittest.main()
