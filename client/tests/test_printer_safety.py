"""No tool of this Sentinel sends data to a raw print port (``cvengine_scanner.printers.PRINT_PORTS``: 515 and 9100 to 9107).

On 2026-11-26 the fingerprint pass's ``banner`` script sent a TLS ClientHello to port 9100 of two printers on Bill's home network, and ``-sV``
sent HTTP, TLS and RPC probes to their port 515; a printer printed it. Each test here asks one tool for a print port and checks that the tool
refuses before any process starts or any socket opens.
"""
import struct
import threading
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from client import host_names, openvas, scope, shotproxy, tools
from cvengine_scanner import scope as library_scope
from cvengine_scanner import flags, printers
from cvengine_scanner.probes import java_runtime, transport
from cvengine_scanner.probes.policy import ScopePolicy

PUBLIC = '93.184.215.14'
FINISHED_REPORT = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'


def fake_getaddrinfo(name, port, *args, **kwargs):
    if name != 'www.example.test':
        raise OSError('no such host')
    return [(2, 1, 6, '', (PUBLIC, port or 0))]


def setUpModule():
    for patcher in (mock.patch('socket.getaddrinfo', side_effect=fake_getaddrinfo),
                    mock.patch.object(scope, 'own_addresses', return_value=frozenset({'172.19.0.2'})),
                    mock.patch.object(scope, 'internal_allowed', return_value=False)):
        patcher.start()
        unittest.addModuleCleanup(patcher.stop)


def no_process():
    """Patch every way a runner starts a tool; the test fails if one is used."""
    return mock.patch.multiple('client.tools', _run=mock.DEFAULT, _start=mock.DEFAULT, _run_status=mock.DEFAULT)


class PortArgumentTests(unittest.TestCase):
    """The kinds that take a port from the task refuse a print port before anything runs."""

    def assert_refused(self, call):
        with no_process() as started:
            with self.assertRaises(tools.TargetError) as raised:
                call()
        self.assertIn('print port', str(raised.exception))
        for name, fake in started.items():
            self.assertFalse(fake.called, f'{name} was called')

    def test_every_print_port_is_refused_and_its_neighbours_are_not(self):
        for port in (515, 9100, 9101, 9104, 9107):
            with self.assertRaises(tools.TargetError):
                tools._validate_port(port)
        for port in (514, 516, 631, 9099, 9108, 443):
            self.assertEqual(tools._validate_port(port), port)

    def test_testssl(self):
        self.assert_refused(lambda: tools.run_testssl('www.example.test', PUBLIC, 9100))

    def test_waf(self):
        self.assert_refused(lambda: tools.run_waf('www.example.test', PUBLIC, 515, 'http'))

    def test_nmap_verify(self):
        self.assert_refused(lambda: tools.run_nmap_verify(PUBLIC, [80, 9100], version_all=True))

    def test_rdp_shot(self):
        self.assert_refused(lambda: tools.run_rdp_shot(PUBLIC, 9102))

    def test_db_probe(self):
        self.assert_refused(lambda: tools.run_db_probe(PUBLIC, 9100, 'redis'))

    def test_path_probe(self):
        self.assert_refused(lambda: tools.run_path_probe([{'ip': PUBLIC, 'port': 515}]))

    def test_ssh_probe(self):
        self.assert_refused(lambda: tools.run_ssh_probe({'targets': [{'address': PUBLIC, 'port': 9100}], 'scope': {}}))


class UrlTests(unittest.TestCase):
    """A URL that names a print port is refused by scope, which every URL kind goes through (wpscan, node2shell, nuclei's URL targets)."""

    def test_scope_refuses_a_url_on_a_print_port(self):
        for url in ('http://www.example.test:9100/', 'https://www.example.test:515/x', 'http://93.184.215.14:9107'):
            with self.assertRaises(library_scope.ScopeError):
                library_scope.check_url(url, resolver=fake_getaddrinfo)
        self.assertEqual(library_scope.check_url('http://www.example.test:631/', resolver=fake_getaddrinfo), 'http://www.example.test:631/')

    def test_wpscan_and_node2shell(self):
        for call in (lambda: tools.run_wpscan('http://www.example.test:9100/'), lambda: tools.run_node2shell('http://www.example.test:9100/')):
            with no_process() as started:
                with self.assertRaises(tools.TargetError):
                    call()
            self.assertFalse(any(f.called for f in started.values()))


class NucleiTests(unittest.TestCase):
    def test_a_host_port_or_url_target_on_a_print_port_is_refused_and_named(self):
        allowed, refused = tools._judged_targets([f'{PUBLIC}:9100', f'{PUBLIC}:515', f'http://{PUBLIC}:9101/', f'{PUBLIC}:443', PUBLIC],
                                                 fake_getaddrinfo)
        self.assertEqual(allowed, [f'{PUBLIC}:443', PUBLIC])
        self.assertEqual(sorted(refused), sorted([f'{PUBLIC}:9100', f'{PUBLIC}:515', f'http://{PUBLIC}:9101/']))
        self.assertTrue(all('print port' in why for why in refused.values()))

    def test_a_task_of_only_print_ports_runs_no_nuclei(self):
        with no_process() as started, mock.patch.object(tools, 'nuclei_version', return_value=(3, 11, 1)):
            got = tools.run_nuclei([f'{PUBLIC}:9100'], services={f'{PUBLIC}:9100': 'unknown'})
        self.assertFalse(any(f.called for f in started.values()))
        self.assertEqual(got['findings'], [])
        self.assertEqual(got['unreachable'], [f'{PUBLIC}:9100'])  # named as not checked, so the server never reads it as clean
        self.assertIn('print port', got['not_checked'][0]['reason'])

    def test_the_web_pass_never_runs_raw_tcp_templates(self):
        # a bare host's raw tcp templates would connect to the ports their template names, a print port among them
        web = flags.nuclei_web_flags()
        self.assertEqual(web[web.index('-ept') + 1], 'tcp,javascript')


class NmapPassTests(unittest.TestCase):
    """The fingerprint pass leaves the print ports out whole, and a SYN-only pass says which are open."""

    def test_the_fingerprint_pass_excludes_print_ports_and_the_syn_pass_sends_no_data(self):
        runs = []
        main = ('<nmaprun><host><status state="up"/><address addr="93.184.215.14" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="80"><state state="open"/><service name="http" method="probed" conf="10"/></port></ports></host>'
                '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')
        syn = ('<nmaprun><host><status state="up"/><address addr="93.184.215.14" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect" method="table" conf="3"/></port>'
               '<port protocol="tcp" portid="515"><state state="open"/><service name="printer" method="table" conf="3"/></port></ports></host>'
               '<runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')

        def fake_run(argv, timeout, register=None, **kw):
            runs.append(argv)
            return main if '-sV' in argv else syn
        with mock.patch('client.tools._run', side_effect=fake_run), mock.patch('client.tools._nmap_follow_up', return_value=[]):
            result = tools.run_nmap([PUBLIC], ports=[80, 515, 9100, 9105])
        fingerprint, print_pass = runs
        self.assertEqual(fingerprint[fingerprint.index('--exclude-ports') + 1], '515,9100-9107')
        listed = fingerprint[fingerprint.index('-p') + 1]
        self.assertNotIn('9100', listed)
        self.assertNotIn('515', listed.split(','))
        for flag in ('-sV', '--script', '-O', '-sT', '-sC', '--version-all', '--allports'):
            self.assertNotIn(flag, print_pass)
        self.assertIn('-sS', print_pass)
        self.assertEqual(print_pass[print_pass.index('-p') + 1], '515,9100-9107')
        ports = sorted(p['number'] for p in result['hosts'][0]['ports'])
        self.assertEqual(ports, [80, 515, 9100])

    def test_a_failed_syn_pass_leaves_the_fingerprint_pass_whole(self):
        main = ('<nmaprun><host><status state="up"/><address addr="93.184.215.14" addrtype="ipv4"/><ports>'
                '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" method="probed" conf="10"/></port></ports></host>'
                '<runstats><finished exit="success"/></runstats></nmaprun>')

        def fake_run(argv, timeout, register=None, **kw):
            if '-sV' in argv:
                return main
            raise tools.ToolExitError('nmap failed')
        with mock.patch('client.tools._run', side_effect=fake_run), mock.patch('client.tools._nmap_follow_up', return_value=[]):
            result = tools.run_nmap([PUBLIC])
        self.assertEqual([p['number'] for p in result['hosts'][0]['ports']], [22])

    def test_the_syn_pass_adds_no_row_for_a_host_the_fingerprint_pass_did_not_cover(self):
        syn = ('<nmaprun><host><status state="up"/><address addr="93.184.215.14" addrtype="ipv4"/><ports>'
               '<port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect" method="table" conf="3"/></port></ports></host>'
               '<runstats><finished exit="success"/></runstats></nmaprun>')
        with mock.patch('client.tools._run', side_effect=lambda argv, *a, **kw: FINISHED_REPORT if '-sV' in argv else syn), \
                mock.patch('client.tools._nmap_follow_up', return_value=[]):
            self.assertEqual(tools.run_nmap([PUBLIC])['hosts'], [])


class SocketTests(unittest.TestCase):
    """The in-process probes open their connections through ``transport``, the screenshot browser through its proxy, the secrets scan through its
    own pinned connections: each refuses a print port before connecting."""

    def test_transport_resolve_and_open_socket(self):
        policy = mock.Mock(spec=ScopePolicy)  # allows everything: only the print port guard can refuse
        policy.address_refusal.return_value = ''
        with self.assertRaises(printers.PrintPortRefused):
            transport.resolve('www.example.test', 9100, policy)
        with mock.patch('socket.socket') as sock:
            with self.assertRaises(printers.PrintPortRefused):
                transport.open_socket(((2, (PUBLIC, 515)),), 5, policy, host=PUBLIC)
        sock.assert_not_called()

    def test_the_screenshot_proxy_never_admits_a_print_port(self):
        admit, connect = mock.Mock(return_value=((PUBLIC, 9100), '')), mock.Mock()
        proxy = shotproxy.VettingProxy(admit, connect, 'secret')
        self.assertEqual(proxy._open_upstream('page', 'www.example.test', 9100), (None, 'refused'))
        admit.assert_not_called()
        connect.assert_not_called()

    def test_the_secrets_scan_connections(self):
        from client import secrets_scan
        for cls in (secrets_scan._Pinned, secrets_scan._PinnedTLS):
            with mock.patch('socket.create_connection') as connect:
                with self.assertRaises(printers.PrintPortRefused):
                    cls('www.example.test', PUBLIC, 9100, 5).connect()
            connect.assert_not_called()

    def test_the_jdwp_handshake(self):
        policy = mock.Mock()
        connect = mock.Mock()
        got = java_runtime.run_jdwp({'id': 'j1', 'address': PUBLIC, 'port': 9100}, policy, connect=connect)
        self.assertIsNone(got['speaks'])
        self.assertIn('print port', got['error'])
        connect.assert_not_called()


class OpenvasPortListTests(unittest.TestCase):
    def test_the_print_ports_are_cut_out_of_the_iana_list(self):
        self.assertEqual(openvas.print_safe_ranges([(1, 1024), (9000, 9200)]), 'T:1-514,516-1024,9000-9099,9108-9200')
        self.assertEqual(openvas.print_safe_ranges([(515, 515), (9100, 9107)]), '')

    def test_a_list_that_still_names_a_print_port_is_refused(self):
        ranges = '<port_range><start>1</start><end>65535</end><type>tcp</type></port_range>'
        gmp = mock.Mock()
        gmp.get_port_lists.return_value = ET.fromstring(f'<r><port_list id="mine"><name>{openvas.PRINT_SAFE_PORT_LIST}</name></port_list></r>')
        gmp.get_port_list.return_value = ET.fromstring(f'<r><port_list id="mine"><port_ranges>{ranges}</port_ranges></port_list></r>')
        with self.assertRaises(openvas.OpenvasError):
            openvas.ensure_port_list(gmp)

    def test_a_new_list_is_made_without_print_ports(self):
        gmp = mock.Mock()
        gmp.get_port_lists.return_value = ET.fromstring(f'<r><port_list id="{openvas.PORT_LIST[0]}"><name>{openvas.PORT_LIST[1]}</name></port_list></r>')

        def one(list_id):
            ranges = [(1, 1024), (9100, 9100)] if list_id == openvas.PORT_LIST[0] else [(1, 514), (516, 1024)]
            body = ''.join(f'<port_range><start>{a}</start><end>{b}</end><type>tcp</type></port_range>' for a, b in ranges)
            return ET.fromstring(f'<r><port_list id="{list_id}"><port_ranges>{body}</port_ranges></port_list></r>')
        gmp.get_port_list.side_effect = one
        gmp.create_port_list.return_value = ET.fromstring('<r id="new"/>')
        self.assertEqual(openvas.ensure_port_list(gmp), 'new')
        name, text = gmp.create_port_list.call_args[0][:2]
        self.assertEqual((name, text), (openvas.PRINT_SAFE_PORT_LIST, 'T:1-514,516-1024'))


class DiscoverNameTests(unittest.TestCase):
    """The discover sweep names each host it found: reverse DNS from nmap, and the host's own mDNS and NetBIOS names."""

    @staticmethod
    def mdns_answer(name):
        def encode(n):
            return b''.join(bytes([len(p)]) + p.encode() for p in n.split('.')) + b'\x00'
        question = encode('71.1.168.192.in-addr.arpa')
        target = encode(name)
        return (struct.pack('!HHHHHH', 0, 0x8400, 1, 1, 0, 0) + question + struct.pack('!HH', 12, 1)
                + b'\xc0\x0c' + struct.pack('!HHIH', 12, 1, 120, len(target)) + target)

    @staticmethod
    def netbios_answer(*entries):
        name = b'\x20' + b'CK' + b'AA' * 15 + b'\x00'
        body = bytes([len(entries)]) + b''.join(n.ljust(15).encode()[:15] + bytes([suffix]) + struct.pack('!H', fl) for n, suffix, fl in entries)
        return struct.pack('!HHHHHH', 0, 0x8400, 0, 1, 0, 0) + name + struct.pack('!HHIH', 0x21, 1, 0, len(body)) + body

    def test_the_mdns_and_netbios_answers_are_read(self):
        self.assertEqual(host_names.parse_mdns_answer(self.mdns_answer('BRWA8934A937F17.local')), 'brwa8934a937f17.local')
        self.assertEqual(host_names.parse_netbios_answer(self.netbios_answer(('WORKGROUP', 0, 0x8000), ('COGSWELL', 0x20, 0), ('COGSWELL', 0, 0))),
                         'COGSWELL')
        self.assertEqual(host_names.parse_mdns_answer(b'junk'), '')
        self.assertEqual(host_names.parse_netbios_answer(b''), '')

    def test_the_questions_are_what_the_protocols_expect(self):
        question = host_names.netbios_question(query_id=7)
        self.assertEqual(question[:12], struct.pack('!HHHHHH', 7, 0, 1, 0, 0, 0))
        self.assertEqual(question[12:46], b'\x20CK' + b'AA' * 15 + b'\x00')
        self.assertEqual(question[-4:], struct.pack('!HH', 0x21, 1))
        self.assertIn(b'\x0271\x011\x03168\x03192\x07in-addr\x04arpa\x00', host_names.mdns_question('192.168.1.71', query_id=1))

    def test_names_that_are_not_host_names_are_dropped(self):
        self.assertEqual(host_names.clean_host_name('Living Room.local'), '')
        self.assertEqual(host_names.clean_host_name('a' * 300), '')
        self.assertEqual(host_names.clean_host_name('Johnny.LAN.'), 'johnny.lan')

    def test_the_sweep_returns_each_hosts_names(self):
        xml = ('<nmaprun><host><status state="up"/><address addr="192.168.1.71" addrtype="ipv4"/>'
               '<hostnames><hostname name="brwa8934a937f17.lan" type="PTR"/></hostnames></host>'
               '<host><status state="up"/><address addr="192.168.1.77" addrtype="ipv4"/><hostnames/></host>'
               '<runstats><finished exit="success"/></runstats></nmaprun>')
        with mock.patch('client.config._local_internal', return_value=True), mock.patch('client.tools._run', return_value=xml), \
                mock.patch.object(host_names, 'mdns_name', side_effect=lambda ip, **kw: 'chromecast.local' if ip.endswith('.77') else ''), \
                mock.patch.object(host_names, 'netbios_name', return_value=''), mock.patch('client.scope.check_network'):
            result = tools.run_discover('192.168.1.0/24')
        rows = {h['ip']: h for h in result['hosts']}
        self.assertEqual(rows['192.168.1.71']['hostnames'], ['brwa8934a937f17.lan'])
        self.assertNotIn('names', rows['192.168.1.71'])
        self.assertEqual(rows['192.168.1.77']['names'], {'mdns': 'chromecast.local'})

    def test_a_slow_host_does_not_hold_the_sweep(self):
        gate = threading.Event()
        rows = [{'ip': '192.168.1.5', 'hostnames': []}]
        host_names.name_hosts(rows, budget=0.2, mdns=lambda ip: gate.wait(5) and '', netbios=lambda ip: '')
        gate.set()
        self.assertNotIn('names', rows[0])

    def test_name_questions_go_only_to_ports_that_are_not_print_ports(self):
        self.assertFalse(printers.is_print_port(host_names.MDNS_PORT))
        self.assertFalse(printers.is_print_port(host_names.NETBIOS_PORT))


if __name__ == '__main__':
    unittest.main()
