"""The nmap kind's result keeps what nmap learned and says what it cut (TL-1, TL-13, SN-6; contract 5)."""
import os
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from client import tools
from cvengine_scanner import contract

XML = open(os.path.join(os.path.dirname(contract.__file__), '..', 'tests', 'fixtures', 'nmap_fingerprint.xml'), encoding='utf-8').read()


class RunNmapKeepsTheDetailTests(unittest.TestCase):
    def run_nmap(self, xml=XML, addresses=('8.8.8.8', '1.1.1.1')):
        with mock.patch('client.tools._run', return_value=xml):
            return tools.run_nmap(list(addresses))

    def test_the_result_carries_the_banner_tunnel_certificate_and_scanned_ports_and_validates(self):
        result = self.run_nmap()
        host = {h['ip']: h for h in result['hosts']}['192.0.2.11']
        ports = {p['number']: p for p in host['ports']}
        self.assertEqual(ports[443]['tunnel'], 'ssl')
        self.assertEqual(ports[22]['banner'], 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5')
        self.assertIn('ssl-cert', ports[21]['scripts'])
        self.assertTrue(host['scanned_ranges'])
        self.assertEqual(host['closed_tcp'], 1)
        self.assertEqual(list(Draft202012Validator(contract.result_schema('nmap')).iter_errors({'outcome': 'done', **result})), [])

    def test_a_cut_of_the_run_reaches_the_result(self):
        result = self.run_nmap()
        self.assertEqual([c['what'] for c in result['cuts']], ['host_timeout'])

    def test_the_ipv4_and_ipv6_runs_add_up_their_cuts(self):
        one = ('<nmaprun><host timedout="true"><address addr="{ip}" addrtype="{kind}"/><ports/></host><runstats><finished exit="success"/></runstats></nmaprun>')
        answers = iter([one.format(ip='192.0.2.1', kind='ipv4'), one.format(ip='2001:db8::1', kind='ipv6')])
        with mock.patch('client.tools._run', side_effect=lambda *a, **k: next(answers)):
            result = tools.run_nmap(['8.8.8.8', '2606:4700:4700::1111'])
        self.assertEqual(sorted(c['target'] for c in result['cuts']), ['192.0.2.1', '2001:db8::1'])

    def test_a_clean_run_has_no_cuts(self):
        with mock.patch('client.tools._run', return_value=open(os.path.join(os.path.dirname(contract.__file__), '..', 'tests', 'fixtures', 'sample_nmap.xml'), encoding='utf-8').read()):
            self.assertNotIn('cuts', tools.run_nmap(['8.8.8.8', '1.1.1.1']))


FEATURES_XML = open(os.path.join(os.path.dirname(contract.__file__), '..', 'tests', 'fixtures', 'nmap_service_features.xml'),
                    encoding='utf-8').read().replace('192.0.2.20', '8.8.8.8').replace('192.0.2.21', '1.1.1.1')


class RunNmapFeatureReadingsTests(unittest.TestCase):
    """The fingerprint pass carries the service feature readings: the SSH and RDP ones from its own NSE output, the SMTP and SMB ones from the
    follow-up probes on the task's own addresses."""

    def test_the_nse_readings_and_the_follow_up_reach_the_result_and_validate(self):
        seen = {}

        def follow_up(hosts, vetted, budget):
            seen.update(vetted=vetted, budget=budget, ips=[h['ip'] for h in hosts])
            return [{'host': '8.8.8.8', 'port': 445, 'transport': 'tcp', 'feature': 'smbv1', 'value': 'no', 'detail': ''}], 3
        with mock.patch('client.tools._run', return_value=FEATURES_XML), \
                mock.patch('cvengine_scanner.probes.service_probes.follow_up', side_effect=follow_up):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'], timeout=600)
        got = {(i['host'], i['port'], i['feature']): i['value'] for i in result['service_features']}
        self.assertEqual(got[('8.8.8.8', 22, 'ssh_terrapin')], 'exposed')
        self.assertEqual(got[('1.1.1.1', 3389, 'rdp_nla')], 'not_required')
        self.assertEqual(got[('8.8.8.8', 445, 'smbv1')], 'no')
        self.assertEqual(seen['vetted'], {'8.8.8.8', '1.1.1.1'})
        self.assertLessEqual(seen['budget'], 120)
        self.assertIn({'what': 'feature_probes', 'kind': 'items', 'limit': 64, 'dropped': 3}, result['cuts'])
        self.assertEqual(list(Draft202012Validator(contract.result_schema('nmap')).iter_errors({'outcome': 'done', **result})), [])

    def test_a_failing_follow_up_never_fails_the_pass(self):
        with mock.patch('client.tools._run', return_value=FEATURES_XML), \
                mock.patch('cvengine_scanner.probes.service_probes.follow_up', side_effect=RuntimeError('boom')):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'])
        self.assertEqual(len(result['hosts']), 2)
        self.assertNotIn('service_features', result)

    def test_no_time_left_asks_nothing(self):
        with mock.patch('client.tools._run', return_value=FEATURES_XML), \
                mock.patch('cvengine_scanner.probes.service_probes._connect', side_effect=AssertionError('nothing may be asked')):
            result = tools.run_nmap(['8.8.8.8', '1.1.1.1'], timeout=tools.FOLLOW_UP_MARGIN)
        self.assertIn('service_features', result)  # the NSE readings cost nothing


if __name__ == '__main__':
    unittest.main()
