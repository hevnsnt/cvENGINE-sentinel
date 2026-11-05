"""The shared scan policy (``cvengine_scanner.flags``): the nuclei exclusion floor and flag builder, the UDP sweep's flags, the reviewed NSE
scripts and the probe ports. Ported from the cvENGINE server's tests (tests.test_resources, tests.test_authcheck, tests.test_egress_proxy,
tests.test_udp_scan, tests.test_hard_naabu, tests.test_probes, tests.test_discovery)."""
import unittest

from cvengine_scanner import flags


class NucleiFlagTests(unittest.TestCase):
    def test_every_nuclei_run_excludes_the_dos_templates(self):
        for argv in (flags.NUCLEI_FLAGS, flags.NUCLEI_BASE_FLAGS, flags.nuclei_flags(), flags.nuclei_flags(['rce'], 'light'),
                     flags.nuclei_flags(tech=True), flags.nuclei_flags(['wordpress'], secret_file='/tmp/x/secrets.json')):
            with self.subTest(argv=argv):
                self.assertEqual(argv[argv.index('-etags') + 1], 'dos')

    def test_the_sentinel_run_is_unchanged(self):
        # what a Sentinel ran before the builders moved here: a 1.3 server's tasks must run exactly as before
        self.assertEqual(flags.NUCLEI_FLAGS, ['-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150', '-c', '40', '-timeout', '10', '-retries', '1',
                                              '-omit-raw', '-etags', 'dos'])

    def test_the_server_run_is_unchanged(self):
        self.assertEqual(flags.NUCLEI_BASE_FLAGS, ['-severity', 'info,low,medium,high,critical', '-jsonl', '-silent', '-duc', '-ni', '-nc', '-rl', '150',
                                                   '-c', '40', '-timeout', '10', '-retries', '1', '-etags', 'dos'])

    def test_the_light_profile_lowers_rate_and_concurrency(self):
        normal, light = flags.nuclei_flags(), flags.nuclei_flags(profile='light')
        self.assertEqual(normal[normal.index('-rl') + 1], '150')
        self.assertEqual(light[light.index('-rl') + 1], '50')
        self.assertEqual(light[light.index('-c') + 1], '10')
        self.assertIn('-bs', light)
        self.assertEqual(flags.nuclei_flags(['rce', 'apache'], 'light')[-2:], ['-tags', 'apache,rce'])

    def test_severities_and_the_tech_pass(self):
        argv = flags.nuclei_flags(severities=['high', 'critical'])
        self.assertEqual(argv[argv.index('-severity') + 1], 'high,critical')
        tech = flags.nuclei_flags(['ignored'], tech=True)
        self.assertEqual(tech[tech.index('-severity') + 1], 'info')
        self.assertEqual(tech[-2:], ['-tags', 'tech'])

    def test_a_signed_in_run_adds_only_the_file_path_and_no_redirects(self):
        plain = flags.nuclei_flags(['wordpress'])
        signed = flags.nuclei_flags(['wordpress'], secret_file='/tmp/x/secrets.json')
        self.assertEqual(signed, plain + ['-sf', '/tmp/x/secrets.json', '-dr'])

    def test_the_templates_and_the_proxy_arguments(self):
        self.assertNotIn('-proxy', flags.nuclei_flags())
        self.assertEqual(flags.nuclei_flags(proxy_args=['-proxy', 'http://192.0.2.1:3128'])[-2:], ['-proxy', 'http://192.0.2.1:3128'])
        with_templates = flags.nuclei_flags(templates_dir='/t')
        self.assertEqual(with_templates[with_templates.index('-t') + 1], '/t')

    def test_host_of_reads_a_url_a_host_port_or_a_bare_host(self):
        self.assertEqual(flags.host_of({'host': 'https://Www.Example.test:8443/x'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test:8443'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': 'www.example.test'}), 'www.example.test')
        self.assertEqual(flags.host_of({'host': '', 'ip': '[2001:db8::1]'}), '2001:db8::1')
        self.assertEqual(flags.host_of({'host': 'http://[::1'}), '')  # a URL that does not parse names no host
        self.assertEqual(flags.host_of({'host': 5}), '')


class NmapFlagTests(unittest.TestCase):
    def test_only_reviewed_scripts_survive_and_the_udp_ones_are_reviewed(self):
        self.assertTrue(set(flags.UDP_NSE_SCRIPTS) <= flags.NSE_SCRIPT_SET)
        self.assertNotIn('ntp-monlist', flags.NSE_SCRIPT_SET)  # nmap files it under intrusive, and the target records it
        self.assertNotIn('snmp-brute', flags.NSE_SCRIPT_SET)
        self.assertEqual(flags.reviewed_scripts({'snmp-sysdescr': 'x', 'ntp-monlist': 'y', 'ike-version': 'z'}), {'snmp-sysdescr': 'x'})
        self.assertEqual(flags.reviewed_scripts(None), {})

    def test_the_udp_sweep_is_slow_and_low(self):
        argv = flags.udp_nmap_flags()
        self.assertEqual(argv[:2], ['-sU', '-sV'])
        self.assertEqual(argv[argv.index('--version-intensity') + 1], '3')
        self.assertEqual(argv[argv.index('--max-retries') + 1], '1')
        self.assertEqual(argv[argv.index('--max-rate') + 1], '20')
        self.assertIn('-Pn', argv)
        self.assertIn('-n', argv)
        self.assertNotIn('-T4', argv)
        self.assertTrue(set(argv[argv.index('--script') + 1].split(',')) <= flags.NSE_SCRIPT_SET)
        self.assertEqual(argv[argv.index('-p') + 1], 'U:' + ','.join(str(p) for p in flags.UDP_PORTS))
        custom = flags.udp_nmap_flags([123, 161], 5)
        self.assertEqual((custom[custom.index('-p') + 1], custom[custom.index('--max-rate') + 1]), ('U:123,161', '5'))

    def test_the_fingerprint_pass_runs_the_reviewed_scripts(self):
        self.assertEqual(flags.NMAP_FAST_FLAGS[flags.NMAP_FAST_FLAGS.index('--script') + 1], ','.join(flags.NSE_SCRIPTS))
        self.assertEqual(flags.NMAP_FAST_FLAGS[flags.NMAP_FAST_FLAGS.index('--top-ports') + 1], str(flags.TOP_PORTS))
        self.assertEqual(len(flags.EXTRA_PORTS), len(set(flags.EXTRA_PORTS)))
        self.assertTrue({6379, 27017, 2375, 10250} <= set(flags.EXTRA_PORTS))

    def test_the_port_argument_is_compact(self):
        self.assertEqual(flags.port_argument([8080, 22, 80, 81, 82, 443, 22]), '22,80-82,443,8080')
        self.assertEqual(flags.port_argument([5]), '5')
        self.assertEqual(flags.port_argument([*flags.CLOSED_PROBE_PORTS, 22]), '1,3,22')

    def test_the_version_probe_runs_only_reviewed_scripts_for_the_service(self):
        for service, expected in (('http', 'http-server-header'), ('ssl/http', 'http-server-header'), ('https', 'http-server-header'),
                                  ('ssh', 'ssh2-enum-algos'), ('ftp', 'ftp-anon'), ('mystery', 'banner'), ('', 'banner')):
            with self.subTest(service=service):
                argv = flags.probe_nmap_flags(443, service)
                scripts = argv[argv.index('--script') + 1].split(',')
                self.assertIn(expected, scripts)
                self.assertTrue(set(scripts) <= flags.NSE_SCRIPT_SET)
                self.assertEqual(argv[argv.index('-p') + 1], '443')
        with self.assertRaises(ValueError):
            flags.probe_nmap_flags('443; rm -rf /')

    def test_a_desktop_vm_kernel_is_named(self):
        for release in ('6.10.14-linuxkit', '5.15.153.1-microsoft-standard-WSL2', '6.7.11-orbstack-00143', '4.9.93-boot2docker', '4.9.87-moby'):
            self.assertTrue(any(marker in release.lower() for marker in flags.KERNEL_MARKERS), release)
        self.assertFalse(any(marker in '6.8.0-45-generic' for marker in flags.KERNEL_MARKERS))


if __name__ == '__main__':
    unittest.main()
